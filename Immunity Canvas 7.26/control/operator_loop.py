#!/usr/bin/env python

import sys
if '.' not in sys.path: sys.path.append('.')

import os
import zmq
import uuid
import time
import json
import logging
import Queue as queue

import zmq.eventloop.zmqstream as zmqstream
import zmq.eventloop.ioloop as ioloop

from canvasengine import canvas_root_directory as CANVAS_ROOT
from control.event_loop import EventLoop
from control.exceptions import ZMQConnectionError

ALIVE_THRESHOLD  = 10
EVENT_BURST_RATE = 50

def commander_handler(f):
    """
    Simple decorator that is used to define msg handlers.
    If the wrapped method returns a value, Operator.msg()
    is called with that value as an argument.
    """
    def decorated(self, *args):
        try:
            ret = f(self, *args)
            if ret: self.msg(*ret)
        except Exception:
            self.logger.exception('Handler exception:')
    return decorated

def canvas_handler(f):
    """
    Simple decorator that is used to define msg handlers.
    If the wrapped method returns a value, that value is
    inserted into the local event queue.
    """
    def decorated(self, *args):
        try:
            ret = f(self, *args)
            if ret: self.event_queue.put_nowait(ret)
        except Exception:
            self.logger.exception('Handler exception:')
    return decorated



class OperatorLoop(EventLoop):
    INITIALIZED  = 'INITIALIZED'
    CONNECTED    = 'CONNECTED'
    DISCONNECTED = 'DISCONNECTED'

    def __init__(self, engine):
        try:
            EventLoop.__init__(self)
            self.state      = OperatorLoop.INITIALIZED
            self.engine     = engine
            self.commander  = engine.config['commander']

            self.commander_sub_addr  = 'tcp://%s:%s' % (self.commander, self.engine.config['commander_pub_port'])
            self.commander_push_addr = 'tcp://%s:%s' % (self.commander, self.engine.config['commander_pull_port'])

            self.uuid       = '%X' % uuid.getnode()
            self.session_id = time.time()
            self.context    = zmq.Context()

            self.config     = None
            self.node_tree  = None

            # Sockets
            self.outgoing   = self.context.socket(zmq.PUSH)
            self.incoming   = self.context.socket(zmq.SUB)

            # Chat
            self.chat_queue  = queue.Queue()

            # Events
            self.event_queue = queue.Queue()

            # For heartbeating
            self.commander_last_seen = 0

            # Dictionary of dictionaries
            # Keys for first are:  UUIDs
            # Keys for second are: UUID, alias
            self._operators  = {}

            # Keys are group names
            # Values are dictionaries with UUIDs as keys and dictionaries from
            # self.operators are values
            self.groups     = {}

            # Logging
            log_path = os.path.join(CANVAS_ROOT, 'control', 'log')
            if not os.path.exists(log_path): os.mkdir(log_path)

            self.logger     = logging.getLogger(self.uuid)
            self.logger.setLevel(logging.DEBUG)

            if not self.logger.disabled:
                formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s %(message)s')
                # handler_stderr = logging.StreamHandler(sys.stderr)
                # handler_stderr.setLevel(logging.DEBUG)
                # handler_stderr.setFormatter(formatter)
                # self.logger.addHandler(handler_stderr)

                handler_debug = logging.FileHandler(os.path.join(log_path, '%s_debug.log' % self.uuid), 'ab', delay=True)
                handler_debug.setLevel(logging.DEBUG)
                handler_debug.setFormatter(formatter)
                self.logger.addHandler(handler_debug)

                handler_error = logging.FileHandler(os.path.join(log_path, '%s_error.log' % self.uuid), 'ab', delay=True)
                handler_error.setLevel(logging.ERROR)
                handler_error.setFormatter(formatter)
                self.logger.addHandler(handler_error)
            else:
                self.logger.disabled = False

            self.update_config()
            self.update_nodes()

            # This is for debugging, way to force UUID so that we can run multiple
            # CANVAS instances on the same machine
            if self.config['operator_uuid']:
                self.uuid = self.config['operator_uuid']

            # Initialization
            self.outgoing.setsockopt(zmq.LINGER, 500) # 500ms default linger
            self.incoming.setsockopt(zmq.SUBSCRIBE, self.uuid)
            self.incoming.setsockopt(zmq.SUBSCRIBE, "command")
            self.incoming.setsockopt(zmq.SUBSCRIBE, "register")

            try:
                self.incoming.connect(self.commander_sub_addr)
                self.outgoing.connect(self.commander_push_addr)
            except Exception:
                raise ZMQConnectionError('Error when connecting to commander @ %s' % self.commander)

            # Join the default global group
            self.join_group('global')
        except Exception:
            self.logger.disabled = True
            raise

    @property
    def name(self):
        return self.config.get('operator_alias') or self.uuid


    def _parse_node(self, node):
        """
        Return a dictionary that contains the entire structure for node,
        including children nodes in the form of a tree (embedded dicts).
        """
        ret                  = {}
        ret['name']          = node.getname()
        ret['type']          = node.nodetype
        ret['capabilities']  = node.capabilities
        ret['known_hosts']   = [{'node'      : ret['name'],
                                 'host'      : host.interface,
                                 'knowledge' : [{'tag'     : str(x.tag),
                                                 'text'    : str(x.known_text),
                                                 'percent' : x.percentage}
                                              for x in host.get_all_knowledge_as_list()],
                                 'target'    : True if host in node.engine.target_hosts else False}
                              for host in node.hostsknowledge.get_children()]

        ret['interfaces']    = [{'node'      : ret['name'],
                                 'interface' : iface.interface,
                                 'ip'        : iface.ip,
                                 'netmask'   : iface.netmask,
                                 'NAT'       : True if iface.isNAT else False,
                                 'callback'  : True if iface == node.engine.callback_interface else False,
                                 'listeners' : [{'type'             : x[0],
                                                 'port'             : x[1],
                                                 'fromcreatethread' : x[2]} for x in iface.listeners_that_are_listening]}
                                for iface in node.interfaces.all_interface_objects()]

        ret['children']      = map(self._parse_node, node.child_nodes)
        ret['listener']      = node.listener_type
        return ret

    def update_config(self):
        """
        Update our copy of CANVAS state with the CANVAS configuration.
        """
        self.config = self.engine.config

    def update_nodes(self):
        """
        Update our copy of CANVAS state with the CANVAS node information.
        The root node will always be the LocalNode.
        """
        self.node_tree = self._parse_node(self.engine.nodeTree)

    def join_group(self, group):
        if group == 'commander':
            self.logger.error('You can not join the commander group.')
        elif group not in self.groups:
            self.incoming.setsockopt(zmq.SUBSCRIBE, group)
            self.groups[group] = {}
            self.tell('', group, event='join')
        else:
            self.logger.error('You are already in group %s' % group)

    def leave_group(self, group):
        if group == 'global':
            self.logger.error('You can not depart the global group.')
        elif group in self.groups:
            self.incoming.setsockopt(zmq.UNSUBSCRIBE, group)
            self.tell('', group, event='depart')
            del self.groups[group]
        else:
            self.logger.error('You have not joined group %s' % group)

    ######################################################################
    #
    # Commander message handlers
    #
    ######################################################################

    @commander_handler
    def _pong(self, count, time_ref):
        """
        Heartbeating
        """

        if self.state in (OperatorLoop.INITIALIZED, OperatorLoop.DISCONNECTED):
            self.incoming.setsockopt(zmq.UNSUBSCRIBE, "register")

            if self.state == OperatorLoop.INITIALIZED:
                self.logger.info('Connected to commander @ %s' % self.commander)
            else:
                self.logger.info('Re-connected to commander @ %s' % self.commander)

            self.state = OperatorLoop.CONNECTED

        return ('pong', count, int(time.time()*1000.0))

    @commander_handler
    def _state(self):
        """
        Sends out entire CANVAS state.

        Currently this means: config, node_tree and group information.
        Useful for initialization/synchronization.
        """

        self.update_config()
        self.update_nodes()

        return ('state', self.config, self.node_tree, self.groups.keys())

    @commander_handler
    def _tell(self, source, dest, message, meta):
        """
        This is a communication message.

        source should be an operator id or commander
        meta should be a dictionary with optional keys:
        alias (if source is an operator), event (join/depart/list/pong)
        """
        alias = meta['alias']

        if dest not in self.groups and dest != self.uuid:
            self.logger.error('Received message from %s for %s' % (source, dest))
            return

        if source not in ('commander', self.uuid):
            # Update local aliases
            if source not in self._operators:
                self._operators[source] = {'uuid' : source, 'alias' : alias}
            else:
                self._operators[source]['alias'] = alias

        if dest in self.groups:
            if 'event' in meta and source != self.uuid:
                event = meta['event']

                if event == 'join':
                    # Operator joined one of our groups
                    self.groups[dest][source] = self._operators[source]

                    # Tell him we're there
                    self.tell('', dest, event='pong')
                elif event == 'depart':
                    # Operator departed one of our groups
                    if source in self.groups[dest]:
                        del self.groups[dest][source]
                elif event == 'list':
                    # Operator asked for group list
                    self.tell('', dest, event='pong')
                elif event == 'pong':
                    # Operator is active in group
                    self.groups[dest][source] = self._operators[source]
            else:
                if source not in ('commander', self.uuid) and source not in self.groups[dest]:
                    self.groups[dest][source] = self._operators[source]

        self.chat_queue.put((source, dest, message, meta))

    def dispatch(self, msg):
        """
        Dispatch on `msg' (sequence). msg[0] is the keyword
        to dispatch on according to the handlers dictionary.

        msg[1:] must contain arguments that are going to be passed
        verbatim to the handler function.
        """
        handlers = {
            'ping'          : self._pong,
            'state'         : self._state,
            'tell'          : self._tell,
        }

        handlers[msg[0]](*msg[1:])

    def handle_commander(self, msg):
        """
        Callback function for messages sent by commander.
        """
        topic, msg = msg[0], msg[1]

        try:
            msg = json.loads(msg)
        except Exception:
            self.logger.exception('(%s) handle_commander:' % topic)
            return

        self.commander_last_seen = time.time()
        self.dispatch(msg)


    ######################################################################
    #
    # Messaging to commander
    #
    ######################################################################

    def msg(self, *args):
        """
        Sends a message to commander.
        """
        self.outgoing.send_multipart((self.uuid, json.dumps(args, ensure_ascii=True)))

    def tell(self, msg, dest, event=None):
        """
        Sends a message to dest which must be a joined group or commander.
        """

        if dest not in ('global', 'commander') and dest not in self.groups:
            self.logger.error('We have not joined group %s' % dest)
            return

        meta = {'alias' : self.name}
        if event: meta['event'] = event

        self.msg('tell', dest, msg, meta)

    ######################################################################
    #
    # CANVAS event handler
    #
    ######################################################################

    @canvas_handler
    def _new_alias(self):
        return ('new_alias', self.config['operator_alias'])

    @canvas_handler
    def _updated_targets(self):
        return ('updated_targets', self.node_tree)

    @canvas_handler
    def _new_node(self, node_name):
        return ('new_node', self.node_tree, node_name)

    @canvas_handler
    def _node_deleted(self, node_name):
        return ('node_deleted', self.node_tree, node_name)

    @canvas_handler
    def _new_host(self, node, ip):
        return ('new_host', self.node_tree, node, ip)

    @canvas_handler
    def _host_deleted(self, node, ip):
        return ('host_deleted', self.node_tree, node, ip)

    @canvas_handler
    def _callback_changed(self):
        return ('callback_changed', self.node_tree)

    @canvas_handler
    def _knowledge_updated(self, knowledge):
        """
        knowledge should be a dictionary with following keys:
        node, host, tag, knowledge, percentage
        """
        return ('knowledge_updated', self.node_tree, knowledge)

    @canvas_handler
    def _knowledge_deleted(self, knowledge):
        """
        knowledge should be a dictionary with following keys:
        node, host, tag
        """
        return ('knowledge_deleted', self.node_tree, knowledge)

    @canvas_handler
    def _interface_added(self, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, netmask, NAT
        """
        return ('interface_added', self.node_tree, data)

    @canvas_handler
    def _new_listener(self, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, type, port, fromcreatethread
        """
        return ('new_listener', self.node_tree, data)

    @canvas_handler
    def _killed_listener(self, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, type, port, fromcreatethread
        """
        return ('killed_listener', self.node_tree, data)


    @canvas_handler
    def _module_started(self, data):
        """
        data should be a dictionary with the following keys:
        name, id, target, nodes, session, local
        """
        return ('module_started', data)

    @canvas_handler
    def _module_returned(self, data):
        """
        data should be a dictionary with the following keys:
        name, id, success, session
        """
        return ('module_returned', data)

    def handle_CANVAS(self, name, data, module):
        """
        This function is our registered CANVAS event handler.
        It will get called for every event generated by CANVAS.
        """

        if name == 'configuration changed':
            self.update_config()

            if 'operator_alias' in data:
                self._new_alias()

        elif name in ['new target', 'new additional target', 'removed target']:
            self.update_nodes()
            self._updated_targets()

        elif name == 'new node':
            self.update_nodes()
            self._new_node(data['name'])

        elif name == 'node deleted':
            self.update_nodes()
            self._node_deleted(data['node'])

        elif name == 'new host':
            self.update_nodes()
            self._new_host(data['node'], data['ip'])
        elif name == 'host deleted':
            self.update_nodes()
            self._host_deleted(data['node'], data['ip'])
        elif name == 'callback changed':
            self.update_nodes()
            self._callback_changed()

        elif name in ['knowledge added', 'knowledge replaced']:
            self.update_nodes()

            # Do this here before we send over zmq to avoid serializing
            # CANVAS internals
            if not isinstance(data['knowledge'], basestring):
                if isinstance(data['knowledge'], (list, tuple)):
                    # If list or tuple, call str on all values
                    data['knowledge'] = str(map(str, data['knowledge']))
                else:
                    data['knowledge'] = str(data['knowledge'])

            self._knowledge_updated(data)
        elif name == 'knowledge deleted':
            self.update_nodes()
            self._knowledge_deleted(data)


        elif name == 'interface added':
            self.update_nodes()
            self._interface_added(data)

        elif name == 'new listener':
            self.update_nodes()
            self._new_listener(data)

        elif name == 'killed listener':
            self.update_nodes()
            self._killed_listener(data)

        elif name == 'exploit started':
            self._module_started({'name'        : data['name'],
                                  'id'          : data['id'],
                                  'target'      : data['target'],
                                  'type'        : data['type'],
                                  'nodes'       : data['fromnodes'],
                                  'arguments'   : data['arguments'],
                                  'session'     : self.session_id})

        elif name == 'exploit returned':
            self._module_returned({'name'    : data['name'],
                                   'id'      : data['id'],
                                   'success' : data['success'],
                                   'session' : self.session_id})

    ######################################################################
    #
    # Main loop
    #
    ######################################################################


    def run(self):
        """
        Main method.
        """

        in_stream = zmqstream.ZMQStream(self.incoming, self.ioloop)
        in_stream.on_recv(self.handle_commander)

        # Exception handlers
        def handle_interrupt(_):
            self.logger.info('Caught CTRL-C')

        def handle_exception(_):
            self.logger.exception('Unhandled exception @ run():')

        self.add_exception_handler(KeyboardInterrupt, handle_interrupt)
        self.add_exception_handler(Exception, handle_exception)


        def is_alive():
            """
            Runs periodically and updates Commander connection state.

            The transitions are: CONNECTED -> DISCONNECTED
            INITIALIZED -> CONNECTED and DISCONNECTED -> CONNECTED take place
            inside the pong handler.
            """
            if self.state in (OperatorLoop.INITIALIZED,
                              OperatorLoop.DISCONNECTED):
                return

            if time.time() - self.commander_last_seen > ALIVE_THRESHOLD:
                self.state = OperatorLoop.DISCONNECTED
                self.logger.info('Can not reach commander @ %s' % self.commander)
                self.incoming.setsockopt(zmq.SUBSCRIBE, "register")


        def process_event():
            """
            Runs periodically and passes queued events to the native ZMQ side.
            Events are processed in bursts, in order to avoid saturating the
            IO loop.
            """
            for _ in range(0, EVENT_BURST_RATE):
                try:
                    args = self.event_queue.get_nowait()
                    self.msg(*args)
                except queue.Empty:
                    return

        ioloop.PeriodicCallback(is_alive,  2000, self.ioloop).start()
        ioloop.PeriodicCallback(process_event, 200, self.ioloop).start()

        # Shutdown handler
        def on_shutdown():
            # Depart all joined groups
            map(self.leave_group, [x for x in self.groups if x != 'global'])

            # Shutdown
            self.msg('quit')
            self.logger.info('Shutting down')
            self.logger.disabled = True
            self.incoming.close()
            in_stream.close()
            self.outgoing.close()
            self.context.term()

        self.add_shutdown_handler(on_shutdown)

        self.logger.info('Connecting to commander (SUB) @ %s'  % self.commander_sub_addr)
        self.logger.info('Connecting to commander (PUSH) @ %s' % self.commander_push_addr)
        self.logger.info('Entered message loop')
        self.start()


