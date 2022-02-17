#!/usr/bin/env python

import sys
if '.' not in sys.path: sys.path.append('.')

import os
import zmq
import time
import logging
import Queue as queue

import json
import zmq.eventloop.ioloop as ioloop
import zmq.eventloop.zmqstream as zmqstream

from canvasengine import canvas_root_directory as CANVAS_ROOT
from engine.config import CanvasConfig

from control.event_loop import EventLoop
from control.state import Operator
from control.event import EventWriter, EventReader
from control.exceptions import ZMQConnectionError

ALIVE_THRESHOLD  = 10 # 10 seconds

def valid_operator(node_updated=False):
    """
    This decorator will make sure that the operator who sent us a message is valid.
    If node_updated is set, it will also make sure that we cleanly abort early when the remote
    node_tree is in sync with our local copy.
    """
    def _valid_operator(f):
        def decorated(self, oper_id, *args):

            if oper_id not in self.operators:
                self.commander_logger.debug('Operator %s not in our connected list. (%s)' % (oper_id, repr(args)))
                return

            if node_updated:
                node_tree = args[0]
                if self.operators[oper_id].node_tree == node_tree:
                    return
            return f(self, oper_id, *args)
        return decorated
    return _valid_operator

class CommanderLoop(EventLoop):
    COMMANDER_ALIAS    = 'commander'
    COMMANDER_LOG_NAME = 'COMMANDER'
    OPERATOR_LOG_NAME  = 'OPERATOR'

    def __init__(self, do_capture=True):
        try:
            EventLoop.__init__(self)
            self.do_capture = do_capture

            # Contains Operator instances, keyed by Operator.uuid
            self.operators = {}
            self.commander_logger    = None
            self.operator_logger     = None

            self.bind_ip   = CanvasConfig['commander_bind_ip']
            self.pub_addr  = 'tcp://%s:%s' % (self.bind_ip, CanvasConfig['commander_pub_port'])
            self.pull_addr = 'tcp://%s:%s' % (self.bind_ip, CanvasConfig['commander_pull_port'])

            self.setup_logging()

            # Chat
            self.chat_queue = queue.Queue()

            # Pickling
            if self.do_capture:
                session_path = os.path.join(CANVAS_ROOT, 'control', 'sessions')
                if not os.path.exists(session_path): os.mkdir(session_path)
                self.event_writer = EventWriter(os.path.join(session_path, '%s.pkl' % time.strftime('%y-%m-%d-%H_%M_%S')))

            # The following are initialized in setup_zmq()
            self.context  = None
            self.outgoing = None
            self.incoming = None

            self.setup_zmq()

        except Exception:
            self.commander_logger.disabled = True
            self.operator_logger.disabled = True
            raise

    def setup_zmq(self):
        # Sockets
        self.context   = zmq.Context()

        self.outgoing  = self.context.socket(zmq.PUB)
        self.incoming  = self.context.socket(zmq.PULL)

        self.outgoing.setsockopt(zmq.LINGER, 500) # 500ms default linger

        try:
            self.outgoing.bind(self.pub_addr)
        except Exception:
            raise ZMQConnectionError('Error when binding to %s' % self.pub_addr)

        try:
            self.incoming.bind(self.pull_addr)
        except Exception:
            raise ZMQConnectionError('Error when binding to %s' % self.pull_addr)

    def setup_logger(self, logger):
        """
        This method will setup the given logger using CANVAS_ROOT/control/log
        as the log directory. All log entries will be split into different files
        according to three log levels (debug, info, error).
        """
        if not logger.disabled:
            # Do initial setup here
            log_path = os.path.join(CANVAS_ROOT, 'control', 'log')
            if not os.path.exists(log_path): os.mkdir(log_path)

            formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s %(message)s')
            # handler_stderr = logging.StreamHandler(sys.stderr)
            # handler_stderr.setLevel(logging.DEBUG)
            # handler_stderr.setFormatter(formatter)
            # logger.addHandler(handler_stderr)

            handler_debug = logging.FileHandler(os.path.join(log_path, '%s_debug.log' % logger.name.lower()), 'ab', delay=True)
            handler_debug.setLevel(logging.DEBUG)
            handler_debug.setFormatter(formatter)
            logger.addHandler(handler_debug)

            handler_info = logging.FileHandler(os.path.join(log_path, '%s_info.log' % logger.name.lower()), 'ab', delay=True)
            handler_info.setLevel(logging.INFO)
            handler_info.setFormatter(formatter)
            logger.addHandler(handler_info)

            handler_error = logging.FileHandler(os.path.join(log_path, '%s_error.log' % logger.name.lower()), 'ab', delay=True)
            handler_error.setLevel(logging.ERROR)
            handler_error.setFormatter(formatter)
            logger.addHandler(handler_error)
        else:
            logger.disabled = False

    def setup_logging(self):
        """
        Setup the logging scheme we are going to use. This method can be
        overridden in subclasses. The default scheme is based on using two
        different loggers, one for the commander (`COMMANDER' prefix) and
        one for all the operators (`OPERATOR' prefix).
        """

        # Logging
        logging.addLevelName(Operator.LOG_EXECUTE, 'EXECUTE')
        logging.addLevelName(Operator.LOG_SUCCESS, 'SUCCESS')
        logging.addLevelName(Operator.LOG_FAILURE, 'FAILURE')

        # Commander logger
        self.commander_logger = logging.getLogger(self.COMMANDER_LOG_NAME)
        self.commander_logger.setLevel(logging.DEBUG)
        self.setup_logger(self.commander_logger)

        # Operator logger
        self.operator_logger = logging.getLogger(self.OPERATOR_LOG_NAME)
        self.operator_logger.setLevel(logging.DEBUG)
        self.setup_logger(self.operator_logger)


    @valid_operator()
    def forget(self, oper_id):
        """
        Assuming operator with oper_id is in DISCONNECTED state, remove him
        from the system.
        """
        oper = self.operators[oper_id]

        if oper.state != Operator.DISCONNECTED: return

        oper.logger.warn('Removed from system.')
        del self.operators[oper_id]

    def _is_unique_alias(self, alias):
        if alias == self.COMMANDER_ALIAS:
            return False
        if alias and alias in [x.alias for x in self.operators.values()]:
            return False

        return True

    def _find_node(self, node_tree, node_name):
        """
        Return a node (dictionary) given node_name, by recursively searching node_tree.
        Return None if not found.
        """
        if node_tree['name'] == node_name: return node_tree
        ret = filter(None, map(lambda x: self._find_node(x, node_name), node_tree['children']))

        return ret[0] if ret else None

    ######################################################################
    #
    # Operator messsage handlers
    #
    ######################################################################

    def _pong(self, oper_id, count, time_ref):
        if oper_id not in self.operators:
            # Send operator-specific message to receive remote state
            self.broadcast(oper_id, 'state')
        else:
            # Update last_seen
            oper = self.operators[oper_id]
            oper.last_seen = time.time()
            oper.pong_acknowledged = True

            if oper.state == Operator.DISCONNECTED:
                oper.logger.warn('Operator %s is alive, updating state.' % oper.name)
                oper.state = Operator.ACTIVE

                # Get new state
                self.broadcast(oper_id, 'state')

    def _state(self, oper_id, config, node_tree, groups):
        """
        This message is sent when a remote CANVAS operator first connects or
        connects after a disconnection. It is used to synchronize local and remote
        knowledge.
        """
        new_operator = False

        if oper_id not in self.operators:
            # New Operator
            oper = Operator(oper_id, self.OPERATOR_LOG_NAME)
            self.operators[oper_id] = oper
            new_operator = True

        else:
            oper = self.operators[oper_id]

        new_alias = config['operator_alias']


        if new_alias != oper.alias:
            if not self._is_unique_alias(new_alias):
                self.tell('Alias "%s" already exists, you should choose a new one.' % new_alias, oper_id)

            oper.alias = new_alias

        if oper.node_tree != node_tree:
            oper.node_tree = node_tree

        oper.groups = set(groups)

        if new_operator:
            oper.logger.info('New operator connected: %s', oper.alias or 'no alias')

        oper.logger.info('(alias): %s (groups): %s (callback): %s:%s/%s (target): %s' %
                         (oper.alias or 'None',
                          list(oper.groups) or 'None',
                          oper.callback['node'],
                          oper.callback['ip'],
                          oper.callback['interface'],
                          repr(['%s:%s' % (x['node'], x['host']) for x in oper.targets])))

    def _tell(self, oper_id, dest, message, meta):
        """
        This is a communication message.
        """

        if oper_id not in self.operators and oper_id != self.COMMANDER_ALIAS:
            return

        self.chat_queue.put((oper_id, dest, message, meta))
        if oper_id == self.COMMANDER_ALIAS: return

        oper = self.operators[oper_id]

        if dest != 'commander':
            self.forward(message, oper_id, dest, meta)

            if 'event' in meta:
                event = meta['event']

                if event == 'join' and dest not in oper.groups:
                    oper.logger.info('Operator %s has joined group %s.' % (oper.name, dest))
                    oper.groups.add(dest)
                elif event == 'depart' and dest in oper.groups:
                    oper.logger.info('Operator %s has left group %s.' % (oper.name, dest))
                    oper.groups.remove(dest)
        else:
            # return the message to the source
            self.forward(message, 'commander', oper_id, meta)

    @valid_operator()
    def _new_alias(self, oper_id, alias):
        oper = self.operators[oper_id]
        old_name = oper.name

        if alias == oper.alias: return

        if not self._is_unique_alias(alias):
            self.tell('Alias %s already exists, you should choose a new one.' % alias, oper_id)

        oper.alias = alias
        oper.logger.info('Operator %s is now known as %s.' % (old_name, oper.name))

    @valid_operator(node_updated=True)
    def _updated_targets(self, oper_id, node_tree):
        oper = self.operators[oper_id]

        oper.node_tree = node_tree
        oper.logger.info('Updated targets: %s' % repr(['%s:%s' % (x['node'], x['host']) for x in oper.targets]))

    @valid_operator(node_updated=True)
    def _new_node(self, oper_id, node_tree, node_name):
        oper = self.operators[oper_id]

        oper.node_tree = node_tree
        node = self._find_node(node_tree, node_name)
        oper.logger.info('New node: %s (%s)' % (node_name, node['type']))


    @valid_operator(node_updated=True)
    def _node_deleted(self, oper_id, node_tree, node_name):
        oper =self.operators[oper_id]

        oper.node_tree = node_tree
        oper.logger.info('Node deleted: %s' % node_name)

    @valid_operator(node_updated=True)
    def _callback_changed(self, oper_id, node_tree):
        oper = self.operators[oper_id]

        oper.node_tree = node_tree
        oper.logger.info('Callback updated: %s:%s (%s)' % (oper.callback['node'],
                                                           oper.callback['ip'],
                                                           oper.callback['interface']))

    @valid_operator(node_updated=True)
    def _knowledge_updated(self, oper_id, node_tree, knowledge):
        """
        knowledge should be a dictionary with following keys:
        node, host, tag, knowledge, percentage
        """
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('Knowledge updated for %s:%s [%s] %s (%s%%)' %
                         (knowledge['node'],
                          knowledge['host'],
                          knowledge['tag'],
                          knowledge['knowledge'],
                          knowledge['percentage']))

    @valid_operator(node_updated=True)
    def _knowledge_deleted(self, oper_id, node_tree, knowledge):
        """
        knowledge should be a dictionary with following keys:
        node, host, tag
        """
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('Knowledge deleted for: %s:%s [%s]' %
                         (knowledge['node'],
                          knowledge['host'],
                          knowledge['tag']))

    @valid_operator(node_updated=True)
    def _new_host(self, oper_id, node_tree, node, ip):
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('New host: %s:%s' % (node, ip))

    @valid_operator(node_updated=True)
    def _host_deleted(self, oper_id, node_tree, node, ip):
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('Host deleted: %s:%s' % (node, ip))

    @valid_operator(node_updated=True)
    def _interface_added(self, oper_id, node_tree, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, netmask, NAT
        """
        oper = self.operators[oper_id]
        oper.node_tree = node_tree

        oper.logger.info('New interface: %s:%s (%s) NAT: %s' % (data['node'],
                                                                data['ip'],
                                                                data['interface'],
                                                                data['NAT']))

    @valid_operator(node_updated=True)
    def _new_listener(self, oper_id, node_tree, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, type, port, fromcreatethread
        """
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('New listener: %s:%s (%s) %s at %s (fromcreatethread: %s)' %
                         (data['node'],
                          data['ip'],
                          data['interface'],
                          data['type'],
                          data['port'],
                          data['fromcreatethread']))

    @valid_operator(node_updated=True)
    def _killed_listener(self, oper_id, node_tree, data):
        """
        data should be a dictionary with the following keys:
        node, interface, ip, type, port, fromcreatethread
        """
        oper = self.operators[oper_id]
        oper.node_tree = node_tree
        oper.logger.info('Killed listener: %s:%s (%s) %s at %s (fromcreatethread: %s)' %
                         (data['node'],
                          data['ip'],
                          data['interface'],
                          data['type'],
                          data['port'],
                          data['fromcreatethread']))


    @valid_operator()
    def _module_started(self, oper_id, data):
        """
        data should be a dictionary with the following keys:
        name, id, target, nodes, session, type, arguments
        """
        oper = self.operators[oper_id]

        module_name    = data['name']
        module_id      = data['id']
        module_target  = data['target']
        module_session = data['session']
        module_type    = data['type']

        key = (module_name, module_id, module_session)

        if key in oper.modules:
            oper.logger.error('Module entry %s already exists.' % repr(key))
            return

        oper.modules[key]           = data
        oper.modules[key]['status'] = 'RUNNING'

        if module_type == 'local':
            oper.logger.execute('Module started: %s/%s on nodes %s' %
                                (module_name,
                                 module_id,
                                 repr([x['name'] for x in data['nodes']])))
        elif module_type == 'remote':
            oper.logger.execute('Module started: %s/%s (from: %s) against %s' %
                                (module_name,
                                 module_id,
                                 data['nodes'][0]['name'],
                                 module_target))
        elif module_type == 'utility':
            oper.logger.execute('Module started (utility): %s/%s' % (module_name, module_id))

    @valid_operator()
    def _module_returned(self, oper_id, data):
        """
        data should be a dictionary with the following keys:
        name, id, success, session
        """
        oper = self.operators[oper_id]

        module_name    = data['name']
        module_id      = data['id']
        module_session = data['session']
        module_status  = 'SUCCESS' if data['success'] else 'FAILURE'

        key = (module_name, module_id, module_session)

        if key not in oper.modules:
            oper.logger.error('Module entry %s not found.' % repr(key))
            return

        oper.modules[key]['status'] = module_status

        if module_status == 'SUCCESS':
            oper.logger.success('Module success: %s/%s' %
                                (module_name,
                                 module_id))
        else:
            oper.logger.failure('Module failure: %s/%s' %
                                (module_name,
                                 module_id))

    @valid_operator()
    def _quit(self, oper_id):
        """
        This message is sent when an operator quits.
        """
        oper = self.operators[oper_id]
        oper.logger.warn('Operator %s shutting down.' % self.operators[oper_id].name)
        del self.operators[oper_id]

    def dispatch(self, oper_id, msg):
        """
        Dispatch on `msg' (sequence). msg[0] is the keyword to dispatch on
        according to the handlers dictionary.

        msg[1:] must contain arguments that are going to be passed verbatim
        to the handler function.
        """

        handlers = {
            'pong'              : self._pong,
            'state'             : self._state,
            'tell'              : self._tell,
            'quit'              : self._quit,
            'new_alias'         : self._new_alias,
            'updated_targets'   : self._updated_targets,
            'callback_changed'  : self._callback_changed,
            'knowledge_updated' : self._knowledge_updated,
            'knowledge_deleted' : self._knowledge_deleted,
            'new_node'          : self._new_node,
            'node_deleted'      : self._node_deleted,
            'new_host'          : self._new_host,
            'host_deleted'      : self._host_deleted,
            'interface_added'   : self._interface_added,
            'new_listener'      : self._new_listener,
            'killed_listener'   : self._killed_listener,
            'module_started'    : self._module_started,
            'module_returned'   : self._module_returned,
        }

        try:
            # Save event
            if self.do_capture: self.event_writer.dump(oper_id, msg[0], msg[1:])
            handlers[msg[0]](oper_id, *msg[1:])
        except Exception:
            self.commander_logger.exception('Dispatch exception:')

    def handle_operator(self, msg):
        """
        Callback function for messages sent by operators.
        """
        oper_id, msg = msg[0], msg[1]

        try:
            msg = tuple(json.loads(msg))
        except Exception:
            self.commander_logger.exception('(%s) handle_operator:' % oper_id)
            return

        self.dispatch(oper_id, msg)


    ######################################################################
    #
    # Messaging to operators
    #
    ######################################################################

    def broadcast(self, topic, *msg):
        """
        Broadcast a message to clients that subscribe to topic.

        A multipart message will be sent with topic sent as is,
        subsequent arguments pickled in a list.
        """

        if isinstance(topic, unicode): topic = topic.encode('UTF-8')
        self.outgoing.send_multipart((topic, json.dumps(msg, ensure_ascii=True)))


    def tell(self, msg, dest, event=None):
        """
        Send a communication message to dest which can be a group or operator id.
        """

        meta = {'alias' : self.COMMANDER_ALIAS}
        if event: meta['event'] = event

        if self.do_capture: self.event_writer.dump(self.COMMANDER_ALIAS, 'tell',
                                                   (dest, msg, meta))

        self.broadcast(dest, 'tell', self.COMMANDER_ALIAS, dest, msg, meta)

    def forward(self, msg, source, dest, meta):
        """
        Forward a message to dest.
        """
        self.broadcast(dest, 'tell', source, dest, msg, meta)

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
        in_stream.on_recv(self.handle_operator)

        # Periodic tasks
        # Heartbeating
        counter = [0] # read/write closure workaround

        def register():
            """
            Runs periodically and broadcasts a ping message in order to
            discover subscribers.
            """

            self.broadcast('register', 'ping', counter[0], int(time.time()*1000.0))
            counter[0] += 1

        def heartbeat():
            """
            Runs periodically and pings operators to determine liveness.
            """
            for (oper_id, operator) in self.operators.items():
                if operator.pong_acknowledged:
                    operator.pong_acknowledged = False
                    self.broadcast(oper_id, 'ping', counter[0], int(time.time()*1000.0))
                    counter[0] += 1

        # Handle network issues with operators
        def is_alive():
            """
            Runs periodically and updates Operator state given last_seen values.

            Currently, the transition is: ACTIVE -> DISCONNECTED
            We do DISCONNECTED -> ACTIVE inside the pong handler
            since we want no delay on this.
            """
            for operator in self.operators.values():
                if time.time() - operator.last_seen > ALIVE_THRESHOLD:
                    if operator.state == Operator.ACTIVE:
                        operator.state = Operator.DISCONNECTED
                        operator.logger.warn('Operator %s not responding, updating state.' % operator.name)

        ioloop.PeriodicCallback(register,  1000, self.ioloop).start()
        ioloop.PeriodicCallback(heartbeat, 3000, self.ioloop).start()
        ioloop.PeriodicCallback(is_alive,  5000, self.ioloop).start()

        # Exception handlers
        def handle_interrupt(_):
            self.commander_logger.info('Caught CTRL-C')

        def handle_exception(_):
            self.commander_logger.exception('Unhandled exception @ run():')

        self.add_exception_handler(KeyboardInterrupt, handle_interrupt)
        self.add_exception_handler(Exception, handle_exception)

        # Shutdown handler
        def on_shutdown():
            # Shutdown
            self.commander_logger.info('Shutting down')
            self.commander_logger.disabled = True
            self.operator_logger.disabled = True
            self.incoming.close()
            in_stream.close()
            self.outgoing.close()
            self.context.term()
            self.event_writer.close()

        self.add_shutdown_handler(on_shutdown)
        self.commander_logger.info('Entered message loop')
        self.commander_logger.info('Binding to %s' % self.pub_addr)
        self.commander_logger.info('Binding to %s' % self.pull_addr)
        self.start()


######################################################################
#
# ReplayLoop
#
######################################################################


class ReplayLoop(CommanderLoop):
    """
    This is basically a CommanderLoop without networking/sockets.
    We still run on top of a ZMQ IOLoop that we use for event scheduling,
    but we create no ZMQ context (and therefore no sockets).

    Used for our session replay functionality.
    """

    # Replay states
    PAUSED   = 'PAUSED'
    PAUSING  = 'PAUSING'
    RUNNING  = 'RUNNING'

    COMMANDER_LOG_NAME = 'REPLAY'
    OPERATOR_LOG_NAME  = 'OPERATOR (REPLAY)'

    def __init__(self, playback_session=None):
        try:
            CommanderLoop.__init__(self, do_capture=False)
            self.playback_session  = playback_session
            self.event_reader      = EventReader(playback_session)

            # See replay functions for details
            self.event_stream      = None

            # Time of last event processed
            self.event_time_ref    = None
            self.event_state       = ReplayLoop.PAUSED

            # Linear time (with reference to 0) of the current event
            self.event_delta       = 0

            # Current event index (min=0, max=self.event_reader.event_count)
            self.current_event_idx = 0

            self.replay_speed      = 1.0
        except Exception:
            self.commander_logger.disabled = True
            self.operator_logger.disabled  = True
            raise

    # Override parent methods for zmq/socket stuff
    def broadcast(self, topic, *msg):
        return

    def setup_zmq(self):
        return

    def setup_logging(self):
        """
        Setup the logging scheme we are going to use. This method can be
        overridden in subclasses. The default scheme is based on using two
        different loggers, one for the commander-replayer (`REPLAY' prefix)
        and one for all the operators (`OPERATOR' prefix).

        The operator logger will not log to the filesystem.
        """

        # Logging
        logging.addLevelName(Operator.LOG_EXECUTE, 'EXECUTE')
        logging.addLevelName(Operator.LOG_SUCCESS, 'SUCCESS')
        logging.addLevelName(Operator.LOG_FAILURE, 'FAILURE')

        # Commander logger
        self.commander_logger = logging.getLogger(self.COMMANDER_LOG_NAME)
        self.commander_logger.setLevel(logging.DEBUG)
        self.setup_logger(self.commander_logger)

        # Operator logger
        self.operator_logger = logging.getLogger(self.OPERATOR_LOG_NAME)
        self.operator_logger.setLevel(logging.DEBUG)

        if not self.operator_logger.disabled:
            formatter = logging.Formatter('[%(levelname)s:%(name)s] %(asctime)s %(message)s')
            handler_stderr = logging.StreamHandler(sys.stderr)
            handler_stderr.setLevel(logging.DEBUG)
            handler_stderr.setFormatter(formatter)
            self.operator_logger.addHandler(handler_stderr)
        else:
            self.operator_logger.disabled = False



    ######################################################################
    #
    # Replay controls
    #
    ######################################################################

    def replay(self):
        """
        This method will replay events from the beginning of a session file.
        Can also be used to rewind the event stream.
        """
        if self.event_state != ReplayLoop.PAUSED: return

        # Reset our state
        self.operators         = {}

        # Get a fresh iterator
        self.event_stream      = self.event_reader.events()
        self.current_event_idx = 0
        self.event_delta       = 0
        self.event_time_ref    = None

        self.commander_logger.info('%s: replaying (%s events total)' % (
            self.playback_session, self.event_reader.event_count))

    def step(self, jump_to=None):
        """
        This method will replay the next event only.
        """
        if self.event_state != ReplayLoop.PAUSED: return

        if jump_to:
            if jump_to < 0:
                self.commander_logger.error('step(%s): event index can not be negative' % jump_to)
                return

            if jump_to >= self.event_reader.event_count:
                self.commander_logger.error('step(%s): event index > event count' % jump_to)
                return

            if jump_to == self.current_event_idx:
                return

            if jump_to < self.current_event_idx:
                self.commander_logger.error('step(%s): can not go back in time' % jump_to)
                return

        while True:
            # Read the first event
            try:
                event = self.event_stream.next()
            except StopIteration:
                self.event_time_ref = None
                self.commander_logger.info('%s: no more events in session file.' % self.playback_session)
                return

            if not self.event_time_ref:
                self.event_time_ref = event.time
            else:
                self.event_delta += event.time - self.event_time_ref
                self.event_time_ref = event.time

            self.dispatch(event.source, (event.name,) + event.data)
            self.current_event_idx += 1

            if jump_to and jump_to == self.current_event_idx:
                break

            if event.name != 'pong' and not jump_to: break

    def pause(self):
        if self.event_state != ReplayLoop.RUNNING: return
        self.event_state = ReplayLoop.PAUSING
        self.commander_logger.info('%s: pausing..' % self.playback_session)

    def resume(self):
        if self.event_state != ReplayLoop.PAUSED: return

        self.event_state = ReplayLoop.RUNNING
        self.commander_logger.info('%s: playback resumed' % self.playback_session)

        # Read the first event
        try:
            event = self.event_stream.next()
        except StopIteration:
            self.event_time_ref = None
            self.commander_logger.info('%s: no more events in session file.' % self.playback_session)
            self.event_state = ReplayLoop.PAUSED
            return

        # Set up reference time
        self.event_time_ref = event.time

        def replay_event(event):
            # Dispatch on event
            self.dispatch(event.source, (event.name,) + event.data)
            self.current_event_idx += 1

            if self.event_state == ReplayLoop.PAUSING:
                self.event_state = ReplayLoop.PAUSED
                self.commander_logger.info('%s: paused.' % self.playback_session)
                return

            # Read an event
            try:
                event = self.event_stream.next()
            except StopIteration:
                self.event_time_ref = None
                self.commander_logger.info('%s: no more events in session file.' % self.playback_session)
                self.event_state = ReplayLoop.PAUSED
                return

            delay = event.time - self.event_time_ref
            self.event_delta += delay
            self.event_time_ref = event.time

            deadline = time.time() + (delay if self.replay_speed == 1.0 else (1.0/self.replay_speed)*delay)
            self.ioloop.add_timeout(deadline, lambda:replay_event(event))

        # Start the first event
        self.add_callback(lambda:replay_event(event))

    def run(self):
        """
        Main method.
        """

        self.replay()

        # Exception handlers
        def handle_interrupt(_):
            self.commander_logger.info('Caught CTRL-C')

        def handle_exception(_):
            self.commander_logger.exception('Unhandled exception @ run():')

        self.add_exception_handler(KeyboardInterrupt, handle_interrupt)
        self.add_exception_handler(Exception, handle_exception)

        # Shutdown handler
        def on_shutdown():
            # Shutdown
            self.commander_logger.info('Shutting down')
            self.commander_logger.disabled = True
            self.operator_logger.disabled = True
            self.event_reader.close()

        self.add_shutdown_handler(on_shutdown)
        self.commander_logger.info('Entered message loop')
        self.start()


