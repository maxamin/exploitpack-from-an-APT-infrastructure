#!/usr/bin/env python

# XML-RPC Proxy to Engine

import sys
import os
import copy
import xmlrpclib
import time
import threading

from SimpleXMLRPCServer import SimpleXMLRPCServer
from threading import Thread, Lock
import thread

import canvasengine
import timeoutsocket

XMLRPCPORT = 65520

# so we can filter output
class StdoutCache:
    def __init__(self):
        self.out    = []
        self.cache  = []
        self.lock   = Lock()
        return

    def reset(self):
        self.lock.acquire()
        self.out = []
        self.lock.release()
        return

    def write(self, line):
        self.lock.acquire()
        #should never throw an exception.
        self.cache.append(line.decode('utf-8',"ignore"))
        self.out.append(line.decode('utf-8',"ignore"))
        self.lock.release()
        return

    # real code calls this
    def flush(self):
        self.lock.acquire()
        out = self.out
        try:
            out = u''.join(out)
        except:
            # make sure we release a lock on operations that may blow up
            # XXX: Is self.out ever not a list?
            import traceback
            traceback.print_exc(file=sys.stderr)
        self.lock.release()
        self.reset()
        return out

    # our code calls this
    def flush_cache(self):
        self.lock.acquire()
        cache = self.cache
        self.cache = []
        self.lock.release()
        return cache

class StdinCache:
    def __init__(self):
        self.inbuf  = []
        self.lock   = Lock()
        return

    def reset(self):
        self.lock.acquire()
        self.inbuf = []
        self.lock.release()
        return

    # just so we win at life (for shellshock/select)
    def fileno(self):
        return 0

    def isactive(self):
        self.lock.acquire()
        if self.inbuf != []:
            self.lock.release()
            return True
        self.lock.release()
        return False

    # XXX
    def read(self, n=0):
        # XXX: threadsafe?
        while not len(self.inbuf):
            time.sleep(0.01)
        self.lock.acquire()
        self.inbuf.reverse()
        out = self.inbuf.pop()
        self.inbuf.reverse()
        self.lock.release()
        return out

    # XXX
    def readline(self):
        while not len(self.inbuf):
            time.sleep(0.01)
        self.lock.acquire()
        self.inbuf.reverse()
        out = self.inbuf.pop()
        self.inbuf.reverse()
        self.lock.release()
        return out

    def flush(self):
        self.lock.acquire()
        try:
            inbuf = ''.join(self.inbuf)
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
        self.lock.release()
        self.reset()
        return inbuf

class SessionInteract(Thread):
    def __init__(self, node):
        Thread.__init__(self)
        self.stdin          = sys.stdin
        self.stdout         = sys.stdout
        self.stdin_cache    = StdinCache()
        self.stdout_cache   = StdoutCache()
        self.node           = node
        sys.stdin           = self.stdin_cache
        sys.stdout          = self.stdout_cache
        return

    def run(self):
        self.node.interact()
        return

    def suicide(self):
        sys.stdin   = self.stdin
        sys.stdout  = self.stdout
        thread.exit()

from canvasengine import DEFAULTCOLOR
from exploitutils import commandline_fromengine

# so we can thread off commandline_fromengine
# and not have XMLRPC timeout
class CommandlineThread(Thread):
    def __init__(self, app, node, args, engine=None):
        Thread.__init__(self)
        self.engine     = engine
        self.app        = app
        # we don't want a rogue commandline thread locking our engine up
        # we only use the engine as a vehicle to register nodes if needed
        # so commandline threads get their own engines, and a register engine
        self.app.engine = None
        self.node       = node
        self.args       = args
        # poll this from CLI end
        self.done       = False
        self.lock       = Lock()
        self.state = False

    def run(self):
        commandline_fromengine(self.app, self.node, self.args, register_engine = self.engine)
        self.lock.acquire()
        self.done = True
        self.lock.release()
    def getstate(self):
        self.lock.acquire()
        state = self.done
        self.lock.release()
        return state

# super class canvas engine functionality
class CanvasEngineXMLRPC(Thread, canvasengine.canvasengine):
    def __init__(self, gui=None, host='localhost', port=XMLRPCPORT):
        # so we can use a singular engine object in the GUI tab
        Thread.__init__(self)
        self.logbuffer              = []
        self.loglock                = Lock()
        self.node_session_threads   = {}
        self.commandline_threads    = []
        self.gui                    = gui
        # we want to cache stdout on commandline and append to log buffer
        canvasengine.canvasengine.__init__(self, gui=gui)
        try:
            self.server = SimpleXMLRPCServer((host, port), logRequests=False)
        except:
            self.log("\n\nCannot bind the CANVAS Engine XMLRPC interface to port %d. It is likely another CANVAS Engine is running at the same time.\n\n"%(XMLRPCPORT))
            self.server = None
            #os._exit(0)
            return

        # register exposed engine functionality here
        self.server.register_function(self.state, 'state')
        self.server.register_function(self.flush_log_xmlrpc, 'flush_log')
        self.server.register_function(self.list_modules_xmlrpc, 'list_modules')
        self.server.register_function(self.load_module_xmlrpc, 'load_module')
        self.server.register_function(self.unload_module_xmlrpc, 'unload_module')
        self.server.register_function(self.run_module_xmlrpc, 'run_module')
        self.server.register_function(self.silica_srv_action, 'silica_srv_action')
        self.server.register_function(self.poll_commandline_thread_xmlrpc, 'poll_commandline_thread')
        self.server.register_function(self.list_listener_types_xmlrpc, 'list_listener_types')
        self.server.register_function(self.list_listeners_xmlrpc, 'list_listeners')
        self.server.register_function(self.list_localnode_interfaces_xmlrpc, 'list_localnode_interfaces')
        self.server.register_function(self.list_remotenode_interfaces_xmlrpc, 'list_remotenode_interfaces')
        self.server.register_function(self.list_listener_nodes_xmlrpc, 'list_listener_nodes')
        self.server.register_function(self.list_all_nodes_xmlrpc, 'list_all_nodes')
        self.server.register_function(self.get_node_count, 'get_node_count')
        self.server.register_function(self.srv_screengrab_passwordhash_status, 'srv_screengrab_passwordhash_status')
        self.server.register_function(self.convert_srv_all_nodes_to_win32, 'convert_srv_all_nodes_to_win32')
        self.server.register_function(self.run_srv_screengrab_passwordhash_all_nodes, 'run_srv_screengrab_passwordhash_all_nodes')
        self.server.register_function(self.start_localnode_listener_xmlrpc, 'start_localnode_listener')
        self.server.register_function(self.check_listener_xmlrpc, 'check_listener')
        self.server.register_function(self.node_close_xmlrpc, 'node_close')
        self.server.register_function(self.node_interact_xmlrpc, 'node_interact')
        self.server.register_function(self.node_interact_suicide_xmlrpc, 'node_interact_suicide')
        self.server.register_function(self.node_interact_getstdout_xmlrpc, 'node_interact_getstdout')
        self.server.register_function(self.node_interact_putstdin_xmlrpc, 'node_interact_putstdin')
        self.server.register_function(self.suicide, 'suicide')
        self.state = True # True when it loads (used for syncing)


    def state(self):
        """
        Returns the state (running/stopped) for thread sync
        """
        return self.state

    # hijack self.log from engine
    def log(self, line, color=DEFAULTCOLOR, enter="\n",maxlength=130,startlength=80):
        # buffer log lines from the engine so we can dump them over rpc
        self.loglock.acquire()
        self.logbuffer.append(line)
        self.loglock.release()
        canvasengine.canvasengine.log(self, line,\
                                      color=color,\
                                      enter=enter,\
                                      maxlength=maxlength,\
                                      startlength=startlength)
        # dump to stdout so we don't have to flushlog in gui mode
        # due to unicode being a mess in windows we need to do:
        # first try to print as unicode, if exception is raised
        # terminal is not unicode-aware (default cmd.exe in windows, even win7)
        # so we encode to ascii

        # Deprecated
        # if self.gui:
        #     try:
        #         print line
        #     except:
        #         print line.encode('ascii', 'replace')

    # XXX: run a module on localnode
    def run_module_xmlrpc(self, module, args):
        app = self.getModuleExploit(module)
        if not app:
            return -1
        t = CommandlineThread(app, None, args, engine=self)
        self.commandline_threads.append(t)
        t.start()
        return self.commandline_threads.index(t)


    def silica_srv_action(self, args):
        print "xmlrpc server args: ", args
        return self.run_module_xmlrpc(args['module_name'], args['module_args'])


    def poll_commandline_thread_xmlrpc(self, i):
        try:
            t = self.commandline_threads[i]
        except IndexError:
            print "XXX: Thread Indexing Error!!!"
            return True
        # join thread when it is done
        thread_state = t.getstate()
        if thread_state == True:
            self.commandline_threads.remove(t)
            t.join()
        return thread_state

    # when using all nodes approach to interact ...
    def node_interact_xmlrpc(self, nodeid):
        i = 0
        for node in self.nodeList:
            # XXX
            if i == nodeid:
                sessionid = '%s:%s' % (node.nodetype, node.getname())
                if sessionid not in self.node_session_threads:
                    self.node_session_threads[sessionid] = SessionInteract(node)
                    self.node_session_threads[sessionid].start()
                return [node.nodetype, node.getname()]
            i += 1
        return []

    def node_close_xmlrpc(self, nodeid):
        i = 0
        for node in self.nodeList:
            if i == nodeid:
                try:
                    # rm from meatmarket/gaphas
                    if hasattr(self.gui, 'meatmarket'):
                        self.gui.meatmarket.remove_canvas_node(node)

                    # rm node from engine
                    node.close_node_clean_gui()

                    return True
                except:
                    return False
        return False

    # XXX: ugly hack for cleaner detach
    def node_interact_suicide_xmlrpc(self, sessionid):
        if sessionid not in self.node_session_threads:
            return False
        try:
            self.node_session_threads[sessionid].suicide()
        except SystemExit:
            pass
        del(self.node_session_threads[sessionid])
        return True

    def node_interact_getstdout_xmlrpc(self, sessionid):
        return self.node_session_threads[sessionid].stdout_cache.flush_cache()

    def node_interact_putstdin_xmlrpc(self, sessionid, line):
        self.node_session_threads[sessionid].stdin_cache.lock.acquire()
        self.node_session_threads[sessionid].stdin_cache.inbuf += [line]
        self.node_session_threads[sessionid].stdin_cache.lock.release()
        return True

    # we only wanna use this for MOSDEFSock listeners that != localNode
    def check_listener_xmlrpc(self, ip, port):
        # gives a list of nodes for a listener
        for listener in self.allListeners:
            if ip == listener.ip and port == listener.port:
                ret = listener.check()
                if ret:
                    # we got a new node
                    return True
        return False

    def list_listener_nodes_xmlrpc(self, ip, port):
        nodes = []
        for listener in self.allListeners:
            if ip == listener.ip and port == listener.port:
                for node in listener.totalnodes:
                    nodes += [[node.nodetype, node.getname()]]
        return nodes

    def list_all_nodes_xmlrpc(self):
        nodes = []
        for node in self.nodeList:
            nodes += [[node.nodetype, node.getname()]]
        return nodes

    def get_node_count(self):
        return len(self.nodeList)


    def convert_srv_all_nodes_to_win32(self):
        converted_nodes = 0
        original_nodes  = len(self.nodeList)

        for node in self.nodeList:
            if node.nodetype != 'win32Node':
                # this needs to run threaded as some nodes do not support spawn and the node gets stuck
                thread.start_new_thread(self.runmod_exp, ("converttomosdef", node))
                converted_nodes += 1

        return [converted_nodes, original_nodes]


    def run_srv_screengrab_passwordhash_all_nodes(self):
        """
        Note all actions must be threaded as blocking the main xmlrpc thread that does the processing
        may cause timeout's for other active actions. i.e. if it's processing an active module like
        massattack or vulnassess, clientd etc.
        """

        thread.start_new_thread(self.run_srv_screengrab_passwordhash_all_nodes_real, ("x",))


    def run_srv_screengrab_passwordhash_all_nodes_real(self,x):
        self.screengrab_active = True
        for node in self.nodeList:
            if node.nodetype == 'win32Node':
                # We run those serially as it blows up on some windows xp hosts if they're executed in parallel
                self.runmod_exp("getpasswordhashes", node)
                self.runmod_exp("screengrab", node)

        self.log("Finished getting screenshots and password hashes")
        self.screengrab_active = False
        return True

    def srv_screengrab_passwordhash_status(self):
        """
        We introduce this for thread sync and to avoid blocking on the client until the action is done
        """
        return self.screengrab_active


    def runmod_exp(self, ename, node):
        mod=self.MygetModuleExploit(ename, node)
        if mod:
            try:
                mod.run()
                return mod
            except:
                self.log("Module: %s died during a run, or remote end has terminated"%ename)

        return False

    def MygetModuleExploit(self,modulename, node):
        newexploit=canvasengine.getModuleExploit(modulename)
        newexploit.engine=self
        newexploit.argsDict["passednodes"] = [node]
        newexploit.passedNodes=[node]

        try:
            target_node_ip = node.interfaces.all_ips()[0]
        except:
            return False
        newexploit.engine.set_target_host(target_node_ip)
        newexploit.target = self.target_hosts[0]
        return newexploit

    def list_listeners_xmlrpc(self):
        listeners = []
        for listener in self.allListeners:
            listeners += [[listener.ip, listener.port, listener.type]]
        return listeners

    def list_localnode_interfaces_xmlrpc(self):
        interfaces  = []
        ret         = self.localnode.interfaces.all_interface_objects()
        for interface_line in ret:
            iface   = interface_line.interface
            ip      = interface_line.ip
            if type(interface_line.netmask) == type(''):
                netmask = interface_line.netmask
            else:
                netmask = '%X' % interface_line.netmask
            interfaces += [[iface, ip, netmask]]
        return interfaces

    def list_remotenode_interfaces_xmlrpc(self, nodeid):
        i           = 0
        interfaces  = []
        for node in self.nodeList:
            # XXX
            if i == nodeid:
                ret = node.interfaces.all_interface_objects()
                for interface_line in ret:
                    iface   = interface_line.interface
                    ip      = interface_line.ip
                    if type(interface_line.netmask) == type(''):
                        netmask = interface_line.netmask
                    else:
                        netmask = '%X' % interface_line.netmask
                    interfaces += [[iface, ip, netmask]]
            i += 1
        return interfaces

    def start_localnode_listener_xmlrpc(self, listener_type, interface, port, fromcreatethread):

        engine_interface = self.localnode.interfaces.get_interface(interface)
        ret = self.start_listener(engine_interface,\
                                  listener_type,\
                                  port,\
                                  fromcreatethread=fromcreatethread)
        if not ret:
            return False
        return True

    def list_listener_types_xmlrpc(self):
        return canvasengine.getAllListenerOptions()

    def load_module_xmlrpc(self, module):
        module = canvasengine.registerModule(module)
        if module:
            return True
        else:
            return False

    def unload_module_xmlrpc(self, module):
        canvasengine.unregisterModule(module)
        return True

    def list_modules_xmlrpc(self):
        modules = canvasengine.registeredModuleList()
        return modules

    def flush_log_xmlrpc(self):
        self.loglock.acquire()
        out             = self.logbuffer
        self.logbuffer  = []
        self.loglock.release()
        return out

    def run(self):
        # timeoutsocket will raise timeouts
        while 1:
            #XXX: This loop will cause some exploits to hang when
            #they are run from the commandline!
            try:
                self.server.serve_forever()
            except timeoutsocket.Timeout:
                # just in case
                time.sleep(0.01)

    def suicide(self):
        self.state = False
        os._exit(0)

# so we can thread off an XMPLRPC Server
class StartServerThread:
    def __init__(self, gui=None, port=XMLRPCPORT):
        self.server_thread = CanvasEngineXMLRPC(gui=gui, port=XMLRPCPORT)
        if self.server_thread.server is not None:
            self.server_thread.start()
        return

    def server_shutdown(self):
        self.server_thread.shutdown()
        self.server_thread.suicide()
        return

# so we can talk to the engine over XML-RPC
class XMLRPCRequest:
    def __init__(self, host='localhost', port=XMLRPCPORT):
        self.proxy = xmlrpclib.ServerProxy('http://%s:%d/' % (host, port))
        return

