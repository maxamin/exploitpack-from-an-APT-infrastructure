
#!/usr/bin/env python

# CANVAS: Command Line Interface
# Bas Alberts, v0.1

import sys
import select
import time
import code
import ConfigParser

import canvascode
import xmlrpc
import xmlrpclib
import socket

from threading import Lock
from internal import devlog

try:
    import readline
except ImportError:
    print 'Module readline not available'
    
import rlcompleter    

class CANVASCompleter(rlcompleter.Completer):
    def __init__(self):
        rlcompleter.Completer.__init__(self)
        return
    
    def complete(self, text, state):
        return rlcompleter.Completer.complete(self, text, state)

# so we can filter output ... has to be thread safe for auto engine   
class StdoutCache:
    def __init__(self):
        self.out    = []
        self.lock   = Lock()
        return
    
    def reset(self):
        self.lock.acquire()
        self.out = []
        self.lock.release()
        return
    
    def write(self, line):
        self.lock.acquire()
        self.out.append(line.encode("utf-8"))
        self.lock.release()
        return
    
    def flush(self):
        self.lock.acquire()
        out = u''.join(self.out)
        self.lock.release()
        self.reset()
        return out
            
def select_stdin_for_reading(timeout = 0.2, stdin=sys.stdin):
    try:
        rd = []
        wr = []
        ex = []
        if hasattr(stdin, 'isactive'):
            if stdin.isactive() == True:
                rd += [stdin.fileno()]
        else:
            rd, wr, ex = select.select([stdin.fileno()], [], [], timeout)
    except TypeError:
        raise
    except select.error, (errcode, errmsg):
        if errcode == 10038: # win32 ENOTSOCK
            import os
            if os.name != 'nt':
                raise
            import msvcrt
            while True:
                rd = []
                wr = []
                ex = []
                if msvcrt.kbhit():
                    rd += [stdin.fileno()]
                if rd != []:
                    return (rd, [], [])
            raise select.error
    return (rd, [], [])
    
class CommandLineInterface(code.InteractiveConsole,\
                           canvascode.CanvasInteractiveInterpreter):
    def __init__(self, host='localhost'):
        # stdout caching ...
        self.stdout = sys.stdout
        self.cache  = StdoutCache()
        self.rpc    = xmlrpc.XMLRPCRequest(host=host)
        code.InteractiveConsole.__init__(self)
        canvascode.CanvasInteractiveInterpreter.__init__(self)
        try:
            readline.parse_and_bind('tab: complete')
            readline.set_completer(CANVASCompleter().complete)
        except NameError:
            ##Probably Windows where the readline package hasn't been installed - no special history of tab complete for them!
            pass
            
        self.python = False
        # commands that get handle before any scripting
        self.commands = {
            # COMMAND, usage, valid argument counts, command callback
            'RUNMODULE'     : ['<module> [<options>]', [-1], self.run_module],
            'SPAWNRUNMODULE': ['<module> [<options>]', [-1], self.spawn_run_module],
            'LOAD'          : ['<module> -- Loads a module', [1], self.load_module],
            'UNLOAD'        : ['<module> -- Unloads a module', [1], self.unload_module],
            'LIST'          : ['-- Lists loaded modules', [0], self.list_modules],
            'FLUSHLOG'      : ['-- Flushes engine log', [0], self.flush_log],
            'TYPES'         : ['-- Lists available listener types', [0], self.list_listener_types],
            'LISTENERS'     : ['-- Lists active listeners', [0], self.list_listeners],
            'INTERFACES'    : ['-- Lists available interfaces [<node ID>]', [0, 1], self.list_interfaces],
            'BIND'          : ['<listener TYPE> <interface ID> <port> [<fromcreatethread 0/1>] -- Starts a MOSDEF listener', [3, 4], self.start_listener],
            'LISTENERNODES' : ['<listener ID> -- Check active nodes on listener', [1], self.list_listener_nodes],

            'NODES'         : ['-- List all available nodes', [0], self.list_all_nodes],
            'INTERACT'      : ['<node ID> -- Interact with a node', [1], self.node_interact],
            'PYSHELL'       : ['ON/OFF -- Switches to the Python shell', [1], self.pyshell],
            'HELP'          : ['[<command>] -- Shows help for a command', [0, 1], self.help],
            '?'             : ['[<command>] -- Shows help for a command', [0, 1], self.help],
            'SUICIDE'       : ['-- Suicide engine thread', [0], self.suicide],
            'CLOSE'         : ['<node ID> -- Close a node', [1], self.node_close],
            # XXX: debugging functions
            #'TEST'          : ['-- Test a feature, remove on release!', [0], self.test_feature]
            }
        self.listener_types = {}
        self.interfaces     = {}
        self.listeners      = {}
        self.fromgui        = False
        self.guisession     = None
        return
    
    # for debugging
    def suicide(self, args):
        try:
            self.rpc.proxy.suicide()
        except xmlrpclib.Fault:
            pass
        except xmlrpclib.ProtocolError:
            sys.stdout.write('[+] Server Thread Suicided\n')
            pass
        return
    
    def help(self, args):
        if len(args) == 2:
            if args[1].upper() in self.commands:
                sys.stdout.write('%s %s\n' % (args[1].upper(),\
                                            self.commands[args[1].upper()][0]))
            else:
                sys.stdout.write('No such command')
        else:        
            for command in self.commands:
                sys.stdout.write('%s %s\n' % (command, self.commands[command][0]))
        return
    
    # XXX: needs more intelligent arg parsing
    def handle_command_line(self, line):
        command = line.split(' ')
        if command[0].upper() not in self.commands:
            return False
        else:
            # checks for matching amount of args, -1 means variable n args
            if self.commands[command[0].upper()][1][0] != -1:
                if len(command) - 1 not in self.commands[command[0].upper()][1]:
                    sys.stdout.write('Usage: ' + command[0].upper() + ' ' +\
                                    self.commands[command[0].upper()][0] + '\n')
                    return False
            else:
                # variable command args with no args ... dump usage
                if not len(command) - 1:
                    sys.stdout.write('Usage: ' + command[0].upper() + ' ' +\
                                    self.commands[command[0].upper()][0] + '\n')                
                    return False
            # call the handler for that command
            # handlers are responsible for type conversion
            try:
                devlog("cli", "Running command: %s"%command[0].upper())
                self.commands[command[0].upper()][2](command)
            except socket.error:
                sys.stdout.write('[+] Failed to connect to RPC Server!\n')
                return False 
            except:
                import traceback
                traceback.print_exc(file=sys.stderr)
                sys.stdout.write('[+] Check your command please\n')
                return False 
        return True
    
    def node_close(self, args):
        try:
            nodeid = int(args[1])
            sys.stdout.write('[+] Closing node %d\n' % nodeid) 
            ret = self.rpc.proxy.node_close(nodeid)
            if ret == True:
                sys.stdout.write('[+] Closed node %d\n' % nodeid)
            else:
                sys.stdout.write('[+] No such active node\n')
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def node_interact(self, args):
        try:
            nodeid = int(args[1])
            if self.fromgui == True and hasattr(self, 'interactmode') and self.interactmode == False:
                # pyconsole specific! first toggle the mode
                if hasattr(self, 'input_buffer'):
                    self.input_buffer = ''
                self.interactmode   = True
                session             = self.rpc.proxy.node_interact(nodeid)
                self.guisession     = session
                stdin               = self
                if session != []:
                    self._stdout.write('[+] Got an active session for node %d (GUI Mode)\n' % (nodeid))
                else:
                    self._stdout.write('[-] No such session\n')
                    self.interactmode = False
                    self._stdout.flush()
                    return
            # gui stdin poll from textview
            elif self.fromgui == True and hasattr(self, 'interactmode') and self.interactmode == True:
                session = self.guisession
                stdin   = self
            else:
                # real commandline uses real stdout/stdin
                self._stdout    = sys.stdout
                stdin           = sys.stdin
                session         = self.rpc.proxy.node_interact(nodeid) 
                if session != []:
                    self._stdout.write('[+] Got an active session for node %d (Console Mode)\n' % (nodeid))
                else:
                    self._stdout.write('[-] No such session\n')
                    return
                
            if session and session != []:
                # got a valid session
                self._stdout.write("[+] Note: will revert back to <<<CANVAS>>> on \"detach\"\n")
                sessionid = '%s:%s' % (session[0], session[1])               
                while 1:
                    try:
                        out = self.rpc.proxy.node_interact_getstdout(sessionid)
                        #out is what used to be in the cache (aka, a list of strings (lines))
                    except:
                        out = ''
                    if out:
                        #there are some interesting unicode issues here that we try to avoid
                        #in particular, each line in the "out" list is in some random unicode format
                        #TODO: use the node's localize_string() function to turn them into utf-8
                        tmp = u""
                        for u in out:
                            devlog("cli", "outstring: %s %s"%(type(u),u))
                            if type(tmp)!=type(u''):
                                tmp+=u.decode("utf-8")
                            else:
                                tmp+=u
                        
                        self._stdout.write(tmp.encode('utf-8','ignore'))
                        # flushes gtk events for pyconsole
                        self._stdout.flush()
                    line = ''
                    rd, wr, ex = select_stdin_for_reading(stdin=stdin)
                    if rd != []:
                        line = stdin.readline()
                    if line:
                        # detach and flushlog are pre-commands
                        if 'DETACH' in line.upper():
                            self._stdout.write('[+] Detaching from session\n')
                            if self.rpc.proxy.node_interact_suicide(sessionid) == True:
                                self._stdout.write('[+] Detached\n')
                            else:
                                sys.stdout.write('[+] Could not detach!\n')
                            if self.fromgui == True:
                                self.interactmode   = False
                                self.guisession     = []
                                self._stdout.flush()
                            break
                        elif 'FLUSHLOG' in line.upper():
                            self.flush_log([])
                            self._stdout.flush()
                        else:
                            self.rpc.proxy.node_interact_putstdin(sessionid, line)
                    # prevent consumption of cpu in gui polling ...
                    if self.fromgui == True:
                        time.sleep(0.1)
                    
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def list_listener_nodes(self, args):
        try:
            
            if not len(self.listeners):
                self.list_listeners([])
            if int(args[1]) not in self.listeners:
                sys.stdout.write('[+] No such active listener\n')
            else:
                ip      = self.listeners[int(args[1])][0]
                port    = self.listeners[int(args[1])][1]
                ret = self.rpc.proxy.list_listener_nodes(ip, port)
                if ret != []:
                    sys.stdout.write('[+] Active nodes on listener ID %d: %s:%d\n' % (int(args[1]), ip, port))
                    for node in ret:
                        sys.stdout.write('%s:%s\n' % (node[0], node[1]))
                    sys.stdout.write('[+] Listed active nodes\n')
                else:
                    sys.stdout.write('[+] No active nodes on listener %s:%d\n' % (ip, port))
                    
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
            pass
        return
    
    def list_all_nodes(self, args):
        ret = []
        try:
            ret = self.rpc.proxy.list_all_nodes()
            if ret != []:
                sys.stdout.write('[+] Listing all active nodes\n')
                i = 0
                for node in ret:
                    sys.stdout.write('ID: %d - %s:%s\n' % (i, node[0], node[1]))
                    i += 1
                sys.stdout.write('[+] Listed all active nodes\n')
            else:
                sys.stdout.write('[+] No active nodes\n')

        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
            pass
        except socket.error, msg:
            #connection refused, etc.
            sys.stdout.write('No XMLRPC Engine Server available - please start one up\n')
        return ret
    
                
    def list_listeners(self, args):
        try:
            
            sys.stdout.write('[+] Listing active listeners\n')
            ret = self.rpc.proxy.list_listeners()
            i = 0
            for line in ret:
                self.listeners[i] = line
                sys.stdout.write('ID: %d - ' % i + '%s:%s (%s)' %\
                                 (line[0], line[1], line[2]) + '\n')
                i += 1
            sys.stdout.write('[+] Listed active listeners\n')
        
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
            pass
        return
    
    def list_interfaces(self, args):
        try:
            
            # remote node interfaces from remote node ID
            if len(args) == 2:
                nodeid = int(args[1])
                sys.stdout.write('[+] Listing available interfaces for remote node %d\n' % nodeid)
                ret = self.rpc.proxy.list_remotenode_interfaces(int(args[1]))
                i = 0
                for line in ret:
                    sys.stdout.write('ID: %d - ' % i + '%s: inet %s netmask %s' %\
                                     (line[0], line[1], line[2]) + '\n')
                    i += 1
            # local node interfaces             
            else: 
                # self.interfaces only caches localnode interfaces
                sys.stdout.write('[+] Listing available interfaces for local node\n')
                if not len(self.interfaces):
                    ret = self.rpc.proxy.list_localnode_interfaces()
                    i = 0
                    for line in ret:
                        self.interfaces[i] = line
                        sys.stdout.write('INTERFACE: %d - ' % i + '%s: inet %s netmask %s' %\
                                         (line[0], line[1], line[2]) + '\n')
                        i += 1
                else:
                    for i in self.interfaces:
                        line = self.interfaces[i]
                        sys.stdout.write('INTERFACE: %d - ' % i + '%s: inet %s netmask %s' %\
                                         (line[0], line[1], line[2]) + '\n')
            sys.stdout.write('[+] Listed available interfaces\n')
                
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def list_listener_types(self, args):
        try:
            
            sys.stdout.write('[+] Listing available listener types\n')
            if not len(self.listener_types):
                ret = self.rpc.proxy.list_listener_types()
                i = 0
                for line in ret:
                    self.listener_types[i] = line
                    sys.stdout.write('TYPE: %d - ' % i + line + '\n')
                    i += 1
            else:
                for i in self.listener_types:
                    sys.stdout.write('TYPE: %d - ' % i + self.listener_types[i] + '\n')
            sys.stdout.write('[+] Listed available listener types\n')

        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def spawn_run_module(self, args):
        devlog("cli", "Spawn run module: %s"%repr(args))
        return self.run_module(args, spawn=True)


    def get_server_state(self):
        """
        Gets the state from the remote XML rpc server
        """
        
        return self.rpc.proxy.state()

        
    def silica_cli_action(self, args, tspawn=False):
        print "SILICA cli args: ", args, "Spawn: ", tspawn
        cmd = [-1, args['module_name']]+ args['module_args'].split(" ")
        
        return self.run_module(cmd, spawn=tspawn)
    

    def get_node_count(self, args):
        return self.rpc.proxy.get_node_count()

    def cli_screengrab_passwordhash_status(self, args):
        return self.rpc.proxy.srv_screengrab_passwordhash_status()
    
    def convert_cli_all_nodes_to_win32(self, args):
        try:
            return self.rpc.proxy.convert_srv_all_nodes_to_win32()
        except xmlrpclib.Fault:
            print "Null argument catching, the XMLrpc server does not support this"

    def run_cli_screengrab_passwordhash_all_nodes(self, args):
        try:
            self.rpc.proxy.run_srv_screengrab_passwordhash_all_nodes()
        except:
            print "Null argument catching, the XMLrpc server does not support this"
        
    # XXX: threading mojo on XMLRPC end to prevent timeouts
    def run_module(self, args, spawn=False):
        devlog("cli", "Run module: %s"%repr(args))
        try:
            # flush engine log to clear pending output
            self.rpc.proxy.flush_log()
            sys.stdout.write('[+] Running module: %s\n' % args[1])
            # spawns a thread for the module in the engine
            i = self.rpc.proxy.run_module(args[1], ' '.join(args[2:]))
            if not spawn:
            # polls the thread to see if it's done yet(tm)
                thread_done = False
                while thread_done == False:
                    thread_done = self.rpc.proxy.poll_commandline_thread(i)
                    if thread_done == False:
                        time.sleep(0.1)
    
                    sys.stdout.flush()                   
                sys.stdout.write('[+] Done running module\n')
            else:
                sys.stdout.write('[+] Spawned module: %s\n'%i)
        except xmlrpclib.Fault:
            
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def load_module(self, args):
        try:
            
            sys.stdout.write('[+] Loading module into engine\n')
            ret = self.rpc.proxy.load_module(args[1])
            if ret == True:
                sys.stdout.write('[+] Module loaded\n')
            else:
                sys.stdout.write('[+] Could not load module\n')
            
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def unload_module(self, args):
        try:
            
            sys.stdout.write('[+] Unloading module from engine\n')
            self.rpc.proxy.unload_module(args[1])
            sys.stdout.write('[+] Module unloaded\n')
            
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def list_modules(self, args):
        try:
            sys.stdout.write('[+] Getting module list\n')
            ret = self.rpc.proxy.list_modules()
            for line in ret:
                sys.stdout.write('[MODULE] ' + line + '\n')
            sys.stdout.write('[+] End of module list\n')
            
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def flush_log(self, args):
        try:

            sys.stdout.write('[+] Flushing engine log\n')
            ret = self.rpc.proxy.flush_log()
            for line in ret:
                sys.stdout.write('[ENGINE] ' + line + '\n')
            sys.stdout.write('[+] Flushed engine log\n')
            
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def start_listener(self, args):
        try:
            if not len(self.listener_types):
                self.list_listener_types([])
            if not len(self.interfaces):
                self.list_interfaces([])
            if int(args[1]) not in self.listener_types:
                sys.stdout.write('[+] No such listener type\n')
                return
            if int(args[2]) not in self.interfaces:
                sys.stdout.write('[+] No such interface\n')
                return
            sys.stdout.write('[+] Starting listener\n')
            typeID  = int(args[1])
            ifaceID = int(args[2])
            port    = int(args[3])
            if len(args) == 4:
                ret = self.rpc.proxy.start_localnode_listener(self.listener_types[typeID],\
                                                    self.interfaces[ifaceID][0],\
                                                    port,\
                                                    0) # default to off for fct
            if len(args) == 5:
                fcThreadToggle = int(args[4])
                ret = self.rpc.proxy.start_localnode_listener(self.listener_types[typeID],\
                                                    self.interfaces[ifaceID][0],\
                                                    port,\
                                                    int(fcThreadToggle))
                
            if ret == True:
                self.list_listeners([])
                sys.stdout.write('[+] Listener started\n')
            else:
                sys.stdout.write('[+] Could not start listener\n')
                
        except xmlrpclib.Fault:
            import traceback
            traceback.print_exc(file=sys.stderr)
        return
    
    def pyshell(self, args):
        if 'ON' in args[1].upper():
            if self.python != True:
                self.python = True
                self.cache.flush()
                self.resetbuffer()
                sys.ps1     = '>>> '
            else:
                sys.stdout.write('Already in Python mode\n')
                out = self.cache.flush()
                sys.stdout.write(out)
                
        if 'OFF' in args[1].upper():
            if self.python != False:
                self.python = False
                self.cache.flush()
                self.resetbuffer()
                sys.ps1     = '<<<CANVAS>>> '
            else:
                sys.stdout.write('Already in CANVAS mode\n')
                out = self.cache.flush()
                sys.stdout.write(out)        
        return

    # XXX: for when we wanna config
    # [SECTION1]
    # item1: value1
    # item2: value2
    # [SECTION2]
    # item1: value1
    # item2: value2
    def read_config(self, file='config.ini'):
        Config = ConfigParser.ConfigParser()
        Config.read(file)
        sections = Config.sections()
        for section in sections:
            print Config.items(section)
    
    def get_output(self):
        sys.stdout = self.cache
        return
    
    def return_output(self):
        sys.stdout = self.stdout
        return
    
    def interact(self, banner=None):
        self.resetbuffer()
        if self.python == False:
            try:
                sys.ps1
            except AttributeError:
                sys.ps1 = '<<<CANVAS>>> '
        else:
            try:
                sys.ps1
            except AttributeError:
                sys.ps1 = '>>> '
                
        try:
            sys.ps2
        except AttributeError:
            sys.ps2 = '... '
            
        more = 0
        while 1:
            try:
                if more:
                    prompt = sys.ps2
                else:
                    prompt = sys.ps1
                try:
                    line = self.raw_input(prompt)
                except EOFError:
                    self.write('\n')
                    break
                else:
                    more = self.push(line, python=self.python)
            except KeyboardInterrupt:
                self.write('\nKeyboardInterrupt\n')
                self.resetbuffer()
                more = 0
                
    def push_python_script(self, script):
        self.resetbuffer()
        more = 0
        for line in script:
            try:
                if more:
                    prompt = '... '
                else:
                    prompt = '>>> '
                sys.stdout.write(prompt + line + '\n')
                more = code.InteractiveConsole.push(self, line)
            except KeyboardInterrupt:
                self.write('\nKeyboardInterrupt\n')
                self.resetbuffer()
                more = 0           

    def canvas_push(self, line):
        devlog("cli", "CANVAS_PUSH: %s"%line)
        line = line.lstrip() #remove spaces off the front (this confuses CANVAS)
        self.buffer.append(line)
        source  = '\n'.join(self.buffer)
        more    = self.runscript(source)
        if not more:
            self.resetbuffer()
        return more
    
    # we can intercept commands here
    def filter_line(self, line):
        if self.handle_command_line(line) == True:
            return None
        return line

    def push(self, line, python=False):
        ## stdout caching on
        cache_stdout = False
        
        if cache_stdout == True:
            self.get_output()
            
        line = self.filter_line(line)
        if line == None:
            return 0
        if python == True:
            ret = code.InteractiveConsole.push(self, line)
        else:
            ret = self.canvas_push(line)

        ## stdout caching off
        if cache_stdout == True:
            self.return_output()
            out = self.cache.flush()
            sys.stdout.write(out)
            
        return ret
    
    def test_feature(self, args):
        script = []
        script.append('def hi():')
        script.append('  print "LOL"')
        script.append('')
        script.append('hi()')
        self.push_python_script(script)
        return None        
    
