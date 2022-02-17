#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
11:16 < dave> a shellserver has the command line interface to remote nodes
11:16 < dave> but is the overarching class for the MOSDEF functionality that
              does the good stuff
"""

import socket
from exploitutils import *
import sys
import hostlistener
from hostlistener import hostlistener
from threading import Lock
import traceback
import cmd
import select

from Nodes.NodeUtils import NodePrompt
from canvaserror import *

have_readline=False
try:
    import readline
    have_readline=True
except:
    pass
    print "No readline imported."

class ExitException(Exception):
    """
    Used to signal "Time to exit"
    """
    pass

class canvascmdline(cmd.Cmd, NodePrompt):
    def __init__(self):
        # we have to prepare hooked functions before to initialize Cmd.
        self.hook_do_func()
        cmd.Cmd.__init__(self)

    def default(self, line):
        line=unicode(line)
        words = line.split(u' ')
        args = None
        cmd = words[0]
        if len(words) > 1:
            args = words[1:]
            devlog("shellserver", "Args: %s"%repr(args))

        #here we look for a handler for that particular "command" and if we don't see one, we just
        #run it as a "command"
        if not hasattr(self, cmd):
            devlog('shellserver::parsecmdline', "unknown command [%s] -> default command" % cmd)
            #m = self.runcommand(line)
            #print shellcode_dump(m)
            self._log(self.runcommand(line))
            return None
        f = getattr(self, cmd)
        #print f, args
        if callable(f):
            devlog('shellserver::parsecmdline', "calling %s" % f)
            #try:
            if args not in ["", None]:
                f(args)
            #except TypeError:
            else:
                f()
        else:
            devlog('shellserver::parsecmdline', "not callable [%s] -> default command" % cmd)
            self._log(self.runcommand(line))
        return None

    def preloop(self):
        devlog('shellserver::parsecmdline', "looping on canvascmdline, Engine=%s" % self.engine)

    def precmd(self, line):
        if line == "EOF":
            return "exit"
        return line

    def postcmd(self, stop, line):
        if not self.connection:
            return 17 # XXX
        rd, wr, ex = select.select([self.connection], [], [], 0.1)
        #print "Self.connection=%s"%self.connection
        if self.connection in rd and self.connection.recv(1) == "":
            print "\nConnection closed."
            return 42
        return stop

    def postloop(self):
        devlog('shellserver::parsecmdline', "exiting loop from canvascmdline, Engine=%s" % self.engine)

    def hook_do_func(self):
        for funcname in dir(self):
            if funcname[0:3] == 'do_' and not hasattr(self, funcname[3:]):
                devlog('shellserver::hooks', "hooking %s -> %s" % (funcname[3:], funcname))
                setattr(self, funcname[3:], getattr(self, funcname))
        for funcname in self.shortcuts.keys():
            if hasattr(self, self.shortcuts[funcname]):
                devlog('shellserver::hooks', "hooking %s -> %s" % ('do_' + funcname, self.shortcuts[funcname]))
                setattr(self, 'do_' + funcname, getattr(self, self.shortcuts[funcname]))
            elif hasattr(self, 'do_' + self.shortcuts[funcname]):
                devlog('shellserver::hooks', "hooking %s -> %s" % ('do_' + funcname, 'do_' + self.shortcuts[funcname]))
                setattr(self, 'do_' + funcname, getattr(self, 'do_' + self.shortcuts[funcname]))

    def _log(self, msg):
        if type(msg)==type(''):
            print iso8859toascii(msg)
        else:
            #unicode
            print msg

    def succeeded(self, msg):
        if msg:
            self._log(msg)
        return None

    def failed(self, msg):
        if msg:
            self._log("[!] " + msg)
        return None #17 XXX


class shellserver(hostlistener, canvascmdline):
    "new shellserver"

    def not_implemented(self, msg = "not implemented on this shell"):
        return self.failed(msg)

    def not_supported(self, msg = "not supported on this listener"):
        return self.failed(msg)


class old_shellserver(shellserver):
    "overall class for all shellservers."

    _shortcuts = {  'h': "interact_help",
                    'help': "interact_help",
                    'p': "pwd",
                    'u': "upload",
                    #'d': "download",
                    'd': "cmdline_download",
                    'c': "runcommand",
                    'de': "do_exitthread",
                    're': "runexitprocess",
                    'cz': "callzero",
                    'pt': "printvalidthreadtokens",
                    'st': "SetThreadToken",
                    'quit': "quit_commandline",
                    '?': "interact_help",
                    'getpid': "getpid",
                    'getppid': "getppid",
                    'id': "getids",
                    'seteuid': "seteuid",
                    'uid': "do_setuid",
                    'gid': "do_setgid",
                    'tcpscan': "tcpportscan",
                    'dodir': "dodir",
                    'mkdir': "mkdir",
                    'dounlink': "dounlink",
                    'ps': "doprocesslisting",
                    'dokill': "dokillprocess",
                    'runmodule': "runmodule",
                    'shellshock': "shellshock",
                    'reload': "reload",
                    'checkvm': "checkvm",
                    'chdir': 'cd',
                    'powershell': 'ps_interact',
    }

    def __init__(self, connection, id=0, port=0, type="Unknown", GtkID=0, logfunction=None):
        """
        connection is our tcp socket
        """
        self.engine         = None
        hostlistener.__init__(self, id, type, GtkID, logfunction)
        self.argsDict       = {}
        self.port           = port
        self.connection     = connection
        self.info           = ""
        self.started        = 0
        self.donestarting   = 0
        self.client         = None
        self.host           = "127.0.0.1"
        if not hasattr(self, 'prompt'):
            self.prompt     = "Command"
        self.commands       = {}
        self.lock           = Lock()
        self.verbose        = False
        self._init_shortcuts()

        return

    def copy(self):
        import copy
        return copy.copy(self)

    def restart(self):
        """ in case of privilege escalation """
        self.started = 0
        self.startup()

    def _init_shortcuts(self):
        for shortcut in self._shortcuts.keys():
            self.add_shortcut(shortcut, self._shortcuts[shortcut])

    def add_shortcut(self, shortcut, funcname):
        if hasattr(self, funcname):
            self.commands[shortcut] = getattr(self, funcname)

    def enter(self):
        """
        Threading lock enter and set the node to busy
        """
        devlog('shellserver', "enter() +lock")
        if 0:
            import traceback
            traceback.print_stack(file=sys.stderr)

        if self.node:
            self.node.setbusy(1)
        self.lock.acquire()
        return

    def leave(self):
        """
        Threading lock leave and set node to non-busy
        """
        devlog('shellserver', "leave() -lock")

        if self.node:
            self.node.setbusy(0)
        # patch by steven
        #if self.lock.locked():
        self.lock.release()
        return

    def checkvm(self):
        """Not implemented on this shell"""
        #"""check if we're inside a virtual machine (IA32 architectures)"""
        return "not implemented on this shell!"

    def setLogFunction(self,logfunction):
        self.logfunction=logfunction

    def shellshock(self, logfile=None):
        """Not implemented on this shell"""
        #"""transform the connection into a shell"""
        return "not implemented on this shell"

    def getPort(self):
        return self.port

    def setPort(self,port):
        self.port=port

    def receiveDataFromSocket(self):
        """
        needs to be overridden if you want to actually handle it
        """
        data=""
        try:
            data=self.connection.recv(1000)
        except:
            pass

        if len(data)==0:
            self.closeme()
            return 0

        print "Recieved erroneous data of length %d: %s"%(len(data),prettyprint(data))
        return 1

    def handleData(self):
        """
        Called by GTK select() handler
        """
        print "Handling data"
        self.informClient()
        if self.started:
            return self.receiveDataFromSocket()
        else:
            print "Calling startup"
            self.startup()
            self.started=1
        #print  "Done handling data"
        return 1

    def getRemoteHost(self):
        self.informClient()
        try:
            ret=self.connection.getpeername()
        except socket.error:
            self.log("Connection was closed before we could get address...")
            ret=0

        return ret

    def setID(self,id):
        self.id=id

    def setInfo(self,info):
        self.info=str(info)

    def getID(self):
        return self.id

    def getInfo(self):
        return self.info

    def disconnect(self):
        retval = self.connection
        if self.connection:
            self.connection.close()
            self.connection = None
        return retval

    def getSocket(self):
        return self.connection

    def closeme(self):
        return self.disconnect()

    def pwd(self):
        """Not implemented on this shell"""
        #"""gets working directory"""
        return "Not implemented on this shell!"

    def cd(self,directory):
        """Not implemented on this shell"""
        #"""changes working directory"""
        return "Not implemented on this shell!"

    def dodir(self,directory):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    def upload(self,source,dest="."):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    #def download(self,source,destdir="."):
        #"""
        #Downloads a file - DEPRECIATED - now usinf cmdline_download
        #"""
        #return "Not implemented on this shell!"

    def cmdline_download(self,source,destdir="."):
        ##Downloads a file - now using the download module so all the session
        ##path is set etc rather than just downloading to ./ as it did before
        """
        Downloads a file to the session directory
                    e.g. /Reports/default/192.168.1.1/downlaods/file.doc
        """
        ##Make sure any '\' in the source path don't act like escape chars
        source = source.replace("\\","\\\\")
        string_to_send = "download -O source:%s"%(source)
        self.runmodule(string_to_send)
        return "Done"

    def dounlink(self,filename):
        """Not implemented on this shell"""
        #"""deletes a file"""
        return "Not implemented on this shell!"

    def dospawn(self,filename):
        """Not implemented on this shell"""
        #"""spawns an executable"""
        return "Not implemented on this shell!"

    def docreateprocessasuser(self,command):
        """Not implemented on this shell"""
        return "not implemented on this shell!"

    def runcommand(self,command):
        """Not implemented on this shell"""
        #"""Runs a command via popen"""
        return "Not implemented on this shell!"

    def runexitprocess(self):
        """Not implemented on this shell"""
        #"""calls exit process"""
        return "Not implemented on this shell!"

    def quit_commandline(self):
        """
        Exit the shell entirely
        """
        raise ExitException, "Exit please"


    def callzero(self):
        """Not implemented on this shell"""
        #"""call zero - usually exits the shell"""
        return "Not implemented on this shell!"

    def ps_interact(self):
        """Not implemented on this shell"""
        #"""Starts a Powershell interactive console"""
        return "Not implemented on this shell!"
    def informClient(self):
        if self.client!=None:
            self.log("Setting client success flag!")
            self.client.setSucceeded()
        return

    def isBusy(self):
        if self.client!=None:
            state=self.client.getState()
            #print "State=%s"%state
            if state=="done":
                return 0
            return 1
        return 0

    def setExploit(self,client):
        self.client=client
        return

    def clearExploit(self):
        self.client=None
        self.initstring=""
        return

    def localize_string(self, instring):
        """
        Win32Nodes and other nodes that deal with unicode text will want to be able to
        localize it! So override this!
        """
        return instring

    def interact(self):
        """
        do our commandline - we don't use cmd.Cmd here for some reason.
        """
        # TODO: this code should be re-thinked and common code with shellshock_loop extracted.
        import select
        devlog('shellserver::interact', "Starting interaction. Engine:%s" % self.engine)
        #print "Self.connection=%s"%self.connection
        pmt             = self.getprompt()
        while 1:
            if not self.connection:
                print "\nConnection closed. (No more opened sockets to select on)"
                return 0
            sys.stdout.write(pmt+' ')
            sys.stdout.flush()
            try:
                if hasattr(self.connection, "isactive"):
                    if self.connection.isactive():
                        devlog("shellserver", "Handle active connection...")
                        rd = [ self.connection ]
                        pass
                    else:
                        rd, wr, ex = select_stdin_and_socket_for_reading(None)
                else:
                    rd, wr, ex = select_stdin_and_socket_for_reading(self.connection)
            except KeyboardInterrupt:
                return 0

            if self.connection in rd:
                # Avoid calling recv() on anything != socket
                if isinstance(self.connection, socket._socketobject):
                    # XXX broken code here...
                    try:
                        buf = self.connection.recv(4)
                    except socket.error, errlist:
                        if errlist[0] == 104: # Connection reset by peer
                            buf = ""
                        else:
                            raise
                    if buf == "":
                        print "\nConnection closed. (Connection reset by peer)"
                        return 0
                    # else ... ? what to do if buf != ""? eat socket, print buf ???
                    # XXX
            # else it's probably stdin
            try:
                data = sys.stdin.readline()
                try:
                    data = data.decode("utf_8")
                except UnicodeDecodeError:
                    devlog("shellserver", "Shellserver Need to localize this input string: %s."%repr(data))
                    #retry using a function that should be overriden by the shellserver (like win32Mosdef does)
                    #this assumes we entered in data in the same localization as our target (which is likely)
                    data = self.localize_string(data)

            except (EOFError, KeyboardInterrupt):
                return 0
            c=data.split(u' ')[0]
            if not len(c):
                continue
            argument=u" ".join(data.split(u" ")[1:])
            do_handler = 'do_' + str(c) #un-unicode here
            if hasattr(self, do_handler):
                handler = getattr(self, do_handler)
            else:
                potential_command=str(c).strip()
                if potential_command not in self.commands:
                    if self.verbose:
                        stdout.write("Defaulting to run command: %s" % data)

                    potential_command="c" #run command is the default

                    # MOSDEF will crash and burn if we pass unicode string
                    try:
                        argument = data.encode('ASCII')
                    except UnicodeError:
                        sys.stdout.write("Could not encode argument")
                        return

                handler = self.commands[potential_command]
            devlog('shellserver::interact', "handler: %s" % handler)

            try:
                if argument != "":
                    # changed to readline()
                    # so eat the readline newline
                    if argument[-1:] == u'\n':
                        argument = argument[:-1]
                    output = handler(argument)
                else:
                    output = handler()
                if output:
                    if type(output)!=type(u''):
                        print iso8859toascii(str(output))
                    else:
                        print output
            except TypeError:
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.write("Wrong number of arguments, sorry\n")
            except ExitException:
                sys.stdout.write("Got quit instruction...exiting\n")
                sys.exit(1)
            except:
                sys.stdout.write("Unknown error\n")
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.write("\n")

    def interact_help(self):
        """Print out useful help messages!"""
        pretty_help = {}
        alignment   = 0

        for c in self.commands:

            ##Do alignment so easier to read
            if len(c) > alignment:
                alignment = len(c)

            if self.commands[c].__doc__ == None:
                #print "%s - No help available"%c
                pretty_help[c]= "No help available"
            else:
                # format it so that anything > 2 spaces == 1 space (kludge)
                formatted = self.commands[c].__doc__
                formatted = formatted.replace("\n","")
                formatted = formatted.replace("\r","")
                formatted = formatted.replace("\t","")
                formatted = no_double_spaces(formatted)
                formatted = formatted.strip()
                #print "%s - %s"%(c, formatted)
                pretty_help[c]= formatted

        ##Display to screen
        ordered_help=[]
        for h in pretty_help.items():
            ordered_help.append( "%s%s - %s"%(h[0], ((alignment-len(h[0]))*" "), h[1]) )
        ordered_help.sort()
        print "\n"
        for h in ordered_help:
            print h


    def getInitString(self):
        return self.initstring

    def addInitString(self,mystr):
        self.initstring+=mystr
        return

    def getpid(self):
        """Not implemented on this shell!"""
        return "Not implemented on this shell!"

    def getppid(self):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    def getids(self):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    def seteuid(self,uid):
        return "Not implemented on this shell!"

    def mkdir(self,directory):
        """Not implemented on this shell"""
        return "Not implemented on this shell"

    def setgid(self,gid):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    def seteuid(self,euid):
        """Not implemented on this shell"""
        return "Not implemented on this shell!"

    def tcpportscan(self,network,startport,endport):
        """Not implemented on this shell"""
        #"""tcp portscans from the remote host"""
        return "Not implemented on this shell!"

    def doprocesslisting(self):
        """Not implemented on this shell"""
        return "Not implemented on this shell"

    def dokillprocess(self):
        """Not implemented on this shell"""
        return "Not implemented on this shell"

    def runmodule(self,args):
        """
        When you call "runmodule whoami -O k:8 -O b:9", this is where you end up.
        args is: whoami -O -k:8 -O b:9
        TODO: proper parser on argument string!
        """
        module=args.split(" ")[0].strip()
        self.log("Running module: %s"%module)
        args=" ".join(args.split(" ")[1:])
        self.log("Args: %s"%args)
        import canvasengine
        app = canvasengine.getModuleExploit(module)
        app.link(self)

        if not app.argsDict['passednodes']:
            app.argsDict['passednodes'] = [self.node]

        if hasattr(app, "neededListenerTypes"):
            needed_listeners = app.neededListenerTypes()

            if needed_listeners:
                listener = self.engine.autoListener(app, needed_listeners[0])
                app.callback = listener

        #we do quote parsing here because we need to handle arguments like
        #-O command:"sh -c id"

        node = standard_callback_commandline(app, node=self.node, args=args, fromcommandline=False, quoteparse=True)
        if node not in [0, 1, None]:
            if hasattr(node, 'interact'):
                node.interact()

    def reload(self,args):
        """
        Reload a CANVAS module if the code has been changed while CANVAS has been running
               e.g. reload screengrab
        """
        import os
        module=args.split(" ")[0].strip()
        print "Reloading %s"%module
        try:
            mod=sys.modules[module]
            found=1
        except:
            #did not find module
            print "Did not find module in our modules list"
            found=0
            return
        # XXX do we really need pathunique() here?
        pathunique("exploits" + os.path.sep + module)
        #print "Found=%d"%found
        if not found:
            mod=self.engine.getModule(module)
        reload(mod)
        print "Reloaded %s"%module

    # XXX: this is duplicate code for now, needs to become a gui friendly handler
    def upexec_loop(self, msleeptime = 0.1, endian="big"):
        _endian_struct = {'big': ">", 'little': "<", 'small': "<"}
        assert endian.lower() in _endian_struct.keys(), "endian <%s> not in %s" % (endian, _endian_struct.keys())
        print "[!] Turning MOSDEF-Node into UploadExec environment"
        print "[!] Note: will revert back to MOSDEF when finished or on \'exit\'"

        # prompt loop
        i = 5
        import time
        while i:
            time.sleep(msleeptime)
            sys.stdout.write(".")
            sys.stdout.flush()
            i -= 1
        sys.stdout.write("\n")
        import select
        import struct
        retval = 0
        while 1:
            try:
                rd, wr, ex = select_stdin_and_socket_for_reading(self.connection)
            except KeyboardInterrupt:
                self.node.parentnode.send(self.connection, "exit\n")
                self.connection.recv(4)
                break
            if sys.stdin.fileno() in rd:
                try:
                    line = sys.stdin.readline()
                    self.node.parentnode.send(self.connection, line)
                except (EOFError, KeyboardInterrupt):
                    self.node.parentnode.send(self.connection, "exit\n")
                    self.connection.recv(4)
                    break
            # using sendstring protocol
            if self.connection in rd:
                buf = ""
                while len(buf) < 4:
                    tbuf = self.connection.recv(4 - len(buf))
                    if len(tbuf) == 0:
                        break
                    buf += tbuf
                if len(tbuf) == 0:
                    retval = -1
                    break

                datalen = struct.unpack(_endian_struct[endian] + "L", buf)[0]

                if datalen == 0:
                    devlog('shellshock_loop', "peer finished sending data")
                    break
                devlog('shellshock_loop', "trying to receive %d byte(s) from socket..." % datalen)
                lastchar = '\n'
                while datalen > 0:
                    # print "[!] datalen: %d / %X"%(datalen, datalen)
                    data = self.connection.recv(datalen)
                    tlen = len(data)
                    if tlen == 0: # connection reset by peer
                        self.connection.close()
                        break
                    lastchar = data[-1]
                    datalen -= tlen
                    sys.stdout.write(iso8859toascii(data))
                    sys.stdout.flush()
                if datalen > 0 and tlen == 0:
                    if lastchar != '\n':
                        sys.stdout.write('\n')
                    print "Connection reset by peer, we missed %d byte(s)" % datalen
                    retval = -1
                    break

        print "[!] Your regular MOSDEF programming will return shortly.."
        return retval

    def shellshock_loop(self, msleeptime = 0.1, endian="big", logfile=None):
        _endian_struct = {'big': ">", 'little': "<", 'small': "<"}
        assert endian.lower() in _endian_struct.keys(), "endian <%s> not in %s" % (endian, _endian_struct.keys())
        print "[!] Turning MOSDEF-Node into temporary interactive shell"
        print "[!] Note: will revert back to MOSDEF on \"exit\""

        log = None
        if logfile != None:
            # logfile will be the direct args line passed to it from the commandline
            print "[!] ShellShock logfile set to: %s" % logfile
            try:
                log = file(logfile, 'wb+')
            except:
                print "[!] could not open session log file .."
                log = None

        # prompt loop
        i = 10
        import time
        while i:
            time.sleep(msleeptime)
            #sys.stdout.write(".")
            #sys.stdout.flush()
            i -= 1
        sys.stdout.write("shellshocked!\n")
        import select
        import struct
        retval = 0
        while 1:
            try:
                # deal with shellshock on bounced nodes ...
                if hasattr(self.connection, 'isactive'):
                    r = []
                    if self.connection.isactive() == True:
                        r += [self.connection]
                    rd, wr, ex = select_stdin_and_socket_for_reading(None)
                    rd += r
                else:
                    rd, wr, ex = select_stdin_and_socket_for_reading(self.connection)
            except KeyboardInterrupt:
                self.node.parentnode.send(self.connection, "exit\n")
                self.connection.recv(4)
                break
            if sys.stdin.fileno() in rd:
                try:
                    line = sys.stdin.readline()
                    if hasattr(sys.stdin, 'isactive'):
                        if line[-1:] != '\n':
                            # append newlines to lines from gui 'stdin'
                            line += '\n'
                    #file('/tmp/lol.txt', 'ab').write('shellshock stdin line: %s EOL\n' % line)
                    if line:
                        if log:
                            log.write("%s" % line)
                            log.flush()
                        self.node.parentnode.send(self.connection, line)
                except (EOFError, KeyboardInterrupt):
                    self.node.parentnode.send(self.connection, "exit\n")
                    self.connection.recv(4)
                    break
            # using sendstring protocol
            if self.connection in rd:
                buf = ""
                while len(buf) < 4:
                    tbuf = self.connection.recv(4 - len(buf))
                    if len(tbuf) == 0:
                        break
                    buf += tbuf
                if len(tbuf) == 0:
                    retval = -1
                    break

                datalen = struct.unpack(_endian_struct[endian] + "L", buf)[0]

                if datalen == 0:
                    devlog('shellshock_loop', "peer finished sending data")
                    break
                devlog('shellshock_loop', "trying to receive %d byte(s) from socket..." % datalen)
                lastchar = '\n'
                while datalen > 0:
                    devlog('shellshock_loop', "[!] datalen: %d / %X"%(datalen, datalen))
                    data = self.connection.recv(datalen)
                    #If you need to debug messages use GetLastError and enable this
                    #if datalen == 4:
                    #    datadebug = struct.unpack(_endian_struct[endian] + "L", data)[0]
                    #    devlog('shellshock_loop', "message: %d / %X"%(datadebug, datadebug))

                    tlen = len(data)
                    if tlen == 0: # connection reset by peer
                        self.connection.close()
                        break
                    lastchar = data[-1]
                    datalen -= tlen
                    sys.stdout.write(iso8859toascii(data))
                    sys.stdout.flush()
                    if log:
                        log.write("%s" % data)
                        log.flush()
                if datalen > 0 and tlen == 0:
                    if lastchar != '\n':
                        sys.stdout.write('\n')
                    print "Connection reset by peer, we missed %d byte(s)" % datalen
                    retval = -1
                    break

        print "[!] Cleaning up left over muckery, please remain seated.."
        print "[!] Your regular MOSDEF programming will return shortly.."
        if log:
            log.close()
        return retval


#######################################
#
# hack until new_shellserver get ready
#
#  code below is deprecated (kludged)
#######################################


class temporary_hooked_old_shellserver(old_shellserver):

    def succeeded(self, msg = None):
        return msg

    def failed(self, msg = None):
        return msg

new_shellserver = shellserver
shellserver = temporary_hooked_old_shellserver


#######################################
#
#            end of hack
#
#######################################


class unixshellserver(shellserver):
    """
    Mixed into every UNIX shellserver in CANVAS.
    """
    # TODO: join stat/cat/uuencode code...

    def upload(self, source, dest="", destfilename=None):
        """
        Upload a file to the remote host
        """

        rv = True

        try:
            tFile   = open(source,"rb")
            alldata = tFile.read()
            tFile.close()
        except IOError, i:
            raise NodeCommandError("Unable to read source file at %s" % str(i))

        if destfilename:
            destfile = destfilename
        else:
            if dest and not dest.endswith('/'): dest += '/'
            destfile = dest + source.split('/')[-1]

        self.log("[+] Trying to create %s" % destfile)

        O_RDWR  = self.libc.getdefine('O_RDWR')
        O_CREAT = self.libc.getdefine('O_CREAT')
        O_TRUNC = self.libc.getdefine('O_TRUNC')
        newfile = self.open(destfile, O_RDWR|O_CREAT|O_TRUNC)

        if newfile < 0:
            e = "[EE] Could not create remote file"
            if hasattr(self, "perror"):
                e += ": %s" % self.perror(newfile)

            self.log(e)
            ret = e
            rv  = False

        if rv:
            #now write the data directly down the pipe
            self.writetofd(newfile, alldata) # writetofd can't report error?
            x = self.close(newfile)
            if x == -1:
                rv  = False
                ret = "Couldn't close file, that's weird - possibly some kind of error."
            else:
                rv = True

        if rv:
            ret = "Uploaded file successfully to %s" % destfile
        else:
            raise NodeCommandError(ret)

        return ret

    def download(self, source, dest="."):
        """
        downloads a file from the remote server
        """
        rv  = True
        ret = ""

        O_RDONLY    = self.libc.getdefine('O_RDONLY')
        infile      = self.open(source, O_RDONLY)

        if infile < 0:
            e = "Error opening remote file"
            if hasattr(self, "perror"):
                e += ": %s" % self.perror(infile)
            raise NodeCommandError(e)

        #if dest is None, we run into some problems here. So correct it.
        #the File Browser GUI sets it to None sometimes.
        if dest == None:
            dest = "."

        if os.path.isdir(dest):
            dest = os.path.join(dest, source.replace("/","_").replace("\\","_"))

        x,fs = self.fstat(infile)
        if x != 0:
            e = "fstat failed on file"
            if hasattr(self, "perror"):
                e += ": %s" % self.perror(infile)
            rv  = False
            ret = e

        if rv:
            size = fs["st_size"]
            if size == 0:
                e = "Error opening remote file"
                raise NodeCommandError(e)

            try:
                outfile=open(dest,"wb")
            except IOError, i:
                e   = "Failed to open local file: %s" % str(i)
                rv  = False
                ret = e

        if rv:
            data = self.readfromfd(infile,size)
            try:
                outfile.write(data)
                outfile.close()
                rv  = True
                ret = "Read %d bytes of data into %s"%(len(data),dest)

            except IOError,i:
                e   = "Error writing to local file: %s" % str(i)
                self.log(e)
                ret = e
                rv  = False


        x = self.close(infile)
        if x < 0:
            e   = "Some kind of error closing fd %d"%infile
            self.log(e)
            ret = e
            rv  = False

        if not rv:
            raise NodeCommandError(ret)

        return ret

    def getpeername(self):
        """
        Call getpeername() on connected node and return tuple with IP, PORT
        Return None on error.
        """

        vars = {
            'FD' : self.fd,
        }

        code = """
        #import "local"  , "sendint" as "sendint"
        #import "REMOTE" , "getpeername" as "getpeername"
        #import "int"    , "FD" as "FD"

        struct sockaddr_in {
            unsigned short int family;
            unsigned short int port;
            unsigned int saddr;
            char pad[6];
        };

        void main()
        {
            int ret;
            struct sockaddr_in addr;
            int size;
            int port;

            size = 14;
            port = 0;
            ret = getpeername(FD, &addr, &size);
            port = addr.port;

            sendint(ret);

            if (ret == 0) {
                sendint(port);
                sendint(addr.saddr);
            }
        }
        """

        lp64 = False
        if hasattr(self, "LP64"):
            lp64 = self.LP64

        if lp64:
            code = code.replace("REMOTE", "remote64")
        else:
            code = code.replace("REMOTE", "remote")

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        ret = self.readint()

        if ret == 0:
            port = socket.ntohs(self.readint())
            ip   = '.'.join(map(str, (map(ord, self.reliableread(4)))))
            self.leave()
            return (ip, port)

        self.leave()
        devlog('chris', 'unixshellserver: getpeername returned None')
        return None


    def do_setuid(self, uid):
        """
        Sets the user ID of the listener - supported on Unix MOSDEF nodes only
        """
        try:
            val = self.setuid(uid)
        except:
            return self.not_supported("setuid not supported on this listener")
        if val == -1:
            return self.failed(None)
        return self.succeeded(None)

    def do_setgid(self, gid):
        """
        Sets the group ID of the listener - supported on Unix MOSDEF only
        """
        try:
            val = self.setgid(gid)
        except:
            return self.not_supported("setgid not supported on this listener")
        if val == -1:
            return self.failed(None)
        return self.succeeded(None)

    def do_stat(self, filename):
        fd = self.open(filename, self.libc.getdefine('O_RDONLY'))
        if fd < 0:
            return self.failed("Couldn't open remote file %s, sorry." % filename)
        ret, fs = self.fstat(fd)
        if ret != 0:
            return self.failed("fstat failed on file %s" % filename)
        ret = self.close(fd)
        if ret != 0:
            return self.failed("error while closing the fd")
        output = "uid=%d gid=%d size=%d mode=%o" % (fs['st_uid'], fs['st_gid'], fs['st_size'], fs['st_mode'])
        return self.succeeded(output)

    def XXX_do_cat(self, filename):
        fd = self.open(filename, self.libc.getdefine('O_RDONLY'))
        if fd < 0:
            return self.failed("Couldn't open remote file %s, sorry." % filename)
        ret, fs = self.fstat(fd)
        if ret != 0:
            return self.failed("fstat failed on file %s" % filename)
        size = fs["st_size"]
        data = self.readfromfd(fd, size)
        if len(data) != size:
            return self.failed("could not read the whole file") # XXX already opened files?
        ret = self.close(fd)
        if ret != 0:
            return self.failed("error while closing the fd")
        return self.succeeded(data)

    def do_uuencode(self, filename):
        fd = self.open(filename, self.libc.getdefine('O_RDONLY'))
        if fd < 0:
            return self.failed("Couldn't open remote file %s, sorry." % filename)
        ret, fs = self.fstat(fd)
        if ret != 0:
            return self.failed("fstat failed on file %s" % filename)
        size = fs["st_size"]
        data = self.readfromfd(fd, size)
        if len(data) != size:
            return self.failed("could not read the whole file") # XXX already opened files?
        ret = self.close(fd)
        if ret != 0:
            return self.failed("error while closing the fd")
        return self.succeeded(uuencode_file(data, filename, fs['st_mode']))

