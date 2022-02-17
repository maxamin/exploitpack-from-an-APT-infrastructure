#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""

commandlineInterface.py

Use this before running the exploit modules

"""

import getopt,sys,os,socket,time

#covers both angles
if "." not in sys.path: sys.path.append(".")

from internal.debug import debug_enabled
from internal.utils import setup_logging
setup_logging(enable_debug=debug_enabled)

from exploitutils import *
try:
    from linuxNode   import linuxNode
    from solarisNode import solarisNode
    from bsdNode     import bsdNode
    from osxNode     import osxNode
    from ScriptNode  import ScriptNode
    from aixNode     import aixNode
except:
    logging.warning("Not loading linux or solaris for CRI")

from unixShellNode import unixShellNode
from localNode import localNode
old_tech=0
if old_tech:
    from solarissparcsyscallserver import solarissparc

#for Unixshell Nodes
from libs.ctelnetlib import Telnet
from shelllistener import shelllistener
from shelllistener import shellfromtelnet
from MOSDEFShellServer import MosdefShellServer

import canvasengine

class commandline_logger:

    def __init__(self, *fd):
        self.fileobjects = fd

    def write(self, string):

        for fileobject in self.fileobjects:
            fileobject.write(string)

    def flush( self ):
        for fileobject in self.fileobjects:
            fileobject.flush()

class interactiveServer:
    def __init__(self):
        port=""
        self.type       = ""
        self.mode       = "interactive"
        self.callback   = None
        self.command    = ""
        self.uploadfiles= []
        self.debug      = 0
        self.targets= [] #initialized from engine
        self.argsDict   = {}
        self.client     = None
        self.engine     = None
        # used for secondary callbacks...
        self.localport  = None
        self.localhost  = None
        self.infile     = None
        self.ipv6       = 0
        self.initstring = ""
        return

    def loadTargets(self):
        """
        Loads a list of potential targets from our engine.
        """
        import canvasengine
        self.targets = canvasengine.getAllListenerOptions()
        return

    def log(self,buf):
        """stub that prints out a string: buf"""
        #print buf
        self.engine.log(buf)


    def setMode(self,mode):
        self.mode=mode

    def setType(self,type):
        # see targets list for valid types
        self.type = type
        return

    def setConnectionCallback(self,callback):
        """
        register a callback - used by the engine to get statistics and stuff
        """
        self.callback=callback
        return

    def setPort(self,port):
        self.port=int(port)
        return

    def getPort(self):
        return self.port

    def doBind(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.set_timeout(None)
        listenhost=""
        listenport=self.port
        self.log("Binding to %s:%d"%(listenhost,listenport))
        s.bind((listenhost, listenport))
        s.listen(5)
        self.s=s
        return

    def doBind6(self):
        s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listenhost="::"
        listenport=self.port
        self.log("Binding to %s:%d"%(listenhost,listenport))
        s.bind((listenhost, listenport))
        s.listen(5)
        self.s=s
        return

    def getArgs(self):
        """This function will get arguments from some global places..."""
        #not finished
        if not self.localhost:
            self.localhost=getLocalIP()
            logging.info("Localhost set to %s" % self.localhost)
        return

    def run(self):
        self.getArgs()
        filename="listener-%d" % self.port
        try:
            os.unlink(filename)
        except :
            pass

        # start the proxy and change the type and port to regular win32 mosdef
        if self.type == canvasengine.HTTPMOSDEF:
            self.engine.set_callback_interface(self.localhost)
            if not self.engine.start_http_mosdef(self.port):
                logging.critical("commandline http_proxy failed")
                sys.exit(0)
            self.port += 1
            self.type = canvasengine.UNIVERSAL_MOSDEF

        # start the proxy and change the type and port to regular win64 mosdef
        #elif self.type == canvasengine.HTTPMOSDEF64:
        #    self.engine.set_callback_interface(self.localhost)
        #    if not self.engine.start_http_mosdef(self.port):
        #        print "XXX: commandline http_proxy failed ..."
        #        sys.exit(0)
        #    self.port += 1
        #    self.type = canvasengine.WIN64MOSDEF_INTEL

        # start the proxy and change the type and port to regular win64 mosdef
        #elif self.type == canvasengine.HTTPMOSDEF64_SSL:
        #    self.engine.set_callback_interface(self.localhost)
        #    if not self.engine.start_http_mosdef(self.port, ssl=True):
        #        print "XXX: commandline http_proxy failed ..."
        #        sys.exit(0)
        #    self.port += 1
        #    self.type = canvasengine.WIN64MOSDEF_INTEL

        # start the proxy and change the type and port to regular win32 mosdef
        elif self.type == canvasengine.HTTPMOSDEF_SSL:
            self.engine.set_callback_interface(self.localhost)
            if not self.engine.start_http_mosdef(self.port, ssl=True):
                logging.critical("commandline http_proxy failed")
                sys.exit(0)
            self.port += 1
            self.type = canvasengine.UNIVERSAL_MOSDEF

        # start the dns proxy and change the type and port to regular win32 mosdef
        elif self.type == canvasengine.DNSMOSDEF:
            self.engine.set_callback_interface(self.localhost)
            if not self.engine.start_dns_mosdef(self.localhost, self.port):
                logging.critical("commandline dns_proxy failed")
                sys.exit(0)
            self.type = canvasengine.WIN32MOSDEF

        if self.ipv6:
            logging.info("Switching MOSDEF into IPv6 mode")
            self.doBind6()
        else:
            self.doBind()

        while 1:
            #Here we write our listener-5555 file
            #this tells other commandline exploits that we succeeded.
            #AKA. If the file exists, we get a callback.
            devlog("commandline","[!] Listening on port %d ..."%self.port)

            try:
                self.s.set_timeout(None)
            except:
                devlog("commandline", "[!] likely a socket wrapper object, set_timeout not supported ...")

            conn, addr = self.s.accept()
            logging.info("Connected to by %s" % str(addr))
            f=file(filename, "w")
            self.client=addr
            self.handleConnection(conn)

        return

    def handleConnection(self,connection):

        try:
            connection.set_timeout(None)
        except:
            logging.warning("likely an ipv6 socket, set_timeout not supported")

        server = self.engine.new_node_connection(None, connection, mosdef_type=self.type)


        if self.mode=="interactive":
            logging.info("Letting user interact with server")
            if server:
                server.interact()
            else:
                logging.info("No server - exiting this shell")

        if server and hasattr(server, "disconnect"):
            server.disconnect()
        return

def printTargets(targets):
    for a in range(0, len(targets)):
        logging.info("%d) %s" % (a, targets[a]))

def usage(targets):
    print """
    Command Line Interface Version 1.0, Immunity, Inc.
    usage: commandlineInterface.py -p port -v <ver number> [-i initstring] [-l localip (for HTTP)]
    initstring values:
          fromcreatethread (used for MSRPC attacks, for example)
    """
    printTargets(targets)

#this stuff happens.
if __name__ == '__main__':

    ##Do pre run sanity checks
    canvasengine.license_check()

    logging.info("Running command line interface v 1.0")

    app = interactiveServer()

    import canvasengine
    engine=canvasengine.canvasengine(None)
    # sys.stdout = commandline_logger( sys.stdout, engine.logfile )
    app.engine=engine #set the app's engine here.
    app.loadTargets()

    app.setType("WIN32MOSDEF")
    port=""

    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"dp:c:u:v:i:l:df:X")
    except getopt.GetoptError:
        #print help
        usage(app.targets)
        sys.exit(2)
    i=0
    for o,a in opts:
        if o in ["-f"]:
            app.infile=a
        if o in ["-p"]:
            i+=1
            port=a
            app.setPort(a)
        if o in ["-c"]:
            app.command=a
            app.setMode("Run one command")
        if o in ["-d"]:
            app.localport=int(a)
        if o in ["-u"]:
            app.uploadfiles.append(a)
        if o in ["-i"]:
            a=a.replace("formcreatethread","fromcreatethread")
            app.argsDict[a]=1
        if o in ["-l"]:
            app.localhost=a

        # XXX: switches commandline mosdef into IPv6 mode ;)
        if o in ["-X"]:
            app.ipv6 = 1

        if o in ["-v"]:
            a=int(a)
            if a < len(app.targets) :
                i+=1
                app.setType(app.targets[a])
            else:
                logging.error("Unknown target")

    if i!=2 :
        usage(app.targets)
        sys.exit(0)

    try:
        engine.localsniffer.shutdown() #don't need this
    except:
        pass
    try:
        app.run()
    except timeoutsocket.Timeout:
        logging.error("Failed to run commandline (socket timed out - DEP?)")
