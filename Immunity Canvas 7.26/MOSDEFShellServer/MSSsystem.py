#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
# vim: sw=4 ts=4 expandtab

import os

from canvaserror import *
from MOSDEFShellServer.MSSerror import *

class MSSsystem:
    
    def memset(self, ptr, const_char, bytes):
        self.clearfunctioncache()
        request = self.compile("""
        #import "local", "memset" as "memset"
        #import "local", "sendint" as "sendint"
        #import "int", "ptr" as "ptr"
        #import "int", "const_char" as "const_char"
        #import "int", "bytes" as "bytes"
        
        int main()
        {
            int ret;
            
            memset(ptr, const_char, bytes);
            
            sendint(ret);
        }
        """, {'ptr': ptr, 'const_char': const_char, 'bytes': bytes})
        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        if (ret != ptr):
            print "ERROR memset() ret=0x%x" % ret
        
        return

    # can take either 0xaddress, or "abcd"
    def strcpy(self, outstr, instr):
        self.clearfunctioncache()
        # pointer or string handling
        ptrImports = ""

        try:
            int(outstr)
            ptrImports += '#import "int", "outstr" as "outstr"\n'
        except:
            ptrImports += '"#import "string", "outstr" as "outstr"\n'

        try:
            int(int)
            ptrImports += '#import "int", "instr" as "instr"\n'
        except:
            ptrImports += '#import "string", "instr" as "instr"\n'
            
        request = self.compile(ptrImports + """
        #import "local", "sendint" as "sendint"
        #import "local", "strcpy" as "strcpy"

        int main()
        {
            int ret;
            
            strcpy(outstr, instr);
            
            sendint(ret);
        }
        """, { 'outstr':outstr, 'instr':instr })

        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        return ret
    
    def bzero(self, ptr, size):
        return self.memset(ptr, 0, size)
    
    def close(self,fd):
        vars={}
        vars["fdtoclose"]=fd
        code="""
        //start of code
        #import "local","close" as "close"
        #import "local","sendint" as "sendint"
        #import "int","fdtoclose" as "fdtoclose"
        
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
        Get the pid of the process this shell is in
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
        Get the pid of the parent of the process this shell is in
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
        """
        Closes the shell. Call with exit code to use e.g. quit 0
        """
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

    def getuid(self):
        """
        Return the UID for this shell
        """
        vars = {}
        code = """
        #import "local","getuid" as "getuid"
        #import "local","sendint" as "sendint"
        
        void main()
        {
                int ret;

                ret = getuid();
                sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.uid = self.readint()
        self.leave()
        
        return self.uid
    
    def seteuid(self,euid):
        vars={}
        vars["euid"]=int(euid)
        code="""
        //start of code
        #import "local","seteuid" as "seteuid"
        #import "local", "sendint" as "sendint"
        #import "int","euid" as "euid"
        
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
        ret=self.readint()
        self.leave()
        
        return ret
    
    def ids(self):
        """
        Return the UID, EUID, GID and EGID for this shell
        """
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
        request = self.compile(code,vars)
        self.sendrequest(request)
        self.uid = self.readint() #we're gone!
        self.euid = self.readint() #we're gone!
        self.gid = self.readint() #we're gone!
        self.egid = self.readint() #we're gone!
        self.leave()
        
        return (self.uid, self.euid, self.gid, self.egid)
    
    def open(self,filename,flags,mode=None):
        vars = self.libc.getdefines()
        if not mode:
            mode = vars['MODE_ALL']
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
        code="""
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
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd=self.readint(signed=True)
        self.leave()
        
        return fd

    def link(self, oldpath, newpath):
        """
        Make a new name for a file
        """
        
        vars={}
        vars["oldpath"] = oldpath
        vars["newpath"] = newpath

        code = """
        #import "local","sendint" as "sendint"
        #import "local","link" as "link"
        #import "string","oldpath" as "oldpath"
        #import "string","newpath" as "newpath"
        
        void main()
        {
                int i;

                i = link(oldpath, newpath);
                sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def unlink(self,dir):
        """
        Unlinks (deletes) a file/dir
        """
        
        vars={}
        vars["dir"] = dir

        code = """
        #import "local","sendint" as "sendint"
        #import "local","unlink" as "unlink"
        #import "string","dir" as "dir"
        
        void main()
        {
          int i;
          i = unlink(dir);
          sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret
    
    def signal(self, signum, action):
        """
        Calls signal to get the signal handler set
        """
        vars                = {}
        vars["signum"]      = signum
        vars["sighandler"]  = action

        self.clearfunctioncache()
        request = self.compile("""
        #import "local", "sendint" as "sendint"
        #import "local", "signal" as "signal"
        
        #import "int", "signum" as "signum"
        #import "int", "sighandler" as "sighandler"
        
        void main()
        {
            int i;
            
            i = signal(signum, sighandler);
            
            sendint(i);
        }
        """, vars)

        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        
        return ret
    
    def getrlimit(self, resource):
        vars = self.libc.getdefines()
        vars['resource'] = resource
        self.clearfunctioncache()
        request = self.compile("""
        #include <sys/resource.h>
        
        #import "local", "sendint" as "sendint"
        #import "local", "getrlimit" as "getrlimit"
        
        #import "int", "resource" as "resource"
        
        void main()
        {
             int ret;
             struct rlimit rlim;
             
             ret = getrlimit(resource, &rlim);
             sendint(ret);
             
             if (ret != -1) {
                 sendint(rlim.rlim_cur);
                 sendint(rlim.rlim_max);
             }
        }
        """, vars)
        self.sendrequest(request)
        ret = self.readint()
        if (ret == -1):
            ret = []
        else:
            rlim_cur = self.readint()
            rlim_max = self.readint()
            ret = [rlim_cur, rlim_max]
        self.leave()
        
        return ret
    
    def setrlimit(self, resource, rlimit):
        vars = self.libc.getdefines()
        vars['resource'] = resource
        vars['rlim_cur'] = rlimit[0]
        vars['rlim_max'] = rlimit[1]
        self.clearfunctioncache()
        request = self.compile("""
        #include <sys/resource.h>
        
        #import "local", "sendint" as "sendint"
        #import "local", "setrlimit" as "setrlimit"
        
        #import "int", "resource" as "resource"
        #import "int", "rlim_cur" as "rlim_cur"
        #import "int", "rlim_max" as "rlim_max"
        
        void main()
        {
             int ret;
             struct rlimit rlim;
             
             rlim.rlim_cur = rlim_cur;
             rlim.rlim_max = rlim_max;
             ret = setrlimit(resource, &rlim);
             
             sendint(ret);
        }
        """, vars)
        self.sendrequest(request)
        ret = self.readint()
        #print "Ret=%s"%ret
        self.leave()
        
        return ret

    def kill(self, pid, sig):
        vars = self.libc.getdefines()
        vars['pid'] = pid
        vars['sig'] = sig
        self.clearfunctioncache()
        request = self.compile("""
        #include <signal.h>
        
        #import "local", "sendint" as "sendint"
        #import "local", "kill" as "kill"
        
        #import "int", "pid" as "pid"
        #import "int", "sig" as "sig"

        void main()
        {
             int ret;
             ret = kill(pid, sig);
             sendint(ret);
        }
        """, vars)

        self.sendrequest(request)
        ret = self.readint()
        #print "Ret=%s"%ret
        self.leave()
        
        return ret

    # XXX: I guess we don't want this fork her until
    # it can take 'fork this code' argument, used for DSU
    # for now, so please keep in place

    def fork(self):
        vars = self.libc.getdefines()
        self.clearfunctioncache()
        request = self.compile("""
        #import "local", "sendint" as "sendint"
        #import "local", "fork" as "fork"
        
        void main()
        {
             int ret;
             ret = fork();
             if (ret == 0)
             {
                 // child actions here
                 // this should be 'fork this code'
                 while(1) ret = 1;
             }
             else
             {
               sendint(ret);
             }
        }
        """, vars)

        self.sendrequest(request)
        ret = self.readint()
        #print "Ret=%s"%ret
        self.leave()
        
        return ret

    def mmap(self, start = 0, length = 0, prot = 0, flags = 0, fd = -1, offset = 0):
        vars = self.libc.getdefines()
        vars['start'] = start
        vars['length'] = length
        vars['prot'] = prot
        vars['flags'] = flags
        vars['fd'] = fd
        vars['offset'] = offset
        self.clearfunctioncache()
        request = self.compile("""
        #import "local", "sendint" as "sendint"
        #import "local", "mmap" as "mmap"
        
        #import "int", "start" as "start"
        #import "int", "length" as "length"
        #import "int", "prot" as "prot"
        #import "int", "flags" as "flags"
        #import "int", "fd" as "fd"
        #import "int", "offset" as "offset"
        
        void main()
        {
             int ret;
             
             ret = mmap(start, length, prot, flags, fd, offset);
             
             sendint(ret);
        }
        """, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        
        return ret
    
    def execve(self, filename, argv = [], envp = [], fork = 0):
        code = ""
        vars = self.libc.getdefines()
        vars["filename"] = filename
        for i in range(0, len(argv)):
            argi = "arg%d" % i
            vars[argi] = argv[i]
            code += '        #import "string", "%s" as "%s"\n' % (argi, argi)
        if envp != []:
            for i in range(0, len(envp)):
                envi = "env%d" % i
                vars[envi] = envp[i]
                code += '        #import "string", "%s" as "%s"\n' % (envi, envi)
        code += """
        #import "string", "filename" as "filename"
        #import "local","sendint" as "sendint"
        #include <mosdef.h>
        #include <unistd.h>
        #include <stddef.h>
        
        void main()
        {
          int ret;
          int pid;
        """
        
        if argv != []:
            code += "          char *argv[%d];\n" % (len(argv) + 1)
        if envp != []:
            code += "          char *envp[%d];\n" % (len(envp) + 1)
        
        if argv != []:
            #self.log("setting execve char **argv ... ")
            for i in range(0, len(argv)):
                code += "          argv[%d] = arg%d;\n" % (i, i)
            code += "          argv[%d] = NULL;\n" % (i + 1)
            argv = "argv"
        else:
            argv = "NULL"
        
        if envp != []:
            for i in range(0, len(envp)):
                code += "          envp[%d] = env%d;\n" % (i, i)
            code += "          envp[%d] = NULL;\n" % (i + 1)
            envp = "envp"
        else:
            envp = "NULL"

        if fork:
            #self.log("forking node execve ...")
            code += """
                pid = fork();

                if (pid == 0) {
                        ret = execve(filename, %s, %s);
                } else {
                        sendint(pid);
                }
            }
            """ % (argv, envp)
        else:
            #self.log("regular node execve ...")
            code += """ 
                ret = execve(filename, %s, %s);
            }
            """ % (argv, envp)
            
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)

        # If we forked off, return the pid of the child.
        if fork:
            ret = self.readint()
            self.leave()
            return ret

        self.leave()
        return None

    def waitpid(self, pid, options = 0):
        vars = self.libc.getdefines()
        vars['pid'] = pid
        vars['options'] = options

        self.clearfunctioncache()
        request = self.compile("""
        #include <errno.h>
        #import "local", "sendint" as "sendint"
        #import "local", "waitpid" as "waitpid"
        
        #import "int", "pid" as "pid"
        #import "int", "options" as "options"

        void main()
        {
                int status;
                int ret;

                do {
                        ret = waitpid(pid, &status, options);
                } while (ret == - EINTR);

                if (ret <= 0) {
                        sendint(ret);
                        return;
                }

                sendint(ret);
                sendint(status);
        }
        """, vars)

        self.sendrequest(request)

        ret = self.readint(signed = True)
        if ret < 0:
            self.leave()
            raise MSSError(-ret, "waitpid", os.strerror(-ret))

        if ret > 0:
            status = self.readint(signed = True)
        else:
            status = None

        self.leave()

        return ret, status

    def rename(self, oldpath, newpath):
        vars = self.libc.getdefines()
        vars['oldpath'] = oldpath
        vars['newpath'] = newpath

        self.clearfunctioncache()
        request = self.compile("""
        #include <errno.h>
        #import "local", "sendint" as "sendint"
        #import "local", "rename" as "rename"
        
        #import "string", "oldpath" as "oldpath"
        #import "string", "newpath" as "newpath"

        void main()
        {
                int ret;

                ret = rename(oldpath, newpath);
                sendint(ret);
        }
        """, vars)

        self.sendrequest(request)

        ret = self.readint(signed = True)
        self.leave()

        if ret < 0:
            raise MSSError(-ret, "rename", os.strerror(-ret))
