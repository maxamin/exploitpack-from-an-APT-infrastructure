#! /usr/bin/env python
# -*- coding: utf-8 -*-

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
# vim: sw=4 ts=4 expandtab

from subC import subC
from ANSI import ANSI
from POSIX import POSIX

class UNIX(POSIX, ANSI, subC):
    
    def __init__(self):
        POSIX.__init__(self)
        ANSI.__init__(self)
        subC.__init__(self)
        self._UNIX_initLocalFunctions()
    
    def _UNIX_initLocalFunctions(self):
        #
        # every function in that class can be overwritten at upper levels
        # you want to overwrite if:
        # - a syscall acts differently on your architecture
        # - you have an optimized asm version of that code
        #
        
        ###########
        #
        # syscall% can be shortcut to syscallN
        #
        ###########
        
        for n in range(0, 8):
            code = """
            #import "local", "syscallN" as "syscallN"
            int syscall%d(int sysnum""" % n
            for i in range(0, n):
                code += ", int arg%d" % i
            code += """)
            {
                int i;
            
                i = syscallN(sysnum"""
            for i in range(0, n):
                code += ", arg%d" % i
            code += """);
            
                return i;
            }
            """
            # because this is a base class, even when our init ordering is messed up
            # we do not want it to redefine existing syscall definitions
            if not self.localfunctions.has_key("syscall%d" % n):
                self.localfunctions["syscall%d" % n] = ("c", code)

        ###########
        #
        # syscalls (syntax to add SYS_name: add_generic_syscall('name', 'return type', 'type argN'))
        #
        ###########
        
        # XXX
        # TODO: set C_header
        # TODO: includes support (i.e. fstat)
        # XXX
        #                         NAME     RETADDR  ARGS
        self.add_generic_syscall('umask', 'int', 'int mask')
        self.add_generic_syscall('_exit', 'void', 'int exitcode')
        self.add_generic_syscall('fork', 'int')
        self.add_generic_syscall('kill', 'int', 'int pid', 'int sig')
        self.add_generic_syscall('open', 'int', 'char *path', 'int oflag', 'int mode')
        self.add_generic_syscall('close', 'int', 'int fd')
        self.add_generic_syscall('unlink', 'int', 'char *path')
        self.add_generic_syscall('rename', 'int', 'char *oldpath', 'char *newpath')
        self.add_generic_syscall('mkdir', 'int', 'char *path', 'int mode')
        self.add_generic_syscall('rmdir', 'int', 'char *path')
        self.add_generic_syscall('read', 'int', 'int fd', 'char *buf', 'int nbytes')
        self.add_generic_syscall('write', 'int', 'int fd', 'char *buf', 'int nbytes')
        self.add_generic_syscall('execve', 'int', 'char *filename', 'char **argv', 'char **envp')
        self.add_generic_syscall('chdir', 'int', 'char *path')
        self.add_generic_syscall('fchdir', 'int', 'int fd')
        self.add_generic_syscall('getcwd', 'char *', 'char *buf', 'int size')
        self.add_generic_syscall('getwd', 'char *', 'char *buf')
        self.add_generic_syscall('getpid', 'int')
        self.add_generic_syscall('getppid', 'int')
        self.add_generic_syscall('getuid', 'int')
        self.add_generic_syscall('geteuid', 'int')
        self.add_generic_syscall('getgid', 'int')
        self.add_generic_syscall('getegid', 'int')
        self.add_generic_syscall('setuid', 'int', 'int uid')
        self.add_generic_syscall('seteuid', 'int', 'int euid')
        self.add_generic_syscall('setgid', 'int', 'int gid')
        self.add_generic_syscall('setegid', 'int', 'int egid')
        self.add_generic_syscall('dup', 'int', 'int oldfd')
        self.add_generic_syscall('dup2', 'int', 'int oldfd', 'int newfd')
        self.add_generic_syscall('fcntl', 'int', 'int fd', 'int cmd', 'long arg')
        self.add_generic_syscall('chmod', 'int', 'char *path', 'int mode')
        self.add_generic_syscall('fchmod', 'int', 'int fd', 'int mode')
        self.add_generic_syscall('chown', 'int', 'char *path', 'int owner', 'int group')
        self.add_generic_syscall('fchown', 'int', 'int fd', 'int owner', 'int group')
        self.add_generic_syscall('lchown', 'int', 'char *path', 'int owner', 'int group')
        self.add_generic_syscall('ioctl', 'int', 'int fd', 'unsigned long request', 'char *argp')
        self.add_generic_syscall('wait', 'int', 'int *status')
        self.add_generic_syscall('waitpid', 'int', 'int wpid', 'int *status', 'int options')
        #self.add_generic_syscall('wait3', 'int', 'int *status', 'int options', 'struct rusage *rusage')
        self.add_generic_syscall('wait4', 'int', 'int wpid', 'int *status', 'int options', 'void *rusage')
        self.add_generic_syscall('uname', 'int', "void *utsname")
        self.add_generic_syscall('readlink', 'int', 'char *path', 'char *buf', 'int bufsiz')

        # shared memory syscall are POSIX 1.b
        self.add_generic_syscall('mmap', 'void *', 'void *addr', 'int len', 'int prot', 'int flags', 'int fd', 'int offset')
        self.add_generic_syscall('munmap', 'int', 'void *addr', 'int len')
        self.add_generic_syscall('mprotect', 'int', 'void *addr', 'int len', 'int prot')

        # nanosleep is POSIX 1.b
        self.add_generic_syscall('nanosleep', 'int', 'void *req', 'void *rem')
        
        self.add_generic_syscall('stat', 'int', 'char *path', 'void *stat_st') # <sys/stat.h> and struct stat *
        self.add_generic_syscall('lstat', 'int', 'char *path', 'void *stat_st') # <sys/stat.h> and struct stat *
        self.add_generic_syscall('fstat', 'int', 'int fd', 'void *stat_st') # <sys/stat.h> and struct stat *
        self.add_generic_syscall('pipe', 'int', 'int *fildes')
        self.add_generic_syscall('poll', 'int', 'int *fds', 'int nfds', 'int timeout') # warning with struct pollfd
        # XXX fd_set, struct timeval *
        self.add_generic_syscall('select', 'int', 'int nfds', 'void *rfds', 'void *wfds', 'void *efds', 'void *tvtimeout')
        
        #include <sys/resource.h>: struct rlimit *
        self.add_generic_syscall('getrlimit', 'int', 'int resource', 'long *rlim')
        self.add_generic_syscall('setrlimit', 'int', 'int resource', 'long *rlim')
        self.add_generic_syscall('getrusage', 'int', 'int who', 'long *usage')
        
        # ANSI
        self.add_generic_syscall('signal', 'void *', 'int sig', 'void *sighandler') #XXX
        
        # POSIX.1, 4.2BSD, SVr4 mess
        self.add_generic_syscall('setpgid', 'int', 'int pid', 'int pgid')
        self.add_generic_syscall('getpgid', 'int', 'int pgid')
        self.add_generic_syscall('setpgrp', 'int')
        self.add_generic_syscall('getpgrp', 'int')
        
        # POSIX, SVr4
        self.add_generic_syscall('sigaction', 'int', 'int signum', 'void *act', 'void *oldact')
        self.add_generic_syscall('setsid', 'int')
        # <sys/socket.h>
        self.add_generic_syscall('socket', 'int', 'int domain', 'int type', 'int protocol')
        self.add_generic_syscall('socketpair', 'int', 'int d', 'int type', 'int protocol', 'int *sv')
        self.add_generic_syscall('connect', 'int', 'int sockfd', 'void *sa', 'int salen')
        self.add_generic_syscall('bind', 'int', 'int sockfd', 'void *sa', 'int salen')
        self.add_generic_syscall('listen', 'int', 'int sockfd', 'int backlog')
        self.add_generic_syscall('accept', 'int', 'int sockfd', 'void *sa', 'int *salen')
        self.add_generic_syscall('getsockopt', 'int', 'int fd', 'int level', 'int optname', 'void *optval', 'int *optlen')
        self.add_generic_syscall('setsockopt', 'int', 'int fd', 'int level', 'int optname', 'void *optval', 'int optlen')
        self.add_generic_syscall('recv', 'int', 'int fd', 'void *buf', 'int len', 'int flags')
        self.add_generic_syscall('send', 'int', 'int fd', 'void *buf', 'int len', 'int flags')
        self.add_generic_syscall('recvfrom', 'int', 'int fd', 'void *buf', 'int len', 'int flags', 'void *sa', 'int *salen')
        self.add_generic_syscall('sendto', 'int', 'int fd', 'void *buf', 'int len', 'int flags', 'void *sa', 'int salen')
        self.add_generic_syscall('recvmsg', 'int', 'int fd', 'void *msghdr', 'int flags')
        self.add_generic_syscall('sendmsg', 'int', 'int fd', 'void *msghdr', 'int flags')
        self.add_generic_syscall('getsockname', 'int', 'int sockfd', 'void *sa', 'int *salen')
        self.add_generic_syscall('getpeername', 'int', 'int sockfd', 'void *sa', 'int *salen')
        self.add_generic_syscall('shutdown', 'int', 'int sockfd', 'int how') 
        # GETDENTS
        self.add_generic_syscall('getdents', 'int', 'int fd', 'void *dirp', 'int count')

        self.add_generic_syscall('gettimeofday', 'int', 'void *tv', 'void *tz')
        self.add_generic_syscall('settimeofday', 'int', 'void *tv', 'void *tz')
        self.add_generic_syscall('statfs', 'int', 'char *path', 'void *buf')
        self.add_generic_syscall('access', 'int', 'char *pathname', 'int mode')
        self.add_generic_syscall('link', 'int', 'char *oldpath', 'char *newpath')

        #############
        #
        #  macros
        #
        #############
        
    def add_generic_syscall(self, name, type, *args): #(self, name, type, includes, *args):
        code = ""
        sargs = "void"
        fargs = ""
        nargs = len(args)
        assert self.localfunctions.has_key("syscall%d" % nargs) # should not happen, but in case...
        if args != ():
            sargs = ", ".join(args)
            fargs = list(args)
            for n in range(0, nargs):
                fargs[n] = args[n].split('*')[-1].split()[-1]
            fargs = ", " + ", ".join(fargs)
        #for include in includes:
        #    code += "        #include \"%s\"" % include
        if sargs == "void": # KLUDGE because MOSDEF does not know about void args and fails
            sargs = ""
        code += """
        #import "local", "syscall%d" as "syscall%d"
        // #import "int", "SYS_%s" as "SYS_%s"
        
        %s %s(%s)
        {
        """ % (nargs, nargs, name, name, type, name, sargs)
        if type != "void":
            code += "    %s retval;\n            \n            retval = " % type
        else:
            code += "    "
        code += "syscall%d(SYS_%s%s);\n" % (nargs, name, fargs)
        if type != "void":
            code += "        \n            return retval;\n"
        code += "        }\n"
        
        # redefine only when non-existant
        test = ""
        if not self.localfunctions.has_key(name):
            # define this function
            self.localfunctions[name] = ("c", code)
        #print "# %s\n" % name, code

