#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
# vim: sw=4 ts=4 expandtab

class POSIX:
    
    # <signal.h>
    
    SIGHUP =  1
    SIGQUIT = 3
    SIGTRAP = 5
    SIGKILL = 9
    SIGUSR1 = 10
    SIGUSR2 = 12
    SIGPIPE = 13
    SIGALRM = 14
    SIGCHLD = 17
    SIGCONT = 18
    SIGSTOP = 20
    
    # <sys/stat.h>
    
    S_IXOTH = 00001
    S_IWOTH = 00002
    S_IROTH = 00004
    S_IRWXO = 00007
    S_IXGRP = 00010
    S_IWGRP = 00020
    S_IRGRP = 00040
    S_IRWXG = 00070
    S_IXUSR = 00100
    S_IWUSR = 00200
    S_IRUSR = 00400
    S_IRWXU = 00700

    # <errno.h> POSIX 1003.1 of 1990
    # XXX you should verify your OS includes before using those
    
    EPERM =   1
    ENOENT =  2
    ESRCH =   3
    EINTR =   4
    EIO =     5
    ENXIO =   6
    E2BIG =   7
    ENOEXEC = 8
    EBADF =   9
    ECHILD =  10
    EDEADLK = 11
    ENOMEM =  12
    EACCES =  13
    EFAULT =  14
    EBUSY =   16
    EEXIST =  17
    EXDEV =   18
    ENODEV =  19
    ENOTDIR = 20
    EISDIR =  21
    EINVAL =  22
    ENFILE =  23
    EMFILE =  24
    ENOTTY =  25
    EFBIG =   27
    ENOSPC =  28
    ESPIPE =  29
    EROFS =   30
    EMLINK =  31
    EPIPE =   32
    EDOM =    33 # C89 Standard
    ERANGE =  34 # C89 Standard
    EAGAIN =  35
    
    # <unistd.h>
    
    STDIN_FILENO  = 0 #i'm not sure it's really POSIX
    STDOUT_FILENO = 1
    STDERR_FILENO = 2

    F_OK    = 0
    X_OK    = 1
    W_OK    = 2
    R_OK    = 4
    
    def __init__(self):
        pass

