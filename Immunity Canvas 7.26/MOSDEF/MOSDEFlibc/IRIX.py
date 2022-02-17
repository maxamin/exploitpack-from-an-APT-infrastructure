#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from UNIX import UNIX

class IRIX(UNIX): # IRIX is Unix System III
    
    # <sys/fcntl.h>
    
    O_RDONLY = 0
    O_WRONLY = 1
    O_RDWR = 2
    O_NDELAY = 0x04
    O_APPEND = 0x08
    O_NONBLOCK = 0x80
    O_LARGEFILE = 0x2000
    
    O_CREAT = 0x100
    O_TRUNC = 0x200
    O_EXCL = 0x400
    O_NOCTTY = 0x800
    
    F_DUPFD = 0
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    
    # <sys/socket.h>
    
    SOCK_DGRAM = 1
    SOCK_STREAM = 2
    SOCK_RAW = 4
    
    SO_DEBUG = 0x0001
    SO_REUSEADDR = 0x0004
    SO_KEEPALIVE = 0x0008
    SO_LINGER = 0x0080
    SO_ERROR = 0x1007
    SO_TYPE = 0x1008
    
    SOL_SOCKET = 0xffff
    
    AF_LOCAL = 1
    AF_UNIX = AF_LOCAL
    AF_INET = 2
    AF_INET6 = 24
    
    PF_LOCAL = AF_LOCAL
    PF_UNIX = PF_LOCAL
    PF_INET = AF_INET
    PF_INET6 = AF_INET6
    
    MSG_OOB = 0x1
    MSG_PEEK = 0x2
    
    SHUT_RD = 0
    SHUT_WR = 1
    SHUT_RDWR = 2
    
    # <signal.h>
    
    SIGKILL = 9
    SIGBUS = 10
    SIGUSR1 = 16
    SIGUSR2 = 17
    SIGCLD = 18
    SIGCHLD = SIGCLD
    SIGSTOP = 23
    SIGCONT = 25
    
    SIG_ERR = -1
    SIG_IGN = 1
    SIG_DFL = 0
    
    def __init__(self, *args):
        UNIX.__init__(self)

class IRIX_mips(IRIX):
    
    Endianness = 'big'
    
    def __init__(self, version = None):
        self.version = version
        IRIX.__init__(self)

