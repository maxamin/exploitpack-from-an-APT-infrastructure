#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from UNIX import UNIX
from BSD import BSD43
from SVR4 import SVR4
from OSF1 import OSF1

class AIX(OSF1, SVR4, BSD43, UNIX):
    
    # XXX those are 5.1 ppc values
    
    # <fcntl.h>
    
    _FNONBLOCK =  0x00000004
    _FAPPEND =    0x00000008
    _FCREAT =     0x00000100
    _FTRUNC =     0x00000200
    _FEXCL =      0x00000800
    _FNOCTTY =    0x00000800
    _FLARGEFILE = 0x04000000
    
    O_RDONLY = 0
    O_WRONLY = 1
    O_RDWR =   2
    
    #O_NDELAY = 0x04
    O_APPEND =    _FAPPEND
    O_NONBLOCK =  _FNONBLOCK
    O_LARGEFILE = _FLARGEFILE
    
    O_CREAT =  _FCREAT
    O_TRUNC =  _FTRUNC
    O_EXCL =   _FEXCL
    O_NOCTTY = _FNOCTTY
    
    F_DUPFD = 0
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    
    # <sys/socket.h>
    
    SOCK_STREAM = 1
    SOCK_DGRAM =  2
    SOCK_RAW =    3
    
    SO_DEBUG =     0x0001
    SO_REUSEADDR = 0x0004
    SO_KEEPALIVE = 0x0008
    SO_LINGER =    0x0080
    SO_ERROR =     0x1007
    SO_TYPE =      0x1008
    
    SOL_SOCKET = 0xffff
    
    AF_UNIX =   1
    AF_INET =   2
    AF_INET6 = 24
    
    PF_UNIX =  AF_UNIX
    PF_INET =  AF_INET
    PF_INET6 = AF_INET6
    
    MSG_OOB =  0x1
    MSG_PEEK = 0x2
    
    SHUT_RD =   0
    SHUT_WR =   1
    SHUT_RDWR = 2
    
    # <sys/signal.h>
    
    SIGBUS =  10
    SIGSTOP = 17
    SIGCONT = 19
    SIGCHLD = 20
    SIGUSR1 = 30
    SIGUSR2 = 31
    
    SIG_DFL = 0
    SIG_IGN = 1
    SIG_ERR = -1
    
    # <errno.h>
    
    EAGAIN =  11
    ENOTBLK = 15
    ETXTBSY = 26
    ENOMSG =  35
    ENOTSOCK = 57
    
    # <sys/poll.h>
    
    NO_TIMEOUT = 0
    INF_TIMEOUT = -1
    
    POLLIN = 0x0001
    POLLOUT = 0x0002
    POLLPRI = 0x0004
    POLLWRNORM = POLLOUT
    POLLRDNORM = 0x0010
    POLLSYNC = 0x8000
    
    POLLNVAL = POLLSYNC
    POLLERR = 0x4000
    POLLHUP = 0x2000
    
    def __init__(self, *args):
        UNIX.__init__(self)
        BSD43.__init__(self)
        SVR4.__init__(self)
        OSF1.__init__(self)
        self._AIX_initLocalFunctions()
    
    def _AIX_initLocalFunctions(self):
        
        self.createSyscall()

        self.localfunctions['debug'] = ('asm', """
            debug:
                trap
                blr
        """)

        self.localfunctions["sigemptyset"] = ("asm", """
            sigemptyset:
                stw r0, -4(r2)
                li r0, 0
                stw r0, 0(r2)
                stw r0, 4(r2)
                lwz r0, -4(r2)
                blr
        """)
        
        self.localfunctions["setegid"] = ("c", """
        #import "local", "syscall2" as "syscall2"
        //#import "int", "SYS_setgidx" as "SYS_setgidx"
        
        int setegid(int egid)
        {
            int i;
            
            i = syscall2(SYS_setgidx, 1, egid);
            
            return i;
        }
        """)
        
        self.localfunctions["getuid"] = ("c", """
        #import "local", "syscall1" as "syscall1"
        //#import "int", "SYS_getuidx" as "SYS_getuidx"
        
        int getuid()
        {
            int i;
            
            i = syscall1(SYS_getuidx, 2);
            
            return i;
        }
        """)
        
        self.localfunctions["geteuid"] = ("c", """
        #import "local", "syscall1" as "syscall1"
        //#import "int", "SYS_getuidx" as "SYS_getuidx"
        
        int geteuid()
        {
            int i;
            
            i = syscall1(SYS_getuidx, 1);
            
            return i;
        }
        """)
        
        self.localfunctions["getgid"] = ("c", """
        #import "local", "syscall1" as "syscall1"
        //#import "int", "SYS_getgidx" as "SYS_getgidx"
        
        int getgid()
        {
            int i;
            
            i = syscall1(SYS_getgidx, 2);
            
            return i;
        }
        """)
        
        self.localfunctions["getegid"] = ("c", """
        #import "local", "syscall1" as "syscall1"
        //#import "int", "SYS_getgidx" as "SYS_getgidx"
        
        int getegid()
        {
            int i;
            
            i = syscall1(SYS_getgidx, 1);
            
            return i;
        }
        """)
        
        self.localfunctions["dup"] = ("c", """
        #include <sys/fcntl.h>
        #import "local", "syscall3" as "syscall3"
        //#import "int", "SYS_kfcntl" as "SYS_kfcntl"
        //#import "int", "F_DUPFD" as "F_DUPFD"
        
        int dup(int oldfd)
        {
            int i;
            
            i = syscall3(SYS_kfcntl, oldfd, F_DUPFD, 0);
            
            return i;
        }
        """)
        
        self.localfunctions["dup2"] = ("c", """
        #include <sys/fcntl.h>
        #import "local", "syscall3" as "syscall3"
        //#import "int", "SYS_kfcntl" as "SYS_kfcntl"
        //#import "int", "F_DUPFD" as "F_DUPFD"
        
        int dup2(int oldfd, int newfd)
        {
            int i;
            
            i = syscall3(SYS_kfcntl, oldfd, F_DUPFD, newfd);
            
            return i;
        }
        """)
        
        self.localfunctions["wait"] = ("c", """
        #import "local", "syscall3" as "syscall3"
        //#import "int", "SYS_kwaitpid" as "SYS_kwaitpid"
        
        int wait(int *status)
        {
            int i;
            
            i = syscall3(SYS_kwaitpid, status, -1, 4);
            
            return i;
        }
        """)
        
        self.localfunctions["signal"] = ("c", """
        #import "local", "syscall3" as "syscall3"
        #import "local", "memset" as "memset"
        #import "local", "sigemptyset" as "sigemptyset"
        
        struct sigset {
            int _s[2];
        };
        
        struct sigaction {
            void *sa_handler;
            struct sigset sa_mask;
            int sa_flags;
        };
        
        int signal(int sig, void *func)
        {
            int i;
            struct sigaction sa;
            
            sa.sa_handler = func;
            sa.sa_flags = 0;
            memset(&sa.sa_mask, 0, 8);
            
            i = syscall3(SYS__sigaction, sig, &sa, 0);
            
            return i;
        }
        """)

        self.localfunctions['fstat.h'] = ("header", """
        struct stat {
            unsigned int st_dev;
            unsigned int st_ino;
            unsigned int st_mode;
            unsigned short st_nlink;
            unsigned short st_flag;
            unsigned int st_uid;
            unsigned int st_gid;
            unsigned int st_rdev;
            unsigned int st_size;
            unsigned int st_atime;
            unsigned int st_spare1;
            unsigned int st_mtime;
            unsigned int st_spare2;
            unsigned int st_ctime;
            unsigned int st_spare3;
            unsigned int st_blksize;
            unsigned int st_blocks;
            unsigned int st_vfstype;
            unsigned int st_vfs;
            unsigned int st_type;
            unsigned int st_gen;
            unsigned int st_reserved[10];
        };
        """)

        self.localfunctions["socket.h"]=("header","""
           struct sockaddr {
             unsigned short int family;
             char data[14];
           };

           struct sockaddr_in {
             unsigned short int family;
             unsigned short int port;
             unsigned int addr;
             char zero[8];
           };
        """)

        self.localfunctions['fstat'] = ("c", """
        #import "local", "syscall4" as "syscall4"
       
        int fstat(int fd, void *buf)
        {
            int i;

            i = syscall4(SYS_fstatx, fd, buf, 0, 0);
            
            return i;
        }
        """)

class AIX_powerpc(AIX):
    
    Endianness = 'big'
    
    _syscall_table = {
        '5.1': {
            'kfork': 3,
            'execve': 5,
            'kill': 20,
            '_exit': 36,
            'kwaitpid': 38,
            'setrlimit64': 55,
            'getrlimit64': 56,
            '_sigaction': 64,
            'times': 91,
            '_nsleep': 92,
            'getpeername': 119,
            'ngetpeername': 120,
            'getsockname': 121,
            'ngetsockname': 122,
            'getsockopt': 123,
            'setsockopt': 124,
            'shutdown': 125,
            'recvmsg': 126,
            'recv': 127,
            'nrecvfrom': 128,
            'recvfrom': 129,
            'nsendmsg': 130,
            'sendmsg': 131,
            'send': 132,
            'sendto': 133,
            'socketpair': 134,
            'accept': 135,
            'naccept': 136,
            'listen': 137,
            'bind': 138,
            'socket': 139,
            'connext': 140,
            'close': 158,
            'fsync': 160,
            'kpwrite': 161,
            'kwritev': 162,
            'kwrite': 163,
            'kpread': 164,
            'kreadv': 165,
            'kread': 166,
            'klseek': 167,
            '_lseek': 168,
            'lseek': 169,
            '_setsid': 170,
            '_setpgid': 171,
            '_setpgrp': 172,
            '_getpgrp': 174,
            '_getppid': 175,
            '_getpid': 177,
            'setuid': 179,
            'setuidx': 180,
            'getuidx': 181,
            'seteuid': 182,
            'setreuid': 183,
            'chdir': 184,
            'fchdir': 185,
            'chroot': 186,
            'fchmod': 187,
            'chmod': 188,
            'chown': 189,
            'lchown': 190,
            'fchown': 191,
            'fchownx': 192,
            'chownx': 193,
            'unlink': 194,
            'getdirent': 204,
            'kioctl32': 205,
            'kioctl': 206,
            'link': 207,
            'lockf': 209,
            'mkdir': 210,
            'mknod': 211,
            'creat': 214,
            'openx': 215,
            'open': 216,
            'rename': 218,
            'rmdir': 219,
            'fstatx': 220,
            'statx': 221,
            'symlink': 222,
            'readlink': 223,
            'sync': 224,
            'umask': 225,
            'umount': 227,
            'unameu': 228,
            'unamex': 229,
            'uname': 230,
            'ustat': 231,
            'utimes': 232,
            'getgidx': 238,
            '_poll': 250,
            '_select': 251,
            'brk': 256,
            'sbrk': 260,
            'getgroups': 280,
            'setgid': 281,
            'setgidx': 282,
            'setgroups': 283,
            'pipe': 288,
            'munmap': 296,
            'msync': 297,
            'mprotect': 298,
            'mmap': 299,
            'kfcntl': 319,

            # XXX: DOES NOT EXIT! AIX does lamo-fstat walk
            # XXX: we define it cuz our unistd.h imports it

            'getcwd': 999 
        },
        
        '5.2': {
            'kfork': 3,
            'execve': 5,
            '_exit': 37,
            'kwaitpid': 39,
            'setrlimit64': 56,
            'getrlimit64': 57,
            '_sigaction': 77,
            'times': 108,
            '_nsleep': 109,
            'nrecvmsg': 136,
            'nrecvmsg': 136,
            'getpeername': 140,
            'ngetpeername': 141,
            'getsockname': 142,
            'ngetsockname': 143,
            'getsockopt': 144,
            'setsockopt': 145,
            'shutdown': 146,
            'recvmsg': 147,
            'recv': 148,
            'nrecvfrom': 149,
            'recvfrom': 150,
            'nsendmsg': 151,
            'sendmsg': 152,
            'send': 153,
            'sendto': 154,
            'socketpair': 155,
            'accept': 156,
            'naccept': 157,
            'listen': 158,
            'bind': 159,
            'socket': 160,
            'connext': 161,
            'send_file': 168,
            'close': 181,
            'fsync': 183,
            'kpwrite': 184,
            'kwritev': 185,
            'kwrite': 186,
            'kpread': 187,
            'kreadv': 188,
            'kread': 189,
            'klseek': 190,
            '_lseek': 191,
            'lseek': 192,
            '_setsid': 193,
            '_setpgid': 194,
            '_setpgrp': 195,
            '_getpgrpx': 196,
            '_getpgrp': 197,
            '_getppid': 198,
            '_getpid': 200,
            'setuid': 202,
            'setuidx': 203,
            'getuidx': 204,
            'seteuid': 205,
            'setreuid': 206,
            'chdir': 207,
            'fchdir': 208,
            'chroot': 209,
            'fchmod': 210,
            'chmod': 211,
            'chown': 212,
            'lchown': 213,
            'fchown': 214,
            'fchownx': 215,
            'chownx': 216,
            'getdirent64': 226,
            'getdirent': 227,
            'kioctl32': 228,
            'kioctl': 229,
            'link': 230,
            'klockf': 231,
            'lockf': 232,
            'mkdir': 233,
            'mknod': 234,
            'creat': 237,
            'openx': 238,
            'open': 239,
            'rename': 241,
            'rmdir': 242,
            'fstatx': 243,
            'statx': 244,
            'symlink': 245,
            'readlink': 246,
            'sync': 248,
            'umask': 249,
            'umount': 251,
            'unameu': 252,
            'unamex': 253,
            'uname': 254,
            'unlink': 255,
            'ustat': 256,
            'utimes': 257,
            'getgidx': 263,
            '_poll': 294,
            '_select': 295,
            'brk': 300,
            'sbrk': 310,
            'getgroups': 361,
            'setgid': 362,
            'setgidx': 363,
            'setgroups': 364,
            'pipe': 374,
            'kmmap': 377,
            'munmap': 381,
            'msync': 382,
            'mprotect': 383,
            'mmap': 384,
            'kfcntl': 403,

            # XXX: DOES NOT EXIT! AIX does lamo-fstat walk
            # XXX: we define it cuz our unistd.h imports it

            'getcwd': 999 
        },
    }
    
    _aliases_table = [
        ('SYS_fork', 'SYS_kfork'),
        ('SYS_write', 'SYS_kwrite'),
        ('SYS_read', 'SYS_kread'),
        ('SYS_setsid', 'SYS__setsid'),
        ('SYS_getpid', 'SYS__getpid'),
        ('SYS_getppid', 'SYS__getppid'),
        ('SYS_poll', 'SYS__poll'),
        ('SYS_select', 'SYS__select'),
        ('SYS_fcntl', 'SYS_kfcntl'),
        ('SYS_getpgrp', 'SYS__getpgrp'),
        ('SYS_connect', 'SYS_connext'),
        ('SYS_waitpid', 'SYS_kwaitpid'),
        ('SYS_ioctl', 'SYS_kioctl'),
    ]
    
    def __init__(self, version = None):
        self.version = version
        AIX.__init__(self)
    
    def createSyscall(self):
        """
        
        -[ Kernel Extensions and Device Support Programming Concepts ]-
        
        a system call in the 32.bit kernel cannot return a long long value to a 32.bit application. In 32.bit mode, long long values are returned in a pair of general purpose registers, GPR3 and GPR4. Only GPR3 is preserved by the system call handler before it returns to the application. A system call in the 32.bit kernel can return a 64.bit value to a 64.bit application, but the saveretval64 kernel service must used.
        
        since a system call runs on its own stack, the number of arguments that can be passed to a system call is limited. The operating system linkage conventions specify that up to eight general purpose registers are used for parameter passing. If more parameters exist than will fit in eight registers, the remaining parameters are passed in the stack. Because a system call does not have direct access to the application's stack, all parameters for system calls must fit in eight registers.
        
        """
        TODO = """ LP64 data model """
        self.localfunctions["syscallN"] = ("asm", """
            ! XXX 32-Bit version only (ILP32 data model)
            syscallN: ! sp [0:r1][4:r2][...][208:

            ! trap
            !.long 0x7fe00008
            
                ! XXX: ok .. so we use r2 as the internal stack pointer
                ! XXX: for some reason in il2ppc.py .. so anything that 
                ! XXX: calls through to syscallN will have been using
                ! XXX: r2 as the sp ... why!??! .. this is not the ABI! 

                mflr r19
                
                ! XXX: this r2 business complicates life, because r2
                ! XXX: is TOC reg , so now we have to save it accross
                ! XXX: system calls ...
  
                stwu r2, -208(r2)       ! store word and update
                stmw r3, 4(r2)          ! save regs into stack
                addi r6, r20, errno_check - RESERVED_pcloc ! r20 is RESERVED_pcloc
                mtlr r6
                ! load args from the original entry frame r2
                lmw r3, 212(r2)         ! set args 3 ... 10
                lmw r11, 36(r2)         ! restore regs >= 11
                mr r13, r2              ! XXX: kludge to save TOC reg which we use as SP
                lwz r2, 208(r2)         ! set syscall num
                crorc 6, 6, 6           ! clr eq in cr6
                sc

                ! PPC ABI specifies cr0 Summary Overflow flag is set on syscall error
                ! MOSDEF convention is to negate the errno into the return value on error
                ! the errno is contained in r4 .. hopefully this is consistent :>
                ! NOTE: this means that error codes always have to be tested as < 0
                !
                ! UPDATE: SO doesn't seem to get set .. so checking for < 0 for now :/

            errno_check:
                xor r16, r16, r16
                cmpw r3, r16            ! 32 bit compare 
                bge syscallN_end        ! >= 0 .. no error .. assumption ..
                sub r3, r4, r16         ! subtract r4 from 0 to negate errno

            syscallN_end:
                mr r2, r13              ! XXX: kludge to restore TOC reg which we use as SP
                lmw r4, 8(r2)           ! restore regs
                mr r13, r3              ! r13 for MOSDEF retval
                lwz r3, 4(r2)           ! restore r3
                lwz r2, 0(r2)           ! restore sp
                mtlr r19
                blr
        """)

class AIX_rs6000(AIX):
    """
    TODO: verify #defines
    """
    
    Endianness = 'big'
    
    def __init__(self, version = None):
        self.version = version
        AIX.__init__(self)
    
    def createSyscall(self):
        # not yet implemented
        pass

