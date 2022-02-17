#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from SVR4 import SVR4
from SunOS import SunOS
from asm.Solaris.i386 import i386


class Solaris(SVR4, SunOS):

    # <sys/mman.h>
    PROT_NONE  = 0x0
    PROT_READ  = 0x1
    PROT_WRITE = 0x2
    PROT_EXEC  = 0x4

    MAP_SHARED    = 0x01
    MAP_PRIVATE   = 0x02
    MAP_FIXED     = 0x10
    MAP_ANONYMOUS = 0x100
    MAP_FAILED    = -1

    # <sys/errno.h>
    
    ERESTART = 91
    # <sys/fcntl.h>
    
    O_RDONLY = 0
    O_WRONLY = 1
    O_RDWR =   2
    
    O_NDELAY =      0x04
    O_APPEND =      0x08
    O_NONBLOCK =    0x80
    O_LARGEFILE = 0x2000
    
    O_CREAT =  0x100
    O_TRUNC =  0x200
    O_EXCL =   0x400
    O_NOCTTY = 0x800
    
    F_DUPFD = 0
    F_GETFD = 1
    F_SETFD = 2
    F_GETFL = 3
    F_SETFL = 4
    F_DUP2FD = 9
    
    # <sys/socket.h>
    
    SOCK_DGRAM =  1
    SOCK_STREAM = 2
    SOCK_RAW =    4
    
    SO_DEBUG =     0x0001
    SO_REUSEADDR = 0x0004
    SO_KEEPALIVE = 0x0008
    SO_LINGER =    0x0080
    SO_ERROR =     0x1007
    SO_TYPE =      0x1008
    
    SOL_SOCKET = 0xffff
    
    AF_UNIX =   1
    AF_INET =   2
    AF_INET6 = 26
    AF_KEY =   27
    
    PF_UNIX =  AF_UNIX
    PF_INET =  AF_INET
    PF_INET6 = AF_INET6
    PF_KEY =   AF_KEY
    
    MSG_OOB =  0x1
    MSG_PEEK = 0x2
    
    SHUT_RD =   0
    SHUT_WR =   1
    SHUT_RDWR = 2
    
    # <signal.h>
    
    SIGBUS =  10
    SIGCHLD = 18
    SIGSTOP = 23
    
    SIG_DFL = 0
    SIG_ERR = -1
    SIG_IGN = 1
    
    # <sys/poll.h>
    
    POLLIN =     0x0001
    POLLPRI =    0x0002
    POLLOUT =    0x0004
    POLLRDNORM = 0x0040
    POLLWRNORM = POLLOUT
    
    POLLERR =    0x0008
    POLLHUP =    0x0010
    POLLNVAL =   0x0020
    
    # <netinet/in.h>
    
    IPPROTO_IP   = 0
    IPPROTO_ICMP = 1
    IPPROTO_TCP  = 6
    IPPROTO_UDP  = 17
    IPPROTO_IPV6 = 41
    IPPROTO_RAW  = 255
    
    INET_ADDRSTRLEN  = 16
    INET6_ADDRSTRLEN = 46
    
    # <sys/socketvar.h>
    
    SOV_STREAM     = 0
    SOV_DEFAULT    = 1
    SOV_SOCKSTREAM = 2
    SOV_SOCKBSD    = 3
    SOV_XPG4_2     = 4
    
    # <sys/resource.h>
    
    _RUSAGESYS_GETRUSAGE      = 0
    _RUSAGESYS_GETRUSAGE_CHLD = 1
    _RUSAGESYS_GETRUSAGE_LWP  = 2
    
    # http://cvs.opensolaris.org/source/xref/on/usr/src/uts/common/sys/syscall.h
    SYS_syscall             = 0
    SYS_exit                = 1
    SYS_fork                = 2
    SYS_forkall             = SYS_fork
    SYS_read                = 3
    SYS_write               = 4
    SYS_open                = 5
    SYS_close               = 6
    SYS_wait                = 7
    SYS_creat               = 8
    SYS_link                = 9
    SYS_unlink              = 10
    SYS_exec                = 11
    SYS_chdir               = 12
    SYS_time                = 13
    SYS_mknod               = 14
    SYS_chmod               = 15
    SYS_chown               = 16
    SYS_brk                 = 17
    SYS_stat                = 18
    SYS_lseek               = 19
    SYS_getpid              = 20
    SYS_mount               = 21
    SYS_umount              = 22
    SYS_setuid              = 23
    SYS_getuid              = 24
    SYS_stime               = 25
    SYS_pcsample            = 26
    SYS_alarm               = 27
    SYS_fstat               = 28
    SYS_pause               = 29
    SYS_utime               = 30
    SYS_stty                = 31
    SYS_gtty                = 32
    SYS_access              = 33
    SYS_nice                = 34
    SYS_statfs              = 35
    SYS_sync                = 36
    SYS_kill                = 37
    SYS_fstatfs             = 38
    SYS_pgrpsys             = 39
    SYS_xenix               = 40
    SYS_dup                 = 41

    # XXX: we have our own SYS_pipe handler due to retval specifics in pipe(2)
    # XXX: make sure you override this function in the dict with your own handler !
    # XXX: for any new archs ...
    SYS_pipe                = 42
 
    SYS_times               = 43
    SYS_profil              = 44
    SYS_plock               = 45
    SYS_setgid              = 46
    SYS_getgid              = 47
    SYS_signal              = 48
    SYS_msgsys              = 49
    SYS_syssun              = 50
    SYS_sysi86              = 50
    SYS_acct                = 51
    SYS_shmsys              = 52
    SYS_semsys              = 53
    SYS_ioctl               = 54
    SYS_uadmin              = 55
    SYS_utssys              = 57
    SYS_fdsync              = 58
    SYS_execve              = 59
    SYS_umask               = 60
    SYS_chroot              = 61
    SYS_fcntl               = 62
    SYS_ulimit              = 63
    SYS_tasksys             = 70
    SYS_acctctl             = 71
    SYS_exacctsys           = 72
    SYS_getpagesizes        = 73
    SYS_rctlsys             = 74
    SYS_issetugid           = 75
    SYS_fsat                = 76
    SYS_lwp_park            = 77
    SYS_sendfilev           = 78
    SYS_rmdir               = 79
    SYS_mkdir               = 80
    SYS_getdents            = 81
    SYS_privsys             = 82
    SYS_ucredsys            = 83
    SYS_sysfs               = 84
    SYS_getmsg              = 85
    SYS_putmsg              = 86
    SYS_poll                = 87
    SYS_lstat               = 88
    SYS_symlink             = 89
    SYS_readlink            = 90
    SYS_setgroups           = 91
    SYS_getgroups           = 92
    SYS_fchmod              = 93
    SYS_fchown              = 94
    SYS_sigprocmask         = 95
    SYS_sigsuspend          = 96
    SYS_sigaltstack         = 97
    SYS_sigaction           = 98
    SYS_sigpending          = 99
    SYS_context             = 100
    SYS_evsys               = 101
    SYS_evtrapret           = 102
    SYS_statvfs             = 103
    SYS_fstatvfs            = 104
    SYS_getloadavg          = 105
    SYS_nfssys              = 106
    SYS_waitsys             = 107
    SYS_waitid              = 107 #another way of calling it
    SYS_sigsendsys          = 108
    SYS_hrtsys              = 109
    SYS_acancel             = 110
    SYS_async               = 111
    SYS_priocntlsys         = 112
    SYS_pathconf            = 113
    SYS_mincore             = 114
    SYS_mmap                = 115
    SYS_mprotect            = 116
    SYS_munmap              = 117
    SYS_fpathconf           = 118
    SYS_vfork               = 119
    SYS_fchdir              = 120
    SYS_readv               = 121
    SYS_writev              = 122
    SYS_xstat               = 123
    SYS_lxstat              = 124
    SYS_fxstat              = 125
    SYS_xmknod              = 126
    SYS_clocal              = 127
    SYS_setrlimit           = 128
    SYS_getrlimit           = 129
    SYS_lchown              = 130
    SYS_memcntl             = 131
    SYS_getpmsg             = 132
    SYS_putpmsg             = 133
    SYS_rename              = 134
    SYS_uname               = 135
    SYS_setegid             = 136
    SYS_sysconfig           = 137
    SYS_adjtime             = 138
    SYS_systeminfo          = 139
    SYS_seteuid             = 141
    SYS_vtrace              = 142
    SYS_fork1               = 143
    SYS_sigtimedwait        = 144
    SYS_lwp_info            = 145
    SYS_yield               = 146
    SYS_lwp_sema_wait       = 147
    SYS_lwp_sema_post       = 148
    SYS_lwp_sema_trywait    = 149
    SYS_lwp_detach          = 150
    SYS_corectl             = 151
    SYS_modctl              = 152
    SYS_fchroot             = 153
    SYS_utimes              = 154
    SYS_vhangup             = 155
    SYS_gettimeofday        = 156
    SYS_getitimer           = 157
    SYS_setitimer           = 158
    SYS_lwp_create          = 159
    SYS_lwp_exit            = 160
    SYS_lwp_suspend         = 161
    SYS_lwp_continue        = 162
    SYS_lwp_kill            = 163
    SYS_lwp_self            = 164
    SYS_lwp_setprivate      = 165
    SYS_lwp_getprivate      = 166
    SYS_lwp_wait            = 167
    SYS_lwp_mutex_wakeup    = 168
    SYS_lwp_mutex_lock      = 169
    SYS_lwp_cond_wait       = 170
    SYS_lwp_cond_signal     = 171
    SYS_lwp_cond_broadcast  = 172
    SYS_pread               = 173
    SYS_pwrite              = 174
    SYS_llseek              = 175
    SYS_inst_sync           = 176
    SYS_kaio                = 178
    SYS_cpc                 = 179
    SYS_lgrpsys             = 180
    SYS_meminfosys          = SYS_lgrpsys
    SYS_rusagesys           = 181
    SYS_port                = 182
    SYS_pollsys             = 183
    SYS_tsolsys             = 184
    SYS_acl                 = 185
    SYS_auditsys            = 186
    SYS_processor_bind      = 187
    SYS_processor_info      = 188
    SYS_p_online            = 189
    SYS_sigqueue            = 190
    SYS_clock_gettime       = 191
    SYS_clock_settime       = 192
    SYS_clock_getres        = 193
    SYS_timer_create        = 194
    SYS_timer_delete        = 195
    SYS_timer_settime       = 196
    SYS_timer_gettime       = 197
    SYS_timer_getoverrun    = 198
    SYS_nanosleep           = 199
    SYS_facl                = 200
    SYS_door                = 201
    SYS_setreuid            = 202
    SYS_setregid            = 203
    SYS_install_utrap       = 204
    SYS_signotify           = 205
    SYS_schedctl            = 206
    SYS_pset                = 207
    SYS_sparc_utrap_install = 208
    SYS_resolvepath         = 209
    SYS_signotifywait       = 210
    SYS_lwp_sigredirect     = 211
    SYS_lwp_alarm           = 212
    SYS_getdents64          = 213
    SYS_mmap64              = 214
    SYS_stat64              = 215
    SYS_lstat64             = 216
    SYS_fstat64             = 217
    SYS_statvfs64           = 218
    SYS_fstatvfs64          = 219
    SYS_setrlimit64         = 220
    SYS_getrlimit64         = 221
    SYS_pread64             = 222
    SYS_pwrite64            = 223
    SYS_creat64             = 224
    SYS_open64              = 225
    SYS_rpcsys              = 226
    SYS_zone                = 227
    SYS_autofssys           = 228
    SYS_getcwd              = 229
    SYS_so_socket           = 230
    SYS_so_socketpair       = 231
    SYS_bind                = 232
    SYS_listen              = 233
    SYS_accept              = 234
    SYS_connect             = 235
    SYS_shutdown            = 236
    SYS_recv                = 237
    SYS_recvfrom            = 238
    SYS_recvmsg             = 239
    SYS_send                = 240
    SYS_sendmsg             = 241
    SYS_sendto              = 242
    SYS_getpeername         = 243
    SYS_getsockname         = 244
    SYS_getsockopt          = 245
    SYS_setsockopt          = 246
    SYS_sockconfig          = 247
    SYS_ntp_gettime         = 248
    SYS_ntp_adjtime         = 249
    SYS_lwp_mutex_unlock    = 250
    SYS_lwp_mutex_trylock   = 251
    SYS_lwp_mutex_init      = 252
    SYS_cladm               = 253
    SYS_umount2             = 255
    
    _aliases_table = [
        ('SYS__exit', 'SYS_exit'),
    ]
    
    def __init__(self, *args):
        SVR4.__init__(self)
        SunOS.__init__(self)
        self.add_generic_syscall('waitid', 'int', 'int idtype', 'int id', 'char *siginfo', 'int options')        
        
        self.localfunctions["socket"] = ("c", """
        #include <stddef.h>
        #include <sys/socketvar.h>

        #import "local", "syscall5" as "syscall5"
         
        //#import "int", "SYS_so_socket" as "SYS_so_socket"
        //#import "local", "debug" as "debug"
        
        int
        socket(int domain, int type, int protocol)
        {
            int i;
            
            i = syscall5(SYS_so_socket, domain, type, protocol, NULL, SOV_DEFAULT);
            
            // if retval < 0, it's -errno.
            if (i < 0) {
                return -1;
            }
            
            return i;
            }
        """)
                
        self.localfunctions["bind"] = ("c", """
        #include <stddef.h>
        #include <sys/socketvar.h>

        #import "local", "syscall3" as "syscall3"
        
        int
        bind(int sockfd, int *addr, int addrlen)
        {
            int i;
            i = syscall3(SYS_bind, sockfd, addr, addrlen);
            
            if (i < 0) {
                return -1;
            }
            
            return i;
        }
        """)                    
        
        self.localfunctions["dup2"] = ("c", """
        #include <unistd.h>
        #include <fcntl.h>

        int
        dup2(int oldfd, int newfd)
        {
            int i;
            
            i = syscall3(SYS_fcntl, oldfd, F_DUP2FD, newfd);
            
            return i;
        }
        """)
        
        self.localfunctions["getpgrp"] = ("c", """
        #include <unistd.h>
        
        int
        getpgrp(void)
        {
            int i;
            
            i = syscall1(SYS_pgrpsys, 0);
            
            return i;
        }
        """)
        
        self.localfunctions["setpgrp"] = ("c", """
        #include <unistd.h>
        
        int
        setpgrp(void)
        {
            int i;
            
            i = syscall1(SYS_pgrpsys, 1);
            
            return i;
        }
        """)
        
        self.localfunctions["getsid"] = ("c", """
        #include <unistd.h>
        
        int
        getsid(int pid)
        {
            int i;
            
            i = syscall2(SYS_pgrpsys, 2, pid);
            
            return i;
        }
        """)
        
        self.localfunctions["setsid"] = ("c", """
        #include <unistd.h>
        
        int
        setsid(void)
        {
            int i;
            
            i = syscall1(SYS_pgrpsys, 3);
            
            return i;
        }
        """)
        
        self.localfunctions["getpgid"] = ("c", """
        #include <unistd.h>
        
        int
        getpgid(int pid)
        {
            int i;
            
            i = syscall2(SYS_pgrpsys, 4, pid);
            
            return i;
        }
        """)
        
        self.localfunctions["setpgid"] = ("c", """
        #include <unistd.h>
        
        int
        setpgid(int pid, int pgid)
        {
            int i;
            
            i = syscall3(SYS_pgrpsys, 5, pid, pgid);
            
            return i;
        }
        """)
        
        self.localfunctions["ustat"] = ("c", """
        #include <sys/utssys.h>
        #include <unistd.h>
        #include <ustat.h>
        
        int
        ustat(int dev, void *obuf)
        {
            int i;
            
            i = syscall3(SYS_utssys, obuf, dev, UTS_USTAT);
            
            return i;
        }
        """)
        
        self.localfunctions["fusers"] = ("c", """
        #include <sys/utssys.h>
        #include <unistd.h>
        #include <ustat.h>
        
        int
        ustat(char *path, int flags, void *obuf)
        {
            int i;
            
            i = syscall4(SYS_utssys, path, flags, UTS_FUSERS, obuf);
            
            return i;
        }
        """)
        
        self.add_header('<sys/resource.h>', {
            'structure': """
                struct rlimit { // _FILE_OFFSET_BITS == 32
                    long rlim_cur;
                    long rlim_max;
                };""",
            # struct rusage
            'define': ["RLIMIT_CPU", "RLIMIT_FSIZE", "RLIMIT_DATA", "RLIMIT_STACK", "RLIMIT_CORE",
                       "_RUSAGESYS_GETRUSAGE", "_RUSAGESYS_GETRUSAGE_CHLD", "_RUSAGESYS_GETRUSAGE_LWP"],
            'function': ["getrlimit", "setrlimit", "getrusage"]
        })
        
        self.localfunctions["getrusage"] = ("c", """
        #include <sys/resource.h>
        #include <unistd.h>
        
        int
        getrusage(int who, void *r_usage)
        {
            int i;
            
            i = syscall3(SYS_rusagesys, _RUSAGESYS_GETRUSAGE, who, r_usage);
            
            return i;
        }
        """)

        # XXX: move this to fancy add struct method ...

        self.localfunctions["fstat.h"]=("header","""
        // XXX: now using the actual SOLARIS stat struct !

//typedef long    time_t;         /* time of day in seconds */
//typedef struct  timespec {              /* definition per POSIX.4 */
//        time_t          tv_sec;         /* seconds */
//        long            tv_nsec;        /* and nanoseconds */
//} timespec_t;
//typedef struct timespec timestruc_t;    /* definition per SVr4 */

        struct stat {
        unsigned long st_dev;
        unsigned long st_pad1[3];
        unsigned long st_ino;
        unsigned long st_mode;
        unsigned long st_nlink;
        unsigned long st_uid;
        unsigned long st_gid;
        unsigned long st_rdev;
        unsigned long st_pad2[2];
        unsigned long  st_size;
        unsigned long st_pad3;

        // timestruc_t st_atim;
        // timestruc_t st_mtim;
        // timestruc_t st_ctim;
        unsigned long  st_atime;
        unsigned long  __unused1;
        unsigned long  st_mtime;
        unsigned long  __unused2;
        unsigned long  st_ctime;
        unsigned long  __unused3;

        unsigned long  st_blksize;
        unsigned long  st_blocks;
        char st_fstype[16]; // _ST_FSTYPSZ
        long st_pad4[8];

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
             char pad[6];
           };
        """)

        self.localfunctions["sysinfo"]=("c","""
        #import "local", "syscall" as "syscall"
        int
        sysinfo(int request, char *buf, int buflen) {
          int i;
          i = syscall(139, request, buf, buflen);
          return i;
        }
        """)

    def initPlatformStaticFunctions(self, fd):
        """ inits all platform libc specific local functions """

        code="""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"

        int sendblock2self(char * buf, int size) {
          sendint(size);
          writeblock(FD,buf,size);
        }
        """
        code=code.replace("FD",str(fd))
        self.localfunctions["sendblock2self"]=("c",code)

        code="""
        #import "local","writeblock" as "writeblock"
        #import "local","strlen" as "strlen"
        #import "local","sendint" as "sendint"

        int writeblock2self(char * buf, int size) {
          writeblock(FD,buf,size);
        }
        """
        code=code.replace("FD",str(fd))
        self.localfunctions["writeblock2self"]=("c",code)

        self.localfunctions["writestring"]=("c","""
        #import "local","sendblock" as "sendblock"
        #import "local","strlen" as "strlen"
        int writestring(int fd, char * outstr) {
         sendblock(fd,outstr,strlen(outstr));
        }
        """)

        #our reliable reading function
        self.localfunctions["readblock"]=("c","""
        #import "local","read" as "read"
        #import "local","strlen" as "strlen"
        int readblock(int fd, char * outstr,int size) {
          int left;
          int i;
          char * p;
          left=size;
          p=outstr;
          while (left > 0) {
            i=read(fd,p,left);
            if (i<0) {
              return 0;
            }
            left=left-i;
            p=p+i;
          }
         return 1;
        }
        """)

        self.localfunctions["sendshort"]=("c","""
        #import "local","writeblock" as "writeblock"
        void sendshort(short tosend)
        {
           short i;
           i=tosend;
           writeblock(SOCKETFD, &i,2);
        }
        """.replace("SOCKETFD",str(fd)))
                
        
class Solaris_sparc(Solaris):
    
    Endianness = 'big'
    
    # <sys/fcntl.h>
    
    F_DUP2FD = 9
    
    def __init__(self, version = None):
        self.version = version
        Solaris.__init__(self)
        self.fd = 0
        # so we can compile local code we need to have syscallN
        self.initArchStaticFunctions(0)

    def initArchStaticFunctions(self, fd):
        """ inits all architecture specific local functions """
        self.fd = fd

        self.localfunctions["syscallN"] = ("asm", """
            syscallN:
                save %sp, -96, %sp
                ! local syscall number from first argument
                mov %i0, %g1
                mov %i1, %o0
                mov %i2, %o1
                mov %i3, %o2
                mov %i4, %o3
                mov %i5, %o4
                ld  [ %fp + 0x5c ], %o5 ! safe?
                ! call syscall
                ta  8
                ! store return value (errno on failure)
                mov %o0, %i0
                bcs,a syscall_waserror
                !old: mov 1,%l1 !one into %l1 (there was an error) in delay slot
                !old: mov %g0,%l1  ! (there was no error)
                ! if there was an error we negate the errno in the delayslot so we have similar
                ! behaviour to our linux style direct syscall 'libc'
                sub %g0,%o0,%i0
            syscall_waserror:
                !old: mov %l1, %i1
                ret
                ! restore in delayslot of ret
                restore
        """)

        self.localfunctions["debug"] = ("asm", """
        debug:
        save %sp, -96, %sp
        ! XXX: DEBUG TRACE TRAP
        ta 1
        ret
        restore
        """)

        #(type,code)
        self.localfunctions["sendint"]=("asm","""
        sendint:
        ! -(96+8)
        save %sp,-104,%sp
        st %i0,[%sp+96]
        mov FDVAL,%o0
        add %sp,96,%o1
        mov 4,%o2 
        mov 0,%o3
        mov 240,%g1
        !ta 1
        ta 8
        jmpl %i7+8,%g0
        restore
        """.replace("FDVAL",str(fd)))

        #print "Initialized sendint with fd=%s"% fd

        # int * fildes is ptr to int fildes[2]
        self.localfunctions["pipe"]=("asm","""
        pipe:
        mov %o0,%o2
        mov 42,%g1
        ta 8
        ! pipe syscall expects you to store results yourself, weirdos
        st %o0,[%o2]  
        st %o1,[%o2+4]
        jmpl %o7+8,%g0
        nop
        """)
        
        # temporary
        self.localfunctions["syscall"] = ("asm", self.localfunctions["syscallN"][1])
        
        if self.version not in ["2.10", "5.10", "10", 10]:
            self.localfunctions["getcwd"] = ("c", """
            #include <stddef.h>
            #include <unistd.h>
            //#warn "getcwd not implemented on Solaris %s"
    
            char *
            getcwd(char *buf, int size)
            {
                return NULL;
            }
            """ % str(self.version))
        
        self.localfunctions["geteuid"] = ("asm", """
            geteuid:
               mov SYS_getuid, %g1
               ta 8
               retl
               mov %o1, %o0
        """)
        
        self.localfunctions["getegid"] = ("asm", """
            getegid:
               mov SYS_getgid, %g1
               ta 8
               retl
               mov %o1, %o0
        """)
        
        self.localfunctions["getppid"] = ("asm", """
            getppid:
               mov SYS_getpid, %g1
               ta 8
               retl
               mov %o1, %o0
        """)



class Solaris_intel_constants:
    """Place to store some constants, so they dont get parsed into #defines by the libc init stuff"""
    # SYSCALL TYPE DEFINES

    LCALL = "lcall"
    SYSENTER = "sysenter"
    SYSCALL = "syscall"
    INT91 = "int91"
    # maps to value returned by CPUID function in the first stage loader in solarisx86shellcodegenerat$
    #SYSCALL_TYPE = { 0 : LCALL, 1 : LCALL, 2 : SYSCALL, 3 : SYSENTER, 4 : INT91}
    #SYSCALL_TYPE = { 0 : LCALL, 1 : LCALL, 2 : SYSCALL, 3 : INT91, 4 : INT91}
    # haha, so like, sun smoke crack. I'm just gonna use int91 for everything
    # until I get proved wrong, then I'll fix the lcall handler. I think. 
    # Sun's sysenter-enabled libc sneakily uses int91 for doing two-return-val syscalls
    # like pipe, and I didnt notice cause truss was using the libc wrapper behind my back.
    SYSCALL_TYPE = { 0 : INT91, 1 : INT91, 2 : INT91, 3 : INT91, 4 : INT91}

class Solaris_intel(Solaris, i386):
    
    Endianness = 'little'

    # <sys/fcntl.h>
    
    F_GETXFL = 45
       
    def __init__(self, version = None):
        self.version = version
        Solaris.__init__(self)
        i386.__init__(self)
        self.fd = 0
        # init arch functions by default int91 __ sys SYSCALL_MAP
        # we need to init them here so we have syscallN when we
        # want to compile local code .. without being on an active
        # solarisNode .. :>
        self.initArchStaticFunctions(0, 0)        

    def initArchStaticFunctions(self, fd, sysval):
        """ inits all architecture specific local functions """

        self.fd = fd

        self.localfunctions["syscall_sysenterN"] = ("asm", """
            syscallN:
                push %ebp
                movl %esp,%ebp
                pushl %ebx
                pushl %ecx
                mov 8(%ebp), %eax
                jmp syscall_sysenter_getloc
            syscall_sysenter_getloc_back:
                pop %edx    // addr of syscall_sysenter_out
                mov %ebp,%ecx  // %ecx points to arguments on stack
                addl $8,%ecx
                // syscall entry arguments 
                // ecx points to arguments to the systemcall (esp)
                // edx points to systemcall return in usermode 
                // eax holds the systemcall numbers
                mov %esp, %esi // stash our esp in esi, cause syscall clobbers it :(
                sysenter
                // rets to syscall_sysenter_out below, jmping over the next instruction
            syscall_sysenter_getloc:
                call syscall_sysenter_getloc_back
            syscall_sysenter_out:
                movl %esi,%esp
                movl 8(%ebp),%ebx
                cmpl $42,%ebx
                jne syscall_zomg
                int3
            syscall_zomg:
                jb syscallN_error
                jmp syscallN_out
            syscallN_error:
                cmp $ERESTART,%eax
                jne syscallN_noterestart
                mov $EINTR,%eax
                jmp syscalN_out
            syscallN_noterestart:
                xorl %ebx,%ebx
                subl %eax,%ebx
                movl %ebx,%eax 
            syscallN_out:
                popl %ecx
                popl %ebx
                movl %ebp,%esp
                popl %ebp
                ret
        """)
        
        self.localfunctions["syscall_int91N"] = ("asm", """
            // XXX: this logic is flawed .. you cant make esp point above
            // XXX: the saved values .. go into the syscall .. and expect
            // XXX: it not to clobber your saved values !
            syscallN:
                pushl %ebp
                movl %esp,%ebp
                pushl %ebx
                pushl %ecx
                // A. push through the max args so we dont tread on our saved values
                pushl 44(%ebp)
                pushl 40(%ebp)
                pushl 36(%ebp)
                pushl 32(%ebp)
                pushl 28(%ebp)
                pushl 24(%ebp)
                pushl 20(%ebp)
                pushl 16(%ebp)
                pushl 12(%ebp)
                pushl 8(%ebp) // has syscall val
                popl %eax // get syscall
                pushl %eax // save dummy ret
                int $0x91
                jb syscallN_error
                jmp syscallN_out
            syscallN_error:
                cmp $ERESTART,%eax
                jne syscallN_noterestart
                movl $EINTR,%eax
            syscallN_noterestart:
                xorl %ebx,%ebx
                subl %eax,%ebx
                movl %ebx,%eax // negative ERRNO as retval
            syscallN_out:
                addl $40,%esp // A. restore esp
                popl %ecx
                popl %ebx
                movl %ebp,%esp
                popl %ebp
                ret
        """)
                
        # Metl: Untested, cause causes SIGILL on my hardware. 
        self.localfunctions["syscall_syscallN"] = ("asm", """
            syscallN:
                pop %edx   // retaddr
                pop %eax   // syscall number
                push %edx  // original return address back on
                syscall
                mov (%esp), %edx
                push %edx
                jb syscallN_error
                ret
            syscallN_error:
                cmp $ERESTART,%eax
                jne syscallN_noterestart
                mov $EINTR,%eax
            syscallN_noterestart:
                not %eax
                ret
        """)

        self.localfunctions["syscall_lcallN"] = ("asm", """
            syscallN:
                pop %edx   // retaddr
                pop %eax   // syscall number
                push %edx  // original return address back on
                // lcall  $0x27,$0x0
                .long 0x0000009a
                //.word 0x0027
                .byte 0x00
                .byte 0x27
                .byte 0x00
                mov (%esp), %edx
                push %edx
                jb syscallN_error
                ret
            syscallN_error:
                cmp $ERESTART,%eax
                jne syscallN_noterestart
                mov $EINTR,%eax
            syscallN_noterestart:
                not %eax
                ret
        """)
        
        self.localfunctions["geteuid"] = ("asm", """
            geteuid:
               mov $SYS_getuid, %eax
               int $0x91
               mov %edx, %eax
               ret
               nop
        """)
        
        self.localfunctions["getegid"] = ("asm", """
            getegid:
               mov $SYS_getgid, %eax
               int $0x91
               mov %edx, %eax
               ret
               nop
        """)
        
        self.localfunctions["getppid"] = ("asm", """
            getppid:
               mov $SYS_getpid, %eax
               int $0x91
               mov %edx, %eax
               ret
               nop
        """)

        self.localfunctions["pipe"]=("asm","""
    pipe:
        push %ebp
        mov %esp,%ebp
        push $SYS_PIPE
        call syscallN
        jb pipe_out         // error, return as is
        mov 8(%ebp),%edi    // load eax into filedes[1]
        mov %eax,(%edi)
        mov %edx,4(%edi)
    pipe_out:
        mov %ebp,%esp
        pop %ebp
        ret
        """.replace("SYS_PIPE", str(42))) # SYS_pipe .. no access to defines from here

        # end of function inits

        # init syscall type
        self.setSyscallTypeCPUID(sysval)

        return

    def setSyscallTypeCPUID(self, val):
        good = False
                
        if type(val) in [int, long]:
            self.syscallType = Solaris_intel_constants.SYSCALL_TYPE[val]
            good = True
        else:
            if val in Solaris_intel_constants.SYSCALL_TYPE.values():
                self.syscallType = val
                good = True

        if good:
            self.setSyscallType(self.syscallType)
        else:
            raise ValueError("Invalid syscall type: %s. Known values are: %s" % (val, Solaris_intel_constants.SYSCALL_TYPE))

    def syscallArgToLabel(self, sc):
        """Given a name or numeric arg, returns the name of the self.function to use for sycalls"""
        x = None
        
        if type(sc) in [int, long]:
            x = Solaris_intel_constants.SYSCALL_TYPE[sc]
        else:
            for k,v in Solaris_intel_constants.SYSCALL_TYPE.iteritems():
                if sc == v:
                    x = v
                    break
            raise ValueError("Unknown syscall type: %s" % sc)

        return "syscall_" + x
        
    # Actual libc setSyscallType
    def setSyscallType(self, syscallType):
        SYSCALL_MAP={"lcall":"syscall_lcallN", "int91":"syscall_int91N", "sysenter":"syscall_sysenterN", "syscall":"syscall_syscallN"}
        if syscallType in SYSCALL_MAP.keys():
            self.localfunctions["syscallN"] = self.localfunctions[SYSCALL_MAP[syscallType]]
        else:
            raise ValueError("Invalid syscallType: %s, valid are %s" % (syscallType, SYSCALL_MAP.keys()))

Solaris_x86 = Solaris_intel
