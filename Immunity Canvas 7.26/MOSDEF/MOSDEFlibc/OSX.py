#! /usr/bin/env python

from Rhapsody import RhapsodyDR2
from Mach import Mach3
from FreeBSD import FreeBSD32, FreeBSD45
from internal.debug import devlog
from C_headers import C_headers

class OSX_Server(RhapsodyDR2):

    def __init__(self, *args):
        RhapsodyDR2.__init__(self)


class OSX_DP1(Mach3):

    def __init__(self, *args):
        Mach3.__init__(self)


class OSX_DP2(OSX_DP1, FreeBSD32):

    def __init__(self, *args):
        OSX_DP1.__init__(self)
        FreeBSD32.__init__(self)


class OSX_DP3(OSX_DP2):

    def __init__(self, *args):
        OSX_DP2.__init__(self)


class OSX_10_0(OSX_DP3):

    def __init__(self, *args):
        OSX_DP3.__init__(self)


class OSX_10_2(OSX_10_0, FreeBSD45):

    def __init__(self, *args):
        OSX_10_0.__init__(self)
        FreeBSD45.__init__(self)


class OSX_10_4(OSX_10_2):

    # <sys/syscall.h> automatically generated from syscalls.master

    SYS_syscall         = 0
    SYS_exit            = 1
    SYS_fork            = 2
    SYS_read            = 3
    SYS_write           = 4
    SYS_open            = 5
    SYS_close           = 6
    SYS_wait4           = 7
    SYS_link            = 9
    SYS_unlink          = 10
    SYS_chdir           = 12
    SYS_fchdir          = 13
    SYS_mknod           = 14
    SYS_chmod           = 15
    SYS_chown           = 16
    SYS_obreak          = 17
    SYS_ogetfsstat      = 18
    SYS_getfsstat       = 18
    SYS_getpid          = 20
    SYS_setuid          = 23
    SYS_getuid          = 24
    SYS_geteuid         = 25
    SYS_ptrace          = 26
    SYS_recvmsg         = 27
    SYS_sendmsg         = 28
    SYS_recvfrom        = 29
    SYS_accept          = 30
    SYS_getpeername     = 31
    SYS_getsockname     = 32
    SYS_access          = 33
    SYS_chflags         = 34
    SYS_fchflags        = 35
    SYS_sync            = 36
    SYS_kill            = 37
    SYS_getppid         = 39
    SYS_dup             = 41
    SYS_pipe            = 42
    SYS_getegid         = 43
    SYS_profil          = 44
    SYS_ktrace          = 45
    SYS_sigaction       = 46
    SYS_getgid          = 47
    SYS_sigprocmask     = 48
    SYS_getlogin        = 49
    SYS_setlogin        = 50
    SYS_acct            = 51
    SYS_sigpending      = 52
    SYS_sigaltstack     = 53
    SYS_ioctl           = 54
    SYS_reboot          = 55
    SYS_revoke          = 56
    SYS_symlink         = 57
    SYS_readlink        = 58
    SYS_execve          = 59
    SYS_umask           = 60
    SYS_chroot          = 61
    SYS_msync           = 65
    SYS_vfork           = 66
    SYS_sbrk            = 69
    SYS_sstk            = 70
    SYS_ovadvise        = 72
    SYS_munmap          = 73
    SYS_mprotect        = 74
    SYS_madvise         = 75
    SYS_mincore         = 78
    SYS_getgroups       = 79
    SYS_setgroups       = 80
    SYS_getpgrp         = 81
    SYS_setpgid         = 82
    SYS_setitimer       = 83
    SYS_swapon          = 85
    SYS_getitimer       = 86
    SYS_getdtablesize   = 89
    SYS_dup2            = 90
    SYS_fcntl           = 92
    SYS_select          = 93
    SYS_fsync           = 95
    SYS_setpriority     = 96
    SYS_socket          = 97
    SYS_connect         = 98
    SYS_getpriority     = 100
    SYS_bind            = 104
    SYS_setsockopt      = 105
    SYS_listen          = 106
    SYS_sigsuspend      = 111
    SYS_getrusage       = 117
    SYS_getsockopt      = 118
    SYS_readv           = 120
    SYS_writev          = 121
    SYS_settimeofday    = 122
    SYS_fchown          = 123
    SYS_fchmod          = 124
    SYS_rename          = 128
    SYS_flock           = 131
    SYS_mkfifo          = 132
    SYS_sendto          = 133
    SYS_shutdown        = 134
    SYS_socketpair      = 135
    SYS_mkdir           = 136
    SYS_rmdir           = 137
    SYS_utimes          = 138
    SYS_futimes         = 139
    SYS_adjtime         = 140
    SYS_setsid          = 147
    SYS_getpgid         = 151
    SYS_setprivexec     = 152
    SYS_pread           = 153
    SYS_pwrite          = 154
    SYS_nfssvc          = 155
    SYS_statfs          = 157
    SYS_fstatfs         = 158
    SYS_unmount         = 159
    SYS_getfh           = 161
    SYS_quotactl        = 165
    SYS_mount           = 167
    SYS_table           = 170
    SYS_waitid          = 173
    SYS_add_profil      = 176
    SYS_kdebug_trace    = 180
    SYS_setgid          = 181
    SYS_setegid         = 182
    SYS_seteuid         = 183
    SYS_stat            = 188
    SYS_fstat           = 189
    SYS_lstat           = 190
    SYS_pathconf        = 191
    SYS_fpathconf       = 192
    SYS_getfsstat       = 193
    SYS_getrlimit       = 194
    SYS_setrlimit       = 195
    SYS_getdirentries   = 196
    SYS_mmap            = 197
    SYS_lseek           = 199
    SYS_truncate        = 200
    SYS_ftruncate       = 201
    SYS___sysctl        = 202
    SYS_mlock           = 203
    SYS_munlock         = 204
    SYS_undelete        = 205
    SYS_kqueue_from_portset_np = 214
    SYS_kqueue_portset_np = 215
    SYS_mkcomplex       = 216
    SYS_statv           = 217
    SYS_lstatv          = 218
    SYS_fstatv          = 219
    SYS_getattrlist     = 220
    SYS_setattrlist     = 221
    SYS_getdirentriesattr = 222
    SYS_exchangedata    = 223
    SYS_searchfs        = 225
    SYS_delete          = 226
    SYS_copyfile        = 227
    SYS_poll            = 230
    SYS_watchevent      = 231
    SYS_waitevent       = 232
    SYS_modwatch        = 233
    SYS_getxattr        = 234
    SYS_fgetxattr       = 235
    SYS_setxattr        = 236
    SYS_fsetxattr       = 237
    SYS_removexattr     = 238
    SYS_fremovexattr    = 239
    SYS_listxattr       = 240
    SYS_flistxattr      = 241
    SYS_fsctl           = 242
    SYS_initgroups      = 243
    SYS_nfsclnt         = 247
    SYS_fhopen          = 248
    SYS_minherit        = 250
    SYS_semsys          = 251
    SYS_msgsys          = 252
    SYS_shmsys          = 253
    SYS_semctl          = 254
    SYS_semget          = 255
    SYS_semop           = 256
    SYS_semconfig       = 257
    SYS_msgctl          = 258
    SYS_msgget          = 259
    SYS_msgsnd          = 260
    SYS_msgrcv          = 261
    SYS_shmat           = 262
    SYS_shmctl          = 263
    SYS_shmdt           = 264
    SYS_shmget          = 265
    SYS_shm_open        = 266
    SYS_shm_unlink      = 267
    SYS_sem_open        = 268
    SYS_sem_close       = 269
    SYS_sem_unlink      = 270
    SYS_sem_wait        = 271
    SYS_sem_trywait     = 272
    SYS_sem_post        = 273
    SYS_sem_getvalue    = 274
    SYS_sem_init        = 275
    SYS_sem_destroy     = 276
    SYS_open_extended   = 277
    SYS_umask_extended  = 278
    SYS_stat_extended   = 279
    SYS_lstat_extended  = 280
    SYS_fstat_extended  = 281
    SYS_chmod_extended  = 282
    SYS_fchmod_extended = 283
    SYS_access_extended = 284
    SYS_settid          = 285
    SYS_gettid          = 286
    SYS_setsgroups      = 287
    SYS_getsgroups      = 288
    SYS_setwgroups      = 289
    SYS_getwgroups      = 290
    SYS_mkfifo_extended = 291
    SYS_mkdir_extended  = 292
    SYS_identitysvc     = 293
    SYS_load_shared_file = 296
    SYS_reset_shared_file = 297
    SYS_new_system_shared_regions = 298
    SYS_shared_region_map_file_np = 299
    SYS_shared_region_make_private_np = 300
    SYS_getsid          = 310
    SYS_settid_with_pid = 311
    SYS_aio_fsync       = 313
    SYS_aio_return      = 314
    SYS_aio_suspend     = 315
    SYS_aio_cancel      = 316
    SYS_aio_error       = 317
    SYS_aio_read        = 318
    SYS_aio_write       = 319
    SYS_lio_listio      = 320
    SYS_mlockall        = 324
    SYS_munlockall      = 325
    SYS_issetugid       = 327
    SYS___pthread_kill  = 328
    SYS_pthread_sigmask = 329
    SYS_sigwait         = 330
    SYS___disable_threadsignal = 331
    SYS___pthread_markcancel = 332
    SYS___pthread_canceled = 333
    SYS___semwait_signal = 334
    SYS_utrace          = 335
    SYS_audit           = 350
    SYS_auditon         = 351
    SYS_getauid         = 353
    SYS_setauid         = 354
    SYS_getaudit        = 355
    SYS_setaudit        = 356
    SYS_getaudit_addr   = 357
    SYS_setaudit_addr   = 358
    SYS_auditctl        = 359
    SYS_kqueue          = 362
    SYS_kevent          = 363
    SYS_lchown          = 364
    SYS_MAXSYSCALL      = 370

    def __init__(self, *args):
        OSX_10_2.__init__(self)
        self.initLocalFunctions()

    def initLocalFunctions(self):
        C_headers.add_header(self, '<sys/socket.h>', {
            'structure': """
                struct sockaddr {
                     unsigned char len;
                     unsigned char family;
                     char data[14];
                 };

                 struct sockaddr_storage {
                     char padding[128];
                 };
                 """,
            'function': ["socket", "connect", "accept", "listen", "bind", "getsockopt", "setsockopt",
                         "send", "sendto", "sendmsg", "recv", "recvfrom", "recvmsg","htonl","htons", 'shutdown']})

        C_headers.add_header(self, '<netinet/in.h>', {
            'structure': """
                 struct sockaddr_in {
                     unsigned char sin_len;
                     unsigned char sin_family;
                     unsigned short sin_port;
                     unsigned int sin_addr_s_addr;
                     char zero[8];
                 };
                 """})
        self.localfunctions["htonl"]=("c","""
        int htonl(unsigned int port) {
        unsigned int ret;
        unsigned int ret2;
        unsigned int ret3;
        unsigned int ret4;
        //debug();
        //ret=4;
        ret=port & 0x000000ff;
        ret=ret << 24;

        ret2=port & 0x0000ff00;
        ret2=ret2 << 8;

        ret3=port & 0x00ff0000;
        ret3=ret3 >> 8;

        ret4=port & 0xff000000;
        ret4=ret4 >> 24;

        ret=ret+ret2+ret3+ret4;
        return ret;
        }
        """)

        self.localfunctions["htons"]=("c","""
        int htons(unsigned short int port) {
        unsigned short ret;
        unsigned short ret2;
        ret=port & 0xff;
        ret=ret << 8;
        ret2=port & 0xff00;
        ret2=ret2 >> 8;
        ret=ret+ret2;
        return ret;
        }
        """)


class OSX_10_5(OSX_10_4):
    # <sys/syscall.h> automatically generated from syscalls.master
    # headers
    # sys/socket.h
    SOL_SOCKET    = 0xffff
    SO_DEBUG      = 0x0001
    SO_ACCEPTCONN = 0x0002
    SO_REUSEADDR  = 0x0004
    SO_KEEPALIVE  = 0x0008
    SO_DONTROUTE  = 0x0010
    SO_BROADCAST  = 0x0020
    SO_SNDBUF     = 0x1001
    SO_RCVBUF     = 0x1002
    SO_SNDLOWAT   = 0x1003
    SO_RCVLOWAT   = 0x1004
    SO_SNDTIMEO   = 0x1005
    SO_RCVTIMEO   = 0x1006
    SO_ERROR      = 0x1007
    SO_TYPE       = 0x1008
    SOCK_STREAM   = 1
    SOCK_DGRAM    = 2
    SOCK_RAW      = 3
    AF_INET       = 2
    # fcntl.h
    F_GETPATH     = 50
    O_RDONLY      = 0x0000
    O_RDWR        = 0x0002
    O_CREAT       = 0x0200
    O_TRUNC       = 0x0400
    O_RDONLY      = 0x0000
    O_WRONLY      = 0x0001
    O_RDWR        = 0x0002
    O_ACCMODE     = 0x0003
    O_NONBLOCK    = 0x0004
    O_BLOCK       = ~O_NONBLOCK
    O_APPEND      = 0x0008
    F_DUPFD       = 0
    F_GETFD       = 1
    F_SETFD       = 2
    F_GETFL       = 3
    F_SETFL       = 4
    F_GETOWN      = 5
    F_SETOWN      = 6
    F_GETLK       = 7
    F_SETLK       = 8
    F_SETLKW      = 9
    # sys/mman.h
    PROT_NONE     = 0x00
    PROT_READ     = 0x01
    PROT_WRITE    = 0x02
    PROT_EXEC     = 0x04
    MAP_SHARED    = 0x0001
    MAP_PRIVATE   = 0x0002
    MAP_FIXED     = 0x0010
    MAP_ANON      = 0x1000
    MAP_FAILED    = -1
    # netinet/in.h
    IPPROTO_TCP   = 6
    IPPROTO_UDP   = 17

    def __init__(self, *args):
        OSX_10_4.__init__(self)
        self.SYS__exit = self.SYS_exit # for generic syscall compatibility

class OSX_powerpc(OSX_10_5):
    Endianness = 'big'
    SYS_ppc_gettimeofday = 116
    SYS_gettimeofday     = 116
    SYS_sigreturn        = 184
    SYS_ATsocket         = 206
    SYS_ATgetmsg         = 207
    SYS_ATputmsg         = 208
    SYS_ATPsndreq        = 209
    SYS_ATPsndrsp        = 210
    SYS_ATPgetreq        = 211
    SYS_ATPgetrsp        = 212

    def __init__(self, *args):
        OSX_10_5.__init__(self)

class OSX_x86(OSX_10_5):
    Endianness       = 'little'
    SYS_sigreturn    = 103
    SYS_gettimeofday = 116
    SYS_ATsocket     = 206
    SYS_ATgetmsg     = 207
    SYS_ATputmsg     = 208
    SYS_ATPsndreq    = 209
    SYS_ATPsndrsp    = 210
    SYS_ATPgetreq    = 211
    SYS_ATPgetrsp    = 212

    def __init__(self, *args):
        OSX_10_5.__init__(self)
        self.createSyscall()
        C_headers.add_header(self, '<asm/i386.h>',
                             {'function' : ["callptr"]})

        self.localfunctions["callptr"] = ("asm", """
        callptr:
            pushl %ebp
            movl %esp,%ebp
            pushl %ebx
            mov 8(%ebp),%eax
            call *%eax
            popl %ebx
            movl %ebp,%esp
            popl %ebp
            ret
        """)

        self.localfunctions["_cpuid_proc"] = ("asm", """
        _cpuid_proc:
            pushl %ebp
            movl %esp, %ebp
            jmp _is_cpuid_proc_avail

        _is_cpuid_proc_avail:
            pushfd
            pushfd
            xor $0x00200000, (%esp)
            popfd
            pushfd
            pop %eax
            popfd
            and $0x00200000, %eax
            jnz _cpuid_proc_present
            jmp _cpuid_proc_fail

        _cpuid_proc_present:
            movl $0x80000001, %eax
            cpuid
            mov %edx, %eax

        _cpuid_proc_exit:
            movl %ebp, %esp
            popl %ebp
            ret

        _cpuid_proc_fail:
            mov $0, %eax
            jmp _cpuid_proc_exit
        """)

        self.localfunctions["_cpuid_features"] = ("asm", """
        _cpuid_features:
            pushl %ebp
            movl %esp, %ebp
            jmp _is_cpuid_features_avail

        _is_cpuid_features_avail:
            pushfd
            pushfd
            xor $0x00200000, (%esp)
            popfd
            pushfd
            pop %eax
            popfd
            and $0x00200000, %eax
            jnz _cpuid_features_present
            jmp _cpuid_features_fail

        _cpuid_features_present:
            xorl %ecx, %ecx                     // sub-leaf 0
            movl $0x7, %eax
            cpuid
            mov %ebx, %eax

        _cpuid_features_exit:
            movl %ebp, %esp
            popl %ebp
            ret

        _cpuid_features_fail:
            mov $0, %eax
            jmp _cpuid_features_exit
        """)

    # generates sycallN localfunctions
    def createSyscall(self):
        for n in range(0, 8):
            # the reason we save %ebx here is because it is 'special'
            # as dictated by il2x86.py .. ebx is the getpc reg ..
            # ala PIC .. we want to make sure it does not get clobbered
            code = """
            syscall%d:
            pushl %%ebp
            movl %%esp,%%ebp
            """ % n
            for i in range(0, n + 1):
                off = 4 * (2 + n - i) # adjust offset for ebx save here on first val ..
                # this is the last push
                if i == n:
                    code += "movl %d(%%ebp),%%eax\n" % off # syscall number
                    code += "pushl %eax\n"
                else:
                    # push through the arguments
                    code += "pushl %d(%%ebp)\n" % off
            code += """
            int $0x80
            movl %%ebp,%%esp
            popl %%ebp
            ret $%d
            """ % (4 * (n + 1))
            #print "XXX\n%s" % code
            self.localfunctions['syscall%d' % n] =  ('asm', code)


class OSX_x64(OSX_10_5):
    Endianness = 'little'

    def __init__(self, *args):
        self.LP64 = True
        OSX_10_5.__init__(self)
        self._OSX_x64_initLocalFunctions()

    def _OSX_x64_initLocalFunctions(self):
        self.createSyscall()
        C_headers.add_header(self, '<mosdef/asm.h>',
                             {'function' : ["callptr"]})

        self.localfunctions["callptr"] = ("asm", """
        callptr:
            pushq  %r15
            pushq  %rbp
            movq   %rsp, %rbp
            movq   24(%rbp), %rax
            call   *%rax
            movq   %rbp, %rsp
            popq   %rbp
            popq   %r15
            ret    $8
        """)

        self.localfunctions['debug'] = ('asm', """
        debug:
            int3
            ret
        """)

        self.localfunctions["_cpuid_proc"] = ("asm", """
        _cpuid_proc:
            pushq %rbp
            movq %rsp, %rbp
            jmp _is_cpuid_proc_avail

        _is_cpuid_proc_avail:
            pushfd
            pushfd
            xor $0x00200000, (%rsp)
            popfd
            pushfd
            pop %rax
            popfd
            and $0x00200000, %rax
            jnz _cpuid_proc_present
            jmp _cpuid_proc_fail

        _cpuid_proc_present:
            movl $0x80000001, %eax
            cpuid
            mov %rdx, %r13

        _cpuid_proc_exit:
            movq %rbp, %rsp
            popq %rbp
            ret

        _cpuid_proc_fail:
            mov $0, %r13
            jmp _cpuid_proc_exit
        """)

        self.localfunctions["_cpuid_features"] = ("asm", """
        _cpuid_features:
            pushq %rbp
            movq %rsp, %rbp
            jmp _is_cpuid_features_avail

        _is_cpuid_features_avail:
            pushfd
            pushfd
            xor $0x00200000, (%rsp)
            popfd
            pushfd
            pop %rax
            popfd
            and $0x00200000, %rax
            jnz _cpuid_features_present
            jmp _cpuid_features_fail

        _cpuid_features_present:
            xorl %ecx, %ecx                     // sub-leaf 0
            movl $0x7, %eax
            cpuid
            mov %rbx, %r13

        _cpuid_features_exit:
            movq %rbp, %rsp
            popq %rbp
            ret

        _cpuid_features_fail:
            mov $0, %r13
            jmp _cpuid_features_exit
        """)

    # generates sycallN localfunctions
    def createSyscall(self):
        devlog('MOSDEFLibC','OSXx64, creating syscall localfunctions')
        arg_map = { 1 : 'mov 24(%rbp),%rdi',
                    2 : 'mov 32(%rbp),%rsi',
                    3 : 'mov 40(%rbp),%rdx',
                    4 : 'mov 48(%rbp),%r10',
                    5 : 'mov 56(%rbp),%r8',
                    6 : 'mov 64(%rbp),%r9' }
        # XXX: Syscalls with more args
        for n in range(0, 7):
            # we dont need to save any register here, r15/rbp are not used by syscalls
            # ala PIC .. we want to make sure it does not get clobbered ^^^
            code = """
            syscall%d:
            pushq %%rbp
            movq %%rsp,%%rbp
            and $0xfffffffffffffff0,%%rsp
            """ % n
            stack_args = []
            reg_args   = []
            i          = 1

            while i <= n:
                if i in arg_map.keys():
                    reg_args.append('    '
                                    + arg_map[i]
                                    + ' // arg%d' % i
                                    + '\n')
                else:
                    stack_args.append('    '
                                      + 'push %d(%%rbp)' % (16+(8*i))
                                      + ' // arg%d' % i
                                      + '\n')
                i = i + 1


            if len(stack_args) % 2:
                # keep frame 16 aligned on call entry
                stack_args.append('    '
                                  + 'push %rax // frame align dummy\n')

            # order the arg ops in reverse for readability ...
            if len(stack_args):
                stack_args.reverse()
                code += ''.join(stack_args)
            if len(reg_args):
                reg_args.reverse()
                code += ''.join(reg_args)

            #XXX: portability by obscurity
            code += """
            mov 16(%rbp),%rax
            add $0x2000000,%rax
            syscall
            //r13 is the accumulator in MOSDEF
            movq %rax,%r13
            movq %rbp,%rsp
            popq %rbp
            ret
            """
            self.localfunctions['syscall%d' % n] =  ('asm', code)
            self.localfunctions['syscallN'] = ('asm', """
            syscallN:
                // this functions should not be reached
                int3
                ret
            """)
