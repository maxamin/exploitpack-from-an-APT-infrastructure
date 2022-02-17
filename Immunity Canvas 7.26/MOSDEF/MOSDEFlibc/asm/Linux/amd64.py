#! /usr/bin/env python

from C_headers import C_headers

class amd64(C_headers):

    def __init__(self):
        # not initializing C_headers() on purposes.
        self.__amd64_initLocalFunctions()

    def __amd64_initLocalFunctions(self):

        self.localfunctions["debug"] = ("asm", """
        debug:
            int3
            ret
        """)

        self.localfunctions["callptr"] = ("asm", """
        callptr:
            pushq %r15
            pushq %rbp
            movq  %rsp,%rbp
            movq  24(%rbp), %rax
            call  *%rax
            movq  %rbp,%rsp
            popq  %rbp
            popq  %r15
            ret $8
        """)

        self.localfunctions["checkvm"] = ("asm","""
        checkvm:
            // TODO
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
            push %rbx
            cpuid
            mov %rdx, %r13

        _cpuid_proc_exit:
            pop %rbx
            movq %rbp, %rsp
            popq %rbp
            xorl %eax, %eax
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
            push %rbx
            cpuid
            mov %rbx, %r13

        _cpuid_features_exit:
            pop %rbx
            movq %rbp, %rsp
            popq %rbp
            ret

        _cpuid_features_fail:
            mov $0, %r13
            jmp _cpuid_features_exit
        """)

        self.add_header('<asm/stat.h>', {
            'structure': """


        struct stat {
          unsigned long long st_dev;
          unsigned long long st_ino;
          unsigned long long st_nlink;

          unsigned int       st_mode;
          unsigned int       st_uid;
          unsigned int       st_gid;
          unsigned int       pad0;
          unsigned long long st_rdev;
          unsigned long long st_size;
          unsigned long long st_blksize;
          unsigned long long st_blocks;

          unsigned long long st_atime;
          unsigned long long st_atimensec;
          unsigned long long st_mtime;
          unsigned long long st_mtimensec;
          unsigned long long st_ctime;
          unsigned long long st_ctimensec;

          unsigned long long unused1;
          unsigned long long unused2;
          unsigned long long unused3;
        };"""})
        self.add_header('<asm/amd64.h>', {'function': ["callptr", "debug", "checkvm"]})
