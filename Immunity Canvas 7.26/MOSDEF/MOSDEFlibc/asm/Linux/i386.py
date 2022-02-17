#! /usr/bin/env python

from C_headers import C_headers

# actually this file was coded as a kludge to bypass a
# MOSDEF limitation: define and call function pointers.
# maybe there is another asm optimization than can be
# held here.

class i386(C_headers):

    def __init__(self):
        # not initializing C_headers() on purposes.
        self.__i386_initLocalFunctions()

    def __i386_initLocalFunctions(self):

        self.localfunctions["debug"] = ("asm", """
        debug:
            int3
            ret
        """)

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

        self.localfunctions["checkvm"] = ("asm","""
        checkvm:
            xorl %eax, %eax
            subl $6, %esp
            sidt (%esp)
            movb 0x5(%esp), %al
            addl $6, %esp
            // We comment out the comparison logic below because we want to move it
            // to the client (python). We do the test and simply return the value.
            // jge 0xd0, 0xff --> vmware, 0xe8 virtual pc
            // from joanna's redpill thingy
            //     cmpb $0xd0,%al
            //     jg virtualmachine
            //     xorl %eax,%eax
            //  virtualmachine:
            // return value of !zero == virtualmachine
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
            pushl %ebx
            cpuid
            mov %edx, %eax

        _cpuid_proc_exit:
            popl %ebx
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
            pushl %ebx
            cpuid
            mov %ebx, %eax

        _cpuid_features_exit:
            popl %ebx
            movl %ebp, %esp
            popl %ebp
            ret

        _cpuid_features_fail:
            mov $0, %eax
            jmp _cpuid_features_exit
        """)

        self.add_header('<asm/i386.h>', {'function': ["callptr", "debug", "checkvm"]})


        self.add_header('<asm/stat.h>', {
            'structure': """


        struct stat {
          unsigned short st_dev;
          unsigned short __pad1;
          unsigned long st_ino;
          unsigned short st_mode;
          unsigned short st_nlink;
          unsigned short st_uid;
          unsigned short st_gid;
          unsigned short st_rdev;
          unsigned short __pad2;
          unsigned long  st_size;
          unsigned long  st_blksize;
          unsigned long  st_blocks;
          unsigned long  st_atime;
          unsigned long  __unused1;
          unsigned long  st_mtime;
          unsigned long  __unused2;
          unsigned long  st_ctime;
          unsigned long  __unused3;
          unsigned long  __unused4;
          unsigned long  __unused5;
        };"""})

