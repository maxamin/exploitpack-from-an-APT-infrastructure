#! /usr/bin/env python

from subC import subC
from ANSI import ANSI

class Win32(ANSI, subC):

    def __init__(self):
        ANSI.__init__(self)
        subC.__init__(self)

# XXX hook
class Win32_intel(Win32):

    Endianness = 'little'

    def __init__(self, version = None):
        self.version = version
        Win32.__init__(self)

        self.localfunctions["_cpuid_proc"] = ("asm", """
        _cpuid_proc:
            pushl %ebp
            movl %esp, %ebp
            pushl %ebx
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
            pushl %ebx
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
            popl %ebx
            movl %ebp, %esp
            popl %ebp
            ret

        _cpuid_features_fail:
            mov $0, %eax
            jmp _cpuid_features_exit
        """)

Win32_x86=Win32_intel
