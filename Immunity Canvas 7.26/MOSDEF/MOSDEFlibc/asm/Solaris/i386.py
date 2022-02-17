#! /usr/bin/env python

from C_headers import C_headers

# actually this file was coded as a kludge to bypass a
# MOSDEF limitation: define and call function pointers.
# maybe there is another asm optimization than can be
# holded here.

class i386(C_headers):
    
    def __init__(self):
        # no initializing C_headers() on purposes.
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
            // jge 0xd0, 0xff --> vmware, 0xe8 virtual pc
            // from joanna's redpill thingy
            cmpb $0xd0,%al
            jg virtualmachine
            xorl %eax,%eax
            
        virtualmachine:
            // return value of !zero == virtualmachine
            ret
        """)

        self.add_header('<asm/i386.h>', {'function': ["callptr", "debug", "checkvm"]})

        #print "XXX: ADDING HEADER ASM/STAT.H"

        self.add_header('<asm/stat.h>', {
            'structure': """

        // XXX: this is only a valid struct stat for i386 !!!

        // XXX: Check for Solaris INTEL when we port to it !!!

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
        
