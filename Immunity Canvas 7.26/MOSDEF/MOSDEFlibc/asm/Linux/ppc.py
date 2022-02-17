#! /usr/bin/env python

from C_headers import C_headers

# actually this file was coded as a kludge to bypass a
# MOSDEF limitation: define and call function pointers.
# maybe there is another asm optimization than can be
# holded here.

class ppc(C_headers):
    
    def __init__(self):
        # no initializing C_headers() on purposes.
        self.__ppc_initLocalFunctions()
    
    def __ppc_initLocalFunctions(self):
        
        self.localfunctions["debug"] = ("asm", """
        debug:
            trap
        """)
        
        self.localfunctions["callptr"] = ("asm", """
        callptr:
            lwz r0, 0(r2)
            mtctr r0
            bctrl
        """)
        
        self.add_header('<asm/ppc.h>', {'function': ["callptr", "debug"]})

        #print "XXX: ADDING HEADER ASM/STAT.H"

        self.add_header('<asm/stat.h>', {
            'structure': ["""

        // XXX: this is only a valid struct stat for ppc32 installs !!!

        // XXX: annoying .. st_link and st_mode are reverse pending
        // XXX: pending whether or not it's a ppc64 processor ..
        // XXX: I think it depends on install tho .. and not actual CPU

        struct stat {
          unsigned long st_dev;
          unsigned long st_ino;
          unsigned long st_mode;
          unsigned long st_nlink;
          unsigned long st_uid;
          unsigned long st_gid;
          unsigned long st_rdev;
          unsigned long st_size;
          unsigned long st_blksize;
          unsigned long st_blocks;
          unsigned long st_atime;
          unsigned long st_atime_nsec;
          unsigned long st_mtime;
          unsigned long st_mtime_nsec;
          unsigned long st_ctime;
          unsigned long st_ctime_nsec;
          unsigned long __unused4;
          unsigned long __unused5;
          unsigned long __unused6;
        };""",
           
        """
        struct stat_ppc64 {
          unsigned long st_dev;
          unsigned long st_ino;
          unsigned long st_mode;
          unsigned long st_nlink;
          unsigned long st_uid;
          unsigned long st_gid;
          unsigned long st_rdev;
          unsigned long st_size;
          unsigned long st_blksize;
          unsigned long st_blocks;
          unsigned long st_atime;
          unsigned long st_atime_nsec;
          unsigned long st_mtime;
          unsigned long st_mtime_nsec;
          unsigned long st_ctime;
          unsigned long st_ctime_nsec;
          unsigned long __unused4;
          unsigned long __unused5;
          unsigned long __unused6;
        };""",

        """
        struct stat64_ppc {
          unsigned long st_dev[2]; // long long
          unsigned long st_ino[2];
          unsigned long st_mode;
          unsigned long st_nlink;
          unsigned long st_uid;
          unsigned long st_gid;
          unsigned long st_rdev[2];
          unsigned short __pad2;
          unsigned long st_size[2];
          unsigned long st_blksize;
          unsigned long st_blocks[2];
          unsigned long st_atime;
          unsigned long st_atime_nsec;
          unsigned long st_mtime;
          unsigned long st_mtime_nsec;
          unsigned long st_ctime;
          unsigned long st_ctime_nsec;
          unsigned long __unused4;
          unsigned long __unused5;
        };"""]})
