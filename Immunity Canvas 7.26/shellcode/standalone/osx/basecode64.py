# a _more respectful__ osx payload generator
#
# these operate under the assumption that you will be using
# mosdef.assemble() in your exploit on the returned code ..
#
# NOTE: add whatever you want!

USAGE = """
XXX: functions removed from this basecode, we are using syscalls.
XXX: Just ignore libraries and functions on the comments above.

This payload generator works on the concept of being a function
generator. Function calls made will be translated into a self.main
and a self.functions. Returned code then equals:

self.getpcloc + self.globals + self.functions + self.main

For example:

# get a code generator
codegen = basecode()
codegen.find_function('kernel32!loadlibrarya')
codegen.loadlibrary('ws2_32.dll')
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
    def __init__(self):
        self.heading        = ''
        self.functions      = ''
        self.main           = ''
        self._globals       = Globals()
        self.globals        = ''
        # code always starts with getpcloc
        self.getpcloc = """
        shellcodestart:
            jmp findyou
        retpcloc:
            // save the pcloc as base pointer ..
            mov (%rsp),%rbp
            ret
        findyou:
            call retpcloc
        getpcloc:
            // 16 byte stack alignment
            xor %rbx, %rbx
            sub $0x10, %rbx
            and %rbx, %rsp

            // MAIN
            jmp main
        """

    def _set_globals(self):
        """ sets the globals section """
        self.globals = "globals:\n"
        self.globals += self._globals.get()
        return self.globals

    def __str__(self):
        return self.get()

    def get(self):
        """ constructs and returns the final payload """
        asm = ''
        # we put the globals and functions _before_ main
        # so we get negative call offsets .. this reduces
        # the amount of encoding we have to do

        # in this order, always ..
        self._set_globals() # sets our globals

        asm += self.heading
        asm += '\n'
        asm += self.getpcloc
        asm += '\n'
        asm += self.globals
        asm += '\n'
        asm += '// END OF GLOBALS\n'
        asm += 'main:\n' # entry point from pcloc
        asm += self.main
        asm += '\n'
        asm += 'codeend: // END OF MAIN\n'

        # XXX: if you get YACC EOF errors .. this means you
        # XXX: are missing labels ...
   
        return asm

    def insertHeadingCode(self, code):
        self.heading = code
        return 
