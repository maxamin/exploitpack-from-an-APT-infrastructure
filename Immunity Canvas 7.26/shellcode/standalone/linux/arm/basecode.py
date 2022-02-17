# a _more respectful__ linux arm payload generator
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

import sys
if '.'  not in sys.path:  sys.path.append('.')

import urllib

from exploitutils import msunistring

class Globals:
    def __init__(self):
        self.data   = []
        self.names  = []

    # default can't be 0 .. for parsing semantics        
    def addDword(self, name, val = 0x41424344):
        if name not in self.names:
            self.data.append(("_get_dword", name, val))
            self.names.append(name) 
    
    def addUnicodeString(self, name, val):
        if name not in self.names:
            self.data.append(("_get_urllib", name,  msunistring(val)))
            self.names.append(name)

    def addString(self, name, val):
        if name not in self.names:
            self.data.append(("_get_urllib_nul", name, val))
            self.names.append(name)

    def addLabel(self, name):
        if name not in self.names:
            self.data.append(("_get_label", name, 0))
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
        self.functions      = ''
        self.main           = ''
        self._globals       = Globals()
        self.globals        = ''

        # code always starts with getpcloc
        self.getpcloc = """
        shellcodestart:
            ! GET PC
            mov      r10, r15
            sub      r10, r10, #8

            ! call main
            stmfd    sp!, {r14, r11}
            add      r11, r13, #8
            bl       main
        """

    def _set_globals(self):
        """ sets the globals section """
        self.globals = "globals:\n"
        self.globals += self._globals.get()
        return self.globals

    def __str__(self):
        return self.get()

    def get(self):
        """
        constructs and returns the final payload
        """
        asm = ''
        # we put the globals and functions _before_ main
        # so we get negative call offsets .. this reduces
        # the amount of encoding we have to do

        # in this order, always ..
        self._set_globals() # sets our globals

        asm += self.getpcloc
        asm += '\n'
        asm += self.globals
        asm += '\n'
        asm += '! END OF GLOBALS\n'
        asm += self.functions
        asm += '\n'
        asm += '! END OF FUNCTIONS\n'
        asm += 'main:\n' # entry point from pcloc
        asm += self.main
        asm += '\n'
        asm += '! END OF MAIN\n'
        asm += 'codeend:\n'

        # XXX: if you get YACC EOF errors .. this means you
        # XXX: are missing labels ...
   
        return asm

    def enable_debug(self):
        """ add a debug stub """
        if 'debug:' not in self.functions:
            self.functions += """
            
            debug:
                movw    r7, #1
                movt    r7, #15
                svc     #0
                mov     r12, r14
                ldmfd   sp!, {r14, r11}
                bx      r12
            """
