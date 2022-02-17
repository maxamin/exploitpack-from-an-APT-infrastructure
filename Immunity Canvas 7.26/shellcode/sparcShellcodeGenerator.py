#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
SPARC shellcode generator
"""


import random
from MOSDEF import mosdef
from exploitutils import *
from mosdef_shellcodeGenerator import shellcodeGenerator

class sparc(shellcodeGenerator):
    def __init__(self):
        shellcodeGenerator.__init__(self)
        self.findeipcode=""
        self.arch="SPARC"
        self.code=""
        self.normalizedstack=0
        self.foundeip=0
        self.handlers["findeip"]=self.findeip
                
        
    def finalize(self):
        #print "Self.code=%s"%self.code
        bin=mosdef.assemble(self.code,self.arch)
        self.value=bin
        return bin
        
    def findeip(self,args):
        #print "Findeip called"
        if self.foundeip:
            return
        
        #sets o7 to be a nice scratchspace
        code="""
        find_location1:
            bn,a find_location1-4
        find_location1_helper:
            bn,a find_location1
        call_dest:
            call   find_location1_helper 
            nop
            !our length is in %l1
            sub %o7,0x100, %o7 !get me away from the current location a bit
            """
        self.code+=code
        #print "findeip code=%s"%self.code
        self.foundeip=1
        
