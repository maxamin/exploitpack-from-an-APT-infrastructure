#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
PPC shellcode generator
"""


import random
from exploitutils import *
from MOSDEF import mosdef
from mosdef_shellcodeGenerator import shellcodeGenerator

class ppc(shellcodeGenerator):
    def __init__(self):
        shellcodeGenerator.__init__(self)
        self.findeipcode=""
        self.arch="PPC"
        self.normalizedstack=0
        self.foundeip=0
        self.handlers["findeip"]=self.findeip
        self.reset()
    
    def reset(self):
        shellcodeGenerator.reset(self)
        self.code=""
    
    def finalize(self):
        #print "Self.code=%s"%self.code
        bin=mosdef.assemble(self.code,self.arch)
        self.value=bin
        return bin
        
    def findeip(self,args):
        #print "Findeip called"
        if self.foundeip:
            return
        
        # Get ip
        code="""
        RESERVED_getpc:
            xor.  r6,r6,r6
            bnel  RESERVED_getpc
            mflr  r31
            """
        
        self.code+=code
        #print "findeip code=%s"%self.code
        self.foundeip=1
        
