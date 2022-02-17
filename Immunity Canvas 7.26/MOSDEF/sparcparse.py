#! /usr/bin/env python
"""
sparcparse.py

SPARC parser for CANVAS

Some good reference material below:
http://www.owlnet.rice.edu/~comp320/2001/assignments/sparc_subset.html
"""

from riscparse import *
from sparcassembler import sparcassembler

class sparcparse(sparcassembler,riscparse):
    
    register_prefix = '%'
    
    def __init__(self,runpass=1):
        riscparse.__init__(self, 'sparc', runpass)
    
    def p_linelist_2(self,p):
        'linelist : line linelist'
    
    #def p_line_7(self,p):
    #    'line : OPCODE COMMA ID opcodeargslist ID COLON'
    #    self.value+=[self.instruction(p[1],[])]
    #    self.newlabel(p[2])
    
    def p_opcodearg_4(self,p):
        'opcodearg : ID'
        p[0]=self.resolvelabel(p[1])
    
    def p_register(self,p):
        'register : PERCENT ID'
        p[0]=p[1]+p[2]

def getparser(runpass=1):
    return procgetparser(sparcparse, runpass=runpass, parsetab_name="sparc_parsetab")

if __name__ == "__main__":
    testparser(getparser)

