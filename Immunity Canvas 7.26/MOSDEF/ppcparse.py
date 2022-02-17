#! /usr/bin/env python
"""
ppcparse.py

PPC parser for CANVAS

"""

import mosdefutils
from riscparse import *
from ppcassembler import ppcassembler

class ppcparse(ppcassembler, riscparse):
    def __init__(self, runpass=1):
        riscparse.__init__(self, 'ppc', runpass)
    
    def p_linelist_2(self,p):
        'linelist : line linelist'
        #"""linelist : line newlinelist linelist
        #   linelist : newlinelist linelist
        #   linelist : 
        #"""
    
    #def p_newlinelist(self,p):
    #    """newlinelist : NEWLINE
    #        newlinelist : NEWLINE newlinelist
    #    """
    
    def p_line_7(self, p):
        'line : OPCODE'
        self.value+= [self.instruction(p[1], [])]
    
    #def p_line_9(self, p):
    #    'line : NEWLINE NEWLINE'
    #    pass
    
    def p_opcodearg_4(self,p):
        'opcodearg : ID'
        p[0]=self.resolvelabel(p[1]) - self.length
    
    def p_expression_2(self,p):
        'expression : number LPAREN expressionlist RPAREN'
        p[0]=(p[1], p[3])
    
    def p_register(self,p):
        '''register : REGISTER
           register : PERCENT REGISTER
           '''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = p[1] + p[2]

    #def p_branchcode(self,p):
    #    'branchcode : BRANCHCODE'
    #    p[0]=p[1]

def getparser(runpass=1):
    return procgetparser(ppcparse, runpass=runpass, parsetab_name="ppc_parsetab")

if __name__ == "__main__":
    testparser(getparser)

