#! /usr/bin/env python

from riscparse import *
from arm9assembler import arm9assembler

class arm9parse(arm9assembler, riscparse):
    def __init__(self, runpass=1):
        riscparse.__init__(self, 'arm9', runpass)

    def p_linelist_2(self, p):
        'linelist : line linelist'

    def p_line_7(self, p):
        'line : OPCODE'
        self.value += [self.instruction(p[1], [])]

    def p_opcodearg_4(self, p):
        'opcodearg : ID'
        p[0] = self.resolvelabel(p[1])

    def order_long(self, longint):
        return intel_order(longint)

    def p_registerrange(self, p):
        '''registerrange : REGISTER SUBTRACT REGISTER
           registerrange : REGISTER
        '''
        #print 'XXX: register range'
        #for t in p: print repr(t)
        
        regs = []
        if len(p) == 4:
            for i in range(int(p[1][1:]), int(p[3][1:])+1):
                #print 'Appending reg: r%d' % i
                regs.append('r%d' % i)
            p[0] = regs
        else:
            p[0] = p[1]

    # XXX is there an easier way to define this in the grammar?
    def p_rlist(self, p):
        '''rlist : LBRACE registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE
           rlist : LBRACE registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
           rlist : LBRACE registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange COMMA registerrange RBRACE ROOF
        '''
        #for t in p: print repr(t)
        p[0] = p[1:]

    # deal with all the indexing addressing modes ... we deal with them in detail in the opcode handler
    def p_opcodearg_5(self, p):
        '''opcodearg : LBRACKET REGISTER COMMA REGISTER RBRACKET
           opcodearg : LBRACKET REGISTER RBRACKET
           opcodearg : LBRACKET REGISTER COMMA HASHICONST RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA HASHICONST RBRACKET
           opcodearg : LBRACKET REGISTER COMMA PLUS REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA PLUS REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET
           opcodearg : LBRACKET REGISTER COMMA SUBTRACT REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA SUBTRACT REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET
           opcodearg : LBRACKET REGISTER COMMA REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA REGISTER COMMA BARRELSHIFT HASHICONST RBRACKET
           opcodearg : LBRACKET REGISTER COMMA PLUS REGISTER RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA PLUS REGISTER RBRACKET
           opcodearg : LBRACKET REGISTER COMMA SUBTRACT REGISTER RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA SUBTRACT REGISTER RBRACKET
           opcodearg : LBRACKET REGISTER COMMA REGISTER RBRACKET BANG
           opcodearg : LBRACKET REGISTER COMMA REGISTER RBRACKET
           opcodearg : LBRACKET REGISTER RBRACKET COMMA HASHICONST
           opcodearg : LBRACKET REGISTER RBRACKET COMMA REGISTER
           opcodearg : LBRACKET REGISTER RBRACKET COMMA PLUS REGISTER
           opcodearg : LBRACKET REGISTER RBRACKET COMMA SUBTRACT REGISTER
           opcodearg : LBRACKET REGISTER RBRACKET COMMA REGISTER COMMA BARRELSHIFT HASHICONST
           opcodearg : LBRACKET REGISTER RBRACKET COMMA PLUS REGISTER COMMA BARRELSHIFT HASHICONST
           opcodearg : LBRACKET REGISTER RBRACKET COMMA SUBTRACT REGISTER COMMA BARRELSHIFT HASHICONST
        '''
        p[0] = ' '.join(p[1:])

    # deal with Rlist param to block data transfer
    def p_opcodearg_6(self, p):
        'opcodearg : rlist'
        regs = []
        for t in p[1]:
            if type(t) == type([]):
                for reg in t:
                    regs.append(reg)
            if type(t) == type(''):
                if t in self.registers and t not in regs:
                    regs.append(t)
                if t == '^':
                    regs.append(t)
        p[0] = regs

    # we treat barrelshifts as a constant and deal with them in the opcode handler
    def p_opcodearg_constant(self, p):
        '''opcodearg : HASHICONST
           opcodearg : HASHHCONST
           opcodearg : BARRELSHIFT HASHICONST
           opcodearg : BARRELSHIFT REGISTER
        '''
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = ' '.join(p[1:])

    def p_register(self, p):
        'register : REGISTER'
        if len(p) == 2:
            p[0] = p[1]
        else:
            p[0] = p[1] + p[2]

def getparser(runpass=1):
    return procgetparser(arm9parse, 
                        runpass=runpass, 
                        parsetab_name ='arm9_parsetab')

if __name__ == '__main__':
    testparser(getparser)
