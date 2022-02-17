#! /usr/bin/env python

from riscscan import *

class arm9lex(risclex):
    
    # hash is a const expression delimiter in arm syntax
    t_HASHICONST = r'[#]([-+])?\d+'
    t_HASHHCONST = r'[#]([-+])?0x([\da-fA-F])+'
    t_BANG = r'\!'
    t_ROOF = r'\^'

    def __init__(self):
        self.literals_init = self.literals_init + ('HASHICONST','HASHHCONST',)
        self.deliminators_init = self.deliminators_init + ('BANG','ROOF')
        risclex.__init__(self, 'arm9')

    def t_preprocessor(self, t):
        # hash expressions are common in ARM so we blank out the preprocessor directive
        # we will probably have to rethink how we deal with the preprocessor directives
        # and regular expression matching when we get to the C compiling stage
        # for now we have only simple HASH EXPRESSION support so anything that starts
        # with a-zA-Z can be assumed to be a preprocessor directive and left alone
        r'\#[a-zA-Z](.)*?\n'
        t.lineno += 1

    def t_ID(self, t):
        r'[.]?[\w_]+]\w]*|[a-zA-Z_][\w]*[!]?'
        #print 'XXX t_ID'
        #print t.value
        #print t.type

        if t.value in self.registers:
            t.type = 'REGISTER'
        elif t.value[-1] == '!' and t.value[:-1] in self.registers:
            t.type = 'REGISTER' # bang append to register, dealt with in opcode handler
        elif t.value[0] == '.' and t.value[1:] in self.tconsts:
            t.type = 'TCONST'
        elif t.value in self.barrel_shift:
            t.type = self.reserved_dict.get(t.value, 'BARRELSHIFT')
        elif t.value in self.opcodes:
            t.type = self.reserved_dict.get(t.value, 'OPCODE')
        else:
            t.type = self.reserved_dict.get(t.value, 'ID')

        return t

if __name__ == '__main__':
    testlexer('arm9')
