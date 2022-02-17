#! /usr/bin/env python

"""
ppcscan.py

PPC lexer for CANVAS

"""

from riscscan import *

branchcode=["lt", "eq", "gt", "so"]


class ppclex(risclex):
    def __init__(self):
        self.literals = ("BRANCHCODE",)
        risclex.__init__(self, 'ppc')
    
    def t_ID(self,t):
        r'[.]?[a-zA-Z_]+[\w]*[-+.]?(?!\w)|[%]?[a-zA-Z]+[a-zA-Z0-9]*'
        if t.value in self.registers:
            t.type = "REGISTER"
        elif t.value in branchcode:
            t.type = "BRANCHCODE"
        elif t.value[0] == "." and t.value[1:] in self.tconsts:
            t.type = "TCONST"
        elif t.value in self.opcodes:
            t.type = self.reserved_dict.get(t.value, "OPCODE")
        elif t.value[0] == 'b' and t.value[-1] in "+-_" and t.value[:-1] in self.opcodes:
            # we have a predicted branch opcode
            t.type = self.reserved_dict.get(t.value[:-1], "OPCODE")
        else:
            t.type = self.reserved_dict.get(t.value, "ID")
        return t    


if __name__ == "__main__":
    testlexer('ppc')

