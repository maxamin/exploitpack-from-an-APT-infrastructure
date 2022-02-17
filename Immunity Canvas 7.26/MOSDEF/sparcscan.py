#! /usr/bin/env python

"""
sparcscan.py

SPARC lexer for CANVAS

"""

from riscscan import *

class sparclex(risclex):
    def __init__(self):
        risclex.__init__(self, 'sparc')
    
    def t_ID(self,t):
        r'[.]?[A-Za-z_]+[\w_]*'
        if t.value in ["nop", "ret", "retl", "restore"]:
            t.type=self.reserved_dict.get(t.value,"NOARGOPCODE")
        elif t.value=="a":
            t.type=self.reserved_dict.get(t.value,"ANNUL")
        elif t.value[0] == "." and t.value[1:] in self.tconsts:
            t.type = "TCONST"
        elif t.value in self.opcodes:
            t.type= self.reserved_dict.get(t.value,"OPCODE")
        
        #Can't do forward references this way...
        #elif t.value in self.labels.keys():
        #    t.type= self.reserved_dict.get(t.value,"LABEL")
        else:
            t.type = self.reserved_dict.get(t.value,"ID")
        return t


if __name__ == "__main__":
    testlexer('sparc')

