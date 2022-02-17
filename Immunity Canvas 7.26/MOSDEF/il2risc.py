#! /usr/bin/env python

from il2proc import ProcGenerate


# common to all RISC
# function can be overwritten later
class RISCGenerate(ProcGenerate):
    def __init__(self, pointersize=4):
        ProcGenerate.__init__(self, pointersize)
        
        # in order
        self.operand_fmt = ('b', 'h', 'w')
        
        # for hi() and lo()
        self.max_addr_loadable = 2 << (self.pointersize - 1)
    
    #------------------
    # kind of 'macros'
    #------------------
    
    def opfmt(self, operand_size, fmt):
        # TODO: check operand_size in range
        if not '_' in fmt:
            return ""
        pos = fmt.find('_')
        return fmt[0:pos] + self.operand_fmt[int(operand_size) >> 1] + fmt[pos+1:]
    
    # for hi() and lo(): 'bits' is the size of the instruction
    
    def hi(self, myint, bits=None):
        if not bits:
            bits = self.max_addr_loadable
        return myint >> bits
    
    def lo(self, myint, bits=None):
        if not bits:
            bits = self.max_addr_loadable
        return myint & ((1 << bits) - 1)
    
    def is_loadable(self, myint, bits=None):
        if not bits:
            bits = self.max_addr_loadable
        if abs(myint) <= (1 << (bits - 1)) - 1:
             return True
        return False
    
    #--------------
    # commun instr
    #--------------
    
    def t_jump(self, args):
        self.out += "b %s\n" % args[0]

