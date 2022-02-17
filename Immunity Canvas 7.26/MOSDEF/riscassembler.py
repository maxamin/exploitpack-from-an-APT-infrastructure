#! /usr/bin/env python
"""
riscassembler.py

RISC assembler parent class for CANVAS's assemblers

"""

import mosdefutils

class riscassembler:
    def __init__(self,procname,runpass=1):
        procasm = '%sassembler' % procname
        procasm_mod = __import__(procasm)
        try:
            getattr(procasm_mod, procasm).__init__(self)
        except:
            print "riscassembler is unable to be initialised on %s" % procname
            raise

if __name__=="__main__":
    print "%s can not be called directly, but should be included as a module" % __file__

