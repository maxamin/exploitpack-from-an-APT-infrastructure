#! /usr/bin/env python

"""
riscscan.py

RISC lex parent class for MOSDEF

"""
import sys
if "MOSDEF" not in sys.path: sys.path.append("MOSDEF")
from mosdefutils import *
from asmscan import asmlex

class risclex(asmlex):
    
    opcodes = []
    registers = []
    labels = {}

    def __init__(self, procname=None):
        if procname:
            mod = __import__('%sassembler' % procname)
            self.opcodes = getattr(mod, 'opcodes').keys()
            if hasattr(mod, 'registers'):
                self.registers = getattr(mod, 'registers')
            if hasattr(mod, 'barrel_shift'):
                self.barrel_shift = getattr(mod, 'barrel_shift')
        asmlex.__init__(self)


def testlexer(procname,procfile=None):
    import os
    if not procfile:
        procfile = '%s.s' % procname
    if not os.path.isfile(procfile):
        print "[%s] can not run test (%s not existant)" % (procname, procfile)
        return False
    from asmscan import getlexer
    print "[%s] starting test..." % procname
    newlex = getlexer(procname)
    data=file(procfile).read()
    newlex.input(data)
    while 1:
        token=newlex.token()
        print "[%s] Token=%s" % (procname, token)
        if not token: break
    print "[%s] successfully tested." % procname
    return True


if __name__ == "__main__":
    proclist = ["sparc", "ppc", "arm9"]
    for proc in proclist:
        if not testlexer(proc):
            print "[%s] failed." % proc
    print "all test done."

