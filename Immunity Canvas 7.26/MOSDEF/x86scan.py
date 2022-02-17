#! /usr/bin/env python

"""
atandtscan2.py

atandtscan2 lex parent class for MOSDEF

"""

from mosdefutils import *
from asmscan import asmlex

class x86lex(asmlex):
    
    opcodes = []
    from x86opcodes import regpos
    from x86opcodes import getAllMnemonics
    
    for o in getAllMnemonics():
        opcodes.append(o)
    #get our registers from x86opcodes
    regs=regpos.keys()
    registers = []
    for r in regs:
        registers.append(r.replace("%",""))
    labels = {}

    def __init__(self, procname=None):
        asmlex.__init__(self)
        return 

    def t_NEWLINE(self,t):
        r'\n+'
        #we redefine this here from asmscan.py since this is
        #the CORRECT WAY - i.e. we emit a NEWLINE symbol whenwe 
        #see a NEWLINE or string of newlines. This means
        #that the parser doens't have to go through hoops
        #to figure out when a line ends!
        
        #print "ASM NEWLINE"
        t.lineno += t.value.count("\n")
        t.type = "NEWLINE"
        return t

    def t_ID(self,t):
        r'[.]?[A-Za-z_]+[\w_]*'
        if t.value[0] == "." and t.value[1:] in self.tconsts:
            t.type = "TCONST"
        elif t.value in self.opcodes:
            t.type= self.reserved_dict.get(t.value,"OPCODE")        
        elif t.value.lower() in self.registers:
            t.type = "REGISTER"
        else:
            t.type = self.reserved_dict.get(t.value,"ID")
        return t

    # ASM style Comments
    def t_comment(self,t):
        r'//.*\n'
        #print "ASM COMMENT", t.type
        t.lineno += t.value.count('\n')
        t.type = "NEWLINE"
        return t
    

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
    proclist = ["x86"]
    filename=None
    if len(sys.argv)>1:
        filename=sys.argv[1]
    for proc in proclist:
        if not testlexer(proc,filename):
            print "[%s] failed." % proc
    print "all test done."

