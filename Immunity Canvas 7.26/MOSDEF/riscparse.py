##ImmunityHeader v1 
###############################################################################
## File       :  riscparse.py
## Description:  
##            :  
## Created_On :  Tue Oct 13 10:14:18 2009
## Created_By :  Justin Seitz
## Modified_On:  Tue Oct 13 10:19:59 2009
## Modified_By:  Justin Seitz
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
#! /usr/bin/env python

"""
riscparse.py

A RISC parser for CANVAS

"""

todo="""
Addresses [] etc
branch append , a stuff
manage labels	
split with asmparse.py
"""
import sys
if "MOSDEF" not in sys.path: sys.path.append("MOSDEF")
from mosdefutils import *
from asmparse import asmparse
from riscassembler import riscassembler

class riscparse(riscassembler, asmparse):
    
    register_prefix = ""
    
    def __init__(self, procname, runpass=1):
        from asmscan import getlexer
        riscassembler.__init__(self, procname, runpass)
        asmparse.__init__(self, runpass)
        self.lexer = getlexer(procname)
        self.tokens = self.lexer.lextokens.keys()
        self.labelinfo = {}
        self.precedence = ( 
            ('left','OPCODE'),
            ('left','ID','COLON'),
            ('left','PERIOD'),
            ('left','COMMA'),
        )
        #Rich remove: ('left','NOP'),
        #print "self.runpass=%s"%self.runpass
    
    def instruction(self,opcode,arglist):
        #print "Doing opcode: %s (pass %d) %s" % (opcode, self.runpass, arglist)
        #print arglist
        #print "SELF.LENGTH (pointing at opcode): %d"%self.length
        if self.runpass==1:
            # eh, on RISC we are (for now) 1 instr = 4 bytes
            # self.compound_opcodes should contains macros ?
            if opcode in self.compound_opcodes:
                tmp=self.doinstruction(opcode,arglist)
                self.length+=len(tmp)
            else:
                self.length+=4 #all others are just 4 bytes long
            #print "pass 1, len += 4"
            #print "CHECKING!!!...",
            #tmp = self.doinstruction(opcode,arglist)
            #checklen = len(tmp)
            #if checklen != 4:
            #    print "OMFG! SHENANIGANS!"
            #    sys.stdin.readline()
            #else:
            #    print "ASSEMBLED LEN CHECKED OUT OK!"
            return ""
        else:
            #second pass.
            ret=self.doinstruction(opcode,arglist)
            if ret==None:
                print "Some kind of error! Ret==None with opcode=%s and args=%s!!!"%(opcode,arglist)
                return ""
            self.length+=len(ret)
            #print "pass 2, len += %d"%len(ret)
            return ret
    
    # KLUDGE: p_file is commented to avoid boring warnings:
    #  Warning. Rule 'file' defined, but not used.
    #  yacc: Warning. There is 1 unused rule.
    #  yacc: Symbol 'file' is unreachable.
    # if someone need to use that, he can fix that problem (probably some dependance missing)
    #
    # <COMMENTED>
    #def p_file(self, p):
    #    'file : linelist'
    #    #print "Done!"
    #    if self.runpass==1:
    #        self.runpass=2 #set to pass 2, where we actually do instructions
    #        self.value=[]
    # </COMMENTED>
    
    def p_line_3(self,p):
        'line : OPCODE COMMA ANNUL opcodeargslist'
        #branch instructions with a ,a
        dest=p[4][0]-self.length
        self.value+=[self.instruction(p[1],[1]+[dest])]
        pass
    
    def p_line_4(self,p):
        'line : OPCODE opcodeargslist'
        if p[1]=="call": 
            #call label or call register
            
            if str(p[2][0]).count(self.register_prefix):
                #print "P=%s %s"%(p[1],p[2])
                if len(p[2])==1:
                    argsdict=p[2]+[0]
                else:
                    argsdict=p[2]
                self.value+=[self.instruction(p[1],argsdict)]
            else:
                #label only
                #print "p2=%s"%p[2]                
                dest=p[2][0]-self.length
                #print "dest=%s"%dest
                self.value+=[self.instruction(p[1],[dest])]
        elif p[1] not in self.branch_opcodes:
            self.value+=[self.instruction(p[1],p[2])]
        else:
            #branch with no annul argument
            dest=p[2][0]-self.length
            self.value+=[self.instruction(p[1],[0]+[dest])]
    
    def p_line_5(self,p):
        "line : NOARGOPCODE"
        #nop
        self.value+=[self.instruction(p[1],[])]
        pass
    
    def p_line_6(self,p):
        'line : OPCODE ID COLON'
        #print "p_line_6", p[2]
        self.value+=[self.instruction(p[1],[])]
        self.newlabel(p[2])
    
    """
    # following is RISC?
    
    #(from PPC):
    
    def p_line_7(self, p):
        'line : OPCODE'
        self.value+= [self.instruction(p[1], []) ]
    
    def p_line_9(self, p):
        'line : NEWLINE NEWLINE'
        pass
    
    #(from SPARC):
    
    #def p_line_7(self,p):
    #    'line : OPCODE COMMA ID opcodeargslist ID COLON'
    #    self.value+=[self.instruction(p[1],[])]
    #    self.newlabel(p[2])
    """
    
    def p_opcodeargslist_1(self,p):
        'opcodeargslist : opcodearg'
        try: 
            #sometimes opcodearg will return a list, and in that case, we need
            #to just add that list.
            a=p[1]+[] #test if list-like
            p[0]=p[1]
        except:
            p[0]=[p[1]]
    
    def p_opcodeargslist_2(self,p):
        'opcodeargslist : opcodearg COMMA opcodeargslist'
        try: 
            #sometimes opcodearg will return a list, and in that case, we need
            #to just add that list.
            a=p[1]+[] #test if list-like
            p[0]=p[1]+p[3]
        except:
            p[0]=[p[1]]+p[3]
    
    # FIXME
    #def p_opcodeargslist_3(self,p):
    #    'opcodeargslist : empty'
    #    p[0]=[]
    
    def p_opcodearg_1(self,p):
        '''opcodearg : number'''
        p[0]=p[1]
    
    def p_opcodearg_2(self,p):
        'opcodearg : register'
        p[0]=p[1]
    
    def p_opcodearg_3(self,p):
        'opcodearg : expression'
        #register + constantlist?
        p[0]=p[1]
    
    # TODO what is default RISC?    
    #def p_opcodearg_4(self,p):
    #    'opcodearg : ID'
    #    p[0]=self.resolvelabel(p[1])               # SPARC
    #    p[0]=self.resolvelabel(p[1]) - self.length # PPC
    
    def p_opcodearg_5(self, p):
        'opcodearg : parenexpr'
        p[0]=p[1]
    
    def p_opcodearg_6(self, p):
        'opcodearg : idornumberliststart'
        p[0]=p[1]
    
    def p_opcodearg_7(self, p):
        'opcodearg : register idornumberlist'
        p[0]=[p[1],p[2]]
    
    def p_parenexpr(self,p):
        'parenexpr : LPAREN idornumberliststart RPAREN'
        p[0]=p[2]
    
    def p_idornumberliststart_1(self,p):
        '''idornumberliststart : ID
           idornumberliststart : ID idornumberlist
        '''
        #start with id
        if len(p)==3:
            p[0]=self.resolvelabel(p[1])+p[2]
        else:
            p[0]=self.resolvelabel(p[1])
    
    def p_idornumberliststart_2(self,p):
        '''idornumberliststart : number
           idornumberliststart : number idornumberlist'''
        #start with number
        if len(p)==3:
            p[0]=p[1]+p[2]
        else:
            p[0]=p[1]
    
    #we fail to account for paren expressions in idornumberlists for now.
    #sucks to be us.
    def p_idornumberlist_1(self,p):
        """idornumberlist : number"""
        p[0]=int(p[1])
    
    def p_idornumberlist_2(self,p):
        """idornumberlist : ICONST idornumberlist
           idornumberlist : HCONST idornumberlist
           """
        #constants include their own sign
        p[0]=int(p[1])+p[2]
    
    def p_idornumberlist_3(self,p):
        """idornumberlist : PLUS ID 
           idornumberlist : SUBTRACT ID
           """
        if p[1]=="-":
            p[0]=-self.resolvelabel(p[2])            
        else:
            p[0]=self.resolvelabel(p[2])                        
    
    def p_idornumberlist_4(self,p):
        """idornumberlist : PLUS ID idornumberlist
           idornumberlist : SUBTRACT ID idornumberlist
           """
        if p[1]=="+":
            p[0]=self.resolvelabel(p[2])+int(p[3])
        else:
            p[0]=-self.resolvelabel(p[2])+int(p[3])
    
    def p_expression(self,p):
        'expression : LBRACKET expressionlist RBRACKET'
        p[0]=p[2]
    
    def p_expressionlist_1(self,p):
        'expressionlist : register'
        p[0]=p[1]
    
    def p_expressionlist_2(self,p):
        'expressionlist : register PLUS register'
        p[0]=[p[1],p[3]]
    
    def p_expressionlist_3(self,p):
        'expressionlist : register idornumberlist'
        p[0]=[p[2],p[1]] #reverse this for the assembler (we want immediate, register)
    
    #def p_empty(self,p):
    #    'empty : '
    #    p[0]=None


#import profile
# Build the grammar

#LALR doesn't work! DONT USE IT
#profile.run("yacc.yacc(method='LALR')")
existing_parsetables={}
import os
try:
    from engine import CanvasConfig as config
    TABLE_PREFIX="MOSDEF%s"%(os.sep)
except ImportError:
    ##For Standalone MOSDEF
    print "Standalone MOSDEF"
    config={"cparse_version":"2"}
    TABLE_PREFIX=""
    
def procgetparser(procparse,runpass=1, parsetab_name="parsetab",arch=None):
    
    parser=procparse(runpass=runpass)    

    try:
        parser.set_arch(arch)
    except:
        pass
    
    
    if config["cparse_version"] == "2":
        import yacc2 ##Use PLY 2.5 now we can use LALR
        ##Get existing parsetable for optimisation
        global existing_parsetables
        yaccer=yacc2.yacc(module=parser,debug=0,write_tables=1,optimize=1, method="LALR",tabmodule="%s%s"%(TABLE_PREFIX, parsetab_name), pass_the_pickle=existing_parsetables)
        ##Save the unpickled parse table to the canvasengine so as other parses can grab it in future
        existing_parsetables=yaccer.pass_the_pickle
    else:
        import yacc
        yaccer=yacc.yacc(module=parser,debug=0,method="SLR",write_tables=0)
    
    return parser, yaccer

def testparser(getparser):
    import sys
    if len(sys.argv)!= 2:
        sys.stderr.write("Usage:\n         %s <file_to_compile>\n\n" % sys.argv[0])
        sys.exit(0)
    
    parser,yaccer=getparser()
    lexer=parser.lexer
    data=file(sys.argv[1]).read()
    print "pass 1" 
    yaccer.parse(data,lexer=lexer)
    print "1: %s"%parser.labelinfo
    if 1:
        #import struct
        parser2,yaccer2=getparser(runpass=2)
        parser2.labelinfo=parser.labelinfo #saved off from runpass 1
        print "2: %s %s"%(parser2.labelinfo,parser2.runpass)
        lexer2=parser2.lexer
        print "pass 2"
        yaccer2.parse(data,lexer=lexer2,debug=0)
        
        #for a in parser2.value:
        #    print "0x%08x" % struct.unpack("!L", a),
        
        print hexprint("".join(parser2.value))


if __name__ == "__main__":
    import sys, os
    if len(sys.argv) > 1:
        print "%s called with arguments, they will be ignored" % __file__
    else:
        sys.argv += [[]]
    for proc in ["sparc", "ppc", "arm9"]:
        procfile = '%s.s' % proc
        if not os.path.isfile(procfile):
            print "[%s] can not run test (%s not existant)" % (proc, procfile)
        else:
            print "[%s] starting test..." % proc
            sys.argv[1] = procfile
            procparse = __import__('%sparse' % proc)
            assert hasattr(procparse, 'getparser')
            try:
                testparser(procparse.getparser)
                print "[%s] successfully tested." % proc
            except:
                print "[%s] failed." % proc
    print "all test done."

