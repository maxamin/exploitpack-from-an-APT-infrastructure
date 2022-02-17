##ImmunityHeader v1
###############################################################################
## File       :  x86parse.py
## Description:
##            :
## Created_On :  Tue Sep 22 22:30:34 2009
## Created_By :  Justin Seitz
## Modified_On:  Tue Oct 13 10:20:33 2009
## Modified_By:  Justin Seitz
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
#! /usr/bin/env python

from __future__ import with_statement

"""
x86parse.py

x86 atandt parser for CANVAS

If you're getting infinite loops, check for double label defines!

Assemblers are not thread-safe!

"""

from riscparse import *
from asmparse import *
from asmscan import getlexer
import x86opcodes
import copy
from mosdefutils import *
import struct
from threading import RLock

globallock = RLock()

class x86parse(asmparse):

    register_prefix = '%'

    def __init__(self,runpass=1,arch=""):
        asmparse.__init__(self, runpass)
        self.lexer = getlexer("x86")
        #a global dictionary, so we copy portions out of it as necessary
        #this avoids threading issues and other complications
        #each parser is in its own thread! (Or if not, I hope you
        #know what you're doing!)
        self.mnargsDict=x86opcodes.x86args

        # Set the arch
        # x86opcodes.arch = arch
        self.arch       = arch

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
        self.value=[]
        self.callnum=0
        self.longcalls={}
        self.changed_labelinfo=False
        self.labels_that_have_changed={}
        return

    def set_arch(self,arch):
        self.arch       = arch
        #x86opcodes.arch = arch

    def inccall(self):
        """
        This is used to set the NEEDLONGJUMP attribute as we do this sort of thing
        """
        #print "Incrementing self.callnum"
        self.callnum+=1
        return

    def needlongcall(self):
        if self.longcalls.get(self.callnum):
            #print "Yes, we need a long call"
            return True
        #print "No we do not need a long call"
        return False

    def isLabelDefined(self, label):
        """
        We used to need this, but now we always assume EVERY label is defined
        """
        return True

    def getLabel(self, label):
        #another stub
        #print "Resolving label: %s as %d"%(label, self.resolvelabel(label))
        return self.resolvelabel(label)

    def newlabel(self,labelname):
        """
        This function overrides the newlabel from asmparse.py, because x86 is not
        a two pass assembler where all the instructions are of a known length.

        If this happens twice during one run, then we have a duplicate label, and
        we need to raise an exception and complain!!!
        """
        if self.labelinfo.get(labelname)!=self.length:
            self.changed_labelinfo=True
            self.labelinfo[labelname]=self.length
            devlog("mosdef", "Label changed length: %s"%labelname)
            #increment our labels have changed counter
            change_counter=self.labels_that_have_changed.get(labelname,0)+1
            self.labels_that_have_changed[labelname]=change_counter
            if change_counter>1:
                #we've changed this label more than once!!!
                devlog("mosdef", "Changed label %s more than once, this is a bug in their asm!"%labelname)
                raise Exception, "Label %s defined more than once!"%labelname
            #print "Newlabel %s at %d"%(labelname, self.length)
        return

    def argsListFromValueList(self, valuelist):
        #print "Valuelist: %s"%valuelist
        argList=[]
        for a in valuelist:
            #print "Type of a (%s): %s"%(a,type(a))
            if type(a) in [ type(0), type(0L) ]:
                #integer
                argList+=["constant"]
            elif type(a) == type({}):
                #if it's a dictionary, then we have a register expression on our hands
                argList+=["registerexpression"]
            elif a[0] =="%":
                argList+=["reg"]
            elif dInt_n(a)!=None:
                #dInt_n will return None if dInt is not possible (note: Zero is a valid value)
                argList+=["constant"]
            elif type(a) in [type("")]:
                #strings are assumed to be names
                argList+=["name"]
        #print "Arglist: %s"%argList
        return argList

    def instruction(self,mn,valuelist):

            """
            gets an instruction from a mnemonic, arglist, and valuelist
            return assembled binary bytes and opcode for reference
            """
            ##Rich: From Hotspotting this is a speed critical function and so we should
            ## optimise the ass off it

            argList=self.argsListFromValueList(valuelist)

            oldarglist=[]
            regbutnotconstantlist=[]

            valueList=valuelist

            for a in argList:
                oldarglist.append(a)
                regbutnotconstantlist.append(a)


            #first we go through and replace all constants with constant8 if they are small enough
            for i in range(len(argList)):
                if argList[i]=="constant":
                    #first convert it to an integer
                    valueList[i]=dInt(valueList[i])
                    #then check to see if it's a small integer...
                    if isbyte(valueList[i]):
                        #and if so, replace our argList with constant8 here
                        argList[i]="constant8"

            #ok, now we replace all the registers in the arguments with their actual values
            #this is so we can search for a special argument list that lists actual registers
            regargsL=[]
            for i in range(len(argList)):
                if argList[i]=="reg":
                    regargsL.append(valueList[i])
                    regbutnotconstantlist[i]=valueList[i]
                else:
                    regargsL.append(argList[i])


            #print "RegargsL[%s]: %s"%(mn,regargsL)
            args=argList
            #print "Args[%s]=%s"%(mn,args)
            #print "Values=%s"%(valueList)

            if mn not in self.mnargsDict:
                print "Unrecognized mnemonic %s!"%mn
                raise SystemExit

##            #get a copy of these objects here (not DEEPCOPY, which would take forever)
##            if False:
##                #no threading mutex
##                argsLL=copy.copy(self.mnargsDict[mn])
##            else:
##                #we do have a threading mutex. so we can do this
##                #directly (saving time since copy is slow!)
##                argsLL=self.mnargsDict[mn]

            #Rich replacing above NULL if statement
            argsLL=self.mnargsDict[mn]

            found=None
            i=0
            #this little loop goes through and finds which argument list we're using
            for argsL in argsLL:
                if hasattr(argsL, 'opcode') and argsL.opcode:
                    if len(argsL.opcode) == 1 and ord(argsL.opcode[0]) & 0xf0 == 0x40 \
                       and self.arch.upper() == 'X64':
                        #print 'XXX: skipping optimized inc for X64'
                        continue
                if oldarglist==argsL.arglist:
                    if i==0:
                        found=argsL
                if regbutnotconstantlist==argsL.arglist:
                    if i==0:
                        found=argsL
                        i=1
                if args==argsL.arglist:
                    #print "Found normal arg with constant8 converted"
                    if i<3:
                        found=argsL
                        i=2
                if regargsL==argsL.arglist:
                    #print "Found regargs"
                    #regargs has both the registers and the constants converted, so it
                    #is most precice
                    found=argsL
                    i=3

            if found==None:
                print "Did not find an argument list! Some sort of weird error mn=%s args=%s."%(mn,argList)
                #for argsL in argsLL:
                #    print "argsL.arglist=%s"%(argsL.arglist)
                print "Args[%s]=%s"%(mn,args)
                print "Values=%s"%(valueList)
                for i in self.mnargsDict[mn]:
                    print "Possible: %s"%i.arglist
                raise SystemError

            #now "found" has the argument list - unless there is an argument with a label
            #that is yet to be defined, we now know everything we need to assemble this instruction
            #if the instruction cannot be assembled now (due to a missing label) then this should
            #(MUST) return some 0x90 padding for itself to fill in later.
            #save this off with a copy to prevent any other thread from doing anything to it...
            #slow but sure saves the threading dealocks!
            #no need since we have a threading mutex now
            #found=copy.copy(found)
            instr=found.get(valueList,context=self,arch=self.arch)
            #instr here is a string...not an x86opcodes object
            if instr=="":
                print "******ERROR************"
                print "MOSDEF Instruction did not return value"
                print "valueList=%s"%valueList
                raise GenerateException, "Error: %s"%valueList
            return instr, found

    def order_longlong(self, longlongint):
        return struct.pack('<Q', longlongint)

    #two functions that are used by asmparse.py::p_line_with_TCONST()
    def order_long(self, longint):
        return intel_order(longint)

    def order_word(self, word):
        return int2str16_swapped(word)

    def p_linelist_2(self,p):
        '''linelist : line NEWLINE linelist
           linelist : NEWLINE line linelist
           linelist : line linelist
        '''

    def p_linelist_newline(self, p):
        '''linelist : NEWLINE
        '''

    """
    A line can be many things:
        #one of which we handle here
        stmt ::= mnemonic argumentlist

        #this is handled in asmparse.py (line_of_lable function)
        stmt ::= labeldefine

        #lines with TCONST (in asmparse.py)
        #so we don't handle these at all
        stmt ::= longdefine number
        stmt ::= shortdefine number
        stmt ::= globaldefine name ??? (I think this does not exist)
        stmt ::= asciidefine quotedstring
        stmt ::= asciizdefine quotedstring
        stmt ::= urlencodeddefine quotedstring
        stmt ::= bytedefine numberlist
    """

    def p_line_5(self, p):
        'line : OPCODE argumentlist'
        #print "Line: Opcode: %s argumentlist %s"%(p[1], p[2])
        #here we should assemble the instruction
        try:
            #print "Testing self.callnum %d"%self.callnum
            value,opcode=self.instruction(p[1],p[2])
        except x86opcodes.needLongCall:
            #print "Setting self.callnum %d to True"%(self.callnum)
            self.longcalls[self.callnum]=True
            self.callnum=self.callnum-1 #adjust this because we will increment it again here
            value,opcode=self.instruction(p[1],p[2])
        self.length+=len(value)
        self.value+=[value]

    def p_argumentlist_1(self,p):
        r'argumentlist : opcodearg COMMA opcodearg'
        p[0]=[p[1],p[3]]

    def p_argumentlist_2(self,p):
        r'argumentlist : opcodearg'
        p[0] = [p[1]]

    def p_argumentlist_empty(self, p):
        r'argumentlist : '
        #empty argumentlist, used by RET, etc
        p[0]=[]

    def p_opcodearg_id(self,p):
        'opcodearg : ID'
        #we don't resolve the labels like our other assemblers
        #we just let it be resolved by x86opcodes.py
        #p[0]=self.resolvelabel(p[1])
        p[0]=p[1] #name is a string

    def p_opcodearg_constant(self,p):
        '''opcodearg : DOLLAR ICONST
           opcodearg : DOLLAR HCONST

        '''
        p[0]=p[2]

    def p_opcodearg_3(self,p):
        'opcodearg : register'
        p[0]=p[1]

    def p_opcodearg_starreg(self, p):
        'opcodearg : STAR register'
        p[0] = p[2]


    def p_opcodearg_4(self,p):
        '''opcodearg : expression
           opcodearg : STAR expression
        '''
        if len(p)==3:
            #call *(%ebx)
            registerexpression=p[2]
        else:
            #default
            registerexpression=p[1]

        #new assembler has a list, instead of a dictionary
        #print "Register Expression: %s"%registerexpression
        regexp={}
        regexp["segreg"]=registerexpression[0]
        regexp["labelsandnumbers"]=registerexpression[1]
        regexp["reg1"]=registerexpression[2][0]
        regexp["reg2"]=registerexpression[2][1]
        regexp["scalefactor"]=registerexpression[2][2]
        #as a note, for reg1, we sometimes use numbers (in string format)
        #like for %fs:(0x30)
        #in this case you get:
        #{'reg2': '', 'segreg': '%fs:', 'reg1': '0x30', 'labelsandnumbers': [], 'scalefactor': 1, 'additives': []}

        p[0]=regexp

    #register expressions are complex!
    """
    some example register expressions on at&t x86 assembly
    lea functiontable-geteip(%ebx),%edi
    call *reverttoself-geteip(%ebx)
    call *%ebx
    movl %fs:(0x30), %ecx
    """


    def p_expression_3(self, p):
        '''expression : segmentexpression arithmaticexpression registerderef
           expression : arithmaticexpression registerderef
        '''
        #lea functiontable-geteip(%ebx),%edi
        if len(p)==3:
            #no segment expression
            p[0]=[None, p[1],p[2]]
        else:
            #yes, segment expression
            p[0]=[p[1],p[2],p[3]]

    def p_segmentexpression(self, p):
        #movl %fs:0x30(%ecx),%eax
        #usually empty, but also has a chance of %fs
        '''
           segmentexpression : PERCENT ID COLON
        '''
        #just grab the fs part, readd the percent sign to the front and the colon
        p[0]=p[2]

    def p_registerderef(self, p):
        #for (%ebx, %ecx, 4) or (%ecx, %edi) or (%ecx) or (%ecx, 4) and similar
        #or (0x30) is also valid for the %fs:(0x30) stuff we do a lot
        '''registerderef : LPAREN register RPAREN
           registerderef : LPAREN number RPAREN
           registerderef : LPAREN register COMMA register RPAREN
           registerderef : LPAREN register COMMA number RPAREN
           registerderef : LPAREN register COMMA register COMMA number RPAREN
        '''
        #returns [reg1, reg2, scalefactor]
        #we treat all of these the same
        registerderef=[]
        if len(p)==8:
            #secondary register and multiplier
            if p[6] not in [1,2,4,8]:
                print "ERROR: invalid scale factor"
            registerderef=[p[2],p[4],p[6]]
        elif len(p)==6:
            if dInt_n(p[4]) != None: # is this a register or a scale value
                #it's a scale value
                registerderef=[p[2], None, p[4]]
            else:
                #secondary register (set scale value to 1)
                registerderef=[p[2],p[4],1]
        elif len(p)==4:
            #no secondary register or multiplier
            registerderef=[p[2],None, 1]
        else:
            print "ERROR in x86 parser: length is incorrect!"
        p[0]=registerderef


    def p_arithmaticexpression(self, p):
        #for functiontable-geteip and similar
        '''
        arithmaticexpression :
        arithmaticexpression : number
        arithmaticexpression : idornumberliststart
        arithmaticexpression : STAR idornumberliststart
        '''
        if len(p) == 2:
            p[0] = p[1]
        elif len(p)==3:
            #STAR idornumberliststart
            p[0] = p[2]
        #otherwise we are a null list here so return None, I assume.

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


    def p_register(self,p):
        'register : PERCENT REGISTER'
        p[0]=p[1]+p[2]

def getparser(runpass=1,arch=None):
    return procgetparser(x86parse, runpass=runpass, parsetab_name="x86_parsetab",arch=arch)

def line_testparser(getparser):
    import sys
    if len(sys.argv)!= 2:
        sys.stderr.write("Usage:\n         %s <file_to_compile>\n\n" % sys.argv[0])
        sys.exit(0)

    parser,yaccer=getparser()
    lexer=parser.lexer
    data=file(sys.argv[1]).readlines()
    failed=[] # a list of the lines we failed on
    oldlen=0
    for line in data:
        print "\nLine: %s"%line.strip()
        try:
            yaccer.parse(line, lexer=lexer)
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
            failed+=[line]
            continue
        value="".join(parser.value)
        newlen=len(value)
        instrlen=newlen-oldlen
        oldlen=newlen
        if instrlen:
            print "Result: %s"%shellcode_dump(value[-instrlen:])
            print "Length of result: %d"%instrlen
    print "Failed:"
    for line in failed:
        print "%s"%line.strip()

def assemble_x86(data,arch):
    """
    Does the assembly, catches NEEDLONGCALL exceptions and then sets the parser up for that
    """
    #we are not thread safe! :<
    with globallock:
        if data in ["", None]:
            return ""

        done=False
        longcalls={}
        i=1
        labelinfo={}
        while not done:
            devlog("mosdef","Parser running stage %d"%i)
            parser,yaccer=getparser(arch=arch)
            parser.longcalls=longcalls
            parser.labelinfo=labelinfo
            parser.runpass=i
            i+=1
            lexer=parser.lexer
            try:

                yaccer.parse(data,lexer=lexer)
            except x86opcodes.needLongCall:
                #this doesn't get called?
                #import traceback
                #traceback.print_exc(file=sys.stderr)

                #catch this exception
                longcalls[parser.callnum]=True
                #invalidate label info since size has changed!
                devlog("mosdef","Invalidated label info")
                labelinfo={}
            else:
                #If the parser has changed the label info, then
                #we need to do another pass
                #otherwise we're done, because all the labels have been
                #resolved!
                #"i" should typically be around 3 when we get here.
                #if you see something really high, then there's a problem
                #most likely this problem is that you have two label defines
                #which are the same. you'll want to turn on "mosdef" debugging (>> .debug)
                #in order to see which label this is (or just use the WingIDE debugger)
                if not parser.changed_labelinfo:
                    done=True
        devlog("mosdef","Parser ran %d times"%i)
        #print "parser.value=%s"%repr(parser.value)
        return "".join(parser.value)

def testparser(getparser):
    import sys
    if len(sys.argv)!= 2:
        sys.stderr.write("Usage:\n         %s <file_to_compile>\n\n" % sys.argv[0])
        sys.exit(0)
    data=file(sys.argv[1]).read()
    for i in xrange(0,1):
        result=assemble_x86(data, "X64")
    print hexprint(result)
    print "Length: %d"%len(result)

if __name__ == "__main__":
    testparser(getparser)
    #line_testparser(getparser)

