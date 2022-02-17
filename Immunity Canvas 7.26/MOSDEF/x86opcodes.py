##ImmunityHeader v1
###############################################################################
## File       :  x86opcodes.py
## Description:
##            :
## Created_On :  Fri Aug 21 08:17:17 2009
## Created_By :  Justin Seitz
## Modified_On:  Tue Oct 13 10:30:55 2009
## Modified_By:  Justin Seitz
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
#! /usr/bin/env python

"""
x86 opcode list


Notes:

    Argsize is the size of the ARGUMENTS and does not account for modrm things
    or register expression stuff of any kind.

    If the opcode doesn't have a constant or constant8, it has argsize=0!


X64 NOTES:
==========

REX prefixes (0x40-0x4f):

-7---4--3---2---1---0-- <-- Bits Index
| REX | W | R | X | B | <-- Field Name
----------------------- <-- End Line Marker


REX.W to 0 sets default operand size, REX.W to 1 sets 64 bits operand size
REX.B sets Bits index to the additional regs

"""

TODO="""
Write test-suite
"""

import re
import sys
import traceback
from mosdefutils import *

x86args={}

def issignedbyte(anint):
    """
    tests if this int fits into a byte when signed
    """
    if anint>=0 and anint<=127:
        return 1
    if anint<0 and anint>=-128:
        return 1
    return 0

# 64-bit registers
r64 = [
    "%rax",
    "%rcx",
    "%rdx",
    "%rbx",
    "%rsp",
    "%rbp",
    "%rsi",
    "%rdi"]
r64_REX_R = [
    '%r8',
    '%r9',
    '%r10',
    '%r11',
    '%r12',
    '%r13',
    '%r14',
    '%r15']
# 32-bit registers
r32 = [
    "%eax",
    "%ecx",
    "%edx",
    "%ebx",
    "%esp",
    "%ebp",
    "%esi",
    "%edi"]
r32_REX_R = [
    '%r8d',
    '%r9d',
    '%r10d',
    '%r11d',
    '%r12d',
    '%r13d',
    '%r14d',
    '%r15d']
# 16-bit registers
r16 = [
    "%ax",
    "%cx",
    "%dx",
    "%bx",
    "%sp",
    "%bp",
    "%si",
    "%di"]
r16_REX_R = [
    '%r8w',
    '%r9w',
    '%r10w',
    '%r11w',
    '%r12w',
    '%r13w',
    '%r14w',
    '%r15w']
# 8-bit registers
r8 = [
    "%al",
    "%cl",
    "%dl",
    "%bl",
    "%ah",
    "%ch",
    "%dh",
    "%bh"]

# ah, ch, dh, bh re-mapped with REX to spl, bpl, sil, dil
r8_REX_R = [
    '%r8b',
    '%r9b',
    '%r10b',
    '%r11b',
    '%r12b',
    '%r13b',
    '%r14b',
    '%r15b']

# give reg correct column index
def index_reg(posdict, reglist):
    pos = 0
    for reg in reglist:
        posdict[reg] = pos
        pos += 1

regpos = {}
index_reg(regpos, r8)
index_reg(regpos, r8_REX_R)
index_reg(regpos, r16)
index_reg(regpos, r16_REX_R)
index_reg(regpos, r32)
index_reg(regpos, r32_REX_R)
index_reg(regpos, r64)
index_reg(regpos, r64_REX_R)

REX = 0x40
B   = 1<<0 # Base field, extension of ModR/M or SIB Base field
X   = 1<<1 # indeX field, extension of SIB Index field
R   = 1<<2 # Register field, extension of the ModR/M REG field
W   = 1<<3 # Width, 0: default operand size, 1: 64 bits operand size

regpos['needsib']   = 4
regpos['disp32']    = 5

def opc(op,oplist):
    """
    Adds an opcode to our global list of opcodes, "x86args"
    """
    if op in x86args:
        pass
    else:
        x86args[op]=[]
    oplist.name=op #really a class
    x86args[op].append(oplist)
    return

def getAllMnemonics():
    return x86args.keys()

#format is ([arglist],opcode,column,argsize)
#valid values for column are "" (for n/a), r (for by dest register), and 0-7 for hardcoded

#the ss bits from a scale factor
ssfromscale={}
ssfromscale[1]=0
ssfromscale[2]=1
ssfromscale[4]=2
ssfromscale[8]=3


def intel_byte(myint):
    #used to make negative numbers work as a byte
    if myint<0:
        tmp=chr(256-abs(myint))
    else:
        tmp=chr(myint)
    return tmp

def intel_2byte(myint):
    #used to do 2 byte "words"
    a=chr(myint % 256)
    myint=myint >> 8
    b=chr(myint % 256)
    str="%c%c"%(a,b)
    return str


class needLongCall(Exception): pass

looplist=["loop", "loope","loopz", "loopne", "loopnz"]
class looptoolong(Exception): pass

from threading import RLock

#global mutex here since the x86opcode code can only be used
#by a single thread at a time
x86_assembler_mutex=RLock()

class x86mnemonic:
    def __init__(self,arglist,opcode,column = "",columnloc = 0,argsize = 0 ,effectiveaddressloc = 0,needprefix=1):
        self.name="" #mnemonic
        self.arglist=arglist
        self.opcode=opcode
        self.column=column
        self.columnloc=columnloc
        self.argsize=argsize
        self.longargsize=argsize #only used for calls, but we need this for
        #atandtparse regardless
        self.prefix="" #set if we encounter %fs: in a register expression
        #effectiveaddress is the index into the arglist for the modrm row
        self.effectiveaddressloc=effectiveaddressloc
        self.needprefix=needprefix
        self.modrm = 0
        return

    def get(self,valuelist,context=None,arch=""):

        tmp=""
        self.prefix=""
        global x86_assembler_mutex
        x86_assembler_mutex.acquire()

        #try except block here is because we always always
        #want to release our mutex, but we never want to
        #have more than one thread in this block at any one moment
        #it's also important to notice that no child of this
        #object can override x86mnemonic::get()!!!

        try:
            self.modrm = self.getModRM(valuelist,
                                     context = context,
                                     arch = arch)
            # print "modrm=%s"%hexprint(self.modrm)
            self.argument = self.getArgument(valuelist,
                                             context = context,
                                             arch = arch)
            # print "Arg=%s"%hexprint(self.argument)
        except Exception, msg:
            x86_assembler_mutex.release()
            ##traceback.print_exc(file=sys.stderr)
            raise Exception, msg

        x86_assembler_mutex.release()

        tmp+=self.opcode
        #print "OPCODE=%s"%hexprint(self.opcode)
        tmp+=self.modrm
        tmp+=self.argument
        tmp=self.prefix+tmp
        return tmp

    def getname(self):
        """
        Returns a string representation of this opcode
        """
        ret="%s %s"%(self.name, repr(self.arglist))
        return ret

    def getModRM(self,valuelist,context=None,arch=""):

        # print repr(valuelist)
        # print repr(self.column)
        # print repr(arch)

        # print "Inside getModRM Valuelist=%s"%valuelist
        column=self.column
        # print "column: " + column
        if column=="":
            #we don't need a ModRM byte
            return ""
        if column=="r":
            #get the position of this register in the column list
            #if you get an error here, your columnloc is pointing to a registerexpression...
            additive=regpos[valuelist[self.columnloc]]
        else:
            additive=int(self.column)
        #now we need to find the now
        if self.arglist[self.effectiveaddressloc]=="name":
            return ""
        elif self.arglist[self.effectiveaddressloc]=="reg" \
            or self.arglist[self.effectiveaddressloc] in r8 \
            or self.arglist[self.effectiveaddressloc] in r8_REX_R \
            or self.arglist[self.effectiveaddressloc] in r16 \
            or self.arglist[self.effectiveaddressloc] in r16_REX_R \
            or self.arglist[self.effectiveaddressloc] in r32 \
            or self.arglist[self.effectiveaddressloc] in r32_REX_R \
            or self.arglist[self.effectiveaddressloc] in r64 \
            or self.arglist[self.effectiveaddressloc] in r64_REX_R:
            #print 'Handling reg'
            rp=regpos[valuelist[self.effectiveaddressloc]]
            additive=additive*8
            base=64*3
            row=base+rp
            # print "Row=%2.2x attitive=%d rp=%x"%(row,additive,rp)
            ret=chr(row+additive)
            # print "MODRM=%x"%ord(ret)
            return ret
        elif self.arglist[self.effectiveaddressloc]=="registerexpression":
            # print "Parsing register expression"
            if context==None:
                print "Cannot get argument for a registerexpression with no context, sorry"
                return ""

            registerexpression=valuelist[self.effectiveaddressloc]
            # print "Regexp=%s"%registerexpression
            #a register expression needs to get parsed.
            #you can have label+/-label+/-number(register[,[register,]number])
            # print "Parsing registerexpression: %s"%registerexpression
            newlabels=[]

            #add any prefix needed
            # print "Register Expression Segment Register: %s"%str(registerexpression)
            if registerexpression["segreg"] in ["%fs:", "fs"]:
                if not self.prefix.count("\x64"):
                    self.prefix+="\x64"

            #add any prefix needed
            if registerexpression["segreg"] in ["%gs:", "gs"]:
                if not self.prefix.count("\x65"):
                    self.prefix+="\x65"


            # print "reg2=%s scale=%s reg1=%s"%(registerexpression["reg2"],registerexpression["scalefactor"],registerexpression["reg1"])
            if registerexpression["reg2"] not in ["",None] or registerexpression["scalefactor"]!=1 \
               or registerexpression["reg1"] in ['%esp', '%rsp']:
                # print "Need sib: %s"%str(registerexpression)
                eaddress="needsib"
            elif IsInt(registerexpression["reg1"]):
                # print "Disp32"
                eaddress="disp32"
            else:
                # print "Neither"
                eaddress=registerexpression["reg1"]

            #old versus new check (new being x86parse.py)
            if type(registerexpression["labelsandnumbers"]) in [type(0), type(0L)]:
                #this is the new way to compute the leftvalue - we get it from the parser who
                #has already resolved all the labels into numbers for us and done the addition.
                leftresult=registerexpression["labelsandnumbers"]
            else:
                #this is the old way of computing the leftvalue. We do quite a lot of stuff
                #to a list and add them up ourselves. We know because are passed a list!
                if registerexpression["labelsandnumbers"]:
                    for l in registerexpression["labelsandnumbers"]:
                        loc=context.getLabel(l)
                        # print "Here"
                        if loc!=None:
                            # print "Found location %s at %s"%(l,loc)
                            newlabels.append(loc)
                            continue
                        try:
                            #should this be uint32(int(l,0))? (FutureWarning!)
                            #l=int(l,0)
                            l=long(l,0)
                            newlabels.append(l)
                        except:
                            # print "Could not find %s as a label or number!"%l
                            #Why is this +4+1 there? (sib byte and potential 4 byte register expression argument?)
                            #ok, potentially we have 4 addaddr,1 modrm, and 1 sib bytes
                            #correct way here is to do a needlongcall exception
                            #handler, the way we do in call() opcodes. :<
                            #XXX: TODO: need to make our lea throw these exceptions
                            #to make our shellcode smaller
                            oplen=len(self.prefix)+4+1
                            if eaddress=="needsib":
                                oplen+=1

                            context.addToRedoList(l,oplen)
                            ##TODO WE NEED TO CALCULATE THIS VALUE BETTER!
                            #+1 for modrm byte

                            # print "oplen=%d"%oplen
                            return "\x90"*(oplen)


                leftresult=0
                i=0
                for l in newlabels:
                    if registerexpression["additives"][i]=="+":
                        leftresult+=l
                    else:
                        leftresult+=-l
                    i+=1

            #print "Left Result=%s"%leftresult

            if leftresult==0:
                modbits=0
                #special case for ebp here
                if registerexpression["reg1"] in ['%ebp', '%rbp']:
                    modbits=1
                    addrarg=chr(0)
                else:
                    addrarg=""
            elif abs(leftresult)<128:
                #we are a 8 bit displacement
                modbits=1
                #handle negatives here
                if leftresult<0:
                    addrarg=chr(256-abs(leftresult))
                    #print "Addrarg=%2.2x"%ord(addrarg)
                else:
                    addrarg=chr(leftresult)
            else:
                #32 bit displacement
                modbits=2
                addrarg=intel_order(leftresult)


            #now we have the rmbits and the modbits
            rmbits=regpos[eaddress]
            modrm=chr((modbits<<6)+(additive<<3)+rmbits)
            #print "ModRM Byte=%s"%hexprint(modrm)
            if eaddress=="needsib":
                #print "registerexpression[\"scalefactor\"]=%s"%registerexpression["scalefactor"]
                ss=ssfromscale[dInt(registerexpression["scalefactor"])]
                if registerexpression["scalefactor"]!=1 and registerexpression["reg2"]=="":
                    basebits=5
                    indexbits=regpos[registerexpression["reg1"]]
                else:
                    if registerexpression["reg2"] in ["%esp", '%rsp']:
                        print "ERROR: esp is not allowed to be a index register!"
                    basebits=regpos[registerexpression["reg1"]]
                    if not registerexpression["reg2"]:
                        #we are (esp)
                        indexbits=4
                    else:
                        indexbits=regpos[registerexpression["reg2"]]
                sib=chr((ss<<6)+(indexbits<<3)+basebits)
            elif eaddress=="disp32":
                addrarg=intel_order(dInt(registerexpression["reg1"]))
                sib=""
            else:
                sib=""
            #print "MODRM=%s sib=%s addrarg=%s"%(hexprint(modrm),hexprint(sib),hexprint(addrarg))
            if registerexpression["reg1"] in r64_REX_R:
                self.modrm = modrm
                modrm_test = modrm

                reg = registerexpression['reg1']
                #print "XXX: HANDLING REGISTER EXPRESSION REX SPECIAL CASES R12/R13!"
                if reg == '%r13': # ebp match case
                    self.modrm  = chr(ord(self.modrm)|(0x40))
                    sib += chr(0x00)
                if reg == '%r12':
                    sib = chr((regpos[reg]<<3)|regpos[reg])

                if arch and arch.upper() == "X64":
                    self.get_X64_REX_prefix(valuelist)

                if modrm_test != self.modrm:
                    return self.modrm+sib+addrarg

            return modrm+sib+addrarg

        elif self.arglist[self.effectiveaddressloc]=="constant":
            #movl 1,($1)
            print "Constant location detected in a register expression."
            return "\x05"+intel_order(valuelist[self.effectiveaddressloc])
        else:
            print "ERROR: Was not able to produce a modrm for %s"%self.arglist[self.effectiveaddressloc]
            return ""
        print "How did I get here? effective address is %s"%(self.arglist[self.effectiveaddressloc])
        return ""

    def getArgument(self,valuelist,context=None,arch=""):

        i=0
        tmp=""
        #print "constant getargument"
        for a in self.arglist:
            if a not in ["constant","constant8"]:
                i+=1
                continue

            # 64-bit argument
            if self.argsize == 8:
                #tmp+=int2str64_swapped(int(str(valuelist[i])))
                import struct
                tmp+=struct.pack("<Q",uint64(valuelist[i]))

            if self.argsize == 4:
                #32 bit contant
                #print "Value is %8.8x"%uint32(str(valuelist[i]))

                tmp+=intel_order(uint32(str(valuelist[i])))
            if self.argsize == 1:
                #8 bit constant
                #print "Value: %s"%valuelist[i]
                value=long(valuelist[i])
                #correct for large values which are actually small negative values
                if value>0x7fffffff:
                    value=(value-0xffffffffL-1)
                intval=int(value)
                if intval>0xff:
                    print "ERROR: Trying to use a larger-than-byte constant in x86opcodes: %s: %s - %s"%(self.name,self.arglist,intval)
                    devlog("ERROR: Trying to use a larger-than-byte constant in x86opcodes: %s: %s - %s"%(self.name,self.arglist,intval))
                tmp+=intel_byte(intval)
            if self.argsize == 2:
                #word size, odd.
                tmp+=intel_2byte(int(str(valuelist[i]),0))
                if self.needprefix and not self.prefix.count("\x66"):
                    self.prefix=chr(0x66) + self.prefix
            i+=1

        #we need to add the 16 bit prefix if we are doing a mov for a word ptr (16 bits..)
        for a in valuelist:
            if a in r16:
                if self.needprefix and not self.prefix.count("\x66"):
                    self.prefix=chr(0x66)+self.prefix

        try:
            if arch and arch.upper() == "X64":
                self.get_X64_REX_prefix(valuelist)
        except IndexError:
            pass
        except:
            pass

        return tmp

    # baked in X64 extension support ...
    def get_X64_REX_prefix(self, valuelist, debug = False):

        if debug == True:
            print "[+] Entering get_X64_REX_prefix"
            print "XXX: valuelist: " + repr(valuelist)
            print "XXX: arglist: " + repr(self.arglist)
            print "XXX: argsize: " + repr(self.argsize)

        # XXX: we'll fix up any and all prefixes needed here ...
        # XXX: don't forget to include gs/fs support! :P
        self.prefix = ''

        # 66H: operand-size prefix
        # 67H: address-size prefix

        base_REX    = REX # 0x40 is base REX prefix
        word_mode   = False
        addr32      = False
        position    = 0
        SIB         = False

        for reg in valuelist:

            if self.arglist[position] == 'registerexpression':

                SIB = True

                if 'segreg' in reg:
                    if reg['segreg'] in ['%fs:', 'fs']:
                        self.prefix += chr(0x64)
                    if reg['segreg'] in ['%gs:', 'gs']:
                        self.prefix += chr(0x65)

                if reg['reg1']:

                    if reg['reg1'] in r32 + r32_REX_R:
                        addr32 = True

                        # check for base/index operand size mismatches
                        if (reg['reg2']
                            and reg['reg2'] in r64 + r64_REX_R):
                            print 'XXX: not a valid base/index expression'

                    if (reg['reg1'] in r64_REX_R + r32_REX_R):
                        base_REX    = base_REX | B

                if reg['reg2']:

                    if reg['reg2'] in r32 + r32_REX_R:
                        addr32 = True

                        # check for base/index operand size mismatches
                        if (reg['reg1']
                            and reg['reg1'] in r64 + r64_REX_R):
                            print 'XXX: not a valid base/index expression'

                    if reg['reg2'] in r64_REX_R:
                        base_REX = base_REX | X

            elif self.arglist[position] not in ['constant', 'constant8']:

                if reg in r16 + r16_REX_R:
                    word_mode = True

                if reg in r64 + r64_REX_R:
                    # 64 bit operand size
                    base_REX = base_REX | W

                if (reg in r64_REX_R
                    + r32_REX_R
                    + r16_REX_R
                    + r8_REX_R):
                    rex_map     = { False : {0 : R, 1 : B}, True : {0: B, 1 : R} }
                    base_REX    = base_REX | rex_map[SIB][position]

            elif self.arglist[position] in ['constant', 'constant8']:

                if self.argsize == 2:
                    word_mode = True

            position += 1

        # explicitly set 64 bit operand size on movq, cltq, subq, addq...
        if self.name in ['movq', 'cltq', 'subq', 'addq']:
            base_REX = base_REX | W

        if addr32 == True:
            self.prefix = self.prefix + chr(0x67)

        if word_mode == True:
            self.prefix = self.prefix + chr(0x66)

        # not really sure if inc/dec should be managed here
        # special case single reg operands
        if (self.name in ['push',
                         'pushq',
                         'pop',
                         'popq',
                         'call',
                         'jmp',
                         'mul',
                         'mulq',
                         'inc',
                         'dec']
            or self.name.count('set')):

            # if extended mode, throttle down to just B flag
            if base_REX & R:
                base_REX = (base_REX|B) ^ R

            # no need for explicit size on push/pop/call/jmp...
            if (base_REX & W
                and self.name not in ['mul', 'mulq', 'inc', 'dec']):
                base_REX = base_REX ^ W

        if base_REX != REX:
            # only add prefix on instructions that logically need it
            self.prefix = self.prefix + chr(base_REX)

        return


class signedextended(x86mnemonic):
    """
    Some opcodes, like pushl, take in a signed byte, rather than an unsigned byte
    so we have to account for that here
    """

    def __init__(self,arglist,shortopcode,shortargsize,longopcode,longargsize,column,columnloc,effectiveaddressloc):
        #we default to short.
        x86mnemonic.__init__(self,arglist,shortopcode,column,columnloc,shortargsize,effectiveaddressloc)
        self.shortopcode=shortopcode
        self.shortargsize=shortargsize
        self.longopcode=longopcode
        self.longargsize=longargsize
        self.debug=0

    def getArgument(self,valuelist,context=None,arch=""):
        """
        Get the argument - we may be 1 or 4 bytes depending on sign.
        We currently don't handle 2 byte arguments yet (pushw, etc)
        """
        i=0
        tmp=""
        #print "constant getargument"
        for a in self.arglist:
            if a not in ["constant8"]:
                i+=1
                continue
            if self.shortargsize == 1:
                #8 bit contant - signed though
                #print "Value is %8.8x"%uint32(str(valuelist[i]))
                if issignedbyte(valuelist[i]):
                    #print "Is a signed byte..."
                    self.opcode=self.shortopcode
                    self.argsize=self.shortargsize
                    if valuelist[i]<0:
                        tmp+=chr(0x100-abs(valuelist[i]))
                    else:
                        tmp+=chr(valuelist[i])
                else:
                    self.opcode=self.longopcode
                    self.argsize=self.longargsize
                    tmp+=intel_order(uint32(str(valuelist[i])))

            if self.shortargsize == 2:
                print "!!!!x86opcode.py: We don't handle this yet!!!!"

        try:
            if arch and arch.upper() == 'X64':
                self.get_X64_REX_prefix(valuelist)
        except IndexError:
            pass
        except:
            pass

        return tmp

class call(x86mnemonic):
    """
    A call or jump (or loop) can throw an exception if it needs to be resolved at 4 bytes
    but the backwards resolution has only allocated 2 bytes. Then it gets
    reallocated as 4 the next time around.
    """

    def __init__(self,arglist,shortopcode,shortargsize,longopcode,longargsize,column,columnloc,effectiveaddressloc):
        #we default to short.
        x86mnemonic.__init__(self,arglist,shortopcode,column,columnloc,shortargsize,effectiveaddressloc)
        self.shortopcode=shortopcode
        self.shortargsize=shortargsize
        self.longopcode=longopcode
        self.longargsize=longargsize
        self.debug=0


    def getArgument(self,valuelist,context=None,arch=""):
        """
        our argument is a label ("name") so we need to check to see if it is resolved.
        If it IS resolved, our job is simple
        If it IS NOT resolved, our job is quite complex
        In this, we handle single labels, not register expressions with labels.
        """
        #devlog("mosdef","Call self.argsize=%d - arglist=%s valuelist=%s"%(self.argsize,self.arglist[0],valuelist[0]))
        #print "getArgument: self.arglist[0]=%s"%self.arglist[0]

        if context==None:
            print "Cannot get argument for a call with no context, sorry"
            return None
        #increment the context's call number
        if hasattr(context, "inccall"):
            context.inccall()
        #here we adjust in case we need a long call and we know it
        if hasattr(context, "needlongcall") and context.needlongcall():
            self.argsize=self.longargsize
            self.opcode=self.longopcode
        else:
            self.argsize=self.shortargsize
            self.opcode=self.shortopcode

        if self.arglist[0] in ["constant","constant8"]:

            if self.argsize==4:
                value=dInt(valuelist[0])
                #devlog("mosdef","Constant call value: 0x%x"%value)
                return intel_order(value)

            if self.argsize==1:
                #print "valuelist[0]=%s"%valuelist[0]
                v=dInt(valuelist[0])
                a=abs(v)
                if a>=128:
                    #print "Raising needLongCall!"
                    raise needLongCall
                return intel_byte(v)


        if self.arglist[0]=="name":
            l=valuelist[0]
            if not context.isLabelDefined(l):
                length=self.argsize #taken care of by argsize
                context.addToRedoList(l,0) #was zero...
                #return some filler nops
                if self.debug:
                    #print "Label %s was not defined! Argsize=%d"%(l,self.argsize)
                    pass
                return "\x90"*(length)

            #if we got here, all our labels are defined
            #get location of current instruction
            addr=context.getLabel("./")+len(self.opcode)+len(self.modrm)+self.argsize
            #print "Call Addr: %d"%addr
            #calls and jumps
            dest=context.getLabel(l)
            #print "Call Dest: %d Argsize: %d"%(dest, self.argsize)
            delta=dest-addr
            if self.argsize==1:
                a=abs(delta)
                if self.debug:
                    print "A=%d"%a
                if a>127:
                    if self.debug:
                        print "I need a long call!"
                    if self.name in looplist:
                        raise looptoolong
                    raise needLongCall

            #return 4 bytes in intel order
            #if self.debug:
            #    print "jmp/call found to %s. current=%d dst=%d delta=%d"%(l,addr,dest,delta)
            if self.argsize==4:
                #devlog("mosdef","Call using delta of %x"%delta)
                d= intel_order(delta)
                return d
            else:
                #we are a short call or short jmp
                return intel_byte(delta)

        if self.arglist[0]=="registerexpression":
            #we handle this as a ModRM
            if arch and arch.upper() == "X64":
                self.get_X64_REX_prefix(valuelist)
            return ""
        if self.arglist[0]=="reg":
            if arch and arch.upper() == "X64":
                self.get_X64_REX_prefix(valuelist)
            #we handle this as a ModRM
            return ""
#END CALL FUNCTION


# ADD
opc("add",x86mnemonic(['constant', '%al'],chr(0x04),"",None,1,-1))
opc("add",x86mnemonic(['constant', '%eax'],chr(0x05),"",None,4,-1))
opc("add",x86mnemonic(['constant', '%rax'],chr(0x05),"",None,4,-1))

opc("addb",x86mnemonic(['constant', '%al'],"\x04","",None,1,-1))
opc("addl",x86mnemonic(['constant', '%eax'],"\x05","",None,4,-1))
opc("addq",x86mnemonic(['constant', '%rax'],"\x05","",None,4,-1))

opc("add",x86mnemonic(['constant', 'reg'],"\x81","0",None,4,1))
opc("add",x86mnemonic(['constant', 'registerexpression'],"\x81","0",None,4,1))
opc("addl",x86mnemonic(['constant', 'reg'],"\x81","0",None,4,1))
opc("addl",x86mnemonic(['constant', 'registerexpression'],chr(0x81),"0",None,4,1,needprefix=0))
opc("addq",x86mnemonic(['constant', 'registerexpression'],chr(0x81),"0",None,4,1))

opc("addb",x86mnemonic(['constant8', 'reg'],"\x83","0",None,1,1))
opc("addl",signedextended(['constant8', 'reg'],"\x83", 1, "\x81", 4, "0",None,1))
opc("add",signedextended(['constant8', 'reg'],"\x83", 1, "\x81", 4, "0",None,1))
opc("addb",x86mnemonic(['constant8', 'registerexpression'],"\x83","0",None,1,1))

opc("add",x86mnemonic(["registerexpression","reg"],"\x03","r",1,0,0))
opc("add",x86mnemonic(["reg","registerexpression"],"\x01","r",0,0,1))
opc("addl",x86mnemonic(["registerexpression","reg"],"\x03","r",1,0,0))
opc("addl",x86mnemonic(["reg","registerexpression"],"\x01","r",0,0,1))
opc("addq",x86mnemonic(["registerexpression","reg"],"\x03","r",1,0,0))
opc("addq",x86mnemonic(["reg","registerexpression"],"\x01","r",0,0,1))

for r in r8+r8_REX_R:
    opc("addb",x86mnemonic(["registerexpression",r],"\x02","r",1,0,0))
    opc("addb",x86mnemonic([r,'registerexpression'],"\x00","r",0,0,1))

# 64 bit adds
modifier = 0
for r in r64:
    for r2 in r64_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addq",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addq",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64:
    for r2 in r64:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addq",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addq",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# 32 bit adds
modifier = 0
for r in r32:
    for r2 in r32_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addl",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addl",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32:
    for r2 in r32:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addl",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addl",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8


# 16 bit adds
modifier = 0
for r in r16:
    for r2 in r16_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addw",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16_REX_R:
    for r2 in r16:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addw",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16:
    for r2 in r16:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addw",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16_REX_R:
    for r2 in r16_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addw",x86mnemonic([r,r2],chr(0x01)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# 8 bit adds
modifier = 0
for r in r8:
    for r2 in r8_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addb",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8_REX_R:
    for r2 in r8:
        opc("add",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addb",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8:
    for r2 in r8:
        opc("add",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addb",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8_REX_R:
    for r2 in r8_REX_R:
        opc("add",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("addb",x86mnemonic([r,r2],chr(0x00)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# subs

# 64 bit subs
modifier = 0
for r in r64:
    for r2 in r64_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subq",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subq",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64:
    for r2 in r64:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subq",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subq",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# 32 bit subs
modifier = 0
for r in r32:
    for r2 in r32_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subl",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subl",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32:
    for r2 in r32:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subl",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subl",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# 16 bit subs
modifier = 0
for r in r16:
    for r2 in r16_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subw",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16_REX_R:
    for r2 in r16:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subw",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16:
    for r2 in r16:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subw",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r16_REX_R:
    for r2 in r16_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subw",x86mnemonic([r,r2],chr(0x29)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

# 8 bit subs
modifier = 0
for r in r8:
    for r2 in r8_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subb",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8_REX_R:
    for r2 in r8:
        opc("sub",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subb",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8:
    for r2 in r8:
        opc("sub",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subb",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r8_REX_R:
    for r2 in r8_REX_R:
        opc("sub",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("subb",x86mnemonic([r,r2],chr(0x28)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

#ADD WORD
opc("addw",x86mnemonic(['constant', 'reg'],"\x83","0",None,2,-1))
opc("addw",x86mnemonic(['constant', '%ax'],"\x05","",None,2,-1))
opc("addw",x86mnemonic(['constant', 'registerexpression'],"\x81","0",None,2,-1))

#SUB
opc("sub",x86mnemonic(['constant','%al'],"\x2c","",None,1,-1))
opc("sub",x86mnemonic(['constant','%eax'],"\x2d","",None,4,-1))
opc("sub",x86mnemonic(['constant','%rax'],"\x2d","",None,4,-1))

opc("sub",x86mnemonic(['constant','reg'],"\x81","5",1,4,1))
opc("sub",signedextended(['constant8','reg'],"\x83",1,"\x81",4,"5",1,1))

opc("subl",x86mnemonic(['constant','reg'],"\x81","5",1,4,1))
opc("subl",signedextended(['constant8','reg'],"\x83",1,"\x81",4,"5",1,1))

opc("subq",x86mnemonic(['constant','reg'],'\x81','5',1,4,1))
opc("subq",x86mnemonic(['constant','registerexpression'],'\x81','5',1,4,1))
opc("subq",x86mnemonic(['registerexpression', 'reg'],'\x2b','r',1,1,0))
opc("subq",signedextended(['constant8','reg'],"\x83",1,'\x81',4,'5',1,1))
opc("subq",signedextended(['constant8','registerexpression'],'\x83',1,'\x81',4,'5',1,1))

#CALL
opc("call",call(['name'],"\xe8",4,"\xe8",4,"",None,-1))
opc("call",call(['registerexpression'],"\xff",0,"\xff",0,"2",None,0))
opc("call",call(['reg'],"\xff",1,"\xff",1,"2",4,0))
#call a constant forward/backward (always long call)
opc("call",call(['constant'],"\xe8",4,"\xe8",4,"",None,-1))

for r in r32 + r32_REX_R:
    opc("pop",x86mnemonic([r],chr(0x58+regpos[r]),"",None,0,0,1))
    opc("popl",x86mnemonic([r],chr(0x58+regpos[r]),"",None,0,0,1))
    opc("push",x86mnemonic([r],chr(0x50+regpos[r]),"",None,0,0,1))
    opc("pushl",x86mnemonic([r],chr(0x50+regpos[r]),"",None,0,0,1))

for r in r64 + r64_REX_R:
    opc("pop",x86mnemonic([r],chr(0x58+regpos[r]),"",None,0,0,1))
    opc("popq",x86mnemonic([r],chr(0x58+regpos[r]),"",None,0,0,1))
    opc("push",x86mnemonic([r],chr(0x50+regpos[r]),"",None,0,0,1))
    opc("pushq",x86mnemonic([r],chr(0x50+regpos[r]),"",None,0,0,1))

opc("push",x86mnemonic(["constant"],chr(0x68),"",None,4,0,-1))
opc("pushw",x86mnemonic(["constant"],chr(0x68),"",None,2,0,-1))
opc("pushl",x86mnemonic(["constant"],chr(0x68),"",None,4,0,-1))
opc("pushq",x86mnemonic(["constant"],chr(0x68),"",None,4,0,-1))

#pushw is really 66:68<halfword>
#because we don't know that 201 is < 256 but that it will get sign extended
#by pushl into -55, we have to comment this out. We really need another argument
#type for "constant8unsigned/constant8signed"
opc("pushl",signedextended(["constant8"],chr(0x6a),1,chr(0x68),4,"",None,-1))
opc("push",signedextended(["constant8"],chr(0x6a),1,chr(0x68),4,"",None,-1))

opc("push",x86mnemonic(["registerexpression"],chr(0xff),"6",None,0,0))
opc("pop",x86mnemonic(["registerexpression"],chr(0x8f),"0",None,0,0))

opc("pushl",x86mnemonic(["registerexpression"],chr(0xff),"6",None,0,0))
opc("popl",x86mnemonic(["registerexpression"],chr(0x8f),"0",None,0,0))

opc("pushq",x86mnemonic(["registerexpression"],chr(0xff),"6",None,0,0))
opc("popq",x86mnemonic(["registerexpression"],chr(0x8f),"0",None,0,0))

for r in r64 + r64_REX_R:
    # movw is legal but movl is not
    # switched movq to b8
    opc("movw",x86mnemonic(["constant",r],chr(0xc7)+chr(0xc0+regpos[r]),"",None,2,1))
    opc("mov",x86mnemonic(["constant",r],chr(0xc7)+chr(0xc0+regpos[r]),"",None,4,1))
    opc("movq",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,8,1))

    opc("movw",x86mnemonic(["constant8",r],chr(0xc7)+chr(0xc0+regpos[r]),"",None,2,1))
    opc("mov",x86mnemonic(["constant8",r],chr(0xc7)+chr(0xc0+regpos[r]),"",None,4,1))
    opc("movq",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,8,1))

modifier = 0
for r in r64:
    for r2 in r64_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movq",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("movq",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    opc("movq",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movq",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("movq",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    opc("movq",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    modifier += 8

modifier = 0
for r in r64:
    for r2 in r64:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movq",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r64_REX_R:
    for r2 in r64_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movq",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

for r in r32 + r32_REX_R:
    opc("mov",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,4,1))
    opc("movw",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,2,1))
    opc("movl",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,4,1))

    opc("mov",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",None,4,1))
    opc("movw",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",None,2,1))
    opc("movl",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",None,4,1))

for r in r16 + r16_REX_R:
    opc("movw",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,2,1))
    opc("mov",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",None,2,1))
    opc("movw",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",None,2,1))
    opc("mov",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",None,2,1))

for r in r8 + r8_REX_R:
    opc("movb",x86mnemonic(["constant8",r],chr(0xb0+regpos[r]),"",None,1,1))
    opc("mov",x86mnemonic(["constant8",r],chr(0xb0+regpos[r]),"",None,1,1))

opc("movw",x86mnemonic(["constant","reg"],chr(0xc7),"0",None,2,1))
opc("mov",x86mnemonic(["constant","reg"],chr(0xc7),"0",None,4,1))
opc("movl",x86mnemonic(["constant","reg"],chr(0xc7),"0",None,4,1))

opc("movw",x86mnemonic(["constant8","reg"],chr(0xc7),"0",None,2,1))
opc("mov",x86mnemonic(["constant8","reg"],chr(0xc7),"0",None,4,1))
opc("movl",x86mnemonic(["constant8","reg"],chr(0xc7),"0",None,4,1))

opc("movw",x86mnemonic(["constant","registerexpression"],chr(0xc7),"0",None,2,1))
opc("mov",x86mnemonic(["constant","registerexpression"],chr(0xc7),"0",None,4,1))
opc("movl",x86mnemonic(["constant","registerexpression"],chr(0xc7),"0",None,4,1))
opc("movq",x86mnemonic(["constant","registerexpression"],chr(0xc7),"0",None,4,1))

opc("movw",x86mnemonic(["constant8","registerexpression"],chr(0xc7),"0",None,2,1))
opc("mov",x86mnemonic(["constant8","registerexpression"],chr(0xc7),"0",None,4,1))
opc("movl",x86mnemonic(["constant8","registerexpression"],chr(0xc7),"0",None,4,1))
opc("movq",x86mnemonic(["constant8","registerexpression"],chr(0xc7),"0",None,4,1))

modifier = 0
for r in r32:
    for r2 in r32_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movl",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("movl",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    opc("movl",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movl",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("movl",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,0,0))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    opc("movl",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,0,1))
    modifier += 8

modifier = 0
for r in r32:
    for r2 in r32:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movl",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

modifier = 0
for r in r32_REX_R:
    for r2 in r32_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movl",x86mnemonic([r,r2],chr(0x89)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8

for r in r16 + r16_REX_R:
    opc("movw",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,2,0))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8b),"r",1,2,0))
    opc("movw",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,2,1))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x89),"r",0,2,1))

opc("mov",x86mnemonic(["registerexpression","reg"],chr(0x8b),"r",1,4,0))

#for r in r16:
#    opc("movw",x86mnemonic(["constant",r],chr(0xb8+regpos[r]),"",0,2,1))
#    opc("movw",x86mnemonic(["constant8",r],chr(0xb8+regpos[r]),"",0,2,1))

modifier = 0
for r in r8:
    for r2 in r8:
        opc("mov",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movb",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8
modifier = 0
for r in r8:
    for r2 in r8_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movb",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8
modifier = 0
for r in r8_REX_R:
    for r2 in r8:
        opc("mov",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movb",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8
modifier = 0
for r in r8_REX_R:
    for r2 in r8_REX_R:
        opc("mov",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
        opc("movb",x86mnemonic([r,r2],chr(0x88)+chr(0xc0+regpos[r2]+modifier),"",None,0,0))
    modifier += 8
for r in r8+r8_REX_R:
    opc("mov",x86mnemonic(["constant8",r],chr(0xc6),"0",None,1,1))
    opc("mov",x86mnemonic(["constant8","registerexpression"],chr(0xc6),"0",None,1,1))
    opc("movb",x86mnemonic(["constant8","registerexpression"],chr(0xc6),"0",None,1,1))
    opc("mov",x86mnemonic(["registerexpression",r],chr(0x8a),"r",1,1,0))
    opc("movb",x86mnemonic(["registerexpression",r],chr(0x8a),"r",1,1,0))
    opc("mov",x86mnemonic([r,"registerexpression"],chr(0x88),"r",0,1,1))
    opc("movb",x86mnemonic([r,"registerexpression"],chr(0x88),"r",0,1,1))

opc("lea",x86mnemonic(["registerexpression","reg"],chr(0x8d),"r",1,0,0))
opc("leal",x86mnemonic(["registerexpression","reg"],chr(0x8d),"r",1,0,0))
opc("leaq",x86mnemonic(["registerexpression","reg"],chr(0x8d),"r",1,0,0))


#How to add a new instruction to this list
#1. Go to the intel reference for x86 and find the page with the instruction on it - probably best
#   is to just binary search, rather than using find functionality, although that also works
#2. If the instruction looks like 90+rd or has named registers in it (like EAX)
#   then you have to special case them.
#3. for a /r you use "r" as the register, and the register column location in the argument list
#   needs to be put next
#   Put whatever the memory address argument is as the OTHER argument (i.e. if you have "r",1,whatever,X
#   then X must be 0, and if you have "r",0, then X is 1.
#4. for a /[0-9] you do the same, but hardcode the number instead of r. Column location is None.
#5. If you don't need a second byte, then just use "" for the column
#6. Ignore the 16 bit operations

for r in r32:
    opc("xchg",x86mnemonic([r,"%eax"],chr(0x90+regpos[r]),"",0,0,1))
    opc("xchg",x86mnemonic(["%eax",r],chr(0x90+regpos[r]),"",0,0,1))

for r in r8:
    opc("xchg",x86mnemonic(["registerexpression",r],chr(0x86),"r",1,0,0))
    opc("xchg",x86mnemonic([r,"registerexpression"],chr(0x86),"r",0,0,1))

opc("xchg",x86mnemonic(["reg","registerexpression"],chr(0x87),"r",0,0,1))
opc("xchg",x86mnemonic(["registerexpression","reg"],chr(0x87),"r",1,0,0))
opc("xchg",x86mnemonic(["reg","reg"],chr(0x87),"r",0,2,1))

#if int 3, then we need cc opcode with no arg- - not handled properly here.
#Probably have to hardcode a check for the constant itself. That would suck,
#so you'll just have to use int3 instead
opc("int",x86mnemonic(["constant8"],chr(0xcd),"",0,1,1))
opc("int3",x86mnemonic([],chr(0xcc),"",None,0,-1))

opc("cpuid",x86mnemonic([],chr(0x0f)+chr(0xa2),"",None,0,-1))


opc("cmp",x86mnemonic(["constant8","%al"],chr(0x3c),"",None,1,-1))
opc("cmpb",x86mnemonic(["constant8","%al"],chr(0x3c),"",None,1,-1))
opc("cmp",x86mnemonic(["constant","%eax"],chr(0x3d),"",None,4,-1))
opc("cmpw",x86mnemonic(["constant","%eax"],chr(0x3d),"",None,2,-1))
opc("cmpl",x86mnemonic(["constant","%eax"],chr(0x3d),"",None,4,-1))

# 64-bit
opc("cmp",x86mnemonic(["constant","%rax"],chr(0x3d),"",None,4,-1))
opc("cmpq",x86mnemonic(["constant","%rax"],chr(0x3d),"",None,4,-1))


opc("cmp",x86mnemonic(["constant8","registerexpression"],chr(0x80),"7",None,1,1))
opc("cmpb",x86mnemonic(["constant8","registerexpression"],chr(0x80),"7",None,1,1))

for r in r8:
    opc("cmp",x86mnemonic(["constant8",r],chr(0x80),"7",None,1,1))
    opc("cmpb",x86mnemonic(["constant8",r],chr(0x80),"7",None,1,1))

    opc("cmp",x86mnemonic(["registerexpression",r],chr(0x38),"r",1,0,0))
    opc("cmpb",x86mnemonic(["registerexpression",r],chr(0x38),"r",1,0,0))
    opc("cmpb",x86mnemonic(["reg",r],chr(0x38),"r",0,1,1))
    opc("cmp",x86mnemonic([r,"registerexpression"],chr(0x3a),"r",0,0,1))
    opc("cmpb",x86mnemonic([r,"registerexpression"],chr(0x3a),"r",0,0,1))
    #TODO: CHECK THIS:
    for r2 in r8:
        opc("cmpb",x86mnemonic([r,r2],chr(0x3a),"r",1,0,0))

opc("cmp",x86mnemonic(["constant8","reg"],chr(0x83),"7",None,1,1))
opc("cmpl",x86mnemonic(["constant8","reg"],chr(0x83),"7",None,1,1))
opc("cmp",x86mnemonic(["constant8","registerexpression"],chr(0x83),"7",None,1,1))

opc("cmp",x86mnemonic(["constant","reg"],chr(0x81),"7",None,4,1))
opc("cmpw",x86mnemonic(["constant","reg"],chr(0x81),"7",None,2,1))
opc("cmpl",x86mnemonic(["constant","reg"],chr(0x81),"7",None,4,1))
opc("cmpq",x86mnemonic(["constant","reg"],chr(0x81),"7",None,4,1))


opc("cmp",x86mnemonic(["constant","registerexpression"],chr(0x81),"7",None,4,1))
opc("cmpw",x86mnemonic(["constant","registerexpression"],chr(0x81),"7",None,2,1))
opc("cmpl",x86mnemonic(["constant","registerexpression"],chr(0x81),"7",None,4,1))
opc("cmpq",x86mnemonic(["constant","registerexpression"],chr(0x81),"7",None,4,1))


opc("cmp",x86mnemonic(["reg","registerexpression"],chr(0x39),"r",0,0,1))
opc("cmp",x86mnemonic(["reg","reg"],chr(0x39),"r",0,4,1))
opc("cmpw",x86mnemonic(["reg","registerexpression"],chr(0x39),"r",0,0,1))
opc("cmpl",x86mnemonic(["reg","registerexpression"],chr(0x39),"r",0,0,1))
opc("cmpl",x86mnemonic(["reg","reg"],chr(0x39),"r",0,4,1))
opc("cmpq",x86mnemonic(["reg","reg"],chr(0x39),"r",0,8,1))

opc("cmp",x86mnemonic(["registerexpression","reg"],chr(0x3b),"r",1,0,0))
opc("cmpw",x86mnemonic(["registerexpression","reg"],chr(0x3b),"r",1,0,0))
opc("cmpl",x86mnemonic(["registerexpression","reg"],chr(0x3b),"r",1,0,0))
opc("cmpq",x86mnemonic(["registerexpression","reg"],chr(0x3b),"r",1,0,0))

#All the jumps. Sheesh

opc("ja",call(["constant"],chr(0x77),1,"\x0f\x87",4,"",None,-4))
opc("jae",call(["constant"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jb",call(["constant"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("jbe",call(["constant"],chr(0x76),1,"\x0f\x86",4,"",None,-4))
opc("jcxz",call(["constant"],chr(0xe3),1,chr(0xe3),1,"",None,-4))
opc("jecxz",call(["constant"],chr(0xe3),1,chr(0xe3),1,"",None,-4))
opc("jc",call(["constant"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("je",call(["constant"],chr(0x74),1,"\x0f\x84",4,"",None,-4))
opc("jg",call(["constant"],chr(0x7f),1,"\x0f\x8f",4,"",None,-4))
opc("jge",call(["constant"],chr(0x7d),1,"\x0f\x8d",4,"",None,-4))
opc("jl",call(["constant"],chr(0x7c),1,"\x0f\x8c",4,"",None,-4))
opc("jle",call(["constant"],chr(0x7e),1,"\x0f\x8e",4,"",None,-4))
opc("jna",call(["constant"],chr(0x76),1,"\x0f\x86",4,"",None,-4))
opc("jnae",call(["constant"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("jnb",call(["constant"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jnbe",call(["constant"],chr(0x77),1,"\x0f\x87",4,"",None,-4))
opc("jnc",call(["constant"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jne",call(["constant"],chr(0x75),1,"\x0f\x85",4,"",None,-4))
opc("jng",call(["constant"],chr(0x7e),1,"\x0f\x8e",4,"",None,-4))
opc("jnge",call(["constant"],chr(0x7c),1,"\x0f\x8c",4,"",None,-4))
opc("jnl",call(["constant"],chr(0x7d),1,"\x0f\x8d",4,"",None,-4))
opc("jnle",call(["constant"],chr(0x7f),1,"\x0f\x8f",4,"",None,-4))
opc("jno",call(["constant"],chr(0x71),1,"\x0f\x84",4,"",None,-4))
opc("jnp",call(["constant"],chr(0x7b),1,"\x0f\x8b",4,"",None,-4))
opc("jns",call(["constant"],chr(0x79),1,"\x0f\x89",4,"",None,-4))
opc("jnz",call(["constant"],chr(0x75),1,"\x0f\x85",4,"",None,-4))
opc("jo",call(["constant"],chr(0x70),1,"\x0f\x80",4,"",None,-4))
opc("jp",call(["constant"],chr(0x7a),1,"\x0f\x8a",4,"",None,-4))
opc("jpe",call(["constant"],chr(0x7a),1,"\x0f\x8a",4,"",None,-4))
opc("jpo",call(["constant"],chr(0x7b),1,"\x0f\x8b",4,"",None,-4))
opc("js",call(["constant"],chr(0x78),1,"\x0f\x88",4,"",None,-4))
opc("jz",call(["constant"],chr(0x74),1,"\x0f\x84",4,"",None,-4))


opc("ja",call(["name"],chr(0x77),1,"\x0f\x87",4,"",None,-4))
opc("jae",call(["name"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jb",call(["name"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("jbe",call(["name"],chr(0x76),1,"\x0f\x86",4,"",None,-4))
opc("jcxz",call(["name"],chr(0xe3),1,chr(0xe3),1,"",None,-4))
opc("jecxz",call(["name"],chr(0xe3),1,chr(0xe3),1,"",None,-4))
opc("jc",call(["name"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("je",call(["name"],chr(0x74),1,"\x0f\x84",4,"",None,-4))
opc("jg",call(["name"],chr(0x7f),1,"\x0f\x8f",4,"",None,-4))
opc("jge",call(["name"],chr(0x7d),1,"\x0f\x8d",4,"",None,-4))
opc("jl",call(["name"],chr(0x7c),1,"\x0f\x8c",4,"",None,-4))
opc("jle",call(["name"],chr(0x7e),1,"\x0f\x8e",4,"",None,-4))
opc("jna",call(["name"],chr(0x76),1,"\x0f\x86",4,"",None,-4))
opc("jnae",call(["name"],chr(0x72),1,"\x0f\x82",4,"",None,-4))
opc("jnb",call(["name"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jnbe",call(["name"],chr(0x77),1,"\x0f\x87",4,"",None,-4))
opc("jnc",call(["name"],chr(0x73),1,"\x0f\x83",4,"",None,-4))
opc("jne",call(["name"],chr(0x75),1,"\x0f\x85",4,"",None,-4))
opc("jng",call(["name"],chr(0x7e),1,"\x0f\x8e",4,"",None,-4))
opc("jnge",call(["name"],chr(0x7c),1,"\x0f\x8c",4,"",None,-4))
opc("jnl",call(["name"],chr(0x7d),1,"\x0f\x8d",4,"",None,-4))
opc("jnle",call(["name"],chr(0x7f),1,"\x0f\x8f",4,"",None,-4))
opc("jno",call(["name"],chr(0x71),1,"\x0f\x84",4,"",None,-4))
opc("jnp",call(["name"],chr(0x7b),1,"\x0f\x8b",4,"",None,-4))
opc("jns",call(["name"],chr(0x79),1,"\x0f\x89",4,"",None,-4))
opc("jnz",call(["name"],chr(0x75),1,"\x0f\x85",4,"",None,-4))
opc("jo",call(["name"],chr(0x70),1,"\x0f\x80",4,"",None,-4))
opc("jp",call(["name"],chr(0x7a),1,"\x0f\x8a",4,"",None,-4))
opc("jpe",call(["name"],chr(0x7a),1,"\x0f\x8a",4,"",None,-4))
opc("jpo",call(["name"],chr(0x7b),1,"\x0f\x8b",4,"",None,-4))
opc("js",call(["name"],chr(0x78),1,"\x0f\x88",4,"",None,-4))
opc("jz",call(["name"],chr(0x74),1,"\x0f\x84",4,"",None,-4))

opc("jmp",call(["constant"],"\xeb",1,"\xe9",4,"",None,-4))
opc("jmp",call(["name"],"\xeb",1,"\xe9",4,"",None,-4))


opc("jmp",call(["registerexpression"],"\xff",4,"\xff",4,"4",None,0))
opc("jmp",call(["reg"],"\xff",4,"\xff",4,"4",None,0))



#RET
opc("ret",x86mnemonic([],chr(0xc3),"",0,0,-1))
opc("farret",x86mnemonic([],chr(0xcb),"",0,0,-1))
opc("ret",x86mnemonic(["constant"],chr(0xc2),"",0,2,-1,needprefix=0))
opc("farret",x86mnemonic(["constant"],chr(0xca),"",0,2,-1,needprefix=0))



#TEST
opc("test",x86mnemonic(["constant8","%al"],chr(0xa8),"",None,1,-1))
opc("test",x86mnemonic(["constant","%eax"],chr(0xa9),"",None,4,-1))
opc("test",x86mnemonic(["constant8","registerexpression"],chr(0xf6),"0",None,1,-1))
#test constant8 and testb here are slightly incorrect - we don't
#check for edi or esi as our reg and hence are incorrect on those
#registers.
opc("test",x86mnemonic(["constant8","reg"],chr(0xf6),"0",None,1,-1))
opc("testb",x86mnemonic(["constant8","reg"],chr(0xf6),"0",None,1,-1))
opc("test",x86mnemonic(["constant","registerexpression"],chr(0xf7),"0",None,1,-1))
opc("testw",x86mnemonic(["constant","reg"],chr(0xf7),"0",None,2,-1))
for r in r8:
    opc("test",x86mnemonic([r,"registerexpression"],chr(0x84),"r",0,0,1))
    for r2 in r8:
        opc("test",x86mnemonic([r,r2],chr(0x84),"r",0,0,1))

opc("test",x86mnemonic(["reg","registerexpression"],chr(0x85),"r",0,0,1))
opc("test",x86mnemonic(["reg","reg"],chr(0x85),"r",0,0,1))
opc("testl",x86mnemonic(["reg","reg"],chr(0x85),"r",0,0,1))
opc("testq",x86mnemonic(["reg","reg"],chr(0x85),"r",0,0,1))

#XOR
opc("xor", x86mnemonic(["constant8","%al"],chr(0x34),"",None,1,-1))
opc("xorb", x86mnemonic(["constant8","%al"],chr(0x34),"",None,1,-1))
opc("xor", x86mnemonic(["constant","%eax"],chr(0x35),"",None,4,-1))
opc("xorl", x86mnemonic(["constant","%eax"],chr(0x35),"",None,4,-1))
opc("xorb", x86mnemonic(["constant8","registerexpression"],chr(0x80),"6",None,1,-1))
opc("xor", x86mnemonic(["constant","registerexpression"],chr(0x81),"6",None,4,-1))
opc("xorl", x86mnemonic(["constant","registerexpression"],chr(0x81),"6",None,4,-1))
opc("xor", x86mnemonic(["constant","reg"],chr(0x81),"6",None,4,-1))
opc("xorl", x86mnemonic(["constant","reg"],chr(0x81),"6",None,4,-1))
opc("xorb", x86mnemonic(["reg","registerexpression"],chr(0x30),"r",0,0,1))
opc("xor", x86mnemonic(["reg","registerexpression"],chr(0x31),"r",0,0,1))
opc("xorl", x86mnemonic(["reg","registerexpression"],chr(0x31),"r",0,0,1))
opc("xorb", x86mnemonic(["registerexpression","reg"],chr(0x32),"r",1,0,0))
opc("xor", x86mnemonic(["registerexpression","reg"],chr(0x33),"r",1,0,0))
opc("xor", x86mnemonic(["reg","reg"],chr(0x33),"r",1,0,0))
opc("xorl", x86mnemonic(["reg","reg"],chr(0x33),"r",1,0,0))
opc("xorl", x86mnemonic(["registerexpression","reg"],chr(0x33),"r",1,0,0))

#SHL
for r in r8:
    opc("shl",  x86mnemonic(["constant8",r],chr(0xc0),"4",None,1,1))
    opc("shr",  x86mnemonic(["constant8",r],chr(0xc0),"5",None,1,1))
for r in r8:
    opc("shl",  x86mnemonic(["%cl",r],chr(0xd2),"4",None,0,1))
    opc("shr",  x86mnemonic(["%cl",r],chr(0xd2),"5",None,0,1))

for r in r32:
    opc("shl",  x86mnemonic(["%cl",r],chr(0xd3),"4",None,0,1))
    opc("shr",  x86mnemonic(["%cl",r],chr(0xd3),"5",None,0,1))

for r in r64 + r64_REX_R:
    opc("shl",  x86mnemonic(["%cl",r],chr(0xd3),"4",None,0,1))
    opc("shr",  x86mnemonic(["%cl",r],chr(0xd3),"5",None,0,1))

opc("shl",  x86mnemonic(["constant8","registerexpression"],chr(0xc1),"4",None,1,1))
opc("shr",  x86mnemonic(["constant8","registerexpression"],chr(0xc1),"5",None,1,1))
opc("shl",  x86mnemonic(["constant8","reg"],chr(0xc1),"4",None,1,1))
opc("shr",  x86mnemonic(["constant8","reg"],chr(0xc1),"5",None,1,1))
opc("shll",  x86mnemonic(["constant8","registerexpression"],chr(0xc1),"4",None,1,1))
opc("shrl",  x86mnemonic(["constant8","registerexpression"],chr(0xc1),"5",None,1,1))
opc("shll",  x86mnemonic(["constant8","reg"],chr(0xc1),"4",None,1,1))
opc("shrl",  x86mnemonic(["constant8","reg"],chr(0xc1),"5",None,1,1))

#ROR
opc("ror", x86mnemonic(["constant8", "reg"], chr(0xc1), "1", None, 1, 1))

#OR
opc("or",x86mnemonic(["constant8","%al"],chr(0x0c),"",None,1,-1))
opc("or",x86mnemonic(["constant","%eax"],chr(0x0d),"",None,4,-1))
opc("orb",x86mnemonic(["constant8","registerexpression"],chr(0x80),"1",None,1,1))
opc("orb",x86mnemonic(["constant8","reg"],chr(0x80),"1",None,1,1))
opc("orb",x86mnemonic(["reg","reg"],chr(0x0a),"r",1,0,0))
opc("or",x86mnemonic(["constant8","registerexpression"],chr(0x80),"1",None,1,1))
opc("or",x86mnemonic(["constant8","reg"],chr(0x80),"1",None,1,1))


opc("or",x86mnemonic(["constant","registerexpression"],chr(0x81),"1",None,4,1))
opc("orl",x86mnemonic(["constant","registerexpression"],chr(0x81),"1",None,4,1))
opc("or",x86mnemonic(["constant","reg"],chr(0x81),"1",None,4,1))
opc("orl",x86mnemonic(["constant","reg"],chr(0x81),"1",None,4,1))
#sign extended
#opc("or",x86mnemonic(["constant8"."registerexpression"],chr(0x83),"1",None,1,1))
opc("or",x86mnemonic(["reg","registerexpression"],chr(0x09),"r",0,0,1))
opc("or",x86mnemonic(["reg","reg"],chr(0x09),"r",0,0,1))
opc("orl",x86mnemonic(["reg","reg"],chr(0x09),"r",0,0,1))
opc("orl",x86mnemonic(["reg","registerexpression"],chr(0x09),"r",0,0,1))

for r in r8:
    opc("or",x86mnemonic([r,"registerexpression"],chr(0x08),"r",0,0,1))

    # support orb %bl,%bh type stuff
    for shortreg in r8:
        opc("or",x86mnemonic([r,shortreg],chr(0x08),"r",0,0,1))
        opc("orb",x86mnemonic([r,shortreg],chr(0x08),"r",0,0,1))

    opc("or",x86mnemonic(["registerexpression",r],chr(0x0a),"r",1,0,0))

opc("or",x86mnemonic(["registerexpression","reg"],chr(0x0b),"r",1,0,0))

#LOOP
opc("loop",call(["name"],chr(0xe2),1,chr(0xe2),1,"",None,0))
opc("loope",call(["name"],chr(0xe1),1,chr(0xe2),1,"",None,0))
opc("loopz",call(["name"],chr(0xe1),1,chr(0xe2),1,"",None,0))
opc("loopne",call(["name"],chr(0xe0),1,chr(0xe2),1,"",None,0))
opc("loopnz",call(["name"],chr(0xe0),1,chr(0xe2),1,"",None,0))

# we invented a new opcode: loop $rel16/rel32 !!
opc("loop",call(["constant"],chr(0xe2),1,"\x49\xe9",4,"",None,0))
opc("loope",call(["constant"],chr(0xe1),1,"\x49\x0f\x84",4,"",None,0))
opc("loopz",call(["constant"],chr(0xe1),1,"\x49\x0f\x84",4,"",None,0))
opc("loopne",call(["constant"],chr(0xe0),1,"\x49\x0f\x85",4,"",None,0))
opc("loopnz",call(["constant"],chr(0xe0),1,"\x49\x0f\x85",4,"",None,0))

#INC
opc("inc",x86mnemonic(["registerexpression"],chr(0xff),"0",None,0,0))
opc("inc",x86mnemonic(["reg"],chr(0xff),"0",None,0,0))
opc("incl",x86mnemonic(["registerexpression"],chr(0xff),"0",None,0,0))
opc("incl",x86mnemonic(["reg"],chr(0xff),"0",None,0,0))
opc("incb",x86mnemonic(["registerexpression"],chr(0xfe),"0",None,0,0))
for r2 in r8:
    opc("incb",x86mnemonic([r2],chr(0xfe),"0",None,0,0))



#bit test instruction
opc("bt",x86mnemonic(["constant8","reg"],"\x0f\xba","4",None,1,1))

for r in r32:
    # we invalidate the optimised matches for X64 in x86parse
    # and fall through to the non-optimized matches, REX prefix range
    # can NOT be used as an opcode in X64 mode
    opc("inc",x86mnemonic([r],chr(0x40+regpos[r]),"",None,0,0))
    opc("incl",x86mnemonic([r],chr(0x40+regpos[r]),"",None,0,0))
    opc("bswap",x86mnemonic([r],"\x0f"+chr(0xc8+regpos[r]),"",None,0,0))

for r in r16:
    #add halfword prepend to them
    opc("incw",x86mnemonic([r],chr(0x40+regpos[r]),"",None,0,0))

#DEC
opc("dec",x86mnemonic(["registerexpression"],chr(0xff),"1",None,0,0))
opc("dec",x86mnemonic(["reg"],chr(0xff),"1",None,0,0))
opc("decl",x86mnemonic(["registerexpression"],chr(0xff),"1",None,0,0))
opc("decl",x86mnemonic(["reg"],chr(0xff),"1",None,0,0))
opc("decb",x86mnemonic(["registerexpression"],chr(0xfe),"1",None,0,0))
for r2 in r8:
    opc("decb",x86mnemonic([r2],chr(0xfe),"1",None,0,0))

for r in r32:
    opc("dec",x86mnemonic([r],chr(0x48+regpos[r]),"",None,0,0))
    opc("decl",x86mnemonic([r],chr(0x48+regpos[r]),"",None,0,0))

#CWD/CDQ page 854
opc("cdq",x86mnemonic([],chr(0x99),"",None,0,0))
opc("cwd",x86mnemonic([],chr(0x99),"",None,0,0))
opc("cdql",x86mnemonic([],chr(0x99),"",None,0,0))
opc("nop",x86mnemonic([],chr(0x90),"",None,0,0))
opc("cld",x86mnemonic([],chr(0xfc),"",None,0,0))
#can be used to clear or set edx based on eax's top bit
opc("cltd",x86mnemonic([],chr(0x99),"",None,0,0))
opc("cltq", x86mnemonic([],chr(0x98), "", None, 0, 0))
opc("pushad",x86mnemonic([],chr(0x60),"",None,0,0))
opc("popad",x86mnemonic([],chr(0x61),"",None,0,0))

opc("pushfd",x86mnemonic([],chr(0x9c),"",None,0,0))
opc("popfd",x86mnemonic([],chr(0x9d),"",None,0,0))

opc("pushf",x86mnemonic([],chr(0x9c),"",None,0,0))
opc("popf",x86mnemonic([],chr(0x9d),"",None,0,0))

opc("leave",x86mnemonic([],chr(0xc9),"",None,0,0))

#AND - Logical And, Page 70
#remember, intel's documentation is backwards...
opc("and",x86mnemonic(["constant8","registerexpression"],chr(0x83),"4",None,0,1))
opc("andb",x86mnemonic(["constant8","registerexpression"],chr(0x83),"4",None,0,1))
opc("and",x86mnemonic(["constant8","reg"],chr(0x83),"4",None,1,1))
opc("andb",x86mnemonic(["constant8","reg"],chr(0x83),"4",None,1,1))

#81 /4 id   AND r/m32,imm32
opc("and",x86mnemonic(["constant","registerexpression"],chr(0x81),"4",None,4,1))
opc("andl",x86mnemonic(["constant","registerexpression"],chr(0x81),"4",None,4,1))
opc("and",x86mnemonic(["constant","reg"],chr(0x81),"4",None,4,1))

opc("andw",x86mnemonic(["constant","reg"],chr(0x81),"4",None,2,1))

opc("andl",x86mnemonic(["constant","reg"],chr(0x81),"4",None,4,1))

opc("and",x86mnemonic(["constant8","%al"],chr(0x24),"",None,1,1))
opc("andb",x86mnemonic(["constant8","%al"],chr(0x24),"",None,1,1))
opc("and",x86mnemonic(["constant","%eax"],chr(0x25),"",None,4,1))
opc("andl",x86mnemonic(["constant","%eax"],chr(0x25),"",None,4,1))

for r2 in r8:
    opc("and",x86mnemonic(["constant8",r2],chr(0x80),"4",None,1,1))
    opc("andb",x86mnemonic(["constant8",r2],chr(0x80),"4",None,1,1))
    opc("and",x86mnemonic([r2,"registerexpression"],chr(0x20),"r",1,0,0))
    opc("andb",x86mnemonic([r2,"registerexpression"],chr(0x20),"r",1,0,0))

    # support andb %cl,%bl type stuff correctly
    for shortreg in r8:
        opc("and",x86mnemonic([r2, shortreg],chr(0x20),"r",0,0,1))
        opc("andb",x86mnemonic([r2, shortreg],chr(0x20),"r",0,0,1))

#CHECK THIS
for r2 in r8:
    opc("andb",x86mnemonic(["registerexpression",r2],chr(0x22),"r",0,0,1))
    opc("andb",x86mnemonic(["reg",r2],chr(0x22),"r",0,0,1))
    opc("and",x86mnemonic(["registerexpression",r2],chr(0x22),"r",0,0,1))
    opc("and",x86mnemonic(["reg",r2],chr(0x22),"r",0,0,1))

opc("and",x86mnemonic(["reg","registerexpression"],chr(0x21),"r",1,0,0))
opc("and",x86mnemonic(["reg","reg"],chr(0x21),"r",0,0,1))
opc("andl",x86mnemonic(["reg","registerexpression"],chr(0x21),"r",1,0,0))
opc("andl",x86mnemonic(["reg","reg"],chr(0x21),"r",0,0,1))

opc("and",x86mnemonic(["registerexpression","reg"],chr(0x23),"r",1,0,0))

opc("mul",x86mnemonic(["registerexpression"],chr(0xf7),"4",None,0,0))
opc("mul",x86mnemonic(["reg"],chr(0xf7),"4",None,0,0))
opc("imul",x86mnemonic(["constant","reg"],chr(0x69),"r",1,4,1))


for r2 in r8:
    opc("mul",x86mnemonic([r2],chr(0xf6),"4",None,0,0))

opc("neg",x86mnemonic(["registerexpression"],chr(0xf7),"3",None,0,0))
opc("neg",x86mnemonic(["reg"],chr(0xf7),"3",None,0,0))
for r2 in r8:
    opc("neg",x86mnemonic([r2],chr(0xf6),"3",None,0,0))

opc("not",x86mnemonic(["registerexpression"],chr(0xf7),"2",None,0,0))
opc("not",x86mnemonic(["reg"],chr(0xf7),"2",None,0,0))

for r2 in r8:
    opc("not",x86mnemonic([r2],chr(0xf6),"2",None,0,0))

for r2 in r8:
    opc("movzbl",x86mnemonic([r2,"registerexpression"],"\x0f\xb6","r",1,0,0))
    opc("movzbl",x86mnemonic([r2,"reg"],"\x0f\xb6","r",1,0,0))

opc("movzbl",x86mnemonic(["reg","reg"],"\x0f\xb6","r",1,0,0))

opc("movzbl",x86mnemonic(["registerexpression","reg"],"\x0f\xb6","r",1,0,0))
#for r2 in r16:
#    opc("movzwl",x86mnemonic([r2,"reg"],"\x0f\xb7","r",1,0,0))
#    opc("movzwl",x86mnemonic([r2,"registerexpression"],"\x0f\xb7","r",1,0,0))

opc("movzwl",x86mnemonic(["registerexpression","reg"],"\x0f\xb7","r",1,0,0))
opc("movzwl",x86mnemonic(["reg","reg"],"\x0f\xb7","r",1,0,0))
opc("movzwl",x86mnemonic(["reg","registerexpression"],"\x0f\xb7","r",1,0,0))

opc("div",x86mnemonic(["registerexpression"],"\xf7","6",0,0,0))
opc("div",x86mnemonic(["reg"],"\xf7","6",0,0,0))
opc("idivl",x86mnemonic(["reg"],"\xf7","6",0,0,0))

for r in r8:
    opc("div",x86mnemonic([r],"\xf6","6",0,0,0))

#page 409 in intel.pdf
opc("lodsb",x86mnemonic([],chr(0xac),"",None,0,0))
opc("lodsd",x86mnemonic([],chr(0xad),"",None,0,0))
opc("lodsl",x86mnemonic([],chr(0xad),"",None,0,0))
opc("lodsw",x86mnemonic([],chr(0xad),"",None,2,0)) #UNSURE IF IS CORRECT! This is a word operation


#see page 672 of intel.pdf
for r in r8:
    opc("seta",x86mnemonic([r],"\x0f\x97","r",0,0,0))
    opc("setae",x86mnemonic([r],"\x0f\x93","r",0,0,0))
    opc("setb",x86mnemonic([r],"\x0f\x92","r",0,0,0))
    opc("setbe",x86mnemonic([r],"\x0f\x96","r",0,0,0))
    opc("setna",x86mnemonic([r],"\x0f\x96","r",0,0,0))
    opc("setc",x86mnemonic([r],"\x0f\x92","r",0,0,0))
    opc("setg",x86mnemonic([r],"\x0f\x9f","r",0,0,0))
    opc("setge",x86mnemonic([r],"\x0f\x9d","r",0,0,0))
    opc("setl",x86mnemonic([r],"\x0f\x9c","r",0,0,0))
    opc("setle",x86mnemonic([r],"\x0f\x9e","r",0,0,0))
    opc("setne",x86mnemonic([r],"\x0f\x95","r",0,0,0))
    opc("sete",x86mnemonic([r],"\x0f\x94","r",0,0,0))
for r in r8_REX_R:
    opc("seta",x86mnemonic([r],"\x0f\x97"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setae",x86mnemonic([r],"\x0f\x93"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setb",x86mnemonic([r],"\x0f\x92"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setbe",x86mnemonic([r],"\x0f\x96"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setna",x86mnemonic([r],"\x0f\x96"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setc",x86mnemonic([r],"\x0f\x92"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setg",x86mnemonic([r],"\x0f\x9f"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setge",x86mnemonic([r],"\x0f\x9d"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setl",x86mnemonic([r],"\x0f\x9c"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setle",x86mnemonic([r],"\x0f\x9e"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("setne",x86mnemonic([r],"\x0f\x95"+chr(0xc0+regpos[r]),"",0,0,0))
    opc("sete",x86mnemonic([r],"\x0f\x94"+chr(0xc0+regpos[r]),"",0,0,0))

opc("rep",x86mnemonic([],"\xf3","",0,0,0))
opc("repe",x86mnemonic([],"\xf3","",0,0,0))
opc("repne",x86mnemonic([],"\xf2","",0,0,0))

opc("insb",x86mnemonic([],"\x6c","",0,0,0))
opc("insw",x86mnemonic([],"\x6d","",0,0,0))
opc("insl",x86mnemonic([],"\x6d","",0,0,0))
opc("movsb",x86mnemonic([],"\xa4","",0,0,0))
opc("movsw",x86mnemonic([],"\xa5","",0,0,0))
opc("movsl",x86mnemonic([],"\xa5","",0,0,0))
opc("stosb",x86mnemonic([],"\xaa","",0,0,0))
opc("stosw",x86mnemonic([],"\xab","",0,0,0))
opc("stosl",x86mnemonic([],"\xab","",0,0,0))
opc("cmpsb",x86mnemonic([],"\xa6","",0,0,0))
opc("cmpsw",x86mnemonic([],"\xa7","",0,0,0))
opc("cmpsl",x86mnemonic([],"\xa7","",0,0,0))
opc("scasb",x86mnemonic([],"\xae","",0,0,0))
opc("scasw",x86mnemonic([],"\xaf","",0,0,0))
opc("scasl",x86mnemonic([],"\xaf","",0,0,0))

opc("sidt",x86mnemonic(["registerexpression"],"\x0f\x01","1",1,0,0))
opc("sgdt",x86mnemonic(["registerexpression"],"\x0f\x01","0",1,0,0))

opc("syscall", x86mnemonic([], "\x0f\x05"))
opc("sysenter", x86mnemonic([], "\x0f\x34"))


def convertfromintel(opcode, instruction,definition=""):
    """
    Converts the format in intel's pdf to our stuff
    Example:
    >>print convertfromintel("25 id","AND EAX,imm32")
    opc("AND",x86mnemonic(["constant",%eax],chr(0x25),"",None,0,4))

    """
    words=opcode.split(" ")
    op="chr(0x%s)"%words[0]
    words=words[1:]
    for w in words:
        if not w[0].isupper():
            #time to move on to next step
            break
        op+="+chr(%s)"%w
        words=words[1:]
    #now we're looking at either nothing
    #or at /r
    #or at /4 id
    columnloc=0
    if len(words)>0:
        #we do have a register or argument
        if words[0][0]=="/":
            #we have a register column (number or r)
            column="\"%s\""%words[0][1]
            words=words[1:]
        else:
            column="\"\""
            columnloc="None"

    argsize=0
    if len(words)>0:
        #we do have a argument
        dic={"b":1,"w":2,"d":4}
        argsize=dic[words[0][1]]


    #now we need to parse the instruction
    words=instruction.split(" ")
    name=words[0].lower()
    words=words[1:]
    prefix=""
    arglist=[]
    if len(words)>0:
        argloc=0
        currloc=0
        #we have arguments
        words=words[0].split(",")
        args=[]
        for w in words:
            if w.count("/"):
                #we don't treat r/m8 and r/m32 differently...bug?
                arg="\"registerexpression\""
                argloc=currloc
            elif w=="r8":
                arg="r"
                prefix="for r in r8:\n    "
            elif w=="r32":
                arg="\"reg\""
            elif w=="imm8":
                arg="\"constant8\""
            elif w=="imm32":
                arg="\"constant\""
            else:
                arg="%"+w.lower()
            args+=[arg]
        #intel has it backwards...
        args.reverse()
        arglist=",".join(args)

    if argloc==0 and columnloc==0:
        columnloc=1

    ret=prefix+"opc(\"%s\",x86mnemonic([%s],%s,%s,%s,%s,%s)) %s"%(name,arglist,op,column,columnloc,argsize,argloc,"#"+definition)
    return ret

if __name__=="__main__":
    #print convertfromintel("25 id","AND EAX,imm32")
    ##print convertfromintel("23 /r","AND r32,r/m32")
    #print convertfromintel("20 /r","AND r/m8,r8")
    #l=getAllMnemonics()
    #l.sort()
    #l.reverse()
    #print "r'%s'"%"|".join(l)
    for i in x86args:
        for y in x86args[i]:
            if y.opcode==y.opcode.lower():
                print "%s"%i

