#! /usr/bin/env python


"""
atandtparse.py

Copyright Dave Aitel 2003
"""
import sys
sys.setrecursionlimit (4000)
import urllib

from mosdefutils import *
import re
import time
VERSION="1.0"

TODO="""

.db

TEST IT ALL

"""

from spark import GenericParser
from spark import GenericASTBuilder
from spark import GenericASTTraversal

from ast import AST

from x86opcodes import x86args
from x86opcodes import needLongCall
from mosdefutils import *

nonterminal = GenericASTBuilder.nonterminal
foldtree = lambda n: getattr(n,'attr',0) or ''.join(map(foldtree,n._kids))

class GenerateException(Exception):
    pass

#overwrites a string in place...hard to do in python
def stroverwrite(instring,overwritestring,offset):
    head=instring[:offset]
    #print head
    tail=instring[offset+len(overwritestring):]
    #print tail
    result=head+overwritestring+tail
    return result


#def halfword2istr(halfword):
#    data=""
#    a=halfword & 0xff
#    b=halfword/256 & 0xff
#    data+=chr(a)+chr(b)
#    return data

def isbyte(anint):
    """
    tests if this int fits into a byte
    This will break opcodes that do sign extention...
    """
    if anint>=0 and anint<=256:
        return 1
    if anint<0 and anint>=-128:
        return 1
    return 0
        

def unslashify(value):
    """
    \r -> 0x0d, etc
    """
    replacements=[["\\r","\r"],["\\n","\n"],["\\\\","\\"],["\\0","\0"]]
    for r in replacements:
        value=value.replace(r[0],r[1])
    return value


def atandtpreprocess(data):
    """
    This function's job is to fix up all the .set's and do any other preprocessing
    """

    datalines=data.split("\n")
    for line in datalines:
        # allows the asm to have comments after instructions
        if line.count(";") != 0:
                old = line
                #print "line contains comments"
                line,misc = line.split(";")
                data = data.replace(old,line)
        line=line.strip()
        if line[:len(".set")]==".set":
            line2=line[4:]
            name=line2.split(",")[0]
            value=line2.split(",")[1]
            name=name.strip()
            value=value.strip()
            #print "Name=%s Value=%s"%(name,value)
            #match a whole word.
            r=re.compile(name+r'([^a-zA-Z0-9])')
            data=data.replace(line,"")
            olddata=data
            #the \1 means replace the last character, so we don't erase it
            data=r.sub(value+r'\1',data)
    
    #print "Returning %s"%data
    return data

    
class attx86parser(GenericASTBuilder):
    def p_start(self, args):
        '''
        file_input ::= file_contents 
        file_contents ::= file_contents stmt 
        file_contents ::= file_contents NEWLINE
        file_contents ::=
        stmt ::= mnemonic argumentlist
        stmt ::= labeldefine
        stmt ::= longdefine number
        stmt ::= shortdefine number
        stmt ::= globaldefine name
        stmt ::= asciidefine quotedstring
        stmt ::= asciizdefine quotedstring
        stmt ::= urlencodeddefine quotedstring
        stmt ::= bytedefine numberlist
        numberlist ::= number
        numberlist ::= number , numberlist
        labeldefine ::= name :
        argumentlist ::= constant , registerexpression
        argumentlist ::= registerexpression , registerexpression
        argumentlist ::= number
        argumentlist ::= reg
        argumentlist ::= constant , reg
        argumentlist ::= registerexpression , reg
        argumentlist ::= reg , registerexpression
        argumentlist ::= reg , reg
        argumentlist ::= registerexpression
        argumentlist ::= constant
        argumentlist ::= name
        argumentlist ::= 
        registerexpression ::= registerexpressionprefix leftregisterexpression ( rightregisterexpression )
        registerexpressionprefix ::= segreg
        registerexpressionprefix ::= 
        leftregisterexpression ::= - leftcomponent
        leftregisterexpression ::= leftcomponent
        leftregisterexpression ::= leftcomponent - leftcomponent
        leftregisterexpression ::= leftcomponent + leftcomponent
        leftregisterexpression ::= 
        leftcomponent ::= name
        leftcomponent ::= number
        rightregisterexpression ::= reg
        rightregisterexpression ::= reg , reg
        rightregisterexpression ::= reg , reg , number
        rightregisterexpression ::= reg , number
        rightregisterexpression ::= number
        constant ::= $ number
        number ::= hexnumber
        number ::= decnumber 
        
        '''
    
    def typestring(self, token):
        return token.type
    
    def error(self, token):
        errmsg  = "Syntax error at `%s' of type %s (line %s)\n" % (token.attr, token.type,token.lineno)
        errmsg += "Often this is because the line contains a mnemonic we don't have in our list yet.\n"
        if token.attr=="$":
            errmsg += "My guess is that you used $eax instead of %eax, or similar\n"
        sys.stderr.write(errmsg)
        raise SystemExit
    
def parse(tokens):
    parser = attx86parser(AST,'file_input')
    parsed = parser.parse(tokens)
    return parsed

def showtree(node, depth=0):
    if hasattr(node, 'attr'):
        print "%2d" % depth, " "*depth, '<<'+node.type+'>>',
        try:
            if len(node.attr) > 50:
                print node.attr[:50]+'...'
            else: print node.attr
        except:
            print ""
            #print "Error: attr=%s"%str(node.attr)
    else:
        print "%2d" %depth, "-"*depth, '<<'+node.type+'>>'
        for n in node._kids:
            showtree(n, depth+1)

            
class gastypecheck(GenericASTTraversal):
    """
    Generic GNU Assembler typecheck
    """
    def __init__(self, ast):
        GenericASTTraversal.__init__(self, ast)
        self.postorder()

    def n_reg(self,node):
        #print "Reg is %s"%node.attr
        node.exprType="reg"
        
    def n_registerexpression(self,node):
        #print "Reg expr"
        node.exprType="registerexpressions"
        
    def n_name(self,node):
        node.exprType="name"
        
    def n_constant(self,node):
        node.exprType="constant"

    def n_mnemonic(self,node):
        #print "Mnemonic: %s"%node.attr
        node.exprType="mnemonic"
        
    def n_labeldefine(self,node):
        #print "Label Defined: %s"%node[0].attr
        node.exprType="labeldefine"
        
    def n_argumentlist(self,node):
        #construct the argumentlist types
        node.exprType="argumentlist"
        node.argList=[]
        for n in node:
            #just ignore the seperators
            if n.type!=",":
                node.argList.append(n.type)
            
    def n_stmt(self,node):
        if node[0].exprType=="labeldefine":
            #no verification on label definitions
            pass
        elif node[0].exprType=="mnemonic":
            #print "Found mnemonic %s with arguments %s"%(node[0].attr,node[1].argList)
            if not self.validateargs(node[0].attr,node[1].argList):
                print "%s is not a valid argument list for %s on line %d"%(node[1].argList,node[0].attr,node[0].lineno)
                raise SystemExit
            
    def validateargs(self,mnemonic,arglist):
        """
        We return 1 by default
        """
        return 1
    
    
class x86typecheck(gastypecheck):
    """
    X86 Gnu Assembler Type Check
    
    """
    
    def __init__(self,ast):
        self.validargs={}
        self.validargs["pop"]=[["reg"]]
        self.validargs["sub"]=[["constant","reg"]]
        self.validargs["call"]=[["name"]]
        self.validargs["movl"]=[['reg', 'reg']]
        self.validargs["subl"]=[['constant', 'reg']]
        self.validargs["mov"]=[['reg', 'reg']]
        self.validargs["lea"]=[['registerexpression', 'reg']]
        self.validargs["push"]=[['reg']]
        self.validargs["xchg"]=[['reg', 'reg']]
        self.validargs["mov"].append(['constant', 'reg'])
        self.validargs["int"]=[['constant']]
        self.validargs["cmpw"]=[['constant', 'registerexpression']]
        self.validargs["jne"]=[['name']]
        self.validargs["cmp"]=[['constant', 'reg']]
        self.validargs["add"]=[['constant', 'reg']]
        self.validargs["movl"].append(['constant', 'registerexpression'])

        gastypecheck.__init__(self,ast)

                    
    def validateargs(self,mnemonic,arglist):
        debug=0
        if debug:
            print "Validating %s %s"%(mnemonic,arglist)
        if self.validargs.has_key(mnemonic):
            args=self.validargs[mnemonic]
        else:
            print "Did not have a valid args list for %s"%mnemonic
            print "self.validargs[\"%s\"]=[%s]"%(mnemonic,arglist)
            return 1
        
        for l in args:
            if l==arglist:
                return 1
        print "Did not find our arglist in the valid args list"
        print "self.validargs[\"%s\"].append(%s)"%(mnemonic,arglist)
        return 0

from copy import deepcopy
    
    
class x86generate(GenericASTTraversal):
    """
    Assembles X86 Code
    Repeats some of the work of the validator so we don't need to run validate first necessarally.
    BUGS:
        Assumes 32 bit constants unless explicitly told via mnemonic that it's not 32 bits (eg addb, subb)
    """
    
    def __init__(self, ast):
        """
        We deepcopy the original x86opcodes.x86args dictionary here
        because we need our very own instructions since we modify internal
        variables inside them
        """
        self.mnargsDict=deepcopy(x86args)
        self.longcalls={}
        
        
        done=0
        GenericASTTraversal.__init__(self, ast)
        while not done:
            try:
                #print "Trying traversal"
                self.metadata=[] #our list of metadata which can be used by advanced assemblers
                self.currentMN=""
                self.currentAL=[]
                self.currentVL=[]
                self.tempaddr=None
                self.value=""
                self.calls=0
                self.labels={}
                self.redoDict={}
                self.inredo=0
                self.redocallnum=0
                self.postorder()
                done=1
            except needLongCall:
                #print "New long call at %d"%self.calls
                if self.inredo:
                    self.longcalls[self.redocallnum]=1
                else:
                    self.longcalls[self.calls]=1

        unresolved=0
        for k in self.redoDict:
            print "Note: unresolved symbol: %s"%k
            unresolved=1
        if unresolved:
            import traceback
            traceback.print_stack()
        #self.value=ast.value

        
        
    def inccall(self):
        if not self.inredo:
            self.calls+=1
        return
    
    def inRedo(self,callnum):
        self.redocallnum=callnum
        self.inredo=1
        return
    
    def outRedo(self):
        self.inredo=0
        return
    
    def needlongcall(self):

        if self.inredo:
            if self.longcalls.has_key(self.redocallnum):
                #print "REDO: %d needs a long call."%self.redocallnum
                return 1
            #print "REDO: %d does not need a long call."%self.redocallnum
            return 0
        elif self.longcalls.has_key(self.calls):
            #print "NORMAL: %d needs a long call."%self.calls
            return 1
        #print "NORMAL: %d does not need a long call."%self.calls
        return 0
        
        
    def addlabel(self,label):
        """
        Adds a label to the current position
        """
        ret=self.getLabel("./")
        #print "Adding label %s at %d"%(label,ret)
        self.labels[label]=ret

        
        return
        
    def n_reg(self,node):
        #print "Reg is %s"%node.attr
        node.exprType="reg"
        node.value=node.attr

    def n_longdefine(self,node):
        node.exprType="longdefine"

    def n_shortdefine(self,node):
        node.exprType="shortdefine"

    def n_globaldefine(self,node):
        node.exprType="globaldefine"
        
    def n_asciidefine(self,node):
        node.exprType="asciidefine"
        
    def n_asciizdefine(self,node):
        node.exprType="asciizdefine"
        
    def n_urlencodeddefine(self,node):
        node.exprType="urlencodeddefine"
        
    def n_numberlist(self,node):
        node.attr=[]
        for n in node:
            if n.type==",":
                continue
            if n.type=="number":
                #print "Number: node[0].attr=%s"%n.attr
                node.attr.append(n.attr)
            else:
                #we have number , numberlist
                node.attr+=n.attr
            
    def n_bytedefine(self,node):
       node.exprType="bytedefine"
       #numberlist from first arg
       #nl=node[0].attr
       #for n in nl:
       #    self.value+=chr(int(n,0))
        
    def n_registerexpressionprefix(self,node):
        node.exprType="segreg"
        if len(node)==1:
            node.segreg=node[0].attr
        else:
            node.segreg=""
            
    def n_segreg(self,node):
        node.exprType="segreg"
        node.value=node.attr
        
    def n_leftcomponent(self,node):
        node.attr=node[0].attr
    
    def n_leftregisterexpression(self,node):
        #generates 2 lists to hold the left side of a register expression
        #one list is for the labels and numbers
        #one list is for the sign of each label or number (+ or -)
        #node.exprType="leftregisterexpression"
        #print "PARSER: left register expression"
        #print "len(node)=%d"%len(node)
        node.labelsandnumbers=[]
        node.additives=[]
        if len(node)==0:
            return
        if node[0].attr!="-":
            node.additives.append("+")
        for n in node:
            #eh? This shouldn't be here, should it?
            #if n.attr == ",":
            #    continue
            if n.attr in ["+","-"]:
                node.additives.append(n.attr)
            else:
                node.labelsandnumbers.append(n.attr)
        
    def n_rightregisterexpression(self,node):
        #need to set up all the register expression variables here for the right side
        #print "PARSER: right register expression"
        node.exprType="rightregisterexpression"
        node.reg1=""
        node.reg2=""
        node.scalefactor=1
        length=len(node)
        node.reg1=node[0].attr
        #print "Length=%d"%length
        if length==5:
            #print "5"
            node.scalefactor=node[4].attr
            node.reg2=node[2].attr
        elif length==3:
            if node[2].exprType=="reg":
                node.reg2=node[2].attr
            else:
                node.scalefactor=node[2].attr
        elif length==1:
            pass
        return
    
    def n_registerexpression(self,node):
        #sets up a dictionary to hold the register expression variables
        #print "PARSER: Reg expr"
        node.exprType="registerexpression"
        node.regexpressionDict={}
        node.regexpressionDict["labelsandnumbers"]=node[1].labelsandnumbers
        node.regexpressionDict["additives"]=node[1].additives
        node.regexpressionDict["reg1"]=node[3].reg1
        #as a note, for reg1, we sometimes use numbers (in string format)
        #like for %fs:(0x30) 
        #in this case you get:
        #{'reg2': '', 'segreg': '%fs:', 'reg1': '0x30', 'labelsandnumbers': [], 'scalefactor': 1, 'additives': []}
        node.regexpressionDict["reg2"]=node[3].reg2
        node.regexpressionDict["scalefactor"]=node[3].scalefactor
        node.regexpressionDict["segreg"]=node[0].segreg
        #print "Regular Expression Dict: %s"%node.regexpressionDict
        node.value=node.regexpressionDict
        
    def n_number(self,node):
        node.exprType="number"
        node.attr=node[0].attr
    
    def n_name(self,node):
        node.exprType="name"
        node.value=node.attr
        
    def n_constant(self,node):
        node.exprType="constant"
        node.value=long(node[1][0].attr,0)
        
    def n_argumentlist(self,node):
        #construct the argumentlist types
        node.exprType="argumentlist"
        node.argList=[]
        node.valueList=[]
        for n in node:
            #print "Node.attr=%s"%n.attr
            try:
                value=n.value
                type=n.type
            except AttributeError:
                #it doesn't have a value
                value=n.attr
                type="constant"
                
            #just ignore the seperators
            if n.type!=",":
                node.argList.append(type)
                node.valueList.append(value)
                
    def n_mnemonic(self,node):
        #print "Mnemonic: %s"%node.attr
        node.exprType="mnemonic"
    
    def n_labeldefine(self,node):
        #print "Label Defined: *%s*"%node[0].attr
        node.exprType="labeldefine"    
        #also I need to add this label to the lable list
        if self.isLabelDefined(node[0].attr):
            print "ERROR: Duplicate define of label %s"%node[0].attr
            print "Sleeping for 10 seconds"
            import time
            time.sleep(10)
            raise SystemError
        label=node[0].attr
        self.addlabel(label)
        
        #every time a label is defined I need to go through and see if I can fix anything
        #in the redolist
        l=label #dunno why we do this here - just to save typing, I assume
        if self.redoDict.has_key(l):
            rdict=self.redoDict[l]
            del self.redoDict[l]
            for r in rdict:
                addr=r[0]
                mn=r[1]
                al=r[2]
                vl=r[3]
                length=r[4]
                #length does not include opcode length or argsize
                #call exit <-- length is zero 
                callnum=r[5]
                #print "Getting a new instruction for %s %s %s"%(mn,al,vl)
                #this will put itself back on the redolist if something else is not defined
                self.tempaddr=addr #+length
                #we store off the self.calls and pretend like we're doing the old instruction now...
                self.inRedo(callnum)
                instr,myopcode=self.getInstrEx(mn,al,vl)
                self.outRedo()
                opcodelen=len(myopcode.opcode)
                #longargsize is used because we always assume we are using a long
                #argument when we have not resolved a name yet...
                #this makes totallength 5 for a call <name>
                #ok, we don't do this anymore. We throw an exception when we're too long...
                #and then recalculate the entire buffer with that one as a long opcode
                totallength=length+opcodelen+myopcode.argsize

                #print "Length instr=%d and length=%d totallength=%d"%(len(instr),length,totallength)
                #if len(instr)<totallength:
                #    #call 0 is not less than 2
                #    #devlog("atandtparse", "Length of instr: %d (%s)"%(len(instr),hexprint(instr)))
                #    instr+="\x90"*(totallength-len(instr))
                
                
                #opcodelen + 5 - argsize of 1
                #ind=opcodelen
                #endex=ind+len(instr)-myopcode.longargsize
                s=self.value[addr:addr+totallength]
                #s is the entire opcode+everything
                #length is zero when we have a call/jmp
                #but if we have a lea then we need to use it
                #as this is calculated from a register expression...
                if length:
                    s2=s[-length:]
                else:
                    s2=s[-myopcode.longargsize:]
                #s2 is the argument only - we assume its the last thing there
                #and because we have allocated space for it on a worst-case scenario
                #we assume it's the longest it can be
                if s2!="\x90"*len(s2):
                   devlog("atandtparse", "Warning: s2=%s s=%s"%(hexprint(s2), hexprint(s)))
                if len(instr)>totallength:
                    print "WARNING: overwriting bytes that probably need to be there...%s"%hexprint(s)
                    print "WARNING: with these bytes:                                  %s"%hexprint(instr)
                    print "Length instr=%d and totallength=%d"%(len(instr),totallength)

                    print "opcodelen=%d "%(opcodelen)
                    print "mn=%s vl=%s"%(mn,vl)
                    print "s2=%s"%hexprint(s2)
                    raise GenerateException, "Error compiling code!"
                #print "len(instr)=%d length=%d"%(len(instr),length)
                
                self.value=stroverwrite(self.value,instr,addr)
                #print "Current self.value=%s"%hexprint(self.value)
        #Clear this when we are done
        self.tempaddr=None
        #now do metadata
        meta={}
        meta["type"]="label"
        meta["label"]=label
        meta["offset"]=len(self.value)
        self.metadata+=[meta]       
        return
            
        

    def n_stmt(self,node):
        if node[0].exprType=="labeldefine":
            #no verification on label definitions
            #need to add this to our labellist
            label=node[0][0].attr
            #print "Label Defined %s at location %d"%(label,len(self.value))
            self.addlabel(label)

        elif node[0].exprType=="mnemonic":
            #print "Found mnemonic %s with arguments %s : %s"%(node[0].attr,
            #                                                  node[1].argList,node[1].valueList)
            mn=node[0].attr.lower()
            argList=node[1].argList
            valueList=node[1].valueList
            self.currentAL=argList
            self.currentVL=valueList
            self.currentMN=mn
            
            instr=self.getInstr(mn,argList,valueList)
            #ADD THIS TO OUR INSTRUCTION STREAM!
            meta={}
            meta["type"]=mn
            meta["length"]=len(instr)
            #please add to this as necessary...
            jmptypes=["jmp","call","jne","jn","loop", "loope","loopz", "loopne", "loopnz", "ja", "jae", "jb", "jbe","jcxz", "jecxz", \
                      "jc", "je", "jg", "jge", "jl", "jle", "jna","jnae","jnb","jnbe","jnc",\
                      "jng","jnge","jnl","jnle","jno","jnp","jns","jnz","jo","jp","jpe","jpo",\
                      "js","jz"]
            
            if mn in jmptypes:
                meta["isjmp"]=1
                meta["jumpto"]=valueList[0] #this is a cheesy way of doing it, but it works
            else:
                meta["isjmp"]=0
            meta["offset"]=len(self.value)
            meta["instruction"]=[argList,valueList]
            self.metadata+=[meta]
            self.value+=instr
            #print "%s is %s"%(mn+str(valueList),hexprint(instr))

        elif node[0].exprType=="asciidefine":
            value=node[1].attr
            #cut the quotes off the ends
            value=value[1:-1]
            value=unslashify(value)
            self.value+=value

        elif node[0].exprType=="asciizdefine":
            value=node[1].attr
            #cut the quotes off the ends
            value=value[1:-1]
            value=unslashify(value)
            self.value+=value
            self.value+="\x00"

        elif node[0].exprType=="urlencodeddefine":
            value=node[1].attr
            #cut the quotes off the ends
            value=value[1:-1]
            value=urllib.unquote(value)
            #print "Adding Value of len %d"%len(value)
            self.value+=value

            
        elif node[0].exprType=="longdefine":
            #value=int(node[1].attr,0)
            value=long(node[1].attr,0)
            self.value+=intel_order(value)

            
        elif node[0].exprType=="shortdefine":
            #value=int(node[1].attr,0)
            value=long(node[1].attr,0)
            self.value+=halfword2istr(value)

        elif node[0].exprType=="bytedefine":
            nl=node[1]
            for n in nl:
                #print "n.attr: %s"%n.attr
                if n.attr!=",":
                    try:
                        self.value+=chr(int(n.attr,0))
                    except:
                        #could be a list
                        for v in n.attr:
                            self.value+=chr(int(v,0))

        elif node[0].exprType=="globaldefine":
            pass #just ignore global defines for now
        else:
            print "I don't know how to handle %s in n_stmt"%node[0].exprType
                
    def isLabelDefined(self,l):
        if l in self.labels:
            return 1
        return 0
        
    def addToRedoList(self,l,length):
        #if length==0:
        #    devlog("atandtparse", "Length is zero!")
        #adds the current instruction to the redo list based on a label
        addr=self.getLabel("./")
        mn=self.currentMN
        vl=self.currentVL
        al=self.currentAL
        calls=self.calls
        if l not in self.redoDict:
            self.redoDict[l]=[]
        self.redoDict[l].append((addr,mn,al,vl,length,calls))
                
                
    def getLabel(self,l):
        #print "GetLabel: %s"%l
        if l=="./" and self.tempaddr!=None:
            #print "templabel!"
            return self.tempaddr
        if l=="./":
            return len(self.value)
        
        if l not in self.labels:
            return None
        ret=self.labels[l]
        #print "ret=%d"%ret
        return ret

    def getInstr(self,mn,arglist,valuelist):
        """older function - doesn't return opcode itself"""
        return self.getInstrEx(mn,arglist,valuelist)[0]
    
    def getInstrEx(self,mn,arglist,valuelist):
        

        """
        gets an instruction from a mnemonic, arglist, and valuelist
        return assembled binary bytes and opcode for reference
        """
        oldarglist=[]
        regbutnotconstantlist=[]
        argList=arglist
        valueList=valuelist
        
        for a in argList:
            oldarglist.append(a)
            regbutnotconstantlist.append(a)
                              

        #first we go through and replace all constants with constant8 if they are small enough
        for i in range(len(argList)):
            if argList[i]=="constant":
                if isbyte(valueList[i]):
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
        args=arglist
        #print "Args[%s]=%s"%(mn,args)
        #print "Values=%s"%(valueList)
        
        if mn not in self.mnargsDict:
            print "Unrecognized mnemonic %s!"%mn
            raise SystemExit
        argsLL=self.mnargsDict[mn]
        found=None
        i=0
        #this little loop goes through and finds which argument list we're using 
        for argsL in argsLL:
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
            #    print "argsL.arglist=%s"%(argsL.argslist)
            print "Args[%s]=%s"%(mn,args)
            print "Values=%s"%(valueList)
            for i in self.mnargsDict[mn]:
                print "Possible: %s"%i.arglist
            raise SystemError
        
        #now "found" has the argument list - unless there is an argument with a label
        #that is yet to be defined, we now know everything we need to assemble this instruction
        #if the instruction cannot be assembled now (due to a missing label) then this should
        #(MUST) return some 0x90 padding for itself to fill in later.
        instr=found.get(valueList,context=self)
        if instr=="":
            print "******ERROR************"
            print "MOSDEF Instruction did not return value"
            print "valueList=%s"%valueList
            raise GenerateException, "Error: %s"%valueList
        return instr, found

import atandtscan
def assemble(data):
    data=atandtpreprocess(data)

    tokens=atandtscan.scan(data)
    #print tokens
    #print "-"*50
    tree=parse(tokens)
    #print "-"*50

    #print "-"*50
    #print "Showing tree"
    #showtree(tree)
    #print "-"*50
    
    #print "-"*50
    #Typecheck is basically useless since we do real checking when we generate it...
    #print "Doing typecheck"
    #typecheck=x86typecheck(tree)
    #print "-"*50
    #print "Doing Generation of Code"
    try:
        x=x86generate(tree)
    except GenerateException, msg:
        name="parserbug.txt"
        print "Writing code that generated exception to %s"%name
        o=file(name,"wb")
        o.write(data)
        o.close()
        x=""
    return x

if __name__=="__main__":
    filename="test.s"
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    try:
        data=open(filename).read()
    except:
        data=open("MOSDEF/"+filename).read()

    print "Assembling: %s"%data
    import time
    t1=time.clock()
    import hotshot
    prof=hotshot.Profile("hotshot_edi_stats")
    for i in xrange(0,1):
        prof.run("result=assemble(data)")
    prof.close()
    print "Result: %s"%shellcode_dump(result.value)
    print "Result length: %d"%len(result.value)
    t2=time.clock()
    print "t1=%f t2=%f"%(t1, t2)
    if 0:
        from hotshot import stats
        print "Loading stats"
        s=stats.load("hotshot_edi_stats")
        s.sort_stats("time").print_stats()
    #print "Length of shellcode: %d"%len(x.value)
    #print hexprint(x.value)
    #import makeexe
    #have to have a lot of A's to make the "stack" look normal.
    #makeexe.makelinuxexe("A"*0x1500+"\xcc"+x.value,"a.out")
    #print "Metadata:"
    #print x.metadata
    
    
    
    
    
    
    
    
    
