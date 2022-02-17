#! /usr/bin/env python
"""
A SPARC assembler for CANVAS

Some good reference material below:    
http://www.owlnet.rice.edu/~comp320/2001/assignments/sparc_subset.html
http://www.cs.unm.edu/~maccabe/classes/341/labman/node9.html#fldformat
"""

from mosdefutils import *

def hi(myint):
    """return high 22 order bits of integer"""
    tmp=myint>>10 
    return tmp

def lo(myint):
    """returns lo 10 order bits of integer"""
    tmp=myint & 0x3FF
    return tmp

def simm13(myint):
    #signed 13 bit immediate integer
    return (dInt(myint)&b("1"*13))


def imm7(myint):
    #7 bit immediate
    return dInt(myint)

def disp22(myint):
    return (dInt(myint)>>2)&b("1"*22)


def disp30(myint):
    return (dInt(myint)>>2)&b("1"*30)

normalregs={"g":0,"o":8,"l":16,"i":24}
def getreg(reg):
    """reg is a string that contains the %r1,%l0 etc
       we return its binary encoding """
    #print "Getreg: %s"%reg
    if reg[1]=="y":
        return 0
    
    if reg[1]=="r":
        #direct register access
        number=int(reg[2:])
        return number

    if reg[1] in normalregs:
        number=int(reg[2:])+normalregs[reg[1]]
        return number
    
    if reg=="%sp":
        return getreg("%o6")
    
    if reg=="%fp":
        return getreg("%i6")
    print "Register %s not found!"%reg
    print "ERROR - should not continue!"
    return ""

compound_opcodes=[]
compound_opcodes+=["set"]

#a dict of opcodes we support
#f3 is op,op3
opcodes={}
opcodes["set"]=["set"]
opcodes["sethi"]=["f2",b("00"),b("100"),""]
opcodes["nop"]=["f2",b("00"),b("100"),""]

opcodes["mov"]=["mov"]
opcodes["deccc"]=["deccc"]
opcodes["clr"]=["clr"]
opcodes["cmp"]=["cmp"]

opcodes["ld"]=["f3",b("11"),b("000000")]
opcodes["ldsb"]=["f3",b("11"),b("001001")]
opcodes["ldsh"]=["f3",b("11"),b("001010")]
opcodes["ldub"]=["f3",b("11"),b("000001")]
opcodes["lduh"]=["f3",b("11"),b("000010")]

#version 7 supported...
opcodes["mulscc"]=["f3",b("10"),b("100100")]
opcodes["rdy"]=["rdy"]
opcodes["wry"]=["wry"]
opcodes["rdy_internal"]=["f3",b("10"),b("101000")]
opcodes["wry_internal"]=["f3",b("10"),b("110000")]


#version 8 only!
#for version <8, you need to use mulscc, which is a single step operation
opcodes["umul"]=["f3",b("10"),b("001010")]
opcodes["umulcc"]=["f3",b("10"),b("011010")]
opcodes["smul"]=["f3",b("10"),b("001011")]
opcodes["smulcc"]=["f3",b("10"),b("011011")]

#end version 8 only
                                                   
opcodes["st"]=["f3",b("11"),b("000100")]
opcodes["stb"]=["f3",b("11"),b("000101")]
opcodes["sth"]=["f3",b("11"),b("000110")]

opcodes["swap"]=["f3",b("11"),b("001111")]

opcodes["add"]=["f3",b("10"),b("000000")]
opcodes["addcc"]=["f3",b("10"),b("010000")]
opcodes["addx"]=["f3",b("10"),b("001000")]
opcodes["addxcc"]=["f3",b("10"),b("011000")]

opcodes["sub"]=["f3",b("10"),b("000100")]
opcodes["subcc"]=["f3",b("10"),b("010100")]
opcodes["subx"]=["f3",b("10"),b("001100")]
opcodes["subxcc"]=["f3",b("10"),b("011100")]

opcodes["and"]=["f3",b("10"),b("000001")]
opcodes["andcc"]=["f3",b("10"),b("010001")]
opcodes["andn"]=["f3",b("10"),b("000101")]
opcodes["andncc"]=["f3",b("10"),b("010101")]


opcodes["or"]=["f3",b("10"),b("000010")]
opcodes["orcc"]=["f3",b("10"),b("010010")]
opcodes["orn"]=["f3",b("10"),b("010110")]
opcodes["orncc"]=["f3",b("10"),b("010110")] #??

opcodes["xor"]=["f3",b("10"),b("000011")]
opcodes["xorcc"]=["f3",b("10"),b("010011")]
opcodes["xnor"]=["f3",b("10"),b("000111")]
opcodes["xnorcc"]=["f3",b("10"),b("010111")]

opcodes["sll"]=["f3",b("10"),b("100101")]
opcodes["srl"]=["f3",b("10"),b("100110")]
opcodes["sra"]=["f3",b("10"),b("100111")]

opcodes["jmpl"]=["f3",b("10"),b("111000")]

opcodes["call"]=["f1",b("01")]

#unsure if op is correct
opcodes["flush"]=["f3",b("01"),b("111011")]

opcodes["ret"]=["ret"]
opcodes["retl"]=["retl"]
opcodes["restore"]=["f3",b("10"),b("111101")]
opcodes["save"]=["f3",b("10"),b("111100")]

#our condition codes are the same for trap and for branch
cond={}
cond["a"]=b("1000")
cond["n"]=b("0000")
cond["ne"]=b("1001")
cond["e"]=b("0001")
cond["nz"]=b("1001")
cond["z"]=b("0001")
cond["g"]=b("1010")
cond["le"]=b("0010")
cond["ge"]=b("1011")
cond["l"]=b("0011")
cond["gu"]=b("1100")
cond["leu"]=b("0100")
cond["cc"]=b("1101")
cond["geu"]=b("1101")
cond["cs"]=b("0101")
cond["lu"]=b("0101")
cond["pos"]=b("1110")
cond["neg"]=b("0110")
cond["vc"]=b("1111")
cond["bs"]=b("0111")

branch_opcodes=[]
for k in cond:
    # a trap is like a f3, but not quite
    opcodes["t%s"%k]=["trap",b("10"),b("111010"),cond[k]]
    #op, op2, cond
    bfunc="b%s"%k
    opcodes[bfunc]=["f2",b("00"),b("010"),cond[k]]
    branch_opcodes.append(bfunc)

class sparcassembler:
    def __init__(self):
        self.value=[]
        self.branch_opcodes = branch_opcodes
        self.compound_opcodes = compound_opcodes
        self.unused=b("0"*7) #seven bytes of zeros 
    
    def doinstruction(self,opcode,opcodeargslist):
        #uncomment for debug
        #print "opcode=%s"%opcode
        #print "argslist=%s"%opcodeargslist
        #tmp=""
        
        if opcode not in opcodes:
            print "Error, tried to assemble a sparc opcode %s but we do not support it!"%opcode
            return ""
        
        functionname=opcodes[opcode][0]
        func = getattr(self, "op_" + functionname)
        return func(opcode,opcodeargslist)
        
    def op_set(self,opcode,opcodeargslist):
        value=dInt(opcodeargslist[0])
        if value & 0x1fff==0:
            offsetfix = self.doinstruction("sethi",[hi(value), opcodeargslist[1]])
            offsetfix += self.doinstruction("nop",[])
            return offsetfix
        elif value <= 4095 and value >= -4096:
            offsetfix = self.doinstruction("or",["%g0"]+opcodeargslist)
            offsetfix += self.doinstruction("nop",[])
            return offsetfix
        else:
            tmp=self.doinstruction("sethi",[hi(value), opcodeargslist[1]])
            tmp+=self.doinstruction("or",[opcodeargslist[1],lo(value), opcodeargslist[1]])
        return tmp
    
    def op_mov(self,opcode,opcodeargslist):
        tmp=self.doinstruction("or",["%g0"]+opcodeargslist)
        return tmp
    
    def op_cmp(self,opcode,opcodeargslist):
        tmp=self.doinstruction("subcc",opcodeargslist+["%r0"])
        return tmp
    
    def op_clr(self,opcode,opcodeargslist):
        tmp=self.doinstruction("or",["%g0","%g0"]+opcodeargslist)
        return tmp
    
    def op_rdy(self,opcode,opcodeargslist):
        tmp=self.doinstruction("rdy_internal",opcodeargslist)
        return tmp
    
    def op_wry(self,opcode,opcodeargslist):
        tmp=self.doinstruction("wry_internal",opcodeargslist)
        return tmp
    
    def op_deccc(self,opcode,opcodeargslist):
        if len(opcodeargslist)==1:
            opcodeargslist=[1]+opcodeargslist
        tmp=self.doinstruction("subcc",[opcodeargslist[1]]+opcodeargslist)
        return tmp
    
    def op_ret(self,opcode,arglist):
        tmp=self.doinstruction("jmpl",["%i7",8,"%g0"])
        return tmp
    
    def op_retl(self,opcode,arglist):
        tmp=self.doinstruction("jmpl",["%o7",8,"%g0"])
        return tmp
    
    def op_trap(self,opcode,opcodeargslist):
        #like an f3, but not.
        attributeList=opcodes[opcode]
        optype,op,op3,cond=attributeList
            
        if len(opcodeargslist)==2:
            rs2,rs1=opcodeargslist
        elif len(opcodeargslist)==1:
            rs2=opcodeargslist[0]
            rs1="%r0"
        else:
            print "Wrong number of args in op_trap!"
            return -1
        
        if str(rs2).count("%") and not str(rs1).count("%"):
            #someone has decided to do a or 1,%g0,%g0 style opcode
            #so we reverse it for them...as rs1 is always a register
            rs1,rs2=rs2,rs1           
            
        reserved=b("0")
        #print "trap: rs1, rs2=%s %s"%(rs1,rs2)
        ret=(long(op)<<30)+(reserved<<29)+(cond<<25)+(op3<<19)+(getreg(rs1)<<14)
        if str(rs2).count("%"):
            print "we are of a rs1,rs2 type"
            i=0
            ret+=(i<<13)+(reserved<<5)+(getreg(rs2))
        else:
            #print "we are of a rs1,integer,rd type"
            i=1
            imm=rs2
            ret+=(i<<13)+(reserved<<7)+imm7(imm)
            
        return big_order(ret)
    
    def op_f3(self,opcode,opcodeargslist):
        attributeList=opcodes[opcode]
        optype,op,op3=attributeList
            
        if len(opcodeargslist)==3:
            rs1,rs2,rd=opcodeargslist

        elif len(opcodeargslist)==2:
            rs1,rd=opcodeargslist
            rs2="%r0"
        elif len(opcodeargslist)==1:
            rd=opcodeargslist[0]
            rs1="%r0"
            rs2="%r0"
        elif len(opcodeargslist)==0:
            #restore has this ...
            rs1="%r0"
            rs2="%r0"
            rd="%r0"
        else:
            print "Wrong number of args in op_f3!"
            return -1

        if opcode in ["st","stb","sth"]:
            #backwards...the parser does the work of removing the [] and doing some processing
            #for us. We just get a list of 3 or less things.
            #print "Store found: backwards"
            rd,rs1=rs1,rd
        if opcode in ["ld","ldsb","ldsh","ldub","lduh"]:
            if not str(rs1).count("%"):
                #both work, but in this case, we'll conform to gcc's way
                #it's a good note that we can reverse this to 
                #print "load found, backwards"
                rs1,rs2=rs2,rs1
            #print "Load arguments: rs1 %s rs2 %s rd %s"%(rs1,rs2,rd)

        if str(rs2).count("%") and not str(rs1).count("%"):
            #someone has decided to do a or 1,%g0,%g0 style opcode
            #so we reverse it for them...as rs1 is always a register
            rs1,rs2=rs2,rs1           
        #print "f3: rs1, rs2, rd=%s %s %s"%(rs1,rs2,rd)
        if str(rs2).count("%"):
            #print "we are of a rs1,rs2,rd type"
            i=0
            ret=(long(op)<<30)+(getreg(rd)<<25)+(op3<<19)+(getreg(rs1)<<14)+(i<<13)+(self.unused<<5)+(getreg(rs2))
        else:
            #print "we are of a rs1,integer,rd type"
            i=1
            imm=rs2
            ret=(long(op)<<30)+(getreg(rd)<<25)+(op3<<19)+(getreg(rs1)<<14)+(i<<13)+simm13(imm)
        return big_order(ret)
    
    def op_f2(self,opcode,argslist):
        """branches, nop, sethi"""
        attributeList=opcodes[opcode]
        optype,op,op2,cond=attributeList
        if opcode in ["nop","sethi"]:
            if len(argslist)==2:
                imm,rd=argslist
            elif len(argslist)==0:
                rd="%r0"
                imm=0
            else:
                print "Wrong number of args in op_f2!"
                return -1
            #print "sethi with rd=%s and imm=%s"%(rd,imm)
            #print "op=%s op2=%s"%(op,print_binary(op2))
            ret=(long(op)<<30)+(getreg(rd)<<25)+(op2<<22)+int(imm)
            #print "ret=%s"%print_binary(ret)
        else:
            #a branch           
            if len(argslist)==3:
                a,imm,rd=argslist
            else:
                a,disp=argslist
                #print "disp=%s"%disp
                rd="%r0"
                #disp=disp>>2
            ret=(long(op)<<30)+(a<<29)+(cond<<25)+(op2<<22)+disp22(disp)

        return big_order(ret)

    def op_f1(self,opcode,argslist):
        #call     
        attributeList=opcodes[opcode]
        optype,op=attributeList
        if len(argslist)==1:
            disp=argslist[0]
        else:
            return self.doinstruction("jmpl",argslist+["%g0"])
        ret=(long(op)<<30)+disp30(disp)
        return big_order(ret)
            
    def test(self):
        print "testing"
        testinstr=[["set",["1","%l1"]]]
        testinstr+=[["sub",["%r27","%r16","%r26"]]]
        testinstr+=[["mov",["2048","%l1"]]]
        testinstr+=[["mov",["%l0","%l2"]]]
        testinstr+=[["st",["%g1","%l2"]]] #actually st %g0,[%l2]
        testinstr+=[["rdy",["%y","%l1"]]]        
        testinstr+=[["wry",["%g0","%o0","%y"]]]        
        for i in testinstr:
            tmp=self.doinstruction(i[0],i[1])
            print "%s=%s"%(i,hexprint(tmp))
        print "done testing"

if __name__=="__main__":
    c=sparcassembler()
    c.test()
