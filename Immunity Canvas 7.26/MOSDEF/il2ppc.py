#! /usr/bin/env python

import string
import urllib
from mosdefutils import *

"""
Converts a IL file (or buffer) into PPC asm
r13 -> accumulator (%eax)
r14 -> secondary   (%edx)
r15 -> shiftreg    (%ecx)
r16 -> store       (%edi)
r17 -> temporal
r20 -> eip
"""

# NOTE:
#   About label issues: We can support it, using the op_set (which is done on
#     ppcassembler, but we are not doing it here, since the relative jumps are
#     word offset, that means more than +-32kb we can jump (enough, i belive)
#
#<bas> so yeh -4096 to 4096 -> 16 bit signed, makes sense
#<bas> basically you just wanna assume a value > 4096 < -4096 on calls and
          #jumps
#<bas> cuz on pass 1 the label offsets will be set to 0
#<bas> so there's no way for you to know the correct label offsets if you have
          #a varying value-set for label offset values in jumps or calls
#<bas> ie: if on pass 1 the label offset is 0, and you 'mov val to wherever'
          #with a literal, ie: a 4 byte instruction, it uses pass 1 to calc the
          #actual offsets, so if on pass 2 the offsets are actually > 4096,
          #it'll now use a 'set val bla bla' which is 8 or more bytes, so then
          #the pass 0 calculated offsets are propegating with a n-4 offset
          #error, where n is whatever your > 4096 value set is
#<bas> the bug i described
#<bas> but like i said just assume > 4096 vals in label derived value sets
#<bas> so your instruction count remains consistent when label offsets are
          #filled in on pass 2 in the assembler
#<nico> and u did that on op_set, right?
#<bas> i use set yeh, which is the SPARC 8 byte, set word value opcode
#<bas> it actually becomes a sethi and an and
#<nico> yeah
#<nico> got that
#<bas> "call" and "jump" is where it comes into play
#<bas>                 # we're gonna have to assume that label offsets
#<bas>                 # are possibly > 4096 or < -4096
#<bas>                 out+="set %s-RESERVED_pcloc,%%l5\n"%words[1]
#<bas> like that


# Notes about our calling convention
# Every function have at least 60 of stack space. 
# 16 bytes for saving register: - 0(sp) -> old sp
#                               - 8(sp) -> ret address
# Then, the other 44 bytes are for saving/restoring the volatile register.
# We are using reg3-reg11 for passing arguments, so every time we do a arg, we save
# that into 16+arg*4(sp)
# and when ret is called, once we restore the old SP we do a serie of lwz 
# loading the saved register to the volatile registers.
# Arguments start obviously at 60(sp) 

# At call time we save up to 6 arguments, and at ret time we load it back.
# Personally, i dont like this much, i need to improve this a lot.
# Why i used to do, was save only the needed arguments (but, then, for example
# on sendint(3), sendint will use r3,r4,r5 for sc, so the saving didn't work.

# ^ bs...

# TODO:
#  For the future redesign:
#    - To ensure optimal alignment, the stack pointer is quadword aligned (i.e., its address is a multiple of 16).
#      [we can add canaries in case, to avoid bugs such wait()/wait4()]
#    - redesign the stack usage
#    - use il2ppc_ng model

# v ok!

"""
DOC:
http://developer.apple.com/documentation/DeveloperTools/Conceptual/LowLevelABI/Articles/32bitPowerPC.html#//apple_ref/doc/uid/TP40002438-SW17 this doc is the crap

r1: stack pointer
(nico) r2: frame pointer

"""

def bugout(lines):
    print "Writing bug.ppc.s"
    f=file("bug.ppc.s","w")
    f.write("\n".join(lines))
    f.close()
    return 

def hi(myint):
    return ((myint >> 16) & 0xFFFF)

def lo(myint):
    return myint & 0xFFFF

def generate(data):

    #fd = open("out.il", "a")
    #fd.write("!!! NEWIL:\n\n" + data)
    #fd.close()

    labelcount=0
    argcount=0
    callhappened=0
    lastword=""
    lastloadint=0
    out=""
    lines=data.split("\n")
    alignlen=0
    
    # PowerPC ABI
    linkageArea = 24
    params = 32
    localVars = 0
    numGPRs = 0
    numFPRs = 0
    spaceToSave = linkageArea + params + localVars + 4*numGPRs + 8*numFPRs
    spaceToSaveAligned = ((spaceToSave+15) & (-16))
    
    lXz = {'1': "lbz", '2': "lhz", '4': "lwz"}
    stX = {'1': "stb", '2': "sth", '4': "stw"}
    
    try:
        for line in lines:
            if line=="":
                continue
            words=line.split(" ")
            # r20 == eip
            if words[0]=="GETPC":
                # we are called !
                out += """
                mflr r0
                mr     r2, r1
                addi   r2, r2, 16
                RESERVED_getpc:
                xor.  r6,r6,r6
                bnel  RESERVED_getpc
                RESERVED_pcloc:
                mflr  r20
                mtlr  r0
                b main
                """
            elif words[0]=="rem":
                #comment
                out+="! %s\n"%(" ".join(words[1:]))
                
            elif words[0]=="asm":
                out+=" ".join(words[1:])+"\n"
                
            elif words[0]=="debug":
                out+="tw r31,r0,r0\n"
      
            elif words[0]=="functionprelude":
                out+="mflr  r0\n"
                out+="stw r0, -4(r2)\n"
                out+="stw r1, -8(r2)\n"
                out+="mr  r1, r2\n"
                out+="subi r2,r2,8" # allocate space for our internal callframe
                #out+="subi r2, r2, %d\n" % spaceToSaveAligned
                
                # PROLOG
                _out = """
                mflr r0
                stw  r0, 8(r1)   ! lr
                stwu r1, -%d(r1) ! sp
                """ % spaceToSaveAligned
            
            elif words[0]=="getstackspace":
                #mod 8 stackspace
                # 
                stackspace=int(words[1],0) + spaceToSaveAligned
                mod8=stackspace%8
                if mod8!=0:
                    stackspace+=8-mod8
                if stackspace:
                    out+="subi    r2, r2, %d  ! get stack space\n" % (stackspace)
            elif words[0]=="freestackspace":
                stackspace=int(words[1],0) + spaceToSaveAligned
                mod8=stackspace%8
                if mod8!=0:
                    stackspace+=8-mod8
                if stackspace:
                    out += "addi   r2, r2, %d  ! freeing stack space\n" % (stackspace)

            elif words[0] == "functionpostlude":
                #print "SKIPPING FREE STACKSPACE !"
                #mod 8 stackspace
                # XXX why postlude has to manage stack space?
                stackspace=int(words[1],0)
                mod8=stackspace%8
                if mod8!=0:
                    stackspace+=8-mod8
                # each function has to restore the stack before leaving
                out += "mr  r2, r1             ! restoring stack on postlude\n" 
                                        
            elif words[0]=="arg":
                argcount = uint32(int(words[1]))
                if argcount > 9:
                    print "ERROR: number of arguments > 9 (%r3-%r11)"
                    bugout(lines)
                #out+="stw r%d, %d(r1)   ! saving arg\n" % (argcount+3, argcount*4+16)
                #out+="mr  r%d, r13      ! arg%d \n" % (argcount+3, argcount)
                
                # FIXME shouldn't be atomic?
                out+="subi    r2, r2, 4\n"
                out+="stw     r13, 0(r2)     ! PUSH arg%d\n" % argcount
                
            elif words[0]=="call":
                callhappened=1
                #for a in range(0, 6):
                #          out+="stw r%d, %d(r1)   ! saving arg\n" % (a+3, (a*4+16)*-1)
                out+="bl    %s\n" % words[1]
                if len(words) > 2:
                    out += "addi r2, r2, %d ! XXX restore stackargs after call...\n" % (4 * int(words[2]))
                                
            elif words[0]=="ret":
                argnum = int(words[1])
                
                '''
                postlude:
                mr  r2, r1
                '''
                out+="lwz    r0, -4(r2)\n" #  -4(r2) saved return address
                out+="lwz    r1, -8(r2) \n" # -8(r2) saved stack
                
                # uh?
                #if argnum:
                #    out+="addi   r2, r2, %d\n" % argnum
                
                #for a in range(0, 6):                          
                #          out+="lwz  r%d, %d(r1)   ! restoring registers\n" % \
                #             (a+3, (a*4+ 16)*-1)
                
                out+="mtlr   r0\n"        # put it on the LR
                out+="blr\n"              # jump to the LR
                
                # EPILOG <- in postlude
                _out = """
                lwz  r0, %d(r1)     ! postlude
                mtlr r0             ! postlude
                _addi r1, r1, %d     ! postlude
                blr                 ! ret
                """ % (spaceToSaveAligned + 8, spaceToSaveAligned)
            
            elif words[0]=="callaccum":
                callhappened=1
                out+="mtctr   r13\n"
                out+="bctrl\n"
                
            elif words[0]=="addconst":
                if int(words[1]):
          
                    if int(words[1]) >= -0x7FFF and int(words[1]) <= 0x7fff:
                              out+="addi     r13, r13,  %d\n" % int(words[1])
                    else:
                              out+="lis    r14, %d\n" % hi(int(words[1]))
                              out+="ori    r14,r14, %d\n" % lo(int(words[1]))
                              out+="add    r13, r13, r3\n"
                else:
                   # print "NOT ADDING ZERO"
                   pass

            elif words[0]=="subconst":
                if int(words[1]):
                    if int(words[1]) >= -0x7FFF and int(words[1]) <= 0x7FFF:
                        out+="subi r13, r13, %d" % int(words[1])
                    else:
                        out+="lis    r14, %d\n" % hi(int(words[1]))
                        out+="ori    r14,r14,  %d\n" % lo(int(words[1]))                              
                        out+="sub    r13, r13, r14\n"
                else:
                    #print "NOT SUBBING ZERO"
                    pass
                
            elif words[0]=="labeldefine":
                out+="%s:\n"%words[1]
                
            elif words[0]=="longvar":
                out+=".long %s\n" % uint32fmt(words[1])
                
            elif words[0]=="ascii":
                out+=".ascii \"%s\"\n"%(" ".join(words[1:]))
                # archalign mod 4
                mod4 = len(string.join(words[1:]))%4
                #if mod4:
                #    out+=".ascii \""+"A"*(4-mod4)+"\"\n"
                alignlen = 4-mod4
                    
            elif words[0]=="urlencoded":
                out+=".urlencoded \"%s\"\n"%(" ".join(words[1:]))
                mod4 = len(urllib.unquote(string.join(words[1:])))%4
                #if mod4:
                #    out+=".ascii \""+"A"*(4-mod4)+"\"\n"
                alignlen = 4 - mod4
                    
            elif words[0]=="databytes":
                if int(words[1]) > 255:
                    print "BYTE VALUE OUTSIDE BYTE 0-255 RANGE !"
                out+=".byte %d\n"%int(words[1])
                if alignlen:
                    alignlen -= 1
                
            elif words[0]=="archalign":
                if alignlen:
                    out+=".ascii \""+"A"*alignlen+"\"\n"
                    alignlen = 0
        
                #comparison fun
            elif words[0]=="compare":
                out+="cmp 3, 0, r13, r14\n" # saved on cr3
                
            elif words[0]=="setifless":
                out+="mfcr   r13\n"
                out+="rlwinm r13, r13, 13, 19, 31\n"
                #out+="clrwi  r13, r13, 31\n" 
                out+="rlwinm  r13, r13, 0, 31,31\n"
                
            elif words[0]=="setifgreater":
                out+="mfcr   r13\n"
                out+="rlwinm r13, r13, 14, 18, 31\n"
                out+="rlwinm  r13, r13, 0, 31,31\n"
                
            elif words[0]=="setifnotequal":
                out+="mfcr   r13\n"
                out+="not    r13, r13\n"
                out+="rlwinm r13, r13, 15, 17, 31\n"
                out+="rlwinm  r13, r13, 0, 31,31\n"
                
            elif words[0]=="setifequal":
                out+="mfcr   r13\n"
                out+="rlwinm r13, r13, 15, 17, 31\n"
                out+="rlwinm  r13, r13, 0, 31,31\n"
                #out+="clrwi  r13, r13, 31\n"
                
            # XXX: check if this work as expected
            elif words[0]=="jumpiffalse":
                out+="and.  r16, r13, r13\n" 
                out+="beq   %s\n" % words[1]
            elif words[0]=="jumpiftrue":
                out+="and.  r16, r13, r13\n" 
                out+="bne   %s\n" % words[1]
                
            elif words[0]=="jump":
                out+="b %s\n" % words[1]
            
            # we're using %l4 as our stackbase
                            
            elif words[0]=="pushaccum":
                out+="stw     r13, -4(r2)     ! PUSH acumulator\n"
                out+="subi    r2, r2, 8\n"
                
            elif words[0]=="poptosecondary":
                out+="addi  r2, r2, 8\n"
                out+="lwz   r14, -4(r2)   ! POP to secondary\n"
                
            elif words[0]=="addsecondarytoaccum":
                out+="add r13,r13,r14\n"
                
            elif words[0]=="subtractsecondaryfromaccum":
                out+="subf r13, r14, r13\n"
                
            elif words[0]=="loadint":
                      
                lastloadint = long(words[1],0)

                if lastloadint >= -0x7fff and lastloadint <= 0x7fff:
                    out+="li r13, %d\n" % lastloadint
                else:
                    out+="lis    r13, %d\n" % hi(lastloadint)
                    out+="ori    r13,r13,  %d\n" % lo(lastloadint)                              
                
            elif words[0]=="accumulator2memorylocal":
                if words[1][:2]=="in":
                    argnum = int(words[1][2:])
                    if argnum > 9:
                        print "ERROR: number of arguments > 9 (r3-r11)"
                        bugout(lines)
                    out += "%s r13, %d(r1)\n" % (stX[words[2]], argnum*4)
                else:
                    out += "%s r13, %d(r1)\n" % (stX[words[2]], uint32(int(words[1])+ 56)*-1)
                    
            elif words[0]=="accumulator2index":
                #save index value currently in accumulator for array referenceing
                out+="mr  r14, r13\n"
                
            elif words[0]=="derefwithindex":
                #do a pointer derefernce using our index register (l2)
                if len(words) == 2:
                    out+="%sx   r13, r14, r13\n" % lXz[ words[1] ]
                else:
                    out+="lwzx   r13, r14, r13\n"

                
            elif words[0]=="multiply":
                out+="mulli r13, r13, %d\n" % int(words[1])
                
            elif words[0]=="storeaccumulator":
                out+="mr  r16, r13\n"
                
            elif words[0]=="modulussecondaryfromaccum":
                out+="mr    r17, r13     ! modulus secondary from acc\n"                   
                out+="divw  r13, r17, r14\n"
                out+="mullw r13, r13, r14\n"
                out+="subf  r13, r13, r17\n"
            
            elif words[0]=="storewithindex":
                # r16 is our edi equiv
                out += "%sx r16, r13, r14\n" % stX[words[1]]
            
            elif words[0]=="derefaccum":
                out += "%s  r13, 0(r13)\n" % lXz[words[1]]
            
            elif words[0]=="loadlocal":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                size=int(words[2])
                if words[1][:2]=="in":
                    #input register on sparc, stack arg on x86
                    argnum=int(words[1][2:])
                    #argnum-=1
                    # XXX: can argnum be > 5 here ?
                    if argnum > 9:
                        print "ERROR: number of arguments > 9 (r3-r11)"
                        bugout(lines)
                    # out becomes in on call
                    #out+="mr r13, r%d       ! arg%d\n" % (argnum+3, argnum)
                    out+="lwz r13, %d(r1)\n" % (argnum*4)
                else:
                    argnum=int(words[1])
                    out += "%s  r13, %d(r1)\n" % (lXz[words[2]], (argnum+56)*-1)
            elif words[0]=="loadlocaladdress":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                if words[1][:2]=="in":
                    print "! CHECKOUT CORRECT USAGE HERE (loadlocaladdress in)"
                    # set %l1 to arg
                    argnum=int(words[1][2:])
                    #argnum-=1
                    if argnum > 9:
                        print "ERROR: number of arguments > 9 (r3-r11)"
                        bugout(lines)
                    # out becomes in
                    out+="lwz r13, %d(r1)\n" % (argnum*4)
                    #out+="mr r13, r%d      ! arg%d\n" % (argnum+3, argnum)
                else:
                    out+="subi  r13, r1, %d\n"%uint32(int(words[1])+56)
                    
            elif words[0]=="loadglobaladdress":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                #print "Loading global address"
                #out+="ta 1\n"
                out+="set r13,%s-RESERVED_pcloc\n"%(words[1])
                out+="add r13, r13, r20\n"
                                    
            elif words[0]=="loadglobal":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                out+="%s  r13, %s-RESERVED_pcloc(r20)\n" % (lXz[words[2]], words[1])
            
            # l3 is our shift reg
            elif words[0]=="pushshiftreg":
                out+="stw     r15, -4(r2)     ! PUSH acumulator\n"
                out+="subi    r2, r2, 8\n"
                
            elif words[0]=="poptoshiftreg":
                out+="addi  r2, r2, 8\n"
                out+="lwz   r15, -4(r2)   ! POP to secondary\n"
                
            elif words[0]=="shiftright":
                # do we want a logical or arthmetic shift? assuming logical
                out+="srw  r13, r13, r15\n"
                
            elif words[0]=="shiftleft":
                out+="slw  r13, r13, r15\n"
            elif words[0]=="dividesecondaryfromaccum":
                out+="divw  r13, r13, r14\n"
                
            elif words[0]=="andaccumwithsecondary":
                out+="and   r13, r13, r14\n"
                
            elif words[0]=="oraccumwithsecondary":
                out+="or    r13, r13, r14\n"

            elif words[0]=="xoraccumwithsecondary":
                out+="xor r13, r13, r14\n"

            elif words[0]=="multaccumwithsecondary":
                out+="mullhw r13, r13, r14\n"
            else:
                print "WARNING ERROR IN IL: %s"%words[0]
            lastword=words[0]
    except ZeroDivisionError:
        print out
#    print "writing to OUT.s"
#    fd = open("out.s", "a")
#    fd.write("!!! NEWASM:\n\n" + out)
#    fd.close()
    #print "ASM = %s"%out
    return out
                                                                                     
if __name__=="__main__":
    filename="lcreat.il"
    data=open(filename).read()
    print "-"*50
    print "PPC code: \n%s"%(generate(data))

