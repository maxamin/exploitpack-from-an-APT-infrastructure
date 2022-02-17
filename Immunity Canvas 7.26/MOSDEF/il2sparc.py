#! /usr/bin/env python

import string
import urllib

"""
Converts a IL file (or buffer) into SPARC asm
"""

from mosdefutils import *


def generate(data):

    ldX = { '1':"ldub", '2':"lduh", '4':"ld" }

#    fd = open("out.il", "a")
#    fd.write("!!! NEWIL:\n\n" + data)
#    fd.close()

    labelcount=0
    argcount=0
    callhappened=0
    lastword=""
    lastloadint=0
    out=""
    lines=data.split("\n")
    alignlen=0
    try:
        for line in lines:
            if line=="":
                continue
            words=line.split(" ")

            if words[0]=="GETPC":
                # we are called !
                out+="nop\n"
                out+="save %sp,-96,%sp\n"
                out+="nop\n"
                #we put base in %g7
                out+="RESERVED_getpc:\n"
                out+="bn,a RESERVED_getpc-4\n"
                out+="bn,a RESERVED_getpc\n"
                out+="RESERVED_pcloc:\n"
                out+="call RESERVED_getpc+4\n"
                out+="mov %o7,%g7\n"
                
            elif words[0]=="rem":
                #comment
                out+="! %s\n"%(" ".join(words[1:]))
                
            elif words[0]=="asm":
                out+=" ".join(words[1:])+"\n"
                
            elif words[0]=="debug":
                out+="ta 1\n"
                
            elif words[0]=="call":
                callhappened=1
                # we're gonna have to assume that label offsets
                # are possibly > 4096 or < -4096
                out+="set %s-RESERVED_pcloc,%%l5\n"%words[1]
                out+="addcc %g7,%l5,%l5\n"
                out+="jmpl %l5,%o7\n"

                #out+="jmpl %%g7+%s-RESERVED_pcloc,%%o7\n"%words[1]
                # delay slot
                out+="nop\n"
                out+="mov %o0, %l1\n" #load accumulator from function result
                
            elif words[0]=="ret":
                out+="mov %l1,%i0\n" #save off accumulator as return value
                out+="jmpl %i7+8,%g0\n"
                # use %l1 and %l2 as we would %eax, %edx
                out+="! restore in delayslot of ret\n"
                out+="restore\n"
                
            elif words[0]=="callaccum":
                callhappened=1
                out+="jmpl %l1,%o7\n"
                out+="nop\n"
                
            elif words[0]=="addconst":
                if int(words[1]):
                    if int(words[1]) >= -4096 and int(words[1]) <= 4096:
                        out+="mov %d,%%l2\n"%int(words[1])
                    else:
                        out+="set %d,%%l2\n"%int(words[1])
                    out+="addcc %l1,%l2,%l1\n"
                else:
                   # print "NOT ADDING ZERO"
                   pass

            elif words[0]=="subconst":
                if int(words[1]):
                    if int(words[1]) >= -4096 and int(words[1]) <= 4096:
                        out+="mov %d,%%l2\n"%int(words[1])
                    else:
                        out+="set %d,%%l2\n"%int(words[1])
                    out+="subcc %l1,%l2,%l1\n"
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
                else:
                    alignlen = 3 # 4 - 1
                
            elif words[0]=="archalign":
                if alignlen:
                    out+=".ascii \""+"A"*alignlen+"\"\n"
                    alignlen = 0
        
                #comparison fun
            elif words[0]=="compare":
                out+="cmp %l1,%l2\n"
                
            elif words[0]=="setifless":
                # PROBLEM: what if there's multiple of these? labels will heck up..need more elegant port
                # SOLUTION: labelcountman truss               
                out+="bl setifless%d\n"%labelcount
                # set in delay slot
                out+="mov 1,%l1\n"
                # no set
                out+="mov %g0,%l1\n"
                out+="setifless%d:\n"%labelcount
                labelcount+=1
                
            elif words[0]=="setifgreater":
                out+="bg setifgreater%d\n"%labelcount
                # set in delay slot
                out+="mov 1,%l1\n"
                # no set
                out+="mov %g0,%l1\n"
                out+="setifgreater%d:\n"%labelcount
                labelcount+=1
                
            elif words[0]=="setifnotequal":
                out+="bne setifnotequal%d\n"%labelcount
                # set in delay slot
                out+="mov 1,%l1\n"
                # no set
                out+="mov %g0,%l1\n"
                out+="setifnotequal%d:\n"%labelcount
                labelcount+=1
                
            elif words[0]=="setifequal":
                out+="be setifequal%d\n"%labelcount
                # set in delay slot
                out+="mov 1,%l1\n"
                # no set
                out+="mov %g0,%l1\n"
                out+="setifequal%d:\n"%labelcount
                labelcount+=1
                
            elif words[0] in ["jumpiffalse", "jumpiftrue"]:
                jumpif_op = {'jumpiffalse': "be", 'jumpiftrue': "bne"}
                out+="cmp %g0,%l1\n"
                # XXX: + 4 to fix our weird offset bug for now
                out+="%s %s\n" % (jumpif_op[words[0]], words[1])
                # delay slot
                out+="!delay slot\n"
                out+="nop\n"
                
            elif words[0]=="jump":
                # use junk reg to keep %o7 intact, jmp not call :>
                #out+="jmpl %%g7+%s-RESERVED_pcloc,%%g0\n"%words[1]
                
                # we're gonna have to assume that label offsets         
                # are possibly > 4096 or < -4096
                out+="set %s-RESERVED_pcloc,%%l5\n"%words[1]
                out+="addcc %g7,%l5,%l5\n"
                out+="jmpl %l5,%g0\n"
                # delayslot
                out+="nop\n"

            
            # we're using %l4 as our stackbase
            
            elif words[0]=="functionprelude":
                # should save locals space here too
                #out+="ta 1\n"
                out+="save %sp,-96,%sp\n"
                
            elif words[0]=="functionpostlude":
                #out+="restore\n" XXX
                we_dont_yet_use_restore_in_functionpostlude_on_sparc = True
            
            elif words[0]=="getstackspace":
                #mod 8 stackspace
                stackspace=int(words[1],0)
                mod8=stackspace%8
                if mod8!=0:
                    stackspace+=8-mod8
                if stackspace > 4096:
                    out+="set %d,%%l6\n"%(stackspace)
                    out+="sub %sp,%l6,%sp\n"
                else:
                    out+="sub %%sp,%d,%%sp\n"%(stackspace)
                
            elif words[0]=="freestackspace":
                #print "SKIPPING FREE STACKSPACE !"
                #mod 8 stackspace
                stackspace=int(words[1],0)
                mod8=stackspace%8
                if mod8!=0:
                    stackspace+=8-mod8
                if stackspace > 4096:
                    out+="set %d,%%l6\n"%(stackspace)
                    out+="add %sp,%l6,%sp\n"
                else:
                    out+="add %%sp,%d,%%sp\n"%(stackspace)
                
            elif words[0]=="pushaccum":
                out+="sub %sp,8,%sp\n"
                out+="st %l1,[%sp + 96]\n"
                
            elif words[0]=="poptosecondary":
                out+="ld [%sp + 96],%l2\n"
                out+="add %sp,8,%sp\n"
                
            elif words[0]=="addsecondarytoaccum":
                out+="add %l1,%l2,%l1\n"
                
            elif words[0]=="subtractsecondaryfromaccum":
                out+="sub %l1,%l2,%l1\n"
                
            elif words[0]=="loadint":
                lastloadint = long(words[1],0)
                if int(words[1]) >= -4096 and int(words[1]) <= 4096:
                    out+="mov %d,%%l1\n"%int(words[1])
                else:
                    out+="set %d,%%l1\n"%int(words[1])
                
            elif words[0]=="accumulator2memorylocal":
                # deal with in0 = in0 - whatever ;)
                if words[1][:2]=="in":
                    #input register on sparc, stack arg on x86
                    argnum=int(words[1][2:])
                    # out becomes in on call
                    if argnum > 6:
                        print "ERROR: number of arguments > 5 (%o0-%o6)"
                    elif argnum > 5:
                        out += "ld [ %%sp + 0x%x ], %%i%d\n" % (0x5c + ((argnum - 6) * 4), argnum)
                    else:
                        out+="mov %%l1,%%i%d\n"%argnum
                else:
                    if words[2]=="4":
                        out+="sub %sp,8,%sp\n"
                        out+="st %%l1,[%%fp-%d]\n"%uint32(int(words[1]))
                    elif words[2]=="2":
                        out+="sub %sp,8,%sp\n"
                        out+="sth %%l1,[%%fp-%d]\n"%uint32(int(words[1]))
                    elif words[2]=="1":
                        out+="sub %sp,8,%sp\n"
                        out+="stb %%l1,[%%fp-%d]\n"%uint32(int(words[1]))
                    else:
                        print "ERROR: Unknown load size %d asked for..."%int(words[2])
                    
            elif words[0]=="accumulator2index":
                #save index value currently in accumulator for array referenceing
                out+="mov %l1, %l2\n"
                
            elif words[0]=="derefwithindex":
                #do a pointer derefernce using our index register (l2)
                if len(words) > 1:
                    out += "%s [%%l1 + %%l2],%%l1\n"% ldX[ words[1] ]
                else:
                    print "XXX: defaulting to load size of 4 for derefwithindex !"
                    out+="ld [%l1 + %l2],%l1\n"
                
            elif words[0]=="multiply":
                # little hack so we dont have to do the full mulscc crap on certain common situations
                # such as (IL):
                # loadint 1
                # multiply 4
                multiplier = int(words[1])

                # don't forget to set %l2
                if lastloadint == 0 or multiplier == 0:
                    out += "mov %g0,%l1\n"
                    out += "mov %g0,%l2\n"
                    lastloadint = -1
                elif lastloadint == 1:
                    out += "mov %d,%%l1\n"%multiplier
                    out += "mov %d,%%l2\n"%multiplier
                    lastloadint = -1
                elif multiplier == 1:
                    # %l1 is correct
                    out += "mov %d,%%l2\n"%multiplier
                else:

                # we'll use mulscc because SPARC v7 doesn't have a real mul instruction
                # solution from 'SPARC Architecture, assembly language programming'
                    
                    if int(words[1]) >= -4096 and int(words[1]) <= 4096:
                        out+="mov %d,%%l2\n"%int(words[1])
                    else:
                        out+="set %d,%%l2\n"%int(words[1])
                    # multiplier is %l2, %l1 x %l2
                    out+="mov %l1,%o2\n"
                    out+="mov %l2,%o0\n"
                    out+="wry %g0,%o0,%y\n"
                    # wait to get %y reg
                    out+="nop\n"*3
                    out+="andcc %g0,%g0,%o1\n"
                    # 32 mulscc's
                    out+="mulscc %o1,%o2,%o1\n"*32
                    # final shift
                    out+="mulscc %o1,%g0,%o1\n"
                    # get result (high order is in %rd, low order in %y)
                    out+="rdy %y,%l1\n"
                
            elif words[0]=="storeaccumulator":
                out+="mov %l1,%l6\n" #store it into %l6
                
            elif words[0]=="storewithindex":
                # l6 is our edi equiv
                #words[1] is size of type (1,2,4)
                if words[1]=="4":
                    out+="st %l6,[%l1 + %l2]\n"
                if words[1]=="2":
                    out+="sth %l6,[%l1 + %l2]\n"  
                if words[1]=="1":
                    out+="stb %l6,[%l1 + %l2]\n"
                    
            elif words[0]=="derefaccum":
                #words[1] is size of argument (1,2,4)
                # save %l2
                out+="mov %l2,%l7\n"
                out+="mov %g0,%l2\n"
                if words[1]=="4":
                    out+="ld [%l1],%l2\n"
                elif words[1]=="2":
                    out+="lduh [%l1],%l2\n"   
                elif words[1]=="1":
                    out+="ldub [%l1],%l2\n" 
                else:
                    print "dereferencing unknown accumulator length...%s"%words[1]
                out+="mov %l2,%l1\n"
                out+="mov %l7,%l2\n"
                                        
            elif words[0]=="loadlocal":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                size=int(words[2])
                if words[1][:2]=="in":
                    #input register on sparc, stack arg on x86
                    argnum=int(words[1][2:])
                    #argnum-=1
                    # out becomes in on call
                    # on sparc, arg5 and further are stored at %fp+0x5c...
                    if argnum > 5:
                        out += "ld [ %%fp + 0x%x ], %%l1\n" % (0x5c + ((argnum - 6) * 4))
                    else:
                        out+="mov %%i%d,%%l1\n"%argnum
                else:
                    argnum=int(words[1])
                    if words[2]=="4":
                        out+="ld [%%fp - %d],%%l1\n"%argnum
                    elif words[2]=="2":
                        out+="lduh [%%fp - %d],%%l1\n"%argnum
                    elif words[2]=="1":
                        out+="ldub [%%fp - %d],%%l1\n"%argnum
                    else:
                        print "ERROR: Unknown load size %d asked for..."%size
                    
            elif words[0]=="loadlocaladdress":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                if words[1][:2]=="in":
                    # XXX is that here like loadlocal?
                    print "! CHECKOUT CORRECT USAGE HERE (loadlocaladdress in)"
                    # set %l1 to arg
                    argnum=int(words[1][2:])
                    #argnum-=1
                    if argnum > 5:
                        #print "ERROR: number of arguments > 5 (%o0-%o5)"
                        # XXX check here for localaddress...
                        out += "ld [ %%fp + 0x%x ], %%l1\n" % (0x5c + ((argnum - 6) * 4))
                    else:
                        # out becomes in
                        out+="mov %%i%d,%%l1\n"%argnum
                else:
                    out+="sub %%fp,%d,%%l1\n"%uint32(int(words[1]))
                                        
            elif words[0]=="arg":
                argcount = uint32(int(words[1]))
                if argcount > 5:
                    # XXX should we make space on the stack previously?
                    #print "ERROR: number of arguments > 5 (%o0-%o5)"
                    out += "st  %%l1, [ %%sp + 0x%x ]\n" % (0x5c + ((argcount - 6) * 4))
                else:
                    out+="mov %%l1,%%o%d\n"%argcount
                    
            elif words[0]=="loadglobaladdress":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                #print "Loading global address"
                #out+="ta 1\n"
                out+="set %s-RESERVED_pcloc,%%l6\n"%(words[1])
                out+="add %g7,%l6,%l1\n"
                                    
            elif words[0]=="loadglobal":
                # set lastloadint to -1 so multiply doesn't think it's still valid
                lastloadint = -1
                if words[2]=="4":
                    out+="ld [%%g7 + %s-RESERVED_pcloc],%%l1\n"%(words[1])
                elif words[2]=="2":
                    out+="lduh [%%g7 + %s-RESERVED_pcloc],%%l1\n"%(words[1])
                elif words[2]=="1":
                    out+="ldub [%%g7 + %s-RESERVED_pcloc],%%l1\n"%(words[1])
                    
            # l3 is our shift reg
            elif words[0]=="pushshiftreg":
                out+="sub %sp,8,%sp\n"
                out+="st %l3,[%sp + 96]\n"
                
            elif words[0]=="poptoshiftreg":
                out+="ld [%sp + 96],%l3\n"
                out+="add %sp,8,%sp\n"
                
            elif words[0]=="shiftright":
                # do we want a logical or arthmetic shift? assuming logical
                out+="srl %l1,%l3,%l1\n"
                
            elif words[0]=="shiftleft":
                out+="sll %l1,%l3,%l1\n"
                
            elif words[0]=="andaccumwithsecondary":
                out+="andcc %l2,%l1,%l1\n"
                
            elif words[0]=="oraccumwithsecondary":
                out+="orcc %l2,%l1,%l1\n"

            elif words[0]=="multaccumwithsecondary":
                # l1 and l2 are already loaded, doesnt really matter who the actual multiplier is (i hope ;))

                # we'll use mulscc because SPARC v7 doesn't have a real mul instruction
                # solution from 'SPARC Architecture, assembly language programming'
                    
                # multiplier is %l2, %l1 x %l2
                out+="mov %l1,%o2\n"
                out+="mov %l2,%o0\n"
                out+="wry %g0,%o0,%y\n"
                # wait to get %y reg
                out+="nop\n"*3
                out+="andcc %g0,%g0,%o1\n"
                # 32 mulscc's
                out+="mulscc %o1,%o2,%o1\n"*32
                # final shift
                out+="mulscc %o1,%g0,%o1\n"
                # get result (high order is in %rd, low order in %y)
                out+="rdy %y,%l1\n"
                
            else:
                print "WARNING ERROR IN IL: %s"%words[0]
            lastword=words[0]
    except ZeroDivisionError:
        print out
    #fd = open("out.s", "a")
    #fd.write("!!! NEWASM:\n\n" + out)
    #fd.close()
    #print "ASM = %s"%out
    return out
                                                                                     
if __name__=="__main__":
    filename="lcreat.il"
    data=open(filename).read()
    print "-"*50
    print "SPARC code: \n%s"%(generate(data))

