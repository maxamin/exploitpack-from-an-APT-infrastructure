#! /usr/bin/env python
"""
Converts a IL file (or buffer) into AT&T syntax x86
"""

from mosdefutils import *
from il2proc import IL2Proc


#iltable = { "GETPC":["call RESERVED_getpc\n", "RESERVED_getpc:\n", "pop %ebx\n"],
            #"rem":  lambda words: " # %s\n"%(" ".join(words[1:])),
            #"asm":  lambda words: " ".join(words[1:])+"\n",
            #"debug": ["int3\n"],
            #"call": lambda words: "call %s\n"%words[1],
            #"ret":  lambda words: "ret\n" if words[1] =="0" else "ret $%d\n"%int(words[1],0),
            #"callaccum": ["call *%eax\n"],
            #"addconst": lambda words: "addl $%d,%%eax\n"%int(words[1]),
            #"subconst": lambda words: "subl $%d,%%eax\n"%int(words[1]),
            #"labeldefine": lambda words: "%s:\n"%words[1],
            #"longvar": lambda words:".long %s\n" % uint32fmt(words[1]),
            #"ascii": lambda words: ".ascii \"%s\"\n"%(" ".join(words[1:])),
            #"urlencoded": lambda words: ".urlencoded \"%s\"\n"%(" ".join(words[1:])),
            #"databytes": lambda words: ".byte %s\n" % words[1],
            #"archalign": [""],
            #"compare": ["cmpl %edx, %eax\n"],
            #"setifless": ["setl %al\n", "movzbl %al,%eax\n"],
            #"setifgreater": ["setg %al\n", "movzbl %al,%eax\n"],
            #"setifnotequal": ["setne %al\n", "movzbl %al,%eax\n"],
            #"setifequal": ["sete %al\n", "movzbl %al,%eax\n"],
            #"jumpiffalse": lambda words: "test %%eax, %%eax\n jz %s\n" % words[1],
            #"jumpiftrue":  lambda words: "test %%eax, %%eax\n jnz %s\n" % words[1],
            #"jump": lambda words: "jmp %s\n"%words[1],
            #"functionprelude": ["pushl %ebp\nmovl %esp,%ebp\n"],
            #"functionpostlude": ["movl %ebp,%esp\npopl %ebp\n"], # FIXME see "freestackspace"
            #"getstackspace": _getstackspace,
            #"freestackspace": _freestackspace,
            #"pushaccum":  ["pushl %eax\n"],
            #"poptosecondary": ["popl %edx\n"],
            #"addsecondarytoaccum": ["addl %edx, %eax\n"],
            #"subtractsecondaryfromaccum": ["subl %edx, %eax\n"],
            #"modulussecondaryfromaccum": ["pushl %ecx\n", #save it
                                          #"movl %edx, %ecx\n", #argument
                                          #"movl $0, %edx\n", #clear edx otherwise you'll get integer overflow
                                          #"idivl %ecx\n", #do divide, edx is modulus now, eax is result
                                          #"movl %edx, %eax\n", #save result in accumulator
                                          #"popl %ecx\n"], #restore it
            #"dividesecondaryfromaccum":  ["pushl %ecx\n", #save it (#idivl %ecx means eax=edx:eax/ecx / eax is already our first argument
                                          #"movl %edx, %ecx\n", #argument
                                          #"movl $0, %edx\n", #clear edx otherwise you'll get integer overflow
                                          #"idivl %ecx\n", #do divide, edx is modulus now, eax is result
                                          #"popl %ecx\n"], #restore it                        
            #"loadint": lambda words: "movl $%d,%%eax\n" % long(words[1],0),
            #"accumulator2memorylocal": _accumulator2memorylocal,           
            #"accumulator2index": ["movl %eax, %edx\n"],
            #"derefwithindex": ["movl (%eax,%edx,1),%eax\n"],
            #"multiply": lambda words: "mov $%d,%%edx\n mul %%edx\n"%int(words[1]),  #destroys %edx, our index reg
            #"multaccumwithsecondary": ["mul %edx\n"], #our secondary register holds the value to multiply by
            ##in our case, %edx
            #"storeaccumulator": ["mov %eax, %edi\n"], #store it into edi
            #"storewithindex": _storewithindex,
            #"derefaccum": _derefaccum,
            #"loadlocal": _loadlocal,
            #"arg":["pushl %eax\n"],
            #"loadlocaladdress": _loadlocaladdress,
            #"loadglobaladdress": lambda words: "lea %s-RESERVED_getpc(%%ebx), %%eax\n"%(words[1]),
            #"loadglobal": _loadglobal,
            #"pushshiftreg": ["pushl %ecx\n"],
            #"poptoshiftreg":["popl %ecx\n"],
            #"shiftright":   ["shr %cl, %eax\n"],
            #"shiftleft":    ["shl %cl, %eax\n"],
            #"andaccumwithsecondary": ["and %edx, %eax\n"],
            #"xoraccumwithsecondary":["xor %edx, %eax\n"],
            #"oraccumwithsecondary": ["orl %edx, %eax\n"]
#}


class ilX86(IL2Proc):
    def __init__(self):
        IL2Proc.__init__(self)

    def _save_stack(self, words):
        """
        Save ESP so that we can restore it later.
        ESI is saved and restored by the callee according to SystemV x86 ABI.
        """
        return ["pushl %ecx\n", "pushl %edx\n", "pushl %esi\n", "movl %esp, %esi\n"]


    def _restore_stack(self, words):
        """
        Restore previously saved ESP.    
        """
        return ["movl %esi, %esp\n", "popl %esi\n", "popl %edx\n", "popl %ecx\n"]
        
    def _alignstack_pre(self, words):
        """
        Ensure stack is 16-byte aligned (osx/intel32)
        
        From OSX ABI: "The stack is 16-byte aligned at the point of function calls"
        If we try to call library functions without the correct stack alignment, 
        the process will crash with dyld_misaligned_stack_error.
        We therefore ensure that %esp % 16 == 0 before every library function call.
        """
        def fixstack(vars):
            tmp = (4*vars)%16
            if tmp == 0:
                return "$0x00"
            
            return "$" + str(16-tmp)
        
        return ["andl $0xfffffff0, %esp\n",
                "subl %s, %%esp\n" % fixstack(int(words[1]))]
    
    def _labeldefine(self, words):
        return ["%s:\n"%words[1]]

    def _compare(self, words):
        return ["cmpl %edx, %eax\n"]

    def _poptosecondary(self, words):
        return ["popl %edx\n"]

    def _jump(self, words):
        return ["jmp %s\n" % words[1] ]

    def _accumulator2index(self, words):
        return ["movl %eax, %edx\n"]

    def _oraccumwithsecondary(self, words):
        return ["orl %edx, %eax\n"]

    def _derefwithindex(self, words):
        return ["movl (%eax,%edx,1),%eax\n"]

    def _setifless(self, words):
        return ["setl %al\n", "movzbl %al,%eax\n"]

    def _xoraccumwithsecondary(self, words):
        return ["xor %edx, %eax\n"]

    def _ascii(self, words):
        return [".ascii \"%s\"\n"%(" ".join(words[1:]))]

    def _subtractsecondaryfromaccum(self, words):
        return ["subl %edx, %eax\n"]

    def _addconst(self, words):
        return ["addl $%d,%%eax\n"%int(words[1])]

    def _jumpiftrue(self, words):
        return ["test %eax, %eax\n", "jnz %s\n" % words[1] ]

    def _multaccumwithsecondary(self, words):
        return ["mul %edx\n"] #our secondary register holds the value to multiply by
                              #in our case, %edx
                              
    def _subconst(self, words):
        return ["subl $%d,%%eax\n"%int(words[1])]

    def _setifnotequal(self, words):
        return ["setne %al\n", 
                "movzbl %al,%eax\n"]

    def _ret(self, words):
        if words[1] =="0":
            return ["ret\n"] 
        else:
            return ["ret $%d\n"%int(words[1],0)]

    def _loadint(self, words):
        return ["movl $%d,%%eax\n" % long(words[1],0)]

    def _call(self, words):
        return ["call %s\n"%words[1]]

    def _asm(self, words):
        return [" ".join(words[1:])+"\n"]

    def _rem(self, words):
        return [" # %s\n"%(" ".join(words[1:]))]

    def _addsecondarytoaccum(self, words):
        return ["addl %edx, %eax\n"]

    def _functionpostlude(self, words):
        return ["movl %ebp,%esp\n", # FIXME see "freestackspace" 
                "popl %ebp\n"]

    def _urlencoded(self, words):
        return [".urlencoded \"%s\"\n"%(" ".join(words[1:]))]

    def _dividesecondaryfromaccum(self, words):
        return ["pushl %ecx\n", #save it (#idivl %ecx means eax=edx:eax/ecx / eax is already our first argument
                "movl %edx, %ecx\n", #argument
                "movl $0, %edx\n", #clear edx otherwise you'll get integer overflow
                "idivl %ecx\n", #do divide, edx is modulus now, eax is result
                "popl %ecx\n"] #restore it                        


    def _setifequal(self, words):
        return ["sete %al\n", 
                "movzbl %al,%eax\n"]

    def _archalign(self, words):
        return [""]

    def _shiftright(self, words):
        return ["shr %cl, %eax\n"]
    
    def _pushaccum(self, words):
        return ["pushl %eax\n"]

    def _jumpiffalse(self, words):
        return ["test %eax, %eax\n", "jz %s\n" % words[1]]

    def _multiply(self, words):
        return ["mov $%d,%%edx\n" %int(words[1]),  #destroys %edx, our index reg
                "mul %edx\n"] 

    def _arg(self, words):
        return ["pushl %eax\n"]
    
    def _poptoshiftreg(self, words):
        return ["popl %ecx\n"]

    def _longvar(self, words):
        return [".long %s\n" % uint32fmt(words[1])]

    def _callaccum(self, words):
        return ["call *%eax\n"]

    def _pushshiftreg(self, words):
        return ["pushl %ecx\n"]    

    def _databytes(self, words):
        return [ ".byte %s\n" % words[1] ]

    def _modulussecondaryfromaccum(self, words):
        return ["pushl %ecx\n", #save it
                "movl %edx, %ecx\n", #argument
                "movl $0, %edx\n", #clear edx otherwise you'll get integer overflow
                "idivl %ecx\n", #do divide, edx is modulus now, eax is result
                "movl %edx, %eax\n", #save result in accumulator
                "popl %ecx\n"] #restore it

    def _loadglobaladdress(self, words):
        return ["lea %s-RESERVED_getpc(%%ebx), %%eax\n"%(words[1]) ]
    

    def _functionprelude(self, words):
        return ["pushl %ebp\n", 
                "movl %esp,%ebp\n"]

    def _shiftleft(self, words):
        return ["shl %cl, %eax\n"]
    
    def _GETPC(self, words):
        return ["call RESERVED_getpc\n", 
                "RESERVED_getpc:\n", 
                "pop %ebx\n"]

    def _debug(self, words):
        return ["int3\n"]

    def _andaccumwithsecondary(self, words):
        return ["and %edx, %eax\n"]

    def _setifgreater(self, words):
        return ["setg %al\n", "movzbl %al,%eax\n"]

    def _storeaccumulator(self, words):
        return ["mov %eax, %edi\n"] #store it into edi

    def _getstackspace(self, words):
        #mod 4 stackspace
        stackspace=int(words[1],0)
        mod4=stackspace%4
        if mod4!=0:
            stackspace+=4-mod4
        return ["sub $%d,%%esp\n" % (stackspace) ]

    def _freestackspace(self, words):
        no_freestackspace_on_x86_coz_in_postlude = True
        return ""

    def _accumulator2memorylocal(self, words):
        #BROKEN - what if I need to store into an argument?
        #FIXED - deal with in* ;)
        if words[1][:2]=="in":
            #input register on sparc, stack arg on x86
            argnum=int(words[1][2:])
            end="%s(%%ebp)"%uint32fmt((argnum*4)+8)
        else:
            #local stack variable
            argnum=int(words[1])
            end="%s(%%ebp)"%uint32fmt(-(argnum))
        if words[2]=="4":
            return ["movl %%eax, %s\n"%(end)]
        elif words[2]=="2":
            return ["movw %%ax, %s\n"%(end)]
        elif words[2]=="1":
            return ["movb %%al, %s\n"%(end)]
        else:
            print "ERROR: Unknown store size %d asked for..."%int(words[2])

    def _storewithindex(self, words):
        #uses edx as the index register, and eax as the source register
        #uses %edi as the value to store
        #words[1] is size of type (1,2,4)
        if words[1]=="4":
            return ["movl %edi, (%eax,%edx,1)\n"]
        if words[1]=="2":
            return ["movw %di, (%eax,%edx,1)\n"]
        if words[1]=="1":
            return ["push %ecx\n",
                    "mov %edi, %ecx\n",
                    "movb %cl, (%eax,%edx,1)\n",
                    "pop %ecx\n"]

    def _derefaccum(self, words):
        #words[1] is size of argument (1,2,4)
        out=["push %edx\n"]
        out+=["xor %edx, %edx\n"]
        if words[1]=="4":
            out+=["movl (%eax), %edx\n"]
        elif words[1]=="2":
            out+=["movw (%eax), %dx\n"  ] 
        elif words[1]=="1":
            out+=["movb (%eax), %dl\n" ]
        else:
            print "dereferencing unknown accumulator length...%s"%words[1]
        out+=["movl %edx, %eax\n"]
        out+=["popl %edx\n"]
        return out

    def _loadlocal(self, words):
        size=int(words[2])        
        if words[1][:2]=="in":
            #input register on sparc, stack arg on x86
            argnum=int(words[1][2:])
            end="%s(%%ebp)"%uint32fmt((argnum*4)+8)
        else:
            #local stack variable
            argnum=int(words[1])
            #out+=["argnum = %s\n"%argnum
            end="%s(%%ebp)"%uint32fmt(-(argnum))
        if words[2]=="4":
            return [ "movl %s, %%eax\n"% (end) ]
        elif words[2]=="2":
            #first, we must clear the accumulator
            return ["xor %%eax, %%eax\n movw %s, %%ax\n"% (end) ]
        elif words[2]=="1":
            #first, we must clear the accumulator
            return ["xor %%eax, %%eax\n movb %s, %%al\n"%(end) ]
        else:
            print "ERROR: Unknown load size %d asked for..."%size



    def _loadlocaladdress(self, words):
        if words[1][:2]=="in":
            argnum=int(words[1][2:])
            return ["lea %s(%%ebp), %%eax\n"% uint32fmt(8+4*argnum)]
        else:
            return ["lea %s(%%ebp), %%eax\n"% uint32fmt(-1*(int(words[1])))]

    def _loadglobal(self, words):
        if words[2]=="4":
            return ["movl %s-RESERVED_getpc(%%ebx), %%eax\n" % (words[1])]
        elif words[2]=="2":
            #first, we must clear the accumulator
            return ["xor %eax, %eax\n movw %s-RESERVED_getpc(%%ebx), %%ax\n"%(words[1])]
        elif words[2]=="1":
            #first, we must clear the accumulator
            return ["xor %eax, %eax\n movb %s-RESERVED_getpc(%%ebx), %%al\n"%(words[1])]


def generate(data):
    il = ilX86()
    return il.generate(data)
    
def generate_(data):
    out=[]
    lines=data.split("\n")
    try:
        for line in lines:
            if line=="":
                continue
            words=line.split(" ")
            try:
                f = iltable[ words[0] ]
            except KeyError:
                print "IL tag not known: %s" % str(words)
            if callable(f):
                out += [ f( words ) ]
            else:
                out += f
        
    except ZeroDivisionError:
        print out    
        
    return "".join(out)


def generate_(data):
    out=[]
    lines=data.split("\n")

    try:
        for line in lines:
            if line=="":
                continue
            words=line.split(" ")
            if words[0]=="GETPC":
                #this is 5 bytes
                out+=["call RESERVED_getpc\n"]
                out+=["RESERVED_getpc:\n"]
                out+=["pop %ebx\n"]
            elif words[0]=="rem":
                #comment
                out+=[" # %s\n"%(" ".join(words[1:]))]
            elif words[0]=="asm":
                out+=[" ".join(words[1:])+"\n"]
            elif words[0]=="debug":
                out+=["int3\n"]
            elif words[0]=="call":
                out+=["call %s\n"%words[1]]
            elif words[0]=="ret":
                if words[1]!="0":
                    out+=["ret $%d\n"%int(words[1],0)]
                else:
                    out+=["ret\n"]
            elif words[0]=="callaccum":
                out+=["call *%eax\n"]
            elif words[0]=="addconst":
                out+=["addl $%d,%%eax\n"%int(words[1])]
            elif words[0]=="subconst":
                out+=["subl $%d,%%eax\n"%int(words[1])]
            elif words[0]=="labeldefine":
                out+=["%s:\n"%words[1]]
            elif words[0]=="longvar":
                out+=[".long %s\n" % uint32fmt(words[1])]
            elif words[0]=="ascii":
                out+=[".ascii \"%s\"\n"%(" ".join(words[1:]))]
            elif words[0]=="urlencoded":
                out+=[".urlencoded \"%s\"\n"%(" ".join(words[1:]))]
            elif words[0]=="databytes":
                out+=[".byte %s\n"%words[1]]
            elif words[0]=="archalign":
                out+=[""]

            #comparison fun
            elif words[0]=="compare":
                out+=["cmpl %edx, %eax\n"]
            elif words[0]=="setifless":
                out+=["setl %al\n"]
                out+=["movzbl %al,%eax\n"]
            elif words[0]=="setifgreater":
                out+=["setg %al\n"]
                out+=["movzbl %al,%eax\n"]
            elif words[0]=="setifnotequal":
                out+=["setne %al\n"]
                out+=["movzbl %al,%eax\n"]
            elif words[0]=="setifequal":
                out+=["sete %al\n"]
                out+=["movzbl %al,%eax\n"]
            elif words[0]=="jumpiffalse":
                out+=["test %eax, %eax\n"]
                out+=["jz %s\n"%words[1]]
            elif words[0]=="jumpiftrue":
                out+=["test %eax, %eax\n"]
                out+=["jnz %s\n"%words[1]]

            elif words[0]=="jump":
                out+=["jmp %s\n"%words[1]]

            elif words[0]=="functionprelude":
                out+=["pushl %ebp\nmovl %esp,%ebp\n"]
            elif words[0]=="functionpostlude": # FIXME see "freestackspace"
                # XXX not yet implemented
                #functionpostlude_not_yet_implemented = True
                # XXX broken mosdef!
                out+=["movl %ebp,%esp\npopl %ebp\n"]
            elif words[0]=="getstackspace":
                #mod 4 stackspace
                stackspace=int(words[1],0)
                mod4=stackspace%4
                if mod4!=0:
                    stackspace+=4-mod4
                out+=["sub $%d,%%esp\n"%(stackspace)]
            elif words[0]=="freestackspace": # FIXME see "functionpostlude"
                # XXX out+=["movl %ebp,%esp\npopl %ebp\n"]
                no_freestackspace_on_x86_coz_in_postlude = True
            elif words[0]=="pushaccum":
                out+=["pushl %eax\n"]
            elif words[0]=="poptosecondary":
                out+=["popl %edx\n"]
            elif words[0]=="addsecondarytoaccum":
                out+=["addl %edx, %eax\n"]
            elif words[0]=="subtractsecondaryfromaccum":
                out+=["subl %edx, %eax\n"]
            elif words[0]=="modulussecondaryfromaccum":
                #idivl %ecx means eax=edx:eax/ecx
                #eax is already our first argument
                out+=["pushl %ecx\n"] #save it
                out+=["movl %edx, %ecx\n"] #argument
                out+=["movl $0, %edx\n"] #clear edx otherwise you'll get integer overflow
                out+=["idivl %ecx\n"] #do divide, edx is modulus now, eax is result
                out+=["movl %edx, %eax\n"] #save result in accumulator
                out+=["popl %ecx\n"] #restore it
            elif words[0]=="dividesecondaryfromaccum":
                #idivl %ecx means eax=edx:eax/ecx
                #eax is already our first argument
                out+=["pushl %ecx\n"] #save it
                out+=["movl %edx, %ecx\n"] #argument
                out+=["movl $0, %edx\n"] #clear edx otherwise you'll get integer overflow
                out+=["idivl %ecx\n"] #do divide, edx is modulus now, eax is result
                out+=["popl %ecx\n"] #restore it                        
            elif words[0]=="loadint":
                out+=["movl $%d,%%eax\n"%long(words[1],0)]
            elif words[0]=="accumulator2memorylocal":
                #BROKEN - what if I need to store into an argument?
                #FIXED - deal with in* ;)
                if words[1][:2]=="in":
                    #input register on sparc, stack arg on x86
                    argnum=int(words[1][2:])
                    end="%s(%%ebp)"%uint32fmt((argnum*4)+8)
                else:
                    #local stack variable
                    argnum=int(words[1])
                    end="%s(%%ebp)"%uint32fmt(-(argnum))
                if words[2]=="4":
                    out+=["movl %%eax, %s\n"%(end)]
                elif words[2]=="2":
                    out+=["movw %%ax, %s\n"%(end)]
                elif words[2]=="1":
                    out+=["movb %%al, %s\n"%(end)]
                else:
                    print "ERROR: Unknown store size %d asked for..."%int(words[2])
            elif words[0]=="accumulator2index":
                #save index value currently in accumulator for array referenceing
                out+=["movl %eax, %edx\n"]
            elif words[0]=="derefwithindex":
                #do a pointer derefernce using our index register (edx)
                out+=["movl (%eax,%edx,1),%eax\n"]
            elif words[0]=="multiply":
                #destroys %edx, our index reg
                out+=["mov $%d,%%edx\n"%int(words[1])]
                out+=["mul %edx\n"]
            elif words[0]=="multaccumwithsecondary":
                #our secondary register holds the value to multiply by
                #in our case, %edx
                out+=["mul %edx\n"]
            elif words[0]=="storeaccumulator":
                out+=["mov %eax, %edi\n"] #store it into edi
            elif words[0]=="storewithindex":
                #uses edx as the index register, and eax as the source register
                #uses %edi as the value to store
                #words[1] is size of type (1,2,4)
                if words[1]=="4":
                    out+=["movl %edi, (%eax,%edx,1)\n"]
                if words[1]=="2":
                    out+=["movw %di, (%eax,%edx,1)\n"   ]
                if words[1]=="1":
                    out+=["push %ecx\n"]
                    out+=["mov %edi, %ecx\n"]
                    out+=["movb %cl, (%eax,%edx,1)\n" ]
                    out+=["pop %ecx\n"]
            elif words[0]=="derefaccum":
                #words[1] is size of argument (1,2,4)
                out+=["push %edx\n"]
                out+=["xor %edx, %edx\n"]
                if words[1]=="4":
                    out+=["movl (%eax), %edx\n"]
                elif words[1]=="2":
                    out+=["movw (%eax), %dx\n"  ] 
                elif words[1]=="1":
                    out+=["movb (%eax), %dl\n" ]
                else:
                    print "dereferencing unknown accumulator length...%s"%words[1]
                out+=["movl %edx, %eax\n"]
                out+=["popl %edx\n"]

            elif words[0]=="loadlocal":
                size=int(words[2])
                if words[1][:2]=="in":
                    #input register on sparc, stack arg on x86
                    argnum=int(words[1][2:])
                    end="%s(%%ebp)"%uint32fmt((argnum*4)+8)
                else:
                    #local stack variable
                    argnum=int(words[1])
                    #out+=["argnum = %s\n"%argnum
                    end="%s(%%ebp)"%uint32fmt(-(argnum))
                if words[2]=="4":
                    out+=["movl %s, %%eax\n"%(end)]
                elif words[2]=="2":
                    out+=["xor %eax, %eax\n"] #first, we must clear the accumulator
                    out+=["movw %s, %%ax\n"%(end)]
                elif words[2]=="1":
                    out+=["xor %eax, %eax\n"] #first, we must clear the accumulator
                    out+=["movb %s, %%al\n"%(end)]
                else:
                    print "ERROR: Unknown load size %d asked for..."%size

            elif words[0]=="arg":
                out+=["pushl %eax\n"]
            elif words[0]=="loadglobaladdress":
                #print "Loading global address"
                out+=["lea %s-RESERVED_getpc(%%ebx), %%eax\n"%(words[1])]
            elif words[0]=="loadlocaladdress":
                if words[1][:2]=="in":
                    argnum=int(words[1][2:])
                    out+=["lea %s(%%ebp), %%eax\n"%uint32fmt(8+4*argnum)]
                else:
                    out+=["lea %s(%%ebp), %%eax\n"%uint32fmt(-1*(int(words[1])))]
            elif words[0]=="loadglobal":
                if words[2]=="4":
                    out+=["movl %s-RESERVED_getpc(%%ebx), %%eax\n"%(words[1])]
                elif words[2]=="2":
                    out+=["xor %eax, %eax\n"] #first, we must clear the accumulator
                    out+=["movw %s-RESERVED_getpc(%%ebx), %%ax\n"%(words[1])]
                elif words[2]=="1":
                    out+=["xor %eax, %eax\n"] #first, we must clear the accumulator
                    out+=["movb %s-RESERVED_getpc(%%ebx), %%al\n"%(words[1])]
            elif words[0]=="pushshiftreg":
                out+=["pushl %ecx\n"]
            elif words[0]=="poptoshiftreg":
                out+=["popl %ecx\n"]
            elif words[0]=="shiftright":
                out+=["shr %cl, %eax\n"]
            elif words[0]=="shiftleft":
                out+=["shl %cl, %eax\n"]
            elif words[0]=="andaccumwithsecondary":
                out+=["and %edx, %eax\n"]
            elif words[0]=="xoraccumwithsecondary":
                out+=["xor %edx, %eax\n"]
            elif words[0]=="oraccumwithsecondary":
                out+=["orl %edx, %eax\n"]

            else:
                print "WARNING ERROR IN IL: %s"%words[0]
    except ZeroDivisionError:
        print out
    #print "".join(out)

    return "".join(out)





if __name__=="__main__":
    import sys
    filename="lcreat.il"
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    data=open(filename).read()
    print "-"*50
    print "x86 code: \n%s"%(generate(data))
    #transform into AT&T style x86 assembly
    #then run through at&t x86 assembler
    #then done!
