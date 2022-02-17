#! /usr/bin/env python
"""
x86asm.py

A sort of weird collection of hand-assembled things
"""
from exploitutils import *


def normalizeespebp():
    """
    Normalizes the stack
    normalizeespandebp:
        sub $0x50,%esp
        call geteip
        geteip:
        pop %ebx
        //ebx now has our base!
        movl %ebx,%esp
        subl $0x1000,%esp
        //esp is now a nice value
        mov    %esp,%ebp
        //ebp is now a nice value too! :>
    donenormalize:
    """
    tmp=binstring("83 ec 50 e8 00 00 00	00")
    tmp+=binstring("0x5b 0x89 0xdc 0x81 0xec 0x00 0x10 0x00")
    tmp+=binstring("0x00 0x89 0xe5")
    return tmp


def cleanreg(reg):
    reg=reg.replace("%","")
    reg=reg.replace("$","")
    reg=reg.lower()
    return reg

def callzero():
    """
    Useful for crashing the program at a known place
    callzero:
        xorl %eax,%eax
        call *%eax
    donecallzero:
            
    """
    
    tmp=binstring("0x31	0xc0	0xff	0xd0")
    return tmp

def xorl_regreg(reg1,reg2):
    reg1=cleanreg(reg1)
    reg2=cleanreg(reg2)
    dict1={"eax": "\x31" }
    dict2={"eax": "\xc0" }
    return dict1[reg1]+dict2[reg2]

def push_reg(reg):
    reg=cleanreg(reg)
    dict={ "eax" : "\x50" , "ebx": "\x53" }
    return dict[reg]

def movl_immreg(imm,reg):
    reg=cleanreg(reg)
    dict={ "eax" : "\xb8" , "ebx": "\xbb" }
    return dict[reg]+intel_order(int(imm))

def int_imm(imm):
    return "\xcd"+chr(int(imm)&0xff)

def pop_reg(reg):
    reg=cleanreg(reg)
    dict={ "eax" : "\x58" , "ebx": "\x5b" }
    return dict[reg]

def jmpshort(imm):
    tmp="\xeb"+chr(imm&0xff)
    return tmp

def jmp_reg(reg):
    """
    jmp *%reg
    """
    reg=cleanreg(reg)
    dict={ "eax": "\xe0", "esp": "\xe4"}
    return "\xff"+dict[reg]
    

def callesp():
    """
    call *%esp
    """
    return binstring("ff d4")

def jmpesp():
    """
    jmp *%esp
    """