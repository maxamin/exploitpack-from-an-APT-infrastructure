#! /usr/bin/env python
"""
A PowerPC assembler for CANVAS

Some good reference material below:
http://developer.apple.com/documentation/DeveloperTools/Reference/Assembler/index.html
http://wall.riscom.net/books/proc/ppc/cwg/a_abi.html

"""

from mosdefutils import *

TODO = """
- parse cr registers
- fix broken instr     | MOSDEF      | GAS
  . ble-    0xfffffff4   0x40c1fff8    0x40a1ffec
  . bgt- cr7, 0x4        0x41810007    0x41a7ffec       
  . bso- cr1, 0x4        0x41810007    0x41a7ffec
  . cmpwi cr7,r7,0       2f870000      0x2f870000
- add instr
  . cmpwi cr3, r3, -1
"""

def hi(myint):
    return ((myint >> 16) & 0xFFFF)

def lo(myint):
    return myint & 0xFFFF

cr = {"lt":0, "gt":1, "eq":2, "so":3}
for field in range(0, 8):
    cr["cr%d" % field] = field
    cr["%%cr%d" % field] = field

def getcr(reg):
    #print "getcr: %s" % reg
    if reg in cr:
        return cr[reg]
    else:
        try:
            return dInt(reg)
        except ValueError:
            print "Control Register %s not found!"%reg
            print "ERROR - should not continue!"
            return ""

normalregs={"r":32}
def getreg(reg):
    """reg is a string that contains the %r1,%l0 etc
       we return its binary encoding """
    #print "getreg: %s" % reg
    # general registers
    if reg in range(0, 32):
        return reg
    try:
        if reg[0] == '%':
            reg = reg[1:]
        if reg[0]=="r":
            number=int(reg[1:])
            return number
    except TypeError, msg:
        raise error, "Failed to understand register (%s)" % reg
    
    if reg in ["sp", "%sp"]:
        return getreg("r1")
    try:
        return dInt(reg)
    except ValueError:
        print "Register %s not found!"%reg
        print "ERROR - should not continue!"
        return ""

    print "Register %s not found!"%reg
    print "ERROR - should not continue!"
    return ""

registers = []
for a in range(0, 32):
    registers += ["r%d" % a, "%%r%d" % a]
registers += ["sp", "%sp"]
# XXX TODO should work...
#registers += cr

#a dict of opcodes we support
#f3 is op,op3
opcodes={}

# iform:
#                             OP  AA LK
opcodes["b"]      = ["iform", 18, 0, 0 ]
opcodes["ba"]     = ["iform", 18, 1, 0 ]
opcodes["bl"]     = ["iform", 18, 0, 1 ]
opcodes["bla"]    = ["iform", 18, 1, 1 ]

# bform:
#                             OP  AA LK
opcodes["bc"]     = ["bform", 16, 0, 0 ]
opcodes["bca"]    = ["bform", 16, 1, 0 ]
opcodes["bcl"]    = ["bform", 16, 0, 1 ]
opcodes["bcla"]   = ["bform", 16, 1, 1 ]

# xlform                       OP  XO     LK
opcodes["bclr"]   = ["xlform", 19, 16, b("00") ]
opcodes["bclrl"]  = ["xlform", 19, 16, b("01")]
opcodes["bcctr"]  = ["xlform", 19, 528, b("00") ]
opcodes["bcctrl"] = ["xlform", 19, 528, b("01")]

opcodes["crand"]  = ["xlform", 19, 257]
opcodes["cror"]   = ["xlform", 19, 449]
opcodes["crxor"]  = ["xlform", 19, 193]
opcodes["crnand"] = ["xlform", 19, 225]

opcodes["crnor"]  = ["xlform", 19, 33]
opcodes["creqv"]  = ["xlform", 19, 289]
opcodes["crandc"] = ["xlform", 19, 129]
opcodes["crorc"]  = ["xlform", 19, 417]

opcodes["isync"]  = ["xlform", 19, 150]

#dform                        OP  RA!=RT
opcodes["lbz"]    = ["dform", 34, 0]
opcodes["lbzu"]   = ["dform", 35, 1]
opcodes["lhz"]    = ["dform", 40, 0]
opcodes["lhzu"]   = ["dform", 41, 1]
opcodes["lha"]    = ["dform", 42, 0]
opcodes["lhau"]   = ["dform", 43, 1]
opcodes["lwz"]    = ["dform", 32, 0]
opcodes["lwzu"]   = ["dform", 33, 1]
#                                 3=RA!=0
opcodes["stb"]    = ["dform", 38, 0]
opcodes["stbu"]   = ["dform", 39, 3]
opcodes["sth"]    = ["dform", 44, 0]
opcodes["sthu"]   = ["dform", 45, 3]
opcodes["stw"]    = ["dform", 36, 0]
opcodes["stwu"]   = ["dform", 37, 3]
opcodes["lmw"]    = ["dform", 46, 3]
opcodes["stmw"]   = ["dform", 47, 3]

opcodes["addi"]   = ["dform", 14, 0]

opcodes["addis"]  = ["dform", 15, 0]
opcodes["addic"]  = ["dform", 12, 0]
opcodes["addic."] = ["dform", 13, 0]
opcodes["subfic"] = ["dform", 8, 0]
opcodes["mulli"]  = ["dform", 7, 0]
opcodes["cmpi"]   = ["dform", 11, 0]
opcodes["cmpli"]  = ["dform", 10, 4] # 4 == UI (unsigned integer)
opcodes["tdi"]    = ["dform", 2, 0]
opcodes["twi"]    = ["dform", 3, 0]
opcodes["andi."]  = ["dform", 28, 4]
opcodes["andis."] = ["dform", 29, 4]
opcodes["ori"]    = ["dform", 24, 4]
opcodes["xori"]   = ["dform", 26, 4]
opcodes["oris"]   = ["dform", 25, 4]
opcodes["xoris"]  = ["dform", 27, 4]
opcodes["nop"]    = ["argsalias", "ori", ["r0", "r0", 0]] # prefered ISA nop


RA_EQ_RT   =  1
RA_EQ_ZERO =  4
EX_TO_RC   =  8
RT_IS_RA   = 0x10
#xform                        OP  XO   RA!=RT
opcodes["lbzx"]   = ["xform", 31, 87,  0]
opcodes["lbzux"]  = ["xform", 31, 119, RA_EQ_RT]
opcodes["lhzx"]   = ["xform", 31, 279, 0]
opcodes["lhzux"]  = ["xform", 31, 311, RA_EQ_RT]
opcodes["lhax"]   = ["xform", 31, 343, 0]
opcodes["lhaux"]  = ["xform", 31, 375, RA_EQ_RT]
opcodes["lwzx"]   = ["xform", 31, 23,  0]
opcodes["lwzux"]  = ["xform", 31, 55,  RA_EQ_RT]
opcodes["lwax"]   = ["xform", 31, 341, 0]
opcodes["lwaux"]  = ["xform", 31, 373, RA_EQ_RT]
#                                      3=RA!=0
opcodes["stbx"]   = ["xform", 31, 215, 0]
opcodes["stbux"]  = ["xform", 31, 215, RA_EQ_ZERO]
opcodes["sthx"]   = ["xform", 31, 407, 0]
opcodes["sthux"]  = ["xform", 31, 439, RA_EQ_ZERO]
opcodes["stwx"]   = ["xform", 31, 151, 0]
opcodes["stwux"]  = ["xform", 31, 183, RA_EQ_ZERO]
opcodes["lhbrx"]  = ["xform", 31, 790, 0]
opcodes["lwbrx"]  = ["xform", 31, 534, 0]
opcodes["sthbrx"] = ["xform", 31, 918, 0]
opcodes["stwbrx"] = ["xform", 31, 662, 0]
NB = [597, 725]
opcodes["lswi"]   = ["xform", 31, 597, RA_EQ_ZERO] # this two, have errors related with
opcodes["lswx"]   = ["xform", 31, 533, RA_EQ_RT] # XXX the "range" where the reg are loaded (i'll fixed it later)
opcodes["stswi"]  = ["xform", 31, 725, 0]
opcodes["stswx"]  = ["xform", 31, 661, 0]
opcodes["cmp"]    = ["xform", 31, 0,   0]
opcodes["cmpl"]   = ["xform", 31, 32,  0]
opcodes["td"]     = ["xform", 31, 68,  0]
opcodes["tw"]     = ["xform", 31, 4,   0]
#                                    Ex  RC  # 4 extend to be able to pass a RC
opcodes["and"]    = ["xform", 31, 28, EX_TO_RC | RT_IS_RA,  0]
opcodes["and."]   = ["xform", 31, 28, EX_TO_RC | RT_IS_RA,  1]
opcodes["xor"]    = ["xform", 31, 316, EX_TO_RC | RT_IS_RA, 0]
opcodes["xor."]   = ["xform", 31, 316, EX_TO_RC | RT_IS_RA, 1]
opcodes["or"]     = ["xform", 31, 444, EX_TO_RC | RT_IS_RA, 0]
opcodes["or."]    = ["xform", 31, 444, EX_TO_RC | RT_IS_RA, 1]
opcodes["nand"]   = ["xform", 31, 476, EX_TO_RC | RT_IS_RA, 0]
opcodes["nand"]   = ["xform", 31, 476, EX_TO_RC | RT_IS_RA, 1]
opcodes["nor"]    = ["xform", 31, 124, EX_TO_RC | RT_IS_RA, 0]
opcodes["nor."]   = ["xform", 31, 124, EX_TO_RC | RT_IS_RA, 1]
opcodes["andc"]   = ["xform", 31,  60, EX_TO_RC | RT_IS_RA, 0]
opcodes["andc."]  = ["xform", 31,  60, EX_TO_RC | RT_IS_RA, 1]
opcodes["eqv"]    = ["xform", 31, 284, EX_TO_RC | RT_IS_RA, 0]
opcodes["eqv."]   = ["xform", 31, 284, EX_TO_RC | RT_IS_RA, 1]
opcodes["orc"]    = ["xform", 31, 412, EX_TO_RC | RT_IS_RA, 0]
opcodes["orc."]   = ["xform", 31, 412, EX_TO_RC | RT_IS_RA, 1]
opcodes["extsb"]  = ["xform", 31, 954, EX_TO_RC | RT_IS_RA, 0]
opcodes["extsb."] = ["xform", 31, 954, EX_TO_RC | RT_IS_RA, 1]
opcodes["extsw"]  = ["xform", 31, 986, EX_TO_RC | RT_IS_RA, 0]
opcodes["extsw."] = ["xform", 31, 986, EX_TO_RC | RT_IS_RA, 1]
opcodes["extsh"]  = ["xform", 31, 922, EX_TO_RC | RT_IS_RA, 0]
opcodes["extsh"]  = ["xform", 31, 922, EX_TO_RC | RT_IS_RA, 1]
opcodes["cntlzd"] = ["xform", 31,  58, EX_TO_RC | RT_IS_RA, 0]
opcodes["cntlzd."]= ["xform", 31,  58, EX_TO_RC | RT_IS_RA, 1]
opcodes["cntlzw"] = ["xform", 31,  26, EX_TO_RC | RT_IS_RA, 0]
opcodes["cntlzw."]= ["xform", 31,  26, EX_TO_RC | RT_IS_RA, 1]
opcodes["sld"]    = ["xform", 31, 27, EX_TO_RC | RT_IS_RA,  0]  # 64b (not tested)
opcodes["sld."]   = ["xform", 31, 27, EX_TO_RC | RT_IS_RA, 1]  # 
opcodes["slw"]    = ["xform", 31, 24, EX_TO_RC | RT_IS_RA, 0]
opcodes["slw."]   = ["xform", 31, 24, EX_TO_RC | RT_IS_RA, 1]
opcodes["srw"]    = ["xform", 31, 536, EX_TO_RC | RT_IS_RA, 0]
opcodes["srw."]   = ["xform", 31, 536, EX_TO_RC | RT_IS_RA, 1]
opcodes["srawi"]  = ["xform", 31, 413, EX_TO_RC | RT_IS_RA, 0]
opcodes["srawi."] = ["xform", 31, 413, EX_TO_RC | RT_IS_RA, 1]
opcodes["srad"]   = ["xform", 31, 792, EX_TO_RC | RT_IS_RA, 0]
opcodes["srad."]  = ["xform", 31, 792, EX_TO_RC | RT_IS_RA, 1]

opcodes["sync"]   = ["xform", 31, 598, 0]
opcodes["eieio"]  = ["xform", 31, 854, 0]
opcodes["dcbf"]   = ["xform", 31, 86, RT_IS_RA | RA_EQ_ZERO, 0]
opcodes["dcbtst"] = ["xform", 31, 246, RT_IS_RA, 0]
opcodes["dcbst"]  = ["xform", 31, 54, 0]
opcodes["icbi"]   = ["xform", 31, 982, 0]

# mform                           Rc
opcodes["rlwinm"] = ["mform", 21, 0]
opcodes["rlwinm."]= ["mform", 21, 1]
opcodes["rlwnm"]  = ["mform", 23, 0]
opcodes["rlwnm."] = ["mform", 23, 1]
opcodes["rlwimi"]  = ["mform", 20, 0]
opcodes["rlwimi."]  = ["mform", 20, 1]

# mdform                           XO Rc
opcodes["rldicl"] = ["mdform", 30, 0, 0] # Not tested, for 64 bit processor
opcodes["rldicl."]= ["mdform", 30, 0, 1]
opcodes["rldicr"] = ["mdform", 30, 1, 0]  
opcodes["rldicr."]= ["mdform", 30, 1, 1]  

#mdsform                           XO Rc
opcodes["rldcl"] = ["mdsform", 30, 8, 0] # NOT TESTED (64b)
opcodes["rldcl."]= ["mdsform", 30, 8, 1]
opcodes["rldcr"] = ["mdsform", 30, 9, 0] # NOT TESTED (64b)
opcodes["rldcr."] = ["mdsform", 30, 9, 1] # NOT TESTED (64b)

# dsform
#                              OP RA!=RT
opcodes["ld"]     = ["dsform", 0, 0]
opcodes["ldu"]    = ["dsform", 0, 0]
#opcodes["lwa"] = ["dsform", 2] only for 64 bits


REVERSE=1
FXM = 2
# xfxform                            XO FLAG  UNKNOWN BIT
opcodes["mtspr"]  = ["xfxform", 31, 467, 0 , 0]
opcodes["mfspr"]  = ["xfxform", 31, 339, REVERSE, 0]
opcodes["mtcrf"]  = ["xfxform", 31, 144, FXM, 0]
opcodes["mfcr"]   = ["xfxform", 31,  19,  0, 0]


# xoform                       OP  XO  OE  RC
opcodes["add"]    = ["xoform", 31, 266, 0, 0 ]
opcodes["add."]   = ["xoform", 31, 266, 0, 1 ]
opcodes["addo"]   = ["xoform", 31, 266, 1, 0 ]
opcodes["addo."]  = ["xoform", 31, 266, 1, 1 ]
opcodes["subf"]   = ["xoform", 31, 40, 0, 0 ]
opcodes["subf."]  = ["xoform", 31, 40, 0, 1 ]
opcodes["subfo"]  = ["xoform", 31, 40, 1, 0 ]
opcodes["subfo."] = ["xoform", 31, 40, 1, 1 ]
opcodes["addc"]   = ["xoform", 31, 10, 0,0 ]
opcodes["addc."]  = ["xoform", 31, 10, 0,1 ]
opcodes["addco"]  = ["xoform", 31, 10, 1,0 ]
opcodes["addco."] = ["xoform", 31, 10, 1,1 ]
opcodes["subfc"]  = ["xoform", 31, 8, 0,0 ]
opcodes["subfc."] = ["xoform", 31, 8, 0,1 ]
opcodes["subfco"] = ["xoform", 31, 8, 1,0 ]
opcodes["subfco."]= ["xoform", 31, 8, 1,1 ]
opcodes["adde"]   = ["xoform", 31, 138, 0,0 ]
opcodes["adde."]  = ["xoform", 31, 138, 0,1 ]
opcodes["addeo"]  = ["xoform", 31, 138, 1,0 ]
opcodes["addeo."] = ["xoform", 31, 138, 1,1 ]
opcodes["subfe"]  = ["xoform", 31, 136, 0,0 ]
opcodes["subfe."] = ["xoform", 31, 136, 0,1 ]
opcodes["subfeo"] = ["xoform", 31, 136, 1,0 ]
opcodes["subfeo."]= ["xoform", 31, 136, 1,1 ]
opcodes["addme"]  = ["xoform", 31, 234, 0,0 ]
opcodes["addme."] = ["xoform", 31, 234, 0,1 ]
opcodes["addmeo"] = ["xoform", 31, 234, 1,0 ]
opcodes["addmeo."]= ["xoform", 31, 234, 1,1 ]
opcodes["subfme"] = ["xoform", 31, 232, 0,0 ]
opcodes["subfme."]= ["xoform", 31, 232, 0,1 ]
opcodes["subfmeo"]= ["xoform", 31, 232, 1,0 ]
opcodes["subfmeo."]= ["xoform", 31, 232, 1,1 ]
opcodes["addze"]  = ["xoform", 31, 202, 0,0 ]
opcodes["addze."] = ["xoform", 31, 202, 0,1 ]
opcodes["addzeo"] = ["xoform", 31, 202, 1,0 ]
opcodes["addzeo."]= ["xoform", 31, 202, 1,1 ]
opcodes["subfze"] = ["xoform", 31, 200, 0,0 ]
opcodes["subfze."]= ["xoform", 31, 200, 0,1 ]
opcodes["subfzeo"]= ["xoform", 31, 200, 1,0 ]
opcodes["subfzeo."]= ["xoform", 31, 200, 1,1 ]
opcodes["neg"]    = ["xoform", 31, 104, 0,0 ]
opcodes["neg."]   = ["xoform", 31, 104, 0,1 ]
opcodes["nego"]   = ["xoform", 31, 104, 1,0 ]
opcodes["nego."]  = ["xoform", 31, 104, 1,1 ]
opcodes["mulld"]  = ["xoform", 31, 233, 0,0 ]
opcodes["mulld."] = ["xoform", 31, 233, 0,1 ]
opcodes["mulldo"] = ["xoform", 31, 233, 1,0 ]
opcodes["mulldo."]= ["xoform", 31, 233, 1,1 ]
opcodes["mullw"]  = ["xoform", 31, 235, 0,0 ]
opcodes["mullw."] = ["xoform", 31, 235, 0,1 ]
opcodes["mullwo"] = ["xoform", 31, 235, 1,0 ]
opcodes["mullwo."]= ["xoform", 31, 235, 1,1 ]
opcodes["mullhd"] = ["xoform", 31, 73, 0,0 ]
opcodes["mullhd."]= ["xoform", 31, 73, 0,1 ]
opcodes["mullhdu"]= ["xoform", 31, 9, 0,0 ]
opcodes["mullhdu."]= ["xoform", 31, 9, 0,1 ]
opcodes["mullhw"] = ["xoform", 31, 75, 0,0 ]
opcodes["mullhw."]= ["xoform", 31, 75, 0,1 ]
opcodes["mullhwu"]= ["xoform", 31, 11, 0,0 ]
opcodes["mullhwu."]= ["xoform", 31, 11, 0,1 ]
opcodes["divd"]   = ["xoform", 31, 489, 0,0 ]
opcodes["divd."]  = ["xoform", 31, 489, 0,1 ]
opcodes["divdo"]  = ["xoform", 31, 489, 1,0 ]
opcodes["divdo."] = ["xoform", 31, 489, 1,1 ]
opcodes["divw"]   = ["xoform", 31, 491, 0,0 ]
opcodes["divw."]  = ["xoform", 31, 491, 0,1 ]
opcodes["divwo"]  = ["xoform", 31, 491, 1,0 ]
opcodes["divwo."] = ["xoform", 31, 491, 1,1 ]

#wrong, but whatever
opcodes["andi"]= ["xoform", 31,491,1,1]

#scform
opcodes["sc"]     = ["scform", 17]
opcodes["svca"]   = ["samealias", "sc"] # POWER mnemonic

# branch alias                        BO   BI?
opcodes["bt"] = ["branchalias", "bc", 0xc,  0]
opcodes["bt-"] = ["branchalias", "bc", 0xF, 0]
opcodes["bt+"] = ["branchalias", "bc",0xE , 0]
opcodes["bf"] = ["branchalias", "bc", 0x4,0]
opcodes["bf-"] = ["branchalias", "bc",0x7,0]
opcodes["bf+"] = ["branchalias", "bc",0x6,0]
opcodes["bdnz"] = ["branchalias", "bc",0x11, 1]  # kludge (to be changed, when we support prediction, it should be 0x10)
opcodes["bdnz-"] = ["branchalias", "bc",0x19, 1]
opcodes["bdnz+"] = ["branchalias", "bc",0x18, 1]
opcodes["bdnzt"] = ["branchalias", "bc",0x8, 0]
opcodes["bdzzf"] = ["branchalias", "bc",0x0,0]
opcodes["bdz"] = ["branchalias", "bc",0x12, 1]
opcodes["bdz-"] = ["branchalias", "bc",0x1B,1]
opcodes["bdz+"] = ["branchalias", "bc",0x1A,1]
opcodes["bdzt"] = ["branchalias", "bc",0xA,0]
opcodes["bdzf"] = ["branchalias", "bc",0x2,0]

opcodes["bta"] = ["branchalias", "bca", 0xc,  0]
opcodes["bta-"] = ["branchalias", "bca", 0xF, 0]
opcodes["bta+"] = ["branchalias", "bca",0xE , 0]
opcodes["bfa"] = ["branchalias", "bca", 0x4,0]
opcodes["bfa-"] = ["branchalias", "bca",0x7,0]
opcodes["bfa+"] = ["branchalias", "bca",0x6,0]
opcodes["bdnza"] = ["branchalias", "bca",0x10, 1]
opcodes["bdnza-"] = ["branchalias", "bca",0x19, 1]
opcodes["bdnza+"] = ["branchalias", "bca",0x18, 1]
opcodes["bdnzta"] = ["branchalias", "bca",0x8, 0]
opcodes["bdnzfa"] = ["branchalias", "bca",0x0,0]
opcodes["bdza"] = ["branchalias", "bca",0x12, 1]
opcodes["bdza-"] = ["branchalias", "bca",0x1B,1]
opcodes["bdza+"] = ["branchalias", "bca",0x1A,1]
opcodes["bdzta"] = ["branchalias", "bca",0xA,0]
opcodes["bdzfa"] = ["branchalias", "bca",0x2,0]

opcodes["blr"] = ["branchalias", "bclr", 0x14,  1]
opcodes["btlr"] = ["branchalias", "bclr", 0xc,  0]
opcodes["btlr-"] = ["branchalias", "bclr", 0xF, 0]
opcodes["btlr+"] = ["branchalias", "bclr",0xE , 0]
opcodes["bflr"] = ["branchalias", "bclr", 0x4,0]
opcodes["bflr-"] = ["branchalias", "bclr",0x7,0]
opcodes["bflr+"] = ["branchalias", "bclr",0x6,0]
opcodes["bdnzlr"] = ["branchalias", "bclr",0x10, 1]
opcodes["bdnzlr-"] = ["branchalias", "bclr",0x19, 1]
opcodes["bdnzlr+"] = ["branchalias", "bclr",0x18, 1]
opcodes["bdnztlr"] = ["branchalias", "bclr",0x8, 0]
opcodes["bdzflr"] = ["branchalias", "bclr",0x0,0]
opcodes["bdzlr"] = ["branchalias", "bclr",0x12, 1]
opcodes["bdzlr-"] = ["branchalias", "bclr",0x1B,1]
opcodes["bdzlr+"] = ["branchalias", "bclr",0x1A,1]
opcodes["bdztlr"] = ["branchalias", "bclr",0xA,0]
opcodes["bdzflr"] = ["branchalias", "bclr",0x2,0]

opcodes["btl"] = ["branchalias", "bcl", 0xc,  0]
opcodes["btl-"] = ["branchalias", "bcl", 0xF, 0]
opcodes["btl+"] = ["branchalias", "bcl",0xE , 0]
opcodes["bfl"] = ["branchalias", "bcl", 0x4,0]
opcodes["bfl-"] = ["branchalias", "bcl",0x7,0]
opcodes["bfl+"] = ["branchalias", "bcl",0x6,0]
opcodes["bdnzl"] = ["branchalias", "bcl",0x10, 1]
opcodes["bdnzl-"] = ["branchalias", "bcl",0x19, 1]
opcodes["bdnzl+"] = ["branchalias", "bcl",0x18, 1]
opcodes["bdnztl"] = ["branchalias", "bcl",0x8, 0]
opcodes["bdzzfl"] = ["branchalias", "bcl",0x0,0]
opcodes["bdzl"] = ["branchalias", "bcl",0x12, 1]
opcodes["bdzl-"] = ["branchalias", "bcl",0x1B,1]
opcodes["bdzl+"] = ["branchalias", "bcl",0x1A,1]
opcodes["bdztl"] = ["branchalias", "bcl",0xA,0]
opcodes["bdzfl"] = ["branchalias", "bcl",0x2,0]

opcodes["btla"] = ["branchalias", "bcla", 0xc,  0]
opcodes["btla-"] = ["branchalias", "bcla", 0xF, 0]
opcodes["btla+"] = ["branchalias", "bcla",0xE , 0]
opcodes["bfla"] = ["branchalias", "bcla", 0x4,0]
opcodes["bfla-"] = ["branchalias", "bcla",0x7,0]
opcodes["bfla+"] = ["branchalias", "bcla",0x6,0]
opcodes["bdnzla"] = ["branchalias", "bcla",0x10, 1]
opcodes["bdnzla-"] = ["branchalias", "bcla",0x19, 1]
opcodes["bdnzla+"] = ["branchalias", "bcla",0x18, 1]
opcodes["bdnztla"] = ["branchalias", "bcla",0x8, 0]
opcodes["bdzzfla"] = ["branchalias", "bcla",0x0,0]
opcodes["bdzla"] = ["branchalias", "bcla",0x12, 1]
opcodes["bdzla-"] = ["branchalias", "bcla",0x1B,1]
opcodes["bdzla+"] = ["branchalias", "bcla",0x1A,1]
opcodes["bdztla"] = ["branchalias", "bcla",0xA,0]
opcodes["bdzfla"] = ["branchalias", "bcla",0x2,0]

opcodes["blrl"] = ["branchalias", "bclrl", 0x14, 0]
opcodes["btlrl"] = ["branchalias", "bclrl", 0xc,  0]
opcodes["btlrl-"] = ["branchalias", "bclrl", 0xF, 0]
opcodes["btlrl+"] = ["branchalias", "bclrl",0xE , 0]
opcodes["bflrl"] = ["branchalias", "bclrl", 0x4,0]
opcodes["bflrl-"] = ["branchalias", "bclrl",0x7,0]
opcodes["bflrl+"] = ["branchalias", "bclrl",0x6,0]
opcodes["bdnzlrl"] = ["branchalias", "bclrl",0x10, 1]
opcodes["bdnzlrl-"] = ["branchalias", "bclrl",0x19, 1]
opcodes["bdnzlrl+"] = ["branchalias", "bclrl",0x18, 1]
opcodes["bdnztlrl"] = ["branchalias", "bclrl",0x8, 0]
opcodes["bdzflrl"] = ["branchalias", "bclrl",0x0,0]
opcodes["bdzlrl"] = ["branchalias", "bclrl",0x12, 1]
opcodes["bdzlrl-"] = ["branchalias", "bclrl",0x1B,1]
opcodes["bdzlrl+"] = ["branchalias", "bclrl",0x1A,1]
opcodes["bdztlrl"] = ["branchalias", "bclrl",0xA,0]
opcodes["bdzflrl"] = ["branchalias", "bclrl",0x2,0]


opcodes["bctr"] = ["argsalias", "bcctr", [0x14,0]]
opcodes["bctrl"] = ["argsalias", "bcctrl", [0x14, 0]]
opcodes["lwsync"] = ["argsalias", "sync", [1]]
opcodes["ptesync"] = ["argsalias", "sync", [2]]

opcodes["btctr"] = ["branchalias", "bcctr", 0xc,  0]
opcodes["btctr-"] = ["branchalias", "bcctr", 0xF, 0]
opcodes["btctr+"] = ["branchalias", "bcctr",0xE , 0]
opcodes["bfctr"] = ["branchalias", "bcctr", 0x4,0]
opcodes["bfctr-"] = ["branchalias", "bcctr",0x7,0]
opcodes["bfctr+"] = ["branchalias", "bcctr",0x6,0]

opcodes["btctrl"] = ["branchalias", "bcctrl", 0xc,  0]
opcodes["btctrl-"] = ["branchalias", "bcctrl", 0xF, 0]
opcodes["btctrl+"] = ["branchalias", "bcctrl",0xE , 0]
opcodes["bfctrl"] = ["branchalias", "bcctrl", 0x4,0]
opcodes["bfctrl-"] = ["branchalias", "bcctrl",0x7,0]
opcodes["bfctrl+"] = ["branchalias", "bcctrl",0x6,0]
lt =0
gt  =1
eq = 2
so = 3
un = 3
opcodes["blt"] = ["branchalias", "bc", 12, 3, lt]
opcodes["blt+"] = ["branchalias", "bc", 12, 3, lt]
opcodes["ble"] = ["branchalias", "bc",  4, 3, gt]
opcodes["beq"] = ["branchalias", "bc", 12, 3, eq]
opcodes["bge"] = ["branchalias", "bc",  4, 3, lt]
opcodes["bgt"] = ["branchalias", "bc", 12, 3, gt]
opcodes["bnl"] = ["branchalias", "bc",  4, 3, lt]
opcodes["bne"] = ["branchalias", "bc",  4, 3, eq]
opcodes["bng"] = ["branchalias", "bc",  4, 3, gt]
opcodes["bso"] = ["branchalias", "bc", 12, 3, so]
opcodes["bns"] = ["branchalias", "bc" , 4, 3, so]
opcodes["bun"] = ["branchalias", "bc", 12, 3, un]
opcodes["bnu"] = ["branchalias", "bc",  4, 3, un]

opcodes["bltl"] = ["branchalias", "bcl", 12, 3, lt]
opcodes["blel"] = ["branchalias", "bcl",  4, 3, gt]
opcodes["beql"] = ["branchalias", "bcl", 12, 3, eq]
opcodes["bgel"] = ["branchalias", "bcl",  4, 3, lt]
opcodes["bgtl"] = ["branchalias", "bcl", 12, 3, gt]
opcodes["bnll"] = ["branchalias", "bcl",  4, 3, lt]
opcodes["bnel"] = ["branchalias", "bcl",  4, 3, eq]
opcodes["bngl"] = ["branchalias", "bcl",  4, 3, gt]
opcodes["bsol"] = ["branchalias", "bcl", 12, 3, so]
opcodes["bnsl"] = ["branchalias", "bcl" , 4, 3, so]
opcodes["bunl"] = ["branchalias", "bcl", 12, 3, un]
opcodes["bnul"] = ["branchalias", "bcl",  4, 3, un]


opcodes["crset"] = ["multhreealias", "creqv"]
opcodes["crclr"] = ["multhreealias", "crxor"]

opcodes["crmove"] = ["lasttwoalias", "crxor"]
opcodes["crnot"] = ["lasttwoalias", "crnot"]
opcodes["mr"] = ["lasttwoalias", "or"]
opcodes["not"] = ["lasttwoalias", "nor"]

opcodes["subi"]  = ["subalias", "addi"]
opcodes["subis"] = ["subalias", "addis"]
opcodes["subic"] = ["subalias", "addic"]
opcodes["subic."]= ["subalias", "addic."]

opcodes["sub"]  = ["samealias", "subf"]
opcodes["subc"] = ["samealias", "subfc"]
opcodes["sub."] = ["samealias", "subf."]

# SPR, rS
opcodes["mtxer"] = ["branchalias", "mtspr", 1, 0]
opcodes["mtlr"] = ["branchalias",  "mtspr", 8, 0]
opcodes["mtctr"] = ["branchalias", "mtspr", 9, 0]

# rs, SPR
opcodes["mfxer"] = ["cmpalias", "mfspr", 1, 0]
opcodes["mflr"] = ["cmpalias",  "mfspr", 8, 0]
opcodes["mfctr"] = ["cmpalias", "mfspr", 9, 0]

opcodes["li"] = ["cmpalias", "addi", 0]
opcodes["lis"] = ["cmpalias", "addis", 0]
opcodes["trap"] = ["trapo"]
opcodes["set"] = ["set"]

opcodes["cmpw"] = ["cmpalias3", "cmp", 0]
opcodes["cmpwi"] = ["cmpalias23", "cmpi", 0]
opcodes["cmplwi"] = ["cmpalias23", "cmpi", 0]
opcodes["cmpd"] = ["cmpalias2", "cmp", 0, 1] # to check
opcodes["cmpdi"] = ["cmpalias2", "cmpi", 0, 1] # to check
opcodes["cmplw"] = ["cmpalias3", "cmpl", 0]
opcodes["cmpldi"] = ["cmpalias", "cmpli", 1]
opcodes["cmpld"] = ["cmpalias", "cmpl", 1]

branch_opcodes=[]
compound_opcodes=[]
compound_opcodes+=["set"]


class error(Exception):
        def __init__(self, args=None):
            self.args = args                                                                                                                        
        def __str__(self):
            return `self.args`

class ppcassembler:
    def __init__(self):
        self.branch_opcodes = branch_opcodes
        self.compound_opcodes = compound_opcodes
        self.value=[]
        self.unused=b("0"*7) #seven bytes of zeros 
        self.functions = {}
        for f in dir(self):
            if f[:3] == "op_":
                self.functions[f[3:]] = getattr(self, f)
    
    def doinstruction(self,opcode,opcodeargslist):
        #uncomment for debug
        #print "opcode=%s"%opcode
        #tmp=""
        
        if opcode[-1] == '_':
            opcode = opcode[:-1] + '-'
        opcodeindex = opcode
        if opcode not in opcodes:
            # we have a predicted branch opcode
            # we resolve the unpredicted opcode and will parse prediction
            # later in branchalias() and use a kludge in the b-form()
            if opcode[0] == 'b' and opcode[-1] in "+-":
                opcodeindex = opcode[:-1]
            else:
                raise AssertionError, "Error, tried to assemble a ppc opcode \"%s\" but we do not support it!" % opcode
        
        #print opcode, opcodes[opcodeindex], opcodeargslist
        functionname=opcodes[opcodeindex][0]
        tmp = self.functions[functionname](opcode,opcodeargslist)
        return tmp
    
    def op_trapo(self, opcode, opcodeargslist):
        return big_order(0x7fe00008)
    
    def op_argsalias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], op[2])
        
    # alias_opcode bf, ra, si == opcode bf, op[2], ra, si 
    def op_cmpalias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        #print "cmpalias:", opcode, op, opcodeargslist, [opcodeargslist[0],op[2]]+ opcodeargslist[1:]
        return self.doinstruction(op[1], [opcodeargslist[0],op[2]]+ opcodeargslist[1:])

    # alias_opcode ra, si|rb == opcode 0, 1, ra, si|rb
    def op_cmpalias2(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], op[2:] + opcodeargslist)
    
    # alias_opcode ra, rb == opcode 0, 0, ra, rb
    def op_cmpalias3(self, opcode, opcodeargslist):
        return self.op_cmpalias(opcode, [0] + opcodeargslist)
    
    # some weird cmpalias, cmpwi only?
    def op_cmpalias23(self, opcode, opcodeargslist):
        #print "cmpalias23:", opcode, opcodes[opcode], opcodeargslist
        if len(opcodeargslist) == 2:
            return self.op_cmpalias3(opcode, opcodeargslist)
        else:
            return self.op_cmpalias(opcode, opcodeargslist)
    
    # same alias
    # alias_opcode == opcode
    def op_samealias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], opcodeargslist)
    
    # the only argument is repeated three times
    # alias_opcode rX     == opcode rX,rX,rX    
    def op_multhreealias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], opcodeargslist*3)

    # the last two arguments are repetead
    # alias_opcode rX, ry == opcode rX, ry, ry
    def op_lasttwoalias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], [opcodeargslist[0]] + [opcodeargslist[1]] *2 )

    # the last value is negative
    # alias opcode rx, ry, value == opcode rx, ry, -value
    def op_subalias(self, opcode, opcodeargslist):
        op=opcodes[opcode]
        return self.doinstruction(op[1], [opcodeargslist[0],opcodeargslist[1],\
                                          opcodeargslist[2] * -1])
        
    def op_branchalias(self, opcode, opcodeargslist):
        # opcodes["bt"] = ["branchalias", "bc", 0xc, 0]

        if opcode[-1] in "+-":
            if opcode[-1] == '+':
                at = b("11")
            else:
                at = b("10")
            opcode = opcode[:-1]
        else:
            at = b("00")
        op=opcodes[opcode]
        if op[3] == 1:
            return self.doinstruction(op[1], [op[2], 0]+opcodeargslist)
        elif op[3] == 3:
            return self.doinstruction(op[1], [op[2], op[4]] + opcodeargslist + [at]) # kludged!
        else:
            return self.doinstruction(op[1], [op[2]]+opcodeargslist)
            
    # user supplies: target (relative or absolute addr depends of AA)    
    def op_iform(self, opcode, opcodeargslist):
        assert opcodeargslist != [], "branching into the unknown!!!"
        op = opcodes[opcode]
        if opcode == 'b' and opcodeargslist[0] == 4: # branch next a.k.a. nop ?
            return self.doinstruction("nop", [])     # nop is easier to debug, better to avoid that instr
        if len(op) ==4 and len(opcodeargslist)== 1 :
            # CHECK THIS OUT
            offset = dInt(opcodeargslist[0]) & 0x3FFFFFF # only 24 bits
            iform, opcd, aa, lk = op
            return big_order( opcd << 26 | offset | aa<<1 | lk )
        
        return None

    # user supplies: LEV
    def op_scform(self, opcode, opcodeargslist):
        opcd = opcodes[opcode][1]
        if len(opcodeargslist) == 0:
            lev = 0
        elif len(opcodeargslist) > 1:
            warnmsg("sc got more than 1 unique argument (%d args: %s)" % (len(opcodeargslist), opcodeargslist))
        else:
            lev = opcodeargslist[0]
        if lev > 1:
            warnmsg("sc LEV > 1 (%s) is reserved" % lev)
        
        return big_order(opcd << 26 | lev << 4 | 0x2)
    
    # user supplies:  
    #      BO: condition of branch
    #      BI: Condition register
    #      target: relative or absolute addr depends of AA 
    def op_bform(self, opcode, opcodeargslist):
        """
        0       6     11    16         30  31
        [ opcd ][ bo ][ bi ][   bd   ][aa][lk]
        """
        op = opcodes[opcode]
        if len(op) ==4:
            if len(opcodeargslist) >= 3 :
                iform, opcd, aa, lk = op
                at = 0
                if len(opcodeargslist) > 3: # KLUDGE for at
                    at = opcodeargslist[3]
                #print "at =", binary_string_char(at)
                bo, bi, target = opcodeargslist[:3]
                return big_order( opcd << 26 | ((dInt(bo)|at) & 0x1F) << 21\
                                  | ( dInt(bi) &0x1F) <<16 |\
                                  (dInt(target)&0xffff) | aa<<1 | lk )                
                #print binary_string_int32(str2int32(r)), uint32fmt(str2int32(r))
            else:
                return None
            
        return None
    
    # user supplies:
    #      BO: condition of branch (prediction also)
    #      BI: Condition register
    #      BH: hint about the use
    def op_xlform(self, opcode, opcodeargslist):
        op= opcodes[opcode]
        # ugly ... por favor :)
        method1=(16, 528, 258, 19)
        method2=(257, 449, 225, 193, 33, 289, 129, 417)
        method3=(150, )

        if len(op) == 4:   
            if op[2] in method1:
                iform, opcd, xo, lk = op
                bo, bi, bh = (0, 0, 0)
                if len(opcodeargslist)== 3:
                    bo, bi, bh = opcodeargslist
                elif len(opcodeargslist)== 2:
                    bo, bi = opcodeargslist
                else:
                    bo, = opcodeargslist
                
                return big_order(opcd << 26 | dInt(bo) << 21 | dInt(bi) <<16\
                                 | dInt(bh) <<11 | xo <<1| lk)
            # XXX reached?
            else:
                raise AssertionError, "INCOMPLETE CODE"
                
        elif len(op) == 3:
            if op[2] in method2:
                iform, opcd, xo = op
                bt, ba, bb = opcodeargslist
                bt = getcr(bt)
                ba = getcr(ba)
                bb = getcr(bb)
                return big_order(opcd << 26 | bt <<21 | ba << 16 | bb << 11 | xo <<1)
            elif op[2] in method3: # isnt it better to expand opcodeargslist=[] to [0,0,0] and use method2?
                iform, opcd, xo = op
                return big_order(opcd << 26 | xo <<1)
        else:
            return None

    def op_dform(self, opcode, opcodeargslist):        
        """
        0       6     11    16      31
        [ opcd ][ rt ][ ra ][ d|si|ui ]
        """
        op = opcodes[opcode]

        #print "op_dform:%s" % opcode, len(opcodeargslist), opcodeargslist
        if len(opcodeargslist) == 2:
            opcd = op[1]
            try:
                d  = opcodeargslist[1][0] & 0xffff
            except:
                print opcode, op, opcodeargslist
                import sys
                sys.exit(0)
            rt = getreg(opcodeargslist[0])
            ra = getreg(opcodeargslist[1][1])
            if op[2]==1:
                if rt == ra or ra == 0:
                    raise error, "Instruction format is invalid (rt != ra)"
            elif op[2] == 3:
                if ra ==0:
                    raise error, "Instruction format is invalid (rt != ra)"
            return big_order(opcd << 26 | rt << 21 | ra << 16 | d)

        elif len(opcodeargslist) == 3: # ra, rs, ui
            opcd = op[1]
            try:
                ra = getreg(opcodeargslist[1])
            except error:
                ra = opcodeargslist[1]
            rt = getreg(opcodeargslist[0])
            si = dInt(opcodeargslist[2])
            if si > 0 and si & ~0xFFFF: # ui and not si
                warnmsg("16-bit integer overflow(0x%X > 0xFFFF): %s %s" % (si & ~0xffff, opcode, opcodeargslist))
            si &= 0xFFFF
            #print "rt:%s ra:%s si:%s" % (rt, ra, si)
            if opcode in ["ori", "oris", "andi.", "andis.", "xori", "xoris"]: # XXX KLUDGE XXX ?
                # switching rt <==> ra
                t = rt
                rt = ra
                ra = t
            return big_order(opcd << 26 | rt << 21 | ra << 16 | si)

        elif len(opcodeargslist) == 4:
            if op[2] == 4 and opcodeargslist[3] < 0:
                    raise error, "Immediate is an usigned integer (ui == %d)" %opcodeargslist[3]                 
            opcd = op[1]
            bf = getcr(opcodeargslist[0])
            l  = opcodeargslist[1]
            ra = getreg(opcodeargslist[2])
            si = dInt(opcodeargslist[3]) & 0xFFFF
            
            return big_order(opcd << 26 | bf << 23 | l << 21 | ra <<16 | si)
            
        return None
    
    def op_xform(self, opcode, opcodeargslist):
        # this function seems incomplete
        
        op = opcodes[opcode]
        if opcode in ["sync", "eieio"]: # hmmm, is that a kludge?
            if len(opcodeargslist) == 0:
                opcodeargslist = [0]
            opcodeargslist = [0] + opcodeargslist + [0, 0]
            assert opcodeargslist[1] <= 2, "invalid L field value"
        
        if opcode in ["dcbf", "dcbfl", "dcbst", "dcbtst", "icbi"]: # FIXME opcode[:2] == "dc" ?
            if len(opcodeargslist) == 2:
                opcodeargslist += [0]
            if len(opcodeargslist) != 4:
                opcodeargslist = [0, opcodeargslist[2]] + opcodeargslist[0:2]
        
        if len(opcodeargslist) <= 3:
            opcd = op[1]
            xo   = op[2]
            rc = 0
            ra = getreg(opcodeargslist[1])
            rt = getreg(opcodeargslist[0])
            rb = 0
            
            if op[3] & EX_TO_RC:
                rc = op[4] & 0x1
            if op[3] & RT_IS_RA:
                ra = getreg(opcodeargslist[0])
                rt = getreg(opcodeargslist[1])
            else:
                ra = getreg(opcodeargslist[1])
                rt = getreg(opcodeargslist[0])
            if len(opcodeargslist) ==3:
                if xo in NB:
                    rb = opcodeargslist[2] & 0x1F
                else:
                    rb = getreg(opcodeargslist[2])
                
            
            if op[3] & RA_EQ_RT:
                if ra == rt or ra == 0:
                    raise error, "Instruction format is invalid (rt != ra or ra==0)"
            elif op[3] & RA_EQ_ZERO:
                if ra == 0:
                    raise error, "Instruction format is invalid (ra==0)"
             
            return big_order(opcd << 26 | rt << 21 | ra << 16 | rb << 11 | xo<<1 | rc) 

        elif len(opcodeargslist) == 4:
            opcd = op[1]
            xo   = op[2]
            bf = getcr(opcodeargslist[0])
            l  = dInt(opcodeargslist[1])
            ra = getreg(opcodeargslist[2])
            rb = getreg(opcodeargslist[3])

            return big_order(opcd << 26 | bf << 23 | l<< 21| ra << 16 | rb << 11 | xo << 1) 
        return None
            
    def op_dsform(self, opcode, opcodeargslist):
        op = opcodes[opcode]

        if len(opcodeargslist) == 3:
            opcd = op[1]
            xo   = op[2] & 0x3
            rt = getreg(opcodeargslist[0])
            d  = opcodeargslist[1][0] & 0x3fff # 14 bits            
            ra = getreg(opcodeargslist[1][1])
            if op[2]:
                if ra == rt or ra == 0:
                    raise error, "Instruction format is invalid (rt != ra or ra==0)"                
            return big_order(opcd << 26 | rt << 21 | ra << 16 | rb << 2 | xo) 
        return None
    
    def op_xoform(self, opcode, opcodeargslist):
        op = opcodes[opcode]
        if len(opcodeargslist) == 3 or len(opcodeargslist) == 2:
            form, opcd, xo, oe, rc = op
            rt = getreg(opcodeargslist[0])
            ra = getreg(opcodeargslist[1])
            rb = 0
            if len(opcodeargslist) == 3:
                rb = getreg(opcodeargslist[2])
                
            xo = xo & 0x1FF
            
            return big_order(opcd << 26 | rt << 21 | ra << 16 | rb << 11| oe <<10|\
                             xo <<1 | rc) 
        return None
    
    def op_mdform(self, opcode, opcodeargslist):
        op = opcodes[opcode]
        if len(opcodeargslist) == 4:
            rs = getreg(opcodeargslist[1])
            ra = getreg(opcodeargslist[0])
            sh = opcodeargslist[2]
            mb = opcodeargslist[3]
            form, opcd, xo, rc = op
            return big_order(opcd << 26 | rs << 21 | ra <<16 | sh << 11 | mb << 5|\
                             xo << 2 | sh << 1 | rc )

    def op_mform(self, opcode, opcodeargslist):
        op = opcodes[opcode]
        if len(opcodeargslist) == 5:
            rs = getreg(opcodeargslist[1])
            ra = getreg(opcodeargslist[0])
            sh = opcodeargslist[2]
            mb = opcodeargslist[3]
            me = opcodeargslist[4]
            form, opcd, rc = op
            return big_order(opcd << 26 | rs << 21 | ra <<16 | sh << 11 | mb << 6|\
                             me << 1| rc )

    def op_mdsform(self, opcode, opcodeargslist):
        op = opcodes[opcode]
        if len(opcodeargslist) == 4:
            rs = getreg(opcodeargslist[1])
            ra = getreg(opcodeargslist[0])
            rb = getreg(opcodeargslist[2])
            mb = opcodeargslist[3]
            form, opcd, xo, rc = op
            return big_order(opcd << 26 | rs << 21 | ra <<16 | rb << 11 | mb << 5|\
                             xo << 1| rc )
        return None
    
    def op_xfxform(self, opcode, opcodeargslist):
        op = opcodes[opcode]
        
        if len(opcodeargslist) == 2:
            form, opcd, xo, reverse , u_bit = op
            if reverse == FXM:
                rs  = getreg(opcodeargslist[1])
                fxm = opcodeargslist[0]                
                return big_order(opcd << 26 | rs << 21 | u_bit <<20 | fxm <<12 | xo <<1)
                
            else:
                if reverse == REVERSE:
                    rs  = getreg(opcodeargslist[0])
                    spr =opcodeargslist[1]
                else:
                    rs  = getreg(opcodeargslist[1])
                    spr =opcodeargslist[0]
    
                spr1 = spr & 0x1f 
                spr2 = (spr>>5) & 0x1F
                                
                return big_order(opcd << 26 | rs << 21 | spr1 <<16| spr2 <<11 | xo <<1)
        elif len(opcodeargslist) == 1:
            form, opcd, xo, reverse , u_bit = op
            rt  = getreg(opcodeargslist[0])
            
            return big_order(opcd << 26 | rt << 21 | u_bit <<20 | xo <<1)
            
        return None
    
    def op_set(self,opcode,opcodeargslist):
        
        value=dInt(opcodeargslist[1])
        if value == 0:
            tmp = self.doinstruction("xor", [opcodeargslist[0], opcodeargslist[0], opcodeargslist[0]])
        elif value & 0xffff==0:
            tmp = self.doinstruction("lis", [opcodeargslist[0], hi(value)])
        elif value <= 0x7FFF and value >= -0x7FFF:
            tmp = self.doinstruction("li", opcodeargslist)
        else:
            tmp=self.doinstruction("lis",[opcodeargslist[0], hi(value)])
            tmp+=self.doinstruction("ori",[opcodeargslist[0],opcodeargslist[0], lo(value) ])
        return tmp
    
            
    def test(self):
        _testinstr = [
            ["bl", ["0x8"]],
            ["sc", []],
            ["bdnz", ["-4"]],
            ["bc", ["12", 0, 8]],
            ["bclrl", ["12", "4", "0"]],
            ["crand", ["lt", "gt", "eq"]],
            ["ble", ["0x8"]],
            ["ble-", ["0x8"]],
            ["sc", [1]],
            ["ble", ["0x8"], "\x40\x81\x00\x08"],
            ["ble-", ["0x8"], "\x40\xc1\x00\x08"],
            ["ble+", ["0x8"], "\x40\xe1\x00\x08"],
            ["cmpwi", ["cr7", "r3", 0]],
            ["cmpwi", [0, "r3", "0"]],
            ["cmpdi", ["r3", 69]],
            ["ori", ["r24", "r5", 20303]],
            ["ori", ["r5", "r24", 20303]],
            ["oris", ["r24", "r5", 20303]],
            ["oris", ["r5", "r24", 20303]],
            ["andi.", ["r24", "r5", 20303]],
            ["andi.", ["r5", "r24", 20303]],
            ["andis.", ["r24", "r5", 20303], "\x74\xb8\x4f\x4f"],
            ["andis.", ["r5", "r24", 20303]],
            ["xori", ["r24", "r5", 20303]],
            ["xori", ["r5", "r24", 20303], "\x6b\x05\x4f\x4f"],
            ["xoris", ["r24", "r5", 20303]],
            ["xoris", ["r5", "r24", 20303]],
            ["ori", ["r0", "r0", 0]],
            ["nop", []],
            ["andi.", ["r5", "r24", 0x12345]],
            ["isync", [], "\x4c\x00\x01\x2c"],
            ["sync", [], "\x7c\x00\x04\xac"],
            ["sync", [1], "\x7c\x20\x04\xac"],
            ["sync", [2], "\x7c\x40\x04\xac"],
            ["lwsync", [], "\x7c\x20\x04\xac"],
            ["ptesync", [], "\x7c\x40\x04\xac"],
            ["eieio", [], "\x7c\x00\x06\xac"],
            ["bdza-", [-12]],
            ["crorc", ["cr6", "cr6", "cr6"]],
            ["crorc", [4, 4, 4]],
            ["sc", [1]],
            ["svca", [0]],
            ["dcbf", ["r2", "r1", 1]],
            ["dcbf", ["r2", "r1"], int2str32(0x7c0208ac)],
            ["addc", ["%r3", "%r4", "%r9"]],
            ["blrl", [], "\x4e\x80\x00\x21"],
            ["dcbtst", ["r0", "r4"], "\x7c\x00\x21\xec"],
            ["dcbst", ["r6", "r7"], "\x7c\x06\x38\x6c"],
            ["icbi", ["r6", "r7"], "\x7c\x06\x3f\xac"],
        ]

        print "testing..."
        for entry in _testinstr:
            tmp = self.doinstruction(entry[0], entry[1])
            print "%s = %s = %s" %(uint32fmt(str2int32(tmp)), hexprint(tmp), entry[0:2])
            if len(entry) > 2:
                assert tmp == entry[2], "%s %s should return %s and returned %s" % \
                    (entry[0], str(entry[1])[1:-1], uint32fmt(str2int32(entry[2])), uint32fmt(str2int32(tmp)))
        print "done testing"

if __name__=="__main__":
    c=ppcassembler()
    c.test()
