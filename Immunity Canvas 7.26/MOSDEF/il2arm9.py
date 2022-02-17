import urllib

from mosdefutils import uint32fmt
from makeexe import align_pow2

"""
ARM EABI

Register  Alt. Name   Usage
r0        a1          First function argument
                      Integer function result
                      Scratch register
r1 	  a2 	      Second function argument
                      Scratch register
r2 	  a3          Third function argument
                      Scratch register
r3 	  a4          Fourth function argument
                      Scratch register
r4 	  v1          Register variable
r5 	  v2          Register variable
r6        v3          Register variable
r7        v4 	      Register variable
r8        v5          Register variable
r9     	  v6          Register variable
          rfp 	      Real frame pointer
r10 	  sl 	      Stack limit
r11       fp          Argument pointer
r12 	  ip 	      Temporary workspace
                      Scrath register
r13 	  sp 	      Stack pointer
r14 	  lr 	      Link register
                      Workspace
r15 	  pc 	      Program counter
"""

#
# MOSDEF-ARM conventions
#
# "EABI function calls" refers to calls to non-MOSDEF functions
# e.g. present in mapped libraries and resolved with MOSDEF resolver
#
# r0-r3   : unused internally, free for EABI function calls and syscalls
# r4      : accumulator, mosdef functions return values here
# r5      : secondary/compare
# r6      : value storage/shift register
# r7      : index
# r8      : used to save/restore the stack pointer during EABI function calls
# r9      : frame pointer
# r10     : code base ptr
# r11     : argument pointer, points to first argument on the stack for MOSDEF functions calls
# r12     : temporary register only used for getstackspace otherwise free
#
# r13-r15 : stack pointer, link register, program counter (no changes)
#
# As is evident, every register is used, no resources are wasted!
#
# One thing to note is that MOSDEF functions expect return values to be in r4,
# but in some platforms (e.g. Linux) syscalls return values in r0. When this happens,
# and in every other case where that might happen (e.g. boundary between EABI function and MOSDEF)
# you have to make sure that mov r4, r0 happens. This is taken into account (for these 2 cases)
# and implemented in MOSDEF but keep in mind when code is extended/updated for other stuff
# later on.
#

COMMENT_CHAR = '!' # Used to mark comments in the generated output

def split_word(number):
    """
    Split number into 16bit (high, low) values and return them.
    """
    low   = number & 0xFFFF
    high  = (number >> 16) & 0xFFFF

    return (high, low)

# The following is currently unused as we assume ARMv6T2 or later
# which supports MOVW, MOVT but maybe it will be useful in the future
def load_reg(reg, value):
    """
    Return assembly that loads REG with 32bit VALUE, a byte at a time.
    This is needed for older ARM architectures (armv6 and earlier).
    """
    out = ""
    bytes = ((value & 0xff000000) >> 24,
             (value & 0xff0000) >> 16,
             (value & 0xff00) >> 8,
             value & 0xff)

    out += "eor\t %s, %s, %s\n" % (reg, reg, reg)
    for b in bytes[:3]:
        out += "orr\t %s, %s, #%s\n" % (reg, reg, b)
        out += "mov\t %s, %s, lsl #8\n" % (reg, reg)

    out += "orr\t %s, %s, #%s\n" % (reg, reg, bytes[3])

    return out


# This is the main Il-to-asm function
def generate(data):
    labelcount   = 0
    out          = ''

    def LABEL(name, definition=True):
        """
        Return a unique LABEL name (if definition = True append : to it).
        Caller is responsible to properly update labelcount in order to control
        uniqueness.
        """
        return "%s_%d%s\n" % (name, labelcount, ':' if definition else '')
        
    try:
        for line in data.split('\n'):
            if line == '': continue
            words = line.split(' ')
            
            if words[0] == 'GETPC':
                out += "mov\t r10, r15\n"
                # r15 AKA pc always points 2 instructions ahead
                out += "sub\t r10, r10, #8\n"

            elif words[0] == 'rem':
                out += COMMENT_CHAR + " %s\n" % (" ".join(words[1:]))
            
            elif words[0] == 'asm':
                out += " ".join(words[1:]) + "\n"

            elif words[0] == 'debug':
                print "[+] debug"
                # No implemented breakpoint instruction (BKPT)?

            elif words[0] == 'call':
                out += COMMENT_CHAR + " calling %s\n" % words[1]
                out += "stmfd\t sp!, {r14, r11}\n"
                out += "add\t r11, r13, #8\n"
                out += "bl\t %s\n" % words[1]
                
            elif words[0] == 'ret':
                stack_fix = int(words[1])
                out += COMMENT_CHAR + " returning (stack_fix: %d)\n" % stack_fix
                out += "mov\t r12, r14\n"
                out += "ldmfd\t sp!, {r14, r11}\n"
                if stack_fix > 0: out += "add\t r13, r13, #%d\n" % stack_fix
                out += "bx\t r12\n"

            elif words[0] == 'callaccum':
                out += COMMENT_CHAR + " call accum (r4)\n"
                out += "stmfd\t sp!, {r14, r11}\n"
                out += "add\t r11, r13, #8\n"
                # PC = address of current instruction + 8
                out += "mov\t r14, r15\n"
                out += "bx\t r4\n"
                out += "ldmfd\t sp!, {r14, r11}\n"

            elif words[0] == 'addconst':
                const = int(words[1])

                if 0 <= const <= 255: # Can use immediate value in instruction
                    out += "add\t r4, r4, #%s\n" % const
                else:
                    # Need to use additional register to hold value
                    if 256 <= const <= 0xFFFF:
                        # Can use movw to load immediate
                        out += "movw\t r7, #%s\n" % const
                    else:
                        # Two's complement negative or unsigned > 16bit
                        high, low = split_word(const)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high

                    # Now we do the addition
                    out += "add\t r4, r4, r7\n"

            elif words[0] == 'subconst':
                const = int(words[1])

                if 0 <= const <= 255:
                    out += "sub\t r4, r4, #%s\n" % const
                else:
                    if 256 <= const <= 0xFFFF:
                        out += "movw\t r7, #%s\n" % const
                    else:
                        high, low = split_word(const)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high

                    out += "sub\t r4, r4, r7\n"
                    
            elif words[0] == 'labeldefine':
                out += "%s:\n" % words[1]

            elif words[0] == 'longvar':
                out += ".long %s\n" % uint32fmt(words[1])

            elif words[0] == 'urlencoded':
                url = urllib.unquote(" ".join(words[1:]))
                l   = len(url) + 2 # 2 null bytes are added from cparse2

                # Number of null bytes to insert for 4 byte alignment
                nulls = align_pow2(l, 4) - l

                # String
                for c in url: out += ".byte 0x%x\n" % ord(c)

                # Padding
                for i in xrange(0, nulls): out += ".byte 0x00\n"


            elif words[0] == 'databytes':
                out += ".byte %s\n" % words[1]

            elif words[0] == 'archalign':
                # Unused, whoever writes the code needs to make sure alignment
                # is right. In practice this should only come up when
                # including arbitrary bytes with .byte since everything else
                # is aligned (and strings auto-aligned and padded)
                pass

            elif words[0] == 'compare':
                out += "cmp\t r4, r5\n"

            elif words[0] == 'setifless':
                out += "movlt\t r4, #1\n"
                out += "movge\t r4, #0\n"

            elif words[0] == 'setifgreater':
                out += "movgt\t r4, #1\n"
                out += "movle\t r4, #0\n"

            elif words[0] == 'setifnotequal':
                out += "movne\t r4, #1\n"
                out += "moveq\t r4, #0\n"
                
            elif words[0] == 'setifequal':
                out += "moveq\t r4, #1\n"
                out += "movne\t r4, #0\n"

            elif words[0] == 'jumpiffalse':
                out += "cmp\t r4, #0\n"
                out += "beq\t %s\n" % words[1]

            elif words[0] == 'jumpiftrue':
                out += "cmp\t r4, #0\n"
                out += "bne\t %s\n" % words[1]

            elif words[0] == 'jump':
                out += "b\t %s\n" % words[1]

            elif words[0] == 'functionprelude':
                # Save non-scratch registers (everything except r0-r3, r4, r11 and r12)
                # and setup r9 as the frame pointer. All subsequent variable references
                # on the stack should go through r9
                out += "stmfd\t sp!, {r5-r10}\n"
                out += "mov\t r9, sp\n"

            elif words[0] == 'functionpostlude':
                # Restore stack pointer from frame pointer and all non-scratch registers
                # saved in prelude
                out += "mov\t sp, r9\n"
                out += "ldmfd\t sp!, {r5-r10}\n"

            elif words[0] == 'getstackspace':
                size = align_pow2(int(words[1]), 4)
                
                if size <= 255:
                    out += "sub\t sp, sp, #%s\n" % size
                else:
                    high, low = split_word(size)
                    out += "movw\t r12, #%s\n" % low
                    out += "movt\t r12, #%s\n" % high
                    out += "sub\t sp, sp, r12\n"

            elif words[0] == 'freestackspace':
                # functionpostlude takes care of this since stack pointer is
                # restored from frame pointer
                pass

            elif words[0] == 'pushaccum':
                out += "stmfd\t sp!, {r4}\n"

            elif words[0] == 'poptosecondary':
                out += "ldmfd\t sp!, {r5}\n"

            elif words[0] == 'addsecondarytoaccum':
                out += "add\t r4, r4, r5\n"

            elif words[0] == 'subtractsecondaryfromaccum':
                out += "sub\t r4, r4, r5\n"

            elif words[0] == "modulussecondaryfromaccum":
                # Assuming there is no modulus instruction, so have to do it manually
                out += COMMENT_CHAR + " modulus secondary from accum start\n"
                out += "stmfd\t sp!, {r0, r1, r2}\n"
                out += "mov\t r1, #0\n"
                out += "rsbs\t r0, r5, r4, lsr #3\n"
                out += "bcc\t " + LABEL('div_3', False)
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "bcc\t " + LABEL('div_8', False)
                out += "mov\t r5, r5, lsl #8\n"
                out += "movt\t r1, #0xFF00\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "bcc\t " + LABEL('div_4', False)
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "bcc\t " + LABEL('div_8', False)
                out += "mov\t r5, r5, lsl #8\n"
                out += "movt\t r1, #0xFFFF\n"
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "movcs\t r5, r5, lsl #8\n"
                out += "movw\t r2, #0xFF00\n"
                out += "orrcs\t r1, r1, r2\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "bcc\t " + LABEL('div_4', False)
                out += "rsbs\t r0, r5, #0\n"
                out += "bcs\t " + LABEL('div_by_zero', False)
                out += LABEL('div_loop')
                out += "movcs\t r5, r5, lsr #8\n"
                out += LABEL('div_8')
                out += "rsbs\t r0, r5, r4, lsr #7\n"
                out += "subcs\t r4, r4, r5, lsl #7\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #6\n"
                out += "subcs\t r4, r4, r5, lsl #6\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #5\n"
                out += "subcs\t r4, r4, r5, lsl #5\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "subcs\t r4, r4, r5, lsl #4\n"
                out += "adc\t r1, r1, r1\n"
                out += LABEL('div_4')
                out += "rsbs\t r0, r5, r4, lsr #3\n"
                out += "subcs\t r4, r4, r5, lsl #3\n"
                out += "adc\t r1, r1, r1\n"
                out += LABEL('div_3')
                out += "rsbs\t r0, r5, r4, lsr #2\n"
                out += "subcs\t r4, r4, r5, lsl #2\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #1\n"
                out += "subcs\t r4, r4, r5, lsl #1\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4\n"
                out += "subcs\t r4, r4, r5\n"
                out += "adcs\t r1, r1, r1\n"
                out += "bcs\t " + LABEL('div_loop', False)
                out += "mov\t r0, r1\n"
                out += LABEL('div_by_zero')
                out += "ldmfd\t sp!, {r0, r1, r2}\n"
                out += COMMENT_CHAR + " modulus secondary from accum end\n"

                labelcount += 1

            elif words[0] == 'dividesecondaryfromaccum':
                # Assuming there is no DIV instruction, so have to do it manually
                out += COMMENT_CHAR + " divide secondary from accum start\n"
                out += "stmfd\t sp!, {r0, r1, r2}\n"
                out += "mov\t r1, #0\n"
                out += "rsbs\t r0, r5, r4, lsr #3\n"
                out += "bcc\t " + LABEL('div_3', False)
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "bcc\t " + LABEL('div_8', False)
                out += "mov\t r5, r5, lsl #8\n"
                out += "movt\t r1, #0xFF00\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "bcc\t " + LABEL('div_4', False)
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "bcc\t " + LABEL('div_8', False)
                out += "mov\t r5, r5, lsl #8\n"
                out += "movt\t r1, #0xFFFF\n"
                out += "rsbs\t r0, r5, r4, lsr #8\n"
                out += "movcs\t r5, r5, lsl #8\n"
                out += "movw\t r2, #0xFF00\n"
                out += "orrcs\t r1, r1, r2\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "bcc\t " + LABEL('div_4', False)
                out += "rsbs\t r0, r5, #0\n"
                out += "bcs\t " + LABEL('div_by_zero', False)
                out += LABEL('div_loop')
                out += "movcs\t r5, r5, lsr #8\n"
                out += LABEL('div_8')
                out += "rsbs\t r0, r5, r4, lsr #7\n"
                out += "subcs\t r4, r4, r5, lsl #7\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #6\n"
                out += "subcs\t r4, r4, r5, lsl #6\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #5\n"
                out += "subcs\t r4, r4, r5, lsl #5\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #4\n"
                out += "subcs\t r4, r4, r5, lsl #4\n"
                out += "adc\t r1, r1, r1\n"
                out += LABEL('div_4')
                out += "rsbs\t r0, r5, r4, lsr #3\n"
                out += "subcs\t r4, r4, r5, lsl #3\n"
                out += "adc\t r1, r1, r1\n"
                out += LABEL('div_3')
                out += "rsbs\t r0, r5, r4, lsr #2\n"
                out += "subcs\t r4, r4, r5, lsl #2\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4, lsr #1\n"
                out += "subcs\t r4, r4, r5, lsl #1\n"
                out += "adc\t r1, r1, r1\n"
                out += "rsbs\t r0, r5, r4\n"
                out += "subcs\t r4, r4, r5\n"
                out += "adcs\t r1, r1, r1\n"
                out += "bcs\t " + LABEL('div_loop', False)
                out += "mov\t r4, r1\n"
                out += LABEL('div_by_zero')
                out += "ldmfd\t sp!, {r0, r1, r2}\n"
                out += COMMENT_CHAR + " divide secondary from accum end\n"

                labelcount += 1

            elif words[0] == 'loadint':
                number = int(words[1])

                if 0 <= number <= 255:
                    out += "mov\t r4, #%s\n" % number
                else:
                    high, low = split_word(number)
                    out += "movw\t r4, #%s\n" % low
                    out += "movt\t r4, #%s\n" % high

            elif words[0] == 'accumulator2memorylocal':
                if words[1][:2] == 'in':
                    argnum = int(words[1][2:]) * 4

                    if argnum > 255:
                        # Need to use a register for indexing
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high

                        if words[2] == "4": 
                            out += "str\t r4, [r11, r7]\n"
                        elif words[2] == "2":
                            out += "strh\t r4, [r11, r7]\n"
                        elif words[2] == "1":
                            out += "strb\t r4, [r11, r7]\n"
                        else:
                            print "ERROR: Unknown store size %d asked for..." % int(words[2])
                    else:
                        if words[2] == "4": 
                            out += "str\t r4, [r11, #%d]\n" % argnum
                        elif words[2] == "2":
                            out += "strh\t r4, [r11, #%d]\n" % argnum
                        elif words[2] == "1":
                            out += "strb\t r4, [r11, #%d]\n" % argnum
                        else:
                            print "ERROR: Unknown store size %d asked for..." % int(words[2])
                else:
                    argnum = int(words[1])
                    if argnum > 255:
                        # Need to use a register for indexing
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high
                        
                        if words[2] == "4":
                            out += "str\t r4, [r9, -r7]\n"
                        elif words[2] == "2":
                            out += "strh\t r4, [r9, -r7]\n"
                        elif words[2] == "1":
                            out += "strb\t r4, [r9, -r7]\n"
                        else:
                            print "ERROR: Unknown store size %d asked for..." % int(words[2])
                    else:
                        if words[2] == "4":
                            out += "str\t r4, [r9, #-%s]\n" % argnum
                        elif words[2] == "2":
                            out += "strh\t r4, [r9, #-%s]\n" % argnum
                        elif words[2] == "1":
                            out += "strb\t r4, [r9, #-%s]\n" % argnum
                        else:
                            print "ERROR: Unknown store size %d asked for..." % int(words[2])
                        
            elif words[0] == 'accumulator2index':
                out += "mov\t r5, r4\n"

            elif words[0] == 'derefwithindex':
                out += "ldr\t r4, [r4, r5]\n"

            elif words[0] == 'multiply':
                number = int(words[1])
                
                if 0 <= number <= 0xFF:
                    out += "mov\t r7, #%s\n" % number
                else:
                    high, low = split_word(number)
                    out += "movw\t r7, #%s\n" % low
                    out += "movt\t r7, #%s\n" % high

                out += "mul\t r4, r4, r7\n"

            elif words[0] == 'storeaccumulator':
                out += "mov\t r6, r4\n"

            elif words[0] == 'storewithindex':
                if words[1] == "4":
                    out += "str\t r6, [r4, r5]\n"
                elif words[1] == "2":
                    out += "strh\t r6, [r4, r5]\n"
                elif words[1] == "1":
                    out += "strb\t r6, [r4, r5]\n"
                else:
                    print 'ERROR: unknown store size %s' % words[1]

            elif words[0] == 'derefaccum':
                if words[1] == "4":
                    out += "ldr\t r4, [r4]\n"
                elif words[1] == "2":
                    out += "ldrh\t r4, [r4]\n"
                elif words[1] == "1":
                    out += "ldrb\t r4, [r4]\n"
                else:
                    print "ERROR: derefaccum with unknown accum length %s" % words[1]

            elif words[0] == 'loadlocal':
                if words[1][:2] == 'in':
                    argnum = int(words[1][2:])*4

                    if argnum > 255:
                        # Need to use a register for indexing
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high

                        if words[2] == "4":
                            out += "ldr\t r4, [r11, r7]\n"
                        elif words[2] == "2":
                            out += "ldrh\t r4, [r11, r7]\n"
                        elif words[2] == "1":
                            out += "ldrb\t r4, [r11, r7]\n"
                        else:
                            print "ERROR: Unknown load size %d asked for..." % int(words[2])
                    else:
                        if words[2] == "4":
                            out += "ldr\t r4, [r11, #%d]\n" % argnum
                        elif words[2] == "2":
                            out += "ldrh\t r4, [r11, #%d]\n" % argnum
                        elif words[2] == "1":
                            out += "ldrb\t r4, [r11, #%d]\n" % argnum
                        else:
                            print "ERROR: Unknown load size %d asked for..." % int(words[2])
                else:
                    argnum = int(words[1])
                    if argnum > 255:
                        # Need to use a register for indexing
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high

                        if words[2] == "4":
                            out += "ldr\t r4, [r9, -r7]\n"
                        elif words[2] == "2":
                            out += "ldrh\t r4, [r9, -r7]\n"
                        elif words[2] == "1":
                            out += "ldrb\t r4, [r9, -r7]\n"
                        else:
                            print "ERROR: Unknown load size %d asked for..." % int(words[2])
                        
                    else:
                        if words[2] == "4":
                            out += "ldr\t r4, [r9, #-%s]\n" % argnum
                        elif words[2] == "2":
                            out += "ldrh\t r4, [r9, #-%s]\n" % argnum
                        elif words[2] == "1":
                            out += "ldrb\t r4, [r9, #-%s]\n" % argnum
                        else:
                            print "ERROR: Unknown load size %d asked for..." % int(words[2])
                        
            elif words[0] == 'loadlocaladdress':
                if words[1][:2] == "in":
                    argnum = int(words[1][2:])*4
                    
                    if argnum > 0xFF:
                        # Need to use an extra register
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high
                        out += "add\t r4, r11, r7\n"
                    else:
                        out += "add\t r4, r11, #%d\n" % argnum
                else:
                    argnum = int(words[1])
                    out += "mov\t r4, r9\n"

                    if argnum > 0xFF:
                        # Need to use an extra register
                        high, low = split_word(argnum)
                        out += "movw\t r7, #%s\n" % low
                        out += "movt\t r7, #%s\n" % high
                        out += "sub\t r4, r4, r7\n"
                    else:
                        out += "sub\t r4, r4, #%s\n" % argnum
                    
            elif words[0] == 'arg':
                out += "stmfd\t sp!, {r4}\n"

            elif words[0] == 'loadglobaladdress':
                # ADR is a pseudo instruction that translates into a MOV
                # Look in arm9assembler.py
                out += "adr\t r4, %s\n" % words[1]
                out += "add\t r4, r4, r10\n"

            elif words[0] == 'loadglobal':
                if words[2] == '4':
                    out += "adr\t r4, %s\n" % words[1]
                    out += "ldr\t r4, [r4, r10]\n"
                elif words[2] == '2':
                    out += "adr\t r4, %s\n" % words[1]
                    out += "ldrh\t r4, [r4, r10]\n"
                elif words[2] == '1':
                    out += "adr\t r4, %s\n" % words[1]
                    out += "ldrb\t r4, [r4, r10]\n"
                else:
                    print 'ERROR: unknown load size %s' % words[2]

            elif words[0] == 'pushshiftreg':
                out += "stmfd\t sp!, {r6}\n"

            elif words[0] == 'poptoshiftreg':
                out += "ldmfd\t sp!, {r6}\n"

            elif words[0] == 'shiftright':
                out += "mov\t r4, r4, lsr r6\n"

            elif words[0] == 'shiftleft':
                out += "mov\t r4, r4, lsl r6\n"

            elif words[0] == 'andaccumwithsecondary':
                out += "and\t r4, r4, r5\n"

            elif words[0] == 'oraccumwithsecondary':
                out += "orr\t r4, r4, r5\n"

            elif words[0] == 'xoraccumwithsecondary':
                out += "eor\t r4, r4, r5\n"

            elif words[0] == 'multaccumwithsecondary':
                out += "mul\t r4, r4, r5\n"

            #
            # Needed for resolver, the following assumes EABI conventions
            # If something else is needed then they should be abstracted out
            # into multiple implementations according to ABI
            #
                
            elif words[0] == 'save_stack':
                # We execute this before an EABI function call
                # Since the stack has to be 8byte aligned, we save the
                # stack pointer into r8 before alignment so that we can
                # restore it later (r8 should be saved and restored by the called
                # function)
                out += "stmfd\t sp!, {r5-r10}\n"
                out += "mov\t r8, r13\n"

            elif words[0] == 'restore_stack':
                # We execute this after an EABI function call
                # First we restore the stack pointer from r8, then
                # restore all registers and copy r0 to r4 (MOSDEF conventions)
                out += "mov\t r13, r8\n"
                out += "mov\t r4, r0\n"
                out += "ldmfd\t sp!, {r5-r10}\n"

                
            elif words[0] == 'alignstack_pre':
                # 8byte aligns the stack pointer as needed by ARM EABI
                # This happens before calling the EABI function
                
                args = int(words[1])
                out += "movw\t r12, #0xfff0\n"
                out += "movt\t r12, #0xffff\n"
                out += "and\t  r13, r12, r13\n"
                
                if args > 4 and (args - 4) % 2:
                    out += "sub\t r13, r13, #4"
                        
            elif words[0] == 'argtoreg':
                # EABI dictates that first 4 function arguments are passed via registers

                # XXX: This does not take into account 64bit arguments as they are a special
                # case and not frequently encountered, if needed implement this here.
                registers = ["r0", "r1", "r2", "r3"]
                idx = int(words[1])

                if idx > 3:
                    # Not enough registers, have to use the stack
                    out += "stmfd\t sp!, {r4}\n"
                else:
                    out += "mov\t %s, r4\n" % registers[idx]

            #
            # End resolver stuff
            #
            
            else:
                print '[X] ERROR IN IL: %s' % words[0]

            lastword = words[0]

    except ZeroDivisionError:
        print out

    # XXX for debugging
    log = open('out.s', 'wb')
    log.write(out)
    log.close()
    # XXX

    return out

if __name__ == '__main__':
    import sys
    
    if len(sys.argv) < 2:
        print 'Usage: %s <file.il>' % sys.argv[0]
        sys.exit(1)
        
    print COMMENT_CHAR + " il2arm9 ASM output:\n" + generate(open(sys.argv[1]).read())
