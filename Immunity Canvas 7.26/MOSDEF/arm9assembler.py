#! /usr/bin/env python

"""
ARMv9 32bit LE assembler (no thumb)

Right now everything we need to implement the MOSDEF-C IL and ARM shellcodes
is there.

TODO:

- coprocessor instructions are completely ignored for now
- full #expression support (right now we just support #0x1234... and #1234)
- 64 bit multiply
- optimize yacc grammar for register list matching
- revisit the lexx tokenizing and optimize the post/pre indexing handling
- implement the full ARMv9 instruction set
- implement MSR/MRS
- implement BX

"""

from mosdefutils import *

NOTES = """

register aliases:
    
    r0  : a1
    r1  : a2
    r2  : a3
    r3  : a4
    r4  : v1
    r5  : v2
    r6  : v3
    r7  : v4
    r8  : v5
    r9  : v6
    r10 : sb
    r11 : sl
    r12 : fp
    r13 : sp
    r14 : lr
    r15 : pc (bits 31:2, 1:0 undefined)

asm syntax:
    
    <op>{cond}{flags} Rd, Rn, Operand2

    op          : 3 letter mnemonic
    cond        : two letter conditional (optional)
    flags       : additional flags (optional)
    Rd          : destination register
    Rn          : first source register
    Operand2    : flexible 2nd operand

    Operand2 is the result of Rm and the barrel shifter, the
    barrelshifter can rotate and shift values. Rn is used
    directly.

"""

registers = {
        'r0':'0000', 'a1':'0000',
        'r1':'0001', 'a2':'0001', 
        'r2':'0010', 'a3':'0010',
        'r3':'0011', 'a4':'0011',
        'r4':'0100', 'v1':'0100',
        'r5':'0101', 'v2':'0101',
        'r6':'0110', 'v3':'0110',
        'r7':'0111', 'v4':'0111',
        'r8':'1000', 'v5':'1000',
        'r9':'1001', 'v6':'1001',
        'r10':'1010', 'sb':'1010',
        'r11':'1011', 'sl':'1011',
        'r12':'1100', 'fp':'1100',
        'r13':'1101', 'sp':'1101',
        'r14':'1110', 'lr':'1110',
        'r15':'1111', 'pc':'1111'
        }

# conditional predicates operate on CPSR (N|Z|C|V) bit 31 to 28 
cond = {}
cond['eq'] = '0000' # Z
cond['ne'] = '0001' # !Z
cond['cs'] = '0010' # C
cond['hs'] = '0010' # C
cond['cc'] = '0011' # !C
cond['lo'] = '0011' # !C
cond['mi'] = '0100' # N
cond['pl'] = '0101' # !N
cond['vs'] = '0110' # V
cond['vc'] = '0111' # !V
cond['hi'] = '1000' # C & !Z
cond['ls'] = '1001' # !C | Z
cond['ge'] = '1010' # N == V
cond['lt'] = '1011' # N != V
cond['gt'] = '1100' # !Z && (N == V)
cond['le'] = '1101' # Z || (N != V)
cond['al'] = '1110' # always (default)
cond['nv'] = '1111' # never

# load and store sizes for single data transfer
# for now we only support the b variant, will add the
# opcodes added in armv4 later (sb, h, sh) XXX
data_size = ['b', 'sb', 'h', 'sh']

# load and store multiple, P, U bits True/False
m_mode = {}
m_mode['ia'] = (False, True) # increment after
m_mode['ib'] = (True, True) # increment before
m_mode['da'] = (False, False) # decrement after
m_mode['db'] = (True, False) # decrement before

ldm_stack_alias = {}
ldm_stack_alias['fd'] = m_mode['ia'] # full descending ldm
ldm_stack_alias['ed'] = m_mode['ib'] # empty descending ldm
ldm_stack_alias['fa'] = m_mode['da'] # full ascending ldm
ldm_stack_alias['ea'] = m_mode['db'] # full descending ldm

stm_stack_alias = {}
stm_stack_alias['fd'] = m_mode['db']
stm_stack_alias['ed'] = m_mode['da']
stm_stack_alias['fa'] = m_mode['ib']
stm_stack_alias['ea'] = m_mode['ia']

# opcodes is used by riscscan.py and has to be a dict
all_opcodes         = []
movement            = ['mov', 'mvn']
imm16_movement      = ['movw', 'movt']
arithmetic          = ['add', 'adc', 'sub', 'sbc', 'rsb', 'rsc']
logical             = ['and', 'eor', 'orr', 'bic']
compare             = ['cmp', 'cmn', 'tst', 'teq']
branching           = ['b', 'bl']
register_branching  = ['bx'] # so riscscan doesn't operate on us as a branching opcode that needs dest resolving
multiply_32bit      = ['mul', 'mla']
multiply_64bit      = ['umull', 'umlal', 'smull', 'smlal']
load_store          = ['ldr', 'str', 'ldrh', 'strh', 'ldrb', 'strb']
load_store_multiple = ['ldm', 'stm']
swap                = ['swp']
svc_swi             = ['svc', 'swi']
pseudo              = ['adr']

branch_opcodes = []

# support _ALL_ of the opcodes! \o/
for c in cond:
    for o in pseudo:
        if o not in all_opcodes:
            all_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))
    for o in swap:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'b')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%sb' % (o, c))
    for o in movement:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'s')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%ss' % (o, c))
    for o in imm16_movement:
        if o not in all_opcodes:
            all_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))
    for o in arithmetic:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'s')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%ss' % (o, c))
    for o in logical:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'s')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%ss' % (o, c))
    for o in compare:
        if o not in all_opcodes:
            all_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))
    for o in register_branching:
        if o not in all_opcodes:
            all_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))
    for o in branching:
        if o not in all_opcodes:
            all_opcodes.append(o)
            branch_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))
        branch_opcodes.append('%s%s' % (o, c))
    for o in multiply_32bit:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'s')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%ss' % (o, c))
    for o in multiply_64bit:
        if o not in all_opcodes:
            all_opcodes.append(o)
            all_opcodes.append(o+'s')
        all_opcodes.append('%s%s' % (o, c))
        all_opcodes.append('%s%ss' % (o, c))
    for o in load_store:
        if o not in all_opcodes:
            all_opcodes.append(o)
            for s in data_size:
                all_opcodes.append('%s%s' % (o, s))
        all_opcodes.append('%s%s' % (o, c))
        for s in data_size:
            all_opcodes.append('%s%s%s' % (o, c, s))
    for o in load_store_multiple:
        if o not in all_opcodes:
            all_opcodes.append(o)
            for m in m_mode:
                all_opcodes.append('%s%s' % (o, m))
            for sa in ldm_stack_alias:
                all_opcodes.append('%s%s' % (o, sa))
        all_opcodes.append('%s%s' % (o, c))
        for m in m_mode:
            all_opcodes.append('%s%s%s' % (o, c, m))
        for sa in ldm_stack_alias:
            all_opcodes.append('%s%s%s' % (o, c, sa))
    for o in svc_swi:
        if o not in all_opcodes:
            all_opcodes.append(o)
        all_opcodes.append('%s%s' % (o, c))

# populate the opcodes dict, we don't really use it for this assembler, but we inherit the logic
opcodes = {}
for opcode in all_opcodes:
    opcodes[opcode] = []

# barrel shift modifiers for Operand2 XXX
barrel_shift = {}
barrel_shift['lsl'] = '00' # logical shift left
barrel_shift['lsr'] = '01' # logical shift right
barrel_shift['asr'] = '10' # arithmetic shift right
barrel_shift['ror'] = '11' # rotate right
barrel_shift['rrx'] = '00' # rotate right extended XXX
 
import struct


class arm9assembler:
    def __init__(self):
        self.debug            = False
        self.registers        = registers
        self.barrel_shift     = barrel_shift
        self.value            = []
        self.branch_opcodes   = branch_opcodes
        self.compound_opcodes = []
        
        # build opcode handler map
        self.op_handlers = {}
        for op_handler in dir(self):
            if op_handler[:3] == 'op_':
                self.op_handlers[op_handler[3:]] = getattr(self, op_handler)

    def doinstruction(self, opcode, args):
        encoded = None
       
        if self.debug == True:
            print 'opcode: %s' % opcode
            print 'args: %s' % repr(args)

        # the additional load/store set
        if len(opcode) >= 4 and opcode[:4] in self.op_handlers:
            encoded = self.op_handlers[opcode[:4]](opcode, args)
        
        # most opther opcodes
        elif len(opcode) >= 3 and opcode[:3] in self.op_handlers:
            encoded = self.op_handlers[opcode[:3]](opcode, args)
        
        # special case the register branching
        elif len(opcode) >= 2 and opcode[:2] == 'bx': 
            encoded = self.op_handlers[opcode[:2]](opcode, args)
        
        # handle offset based branches
        elif opcode in self.branch_opcodes:
            if (not len(opcode) % 2) == True: # bl<c> will always be aligned on 2
                encoded = self.op_handlers[opcode[:2]](opcode, args)
            else: # b<c> will not be aligned on 2
                encoded = self.op_handlers['b'](opcode, args)
        
        # fall through for the 64bit multipliers
        elif len(opcode) >= 5:
            if opcode[:5] in ['umull', 'umlall', 'smull', 'smlal']:
                encoded = self.op_handlers[opcode[:5]](opcode, args)
        else:
            print 'XXX unhandled opcode: %s' % opcode
        
        if self.debug == True and encoded != None:
            dump = struct.unpack('<L', encoded)[0]
            bits = self.bs(dump)
            print 'result: %x (bits: %s)' % (dump, (32 - len(bits)) * '0' + bits)

        return encoded

    def get_cond(self, opcode):
        if len(opcode) >= 2 and opcode[:2] in cond:
            return cond[opcode[:2]], opcode[2:]
        else:
            return cond['al'], opcode

    def bs(self, s):
        return str(s) if s <= 1 else self.bs(s>>1) + str(s&1)                
       
    # data processing, these are all opcodes of the form: 
    # <op>{cond}{S} Rd,<Operand2> (MOV, MVN)
    # <op>{cond}{S} Rn,<Operand2> (CMP,CMN,TEQ,TST)
    # <op>{cond}{S} Rd,Rn,<Operand2> (AND,EOR,SUB,RSB,ADD,ADC,SBC,RSC,ORR,BIC 
    def data_processing(self, opcode, args, Rd_form=False, Rn_form=False, s_bit_implied=False):
        data_ops = {
                'and' : '0000',
                'eor' : '0001',
                'sub' : '0010',
                'rsb' : '0011',
                'add' : '0100',
                'adc' : '0101',
                'sbc' : '0110',
                'rsc' : '0111', 
                'tst' : '1000', # S bit implied
                'teq' : '1001', # S bit implied
                'cmp' : '1010', # S bit implied
                'cmn' : '1011', # S bit implied
                'orr' : '1100',
                'mov' : '1101',
                'bic' : '1110',
                'mvn' : '1111',
                # movt/movw introduced in armv7, handled seperately
                }
        opcode_bits = data_ops[opcode[:3]]
        opcode = opcode[3:]
        if Rd_form == True:
            Rd = args[0]
        else:
            Rd = 'r0' # default Rd to r0 when unused
        if Rn_form == True:
            if Rd_form == True:
                Rn = args[1]
                Operand2 = args[2:]
            else:
                Rn = args[0]
                Operand2 = args[1:]
        else:
            Rn = 'r0' # default Rn to r0 when unused
            Operand2 = args[1:]
        condition, opcode = self.get_cond(opcode)
        bits = condition
        bits += '00'
        if Operand2[0] in self.registers:
            bits += '0'
        else:
            bits += '1' # I bit, 0 means operand2 is a reg, 1 means it's an immediate
        bits += opcode_bits
        if opcode in ['s'] or s_bit_implied == True: # S bit, set CPSR
            bits += '1'
        else:
            bits += '0'
        bits += self.registers[Rn] # Rn
        bits += self.registers[Rd] # Rd
        #print 'XXX OPERAND2 %s' % repr(Operand2)
        if Operand2[0] in self.registers:
            if len(Operand2) > 1 and Operand2[1].split(' ')[0] in self.barrel_shift:
                barrel_op, barrel_const = Operand2[1].split(' ')
                #print 'XXX DO A BARREL ROLL: %s %s' % (barrel_op, barrel_const)
                if barrel_const in self.registers:
                    # register mode
                    #print 'XXX REGISTER MODE'
                    shift = self.registers[barrel_const]
                    shift += '0'
                    shift += self.barrel_shift[barrel_op]
                    shift += '1'
                else:
                    # value mode
                    #print 'XXX VALUE MODE'
                    val = self.bs(int(barrel_const[1:]))
                    if len(val) > 5:
                        print 'XXX: shift amount too large!'
                    val = (5 - len(val)) * '0' + val
                    shift = val
                    shift += self.barrel_shift[barrel_op]
                    shift += '0'
            else:
                shift = '00000000'
            Rm = self.registers[Operand2[0]]
            bits += shift
            bits += Rm
        else:
            # immediate XXX
            if '0x' in Operand2[0]:
                imm8 = int(Operand2[0][1:], 16)
            else:
                imm8 = int(Operand2[0][1:])
            shift = 0
            while len(self.bs(imm8>>shift)) > 8:
                if shift > 30:
                    print 'XXX VALUE TOO LARGE TOO FIT AND UNSHIFTABLE TO FIX'
                    break
                shift += 2
            #print 'XXX: shift %d' % shift
            imm8 = self.bs(imm8>>(shift))
            imm8 = (8 - len(imm8)) * '0' + imm8
            if shift:
                shift = self.bs((32-shift)/2) # XXX
            else:
                shift = self.bs(shift)
            shift = (4 - len(shift)) * '0' + shift
            bits += shift
            bits += imm8
        return struct.pack('<L', int(bits, 2))
    
    def op_mov(self, opcode, args):
        "move"
        return self.data_processing(opcode, args, Rd_form=True)

    def op_mvn(self, opcode, args):
        "move negated"
        return self.data_processing(opcode, args, Rd_form=True)

    # movt and movw have a much simpler encoding that does not warrant going through the data_processing function
    def op_movt(self, opcode, args):
        opcode = opcode[4:]
        opcode_bits = '00110100'
        Rd = args[0]
        Operand2 = args[1:]
        if '0x' in Operand2[0]:
            imm16 = int(Operand2[0][1:], 16)
        else:
            imm16 = int(Operand2[0][1:])
        imm16 = self.bs(imm16)
        imm16 = (16 - len(imm16)) * '0' + imm16
        condition, opcode = self.get_cond(opcode)
        bits  = condition
        bits += opcode_bits
        bits += imm16[:4]
        bits += self.registers[Rd]
        bits += imm16[4:]
        return struct.pack('<L', int(bits, 2))

    def op_movw(self, opcode, args):
        opcode = opcode[4:]
        opcode_bits = '00110000'
        Rd = args[0]
        Operand2 = args[1:]
        if '0x' in Operand2[0]:
            imm16 = int(Operand2[0][1:], 16)
        else:
            imm16 = int(Operand2[0][1:])
        imm16 = self.bs(imm16)
        imm16 = (16 - len(imm16)) * '0' + imm16
        condition, opcode = self.get_cond(opcode)
        bits  = condition
        bits += opcode_bits
        bits += imm16[:4]
        bits += self.registers[Rd]
        bits += imm16[4:]
        return struct.pack('<L', int(bits, 2))

    # arithmetic, <op>{cond}{S} Rd,Rn,<Operand2>
    def op_add(self, opcode, args):
        "add"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_adc(self, opcode, args):
        "add with carry"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_sub(self, opcode, args):
        "subtract"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_sbc(self, opcode, args):
        "subtract with carry"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_rsb(self, opcode, args):
        "reverse subtract"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_rsc(self, opcode, args):
        "reverse subtract with carry"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    # logical, <op>{cond}{S} Rd,Rn,<Operand2>
    def op_and(self, opcode, args):
        "logical AND"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_eor(self, opcode, args):
        "exclusive OR"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_orr(self, opcode, args):
        "logical OR"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    def op_bic(self, opcode, args):
        "bitwise clear"
        return self.data_processing(opcode, args, Rd_form=True, Rn_form=True)

    # compares <op>{cond} Rn,<Operand2>
    def op_cmp(self, opcode, args):
        "compare"
        return self.data_processing(opcode, args, Rn_form=True, s_bit_implied=True)

    def op_cmn(self, opcode, args):
        "compare negative"
        return self.data_processing(opcode, args, Rn_form=True, s_bit_implied=True)

    def op_tst(self, opcode, args):
        "bitwise test"
        return self.data_processing(opcode, args, Rn_form=True, s_bit_implied=True)

    def op_teq(self, opcode, args):
        "test equivelance"
        return self.data_processing(opcode, args, Rn_form=True, s_bit_implied=True)

    # XXX: maybe better way to do this? (chris)
    # Ideally i need the relative addresses of labels exposed to the assembler
    # (via suitable syntax, something similar is done in the other assemblers)
    # This seems like a fast way to do this if we can live with the 16bit limit
    def op_adr(self, opcode, args):
        """
        ADR pseudo instruction (translates into a MOVW).
        Loads the relative address (that should be within 16bit range) of
        given label into passed register.
        """

        if args[1] > 0xFFFF:
            raise Exception('Relative address 0x%x > 16bits' % args[1])

        opcode      = opcode[3:]
        opcode_bits = '00110000'
        Rd          = args[0]
        Operand2    = args[1]
        imm16       = self.bs(Operand2)
        
        imm16 = (16 - len(imm16)) * '0' + imm16
        condition, opcode = self.get_cond(opcode)
        bits  = condition
        bits += opcode_bits
        bits += imm16[:4]
        bits += self.registers[Rd]
        bits += imm16[4:]
        return struct.pack('<L', int(bits, 2))

    # fetch/decode/execute cycle offsetting comes into play
    # the offset that comes in as an arg is relative to the
    # beginning of the branch opcode and not the end so + 4
    # the FDE adjustment
    def branching(self, opcode, args, l_bit=False):
        "branching"
        condition, opcode = self.get_cond(opcode)
        bits = condition
        bit_dict = { True : '1', False : '0' }
        bits += '101'
        bits += bit_dict[l_bit]
        offset = args[1]
        offset -= 8 # adjust for FDE
        if offset % 4:
            print 'XXX: branch offset not aligned on 4!?'
        offset = offset/4
        offset = self.bs((offset&0x00ffffff))
        if len(offset) > 24:
            print 'XXX: offset too big for branch!'
        offset = (24 - len(offset)) * '0' + offset
        bits += offset
        return struct.pack('<L', int(bits, 2))

    # branching <op>{cond} <address>
    def op_b(self, opcode, args):
        "branch"
        return self.branching(opcode[1:], args)

    def op_bl(self, opcode, args):
        "branch with link"
        return self.branching(opcode[2:], args, l_bit=True)

    def op_bx(self, opcode, args):
        "branch link return eq. to mov pc, r14"
        condition, opcode = self.get_cond(opcode[2:])
        bits = condition
        bits += '00010010'
        bits += '1111'
        bits += '1111'
        bits += '1111'
        bits += '0001'
        Rm = args[0]
        bits += self.registers[Rm]
        return struct.pack('<L', int(bits, 2))

    # multipliers
    def multiply32(self, opcode, args, accumulate_bit=False):
        condition, opcode = self.get_cond(opcode)
        #print 'XXX OPCODE: %s' % opcode
        bits = condition
        bits += '000000'
        if accumulate_bit == True:
            bits += '1'
        else:
            bits += '0'
        if opcode in ['s']:
            bits += '1'
        else:
            bits += '0'
        Rd = self.registers[args[0]]
        Rm = self.registers[args[1]]
        Rs = self.registers[args[2]]
        if len(args) == 4:
            Rn = self.registers[args[3]]
        else:
            Rn = self.registers['r0'] # default to r0 when unused
        bits += Rd
        bits += Rn # unused
        bits += Rs
        bits += '1001'
        bits += Rm
        return struct.pack('<L', int(bits, 2))

    # multiply (32 bit result) <op>{cond}{S} Rd, Rm, Rs {,Rn}
    def op_mul(self, opcode, args):
        "multiply"
        return self.multiply32(opcode[3:], args)

    def op_mla(self, opcode, args):
        "multiply with accumulate"
        return self.multiply32(opcode[3:], args, accumulate_bit=True)
        
    # multiply (64 bit result) <op>{cond}{S} RdLo, RdHi, Rm, Rs
    
    # XXX: IMPLEMENT THESE
    def op_umull(self, opcode, args):
        "unsigned multiply long"
        print repr(opcode)
        print repr(args)

    def op_umlal(self, opcode, args):
        "unsigned multiply with accumulate long"
        print repr(opcode)
        print repr(args)

    def op_smull(self, opcode, args):
        "signed multiply long"
        print repr(opcode)
        print repr(args)

    def op_smlal(self, opcode, args):
        "signed multiply with accumulate long"
        print repr(opcode)
        print repr(args)

    def single_data_transfer(self, opcode, args, h_opcode = False, b_bit = False, l_bit = False):
        condition, opcode = self.get_cond(opcode)
        bits = condition
        if h_opcode == False:
            bits += '01'
        else:
            bits += '00'
        i_bit = False
        p_bit = True
        u_bit = True # default to +
        w_bit = False
        Offset = '000000000000'
        Rd = args[0]
        Address = args[1]
        Rn = 'r0' # default
        Rm = 'r0' # default
        # Address can come in 2 forms, a pre/post-indexed form or from a label expression
        if '[' in Address:
            Address = Address.split(' ')
            Address.reverse()
            Address.pop() # LBRACKET
            Rn = Address.pop() # Rn
            if Address[-1] == ']':
                Address.pop()
                if len(Address):
                    p_bit = False
                else:
                    # deal with the simplest h_opcode address case
                    if h_opcode == True:
                        # ldrh r4,[r4] is considered an immediate syntax as well, LDRH<c> <Rt>,[<Rn>{,#+/-<imm8>}]
                        Offset = '0000' + '1011' + '0000'
                        # i_bit remains false, b_bit and l_bit are true already
            if len(Address):
                Address.pop() # comma
                if '#' in Address[-1]:
                    #print 'XXX DEAL WITH HASHICONST'
                    val = Address.pop()
                    if val[1] in ['+', '-']:
                        if val[1] == '-':
                            #print 'XXX set u bit to false'
                            u_bit = False
                        val = val[2:]
                    else:
                        val = val[1:]
                    val = self.bs(int(val))
                    if h_opcode == False:
                        if len(val) > 12:
                            print 'XXX: immediate offset too large!'
                        Offset = (12 - len(val)) * '0' + val
                    else:
                        if len(val) > 8:
                            print 'XXX: immediate offset too large!'
                        val = (8 - len(val)) * '0' + val
                        Offset = val[:4] + '1011' + val[4:]
                else:
                    if Address[-1] in ['+', '-']:
                        #print 'XXX DEAL WITH PLUS SUBTRACT'
                        direction = Address.pop()
                        if direction == '-':
                            u_bit = False
                    Rm = Address.pop()
                    i_bit = True
                    if len(Address) and Address[-1] == ',':
                        #print 'XXX DEAL WITH BARRELSHIFT'
                        Address.pop()
                        barrel_op = Address.pop()
                        barrel_const = Address.pop()
                        #print 'XXX: %s %s' % (barrel_op, barrel_const)
                        # value mode ... register mode is not available in this shift
                        val = self.bs(int(barrel_const[1:]))
                        if len(val) > 5:
                            print 'XXX: shift amount too large!'
                        val = (5 - len(val)) * '0' + val
                        Offset = val
                        Offset += self.barrel_shift[barrel_op]
                        Offset += '0'
                        Offset += self.registers[Rm]
                    else: # no barrelshift
                        Offset = '0' * 8 + self.registers[Rm]
                    if h_opcode == True:
                        Offset = '0000' + '1011' + self.registers[Rm]
                        i_bit = False
                        b_bit = False # THESE TWO ARE OFF FOR REGISTER MODE
                    if len(Address) and Address[-1] == ']':
                        Address.pop()
                    if len(Address) and Address[-1] == '!':
                        #print 'XXX DEAL WITH BANG'
                        w_bit = True
        else:
            # XXX: THIS STILL HAS TO BE DONE IF WE NEED IT!
            print 'XXX DEAL WITH LABEL EXPRESSION'
        
        bit_dict = { True : '1', False : '0' }
        bits += bit_dict[i_bit]
        bits += bit_dict[p_bit]
        bits += bit_dict[u_bit]
        bits += bit_dict[b_bit]
        bits += bit_dict[w_bit]
        bits += bit_dict[l_bit]
        bits += self.registers[Rn]
        bits += self.registers[Rd]
        bits += Offset
        return struct.pack('<L', int(bits, 2))

    # data transfer <op>{cond}{size} Rd, <Address>
    def op_ldrh(self, opcode, args):
        return self.single_data_transfer(opcode[4:], args, h_opcode = True, b_bit = True, l_bit = True)

    def op_ldrb(self, opcode, args):
        "load register byte"
        return self.single_data_transfer(opcode[4:], args, b_bit = True, l_bit = True)

    def op_ldr(self, opcode, args):
        "load"
        return self.single_data_transfer(opcode[3:], args, l_bit = True)

    def op_strh(self, opcode, args):
        return self.single_data_transfer(opcode[4:], args, h_opcode = True, b_bit = True)
    
    def op_strb(self, opcode, args):
        "store register byte"
        return self.single_data_transfer(opcode[4:], args, b_bit = True)

    def op_str(self, opcode, args):
        "store"
        return self.single_data_transfer(opcode[3:], args)

    def block_data_transfer(self, opcode, args, l_bit = False):
        #print 'XXX BLOCK DATA TRANSFER'
        p_bit = False
        u_bit = False
        s_bit = False
        w_bit = False
        condition, opcode = self.get_cond(opcode)
        if opcode in m_mode:
            p_bit, u_bit = m_mode[opcode]
        elif opcode not in ldm_stack_alias and opcode not in stm_stack_alias:
            print 'XXX: weird opcode in block data transfer!'
        if l_bit == True:
            if opcode in ldm_stack_alias:
                p_bit, u_bit = ldm_stack_alias[opcode]
        else:
            if opcode in stm_stack_alias:
                p_bit, u_bit = stm_stack_alias[opcode]
        Rn = args[0]
        Rlist = args[1:]
        if '!' in Rn:
            w_bit = True
            Rn = Rn[:-1]
        if '^' in Rlist:
            s_bit = True
            Rlist.pop()
        bits  = condition
        bits += '100'
        bit_dict = { True : '1', False : '0' }
        bits += bit_dict[p_bit]
        bits += bit_dict[u_bit]
        bits += bit_dict[s_bit]
        bits += bit_dict[w_bit]
        bits += bit_dict[l_bit]
        bits += self.registers[Rn]
        rbits = 0
        for reg in Rlist:
            if reg != '^':
                if self.debug: print 'XXX: handling Rlist reg %s' % reg
                rbits |= (1<<int(reg[1:]))
        rbits = self.bs(rbits)
        rbits = (16 - len(rbits)) * '0' + rbits
        bits += rbits
        return struct.pack('<L', int(bits, 2))

    # multiple register data transfer <op>{cond}<mode> Rn{!}, <reglist>
    # see self.m_mode for <mode>
    # see self.stm/ldm_stack_alias for stack aliases
    def op_ldm(self, opcode, args):
        "load multiple"
        return self.block_data_transfer(opcode[3:], args, l_bit = True)

    def op_stm(self, opcode, args):
        "store multiple"
        return self.block_data_transfer(opcode[3:], args, l_bit = False)

    # swp <op>{cond}{B} Rd,Rm,[Rn]
    def op_swp(self, opcode, args):
        "swap"
        print 'XXX: swap'
        print repr(args)
        condition, opcode = self.get_cond(opcode[3:])
        if opcode == 'b':
            b_bit = True
        else:
            b_bit = False
        Rd = args[0]
        Rm = args[1]
        Rn = args[2].split(' ')[1]
        bits = condition
        bits += '00010'
        bit_dict = { True : '1', False : '0' }
        bits += bit_dict[b_bit]
        bits += '00'
        bits += self.registers[Rn]
        bits += self.registers[Rd]
        bits += '0000'
        bits += '1001'
        bits += self.registers[Rm]
        return struct.pack('<L', int(bits, 2))

    def software_interrupt(self, opcode, args):
        "swi/svc"
        condition, opcode = self.get_cond(opcode)
        bits = condition
        bits += '1111'
        # comment field is ignored by processor
        if '#' in args[0]:
            if '0x' in args[0]:
                comment = self.bs(int(args[0][1:], 16))
            else:
                comment = self.bs(int(args[0][1:], 10))
            if len(comment) > 24:
                print 'XXX: comment field too large for swi'
            comment = (24 - len(comment)) * '0' + comment
        else:
            comment = 24 * '0'
        bits += comment
        return struct.pack('<L', int(bits, 2))

    # interrupts/supervisor calls <op> <Immediate>
    def op_svc(self, opcode, args):
        "supervisor call"
        return self.software_interrupt(opcode[3:], args)

    def op_swi(self, opcode, args):
        "software interrupt"
        return self.software_interrupt(opcode[3:], args)
