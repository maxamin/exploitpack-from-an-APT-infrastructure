#! /usr/bin/env python

# intermediate language for X64

from mosdefutils import *
from il2proc import IL2Proc

NOTES = """

X64 summary
===========

References: 

http://x86asm.net/articles/x86-64-tour-of-intel-manuals/
http://msdn.microsoft.com/en-us/library/ms235286(VS.80).aspx

Modes (IA-32e AKA Long-mode):
=============================

Two sub modes of IA-32e mode:

1) Compatibility mode, identical to 32-bit protected mode:

    * Just good ol' X86

2) 64 bit mode:
    
    * 64-bit linear address space

    * General Purpose Registers and SIMD extension registers
      are 64-bits wide
      
    * Introduces REX opcode prefix to access register extensions
        - REX prefix allows for overriding default operand size
        - e.g. many existing 32bit instructions can be promoted
          to 64 bit variant using REX prefix
    * GPRs support operations on byte, word, dword, qword (quad)
      integers
      
    * Stack pointer (RSP) is 64 bits
        - Size is not controlled by SS register
        - Can not override pointer size with prefix
        - NOTE: size is _fixed_ to 64 bits
        
    * Control registers extend to 64 bits
        - New control registers: CR8/TPR (Task Priority Register)
        
    * Debug registers extend to 64 bits
    
    * Descriptor Tables
        - GDTR/IDTR extend to hold 64 bit base addresses
        - LDTR/TR extend to hold 64 bit base addresses
        
Segmentation in 64-bit mode:
============================

No segmentation (effectively) in 64-bit mode, flat linear address space.
CS/DS/ES/SS all set to 0. No segmented or real address modes available.

Default sizes in 64-bit mode:
=============================

Default address size is 64 bits. Default operand size is 32 bits. You
can change default using prefixes.

Default operand size is 32 bits with exceptions for instructions that 
implicitly reference RIP and RSP:
      
    * Default stack width is 64 bits
        - Instructions that reference RSP have default operand size of 64 bits
        - NOTE: this means you can _NOT_ PUSH EAX in 64-bit mode only
          PUSH RAX
        
    * Near branches operate on RIP register, so default operand
      size for them is 64-bit as well

Progam Counter (instruction pointer) in 64-bit mode:
====================================================

RIP register:

    * Holds 64 bit offset of next instruction

    * Supports RIP-relative addressing (e.g. lea rax,[rip+10h])
        - NOTE: Allows for more convenient get_pc_loc stubs
        
Address Calculations in 64-bit mode:
====================================

1) Displacements and Immediates are not extended to 64 bits

    * Limited to 32 bits and sign extended for effective address calculations
    
    * Exceptions:
        
        - MOV: MOV RAX, [8000000000000000h] works
        - MOV: MOV RAX, 8000000000000000 works
    
2) 16-bit and 32-bit addresses
    
    * zero extended to 64 bits
    
General Purpose Registers in 64-bit mode:
==========================================
    
    * QWORDS: RAX, RBX, RCX, RDX, RDI, RSI, RBP, RSP, R8 - R15

    * DWORDS: EAX, EBX, ECX, EDX, EDI, ESI, EBP, ESP, R8D - R15D
    
    * WORDS: AX, BX, CX, DX, DI, SI, BP, SP, R8W - R15W
    
    * BYTES: AL, BL, CL, DL, DIL, SIL, BPL, SPL, R8L - R15L
        - AH, CH, DH, BH have been remapped to SPL, BPL, SIL, DIL
        
Flags in 64-bit mode:
=====================

EFLAGS is now the 64-bit RFLAGS:
    
    * Upper 32 bits are reserved
    * Lower 32 bits is the same as EFLAGS
    
New instructions:
=================

CDQE: convert dword to qword
CMPSQ: compare qword from string operands
CMPXCHQ16B: compare RDX:RAX with m128
LODSQ: Load qword from (RSI) into RAX
MOVSQ: Move qword from (RSI) into (RDI)
MOVZX: Move dword to qword with zero extension
STOSQ: Store RAX into (RDI)
SWAPGS: Exchanges GS base register with val with MSR address val (C0000102)
SYSCALL: Fast call to privilege level 0 procedures
SYSRET: Return from fast systemcall

VC++ X64 Calling convention and register volatility (Microsoft):
================================================================

"
Calling convention

The x64 Application Binary Interface (ABI) is a 4 register fast-call calling 
convention, with stack-backing for those registers. There is a strict one-to-one 
correspondence between arguments in a function, and the registers for those 
arguments. Any argument that does not fit in 8 bytes, or is not 1, 2, 4, or 
8 bytes, must be passed by reference. There is no attempt to spread a single 
argument across multiple registers. The x87 register stack is unused. It may 
be used, but must be considered volatile across function calls. All floating 
point operations are done using the 16 XMM registers. The arguments are passed 
in registers RCX, RDX, R8, and R9. If the arguments are float/double, they are 
passed in XMM0L, XMM1L, XMM2L, and XMM3L. 16 byte arguments are passed by 
reference. Parameter passing is described in detail in Parameter Passing. 
In addition to these registers, RAX, R10, R11, XMM4, and XMM5 are volatile. 
All other registers are non-volatile. Register usage is documented in detail 
in Register Usage and Caller/Callee Saved Registers.

Caller/Callee Saved Registers 

The registers RAX, RCX, RDX, R8, R9, R10, R11 are considered volatile and must 
be considered destroyed on function calls (unless otherwise safety-provable by 
analysis such as whole program optimization).

The registers RBX, RBP, RDI, RSI, R12, R13, R14, and R15 are considered 
nonvolatile and must be saved and restored by a function that uses them.

"

"""

# we use non-volatile regs makes life more convenient
# value storage: R12
# accumulator: R13
# secondary/index: R14
# code base ptr: R15

class ilX64(IL2Proc):
    def __init__(self):
        IL2Proc.__init__(self)
        self.last_load_size = 0
        return
    
    def _debug(self):
        return ['int 3\n']
    
    # labels
    def _labeldefine(self, words):
        return ['%s:\n' % words[1]]
    
    def _GETPC(self, words):
        # XXX: need RIP relative addressing support in assembler
        # return ['lea 0(%rip),%r15\n', 'GETPC_reserved:\n']
        # added stack align on 128b
        return ['.byte 0x4c\n',
                '.byte 0x8d\n',
                '.byte 0x3d\n',
                '.byte 0x00\n',
                '.byte 0x00\n',
                '.byte 0x00\n',
                '.byte 0x00\n',
                'GETPC_reserved:\n']
    
    def _asm(self, words):
        return [' '.join(words[1:]) + '\n']
    
    # remarks
    def _rem(self, words):
        return ['# %s\n' % (' '.join(words[1:]))]
    
    # branching
    def _jump(self, words):
        return ['jmp %s\n' % words[1]]
    
    def _jumpiftrue(self, words):
        stub = []
        stub.append('test %r13,%r13\n')
        stub.append('jnz %s\n' % words[1])
        return stub
    
    def _jumpiffalse(self, words):
        stub = []
        stub.append('test %r13,%r13\n')
        stub.append('jz %s\n' % words[1])
        return stub
    
    def _ret(self, words):
        if words[1] == '0':
            return ['ret\n']
        else:
            # align arg size restore on 8 ...
            arg_size = int(words[1], 0)
            if arg_size % 8:
                arg_size += 8 - (arg_size % 8)
            return ['ret $%d\n' % arg_size]
    
    def _call(self, words):
        return ['call %s\n' % words[1]]
    
    def _functionprelude(self, words):
        stub = []
        stub.append('push %rbp\n')
        stub.append('mov %rsp,%rbp\n')
        return stub
    
    def _functionpostlude(self, words):
        stub = []
        stub.append('mov %rbp,%rsp\n')
        stub.append('pop %rbp\n')
        return stub
    
    # local vars
    def _getstackspace(self, words):
        alloca = int(words[1], 0)
        if alloca % 16:
            alloca += 16 - (alloca % 16)
        return ['sub $%d,%%rsp\n' % alloca]
    
    def _freestackspace(self, words):
        # postlude already takes care of free-ing stack space
        return ''
    
    # strings
    def _ascii(self, words):
        return ['.ascii "%s"\n' % (' '.join(words[1:]))] 
    
    def _urlencoded(self, words):
        return ['.urlencoded "%s"\n' % (' '.join(words[1:]))]
    
    # life is going to get tricky between ILP64 and LLP64 systems ..
    # I figure we can just blatantly stick to LLP64 accross the board ...
    def _longvar(self, words):
        return ['.long %s\n' % uint32fmt(words[1])]
    
    # LLP64
    def _longlongvar(self, words):
        return ['.longlong %s\n' % uint64fmt(words[1])]
    
    # bytes
    def _databytes(self, words):
        return ['.byte %s\n' % words[1]]
    
    # accumulator/secondary/index operations
    def _accumulator2index(self, words):
        return ['mov %r13,%r14\n']
    
    def _derefwithindex(self, words):
        return ['mov (%r13,%r14,1),%r13\n']

    def _storewithindex(self, words):
        stubs = { '8' : 'movq %r12,(%r13,%r14,1)\n',
                  '4' : 'movl %r12d,(%r13,%r14,1)\n',
                  '2' : 'movw %r12w,(%r13,%r14,1)\n',
                  '1' : 'movb %r12b,(%r13,%r14,1)\n' }
        return [stubs[words[1]]]
    
    def _oraccumwithsecondary(self, words):
        return ['or %r14,%r13\n']
    
    def _andaccumwithsecondary(self, words):
        return ['and %r14,%r13\n']
    
    def _xoraccumwithsecondary(self, words):
        return ['xor %r14,%r13\n']
    
    def _poptosecondary(self, words):
        return ['pop %r14\n']
    
    def _subtractsecondaryfromaccum(self, words):
        return ['sub %r14,%r13\n']
    
    def _addsecondarytoaccum(self, words):
        return ['add %r14,%r13\n']
    
    def _dividesecondaryfromaccum(self, words):
        stub = []
        stub.append('mov %r13,%rax\n')
        stub.append('mov %r14,%rcx\n')
        stub.append('xor %rdx,%rdx\n')
        stub.append('div %rcx\n')
        stub.append('mov %rax,%r13\n')
        return stub
    
    def _multaccumwithsecondary(self, words):
        stub = []
        stub.append('mov %r13,%rax\n')
        stub.append('mul %r14\n')
        stub.append('mov %rax,%r13\n')
        return stub
    
    def _modulussecondaryfromaccum(self, words):
        stub = []
        stub.append('mov %r13,%rax\n')
        stub.append('xor %rdx,%rdx\n')
        stub.append('div %r14\n')
        stub.append('mov %rdx,%r13\n')
        return stub   
    
    def _loadint(self, words):
        return ['movq $%d,%%r13\n' % long(words[1],0)]
    
    def _poptoshiftreg(self, words):
        return ['pop %rcx\n']
    
    def _pushshiftreg(self, words):
        return ['push %rcx\n']
    
    def _shiftright(self, words):
        return ['shr %cl,%r13\n']
    
    def _shiftleft(self, words):
        return ['shl %cl,%r13\n']
    
    def _pushaccum(self, words):
        return ['push %r13\n']
    
    def _multiply(self, words):
        stub = []
        stub.append('mov $%d,%%r14\n' % long(words[1])) # XXX: int or long?
        stub.append('mov %r13,%rax\n') #rax <- accum
        stub.append('mul %r14\n')
        stub.append('mov %rax,%r13\n') #accum <- rax
        return stub

    def _argtoreg(self, words):
        """
        From amd64 ABI:
        The next available register of the sequence %rdi, %rsi, %rdx, %rcx, %r8
        and %r9 is used. 
        """
        registers = ["%rdi", "%rsi", "%rdx", "%rcx", "%r8", "%r9"]
        idx = int(words[1])
        if idx > 5:
            # Not enough registers, have to use the stack
            devlog('chris', 'il2x64: registers for arg passing exhausted, using stack')
            return self._arg(words)
        return ['movq %%r13, %s\n' % registers[idx]]
    
    def _arg(self, words):
        return ['push %r13\n']
    
    def _callaccum(self, words):
        return ['xor %rax, %rax\n', 'call *%r13\n']
    
    def _derefaccum(self, words):
        stub = []
        stub.append('xor %rax,%rax\n')
        stubs = { '8' : 'movq (%r13),%rax\n',
                  '4' : 'movl (%r13),%eax\n',
                  '2' : 'movw (%r13),%ax\n',
                  '1' : 'movb (%r13),%al\n' }
        stub.append(stubs[words[1]])
        stub.append('mov %rax,%r13\n')
        return stub
    
    def _loadglobaladdress(self, words):
        # address size in x64
        self.last_load_size = 8   
        return ['lea %s-GETPC_reserved(%%r15),%%r13\n' % words[1]]
    
    def _loadlocaladdress(self, words):
        # address size in x64
        self.last_load_size = 8     
        stub = []
        if words[1][:2] == 'in':
            argnum = int(words[1][2:])
            stub.append('lea %s(%%rbp),%%r13\n' % \
                        uint32fmt(16+8*argnum))
        else:
            stub.append('lea %s(%%rbp),%%r13\n' % \
                        uint32fmt(-1*(int(words[1]))))
        return stub
    
    def _loadlocal(self, words):
        size = int(words[2])
        if words[1][:2] == 'in':
            argnum = int(words[1][2:])
            end = '%s(%%rbp)' % uint32fmt((argnum * 8) + 16)
        else:
            argnum = int(words[1])
            end = '%s(%%rbp)' % uint32fmt(-(argnum))
        stubs = { '8' : 'movq %s,%%r13\n' % end,
                  '4' : 'xor %%r13,%%r13\nmovl %s,%%r13d\n' % end,
                  '2' : 'xor %%r13,%%r13\nmovw %s,%%r13w\n' % end,
                  '1' : 'xor %%r13,%%r13\nmovb %s,%%r13b\n' % end }
        self.last_load_size = size
        return [stubs[words[2]]]
    
    def _loadglobal(self, words):
        size = int(words[2])
        stubs = { '8' : 'movq %s-GETPC_reserved(%%r15),%%r13\n' % words[1],
                  '4' : 'xor %%r13,%%r13\nmovl %s-GETPC_reserved(%%r15),%%r13d\n' % words[1],
                  '2' : 'xor %%r13,%%r13\nmovq %s-GETPC_reserved(%%r15),%%r13w\n' % words[1],
                  '1' : 'xor %%r13,%%r13\nmovb %s-GETPC_reserved(%%r15),%%r13b\n' % words[1] }
        self.last_load_size = size
        return [stubs[words[2]]]
    
    def _storeaccumulator(self, words):
        return ['mov %r13,%r12\n']
    
    def _accumulator2memorylocal(self, words):
        if words[1][:2] == 'in':
            argnum = int(words[1][2:])
            end = '%s(%%rbp)' % uint32fmt((argnum * 8) + 16)
        else:
            argnum = int(words[1])
            end = '%s(%%rbp)' % uint32fmt(-(argnum))
        stubs = { '8' : 'movq %%r13,%s\n' % end,
                  '4' : 'movl %%r13d,%s\n' % end,
                  '2' : 'movw %%r13w,%s\n' % end,
                  '1' : 'movb %%r13b,%s\n' % end }
        return [stubs[words[2]]]
    
    def _addconst(self, words):
        return ['add $%d,%%r13\n' % int(words[1])]
    
    def _subconst(self, words):
        return ['sub $%d,%%r13\n' % int(words[1])]
    
    # control flags
    def _setifless(self, words):
        return ['setl %r13b\nmovzbl %r13b,%r13\n']
    
    def _setifgreater(self, words):
        return ['setg %r13b\nmovzbl %r13b,%r13\n']
    
    def _setifnotequal(self, words):
        return ['setne %r13b\nmovzbl %r13b,%r13\n']
    
    def _setifequal(self, words):
        return ['sete %r13b\nmovzbl %r13b,%r13\n']
    
    def _compare(self, words):
        # XXX: temporary kludge/fix for int compares on 64bit systems
        if self.last_load_size in [4, 2, 1]:
            # reset to clear load size tracking state
            self.last_load_size = 0
            return ['cmp %r14d,%r13d\n']
        else:
            self.last_load_size = 0
            return ['cmp %r14,%r13\n']
    
    # alignment
    def _archalign(self, words):
        return ['']

    def _save_stack(self, words):
        """
        This will save all non-preserved registers and RSP according
        to amd64 ABI.
        """
        return ["pushq %rax\n", "pushq %rcx\n", "pushq %rdx\n",
                "pushq %rsi\n", "pushq %rdi\n", "pushq %r8\n",
                "pushq %r9\n", "pushq %r10\n", "pushq %r11\n",
                "pushq %rbx\n", "movq %rsp, %rbx\n"]

    def _restore_stack(self, words):
        """
        This will restore the stack as it was before the 16-byte alignment
        fixup. This will also copy rax to r13 (amd64 calling conventions).
        """
        return ["movq %rax, %r13\n", "movq %rbx, %rsp\n", "popq %rbx\n",
                "popq %r11\n", "popq %r10\n", "popq %r9\n", "popq %r8\n",
                "popq %rdi\n", "popq %rsi\n", "popq %rdx\n", "popq %rcx\n",
                "popq %rax\n"]

    def _alignstack_pre(self, words):
        """
        Ensure stack is 16-byte aligned (osx/x64)
        
        From OSX ABI: "The stack is 16-byte aligned at the point of function calls"
        If we try to call library functions without the correct stack alignment, 
        the process will crash with dyld_misaligned_stack_error.
        We therefore ensure that %rsp % 16 == 0 before every library function call.
        """
        devlog('chris', 'alignstack_pre: %s' % repr(words))
        args = int(words[1])

        prelude =  ["and $0xfffffffffffffff0, %rsp\n"]

        # remove args that are passed via registers
        if args > 6:
            args -= 6
            if args % 2:
                # odd number of arguments that are passed via the stack
                # we need to fix the stack further
                return prelude + ["sub $0x8, %rsp\n"]
            
        return prelude
    
def generate(data):
    return ilX64().generate(data)
    
if __name__ == '__main__':

    import sys
    
    if len(sys.argv) > 1:
        filename = sys.argv[1]
        data = open(filename).read()
        print "%s" % (ilX64().generate(data))
    else:
        print "Usage: %s <file.il>" % sys.argv[0]
