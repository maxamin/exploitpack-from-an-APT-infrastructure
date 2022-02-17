#! /usr/bin/env python

from C_headers import C_headers

class arm(C_headers):
    
    def __init__(self):
        # not initializing C_headers() on purposes.
        self.__arm_initLocalFunctions()
    
    def __arm_initLocalFunctions(self):
        # This doesn't seem to work on my setup (Chris)
        self.localfunctions["debug"] = ("asm", """
        debug:
            movw\t  r7, #1
            movt\t  r7, #15
            svc\t   #0
            mov\t   r12, r14
            ldmfd\t sp!, {r14, r11}
            bx\t    r12
        """)

        self.localfunctions["clearcache"] = ("asm", """
        clearcache:
            ldr\t   r0, [r11]
            ldr\t   r1, [r11, #4]
            mov\t   r2, #0
            mov\t   r3, r1
            mov\t   r4, #0
            movw\t  r7, #2
            movt\t  r7, #0xf
            svc\t   #0
            mov\t   r4, r0
            mov\t   r12, r14
            ldmfd\t sp!, {r14, r11}
            add     r13, r13, #8
            bx\t    r12
        """)

        self.localfunctions["syscallN"] = ("asm", """
            ! r0 is arg0
            ! r1 is arg1
            ! r2 is arg2

            ! ... up to r6
            ! r7 has the syscall no
            syscallN:
            ldr\t r7, [r11]
            ldr\t r0, [r11, #4]
            ldr\t r1, [r11, #8]
            ldr\t r2, [r11, #12]
            ldr\t r3, [r11, #16]
            ldr\t r4, [r11, #20]
            ldr\t r5, [r11, #24]
            ldr\t r6, [r11, #28]
            svc\t #0
            mov\t r4, r0
            mov\t r12, r14
            ldmfd\t sp!, {r14, r11}
            bx\t r12
        """)

        self.localfunctions["callptr"] = ("asm", """
            callptr:
            stmfd   sp!, {r10}
            stmfd   sp!, {r14, r11}
            
            mov     r14, r15
            add     r14, r14, #8
            ldr     r4, [r11]
            bx      r4
            ldmfd   sp!, {r10}
            
            mov     r12, r14
            ldmfd   sp!, {r14, r11}
            add     r13, r13, #4
            bx      r12
        """)
            
        self.add_header('<asm/arm.h>', {'function': ["debug", "clearcache", "syscallN", "callptr"]})
