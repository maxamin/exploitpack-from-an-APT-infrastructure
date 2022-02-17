#! /usr/bin/env python

"""
the linux remote resolver. A kind of combination of libc and a few other things...
"""

from remoteresolver import remoteresolver
from unixremoteresolver import unixremoteresolver


class linuxremoteresolver(remoteresolver):
    """
    Our remote resolver for linux

    Threading issue: Cannot call clearfunctioncache() and then
    call compile() as a two step process because another thread
    might call clearfunctioncache() in between, and that's very bad.

    So we call acquire() in clearfunctioncache() and then release()
    in compile() and we're good to go.
    """

    def __init__(self, proc, version = '2.6'):
        remoteresolver.__init__(self, 'Linux', proc, version)
        self.remoteFunctionsUsed = {}
        self.remotefunctioncache = {}

    def initLocalFunctions(self):
        self.functioncache={}

        self.localfunctions["socket.h"]=("header","""
            struct sockaddr {
                unsigned short int family;
                char data[14];
            };

            struct sockaddr_in {
                unsigned short int family;
                unsigned short int port;
                unsigned int addr;
                char pad[8];
            };

            struct sockaddr_storage {
                //unsigned short int family;
                char padding[128];
            };
        """)

        # a bit like popen
        # XXX
        self.localfunctions["fexec"]=("c","""
        #import "local","syscall0" as "syscall0"
        int fexec(char *command) {

        }
        """)

        #fd_zero and fd_set stolen from BSD
        self.localfunctions["FD_ZERO"]=("c","""
        #import "local", "memset" as "memset"
        int
        FD_ZERO(int *fd_set) {
            memset(fd_set,0,128);
            return 1;
        }
        """)

        self.localfunctions["FD_SET"]=("c","""
        #import "local", "memset" as "memset"
        void
        FD_SET(int fd, int *fd_set) {
            int index;
            int flag;
            int *p;
            int bucket;
            int oldvalue;
            int newvalue;

            flag=1;
            index=fd%32;
            //index=32-index;
            bucket=fd/32;
            while (index>0) {
                flag=flag<<1;
                index=index-1;
            }
            //now flag has our bit value set
            p=fd_set+bucket;
            oldvalue=*p;
            newvalue=oldvalue|flag;
            *p=newvalue;
        }
        """)

        #
        #end syscalls, begin libc functions
        #

        # XXX: all libc functions using self.fd go into crippleC.py !
        # XXX: self.fd is then re-set properly using initStaticFunctions ;)


class arm9linuxremoteresolver(linuxremoteresolver, unixremoteresolver):
    def __init__(self, proc="ARM9", version='2.6'):
        linuxremoteresolver.__init__(self, 'ARM9', version)
        unixremoteresolver.__init__(self)

        # We always have a resolver
        self.remote_resolver = True

    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)

        self.localfunctions['sendpointer'] = ("c", """
        #import "local", "sendint" as "sendint"
        void sendpointer(int ptr)
        {
            sendint(ptr);
        }
        """)

        ####################################################################
        #
        # Due to Android not using GLIBC, the internal LIBC function
        # (__libc_dlopen_mode) that is used in the x86 linux remote
        # resolver is not available. This means that we currently
        # have no way to load foreign libraries and `dlopen' functionality
        # is not available.
        #
        # For `dlsym' functionality we'll use the primitive ELF resolver
        # that scans the address space, implemented below.
        #
        ####################################################################


        self.localfunctions["dlsym"] = ("c", """
        #import "local", "resolve" as "resolve"
        void *dlsym(void *handle, char *symbol)
        {
            void *ret;
            ret = resolve(symbol);

            return ret;
        }
        """)


        self.localfunctions["resolve"] = ("asm", """
        b resolve

access:
        stmfd   sp!, {r7, r14}
        mov     r7, #33
        svc     #0
        movw    r1, #0xf001
        movt    r1, #0xffff
        cmp     r0, r1
        movge   r1, #0
        subge   r0, r1, r0
        ldmfd   sp!, {r7, r15}

strcmp:
	mov	r12, #0
	stmfd	sp!, {r4, r14}
L6:
	ldrb	r3, [r0, r12]
	ldrb	r2, [r1, r12]
	cmp	r3, #0
	mov	r4, r3
	beq	L3
	cmp	r3, r2
	movne	r4, #0
	moveq	r4, #1
L3:
	cmp	r2, #0
	add	r12, r12, #1
	beq	L4
	cmp	r4, #0
	bne	L6
	cmp	r3, r2
	mvncc	r0, #0
        bcc     L9

L4:
	cmp	r2, r3
	movcs	r0, #0
	movcc	r0, #1
	ldmfd	sp!, {r4, r15}
L9:
        ldmfd	sp!, {r4, r15}


find_exec_base:
	stmfd	sp!, {r0, r1, r2, r4, r5, r14}
	mov	r3, #127
	strb	r3, [sp, #4]
	mov	r3, #69
	strb	r3, [sp, #5]
	add	r3, r3, #7
	strb	r3, [sp, #6]
	mov	r3, #70
	strb	r3, [sp, #7]
	mov	r4, r0
	ldr	r5, [sp, #4]
L13:
	mov	r0, r4
	mov	r1, #4
	bl	access
	cmp	r0, #14
	beq	L12
	ldr	r3, [r4, #0]
	cmp	r3, r5
	bne	L12
	mov	r0, r4
	ldmfd	sp!, {r1, r2, r3, r4, r5, r15}
L12:
	sub	r4, r4, #4096
	b	L13


scan_elf_header:
	ldrh	r3, [r0, #16]
	stmfd	sp!, {r4, r5, r6, r7, r8, r9, r10, r14}
	cmp	r3, #3
	mov	r6, r0
	mov	r10, r1
	bne	L27
	ldr	r3, [r0, #28]
	mov	r2, #0
	ldrh	r12, [r0, #44]
	mvn	r8, #0
	add	r3, r0, r3
	mov	r0, r2
	b	L28
L212:
	ldr	r1, [r3, #0]
	cmp	r1, #2
	moveq	r1, r8
	moveq	r0, r3
	beq	L210
	cmp	r1, #1
	bne	L211
	ldr	r1, [r3, #8]
	cmp	r8, r1
	bhi	L210
L211:
	mov	r1, r8
L210:
	add	r3, r3, #32
	add	r2, r2, #1
	mov	r8, r1
L28:
	cmp	r2, r12
	blt	L212
	cmp	r0, #0
	beq	L27
	ldr	r7, [r0, #8]
	rsb	r8, r8, r6
	mov	r1, #4
	add	r7, r8, r7
	mov	r0, r7
	bl	access
	cmp	r0, #14
	movne	r3, #0
	movne	r4, r3
	movne	r5, r3
	beq	L27
	b	L213
L216:
	cmp	r2, #6
	addeq	r2, r3, r7
	ldreq	r4, [r2, #4]
	beq	L215
	cmp	r2, #5
	addeq	r2, r3, r7
	ldreq	r5, [r2, #4]
L215:
	add	r3, r3, #8
L213:
	ldr	r2, [r3, r7]
	cmp	r2, #0
	bne	L216
	cmp	r5, #0
	beq	L218
	mov	r0, r5
	mov	r1, #4
	bl	access
	cmp	r0, #14
	bne	L218
	add	r5, r5, r6
	mov	r1, #4
	mov	r0, r5
	bl	access
	cmp	r0, #14
	moveq	r5, #0
L218:
	cmp	r4, #0
	beq	L220
	mov	r0, r4
	mov	r1, #4
	bl	access
	cmp	r0, #14
	bne	L220
	add	r4, r4, r6
	mov	r1, #4
	mov	r0, r4
	bl	access
	cmp	r0, #14
	moveq	r4, #0
L220:
	cmp	r4, #0
	cmpne	r5, #0
	beq	L27
	mov	r6, #0
L223:
	ldr	r0, [r4, r6]
	mov	r1, #4
	add	r0, r5, r0
	bl	access
	cmp	r0, #14
	mov	r0, r10
	beq	L27
	ldr	r1, [r4, r6]
	add	r1, r5, r1
	bl	strcmp
	add	r3, r4, r6
	add	r6, r6, #16
	cmp	r0, #0
	bne	L223
	ldr	r0, [r3, #4]
	cmp	r0, #0
	beq	L223
	add	r0, r0, r8
	ldmfd	sp!, {r4, r5, r6, r7, r8, r9, r10, r15}
L27:
	mov	r0, #0
	ldmfd	sp!, {r4, r5, r6, r7, r8, r9, r10, r15}

resolve:
	stmfd	sp!, {r5, r6, r7, r8, r9, r10, r14}
	mov	r4, #0
        ldr     r0, [r11]
	mov	r7, r0
	mov	r5, r4
L329:
	mov	r0, r5
	bl	find_exec_base
	subs	r3, r5, #0
	movne	r3, #1
	mov	r1, r7
	cmp	r4, r0
	mov	r6, r0
	movne	r3, #0
	sub	r5, r0, #4096
	cmp	r3, #0
	bne	L326
	bl	scan_elf_header
	cmp	r4, #0
	moveq	r4, r6
	cmp	r0, #0
	beq	L329
	ldmfd	sp!, {r5, r6, r7, r8, r9, r10, r14}
        mov     r12, r14
        ldmfd   sp!, {r14, r11}
        add     r13, r13, #8
        mov     r4, r0
        bx      r12
L326:
	mov	r0, #0
	ldmfd	sp!, {r5, r6, r7, r8, r9, r10, r14}
        mov     r12, r14
        ldmfd   sp!, {r14, r11}
        add     r13, r13, #4
        mov     r4, r0
        bx      r12
        """)

class x64linuxremoteresolver(linuxremoteresolver, unixremoteresolver):
    def __init__(self, proc='x64', version='2.4'):
        linuxremoteresolver.__init__(self, 'x64', version)
        unixremoteresolver.__init__(self)

        # X64 remote resolver is disabled by default
        # On shellserver startup, remote resolver setup will be
        # attempted and this attribute set to True if successful
        #
        # We have to do it like that because the method we use
        # for x64 resolutions (/proc/self/maps parsing) is completely
        # different from the one we use on x86.
        #
        # The main difference is that the x86 method can never fail.
        # The x64 method can fail if there is no /proc, or if /proc
        # has been restricted. Thus the entire remote resolver protocol
        # has to be conditional.

        self.remote_resolver = False

    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)

        self.localfunctions['sendpointer'] = ("c", """
        #import "local", "sendlonglong" as "sendlonglong"
        void sendpointer(long long ptr)
        {
            sendlonglong(ptr);
        }
        """)

        self.localfunctions["resolve"] = ("asm", """
        jmp resolve

        access:
            pushq  %rbp
            movq   %rsp,%rbp
            movq   $0x15,%rax
            syscall
            cmp    $0xfffffffffffff001, %rax
            xor    %rdx,%rdx
            sub    %rax,%rdx
            movq   %rdx,%rax
            leave
            ret

        _strcmp:
            pushq   %rbp
            movq    %rsp, %rbp
            movq    %rdi, -40(%rbp)
            movq    %rsi, -48(%rbp)
            movq    -40(%rbp), %rax
            movq    %rax, -8(%rbp)
            movq    -48(%rbp), %rax
            movq    %rax, -16(%rbp)
        .L4:
            movq    -8(%rbp), %rax
            leaq    1(%rax), %rdx
            movq    %rdx, -8(%rbp)
            movzbl  (%rax), %eax
            movb    %al, -17(%rbp)
            movq    -16(%rbp), %rax
            leaq    1(%rax), %rdx
            movq    %rdx, -16(%rbp)
            movzbl  (%rax), %eax
            movb    %al, -18(%rbp)
            cmpb    $0, -17(%rbp)
            jne .L2
            movzbl  -17(%rbp), %edx
            movzbl  -18(%rbp), %eax
            subl    %eax, %edx
            movl    %edx, %eax
            jmp .L3
        .L2:
            movzbl  -17(%rbp), %eax
            cmpb    -18(%rbp), %al
            je  .L4
            movzbl  -17(%rbp), %edx
            movzbl  -18(%rbp), %eax
            subl    %eax, %edx
            movl    %edx, %eax
        .L3:
            popq    %rbp
            ret

        _memcmp:
            pushq   %rbp
            movq    %rsp, %rbp
            movq    %rdi, -24(%rbp)
            movq    %rsi, -32(%rbp)
            movq    %rdx, -40(%rbp)
            jmp .L6
        .L9:
            movq    -24(%rbp), %rax
            movzbl  (%rax), %eax
            movb    %al, -1(%rbp)
            movq    -32(%rbp), %rax
            movzbl  (%rax), %eax
            movb    %al, -2(%rbp)
            movzbl  -1(%rbp), %eax
            cmpb    -2(%rbp), %al
            je  .L7
            movzbl  -1(%rbp), %edx
            movzbl  -2(%rbp), %eax
            subl    %eax, %edx
            movl    %edx, %eax
            jmp .L8
        .L7:
            addq    $1, -24(%rbp)
            addq    $1, -32(%rbp)
        .L6:
            movq    -40(%rbp), %rax
            leaq    -1(%rax), %rdx
            movq    %rdx, -40(%rbp)
            testq   %rax, %rax
            jne .L9
            movl    $0, %eax
        .L8:
            popq    %rbp
            ret

        check_elf_head:
            pushq   %rbp
            movq    %rsp, %rbp
            subq    $32, %rsp
            movq    %rdi, -24(%rbp)
            movb    $127, -16(%rbp)
            movb    $69, -15(%rbp)
            movb    $76, -14(%rbp)
            movb    $70, -13(%rbp)
            movq    -24(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            movl    %eax, -4(%rbp)
            cmpl    $14, -4(%rbp)
            je  .L11
            leaq    -16(%rbp), %rcx
            movq    -24(%rbp), %rax
            movl    $4, %edx
            movq    %rcx, %rsi
            movq    %rax, %rdi
            call    _memcmp
            testl   %eax, %eax
            jne .L11
            movl    $1, %eax
            jmp .L13
        .L11:
            movl    $0, %eax
        .L13:
            leave
            ret

        resolve:
            pushq   %rbp
            movq    %rsp, %rbp
            subq    $112, %rsp

            // mosdef calling conventions, args on the stack
            movq    16(%rbp), %rdi
            movq    24(%rbp), %rsi

            movq    %rdi, -104(%rbp)
            movq    %rsi, -112(%rbp)
            movq    -104(%rbp), %rax
            movq    %rax, -80(%rbp)
            movq    -80(%rbp), %rax
            movzwl  16(%rax), %eax
            cmpw    $3, %ax
            jne .L15
            movq    -80(%rbp), %rax
            movq    32(%rax), %rdx
            movq    -104(%rbp), %rax
            addq    %rdx, %rax
            movq    %rax, -8(%rbp)
            movq    $0, -16(%rbp)
            movq    $-1, -24(%rbp)
            movq    $0, -88(%rbp)
            movl    $0, -28(%rbp)
            jmp .L16
        .L19:
            movq    -8(%rbp), %rax
            movl    (%rax), %eax
            cmpl    $2, %eax
            jne .L17
            movq    -8(%rbp), %rax
            movq    %rax, -16(%rbp)
            jmp .L18
        .L17:
            movq    -8(%rbp), %rax
            movl    (%rax), %eax
            cmpl    $1, %eax
            jne .L18
            movq    -8(%rbp), %rax
            movq    16(%rax), %rax
            cmpq    -24(%rbp), %rax
            jae .L18
            movq    -8(%rbp), %rax
            movq    16(%rax), %rax
            movq    %rax, -24(%rbp)
        .L18:
            addq    $56, -8(%rbp)
            addl    $1, -28(%rbp)
        .L16:
            movq    -80(%rbp), %rax
            movzwl  56(%rax), %eax
            movzwl  %ax, %eax
            cmpl    -28(%rbp), %eax
            jg  .L19
            movq    -104(%rbp), %rax
            subq    -24(%rbp), %rax
            movq    %rax, -88(%rbp)
            cmpq    $0, -16(%rbp)
            je  .L15
            movq    $0, -40(%rbp)
            movq    $0, -48(%rbp)
            movl    $0, -52(%rbp)
            movq    $0, -64(%rbp)
            movq    -16(%rbp), %rax
            movq    %rax, -8(%rbp)
            movq    -8(%rbp), %rax
            movq    16(%rax), %rdx
            movq    -88(%rbp), %rax
            addq    %rdx, %rax
            movq    %rax, -64(%rbp)
            movq    -64(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            cmpl    $14, %eax
            jne .L20
            movl    $0, %eax
            jmp .L21
        .L20:
            jmp .L22
        .L26:
            movq    -64(%rbp), %rax
            movq    (%rax), %rax
            cmpq    $6, %rax
            jne .L23
            movq    -64(%rbp), %rax
            movq    8(%rax), %rax
            movq    %rax, -48(%rbp)
            jmp .L24
        .L23:
            movq    -64(%rbp), %rax
            movq    (%rax), %rax
            cmpq    $5, %rax
            jne .L25
            movq    -64(%rbp), %rax
            movq    8(%rax), %rax
            movq    %rax, -40(%rbp)
            jmp .L24
        .L25:
            movq    -64(%rbp), %rax
            movq    (%rax), %rax
            cmpq    $14, %rax
            jne .L24
            movq    -64(%rbp), %rax
            movq    8(%rax), %rax
            movl    %eax, -52(%rbp)
        .L24:
            addq    $16, -64(%rbp)
        .L22:
            movq    -64(%rbp), %rax
            movq    (%rax), %rax
            testq   %rax, %rax
            jne .L26
            cmpq    $0, -40(%rbp)
            je  .L27
            movq    -40(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            cmpl    $14, %eax
            jne .L27
            movq    -104(%rbp), %rax
            addq    %rax, -40(%rbp)
            movq    -40(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            cmpl    $14, %eax
            jne .L28
            movq    $0, -40(%rbp)
            movq    $0, -40(%rbp)
            jmp .L27
        .L28:
            nop
        .L27:
            cmpq    $0, -48(%rbp)
            je  .L30
            movq    -48(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            cmpl    $14, %eax
            jne .L30
            movq    -104(%rbp), %rax
            addq    %rax, -48(%rbp)
            movq    -48(%rbp), %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            cmpl    $14, %eax
            jne .L31
            movq    $0, -48(%rbp)
            movq    $0, -48(%rbp)
            jmp .L30
        .L31:
            nop
        .L30:
            cmpq    $0, -40(%rbp)
            je  .L15
            cmpq    $0, -48(%rbp)
            je  .L15
            movq    -48(%rbp), %rax
            movq    %rax, -72(%rbp)
            cmpl    $0, -52(%rbp)
            je  .L33
            movl    -52(%rbp), %edx
            movq    -40(%rbp), %rax
            addq    %rdx, %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            movl    %eax, -92(%rbp)
        .L33:
            movq    -72(%rbp), %rax
            movl    (%rax), %eax
            movl    %eax, %edx
            movq    -40(%rbp), %rax
            addq    %rdx, %rax
            movl    $4, %esi
            movq    %rax, %rdi
            call    access
            movl    %eax, -96(%rbp)
            cmpl    $14, -96(%rbp)
            jne .L34
            nop
            jmp .L15
        .L34:
            movq    -72(%rbp), %rax
            movl    (%rax), %eax
            movl    %eax, %edx
            movq    -40(%rbp), %rax
            addq    %rax, %rdx
            movq    -112(%rbp), %rax
            movq    %rdx, %rsi
            movq    %rax, %rdi
            movl    $0, %eax
            call    _strcmp
            testl   %eax, %eax
            jne .L36
            movq    -72(%rbp), %rax
            movq    8(%rax), %rax
            testq   %rax, %rax
            je  .L36
            movq    -72(%rbp), %rax
            movq    8(%rax), %rdx
            movq    -88(%rbp), %rax
            addq    %rdx, %rax

            jmp .L21
        .L36:
            addq    $24, -72(%rbp)
            jmp .L33
        .L15:
            movl    $0, %eax
        .L21:
            // mov ret in r13 (MOSDEF)
            movq    %rax, %r13
            leave
            ret
        """)
        ###################################################################
        #
        # Wrappers for _dlopen and _dlsym that should be resolved during
        # shellserver startup.
        #
        ###################################################################

        self.localfunctions["dlopen"] = ("c", """
        #import "remote64", "_dlopen" as "_dlopen"
        void *dlopen(char *library)
        {
            void *ret;

            ret = _dlopen(library, 0x00100 | 0x1);
            return ret;
        }
        """)

        self.localfunctions["dlsym"] = ("c", """
        #import "remote64", "_dlsym" as "_dlsym"

        void *dlsym(void *handle, char *symbol)
        {
            void *ret;

            ret = _dlsym(handle, symbol);
            return ret;
        }
        """)

class x86linuxremoteresolver(linuxremoteresolver, unixremoteresolver):
    def __init__(self, proc="i386", version = '2.4'):
        linuxremoteresolver.__init__(self, 'i386', version)
        unixremoteresolver.__init__(self)

        # We always have a resolver
        self.remote_resolver = True

    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)

        self.localfunctions['sendpointer'] = ("c", """
        #import "local", "sendint" as "sendint"
        void sendpointer(int ptr)
        {
            sendint(ptr);
        }
        """)

        # Remote ELF in-memory symbol resolver
        # Tested on Linux, FreeBSD

        # Works with PIE/ASLR/PRELINK

        # There are a couple of different approaches one could use to do this.
        # The first is locating the dynamic linker's `linkmap' data structure from
        # the GOT entry in the ELF header and then traversing it in-memory.
        # We follow a different approach here. Scan the whole virtual address space by
        # page-sized amounts, locate all mapped ELF shared objects and traverse their
        # .DYNAMIC section to locate the symbol/string table and do the resolution.
        # This should work pretty much for any kind of architecture that uses ELF and
        # it is quite easy to deal with ASLR and PIE.

        self.localfunctions["resolve"] = ("asm", """
        jmp resolve

        access:
        pushl   %ebp
        movl    %esp,%ebp
        pushl   %ebx
        pushl   %ecx
        movl    $0x21,%eax
        movl    8(%ebp),%ebx
        movl    $0x4,%ecx
        int     $0x80
        cmpl    $0xfffff001,%eax
        jae     mangle
        xorl    %eax,%eax
        jmp     exit
        mangle:
        xorl    %ebx,%ebx
        subl    %eax,%ebx
        movl    %ebx,%eax
        exit:
        popl    %ecx
        popl    %ebx
        leave
        ret

        strncmp:
        pushl   %ebp
        movl    %esp,%ebp
        pushl   %esi
        pushl   %edi
        pushl   %ecx
        xorl    %eax,%eax
        movl    8(%ebp),%esi
        movl    12(%ebp),%edi
        movl    16(%ebp),%ecx
        repe    cmpsb
        je      exit2
        incl    %eax
        exit2:
        popl    %ecx
        popl    %edi
        popl    %esi
        leave
        ret

        strlen:
        pushl   %ebp
        movl    %esp,%ebp
        pushl   %edi
        pushl   %ecx
        movl    8(%ebp),%edi
        xorl    %ecx,%ecx
        not     %ecx
        xorl    %eax,%eax
        repne   scasb
        not     %ecx
        movl    %ecx,%eax
        popl    %ecx
        popl    %edi
        leave
        ret

        // Scan ELF header in memory. Since we are only interested in DYN objects
        // we skip ET_EXEC. This function needs to be fairly robust to account for
        // differences in the memory layout of the ELF structures, since a lot of
        // offsets and address fields in the ELF headers are interpreted differently
        // depending on prelink/PIE or the kernel VDSO for Linux. We can use the
        // access() system call to check virtual memory status (mapped/unmapped) so
        // that we don't SIGSEGV

        scan_elf_header:
        pushl   %ebp
        movl    %esp,%ebp
        subl    $72,%esp
        movl    8(%ebp),%eax
        movl    %eax,-48(%ebp)
        movl    -48(%ebp),%eax
        movzwl  16(%eax),%eax
        cmpw    $3,%ax
        jne     sehL2
        movl    -48(%ebp),%eax
        movl    28(%eax),%eax
        addl    8(%ebp),%eax
        movl    %eax,-44(%ebp)
        movl    $0,-40(%ebp)
        movl    $-1,-36(%ebp)
        movl    $0,-32(%ebp)
        movl    $0,-28(%ebp)
        jmp     sehL4
        sehL5:
        movl    -44(%ebp),%eax
        movl    (%eax),%eax
        cmpl    $2,%eax
        jne     sehL6
        movl    -44(%ebp),%eax
        movl    %eax,-40(%ebp)
        jmp     sehL8
        sehL6:
        movl    -44(%ebp),%eax
        movl    (%eax),%eax
        cmpl    $1,%eax
        jne     sehL8
        movl    -44(%ebp),%eax
        movl    8(%eax),%eax
        cmpl    -36(%ebp),%eax
        jae     sehL8
        movl    -44(%ebp),%eax
        movl    8(%eax),%eax
        movl    %eax,-36(%ebp)
        sehL8:
        addl    $32,-44(%ebp)
        addl    $1,-28(%ebp)
        sehL4:
        movl    -48(%ebp),%eax
        movzwl  44(%eax),%eax
        movzwl  %ax,%eax
        cmpl    -28(%ebp),%eax
        jg      sehL5
        movl    8(%ebp),%eax
        pushl   %ebx
        movl    -36(%ebp), %ebx
        subl    %ebx,%eax
        popl    %ebx
        movl    %eax,-32(%ebp)
        cmpl    $0,-40(%ebp)
        je      sehL2
        movl    $0,-24(%ebp)
        movl    $0,-20(%ebp)
        movl    $0,-16(%ebp)
        movl    $0,-12(%ebp)
        movl    -40(%ebp),%eax
        movl    %eax,-44(%ebp)
        movl    -44(%ebp),%eax
        movl    8(%eax),%eax
        movl    %eax,%edx
        movl    -32(%ebp),%eax
        leal    (%edx,%eax),%eax
        movl    %eax,-12(%ebp)
        movl    -12(%ebp),%eax
        movl    %eax,(%esp)
        call    access
        cmpl    $14,%eax
        jne     sehL17
        movl    $0,-52(%ebp)
        jmp     sehL16
        sehL18:
        movl    -12(%ebp),%eax
        movl    (%eax),%eax
        cmpl    $6,%eax
        jne     sehL19
        movl    -12(%ebp),%eax
        movl    4(%eax),%eax
        movl    %eax,-20(%ebp)
        jmp     sehL21
        sehL19:
        movl    -12(%ebp),%eax
        movl    (%eax),%eax
        cmpl    $5,%eax
        jne     sehL22
        movl    -12(%ebp),%eax
        movl    4(%eax),%eax
        movl    %eax,-24(%ebp)
        jmp     sehL21
        sehL22:
        movl    -12(%ebp),%eax
        movl    (%eax),%eax
        cmpl    $14,%eax
        jne     sehL21
        movl    -12(%ebp),%eax
        movl    4(%eax),%eax
        movl    %eax,-16(%ebp)
        sehL21:
        addl    $8,-12(%ebp)
        sehL17:
        movl    -12(%ebp),%eax
        movl    (%eax),%eax
        test    %eax,%eax
        jne     sehL18
        cmpl    $0,-24(%ebp)
        je      sehL26
        movl    -24(%ebp),%eax
        movl    %eax,(%esp)
        call    access
        cmpl    $14,%eax
        jne     sehL26
        movl    8(%ebp),%eax
        addl    %eax,-24(%ebp)
        movl    -24(%ebp),%eax
        movl    %eax,(%esp)
        call    access
        cmpl    $14,%eax
        jne     sehL26
        movl    $0,-24(%ebp)
        movl    $0,-24(%ebp)
        sehL26:
        cmpl    $0,-20(%ebp)
        je      sehL32
        movl    -20(%ebp),%eax
        movl    %eax,(%esp)
        call    access
        cmpl    $14,%eax
        jne     sehL32
        movl    8(%ebp),%eax
        addl    %eax,-20(%ebp)
        movl    -20(%ebp),%eax
        movl    %eax, (%esp)
        call    access
        cmpl    $14,%eax
        jne     sehL32
        movl    $0,-20(%ebp)
        movl    $0,-20(%ebp)
        sehL32:
        cmpl    $0,-24(%ebp)
        je      sehL2
        cmpl    $0,-20(%ebp)
        je      sehL2
        movl    -20(%ebp),%eax
        movl    %eax,-8(%ebp)
        sehL40:
        movl    -8(%ebp),%eax
        movl    (%eax),%eax
        addl    -24(%ebp),%eax
        movl    %eax,(%esp)
        call    access
        movl    %eax,-4(%ebp)
        cmpl    $14,-4(%ebp)
        je      sehL2
        sehL41:
        movl    12(%ebp),%eax
        pushl   %eax
        call    strlen
        addl    $4,%esp
        pushl   %eax
        movl    -8(%ebp),%eax
        movl    (%eax),%eax
        addl    -24(%ebp),%eax
        pushl   %eax
        movl    12(%ebp),%eax
        pushl   %eax
        call    strncmp
        addl    $12,%esp
        test    %eax,%eax
        jne     sehL43
        movl    -8(%ebp),%eax
        movl    4(%eax),%eax
        test    %eax,%eax
        je      sehL43
        movl    -8(%ebp),%eax
        movl    4(%eax),%eax
        movl    %eax,%edx
        movl    -32(%ebp),%eax
        addl    %eax,%edx
        movl    %edx,-52(%ebp)
        jmp     sehL16
        sehL43:
        addl    $16,-8(%ebp)
        jmp     sehL40
        sehL2:
        movl    $0,-52(%ebp)
        sehL16:
        movl    -52(%ebp),%eax
        leave
        ret


        find_exec_base:
        pushl   %ebp
        movl    %esp,%ebp
        pushl   %ebx
        subl    $20,%esp
        movl    8(%ebp),%ebx
        test    %ebx,%ebx
        jne     febL46

        call   febtag
        febtag:
        popl    %eax

        movl    %eax,%ebx
        andl    $-4096,%ebx
        febL46:
        movb    $127,-8(%ebp)
        movb    $69,-7(%ebp)
        movb    $76,-6(%ebp)
        movb    $70,-5(%ebp)
        febL47:
        pushl   %ebx
        call    access
        addl    $4,%esp
        cmpl    $14,%eax
        jne     febL48
        jmp     febL50
        febL48:
        pushl   $4
        leal    -8(%ebp),%eax
        pushl   %ebx
        pushl   %eax
        call    strncmp
        addl    $12,%esp
        test    %eax,%eax
        je      febL53
        febL50:
        subl    $4096,%ebx
        jmp     febL47
        febL53:
        movl    %ebx,%eax
        movl    -4(%ebp),%ebx
        leave
        ret

        resolve:
        pushl   %ebp
        movl    %esp,%ebp
        pushl   %edi
        pushl   %esi
        pushl   %ebx
        subl    $24,%esp
        pushl   $0
        call    find_exec_base
        addl    $16,%esp
        movl    $0,-16(%ebp)
        movl    %eax,%ebx
        resL69:
        cmpl    $0,-16(%ebp)
        jne     resL56
        movl    %ebx,-16(%ebp)
        resL56:
        pushl   %eax
        pushl   %eax
        pushl   8(%ebp)
        pushl   %ebx
        call    scan_elf_header
        addl    $16,%esp
        test    %eax,%eax
        movl    %eax,%edi
        jne     resL58
        subl    $12,%esp
        leal    -4096(%ebx),%esi
        pushl   %esi
        call    find_exec_base
        addl    $16,%esp
        cmpl    %eax,-16(%ebp)
        movl    %eax,%ebx
        jne     resL69
        test    %esi,%esi
        je      resL69
        resL58:
        leal    -12(%ebp),%esp
        movl    %edi,%eax
        popl    %ebx
        popl    %esi
        popl    %edi
        popl    %ebp
        ret
        """)

        # This is the internal libc function that is equivalent to dlopen and
        # we get it for free without depending on libdl
        self.localfunctions["dlopen"] = ("c", """
        #import "remote", "__libc_dlopen_mode" as "libc_dlopen_mode"
        void *dlopen(char *library)
        {
            void *ret;

            ret = libc_dlopen_mode(library, 0x80000000|0x00001);
            return ret;
        }
        """)

        # We start with using our primitive ELF VA space resolver as dlsym.
        # The reasons for this are that libdl may not be mapped in the target
        # process and its dlsym not available. The primitive resolver will always
        # work so it makes for a good basic case.
        #
        # We can then, at runtime, upgrade to libdl by trying to load libdl.so
        # when ShellServer startup() is called. In this case, these local functions
        # can simply be redefined.

        self.localfunctions["dlsym"] = ("c", """
        #import "local", "resolve" as "resolve"
        void *dlsym(void *handle, char *symbol)
        {
            void *ret;

            ret = resolve(symbol);
            return ret;
        }
        """)


class ppclinuxremoteresolver(linuxremoteresolver):
    def __init__(self, proc="powerpc", version = '2.6'):
        linuxremoteresolver.__init__(self, 'powerpc', version)

    def initLocalFunctions(self):
        linuxremoteresolver.initLocalFunctions(self)

