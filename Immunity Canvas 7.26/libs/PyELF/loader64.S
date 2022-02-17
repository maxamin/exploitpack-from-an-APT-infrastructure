#define PAGE_SIZE   0x1000
#define STACK_SIZE  PG_SIZE * 20

.global main
.global end

main:

/*
class Elf64_Phdr(Struct):
    st = [ 
            ['p_type'   , '<I', 0], 
            ['p_flags'  , '<I', 0], 
            ['p_offset' , '<Q', 0], 
            ['p_vaddr'  , '<Q', 0], 
            ['p_paddr'  , '<Q', 0], 
            ['p_filesz' , '<Q', 0], 
            ['p_memsz'  , '<Q', 0], 
            ['p_align'  , '<Q', 0]
        ]   
    def __init__(self, data = None):
        Struct.__init__(self, data)
*/

/* phdr offsets */
#define P_TYPE      0
#define P_FLAGS     4
#define P_OFFSET    8
#define P_VADDR     16
#define P_PADDR     24
#define P_FILESZ    32
#define P_MEMSZ     40
#define P_ALIGN     48

/* this is a custom entry */
#define P_PROT      56

#define PHDR_SIZE   64

/*
POUVELF format:
+---------------------+
|       e_entry       |
+---------------------+
|       e_phoff       +
+---------------------+ 
|      _dl_phdr       |
+---------------------+
|      _dl_phnum      |
+---------------------+
|      _dl_random     |
+---------------------+
|      hdr_count      |
+---------------------+ 
|      hdr + data     |
+---------------------+
|      ...            |
+---------------------+
|      hdr + data     |
+---------------------+
|      orig phdrs     |
+---------------------+
*/

/* POUVELF offsets */
#define PVELF_E_ENTRY   0
#define PVELF_E_PHOFF   8
#define PVELF_DL_PHDR   16
#define PVELF_DL_PHNUM  24
#define PVELF_DL_RANDOM 32
#define PVELF_HDR_COUNT 40
#define PVELF_HDRS      48

#define PT_LOAD         1
#define PT_NOTE         4
#define PT_TLS          7
#define PT_PVELF_STACK  0x0DEADFED

/* syscall defines */
#define __NR_mmap       9
#define __NR_mprotect   10
#define __NR_munmap     11
#define __NR_brk        12

#define MMAP_FLAGS  50 /* MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS */

#define PAGE_MASK 0xfffffffffffff000

loader64:

    mov pvelf_addr(%rip),%rbp 
    lea PVELF_HDRS(%rbp),%rbp 

    /* PT_PVELF_STACK is always the last header, otherwise we can assume PT_LOAD */
handle_PT_SEGMENT:
    
    cmpl $PT_PVELF_STACK,P_TYPE(%rbp)
    jz handle_PT_PVELF_STACK

    /* brk() */
    mov P_VADDR(%rbp),%rdi
    add P_MEMSZ(%rbp),%rdi
    add $PAGE_SIZE,%rdi
    mov $PAGE_MASK,%rax
    and %rax,%rdi
    mov $__NR_brk,%rax
    syscall

    /* munmap */
    mov P_VADDR(%rbp),%r12
    mov P_MEMSZ(%rbp),%r13
    add $PAGE_SIZE,%r13 /* XXX: kludge to deal with mask align */
    sub $PAGE_SIZE,%r13
    mov $0,%r14

munmap_PT_SEGMENT:

    mov $PAGE_SIZE,%rsi
    mov %r12,%rdi
    add %r14,%rdi
    mov $PAGE_MASK,%rax
    and %rax,%rdi
    mov $__NR_munmap,%rax
    syscall
    add $PAGE_SIZE,%r14
    cmp %r14,%r13
    jge munmap_PT_SEGMENT

mmap_PT_SEGMENT:
    
    xor %r9,%r9
    mov $-1,%r8
    mov $MMAP_FLAGS,%r10
    mov $3,%rdx /* PROT_READ|PROT_WRITE  */
    mov P_MEMSZ(%rbp),%rsi
    add $PAGE_SIZE,%rsi /* XXX: kludge to deal with mask align */
    mov P_VADDR(%rbp),%rdi
    mov $PAGE_MASK,%rax
    and %rax,%rdi
    mov $__NR_mmap,%rax
    syscall

memmove_PT_SEGMENT:

    lea PHDR_SIZE(%rbp),%rsi
    mov P_VADDR(%rbp),%rdi
    mov P_FILESZ(%rbp),%rcx
    repz movsb

mprotect_PT_SEGMENT:

    mov P_PROT(%rbp),%rdx
    mov P_MEMSZ(%rbp),%rsi
    add $PAGE_SIZE,%rsi /* XXX: kludge to deal with mask align */
    mov P_VADDR(%rbp),%rdi
    mov $PAGE_MASK,%rax
    and %rax,%rdi
    mov $__NR_mprotect,%rax
    syscall

    /* point to next POUVELF header */
    add P_FILESZ(%rbp),%rbp
    add $PHDR_SIZE,%rbp

    jmp handle_PT_SEGMENT

handle_PT_PVELF_STACK:
    
    /* reinit the existing stack with ours */
    mov $PAGE_MASK,%rax
    and %rax,%rsp
    add $PAGE_SIZE,%rsp /* XXX: how much should we unwind? */

    lea PHDR_SIZE(%rbp),%rsi
    mov %rsp,%rdi

    /* mask in the correct high bits for our transposed stack */
    sub P_MEMSZ(%rbp),%rdi
    mov $PAGE_MASK,%rax
    and %rax,%rdi

patch_argv_entries:

    /* first iteration skips argc here */
    add $8,%rsi
    mov (%rsi),%rax
    test %rax,%rax
    jz patch_envp_entries
    or %rdi,%rax /* or in the right high bits */
    mov %rax,(%rsi)
    jmp patch_argv_entries

patch_envp_entries:

    add $8,%rsi
    mov (%rsi),%rax
    test %rax,%rax
    jz fixed_stack_pointers
    or %rdi,%rax
    mov %rax,(%rsi)
    jmp patch_envp_entries

fixed_stack_pointers:

    /* move the fixed stack context over */
    lea PHDR_SIZE(%rbp),%rsi
    /* new rsp is set here */
    sub P_MEMSZ(%rbp),%rsp
    mov %rsp,%rdi
    mov P_FILESZ(%rbp),%rcx
    repz movsb

    add P_FILESZ(%rbp),%rbp
    add $PHDR_SIZE,%rbp

    /* at this point rbp is pointing to the original phdrs */
prep_dl_syms:
    
    /* patch up _dl_phnum and _dl_phdr so _libc_setup_tls sets up PT_TLS correctly */
    mov pvelf_addr(%rip),%rsi
    mov PVELF_DL_PHNUM(%rsi),%rdi
    mov PVELF_HDR_COUNT(%rsi),%rcx
    dec %rcx
    mov %rcx,(%rdi)
    mov PVELF_DL_PHDR(%rsi),%rdi
    mov %rbp,(%rdi)
    mov PVELF_DL_RANDOM(%rsi),%rdi
    test %rdi,%rdi
    jz elf_entry /* skip unset _dl_random */
    mov %rsi,(%rdi)
    
elf_entry:

    mov PVELF_E_ENTRY(%rsi),%r10
    xor %rax,%rax /* passed to _libc_start_main */
    xor %rbx,%rbx
    xor %rcx,%rcx
    xor %rdx,%rdx
    xor %rsi,%rsi
    xor %rdi,%rdi

    int3
    jmp *%r10

_data:

pvelf_addr:
.quad 0xcafebabecafebabe

end:
