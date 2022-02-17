#define PAGE_SIZE   0x1000
#define STACK_SIZE  PG_SIZE * 20

.global main
.global end

main:

/*
class Elf32_Phdr(Struct):
    st = [ 
            ['p_type'   , '<I', 0], 
            ['p_offset' , '<I', 0], 
            ['p_vaddr'  , '<I', 0], 
            ['p_paddr'  , '<I', 0], 
            ['p_filesz' , '<I', 0], 
            ['p_memsz'  , '<I', 0], 
            ['p_flags'  , '<I', 0], 
            ['p_align'  , '<I', 0]
        ]   
    def __init__(self, data = None):
        Struct.__init__(self, data)
*/

/* phdr offsets */
#define P_TYPE      0
#define P_OFFSET    4
#define P_VADDR     8
#define P_PADDR     12
#define P_FILESZ    16
#define P_MEMSZ     20
#define P_FLAGS     24
#define P_ALIGN     28

/* this is a custom entry */
#define P_PROT      32

#define PHDR_SIZE   36

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
#define PVELF_E_PHOFF   4
#define PVELF_DL_PHDR   8
#define PVELF_DL_PHNUM  12
#define PVELF_DL_RANDOM 16
#define PVELF_HDR_COUNT 20
#define PVELF_HDRS      24

#define PT_LOAD         1
#define PT_NOTE         4
#define PT_TLS          7
#define PT_PVELF_STACK  0x0DEADFED

/* syscall defines */
#define __NR_mmap2      192
#define __NR_mprotect   125
#define __NR_munmap     91
#define __NR_brk        45

#define MMAP_FLAGS      50 /* MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS */

#define PAGE_MASK       0xfffff000

loader32:

    jmp resolve_pvelf_addr1

resolved_pvelf_addr1:

    pop %ebp
    mov (%ebp),%ebp
    lea PVELF_HDRS(%ebp),%ebp

    /* PT_PVELF_STACK is always the last header, otherwise we can assume PT_LOAD */
handle_PT_SEGMENT:
    
    cmpl $PT_PVELF_STACK,P_TYPE(%ebp)
    jz handle_PT_PVELF_STACK

    /* brk() */
    mov P_VADDR(%ebp),%ebx
    add P_MEMSZ(%ebp),%ebx
    add $PAGE_SIZE,%ebx
    mov $PAGE_MASK,%eax
    and %eax,%ebx
    mov $__NR_brk,%eax
    int $0x80
    
    /* munmap */
    mov P_VADDR(%ebp),%edx
    mov P_MEMSZ(%ebp),%esi
    add $PAGE_SIZE,%ecx /* XXX: kludge to deal with mask align */
    sub $PAGE_SIZE,%esi
    mov $0,%edi

munmap_PT_SEGMENT:

    mov $PAGE_SIZE,%ecx
    mov %edx,%ebx
    add %edi,%ebx
    mov $PAGE_MASK,%eax
    and %eax,%ebx
    mov $__NR_munmap,%eax
    int $0x80
    add $PAGE_SIZE,%edi
    cmp %edi,%esi
    jge munmap_PT_SEGMENT

mmap_PT_SEGMENT:
   
    push %ebp
    mov $-1,%edi
    mov $MMAP_FLAGS,%esi
    mov $3,%edx /* PROT_READ|PROT_WRITE */
    mov P_MEMSZ(%ebp),%ecx
    add $PAGE_SIZE,%ecx /* XXX: kludge to deal with mask align */
    mov P_VADDR(%ebp),%ebx
    xor %ebp,%ebp
    mov $PAGE_MASK,%eax
    and %eax,%ebx
    mov $__NR_mmap2,%eax
    int $0x80
    pop %ebp

memmove_PT_SEGMENT:

    lea PHDR_SIZE(%ebp),%esi
    mov P_VADDR(%ebp),%edi
    mov P_FILESZ(%ebp),%ecx
    repz movsb

mprotect_PT_SEGMENT:

    mov P_PROT(%ebp),%edx
    mov P_MEMSZ(%ebp),%ecx
    add $PAGE_SIZE,%ecx /* XXX: kludge to deal with mask align */
    mov P_VADDR(%ebp),%ebx
    mov $PAGE_MASK,%eax
    and %eax,%ebx
    mov $__NR_mprotect,%eax
    int $0x80

    /* point to next POUVELF header */
    add P_FILESZ(%ebp),%ebp
    add $PHDR_SIZE,%ebp

    jmp handle_PT_SEGMENT

handle_PT_PVELF_STACK:
    
    /* reinit the existing stack with ours */
    mov $PAGE_MASK,%eax
    and %eax,%esp
    add $PAGE_SIZE,%esp /* XXX: how much should we unwind? */

    lea PHDR_SIZE(%ebp),%esi
    mov %esp,%edi

    /* mask in the correct high bits for our transposed stack */
    sub P_MEMSZ(%ebp),%edi
    mov $PAGE_MASK,%eax
    and %eax,%edi

patch_argv_entries:

    /* first iteration skips argc here */
    add $4,%esi
    mov (%esi),%eax
    test %eax,%eax
    jz patch_envp_entries
    or %edi,%eax /* or in the right high bits */
    mov %eax,(%esi)
    jmp patch_argv_entries

patch_envp_entries:

    add $4,%esi
    mov (%esi),%eax
    test %eax,%eax
    jz fixed_stack_pointers
    or %edi,%eax
    mov %eax,(%esi)
    jmp patch_envp_entries

fixed_stack_pointers:

    /* move the fixed stack context over */
    lea PHDR_SIZE(%ebp),%esi
    /* new rsp is set here */
    sub P_MEMSZ(%ebp),%esp
    mov %esp,%edi
    mov P_FILESZ(%ebp),%ecx
    repz movsb

    add P_FILESZ(%ebp),%ebp
    add $PHDR_SIZE,%ebp

    /* at this point rbp is pointing to the original phdrs */
prep_dl_syms:

    jmp resolve_pvelf_addr2

resolved_pvelf_addr2:

    pop %ebp
    mov (%ebp),%esi    

    /* patch up _dl_phnum and _dl_phdr so _libc_setup_tls sets up PT_TLS correctly */
    mov PVELF_DL_PHNUM(%esi),%edi
    mov PVELF_HDR_COUNT(%esi),%ecx
    dec %ecx
    mov %ecx,(%edi)
    mov PVELF_DL_PHDR(%esi),%edi
    mov %ebp,(%edi)
    mov PVELF_DL_RANDOM(%esi),%edi
    test %edi,%edi
    jz elf_entry /* skip unset _dl_random */
    mov %esi,(%edi)
    
elf_entry:

    mov PVELF_E_ENTRY(%esi),%ebp
    xor %eax,%eax /* passed to _libc_start_main */
    xor %ebx,%ebx
    xor %ecx,%ecx
    xor %edx,%edx
    xor %esi,%esi
    xor %edi,%edi

    int3
    jmp *%ebp

_data:

/* XXX */
resolve_pvelf_addr1:
    call resolved_pvelf_addr1
.long 0xcafebabe
resolve_pvelf_addr2:
    call resolved_pvelf_addr2
.long 0xcafebabe

end:
