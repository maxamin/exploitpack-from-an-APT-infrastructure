#! /usr/bin/env python

""" ELF ABI Constants and string Descriptions """

__revision__ = "0.1"


ELF_MAGIC	= "\x7f" + "ELF"
EI_NIDENT	= "16"

ELFCLASS32  	= 1
ELFCLASS64      = 2

ELFDATANONE     = 0
ELFDATA2LSB     = 1
ELFDATA2MSB     = 2

EV_CURRENT      = 1

ET_NONE         = 0
ET_REL          = 1
ET_EXEC         = 2
ET_DYN          = 3
ET_CORE         = 4

EM_NONE         = 0
EM_M32          = 1
EM_SPARC        = 2
EM_386          = 3
EM_68K          = 4
EM_88K          = 5
EM_860          = 7
EM_MIPS         = 8
EM_MIPS_RS3_LE  = 10
EM_PARISC       = 15
EM_SPARC32PLUS  = 18
EM_PPC          = 20
EM_PPC64        = 21
EM_ARM          = 40
EM_SPARCV9      = 43
EM_IA_64        = 50
EM_X86_64       = 62
EM_VAX          = 75


ELFOSABI_SYSV    = 0
ELFOSABI_HPUX    = 1
ELFOSABI_NETBSD  = 2
ELFOSABI_LINUX   = 3
ELFOSABI_SOLARIS = 6
ELFOSABI_AIX     = 7
ELFOSABI_IRIX    = 8
ELFOSABI_FREEBSD = 9
ELFOSABI_TRU64   = 10
ELFOSABI_MODESTO = 11
ELFOSABI_OPENBSD = 12
ELFOSABI_ARM     = 97

# e_flags
EF_CPU32            = 0x00810000
EF_SPARC_32PLUS     = 0x000100
EF_SPARC_SUN_US1    = 0x000200
EF_SPARC_HAL_R1     = 0x000400
EF_SPARC_SUN_US3    = 0x000800
EF_MIPS_NOREORDER   = 1
EF_MIPS_PIC         = 2
EF_MIPS_CPIC        = 4
EF_MIPS_XGOT        = 8
EF_MIPS_64BIT_WHIRL = 16
EF_MIPS_ABI2        = 32
EF_MIPS_ABI_ON32    = 64
EF_MIPS_ARCH        = 0xf0000000
EF_MIPS_ARCH_1      = 0x00000000
EF_MIPS_ARCH_2      = 0x10000000
EF_MIPS_ARCH_3      = 0x20000000
EF_MIPS_ARCH_4      = 0x30000000
EF_MIPS_ARCH_5      = 0x40000000
EF_MIPS_ARCH_32     = 0x60000000
EF_MIPS_ARCH_64     = 0x70000000
EF_PARISC_TRAPNIL   = 0x00010000
EF_PARISC_EXT       = 0x00020000
EF_PARISC_LSB       = 0x00040000
EF_PARISC_WIDE      = 0x00080000
EF_PARISC_NO_KABP   = 0x00100000
EF_PARISC_LAZYSWAP  = 0x00400000
EF_PARISC_ARCH      = 0x0000ffff
EFA_PARISC_1_0      = 0x020b
EFA_PARISC_1_1      = 0x0210
EFA_PARISC_2_0      = 0x0214
EF_ALPHA_32BIT      = 1
EF_PPC_EMB          = 0x80000000
EF_IA_64_MASKOS     = 0x0000000f
EF_IA_64_ABI64      = 0x00000010
EF_IA_64_ARCH       = 0xff000000
EF_ARM_RELEXEC      = 0x01
EF_ARM_HASENTRY     = 0x02
EF_ARM_INTERWORK    = 0x04
EF_ARM_APCS_26      = 0x08
EF_ARM_APCS_FLOAT   = 0x10
EF_ARM_PIC          = 0x20
EF_ARM_ALIGN8       = 0x40
EF_ARM_NEW_ABI      = 0x80
EF_ARM_OLD_ABI      = 0x100
EF_ARM_SYMSARESORTED = 0x04
EF_ARM_DYNSYMSUSESEGIDX = 0x08
EF_ARM_MAPSYMSFIRST = 0x10
EF_ARM_EABIMASK     = 0XFF000000
EF_ARM_EABI_UNKNOWN = 0x00000000
EF_ARM_EABI_VER1    = 0x01000000
EF_ARM_EABI_VER2    = 0x02000000


E32_HALF    = "H" # unsigned short (uint16_t)
E32_WORD    = "I" # unsigned int   (uint32_t)
E32_SWORD   = "i" #   signed int   (int32_t)
E32_ADDR    = "I" # unsigned int   (uint32_t)
E32_OFF     = "I" # unsigned int   (unit32_t)
E32_SECTION = "H"
U_CHAR      = "B"

E64_HALF    = "H"
E64_WORD    = "I"
E64_SWORD   = "i"
E64_SXWORD  = "Q"
E64_XWORD   = "Q"
E64_ADDR    = "Q"
E64_OFF     = "Q"
E64_SECTION = "H"

# Elf types

ETYPE = {
    ELFCLASS32: {
        'Half': "H",
        'Word': "I",
        'Sword': "i",
        'Xword': "Q",
        'Sxword': "q",
        'Addr': "I",
        'Off': "I",
        'Section': "H"
    },
    ELFCLASS64: {
        'Half': "H",
        'Word': "I",
        'Sword': "i",
        'Xword': "Q",
        'Sxword': "q",
        'Addr': "Q",
        'Off': "Q",
        'Section': "H"
    }
}


ELFDOC = {}
ELFDOC['CLASS'] = {ELFCLASS32: "32-bit objects", ELFCLASS64:"64-bit objects"}
ELFDOC['DATA'] = {ELFDATA2LSB: "little endian", ELFDATA2MSB: "big endian"}
ELFDOC['OSABI'] = {
    ELFOSABI_SYSV: "UNIX System V ABI",
    ELFOSABI_HPUX: "HP-UX",
    ELFOSABI_NETBSD: "NetBSD",
    ELFOSABI_LINUX: "Linux",
    ELFOSABI_SOLARIS: "Sun Solaris",
    ELFOSABI_AIX: "IBM AIX",
    ELFOSABI_IRIX: "SGI Irix",
    ELFOSABI_FREEBSD: "FreeBSD",
    ELFOSABI_TRU64: "Compaq TRU64 UNIX",
    ELFOSABI_MODESTO: "Novell Modesto",
    ELFOSABI_OPENBSD: "OpenBSD",
    ELFOSABI_ARM: "ARM",
}
ELFDOC['MACHINE'] = {
    EM_SPARC: "SUN SPARC",
    EM_386: "Intel 80386",
    EM_68K: "Motorola m68k family",
    EM_88K: "Motorola m88k family",
    EM_860: "Intel 80860",
    EM_MIPS: "MIPS R3000 big-endian",
    EM_MIPS_RS3_LE: "MIPS R3000 little-endian",
    EM_PARISC: "HPPA",
    EM_SPARC32PLUS: "SUN SPARC v8plus",
    EM_PPC: "PowerPC",
    EM_PPC64: "PowerPC 64-bit",
    EM_ARM: "ARM",
    EM_SPARCV9: "SUN SPARC v9 64-bit",
    EM_IA_64: "Intel Merced",
    EM_X86_64: "AMD x86-64",
    EM_VAX: "Digital VAX",
}
ELFDOC['FLAGS'] = {
    EF_SPARC_32PLUS: "generic V8+ features",
    EF_SPARC_SUN_US1: "Sun UltraSPARC1 extensions",
    EF_SPARC_HAL_R1: "HAL R1 extensions",
    EF_SPARC_SUN_US3: "Sun UltraSPARCIII extensions",
    EF_MIPS_NOREORDER: "A .noreorder directive was used",
    EF_MIPS_PIC: "Contains PIC code",
    EF_MIPS_CPIC: "Uses PIC calling sequence",
    EF_MIPS_ARCH: "MIPS architecture level",
    EF_MIPS_ARCH_1: "-mips1 code.",
    EF_MIPS_ARCH_2: "-mips2 code.",
    EF_MIPS_ARCH_3: "-mips3 code.",
    EF_MIPS_ARCH_4: "-mips4 code.",
    EF_MIPS_ARCH_5: "-mips5 code.",
    EF_MIPS_ARCH_32: "MIPS32 code.",
    EF_MIPS_ARCH_64: "MIPS64 code.",
    EF_PARISC_TRAPNIL: "Trap nil pointer dereference.",
    EF_PARISC_EXT: "Program uses arch. extensions.",
    EF_PARISC_LSB: "Program expects little endian.",
    EF_PARISC_WIDE: "Program expects wide mode.",
    EF_PARISC_NO_KABP: "No kernel assisted branch prediction",
    EF_PARISC_LAZYSWAP: "Allow lazy swapping.",
    EF_PARISC_ARCH: "Architecture version.",
    EFA_PARISC_1_0: "PA-RISC 1.0 big-endian.",
    EFA_PARISC_1_1: "PA-RISC 1.1 big-endian.",
    EFA_PARISC_2_0: "PA-RISC 2.0 big-endian.",
    EF_ALPHA_32BIT: "All addresses must be < 2GB.",
    EF_PPC_EMB: "PowerPC embedded flag",
    EF_IA_64_MASKOS: "os-specific flags",
    EF_IA_64_ABI64: "64-bit ABI",
    EF_IA_64_ARCH: "arch. version mask",
    EF_ARM_ALIGN8: "8-bit structure alignment is in use",
}

PT_NULL	   = 0
PT_LOAD    = 1
PT_DYNAMIC = 2
PT_INTERP  = 3
PT_NOTE	   = 4
PT_SHLIB   = 5
PT_PHDR	   = 6

PF_X       = (1 << 0)        # Segment is executable
PF_W       = (1 << 1)        # Segment is writable
PF_R       = (1 << 2)        # Segment is readable

DT_NULL            = 0
DT_NEEDED          = 1
DT_PLTRELSZ        = 2
DT_PLTGOT          = 3
DT_HASH            = 4
DT_STRTAB          = 5
DT_SYMTAB          = 6
DT_RELA            = 7
DT_RELASZ          = 8
DT_RELAENT         = 9
DT_STRSZ           = 10
DT_SYMENT          = 11
DT_INIT            = 12
DT_FINI            = 13
DT_SONAME          = 14
DT_RPATH           = 15
DT_SYMBOLIC        = 16
DT_REL             = 17
DT_RELSZ           = 18
DT_RELENT          = 19
DT_PLTREL          = 20
DT_DEBUG           = 21
DT_TEXTREL         = 22
DT_JMPREL          = 23
DT_BIND_NOW        = 24
DT_INIT_ARRAY      = 25
DT_FINI_ARRAY      = 26
DT_INIT_ARRAYSZ    = 27
DT_FINI_ARRAYSZ    = 28
DT_RUNPATH         = 29
DT_FLAGS           = 30
DT_ENCODING        = 32
DT_PREINIT_ARRAY   = 32
DT_PREINIT_ARRAYSZ = 33
DT_NUM             = 34

SHT_NULL          = 0
SHT_PROGBITS      = 1
SHT_SYMTAB        = 2
SHT_STRTAB        = 3
SHT_RELA          = 4
SHT_HASH          = 5
SHT_DYNAMIC       = 6
SHT_NOTE          = 7
SHT_NOBITS        = 8
SHT_REL           = 9
SHT_SHLIB         = 10
SHT_DYNSYM        = 11
SHT_INIT_ARRAY    = 14
SHT_FINI_ARRAY    = 15
SHT_PREINIT_ARRAY = 16
SHT_GROUP         = 17
SHT_SYMTAB_SHNDX  = 18
SHT_NUM           = 19

def ELF32_R_SYM(r_info):
    """extract the sym info from the Elf32_Rel.r_info field"""
    return ((r_info) >> 8)

def ELF32_R_TYPE(r_info):
    """extract the type info from the Elf32_Rel.r_info field"""
    return ((r_info) & 0xff)

def ELF32_R_INFO(elf_sym, elf_type):
    """instert sym+type information held in the Elf32_Rel.r_info field"""
    return ((elf_sym << 8) + ((elf_type) & 0xff))

R_386_NONE     = 0
R_386_32       = 1
R_386_PC32     = 2
R_386_PLT32    = 4
R_386_COPY     = 5
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8
R_386_GOTOFF   = 9
R_386_GOTPC    = 10
R_386_NUM      = 11

STT_NOTYPE    =  0
STT_OBJECT    =  1
STT_FUNC      =  2
STT_SECTION   =  3
STT_FILE      =  4
STT_COMMON    =  5
STT_NUM       =  6
STT_LOOS      =  10
STT_HIOS      =  12
STT_LOPROC    =  13
STT_HIPROC    =  15


def strFromTbl(ndx, tbl):
    """ take a string for a table """
    offset = tbl[ndx:].find("\0")
    if offset == -1:
        return ""
    return tbl[ndx:ndx + offset]

