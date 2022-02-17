# all shared ELF stuff
import ctypes
from struct import pack, unpack, calcsize

class Struct:

    st = []
    
    def __init__(self, data = None):
        self.value = {}
        for i in (range(0, len(self.st))):
            self.value[self.st[i][0]] = self.st[i][2]
        if data is not None:
            self.unpack(data)

    def __getitem__(self, key):
        return self.value[key]

    def __setitem__(self, key, value):
        self.value[key] = value

    def calcsize(self):
        size=0
        for i in (range(0, len(self.st))):
            size += calcsize(self.st[i][1])
        return size

    def pack(self):
        data = ''
        for field in self.st:
            if field[1] != '0s':
                data += pack(field[1], self.value[field[0]])
        return data

    def unpack(self, data):
        pos = 0
        for i in (range(0, len(self.st))):
            npos = pos + calcsize(self.st[i][1])
            self.value[self.st[i][0]] = unpack(self.st[i][1], data[pos:npos])[0]
            pos = npos

    def debugprint(self):
        for i in (range(0, len(self.st))):
            print('%s = %s'%(self.st[i][0], repr(self.value[self.st[i][0]])))
 

Elf32_Addr = ctypes.c_uint
Elf32_Half = ctypes.c_ushort
Elf32_Off = ctypes.c_uint
Elf32_Sword = ctypes.c_int
Elf32_Word = ctypes.c_uint

Elf64_Addr = ctypes.c_ulonglong
Elf64_Half = ctypes.c_ushort
Elf64_SHalf = ctypes.c_short
Elf64_Off = ctypes.c_ulonglong
Elf64_Sword = ctypes.c_int
Elf64_Word = ctypes.c_uint
Elf64_XWord = ctypes.c_ulonglong
Elf64_Sxword = ctypes.c_longlong

PT_NULL         =0
PT_LOAD         =1
PT_DYNAMIC      =2
PT_INTERP       =3
PT_NOTE         =4
PT_SHLIB        =5
PT_PHDR         =6
PT_TLS          =7               # Thread local storage segment 
PT_LOOS         =0x60000000      # OS-specific 
PT_HIOS         =0x6fffffff      # OS-specific 
PT_LOPROC       =0x70000000
PT_HIPROC       =0x7fffffff
PT_GNU_EH_FRAME =0x6474e550

PT_GNU_STACK    =(PT_LOOS + 0x474e551)
PT_PVELF_STACK  =0x0DEADFED

PN_XNUM         =0xffff

# These constants define the different elf file types 
ET_NONE         =0
ET_REL          =1
ET_EXEC         =2
ET_DYN          =3
ET_CORE         =4
ET_LOPROC       =0xff00
ET_HIPROC       =0xffff

# This is the info that is needed to parse the dynamic section of the file 
DT_NULL         =0
DT_NEEDED       =1
DT_PLTRELSZ     =2
DT_PLTGOT       =3
DT_HASH         =4
DT_STRTAB       =5
DT_SYMTAB       =6
DT_RELA         =7
DT_RELASZ       =8
DT_RELAENT      =9
DT_STRSZ        =10
DT_SYMENT       =11
DT_INIT         =12
DT_FINI         =13
DT_SONAME       =14
DT_RPATH        =15
DT_SYMBOLIC     =16
DT_REL          =17
DT_RELSZ        =18
DT_RELENT       =19
DT_PLTREL       =20
DT_DEBUG        =21
DT_TEXTREL      =22
DT_JMPREL       =23
DT_ENCODING     =32
OLD_DT_LOOS     =0x60000000
DT_LOOS         =0x6000000d
DT_HIOS         =0x6ffff000
DT_VALRNGLO     =0x6ffffd00
DT_VALRNGHI     =0x6ffffdff
DT_ADDRRNGLO    =0x6ffffe00
DT_ADDRRNGHI    =0x6ffffeff
DT_VERSYM       =0x6ffffff0
DT_RELACOUNT    =0x6ffffff9
DT_RELCOUNT     =0x6ffffffa
DT_FLAGS_1      =0x6ffffffb
DT_VERDEF       =0x6ffffffc
DT_VERDEFNUM    =0x6ffffffd
DT_VERNEED      =0x6ffffffe
DT_VERNEEDNUM   =0x6fffffff
OLD_DT_HIOS     =0x6fffffff
DT_LOPROC       =0x70000000
DT_HIPROC       =0x7fffffff

# This info is needed when parsing the symbol table 
STB_LOCAL       =0
STB_GLOBAL      =1
STB_WEAK        =2
STB_NUM         =3

STT_NOTYPE      =0
STT_OBJECT      =1
STT_FUNC        =2
STT_SECTION     =3
STT_FILE        =4
STT_COMMON      =5
STT_TLS         =6

def ELF_ST_BIND(x):
    return x >> 4
def ELF_ST_TYPE(x):
    return x & 0xf
def ELF32_ST_BIND(x):
    return ELF_ST_BIND(x)
def ELF32_ST_TYPE(x):
    return ELF_ST_TYPE(x)
def ELF64_ST_BIND(x):
    return ELF_ST_BIND(x)
def ELF64_ST_TYPE(x):
    return ELF_ST_BIND(x)

"""
#define ELF_ST_BIND(x)      ((x) >> 4)
#define ELF_ST_TYPE(x)      (((unsigned int) x) & 0xf)
#define ELF32_ST_BIND(x)    ELF_ST_BIND(x)
#define ELF32_ST_TYPE(x)    ELF_ST_TYPE(x)
#define ELF64_ST_BIND(x)    ELF_ST_BIND(x)
#define ELF64_ST_TYPE(x)    ELF_ST_TYPE(x)
"""

class Elf32_Dyn(Struct):
    st = [
            ['d_tag', '<i', 0],
            ['d_val', '<i', 0] # union with d_ptr
         ]
    def __init__(self, data = None):
        Struct.__init__(self, data)
        self['d_ptr'] = self['d_val']
        self['d_un'] = { 'd_ptr' : self['d_ptr'], 'd_val' : self['d_val'] }

class Elf64_Dyn(Struct):
    st = [
            ['d_tag', '<q', 0],
            ['d_val', '<Q', 0] # unnion with d_ptr
         ]
    def __init__(self, data = None):
        Struct.__init__(self, data)
        self['d_ptr'] = ['d_val']
        self['d_un'] = { 'd_ptr' : self['d_ptr'], 'd_val' : self['d_val'] }

"""
typedef struct dynamic{
  Elf32_Sword d_tag;
  union{
    Elf32_Sword d_val;
    Elf32_Addr  d_ptr;
  } d_un;
} Elf32_Dyn;

typedef struct {
  Elf64_Sxword d_tag;       /* entry tag value */
  union {
    Elf64_Xword d_val;
    Elf64_Addr d_ptr;
  } d_un;
} Elf64_Dyn;
"""

def ELF32_R_SYM(x):
    return x >> 8
def ELF32_R_TYPE(x):
    return x & 0xff

def ELF64_R_SYM(i):
    return i >> 32
def ELF64_R_TYPE(i):
    return i & 0xffffffff

class Elf32_Rel(Struct):
    st = [
            ['r_offset' , '<I', 0],
            ['r_info'   , '<I', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf64_Rel(Struct):
    st = [
            ['r_offset' , '<Q', 0],
            ['r_info'   , '<Q', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf32_Rela(Struct):
    st = [
            ['r_offset' , '<I', 0],
            ['r_info'   , '<I', 0],
            ['r_addend' , '<i', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf64_Rela(Struct):
    st = [
            ['r_offset' , '<Q', 0],
            ['r_info'   , '<Q', 0],
            ['r_addend' , '<q', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf32_Sym(Struct):
    st = [
            ['st_name'  , '<I', 0],
            ['st_value' , '<I', 0],
            ['st_size'  , '<I', 0],
            ['st_info'  , '<B', 0],
            ['st_other' , '<B', 0],
            ['st_shndx' , '<H', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf64_Sym(Struct):
    st = [
            ['st_name'  , '<I', 0],
            ['st_info'  , '<B', 0],
            ['st_other' , '<B', 0],
            ['st_shndx' , '<H', 0],
            ['st_value' , '<Q', 0],
            ['st_size'  , '<Q', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

"""
/* The following are used with relocations */
#define ELF32_R_SYM(x) ((x) >> 8)
#define ELF32_R_TYPE(x) ((x) & 0xff)

#define ELF64_R_SYM(i)          ((i) >> 32)
#define ELF64_R_TYPE(i)         ((i) & 0xffffffff)

typedef struct elf32_rel {
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
} Elf32_Rel;

typedef struct elf64_rel {
  Elf64_Addr r_offset;  /* Location at which to apply the action */
  Elf64_Xword r_info;   /* index and type of relocation */
} Elf64_Rel;

typedef struct elf32_rela{
  Elf32_Addr    r_offset;
  Elf32_Word    r_info;
  Elf32_Sword   r_addend;
} Elf32_Rela;

typedef struct elf64_rela {
  Elf64_Addr r_offset;  /* Location at which to apply the action */
  Elf64_Xword r_info;   /* index and type of relocation */
  Elf64_Sxword r_addend;    /* Constant addend used to compute value */
} Elf64_Rela;

typedef struct elf32_sym{
  Elf32_Word    st_name;
  Elf32_Addr    st_value;
  Elf32_Word    st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half    st_shndx;
} Elf32_Sym;

typedef struct elf64_sym {
  Elf64_Word st_name;       /* Symbol name, index in string tbl */
  unsigned char st_info;    /* Type and binding attributes */
  unsigned char st_other;   /* No defined meaning, 0 */
  Elf64_Half st_shndx;      /* Associated section index */
  Elf64_Addr st_value;      /* Value of the symbol */
  Elf64_Xword st_size;      /* Associated symbol size */
} Elf64_Sym;
"""

EI_NIDENT   =16

class Elf32_Ehdr(Struct):
    st = [
            ['e_ident'      , '%ds' % EI_NIDENT, ''],
            ['e_type'       , '<H', 0],
            ['e_machine'    , '<H', 0],
            ['e_version'    , '<I', 0],
            ['e_entry'      , '<I', 0],
            ['e_phoff'      , '<I', 0],
            ['e_shoff'      , '<I', 0],
            ['e_flags'      , '<I', 0],
            ['e_ehsize'     , '<H', 0],
            ['e_phentsize'  , '<H', 0],
            ['e_phnum'      , '<H', 0],
            ['e_shentsize'  , '<H', 0],
            ['e_shnum'      , '<H', 0],
            ['e_shstrndx'   , '<H', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf64_Ehdr(Struct):
    st = [
            ['e_ident'      , '%ds' % EI_NIDENT, ''],
            ['e_type'       , '<H', 0],
            ['e_machine'    , '<H', 0],
            ['e_version'    , '<I', 0],
            ['e_entry'      , '<Q', 0],
            ['e_phoff'      , '<Q', 0],
            ['e_shoff'      , '<Q', 0],
            ['e_flags'      , '<I', 0],
            ['e_ehsize'     , '<H', 0],
            ['e_phentsize'  , '<H', 0],
            ['e_phnum'      , '<H', 0],
            ['e_shentsize'  , '<H', 0],
            ['e_shnum'      , '<H', 0],
            ['e_shstrndx'   , '<H', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

"""
typedef struct elf32_hdr{
  unsigned char e_ident[EI_NIDENT];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;  /* Entry point */
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
} Elf32_Ehdr;

typedef struct elf64_hdr {
  unsigned char e_ident[EI_NIDENT]; /* ELF "magic number" */
  Elf64_Half e_type;
  Elf64_Half e_machine;
  Elf64_Word e_version;
  Elf64_Addr e_entry;       /* Entry point virtual address */
  Elf64_Off e_phoff;        /* Program header table file offset */
  Elf64_Off e_shoff;        /* Section header table file offset */
  Elf64_Word e_flags;
  Elf64_Half e_ehsize;
  Elf64_Half e_phentsize;
  Elf64_Half e_phnum;
  Elf64_Half e_shentsize;
  Elf64_Half e_shnum;
  Elf64_Half e_shstrndx;
} Elf64_Ehdr;

"""
# These constants define the permissions on sections in the program
# header, p_flags

PF_R        =0x4
PF_W        =0x2
PF_X        =0x1

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

"""
typedef struct elf32_phdr{
  Elf32_Word    p_type;
  Elf32_Off p_offset;
  Elf32_Addr    p_vaddr;
  Elf32_Addr    p_paddr;
  Elf32_Word    p_filesz;
  Elf32_Word    p_memsz;
  Elf32_Word    p_flags;
  Elf32_Word    p_align;
} Elf32_Phdr;

typedef struct elf64_phdr {
  Elf64_Word p_type;
  Elf64_Word p_flags;
  Elf64_Off p_offset;       /* Segment file offset */
  Elf64_Addr p_vaddr;       /* Segment virtual address */
  Elf64_Addr p_paddr;       /* Segment physical address */
  Elf64_Xword p_filesz;     /* Segment size in file */
  Elf64_Xword p_memsz;      /* Segment size in memory */
  Elf64_Xword p_align;      /* Segment alignment, file & memory */
} Elf64_Phdr;
"""

# sh_type
SHT_NULL        =0
SHT_PROGBITS    =1
SHT_SYMTAB      =2
SHT_STRTAB      =3
SHT_RELA        =4
SHT_HASH        =5
SHT_DYNAMIC     =6
SHT_NOTE        =7
SHT_NOBITS      =8
SHT_REL         =9
SHT_SHLIB       =10
SHT_DYNSYM      =11
SHT_NUM         =12
SHT_LOPROC      =0x70000000
SHT_HIPROC      =0x7fffffff
SHT_LOUSER      =0x80000000
SHT_HIUSER      =0xffffffff

# sh_flags
SHF_WRITE       =0x1
SHF_ALLOC       =0x2
SHF_EXECINSTR   =0x4
SHF_MASKPROC    =0xf0000000

# special section indexes
SHN_UNDEF       =0
SHN_LORESERVE   =0xff00
SHN_LOPROC      =0xff00
SHN_HIPROC      =0xff1f
SHN_LOOS        =0xff20
SHN_HIOS        =0xff3f
SHN_ABS         =0xfff1
SHN_COMMON      =0xfff2
SHN_HIRESERVE   =0xffff

class Elf32_Shdr(Struct):
    st = [
            ['sh_name'      , '<I', 0],
            ['sh_type'      , '<I', 0],
            ['sh_flags'     , '<I', 0],
            ['sh_addr'      , '<I', 0],
            ['sh_offset'    , '<I', 0],
            ['sh_size'      , '<I', 0],
            ['sh_link'      , '<I', 0],
            ['sh_info'      , '<I', 0],
            ['sh_addralign' , '<I', 0],
            ['sh_entsize'   , '<I', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

    def debugprint(self):
        if 'section_name' in self.value:
            print 'section name: %s' % self['section_name']
        for i in (range(0, len(self.st))):
            print('%s = %s'%(self.st[i][0], repr(self.value[self.st[i][0]])))

class Elf64_Shdr(Struct):
    st = [
            ['sh_name'      , '<I', 0],
            ['sh_type'      , '<I', 0],
            ['sh_flags'     , '<Q', 0],
            ['sh_addr'      , '<Q', 0],
            ['sh_offset'    , '<Q', 0],
            ['sh_size'      , '<Q', 0],
            ['sh_link'      , '<I', 0],
            ['sh_info'      , '<I', 0],
            ['sh_addralign' , '<Q', 0],
            ['sh_entsize'   , '<Q', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

    def debugprint(self):
        if 'section_name' in self.value:
            print 'section name: %s' % self['section_name']
        for i in (range(0, len(self.st))):
            print('%s = %s'%(self.st[i][0], repr(self.value[self.st[i][0]])))

"""
typedef struct elf32_shdr {
  Elf32_Word    sh_name;
  Elf32_Word    sh_type;
  Elf32_Word    sh_flags;
  Elf32_Addr    sh_addr;
  Elf32_Off sh_offset;
  Elf32_Word    sh_size;
  Elf32_Word    sh_link;
  Elf32_Word    sh_info;
  Elf32_Word    sh_addralign;
  Elf32_Word    sh_entsize;
} Elf32_Shdr;

typedef struct elf64_shdr {
  Elf64_Word sh_name;       /* Section name, index in string tbl */
  Elf64_Word sh_type;       /* Type of section */
  Elf64_Xword sh_flags;     /* Miscellaneous section attributes */
  Elf64_Addr sh_addr;       /* Section virtual addr at execution */
  Elf64_Off sh_offset;      /* Section file offset */
  Elf64_Xword sh_size;      /* Size of section in bytes */
  Elf64_Word sh_link;       /* Index of another section */
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
} Elf64_Shdr;
"""

EI_MAG0         =0 # e_ident[] indexes
EI_MAG1         =1
EI_MAG2         =2
EI_MAG3         =3
EI_CLASS        =4
EI_DATA         =5
EI_VERSION      =6
EI_OSABI        =7
EI_PAD          =8

ELFMAG0         =0x7f # EI_MAG
ELFMAG1         ='E'
ELFMAG2         ='L'
ELFMAG3         ='F'
ELFMAG          ="\177ELF"
SELFMAG         =4

ELFCLASSNONE    =0 # EI_CLASS
ELFCLASS32      =1
ELFCLASS64      =2
ELFCLASSNUM     =3

ELFDATANONE     =0 # e_ident[EI_DATA]
ELFDATA2LSB     =1
ELFDATA2MSB     =2

EV_NONE         =0 # e_version, EI_VERSION
EV_CURRENT      =1
EV_NUM          =2

ELFOSABI_NONE   =0
ELFOSABI_LINUX  =3


# Notes used in ET_CORE. Architectures export some of the arch register sets
# using the corresponding note types via the PTRACE_GETREGSET and
# PTRACE_SETREGSET requests.
NT_PRSTATUS         =1
NT_PRFPREG          =2
NT_PRPSINFO         =3
NT_TASKSTRUCT       =4
NT_AUXV             =6
NT_PRXFPREG         =0x46e62b7f # copied from gdb5.1/include/elf/common.h 
NT_PPC_VMX          =0x100      # PowerPC Altivec/VMX registers 
NT_PPC_SPE          =0x101      # PowerPC SPE/EVR registers 
NT_PPC_VSX          =0x102      # PowerPC VSX registers 
NT_386_TLS          =0x200      # i386 TLS slots (struct user_desc) 
NT_386_IOPERM       =0x201      # x86 io permission bitmap (1=deny) 
NT_X86_XSTATE       =0x202      # x86 extended state using xsave 
NT_S390_HIGH_GPRS   =0x300      # s390 upper register halves 
NT_S390_TIMER       =0x301      # s390 timer register 
NT_S390_TODCMP      =0x302      # s390 TOD clock comparator register 
NT_S390_TODPREG     =0x303      # s390 TOD programmable register 
NT_S390_CTRS        =0x304      # s390 control registers 
NT_S390_PREFIX      =0x305      # s390 prefix register 
NT_S390_LAST_BREAK  =0x306      # s390 breaking event address 

class Elf32_Nhdr(Struct):
    st = [
            ['n_namesz' , '<I', 0],
            ['n_descsz' , '<I', 0],
            ['n_type'   , '<I', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)

class Elf64_Nhdr(Struct):
    st = [
            ['n_namesz' , '<I', 0],
            ['n_descsz' , '<I', 0],
            ['n_type'   , '<I', 0]
        ]
    def __init__(self, data = None):
        Struct.__init__(self, data)


Elf32Structs = {
        'elfhdr'        : Elf32_Ehdr,
        'elf_phdr'      : Elf32_Phdr,
        'elf_shdr'      : Elf32_Shdr,
        'elf_note'      : Elf32_Nhdr,
        'elf_addr_t'    : Elf32_Off,
        'Elf_Half'      : Elf32_Half,
        'elf_sym'       : Elf32_Sym
        }

Elf64Structs = {
        'elfhdr'        : Elf64_Ehdr,
        'elf_phdr'      : Elf64_Phdr,
        'elf_shdr'      : Elf64_Shdr,
        'elf_note'      : Elf64_Nhdr,
        'elf_addr_t'    : Elf64_Off,
        'Elf_Half'      : Elf64_Half,
        'elf_sym'       : Elf64_Sym
        }

"""
/* Note header in a PT_NOTE section */
typedef struct elf32_note {
  Elf32_Word    n_namesz;   /* Name size */
  Elf32_Word    n_descsz;   /* Content size */
  Elf32_Word    n_type;     /* Content type */
} Elf32_Nhdr;

/* Note header in a PT_NOTE section */
typedef struct elf64_note {
  Elf64_Word n_namesz;  /* Name size */
  Elf64_Word n_descsz;  /* Content size */
  Elf64_Word n_type;    /* Content type */
} Elf64_Nhdr;

#ifdef __KERNEL__
#if ELF_CLASS == ELFCLASS32

extern Elf32_Dyn _DYNAMIC [];
#define elfhdr      elf32_hdr
#define elf_phdr    elf32_phdr
#define elf_shdr    elf32_shdr
#define elf_note    elf32_note
#define elf_addr_t  Elf32_Off
#define Elf_Half    Elf32_Half

#else

extern Elf64_Dyn _DYNAMIC [];
#define elfhdr      elf64_hdr
#define elf_phdr    elf64_phdr
#define elf_shdr    elf64_shdr
#define elf_note    elf64_note
#define elf_addr_t  Elf64_Off
#define Elf_Half    Elf64_Half

#endif
"""
# machine types
EM_386      =3  # Intel 80386
EM_X86_64   =62 # AMD x86-64 architecture
