#! /usr/bin/env python
from __future__ import with_statement
"""
makeexe.py
Copywrite: Dave Aitel, 2003
"""

NOTES="""
See this article for information on create a minimal ELF file on Linux
http://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
  BITS 32

                org     0x08048000

  ehdr:                                                 ; Elf32_Ehdr
                db      0x7F, "ELF", 1, 1, 1            ;   e_ident
        times 9 db      0
                dw      2                               ;   e_type
                dw      3                               ;   e_machine
                dd      1                               ;   e_version
                dd      _start                          ;   e_entry
                dd      phdr - $$                       ;   e_phoff
                dd      0                               ;   e_shoff
                dd      0                               ;   e_flags
                dw      ehdrsize                        ;   e_ehsize
                dw      phdrsize                        ;   e_phentsize
                dw      1                               ;   e_phnum
                dw      0                               ;   e_shentsize
                dw      0                               ;   e_shnum
                dw      0                               ;   e_shstrndx

  ehdrsize      equ     $ - ehdr

  phdr:                                                 ; Elf32_Phdr
                dd      1                               ;   p_type
                dd      0                               ;   p_offset
                dd      $$                              ;   p_vaddr
                dd      $$                              ;   p_paddr
                dd      filesize                        ;   p_filesz
                dd      filesize                        ;   p_memsz
                dd      5                               ;   p_flags
                dd      0x1000                          ;   p_align

  phdrsize      equ     $ - phdr

  _start:

  ; your program here

  filesize      equ     $ - $$
"""

#for 2.5 Python users


import sys
from mosdefutils import *
from binfmt import elf
from binfmt.elf_const import *
from binfmt import macho

#returns a binary version of the string
def binstring(instring):
    result=""
    #erase all whitespace
    tmp=instring.replace(" ","")
    tmp=tmp.replace("\n","")
    tmp=tmp.replace("\t","")
    tmp=tmp.replace("\r","")
    tmp=tmp.replace(",","")


    if len(tmp) % 2 != 0:
        print "tried to binstring something of illegal length: %d: *%s*"%(len(tmp),prettyprint(tmp))
        return ""

    while tmp!="":
        two=tmp[:2]
        #account for 0x and \x stuff
        if two!="0x" and two!="\\x":
            result+=chr(int(two,16))
        tmp=tmp[2:]

    return result

__ELF_proc_data = {
    #proc    machine   entry      class data  align    flags
    'X86':   ["386",   0x08048000, 32, "LSB", 0x1000,  0],
    'X64':   ["X86_64",0x400000,   64, "LSB", 0x200000,0],
    'SPARC': ["SPARC", 0x10000,    32, "MSB", 0x10000, 0],
    'PPC':   ["PPC",   0x10000000, 32, "MSB", 0x10000, 0],
    'ARM':   ["ARM",   0x00008000, 32, "LSB", 0x8000,  EF_ARM_HASENTRY],
    'ARMEL': ["ARM",   0x00008000, 32, "LSB", 0x8000,  EF_ARM_HASENTRY],
    'MIPS':  ["MIPS",  0x0e000000, 32, "MSB", 0x4000,  EF_MIPS_ABI2|EF_MIPS_ARCH_3],
    'MIPSEL':["MIPS",  0x00400000, 32, "LSB", 0x1000,  EF_MIPS_NOREORDER|EF_MIPS_PIC|EF_MIPS_CPIC| \
                                                       EF_MIPS_ARCH_2|EF_MIPS_ARCH_5],
}

__ELF_endian = {'LSB': 0, 'MSB': 1}

def get_proc_data(proc):
    # This needs to change
    if proc == 'ARM9': proc = 'ARMEL'

    assert __ELF_proc_data.has_key(proc)

    p = {}
    p['machine'] = getattr(elf, "EM_" + __ELF_proc_data[proc][0])
    p['entry'] = __ELF_proc_data[proc][1]
    p['class'] = getattr(elf, "ELFCLASS%d" % __ELF_proc_data[proc][2])
    p['data'] = getattr(elf, "ELFDATA2" + __ELF_proc_data[proc][3])
    p['align'] = __ELF_proc_data[proc][4]
    p['flags'] = __ELF_proc_data[proc][5]
    p['abi'] = elf.ELFOSABI_SYSV
    try:
        p['abi'] = getattr(elf, "ELFOSABI_" + __ELF_proc_data[proc][0])
    except AttributeError:
        pass
    return p

def elf_ident(pdata):
    e_ident  = elf.ELF_MAGIC + chr(pdata['class']) + chr(pdata['data'])
    e_ident += chr(elf.EV_CURRENT) + chr(pdata['abi']) # ABIVERSION
    e_ident += "\x00" * (int(elf.EI_NIDENT) - (len(e_ident))) # PADDING
    return e_ident

def makeELF(data, filename="", proc="X86"):
    """
    Makes a ELF executable from the data bytes (shellcode) in "data"
    Should be close to optimally small
    e_entry is where our shellcode will start, if you want to debug it with gdb
    """
    pdata = get_proc_data(proc)

    if proc == "X64":
        e = elf.Elf64_Ehdr(config = (pdata['class'], pdata['data']))
        e.e_ident     = elf_ident(pdata)
        e.e_type      = elf.ET_EXEC
        e.e_machine   = pdata['machine']
        e.e_version   = elf.EV_CURRENT
        e.e_phoff     = 0x40
        e.e_shoff     = 0x0
        e.e_flags     = pdata['flags']
        e.e_ehsize    = elf.Elf64_Ehdr.size
        e.e_phentsize = elf.Elf64_Phdr.size
        e.e_phnum     = 0x1
        e.e_shentsize = 0x0
        e.e_shnum     = 0x0
        e.e_shstrndx  = 0x0
        e.offset      = 0
        e.ei_class    = pdata['class']
        e.ei_data     = pdata['data']
        p = elf.Elf64_Phdr(config = e.getconf())

        # p.offset   = e.e_phoff
        p.offset   = 0x0
        p.p_type   = elf.PT_LOAD
        p.p_offset = 0x0
        p.p_vaddr  = pdata['entry']
        p.p_paddr  = pdata['entry']
        p.p_filesz = elf.Elf64_Ehdr.size + elf.Elf64_Phdr.size + len(data)
        # XXX imo p_memsz should be p_filesz rounded up to p_align
        p.p_memsz  = p.p_filesz
        #p.p_memsz = (p.p_filesz & ~(pdata['align'] - 1)) + pdata['align']
        p.p_flags  = elf.PF_X | elf.PF_W | elf.PF_R # read, write and execute!
        p.p_align  = pdata['align']

        # Entry Point
        e.e_entry     = pdata['entry'] + e.size + p.size

    else:
        e=elf.Elf32_Ehdr(config = (pdata['class'], pdata['data']))
        e.e_ident     = elf_ident(pdata)
        e.e_type      = elf.ET_EXEC
        e.e_machine   = pdata['machine']
        e.e_version   = elf.EV_CURRENT
        e.e_entry     = pdata['entry'] + 0x54
        e.e_phoff     = 0x34
        e.e_shoff     = 0x0
        e.e_flags     = pdata['flags']
        e.e_ehsize    = elf.Elf32_Ehdr.size
        e.e_phentsize = elf.Elf32_Phdr.size
        e.e_phnum     = 0x1
        e.e_shentsize = 0x0
        e.e_shnum     = 0x0
        e.e_shstrndx  = 0x0
        e.offset      = 0
        e.ei_class    = pdata['class']
        e.ei_data     = pdata['data']
        p = elf.Elf32_Phdr(config = e.getconf())
        p.offset   = e.e_phoff
        p.p_type   = elf.PT_LOAD
        p.p_offset = 0x0
        p.p_vaddr  = pdata['entry']
        p.p_paddr  = pdata['entry']
        p.p_filesz = elf.Elf32_Ehdr.size + elf.Elf32_Phdr.size + len(data)
        # XXX imo p_memsz should be p_filesz rounded up to p_align
        p.p_memsz  = p.p_filesz
        #p.p_memsz = (p.p_filesz & ~(pdata['align'] - 1)) + pdata['align']
        p.p_flags  = elf.PF_X | elf.PF_W | elf.PF_R # read, write and execute!
        p.p_align  = pdata['align']

    if filename != "":
        try:
            f = open(filename, "w")
            p.fd = e.fd = f
            e.write()
            p.write()
            f.write(data)
            import os
            os.chmod(filename, 0775)
            f.close()
        except:
            print "Couldn't open, write or chmod outfile"
    return e.raw() + p.raw() + data


def makelinuxexe(data, filename="", proc="X86"):
    if proc == 'X86':
        return make_dyn_elf32(data, filename = filename)
    elif proc == 'X64':
        return make_dyn_elf64(data, filename = filename)
    else:
        return makeELF(data, filename=filename, proc=proc)

def makelinuxexeSPARC(data, filename=""):
    return makelinuxexe(data, filename=filename, proc="SPARC")

def makesolarisexe(data, filename="", proc="SPARC"):
    return makeELF(data, filename=filename, proc=proc)

def makeirixexe(data, filename="", proc="MIPS"):
    return makeELF(data, filename=filename, proc=proc)

def makenetbsdexe(data, filename=""):
    """
    Makes a netbsd executable from the data bytes (shellcode) in "data"
    Should be close to optimally small
    0x???????? is where our shellcode will start, if you want to debug it with gdb
    """
    tmp = ""
    tmp += binstring("7f 45 4c 46 01 01 01 00 00 00 00 00 00 00 00 00")
    tmp += binstring("02 00 03 00 01 00 00 00")
    tmp += binstring("54 80 04 08")
    tmp += binstring("34 00 00 00")
    tmp += binstring("00"*8)
    tmp += binstring("34 00 20 00 01 00")
    tmp += binstring("00 00")
    tmp += binstring("00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08")
    tmp += binstring("00 80 04 08")
    tmp += intel_order(0x54+len(data))*2
    tmp += binstring("07 00 00 00 00 10 00 00")
    tmp += data
    if filename!="":
        try:
            fd = open(filename,"w")
            fd.write(tmp)
            fd.close()
            import os
            os.chmod(filename, 0775)
        except:
            print "Couldn't open, write or chmod outfile3"
    return tmp

def makeopenbsdexe(data, filename=""):
    """
    Makes a openbsd executable from the data bytes (shellcode) in "data"
    Should be close to optimally small
    0x???????? is where our shellcode will start, if you want to debug it with gdb
    """
    tmp = ""

def makefreebsdexe(data, filename=""):
    """
    Makes a openbsd executable from the data bytes (shellcode) in "data"
    Should be close to optimally small
    0x???????? is where our shellcode will start, if you want to debug it with gdb
    """
    tmp = ""
    tmp += binstring("7f 45 4c 46 01 01 01 09 00 00 00 00 00 00 00 00")
    tmp += binstring("02 00 03 00 01 00 00 00")
    tmp += binstring("54 80 04 08")
    tmp += binstring("34 00 00 00")
    tmp += binstring("00"*8)
    tmp += binstring("34 00 20 00 01 00 00 00")
    tmp += binstring("00 00 00 00 01 00 00 00 00 00 00 00 00 80 04 08")
    tmp += binstring("00 80 04 08")
    tmp += intel_order(57+len(data))*2
    tmp += binstring("07 00 00 00 00 10 00 00")
    tmp += data
    if filename!="":
        try:
            fd=open(filename,"w")
            fd.write(tmp)
            fd.close()
            import os
            os.chmod(filename, 0775)
        except:
            print "Couldn't open, write or chmod outfile3"
    return tmp


def makewin32exe(data, filename="", imports=None, exports=None):
    """
    Make a windows executable from the data bytes
    """
    # XXX: fix for single default var instantiation
    if not imports:
        imports = []
    if not exports:
        exports = []

    out="MZ"
    out+="\x00"*(0x3c-2)
    out+=intel_order(0x3c+4)
    #now the start of the pe header
    out+="PE\x00\x00"
    machine = {}
    machine["x86"]="\x01\x4c"
    #machine
    out+=machine["x86"]
    #number of sections
    sections=3
    out+=halfword2bstr(sections)
    #Time Date Stamp
    out+="\x00"*4
    #Pointer To Symbol Table
    out+="\x00"*4 #0 for none is present
    #Number of Symbols
    out+="\x00"*4 #0 for none is present
    #Size of Optional Header
    optionalheader=""
    out+=halfword2bstr(len(optionalheader)) # XXX wtf is optionalheader?
    #Charactaristics
    STRIPPED=0x0001
    EXECUTABLE=0x0002
    charactaristics=0
    charactaristics|=STRIPPED
    charactaristics|=EXECUTABLE
    out+=halfword2bstr(charactaristics)

    if filename:
        open(filename, 'wb').write(out)

    return out

makewindowsexe=makewin32exe

def align_pow2(number, multiple):
    """
    Align number to multiple (which must be a power of 2).
    """
    return (number + (multiple-1)) & ~(multiple-1)


def make_dyn_elf32(data, filename=''):
    devlog('makeexe', 'data: %s bytes filename: %s proc: x86 ELF32 DYN' % (len(data), filename))

    import libs.PyELF.Elf as ELF
    base32 = 0x8048000

    # string table
    string_table  = '\x00'
    string_table += 'libc.so.6'
    string_table += '\x00'

    # hash table

    hash_table  = '\x01\x00\x00\x00'
    hash_table += '\x01\x00\x00\x00'
    hash_table += '\x00\x00\x00\x00'
    hash_table += '\x00\x00\x00\x00'

    # symbol table (empty)
    symbol_table = '\x00'*16

    # reloc table (empty)
    reloc_table  = '\x00'*8

    interpreter     = '/lib/ld-linux.so.2'
    interpreter    += '\x00'
    interpreter_len = len(interpreter)

    header = ELF.Elf32_Ehdr()

    header['e_ident']     = '\x7fELF\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    header['e_type']      = 2       # ELF_EXEC
    header['e_machine']   = 3       # EM_386
    header['e_version']   = 1
    header['e_entry']     = 0 # ADDRESS of code from start of file, PATCH IN
    header['e_phoff']     = header.calcsize()
    header['e_shoff']     = 0
    header['e_flags']     = 0
    header['e_ehsize']    = header.calcsize()
    header['e_phentsize'] = 32
    header['e_phnum']     = 3
    header['e_shentsize'] = 0
    header['e_shnum']     = 0
    header['e_shstrndx']  = 0

    # End of elf header

    # Program header

    # PT_INTERP section
    phdr1             = ELF.Elf32_Phdr()
    phdr1['p_type']   = ELF.PT_INTERP
    phdr1['p_offset'] = 0 # OFFSET of interpreter_name, PATCH IN
    phdr1['p_vaddr']  = 0 # ADDRESS of interpreter_name, PATCH IN
    phdr1['p_paddr']  = 0
    phdr1['p_filesz'] = interpreter_len
    phdr1['p_memsz']  = interpreter_len
    phdr1['p_flags']  = 4 # RO ACCESS
    phdr1['p_align']  = 1


    # PT_DYNAMIC section
    phdr2             = ELF.Elf32_Phdr()
    phdr2['p_type']   = ELF.PT_DYNAMIC
    phdr2['p_offset'] = 0 # OFFSET of dynamic, PATCH IN
    phdr2['p_vaddr']  = 0 # ADDRESS of dynamic, PATCH IN
    phdr2['p_paddr']  = 0
    phdr2['p_filesz'] = 80 # 10 dynamic entries
    phdr2['p_memsz']  = 80
    phdr2['p_flags']  = 4 # RO ACCESS
    phdr2['p_align']  = 4

    # PT_LOAD section
    phdr3             = ELF.Elf32_Phdr()
    phdr3['p_type']   = ELF.PT_LOAD
    phdr3['p_offset'] = 0
    phdr3['p_vaddr']  = base32
    phdr3['p_paddr']  = 0
    phdr3['p_filesz'] = 0 # SIZE-OF-FILE, PATCH IN
    phdr3['p_memsz']  = 0 # SIZE-OF-FILE, PATCH IN
    phdr3['p_flags']  = 7 # RWX ACCESS
    phdr3['p_align']  = 0x1000


    # ALIGN 4
    # Dynamic section

    dyn1            = ELF.Elf32_Dyn()
    dyn1['d_tag']   = ELF.DT_NEEDED
    dyn1['d_val']   = 1 # OFFSET of "libc.so.6" inside string_table

    dyn2            = ELF.Elf32_Dyn()
    dyn2['d_tag']   = ELF.DT_STRTAB
    dyn2['d_val']   = 0 # ADDRESS of string_table, PATCH IN

    dyn3            = ELF.Elf32_Dyn()
    dyn3['d_tag']   = ELF.DT_STRSZ
    dyn3['d_val']   = len(string_table)

    dyn4            = ELF.Elf32_Dyn()
    dyn4['d_tag']   = ELF.DT_HASH
    dyn4['d_val']   = 0 # ADDRESS of hash_table, PATCH IN

    dyn5            = ELF.Elf32_Dyn()
    dyn5['d_tag']   = ELF.DT_SYMTAB
    dyn5['d_val']   = 0 # ADDRESS of symbol_table, PATCH IN

    dyn6            = ELF.Elf32_Dyn()
    dyn6['d_tag']   = ELF.DT_SYMENT
    dyn6['d_val']   = 16

    dyn7            = ELF.Elf32_Dyn()
    dyn7['d_tag']   = ELF.DT_REL
    dyn7['d_val']   = 0 # ADDRESS of reloc_table PATCH IN

    dyn8            = ELF.Elf32_Dyn()
    dyn8['d_tag']   = ELF.DT_RELSZ
    dyn8['d_val']   = 0

    dyn9            = ELF.Elf32_Dyn()
    dyn9['d_tag']   = ELF.DT_RELENT
    dyn9['d_val']   = 8

    dyn10           = ELF.Elf32_Dyn()
    dyn10['d_tag']  = 0x0
    dyn10['d_val']  = 0x0


    # PATCH IN the remaining addresses

    size1 = len(header.pack() + phdr1.pack() + phdr2.pack() + phdr3.pack())

    res = align_pow2(size1, 4) - size1

    if res > 0:
        align1 ='\x00'*res
    else:
        align1 = ''

    total_len = len(str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(),
                                  align1,
                                  dyn1.pack(), dyn2.pack(), dyn3.pack(), dyn4.pack(), dyn5.pack(),
                                  dyn6.pack(), dyn7.pack(), dyn8.pack(), dyn9.pack(), dyn10.pack(),
                                  hash_table,
                                  string_table,
                                  symbol_table,
                                  reloc_table,
                                  interpreter,
                                  data)))

    header['e_entry'] = base32 + total_len - len(data)

    phdr1['p_offset'] = total_len - interpreter_len - len(data)
    phdr1['p_vaddr']  = base32 + phdr1['p_offset']

    phdr2['p_offset'] = len(str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(), align1)))
    phdr2['p_vaddr']  = base32 + phdr2['p_offset']

    phdr3['p_filesz'] = total_len
    phdr3['p_memsz']  = total_len

    dyn2['d_val']     = base32 + total_len - len(str.join("", (string_table, symbol_table, reloc_table, interpreter, data)))
    dyn4['d_val']     = base32 + total_len - len(str.join("", (hash_table, string_table, symbol_table, reloc_table, interpreter, data)))
    dyn5['d_val']     = base32 + total_len - len(str.join("", (symbol_table, reloc_table, interpreter, data)))
    dyn7['d_val']     = base32 + total_len - len(str.join("", (reloc_table, interpreter, data)))

    result =  str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(),
                            align1,
                            dyn1.pack(), dyn2.pack(), dyn3.pack(), dyn4.pack(), dyn5.pack(),
                            dyn6.pack(), dyn7.pack(), dyn8.pack(), dyn9.pack(), dyn10.pack(),
                            hash_table,
                            string_table,
                            symbol_table,
                            reloc_table,
                            interpreter,
                            data))

    if filename != "":
        with open(filename, 'wb') as f:
            f.write(result)
            os.chmod(filename, 0775)

    return result

def make_dyn_elf64(data, filename = ''):
    devlog('makeexe', 'data: %s bytes filename: %s proc: x86 ELF32 DYN' % (len(data), filename))

    import libs.PyELF.Elf as ELF
    pdata  = get_proc_data("X64")
    base64 = pdata["entry"]

    # string table
    string_table  = '\x00'
    string_table += 'libc.so.6'
    string_table += '\x00'

    # hash table

    hash_table  = '\x01\x00\x00\x00'
    hash_table += '\x01\x00\x00\x00'
    hash_table += '\x00\x00\x00\x00'
    hash_table += '\x00\x00\x00\x00'

    # symbol table (empty)
    symbol_table = '\x00' * 16

    # reloc table (empty)
    reloc_table  = '\x00' * 8

    interpreter     = '/lib64/ld-linux-x86-64.so.2'
    interpreter    += '\x00'
    interpreter_len = len(interpreter)

    header = ELF.Elf64_Ehdr()

    header['e_ident']     = elf_ident(pdata)
    header['e_type']      = elf.ET_EXEC
    header['e_machine']   = pdata['machine']
    header['e_version']   = elf.EV_CURRENT
    header['e_entry']     = 0 # ADDRESS of code from start of file, PATCH IN
    header['e_phoff']     = header.calcsize()
    header['e_shoff']     = 0
    header['e_flags']     = pdata['flags']
    header['e_ehsize']    = elf.Elf64_Ehdr.size
    header['e_phentsize'] = elf.Elf64_Phdr.size
    header['e_phnum']     = 3
    header['e_shentsize'] = 0
    header['e_shnum']     = 0
    header['e_shstrndx']  = 0

    # End of elf header

    # Program header

    # PT_INTERP section
    phdr1             = ELF.Elf64_Phdr()
    phdr1['p_type']   = ELF.PT_INTERP
    phdr1['p_offset'] = 0 # OFFSET of interpreter_name, PATCH IN
    phdr1['p_vaddr']  = 0 # ADDRESS of interpreter_name, PATCH IN
    phdr1['p_paddr']  = 0
    phdr1['p_filesz'] = interpreter_len
    phdr1['p_memsz']  = interpreter_len
    phdr1['p_flags']  = 4 # RO ACCESS
    phdr1['p_align']  = 1


    # PT_DYNAMIC section
    phdr2             = ELF.Elf64_Phdr()
    phdr2['p_type']   = ELF.PT_DYNAMIC
    phdr2['p_offset'] = 0 # OFFSET of dynamic, PATCH IN
    phdr2['p_vaddr']  = 0 # ADDRESS of dynamic, PATCH IN
    phdr2['p_paddr']  = 0
    phdr2['p_filesz'] = 160 # 10 dynamic entries
    phdr2['p_memsz']  = 160
    phdr2['p_flags']  = 4 # RO ACCESS
    phdr2['p_align']  = 4

    # PT_LOAD section
    phdr3             = ELF.Elf64_Phdr()
    phdr3['p_type']   = ELF.PT_LOAD
    phdr3['p_offset'] = 0
    phdr3['p_vaddr']  = base64
    phdr3['p_paddr']  = 0
    phdr3['p_filesz'] = 0 # SIZE-OF-FILE, PATCH IN
    phdr3['p_memsz']  = 0 # SIZE-OF-FILE, PATCH IN
    phdr3['p_flags']  = 7 # RWX ACCESS
    phdr3['p_align']  = pdata["align"]


    # ALIGN 4
    # Dynamic section

    dyn1            = ELF.Elf64_Dyn()
    dyn1['d_tag']   = ELF.DT_NEEDED
    dyn1['d_val']   = 1 # OFFSET of "libc.so.6" inside string_table

    dyn2            = ELF.Elf64_Dyn()
    dyn2['d_tag']   = ELF.DT_STRTAB
    dyn2['d_val']   = 0 # ADDRESS of string_table, PATCH IN

    dyn3            = ELF.Elf64_Dyn()
    dyn3['d_tag']   = ELF.DT_STRSZ
    dyn3['d_val']   = len(string_table)

    dyn4            = ELF.Elf64_Dyn()
    dyn4['d_tag']   = ELF.DT_HASH
    dyn4['d_val']   = 0 # ADDRESS of hash_table, PATCH IN

    dyn5            = ELF.Elf64_Dyn()
    dyn5['d_tag']   = ELF.DT_SYMTAB
    dyn5['d_val']   = 0 # ADDRESS of symbol_table, PATCH IN

    dyn6            = ELF.Elf64_Dyn()
    dyn6['d_tag']   = ELF.DT_SYMENT
    dyn6['d_val']   = 16

    dyn7            = ELF.Elf64_Dyn()
    dyn7['d_tag']   = ELF.DT_REL
    dyn7['d_val']   = 0 # ADDRESS of reloc_table PATCH IN

    dyn8            = ELF.Elf64_Dyn()
    dyn8['d_tag']   = ELF.DT_RELSZ
    dyn8['d_val']   = 0

    dyn9            = ELF.Elf64_Dyn()
    dyn9['d_tag']   = ELF.DT_RELENT
    dyn9['d_val']   = 8

    dyn10           = ELF.Elf64_Dyn()
    dyn10['d_tag']  = 0x0
    dyn10['d_val']  = 0x0


    # PATCH IN the remaining addresses

    size1 = len(header.pack() + phdr1.pack() + phdr2.pack() + phdr3.pack())

    res = align_pow2(size1, 4) - size1

    if res > 0:
        align1 ='\x00' * res
    else:
        align1 = ''

    total_len = len(str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(),
                                  align1,
                                  dyn1.pack(), dyn2.pack(), dyn3.pack(), dyn4.pack(), dyn5.pack(),
                                  dyn6.pack(), dyn7.pack(), dyn8.pack(), dyn9.pack(), dyn10.pack(),
                                  hash_table,
                                  string_table,
                                  symbol_table,
                                  reloc_table,
                                  interpreter,
                                  data)))

    header['e_entry'] = base64 + total_len - len(data)

    phdr1['p_offset'] = total_len - interpreter_len - len(data)
    phdr1['p_vaddr']  = base64 + phdr1['p_offset']

    phdr2['p_offset'] = len(str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(), align1)))
    phdr2['p_vaddr']  = base64 + phdr2['p_offset']

    phdr3['p_filesz'] = total_len
    phdr3['p_memsz']  = total_len

    dyn2['d_val']     = base64 + total_len - len(str.join("", (string_table, symbol_table, reloc_table, interpreter, data)))
    dyn4['d_val']     = base64 + total_len - len(str.join("", (hash_table, string_table, symbol_table, reloc_table, interpreter, data)))
    dyn5['d_val']     = base64 + total_len - len(str.join("", (symbol_table, reloc_table, interpreter, data)))
    dyn7['d_val']     = base64 + total_len - len(str.join("", (reloc_table, interpreter, data)))

    result =  str.join("", (header.pack(), phdr1.pack(), phdr2.pack(), phdr3.pack(),
                            align1,
                            dyn1.pack(), dyn2.pack(), dyn3.pack(), dyn4.pack(), dyn5.pack(),
                            dyn6.pack(), dyn7.pack(), dyn8.pack(), dyn9.pack(), dyn10.pack(),
                            hash_table,
                            string_table,
                            symbol_table,
                            reloc_table,
                            interpreter,
                            data))

    if filename != "":
        with open(filename, 'wb') as f:
            f.write(result)
            os.chmod(filename, 0775)

    return result


def makeosxexe(data, filename='', proc='x86'):
    devlog('makeexe', 'data: %d bytes filename: %s proc: %s' % (len(data), filename, proc))
    proc = proc.lower()
    assert(proc in ('x86', 'x64'))

    header = macho.MACHOHeader32() if proc == 'x86' else macho.MACHOHeader64()
    header['ncmds'] = 6

    # Load commands & sections
    # The layout of the executables we create is as follows:
    #
    # We include a PAGEZERO segment, a TEXT segment with a single text section,
    # followed by a unixthread load command that contains the state
    # of the registers for the initial thread and two more load commands that
    # are needed in order for DYLD to be mapped successfully in our address
    # space (LCDyldInfoOnly, LCLoadDynamicLinker).
    #
    # LC_DYLD_INFO_ONLY is officially undocumented, more details at
    # MOSDEF/binfmt/macho.py

    load_command0 = macho.LCSegment(segname='__PAGEZERO') if proc=='x86' else macho.LCSegment64(segname='__PAGEZERO')
    load_command1 = macho.LCSegment(segname='__TEXT') if proc=='x86' else macho.LCSegment64(segname='__TEXT')
    load_command2 = macho.LCUnixThread32() if proc=='x86' else macho.LCUnixThread64()
    load_command3 = macho.LCLoadDynamicLinker()
    load_command4 = macho.LCDyldInfoOnly()
    load_command5 = macho.LCLoadDylib(name='/usr/lib/libSystem.B.dylib')

    section1 = macho.Section(sectname='__text', segname='__TEXT') if proc=='x86' else macho.Section64(sectname='__text', segname='__TEXT')
    section1['size'] = len(data)

    # Configuration
    load_command0['maxprot']  = macho.PROT_NONE
    load_command0['initprot'] = macho.PROT_NONE
    load_command1['vmaddr']   = 0x1000
    load_command1['nsects']   = 1
    lc1size                   = load_command1['cmdsize'] + section1.calcsize()

    # This needs to be 4-byte or 8-byte aligned according to arch
    aligned = align_pow2(lc1size, 4) if proc == 'x86' else align_pow2(lc1size, 8)
    load_command1['cmdsize'] = aligned
    pad = '\0'*(aligned-lc1size)

    import operator
    from libs.newsmb.Struct import Struct

    total = reduce(operator.add, map(Struct.calcsize, (header, load_command0,
                                                       load_command1, section1,
                                                       load_command2, load_command3,
                                                       load_command4, load_command5))) + len(data) + len(pad)

    load_command1['vmsize']   = align_pow2(total, 0x1000)
    load_command1['filesize'] = total - load_command0.calcsize()

    header['sizeofcmds'] = reduce(operator.add,
                                  map(lambda x: x['cmdsize'], (load_command0,
                                                               load_command1,
                                                               load_command2,
                                                               load_command3,
                                                               load_command4,
                                                               load_command5)))

    section1['addr']   = header['sizeofcmds'] + header.calcsize() + load_command1['vmaddr']
    section1['offset'] = header['sizeofcmds'] + header.calcsize()

    # Set instruction pointer to where our code begins
    if proc == 'x86':
        load_command2['eip'] = section1['addr']
    else:
        load_command2['rip'] = section1['addr']

    result = str.join("", (header.pack(), load_command0.pack(), load_command1.pack(),
                           section1.pack(), pad, load_command4.pack(), load_command3.pack(),
                           load_command5.pack(), load_command2.pack(), data))

    if filename != "":
        with open(filename, 'wb') as f:
            f.write(result)
            os.chmod(filename, 0775)

    return result

def makeexe(OS, data, filename="", proc = None):
    if hasattr(sys.modules[__name__], "make%sexe" % OS.lower()):
        return getattr(sys.modules[__name__], "make%sexe" % OS.lower())(data, filename, proc)
    print "Cannot make %s an exe"%OS.lower()
    return None

def usage():
    print "%s -s [Solaris|NetBSD|OpenBSD|FreeBSD|Linux|OSX86|OSX64] -f [opcodesfile] -o [outputfile]" % sys.argv[0]
    print "If you want to test a default shellcode /bin/sh just leave out the -f options"
    print "Tested on:"
    print "FreeBSD-5.1 Elf Header"
    print "OpenBSD-3.4 Elf Header"
    print "NetBSD-1.6 Elf Header"
    print "Linux 2.4 Elf Header"
    print "-f [opcodesfile] File with opcodes"
    print "-o [outputfile] Output binary file"
    sys.exit(1)


if __name__=="__main__":
    try:
        import getopt, re
        opts, args = getopt.getopt(sys.argv[1:], 's:f:o:e')
    except getopt.GetoptError:
        usage()

    opcodesfile = ""
    elftype     = 0
    machotype   = None
    outputfile  = ""

    for opt, value in opts:
        if opt == ('-s'):
            netbsd  = re.compile('netbsd'  , re.IGNORECASE)
            openbsd = re.compile('openbsd' , re.IGNORECASE)
            freebsd = re.compile('freebsd' , re.IGNORECASE)
            linux   = re.compile('linux'   , re.IGNORECASE)
            solaris = re.compile('solaris' , re.IGNORECASE)
            osx86 = re.compile('osx86' , re.IGNORECASE)
            osx64 = re.compile('osx64' , re.IGNORECASE)

            if netbsd.match(value):
                elftype = 1
            elif openbsd.match(value):
                elftype = 2
            elif freebsd.match(value):
                elftype = 3
            elif linux.match(value):
                elftype = 4
            elif solaris.match(value):
                elftype = 5
            elif osx86.match(value):
                machotype = 1 # intel 32bit
            elif osx64.match(value):
                machotype = 2 # intel 64bit
            else:
                usage()

        if opt ==  ('-f'):
            opcodesfile = value

        if opt == ('-o'):
            outputfile = value

    try:
        if opcodesfile == "":
            if elftype == 1:
            #netbsd /bin/sh NetBSD 1.6ZC NetBSD 1.6ZC (foo)
                data="\xe9\x0d\x00\x00\x00\x5f\x31\xc0\x50\x89\xe2\x52"
                data+="\x57\x54\xb0\x3b\xcd\x80\xe8\xee\xff\xff\xff\x2f\x62\x69\x6e\x2f"
                data+="\x73\x68"
            elif elftype == 2:
                pass
            elif elftype == 3:
            #freebsd /bin/sh FreeBSD 5.1-RELEASE FreeBSD 5.1-RELEASE
                data="\xe9\x0d\x00\x00\x00\x5f\x31\xc0\x50\x89\xe2\x52"
                data+="\x57\x54\xb0\x3b\xcd\x80\xe8\xee\xff\xff\xff\x2f\x62\x69\x6e\x2f"
                data+="\x73\x68"
            elif elftype == 4:
            #linux /bin/sh Linux 2.4.22-grsec-1.9.12 i686 Pentium III (Katmai) GenuineIntel GNU/Linux
                data="\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x99\x52\x53\x89\xe1\xb0\x0b\xcd\x80"
            elif elftype == 5:
                #ba self, nop
                data= "\x10\x80\x00\x00\x01\x00\x00\x00"
            else:
                print "ERROR: Problem with setting data string"
                sys.exit(1)
        else:
            try:
                data=open(opcodesfile).read()
            except:
                print "ERROR: Can't open opcodesfile."
                usage()

    except:
        usage()
    try:
        import socket
    except:
        pass

    print "Using %d bytes of data" % len(data)

    try:
        if elftype == 1:
            filedata=makenetbsdexe(data)
        elif elftype == 2:
            filedata = makeopenbsdexe(data)
        elif elftype == 3:
            filedata=makefreebsdexe(data)
        elif elftype == 4:
            filedata=makelinuxexe(data)
        elif elftype == 5:
            data= "\x10\x80\x00\x00\x01\x00\x00\x00"+data
            #print "Making file with %d bytes"%(len(data))
            filedata = makelinuxexeSPARC(data)
        elif machotype == 1:
            filedata = makeosxexe(data, proc="x86")
        elif machotype == 2:
            filedata = makeosxexe(data, proc="x64")
        else:
            print "ERROR: Can't choose an elf header type"
            sys.exit(1)

    except socket.error:
        print "ERROR: Can't choose an elf header type"
        sys.exit(1)

    try:
        if outputfile == "":
            print "ERROR: No outputfile"
            sys.exit(1)
        else:
            fd=open(outputfile,"w")
            fd.write(filedata)
            fd.close()
            import os
            os.chmod(outputfile,0775)
    except:
        print "ERROR: Couldn't open, write or chmod %s" % outputfile



