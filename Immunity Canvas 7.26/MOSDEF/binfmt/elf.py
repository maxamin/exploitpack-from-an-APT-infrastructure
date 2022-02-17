#! /usr/bin/env python

import struct
from elf_const import *

TODO = """
use Elf32_Ehdr.ei_data in all format strings, so that module will be Elf64 compatible
now it is (about) endian-compatible
"""

class Elf_Config:
    """
    this class manage endianness and types to allow cross-analyses
    - ELF can be big/little-endian
    - ELF can be 32/64 bits
    """
    endian = 0
    types = {}

    def __init__(fles, config=None):
        fles.endian_fmt = "<" # XXX should NOT be defined here. but nobody will read that code.
        if config:
            fles.setconf(config)
            if hasattr(fles, '_fmt'):
                fles.fmt = fles.getfmt(fles._fmt)
            elif hasattr(fles, '_fmtconfig'): # TODO
                fles._fmtconfig()

    def setconf(fles, configtuple):
        elf_class, elf_dataorder = configtuple
        if elf_dataorder == ELFDATA2MSB:
            fles.endian_fmt = '>'
        else:
            fles.endian_fmt = '<'
        fles.ei_data = elf_dataorder
        fles.ei_class = elf_class
        fles.types = ETYPE[elf_class]

    def getconf(fles):
        return (fles.ei_class, fles.ei_data)

    def getfmt(fles, fmt):
        # we dont need to assert here anymore since little-endian is default endianness in the world
        #assert fles.endian_fmt != ""
        if fmt[0] not in '@=<>!':
            fmt = fles.endian_fmt + fmt
        return fmt

SEEK_SET=0
SEEK_CUR=1
SEEK_END=2


class Elf_Object(Elf_Config):
    def __init__(fles, fd, offset, data, BIGENDIAN, config):
        Elf_Config.__init__(fles, config)
        fles.fd         = fd
        fles.offset     = offset
        fles.size       = fles.size
        fles.BIGENDIAN  = BIGENDIAN
        if data:
            fles.get(data)
        else:
            if fd != -1 and offset !=-1:
                fles.get(fles.read())

    def read(fles):
        fles.fd.seek(fles.offset, SEEK_SET)
        return fles.fd.read(fles.size)

    def write(fles, BIGENDIAN = 0):
        data = fles.raw(BIGENDIAN)
        fles.fd.seek(fles.offset, SEEK_SET)
        fles.fd.write(data)

    def get(fles, data):
        pass


class Elf32_Object(Elf_Object):
    size = 0
    def __init__(fles, fd = -1, offset = -1, data = "", BIGENDIAN = 0, config = None):
        Elf_Object.__init__(fles, fd, offset, data, BIGENDIAN, config)


class Elf64_Object(Elf_Object):
    size = 0
    def __init__(fles, fd = -1, offset = -1, data = "", BIGENDIAN = 0, config = None):
        Elf_Object.__init__(fles, fd, offset, data, BIGENDIAN, config)


EI_DATA = 5
class Elf32_Ehdr(Elf32_Object):
    size = 0x34
    #fmtBIG = "%ss"+ "%s" *14 % (EI_NIDENT,E32_HALFB,E32_HALFB, E32_WORDB, E32_ADDRB, E32_OFFB, E32_OFFB, E32_WORDB, E32_HALFB, E32_HALFB, E32_HALFB,E32_HALFB, E32_HALFB,E32_HALFB)
    def _setfmt(fles):
        fles.setconf((fles.ei_class, fles.ei_data))
        fles.fmt = fles.getfmt("%ss" + "%s" * 13)
        fles.fmt = fles.fmt % (EI_NIDENT, \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Word'], \
                               ETYPE[fles.ei_class]['Addr'], \
                               ETYPE[fles.ei_class]['Off'], \
                               ETYPE[fles.ei_class]['Off'], \
                               ETYPE[fles.ei_class]['Word'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'])
        return fles.fmt

    def endian(fles):
        return fles.ei_data

    def endian_fmt(fles):
        return fles.endian_fmt

    def types(fles):
        return ETYPE[fles.ei_class]

    def get_eident(fles, elfhdr):
        eidentfmt = "4scccccc6x"
        eident = struct.unpack(eidentfmt, elfhdr[:16])
        fles.ei_magic      = eident[0]
        fles.ei_class      = ord(eident[1])
        fles.ei_data       = ord(eident[2])
        fles.ei_version    = ord(eident[3])
        fles.ei_osabi      = ord(eident[4])
        fles.ei_abiversion = ord(eident[5])
        assert fles.ei_magic == "\177ELF", "wrong ELF magic %s" % fles.ei_magic
        assert fles.ei_class in [ELFCLASS32, ELFCLASS64], "invalid ELF class %d" % fles.ei_class
        assert fles.ei_data in [ELFDATA2LSB, ELFDATA2MSB], "invalid ELF data order %d" % fles.ei_data
        assert fles.ei_version == EV_CURRENT, "invalid ELF version %d" % fles.ei_version
        fles._setfmt()
        return eident

    def get_desc(fles):
        fles.desc = "%s / %s / %s / %s" % \
                    (ELFDOC['OSABI'][fles.ei_osabi], \
                     ELFDOC['MACHINE'][fles.e_machine], \
                     ELFDOC['CLASS'][fles.ei_class], \
                     ELFDOC['DATA'][fles.ei_data])
        return fles.desc

    def get(fles, elfhdr):
        fles.get_eident(elfhdr)
        ehdr=struct.unpack(fles.fmt, elfhdr)
        # nasty :D
        fles.e_ident     = ehdr[0]
        fles.e_type      = ehdr[1]
        fles.e_machine   = ehdr[2]
        fles.e_version   = ehdr[3]
        fles.e_entry     = ehdr[4]
        fles.e_phoff     = ehdr[5]
        fles.e_shoff     = ehdr[6]
        fles.e_flags     = ehdr[7]
        fles.e_ehsize    = ehdr[8]
        fles.e_phentsize = ehdr[9]
        fles.e_phnum     = ehdr[10]
        fles.e_shentsize = ehdr[11]
        fles.e_shnum     = ehdr[12]
        fles.e_shstrndx  = ehdr[13]
        print fles.get_desc()

    def raw(fles, BIGENDIAN=0):
        fmt = "%ss"+ "%s" *13
        fmt = fmt % (EI_NIDENT, E32_HALF,E32_HALF, E32_WORD, E32_ADDR, \
                     E32_OFF, E32_OFF, E32_WORD, E32_HALF, E32_HALF, \
                     E32_HALF, E32_HALF, E32_HALF, E32_HALF)
        fmt = fles.getfmt(fmt)
        ehdr = struct.pack(fmt, fles.e_ident, fles.e_type, \
                           fles.e_machine, fles.e_version, fles.e_entry, fles.e_phoff, \
                           fles.e_shoff, fles.e_flags,  fles.e_ehsize, fles.e_phentsize, \
                           fles.e_phnum, fles.e_shentsize, fles.e_shnum, fles.e_shstrndx)
        return ehdr


class Elf64_Ehdr(Elf64_Object):
    size = 0x40

    def _setfmt(fles):
        fles.setconf((fles.ei_class, fles.ei_data))
        fles.fmt = fles.getfmt("%ss" + "%s" * 13)
        fles.fmt = fles.fmt % (EI_NIDENT, \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Word'], \
                               ETYPE[fles.ei_class]['Addr'], \
                               ETYPE[fles.ei_class]['Off'], \
                               ETYPE[fles.ei_class]['Off'], \
                               ETYPE[fles.ei_class]['Word'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'], \
                               ETYPE[fles.ei_class]['Half'])
        return fles.fmt

    def endian(fles):
        return fles.ei_data

    def endian_fmt(fles):
        return fles.endian_fmt

    def types(fles):
        return ETYPE[fles.ei_class]

    def get_eident(fles, elfhdr):
        eidentfmt = "4scccccc6x"
        eident = struct.unpack(eidentfmt, elfhdr[:16])
        fles.ei_magic      = eident[0]
        fles.ei_class      = ord(eident[1])
        fles.ei_data       = ord(eident[2])
        fles.ei_version    = ord(eident[3])
        fles.ei_osabi      = ord(eident[4])
        fles.ei_abiversion = ord(eident[5])
        assert fles.ei_magic == "\177ELF", "wrong ELF magic %s" % fles.ei_magic
        assert fles.ei_class in [ELFCLASS32, ELFCLASS64], "invalid ELF class %d" % fles.ei_class
        assert fles.ei_data in [ELFDATA2LSB, ELFDATA2MSB], "invalid ELF data order %d" % fles.ei_data
        assert fles.ei_version == EV_CURRENT, "invalid ELF version %d" % fles.ei_version
        fles._setfmt()
        return eident

    def get_desc(fles):
        fles.desc = "%s / %s / %s / %s" % \
                    (ELFDOC['OSABI'][fles.ei_osabi], \
                     ELFDOC['MACHINE'][fles.e_machine], \
                     ELFDOC['CLASS'][fles.ei_class], \
                     ELFDOC['DATA'][fles.ei_data])
        return fles.desc

    def get(fles, elfhdr):
        fles.get_eident(elfhdr)
        ehdr = struct.unpack(fles.fmt, elfhdr)
        # nasty :D
        fles.e_ident     = ehdr[0]
        fles.e_type      = ehdr[1]
        fles.e_machine   = ehdr[2]
        fles.e_version   = ehdr[3]
        fles.e_entry     = ehdr[4]
        fles.e_phoff     = ehdr[5]
        fles.e_shoff     = ehdr[6]
        fles.e_flags     = ehdr[7]
        fles.e_ehsize    = ehdr[8]
        fles.e_phentsize = ehdr[9]
        fles.e_phnum     = ehdr[10]
        fles.e_shentsize = ehdr[11]
        fles.e_shnum     = ehdr[12]
        fles.e_shstrndx  = ehdr[13]
        print fles.get_desc()

    def raw(fles, BIGENDIAN=0):
        fmt = "%ss"+ "%s" *13
        fmt = fmt % (EI_NIDENT, E64_HALF,E64_HALF, E64_WORD, E64_ADDR, \
                     E64_OFF, E64_OFF, E64_WORD, E64_HALF, E64_HALF, \
                     E64_HALF, E64_HALF, E64_HALF, E64_HALF)
        fmt = fles.getfmt(fmt)
        ehdr = struct.pack(fmt, fles.e_ident, fles.e_type, \
                           fles.e_machine, fles.e_version, fles.e_entry, fles.e_phoff, \
                           fles.e_shoff, fles.e_flags,  fles.e_ehsize, fles.e_phentsize, \
                           fles.e_phnum, fles.e_shentsize, fles.e_shnum, fles.e_shstrndx)
        return ehdr


class Elf32_Phdr(Elf32_Object):
    size = 0x20
    _fmt = "%c%c%c%c%c%c%c%c" % (E32_WORD, E32_OFF, E32_ADDR, E32_ADDR, E32_WORD, E32_WORD, E32_WORD, E32_WORD)

    def get(fles, buf):
        p = struct.unpack(fles.fmt, buf)
        fles.p_type  = p[0]
        fles.p_offset= p[1]
        fles.p_vaddr = p[2]
        fles.p_paddr = p[3]
        fles.p_filesz= p[4]
        fles.p_memsz = p[5]
        fles.p_flags = p[6]
        fles.p_align = p[7]

    def raw(fles, BIGENDIAN = 0):
        phdr = struct.pack(fles.fmt, fles.p_type, fles.p_offset, \
                           fles.p_vaddr, fles.p_paddr, fles.p_filesz, fles.p_memsz, \
                           fles.p_flags, fles.p_align)
        return phdr


class Elf64_Phdr(Elf64_Object):
    size = 0x38
    _fmt = "%c%c%c%c%c%c%c%c" % (E64_WORD, E64_WORD, E64_OFF, E64_ADDR, E64_ADDR, E64_XWORD, E64_XWORD, E64_XWORD)

    def get(fles, buf):
        p = struct.unpack(fles.fmt, buf)
        fles.p_type  = p[0]
        fles.p_flags = p[1]
        fles.p_offset= p[2]
        fles.p_vaddr = p[3]
        fles.p_paddr = p[4]
        fles.p_filesz= p[5]
        fles.p_memsz = p[6]
        fles.p_align = p[7]

    def raw(fles, BIGENDIAN = 0):
        phdr = struct.pack(fles.fmt, fles.p_type, fles.p_flags, fles.p_offset, \
                           fles.p_vaddr, fles.p_paddr, fles.p_filesz, \
                           fles.p_memsz, fles.p_align)
        return phdr


class Elf32_Dyn(Elf32_Object):
    size = 0x8
    _fmt = "%c%c" % (E32_SWORD, E32_ADDR)

    def get(fles, buf):
       (fles.d_tag, fles.d_ptr) = struct.unpack(fles.fmt, buf)

    def raw(fles, BIGENDIAN = 0):
        return struct.pack(fles.fmt, fles.d_tag, fles.d_ptr)


class Elf64_Dyn(Elf64_Object):
    size = 0x10
    _fmt = "%c%c" % (E64_SXWORD, E64_ADDR)

    def get(fles, buf):
       (fles.d_tag, fles.d_ptr) = struct.unpack(fles.fmt, buf)

    def raw(fles, BIGENDIAN = 0):
        return struct.pack(fles.fmt, fles.d_tag, fles.d_ptr)


class Elf32_Shdr(Elf32_Object):
    size = 0x28
    _fmt = "%c%c%c%c%c%c%c%c%c%c" % (E32_WORD, E32_WORD, E32_WORD, E32_ADDR, \
                                     E32_OFF, E32_WORD, E32_WORD, E32_WORD,  \
                                     E32_WORD, E32_WORD)
    def get(fles, buf):
         s = struct.unpack(fles.fmt,buf)
         fles.sh_name     = s[0]
         fles.sh_type     = s[1]
         fles.sh_flags    = s[2]
         fles.sh_addr     = s[3]
         fles.sh_offset   = s[4]
         fles.sh_size     = s[5]
         fles.sh_link     = s[6]
         fles.sh_info     = s[7]
         fles.sh_addralign= s[8]
         fles.sh_entsize  = s[9]

    def raw(fles, BIGENDIAN=0):
        shdr = struct.pack(fles.fmt, fles.sh_name, fles.sh_type, \
                           fles.sh_flags, fles.sh_addr, fles.sh_offset, \
                           fles.sh_size, fles.sh_link, fles.sh_info, \
                           fles.sh_addralign, fles.sh_entsize)
        return shdr


class Elf32_Sym(Elf32_Object):
    size = 0x10
    _fmt = "%c%c%c%c%c%c" % (E32_WORD, E32_ADDR, E32_WORD,U_CHAR, U_CHAR, E32_SECTION)

    def get(fles, buf):
        s=struct.unpack(fles.fmt, buf)
        fles.st_name =s[0]
        fles.st_value=s[1]
        fles.st_size =s[2]
        fles.st_info =s[3]
        fles.st_other=s[4]
        fles.st_shndx=s[5]

    def raw(fles, BIGENDIAN=0):
        sym = struct.pack(fles.fmt, fles.st_name, fles.st_value, fles.st_size, \
                          fles.st_info, fles.st_other, fles.st_shndx)
        return sym
    def name(fles, strtbl):
        return strFromTbl(fles.st_name, strtbl)


class Elf32_Rel(Elf32_Object):
    size = 0x8
    _fmt = "%c%c" % (E32_ADDR, E32_WORD)

    def get(fles, buf):
        s = struct.unpack(fles.fmt, buf)
        fles.r_offset=s[0]
        fles.r_info  =s[1]

    def raw(fles, BIGENDIAN=0):
        return struct.pack(fles.fmt, fles.r_offset, fles.r_info)

    def ELF32_R_SYM(fles):
        return ELF32_R_SYM(fles.r_info)

    def ELF32_R_TYPE(fles):
        return ELF32_R_TYPE(fles.r_info)

    def isRel(fles, rel_type):
        return (fles.ELF32_R_TYPE() == rel_type)


class Elf32(Elf_Config):
    def __init__(fles, filename, vaddr=0x8048000):
        fles.name = filename
        try:
            fles.fd = open(filename, "r+")
        except IOError:
            fles.fd = open(filename, "r")
        fles.vaddr=vaddr
        fles.parse(fles.fd)

    def addr2pt(fles, addr):
        for p in fles.ptload:
            if p.p_vaddr < addr and (p.p_vaddr + p.p_memsz) > addr:
                return p
        return None

    def writeAddr(fles, where, what):
        data = struct.pack(E32_ADDR, what)
        fles.write(where, data)

    def write(fles, where, what):
        fles.fd.seek(where)
        fles.fd.write(what)

    def parse(fles, fd):
        fles.ehdr = Elf32_Ehdr(fd, 0)
        fles.setconf(fles.ehdr.getconf())
        fles.readPhdr(fd, fles.ehdr.e_phoff, fles.ehdr.e_phnum, \
                      fles.ehdr.e_phentsize)
        fles.dynamic = fles.readObject(fles.ptdynamic.p_offset,Elf32_Dyn, \
                                       fles.ptdynamic.p_filesz)
        fles.shdr= fles.readObject(fles.ehdr.e_shoff, Elf32_Shdr, \
                                   Elf32_Shdr.size * fles.ehdr.e_shnum)
        if fles.shdr:
            fles.getShdrSection()
        else:
            getDynSection()

    def readObject(fles, offset, Clase, tsize):
        t = []
        fles.fd.seek(offset)
        buf = fles.fd.read(tsize)
        for a in range(0, len(buf) / Clase.size):
            c = Clase(fd=fles.fd, data=buf[a * Clase.size: (a+1)* Clase.size], \
                      offset=offset+a*Clase.size, config=fles.getconf())
            t.append(c)
        return t

    def readPhdr(fles, fd, offset, e_phnum,phsize):
        fles.ptload=[]
        fles.phdr=[]
        fles.ptdynamic = None
        fd.seek(offset, SEEK_SET)
        buf = fd.read(e_phnum * phsize)
        assert len(buf)
        for a in range(0, len(buf) / phsize): # len(buf) / phsize == e_phnum
            p = Elf32_Phdr(fd=fles.fd, data = buf[a*phsize: (a+1)*phsize], \
                           offset = offset+a*phsize, config=fles.getconf())

            if p.p_type == PT_LOAD:
                fles.ptload.append(p)
            else:
                if p.p_type == PT_DYNAMIC:
                    fles.ptdynamic=p
                else:
                    fles.phdr.append(p)
        if not fles.ptdynamic:
            print "No DYNAMIC found on program header"
            return 0

        return (a+1)

    def getRel(fles):
        if fles.shdr==[]:
            # get rel through dynamic
            fles.getRelD()
        else:
            # get rel through section
            fles.getRelS()

    # coming soon...
    def getRelD(fles):
        print "feature not supported yet"

    def getDynSection(fles):
        pass

    def getShdrSection(fles):
        shdr = fles.shdr
        rol = []
        off = -1
        sz = 0
        fles.shdrstr = fles.readSection(shdr[fles.ehdr.e_shstrndx])
        for a in range(0, len(shdr)):
            if shdr[a].sh_type==SHT_STRTAB:
                shdrname=strFromTbl(fles.shdr[a].sh_name,\
                                    fles.shdrstr)
                if shdrname==".dynstr":
                    fles.strtbl= fles.readSection(fles.shdr[a])
                    continue
                if shdrname==".strtab":
                    fles.strtab=  fles.readSection(fles.shdr[a])
                    continue
            if shdr[a].sh_type==SHT_SYMTAB:
                fles.symtbl=fles.readObject(shdr[a].sh_offset,\
                                            Elf32_Sym, shdr[a].sh_size)
                continue
            if shdr[a].sh_type== SHT_DYNSYM:
                fles.dynsym=fles.readObject(shdr[a].sh_offset,\
                                            Elf32_Sym, shdr[a].sh_size)
                continue
            if shdr[a].sh_type==SHT_REL:
                sz+=shdr[a].sh_size
                if off== -1 or off > shdr[a].sh_offset:
                    off=shdr[a].sh_offset
                #rol.append(shdr[a])
        if off != -1:
            fles.rel=fles.readObject(off, Elf32_Rel, sz)

    def symbolByType(fles, type):
        shdr = fles.shdr
        for s in shdr:
            if s.sh_type==type:
                return s
        return None

    def getSection(fles, type):
        sym = fles.symbolByType(type)
        if sym==None:
            return None
        return fles.readSection(sym)

    def getStrtbl(fles):
        for a in range(0, len(fles.shdr)):
            if fles.shdr[a][SH_TYPE]==SHT_STRTAB:
                if a==fles.ehdr[E_SHSTRNDX]:
                    fles.strshdr=fles.readSection(a)
                else:
                    fles.strtbl= fles.readSection(a)
            if fles.shdr[a][SH_TYPE]==SHT_SYMTAB:
                h=fles.readSection(a)
                fles.symtbl=fles.readSymbol(h)
            if fles.shdr[a][SH_TYPE]==SHT_DYNSYM:
                h=fles.readSection(a)
                fles.dynsym=fles.readSymbol(h)

    def readSection(fles, shdr):
        fles.fd.seek(shdr.sh_offset)
        return fles.fd.read(shdr.sh_size)