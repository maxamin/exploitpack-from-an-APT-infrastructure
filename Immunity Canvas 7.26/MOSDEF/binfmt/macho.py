#!/usr/bin/env python
# macho.py
#
# Mach-O support (generate) for x86 and x64
#
# chris@immunityinc.com/2011

from libs.newsmb.Struct import Struct
from libs.newsmb.libsmb import extractNullTerminatedString

CPU_TYPE_X86_64          = 0x01000007
CPU_TYPE_X86             = 7
CPU_SUBTYPE_X86_ALL      = 3
MH_EXECUTE               = 2
MH_MAGIC                 = 0xfeedface
MH_CIGAM                 = 0xcefaedfe
MH_MAGIC_64              = 0xfeedfacf
MH_CIGAM_64              = 0xcffaedfe
LC_SEGMENT               = 1
LC_SEGMENT_64            = 25
LC_UNIXTHREAD            = 5
LC_LOAD_DYLINKER         = 0x0E
LC_DYLD_INFO_ONLY        = 0x80000022
LC_LOAD_DYLIB            = 0x0000000C
PROT_NONE                = 0x00
PROT_READ                = 0x01
PROT_WRITE               = 0x02
PROT_EXEC                = 0x04
X86_THREAD_STATE32       = 1
X86_THREAD_STATE64       = 4
X86_THREAD_STATE32_COUNT = 16
X86_THREAD_STATE64_COUNT = 42

class MACHOException(Exception):
    """
    Generic Exception class for all exceptions in this module.
    """
    pass

def pad_and_null_terminate(string, size):
    """
    Encode python string to ASCII and make sure it is at most
    size bytes long including the null terminator. Raise
    MACHOException if size of string is more, pad with null bytes if less.
    """
    string = string.encode('ASCII')
    length = len(string)

    if length > (size-1):
        raise MACHOException('len: %d , String %s > %d bytes.' % (length, string, size-1))

    pad = size - length
    string = string + '\0'*pad
    return string


class MACHOHeader32(Struct):
    st = [
        ['magic'        , '<L', MH_MAGIC],
        ['cputype'      , '<L', CPU_TYPE_X86],
        ['cpusubtype'   , '<L', CPU_SUBTYPE_X86_ALL],
        ['filetype'     , '<L', MH_EXECUTE],
        ['ncmds'        , '<L', 0],
        ['sizeofcmds'   , '<L', 0],
        ['flags'        , '<L', 0],
    ]

    def __init__(self, data=None, cputype='x86'):
        Struct.__init__(self, data)
        if data is None:
            if cputype != 'x86':
                raise MACHOException('Cpu type %s is not supported.' % cputype)


class MACHOHeader64(Struct):
    st = [
        ['magic'        , '<L', MH_MAGIC_64],
        ['cputype'      , '<L', CPU_TYPE_X86_64],
        ['cpusubtype'   , '<L', 0x80000003],
        ['filetype'     , '<L', MH_EXECUTE],
        ['ncmds'        , '<L', 0],
        ['sizeofcmds'   , '<L', 0],
        ['flags'        , '<L', 0],
        ['reserved'     , '<L', 0],
    ]

    def __init__(self, data=None, cputype='x64'):
        Struct.__init__(self, data)
        if data is None:
            if cputype != 'x64':
                raise MACHOException('Cpu type %s is not supported.' % cputype)


class LCSegment(Struct):
    st = [
        ['cmd'      , '<L',   LC_SEGMENT],
        ['cmdsize'  , '<L',   56], # size of segment plus size of all sections, 56 for 0 sections
        ['segname'  , '16s', '\0'*16],
        ['vmaddr'   , '<L',   0],
        ['vmsize'   , '<L',   0x1000],
        ['fileoff'  , '<L',   0],
        ['filesize' , '<L',   0],
        ['maxprot'  , '<L',   PROT_READ|PROT_EXEC],
        ['initprot' , '<L',   PROT_READ|PROT_EXEC],
        ['nsects'   , '<L',   0],
        ['flags'    , '<L',   0],
    ]

    def __init__(self, data=None, segname=''):
        Struct.__init__(self, data)
        if data is None:
            self['segname'] = pad_and_null_terminate(segname, 16)

class LCSegment64(Struct):
    st = [
      ['cmd'      , '<L',   LC_SEGMENT_64],
      ['cmdsize'  , '<L',   72], # size of segment plus size of all sections, 72 for 0 sections
      ['segname'  , '16s', '\0'*16],
      ['vmaddr'   , '<Q',   0],
      ['vmsize'   , '<Q',   0x1000],
      ['fileoff'  , '<Q',   0],
      ['filesize' , '<Q',   0],
      ['maxprot'  , '<L',   PROT_READ|PROT_EXEC],
      ['initprot' , '<L',   PROT_READ|PROT_EXEC],
      ['nsects'   , '<L',   0],
      ['flags'    , '<L',   0],
    ]

    def __init__(self, data=None, segname=''):
        Struct.__init__(self, data)
        if data is None:
            self['segname'] = pad_and_null_terminate(segname, 16)


class Section(Struct):
    st = [
        ['sectname'  , '16s', '\0'*16],
        ['segname'   , '16s', '\0'*16],
        ['addr'      , '<L',   0],
        ['size'      , '<L',   0],
        ['offset'    , '<L',   0],
        ['align'     , '<L',   2],
        ['reloff'    , '<L',   0],
        ['nreloc'    , '<L',   0],
        ['flags'     , '<L',   0],
        ['reserved1' , '<L',   0],
        ['reserved2' , '<L',   0],
    ]

    def __init__(self, data=None, sectname='', segname=''):
        Struct.__init__(self, data)
        if data is None:
            self['sectname'] = pad_and_null_terminate(sectname, 16)
            self['segname'] = pad_and_null_terminate(segname, 16)


class Section64(Struct):
    st = [
        ['sectname'  , '16s', '\0'*16],
        ['segname'   , '16s', '\0'*16],
        ['addr'      , '<Q',   0],
        ['size'      , '<Q',   0],
        ['offset'    , '<L',   0],
        ['align'     , '<L',   2],
        ['reloff'    , '<L',   0],
        ['nreloc'    , '<L',   0],
        ['flags'     , '<L',   0],
        ['reserved1' , '<L',   0],
        ['reserved2' , '<L',   0],
    ]

    def __init__(self, data=None, sectname='', segname=''):
        Struct.__init__(self, data)
        if data is None:
            self['sectname'] = pad_and_null_terminate(sectname, 16)
            self['segname'] = pad_and_null_terminate(segname, 16)


class LCUnixThread32(Struct):
    st = [
        ['cmd'     , '<L', LC_UNIXTHREAD],
        # Size of structure in bytes
        ['cmdsize' , '<L', (X86_THREAD_STATE32_COUNT*4) + 16],
        ['flavor'  , '<L', X86_THREAD_STATE32],
        ['count'   , '<L', X86_THREAD_STATE32_COUNT],
        ['eax'     , '<L', 0],
        ['ebx'     , '<L', 0],
        ['ecx'     , '<L', 0],
        ['edx'     , '<L', 0],
        ['edi'     , '<L', 0],
        ['esi'     , '<L', 0],
        ['ebp'     , '<L', 0],
        ['esp'     , '<L', 0],
        ['ss'      , '<L', 0],
        ['eflags'  , '<L', 0],
        ['eip'     , '<L', 0],
        ['cs'      , '<L', 0],
        ['ds'      , '<L', 0],
        ['es'      , '<L', 0],
        ['fs'      , '<L', 0],
        ['gs'      , '<L', 0],
    ]


class LCUnixThread64(Struct):
    st = [
        ['cmd'     , '<L', LC_UNIXTHREAD],
        # Size of structure in bytes
        ['cmdsize' , '<L', (X86_THREAD_STATE64_COUNT*4) + 16],
        ['flavor'  , '<L', X86_THREAD_STATE64],
        ['count'   , '<L', X86_THREAD_STATE64_COUNT],
        ['rax'     , '<Q', 0],
        ['rbx'     , '<Q', 0],
        ['rcx'     , '<Q', 0],
        ['rdx'     , '<Q', 0],
        ['rdi'     , '<Q', 0],
        ['rsi'     , '<Q', 0],
        ['rbp'     , '<Q', 0],
        ['rsp'     , '<Q', 0],
        ['r8'      , '<Q', 0],
        ['r9'      , '<Q', 0],
        ['r10'     , '<Q', 0],
        ['r11'     , '<Q', 0],
        ['r12'     , '<Q', 0],
        ['r13'     , '<Q', 0],
        ['r14'     , '<Q', 0],
        ['r15'     , '<Q', 0],
        ['rip'     , '<Q', 0],
        ['rflags'  , '<Q', 0],
        ['cs'      , '<Q', 0],
        ['fs'      , '<Q', 0],
        ['gs'      , '<Q', 0],
    ]

class LCLoadDynamicLinker(Struct):
    st = [
        ['cmd',     '<L', LC_LOAD_DYLINKER],
        ['cmdsize', '<L', 32],
        ['offset',  '<L', 12],
        # Extra null bytes for alignment (both 32/64bit)
        ['name',    '20s', '/usr/lib/dyld\0\0\0\0\0\0\0'],
    ]

class LCLoadDylib(Struct):
    st = [
        ['cmd'                   , '<L', LC_LOAD_DYLIB],
        ['cmdsize'               , '<L', 56],
        ['offset'                , '<L', 24],
        ['timestamp'             , '<L', 2],
        ['current_version'       , '<L', 0],
        ['compatibility_version' , '<L', 0],
        ['name'                  , '0s', ''],
    ]

    def __init__(self, data=None, name=''):
        Struct.__init__(self, data)
        if data is None:
            if not name:
                raise MACHOException('LCLoadDylib: name should be a string.')
            size = 24 + len(name)
            # Load command size should be multiple of 8
            final_size      = (size + 7) & ~7
            pad             = (final_size - size) + len(name)
            self['name']    = pad_and_null_terminate(name, pad)
            self['cmdsize'] = final_size
        else:
            size   = self['cmdsize'] - 24
            offset = self['offset'] 
            self['name'] = data[offset:offset+size]

    def pack(self):
        return Struct.pack(self) + self['name']


class LCDyldInfoOnly(Struct):
    st = [
        ['cmd'            , '<L', LC_DYLD_INFO_ONLY],
        ['cmdsize'        , '<L', 48],
        ['rebase_off'     , '<L', 0],
        ['rebase_size'    , '<L', 0],
        ['bind_off'       , '<L', 0],
        ['bind_size'      , '<L', 0],
        ['weak_bind_off'  , '<L', 0],
        ['weak_bind_size' , '<L', 0],
        ['lazy_bind_off'  , '<L', 0],
        ['lazy_bind_size' , '<L', 0],
        ['export_off'     , '<L', 0],
        ['export_size'    , '<L', 0],
    ]

#
# For future reference as LCDyldInfoOnly docs are not easy to find:
#

"""
/*
 * The dyld_info_command contains the file offsets and sizes of
 * the new compressed form of the information dyld needs to
 * load the image.  This information is used by dyld on Mac OS X
 * 10.6 and later.  All information pointed to by this command
 * is encoded using byte streams, so no endian swapping is needed
 * to interpret it.
 */
struct dyld_info_command {
   uint32_t   cmd;		/* LC_DYLD_INFO or LC_DYLD_INFO_ONLY*/
   uint32_t   cmdsize;		/* sizeof(struct dyld_info_command) */

    /*
     * Dyld rebases an image whenever dyld loads it at an address different
     * from its preferred address.  The rebase information is a stream
     * of byte sized opcodes whose symbolic names start with REBASE_OPCODE_.
     * Conceptually the rebase information is a table of tuples:
     *    <seg-index, seg-offset, type>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like "every n'th offset for m times" can be encoded in a few
     * bytes.
     */
    uint32_t   rebase_off;	/* file offset to rebase info  */
    uint32_t   rebase_size;	/* size of rebase info   */

    /*
     * Dyld binds an image during the loading process, if the image
     * requires any pointers to be initialized to symbols in other images.
     * The rebase information is a stream of byte sized
     * opcodes whose symbolic names start with BIND_OPCODE_.
     * Conceptually the bind information is a table of tuples:
     *    <seg-index, seg-offset, type, symbol-library-ordinal, symbol-name, addend>
     * The opcodes are a compressed way to encode the table by only
     * encoding when a column changes.  In addition simple patterns
     * like for runs of pointers initialzed to the same value can be
     * encoded in a few bytes.
     */
    uint32_t   bind_off;	/* file offset to binding info   */
    uint32_t   bind_size;	/* size of binding info  */

    /*
     * Some C++ programs require dyld to unique symbols so that all
     * images in the process use the same copy of some code/data.
     * This step is done after binding. The content of the weak_bind
     * info is an opcode stream like the bind_info.  But it is sorted
     * alphabetically by symbol name.  This enable dyld to walk
     * all images with weak binding information in order and look
     * for collisions.  If there are no collisions, dyld does
     * no updating.  That means that some fixups are also encoded
     * in the bind_info.  For instance, all calls to "operator new"
     * are first bound to libstdc++.dylib using the information
     * in bind_info.  Then if some image overrides operator new
     * that is detected when the weak_bind information is processed
     * and the call to operator new is then rebound.
     */
    uint32_t   weak_bind_off;	/* file offset to weak binding info   */
    uint32_t   weak_bind_size;  /* size of weak binding info  */

    /*
     * Some uses of external symbols do not need to be bound immediately.
     * Instead they can be lazily bound on first use.  The lazy_bind
     * are contains a stream of BIND opcodes to bind all lazy symbols.
     * Normal use is that dyld ignores the lazy_bind section when
     * loading an image.  Instead the static linker arranged for the
     * lazy pointer to initially point to a helper function which
     * pushes the offset into the lazy_bind area for the symbol
     * needing to be bound, then jumps to dyld which simply adds
     * the offset to lazy_bind_off to get the information on what
     * to bind.
     */
    uint32_t   lazy_bind_off;	/* file offset to lazy binding info */
    uint32_t   lazy_bind_size;  /* size of lazy binding infs */

    /*
     * The symbols exported by a dylib are encoded in a trie.  This
     * is a compact representation that factors out common prefixes.
     * It also reduces LINKEDIT pages in RAM because it encodes all
     * information (name, address, flags) in one small, contiguous range.
     * The export area is a stream of nodes.  The first node sequentially
     * is the start node for the trie.
     *
     * Nodes for a symbol start with a byte that is the length of
     * the exported symbol information for the string so far.
     * If there is no exported symbol, the byte is zero. If there
     * is exported info, it follows the length byte.  The exported
     * info normally consists of a flags and offset both encoded
     * in uleb128.  The offset is location of the content named
     * by the symbol.  It is the offset from the mach_header for
     * the image.
     *
     * After the initial byte and optional exported symbol information
     * is a byte of how many edges (0-255) that this node has leaving
     * it, followed by each edge.
     * Each edge is a zero terminated cstring of the addition chars
     * in the symbol, followed by a uleb128 offset for the node that
     * edge points to.
     *
     */
    uint32_t   export_off;	/* file offset to lazy binding info */
    uint32_t   export_size;	/* size of lazy binding infs */
};
"""
