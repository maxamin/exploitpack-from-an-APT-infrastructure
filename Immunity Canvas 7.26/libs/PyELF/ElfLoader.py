import sys
import struct
import platform
import ctypes

import Elf
import Syscall
import MmanHeader as mman_h

import AsmLoader

class ElfLoader:
    
    ElfStructMap = { '32bit' : Elf.Elf32Structs, '64bit' : Elf.Elf64Structs }

    def __init__(self, path = None, elf_data = None):
        self.platform_arch,self.bin_fmt = platform.architecture()
        self.arch = '64bit'
        # assume platform consistency for the initial header parse
        self.elf_structs = self.ElfStructMap[self.arch]
        self.elf_data = ''
        if path is not None:
            self.elf_data = open(path, 'r').read()
        if elf_data is not None:
            self.elf_data = elf_data
        self.executable_stack = False
        self.stack_top = 0

        # this is all the stuff we need for our loader to work
        # add the headers we HAVE to load from our loader here
        self.pouvelf = { 
                'e_entry'       : 0,
                'e_phoff'       : 0,
                'PT_SEGMENTS'   : [], # this consists of PT_LOAD segments and 1 PT_PVELF_STACK segment
                '_dl_phdr'      : 0, 
                '_dl_phnum'     : 0,
                '_dl_random'    : 0
                }

        # init our syscall interface
        self.syscall = Syscall.Syscall()
    
    def load_elf(self, data_only = False):
        """ this mmaps the POUVELF binary + loader, and inits the replacement """
        print '[+] replacing python with POUVELF'
        pack_fmt = { '32bit' : '<I', '64bit' : '<Q' }
        data  = struct.pack(pack_fmt[self.arch], self.pouvelf['e_entry'])
        data += struct.pack(pack_fmt[self.arch], self.pouvelf['e_phoff'])
        data += struct.pack(pack_fmt[self.arch], self.pouvelf['_dl_phdr'])
        data += struct.pack(pack_fmt[self.arch], self.pouvelf['_dl_phnum'])
        data += struct.pack(pack_fmt[self.arch], self.pouvelf['_dl_random'])
        # set the hdr count to -1 in the actual _dl_phnum because PT_PVELF_STACK is a custom segment
        # and does not exist for anything but our elf loader
        data += struct.pack(pack_fmt[self.arch], len(self.pouvelf['PT_SEGMENTS']))
        for phdr in self.pouvelf['PT_SEGMENTS']:
            if phdr['p_type'] not in [Elf.PT_LOAD, Elf.PT_PVELF_STACK]:
                continue # PT_TLS and PT_NOTE data already exist and are mapped from PT_LOAD
            data += phdr.pack()
            if 'prot' in phdr.value:
                data += struct.pack(pack_fmt[self.arch], phdr['prot'])
            else:
                # default to RW mapping
                data += struct.pack(pack_fmt[self.arch], mman_h.PROT_READ|mman_h.PROT_WRITE)
            data += phdr['data'] # data is left intentially left off the Struct pack
        # pack in the orig headers including PT_TLS and PT_NOTE for _dl_phdr to point at
        for phdr in self.pouvelf['PT_SEGMENTS']:
            if phdr['p_type'] != Elf.PT_PVELF_STACK:
                data += phdr.pack()
        if data_only == True:
            return data
        # the reason we are going through a syscall bridge and not using the direct
        # ctype wrappers for these functions is that it give us the flexibility to
        # eventually move to a ptrace based syscall interface into other target
        # processes for our userland execve, we only need mmap and mprotect
        pvelf_addr = self.syscall.syscall_bridge('mmap', 
                0, 
                (len(data) + 0x1000) & ((~0x1000)+1), 
                mman_h.PROT_READ|mman_h.PROT_WRITE, 
                mman_h.MAP_ANONYMOUS|mman_h.MAP_PRIVATE, 
                -1, 
                0)
        ctypes.memmove(pvelf_addr, data, len(data))
        print '[+] allocated space for POUVELF object @ 0x%x' % pvelf_addr
        load_addr = self.syscall.syscall_bridge('mmap',
                0,
                0x1000,
                mman_h.PROT_READ|mman_h.PROT_WRITE, # we have to mprotect this to RX after placing data
                mman_h.MAP_ANONYMOUS|mman_h.MAP_PRIVATE,
                -1,
                0)
        print '[+] allocated space for POUVELF loader @ 0x%x' % load_addr
        loader = ''
        if self.arch == '64bit':
            print '[+] prepping 64bit POUVELF loader'
            loader = ''.join(map(lambda x: chr(x), AsmLoader.LOADER64)) 
            loader = loader.replace(struct.pack('<Q', 0xcafebabecafebabe), struct.pack('<Q', pvelf_addr))
        else:
            print '[+] prepping 32bit POUVELF loader'
            loader = ''.join(map(lambda x: chr(x), AsmLoader.LOADER32))
            loader = loader.replace(struct.pack('<I', 0xcafebabe), struct.pack('<I', pvelf_addr))
        ctypes.memmove(load_addr, loader, len(loader))
        self.syscall.syscall_bridge('mprotect',
            load_addr,
            0x1000,
            mman_h.PROT_READ|mman_h.PROT_EXEC)
        print '[+] primed POUVELF loader, handing over control'
        f_ptr = ctypes.CFUNCTYPE(ctypes.c_int)(load_addr)
        print '[+] ATTACH NOW'; sys.stdin.read(1)
        f_ptr() # bye python, hello userland execve
            
    def prep_elf(self, argv=[], envp=[], arch_override=False):
        """ this parses out everything we might possibly need from the ELF """
        interp_elf_ex = None
        elf_ex = self.elf_structs['elfhdr'](data = self.elf_data)

        # e_machine trumps self.arch from platform
        if elf_ex['e_machine'] == Elf.EM_X86_64:
            print '[+] EM_X86_64'
            self.elf_structs = self.ElfStructMap['64bit']
            self.stack_top = 0x8000000000
            self.arch = '64bit'
        elif elf_ex['e_machine'] == Elf.EM_386:
            print '[+] EM_386'
            self.elf_structs = self.ElfStructMap['32bit']
            self.stack_top = 0xc000000
            self.arch = '32bit'
        else:
            raise Exception, '[-] unsupported ELF binary'
       
        # reparse the header after establishing machine type
        elf_ex = self.elf_structs['elfhdr'](data = self.elf_data)
        elf_ex.debugprint()

        if self.platform_arch != self.arch and arch_override == False:
            raise Exception, '[-] Platform arch and binary arch mismatch'

        for i in range(0, Elf.SELFMAG):
            if elf_ex['e_ident'][i] != Elf.ELFMAG[i]:
                raise Exception, '[-] ELFMAG not found'

        if elf_ex['e_type'] != Elf.ET_EXEC and elf_ex['e_type'] != Elf.ET_DYN:
            raise Exception, '[-] ET_EXEC | ET_DYN e_type not found'

        if elf_ex['e_phentsize'] != self.elf_structs['elf_phdr']().calcsize():
            raise Exception, '[-] e_phentsize does not match'

        if elf_ex['e_phnum'] < 1 or elf_ex['e_phnum'] > 65536 / self.elf_structs['elf_phdr']().calcsize():
            raise Exception, '[-] malformed e_phnum'

        # get the phdrs out into phdr table
        print '[+] building phdr table'
        phdr_size = elf_ex['e_phnum'] * self.elf_structs['elf_phdr']().calcsize()
        phdr_data = self.elf_data[elf_ex['e_phoff']:elf_ex['e_phoff']+phdr_size]
        phdrs = []
        for i in range(0, elf_ex['e_phnum']):
            phdr = self.elf_structs['elf_phdr'](data = phdr_data)
            phdr_data = phdr_data[phdr.calcsize():]
            #phdr.debugprint()
            phdrs.append(phdr)

        # get the shdrs out into shdr table
        print '[+] building shdr table'
        shdr_size = elf_ex['e_shnum'] * self.elf_structs['elf_shdr']().calcsize()
        shdr_data = self.elf_data[elf_ex['e_shoff']:elf_ex['e_shoff']+shdr_size]
        shdrs = []
        for i in range(0, elf_ex['e_shnum']):
            shdr = self.elf_structs['elf_shdr'](data = shdr_data)
            shdr_data = shdr_data[shdr.calcsize():]
            shdrs.append(shdr)

        # get the section names
        print '[+] resolving section names'
        strtab_data = ''
        dynstr_data = ''
        for shdr in shdrs:
            # we can grab .shstrtab index directly from the elf header
            shdr_strtab = shdrs[elf_ex['e_shstrndx']]
            if shdr_strtab['sh_type'] != Elf.SHT_STRTAB:
                print '[+] unexpected type for strtab'
                continue
            str_data = self.elf_data[shdr_strtab['sh_offset']:shdr_strtab['sh_offset']+shdr_strtab['sh_size']]
            #print repr(str_data)
            section_name = str_data[shdr['sh_name']:]
            section_name = section_name[:section_name.find('\x00')]
            #shdr.debugprint()
            if section_name:
                print '[+] section: %s' % section_name
            # grab strtab data for convenience
            if section_name == '.strtab':
                strtab_data = self.elf_data[shdr['sh_offset']:shdr['sh_offset']+shdr['sh_size']]
                print '[+] retrieved .strtab data'
            if section_name == '.dynstr':
                dynstr_data = self.elf_data[shdr['sh_offset']:shdr['sh_offset']+shdr['sh_size']]
                print '[+] retrieved .dynstr data'
            # so name only has to be resolved once
            shdr['section_name'] = section_name

        # parse and resolve the symtabs
        print '[+] parsing symtabs'
        for shdr in shdrs:
            if shdr['sh_type'] == Elf.SHT_SYMTAB or shdr['sh_type'] == Elf.SHT_DYNSYM:
                print '[+] found %s' % { Elf.SHT_SYMTAB : 'SHT_SYMTAB', 
                        Elf.SHT_DYNSYM : 'SHT_DYNSYM' }[shdr['sh_type']]
                #shdr.debugprint()
                esym_num = shdr['sh_size']/self.elf_structs['elf_sym']().calcsize()
                print '[+] %d esyms' % esym_num
                # build esym table
                esym_data = self.elf_data[shdr['sh_offset']:shdr['sh_offset']+shdr['sh_size']]
                esyms = []
                for i in range(0, esym_num):
                    esym = self.elf_structs['elf_sym'](data = esym_data)
                    esym_data = esym_data[esym.calcsize():]
                    #esym.debugprint()
                    esyms.append(esym)
                # resolve names for symbol table from string table
                print '[+] resolving symbol names'
                for esym in esyms:
                    #esym.debugprint()
                    if esym['st_value'] == 0:
                        continue
                    # if you want to test for symbol types see below ...
                    #if Elf.ELF_ST_BIND(esym['st_info']) == Elf.STB_WEAK:
                    #    print '[+] STB_WEAK'
                    #    continue
                    #if Elf.ELF_ST_BIND(esym['st_info']) == Elf.STB_NUM:
                    #    print '[+] STB_NUM'
                    #    continue
                    #if Elf.ELF_ST_TYPE(esym['st_info']) != Elf.STT_FUNC:
                    #    print '[+] !STT_FUNC'
                    #    continue
                    #esym.debugprint()
                    # check for special indexes for the assocated sections
                    if esym['st_shndx'] == Elf.SHN_UNDEF:
                        print '[+] SHN_UNDEF'
                    elif esym['st_shndx'] == Elf.SHN_LORESERVE:
                        print '[+] SHN_LORESERVE'
                    elif esym['st_shndx'] == Elf.SHN_LOPROC:
                        print '[+] SHN_LOPROC'
                    elif esym['st_shndx'] == Elf.SHN_HIPROC:
                        print '[+] SHN_HIPROC'
                    elif esym['st_shndx'] == Elf.SHN_LOOS:
                        print '[+] SHN_LOOS'
                    elif esym['st_shndx'] == Elf.SHN_HIOS:
                        print '[+] SHN_HIOS'
                    elif esym['st_shndx'] == Elf.SHN_ABS:
                        print '[+] SHN_ABS'
                    elif esym['st_shndx'] == Elf.SHN_COMMON:
                        print '[+] SHN_COMMON'
                    elif esym['st_shndx'] == Elf.SHN_HIRESERVE:
                        print '[+] SHN_HIRESERVE'
                    # if you want to do something with associated sections see below ...
                    #else:
                    #    print '[+] dumping associated section ...'
                    #    esym_shdr = shdrs[esym['st_shndx']]
                    #    esym_shdr.debugprint()
                    if shdr['sh_type'] == Elf.SHT_DYNSYM:
                        symbol_name = dynstr_data[esym['st_name']:]
                    if shdr['sh_type'] == Elf.SHT_SYMTAB:
                        symbol_name = strtab_data[esym['st_name']:]
                    symbol_name = symbol_name[:symbol_name.find('\x00')]
                    #if symbol_name:
                    #    print '[+] symbol: %s' % symbol_name
                    esym['symbol_name'] = symbol_name
                    # we have to set these so PT_TLS can be setup correctly
                    if symbol_name in ['_dl_phdr', '_dl_phnum', '_dl_random']:
                        self.pouvelf[symbol_name] = esym['st_value']
                        print '[+] found %s as 0x%x' % (symbol_name, self.pouvelf[symbol_name])

        interp_elf_ex = None
        for phdr in phdrs:
            if phdr['p_type'] == Elf.PT_INTERP:
                print '[+] PT_INTERP found'
                if phdr['p_filesz'] > 0x1000 or phdr['p_filesz'] < 2:
                    raise Exception, '[-] malformed p_filesz'
                elf_interpreter = self.elf_data[phdr['p_offset']:phdr['p_offset']+phdr['p_filesz']]
                print '[+] elf_interpreter %s' % repr(elf_interpreter)
                if elf_interpreter[phdr['p_filesz']-1] != '\x00':
                    raise Exception, '[-] malformed elf_interpreter'
                interp_elf_data = open(elf_interpreter[:-1], 'r').read()
                interp_elf_ex = self.elf_structs['elfhdr'](data = interp_elf_data)

        for phdr in phdrs:
            if phdr['p_type'] == Elf.PT_GNU_STACK:
                print '[+] PT_GNU_STACK found'
                if phdr['p_flags'] & Elf.PF_X:
                    print '[+] enabled executable stack'
                    self.executable_stack = True
                else:
                    print '[+] disabled executable stack'
                    self.executable_stack = False
        
        if interp_elf_ex is not None:
            if interp_elf_ex['e_type'] != Elf.ET_EXEC and interp_elf_ex['e_type'] != Elf.ET_DYN:
                raise Exception, '[-] ET_EXEC | ET_DYN e_type not found'

        # PT_SEGMENTS loop
        for phdr in phdrs:
            
            # get PT_TLS and PT_NOTE out as well
            if phdr['p_type'] in [Elf.PT_TLS, Elf.PT_NOTE]:
                print '[+] PT_TLS or PT_NOTE found'
                phdr.debugprint()
                phdr['data'] = self.elf_data[phdr['p_offset']:phdr['p_offset']+phdr['p_filesz']]
                self.pouvelf['PT_SEGMENTS'].append(phdr)
            
            if phdr['p_type'] != Elf.PT_LOAD:
                continue

            elf_prot = 0
            elf_flags = 0

            print '[+] PT_LOAD segment ... packing into POUVELF'
            # we only care about the PT_LOAD segments really ...
            phdr['data'] = self.elf_data[phdr['p_offset']:phdr['p_offset']+phdr['p_filesz']]
            self.pouvelf['PT_SEGMENTS'].append(phdr)

            if phdr['p_flags'] & Elf.PF_R:
                print '[+] PROT_READ'
                elf_prot |= mman_h.PROT_READ
            if phdr['p_flags'] & Elf.PF_W:
                print '[+] PROT_WRITE'
                elf_prot |= mman_h.PROT_WRITE
            if phdr['p_flags'] & Elf.PF_X:
                print '[+] PROT_EXEC'
                elf_prot |= mman_h.PROT_EXEC
            
            # needed for pouvelf mapping
            phdr['prot'] = elf_prot

            elf_flags = mman_h.MAP_PRIVATE | mman_h.MAP_DENYWRITE | mman_h.MAP_EXECUTABLE
            vaddr = phdr['p_vaddr']
            paddr = phdr['p_paddr']
            print '[+] p_vaddr: 0x%x' % vaddr
            print '[+] p_paddr: 0x%x' % paddr
            if elf_ex['e_type'] == Elf.ET_EXEC:
                print '[+] ET_EXEC'
                elf_flags |= mman_h.MAP_FIXED
            elif elf_ex['e_type'] == Elf.ET_DYN:
                print '[+] ET_DYN'

        # pack in the e_entry
        print '[+] packing e_entry 0x%x into POUVELF' % elf_ex['e_entry']
        self.pouvelf['e_entry'] = elf_ex['e_entry']
        print '[+] packing e_phoff 0x%x into POUVELF' % elf_ex['e_phoff']
        self.pouvelf['e_phoff'] = elf_ex['e_phoff']

        # build PT_PVELF_STACK stack context
        print '[+] building POUVELF stack context'
        print '[+] argv: %s' % repr(argv)
        print '[+] envp: %s' % repr(envp)
        stack_phdr = self.elf_structs['elf_phdr']()
        stack_phdr['p_align'] = 0x1000 # XXX ... this gets dynamically replaced in loader
        stack_phdr['p_type'] = Elf.PT_PVELF_STACK
        stack_phdr['p_offset'] = 0 # moot
        stack_phdr['p_vaddr'] = stack_phdr['p_align']
        stack_phdr['p_paddr'] = stack_phdr['p_align']
        stack_phdr['data'] = self.make_stack(argv, envp) 
        stack_phdr['p_filesz'] = len(stack_phdr['data'])
        stack_phdr['p_memsz'] = len(stack_phdr['data'])
        # pack it in as the last header to load
        self.pouvelf['PT_SEGMENTS'].append(stack_phdr)

    # XXX: stack context can only be <= 0x1000 for right now
    def make_stack(self, argv, envp):
        pack_fmt = { '32bit' : '<I', '64bit' : '<Q' }
        env_addr = []
        arg_addr = []
        env_data = '\x00'.join(envp) + '\x00'
        arg_data = '\x00'.join(argv) + '\x00'
        stack = ''
        top_null = struct.pack(pack_fmt[self.arch], 0)
        stack_top = 0x1000-len(top_null)
        envp.reverse()
        for env in envp:
            stack_top -= (len(env)+1)
            env_addr.append(stack_top)
        env_addr.reverse()
        env_addr.append(0)
        argv.reverse()
        for arg in argv:
            stack_top -= (len(arg)+1)
            arg_addr.append(stack_top)
        arg_addr.reverse()
        arg_addr.append(0)
        # build the actual stack context
        stack += struct.pack(pack_fmt[self.arch], len(argv)) # argc
        # argv
        for addr in arg_addr:
            stack += struct.pack(pack_fmt[self.arch], addr)
        # envp
        for addr in env_addr:
            stack += struct.pack(pack_fmt[self.arch], addr)
        # work out the auxv space + the stack align ... XXX: double check this
        stack += (8*4 + ((0x1000-len(env_data+arg_data+top_null)) - ((0x1000-len(env_data+arg_data+top_null)) & 0xfff0))) * '\x00'
        stack += arg_data + env_data + top_null
        return stack

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print 'Usage: %s path' % sys.argv[0]
        sys.exit(0)
    print '[+] Testing with: %s' % sys.argv[1] 
    pouvelf = ElfLoader(path = sys.argv[1])
    argv = [sys.argv[1]]
    argv += sys.argv[2:]
    pouvelf.prep_elf(argv=argv, envp=['PATH=/tmp'])
    pouvelf.load_elf()
