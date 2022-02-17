#! /usr/bin/env python

__all__ = [
    'mosdef',
    'mosdefutils',
    'mosdef_errno',
    'MOSDEFlibc',
    'binfmt',
    
    'lex',
    'yacc',
    'remoteresolver',    
    'win32remoteresolver',
    'win64remoteresolver',
    'linuxremoteresolver',
    'solarisremoteresolver',
    'bsdremoteresolver',
    'osxremoteresolver',
    
    'cpp',
    'makeexe',
    'pelib',
    'win32peresolver',
    
    'riscscan',
    'riscparse',
    'riscassembler',
    'il2risc',
    
    'struct_endian',
]

def GetMOSDEFlibc(*args):
    from MOSDEFlibc import GetMOSDEFlibc as _GetMOSDEFlibc
    return _GetMOSDEFlibc(*args)

#from mosdef import compile_to_IL, compile, assemble

