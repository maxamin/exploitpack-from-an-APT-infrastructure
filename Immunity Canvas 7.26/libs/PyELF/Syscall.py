# the syscall bridge layer driving the PyElf userland ELF loader
import platform
import sys
import ctypes
import ctypes.util

X64_SYSCALLS = {
        # name, syscall nr., ret type, argtypes
        'write'    : (1, ctypes.c_int, [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]),
        'mmap'     : (9, ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]),
        'mprotect' : (10, ctypes.c_int, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]), 
        'munmap'   : (11, ctypes.c_int, [ctypes.c_void_p, ctypes.c_uint]),
        'getuid'   : (102, ctypes.c_int, []),
        'setuid'   : (105, ctypes.c_int, [ctypes.c_int])
        }
X86_SYSCALLS = {
        'write'    : (4, ctypes.c_int, [ctypes.c_int, ctypes.c_char_p, ctypes.c_int]),
        # mmap2
        'mmap'     : (192, ctypes.c_void_p, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]),
        'mprotect' : (125, ctypes.c_int, [ctypes.c_void_p, ctypes.c_uint, ctypes.c_int]),
        'munmap'   : (91, ctypes.c_int, [ctypes.c_void_p, ctypes.c_uint]),
        'getuid'   : (24, ctypes.c_int, []),
        'setuid'   : (23, ctypes.c_int, [ctypes.c_int])
        }
ARCH_MAP = { 
        '64bit' : X64_SYSCALLS, 
        '32bit' : X86_SYSCALLS 
        }

class SyscallError(Exception):
    def __init__(self, v):
        self.v = v
    def __str__(self):
        return repr(self.v)

class Syscall:
    """ a ctypes based python system call bridge """
    
    def __init__(self):
        self.arch,self.bin_fmt = platform.architecture()
        self.libc = ctypes.cdll.LoadLibrary(ctypes.util.find_library('c'))
        if self.arch not in ARCH_MAP:
            raise SyscallError, '[-] Arch not supported'
        if self.bin_fmt != 'ELF':
            raise SyscallError, '[-] Binary fmt not supported'
        self.syscalls = ARCH_MAP[self.arch]

    # args is a tuple
    def syscall_bridge(self, *args):
        sc = getattr(self.libc, 'syscall')
        sys_nr, sc.restype, sc.argtypes = self.syscalls[args[0]]
        sc.argtypes = [ctypes.c_int] + sc.argtypes
        if len(args[1:]) != len(sc.argtypes)-1:
            raise SyscallError, '[-] Unexpected number of args'
        return sc(*((sys_nr,) + args[1:]))

if __name__ == '__main__':
    test = Syscall()
    print '[+] Testing getuid'
    uid = test.syscall_bridge('getuid')
    print uid
    print '[+] Testing setuid'
    print test.syscall_bridge('setuid', uid)
    bla = 'writewritewrite\n'
    print '[+] Testing write'
    test.syscall_bridge('write', 1, bla, len(bla))
    import MmanHeader as mman_h
    print '[+] Testing mmap'
    addr = test.syscall_bridge('mmap', 0, 0x1000, mman_h.PROT_READ|mman_h.PROT_WRITE, mman_h.MAP_ANONYMOUS|mman_h.MAP_PRIVATE, -1, 0)
    print '0x%x' % addr
    print '[+] Testing mprotect'
    print test.syscall_bridge('mprotect', addr, 0x1000, mman_h.PROT_READ|mman_h.PROT_EXEC)
    print '[+] Testing munmap'
    print test.syscall_bridge('munmap', addr, 0x1000)
