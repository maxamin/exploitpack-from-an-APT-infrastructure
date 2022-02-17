#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
if "." not in sys.path: sys.path.append(".")

from internal import devlog
__all__ = [
    'asm',
]

__MOSDEFlibc_cache = {}

__MOSDEFlibc_proctable = {
    'x86'   : ["i386", "i486", "i586", "i686", "i86pc"],
    'x64'   : ["x64"],
    'sparc' : ["sparc64"],
}

__procname_table = {
    'ppc'    : "powerpc",
    'mipsel' : "mips",
    'armel'  : "armel",
    'arm9'   : "armel",
}


def GetMOSDEFlibc(os, proc=None, version=None):
    import sys
    global __MOSDEFlibc_cache
    if proc:
        proc = proc.lower()

    if proc not in __MOSDEFlibc_proctable.keys():
        for procfamily in __MOSDEFlibc_proctable.keys():
            if proc in __MOSDEFlibc_proctable[procfamily]:
                proc = procfamily
                break

    if proc in __procname_table.keys():
        proc = __procname_table[proc]

    sysnamekey = "%s_%s_%s" % (os, proc, version)

    if __MOSDEFlibc_cache.has_key(sysnamekey):
        #print "returning %s from cache" % sysnamekey, __MOSDEFlibc_cache[sysnamekey]
        return __MOSDEFlibc_cache[sysnamekey]

    old_path = sys.path

    # TODO: fix sys.path here
    sys.path = ['MOSDEFlibc', 'MOSDEF/MOSDEFlibc'] + old_path
    sysname = os
    if proc:
        sysname += '_' + proc
    else:
        proc = "Generic"

    devlog("MOSDEFLibC", "Importing %s.%s" % (os, sysname))

    libc = getattr(__import__(os), sysname)(version)
    setattr(libc, "_names", {'os':os, 'proc':proc, 'version':version})
    sys.path = old_path
    libc.postinit()
    libc.initStaticFunctions()
    __MOSDEFlibc_cache[sysnamekey] = libc

    return libc
