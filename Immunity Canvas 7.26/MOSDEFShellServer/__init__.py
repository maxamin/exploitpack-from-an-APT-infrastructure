#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from MSSgeneric import MSSgeneric

MSS_compat_tbl = {
    'Win32::x86':     ["win32MosdefShellServer", "win32shellserver"],
    'Solaris::sparc': ["solarisMosdefShellServer", "solarisshellserver"],
#    'FreeBSD::i386':  ["bsdMosdefShellserver", "bsdshellserver"],
    'MacOSX::ppc':    ["osxMosdefShellServer", "osxshellserver"],
}

def MosdefShellServer(os, proc, version = None):
    sysname = "%s::%s" % (os, proc)
    
    # old files
    if MSS_compat_tbl.has_key(sysname):
        mss = getattr(__import__(MSS_compat_tbl[sysname][0]), "old_" + MSS_compat_tbl[sysname][1])
    # new way
    else:
        try:
            mss = getattr(__import__("MOSDEFShellServer." + os, globals(), locals(), ["MOSDEFShellServer"]), "%s_%s" % (os, proc))
        except ImportError:
            raise AssertionError, "MosdefShellServer dunno about %s" % sysname
        except: # SyntaxError and so
            raise
    
    # we set a nice prompt here
    setattr(mss, 'prompt', os + "/MOSDEF")
    
    # old files
    return mss

