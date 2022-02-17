#! /usr/bin/env python

import os, sys
import debug

def PythonVersion():
    try:
        import platform
        return platform.python_version_tuple()
    except:
        return sys.version_info[0:3]
 
def OSVersion():
    osversion = os.uname()[0]
    if osversion == "Darwin":
        osversion = "macosx"
    elif osversion == "SunOS":
        osversion = "solaris"
    elif osversion[:6] == "CYGWIN":
        osversion = "win32"
    return osversion.lower()

def MachineVersion():
    machine = os.uname()[-1]
    if machine[0] == "i" and machine[2:4] == "86":
        machine = "i386"
    elif machine[:4] == "sun4":
        machine = "sparc"
    elif machine == "Power Macintosh":
        machine = "powerpc"
    return machine.lower()

def SystemAPI():
    try:
        maj, min, micro = PythonVersion()
        modulename = "PySystemAPI_%s_%s_python%s%s" % (OSVersion(), MachineVersion(), maj, min)
        debug.devlog('SystemAPI', "trying to import module <%s>" % modulename)
        mod = __import__(modulename, globals(), locals(), ["internal"])
        return mod
    except:
        class void:
            pass
        return void()

if __name__ == '__main__':
    print "OS:", OSVersion()
    print "Machine:", MachineVersion()
    maj, min, micro = PythonVersion()
    systemapi = SystemAPI()
    print systemapi
    print "DIR:", dir(systemapi)
    #for m in dir(systemapi):
    #    print "%s is %s: %s" % (m, type(getattr(systemapi, m)), getattr(systemapi, m))
    print "done."

