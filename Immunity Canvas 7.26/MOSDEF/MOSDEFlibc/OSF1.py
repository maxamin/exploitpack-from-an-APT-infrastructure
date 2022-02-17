#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from UNIX import UNIX
from BSD import BSD43
from SVR4 import SVR4

class OSF1(SVR4, BSD43, UNIX):
    
    # <sys/mman.h>
    
    PROT_NONE =  0x0
    PROT_READ =  0x1
    PROT_WRITE = 0x2
    PROT_EXEC =  0x4
    
    MAP_SHARED =  0x001
    MAP_PRIVATE = 0x002
    MAP_FIXED =   0x100
    
    MAP_FAILED = -1
    
    MAP_FILE = 0x00
    MAP_ANON = 0x10
    MAP_ANONYMOUS = MAP_ANON
    
    def __init__(self, *args):
        UNIX.__init__(self)
        BSD43.__init__(self)
        SVR4.__init__(self)

