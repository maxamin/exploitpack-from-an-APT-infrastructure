#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from UnixSystemV import UnixSystemV

class SVR4(UnixSystemV):
    
    # <sys/utssys.h>
    
    # "commands" of utssys
    UTS_UNAME  = 0x0
    UTS_UMASK  = 0x1
    UTS_USTAT  = 0x2
    UTS_FUSERS = 0x3
    
    # Flags to UTS_FUSERS
    F_FILE_ONLY = 0x1
    F_CONTAINED = 0x2
    
    # fu_flags values
    F_CDIR  = 0x1
    F_RDIR  = 0x2
    F_TEXT  = 0x4
    F_MAP   = 0x8
    F_OPEN  = 0x10
    F_TRACE = 0x20
    F_TTY   = 0x40
    
    def __init__(self):
        UnixSystemV.__init__(self)

