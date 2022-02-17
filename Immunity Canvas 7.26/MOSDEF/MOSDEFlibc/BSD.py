#! /usr/bin/env python

from UNIX import UNIX
from asm.Linux.i386 import i386

class BSD(UNIX):
    #S_IREAD =  S_IRUSR
    #S_IWRITE = S_IWUSR
    #S_IEXEC =  S_IXUSR

    def __init__(self):
        UNIX.__init__(self)


class BSD41(BSD): # HPUX+IRIX+SunOS+oldMacOS

    # <sys/ioctl.h>

    SIOCGIFADDR =    0xc020690dL # _IOWR('i',13, struct ifreq)
    SIOCGIFCONF =    0xc0086914L # _IOWR('i',20, struct ifconf)

    def __init__(self):
        BSD.__init__(self)


class BSD42(BSD41):

    # <netinet/in.h>

    INADDR_ANY       = 0x00000000
    INADDR_BROADCAST = 0xffffffff
    INADDR_NONE      = 0xffffffff
    INADDR_LOOPBACK  = 0x7f000001

    IN_LOOPBACKNET = 127

    def __init__(self):
        BSD41.__init__(self)


class BSD43(BSD42):

    # <sys/ioctl.h>

    SIOCGIFNETMASK = 0xc0206919L # _IOWR('i',21, struct ifreq)

    def __init__(self):
        BSD42.__init__(self)


class BSD44(BSD43):

    def __init__(self):
        BSD43.__init__(self)


class BSD44lite1(BSD44):

    def __init__(self):
        BSD44.__init__(self)


class BSD44lite2(BSD44lite1):

    def __init__(self):
        BSD44lite1.__init__(self)


# XXX: place holder untill we have time to fully port it over
# XXX: TODO: port defines, port syscall table, port syscall gen.
# XXX: TODO: deal with stat asm.i386 structs for BSD
# XXX: TODO: match functionality with Linux_intel class
# BuildCallBackTrojan can be used to test this:
# exploits/BuildCallbackTrojan/BuildCallbackTrojan.py -t 0.0.0.0 -O callback_host:192.168.1.1 -O callback_port:5555 -O OS:BSD


class BSD_intel(BSD44lite2, i386):

    #<fcntl.h>
    O_CREAT     =0x0200
    O_RDWR      =0x0002
    O_TRUNC     =0x0400
    O_RDONLY    =0x0000

    def __init__(self, version = None):
        BSD44lite2.__init__(self)
        i386.__init__(self)

class BSD_x86(BSD_intel):

    def __init__(self, version = None):
        BSD_intel.__init__(self, version)
