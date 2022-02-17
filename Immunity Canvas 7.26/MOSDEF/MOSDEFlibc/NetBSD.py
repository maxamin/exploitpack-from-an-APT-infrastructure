#! /usr/bin/env python

# XXX incomplete...

from BSD import BSD43, BSD44lite1, BSD44lite2

class NetBSD0(BSD43):
    
    def __init__(self):
        BSD43.__init__(self)


class NetBSD1(NetBSD0, BSD44lite1):
    
    def __init__(self):
        NetBSD0.__init__(self)
        BSD44lite1.__init__(self)


class NetBSD13(NetBSD1, BSD44lite2):
    
    def __init__(self):
        NetBSD1.__init__(self)
        BSD44lite2.__init__(self)



