#! /usr/bin/env python

from BSD import BSD43, BSD44, BSD44lite2

class FreeBSD1(BSD43):
    
    def __init__(self):
        BSD43.__init__(self)


class FreeBSD2(FreeBSD1, BSD44):
    
    def __init__(self):
        FreeBSD1.__init__(self)
        BSD44.__init__(self)


class FreeBSD3(FreeBSD2, BSD44lite2):
    
    def __init__(self):
        FreeBSD2.__init__(self)
        BSD44lite2.__init__(self)


class FreeBSD32(FreeBSD3):
    
    def __init__(self):
        FreeBSD3.__init__(self)


class FreeBSD33(FreeBSD32):
    
    def __init__(self):
        FreeBSD32.__init__(self)


class FreeBSD34(FreeBSD33):
    
    def __init__(self):
        FreeBSD33.__init__(self)


class FreeBSD40(FreeBSD34):
    
    def __init__(self):
        FreeBSD34.__init__(self)


class FreeBSD41(FreeBSD40):
    
    def __init__(self):
        FreeBSD40.__init__(self)


class FreeBSD42(FreeBSD41):
    
    def __init__(self):
        FreeBSD41.__init__(self)


class FreeBSD45(FreeBSD42):
    
    def __init__(self):
        FreeBSD42.__init__(self)

