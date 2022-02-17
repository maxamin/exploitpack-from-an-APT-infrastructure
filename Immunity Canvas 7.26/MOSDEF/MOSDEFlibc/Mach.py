#! /usr/bin/env python

from BSD import BSD42

class Mach(BSD42):
    
    def __init__(self):
        BSD42.__init__(self)


class Mach2(Mach):
    
    def __init__(self):
        Mach.__init__(self)


class Mach3(Mach2):
    
    def __init__(self):
        Mach2.__init__(self)

