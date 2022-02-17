#! /usr/bin/env python

from UNIX import UNIX
from BSD import BSD43
from SVR4 import SVR4

class NextSTEP(SVR4, BSD43, UNIX):
    
    def __init__(self, *args):
        UNIX.__init__(self)
        BSD43.__init__(self)
        SVR4.__init__(self)

