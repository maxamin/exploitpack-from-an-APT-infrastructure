#! /usr/bin/env python

from Rhapsody import RhapsodyDR2
from MacOSX import MacOSX_DP2, MacOSX_DP3

class Darwin0(RhapsodyDR2, MacOSX_DP2):
    
    def __init__(self, *args):
        RhapsodyDR2.__init__(self)
        MacOSX_DP2.__init__(self)


class Darwin1(Darwin0, MacOSX_DP3):
    
    def __init__(self, *args):
        Darwin0.__init__(self)
        MacOSX_DP3.__init__(self)

