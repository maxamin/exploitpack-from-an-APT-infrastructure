#! /usr/bin/env python

from BSD import BSD44lite2
from OPENSTEP import OPENSTEP
from NetBSD import NetBSD13

class RhapsodyDR1(OPENSTEP, BSD44lite2):
    
    def __init__(self, *args):
        OPENSTEP.__init__(self)
        BSD44lite2.__init__(self)


class RhapsodyDR2(RhapsodyDR1, NetBSD13):
    
    def __init__(self, *args):
        RhapsodyDR1.__init__(self)
        NetBSD13.__init__(self)

