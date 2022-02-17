#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

# XXX TODO verify BSD link later...

from UNIX import UNIX
from BSD import BSD42

class GNU(UNIX, BSD42): # formally it's not UNIX
    
    def __init__(self):
        UNIX.__init__(self)
        BSD42.__init__(self) # XXX hem... need verifications.

