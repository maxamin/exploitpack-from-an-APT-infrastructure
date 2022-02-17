#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from BSD import BSD43

# started on 4.1BSD
# SunOS 5.0 and further is Solaris

class SunOS(BSD43):
    
    def __init__(self):
        BSD43.__init__(self)

