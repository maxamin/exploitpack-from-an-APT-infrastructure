#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys, os
import struct, gzip
ouigz_path = "oui-stripped.gz"

__moddir = os.path.dirname(sys.modules[__name__].__file__)
if __moddir != "":
    ouigz_path = __moddir + os.path.sep + ouigz_path

def MACresolve(macaddr):
    macaddr = "%02x%02x%02x" % struct.unpack('BBB', macaddr[:3])
    for line in gzip.open(ouigz_path).readlines():
        s = line.split(' ')
        mac = s[0]
        comp = " ".join(s[1:]).strip()
        if macaddr == mac:
            return comp
    return None

