
#! /usr/bin/env python
######################################################################################
# White Phosphorus Exploit Pack
#
# Proprietary source code - use only under the license agreement in distribution
#
# This is the exploit pack dialog controller library file.
#
######################################################################################

"""
wp_osversions
"""

CHANGELOG="""
"""
######################################################################################

# Canvas Modules
from libs.canvasos import canvasos

WINALL = canvasos("Windows")

WIN2K = canvasos("Windows")
WIN2K.version = "2000"

WIN2KSP0 = canvasos("Windows")
WIN2KSP0.version = "2000"
WIN2KSP0.servicepack = ["SP0"]

WIN2KSP1 = canvasos("Windows")
WIN2KSP1.version = "2000"
WIN2KSP1.servicepack = ["SP1"]

WIN2KSP2 = canvasos("Windows")
WIN2KSP2.version = "2000"
WIN2KSP2.servicepack = ["SP2"]

WIN2KSP3 = canvasos("Windows")
WIN2KSP3.version = "2000"
WIN2KSP3.servicepack = ["SP3"]

WIN2KSP4 = canvasos("Windows")
WIN2KSP4.version = "2000"
WIN2KSP4.servicepack = ["SP4"]

WIN2K3 = canvasos("Windows")
WIN2K3.version = "2003"

WIN2K3SP0 = canvasos("Windows")
WIN2K3SP0.version = "2003"
WIN2K3SP0.servicepack = ["SP0"]

WIN2K3SP1 = canvasos("Windows")
WIN2K3SP1.version = "2003"
WIN2K3SP1.servicepack = ["SP1"]

WIN2K3SP2 = canvasos("Windows")
WIN2K3SP2.version = "2003"
WIN2K3SP2.servicepack = ["SP2"]


WINXP = canvasos("Windows")
WINXP.version = "XP"

WINXPSP0 = canvasos("Windows")
WINXPSP0.version = "XP"
WINXPSP0.servicepack = ["SP0"]

WINXPSP1 = canvasos("Windows")
WINXPSP1.version = "XP"
WINXPSP1.servicepack = ["SP1"]

WINXPSP2 = canvasos("Windows")
WINXPSP2.version = "XP"
WINXPSP2.servicepack = ["SP2"]

WINXPSP3 = canvasos("Windows")
WINXPSP3.version = "XP"
WINXPSP3.servicepack = ["SP3"]


WINVISTA = canvasos("Windows")
WINVISTA.version = "Vista"

WINVISTASP0 = canvasos("Windows")
WINVISTASP0.version = "Vista"
WINVISTASP0.servicepack = ["SP0"]

WINVISTASP1 = canvasos("Windows")
WINVISTASP1.version = "Vista"
WINVISTASP1.servicepack = ["SP1"]

WINVISTASP2 = canvasos("Windows")
WINVISTASP2.version = "Vista"
WINVISTASP2.servicepack = ["SP2"]


WIN7 = canvasos("Windows")
WIN7.version = "7"

WIN7SP0 = canvasos("Windows")
WIN7SP0.version = "7"
WIN7SP0.servicepack = ["SP0"]

WIN7SP1 = canvasos("Windows")
WIN7SP1.version = "7"
WIN7SP1.servicepack = ["SP1"]

WIN7SP2 = canvasos("Windows")
WIN7SP2.version = "7"
WIN7SP2.servicepack = ["SP2"]


WIN2008 = canvasos("Windows")
WIN2008.version = "2008"

WIN2008SP0 = canvasos("Windows")
WIN2008SP0.version = "2008"
WIN2008SP0.servicepack = ["SP0"]

WIN2008SP1 = canvasos("Windows")
WIN2008SP1.version = "2008"
WIN2008SP1.servicepack = ["SP1"]

WIN2008SP2 = canvasos("Windows")
WIN2008SP2.version = "2008"
WIN2008SP2.servicepack = ["SP2"]


LINALL = canvasos("Linux")


FBSDALL = canvasos("FreeBSD")


def osIsAtLeast(target, remoteos):
    """Considering only attributes which are set in target, are we the same as remoteos?"""
    props = ["base", "servicepack", "version", "build", "language", "arch", "kernel_version", "family"]
    rv = True
        
    for p in [x for x in props if getattr(target,x,None)]:
        ta = getattr(target,p)
        ra = getattr(remoteos,p)
                
        # handle lists, ala service pack
        # either or both could be lists
        if type(ta) == list and type(ra) == list:
            found = False
            for t in ta:
                if t in ra:
                    found = True
                    break
            if not found:
                rv = False
                break
        elif type(ta) == list and type(ra) != list:
            if ra.startswith("["):
                # davestyle 'list'
                davelist =  eval(repr(ra))
                found = False
                for t in ta:
                    if t in davelist:
                        found = True
                        break
                if not found:
                    rv = False
                    break
            else:
                if ra not in ta:
                    rv = False
                    break
        elif type(ta) != list and type(ra) == list:
            if ta not in ra:
                rv = False
                break
        else:
            if ta != ra:
                rv = False
                break
       
    return rv
