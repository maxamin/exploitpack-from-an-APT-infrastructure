#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  samr.py
## Description:
##            :
## Created_On :  Tue Oct 6 CEST 2015
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

# The API is not 100% written but is currently working quite well.
# Implemented from Wireshark && [MS-SAMR].pdf

# Confirmed working with:
#    Windows 2003
#    Windows 2008 R2
#    Windows 7
#    Windows 2012

import sys
import logging
from struct import pack, unpack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libdcerpc import DCERPC, DCERPCString, DCERPCSid
from libs.newsmb.libdcerpc import RPC_C_AUTHN_WINNT
from libs.newsmb.libdcerpc import RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from libs.newsmb.Struct import Struct
from libs.Crypto.Cipher.DES import fiftysix_to_sixtyfour

###
# Constants
###

# The RPC methods
# TODO.

###
# SAMR Objects.
# No exception handling for these objects.
###

# TODO.

#######################################################################
#####
##### Exception classes
#####
#######################################################################

# TODO.

#######################################################################
#####
##### A couple of useful functions for other parts of CANVAS
#####
#######################################################################

# 2.2.11.1.3 Deriving Key1 and Key2 from a Little-Endian, Unsigned Integer Key
def DeriveKeyFromLittleEndian(key_int):
    """
    Key derivation mechanism used to recover hashes.
    """
    k = pack('<L',key_int)
    k1 = fiftysix_to_sixtyfour(k[0:4] + k[0:3])
    k2 = fiftysix_to_sixtyfour(k[3] + k[0:4] + k[0:2])
    return k1,k2


#######################################################################
#####
##### Well, the main :D
#####
#######################################################################

if __name__ == "__main__":
    pass
