#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_smb_serialize.py
## Description:
##            :
## Created_On :  Mon Apr 9 CEST 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import os
import sys
import traceback
from struct import pack, unpack, calcsize

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.Struct import Struct
from libs.newsmb.smbconst import *
from libs.newsmb.smb_serialize import *
from libs.newsmb.serialize import *
from libs.newsmb.smb_string import *
import libs.newsmb.libsmb as libsmb

###
# Test #1 - SMB_COM_TRANSACTION packet (request)
###

def test1():

    s  = "ff534d4225000000000807c800002b05"
    s += "59705a7a009f00000308cf830110ff00"
    s += "10000074000000004000000000000000"
    s += "00000000005200740052000200260002"
    s += "408300005c0050004900500045005c00"
    s += "00000500000310000000740000000000"
    s += "00005c00000000000f00000002000c00"
    s += "0000000000000c000000570068006100"
    s += "74004500760065007200420072006f00"
    s += "0000080002000f000000000000000f00"
    s += "00005300650072007600690063006500"
    s += "73004100630074006900760065000000"
    s += "00003f000000"

    connection = libsmb.SMB_Connection()
    factory = libsmb.SMB_CommandFactory()
    req = factory.request(SMB_COM_TRANSACTION, connection)
    req.header['TID'] = 2051
    req.header['PID'] = 33743
    req.header['UID'] = 4097
    req.header['MID'] = 255

    req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
    req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
    req.header['Flags2'] |= SMB_FLAGS2_UNICODE
    req.header['Flags2'] |= SMB_FLAGS2_KNOWS_LONG_NAMES
    req.header['Flags2'] |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE
    req.header['Flags2'] |= SMB_FLAGS2_EXTENDED_SECURITY

    req.parameters['TotalDataCount'] = 116
    req.parameters['MaxParameterCount'] = 0
    req.parameters['MaxDataCount'] = 16384
    req.parameters['MaxSetupCount'] = 0
    
    req.parameters['ParameterCount'] = 0
    req.parameters['ParameterOffset'] = 82
    req.parameters['DataCount'] = 116
    req.parameters['DataOffset'] = 82

    setup = pack('<HH', TRANS_TRANSACT_NMPIPE, 0x4002)
    req.parameters['SetupCount'] = len(setup) / 2
    req.parameters['Setup'] = USHORT_Array(setup)
    
    data  = "05000003100000007400000000000000"
    data += "5c00000000000f00000002000c000000"
    data += "000000000c0000005700680061007400"
    data += "4500760065007200420072006f000000"
    data += "080002000f000000000000000f000000"
    data += "53006500720076006900630065007300"
    data += "41006300740069007600650000000000"
    data += "3f000000"
    data = data.decode('hex')

    req.data['Name'] = SMB_String(u'\\PIPE\\')
    req.data['Trans_Data'] = UCHAR_Array(data)

    s2 = req.serialize().encode('hex')

    if len(s) != len(s2):
        print "!!!! FAIL !!!!"
        sys.exit(1)

    nbr_errors = 0
    for i in xrange(len(s)):
        if s[i] != s2[i]:
            nbr_errors += 1

    # Signature mismatch is allowed, this should be the only bytes mangled.
    if nbr_errors > 12:
        print "!!!! FAIL !!!!"
        sys.exit(1)

if __name__ == "__main__":
    test1()


