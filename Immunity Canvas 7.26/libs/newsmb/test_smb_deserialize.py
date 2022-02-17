#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_smb_deserialize.py
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
import libs.newsmb.libsmb as libsmb

###
# Test #1 - TransResponse
###

def test1():

    s1  = "ff534d4225000000008807c80000acc9"
    s1 += "a0dde29c8ddd00000308cf8301103f00"
    s1 += "0a060044000000060038000000440040"
    s1 += "00000000004d00004400440003000000"
    s1 += "05000c03100000004400000000000000"
    s1 += "b810b810d24500000d005c706970655c"
    s1 += "6e747376637300000100000000000000"
    s1 += "045d888aeb1cc9119fe808002b104860"
    s1 += "02000000"

    data = s1.decode('hex')
    trans_data = data[64:64+68].encode('hex')
    trans_params = data[56:56+6].encode('hex')

    factory = libsmb.SMB_CommandFactory()
    header = libsmb.SMB_Header.deserialize(data)
    ctx = SMB_SerializationContext()
    command = factory.deserialize_response(header['Command'], data, ctx)

    assertions = []
    assertions += [ command.header['TID'] == 2051 ]
    assertions += [ command.header['MID'] == 63 ]
    assertions += [ command.parameters['TotalParameterCount'] == 6 ]
    assertions += [ str(command.data['Pad1'])== repr('\x00') ]
    assertions += [ str(command.data['Trans_Parameters']) == trans_params ]
    assertions += [ str(command.data['Pad2']) == repr('\x00'*2) ]
    assertions += [ str(command.data['Trans_Data']) == trans_data ]

    #print command

    for a in assertions:
        if not a:
            print "!!!!!!!! Fail !!!!!!!!"
            print command
            sys.exit(1)


###
# Test #2 - TransResponse
###

def test2():

    s  = "ff534d4225000000008806c80000d302"
    s += "b6f3e6f8bdbb0000008875b700603f00"
    s += "0a0600440000000600e40300004400f4"
    s += "03000000000104000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000000000000000000000000000"
    s += "00000000440044000300000000000000"
    s += "0000000005000c031000000044000000"
    s += "00000000b810b8104d4700000d005c70"
    s += "6970655c6e7473766373000001000000"
    s += "00000000045d888aeb1cc9119fe80800"
    s += "2b10486002000000"

    data = s.decode('hex')
    trans_data = data[1012:1012+68].encode('hex')
    trans_params = data[996:996+6].encode('hex')

    factory = libsmb.SMB_CommandFactory()
    header = libsmb.SMB_Header.deserialize(data)
    ctx = SMB_SerializationContext()
    command = factory.deserialize_response(header['Command'], data, ctx)

    assertions = []
    assertions += [ command.header['TID'] == 34816 ]
    assertions += [ command.header['MID'] == 63 ]
    assertions += [ command.parameters['TotalParameterCount'] == 6 ]
    assertions += [ str(command.data['Pad1'])== repr('\x00'*941) ]
    assertions += [ str(command.data['Trans_Parameters']) == trans_params ]
    assertions += [ str(command.data['Pad2']) == repr('\x00'*10) ]
    assertions += [ str(command.data['Trans_Data']) == trans_data ]

    for a in assertions:
        if not a:
            print "!!!!!!!! Fail !!!!!!!!"
            print command
            sys.exit(1)

###
# Test #3 - TransReq
###

# TODO: The test is not ready yet.
def test3():

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

    #print s
    data = s.decode('hex')
    #trans_data = data[1012:1012+68].encode('hex')
    #trans_params = data[996:996+6].encode('hex')
    
    factory = libsmb.SMB_CommandFactory()
    header = libsmb.SMB_Header.deserialize(data)
    ctx = SMB_SerializationContext()
    command = factory.deserialize_request(header['Command'], data, ctx)
    #print command

if __name__ == "__main__":
    test1()
    test2()
    test3()

