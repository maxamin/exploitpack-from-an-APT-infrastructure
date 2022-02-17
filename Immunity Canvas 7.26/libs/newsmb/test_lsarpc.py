#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_lsarpc.py
## Description:
##            :
## Created_On :  Tue Dec 23 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

# The API is not 100% written but is currently working quite well.

import sys
import logging
from struct import pack, unpack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libdcerpc import DCERPC
from libs.newsmb.libdcerpc import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
import libs.newsmb.lsarpc as lsa

HOST = '10.0.0.1'
USER1 = u'jojo1'
USER2 = u'Administrator'
USERS = [ USER1, USER2 ]
SIDS = [ ]

# NTLM account information
USERNAME = 'jojo1'
PASSWORD = 'foobar1234!'

def do_test():

    dce = DCERPC(u'ncacn_np:%s[\\lsarpc]' % HOST, getsock=None, username=USERNAME, password=PASSWORD)
    dce.max_dcefrag = 100
    dce.bind(u'12345778-1234-abcd-ef00-0123456789ab', u'0.0', RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)

    # 1. Open
    data = lsa.LSAOpenPolicy2Request(SystemName='\\\\%s' % HOST, DesiredAccess=lsa.LSA_POLICY_LOOKUP_NAMES).pack()
    dce.call(lsa.LSA_COM_OPEN_POLICY2, data, response=True)
    policy_handle = lsa.LSAOpenPolicy2Response(dce.reassembled_data).get_handle()

    # 2. Perform a lookup with valid names
    data = lsa.LSALookupNames3Request(PolicyHandle=policy_handle, NamesArray=USERS).pack()
    dce.call(lsa.LSA_COM_LOOKUP_NAMES3, data, response=True)
    answer = dce.reassembled_data[:-4]
    if not answer or len(answer) < 4:
        logging.error('[-] Failure! lsa.LSALookupNames3Request() did not return an answer.')
        return False
    status = unpack('<L', dce.reassembled_data[-4:])[0]
    if status == 0:
        resp = lsa.LSALookupNames3Response(dce.reassembled_data)
        domains = resp.get_domains()
        sids = resp.get_sids()
        logging.info(sids)
        SIDS = [ sid['Sid'] for sid in sids ]
        for s in SIDS:
            rid = int(s.split('-')[-1])
            if rid != 500 and (rid < 1100 or rid > 1200):
                return False
    else:
        return False

    # 3. Perform a lookup with invalid names
    data = lsa.LSALookupNames3Request(PolicyHandle=policy_handle, NamesArray=USERS+['notvalid']).pack()
    dce.call(lsa.LSA_COM_LOOKUP_NAMES3, data, response=True)
    answer = dce.reassembled_data[:-4]
    status = unpack('<L', dce.reassembled_data[-4:])[0]
    if status != 0x107: # STATUS_SOME_NOT_MAPPED
        return False

    # 4. Perform a lookup with valid Sids
    data = lsa.LSALookupSidsRequest(PolicyHandle=policy_handle, Sids=SIDS).pack()
    data = dce.call(lsa.LSA_COM_LOOKUP_SIDS, data, response=True)
    answer = dce.reassembled_data[:-4]
    status = unpack('<L', dce.reassembled_data[-4:])[0]
    if status == 0:
        resp = lsa.LSALookupSidsResponse(dce.reassembled_data)
        domains = resp.get_domains()
        names = resp.get_names()
    else:
        return False

    # 5. Perform a lookup with invalid Sids
    data = lsa.LSALookupSidsRequest(PolicyHandle=policy_handle, Sids=SIDS+['S-1-1337']).pack()
    data = dce.call(lsa.LSA_COM_LOOKUP_SIDS, data, response=True)
    answer = dce.reassembled_data[:-4]
    status = unpack('<L', dce.reassembled_data[-4:])[0]
    if status != 0xc0000078: # STATUS_INVALID_SID
        return False

    # 6. Destroy the handle
    data = lsa.LSACloseRequest(PolicyHandle=policy_handle).pack()
    dce.call(lsa.LSA_COM_CLOSE, data, response=True)
    ret = lsa.LSACloseResponse(dce.reassembled_data).get_return_value()
    if ret:
        return False

    # Good :)
    return True

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logger.setLevel(logging.DEBUG)

    res = do_test()
    if res:
        logging.info('[+] Success!')
    else:
        logging.info('[-] Failure!')

