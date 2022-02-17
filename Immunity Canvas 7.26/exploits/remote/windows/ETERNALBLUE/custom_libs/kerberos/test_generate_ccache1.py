#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_generate_ccache1.py
## Description:
##            :
## Created_On :  Mon Dec  14 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

'''
This poc demonstrates the ability to interact between:
    -> CANVAS's kerberos libraries
    -> smbclient's KRB5 MIT libraries
Basically what it does is require a TGT from the KDC and stores it as creds
in the ccache file (by default /tmp/krb5cc_$YOUR_UID)
In this case we assume the prior knowledge of an Administrator account. This is
enough to get a samba shell.

Note: smbclient performs the TGS request to get the service ticket.

$ kdestroy
$ ls -al /tmp/krb5cc_1000
ls: cannot access /tmp/krb5cc_1000: No such file or directory
$ smbclient //dc1.IMMU2.COM/ADMIN$ -k
cli_session_setup_kerberos: spnego_gen_krb5_negTokenInit failed: No such file or directory
session setup failed: NT_STATUS_UNSUCCESSFUL
$ ./libs/kerberos/test_generate_ccache1.py
$ ls -al /tmp/krb5cc_1000
-rw------- 1 foo foo 1142 Dec 15 00:58 /tmp/krb5cc_1000
$ smbclient //dc1.IMMU2.COM/ADMIN$ -k
OS=[Windows Server 2003 R2 3790 Service Pack 2] Server=[Windows Server 2003 R2 5.2]
smb: \>
'''

import os
import sys
import logging

if "." not in sys.path:
    sys.path.append(".")

from protocol import AsReq, AsRep, TgsReq, Kerberos
from protocol import Convert2PrincipalType, Convert2ServiceAndInstanceType
import helper as helper
import ccache as cc
import ticket

test_vectors = [

    # RC4 encryption with a passphrase
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': None,
      'cipher' : helper.ETYPE_ARCFOUR_HMAC_MD5,
      'protocol' : 'udp'
    },  # OK


    # AES128 encryption with a passphrase
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': 'IMMU8.COMAdministrator',
      'cipher' : helper.ETYPE_AES128_CTS_HMAC_SHA1_96,
      'protocol' : 'tcp'
    },  # OK


    # AES256 encryption with a passphrase
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': 'IMMU8.COMAdministrator',
      'cipher' : helper.ETYPE_AES256_CTS_HMAC_SHA1_96,
      'protocol' : 'tcp'
    },  # OK

]

def test_compact(vec):
    try:
        fname = '/tmp/krb5cc_' + str(os.getuid())
        krb = Kerberos(vec['domain'], target=vec['ip'], tcp=0)
        krb.set_credentials(vec['user'], vec['passphrase'])
        krb.do_auth()
        krb.export_into_credential_file(fname)
    except Exception as e:
        logging.error("test_compact() failed: %s" % str(e))
        return False
    else:
        return True


def test_expanded(vec):

    try:
        client_principal = Convert2PrincipalType(vec['user'], vec['domain'])
        auth_principal = Convert2PrincipalType('krbtgt/'+vec['domain'], vec['domain'])
        asreq = AsReq(client_principal, vec['domain'])
        asreq.set_server_principal(auth_principal)
        asreq.set_encryption_types([vec['cipher']])
        asreq.set_passphrase(vec['passphrase'], salt=vec['salt'])
        frame = asreq.pack()

        data = helper.krb5_send_frame(frame, vec['ip'], port=vec['port'], use_tcp= vec['protocol'] == 'tcp')
        if data is None:
            logging.error("No answer!")
            return False

        resp = AsRep(data)
        if not resp.is_valid():
            logging.error("Invalid response or wrong status!")
            return False

        # Extract the ticket
        raw_ticket = resp.get_ticket()

        # Extract the session key, times struct and flags
        resp.set_passphrase(vec['passphrase'], salt=vec['salt'])
        session_key = resp.get_session_key()
        times = resp.get_times()
        flags = resp.get_flags()

        # Adds information to the CCache
        cc1 = cc.CCache()
        cc1.set_header(client_principal, vec['user'])
        cc1.import_creds(client_principal,
                         auth_principal,
                         session_key,
                         times,
                         tktflags=flags,
                         is_skey=0,
                         ticket=raw_ticket)
        cc1.write(fname='/tmp/krb5cc_' + str(os.getuid()), close=1)
        return True

    except Exception as e:
        logging.error('Test failed: %s' % str(e))
        return False

def test_requests(vec):
    ret = True
    ret &= test_compact(vec)
    ret &= test_expanded(vec)
    return ret

###
# Main to test the class!
###

def main():

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        logging.error('Please provide a test number!')
        return False

    try:
        idx = int(sys.argv[1])
        vec = test_vectors[idx]
        ret = test_requests(vec)
        if ret:
            logging.info("Success!")

    except Exception as e:
        logging.error(e)
        return False

if __name__ == "__main__":
    main()
