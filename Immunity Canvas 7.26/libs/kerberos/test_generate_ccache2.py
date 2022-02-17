#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_generate_ccache2.py
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
We assume the prior knowledge of an Administrator account. This is
enough to get a samba shell.

Note: In this case, smbclient does _not_ perform any TGS request as it already
has the service ticket.

$ kdestroy
$ python libs/kerberos/test_generate_ccache2.py
$ klist -f
Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: Administrator@IMMU3.COM

Valid starting       Expires              Service principal
01/06/2015 17:24:03  01/07/2015 03:24:03  krbtgt/IMMU3.COM@IMMU3.COM
	renew until 01/13/2015 17:24:03, Flags: FPRIA
01/06/2015 17:24:03  01/07/2015 03:24:03  cifs/dc2.IMMU3.COM@IMMU3.COM
	renew until 01/13/2015 17:24:03, Flags: FPRAO
$ smbclient //dc2.IMMU3.COM/ADMIN$ -k
OS=[Windows Server 2008 R2 Enterprise 7601 Service Pack 1] Server=[Windows Server 2008 R2 Enterprise 6.1]
smb: \>
'''

import os
import sys
import logging

if "." not in sys.path:
    sys.path.append(".")

from protocol import AsReq, AsRep, TgsReq, TgsRep, Kerberos
from protocol import Convert2PrincipalType, Convert2ServiceAndInstanceType
import ticket
import helper as helper
import ccache as cc

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
        cifs_principal = Convert2ServiceAndInstanceType('cifs/dc1.' + vec['domain'], vec['domain'])

        krb = Kerberos(vec['domain'], target=vec['ip'], tcp=int(vec['protocol'] == 'tcp'))
        krb.set_credentials(vec['user'], vec['passphrase'], salt=vec['salt'])
        if not krb.do_auth():
            return False
        krb.get_ticket_service(service_principal=cifs_principal)
        krb.export_into_credential_file(fname)
        krb.build_apreq_from_credential_file(fname, cifs_principal)
        return True

    except Exception as e:
        logging.error(e)
        return False

def test_expanded(vec):

    try:

        ### PART 1 - AS

        cifs_principal = Convert2ServiceAndInstanceType('cifs/dc1.' + vec['domain'], vec['domain'])
        client_principal = Convert2PrincipalType(vec['user'], vec['domain'])
        auth_principal = Convert2PrincipalType('krbtgt/'+vec['domain'], vec['domain'])

        asreq = AsReq(client_principal, vec['domain'])
        asreq.set_server_principal(auth_principal)
        asreq.set_encryption_types([vec['cipher']])
        asreq.set_passphrase(vec['passphrase'], salt=vec['salt'])
        frame = asreq.pack()

        data = helper.krb5_send_frame(frame, vec['ip'], port=vec['port'], use_tcp= vec['protocol'] == 'tcp')
        if not data:
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

        ### PART 2 - TGS

        tgsreq = TgsReq(vec['domain'], client_principal=client_principal,
                                       server_principal=cifs_principal)
        tgsreq.set_ticket(raw_ticket)
        tgsreq.set_session_key(session_key)
        frame = tgsreq.pack()

        data = helper.krb5_send_frame(frame, vec['ip'], port=vec['port'], use_tcp= vec['protocol'] == 'tcp')
        if not data:
            logging.error("No answer!")
            return False

        subkey = tgsreq.get_subkey()
        resp2 = TgsRep(data)

        if not resp2.is_valid():
            logging.error("Invalid response or wrong status!")
            return False

        resp2.set_key(subkey)

        # Extract the ticket
        raw_ticket2 = resp2.get_ticket()

        # Extract the session key
        session_key2 = resp2.get_session_key()
        times2 = resp2.get_times()
        flags2 = resp2.get_flags()

        # Adds information to the CCache
        cc1 = cc.CCache()
        cc1.open('/tmp/krb5cc_' + str(os.getuid()), new=1)
        cc1.set_header(client_principal, vec['domain'])
        cc1.import_creds(client_principal,
                         auth_principal,
                         session_key,
                         times,
                         tktflags=flags,
                         is_skey=0,
                         ticket=raw_ticket)
        cc1.import_creds(client_principal,
                         cifs_principal,
                         session_key2,
                         times2,
                         tktflags=flags2,
                         is_skey=0,
                         ticket=raw_ticket2)
        cc1.write()
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
