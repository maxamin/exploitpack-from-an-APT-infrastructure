#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_protocol.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import logging

if "." not in sys.path:
    sys.path.append(".")

from protocol import AsReq, AsRep, TgsReq, TgsRep
from protocol import Convert2PrincipalType, Convert2ServiceAndInstanceType
import helper
import ticket

test_vectors = [

    # RC4 encryption with a passphrase (2008)
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': None,
      'cipher' : helper.ETYPE_ARCFOUR_HMAC_MD5,
      'protocol' : 'udp',
      'cifs': 'CIFS/DC1.IMMU8.COM'
    },  # OK


    # AES128 encryption with a passphrase (2008)
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': 'IMMU8.COMAdministrator',
      'cipher' : helper.ETYPE_AES128_CTS_HMAC_SHA1_96,
      'protocol' : 'tcp',
      'cifs': 'CIFS/DC1.IMMU8.COM'
    },  # OK


    # AES256 encryption with a passphrase (2008)
    { 'ip':'192.168.8.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU8.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': 'IMMU8.COMAdministrator',
      'cipher' : helper.ETYPE_AES256_CTS_HMAC_SHA1_96,
      'protocol' : 'tcp',
      'cifs': 'CIFS/DC1.IMMU8.COM'
    },  # OK


    # RC4 encryption with a passphrase (2012)
    { 'ip':'192.168.10.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU10.COM',
      'user' : 'Administrator',
      'passphrase' : 'barbar1234!',
      'salt': '',
      'cipher' : helper.ETYPE_ARCFOUR_HMAC_MD5,
      'protocol' : 'tcp',
      'cifs': 'CIFS/DC3.IMMU10.COM'
    },  # OK

    # AES256 encryption with a passphrase (2012)
    { 'ip':'192.168.10.1',
      'port' : helper.KERBEROS_PORT,
      'domain': 'IMMU10.COM',
      'user' : 'jojo1',
      'passphrase' : 'foobar123!',
      'salt': 'IMMU10.COMjojo1',
      'cipher' : helper.ETYPE_AES256_CTS_HMAC_SHA1_96,
      'protocol' : 'tcp',
      'cifs': 'CIFS/DC3.IMMU10.COM'
    },  # OK

]

###
# PART 1
###

def test_asreq(vec):

    client_principal = Convert2PrincipalType(vec['user'],vec['domain'])
    auth_principal = Convert2PrincipalType('krbtgt/'+vec['domain'], vec['domain'])

    asreq = AsReq(client_principal)
    asreq.set_server_principal(auth_principal)
    asreq.set_encryption_types([vec['cipher']])
    asreq.set_passphrase(vec['passphrase'], salt=vec['salt'])
    frame = asreq.pack()

    data = helper.krb5_send_frame(frame, vec['ip'], port=vec['port'], use_tcp= vec['protocol'] == 'tcp')
    if not data:
        logging.error("No answer!")
        return None

    resp = AsRep(data)
    if not resp.is_valid():
        logging.error("Invalid response or wrong status!")
        return None

    # Extract the ticket
    raw_ticket = resp.get_ticket()

    # Get the session key from the KDC TGT
    t = ticket.Ticket(raw_ticket)
    enc_tgt = t.get_encrypted_data()
    enc_type = t.get_encryption_type()

    if enc_type == helper.ETYPE_AES256_CTS_HMAC_SHA1_96 and vec['domain'] == 'IMMU8.COM':

        tgtobj = ticket.CCacheTGT()
        tgtobj.set_ciphertext(enc_tgt)
        tgtobj.set_mode(ticket.MODE_TGT)

        krbtgt_key_str = '8578fcf78a3b3a4bf4a6eb9d1067f83256938a0866e21f484b61611c0b71769d'.decode('hex')
        tgtobj.set_key([enc_type, krbtgt_key_str])
        clear_tgt = tgtobj.decrypt()
        session_key1 = tgtobj.get_session_key()

        # Also get the session key from the encrypted information that us only
        # should be able to decipher.
        resp.set_passphrase(vec['passphrase'], salt=vec['salt'])
        session_key2 = resp.get_session_key()

        # It's a non fatal issue because it could be a problem of AES key exportation
        if session_key2 != session_key1:
            logging.error("Wrong session key: %s != %s" % (session_key1[1],session_key2[1]))

    return (raw_ticket, session_key2)

###
# PART 2
###

def test_tgsreq(vec, raw_ticket, session_key):

    client_principal = Convert2PrincipalType(vec['user'], vec['domain'])
    cifs_principal = Convert2ServiceAndInstanceType(vec['cifs'], vec['domain'])
    tgsreq = TgsReq(vec['domain'], client_principal=client_principal,
                                   server_principal=cifs_principal)
    tgsreq.set_ticket(raw_ticket)
    tgsreq.set_session_key(session_key)
    frame = tgsreq.pack()

    data = helper.krb5_send_frame(frame, vec['ip'], port=vec['port'], use_tcp= vec['protocol'] == 'tcp')
    if not data:
        logging.error("No answer!")
        return False

    tgsrep = TgsRep(data)
    if not tgsrep.is_valid():
        return False

    return True

def do_tests(vec):

    res = test_asreq(vec)
    if not res:
        logging.error("test_asreq() failed!")
        return False

    (raw_ticket, session_key2) = res
    if not test_tgsreq(vec, raw_ticket, session_key2):
        logging.error("test_tgsreq() failed!")
        return False

    return True

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
        ret = do_tests(vec)
        if ret:
            logging.info("Success!")

    except Exception as e:
        logging.error(e)
        return False

if __name__ == "__main__":
    main()
