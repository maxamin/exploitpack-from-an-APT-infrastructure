#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  ticket.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import struct
import hmac
import hashlib, binascii
import logging

if "." not in sys.path:
    sys.path.append(".")

import helper

try:
    from pyasn1.type import univ
    from pyasn1.codec.ber import encoder, decoder
except ImportError:
    logging.error("kerberos.protocol: Cannot import pyasn1 (required)")
    raise

###
# The 'Ticket' subclass
# https://tools.ietf.org/html/rfc4120
###

'''
 Ticket          ::= [APPLICATION 1] SEQUENCE {
           tkt-vno         [0] INTEGER (5),   // ALWAYS 5
           realm           [1] Realm,
           sname           [2] PrincipalName,
           enc-part        [3] EncryptedData -- EncTicketPart
   }

  EncryptedData   ::= SEQUENCE {
           etype   [0] Int32 -- EncryptionType --,
           kvno    [1] UInt32 OPTIONAL,
           cipher  [2] OCTET STRING -- ciphertext
   }
'''

class Ticket:

    def __init__(self, v):
        self.value = decoder.decode(v)[0]

    def get_realm(self):
        return str(self.value[2])

    def get_principalname(self):
        return str(self.value[1])

    def get_encrypted_data(self):
        return str(self.value[3][2])

    def get_encryption_type(self):
        return int(self.value[3][0])

    def set_encrypted_data(self, data):
        tags = self.value[3][2].getTagSet()
        self.value[3][2] = univ.OctetString(str(data), tagSet=tags)

    def pack(self):
        return encoder.encode(self.value)

###
# The 'TGT' manipulation subclass
###

MODE_TGT=2
MODE_TICKET=8

class CCacheTGT:

    def __init__(self):
        self.enc_data = None
        self.dec_data = None
        self.mode = MODE_TGT
        self.key = None
        self.enctype = helper.ETYPE_ARCFOUR_HMAC_MD5

    def __str__(self):
        return repr(self.enc_data)

    def __len__(self):
        return len(str(self.enc_data))

    def set_cleartext(self, data):
        self.dec_data = data

    def set_ciphertext(self, data):
        self.enc_data = data

    def set_enctype(self, enctype):
        self.enctype = enctype

    def set_key(self, key):
        self.key = key
        self.passphrase = None

    def set_password(self, password, salt=''):
        if self.enctype is None:
            raise ValueError('No encryption type defined at this point!')

        self.key = [self.enctype, helper.krb5_string_to_key(self.enctype, password, salt)] 

    def set_mode(self, mode):
        if not mode in [MODE_TGT, MODE_TICKET]:
            raise ValueError("Invalid mode for PAC deciphering")
        self.mode = mode

    def decrypt(self):
        return helper.krb5_decrypt(self.key, self.mode, self.enc_data)

    def encrypt(self):
        # Note: Investigate why we have a '1' at this point
        return helper.krb5_encrypt(self.key, 1, self.enc_data)

    def get_session_key(self):
        dec = self.decrypt()
        s = decoder.decode(dec)[0][1]
        key = [ int(s[0]), str(s[1]) ]
        return key

    def get_pac(self):
        dec = self.decrypt()
        s = decoder.decode(dec)[0]
        pac = str(s[9][0][1])
        return pac

    def set_pac(self, pac):
        # Note: Possibly a broken function (but unused currently).
        dec = self.decrypt()
        s = decoder.decode()[0]
        # Very important! ASN.1 tagsets _MUST_ be copied.
        tags = s[9][0][1].getTagSet()
        s[9][0][1] = univ.OctetString(str(pac), tagSet=tags)
        self.dec_data = encoder.encode(s)
