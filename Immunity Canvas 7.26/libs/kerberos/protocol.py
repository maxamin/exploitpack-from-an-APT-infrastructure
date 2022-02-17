#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  protocol.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

'''
Notes
-----

- Very far from being perfect
- The answers cannot be built but rather are parsed (quite logical right?)
- About answer parsing. Logically speaking, we should use more often the explicit
  tags. However it seems Windows' asn1 isn't able to deal with permuted elements
  anyway so relying on the index is fine.
'''

import os
import sys
import struct
import time
import tempfile
import logging

if "." not in sys.path:
    sys.path.append(".")

import helper as helper
from filetimes import filetime_to_dt, dt_to_filetime, utc
import ccache as cc

try:
    from pyasn1.type import univ, tag
    from pyasn1.type import char, useful
    from pyasn1.codec.ber import encoder, decoder
except ImportError:
    logging.error("kerberos.protocol: Cannot import pyasn1 (required)")
    raise

try:
    from Crypto.Hash import MD5
except ImportError:
    logging.error("kerberos.protocol: Cannot import Crypto (required)")
    raise

###
# TagSet functions
#
# Note: Current implementation is a bit messy. But it works.
###

def getSeqApplicationTagSet(n):
    return univ.Sequence().getTagSet() + tag.Tag(tagClass=64, tagFormat=32, tagId=n)

def getIntegerTagSet(n):
    return univ.Integer().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getBooleanTagSet(n):
    return univ.Boolean().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getGeneralStringTagSet(n):
    return char.GeneralString().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getOctetStringTagSet(n):
    return univ.OctetString().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getSequenceTagSet(n):
    return univ.Sequence().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getGeneralizedTimeTag(n):
    return useful.GeneralizedTime().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

def getBitStringTag(n):
    return univ.BitString().getTagSet() + tag.Tag(tagClass=128, tagFormat=32, tagId=n)

###
# KerberosFlags
###

# http://stackoverflow.com/questions/10411085/converting-integer-to-binary-in-python
# Nice trick!

class KerberosFlags:

    def __init__(self, flags, tagId):
        self.tagId = tagId
        self.flags = flags

    def build(self):
        val = "'" + '{0:032b}'.format(self.flags) + "'B"
        binstr = univ.BitString(val, tagSet=getBitStringTag(self.tagId))
        return binstr

###
# PrincipalName
###

'''
PrincipalName   ::= SEQUENCE {
        name-type       [0] Int32,
        name-string     [1] SEQUENCE OF KerberosString
}
'''

# TODO: Must be cleaned/modified.
class PrincipalName:

    def __init__(self, principal, tagId=None):
        self.tagId = tagId
        self.components = principal[0].split('/')
        self.name_type = principal[1]
        self.domain = principal[2]

    def build(self):
        subseq = univ.Sequence(tagSet=getSequenceTagSet(1))
        for i in xrange(len(self.components)):
            s = char.GeneralString(self.components[i])
            subseq.setComponentByPosition(i, s)
        if self.tagId:
            seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))
        else:
            seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Integer(self.name_type, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, subseq)
        return seq

    def export(self):
        return cc.CCachePrincipal({'name_type':self.name_type,
                                   'realm':self.domain,
                                   'components':self.components})

def Convert2PrincipalType(name, domain):
    return [name, 1, domain]

def Convert2ServiceAndInstanceType(name, domain):
    return [name, 2, domain]

###
# KerberosString, Realm
###

'''
KerberosString  ::= GeneralString (IA5String)
'''

class KerberosString:

    def __init__(self, value, tagId):
        self.tagId = tagId
        self.value = value

    def build(self):
        s = char.GeneralString(self.value, tagSet=getGeneralStringTagSet(self.tagId))
        return s

class Realm(KerberosString):
    pass

###
# EncryptionKey
###

'''
EncryptionKey   ::= SEQUENCE {
        keytype         [0] Int32 -- actually encryption type --,
        keyvalue        [1] OCTET STRING
}
'''

class EncryptionKey:

    def __init__(self, key, tagId=None):
        self.keytype = key[0]
        self.keyvalue = key[1]
        self.tagId = tagId

    def build(self):
        if self.tagId:
            seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))
        else:
            seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Integer(self.keytype, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, univ.OctetString(self.keyvalue, tagSet=getOctetStringTagSet(1)))
        return seq

    def export(self):
        return cc.CCacheKey({'type':int(self.keytype), 'value':str(self.keyvalue)})

###
# Checksum
###

'''
Checksum        ::= SEQUENCE {
        cksumtype       [0] Int32,
        checksum        [1] OCTET STRING
}
'''

class Checksum:

    def __init__(self, cksumtype, data=None, cksum=None, tagId=None):
        self.cksumtype = cksumtype
        self.data = data
        self.sum = cksum
        self.tagId = tagId

    def build(self):

        if not self.sum:
            # Warning we only deal with MD5 right now!
            if self.cksumtype == 7:
                self.sum = MD5.new(self.data).digest()
            else:
                raise ValueError('Unhandled checksum type: %d' % self.cksumtype)

        seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))
        seq.setComponentByPosition(0, univ.Integer(self.cksumtype, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, univ.OctetString(self.sum, tagSet=getOctetStringTagSet(1)))
        return seq

###
# AuthorizationData
###

'''
AuthorizationData       ::= SEQUENCE OF SEQUENCE {
        ad-type         [0] Int32,
        ad-data         [1] OCTET STRING
}
'''

class AuthorizationData:

    def __init__(self, ad_type, ad_data, tagId=None):
        self.ad_type = ad_type
        self.ad_data = ad_data
        self.tagId = tagId

    def build(self):
        if self.tagId:
            seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))
        else:
            seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Integer(self.ad_type, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, univ.OctetString(str(self.ad_data), tagSet=getOctetStringTagSet(1)))
        seq2 = univ.Sequence()
        seq2.setComponentByPosition(0, seq)
        return seq2


###
# Authenticator
###

'''
-- Unencrypted authenticator
Authenticator   ::= [APPLICATION 2] SEQUENCE  {
        authenticator-vno       [0] INTEGER (5),
        crealm                  [1] Realm,
        cname                   [2] PrincipalName,
        cksum                   [3] Checksum OPTIONAL,
        cusec                   [4] Microseconds,
        ctime                   [5] KerberosTime,
        subkey                  [6] EncryptionKey OPTIONAL,
        seq-number              [7] UInt32 OPTIONAL,
        authorization-data      [8] AuthorizationData OPTIONAL
}
'''

class Authenticator:

    def __init__(self, cname, subkey=None, with_checksum=False):
        self.crealm = cname[2]
        self.cname = cname
        self.cusec = 500000
        self.ctime = time.time()
        self.with_checksum = with_checksum
        self.subkey = subkey

    def build(self):
        seq = univ.Sequence(tagSet=getSeqApplicationTagSet(2))
        seq.setComponentByPosition(0, univ.Integer(5, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, Realm(self.crealm, 1).build())
        seq.setComponentByPosition(2, PrincipalName(self.cname, tagId=2).build())
        if self.with_checksum:
            raise ValueError('Unimplemented feature!')
            ## TODO: Invalid currently, optional anyway.
            ####seq.setComponentByPosition(3, Checksum(7, data=None, cksum='\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\t\x98\xec\xf8B~', tagId=3).build())
        seq.setComponentByPosition(4, univ.Integer(self.cusec, tagSet=getIntegerTagSet(4)))
        seq.setComponentByPosition(5, KerberosTime(self.ctime, 5).build())
        if self.subkey:
            seq.setComponentByPosition(6, EncryptionKey(self.subkey, 6).build())
        return seq

###
# ApReq
###

'''
AP-REQ          ::= [APPLICATION 14] SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (14),
        ap-options      [2] APOptions,
        ticket          [3] Ticket,
        authenticator   [4] EncryptedData -- Authenticator
}

APOptions       ::= KerberosFlags
        -- reserved(0),
        -- use-session-key(1),
        -- mutual-required(2)
'''

class ApReq:

    def __init__(self, ticket, authenticator):
        self.ticket = ticket
        self.authenticator = authenticator

    def build(self):
        seq = univ.Sequence(tagSet=getSeqApplicationTagSet(14))
        seq.setComponentByPosition(0, univ.Integer(5, tagSet=getIntegerTagSet(0)))
        seq.setComponentByPosition(1, univ.Integer(14, tagSet=getIntegerTagSet(1)))
        seq.setComponentByPosition(2, KerberosFlags(0, 2).build()) # APOptions
        seq.setComponentByPosition(3, self.ticket)
        seq.setComponentByPosition(4, self.authenticator)

        return seq


###
# EncryptedData
###

'''
EncryptedData   ::= SEQUENCE {
        etype   [0] Int32 -- EncryptionType --,
        kvno    [1] UInt32 OPTIONAL,
        cipher  [2] OCTET STRING -- ciphertext
}
'''

class EncryptedData:

    def __init__(self, key, data, mode, kvno=99, tagId=None):

        self.key = key
        self.data = data
        self.mode = mode
        self.kvno = kvno
        self.tagId = tagId
        self.etype = key[0]

    def encrypt(self):
        return helper.krb5_encrypt(self.key, self.mode, self.data)

    def decrypt(self):
        return helper.krb5_decrypt(self.key, self.mode, str(self.data))

    def build(self):
        encdata = self.encrypt()
        if self.tagId:
            seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))
        else:
            seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Integer(self.etype, tagSet=getIntegerTagSet(0)))
        #seq.setComponentByPosition(1, univ.Integer(self.kvno, tagSet=getIntegerTagSet(1)))
        seq.setComponentByPosition(2, univ.OctetString(encdata, tagSet=getOctetStringTagSet(2)))
        return seq

# Function to encrypt an authenticator
def build_authenticator(domain, client_principal, session_key, mode=7, subkey=None, with_checksum=False):
    clear_auth = Authenticator(client_principal, subkey=subkey, with_checksum=with_checksum).build()
    enc_auth = EncryptedData(session_key, encoder.encode(clear_auth), mode, kvno=99, tagId=4).build()
    return enc_auth

###
# GeneralizedT1me
###

class GeneralizedT1me:

    def __init__(self, timestamp, tagId):

        self.timestamp = time.strftime('%Y%m%d%H%M%SZ', time.gmtime(int(timestamp)))
        self.tagId = tagId

    def build(self):
        return useful.GeneralizedTime(self.timestamp, tagSet=getGeneralizedTimeTag(self.tagId))

class KerberosTime(GeneralizedT1me):
    pass


###
# PA-PAC-REQUEST
###


'''
KERB-PA-PAC-REQUEST ::= SEQUENCE {
include-pac[0] BOOLEAN --If TRUE, and no pac present, include PAC.
                       --If FALSE, and PAC present, remove PAC
}
'''

class PaPacRequest:

    def __init__(self, value):
        self.value = value

    def build(self):

        seq = univ.Sequence()
        seq.setComponentByPosition(0, univ.Boolean(self.value, tagSet=getBooleanTagSet(0)))
        return [ 128, encoder.encode(seq) ]


###
# PA-TGS-REQ
###

class PaTgsReq:

    def __init__(self, ticket, authenticator):
        self.ticket = ticket
        self.authenticator = authenticator

    def build(self):
        return [ 1, encoder.encode(ApReq(self.ticket, self.authenticator).build()) ]


###
# PA-ENC-TIMESTAMP
###

'''
PA-ENC-TIMESTAMP        ::= EncryptedData -- PA-ENC-TS-ENC

PA-ENC-TS-ENC           ::= SEQUENCE {
        patimestamp     [0] KerberosTime -- client's time --,
        pausec          [1] Microseconds OPTIONAL
}
'''

class PaEncTsEnc:

    def __init__(self, timestamp):
        self.patimestamp = timestamp
        self.pausec = 0

    def build(self):

        seq = univ.Sequence()
        seq.setComponentByPosition(0, GeneralizedT1me(self.patimestamp, 0).build())
        seq.setComponentByPosition(1, univ.Integer(self.pausec, tagSet=getIntegerTagSet(1)))
        return seq

class PaEncTimestamp:

    def __init__(self, key, kvno=4, timestamp=None):
        if timestamp:
            self.timestamp = timestamp
        else:
            self.timestamp = int(time.time())
        self.key = key
        self.kvno = kvno

    def build(self):

        padata = encoder.encode(PaEncTsEnc(self.timestamp).build())
        encData = encoder.encode(EncryptedData(self.key, padata, 1, self.kvno).build())
        return [ 2, encData ]

###
# PA-DATA
###

'''
PA-DATA         ::= SEQUENCE {
        -- NOTE: first tag is [1], not [0]
        padata-type     [1] Int32,
        padata-value    [2] OCTET STRING -- might be encoded AP-REQ
}
'''

class PaData:

    def __init__(self, seq, tagId):
        self.tagId = tagId
        self.seq = seq

    def build(self):
        seq = univ.Sequence(tagSet=getSequenceTagSet(self.tagId))

        for i in xrange(len(self.seq)):
            data_type, data_value = self.seq[i]
            subseq = univ.Sequence()
            subseq.setComponentByPosition(0, univ.Integer(data_type, tagSet=getIntegerTagSet(1)))
            subseq.setComponentByPosition(1, univ.OctetString(data_value, tagSet=getOctetStringTagSet(2)))
            seq.setComponentByPosition(i, subseq)

        return seq

###
# KDC-REQ-BODY
###

'''
KDC-REQ-BODY    ::= SEQUENCE {
        kdc-options             [0] KDCOptions,
        cname                   [1] PrincipalName OPTIONAL
                                    -- Used only in AS-REQ --,
        realm                   [2] Realm
                                    -- Server's realm
                                    -- Also client's in AS-REQ --,
        sname                   [3] PrincipalName OPTIONAL,
        from                    [4] KerberosTime OPTIONAL,
        till                    [5] KerberosTime,
        rtime                   [6] KerberosTime OPTIONAL,
        nonce                   [7] UInt32,
        etype                   [8] SEQUENCE OF Int32 -- EncryptionType
                                    -- in preference order --,
        addresses               [9] HostAddresses OPTIONAL,
        enc-authorization-data  [10] EncryptedData OPTIONAL
                                    -- AuthorizationData --,
        additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                        -- NOTE: not empty
}
'''

class KdcReqBody:

    def __init__(self, client_principal, server_principal, domain=None, pac=None, encryption_types=[helper.ETYPE_ARCFOUR_HMAC_MD5], nonce=12345678, tgs=0):

        self.client_principal = client_principal
        self.server_principal = server_principal
        self.domain = domain
        self.encryption_types = encryption_types
        self.nonce = nonce
        self.pac = pac
        if not self.domain:
            self.domain = self.client_principal[2]

    def build_encryption_types(self, tagId):

        seq = univ.Sequence(tagSet=getSequenceTagSet(tagId))
        for i in xrange(len(self.encryption_types)):
            seq.setComponentByPosition(i, univ.Integer(self.encryption_types[i]))
        return seq

    def build(self):

        kdc_options = KerberosFlags(0x50800000, 0).build()
        if self.client_principal:
            cname = PrincipalName(self.client_principal, tagId=1).build()
        realm = Realm(self.domain, 2).build()
        sname = PrincipalName(self.server_principal, tagId=3).build()
        till = GeneralizedT1me(0, 5).build()
        nonce = univ.Integer(self.nonce, tagSet=getIntegerTagSet(7))
        etypes = self.build_encryption_types(8)

        ## <TODO> Must be improved.
        fromm = GeneralizedT1me(0, 4).build()
        rtime = GeneralizedT1me(0, 6).build()
        ## </TODO>

        pos = 0
        seq = univ.Sequence(tagSet=getSequenceTagSet(4))
        seq.setComponentByPosition(pos, kdc_options); pos += 1
        if self.client_principal:
            seq.setComponentByPosition(pos, cname); pos += 1
        seq.setComponentByPosition(pos, realm); pos += 1
        seq.setComponentByPosition(pos, sname); pos += 1
        seq.setComponentByPosition(pos, till); pos += 1
        seq.setComponentByPosition(pos, nonce); pos += 1
        seq.setComponentByPosition(pos, etypes); pos += 1
        if self.pac:
            seq.setComponentByPosition(8, self.pac)

        return seq


###
# The 'Kerberos' manipulation subclasses
###

'''
KDC-REQ         ::= SEQUENCE {
    -- NOTE: first tag is [1], not [0]
    pvno            [1] INTEGER (5) ,
    msg-type        [2] INTEGER (10 -- AS -- | 12 -- TGS --),
    padata          [3] SEQUENCE OF PA-DATA OPTIONAL
                        -- NOTE: not empty --,
    req-body        [4] KDC-REQ-BODY
}
'''

class KdcReq:

    def __init__(self, msg_type, padata, reqbody):

        self.msg_type = msg_type
        self.padata = padata
        self.reqbody = reqbody
        self.tagId = msg_type

    def build(self):

        pvno = univ.Integer(5, tagSet=getIntegerTagSet(1))
        msg_type = univ.Integer(self.msg_type, tagSet=getIntegerTagSet(2))
        seq = univ.Sequence(tagSet=getSeqApplicationTagSet(self.tagId))
        seq.setComponentByPosition(0, pvno)
        seq.setComponentByPosition(1, msg_type)
        seq.setComponentByPosition(2, self.padata)
        seq.setComponentByPosition(3, self.reqbody)
        return seq


class AsReq:

    def __init__(self, client_principal, domain=None):

        self.raw = False
        self.data = None
        self.seq = None
        self.client_principal = client_principal
        if not domain:
            self.domain = client_principal[2]
        else:
            self.domain = domain
        self.server_principal = Convert2ServiceAndInstanceType('krbtgt/' + self.domain, self.domain)
        self.encryption_types = [ helper.ETYPE_ARCFOUR_HMAC_MD5 ]
        self.till = time.time() # Currently useless
        self.key = None
        self.passphrase = None
        self.set_pac_opt = False
        self.pac_req_opt_val = False
        self.set_debug_opt = False

    def set_pac_req_opt(self, value):
        self.set_pac_opt = True
        self.pac_req_opt_val = value

    def set_debug_opt(self):
        self.set_debug_opt = True

    def set_domain(self, domain):
        self.domain = domain

    def set_server_principal(self, server_principal):
        self.server_principal = server_principal

    def set_encryption_types(self, seq):
        """
        A sequence of etypes.
        We assume they are ordered by preference.
        Note: Post-2012 or if RC4 is explicitly disabled, this function _must_
        be called.
        """
        self.encryption_types = seq

    def set_till(self, till):
        self.till = till

    def set_passphrase(self, password, salt=''):
        self.passphrase = [ password, salt ]
        self.key = None

    def set_key(self, key):
        self.passphrase = None
        self.key = key

    def build(self):

        # Without encryption there is nothing we can do
        if not self.key and not self.passphrase:
            raise ValueError('No key set!')

        # If we have no key, we need to generate it
        if not self.key:
            etype = self.encryption_types[0]
            self.key = [ etype, helper.krb5_string_to_key(etype, self.passphrase[0], salt=self.passphrase[1]) ]

        enctimestamp = PaEncTimestamp(self.key, kvno=4).build()
        padata_list = [enctimestamp]
        if self.set_debug_opt:
            padata_list.append([149,'']) # Comes from kinit (linux/Ubuntu), used for debugging.
        if self.set_pac_opt:
            pacreq = PaPacRequest(self.pac_req_opt_val).build()
            padata_list.append(pacreq)

        padata = PaData(padata_list, 3).build()

        reqbody = KdcReqBody(self.client_principal,
                             self.server_principal,
                             self.domain,
                             tgs=0,
                             encryption_types=self.encryption_types).build()
        self.seq = KdcReq(10, padata, reqbody).build()
        return self.seq

    def pack(self):
        if self.raw:
            return str(self.data)
        else:
            self.raw = False
            if not self.seq:
                self.seq = self.build()
            self.data = encoder.encode(self.seq)
            return str(self.data)

    def unpack(self):
        # Ok so either we had the data from a frame (raw)
        if self.raw:
            self.seq = decoder.decode(self.data)
        # Or we build it using the informations provided
        else:
            self.seq = self.build()


class TgsReq:
    def __init__(self, domain, client_principal=None, server_principal=None, till=None):
        self.raw = False
        self.data = None
        self.seq = None
        self.domain = domain
        self.client_principal = client_principal
        self.server_principal = server_principal
        self.encryption_types = [ helper.ETYPE_ARCFOUR_HMAC_MD5 ] # RC4 by default
        self.till = till
        self.key = None
        self.ticket = None
        self.authenticator = None
        self.session_key = None
        self.subkey = None
        self.pac = None
        self.pac_req_opt_val = False
        self.set_pac_opt = False

    def set_domain(self, domain):
        self.domain = domain

    def set_client_principal(self, client_principal):
        self.client_principal = client_principal

    def set_server_principal(self, server_principal):
        self.server_principal = server_principal

    def set_encryption_types(self, seq):
        self.encryption_types = seq

    def set_till(self, till):
        self.till = till

    def set_pac_req_opt(self, value):
        self.set_pac_opt = True
        self.pac_req_opt_val = value

    def set_ticket(self, ticket):
        val = decoder.decode(ticket)[0]
        # Note: order of tags matters as switching (64,,) and (128,,) doesnt work
        tags = univ.Sequence.tagSet + tag.Tag(64, 32, 1) + tag.Tag(128, 32, 3)
        self.ticket = val.clone(tagSet=tags, cloneValueFlag=True)

    def set_pac(self, pac):
        if not self.subkey:
            self.build_subkey()
        auth = AuthorizationData(1, pac).build()
        key = [int(self.subkey[0]),str(self.subkey[1])]
        self.pac = EncryptedData(key, encoder.encode(auth), 5, kvno=99, tagId=10).build()

    def set_session_key(self, session_key):
        self.session_key = session_key

    def set_authenticator(self, authenticator):
        self.authenticator = authenticator

    def get_subkey(self):
        return [ int(self.subkey[0]), self.subkey[1].asOctets() ]

    def build_subkey(self):
        # Builds an ASN-1 object.
        self.subkey = EncryptionKey(helper.krb5_generate_random_key(self.encryption_types[0]), 6).build()

    def build(self):

        if not self.ticket:
            logging.error("Please provide a ticket first!")
            return None

        # 1. We build the KdcReqBody
        reqbody = KdcReqBody(None,
                             self.server_principal,
                             self.domain,
                             pac=self.pac,
                             tgs=1,
                             encryption_types=self.encryption_types).build()

        # 2. We compute the checksum of reqbody
        cksum = Checksum(7, encoder.encode(reqbody), tagId=3).build()

        # 3. We build the other parameters necessary for the authenticator
        if not self.subkey:
            self.build_subkey()

        if not self.authenticator:
            self.authenticator = build_authenticator(self.domain,
                                                     self.client_principal,
                                                     self.session_key,
                                                     mode=7,
                                                     subkey=self.subkey)

        patgsreq = PaTgsReq(self.ticket, self.authenticator).build()

        if self.set_pac_opt:
            pacreq = PaPacRequest(self.pac_req_opt_val).build()
            padata = PaData([patgsreq, pacreq], 3).build()
        else:
            padata = PaData([patgsreq], 3).build()

        self.seq = KdcReq(12, padata, reqbody).build()
        return self.seq

    def pack(self):
        if self.raw:
            return str(self.data)
        else:
            self.raw = False
            self.seq = self.build()
            self.data = encoder.encode(self.seq)
            return str(self.data)

    def unpack(self):
        # Ok so either we had the data from a frame (raw)
        if self.raw:
            self.seq = decoder.decode(self.data)
        # Or we build it using the informations provided
        else:
            self.seq = self.build()

'''
KDC-REP         ::= SEQUENCE {
        pvno            [0] INTEGER (5),
        msg-type        [1] INTEGER (11 -- AS -- | 13 -- TGS --),
        padata          [2] SEQUENCE OF PA-DATA OPTIONAL
                                -- NOTE: not empty --,
        crealm          [3] Realm,
        cname           [4] PrincipalName,
        ticket          [5] Ticket,
        enc-part        [6] EncryptedData
                                -- EncASRepPart or EncTGSRepPart,
                                -- as appropriate
}
'''

class KdcRep(object):

    def __init__(self, dataframe):
        self.data = dataframe
        self.seq = decoder.decode(dataframe)[0]
        self.passphrase = None
        self.key = None

    def __str__(self):
        return repr(self.seq)

    def __len__(self):
        return len(str(self.seq))

    def set_passphrase(self, password, salt=''):
        self.passphrase = [ password, salt ]
        self.key = None

    def set_key(self, key):
        self.passphrase = None
        self.key = key

    # This function is necessary because we need to retrieve the items using
    # their explicit tag. This is because some of the elements in the sequence
    # are not mandatory so this is the safest way to proceed.
    def get_object_from_tag(self, seq, tagId):
        for elt in seq:
            tagset = elt.getTagSet()
            for tag in tagset:
                t = tag.asTuple()
                if t == (128, 32, tagId):
                    return elt
        return None

    def get_pvno(self):
        try:
            elt = self.get_object_from_tag(self.seq, 0)
            return int(elt)
        except Exception as e:
            logging.error("Can't get pvno: %s", str(e))
            return None

    def get_msg_type(self):
        try:
            elt = self.get_object_from_tag(self.seq, 1)
            return int(elt)
        except Exception as e:
            logging.error("Can't get msg type: %s", str(e))
            return None

    def get_ticket(self):
        try:
            elt = self.get_object_from_tag(self.seq, 5)
            return encoder.encode(elt)
        except Exception as e:
            logging.error("Can't retrieve ticket: %s" % str(e))
            return None

    def get_enc_part(self, mode):

        try:

            elt = self.get_object_from_tag(self.seq, 6)

            if(len(elt) == 3):
                encData = EncryptedData(self.key, elt[2], mode, kvno=elt[1])
                return encData.decrypt()

            if(len(elt) == 2):
                encData = EncryptedData(self.key, elt[1], mode, kvno=99)
                return encData.decrypt()

            raise ValueError('BUG: Invalid ASN-1 within enc-part.')

        except Exception as e:
            logging.error("Invalid KdcRep or invalid session key: %s" % str(e))
            return None

    # At this point, we need to retrieve stuff from the encrypted material.
    def get_session_key(self):
        kdc_rep_part = decoder.decode(self.get_enc_part())[0]
        elt = self.get_object_from_tag(kdc_rep_part, 0)
        return [ int(elt[0]), str(elt[1]) ]

    def get_flags(self):
        kdc_rep_part = decoder.decode(self.get_enc_part())[0]
        elt = self.get_object_from_tag(kdc_rep_part, 4)
        return helper.BitString2Integer(elt)

    def get_times(self):
        kdc_rep_part = decoder.decode(self.get_enc_part())[0]
        authtime = self.get_object_from_tag(kdc_rep_part, 5)
        starttime = self.get_object_from_tag(kdc_rep_part, 6)
        endtime = self.get_object_from_tag(kdc_rep_part, 7)
        renew_till = self.get_object_from_tag(kdc_rep_part, 8)
        s1 = [ authtime, starttime, endtime, renew_till ]
        s2 = []
        for elt in s1:
            t = time.strptime(str(elt),'%Y%m%d%H%M%SZ')
            utc_timestamp = int(time.mktime(t))
            local_timestamp = helper.timestamp_from_utc_to_local(utc_timestamp)
            s2.append(local_timestamp)
        return s2

    def get_authtime(self):
        kdc_rep_part = decoder.decode(self.get_enc_part())[0]
        authtime = self.get_object_from_tag(kdc_rep_part, 5)
        return authtime


'''
AS-REP          ::= [APPLICATION 11] KDC-REP
'''

class AsRep(KdcRep):

    def is_valid(self):
        try:
            pvno = self.get_pvno()
            msg_type = self.get_msg_type()
            return (pvno == 5 and msg_type == 11)
        except Exception as e:
            return False

    def get_enc_part(self):

        if not self.key and not self.passphrase:
            raise ValueError('No key material available!')

        try:
            elt = self.get_object_from_tag(self.seq, 6)
            data_enc_type = int(elt[0])

            # case #1: We have a passphrase. We use the data encryption type
            if self.passphrase:
                self.key = [ data_enc_type,
                             helper.krb5_string_to_key(data_enc_type, self.passphrase[0],
                                                       salt=self.passphrase[1])
                           ]

            # case #2: We have a key. we use its etype if we can
            if data_enc_type != self.key[0]:
                raise ValueError('Trying to decrypt data encrypted with %d using a %d key!' % (data_enc_type, self.key[0]))

            # RC4 is a special case!
            if data_enc_type == helper.ETYPE_ARCFOUR_HMAC_MD5:
                return super(AsRep, self).get_enc_part(8) # RC4
            else:
                return super(AsRep, self).get_enc_part(3) # AES

        except Exception as e:
            logging.error("Invalid AsRep: %s" % str(e))
            return None


'''
TGS-REP         ::= [APPLICATION 13] KDC-REP
'''

class TgsRep(KdcRep):

    def is_valid(self):
        try:
            pvno = self.get_pvno()
            msg_type = self.get_msg_type()
            return (pvno == 5 and msg_type == 13)
        except Exception as e:
            return False

    def get_enc_part(self):
        # TODO.
        return super(TgsRep, self).get_enc_part(9) # RC4??
        #return super(TgsRep, self).get_enc_part(9) # AES
###
# The main class!
# This version is limited to 1 (AS req + TGS req) saved per instance
###

class Kerberos:

    def __init__(self, domain, target=None, tcp=0):
        # Network/kerberos
        self.domain = domain
        self.target_ip = target
        self.target_port = helper.KERBEROS_PORT
        self.tcp = tcp
        self.timeout = 2
        self.username = ''
        self.password = ''
        self.salt = None
        self.key = None

        # Database of credentials
        self.db_name = None
        self.cc = None

        # AsReq
        self.as_client_principal = None
        self.as_service_principal = None
        self.as_session_key = None
        self.sub_key = None
        self.auth_performed = False
        self.auth_copy = False

        # TgsReq
        self.tgs_client_principal = None
        self.tgs_service_principal = None
        self.tgs_subkey = None
        self.tgs_raw_ticket = None
        self.tgs_session_key = None
        self.tgs_times = None
        self.tgs_flags = None
        self.tgs_copy = False

        #self.tgs_rep = None
        self.tgs_performed = False

        # We can retrieve the target automatically if not specified
        if not self.target_ip:
            self.target_ip = self.__discover_target()

    # Try to guess the IP of the target when it's not specified using DNS
    def __discover_target(self):
        return helper.krb5_get_kdc_ip(self.domain, timeout=self.timeout)

    # Send data through a Kerberos socket
    def __send_kerberos_packet(self, frame):
        return helper.krb5_send_frame(frame,
                                      self.target_ip,
                                      port=self.target_port,
                                      use_tcp=self.tcp,
                                      timeout=self.timeout)

    # Ripped from libs/pyjon/utils/main.py
    def __generate_tmp_file(self, prefix="tmp_"):
        """
        creates a tempfile in the most secure manner possible,
        make sure is it closed and return the filename for
        easy usage.
        """
        file_handle, filename = tempfile.mkstemp(prefix=prefix)
        tmpfile = os.fdopen(file_handle, "rb")
        tmpfile.close()
        return filename

    def get_subkey(self):
        return self.sub_key

    def set_credentials(self, username='', password='', salt=''):
        self.username = username.encode('ASCII')
        self.password = password.encode('ASCII')
        self.salt = salt

    def set_timeout(self, timeout):
        self.timeout = timeout

    # Probably useless practically speaking but you never know
    def set_target_port(self, port):
        self.target_port = port

    def __clone_ticket(self, current_ticket):
        try:
            val = decoder.decode(current_ticket)[0]
            # Note: order of tags matters as switching (64,,) and (128,,) doesnt work
            tags = univ.Sequence.tagSet + tag.Tag(64, 32, 1) + tag.Tag(128, 32, 3)
            new_ticket = val.clone(tagSet=tags, cloneValueFlag=True)
            return new_ticket
        except Exception as e:
            return None

    def open_db(self, fname=None, client_principal=None):
        # If the name is not specified, create a new db!
        if not fname:
            self.db_name = self.__generate_tmp_file('tmp_krb5_auth_')
            raw_data = ''
        # If the name exists but the file does not!
        elif not os.path.exists(fname):
            self.db_name = fname
            f = open(fname, 'wb+')
            f.close()
            raw_data = ''
        # The db already exists
        else:
            self.db_name = fname
            try:
                f = open(fname, 'rb')
                raw_data = f.read()
                f.close()
            except Exception as e:
                logging.error("ccache file %s cannot be read: %s" % (fname, str(e)))
                return 0

        self.cc = cc.CCache()
        if len(raw_data):
            self.cc.set_raw_data(raw_data)
        else:
            self.cc.set_header(client_principal, self.domain)
        return 1

    def save_db(self, close=0):
        #self.cc.set_header(self.as_client_principal, self.domain)

        if self.auth_performed and not self.auth_copy:
            self.cc.import_creds(self.as_client_principal,
                             self.as_service_principal,
                             self.as_session_key,
                             self.as_times,
                             tktflags=self.as_flags,
                             is_skey=0,
                             ticket=self.as_raw_ticket)

        if self.tgs_performed and not self.tgs_copy:
            self.cc.import_creds(self.tgs_client_principal,
                             self.tgs_service_principal,
                             self.tgs_session_key,
                             self.tgs_times,
                             tktflags=self.tgs_flags,
                             is_skey=0,
                             ticket=self.tgs_raw_ticket)
        #self.cc.show()
        self.cc.write(fname=self.db_name, close=close)

    def find_entry_in_credential_file(self, client_principal, service_principal):
        if not self.cc:
            logging.error("Must open db before")
            return []

        creds = self.cc.get_credentials(service_principal)

        # There shouldn't be more than one entry per client_principal/service_principal
        # but we can never be sure with the file format so let's pick
        # the first entry what ever the circumstances

        L = []
        given_name = client_principal[0].upper()
        given_type = client_principal[1]
        given_realm = client_principal[2].upper()
        for cred in creds:
            n,t,r = cred.get_client_principal()
            if n.upper() != given_name:
                continue
            # Logically we should check this as well.
            # But because of ms14-068 we do not. This will not prevent other
            # applications from working fine anyway.
            #if t != given_type:
            #    continue
            if r.upper() != given_realm:
                continue
            L.append(cred)
        return L

    def build_apreq_from_credential_db(self, cc=None, service_principal=None, generate_subkey=True):
        if not cc:
            cc = self.cc

        creds = cc.get_credentials(service_principal)

        # There shouldn't be more than one entry per service_principal
        # but we can never be sure with the file format so let's pick
        # the first entry what ever the circumstances

        if not len(creds):
            return None

        cred = creds[0]
        session_key = cred.get_session_key()
        client_principal = cred.get_client_principal()
        ticket = cred.get_ticket()

        if (not session_key) or (not client_principal) or (not ticket):
            return None

        # We can generate our own subkey but it's not mandatory at all
        if generate_subkey:
            subkey = helper.krb5_generate_random_key(helper.ETYPE_ARCFOUR_HMAC_MD5)
            self.sub_key = subkey
        else:
            subkey = None
            self.sub_key = session_key

        # We can then build the authenticator
        authenticator = build_authenticator(self.domain, client_principal, session_key, mode=11, subkey=subkey, with_checksum=False)
        patgsreq = PaTgsReq(self.__clone_ticket(ticket), authenticator).build()
        # And finally return the PA-TGS-REQ
        return patgsreq

    def build_apreq_from_credential_file(self, fname, service_principal=None, generate_subkey=True):
        # Extract data from ccache file
        try:
            f = open(fname, 'rb')
            raw_data = f.read()
            f.close()
        except Exception as e:
            logging.error("ccache file cannot be read: %s" % str(e))
            return None

        # Unserialize data
        cc1 = cc.CCache()
        cc1.set_raw_data(raw_data)
        return self.build_apreq_from_credential_db(cc=cc1, service_principal=service_principal, generate_subkey=generate_subkey)

    def export_into_credential_file(self, fname):
        cc1 = cc.CCache()
        cc1.set_header(self.as_client_principal, self.domain)

        if self.auth_performed:
            cc1.import_creds(self.as_client_principal,
                             self.as_service_principal,
                             self.as_session_key,
                             self.as_times,
                             tktflags=self.as_flags,
                             is_skey=0,
                             ticket=self.as_raw_ticket)

        if self.tgs_performed:
            cc1.import_creds(self.tgs_client_principal,
                             self.tgs_service_principal,
                             self.tgs_session_key,
                             self.tgs_times,
                             tktflags=self.tgs_flags,
                             is_skey=0,
                             ticket=self.tgs_raw_ticket)
        #cc1.show()
        cc1.write(fname=fname, close=1)

    ###
    # Does an ASREQ request
    ###

    def __do_auth(self):

        # Building the frame
        asreq = AsReq(self.as_client_principal, self.domain)
        asreq.set_server_principal(self.as_service_principal)
        asreq.set_passphrase(self.password, salt=self.salt)
        frame = asreq.pack()

        # Sending it
        data = self.__send_kerberos_packet(frame)
        if not data:
            logging.error("No answer!")
            return 0

        resp = AsRep(data)
        if not resp.is_valid():
            logging.error("Invalid response or wrong status")
            return 0

        # Extracting & saving everything
        self.auth_performed = True
        self.as_raw_ticket = resp.get_ticket()
        resp.set_passphrase(self.password, salt=self.salt)
        self.as_session_key = resp.get_session_key()
        self.as_times = resp.get_times()
        self.as_flags = resp.get_flags()
        self.auth_copy = False
        return 1


    def do_auth(self, client_principal=None, service_principal=None, with_db=0):
        if not client_principal:
            self.as_client_principal = Convert2PrincipalType(self.username, self.domain)
        else:
            self.as_client_principal = client_principal
        if not service_principal:
            self.as_service_principal = Convert2ServiceAndInstanceType('krbtgt/'+self.domain, self.domain)
        else:
            self.as_service_principal = service_principal

        if not self.target_ip:
            logging.error("No target KDC server available!")
            return 0

        if not with_db:
            return self.__do_auth()

        ### USING DB!
        else:
            creds = self.find_entry_in_credential_file(client_principal, service_principal)
            if len(creds):
                cred = creds[0]
                self.as_client_principal = cred.get_client_principal()
                self.as_service_principal = cred.get_service_principal()
                self.as_flags = cred.get_flags()
                self.as_raw_ticket = cred.get_ticket()
                self.as_times = cred.get_times()
                self.as_session_key = cred.get_session_key()
                self.auth_performed = True
                self.auth_copy = True
                return 1
            else:
                return self.__do_auth()

    ###
    # Does a TGS request
    ###

    def __get_ticket_service(self):

        # Building the frame
        tgsreq = TgsReq(self.domain,
                        client_principal=self.tgs_client_principal,
                        server_principal=self.tgs_service_principal)
        tgsreq.set_ticket(self.as_raw_ticket)
        tgsreq.set_session_key(self.as_session_key)
        frame = tgsreq.pack()

        # Sending it
        data = self.__send_kerberos_packet(frame)
        if not data:
            logging.error("No answer!")
            return 0

        resp2 = TgsRep(data)
        if not resp2.is_valid():
            logging.debug("Invalid response or wrong status")
            return 0

        # Extracting & saving everything
        self.tgs_performed = True
        self.tgs_subkey = tgsreq.get_subkey()
        resp2.set_key(self.tgs_subkey)
        self.tgs_raw_ticket = resp2.get_ticket()
        self.tgs_session_key = resp2.get_session_key()
        self.tgs_times = resp2.get_times()
        self.tgs_flags = resp2.get_flags()
        self.tgs_copy = False
        return 1

    def get_ticket_service(self, client_principal=None, service_principal=None, with_db=0):
        if not client_principal:
            self.tgs_client_principal = Convert2PrincipalType(self.username, self.domain)
        else:
            self.tgs_client_principal = client_principal
        if not service_principal:
            self.tgs_service_principal = Convert2ServiceAndInstanceType('krbtgt/'+self.domain, self.domain)
        else:
            self.tgs_service_principal = service_principal

        if not self.target_ip:
            logging.debug("DB call not implemented")
            return 0

        if not self.auth_performed:
            logging.debug("Auth not performed")
            return 0

        if not with_db:
            return self.__get_ticket_service()

        ### USING DB!
        else:
            creds = self.find_entry_in_credential_file(self.tgs_client_principal, self.tgs_service_principal)
            if len(creds):
                cred = creds[0]
                self.tgs_client_principal = cred.get_client_principal()
                self.tgs_service_principal = cred.get_service_principal()
                self.tgs_flags = cred.get_flags()
                self.tgs_raw_ticket = cred.get_ticket()
                self.tgs_times = cred.get_times()
                self.tgs_session_key = cred.get_session_key()
                self.tgs_performed = True
                self.tgs_copy = True
                return 1
            else:
                return self.__get_ticket_service()
