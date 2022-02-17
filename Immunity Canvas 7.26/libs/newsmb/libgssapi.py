#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  libgssapi.py
## Description:
##            :
## Created_On :  Thu Sep 16 15:38:51 2010
## Created_By :  Nicolas Pouvesle
## Modified_On:  Mon.Jan.5.15:19:36
## Modified_By:  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

###
# Note: We should either remove the current asn1 implementation or finish it.
# We should not work with both pyasn1 AND the current asn1 primitives.
###

import struct
from struct import pack

try:
    from pyasn1.codec.der import decoder,encoder
except ImportError:
    print "[EE] libgssapi: Cannot import pyasn1 (required)"
    raise

ASN1_BOOLEAN      = 0x01
ASN1_INTEGER      = 0x02
ASN1_BIT_STRING   = 0x03
ASN1_OCTET_STRING = 0x04
ASN1_OID          = 0x06
ASN1_ENUMERATED   = 0x0A
ASN1_SEQUENCE     = 0x30
ASN1_CHOICE       = 0xFE
ASN1_DEFINED      = 0xFF  # Self defined structure

ASN1_FLAG_OPTIONAL = 0x00001

# The OID we currently (or that we will very soon) support
GSS_NTLMSSP = '1.3.6.1.4.1.311.2.2.10'
GSS_KRB5 = '1.2.840.113554.1.2.2'
GSS_MS_KRB5 = '1.2.840.48018.1.2.2'

# The answers we may expect/return
GSS_RESULT_ACCEPT_COMPLETED = 0
GSS_RESULT_ACCEPT_INCOMPLETE = 1

class GSSException(Exception):
    pass

def asn1(string):
    strlen = len(string)
    if strlen < 0x7f:
        string = chr(strlen) + string
    elif strlen <= 0xffff:
        string = chr(0x82) + struct.pack('>H', strlen) + string
    else:
        raise GSSException("len > 0xffff")

    return string

def asn1_encode(code, data):
    return pack('B', code) + asn1(data)

def asn1_decode(data):
    strlen = len(data)

    if strlen < 2:
        raise GSSException('asn1_decode: len(data) < 2')

    code = ord(data[0])
    l    = ord(data[1])
    pos  = 2
    
    if l == 0x82:
        length = struct.unpack('>H', data[2:4])[0]
        pos = 4
    else:
        length = l

    data = data[pos:pos+length]
    pos = pos + length

    return (code, pos, data)

class ASN1Struct:
    st = []
    type = 0

    def __init__(self, data = None):
        self.value = {}

        for i in (range(0, len(self.st))):
            self.value[self.st[i][0]] = None

        if data is not None:
            self.unpack(data)

    def __getitem__(self, key):
        return self.value[key]

    def __setitem__(self, key, value):
        self.value[key] = value

    def encodeoid(self, data):
        list = data.split('.')
        enc = pack('B', int(list[0]) * 40 + int(list[1]))

        for i in (range(2, len(list))):
            v = int(list[i])
            e = ''
            first = True
            while v != 0:
                q = v & 0x7F
                if first == True:
                    first = False
                else:
                    q = q | 0x80
                e = pack('B', q) + e
                v = v >> 7
            enc = enc + e

        return enc

    def pack(self, addtype = False):
        data = ''
        for i in (range(0, len(self.st))):
            field = self.st[i]
            item = ''
            p = True
            opt = False

            if field[2] & ASN1_FLAG_OPTIONAL:
                opt = True
            elif self.type == ASN1_CHOICE:
                opt = True

            if opt == True:
                if self.value[field[0]] is None:
                    p = False

            if p == True:
                value = self.value[field[0]]

                if field[1] == ASN1_SEQUENCE:
                    tmp = ''
                    for f in (value):
                        tmp = tmp + f.pack()
                    value = tmp
                elif field[1] == ASN1_DEFINED:
                    value = value.pack(True)
                elif field[1] == ASN1_OID:
                    value = self.encodeoid(value)

                if field[1] != ASN1_DEFINED:
                    item = asn1_encode(field[1], value)
                else:
                    item = value

                if opt == True:
                    item = asn1_encode(0xa0 + i, item)

                data += item

        if addtype == True:
            if self.type == ASN1_SEQUENCE:
                data = asn1_encode(self.type, data)

        return data

    def unpack(self, data):
        ## XXX TODO XXX
        return data

class MechType(ASN1Struct):
    type = ASN1_OID

    st = [
        ['mechType', ASN1_OID, 0, None]
        ]

class NegTokenInit(ASN1Struct):
    type = ASN1_SEQUENCE

    st  = [
        ['mechTypes',   ASN1_SEQUENCE,     ASN1_FLAG_OPTIONAL, MechType],
        ['reqFlags' ,   ASN1_BIT_STRING,   ASN1_FLAG_OPTIONAL, None],
        ['mechToken',   ASN1_OCTET_STRING, ASN1_FLAG_OPTIONAL, None],
        ['mechListMIC', ASN1_OCTET_STRING, ASN1_FLAG_OPTIONAL, None],
        ]

class NegTokenTarg(ASN1Struct):
    type = ASN1_SEQUENCE

    st = [
        ['negResult',      ASN1_ENUMERATED,   ASN1_FLAG_OPTIONAL, None],
        ['supportedMech',  ASN1_OID,          ASN1_FLAG_OPTIONAL, None],
        ['responseToken',  ASN1_OCTET_STRING, ASN1_FLAG_OPTIONAL, None],
        ['mechListMIC',    ASN1_OCTET_STRING, ASN1_FLAG_OPTIONAL, None],
        ]

class NegotiationToken(ASN1Struct):
    type = ASN1_CHOICE

    st = [
        ['negTokenInit', ASN1_DEFINED, 0, NegTokenInit],
        ['negTokenTarg', ASN1_DEFINED, 0, NegTokenTarg],
        ]

class InitialContextToken(ASN1Struct):
    type = ASN1_SEQUENCE

    st = [
        ['thisMech',           ASN1_OID    , 0, MechType],
        ['innerContextToken',  ASN1_DEFINED, 0, NegotiationToken],
        ]

class GSSAPI:

     ## Supported GSS-API types
    GSSAPI_SPNEGO = '1.3.6.1.5.5.2'

    def __init__(self, data = None, init = False):
        self.init = init
        if self.init == True:
            self.context = InitialContextToken()
        else:
            self.context = NegotiationToken()

        if data is not None:
            self.unpack(data)

    def pack(self):
        if self.type != self.GSSAPI_SPNEGO:
            raise GSSException('type != GSSAPI_SPNEGO')

        data = self.context.pack()
        if self.init == True:
            data = asn1_encode(0x60, data)

        return data

    def unpack(self, data):
        if self.type != self.GSSAPI_SPNEGO:
            raise GSSException('type != GSSAPI_SPNEGO')

        if self.init == True:
            (code, length, data) = asn1_decode(data)

        self.context.unpack(data)

    def spnego_init(self, token, mechtypes=[]):
        self.type = self.GSSAPI_SPNEGO

        if not token:
            raise GSSException('Invalid parameter: token is not set.')

        # Default is GSS_NTLMSSP first then GSS_KRB5
        if not len(mechtypes):
            mechtypes = [ GSS_NTLMSSP ]

        # Build the array of MechType() objects
        m_types = []
        for _type in mechtypes:
            m_type = MechType()
            m_type['mechType'] = _type
            m_types.append(m_type)

        ninit = NegTokenInit()
        ninit['mechTypes'] = m_types
        ninit['mechToken'] = token
        negtoken = NegotiationToken()
        negtoken['negTokenInit'] = ninit
        self.context['thisMech'] = self.GSSAPI_SPNEGO
        self.context['innerContextToken'] = negtoken

    def spnego_cont(self, token):
        self.type = self.GSSAPI_SPNEGO
        ntarg = NegTokenTarg()
        ntarg['responseToken'] = token
        self.context['negTokenTarg'] = ntarg

    def spnego_answer(self, data):
        # For now we'll use pyasn1.
        try:
            ntarg = decoder.decode(data)[0]
            result = int(ntarg[0])
            oid = str(ntarg[1])
            token = str(ntarg[2])
        except Exception as e:
            raise GSSException("GSS: Could not parse negTokenArg: %s" % str(e))
        return result, oid, token
