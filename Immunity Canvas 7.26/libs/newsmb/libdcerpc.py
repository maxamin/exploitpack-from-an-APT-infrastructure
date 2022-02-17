#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  libdcerpc.py
## Description:
##            :
## Created_On :  Wed Jul 22 13:56:57 2009
## Created_By :  Kostya Kortchinsky
## Modified_On:  Wed Jan  5 14:58:20 2011
## Modified_By:  Kostya Kortchinsky
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import random
import socket
import traceback
import logging
from cStringIO import StringIO

if '.' not in sys.path:
    sys.path.append('.')

import dunicode
from struct import pack, unpack, calcsize
from libs.newsmb.libsmb import SMBClient, SMBException
from libs.newsmb.Struct import Struct
from libs.newsmb.libntlm import NTLM
from libs.newsmb.libkrb5 import KRB5
from libs.newsmb.libsmb import SMBTransactException
from libs.newsmb.smbconst import * #SMB constants
from libs.newsmb.libsmb import assert_unicode

try:
    from Crypto.Hash import MD5, HMAC
    from Crypto.Cipher import ARC4
except ImportError:
    from libs.Crypto.Hash import MD5, HMAC
    from libs.Crypto.Cipher import RC4 as ARC4

from MOSDEF.mosdefutils import intel_order

#Custom Options
OPTION_SMB_TRANSACT = 0x01

# http://www.opengroup.org/onlinepubs/009629399/chap12.htm#tagcjh_17_06
DCERPC_HEADER_SIZE  = 16
DCERPC_CONTEXT_SIZE = 20

DCERPC_request            = 0
DCERPC_ping               = 1
DCERPC_response           = 2
DCERPC_fault              = 3
DCERPC_working            = 4
DCERPC_nocall             = 5
DCERPC_reject             = 6
DCERPC_ack                = 7
DCERPC_cl_cancel          = 8
DCERPC_fack               = 9
DCERPC_cancel_ack         = 10
DCERPC_bind               = 11
DCERPC_bind_ack           = 12
DCERPC_bind_nak           = 13
DCERPC_alter_context      = 14
DCERPC_alter_context_resp = 15
DCERPC_auth_3             = 16
DCERPC_shutdown           = 17
DCERPC_co_cancel          = 18
DCERPC_orphaned           = 19

PFC_FIRST_FRAG      = 0x01
PFC_LAST_FRAG       = 0x02
PFC_PENDING_CANCEL  = 0x04
PFC_RESERVED_1      = 0x08
PFC_CONC_MPX        = 0x10
PFC_DID_NOT_EXECUTE = 0x20
PFC_MAYBE           = 0x40
PFC_OBJECT_UUID     = 0x80

RPC_C_AUTHN_NONE          = 0x00
RPC_C_AUTHN_GSS_NEGOTIATE = 0x09
RPC_C_AUTHN_WINNT         = 0x0a
RPC_C_AUTHN_GSS_KERBEROS  = 0x10
RPC_C_AUTHN_NETLOGON      = 0x44
RPC_C_AUTHN_DEFAULT       = 0xff

RPC_C_AUTHN_LEVEL_DEFAULT       = 0x00
RPC_C_AUTHN_LEVEL_NONE          = 0x01
RPC_C_AUTHN_LEVEL_CONNECT       = 0x02
RPC_C_AUTHN_LEVEL_CALL          = 0x03
RPC_C_AUTHN_LEVEL_PKT           = 0x04
RPC_C_AUTHN_LEVEL_PKT_INTEGRITY = 0x05
RPC_C_AUTHN_LEVEL_PKT_PRIVACY   = 0x06

RPC_C_IMPL_LEVEL_IDENTITY    = 0x00
RPC_C_IMPL_LEVEL_IMPERSONATE = 0x00
RPC_C_IMPL_LEVEL_DELEGATE    = 0x00

RPC_C_EP_ALL_ELTS      = 0x00000000
RPC_C_EP_MATCH_BY_IF   = 0x00000001
RPC_C_EP_MATCH_BY_OBJ  = 0x00000002
RPC_C_EP_MATCH_BY_BOTH = 0x00000003

RPC_C_VERS_ALL        = 0x00000001
RPC_C_VERS_COMPATIBLE = 0x00000002
RPC_C_VERS_EXACT      = 0x00000003
RPC_C_VERS_MAJOR_ONLY = 0x00000004
RPC_C_VERS_UPTO       = 0x00000005


###############
#
# Some utility functions
#

def parseStringBinding(binding):
    if binding.count(u':') != 1 or binding.count(u'[') != 1 or binding.count(u']') != 1:
        raise DCERPCException('Malformed binding')
    if binding.find('[') < binding.find(u':') or binding.find(u']') < binding.find(u'['):
        raise DCERPCException('Malformed binding')

    sequence, address_and_endpoint = binding.split(u':')
    address, endpoint_and_option = address_and_endpoint.split(u'[')

    if endpoint_and_option.count(u',') > 0: #String binding contains an Option
        endpoint, option = endpoint_and_option.split(u',')
        option = option[:option.find(u']')]
    else:
        endpoint = endpoint_and_option[:endpoint_and_option.find(u']')]
        option = u''

    return (sequence, address, endpoint, option)


############################
# The following are for compatibility with some exploits and must be removed
# after exploits that use them are updated

def s_dce_wordstring(mystr, nullterm=0):
    """
    turn mystr into a dce string (not null terminated)
    """
    data=""
    #null terminate if necessary
    if nullterm and mystr[-1]!="\x00":
        mystr+="\x00"

    size=len(mystr)
    data+=intel_order(size)
    data+=intel_order(0)
    data+=intel_order(size)
    data+=mystr
    #data+="\x00"
    padding=4-len(data)%4
    if padding==4:
        padding=0

    data+="\x00"*(padding)

    return data

def s_dce_raw_unistring(mystr):
    """
    mystr is already unicoded for us but we null terminate it
    """
    data=""
    if len(mystr)%2!=0:
        logging.debug("Warning, your raw unicode string is not aligned!")
    size=len(mystr)/2+1
    data+=intel_order(size)
    data+=intel_order(0)
    data+=intel_order(size)
    data+=mystr+"\x00\x00"
    padding=4-len(data)%4
    if padding!=4:
        data+="\x00"*(padding)

    return data

def s_dce_win2k_unistring(mystr):
    ret=""
    for c in mystr:
        ret+=c+"\x00"
    #ret=dunicode.win32ucs2(mystr,badstring=badstring)
    return s_dce_raw_unistring(ret)


def s_dce_unistring(mystr, badstring=None):
    """
    Does a windows specific unicode transcoding

    Also does padding and null termination
    """
    ret=""
    #for c in mystr:
    #    ret+=c+"\x00"
    ret = dunicode.win32ucs2(mystr, badstring=badstring)
    return s_dce_raw_unistring(ret)

########################################

class DCERPCException(Exception):
    pass


class DCERPCString(Struct):
    st = [
        ['MaximumCount' , '<L', 0],
        ['Offset'       , '<L', 0],
        ['ActualCount'  , '<L', 0],
        ['String'       , '0s', '']
    ]

    def __init__(self, data=None, string=None, is_unicode=True):
        Struct.__init__(self, data)

        if is_unicode == True:
            self.null = u'\0'.encode('UTF-16LE')
        else:
            self.null = u'\0'.encode('ASCII')

        if data is not None:
            pos = self.calcsize()
            string = data[pos:pos + (self['ActualCount'] * len(self.null))]
            self['String'] = string
        elif string is not None:
            self['String'] = string

    def pack(self, without_padding=0, force_null_byte=1):
        s = self['String']
        # We do not _always_ want to add a terminator
        if force_null_byte:
            if s[-len(self.null):] != self.null:
                s += self.null
        if not self['MaximumCount']:
            self['MaximumCount'] = len(s) / len(self.null)
            self['ActualCount'] = self['MaximumCount']
        data = Struct.pack(self) + s
        if not without_padding:
            if (len(data) % 4) != 0:
                data += '\0' * (4 - (len(data) % 4))
        return data

    def get_string(self):
        return self['String']


"""
//2.3.4.1 GUID--RPC IDL representation ([MS-DTYP].pdf)
typedef struct {
 unsigned long Data1;
 unsigned short Data2;
 unsigned short Data3;
 byte Data4[8];
} GUID, UUID, *PGUID;
"""

class DCERPCUuid(Struct):
    st = [
        ['Data1', '<L', 0 ],
        ['Data2', '<H', 0 ],
        ['Data3', '<H', 0 ],
        ['Data4', '8s', '\x00'*8 ],
    ]

    def __init__(self, data=None, uuid=''):
        Struct.__init__(self, data)

        if data is not None:
            pass
        else:
            s = uuid.split('-')
            self['Data1'] = int(s[0],16)
            self['Data2'] = int(s[1],16)
            self['Data3'] = int(s[2],16)
            self['Data4'] = (s[3] + s[4]).decode('hex')

    def pack(self):

        data = Struct.pack(self)
        return data


class DCERPCGuid(DCERPCUuid):
    def __init__(self, data=None, guid=''):
        DCERPCUuid.__init__(self, data=data, uuid=guid)

"""
typedef struct _RPC_SID {
 unsigned char Revision;
 unsigned char SubAuthorityCount;
 RPC_SID_IDENTIFIER_AUTHORITY IdentifierAuthority;
 [size_is(SubAuthorityCount)] unsigned long SubAuthority[];
} RPC_SID, *PRPC_SID, *PSID;
"""

class DCERPCSid(Struct):
    st = [
        ['Count', '<L', 4 ],
        ['Revision', 'B', 1 ],
        ['NumAuth', 'B', 0 ],
        ['Padding', '<H', 0 ],
        ['Authority', '>L', '' ],
        ['Subauthorities', '0s', '' ],
    ]

    def __init__(self, data=None, Sid=''):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
            self['Subauthorities'] = []
            pos = self.calcsize()
            for i in xrange(self['NumAuth']):
                self['Subauthorities'].append(unpack('<L', data[pos:pos+4])[0])
                pos += 4
        else:
            s = Sid.split('-')
            self['Revision'] = int(s[1])
            self['Authority'] = int(s[2])
            self['NumAuth'] = len(s[3:])
            self['Count'] = self['NumAuth']
            self['Subauthorities'] = [ int(x) for x in s[3:] ]

    def pack(self):

        data = Struct.pack(self)
        for subauth in self['Subauthorities']:
            data += pack('<L', subauth)
        return data

    def get_sid(self):
        L = map(lambda x: str(x), self['Subauthorities'])
        return '-'.join(['S', str(self['Revision']), str(self['Authority'])] + L)


class DCERPCContext(Struct):
    st = [
        ['Uuid'         , '16s', '\0'*16],
        ['VersionMajor' , '<H', 0],
        ['VersionMinor' , '<H', 0],
    ]

    def __init__(self, data=None, uuid=None, version=None):
        Struct.__init__(self, data)
        if uuid is not None and version is not None:
            self.from_string(uuid, version)

    def pack(self):
        data = Struct.pack(self)

        return data

    def tower_pack(self):
        """
        Towers used for epmap have versions components on bytes instead of words
        """
        data = pack('<16sBB', self['Uuid'], self['VersionMajor'], self['VersionMinor'])

        return data

    def from_string(self, uuid, version):
        """
        Parses a UUID and a version (both string) into a DCERPCContext.

        IN:
            uuid [string] - string representation of the uuid: '12345678-1234-abcd-ef00-0123456789ab'
            version [string] - string representation of the version: '1.0'
        """
        x = map(lambda w: int(w, 16), uuid.split('-'))
        self['Uuid'] = pack('<LHH', x[0], x[1], x[2]) + pack('>H', x[3]) + pack('>Q', x[4])[2:]
        self['VersionMajor'], self['VersionMinor'] = map(lambda w: int(w, 10), version.split('.'))

    def to_string(self):
        """
        Dumps a DCERPCContect to a readble string.

        OUT:
            s [string] - string representation of the context: '12345678-1234-abcd-ef00-0123456789ab v1.0'
        """
        x = unpack('<LHH', self['Uuid'][:8]) + unpack('>H', self['Uuid'][8:10]) + unpack('>Q', '\0\0' + self['Uuid'][10:])
        s = u'%08x-%04x-%04x-%04x-%012x v%d.%d'%(x[0], x[1], x[2], x[3], x[4], self['VersionMajor'], self['VersionMinor'])
        return s

class DCERPCAuthVerifier(Struct):
    st = [
        ['auth_pad'        , '0s', ''],
        ['auth_type'       , '<B', 0],
        ['auth_level'      , '<B', 0],
        ['auth_pad_length' , '<B', 0],
        ['auth_reserved'   , '<B', 0],
        ['auth_context_id' , '<L', 0],
        ['auth_value'      , '0s', ''],
    ]

    def __init__(self, data=None, auth_length=0):
        if data is not None:
            pad_len = len(data) - self.calcsize() - auth_length
            if pad_len < 0 or pad_len > 12: #12 seems to be a valid value according to what's happening with the rpc port mapper --Kostya
                logging.debug('pad_len inconcistency (%d) --Kostya')
                raise DCERPCException('pad_len inconcistency: ' % pad_len)

            pad = data[:pad_len]
            data = data[pad_len:]
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['auth_value'] = data[pos:]
            self['auth_pad'] = pad

    def pack(self):
        self['auth_pad_length'] = len(self['auth_pad'])
        data = Struct.pack(self)

        return self['auth_pad'] + data + self['auth_value']

class DCERPCHeader(Struct):
    st = [
        ['rpc_vers'       , '<B', 5],
        ['rpc_vers_minor' , '<B', 0],
        ['PTYPE'          , '<B', 0],
        ['pfc_flags'      , '<B', 0],
        ['packed_drep'    , '<L', 0x10],
        ['frag_length'    , '<H', 0],
        ['auth_length'    , '<H', 0],
        ['call_id'        , '<L', 0],
    ]


class DCERPCAuth3(Struct):
    st = [
        ['pad'           , '<L', 0],
        ['auth_verifier' , '0s', ''],
    ]

    def __init__(self, data = None, auth_length = 0):
        Struct.__init__(self, data)

        if data is not None:
            self['auth_verifier'] = data

    def pack(self):
        data = Struct.pack(self)

        return data + self['auth_verifier']

class DCERPCFault(Struct):
    st = [
        ['alloc_hint'    , '<L', 0],
        ['p_cont_id'     , '<H', 0],
        ['cancel_count'  , '<B', 0],
        ['reserved'      , '<B', 0],
        ['status'        , '<L', 0],
        ['reserved2'     , '<L', 0],
        ['auth_verifier'  , '0s', ''],
    ]
    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['auth_verifier'] = data[pos:]

    def pack(self):
        data = Struct.pack(self)
        return data + self['auth_verifier']

class DCERPCBind(Struct):
    st = [
        ['max_xmit_frag'  , '<H', 4280],
        ['max_recv_frag'  , '<H', 4280],
        ['assoc_group_id' , '<L', 0],
        ['p_context_elem' , '0s', ''],
        ['auth_verifier'  , '0s', ''],
    ]
    n_context_elem = 0

    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self.n_context_elem, _, _ = unpack('<BBH', data[pos:pos + calcsize('<BBH')])
            pos += calcsize('<BBH')
            for i in range(self.n_context_elem):
                p_cont_id, n_transfer_syn = unpack('<HBB', data[pos:pos + calcsize('<HBB')])
                pos += calcsize('<HBB')
                pos += DCERPC_CONTEXT_SIZE #XXX: Unpack abstract syntax here --Kostya
                for j in range(n_transfer_syn):
                    pos += DCERPC_CONTEXT_SIZE #XXX: Unpack transfer syntax here --Kostya
            self['p_context_elem'] = data[self.calcsize():pos]
            self['auth_verifier'] = data[pos:]

    def add_abstract_syntax(self, uuid, version, cont_id=0, t_uuid=None, t_ver=None):
        """
        Adds an abstract/transfer syntax to a DCERPC bind request.

        IN:
            uuid [string]    - abstract syntax string representation of the uuid: '12345678-1234-abcd-ef00-0123456789ab'
            version [string] - abstract syntax string representation of the version: '1.0'
            t_uuid [string]  - transfer syntax string representation of the uuid: '12345678-1234-abcd-ef00-0123456789ab'
            t_vern [string]  - transfer syntax string representation of the version: '1.0'
        """
        abstract_syntax = DCERPCContext(uuid=uuid, version=version)
        if t_uuid and t_ver:
            transfer_syntax = DCERPCContext(uuid=t_uuid, version=t_ver)
        else:
            # default to Version 2.0 data representation protocol
            transfer_syntax = DCERPCContext(uuid = u'8a885d04-1ceb-11c9-9fe8-08002b104860', version = u'2.0')

        s = pack('<HBB', cont_id, 1, 0) + abstract_syntax.pack() + transfer_syntax.pack()
        self.n_context_elem += 1
        self['p_context_elem'] += s

    def pack(self):
        data = Struct.pack(self)

        return data + pack('<BBH', self.n_context_elem, 0, 0) + self['p_context_elem'] + self['auth_verifier']

DCERPCAlterContext = DCERPCBind


class DCERPCBindNak(Struct):
    st = [
        ['provider_reject_reason' , '<H', 0],
    ]

    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)


class DCERPCBindAck(Struct):
    st = [
        ['max_xmit_frag'  , '<H', 4280],
        ['max_recv_frag'  , '<H', 4280],
        ['assoc_group_id' , '<L', 0],
        ['sec_addr'       , '0s', ''],
        ['p_result_list'  , '0s', ''],
        ['auth_verifier'  , '0s', ''],
    ]
    port_spec = ''
    n_results = 0

    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            length = unpack('<H', data[pos:pos + calcsize('<H')])[0]
            self.port_spec = data[pos + calcsize('<H'):pos + calcsize('<H') + length]
            self['sec_addr'] = data[pos:pos + calcsize('<H') + length]
            pos += len(self['sec_addr'])
            if (pos % 4) != 0:
                pos += 4 - (pos % 4)
            marker = pos
            self.n_results, _, _ = unpack('<BBH', data[pos:pos + calcsize('<BBH')])
            pos += calcsize('<BBH')
            for i in range(self.n_results):
                result, reason = unpack('<HH', data[pos:pos + calcsize('<HH')])
                pos += calcsize('<HH')
                pos += DCERPC_CONTEXT_SIZE #XXX: Unpack transfer syntax here --Kostya
            self['p_result_list'] = data[marker:pos]
            self['auth_verifier'] = data[pos:]

    def pack(self):
        data = Struct.pack(self)
        if self.port_spec != '':
            self['sec_addr'] = pack('<H', len(self.port_spec)) + self.port_spec
            while (len(self['sec_addr']) % 4) != 0:
                self['sec_addr'] += '\0'
        transfer_syntax = DCERPCContext(uuid = u'8a885d04-1ceb-11c9-9fe8-08002b104860', version = u'2.0')
        self['p_result_list'] = pack('<BBH', 1, 0, 0) + pack('<BB', 0, 0) + transfer_syntax.pack() #XXX: 1 result only --Kostya

        return data + self['sec_addr'] + self['p_result_list'] + self['auth_verifier']

DCERPCAlterContextResp = DCERPCBindAck

class DCERPCRequest(Struct):
    st = [
        ['alloc_hint'    , '<L', 0],
        ['p_cont_id'     , '<H', 0],
        ['opnum'         , '<H', 0],
        ['data'          , '0s', ''],
        ['auth_verifier' , '0s', ''],
    ]

    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            if auth_length != 0:
                size = DCERPCAuthVerifier().calcsize()
                auth_length += size
                auth_verifier = DCERPCAuthVerifier(data = data[-auth_length:-auth_length + size])
                auth_length += auth_verifier['auth_pad_length']
                self['auth_verifier'] = data[-auth_length:]
                self['data'] = data[pos:-auth_length]
            else:
                self['data'] = data[pos:]

    def pack(self):
        #self['alloc_hint'] = len(self['data']) #XXX: Not true for fragmented requests --Kostya
        data = Struct.pack(self)

        return data + self['data'] + self['auth_verifier']

class DCERPCResponse(Struct):
    st = [
        ['alloc_hint'    , '<L', 0],
        ['p_cont_id'     , '<H', 0],
        ['cancel_count'  , '<B', 0],
        ['reserved'      , '<B', 0],
        ['data'          , '0s', ''],
        ['auth_verifier' , '0s', ''],
    ]

    def __init__(self, data=None, auth_length=0):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            if auth_length != 0:
                size = DCERPCAuthVerifier().calcsize()
                auth_length += size
                auth_verifier = DCERPCAuthVerifier(data = data[-auth_length:-auth_length + size])
                auth_length += auth_verifier['auth_pad_length']
                self['auth_verifier'] = data[-auth_length:]
                self['data'] = data[pos:-auth_length]
            else:
                self['data'] = data[pos:]

    def pack(self):
        #self['alloc_hint'] = len(self['data']) #XXX: Not true for fragmented requests --Kostya
        data = Struct.pack(self)
        return data + self['data'] + self['auth_verifier']

class DCERPCPacket():
    def __init__(self, data=None, packet_type=0):
        self.header = DCERPCHeader(data)

        if data is not None:
            packet_type = self.header['PTYPE']
            data = data[DCERPC_HEADER_SIZE:]
        else:
            self.header['PTYPE'] = packet_type

        dcerpc_dispatch = {
            DCERPC_request:            DCERPCRequest,
            #DCERPC_ping:
            DCERPC_response:           DCERPCResponse,
            DCERPC_fault:              DCERPCFault,
            #DCERPC_working:
            #DCERPC_nocall:
            #DCERPC_reject:
            #DCERPC_ack:
            #DCERPC_cl_cancel:
            #DCERPC_fack:
            #DCERPC_cancel_ack:
            DCERPC_bind:               DCERPCBind,
            DCERPC_bind_ack:           DCERPCBindAck,
            DCERPC_bind_nak:           DCERPCBindNak,
            DCERPC_alter_context:      DCERPCAlterContext,
            DCERPC_alter_context_resp: DCERPCAlterContextResp,
            DCERPC_auth_3:             DCERPCAuth3,
            #DCERPC_shutdown:
            #DCERPC_co_cancel:
            #DCERPC_orphaned:
        }

        self.body = dcerpc_dispatch[packet_type](data, self.header['auth_length'])

    def pack(self):
        data = self.body.pack()
        self.header['frag_length'] = DCERPC_HEADER_SIZE + len(data)
        return self.header.pack() + data

class DCERPCConnection():

    def __init__(self, s, address, port, username, password, domain):
        self.s        = s
        self.address  = address
        self.port     = port
        self.username = username
        self.password = password
        self.domain = domain

class DCERPCOverSMB(DCERPCConnection):
    def __init__(self, s, address, port, named_pipe, username=None, password=None, domain=None, kerberos_db=None, use_krb5=False, frag_level=None, smb_client=None):
        DCERPCConnection.__init__(self, s, address, port, username, password, domain)
        self.named_pipe = named_pipe
        self.smb = None
        self.frag_level = frag_level
        self.kerberos_db = kerberos_db
        self.use_krb5 = use_krb5
        if smb_client:
            self.smb = smb_client

    def connect(self):
        # Return 0 for success, 1 for error
        sockaddr = (self.address, self.port)
        try:
            self.s.connect(sockaddr)
            preexisting_smb = False
            if self.smb:
                preexisting_smb = True

            if self.smb == None:
                self.smb = SMBClient(self.s, username=self.username, password=self.password, domain=self.domain, frag_level=self.frag_level)

            self.smb.is_unicode = True

            # This has to be done only for new connections
            # If we are reusing an existing SMB connection there is no need to
            # re-negotiate and setup_session
            if preexisting_smb == False:
                self.smb.negotiate()
                self.smb.session_setup(kerberos_db=self.kerberos_db, use_krb5=self.use_krb5)

            self.smb.tree_connect(u'IPC$')
            self.smb.nt_create(name=self.named_pipe,
                               desired_access=SYNCHRONIZE|FILE_READ_DATA|FILE_WRITE_DATA|FILE_APPEND_DATA|FILE_READ_EA|FILE_WRITE_EA|FILE_READ_ATTRIBUTES|FILE_WRITE_ATTRIBUTES|READ_CONTROL,
                               share_access = FILE_SHARE_READ|FILE_SHARE_WRITE)
            return 0
        except Exception as e:
            logging.error('DCERPCOverSMB.connect() failed: %s' % str(e))
            return 1

    def recv(self, filesize=65535, option=0):
        data = StringIO()
        if filesize == 65535:
            try:
                to_read, _, _ = self.smb.transact_peek_np()
                filesize = to_read
                logging.debug('recv: %d' % filesize)
            except SMBTransactException as e:
                logging.debug('smb.transact_peek_np() failed: %s' % e)
                # transact_peek_np may not be supported (i.e. samba)
                # in that case we fall back to doing a big read
                pass

        if filesize == 0:
            logging.debug('Returning from recv(), no data in pipe.')
            return None

        try:
            self.smb.read(data, filesize=filesize)
        except Exception as e:
            logging.debug('smb.read() failed: %s' % str(e))
            return None

        return data.getvalue()

    def send_recv(self, data, response=True, option=0):
        try:
            if (option & OPTION_SMB_TRANSACT) == 0:
                send_data = StringIO(data)
                self.smb.write(send_data)
                if response == True:
                    ret = self.recv(option=option)
                    return ret
                else:
                    return None
            else:
                data = self.smb.transact_np(data, response=response)
                return data
        except Exception as e:
            logging.debug('DCERPCOverSMB.send_recv() failed: %s' % str(e))
            return None

    def disconnect(self):
        try:
            self.smb.tree_disconnect()
            self.smb.logoff()
            self.s.close()
        except SMBException, ex:
            logging.debug('DCERPCOverSMB.disconnect() failed: %s' % str(e))


class DCERPCOverTCP(DCERPCConnection):
    def __init__(self, s, address, port, username=None, password=None, domain=None):
        DCERPCConnection.__init__(self, s, address, port, username, password, domain)

    def connect(self):
        # Return 0 for success, 1 for error
        sockaddr = (self.address, self.port)
        try:
            self.s.connect(sockaddr)
        except Exception as e:
            logging.debug('DCERPCOverTCP.connect() failed: %s' % str(e))
            return 1
        return 0

    def recv(self, option=0):
        try:
            data = self.s.recv(DCERPC_HEADER_SIZE)
        except Exception, ex:
            logging.debug('Exception: %s' % ex)
            raise DCERPCException('%s' % ex)

        if len(data) != DCERPC_HEADER_SIZE:
            logging.debug('Received DCERPC header has an invalid length! (%s) --Kostya' % len(data))
            raise DCERPCException('Received DCERPC header has an invalid length! (%s)' % len(data))

        header = DCERPCHeader(data)
        frag_length = header['frag_length']
        while len(data) != frag_length:
            try:
                data += self.s.recv(frag_length - len(data))
            except Exception, ex:
                logging.debug('Exception: %s' % ex)
                raise DCERPCException('%s' % ex)
        return data

    def send_recv(self, data, response=True, option=0):
        try:
            self.s.sendall(data)
            if response == True:
                return self.recv(option)
            else:
                return None
        except Exception as e:
            logging.debug('DCERPCOverTCP.send_recv() failed: %s' % str(e))
            raise DCERPCException('%s' % e)

    def disconnect(self):
        try:
            self.s.close()
        except Exception as e:
            logging.debug('DCERPCOverTCP.disconnect() failed: %s' % str(e))


class DCERPC():
    """
    Fragmentation level should be: None (no fragmentation at all, applies to DCERPC or underlying SMB client if over SMB
                                   1 ( DCERPC fragmentation and moderate SMB fragmentation)
                                   2 ( DCERPC fragmentation and max SMB fragmentation = VERY SLOW)
    """
    def __init__(self, binding, getsock=None, username=None, password=None, computer=None,
                       domain=None, kerberos_db=None, use_krb5=False, frag_level=None, smbport=445, smb_client=None):
        (binding, username, password, computer, domain) = map(assert_unicode, (binding, username, password, computer, domain))
        self.packet               = None
        self.username             = username
        self.password             = password
        self.computer             = computer
        self.domain               = domain
        self.kerberos_db          = kerberos_db
        self.dcerpc_connection    = None
        self.cont_id              = 0
        self.getsock              = getsock
        self.auth_type            = RPC_C_AUTHN_NONE
        self.auth_level           = RPC_C_AUTHN_LEVEL_DEFAULT
        self.SessionKey           = '' #XXX: Keeping notation from [MS-NRPC]
        self.ClientSequenceNumber = 0  #XXX: Keeping notation from [MS-NRPC]
        self.reassembled_data     = ''
        self.ntlm                 = None
        self.krb5                 = None
        self.frag_level           = frag_level
        self.max_dcefrag          = 0 if frag_level == None else 1
        sequence, address, endpoint, _ = parseStringBinding(binding)
        self.address              = address
        self.endpoint             = endpoint

        if self.getsock:
            if ":" in address:
                sock = self.getsock.gettcpsock(AF_INET6=1)
            else:
                sock = self.getsock.gettcpsock()
        else:
            if ":" in address:
                sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        if sequence == u'ncacn_np':
            if endpoint.lower().startswith(u'\\pipe') == True:
                endpoint = endpoint[len(u'\\pipe'):]
            self.dcerpc_connection = DCERPCOverSMB(sock,
                                                   address,
                                                   smbport,
                                                   endpoint,
                                                   username,
                                                   password,
                                                   domain,
                                                   kerberos_db,
                                                   use_krb5,
                                                   frag_level,
                                                   smb_client)
        elif sequence == u'ncacn_ip_tcp':
            self.dcerpc_connection = DCERPCOverTCP(sock, address, int(endpoint))
        else:
            raise DCERPCException('Unsupported transport: %s' % sequence)

    def seal_packet(self):
        if self.auth_type == RPC_C_AUTHN_NONE:
            #XXX: Nothing to do, returning --Kostya
            return
        elif self.auth_type == RPC_C_AUTHN_WINNT:
            if self.auth_level not in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
                return
            auth_verifier = DCERPCAuthVerifier()
            size = len(self.packet.pack()) % 4
            if size != 0:
                auth_verifier['auth_pad'] = '\0' * (4 - size)
            auth_verifier['auth_type'] = self.auth_type
            auth_verifier['auth_level'] = self.auth_level
            auth_verifier['auth_context_id'] = self.auth_context_id
            auth_verifier['auth_value'] = pack('<L8sL', 1, '\0' * 8, 0)
            self.packet.header['auth_length'] = len(auth_verifier['auth_value'])
            self.packet.body['auth_verifier'] = auth_verifier.pack()
            rpc_packet = self.packet.pack()
            if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                sealed_data = self.ntlm.SEAL(self.packet.body['data'] + auth_verifier['auth_pad'])
            auth_verifier['auth_value'] = self.ntlm.MAC(rpc_packet[:-len(auth_verifier['auth_value'])])
            if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                self.packet.body['data'] = sealed_data[:len(self.packet.body['data'])]
                auth_verifier['auth_pad'] = sealed_data[len(self.packet.body['data']):]
        elif self.auth_type == RPC_C_AUTHN_NETLOGON:
            if self.auth_level not in [RPC_C_AUTHN_LEVEL_PKT_INTEGRITY, RPC_C_AUTHN_LEVEL_PKT_PRIVACY]:
                #XXX: Unsupported --Kostya
                return
            auth_verifier = DCERPCAuthVerifier()
            size = len(self.packet.pack()) % 4
            if size != 0:
                auth_verifier['auth_pad'] = '\0' * (4 - size)
            auth_verifier['auth_type'] = self.auth_type
            auth_verifier['auth_level'] = self.auth_level
            auth_verifier['auth_context_id'] = self.auth_context_id
            #XXX: Here we keep the notations of [MS-NRPC] --Kostya
            zeroes = '\0' * 4
            SignatureAlgorithm = 0x77 #HMAC-MD5
            SealAlgorithm = 0xffff
            if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                SealAlgorithm = 0x7a #RC4
            NlAuthSignature = pack('<HHHH', SignatureAlgorithm, SealAlgorithm, 0xffff, 0)
            Confounder = '\x01' * 8 #XXX: Not so random, randomize? --Kostya
            CopySeqNumber = pack('>LL', self.ClientSequenceNumber & 0xffffffff, (self.ClientSequenceNumber >> 32) | 0x80000000)
            self.ClientSequenceNumber += 1
            h = MD5.new()
            h.update(zeroes)
            h.update(NlAuthSignature[:8]) #XXX: At this point, it should only be 8 bytes anyway --Kostya
            h.update(Confounder)
            h.update(self.packet.body['data'])
            Checksum = HMAC.new(self.SessionKey, h.digest()).digest()[:8]

            if self.auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                XorKey = ''
                for i in range(len(self.SessionKey)):
                    XorKey += chr(ord(self.SessionKey[i]) ^ 0xf0)
                TmpData = HMAC.new(XorKey, zeroes).digest()
                EncryptionKey = HMAC.new(TmpData, CopySeqNumber).digest()
                Confounder = ARC4.new(EncryptionKey).encrypt(Confounder)
                self.packet.body['data'] = ARC4.new(EncryptionKey).encrypt(self.packet.body['data'])
            TmpData = HMAC.new(self.SessionKey, zeroes).digest()
            EncryptionKey = HMAC.new(TmpData, Checksum).digest()
            SequenceNumber = ARC4.new(EncryptionKey).encrypt(CopySeqNumber)
            NlAuthSignature += SequenceNumber
            NlAuthSignature += Checksum
            NlAuthSignature += Confounder
            auth_verifier['auth_value'] = NlAuthSignature
        else:
            logging.debug('seal_packet: auth_type or auth_level not supported!')
            return

        self.packet.header['auth_length'] = len(auth_verifier['auth_value'])
        self.packet.body['auth_verifier'] = auth_verifier.pack()

    def unseal_packet(self):
        if self.auth_type == RPC_C_AUTHN_NONE:
            #XXX: Nothing to do, returning --Kostya
            return
        elif self.auth_type == RPC_C_AUTHN_WINNT:
            if self.auth_level != RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                return
            auth_verifier = DCERPCAuthVerifier(self.packet.body['auth_verifier'], self.packet.header['auth_length'])
            if auth_verifier['auth_pad_length'] != 0:
                unsealed_data = self.ntlm.UNSEAL(self.packet.body['data'] + auth_verifier['auth_pad'])
                auth_verifier['auth_pad'] = unsealed_data[-auth_verifier['auth_pad_length']:]
                self.packet.body['data'] = unsealed_data[:-auth_verifier['auth_pad_length']]
            else:
                self.packet.body['data'] = self.ntlm.UNSEAL(self.packet.body['data'])
            auth_value = auth_verifier['auth_value']
            #auth_verifier['auth_value'] = pack('<L8sL', 1, '\0' * 8, 0) #not used --Kostya
            self.packet.body['auth_verifier'] = auth_verifier.pack()
            rpc_packet = self.packet.pack()
            server_mac = self.ntlm.MAC(rpc_packet[:-len(auth_verifier['auth_value'])], False) #this is a server MAC, hence the ClientMode = 'False' --Kostya
            if auth_value != server_mac:
                logging.debug('***** INVALID MAC *****')
                logging.debug('unsealed packet: %s' % (rpc_packet.encode('hex')))
                logging.debug('unsealed data: %s' % (self.packet.body['data'].encode('hex')))
                logging.debug('received MAC: %s' % (auth_value.encode('hex')))
                logging.debug('computed MAC: %s' % (server_mac.encode('hex')))
                return
        elif self.auth_type == RPC_C_AUTHN_NETLOGON:
            if self.auth_level != RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                #XXX: We do not check the Checksum, only decrypt the data --Kostya
                return
            if self.packet.header['auth_length'] != 32:
                #XXX: Something is wrong --Kostya
                return
            zeroes = '\0' * 4
            auth_verifier = DCERPCAuthVerifier(self.packet.body['auth_verifier'], self.packet.header['auth_length'])
            NlAuthSignature = auth_verifier['auth_value']
            _, _, _, _, SequenceNumber, Checksum, Confounder = unpack('<HHHH8s8s8s', NlAuthSignature)
            TmpData = HMAC.new(self.SessionKey, zeroes).digest()
            EncryptionKey = HMAC.new(TmpData, Checksum).digest()
            CopySeqNumber = ARC4.new(EncryptionKey).decrypt(SequenceNumber) #XXX: We trust the server information --Kostya
            XorKey = ''
            for i in range(len(self.SessionKey)):
                XorKey += chr(ord(self.SessionKey[i]) ^ 0xf0)
            TmpData = HMAC.new(XorKey, zeroes).digest()
            EncryptionKey = HMAC.new(TmpData, CopySeqNumber).digest()
            Confounder = ARC4.new(EncryptionKey).decrypt(Confounder)
            self.packet.body['data'] = ARC4.new(EncryptionKey).decrypt(self.packet.body['data'])
        else:
            logging.debug('unseal_packet: auth_type or auth_level not supported!')

    def __bind_alter(self, packet_type, uuid, version, auth_type, auth_level, t_uuid=None, t_ver=None):
        """
        """
        if packet_type not in [DCERPC_bind, DCERPC_alter_context]:
            return 0

        (uuid, version) = map(assert_unicode, (uuid, version))
        self.auth_type                  = auth_type
        self.auth_level                 = auth_level
        self.packet                     = DCERPCPacket(packet_type = packet_type)
        self.packet.header['pfc_flags'] = PFC_FIRST_FRAG|PFC_LAST_FRAG
        self.packet.body.add_abstract_syntax(uuid, version, self.cont_id, t_uuid, t_ver)
        self.cont_id += 1

        if auth_type != RPC_C_AUTHN_NONE:
            auth_verifier = DCERPCAuthVerifier()
            self.auth_context_id = random.randint(0x2000, 0xf000) << 4
            auth_verifier['auth_context_id'] = self.auth_context_id
            size = len(self.packet.pack()) % 4
            if size != 0:
                auth_verifier['auth_pad'] = '\0' * (4 - size)
            auth_verifier['auth_type'] = auth_type
            auth_verifier['auth_level'] = auth_level
            if auth_type == RPC_C_AUTHN_WINNT:
                if auth_level == RPC_C_AUTHN_LEVEL_PKT_INTEGRITY:
                    Integrity = True
                    Confidentiality = False
                elif auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY:
                    Integrity = True
                    Confidentiality = True
                else:
                    Integrity = False
                    Confidentiality = False
                self.ntlm = NTLM(self.username, self.password, self.computer, self.domain, Integrity, Confidentiality)
                auth_verifier['auth_value'] = self.ntlm.negotiate()
            elif auth_type == RPC_C_AUTHN_NETLOGON:
                auth_verifier['auth_value'] = pack('<LL', 0, 3) + self.domain.encode('CP850') + '\0' + self.computer.encode('CP850') + '\0' #XXX: As close to OEM encoding --Kostya
            else:
                raise DCERPCException('auth_type not supported!')
            self.packet.header['auth_length'] = len(auth_verifier['auth_value'])
            self.packet.body['auth_verifier'] = auth_verifier.pack()

        data = self.dcerpc_connection.send_recv(self.packet.pack())
        if data == None:
            logging.debug('data=None')
            return 0

        self.packet = DCERPCPacket(data)
        if self.packet.header['PTYPE'] in [DCERPC_bind_ack, DCERPC_alter_context_resp]:
            max_dcefrag = self.packet.body['max_recv_frag'] - (DCERPC_HEADER_SIZE + 8)
            if self.max_dcefrag == 0 or max_dcefrag < self.max_dcefrag:
                self.max_dcefrag = max_dcefrag

            # Check Ack status and abort if rejected
            if self.packet.header['PTYPE'] == DCERPC_bind_ack:
                result = self.packet.body['p_result_list']
                result = unpack('<H', result[4:6])[0]
                if result == 2: # Bind ack provider rejection
                    logging.debug('bind ack provider rejection')
                    return 0

        if self.packet.header['PTYPE'] == DCERPC_bind_nak:
            logging.debug('DCERPC bind nak received, reason: %d' %  self.packet.body['provider_reject_reason'])
            logging.info('BIND nak received, if using dcerpc crypto disable by setting covertness to 1 and try again.')
            return 0

        if auth_type != RPC_C_AUTHN_NONE:
            auth_verifier = DCERPCAuthVerifier(self.packet.body['auth_verifier'], self.packet.header['auth_length'])
            if auth_type == RPC_C_AUTHN_WINNT:
                self.ntlm.challenge(auth_verifier['auth_value'])

                self.packet = DCERPCPacket(packet_type = DCERPC_auth_3)
                self.packet.header['pfc_flags'] = PFC_FIRST_FRAG|PFC_LAST_FRAG
                size = len(self.packet.pack()) % 4
                if size != 0:
                    auth_verifier['auth_pad'] = '\0' * (4 - size)
                auth_verifier['auth_value'] = self.ntlm.authenticate()
                self.packet.header['auth_length'] = len(auth_verifier['auth_value'])
                self.packet.body['auth_verifier'] = auth_verifier.pack()
                data = self.dcerpc_connection.send_recv(self.packet.pack(), response=False)
                # XXX: we need to keep state and check the status on the next command for auth3
                return 1

            elif auth_type == RPC_C_AUTHN_NETLOGON:
                if auth_verifier['auth_value'] != pack('<LLH', 1, 0, 0):
                    return 0
                self.ClientSequenceNumber = 0
        return 1

    def bind(self, uuid, version, auth_type=RPC_C_AUTHN_NONE, auth_level=RPC_C_AUTHN_LEVEL_DEFAULT, t_uuid=None, t_ver=None):
        logging.debug('auth_type=0x%x auth_level=0x%x' % (auth_type, auth_level))
        status = self.dcerpc_connection.connect()
        if status != 0:
            # XXX: This will trigger unhandled exceptions in old code
            raise DCERPCException('Error while connecting to %s:%s' % (self.address, self.endpoint))
            # logging.error("Error while connecting to %s:%s" % (self.address, self.endpoint))
            # return 0
        return self.__bind_alter(DCERPC_bind, uuid, version, auth_type, auth_level, t_uuid, t_ver)

    def alter_context(self, uuid, version, auth_type=RPC_C_AUTHN_NONE, auth_level=RPC_C_AUTHN_LEVEL_DEFAULT):
        self.__bind_alter(DCERPC_alter_context, uuid, version, auth_type, auth_level)
        return 1

    def call(self, opnum, data, response=True):
        frags = []
        size = len(data)

        if 0 in (self.max_dcefrag, size):
            frags.append(data)
        else:
            for i in range(0, size, self.max_dcefrag):
                frags.append(data[i:i + self.max_dcefrag])

        for i in range(len(frags)):
            self.packet = DCERPCPacket(packet_type = DCERPC_request)
            self.packet.body['opnum'] = opnum
            self.packet.body['alloc_hint'] = size
            self.packet.body['data'] = frags[i]
            if not self.cont_id:
                self.packet.body['p_cont_id'] = 0
            else:
                self.packet.body['p_cont_id'] = self.cont_id - 1
            #XXX: We assume the latest is the one we want. Change that later? --Kostya
            #XXX: There is a bug in the last line. If self.cont_id is 0 then self.packet.body['p_cont_id']
            #     holds -1 (int). However the packing assumes a short thus it falls out of range and the code
            #     crashes. This issue may be triggered when unexpected answers occur. I'm currently unable to
            #     design the appropriate fix. -- r.a.

            if i == 0:
                self.packet.header['pfc_flags'] |= PFC_FIRST_FRAG
            if i == (len(frags) - 1):
                self.packet.header['pfc_flags'] |= PFC_LAST_FRAG
            self.seal_packet()
            if i == (len(frags) - 1):
                #Last packets (or single packets) appear to be TRANSACTION ones and not WRITE_ANDX ones
                data = self.dcerpc_connection.send_recv(self.packet.pack(), response, option=OPTION_SMB_TRANSACT)
            else:
                data = self.dcerpc_connection.send_recv(self.packet.pack(), response=False)

            self.reassembled_data = ''
            if data is not None:
                self.packet = DCERPCPacket(data)
                if self.packet.header['PTYPE'] != DCERPC_fault:
                    self.unseal_packet()
                    self.reassembled_data += self.packet.body['data']
                    while (self.packet.header['pfc_flags'] & PFC_LAST_FRAG) == 0:
                        logging.debug('Not the last fragment, calling dcerpc_connection.recv() one more time.')
                        data = self.dcerpc_connection.recv()
                        if data is None:
                            break
                        self.packet = DCERPCPacket(data)
                        self.unseal_packet()
                        self.reassembled_data += self.packet.body['data']
                else:
                    logging.debug('DCERPC Fault, no reassembled data')
        #XXX: Todo --Kostya
        return 1

if __name__ == '__main__':
    pass
