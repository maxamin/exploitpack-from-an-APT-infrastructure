#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  pac.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import struct
import time
import logging
from datetime import datetime

if "." not in sys.path:
    sys.path.append(".")

import helper
from filetimes import filetime_to_dt, dt_to_filetime, utc
from protocol import getIntegerTagSet, getOctetStringTagSet

try:
    from pyasn1.type import univ
    from pyasn1.codec.ber import encoder, decoder
except ImportError:
    logging.error("kerberos.protocol: Cannot import pyasn1 (required)")
    raise

try:
    from Crypto.Hash import MD5
except ImportError:
    logging.error("kerberos.helper: Cannot import Crypto (required)")
    raise

###
# Packing routines
###

def pack_u8(data):
    return helper.pack_u8(data)

def pack_u16(data):
    return helper.pack_u16(data, little_endian=True)

def pack_u32(data):
    return helper.pack_u32(data, little_endian=True)

def pack_u64(data):
    return helper.pack_u64(data, little_endian=True)

def pack_bytes(data):
    return helper.pack_bytes(data)

###
# Mandatory function!
###

def padding(current_size, adjust):
    remaining = current_size%adjust
    return adjust-remaining

###
# All the subclasses
###

# http://msdn.microsoft.com/en-us/library/cc237955.aspx
class PacSignatureDataIB(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __len__(self):
        return len(self.pack())

    def padding(self, out):
        return padding(len(out),8)

    def pack(self, with_padding=0):
        out = ''
        out += pack_u32(self['type'])
        out += pack_bytes(self['data'])
        if with_padding:
            out += '\x00'*self.padding(out)
        return out

# http://msdn.microsoft.com/en-us/library/cc237951.aspx
class PacClientInfoIB(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __len__(self):
        return len(self.pack())

    def padding(self,out):
        return padding(len(out),8)

    def pack(self, with_padding=0):
        out = ''
        out += pack_u64(self['clientID'])
        out += pack_u16(self['nameLength'])
        out += pack_bytes(self['name'])
        if with_padding:
            out += '\x00'*self.padding(out)
        return out

class PacGenericIB(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __len__(self):
        return len(self.pack())

    def padding(self,out):
        return padding(len(out),8)

    def pack(self, with_padding=0):
        out = pack_bytes(self['raw'])
        if with_padding:
            out += '\x00'*self.padding(out)
        return out

class InfoBufferHeader(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def pack(self):
        out = ''
        out += pack_u32(self['type'])
        out += pack_u32(self['size'])
        out += pack_u32(self['offset'])
        out += pack_u32(0)
        return out

# The PacLogonInformationIB class is an adaptation of the public poc proposed by Sylvain Monne
# https://github.com/bidord/pykek

SE_GROUP_MANDATORY = 1
SE_GROUP_ENABLED_BY_DEFAULT = 2
SE_GROUP_ENABLED = 4
SE_GROUP_ALL = SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT | SE_GROUP_ENABLED

USER_NORMAL_ACCOUNT = 0x00000010
USER_DONT_EXPIRE_PASSWORD = 0x00000200

class PacLogonInformationIB(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)
        self.end = []

    def __len__(self):
        return len(self.pack())

    def padding(self,out):
        return padding(len(out),8)

    def _build_unicode_string(self, eid, s):

        data  = pack_u64(len(s))
        data += pack_u32(len(s))
        data += s.encode('utf-16le')
        self.end.append(data)

        begin = ''
        begin += pack_u16(len(s) * 2)
        begin += pack_u16(len(s) * 2)
        begin += pack_u32(eid)
        return begin

    def _build_groups(self, eid, groups):

        data = pack_u32(len(groups))
        for gr, attr in groups:
            data += pack_u32(gr) + pack_u32(attr)
        self.end.append(data)
        begin = pack_u32(eid)
        return begin

    def _build_sid(self, eid, s):

        l = s.split('-')
        assert l[0] == 'S'
        l = [int(c) for c in l[1:]]
        data = ''
        data += pack_u32(len(l) - 2) + pack_u8(l[0]) + pack_u8(len(l) - 2)
        data += helper.pack_u32(l[1] >> 16, little_endian=False)
        data += helper.pack_u16(l[1] & 0xffff, little_endian=False)
        for c in l[2:]:
            data += pack_u32(c)
        self.end.append(data)

        begin = pack_u32(eid)
        return begin

    # Adaptation of _build_pac_logon_info() from Sylvain Monne
    def pack(self, with_padding=0):

        self.end = []
        username = self['user_name']
        domain_name = self['domain_name']
        user_sid = self['user_sid']
        logon_time = self['logon_time']

        dt = datetime.strptime(logon_time,'%Y%m%d%H%M%SZ')
        logon_time = dt_to_filetime(dt)

        domain_sid, user_id = user_sid.rsplit('-', 1)
        user_id = int(user_id)

        out = ''
        # ElementId
        out += pack_u32(0x20000)
        # LogonTime
        out += pack_u64(logon_time)
        # LogoffTime
        out += pack_u64(0x7fffffffffffffff)
        # KickOffTime
        out += pack_u64(0x7fffffffffffffff)
        # PasswordLastSet
        out += pack_u64(0)
        # PasswordCanChange
        out += pack_u64(0)
        # PasswordMustChange
        out += pack_u64(0x7fffffffffffffff)
        # EffectiveName
        out += self._build_unicode_string(0x20004, username)
        # FullName
        out += self._build_unicode_string(0x20008, '')
        # LogonScript
        out += self._build_unicode_string(0x2000c, '')
        # ProfilePath
        out += self._build_unicode_string(0x20010, '')
        # HomeDirectory
        out += self._build_unicode_string(0x20014, '')
        # HomeDirectoryDrive
        out += self._build_unicode_string(0x20018, '')
        # LogonCount
        out += pack_u16(0)
        # BadPasswordCount
        out += pack_u16(0)
        # UserId
        out += pack_u32(user_id)
        # PrimaryGroupId
        out += pack_u32(513)
        # GroupCount
        out += pack_u32(5)
        # GroupIds[0]
        out += self._build_groups(0x2001c, [(513, SE_GROUP_ALL),
                                            (512, SE_GROUP_ALL),
                                            (520, SE_GROUP_ALL),
                                            (518, SE_GROUP_ALL),
                                            (519, SE_GROUP_ALL)])
        # UserFlags
        out += pack_u32(0)
        # UserSessionKey
        out += pack_u64(0) + pack_u64(0)
        # LogonServer
        out += self._build_unicode_string(0x20020, '')
        # LogonDomainName
        out += self._build_unicode_string(0x20024, domain_name)
        # LogonDomainId
        out += self._build_sid(0x20028, domain_sid)
        # Reserved1
        out += pack_u64(0)
        # UserAccountControl
        out += pack_u32(USER_NORMAL_ACCOUNT | USER_DONT_EXPIRE_PASSWORD)
        # SubAuthStatus
        out += pack_u32(0)
        # LastSuccessFulILogon
        out += pack_u64(0)
        # LastFailedILogon
        out += pack_u64(0)
        # FailedILogonCount
        out += pack_u32(0)
        # Reserved3
        out += pack_u32(0)
        # SidCount
        out += pack_u32(0)
        # ExtraSids
        out += pack_u32(0)
        # ResourceGroupDomainSid
        out += pack_u32(0)
        # ResourceGroupCount
        out += pack_u32(0)
        # ResourceGroupIds
        out += pack_u32(0)

        end_str = ''
        for s in self.end:
            end_str += s
            end_str += chr(0) * ((len(s) + 3) / 4 * 4 - len(s))

        out += end_str
        hdr = '\x01\x10\x08\x00\xcc\xcc\xcc\xcc'
        hdr += pack_u32(len(out)) + pack_u32(0)
        out = hdr + out
        if with_padding:
            out += '\x00'*self.padding(out)
        return out

###
# The 'PAC' manipulation subclass
###

class Pac:

    def __init__(self):
        self.original_data = None
        self.seq = {}
        self.data = None
        self.dict = {}
        self.idx = 0
        self.out = ''

        self.type2sig = {
              0x00000001:['CRC32', 4],
              0x00000007:['MD5', 16],
              0x0000000a:['SHA1', 20],
              0x0000000d:['SHA1', 20],
              0xFFFFFF76:['KERB_CHECKSUM_HMAC_MD5', 16],
              0x0000000F:['HMAC_SHA1_96_AES128', 12],
              0x00000010:['HMAC_SHA1_96_AES256', 12] }

        self.type2unpackhandler = {
              6:self.PacSignatureDataIB_unpack,
              7:self.PacSignatureDataIB_unpack,
              10:self.PacClientInfoIB_unpack,
              11:self.PacGenericIB_unpack,
            }

    def __str__(self):
        return repr(self.seq)

    def __len__(self):
        return len(self.original_data)

    # Extraction routines

    def extract_u8(self):
        s = helper.extract_u8(self.data, self.idx)
        self.idx += 1
        return s

    def extract_u16(self):
        s = helper.extract_u16(self.data, self.idx, little_endian=True)
        self.idx += 2
        return s

    def extract_u32(self):
        s = helper.extract_u32(self.data, self.idx, little_endian=True)
        self.idx += 4
        return s

    def extract_u64(self):
        s = helper.extract_u64(self.data, self.idx, little_endian=True)
        self.idx += 8
        return s

    def extract_bytes(self, nbr_bytes):
        s = helper.extract_bytes(self.data, self.idx, nbr_bytes)
        self.idx += nbr_bytes
        return s

    # Unpacking handlers

    def PacSignatureDataIB_unpack(self, pibhr):
        self.set_index(pibhr['offset'])
        SignatureType = self.extract_u32()
        if not self.type2sig.has_key(SignatureType):
            # We need to throw an error because there is no way to know
            # how much to unpack
            logging.error("Signature struct with unknown type [%d]" % SignatureType)
            return None
        sigdesc = self.type2sig[SignatureType][0]
        siglen = self.type2sig[SignatureType][1]
        sigdata = self.extract_bytes(siglen)
        return PacSignatureDataIB({'data':sigdata,
                                   'len':siglen,
                                   'type': SignatureType,
                                   'description':sigdesc})

    def PacClientInfoIB_unpack(self, pibhr):
        self.set_index(pibhr['offset'])
        clientId = self.extract_u64()
        NameLength = self.extract_u16()
        Name = self.extract_bytes(NameLength) #.decode('utf-16le')
        return PacClientInfoIB({'clientID':clientId,
                                'name':Name,
                                'nameLength':NameLength})

    def PacGenericIB_unpack(self, pibhr):
        self.set_index(pibhr['offset'])
        r = self.extract_bytes(pibhr['size'])
        return PacGenericIB({ 'raw':r })

    # Information Buffer: returns the unpacking handler

    def get_info_buffer_unpack_handler(self, pibhr):
        ulType = pibhr['type']
        if self.type2unpackhandler.has_key(ulType):
            return self.type2unpackhandler[ulType]
        else:
            return self.PacGenericIB_unpack

    # unpacking routines

    def unpack_info_buffer_header(self):

        ulType = self.extract_u32()
        cbBufferSize = self.extract_u32()
        Offset1 = self.extract_u32()
        Offset2 = self.extract_u32()
        pibh = { 'type':ulType, 'size':cbBufferSize, 'offset':Offset1 }
        return InfoBufferHeader(pibh)

    def unpack_info_buffer_headers(self):

        pib_array = []
        cbuffers = self.dict['cbuffers']
        if not cbuffers:
            return pib_array

        for cbuff in xrange(cbuffers):
            pib = self.unpack_info_buffer_header()
            pib_array.append(pib)
        return pib_array

    def pack_info_buffer_headers(self):

        for pibh in self.dict['info_buffer_headers']:
            self.out += pibh.pack()

    def unpack(self):

        self.idx = 0
        self.dict = {}

        self.dict['cbuffers'] = self.extract_u32()
        self.dict['version'] = self.extract_u32()
        self.dict['info_buffer_headers'] = self.unpack_info_buffer_headers()

        # Printing each information buffer using specific handlers
        ib = []
        for pibhdr in self.dict['info_buffer_headers']:
            unpack_handler = self.get_info_buffer_unpack_handler(pibhdr)
            ib.append(unpack_handler(pibhdr))
        self.dict['info_buffers'] = ib
        return self.dict

    def __pack(self):

        self.out = ''
        self.out += pack_u32(self.dict['cbuffers'])
        self.out += pack_u32(self.dict['version'])
        self.pack_info_buffer_headers()
        for pib in self.dict['info_buffers']:
            self.out += pib.pack(with_padding=1)

    def pack(self, compute_signatures=1):

        # 1. Pack a first time
        self.__pack()

        if compute_signatures:
            # 2. Do we have signatures?
            sigServer = self.get_signature(6)
            sigKdc = self.get_signature(7)
            if sigServer:
                sigServer['data'] = MD5.new(self.out).digest()
                if sigKdc:
                    sigKdc['data'] = MD5.new(sigServer['data']).digest()
            # 3. Pack again
            self.out = ''
            self.__pack()

        # 4. Let's wrap it in asn1 sequences
        subseq = univ.Sequence()
        subseq.setComponentByPosition(0, univ.Integer(128, tagSet=getIntegerTagSet(0)))
        subseq.setComponentByPosition(1, univ.OctetString(self.out, tagSet=getOctetStringTagSet(1)))
        seq = univ.Sequence()
        seq.setComponentByPosition(0, subseq)
        self.idx = 0
        self.seq = seq
        self.data = str(self.seq[0][1])
        # 5. We can return the packed data
        return str(encoder.encode(self.seq))

    # main functions

    def set_header(self, version=0):
        self.dict['cbuffers'] = 0
        self.dict['version'] = 0
        self.dict['info_buffer_headers'] = []
        self.dict['info_buffers'] = []
        return

    def add_info_buffer(self, type_ib, ib):
        self.dict['info_buffers'].append(ib)
        last_ibh = self.dict['info_buffer_headers'][-1:]
        if not last_ibh:
            ibh = InfoBufferHeader({'type':type_ib, 'size':len(ib), 'offset':72})
        else:
            offset = last_ibh[0]['offset'] + last_ibh[0]['size']
            offset += padding(offset,8)
            ibh = InfoBufferHeader({'type':type_ib, 'size':len(ib), 'offset':offset})
        self.dict['info_buffer_headers'].append(ibh)
        self.dict['cbuffers'] += 1
        return

    def show(self):

        s  = "##### HEADER (version=%d) #######\n" % self.dict['version']
        s += "\t cbuffers = %d\n" % self.dict['cbuffers']
        s += "##### INFO BUFFER HEADERS #######\n"
        for ibh in self.dict['info_buffer_headers']:
            s += "%s\n" % str(ibh)
        s += "##### INFO BUFFER #######\n"
        for ib in self.dict['info_buffers']:
            s += "%s\n" % str(ib)
	logging.info(s)

    # getters/setters

    def set_raw_data(self, data):
        self.idx = 0
        self.original_data = data
        self.seq = decoder.decode(self.original_data)[0]
        self.data = str(self.seq[0][1])
        self.out = ''

    def get_signature(self, sigtype):
        for ib, ibh in zip(self.dict['info_buffers'], self.dict['info_buffer_headers']):
            if ibh['type'] == sigtype:
                return ib
        return None

    def set_index(self,idx):

        if idx > len(self.data):
            logging.error("Invalid index!")
            sys.exit(1)
        self.idx = idx

