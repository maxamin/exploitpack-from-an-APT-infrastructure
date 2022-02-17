#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  librdp.py
## Description:
##            :
## Created_On :  Mon May 20 2019

## Created_By :  X. (adding code from bas/nicop's libs)
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import md5
import sha
import copy
import struct
import socket
import select
import logging
import time

if '.' not in sys.path:
    sys.path.append('.')

from libs.tlslite.api import X509
from Crypto.Util.number import bytes_to_long

from libs.libwinreg.Struct import Struct # TODO
from libs.rdp.asn1 import mcs_ber_parser
from libs.rdp.asn1 import gcc_ber_parser, gcc_per_parser
from libs.rdp.rdpconst import *
import libs.rdp.mcs as mcs
import libs.rdp.gcc as gcc

from exploitutils import randomstring
from libs.Crypto.Util.number import *
from libs.Crypto.PublicKey import *
from libs.Crypto.Cipher.RC4 import *

###
# Globla logging mechanism
###

rdp_debug_level = RDP_LOG_ERROR

def set_debug_level(dbg_lvl):
    global rdp_debug_level
    rdp_debug_level = dbg_lvl

def display_error(msg):
    if rdp_debug_level & RDP_LOG_ERROR:
        logging.error(msg)

def display_warning(msg):
    if rdp_debug_level & RDP_LOG_WARN:
        logging.warning(msg)

def display_info(msg):
    if rdp_debug_level & RDP_LOG_INFO:
        logging.info(msg)

def display_debug(msg):
    if rdp_debug_level & RDP_LOG_DEBUG:
        logging.debug(msg)

###
# TPKT class - T-REC-T.123-200701-I!!PDF-E.pdf (section 8)
#              [ Layer 0 ]
###

class TPKT(Struct):

    st = [
        ['version', 'B', 3 ],
        ['reserved', 'B', 0 ],
        ['length', '>H', 0 ],
    ]

    def __init__(self, length=4):
        Struct.__init__(self)
        self['length'] = length
        self.payload = ''

    def __str__(self):
        return '[ TPKT: len=%d ]' % (self['length'])

    ###
    # Getters/Setters
    ###

    def get_length(self):
        return self['length']

    def set_length(self, length):
        self['length'] = length

    ###
    # Size fixing function
    ###

    def fix_size(self, data):
        self.set_length(len(data) + 4)

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('TPKT.deserialize() failed: %s' % str(e))
            return None


###
# TPDU - T-REC-X.224-199511-I!!PDF-E.pdf
#        [ Layer 1 ]
###

class x224GenericTPDU(Struct):
    """
    Section 13.2 - Abstract description
    """

    st = [
        ['length', 'B', 0 ],
        ['TPDUCode', 'B', 0 ],
    ]

    def __init__(self, length=0, tpdu_code=0):
        Struct.__init__(self)
        self['length'] = length
        self['TPDUCode'] = (tpdu_code << 4)
        self.payload = ''

    def __str__(self):
        return '[ x224 Generic: len=%d, TPDUCode=%d ]' % (self['length'], self['TPDUCode'])

    ###
    # Getters/Setters
    ###

    def get_length(self):
        return self['length']

    def set_length(self, length):
        self['length'] = length

    def get_tpdu_code(self):
        return self['TPDUCode']

    def set_tpdu_code(self, tpdu_code):
        self['TPDUCode'] = (tpdu_code << 4)

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self['TPDUCode'] = (self['TPDUCode'] >> 4)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('x224GenericTPDU.deserialize() failed: %s' % str(e))
            return None


class x224ConnectionReqTPDU(Struct):
    """
    13.3 Connection Request (CR) TPDU
    """

    st = [
        ['length'     , 'B', 7 ],
        ['TPDUCode'   , 'B', (X224_CONNECTION_REQUEST_CODE << 4) ],
        ['DstRef'     , '<H', 0 ],
        ['SrcRef'     , '<H', 0 ],
        ['ClassOption', 'B', 0],
    ]

    def __init__(self):
        Struct.__init__(self)
        self.CR = X224_CONNECTION_REQUEST_CODE
        self.CDT = 0
        self.payload = ''

    def __str__(self):
        return '[ x224 CR: Length=%d, CR=%d, CDT=%d, DstRef=%x, SrcRef=%x, Class=%d ]' % (self['length'],
                                                                                          self.CR,
                                                                                          self.CDT,
                                                                                          self['DstRef'],
                                                                                          self['SrcRef'],
                                                                                          self.get_class())

    ###
    # Getters/Setters
    ###

    def get_class(self):
        return (self['ClassOption'] >> 4)

    def set_class(self, cls):
        a = self['ClassOption'] & 0xf
        a |= (cls << 4)
        self['ClassOption'] = a 

    def get_length(self):
        return self['length']

    def set_length(self, length):
        self['length'] = length

    def calcsize(self):
        return len(self.pack())

    def fix_size(self, data):
        hdr_length = self.calcsize()
        self.set_length(hdr_length -1 + len(data))

    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['TPDUCode'] = (self.CR << 4) | (self.CDT & 0xf)
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.CR  = (self['TPDUCode'] >> 4) & 0xf
            self.CDT = (self['TPDUCode'] >> 0) & 0xf
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('x224ConnectionReqTPDU.deserialize() failed: %s' % str(e))
            return None


class x224ConnectionConfirmTPDU(x224ConnectionReqTPDU):
    """
    13.4 Connection Confirm (CC) TPDU
    """

    def __init__(self, length=0):
        x224ConnectionReqTPDU.__init__(self)
        self['TPDUCode'] = (X224_CONNECTION_REQUEST_CODE << 4)
        self.CC = X224_CONNECTION_CONFIRM_CODE
        self.CDT = 0

    def __str__(self):
        return '[ x224 CF: Length=%d, CC=%d, CDT=%d, DstRef=%x, SrcRef=%x, Class=%d ]' % (self['length'],
                                                                                          self.CC,
                                                                                          self.CDT,
                                                                                          self['DstRef'],
                                                                                          self['SrcRef'],
                                                                                          self.get_class())


    def pack(self):
        self['TPDUCode'] = (self.CC << 4) | (self.CDT & 0xf)
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.CC  = (self['TPDUCode'] >> 4) & 0xf
            self.CDT = (self['TPDUCode'] >> 0) & 0xf
            return self
        except Exception as e:
            display_error('x224ConnectionConfirmTPDU.deserialize() failed: %s' % str(e))
            return None


class x224DisconnectRequestTPDU(x224ConnectionReqTPDU):
    """
    13.5 Disconnect Request (DR) TPDU
    """

    st = [
        ['length'  , 'B',  7 ],
        ['TPDUCode', 'B',  (X224_DISCONNECT_REQUEST_CODE << 4) ],
        ['DstRef'  , '>H', 0 ],
        ['SrcRef'  , '>H', 0 ],
        ['Reason'  , 'B',  0 ],
    ]

    def __init__(self, length=0):
        x224ConnectionReqTPDU.__init__(self)
        self.DR = self['TPDUCode']
        self.payload = ''

    def __str__(self):
        return '[ x224 CF: Length=%d, CC=%d, CDT=%d, DstRef=%x, SrcRef=%x, Reason=%d ]' % (self['length'],
                                                                                           self.DR,
                                                                                           self['DstRef'],
                                                                                           self['SrcRef'],
                                                                                           self['Reason'])
    def pack(self):
        self['TPDUCode'] = self.DR
        data  = Struct.serialize(self)
        return data

    def fix_size(self, data):
        pass

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.DR = self['TPDUCode']
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('x224DisconnectRequestTPDU.deserialize() failed: %s' % str(e))
            return None


class x224DataTPDU(x224ConnectionReqTPDU):
    """
    13.7 Data (DT) TPDU
    """

    st = [
        ['length', 'B', 2 ],
        ['Code',   'B', (X224_DATA_CODE << 4) ],
        ['NrEot',  'B', 0x80 ],
    ]

    def __init__(self, length=0):
        x224ConnectionReqTPDU.__init__(self)
        self.DT = (self['Code'] >> 4)
        self.ROA = (self['Code'] & 1)
        self.NR = 0
        self.EOT = (self['NrEot'] & 0x80) >> 7

    def __str__(self):
        return '[ x224 Data: Length=%d, DT=%d, ROA=%d, NR=%d, EOT=%d ]' % (self['length'],
                                                                         self.DT,
                                                                         self.get_roa(),
                                                                         self.get_nr(),
                                                                         self.get_eot())
    def get_roa(self):
        return self.ROA

    def get_nr(self):
        return 0

    def get_eot(self):
        return self.EOT

    def fix_size(self, data):
        return

    def pack(self):
        self['Code'] = (self.DT << 4) | self.ROA
        self['NrEot'] = (self.EOT << 7)
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.DT = (self['Code'] >> 4)
            self.ROA = (self['Code'] & 1)
            self.NR = 0
            self.EOT = (self['NrEot'] & 0x80) >> 7
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('x224DataTPDU.deserialize() failed: %s' % str(e))
            return None


###
# RDP specification - [MS-RDPBCGR]
#                     [ Layer 2 - Connection Initiation ]
###


class RDPNegReq(Struct):
    """
    2.2.1.1.1 RDP Negotiation Request (RDP_NEG_REQ)
    """

    st = [
        ['type', 'B', TYPE_RDP_NEG_REQ ],
        ['flags', 'B', 0 ],
        ['length', '<H', 8 ],  # Must be 8 according to [MS-RDPBCGR].pdf
        ['requestedProtocols', '<L', 0 ]
    ]

    def __init__(self, flags=0, requestedProtocols=0):
        Struct.__init__(self)
        self['flags'] = flags
        self['requestedProtocols'] = requestedProtocols
        self.payload = ''

    def __str__(self):
        return '[ RDPNegReq: flags=%s, requestedProtocols=0x%x ]' % (self.get_flags_as_string(), self['requestedProtocols'])

    ###
    # Getters/Setters
    ###

    def get_flags_as_string(self):
        L = []
        flg = self['flags']
        if flg & RESTRICTED_ADMIN_MODE_REQUIRED:
            L.append('RESTRICTED_ADMIN_MODE_REQUIRED')
        if flg & REDIRECTED_AUTHENTICATION_MODE_REQUIRED:
            L.append('REDIRECTED_AUTHENTICATION_MODE_REQUIRED')
        if flg & CORRELATION_INFO_PRESENT:
            L.append('CORRELATION_INFO_PRESENT')
        if not L:
            return '0'
        return '|'.join(L)

    def get_flags(self):
        return self['flags']

    def set_flags(self, flags):
        self['flags'] = flags

    def get_payload(self):
        return self.payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('RDPNegReq.deserialize() failed: %s' % str(e))
            return None


class RDPNegResp(Struct):
    """
    2.2.1.2.1 RDP Negotiation Response (RDP_NEG_RSP)
    """

    st = [
        ['type'            , 'B' , TYPE_RDP_NEG_RSP ],
        ['flags'           , 'B' , 0 ],
        ['length'          , '<H', 8 ], # Must be 8 according to [MS-RDPBCGR].pdf
        ['selectedProtocol', '<L', 0 ]
    ]

    def __init__(self, flags=0, selectedProtocol=0):
        Struct.__init__(self)
        self['flags'] = flags
        self['selectedProtocol'] = selectedProtocol

    def __str__(self):
        return '[ RDPNegResp: flags=%s, requestedProtocols=0x%x ]' % (self.get_flags_as_string(),
                                                                       self['selectedProtocol'])

    ###
    # Getters/Setters
    ###

    def get_flags_as_string(self):
        L = []
        flg = self['flags']
        if flg & EXTENDED_CLIENT_DATA_SUPPORTED:
            L.append('EXTENDED_CLIENT_DATA_SUPPORTED')
        if flg & DYNVC_GFX_PROTOCOL_SUPPORTED:
            L.append('DYNVC_GFX_PROTOCOL_SUPPORTED')
        if flg & NEGRSP_FLAG_RESERVED:
            L.append('NEGRSP_FLAG_RESERVED')
        if flg & RESTRICTED_ADMIN_MODE_SUPPORTED:
            L.append('RESTRICTED_ADMIN_MODE_SUPPORTED')
        if flg & REDIRECTED_AUTHENTICATION_MODE_SUPPORTED:
            L.append('REDIRECTED_AUTHENTICATION_MODE_SUPPORTED')
        if not L:
            return '0'
        return '|'.join(L)

    def get_flags(self):
        return self['flags']

    def set_flags(self, flags):
        self['flags'] = flags

    def get_selected_protocol(self):
        return self['selectedProtocol']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('RDPNegResp.deserialize() failed: %s' % str(e))
            return None


class RdpConnectionReq(x224ConnectionReqTPDU):
    """
    2.2.1.1 Client X.224 Connection Request PDU
    """

    def __init__(self, length=0, cookie=None):
        x224ConnectionReqTPDU.__init__(self)
        self.cookie = cookie

    def __str__(self):
        cookie_str = ''
        if self.cookie:
            cookie_str = ', \"%s\"' % self.cookie
        return '[ RdpConnectionReq: Length=%d, CDT=%d, DstRef=%x, SrcRef=%x, Class=%d%s ]' % (self['length'],
                                                                                     self.CDT,
                                                                                     self['DstRef'],
                                                                                     self['SrcRef'],
                                                                                     self['ClassOption'],
                                                                                     cookie_str)

    ###
    # Getters/Setters
    ###

    def get_cookie(self):
        return self.cookie

    def set_cookie(self, cookie):
        self.cookie = cookie

    ###
    # (De)Serialization API
    ###

    def calcsize(self):
        return len(self.pack())

    def pack(self):
        data  = Struct.serialize(self)
        if self.cookie:
            data += self.cookie + '\x0d\x0a'
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = self.calcsize()
            if data[offset:] and len(data[offset:]) > len("Cookie: mstshash="):
                self.cookie = data[offset:offset+data[offset:].find('\x0d\x0a')]
                offset += (len(self.cookie)+2)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('RdpConnectionReq.deserialize() failed: %s' % str(e))
            return None


class RdpConnectionConfirm(x224ConnectionConfirmTPDU):
    """
    2.2.1.2 Server X.224 Connection Confirm PDU
    """

    def __init__(self, length=0):
        x224ConnectionConfirmTPDU.__init__(self)

    def __str__(self):
        return '[ RdpConnectionConfirm: Length=%d, CDT=%d, DstRef=%x, SrcRef=%x, Class=%d ]' % (self['length'],
                                                                                   self.CDT,
                                                                                   self['DstRef'],
                                                                                   self['SrcRef'],
                                                                                   self['ClassOption'])

    ###
    # (De)Serialization API
    ###

    def calcsize(self):
        return len(self.pack())

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('RdpConnectionConfirm.deserialize() failed: %s' % str(e))
            return None


class RdpDisconnectRequest(x224DisconnectRequestTPDU):
    """
    2.2.1.2 Currently unused.
    """

    def __init__(self, length=0):
        x224DisconnectRequestTPDU.__init__(self)

    def __str__(self):
        return '[ RDP DR: Length=%d, CDT=%d, DstRef=%x, SrcRef=%x, Reason=%d ]' % (self['length'],
                                                                                   self.CDT,
                                                                                   self['DstRef'],
                                                                                   self['SrcRef'],
                                                                                   self['Reason'])

    ###
    # (De)Serialization API
    ###

    def calcsize(self):
        return len(self.pack())

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self.calcsize():]
            return self
        except Exception as e:
            display_error('RdpDisconnectRequest.deserialize() failed: %s' % str(e))
            return None


###
# RDP specification - [MS-RDPBCGR]
#                     [ Layer 2 - RDP Security Commencement ]
###


class ChannelDef(Struct):
    """
    2.2.1.3.4.1 Channel Definition Structure (CHANNEL_DEF)
    """

    st = [
        ['name'   , '8s', 'foo' ],
        ['options', '<L', 0 ],
        ]

    def __init__(self, name, options=0):
        Struct.__init__(self)
        if len(name) > 8:
            display_warn('An invalid channel name was provided: %s [%d]! Cut down to 8 bytes!' % (name, len(name)))
            self['name'] = name[:8]
        else:
            self['name'] = name
        self['options'] = options

    def str_pad(self, s, max_sz):
        return s + '\0'*(max_sz - len(s))

    def pack(self):
        self['name'] = self.str_pad(self['name'], 8)
        data  = Struct.serialize(self)
        return data


class ClientDataBlock(Struct):

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.payload = data[self['length']:]
            return self
        except Exception as e:
            display_error('ClientDataBlock.deserialize() failed: %s' % str(e))
            return None


class GenericDataBlock(ClientDataBlock):
    '''
    This block is especially useful to handle blocks for which we don't
    have yet a parser. This allows us to continue without breaking the
    protocole.

    Note: It's supposed to be used as a temporary placeholder, you may
    implement a correct class if it should ever be used.
    '''

    st = [
        ['type'   , '<H', 0],
        ['length' , '<H', 0],
        ['raw'    , '0s', ''],
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data)
        self['raw'] = data

    def __str__(self):
        return '[ GenericDataBlock: type=0x%.4x, Length=%d ]' % (self['type'], self['length'])

    def pack(self):
        data  = Struct.serialize(self)
        data += self['raw']
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self['raw'] = data[:self['length']]
            self.payload = data[self['length']:]
            return self
        except Exception as e:
            display_error('GenericDataBlock.deserialize() failed: %s' % str(e))
            return None


class CSCore(ClientDataBlock):
    """
    2.2.1.3.2 Client Core Data (TS_UD_CS_CORE)
    """

    st = [
        ['type'                  , '<H' , CS_CORE],
        ['length'                , '<H' , 0], # Patched in pack()
        ['version'               , '<L' , RDP_CLT_VER_5_0],
        ['desktopWidth'          , '<H' , 1024],
        ['desktopHeight'         , '<H' , 768],
        ['colorDepth'            , '<H' , RNS_UD_COLOR_8BPP],
        ['SASSequence'           , '<H' , 0xaa03],
        ['keyboardLayout'        , '<L' , 1033],
        ['clientBuild'           , '<L' , 2600],
        ['clientName'            , '32s', '\0'*64],
        ['keyboardType'          , '<L' , KEYBOARD_TYPE_IBM_ENH],
        ['keyboardSubType'       , '<L' , 0],
        ['keyboardFunctionKey'   , '<L' , 12],
        ['imeFileName'           , '64s', '\0'*64],
        ['postBeta2ColorDepth'   , '<H' , RNS_UD_COLOR_8BPP],
        ['clientProductId'       , '<H' , 1],
        ['serialNumber'          , '<L' , 0],
        ['highColorDepth'        , '<H' , HIGH_COLOR_24BPP],
        ['supportedColorDepths'  , '<H' , 7],
        ['earlyCapabilityFlags'  , '<H' , RNS_UD_CS_SUPPORT_ERRINFO_PDU | RNS_UD_CS_SUPPORT_MONITOR_LAYOUT_PDU | RNS_UD_CS_VALID_CONNECTION_TYPE | RNS_UD_CS_SUPPORT_HEARTBEAT_PDU ],
        ['clientDigProductId'    , '64s', '\0'*64],
        ['connectionType'        , 'B'  , CONNECTION_TYPE_LAN],
        ['pad2octets'            , 'B'  , 0],
        ['serverSelectedProtocol', '<L' , 0],
        ['desktopPhysicalWidth'  , '<L' , 0x158],
        ['desktopPhysicalHeight' , '<L' , 0xc1],
        ['desktopOrientation'    , '<H' , 0],
        ['desktopScaleFactor'    , '<L' , 100],
        ['deviceScaleFactor'     , '<L' , 100],
    ]

    def str_pad(self, s, max_sz):
        return s + '\0'*(max_sz - len(s))

    def __init__(self, serverSelectedProtocol=0):
        Struct.__init__(self)
        self['clientName'] = self.str_pad('ImmuDesktop'.encode('utf-16le'), 32)
        self['clientDigProductId'] = self.str_pad('\0'.encode('utf-16le'), 64)
        self['serverSelectedProtocol'] = serverSelectedProtocol

    def __str__(self):
        return '[ CSCore: serverSelectedProtocol=%d ]' % (self['serverSelectedProtocol'])

    def pack(self):
        data  = Struct.serialize(self)
        self['length'] = len(data)
        data  = Struct.serialize(self)
        return data


class CSSecurity(ClientDataBlock):
    """
    2.2.1.3.3 Client Security Data (TS_UD_CS_SEC)
    """

    st = [
        ['type'                , '<H', CS_SECURITY],
        ['length'              , '<H', 12],
        ['encryptionMethods'   , '<L', ENCRYPTION_METHOD_ALL ],
        ['extEncryptionMethods', '<L', 0],
    ]

    def __str__(self):
        return '[ CSSecurity: encryptionMethods=%d, extEncryptionMethods=%d ]' % (self['encryptionMethods'], self['extEncryptionMethods'])


class CSNet(ClientDataBlock):
    """
    2.2.1.3.4 Client Network Data (TS_UD_CS_NET)
    """

    st = [
        ['type'            , '<H', CS_NET],
        ['length'          , '<H', 8],
        ['channelCount'    , '<L', 0],
        ['channelDefArray' , '0s', ''],
    ]

    def __init__(self):
        ClientDataBlock.__init__(self)
        self.__array = []

    def add_channel(self, channel):
        '''
        Add a channel object (ChannelDef or dictionary) in the channelDefArray.
        '''
        if isinstance(channel, ChannelDef):
            self.__array.append(channel)
            self['channelCount'] += 1
        else:
            self.__array.append(ChannelDef(channel[0], channel[1]))
            self['channelCount'] += 1

    def add_channels(self, channels):
        '''
        Similar to add_channel() but handles arrays instead.
        '''
        for c in channels:
            self.add_channel(c)

    def get_channels(self):
        '''
        Return the important information.
        '''
        return self.__array

    def __str__(self):
        return '[ CSNet: channelCount=%d ]' % (self['channelCount'])

    def pack(self):

        self['length'] = 8 + len(self.__array) * 12
        data  = Struct.serialize(self)
        data += ''.join(map(lambda x: x.pack(), self.__array))
        return data


class CSCluster(ClientDataBlock):
    """
    2.2.1.3.5 Client Cluster Data (TS_UD_CS_CLUSTER)
    """

    st = [
        ['type'               , '<H', CS_CLUSTER],
        ['length'             , '<H', 12],
        ['flags'              , '<L', 9],
        ['RedirectedSessionID', '<L', 0],
    ]

    def __str__(self):
        return '[ CSCluster: flags=%x, RedirectedSessionID=%x ]' % (self['flags'], self['RedirectedSessionID'])


class ServerDataBlock(ClientDataBlock):
    pass

class SCCore(ServerDataBlock):
    """
    2.2.1.4.2 Server Core Data (TS_UD_SC_CORE)
    """

    st = [
        ['type'                    , '<H', SC_CORE],
        ['length'                  , '<H', 12],
        ['version'                 , '<L', 0],
        ['clientRequestedProtocols', '<L', 0],
    ]

    def get_protocol(self):
        return self['clientRequestedProtocols']

    def __str__(self):
        return '[ SCCore: RequestedProtocols=%d ]' % (self['clientRequestedProtocols'])


class SCNet(ClientDataBlock):
    """
    2.2.1.4.4 Server Network Data (TS_UD_SC_NET)
    """

    st = [
        ['type'            , '<H', SC_NET],
        ['length'          , '<H', 8],
        ['MCSChannelId'    , '<H', 0],
        ['channelCount'    , '<H', 0],
        ['channelIdArray'  , '0s', ''],
    ]

    def __init__(self):
        ClientDataBlock.__init__(self)
        self.__array = []
        self.payload = ''

    def __str__(self):
        return '[ SCNet: ChannelIds=[ %s ] ]' % (', '.join(map(lambda x: '%d' %x, self.__array)))

    def get_io_channel_id(self):
        '''
        Return the important information.
        '''
        return self['MCSChannelId']

    def get_channel_ids(self):
        '''
        Return the important information.
        '''
        return self.__array

    def pack(self):

        self['length'] = 8 + len(self.__array) * 12
        data  = Struct.serialize(self)
        data += ''.join(map(lambda x: x.pack(), self.__array))
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self.__array = []
            offset = 8
            for c in xrange(self['channelCount']):
                self.__array.append(struct.unpack('<H', data[offset:offset+2])[0])
                offset += 2
            self.payload = data[offset:]
            return self
        except Exception as e:
            display_error('SCNet.deserialize() failed: %s' % str(e))
            return None


class RSAPublicKey(Struct):

    st = [
        ['magic'                , '4s', 'RSA1'],
        ['keylen'               , '<L', 0],
        ['bitlen'               , '<L', 0],
        ['datalen'              , '<L', 0],
        ['pubExp'               , '<L', 0],
        ['modulus'              , '0s', ''],
    ]

    def __init__(self, data = None):
        Struct.__init__(self, data)

        if data is not None:
            pos = 20
            n = data[pos:pos+self['keylen']]
            n = n[::-1]
            self['modulus'] = bytes_to_long(n)


class MSCCertificate(Struct):

    def pub_key(self):
        return (self['PublicKeyBlob']['pubExp'], self['PublicKeyBlob']['modulus'])


class ProprietaryServerCertificate(MSCCertificate):

    st = [
        ['dwVersion'            , '<L', 0],
        ['dwSigAlgId'           , '<L', 0],
        ['dwKeyAlgId'           , '<L', 0],
        ['wPublicKeyBlobType'   , '<H', 0],
        ['wPublicKeyBlobLen'    , '<H', 0],
        ['PublicKeyBlob'        , '0s', ''],
        ['wSignatureBlobType'   , '<H', 0],
        ['wSignatureBlobLen'    , '<H', 0],
        ['SignatureBlob'        , '0s', 0],
    ]

    def deserialize(self, data):

        self.unpack(data)
        self['dwVersion'] = self['dwVersion'] & 0x7FFFFFFF
        pos = 16
        pub = data[pos:pos+self['wPublicKeyBlobLen']]
        self['PublicKeyBlob'] = RSAPublicKey(pub)
        pos += self['wPublicKeyBlobLen']
        if len(data) > pos:
            self['wSignatureBlobType'] = struct.unpack('<H', data[pos:pos+2])[0]
            self['wSignatureBlobLen'] = struct.unpack('<H', data[pos+2:pos+4])[0]
            pos += 4
            self['SignatureBlob'] = data[pos:pos+self['wSignatureBlobLen']]


class X509ServerCertificate(MSCCertificate):

    st = [
        ['dwVersion'            , '<L', 0],
        ['dwCertNum'            , '<L', 0],
        ['PublicKeyBlob'        , '0s', ''],
    ]

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):

        self.unpack(data)
        self['dwVersion'] = self['dwVersion'] & 0x7FFFFFFF
        pos = 8
        clen = 0

        # Server certificate (last in the chain)
        for i in range(0, self['dwCertNum']):
            pos = pos + clen
            clen = struct.unpack('<L', data[pos:pos+4])[0]
            pos = pos + 4

        x509 = X509()
        x509.parseBinary(data[pos:pos+clen])

        key = {}
        key['pubExp'] = x509.publicKey.e
        key['modulus'] = x509.publicKey.n
        self['PublicKeyBlob'] = key


class SCSecurity(Struct):
    """
    2.2.1.4.3 Server Security Data (TS_UD_SC_SEC1)
    """

    st = [
        ['type'                 , '<H', SC_SECURITY],
        ['length'               , '<H', 0],
        ['encryptionMethod'     , '<L', 0],
        ['encryptionLevel'      , '<L', 0],
        ['serverRandomLen'      , '<L', 0],
        ['serverCertLen'        , '<L', 0],
        ['serverRandom'         , '0s', ''],
        ['serverCertificate'    , '0s', ''],
    ]

    def __init__(self):
        Struct.__init__(self)
        self.__random = ''
        self.__srv_certificate = ''
        self.payload = ''

    def __str__(self):
        cert = self.__srv_certificate
        if cert:
            pub_key = cert.pub_key()
            cert_str = ', e=%d, n=%d' % (pub_key[0], pub_key[1])
        else:
            cert_str = ''
        return '[ SCSecurity: encryptionMethod=%d, encryptionLevel=%d%s ]' % (self['encryptionMethod'], self['encryptionLevel'], cert_str)

    def get_random(self):
        return self['serverRandom']

    def get_certificate(self):
        return self['serverCertificate']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        """
        Currently left unimplemented.
        """
        raise RuntimeError("Must be implemented!")

    def deserialize(self, data):
        try:
            # Note: We cannot use unpack() because sometimes (with TLS for example)
            # the server does not return serverRandomLen nor serverCertLen.
            pos = 0
            self['type'] = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            self['length'] = struct.unpack('<H', data[pos:pos+2])[0]
            pos += 2
            self['encryptionMethod'] = struct.unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['encryptionLevel'] = struct.unpack('<L', data[pos:pos+4])[0]
            pos += 4

            self['serverRandomLen'] = 0
            self['serverCertLen'] = 0
            self['serverRandom'] = ''
            self['serverCertificate'] = ''

            if len(data[pos:]) < 4:
                display_debug('SCSecurity.deserialize(): no cert nor random values')
                return self

            # From this point on, if there is an exception, we do not handle it
            self['serverRandomLen'] = struct.unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['serverCertLen'] = struct.unpack('<L', data[pos:pos+4])[0]
            pos += 4

            if self['serverRandomLen']:
                self.__random = data[pos:pos+self['serverRandomLen']]
                pos += self['serverRandomLen']
            if self['serverCertLen'] > 0:
                raw_certificate = data[pos:pos+self['serverCertLen']]
                dwVersion = struct.unpack('<L', raw_certificate[0:4])[0] & 0x7FFFFFF
                if dwVersion == CERT_CHAIN_VERSION_1:
                    self.__srv_certificate = ProprietaryServerCertificate()
                    self.__srv_certificate.deserialize(raw_certificate)
                else:
                    self.__srv_certificate = X509ServerCertificate()
                    self.__srv_certificate.deserialize(raw_certificate)
                pos += self['serverCertLen']
            self['serverRandom'] = self.__random
            self['serverCertificate'] = self.__srv_certificate
            self.payload = data[pos:]
            return self

        except Exception as e:
            display_error('SCSecurity.deserialize() failed: %s' % str(e))
            return None

    def get_random(self):
        return self.__random

    def get_srv_certificate(self):
        return self.__srv_certificate


class SecurityExchangePDUData(Struct):

    st = [
        ['basicSecurityHeader'  , '<L', SEC_EXCHANGE_PKT],
        ['length'               , '<L', 0],
        ['encryptedClientRandom', '0s', ''],
    ]

    def __str__(self):
        return '[ RDP SecurityExchangePDUData: flags=0x%x, length=%d, encryptedClientRandom=%s... ]' % (self['basicSecurityHeader'],
                                                                                                      self['length'],
                                                                                                      self['encryptedClientRandom'].encode('hex')[:16])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['length'] = len(self['encryptedClientRandom'])
        data  = Struct.serialize(self)
        data += self['encryptedClientRandom']
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            pos = 8
            self['encryptedClientRandom'] = data[pos:]
            return self
        except Exception as e:
            display_error('SecurityExchangePDUData.deserialize() failed: %s' % str(e))
            return None

###
# RDP specification - [MS-RDPBCGR]
#                     [ Layer 2 - Secure Settings Exchange ]
###


class InfoPacket(Struct):
    """
    2.2.1.11.1.1 Info Packet (TS_INFO_PACKET)
    """

    st = [
        ['CodePage'        , '<L', 0],
        ['flags'           , '<L', 0],
        ['cbDomain'        , '<H', 0],
        ['cbUserName'      , '<H', 0],
        ['cbPassword'      , '<H', 0],
        ['cbAlternateShell', '<H', 0],
        ['cbWorkingDir'    , '<H', 0],
        ['Domain'          , '0s', ''],
        ['UserName'        , '0s', ''],
        ['Password'        , '0s', ''],
        ['AlternateShell'  , '0s', ''],
        ['WorkingDir'      , '0s', ''],
    ]

    def __init__(self, username='', password='', domain=''):
        Struct.__init__(self)
        if username:
            self['UserName'] = username
        if password:
            self['Password'] = password
        if domain:
            self['Domain'] = domain
        self.ExtraInfo  = '02001c003100390032002e00310036003800'
        self.ExtraInfo += '2e0031002e0032003000380000003c004300'
        self.ExtraInfo += '3a005c00570049004e004e0054005c005300'
        self.ExtraInfo += '79007300740065006d00330032005c006d00'
        self.ExtraInfo += '7300740073006300610078002e0064006c00'
        self.ExtraInfo += '6c000000a40100004700540042002c002000'
        self.ExtraInfo += '6e006f0072006d0061006c00740069006400'
        self.ExtraInfo += '000000000000000000000000000000000000'
        self.ExtraInfo += '000000000000000000000000000000000000'
        self.ExtraInfo += '00000a000000050003000000000000000000'
        self.ExtraInfo += '00004700540042002c00200073006f006d00'
        self.ExtraInfo += '6d0061007200740069006400000000000000'
        self.ExtraInfo += '000000000000000000000000000000000000'
        self.ExtraInfo += '000000000000000000000000000003000000'
        self.ExtraInfo += '05000200000000000000c4ffffff00000000'
        self.ExtraInfo += '270000000000'
        self.ExtraInfo = self.ExtraInfo.decode('hex')

    def __str__(self):
        return '[ InfoPacket: Domain=%s, UserName=%s, Password=%s, AlternateShell=%s, WorkingDir=%s, ExtraInfo=%s ]' % (self['Domain'],
                                                                                                                         self['UserName'],
                                                                                                                         self['Password'],
                                                                                                                         self['AlternateShell'],
                                                                                                                         self['WorkingDir'],
                                                                                                                         self.ExtraInfo.encode('hex'))

    ###
    # (De)Serialization API
    ###

    def pack(self):

        self['Domain'] = self['Domain'].encode('utf-16le') + '\0\0'
        self['cbDomain'] = len(self['Domain']) - 2

        self['UserName'] = self['UserName'].encode('utf-16le') + '\0\0'
        self['cbUserName'] = len(self['UserName']) - 2

        self['Password'] = self['Password'].encode('utf-16le') + '\0\0'
        self['cbPassword'] = len(self['Password']) - 2

        self['AlternateShell'] = self['AlternateShell'].encode('utf-16le') + '\0\0'
        self['cbAlternateShell'] = len(self['AlternateShell']) - 2

        self['WorkingDir'] = self['WorkingDir'].encode('utf-16le') + '\0\0'
        self['cbWorkingDir'] = len(self['WorkingDir']) - 2

        data = Struct.serialize(self)
        data += self['Domain']
        data += self['UserName']
        data += self['Password']
        data += self['AlternateShell']
        data += self['WorkingDir']
        
        # For now we reuse FreeRDP's ExtraInfo
        data += self.ExtraInfo
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = self.calcsize()
            self['Domain'] = data[offset:offset+2+self['cbDomain']]
            offset += 2+self['cbDomain']
            self['UserName'] = data[offset:offset+2+self['cbUserName']]
            offset += 2+self['cbUserName']
            self['Password'] = data[offset:offset+2+self['cbPassword']]
            offset += 2+self['cbPassword']
            self['AlternateShell'] = data[offset:offset+2+self['cbAlternateShell']]
            offset += 2+self['cbAlternateShell']
            self['WorkingDir'] = data[offset:offset+2+self['cbWorkingDir']]
            offset += 2+self['cbWorkingDir']
            return self
        except Exception as e:
            display_error('InfoPacket.deserialize() failede: %s' % str(e))
            return None


class BasicSecurityHeader(Struct):
    """
    2.2.8.1.1.2.1 Basic (TS_SECURITY_HEADER)
    """
    st = [
        ['flags', '<L', 0],
    ]

    def __init__(self, flags=0):
        Struct.__init__(self)
        if flags:
            self['flags'] = flags

    def __str__(self):
        return '[ BasicSecurityHeader: flags=%x ]' % (self['flags'])


class NonFipsSecurityHeader(Struct):
    """
    2.2.8.1.1.2.2 Non-FIPS (TS_SECURITY_HEADER1)
    """
    st = [
        ['flags'    , '<L', 0],
        ['signature', '8s', '\0'*8 ],
    ]

    def __init__(self, flags=0, signature=None):
        Struct.__init__(self)
        if flags:
            self['flags'] = flags
        if signature:
            self['signature'] = signature

    def __str__(self):
        return '[ NonFipsSecurityHeader: flags=%x, signature=%s ]' % (self['flags'], self['signature'].encode('hex'))


class ValidClientLicenseData(Struct):
    """
    2.2.1.12.1 Valid Client License Data (LICENSE_VALID_CLIENT_DATA)
    +
    2.2.1.12.1.1 Licensing Preamble (LICENSE_PREAMBLE)
    """
    st = [
        ['bMsgType'                 , '<B', 0],
        ['bVersion'                 , '<B', 0],
        ['wMsgSize'                 , '<H', 0],
        ['validClientMessage'       , '0s', ''],
    ]

    def __str__(self):
        return '[ ValidClientLicenseData: bMsgType=%d, bVersion=%d ]' % (self['bMsgType'],
                                                                          self['bVersion'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        if self['wMsgSize'] == 0:
            self['wMsgSize'] = len(self['data'])
        data = Struct.pack(self)

        return data + self['validClientMessage']

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = self.calcsize()
            self['validClientMessage'] = data[offset:]
            return self
        except Exception as e:
            display_error('ValidClientLicenseData.deserialize() failed: %s' % str(e))
            return None


###
# RDP specification - [MS-RDPBCGR]
#                     [ Layer 2 - Connection Finalization ]
###


class shareControlHeader(Struct):
    """
    2.2.8.1.1.1.1 Share Control Header (TS_SHARECONTROLHEADER)
    """

    st = [
        ['totalLength', '<H', 0],
        ['pduType'    , '<H', (TS_PROTOCOL_VERSION << 4) | PDUTYPE_CONFIRMACTIVEPDU],
        ['pduSource'  , '<H', 0],
    ]

    def __init__(self, t, s, v=TS_PROTOCOL_VERSION):
        Struct.__init__(self)
        self['pduType'] = (v << 4) | (t & 0xf)
        self['pduSource'] = s

    def __str__(self):
        return '[ shareControlHeader: totalLength=%d, pduType=%d, pduSource=%d ]' % (self['totalLength'], self['pduType'] & 0xf, self['pduSource'])

    def get_pdutype(self):
        return self['pduType'] & 0xf

    def get_pduversion(self):
        return (self['pduType'] >> 4)

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            self.unpack(data)
            return self
        except Exception as e:
            display_error('shareControlHeader.deserialize() failed: %s' % str(e))
            return None


class ShareDataHeader(Struct):
    """
    2.2.8.1.1.1.2 Share Data Header (TS_SHAREDATAHEADER)
    """

    st = [
        ['shareControlHeader' , '0s', ''],
        ['shareId'            , '<L', 0],
        ['pad1'               , '<B', 0],
        ['streamId'           , '<B', STREAM_UNDEFINED],
        ['uncompressedLength' , '<H', 0],
        ['pduType2'           , '<B', 0],
        ['compressedType'     , '<B', 0],
        ['compressedLength'   , '<H', 0],
    ]

    def __str__(self):
        return '[ ShareDataHeader: %s uncompressedLength=%d, pduType2=%d, compressedLength=%d ]' % (str(self['shareControlHeader']),
                                                                                                     self['uncompressedLength'],
                                                                                                     self['pduType2'],
                                                                                                     self['compressedLength'])

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        data  = self['shareControlHeader'].pack()
        data += struct.pack('<L', self['shareId'])
        data += '\0'
        data += struct.pack('<B', self['streamId'])
        data += struct.pack('<H', self['uncompressedLength'])
        data += struct.pack('<B', self['pduType2'])
        data += struct.pack('<B', self['compressedType'])
        data += struct.pack('<H', self['compressedLength'])
        return data

    def deserialize(self, data):
        try:
            hdr = shareControlHeader(0,0)
            self['shareControlHeader'] = hdr.deserialize(data)
            offset = 6
            self['shareId'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self['pad1'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self['streamId'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self['uncompressedLength'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['pduType2'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self['compressedType'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self['compressedLength'] = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('ShareDataHeader.deserialize() failed: %s' % str(e))
            return None

# Generic type
class CapabilitySet(Struct):
    """
    2.2.1.13.1.1.1 Capability Set (TS_CAPS_SET)
    """

    st = [
        ['capabilitySetType'   , '<H', 0],
        ['lengthCapability'    , '<H', 0],
        ['capabilityData'      , '0s', ''],
    ]

    def __init__(self, t=99, data=''):
        Struct.__init__(self)
        self['capabilitySetType'] = t
        self['capabilityData'] = data
        self['lengthCapability'] = 4 + len(data)

    def __str__(self):
        s  = '[ CapabilitySet: capabilitySetType=%x, raw=%s ]'
        return s % (self['capabilitySetType'], self['capabilityData'].encode('hex'))

    def __len__(self):
        return self['lengthCapability']

    ###
    # getters/setters API
    ###

    def get_type(self):
        return self['capabilitySetType']

    def get_payload(self):
        return self['capabilityData']

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self['capabilityData']
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self['capabilityData'] = data[offset:offset+self['lengthCapability' ]-4]
            return self
        except Exception as e:
            display_error('CapabilitySet.deserialize() failed: %s' % str(e))
            return None


class GeneralCapabilitySet(CapabilitySet):
    """
    2.2.7.1.1 General Capability Set (TS_GENERAL_CAPABILITYSET)
    """

    def __init__(self, extraFlags=NO_BITMAP_COMPRESSION_HDR | LONG_CREDENTIALS_SUPPORTED | ENC_SALTED_CHECKSUM):
        CapabilitySet.__init__(self, CAPSTYPE_GENERAL)
        self.osMajorType = OSMAJORTYPE_UNIX
        self.osMinorType = OSMINORTYPE_NATIVE_XSERVER
        self.protocolVersion = TS_CAPS_PROTOCOLVERSION
        self.generalCompressionTypes = 0
        self.extraFlags = extraFlags # | FASTPATH_OUTPUT_SUPPORTED
        self.updateCapabilityFlag = 0
        self.remoteUnshareFlag = 0
        self.generalCompressionLevel = 0
        self.refreshRectSupport = True
        self.suppressOutputSupport = True

    def __str__(self):
        s  = '[ GeneralCapabilitySet: osMajorType=0x%x, osMinorType=0x%x, extraFlags=0x%x ]'
        return s % (self.osMajorType, self.osMinorType, self.extraFlags)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 24
        self['capabilityData']  = struct.pack('<H', self.osMajorType)
        self['capabilityData'] += struct.pack('<H', self.osMinorType)
        self['capabilityData'] += struct.pack('<H', self.protocolVersion)
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += struct.pack('<H', self.generalCompressionTypes)
        self['capabilityData'] += struct.pack('<H', self.extraFlags)
        self['capabilityData'] += struct.pack('<H', self.updateCapabilityFlag)
        self['capabilityData'] += struct.pack('<H', self.remoteUnshareFlag)
        self['capabilityData'] += struct.pack('<H', self.generalCompressionLevel)
        self['capabilityData'] += struct.pack('<B', self.refreshRectSupport)
        self['capabilityData'] += struct.pack('<B', self.suppressOutputSupport)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.osMajorType = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.osMinorType = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.protocolVersion = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 4
            self.generalCompressionTypes = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.extraFlags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.updateCapabilityFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.remoteUnshareFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.generalCompressionLevel = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.refreshRectSupport = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.suppressOutputSupport = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('GeneralCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class BitmapCapabilitySet(CapabilitySet):
    """
    2.2.7.1.2 Bitmap Capability Set (TS_BITMAP_CAPABILITYSET)
    """

    def __init__(self):
        CapabilitySet.__init__(self, CAPSTYPE_BITMAP)
        self['lengthCapability'] = 28
        self.preferredBitsPerPixel = 0x10
        self.receive1BitPerPixel = True
        self.receive4BitsPerPixel = True
        self.receive8BitsPerPixel = True
        self.desktopWidth = 1024
        self.desktopHeight = 768
        self.desktopResizeFlag = True
        self.bitmapCompressionFlag = True
        self.highColorFlags = 0
        self.drawingFlags = DRAW_ALLOW_SKIP_ALPHA
        self.multipleRectangleSupport = True


    def __str__(self):
        s  = '[ BitmapCapabilitySet: desktopWidth=0x%x, desktopHeight=0x%x, drawingFlags=0x%x ]'
        return s % (self.desktopWidth, self.desktopHeight, self.drawingFlags)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 28
        self['capabilityData']  = struct.pack('<H', self.preferredBitsPerPixel)
        self['capabilityData'] += struct.pack('<H', self.receive1BitPerPixel)
        self['capabilityData'] += struct.pack('<H', self.receive4BitsPerPixel)
        self['capabilityData'] += struct.pack('<H', self.receive8BitsPerPixel)
        self['capabilityData'] += struct.pack('<H', self.desktopWidth)
        self['capabilityData'] += struct.pack('<H', self.desktopHeight)
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += struct.pack('<H', self.desktopResizeFlag)
        self['capabilityData'] += struct.pack('<H', self.bitmapCompressionFlag)
        self['capabilityData'] += struct.pack('<B', self.highColorFlags)
        self['capabilityData'] += struct.pack('<B', self.drawingFlags)
        self['capabilityData'] += struct.pack('<H', self.multipleRectangleSupport)
        self['capabilityData'] += '\0\0'
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.preferredBitsPerPixel = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.receive1BitPerPixel = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.receive4BitsPerPixel = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.receive8BitsPerPixel = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.desktopWidth = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.desktopHeight = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            offset += 2
            self.desktopResizeFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.bitmapCompressionFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.highColorFlags = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self.drawingFlags = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self.multipleRectangleSupport = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('BitmapCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class OrderCapabilitySet(CapabilitySet):
    """
    2.2.7.1.3 Order Capability Set (TS_ORDER_CAPABILITYSET)
    """

    def __init__(self):
        CapabilitySet.__init__(self, CAPSTYPE_ORDER)
        self.terminalDescriptor = '\0'*16
        self.desktopSaveXGranularity = 1
        self.desktopSaveYGranularity = 20
        self.maximumOrderLevel = ORD_LEVEL_1_ORDERS
        self.numberFonts = 0
        self.orderFlags = NEGOTIATEORDERSUPPORT | ZEROBOUNDSDELTASSUPPORT | COLORINDEXSUPPORT | ORDERFLAGS_EXTRA_FLAGS
        self.orderSupport  = [ TS_NEG_PATBLT_INDEX for i in xrange(3) ]
        self.orderSupport += [ TS_NEG_DSTBLT_INDEX for i in xrange(5) ]
        self.orderSupport += [ TS_NEG_PATBLT_INDEX for i in xrange(1) ]
        self.orderSupport += [ TS_NEG_DSTBLT_INDEX for i in xrange(9) ]
        self.orderSupport += [ TS_NEG_PATBLT_INDEX for i in xrange(1) ]
        self.orderSupport += [ TS_NEG_DSTBLT_INDEX for i in xrange(3) ]
        self.orderSupport += [ TS_NEG_PATBLT_INDEX for i in xrange(1) ]
        self.orderSupport += [ TS_NEG_DSTBLT_INDEX for i in xrange(9) ]
        self.textFlags = 0
        self.orderSupportExFlags = ORDERFLAGS_EX_ALTSEC_FRAME_MARKER_SUPPORT
        self.desktopSaveSize = 230400 # 230400 bytes (480 * 480)
        self.textANSICodePage = 65001 # utf-8 Unicode (UTF-8)

    def __str__(self):
        s  = '[ OrderCapabilitySet: orderFlags=0x%x, textFlags=0x%x, orderSupportExFlags=0x%x ]'
        return s % (self.orderFlags, self.textFlags, self.orderSupportExFlags)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 88
        self['capabilityData']  = self.terminalDescriptor
        self['capabilityData'] += '\0\0\0\0'
        self['capabilityData'] += struct.pack('<H', self.desktopSaveXGranularity)
        self['capabilityData'] += struct.pack('<H', self.desktopSaveYGranularity)
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += struct.pack('<H', self.maximumOrderLevel)
        self['capabilityData'] += struct.pack('<H', self.numberFonts)
        self['capabilityData'] += struct.pack('<H', self.orderFlags)
        self['capabilityData'] += ''.join(map(lambda x: struct.pack('<B',x), self.orderSupport))
        self['capabilityData'] += struct.pack('<H', self.textFlags)
        self['capabilityData'] += struct.pack('<H', self.orderSupportExFlags)
        self['capabilityData'] += '\0\0\0\0'
        self['capabilityData'] += struct.pack('<L', self.desktopSaveSize)
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += struct.pack('<H', self.textANSICodePage)
        self['capabilityData'] += '\0\0'
        data  = CapabilitySet.pack(self)
        return data


class PointerCapabilitySet(CapabilitySet):
    """
    2.2.7.1.5 Pointer Capability Set (TS_POINTER_CAPABILITYSET)
    """

    def __init__(self, colorPointerFlag=True, colorPointerCacheSize=0, pointerCacheSize=0):
        CapabilitySet.__init__(self, CAPSTYPE_POINTER)
        self.colorPointerFlag = colorPointerFlag
        self.colorPointerCacheSize = colorPointerCacheSize
        self.pointerCacheSize = pointerCacheSize

    def __str__(self):
        s  = '[ PointerCapabilitySet: colorPointerFlag=0x%x, colorPointerCacheSize=0x%x, pointerCacheSize=0x%x ]'
        return s % (self.colorPointerFlag, self.colorPointerCacheSize, self.pointerCacheSize)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 10
        self['capabilityData']  = struct.pack('<H', self.colorPointerFlag)
        self['capabilityData'] += struct.pack('<H', self.colorPointerCacheSize)
        self['capabilityData'] += struct.pack('<H', self.pointerCacheSize)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.colorPointerFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.colorPointerCacheSize = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.pointerCacheSize = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            return self
        except Exception as e:
            display_error('InputCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class InputCapabilitySet(CapabilitySet):
    """
    2.2.7.1.6 Input Capability Set (TS_INPUT_CAPABILITYSET)
    """

    def __init__(self, inputFlags=0):
        CapabilitySet.__init__(self, CAPSTYPE_INPUT)
        self.inputFlags = inputFlags
        self.keyboardLayout = 1033                   # "US" keyboard layout
        self.keyboardType = KEYBOARD_TYPE_IBM_ENH
        self.keyboardSubType = 0
        self.keyboardFunctionKey = 12
        self.imeFileName = '\0'*64

    def __str__(self):
        s  = '[ InputCapabilitySet: inputFlags=0x%x, keyboardLayout=0x%x, keyboardType=%d ]'
        return s % (self.inputFlags, self.keyboardLayout, self.keyboardType)

    ###
    # getters/setters API
    ###

    def get_flags(self):
        return self.inputFlags

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 88
        self['capabilityData']  = struct.pack('<H', self.inputFlags)
        self['capabilityData'] += '\0\0'
        self['capabilityData'] += struct.pack('<L', self.keyboardLayout)
        self['capabilityData'] += struct.pack('<L', self.keyboardType)
        self['capabilityData'] += struct.pack('<L', self.keyboardSubType)
        self['capabilityData'] += struct.pack('<L', self.keyboardFunctionKey)
        self['capabilityData'] += self.imeFileName
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.inputFlags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            offset += 2 # padding
            self.keyboardLayout = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.keyboardType = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.keyboardSubType = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.keyboardFunctionKey = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.imeFileName = data[offset:offset+64]
            return self
        except Exception as e:
            display_error('InputCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class BrushCapabilitySet(CapabilitySet):
    """
    2.2.7.1.7 Brush Capability Set (TS_BRUSH_CAPABILITYSET)
    """

    def __init__(self, brushSupportLevel=0):
        CapabilitySet.__init__(self, CAPSTYPE_BRUSH)
        self.brushSupportLevel = brushSupportLevel

    def __str__(self):
        s  = '[ BrushCapabilitySet: brushSupportLevel=0x%x ]'
        return s % (self.brushSupportLevel)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 8
        self['capabilityData']  = struct.pack('<L', self.brushSupportLevel)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.brushSupportLevel = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            return self
        except Exception as e:
            display_error('BrushCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class VirtualChannelCapabilitySet(CapabilitySet):
    """
    2.2.7.1.10 Virtual Channel Capability Set (TS_VIRTUALCHANNEL_CAPABILITYSET)
    """

    def __init__(self, flags=0, VCChunkSize=0):
        CapabilitySet.__init__(self, CAPSTYPE_VIRTUALCHANNEL)
        self.flags = flags
        self.VCChunkSize = VCChunkSize # greater than or equal to CHANNEL_CHUNK_LENGTH
                                       # and less than or equal to 16256.

    def __str__(self):
        s  = '[ VirtualChannelCapabilitySet: flags=0x%x, VCChunkSize=0x%x ]'
        return s % (self.flags, self.VCChunkSize)

    ###
    # getters/setters API
    ###

    def get_chunksize(self):
        return self.VCChunkSize

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 12
        self['capabilityData']  = struct.pack('<L', self.flags)
        self['capabilityData'] += struct.pack('<L', self.VCChunkSize)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.flags = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.VCChunkSize = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            return self
        except Exception as e:
            display_error('VirtualChannelCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class SoundCapabilitySet(CapabilitySet):
    """
    2.2.7.1.11 Sound Capability Set (TS_SOUND_CAPABILITYSET)
    """

    def __init__(self, soundFlags=0):
        CapabilitySet.__init__(self, CAPSTYPE_SOUND)
        self.soundFlags = soundFlags

    def __str__(self):
        s  = '[ SoundCapabilitySet: soundFlags=0x%x ]'
        return s % (self.soundFlags)

    ###
    # getters/setters API
    ###

    def get_flags(self):
        return self.soundFlags

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 8
        self['capabilityData']  = struct.pack('<H', self.soundFlags)
        self['capabilityData'] += '\0\0' # padding
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.soundFlags = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('SoundCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class ControlCapabilitySet(CapabilitySet):
    """
    2.2.7.2.2 Control Capability Set (TS_CONTROL_CAPABILITYSET)
    """

    def __init__(self, controlFlags=0, remoteDetachFlag=False, controlInterest=CONTROLPRIORITY_NEVER, detachInterest=CONTROLPRIORITY_NEVER):
        CapabilitySet.__init__(self, CAPSTYPE_CONTROL)
        self.controlFlags = controlFlags
        self.remoteDetachFlag = remoteDetachFlag
        self.controlInterest = controlInterest
        self.detachInterest = detachInterest

    def __str__(self):
        s  = '[ ControlCapabilitySet: controlFlags=0x%x, remoteDetachFlag=0x%x, controlInterest=0x%x, detachInterest=0x%x ]'
        return s % (self.controlFlags, self.remoteDetachFlag, self.controlInterest, self.detachInterest)

    ###
    # getters/setters API
    ###

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 12
        self['capabilityData']  = struct.pack('<H', self.controlFlags)
        self['capabilityData'] += struct.pack('<H', self.remoteDetachFlag)
        self['capabilityData'] += struct.pack('<H', self.controlInterest)
        self['capabilityData'] += struct.pack('<H', self.detachInterest)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.controlFlags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.remoteDetachFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.controlInterest = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.detachInterest = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('SoundCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class WindowActivationCapabilitySet(CapabilitySet):
    """
    2.2.7.2.3 Window Activation Capability Set
    """

    def __init__(self, helpKeyFlag=False, helpKeyIndexFlag=False, helpExtendedKeyFlag=False, windowManagerKeyFlag=False):
        CapabilitySet.__init__(self, CAPSTYPE_ACTIVATION)
        self.helpKeyFlag = helpKeyFlag
        self.helpKeyIndexFlag = helpKeyIndexFlag
        self.helpExtendedKeyFlag = helpExtendedKeyFlag
        self.windowManagerKeyFlag = windowManagerKeyFlag

    def __str__(self):
        s  = '[ WindowActivationCapabilitySet: helpKeyFlag=0x%x, helpKeyIndexFlag=0x%x, helpExtendedKeyFlag=0x%x, windowManagerKeyFlag=0x%x ]'
        return s % (self.helpKeyFlag, self.helpKeyIndexFlag, self.helpExtendedKeyFlag, self.windowManagerKeyFlag)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 12
        self['capabilityData']  = struct.pack('<H', self.helpKeyFlag)
        self['capabilityData'] += struct.pack('<H', self.helpKeyIndexFlag)
        self['capabilityData'] += struct.pack('<H', self.helpExtendedKeyFlag)
        self['capabilityData'] += struct.pack('<H', self.windowManagerKeyFlag)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.helpKeyFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.helpKeyIndexFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.helpExtendedKeyFlag = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self.windowManagerKeyFlag = struct.unpack('<H', data[offset:offset+2])[0]
            return self
        except Exception as e:
            display_error('WindowActivationCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class ShareCapabilitySet(CapabilitySet):
    """
    2.2.7.2.4 Share Capability Set (TS_SHARE_CAPABILITYSET)
    """

    def __init__(self, nodeId=0):
        CapabilitySet.__init__(self, CAPSTYPE_SHARE)
        self.nodeId = nodeId

    def __str__(self):
        s  = '[ ShareCapabilitySet: nodeId=0x%x ]'
        return s % (self.nodeId)

    ###
    # getters/setters API
    ###

    def get_node_id(self):
        return self.nodeId

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 8
        self['capabilityData']  = struct.pack('<H', self.nodeId)
        self['capabilityData'] += '\0\0' # padding
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.nodeId = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            return self
        except Exception as e:
            display_error('ShareCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class FontCapabilitySet(CapabilitySet):
    """
    2.2.7.2.5 Font Capability Set (TS_FONT_CAPABILITYSET)
    """

    def __init__(self, fontSupportFlags=0):
        CapabilitySet.__init__(self, CAPSTYPE_FONT)
        self.fontSupportFlags = fontSupportFlags

    def __str__(self):
        s  = '[ FontCapabilitySet: fontSupportFlags=0x%x ]'
        return s % (self.fontSupportFlags)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 8
        self['capabilityData']  = struct.pack('<H', self.fontSupportFlags)
        self['capabilityData'] += '\0\0' # padding
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.fontSupportFlags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            return self
        except Exception as e:
            display_error('FontCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class MultiFragmentUpdatCapabilitySet(CapabilitySet):
    """
    2.2.7.2.6 Multifragment Update Capability Set (CAPSETTYPE_MULTIFRAGMENTUPDATE)
    """

    def __init__(self, MaxRequestSize=0):
        CapabilitySet.__init__(self, CAPSETTYPE_MULTIFRAGMENTUPDATE)
        self.MaxRequestSize = MaxRequestSize

    def __str__(self):
        s  = '[ MultiFragmentUpdatCapabilitySet: MaxRequestSize=0x%x ]'
        return s % (self.MaxRequestSize)

    ###
    # getters/setters API
    ###

    def get_maxreqsize(self):
        return self.MaxRequestSize

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 8
        self['capabilityData']  = struct.pack('<L', self.MaxRequestSize)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.MaxRequestSize = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            return self
        except Exception as e:
            display_error('MultiFragmentUpdatCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class LargePointerCapabilitySet(CapabilitySet):
    """
    2.2.7.2.7 Large Pointer Capability Set (TS_LARGE_POINTER_CAPABILITYSET)
    """

    def __init__(self, largePointerSupportFlags=0):
        CapabilitySet.__init__(self, CAPSETTYPE_LARGE_POINTER)
        self.largePointerSupportFlags = largePointerSupportFlags

    def __str__(self):
        s  = '[ LargePointerCapabilitySet: largePointerSupportFlags=0x%x ]'
        return s % (self.largePointerSupportFlags)

    ###
    # getters/setters API
    ###


    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 6
        self['capabilityData']  = struct.pack('<H', self.largePointerSupportFlags)
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.largePointerSupportFlags = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            return self
        except Exception as e:
            display_error('LargePointerCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class SurfaceCommandsCapabilitySet(CapabilitySet):
    """
    2.2.7.2.9 Surface Commands Capability Set (TS_SURFCMDS_CAPABILITYSET)
    """

    def __init__(self, cmdFlags=0):
        CapabilitySet.__init__(self, CAPSETTYPE_SURFACE_COMMANDS)
        self.cmdFlags = cmdFlags

    def __str__(self):
        s  = '[ SurfaceCommandsCapabilitySet: cmdFlags=0x%x ]'
        return s % (self.cmdFlags)

    ###
    # getters/setters API
    ###

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        self['lengthCapability'] = 12
        self['capabilityData']  = struct.pack('<L', self.cmdFlags)
	self['capabilityData'] += '\0\0\0\0'
        data  = CapabilitySet.pack(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            offset = 4
            self.cmdFlags = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            return self
        except Exception as e:
            display_error('SurfaceCommandsCapabilitySet.deserialize() failed: %s' % str(e))
            return None


class capabilitySets(list):

    def __init__(self):
        list.__init__(self)

    def __str__(self):
        vals = ''.join(map(lambda x: str(x), self))
        s = '[ capabilitySets: %s]' % vals
        return s

    ###
    # Packing/Unpacking API
    ###

    def pack(self):
        data = ''
        for cap in self:
            data += cap.pack()
        return data

def get_default_capabilities():

    C = capabilitySets()
    C.append(GeneralCapabilitySet(NO_BITMAP_COMPRESSION_HDR | LONG_CREDENTIALS_SUPPORTED | ENC_SALTED_CHECKSUM))
    C.append(BitmapCapabilitySet())
    C.append(OrderCapabilitySet())
    C.append(CapabilitySet(CAPSTYPE_BITMAPCACHE_REV2, '030000055802000058020000000800000010000000080000000000000000000000000000'.decode('hex')))
    C.append(PointerCapabilitySet(True, 20, 20))
    C.append(InputCapabilitySet(inputFlags = INPUT_FLAG_SCANCODES|INPUT_FLAG_MOUSEX|INPUT_FLAG_UNICODE)) #INPUT_FLAG_FASTPATH_INPUT
    C.append(BrushCapabilitySet(BRUSH_COLOR_FULL))
    C.append(CapabilitySet(CAPSTYPE_GLYPHCACHE, 'fe000400fe000400fe000800fe000800fe001000fe002000fe004000fe008000fe000001400000010001000100000000'.decode('hex')))
    C.append(VirtualChannelCapabilitySet(VCCAPS_NO_COMPR, 0x2000)) # Interesting point ?!?
    C.append(SoundCapabilitySet(soundFlags=SOUND_BEEPS_FLAG))
    C.append(ShareCapabilitySet(0))
    C.append(FontCapabilitySet(FONTSUPPORT_FONTLIST))
    C.append(ControlCapabilitySet())
    C.append(CapabilitySet(CAPSTYPE_COLORCACHE, '06000000'.decode('hex')))
    C.append(WindowActivationCapabilitySet())
    C.append(LargePointerCapabilitySet(LARGE_POINTER_FLAG_96x96))
    C.append(MultiFragmentUpdatCapabilitySet(0x3F80)) #65535))
    C.append(CapabilitySet(CAPSETTYPE_SURFACE_COMMANDS, '5200000000000000'.decode('hex')))
    C.append(CapabilitySet(CAPSETTYPE_BITMAP_CODECS, '00'.decode('hex')))
    return C


def CapabilityType2Class(t):

    d = {}
    d[CAPSTYPE_GENERAL] = GeneralCapabilitySet
    d[CAPSTYPE_BITMAP] = BitmapCapabilitySet
    d[CAPSTYPE_ORDER] = OrderCapabilitySet
    d[CAPSTYPE_POINTER] = PointerCapabilitySet
    d[CAPSTYPE_INPUT] = InputCapabilitySet
    d[CAPSTYPE_BRUSH] = BrushCapabilitySet
    d[CAPSTYPE_VIRTUALCHANNEL] = VirtualChannelCapabilitySet
    d[CAPSTYPE_SOUND] = SoundCapabilitySet
    d[CAPSTYPE_CONTROL] = ControlCapabilitySet
    d[CAPSTYPE_ACTIVATION] = WindowActivationCapabilitySet
    d[CAPSTYPE_SHARE] = ShareCapabilitySet
    d[CAPSTYPE_FONT] = FontCapabilitySet
    d[CAPSETTYPE_MULTIFRAGMENTUPDATE] = MultiFragmentUpdatCapabilitySet
    d[CAPSETTYPE_LARGE_POINTER] = LargePointerCapabilitySet
    d[CAPSETTYPE_SURFACE_COMMANDS] = SurfaceCommandsCapabilitySet

    if d.has_key(t):
        return d[t]
    else:
        logging.debug('Could not find a specific class for type %d!' % t)
        return CapabilitySet


def deserialize_capabilities(data):

    off = 0
    capabilities = []
    while len(data[off:]) >= 2:
        capabilitySetType = struct.unpack('<H', data[off:off+2])[0]
        lengthCapability = struct.unpack('<H', data[off+2:off+4])[0]

        cls = CapabilityType2Class(capabilitySetType)
        obj = cls()

        capabilities.append(obj.deserialize(data[off:]))
        off += lengthCapability
    return capabilities


class ConfirmActivePDUData(Struct):
    """
    2.2.1.13.2.1 Confirm Active PDU Data (TS_CONFIRM_ACTIVE_PDU)
    """

    st = [
        ['shareControlHeader'        , '0s', ''],
        ['shareId'                   , '<L', 0x3ea + 0x10000], # rdp_send_demand_active()
        ['originatorId'              , '<H', 1002],
        ['lengthSourceDescriptor'    , '<H', 0],
        ['lengthCombinedCapabilities', '<H', 0],
        ['sourceDescriptor'          , '0s', ''],
        ['numberCapabilities'        , '<H', 0],
        ['pad2Octets'                , '<H', 0],
        ['capabilitySets'            , '0s', ''],
    ]

    def __init__(self, channelID, capabilities=None):
        '''
        Note: For now ripped from FreeRDP.
        '''
        Struct.__init__(self)
        self['shareControlHeader'] = shareControlHeader(PDUTYPE_CONFIRMACTIVEPDU, channelID)
        self['shareControlHeader']['totalLength'] = 465
        self['lengthCombinedCapabilities'] = 441
        self['sourceDescriptor'] = "FREERDP\0"
        self['lengthSourceDescriptor'] = len(self['sourceDescriptor'])
        self['capabilitySets'] = capabilitySets()
        self['numberCapabilities'] = 0
        if capabilities:
            self['numberCapabilities'] = len(capabilities)
            self['capabilitySets'] = capabilities

    def __str__(self):
        capabilities = deserialize_capabilities(self['capabilitySets'])
        capabilities_str = ' '.join(map(lambda x: str(x), capabilities))
        s  = '[ ConfirmActivePDUData: shareControlHeader=%s shareId=%x, originatorId=%d, lengthSourceDescriptor=%d, '
        s += 'lengthCombinedCapabilities=%d, sourceDescriptor=%s, numberCapabilities=%d, capabilitySets=%s ]'
        return s % (str(self['shareControlHeader']),self['shareId'], self['originatorId'], self['lengthSourceDescriptor'], self['lengthCombinedCapabilities'], self['sourceDescriptor'], self['numberCapabilities'], capabilities_str)

    ###
    # getters/setters API
    ###

    def set_capabilities(self, capabilities):
        self['capabilitySets'] = capabilities
        self['numberCapabilities'] = len(capabilities)

    ###
    # Packing/Unpacking API
    ###

    def pack(self, do_sign=True):
        data  = self['shareControlHeader'].pack()
        data += struct.pack('<L', self['shareId'])
        data += struct.pack('<H', self['originatorId'])
        data += struct.pack('<H', self['lengthSourceDescriptor'])
        data += struct.pack('<H', self['lengthCombinedCapabilities'])
        if self['lengthSourceDescriptor']:
            data += self['sourceDescriptor']
        data += struct.pack('<H', self['numberCapabilities'])
        data += '\0\0'
        data += self['capabilitySets'].pack()
        return data

    def deserialize(self, data):
        try:
            self['shareControlHeader'] = shareControlHeader(0,0).deserialize(data)
            offset = 6
            self['shareId'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self['originatorId'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['lengthSourceDescriptor'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['lengthCombinedCapabilities'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['sourceDescriptor'] = data[offset:offset+self['lengthSourceDescriptor']]
            offset += self['lengthSourceDescriptor']
            self['numberCapabilities'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['pad2Octets'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['capabilitySets'] = data[offset:]
            return self
        except Exception as e:
            display_error('ConfirmActivePDUData.deserialize() failed: %s' % str(e))
            return None


class SynchronizePDUData(Struct):
    """
    2.2.1.14.1 Synchronize PDU Data (TS_SYNCHRONIZE_PDU)
    """

    st = [
        ['shareDataHeader', '0s', ''],
        ['messageType'    , '<H', SYNCMSGTYPE_SYNC],
        ['targetUser'     , '<H', 0],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 22
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x10000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 8
        hdr['pduType2'] = PDUTYPE2_SYNCHRONIZE
        self['shareDataHeader'] = hdr
        self['targetUser'] = 1002 # MCS channel ID of the target user.

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self['shareDataHeader'].pack()
        data += struct.pack('<H', self['messageType'])
        data += struct.pack('<H', self['targetUser'])
        return data


class ControlPDUData(Struct):
    """
    2.2.1.15.1 Control PDU Data (TS_CONTROL_PDU)
    """

    st = [
        ['shareDataHeader', '0s', ''],
        ['action'         , '<L', 0],
        ['grantId'        , '<H', 0],
        ['controlId'      , '<H', 0],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 26
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x10000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 12
        hdr['pduType2'] = PDUTYPE2_CONTROL
        self['shareDataHeader'] = hdr

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self['shareDataHeader'].pack()
        data += struct.pack('<L', self['action'])
        data += struct.pack('<H', self['grantId'])
        data += struct.pack('<H', self['controlId'])
        return data


class ControlPDUData_Cooperate(ControlPDUData):
    """
    2.2.1.15 Client Control PDU - Cooperate
    """

    def __init__(self, channelID):
        ControlPDUData.__init__(self, channelID)
        self['action'] = CTRLACTION_COOPERATE


class ControlPDUData_RequestControl(ControlPDUData):
    """
    2.2.1.16 Client Control PDU - Request Control
    """

    def __init__(self, channelID):
        ControlPDUData.__init__(self, channelID)
        self['action'] = CTRLACTION_REQUEST_CONTROL


class PersistentKeyListPDUData(Struct):
    """
    2.2.1.17.1 Persistent Key List PDU Data
    """

    st = [
        ['shareDataHeader'   , '0s', ''],
        ['numEntriesCache0'  , '<H', 0],
        ['numEntriesCache1'  , '<H', 0],
        ['numEntriesCache2'  , '<H', 0],
        ['numEntriesCache3'  , '<H', 0],
        ['numEntriesCache4'  , '<H', 0],
        ['totalEntriesCache0', '<H', 0],
        ['totalEntriesCache1', '<H', 0],
        ['totalEntriesCache2', '<H', 0],
        ['totalEntriesCache3', '<H', 0],
        ['totalEntriesCache4', '<H', 0],
        ['bBitMask'          , '<B', PERSIST_FIRST_PDU | PERSIST_LAST_PDU],
        ['Pad2'              , '<B', 0],
        ['Pad3'              , '<H', 0],
        ['entries'           , '0s', ''],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 42  # = 18 + 24 + nbr_entries * (2 * 4)
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x10000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 28 # Should be 4 + 24 + nbr_entries * (2 * 4) = 228
        hdr['pduType2'] = PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST
        self['shareDataHeader'] = hdr
        #self['numEntriesCache2'] = 0x19
        #self['totalEntriesCache2'] = 0x19
        #self['entries'] = ('\x41'*4 + '\x42'*4) * 0x19

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self['shareDataHeader'].pack()
        data += struct.pack('<H', self['numEntriesCache0'])
        data += struct.pack('<H', self['numEntriesCache1'])
        data += struct.pack('<H', self['numEntriesCache2'])
        data += struct.pack('<H', self['numEntriesCache3'])
        data += struct.pack('<H', self['numEntriesCache4'])
        data += struct.pack('<H', self['totalEntriesCache0'])
        data += struct.pack('<H', self['totalEntriesCache1'])
        data += struct.pack('<H', self['totalEntriesCache2'])
        data += struct.pack('<H', self['totalEntriesCache3'])
        data += struct.pack('<H', self['totalEntriesCache4'])
        data += struct.pack('<B', self['bBitMask'])
        data += '\0'*3
        data += self['entries']
        return data


class FontListPDUData(Struct):
    """
    2.2.1.18.1 Font List PDU Data (TS_FONT_LIST_PDU)
    """

    st = [
        ['shareDataHeader', '0s', ''],
        ['numberFonts'    , '<H', 0],
        ['totalNumFonts'  , '<H', 0],
        ['listFlags'      , '<H', FONTLIST_FIRST | FONTLIST_LAST],
        ['entrySize'      , '<H', 0x0032],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 26    # OK: 14 + 8
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x10000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 12  # OK: 4 + 8
        hdr['pduType2'] = PDUTYPE2_FONTLIST
        self['shareDataHeader'] = hdr

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self['shareDataHeader'].pack()
        data += struct.pack('<H', self['numberFonts'])
        data += struct.pack('<H', self['totalNumFonts'])
        data += struct.pack('<H', self['listFlags'])
        data += struct.pack('<H', self['entrySize'])
        return data


class ChannelPDUHeader(Struct):
    """
    2.2.6.1.1 Channel PDU Header (CHANNEL_PDU_HEADER)
    """

    st = [
        ['length', '<L', 0],
        ['flags' , '<L', 0],
    ]

    def __init__(self, flags=0, length=0):
        Struct.__init__(self)
        self['flags'] = flags
        self['length'] = length

    ###
    # getters/setters API
    ###

    def set_length(self, length):
        self['length'] = length

    def set_flags(self, flags):
        self['flags'] = flags

    ###
    # (De)Serialization API
    ###

    def pack(self, do_sign=True):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            return self
        except Exception as e:
            display_error('ChannelPDUHeader.deserialize() failed: %s' % str(e))
            return None


class shutdownRequestPduData(Struct):
    """
    2.2.2.1.1 Shutdown Request PDU Data (TS_SHUTDOWN_REQ_PDU)
    """

    st = [
        ['shareDataHeader', '0s', ''],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 18  # OK: 18 + 0
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x20000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 4 # OK: 4 + 0
        hdr['pduType2'] = PDUTYPE2_SHUTDOWN_REQUEST
        self['shareDataHeader'] = hdr

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self['shareDataHeader'].pack()
        return data


class ClientInputEventPDUData(Struct):
    """
    2.2.8.1.1.3.1 Client Input Event PDU Data (TS_INPUT_PDU_DATA)
    """

    st = [
        ['shareDataHeader'    , '0s', ''],
        ['numEvents'          , '<H', 0],
        ['pad2Octets'         , '<H', 0],
        ['slowPathInputEvents', '0s', ''],
    ]

    def __init__(self, channelID):
        Struct.__init__(self)
        ctrl_hdr = shareControlHeader(PDUTYPE_DATAPDU, channelID)
        ctrl_hdr['totalLength'] = 22      # Initial value with 0 events
        hdr = ShareDataHeader()
        hdr['shareControlHeader'] = ctrl_hdr
        hdr['shareId'] = 0x10000 | 0x03ea
        hdr['streamId'] = STREAM_LOW
        hdr['uncompressedLength'] = 8     # Initial value with 0 events
        hdr['pduType2'] = PDUTYPE2_INPUT
        self['shareDataHeader'] = hdr
        self['numEvents'] = 0
        self['slowPathInputEvents'] = ''

    def __str__(self):
        return '[ ClientInputEventPDUData:%s, numEvents=%d ]' % (str(self['shareDataHeader']), self['numEvents'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        length = len(self['slowPathInputEvents'])
        if length:
            self['shareDataHeader']['shareControlHeader']['totalLength'] = 22 + length
            self['shareDataHeader']['uncompressedLength'] = 4 + length # To match FreeRDP.
        data  = self['shareDataHeader'].pack()
        data += struct.pack('<H', self['numEvents'])
        data += '\0\0'
        data += self['slowPathInputEvents']
        return data

    def deserialize(self, data):
        try:
            self['shareDataHeader'] = ShareDataHeader().deserialize(data)
            offset = 18
            self['numEvents'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['pad2Octets'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['slowPathInputEvents'] = data[offset:]
            return self
        except Exception as e:
            display_error('ClientInputEventPDUData.deserialize() failed: %s' % str(e))
            return None


###
# TPKT class - T-REC-T.123-200701-I!!PDF-E.pdf (section 8)
#              [ Layer 0 ]
###

class FastPathUpdate(Struct):
    """
    2.2.9.1.2.1 Fast-Path Update (TS_FP_UPDATE)
    """

    st = [
        ['updateHeader'    , 'B', 0 ],
        ['compressionFlags', 'B', 0 ],
        ['size'            , '<H', 0 ],
        ['updateData'      , '0s', '' ],
    ]

    def __init__(self):
        Struct.__init__(self)

    def __str__(self):
        compressionFlags = (self['updateHeader'] >> 6) & 0x3
        compression_flags_str = ''
        if compressionFlags == FASTPATH_OUTPUT_COMPRESSION_USED:
            compression_flags_str = ' (comp_flags:%d) ' % self['compressionFlags']
        return '[ FastPathUpdate: code=%d, frag=%d, compress=%d%s, payload=%s ]' % ((self['updateHeader'] & 0xf),
                                                                                         (self['updateHeader'] >> 4) & 0x3,
                                                                                         compressionFlags,
                                                                                         compression_flags_str,
                                                                                         self['updateData'].encode('hex'))

    ###
    # Getters/Setters
    ###


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = struct.pack('<B', self['updateHeader'])
        if ((self['updateHeader'] >> 6) & 0x3) == FASTPATH_OUTPUT_COMPRESSION_USED:
            data += struct.pack('<B', self['compressionFlags'])
        data += struct.pack('<H', self['size'])
        data += self['updateData']
        return data

    def deserialize(self, data):
        try:
            offset = 0
            self['updateHeader'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            if ((self['updateHeader'] >> 6) & 0x3) == FASTPATH_OUTPUT_COMPRESSION_USED:
                self['compressionFlags'] = struct.unpack('<B', data[offset:offset+1])[0]
                offset += 1
            self['size'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['updateData'] = data[offset:offset+self['size']]
            return self
        except Exception as e:
            display_error('FastPathUpdate.deserialize() failed: %s' % str(e))
            return None

class ServerFastPathUpdatePDU(Struct):

    st = [
        ['fpOutputHeader' , 'B', 0 ],
        ['length1'        , 'B', 0 ],
        ['length2'        , 'B', 0 ],
        ['fipsInformation', '0s', '' ],
        ['dataSignature'  , '8s', '\0'*8 ],
        ['fpOutputUpdates', '0s', '' ],
    ]

    def __init__(self, action_code=FASTPATH_OUTPUT_ACTION_FASTPATH, flags=FASTPATH_OUTPUT_ENCRYPTED, length=0):
        Struct.__init__(self)
        self['fpOutputHeader'] = (action_code & 0x3) | ((flags & 0x3) << 6)
        if length <= 127:
            self['length1'] = length
            self['length2'] = 0
        else:
            self['length1'] = (length >> 8) & 0xff
            self['length2'] = (length >> 0) & 0xff

    def __str__(self):
        return '[ ServerFastPathUpdatePDU: action=%d, flags=%d ]' % (self['fpOutputHeader'] & 0x3,
                                                                     (self['fpOutputHeader'] >> 6) & 0x3)

    ###
    # Getters/Setters
    ###

    def payload_is_encrypted(self):
        flags = (self['fpOutputHeader'] >> 6) & 0x3
        return flags == FASTPATH_OUTPUT_ENCRYPTED

    ###
    # Size fixing function
    ###

    def fix_size(self, data):
        pass

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = struct.pack('<B', self['fpOutputHeader'])
        data += struct.pack('<B', self['length1'])
        if self['length1'] > 127:
            data += struct.pack('<B', self['length2'])
        # Skipping fipsInformation
        data += self['dataSignature']
        data += self['fpOutputUpdates']
        return data

    def deserialize(self, data):
        try:
            offset = 0
            self['fpOutputHeader'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            self['length1'] = struct.unpack('<B', data[offset:offset+1])[0]
            offset += 1
            if self['length1'] > 127:
                self['length2'] = struct.unpack('<B', data[offset:offset+1])[0]
                offset += 1
            else:
                self['length2'] = 0
                offset += 0
            self['dataSignature'] = data[offset:offset+8]
            offset += 8
            self['fpOutputUpdates'] = data[offset:]
            return self
        except Exception as e:
            display_error('ServerFastPathUpdatePDU.deserialize() failed: %s' % str(e))
            return None


###
# RDP packet - implemented as a list of layers
##

class RdpPacket(list):

    def __init__(self):
        super(RdpPacket, self).__init__()
        self.payload = ''
        self.__current_layer_index = 0

    def __str__(self):
        return self.__packet2str(without_size_fix=True)

    ###
    # MISC API
    ###

    def get_class_name(self, cls):
        return type(cls).__name__

    def get_attribute(self, cls, attribute_name, is_callable=True):
        attribute = getattr(cls, attribute_name, None)
        if not attribute:
            return None
        else:
            if not is_callable:
                return attribute
            else:
                if callable(attribute):
                    return attribute
                else:
                    return None

    def get_fixed_layers(self):
        layers = copy.copy(self)
        frame = ''
        for layer in layers[::-1]:
            fix_size = self.get_attribute(layer, "fix_size")
            if fix_size:
                display_debug("Fixing size for layer: %s" % self.get_class_name(layer))
                fix_size(frame)
            frame = layer.pack() + frame
        return layers

    ###
    # Official API
    ###

    def has_layer(self, clsname):
        '''
        Returns True if the layer is found, False otherwise.
        '''
        for layer in self:
            if isinstance(layer, clsname):
                return True
        return False

    def get_layer(self, clsname, restart=1):
        '''
        Returns the first layer corresponding to clsname.
        Note: Since similar layers may be stacked, restart=0 forces to
        continue with the next result.
        '''

        if restart:
            layers = self
        else:
            self.__current_layer_index += 1
            layers = self[self.__current_layer_index:]

        for i in xrange(len(layers)):
            layer = layers[i]
            if isinstance(layer, clsname):
                self.__current_layer_index = i
                return layer
        return None

    def is_tpkt(self):
        if isinstance(self[0], TPKT):
            return True
        else:
            return False

    def is_fast_path_update_pdu(self):
        if isinstance(self[0], ServerFastPathUpdatePDU):
            return True
        else:
            return False


    ###
    # Parsing API
    ###

    def __packet2str(self, without_size_fix=False, with_payload=True):

        def layers_to_string(layers):
            L = []
            for layer in layers:
                L.append(str(layer))
            return ' '.join(L)

        if without_size_fix:
            layers = self
        else:
            layers = self.get_fixed_layers()

        s = layers_to_string(layers)
        if with_payload and self.payload:
            s += ' [ Raw: %s ]' % self.payload.encode('hex')
        return s

    def packet2str(self, without_size_fix=False, with_payload=True):
        return self.__packet2str(without_size_fix, with_payload)

    def pack(self):

        layers = self.get_fixed_layers()
        L = []
        for layer in layers:
            L.append(layer.pack())
        return ''.join(L)

    def __unserialize_mcs_data_blocks(self, d, remaining_payload):

        while 1:
            t, l = struct.unpack('<HH', remaining_payload[:4])
            if d.has_key(t):
                display_debug('Handling datablock with type %x' % t)
                cls = d[t]
                pdu = cls()
                pdu.deserialize(remaining_payload)
                self.append(pdu)
                self.payload = pdu.payload
            else:
                display_debug('Skipping type: %x', t)
                pdu = GenericDataBlock()
                pdu.deserialize(remaining_payload)
                self.append(pdu)
                self.payload = pdu.payload

            remaining_payload = remaining_payload[l:]
            if not len(remaining_payload):
                break

    def __unserialize_mcs_client_data_blocks(self, remaining_payload):

        d = {
            CS_CORE:     CSCore,
            CS_SECURITY: CSSecurity,
            CS_NET:      CSNet,
            CS_CLUSTER:  CSCluster,
        }

        self.__unserialize_mcs_data_blocks(d, remaining_payload)

    def __unserialize_mcs_server_data_blocks(self, remaining_payload):

        d = {
            SC_CORE:           SCCore,
            SC_SECURITY:       SCSecurity,
            SC_NET:            SCNet,
        }

        self.__unserialize_mcs_data_blocks(d, remaining_payload)

    def __unserialize_mcs_connect_init(self, remaining_payload):

        display_debug("__unserialize_mcs_connect_init()")

        pdu = gcc.ConnectGCC()
        pdu.deserialize(remaining_payload)
        self.append(pdu)
        self.payload = pdu.payload
        if not self.payload:
            return

        display_debug("remains: %s..." % self.payload.encode('hex')[:32])
        pdu2 = gcc.ConferenceCreateRequest()
        pdu2.deserialize(self.payload)
        self.append(pdu2)
        self.payload = pdu2.payload
        if self.payload:
            display_debug("remains: %s..." % self.payload.encode('hex')[:32])
            self.__unserialize_mcs_client_data_blocks(self.payload)

    def __unserialize_mcs_connect_response(self, remaining_payload):

        display_debug("__unserialize_mcs_connect_response()")

        pdu = gcc.ConnectGCC()
        pdu.deserialize(remaining_payload)
        self.append(pdu)
        self.payload = pdu.payload
        if not self.payload:
            return

        display_debug("After ConnectGCC.deserialize remains: %s..." % self.payload.encode('hex')[:32])
        pdu2 = gcc.ConferenceCreateResponse()
        pdu2.deserialize(self.payload)
        self.append(pdu2)
        self.payload = pdu2.payload
        if self.payload:
            display_debug("After ConferenceCreateResponse.deserialize remains: %s..." % self.payload.encode('hex')[:32])
            self.__unserialize_mcs_server_data_blocks(self.payload)

    def __unserialize_mcs_frame(self, remaining_payload):

        # Section 4.1 - PER signatures
        MSC_ERECT_DOMAIN_REQ_SIG      = '0401000100'
        MCS_CONNECT_REQUEST_SIG       = '7f65'
        MCS_CONNECT_RESPONSE_SIG      = '7f66'
        MCS_ATTACH_USER_REQ_SIG       = '28'
        MCS_ATTACH_USER_CONFIRM_SIG   = '2e00'
        MCS_CHANNEL_JOIN_REQUEST_SIG  = '38'
        MCS_CHANNEL_JOIN_CONFIRM_SIG  = '3c'
        MCS_CHANNEL_JOIN_CONFIRM_SIG2 = '3e00'
        MCS_CHANNEL_JOIN_CONFIRM_SIG3 = '3dc0'
        MCS_SEND_DATA_INDICATION_SIG  = '6800' # TODO.
        MCS_SEND_DATA_REQUEST_SIG     = '6400' # TODO.

        display_debug("__unserialize_mcs_frame()")

        signature = ''
        for candidate in [ MCS_CONNECT_REQUEST_SIG,
                            MCS_CONNECT_RESPONSE_SIG,
                            MSC_ERECT_DOMAIN_REQ_SIG,
                            MCS_ATTACH_USER_REQ_SIG,
                            MCS_ATTACH_USER_CONFIRM_SIG,
                            MCS_CHANNEL_JOIN_REQUEST_SIG,
                            MCS_CHANNEL_JOIN_CONFIRM_SIG,
                            MCS_CHANNEL_JOIN_CONFIRM_SIG2,
                            MCS_CHANNEL_JOIN_CONFIRM_SIG3,
                            MCS_SEND_DATA_INDICATION_SIG,
                            MCS_SEND_DATA_REQUEST_SIG]:
            candidate = candidate.decode('hex')
            if candidate == remaining_payload[:len(candidate)]:
                signature = candidate.encode('hex')
                break

        if signature == MCS_CONNECT_REQUEST_SIG:
            pdu = mcs.MCSConnectInit()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSConnectInit.deserialize remains: %s..." % self.payload.encode('hex')[:32])
                self.__unserialize_mcs_connect_init(self.payload)

        elif signature == MCS_CONNECT_RESPONSE_SIG:
            pdu = mcs.MCSConnectResp()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSConnectResp.deserialize remains: %s..." % self.payload.encode('hex')[:32])
                self.__unserialize_mcs_connect_response(self.payload)

        elif signature == MSC_ERECT_DOMAIN_REQ_SIG:
            pdu = mcs.MCSErectDomainRequest()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSErectDomainRequest.deserialize remains: %s..." % self.payload.encode('hex')[:32])

        elif signature == MCS_ATTACH_USER_REQ_SIG:
            pdu = mcs.MCSAttachUserRequest()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSAttachUserRequest.deserialize remains: %s..." % self.payload.encode('hex')[:32])

        elif signature == MCS_ATTACH_USER_CONFIRM_SIG:
            pdu = mcs.MCSAttachUserConfirm()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSAttachUserConfirm.deserialize remains: %s..." % self.payload.encode('hex')[:32])

        elif signature == MCS_CHANNEL_JOIN_REQUEST_SIG:
            pdu = mcs.MCSChannelJoinRequest()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSChannelJoinRequest.deserialize remains: %s..." % self.payload.encode('hex')[:32])

        elif signature == MCS_CHANNEL_JOIN_CONFIRM_SIG \
              or signature == MCS_CHANNEL_JOIN_CONFIRM_SIG2 \
              or signature == MCS_CHANNEL_JOIN_CONFIRM_SIG3:
            pdu = mcs.MCSChannelJoinConfirm()
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSChannelJoinConfirm.deserialize remains: %s..." % self.payload.encode('hex')[:32])

        elif signature == MCS_SEND_DATA_INDICATION_SIG:
            pdu = mcs.MCSSendDataIndication(0,0)
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSSendDataIndication.deserialize remains: %s" % self.payload.encode('hex'))

        elif signature == MCS_SEND_DATA_REQUEST_SIG:
            pdu = mcs.MCSSendDataRequest(0,0)
            pdu.deserialize(remaining_payload)
            self.append(pdu)
            self.payload = pdu.payload
            if self.payload:
                display_debug("After MCSSendDataRequest.deserialize remains: %s" % self.payload.encode('hex'))

    def unserialize_fastpath_outputupdates(self, remaining_payload):
        '''
        TODO: For now we have a small design error because of the encryption!
        '''

        display_debug("unserialize_fastpath_outputupdates()")

        data_left = remaining_payload
        try:
            offset = 0
            while 1:
                fpu = FastPathUpdate()
                fpu.deserialize(data_left[offset:])
                if not fpu:
                    return
                self.append(fpu)
                offset += len(fpu.pack())
                self.payload = data_left[offset:]
                if not data_left[offset:]:
                    break

        except Exception as e:
            display_error('unserialize_fastpath_outputupdates failed: %s')

    def unserialize(self, data):

        self.payload = data
        display_debug("unserialize()")

        if data[0] != '\x03':
            display_debug('ServerFastPathUpdatePDU packet!')
            sfpup = ServerFastPathUpdatePDU()
            sfpup.deserialize(data)
            self.append(sfpup)
            self.payload = sfpup['fpOutputUpdates']
            if self.payload:
                display_debug("After ServerFastPathUpdatePDU.deserialize() remains: %s..." % self.payload.encode('hex')[:32])
                # For now cant be done because of the encryption :/
                #self.__unserialize_fastpath_outputupdates(self.payload)
            return self

        rpdhdr = TPKT()
        rpdhdr.deserialize(data)
        self.append(rpdhdr)

        self.payload = rpdhdr.payload
        if self.payload:

            # Creating a temporary object
            tpdu = x224GenericTPDU()
            tpdu.deserialize(self.payload)

            if tpdu.get_tpdu_code() == X224_CONNECTION_REQUEST_CODE:
                tpdu = RdpConnectionReq()
                tpdu.deserialize(self.payload)
                self.append(tpdu)
                self.payload = tpdu.payload
                if self.payload:
                    display_debug("After RdpConnectionReq.deserialize() remains: %s" % self.payload.encode('hex'))
                    if len(self.payload) >= 8:
                        tpdu2 = RDPNegReq()
                        tpdu2.deserialize(self.payload)
                        self.append(tpdu2)
                        self.payload = tpdu2.payload

            elif tpdu.get_tpdu_code() == X224_CONNECTION_CONFIRM_CODE:
                tpdu1 = RdpConnectionConfirm()
                tpdu1.deserialize(self.payload)
                self.append(tpdu1)
                self.payload = tpdu1.payload
                if self.payload:
                    display_debug("After RdpConnectionConfirm.deserialize() remains: %s..." % self.payload.encode('hex')[:32])
                    tpdu2 = RDPNegResp()
                    tpdu2.deserialize(self.payload)
                    self.append(tpdu2)
                    self.payload = tpdu2.payload
                    if self.payload:
                        display_debug("After RDPNegResp.deserialize() remains: %s..." % self.payload.encode('hex')[:32])

            elif tpdu.get_tpdu_code() == X224_DATA_CODE:
                pdu = x224DataTPDU()
                pdu.deserialize(self.payload)
                self.append(pdu)
                self.payload = pdu.payload
                if self.payload:
                    display_debug("After x224DataTPDU.deserialize() remains: %s..." % self.payload.encode('hex')[:32])
                    self.__unserialize_mcs_frame(self.payload)

            else:
                display_debug('unserialization failed: Unhandled TPDU code [%s]' % tpdu.get_tpdu_code())
                self.append(tpdu)
                self.payload = tpdu.payload

        return self


class RawPacket(Struct):

    st = [['data', '0s', ''],]

    def pack(self):
        return self['data']

class RDP:

    def __init__(self, socket, username = '', password = '', domain = ''):

        self.socket = socket
        self.username = username
        self.password = password
        self.domain = domain

        # Channel components
        self.user_channel_id = None
        self.io_channel_id = None
        self.channel_ids = None

        # Server choices
        self.selected_protocol = 0

        # Capabilities
        self.capabilities = get_default_capabilities()

        # Crypto components (RDP protocol specific)
        self.encryption = False # currently unused.
        self._crandom = None
        self._srandom = None
        self._e = None
        self._n = None
        self._MACKey128 = None
        self._MasterSecret = None
        self._SessionKeyBlob = None
        self._PreMasterSecret = None
        self.enc = None
        self.dec = None

    ###
    # Socket wrapping API
    ###

    def raw_recv(self):

        if hasattr(self.socket, 'get_timeout'):
            ready = select.select([self.socket], [], [], self.socket.get_timeout())

            if not ready[0]:
                return ''

        hdr = self.socket.recv(4)
        if len(hdr) != 4:
            display_warning("Invalid TPKT header length")
            return hdr

        version, reserved, length = struct.unpack('>BBH', hdr)

        # Fast Path PDU
        if version != 3:
            display_warning("Invalid TPKT header version, assuming a FastPathPDU")
            length = ord(hdr[1])
            if length > 127:
                length = ((ord(hdr[1]) & 0x7f) << 8)
                length |= ord(hdr[2])
            display_debug("Expecting %d bytes" % length)
            nr_required = length-4

            pdu = ''
            while nr_required:
                data = self.socket.recv(nr_required)
                if not data:
                    break
                pdu += data
                nr_required -= len(data)
                display_debug("Got %d more bytes, we need %d more!" % (len(data) ,nr_required))
            return hdr + pdu

        else:
            length -= 4
            data = ''

            while len(data) < length:
                tmp = self.socket.recv(length-len(data))
                data += tmp

                if not len(tmp):
                    raise ValueError("Invalid TPKT data length")

            return hdr+data

    def raw_send(self, pdu):

        hdr = pdu[:4]
        version, reserved, length = struct.unpack('>BBH', hdr)
        if len(hdr) != 4:
            display_warning("Sending packet with an invalid TPKT header length!")
        ret = self.socket.sendall(pdu)
        time.sleep(0)
        return ret

    def recv(self):

        raw_packet = self.raw_recv()
        if not raw_packet:
            # We may improve this a little bit in the future.
            display_error('No answer received or connection has timed out.')
            return None

        display_debug('Ans [Raw]: %s' % raw_packet.encode('hex'))
        pkt = RdpPacket()
        pkt.unserialize(raw_packet)
        return pkt

    def send(self, pkt):
        display_debug('MSG: %s' % pkt.packet2str(without_size_fix=False))
        raw_packet = pkt.pack()
        display_debug('MSG: %s' % raw_packet.encode('hex'))
        return self.raw_send(raw_packet)

    def send_recv(self, pkt):
        self.send(pkt)
        ans = self.recv()
        if ans:
            display_debug('ANS: %s' % ans.packet2str(without_size_fix=True))
        return ans

    def close(self):
        try:
            # TODO: send disconnect packet
            self.socket.close()
        except Exception as e:
            display_error('close() failed: %s' % str(e))

    def set_timeout(self, timeout):
        """
        This function is absolutely mandatory in an exploitation context.
        """
        if not self.socket:
            raise ValueError("Attempting to assign a timeout on an invalid socket!")

        if self.selected_protocol != PROTOCOL_SSL:
            self.socket.set_timeout(timeout)

    ###
    # RDP - packet creation API
    ###


    def cr_req_erect_domain(self):
        '''
        Creates a MCSErectDomainRequest.
        '''
        try:
            edr = mcs.MCSErectDomainRequest()
            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(edr)
            return pkt
        except Exception as e:
            display_error('cr_req_erect_domain(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_attach_user(self):
        '''
        Creates an AttachUserRequest.
        '''

        try:
            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(mcs.MCSAttachUserRequest())
            return pkt
        except Exception as e:
            display_error('cr_req_attach_user(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_channel_join(self, channel_id, initiator):
        '''
        Creates a ChannelJoinRequest.
        '''

        try:
            cjr = mcs.MCSChannelJoinRequest()
            cjr['initiator'] = initiator
            cjr['channelId'] = channel_id
            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(cjr)
            return pkt
        except Exception as e:
            display_error('cr_req_channel_join(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_client_info(self, channel_id, initiator, username='foo', password='', domain=''):
        '''
        Creates a ClientInfo.
        '''

        try:
            info = InfoPacket()
            info['CodePage'] = 0
            info['flags'] = 0xb47fb #INFO_UNICODE | INFO_LOGONERRORS | INFO_AUTOLOGON
            info['UserName'] = username
            info['Password'] = password
            info['Domain'] = domain
            raw_data = info.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                data  = NonFipsSecurityHeader(SEC_INFO_PKT|SEC_ENCRYPT, self.generate_mac(raw_data)).pack()
                data += encrypted_data
            else:
                data  = BasicSecurityHeader(flags=SEC_INFO_PKT).pack()
                data += raw_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_client_info(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_client_confirm_active(self, channel_id, initiator):
        '''
        Creates a Client Confirm Active PDU.
        '''

        try:
            capd = ConfirmActivePDUData(self.user_channel_id)
            capd.set_capabilities(self.capabilities)
            raw_data = capd.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                flags = SEC_ENCRYPT #SEC_RESET_SEQNO | SEC_IGNORE_SEQNO
                # 4.1.13 Client Confirm Active PDU
                hdr = NonFipsSecurityHeader(flags, signature=self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data
            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_client_confirm_active(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_synchronize(self, channel_id, initiator):
        '''
        Creates a Client Synchronize PDU.
        '''

        try:
            spd = SynchronizePDUData(self.user_channel_id)
            raw_data = spd.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_IGNORE_SEQNO | SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_synchronize(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_control_cooperate(self, channel_id, initiator):
        '''
        Creates a Client Control PDU - Cooperate.
        '''

        try:
            cpd_c = ControlPDUData_Cooperate(self.user_channel_id)
            raw_data = cpd_c.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_control_cooperate(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_control_request_control(self, channel_id, initiator):
        '''
        Creates a Client Control PDU - Request Control.
        '''

        try:
            cpd_rc = ControlPDUData_RequestControl(self.user_channel_id)

            raw_data = cpd_rc.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_control_request_control(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_persistent_key_list(self, channel_id, initiator):
        '''
        Creates a Client Persistent Key List PDU
        '''

        try:
            pklpd = PersistentKeyListPDUData(self.user_channel_id)
            raw_data = pklpd.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_persistent_key_list(): An unexpected error occured: %s' % str(e))
            return None


    def cr_req_client_font_list(self, channel_id, initiator):
        '''
        Creates a Client Font List PDU.
        '''

        try:
            flpd = FontListPDUData(self.user_channel_id)
            raw_data = flpd.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            return pkt
        except Exception as e:
            display_error('cr_req_client_font_list(): An unexpected error occured: %s' % str(e))
            return None


    ###
    # RDP API.
    ###


    def get_capability(self, capability_type, attr_name):
        for cap in self.capabilities:
            if cap.get_type() == capability_type:
                if hasattr(cap, attr_name):
                    return getattr(cap, attr_name)
                else:
                    display_error('get_capability() called with abnormal attribute: %s' % attr_name)
                    return None

        display_error('get_capability() could not find capability type = %x' % capability_type)
        return None

    def set_capability(self, capability_type, attr_name, attr_value):
        for cap in self.capabilities:
            if cap.get_type() == capability_type:
                if hasattr(cap, attr_name):
                    setattr(cap, attr_name, attr_value)
                    return
                else:
                    display_error('set_capability() called with abnormal attribute: %s' % attr_name)
                    return

        display_error('set_capability() could not find capability type = %x' % capability_type)

    def create_channels(self):
        '''
        Creates a list of channel.
        '''

        chans = []
        chans.append(('rdpdr', CHANNEL_OPTION_INITIALIZED|CHANNEL_OPTION_COMPRESS_RDP|CHANNEL_OPTION_ENCRYPT_RDP))
        chans.append(('rdpsnd', CHANNEL_OPTION_INITIALIZED|CHANNEL_OPTION_COMPRESS_RDP|CHANNEL_OPTION_ENCRYPT_RDP))
        chans.append(('drdynvc', CHANNEL_OPTION_COMPRESS_RDP|CHANNEL_OPTION_ENCRYPT_RDP))
        chans.append(('ENCOMSP', CHANNEL_OPTION_ENCRYPT_RDP))
        chans.append(('RAIL', CHANNEL_OPTION_ENCRYPT_RDP))
        return chans

    def disconnect_request(self):
        '''
        Sends a DisconnectRequest to the server.
        Note: To be finished/tested.
        '''

        display_debug('------- Calling disconnect_request() -------')
        try:
            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(RdpDisconnectRequest())
            self.send(pkt)

        except Exception as e:
            display_error('An unexpected error occured: %s' % str(e))
            return -1, None

    def connection_request(self, cookie='Cookie: mstshash=foo', flags=0, requestedProtocols=PROTOCOL_RDP):
        '''
        Sends a ConnectionRequest to the server.
        '''

        display_debug('------- Calling connection_request() -------')
        try:
            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(RdpConnectionReq(cookie=cookie))
            pkt.append(RDPNegReq(flags=flags, requestedProtocols=requestedProtocols))
            ans = self.send_recv(pkt)
            rcc = ans.get_layer(RdpConnectionConfirm)
            if not rcc:
                display_error('Invalid response: expected a RdpConnectionConfirm layer')
                return -2, None

            rnr = ans.get_layer(RDPNegResp)
            if not rcc:
                display_error('Invalid response: expected a RDPNegResp layer')
                return -3, None

            self.selected_protocol = rnr.get_selected_protocol()
            flags = rnr.get_flags()
            return 0, [self.selected_protocol, flags]

        except Exception as e:
            display_error('connection_request(): An unexpected error occured: %s' % str(e))
            return -1, None

    def connect_initial(self, encryption=ENCRYPTION_METHOD_NONE, channels=[]):
        '''
        Send a connect-initial msg to the server.
        Receives a connect-response in return.
        '''

        display_debug('------- Calling connect_initial() -------')
        try:
            net = CSNet()
            net.add_channels(channels)
            sec = CSSecurity()
            sec['encryptionMethods'] = encryption
            client_data_blocks = [ CSCore(serverSelectedProtocol=self.selected_protocol),
                                   CSCluster(),
                                   sec,
                                   net]

            ccr = gcc.ConferenceCreateRequest()
            ccr.set_payload(''.join(map(lambda x: x.pack(), client_data_blocks)))

            cgcc = gcc.ConnectGCC()
            cgcc.set_payload(ccr.pack())

            tgt_param = mcs.DomainParameters()
            ci = mcs.MCSConnectInit()
            ci.set_target_parameters(tgt_param)
            ci.set_payload(cgcc.pack())

            data = x224DataTPDU()

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(data)
            pkt.append(ci)

            ans = self.send_recv(pkt)

            if not ans.has_layer(mcs.MCSConnectResp):
                display_error('Invalid response: expected an MCSConnectResp layer')
                return -2, None

            mcr = ans.get_layer(mcs.MCSConnectResp)
            result = mcr.get_result()
            if result != 'rt-successful':
                display_error('Server returned an error: %s' % result)
                return -3, None

            # First get the channel IDs
            scnet_layer = ans.get_layer(SCNet)
            if not scnet_layer:
                display_error('Invalid response: expected an SCNet layer')
                return -4, None

            '''
            2.2.1.4.4 Server Network Data (TS_UD_SC_NET)
            --------------------------------------------
            MCSChannelId (2 bytes): A 16-bit, unsigned integer.
            The MCS channel identifier of the I/O channel.
            '''
            self.io_channel_id = scnet_layer.get_io_channel_id()

            '''
            channelIdArray (variable): A variable-length array of MCS channel IDs
            (each channel ID is a 16-bit, unsigned integer) which have been
            allocated (the number is given by the channelCount field). Each MCS
            channel ID corresponds in position to the channels requested in the Client
            Network Data structure. A channel value of 0 indicates that the channel
            was not allocated.
            '''
            self.channel_ids = scnet_layer.get_channel_ids()

            display_debug('Server returned: MCSChannelID:%d, ChanIDs:%s' % (self.io_channel_id, self.channel_ids))

            # TODO.
            # We need this info for Client Security Exchange PDU
            scSecurity = ans.get_layer(SCSecurity)
            if not scSecurity:
                display_error('Invalid response: expected an SCSecurity layer')
                return -5, None

            # First let's extract the protocol
            self.encryption_method = scSecurity['encryptionMethod']
            if self.encryption_method != encryption:
                display_warning('The server chose a different encryption mechanism!')

            if encryption != ENCRYPTION_METHOD_NONE:
                # TODO: For now we only handle 128 bits encryption
                if self.encryption_method != ENCRYPTION_METHOD_128BIT:
                    display_error('The configuration on server side does not allow us to go further.')
                    return -6, None

            display_debug('Server confirmed the encryption method: %d' % self.encryption_method)

            scCore = ans.get_layer(SCCore)
            if not scCore:
                display_error('Invalid response: expected an SCCore layer')
                return -7, None

            if scCore.get_protocol() != self.selected_protocol:
                display_error('Invalid response: expected protocol %d while we got %d' % (self.selected_protocol. scCore.get_protocol()))
                return -8, None

            # Let's extract the important parameters (if required)
            if self.selected_protocol == PROTOCOL_RDP:

                self._srandom = scSecurity.get_random()
                cert = scSecurity.get_certificate()

                if not self._srandom or not cert:
                    display_error('Missing crypto parameters within the SCSecurity layer')
                    return -8, None

                self._e = cert['PublicKeyBlob']['pubExp']
                self._n = cert['PublicKeyBlob']['modulus']
                self.generate_keys()
                display_debug('srandom: %s' % self._srandom.encode('hex'))
                display_debug('crandom: %s' % self._crandom.encode('hex'))
                display_debug('e: %s' % self._e)
                display_debug('n: %s' % self._n)
                display_debug('PreMasterSecret: %s' % self._PreMasterSecret.encode('hex'))
                display_debug('MasterSecret: %s' % self._MasterSecret.encode('hex'))
                display_debug('MACKey128: %s' % self._MACKey128.encode('hex'))
                display_debug('InitialClientDecryptKey128: %s' % self.InitialClientDecryptKey128.encode('hex'))
                display_debug('InitialClientEncryptKey128: %s' % self.InitialClientEncryptKey128.encode('hex'))

            return 0, [self.io_channel_id, self.channel_ids, self._srandom]

        except Exception as e:
            display_error('connect_initial(): An unexpected error occured: %s' % str(e))
            return -1, None

    def erect_domain(self):
        '''
        Sends a MCSErectDomainRequest to the server.
        We do _not_ expect an answer.
        '''

        display_debug('------- Calling erect_domain() -------')
        try:
            pkt = self.cr_req_erect_domain()
            if not pkt:
                return -2, None

            # We do not except any answer.
            self.send(pkt)
            return 0, None

        except Exception as e:
            display_error('erect_domain(): An unexpected error occured: %s' % str(e))
            return -1, None


    def attach_user(self):
        '''
        Send an AttachUserRequest to the server.
        Receives an AttachUserConfirm in return.
        '''

        display_debug('------- Calling attach_user() -------')
        try:
            pkt = self.cr_req_attach_user()
            if not pkt:
                return -3, None

            ans = self.send_recv(pkt)
            auc = ans.get_layer(mcs.MCSAttachUserConfirm)
            if not auc:
                display_error('Invalid response: expected an MCSAttachUserConfirm layer')
                return -2, None

            self.user_channel_id = auc.get_initiator()
            display_debug('Server answered with user_channel_id = %d' % self.user_channel_id)
            return 0, [self.user_channel_id]

        except Exception as e:
            display_error('attach_user(): An unexpected error occured: %s' % str(e))
            return -1, None


    def channel_join(self, channel_id=None, initiator=None):
        '''
        Send a ChannelJoinRequest to the server.
        Receives a ChannelJoinConfirm in return.
        '''

        if initiator is None:
            display_debug('Fixing initiator to: %d' % self.user_channel_id)
            initiator = self.user_channel_id

        if channel_id is None:
            display_error('Invalid parameter: channel_id=%d' % channel_id)
            return -5, None

        display_debug('------- Calling channel_join(%d) -------' % channel_id)
        try:
            if initiator < 1001 or initiator > 65535:
                display_error('Invalid parameter: initiator=%d' % initiator)
                return -2, None

            if channel_id > 65535:
                display_error('Invalid parameter: channel_id=%d' % channel_id)
                return -3, None

            if channel_id <= 1000:
                display_debug('channel_join() called with a dynamic channel!')

            pkt = self.cr_req_channel_join(channel_id, initiator)
            if not pkt:
                return -5, None

            ans = self.send_recv(pkt)
            if not ans.has_layer(mcs.MCSChannelJoinConfirm):
                display_error('Invalid response: expected an MCSChannelJoinConfirm layer')
                return -4, None

            return 0, []

        except Exception as e:
            display_error('channel_join(): An unexpected error occured: %s' % str(e))
            return -1, None


    def sec_exchange(self, channel_id=None, initiator=None):
        '''
        Sends a SecurityExchange packet.
        Does _not_ expect an answer.
        '''

        if self.selected_protocol != PROTOCOL_RDP:
            display_warning('Current security protocol is %d therefore we do not send the packet!' % self.selected_protocol)
            return 0, []

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling sec_exchange() -------')
        try:
            pkey = RSA.construct((self._n, long(self._e)))
            encryptedClientRandom = pkey.encrypt(self._crandom, K="")[0]
            encryptedClientRandom = encryptedClientRandom[::-1] + "\0" * 8

            sep = SecurityExchangePDUData()
            sep['encryptedClientRandom'] = encryptedClientRandom

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(sep.pack())

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            self.send(pkt)

            return 0, []

        except Exception as e:
            display_error('sec_exchange(): An unexpected error occured: %s' % str(e))
            return -1, None


    def client_info(self, channel_id=None, initiator=None, expect_answer=True, username='foo', password='', domain=''):
        '''
        Sends a ClientInfo packet.
        Expects 3 (possibly encrypted) packets in return:
            - Server License Error PDU - Valid Client packet
            - Server Demand Active PDU
            - Monitor Layout PDU
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling client_info() -------')

        try:
            pkt = self.cr_req_client_info(channel_id, initiator, username=username, password=password, domain=domain)
            if not pkt:
                return -7, None

            self.send(pkt)

            if not expect_answer:
                return 0, []

            # Handling the first packet
            ans1 = self.recv()
            sle_vc = ans1.get_layer(mcs.MCSSendDataIndication)
            if not sle_vc:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -2, None

            display_debug("Received a Server License Error PDU - Valid Client packet")

            raw_data = sle_vc.get_payload()
            flags = struct.unpack('<L', raw_data[:4])[0]

            if not (flags & SEC_LICENSE_PKT):
                display_error('Invalid response: expected Server License Error PDU - Valid Client packet [flgs=%x]' % flags)
                return -3, None

            display_debug('client_info() returned a Server License Error PDU - Valid Client')

            if self.selected_protocol == PROTOCOL_RDP:
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))

            display_debug('ANS_1: %s' % ans1.packet2str(without_size_fix=True))

            # TODO.
            #vcld = ValidClientLicenseData()
            #vcld.deserialize(raw_data[12:])

            # Handling the second packet
            ans2 = self.recv()
            dapd = ans2.get_layer(mcs.MCSSendDataIndication)
            if not dapd:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -4, None

            display_debug("Received a Server Demand Active PDU")

            '''
            The server advertises its capabilities within this packet:
            2.2.1.13.1.1 Demand Active PDU Data (TS_DEMAND_ACTIVE_PDU)
            '''

            raw_data = dapd.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            # Checking the type of packet
            hdr = shareControlHeader(0,0)
            hdr = hdr.deserialize(raw_data)
            if (hdr.get_pdutype() != PDUTYPE_DEMANDACTIVEPDU) or (hdr.get_pduversion() != TS_PROTOCOL_VERSION):
                display_error('Invalid response: expected a Demand Active PDU Data layer')
                return -5, None

            ans2.append(hdr)
            ans2.payload = raw_data[6:]
            display_debug('ANS_2: %s' % ans2.packet2str(without_size_fix=True))

            # Handling the third packet
            ans3 = self.recv()
            mlp = ans3.get_layer(mcs.MCSSendDataIndication)
            if not mlp:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -6, None

            display_debug("Received a Monitor Layout PDU")

            raw_data = mlp.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            hdr = ShareDataHeader()
            ans3.append(hdr.deserialize(raw_data))
            ans3.payload = raw_data[18:]
            display_debug('ANS_3: %s' % ans3.packet2str(without_size_fix=True))

            return 0, []

        except Exception as e:
            display_error('client_info(): An unexpected error occured: %s' % str(e))
            return -1, None


    def client_confirm_active(self, channel_id=None, initiator=None, expect_answer=True):
        '''
        Sends a Client Confirm Active PDU.
        Expects two messages in return
            - Server Synchronize PDU
            - Server Control (Cooperate) PDU
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling client_confirm_active() -------')
        try:
            pkt = self.cr_req_client_confirm_active(channel_id, initiator)
            if not pkt:
                return -2, None

            self.send(pkt)

            if not expect_answer:
                return 0, []

            # Handling the 1st answer
            ans1 = self.recv()
            mlp = ans1.get_layer(mcs.MCSSendDataIndication)
            if not mlp:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -3, None

            display_debug("Received a Server Synchronize PDU")

            raw_data = mlp.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            hdr = ShareDataHeader()
            ans1.append(hdr.deserialize(raw_data))
            ans1.payload = raw_data[18:]
            display_debug('ANS_1: %s' % ans1.packet2str(without_size_fix=True))

            # Handling the 2nd answer
            ans2 = self.recv()
            mlp = ans2.get_layer(mcs.MCSSendDataIndication)
            if not mlp:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -4, None

            display_debug("Received a Server Control (Cooperate) PDU")

            raw_data = mlp.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            hdr = ShareDataHeader()
            ans2.append(hdr.deserialize(raw_data))
            ans2.payload = raw_data[18:]
            display_debug('ANS_2: %s' % ans2.packet2str(without_size_fix=True))

            return 0, []

        except Exception as e:
            display_error('client_confirm_active(): An unexpected error occured: %s' % str(e))
            return -1, None


    def synchronize(self, channel_id=None, initiator=None):
        '''
        Sends a Client Synchronize PDU.
        Does not expect any answer.
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling synchronize() -------')
        try:
            pkt = self.cr_req_synchronize(channel_id, initiator)
            if not pkt:
                return -2, None

            self.send(pkt)
            return 0, []

        except Exception as e:
            display_error('synchronize(): An unexpected error occured: %s' % str(e))
            return -1, None


    def control_cooperate(self, channel_id=None, initiator=None):
        '''
        Sends a Client Control PDU - Cooperate.
        Does not expect an answer in return.
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling control_cooperate() -------')
        try:
            pkt = self.cr_req_control_cooperate(channel_id, initiator)
            if not pkt:
                return -2, None

            self.send(pkt)
            return 0, []

        except Exception as e:
            display_error('control_cooperate(): An unexpected error occured: %s' % str(e))
            return -1, None


    def control_request_control(self, channel_id=None, initiator=None, expect_answer=True):
        '''
        Sends a Client Control PDU - Request Control.
        Expects a Server Control (Granted Control) PDU.
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling control_request_control() -------')
        try:
            pkt = self.cr_req_control_request_control(channel_id, initiator)
            if not pkt:
                return -2, None

            ans = self.send(pkt)

            if not expect_answer:
                return 0, []

            ans = self.recv()
            sdi = ans.get_layer(mcs.MCSSendDataIndication)
            if not sdi:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -3, None

            display_debug("Received a Server Control (Granted Control) PDU")

            raw_data = sdi.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            hdr = ShareDataHeader()
            ans.append(hdr.deserialize(raw_data))
            ans.payload = raw_data[18:]
            display_debug('ANS: %s' % ans.packet2str(without_size_fix=True))
            return 0, []

        except Exception as e:
            display_error('control_request_control(): An unexpected error occured: %s' % str(e))
            return -1, None


    def persistent_key_list(self, channel_id=None, initiator=None):
        '''
        Sends a Client Persistent Key List PDU
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling persistent_key_list() -------')
        try:
            pkt = self.cr_req_persistent_key_list(channel_id, initiator)
            if not pkt:
                return -2, None

            self.send(pkt)
            return 0, []

        except Exception as e:
            display_error('persistent_key_list(): An unexpected error occured: %s' % str(e))
            return -1, None

    def client_font_list(self, channel_id=None, initiator=None, expect_answer=True):
        '''
        Sends a Client Font List PDU.
        Expects a Font Map PDU in return.
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('------- Calling client_font_list() -------')
        try:
            pkt = self.cr_req_client_font_list(channel_id, initiator)
            if not pkt:
                return -3, None

            self.send(pkt)

            if not expect_answer:
                return 0, []

            ans = self.recv()
            sdi = ans.get_layer(mcs.MCSSendDataIndication)
            if not sdi:
                display_error('Invalid response: expected an MCSSendDataIndication layer')
                return -2, None

            display_debug("Received a Font Map PDU")

            raw_data = sdi.get_payload()
            if self.selected_protocol == PROTOCOL_RDP:
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    decrypted_data = self.decrypt(raw_data[12:])#, mac=raw_data[4:12])
                    display_debug("Decrypted payload: %s" % decrypted_data.encode('hex'))
                    raw_data = decrypted_data

            hdr = ShareDataHeader()
            ans.append(hdr.deserialize(raw_data))
            ans.payload = raw_data[18:]
            display_debug('ANS: %s' % ans.packet2str(without_size_fix=True))
            return 0, []

        except Exception as e:
            display_error('client_font_list(): An unexpected error occured: %s' % str(e))
            return -1, None


    def client_shutdown_request(self, channel_id=None, initiator=None):
        '''
        Sends a Client Shutdown Request PDU
        '''

        if channel_id is None:
            channel_id=self.io_channel_id

        if initiator is None:
            initiator=self.user_channel_id

        display_debug('Calling client_shutdown_request()')
        try:
            srpd = shutdownRequestPduData(self.user_channel_id)
            raw_data = srpd.pack()
            if self.selected_protocol == PROTOCOL_RDP:
                encrypted_data = self.encrypt(raw_data)
                hdr = NonFipsSecurityHeader(SEC_ENCRYPT, self.generate_mac(raw_data))
                raw_data = hdr.pack() + encrypted_data

            sdr = mcs.MCSSendDataRequest(initiator, channel_id)
            sdr.set_payload(raw_data)

            pkt = RdpPacket()
            pkt.append(TPKT())
            pkt.append(x224DataTPDU())
            pkt.append(sdr)
            self.send(pkt)
            return 0, []

        except Exception as e:
            display_error('client_shutdown_request(): An unexpected error occured: %s' % str(e))
            return -1, None


    ###
    # Crypto API
    ###

    def encrypt(self, data):
        '''
        Encryption function.
        Uses a str 2 list function for adaption purpose.
        '''
        new_data = map(lambda x: ord(x), list(data))
        l = self.enc.encrypt(new_data)
        return ''.join(map(lambda x: chr(x), l))

    def decrypt(self, data, mac=None):
        '''
        Encryption function.
        Uses a str 2 list function for adaption purpose.
        Checks the MAC if provided.
        '''
        new_data = map(lambda x: ord(x), list(data))
        l = self.dec.decrypt(new_data)
        decrypted_data = ''.join(map(lambda x: chr(x), l))
        if mac:
            if mac != self.generate_mac(decrypted_data):
                raise ValueError("Invalid packet signature")
            else:
                display_debug('MAC validated!')

        return decrypted_data

    def generate_mac(self, data):
        '''
        [MS-RDPBCGR]: 5.3.6.1 Non-FIPS
        '''

        Pad1 = "\x36" * 40
        Pad2 = "\x5c" * 48
        sh = sha.new()
        sh.update(self._MACKey128)
        sh.update(Pad1)
        sh.update(struct.pack('<L', len(data)))
        sh.update(data)

        SHAComponent = sh.digest()

        m = md5.new()
        m.update(self._MACKey128)
        m.update(Pad2)
        m.update(SHAComponent)

        return m.digest()[0:8]

    def generate_keys(self):

        #self._crandom = randomstring(32)
        self._crandom = 'A'*32 # debug
        self._PreMasterSecret = self._crandom[0:24] + self._srandom[0:24]

        self._MasterSecret  = self._PreMasterHash('A')
        self._MasterSecret += self._PreMasterHash('BB')
        self._MasterSecret += self._PreMasterHash('CCC')

        self._SessionKeyBlob = self._MasterHash('X')
        self._SessionKeyBlob += self._MasterHash('YY')
        self._SessionKeyBlob += self._MasterHash('ZZZ')

        self._MACKey128 = self._SessionKeyBlob[0:16]

        self.InitialClientDecryptKey128 = self._FinalHash(self._SessionKeyBlob[16:32])
        self.InitialClientEncryptKey128 = self._FinalHash(self._SessionKeyBlob[32:48])

        def convert_key(k):
            new_key = map(lambda b: ord(b), list(k))
            return Python_RC4(new_key)

        self.enc = convert_key(self.InitialClientEncryptKey128)
        self.dec = convert_key(self.InitialClientDecryptKey128)

    def _SaltedHash(self, S, I):
        sh = sha.new()
        sh.update(I)
        sh.update(S)
        sh.update(self._crandom)
        sh.update(self._srandom)
        shex = sh.digest()

        m = md5.new()
        m.update(S)
        m.update(shex)
        return m.digest()
    
    def _PreMasterHash(self, I):
        return self._SaltedHash(self._PreMasterSecret, I)
    
    def _MasterHash(self, I):
        return self._SaltedHash(self._MasterSecret, I)
    
    def _FinalHash(self, K):
        m = md5.new()
        m.update(K)
        m.update(self._crandom)
        m.update(self._srandom)
        return m.digest()    

        
if __name__ == "__main__":
    pass
