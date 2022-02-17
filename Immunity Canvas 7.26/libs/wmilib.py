#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  librdp.py
## Description:
##            :
## Created_On :  Wed Oct 2 2019
##
## Created_By :  X. (adding code from bas/nicop's libs)
##
## (c) Copyright 2019, Immunity, Inc. all rights reserved.
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

from libs.libwinreg.Struct import Struct 
from libs.newsmb.libdcerpc import *
###
# Logging flags
###

WMI_LOG_NONE  = (0)
WMI_LOG_INFO  = (1<<0)
WMI_LOG_DEBUG = (1<<1)
WMI_LOG_WARN  = (1<<2)
WMI_LOG_ERROR = (1<<3)

###
# Global logging mechanism
###

wmi_debug_level = WMI_LOG_ERROR

def set_debug_level(dbg_lvl):
    global wmi_debug_level
    wmi_debug_level = dbg_lvl

def display_error(msg):
    if wmi_debug_level & WMI_LOG_ERROR:
        logging.error(msg)

def display_warning(msg):
    if wmi_debug_level & WMI_LOG_WARN:
        logging.warning(msg)

def display_info(msg):
    if wmi_debug_level & WMI_LOG_INFO:
        logging.info(msg)

def display_debug(msg):
    if wmi_debug_level & WMI_LOG_DEBUG:
        logging.debug(msg)


###
# Constants
###

# OBJREF flags
OBJREF_STANDARD = 0x00000001
OBJREF_HANDLER  = 0x00000002
OBJREF_CUSTOM   = 0x00000004
OBJREF_EXTENDED = 0x00000008

# STDOBJREF flags
SORF_NOPING     = 0x00001000

# Context flags
CTXMSHLFLAGS_BYVAL = 0x00000002

# SpecialPropertiesData flags
SPD_FLAG_USE_CONSOLE_SESSION = 0x00000001

# [MS-DCOM] - 1.9 Standards Assignments
CLSID_ActivationContextInfo   = CLSID("000001a5-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesIn  = CLSID("00000338-0000-0000-c000-000000000046")
CLSID_ActivationPropertiesOut = CLSID("00000339-0000-0000-c000-000000000046")
CLSID_CONTEXT_EXTENSION       = CLSID("00000334-0000-0000-c000-000000000046")
CLSID_ContextMarshaler        = CLSID("0000033b-0000-0000-c000-000000000046")
CLSID_ERROR_EXTENSION         = CLSID("0000031c-0000-0000-c000-000000000046")
CLSID_ErrorObject             = CLSID("0000031b-0000-0000-c000-000000000046")
CLSID_InstanceInfo            = CLSID("000001ad-0000-0000-c000-000000000046")
CLSID_InstantiationInfo       = CLSID("000001ab-0000-0000-c000-000000000046")
CLSID_PropsOutInfo            = CLSID("00000339-0000-0000-c000-000000000046")
CLSID_ScmReplyInfo            = CLSID("000001b6-0000-0000-c000-000000000046")
CLSID_ScmRequestInfo          = CLSID("000001aa-0000-0000-c000-000000000046")
CLSID_SecurityInfo            = CLSID("000001a6-0000-0000-c000-000000000046")
CLSID_ServerLocationInfo      = CLSID("000001a4-0000-0000-c000-000000000046")
CLSID_SpecialSystemProperties = CLSID("000001b9-0000-0000-c000-000000000046")
IID_IActivation               = IID("4d9f4ab8-7d1c-11cf861e-0020af6e7c57")
IID_IActivationPropertiesIn   = IID("000001A2-0000-0000-C000-000000000046")
IID_IActivationPropertiesOut  = IID("000001A3-0000-0000-C000-000000000046")
IID_IContext                  = IID("000001c0-0000-0000-C000-000000000046")
IID_IObjectExporter           = IID("99fcfec4-5260-101bbbcb-00aa0021347a")
IID_IRemoteSCMActivator       = IID("000001A0-0000-0000-C000-000000000046")
IID_IRemUnknown               = IID("00000131-0000-0000-C000-000000000046")
IID_IRemUnknown2              = IID("00000143-0000-0000-C000-000000000046")
IID_IUnknown                  = IID("00000000-0000-0000-C000-000000000046")

###
# Datatypes defined in [MS-DTYP]
###

###
# [MS-DTYP] - 2.1.4.5 hyper
###

class _HYPER(Struct):

    st = [
        ['value', '<Q', 0 ]
    ]

    def __init__(self, value):
        Struct.__init__(self)
        self['value'] = value

    def __str__(self):
        return '[ %s: %#x ]' % (self.__class__.__name__, self['value'])

    ###
    # Getters/Setters
    ###
    def get_value(self):
        return self['value']

    def set_value(self, value):
        self['value'] = value

    ###
    # (De)Serialization API
    ###
    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            return self
        except Exception as e:
            display_error('%s.deserialize() failed: %s' % (self.__class__.__name__, str(e)))
            return None

###
# [MS-DTYP] - 2.3.4 GUID and UUID
###

class _UUID(Struct):

    st = [
        ['data1', '<L', 0 ],
        ['data2', '<H', 0 ],
        ['data3', '<H', 0 ],
        ['data4', '>H', 0 ],
        ['data5', '6s', '' ]
    ]

    def __init__(self, string):
        Struct.__init__(self)
        self._string = string
        self._parse_uuid()

    def __str__(self):
        return '[ %s: %s ]' % (self.__class__.__name__, self._string)

    def _parse_uuid(self):
        if self._string == '':
            self._string = "00000000-0000-0000-0000-000000000000"

        parts = self._string.split('-')
        if len(parts) != 5:
            raise AttributeError('Invalid %s string' % self.__class__.__name__)

        self['data1'] = struct.unpack('>L', parts[0].decode('hex'))[0]
        self['data2'] = struct.unpack('>H', parts[1].decode('hex'))[0]
        self['data3'] = struct.unpack('>H', parts[2].decode('hex'))[0]
        self['data4'] = struct.unpack('>H', parts[3].decode('hex'))[0]
        self['data5'] = struct.unpack('6s', parts[4].decode('hex'))[0]

    def _create_string(self):
        self._string =  '%08x-%04x-%04x-%04x-%s' % (self['data1'], self['data2'], self['data3'], self['data4'], self['data5'].encode('hex'))

    ###
    # Getters/Setters
    ###
    def get_string(self):
        return self._string

    def set_string(self, string):
        self._string = string
        self._parse_uuid(self['string'])

    ###
    # (De)Serialization API
    ###
    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self._create_string()
            return self
        except Exception as e:
            display_error('%s.deserialize() failed: %s' % (self.__class__.__name__, str(e)))
            return None


###
# [MS-DCOM] - 2.2.1 OID
###

class OID(_HYPER):
    def __init__(self, value=0):
        _HYPER.__init__(self, value)


###
# [MS-DCOM] - 2.2.2 SETID
###

class SETID(_HYPER):
    def __init__(self, value=0):
        _HYPER.__init__(self, value)

###
# [MS-DCOM] - 2.2.5 GUID
###

class GUID(_UUID):
    def __init__(self, string=''):
        _UUID.__init__(self, string)

###
# [MS-DCOM] - 2.2.6 CID
###

class CID(_UUID):
    def __init__(self, string=''):
        _UUID.__init__(self, string)

###
# [MS-DCOM] - 2.2.7 CLSID
###

class CLSID(_UUID):
    def __init__(self, string=''):
        _UUID.__init__(self, string)

###
# [MS-DCOM] - 2.2.8 IID
###

class IID(_UUID):
    def __init__(self, string=''):
        _UUID.__init__(self, string)

###
# [MS-DCOM] - 2.2.9 IPID
###

class IPID(_UUID):
    def __init__(self, string=''):
        _UUID.__init__(self, string)

###
# [MS-DCOM] - 2.2.10 OXID
###

class OXID(_HYPER):
    def __init__(self, value=0):
        _HYPER.__init__(self, value)

###
# [MS-DCOM] - 2.2.11 COMVERSION
###

class COMVERSION(Struct):

    st = [
        ['MajorVersion', '<H', 0 ],
        ['MinorVersion', '<H', 0 ]
    ]

    def __init__(self, majorVersion, minorVersion):
        Struct.__init__(self)
        self['MajorVersion'] = majorVersion
        self['MinorVersion'] = minorVersion

    def __str__(self):
        return '[ COMVERSION: MajorVersion=%d|MinorVersion=%d ]' % (self['MajorVersion'], self['MinorVersion'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            return self
        except Exception as e:
            display_error('COMVERSION.deserialize() failed: %s' % str(e))
            return None

###
# [MS-DCOM] - 2.2.13.1 ORPC_EXTENT
###

class ORPC_EXTENT(Struct):

    st = [
        ['size', '<I', 0 ],
        ['data', '', '']
    ]

    def __init__(self, id, data):
        Struct.__init__(self)
        self._guid = id
        self.set_data(data)

    def __str__(self):
        return '[ ORPC_EXTENT: Size=%d ]' % (self['size'])


    ###
    # Getters/Setters
    ###

    def set_data(self, data):
        size = len(data)
        self['size'] = size

        if size % 8 != 0:
            size = ((size / 8) + 1) * 8
            data = data.ljust(size, '\x00')

        st[1][1] = '%ds' % size if size != 0 else 's'
        self['data'] = data

    def get_data(self):
        return self['data']

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return self._guid.pack() + data

    def deserialize(self, data):
        try:
            self._guid = GUID().deserialize(data[:16])
            st[1][1] = '%ds' % len(data[16:] - 4)
            self.unpack(data[16:])
            return self
        except Exception as e:
            display_error('ORPC_EXTENT.deserialize() failed: %s' % str(e))
            return None

###
# [MS-DCOM] - 2.2.13.2 ORPC_EXTENT_ARRAY
###

class ORPC_EXTENT_ARRAY(Struct):

    st = [
        ['size', '<I', 0 ]
        ['reserved', '<I', 0]
    ]

    def __init__(self, orcp_extent_items):
        Struct.__init__(self)
        self._orcp_extent_items = orcp_extent_items
        self.set_orcp_extent_items(orcp_extent_items)

    def __str__(self):
        return '[ ORPC_EXTENT_ARRAY: Size=%d ]' % (self['size'])


    ###
    # Getters/Setters
    ###

    def set_orcp_extent_items(self, orcp_extent_items):
        self['size'] = len(orcp_extent_items)
        self._orcp_extent_items = orcp_extent_items
        if len(self._orcp_extent_items) & 1 == 1:
            self._orcp_extent_items.append(ORPC_EXTENT(GUID(), ''))


    def get_orcp_extent_items(self):
        return self._orcp_extent_items

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        for orcp_extent in orcp_extent_items:
            data += orcp_extent.pack()
        return data

    def deserialize(self, data):
        try:
            pos = 8
            self.unpack(data[:pos])
            self._orcp_extent_items = []

            for i in range(self['size']):
                orcp_extent = ORPC_EXTENT(GUID(), '').deserialize(data[pos:])
                size = orcp_extent['size'] 
                if size % 8 != 0:
                    pos += 20 + ((size / 8) + 1) * 8
                else:
                    pos += 20 + size
                self._orcp_extent_items.append(orcp_extent)
            
            return self
        except Exception as e:
            display_error('ORPC_EXTENT_ARRAY.deserialize() failed: %s' % str(e))
            return None

###
# [MS-DCOM] - 2.2.13.3 ORPCTHIS
###

class ORPCTHIS(Struct):

    st = [
        ['flags', '<I', 0 ]
        ['reserved1', '<I', 0]
    ]

    def __init__(self, version, cid, orcp_extent_array=None, flags=0, reserved1=0, ndrsize=8):
        Struct.__init__(self)
        self._version = version
        self._cid = cid
        self._orcp_extent_array = orcp_extent_array
        self._ndrsize = ndrsize

    def __str__(self):
        return '[ ORPCTHIS: version=%s|cid=%s|flags=%d ]' % (self._version, self._cid, self['flags'])


    ###
    # Getters/Setters
    ###

    def set_version(self, version):
        self._version = version

    def get_version(self):
        return self._version

    def set_cid(self, cid):
        self._cid = cid

    def get_cid(self):
        return self._cid

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self._version.pack()
        data += Struct.serialize(self)
        data += self._cid.pack()

        if not self._orcp_extent_array:
            self._orcp_extent_array = 0

        if self._ndrsize == 8:
            data += struct.pack('<Q', self._orcp_extent_array )            
        elif self._ndrsize == 4:
            data += struct.pack('<L', self._orcp_extent_array )   
        else:
            raise ValueError('Invalid size %d for ndrsize attribute.', self._ndrsize)

        return data

    def deserialize(self, data):
        try:
            self._version = COMVERSION(0, 0).deserialize(data[:4])
            self.unpack(data[4:12])
            self._cid = CID().deserialize(data[12:28])

            if self._ndrsize == 8:
                self._orcp_extent_array = struct.unpack('<Q', data[28:36])[0]
            elif self._ndrsize == 4:
                self._orcp_extent_array = struct.unpack('<L', data[28:32])[0]
            else:
                raise ValueError('Invalid size %d for ndrsize attribute.', self._ndrsize)

            return self
        except Exception as e:
            display_error('ORPCTHIS.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.13.3 ORPCTHIS
###

class ORPCTHAT(Struct):

    st = [
        ['flags', '<I', 0 ]
    ]

    def __init__(self, flags=0, orcp_extent_array=None, ndrsize=8):
        Struct.__init__(self)
        self['flags'] = flags
        self._ndrsize = ndrsize
        self._orcp_extent_array = orcp_extent_array

    def __str__(self):
        return '[ ORPCTHAT: flags=%d|orcp_extent_array=%#x ]' % (self['flags'], self._orcp_extent_array)


    ###
    # Getters/Setters
    ###

    def set_orcp_extent_array(self, orcp_extent_array):
        self._orcp_extent_array = orcp_extent_array

    def get_orcp_extent_array(self):
        return self._orcp_extent_array

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data = Struct.serialize(self)

        if not self._orcp_extent_array:
            self._orcp_extent_array = 0

        if self._ndrsize == 8:
            data += struct.pack('<Q', self._orcp_extent_array )            
        elif self._ndrsize == 4:
            data += struct.pack('<L', self._orcp_extent_array )   
        else:
            raise ValueError('Invalid size %d for ndrsize attribute.', self._ndrsize)

        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:4])

            if self._ndrsize == 8:
                self._orcp_extent_array = struct.unpack('<Q', data[4:12])[0]
            elif self._ndrsize == 4:
                self._orcp_extent_array = struct.unpack('<L', data[4:8])[0]
            else:
                raise ValueError('Invalid size %d for ndrsize attribute.', self._ndrsize)

            return self

        except Exception as e:
            display_error('ORPCTHAT.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.18 OBJREF
###

class OBJREF(Struct):

    st = [
        ['signature', '<I', 0x574f454d],
        ['flags', '<I', 0],
    ]

    def __init__(self, iid, ndrsize=8):
        Struct.__init__(self)
        self._iid = iid

    def __str__(self):
        return '[ OBJREF: iid=%s|flags=%d|sinature=%#x ]' % (self._iid, self['flags'], self['signature'])


    ###
    # Getters/Setters
    ###

    def set_iid(self, iid):
        self._iid = iid

    def get_iid(self):
        return self._iid

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self._iid.pack()
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:8])
            self._iid = IID().deserialize('<I', data[8:])
            return self
        except Exception as e:
            display_error('OBJREF.deserialize() failed: %s' % str(e))
            return None

###
# [MS-DCOM] - 2.2.18.2 STDOBJREF
###

class STDOBJREF(Struct):

    st = [
        ['flags', '<I', 0],
        ['cPublicRefs', '<I', 0]
    ]

    def __init__(self, oxid=OXID(), oid=OID(), ipid=IPID(), ndrsize=8):
        Struct.__init__(self)
        self._oxid = oxid
        self._oid  = oid
        self._ipid = ipid   

    def __str__(self):
        return '[ STDOBJREF: ipid=%s|oxid=%s|oid=%s |flags=%#x |cPublicRefs=%#x ]' % \
            (self._ipid, self._oxid, self._oid, self['flags'], self['cPublicRefs'])


    ###
    # Getters/Setters
    ###

    def set_ipid(self, ipid):
        self._ipid = ipid

    def get_ipid(self):
        return self._ipid

    def set_oxid(self, oxid):
        self._oxid = oxid

    def get_oxid(self):
        return self._oxid

    def set_oid(self, oid):
        self._oid = oid

    def get_oid(self):
        return self._oid


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self._oxid.pack()
        data += self._oid.pack()
        data += self._ipid.pack()
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:8])
            self._oxid = OXID().deserialize(data[8:16])
            self._oid  = OID().deserialize(data[16:24])
            self._ipid = IPID().deserialize(data[24:])
            return self
        except Exception as e:
            display_error('STDOBJREF.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.18.4 OBJREF_STANDARD
###

class OBJREF_STANDARD(Struct):

    st = [
    ]

    def __init__(self, std, saResAddr, ndrsize=8):
        Struct.__init__(self)
        self._std = std
        self._saResAddr = saResAddr

    def __str__(self):
        return '[ OBJREF_STANDARD: std=%s|saResAddr=%s ]' %  (self._std, self._saResAddr)


    ###
    # Getters/Setters
    ###

    def set_std(self, std):
        self._std = std

    def get_std(self):
        return self._std

    def set_saResAddr(self, saResAddr):
        self._saResAddr = saResAddr

    def get_saResAddr(self):
        return self._saResAddr

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self._std.pack()
        data += self._saResAddr.pack()
        return data

    def deserialize(self, data):
        try:
            self._std        = STDOBJREF().deserialize(data[:40])
            self._saResAddr  = DUALSTRINGARRAY().deserialize(data[40:])
            return self
        except Exception as e:
            display_error('OBJREF_STANDARD.deserialize() failed: %s' % str(e))
            return None 


###
# [MS-DCOM] - 2.2.18.5 OBJREF_HANDLER
###

class OBJREF_HANDLER(Struct):

    st = [
    ]

    def __init__(self, std, clsid, saResAddr, ndrsize=8):
        Struct.__init__(self)
        self._std = std
        self._clsid = clsid
        self._saResAddr = saResAddr

    def __str__(self):
        return '[ OBJREF_HANDLER: std=%s|clsid=%s|saResAddr=%s ]' %  (self._std, self._clsid, self._saResAddr)


    ###
    # Getters/Setters
    ###

    def set_std(self, std):
        self._std = std

    def get_std(self):
        return self._std

    def set_clsid(self, clsid):
        self._clsid = clsid

    def get_clsid(self):
        return self._clsid

    def set_saResAddr(self, saResAddr):
        self._saResAddr = saResAddr

    def get_saResAddr(self):
        return self._saResAddr

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self._std.pack()
        data += self._clsid.pack()
        data += self._saResAddr.pack()
        return data

    def deserialize(self, data):
        try:
            self._std       = STDOBJREF().deserialize(data[:40])
            self._clsid     = CLSID().deserialize(data[40:56]) 
            self._saResAddr = DUALSTRINGARRAY().deserialize(data[56:])
            return self
        except Exception as e:
            display_error('OBJREF_HANDLER.deserialize() failed: %s' % str(e))
            return None 


###
# [MS-DCOM] - 2.2.18.6 OBJREF_CUSTOM
###

class OBJREF_CUSTOM(Struct):

    st = [
        ['cbExtension', '<I', 0],
        ['reserved', '<I', 0]
    ]

    def __init__(self, clsid, pObjectData='', ndrsize=8):
        Struct.__init__(self)
        self._clsid = clsid
        self._pObjectData = pObjectData

    def __str__(self):
        return '[ OBJREF_CUSTOM: clsid=%s ]' % self._clsid

    ###
    # Getters/Setters
    ###

    def set_clsid(self, clsid):
        self._clsid = clsid

    def get_clsid(self):
        return self._clsid

    def set_pObjectData(self, pObjectData):
        self._pObjectData = pObjectData

    def get_pObjectData(self):
        return self._pObjectData

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self._clsid.pack()
        data += Struct.serialize(self)
        data += self._pObjectData
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[16:24])
            self._clsid       = CLSID().deserialize(data[:16])            
            self._pObjectData = data[24:]
            return self
        except Exception as e:
            display_error('OBJREF_CUSTOM.deserialize() failed: %s' % str(e))
            return None 


###
# [MS-DCOM] - 2.2.18.7 OBJREF_EXTENDED
###

class OBJREF_EXTENDED(Struct):

    st = [
        ['nElms', '<I', 0x00000001],
        ['Signature2', '<I', 0x4E535956]
    ]

    def __init__(self, std, saResAddr, ElmArray, ndrsize=8):
        Struct.__init__(self)
        self._Signature1 = 0x4E535956
        self._std = std
        self._saResAddr = saResAddr
        self._ElmArray = ElmArray

    def __str__(self):
        return '[ OBJREF_EXTENDED: std=%s|saResAddr=%s|ElmArray=%s ]' %  (self._std, self._saResAddr, self._ElmArray)


    ###
    # Getters/Setters
    ###

    def set_std(self, std):
        self._std = std

    def get_std(self):
        return self._std

    def set_saResAddr(self, saResAddr):
        self._saResAddr = saResAddr

    def get_saResAddr(self):
        return self._saResAddr

    def set_ElmArray(self, ElmArray):
        self._ElmArray = ElmArray

    def get_ElmArray(self):
        return self._ElmArray


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = self._std.pack()
        data += struct.pack('<I', self._Signature1)
        data += self._saResAddr.pack()
        data += Struct.serialize(self)
        data += self._ElmArray.pack()
        return data

    def deserialize(self, data):
        try:
            self._std        = STDOBJREF().deserialize(data[:40])
            self._Signature1 = struct.unpack('<I', data[40:44])
            self._saResAddr  = DUALSTRINGARRAY().deserialize(data[44:])
            pos = 44 + len(self._saResAddr.pack())
            self.unpack(data[pos:pos + 8])
            self._ElmArray   = DATAELEMENT().deserialize(data[pos + 8:])
            return self
        except Exception as e:
            display_error('OBJREF_EXTENDED.deserialize() failed: %s' % str(e))
            return None 


###
# [MS-DCOM] - 2.2.18.8 DATAELEMENT
###

class DATAELEMENT(Struct):

    st = [
        ['cbSize', '<I', 0 ],
        ['cbRounded', '<I', 0 ],
        ['data', '', '']
    ]

    def __init__(self, dataID, data):
        Struct.__init__(self)
        self._dataID = dataID
        self.set_data(data)

    def __str__(self):
        return '[ DATAELEMENT: cbSize=%d|data=%s ]' % (self['cbSize'], self['data'].encode('hex'))


    ###
    # Getters/Setters
    ###

    def set_data(self, data):
        size = len(data)
        self['cbSize'] = size

        if size % 8 != 0:
            size = ((size / 8) + 1) * 8
            data = data.ljust(size, '\x00')

        st[2][1] = '%ds' % size if size != 0 else 's'
        self['data'] = data
        self['cbRounded'] = size

    def get_data(self):
        return self['data']

    def set_dataID(self, dataID):
        self._dataID = dataID

    def get_dataID(self):
        return self._dataID

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return self._dataID.pack() + data

    def deserialize(self, data):
        try:
            self._dataID = GUID().deserialize(data[:16])
            st[2][1] = '%ds' % len(data[16:] - 8)
            self.unpack(data[16:])
            return self
        except Exception as e:
            display_error('DATAELEMENT.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.19.1 DUALSTRINGARRAY (Packet Version)
###

class DUALSTRINGARRAY(Struct):

    st = [
        ['wNumEntries', '<I', 0 ],
        ['wSecurityOffset', '<I', 0 ]
    ]

    def __init__(self, stringbindings=[], securitybindings=[]):
        Struct.__init__(self)
        self._stringbindings = stringbindings
        self._securitybindings = securitybindings
        self.__process_arrays()

    def __str__(self):
        return '[ DUALSTRINGARRAY: wNumEntries=%d ]' % (self['wNumEntries'])


    ###
    # Getters/Setters
    ###

    def set_stringbindings(self, stringbindings):
        self._stringbindings = stringbindings
        self.__process_arrays()

    def get_stringbindings(self):
        return self._stringbindings

    def set_securitybindings(self, securitybindings):
        self._securitybindings = securitybindings
        self.__process_arrays()

    def get_securitybindings(self):
        return self._securitybindings

    ###
    # Proccess stringbindings and securitybindings
    ###

    def __process_arrays(self):
        wNumEntries = 0
        wSecurityOffset = 0
        for stringbinding in self._stringbindings:
            wNumEntries += len(stringbinding.pack()) / 2

        if len(self._stringbindings) == 0:
            wNumEntries += 1  # empty StringBinding array

        wNumEntries += 1  # nullterm1

        wSecurityOffset = wNumEntries
        for secbinding in self._securitybindings:
            wNumEntries += len(secbinding.pack()) / 2

        if len(self._stringbindings) == 0:
            wNumEntries += 1  # empty SecBinding array

        wNumEntries += 1  # nullterm2

        self['wNumEntries'] = wNumEntries
        self['wSecurityOffset'] = wSecurityOffset
       
    ###
    # (De)Serialization API
    ###

    def pack(self):        
        data  = Struct.serialize(self)

        if len(self._stringbindings) > 0:
            for stringbinding in self._stringbindings:
                data += stringbinding.pack()
        else:
            data += "\x00\x00"  # empty StringBinding array

        data += "\x00\x00"  # nullterm1

        if len(self._securitybindings) > 0:
            for secbinding in self._securitybindings:
                data += secbinding.pack()
        else:
            data += "\x00\x00"  # empty SecBinding array

        data += "\x00\x00"  # nullterm2

        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:4])  # unpack wNumEntries and wSecurityOffset

            wNumEntries = self['wNumEntries'] 
            wSecurityOffset = self['wSecurityOffset'] 

            self._stringbindings = [] 
            self._securitybindings = []

            if data[4:8] == '\x00\x00\x00\x00' and wSecurityOffset == 2:
                pass  # empty StringBinding array
            else:
                pos = 0
                while pos != wSecurityOffset - 2:
                    stringbinding = STRINGBINDING(data[pos+4:])
                    self._stringbindings.append(stringbinding)
                    pos += len(stringbinding.pack())


            if data[wSecurityOffset:wSecurityOffset+4] == '\x00\x00\x00\x00' and wNumEntries == wSecurityOffset + 2:
                pass  # empty SecBinding array
            else:
                pos = wSecurityOffset
                while pos != wNumEntries - 2:
                    secbinding = SECURITYBINDING(data[pos+4:])
                    self._secbindings.append(secbinding)
                    pos += len(secbinding.pack())

            return self
        except Exception as e:
            display_error('DUALSTRINGARRAY.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.19.3 STRINGBINDING
###

class STRINGBINDING(Struct):

    st = [
        ['wTowerId', '<H', 0 ]
    ]

    def __init__(self, aNetworkAddr=''):
        Struct.__init__(self)
        self._aNetworkAddr = aNetworkAddr

    def __str__(self):
        return '[ STRINGBINDING: wTowerId=%d|aNetworkAddr=%s ]' % (self['wTowerId'], self._aNetworkAddr)


    ###
    # Getters/Setters
    ###

    def set_aNetworkAddr(self, aNetworkAddr):
        self._aNetworkAddr = aNetworkAddr

    def get_aNetworkAddr(self):
        return self._aNetworkAddr

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self._aNetworkAddr.encode('utf-16le')
        data += "\x00\x00"
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:2])
            pos = data[2:].find('\x00\x00')
            if pos < 0:
                raise ValueError("Invalid STRINGBINDING[%s]" % data.encode('hex'))
            self._aNetworkAddr = data[2:pos+2]
            return self
        except Exception as e:
            display_error('STRINGBINDING.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.19.4 SECURITYBINDING
###

class SECURITYBINDING(Struct):

    st = [
        ['wAuthnSvc', '<H', 0 ],
        ['Reserved', '<H', 0xFFFF ]
    ]

    def __init__(self, aPrincName=''):
        Struct.__init__(self)
        self._aPrincName = aPrincName

    def __str__(self):
        return '[ SECURITYBINDING: wAuthnSvc=%d|aPrincName=%s ]' % (self['wAuthnSvc'], self._aPrincName)


    ###
    # Getters/Setters
    ###

    def set_aPrincName(self, aPrincName):
        self._aPrincName = aPrincName

    def get_aPrincName(self):
        return self._aPrincName

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self._aNetworkAddr.encode('utf-16le')
        data += "\x00\x00"
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:4])
            pos = data[4:].find('\x00\x00')
            if pos < 0:
                raise ValueError("Invalid SECURITYBINDING[%s]" % data.encode('hex'))
            self._aNetworkAddr = data[4:pos+2]
            return self
        except Exception as e:
            display_error('SECURITYBINDING.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.20 Context
###

class Context(Struct):

    st = [
        ['MajorVersion', '<H', 0x0001],
        ['MinVersion', '<H', 0x0001],
        ['ContextId', '16s', ''],  # GUID
        ['Flags', '<I', CTXMSHLFLAGS_BYVAL],
        ['Reserved', '<I', 0],
        ['dwNumExtents', '<I', 0],
        ['cbExtents', '<I', 0],
        ['MshlFlags', '<I', 0],
        ['Count', '<I', 0],
        ['Frozen', '<I', 0]
    ]

    def __init__(self, ContextId=GUID(), PropMarshalHeader=[]):
        Struct.__init__(self)
        self._ContextId = ContextId
        self._PropMarshalHeader = PropMarshalHeader

    def __str__(self):
        return '[ Context: ContextID=%s|Count=%d ]' % (self._ContextId, self['Count'])


    ###
    # Getters/Setters
    ###

    def set_ContextId(self, ContextId):
        self._ContextId = ContextId

    def get_ContextId(self):
        return self._ContextId

    def set_PropMarshalHeader(self, PropMarshalHeader):
        self._PropMarshalHeader = PropMarshalHeader

    def get_PropMarshalHeader(self):
        return self._PropMarshalHeader

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['ContextId'] = self._ContextId.pack()
        self['Count'] = len(self._PropMarshalHeader)
        data  = Struct.serialize(self)
        for entry in self._PropMarshalHeader:
            data += entry.pack()
        return data

    def deserialize(self, data):
        try:
            self.unpack(data[:48])
            self._ContextId = GUID().deserialize(data[4:20])
            self._PropMarshalHeader = []
            pos = 48
            for i in range(self['Count']):
                entry = PROPMARSHALHEADER().deserialize(data[pos:])
                pos += len(entry.pack())
                self._PropMarshalHeader.append(entry)

            return self
        except Exception as e:
            display_error('Context.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.19.4 PROPMARSHALHEADER
###

class PROPMARSHALHEADER(Struct):

    st = [
        ['clsid', '16s', ''],
        ['policyId', '16s', ''],
        ['flags', '<I', 0],
        ['cb', '<I', 0],
        ['ctxProperty', '', ''],
    ]

    def __init__(self, clsid=CLSID(), policyId=GUID(), ctxProperty=b''):
        Struct.__init__(self)
        self._clsid = None
        self._policyId = None
        self.set_clsid(clsid)
        self.set_policyId(policyId)
        self.set_ctxProperty(ctxProperty)

    def __str__(self):
        return '[ PROPMARSHALHEADER: clsid=%s|policyId=%s|cb=%d ]' % (self['wAuthnSvc'], self['cb'])


    ###
    # Getters/Setters
    ###

    def set_clsid(self, clsid):
        self._clsid = clsid
        self['clsid'] = clsid.pack()

    def get_clsid(self):
        return self._clsid

    def set_policyId(self, policyId):
        self._policyId = policyId
        self['policyId'] = policyId.pack()

    def get_policyId(self):
        return self._policyId

    def set_ctxProperty(self, ctxProperty):
        self['ctxProperty'] = ctxProperty
        self['cb'] = len(ctxProperty)

        st[4][1] = '%ds' % self['cb'] if self['cb'] > 0 else '0s'

    def get_ctxProperty(self):
        return self._ctxProperty
       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            cb = len(data) - 40
            st[4][1] = '%ds' % cb if cb > 0 else '0s'
            self.unpack(data)
            return self
        except Exception as e:
            display_error('PROPMARSHALHEADER.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.21.2 Custom-Marshaled Error Information Format
###

class ORPC_ERROR_OBJECT(Struct):

    st = [
        ['dwVersion', '<I', 0],
        ['dwHelpContext', '<I', 0],
        ['iid', '16s', ''],

        ['dwSourceSignature', '<I', 0],
        ['Source', '', ''],

        ['dwDescriptionSignature', '<I', 0],
        ['Description', '', ''],

        ['dwHelpFileSignature', '<I', 0],
        ['HelpFile', '', '']
    ]

    def __init__(self, iid, Source=None, Description=None, HelpFile=None):
        Struct.__init__(self)
        self._iid = None
        self._Source = None
        self._Description = None
        self._HelpFile = None
        self.set_iid(iid)
        self.set_Source(Source)
        self.set_Description(Description)
        self.set_HelpFile(HelpFile)

    def __str__(self):
        return '[ ORPC_ERROR_OBJECT: iid=%s|Source=%s|Description=%s|HelpFile=%s ]' % (self._iid, self['Source'], self['Description'], self['HelpFile'])


    ###
    # Getters/Setters
    ###

    def set_iid(self, iid):
        self._iid= iid
        self['iid'] = iid.pack()

    def get_iid(self):
        return self._iid

    def set_Source(self, Source):
        if Source is None:
            self['dwSourceSignature'] = 0x00000000
            st[4][1] = '0s'
        else:
            self['dwSourceSignature'] = 0xFFFFFFFF
            st[4][1] = '%ds' % len(Source.pack())

        self['Source'] = Source.pack() if Source is not None else ''
        self._Source = Source

    def get_Source(self):
        return self._Source

    def set_Description(self, Description):
        if Description is None:
            self['dwDescriptionSignature'] = 0x00000000
            st[6][1] = '0s'
        else:
            self['dwDescriptionSignature'] = 0xFFFFFFFF
            st[6][1] = '%ds' % len(Description.pack())

        self['Description'] = Description.pack() if Description is not None else ''
        self._Description = Description

    def get_Description(self):
        return self._Description

    def set_HelpFile(self, HelpFile):
        if HelpFile is None:
            self['dwHelpFileSignature'] = 0x00000000
            st[8][1] = '0s'
        else:
            self['dwHelpFileSignature'] = 0xFFFFFFFF
            st[8][1] = '%ds' % len(HelpFile.pack())

        self['HelpFile'] = HelpFile.pack() if HelpFile is not None else ''
        self._HelpFile = HelpFile

    def get_HelpFile(self):
        return self._HelpFile
       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            pos = 24

            is_present = struct.unpack('<I', data[pos:pos+4])[0]

            if is_present:
                error = ErrorInfoString().deserialize(data[pos+4:])
                st[4][1] = '%ds' % len(error.pack())
                pos += len(error.pack())
            else:
                st[4][1] = '0s'
                pos += 4

            is_present = struct.unpack('<I', data[pos:pos+4])[0]

            if is_present:
                error = ErrorInfoString().deserialize(data[pos+4:])
                st[6][1] = '%ds' % len(error.pack())
                pos += len(error.pack())
            else:
                st[6][1] = '0s'
                pos += 4

            is_present = struct.unpack('<I', data[pos:pos+4])[0]

            if is_present:
                error = ErrorInfoString().deserialize(data[pos+4:])
                st[8][1] = '%ds' % len(error.pack())
                pos += len(error.pack())
            else:
                st[8][1] = '0s'

            self.unpack(data)
            return self
        except Exception as e:
            display_error('ORPC_ERROR_OBJECT.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.21.3 ErrorInfoString
###

class ErrorInfoString(Struct):

    st = [
        ['dwMax', '<I', 0],
        ['dwOffSet', '<I', 0],
        ['dwActual', '<I', 0],
        ['Name', '', '']
    ]

    def __init__(self, Name):
        Struct.__init__(self)
        self._Name = ''
        self.set_Name(Name)

    def __str__(self):
        return '[ ErrorInfoString: Name=%s ]' % self._Name


    ###
    # Getters/Setters
    ###

    def set_Name(self, Name):
        self._Name = Name
        self['dwMax'] = len(Name) + 1
        self['dwActual'] = self['dwMax']
        name_unicode = Name.encode('utf-16le') + "\x00\x00"
        st[3][1] = '%ds' % len(name_unicode)
        self['Name'] = name_unicode

    def get_Name(self):
        return self._Name

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            dwMax = struct.unpack('<I', data[:4])[0]
            st[3][1] = '%ds' % dwMax
            self.unpack(data)
            return self
        except Exception as e:
            display_error('ErrorInfoString.deserialize() failed: %s' % str(e))
            return None

###
# [MS-DCOM] - 2.2.21.4 Context ORPC Extension
###

class ORPC_CONTEXT_EXTENT(Struct):

    st = [
        ['Signature', '<I', 0x414E554B],
        ['Version', '<I', 0x00010000],
        ['cPolicies', '<I', 0],
        ['cbBuffer', '<I', 0],
        ['cbSize', '<I', 0],
        ['hr', '<I', 0],
        ['hrServer', '<I', 0],
        ['reserved', '<I', 0],
        ['EntryHeader', '', ''],
        ['PolicyData', '', '']
    ]

    def __init__(self, EntryHeaderArray, PolicyDataArray):
        Struct.__init__(self)
        self._EntryHeader = []
        self._PolicyData  = []
        self.set_EntryHeader(EntryHeaderArray)
        self.set_PolicyData(PolicyDataArray)

    def __str__(self):
        return '[ ORPC_CONTEXT_EXTENT: cPolicies=%d ]' % self._Name


    ###
    # Getters/Setters
    ###

    def set_EntryHeader(self, EntryHeaderArray):
        cbSize = 32
        entryData = ''
        for entry in EntryHeaderArray:
            currentData = entry.pack()
            cbSize += len(currentData)
            entryData += currentData

        self['cbSize'] = cbSize
        st[8][1] = '%ds' % len(entryData)
        self['EntryHeader'] = entryData
        self._EntryHeader = EntryHeaderArray


    def get_EntryHeader(self):
        return self._EntryHeader

    def set_PolicyData(self, PolicyDataArray):
        self['cPolicies'] = len(PolicyDataArray)

        entryData = ''
        for entry in PolicyDataArray:
            entryData += entry

        st[9][1] = '%ds' % len(entryData)
        self['PolicyData'] = entryData
        self._PolicyData = PolicyDataArray

    def get_PolicyData(self):
        return self._PolicyData
       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self._EntryHeader = []
            self._PolicyData  = []

            cbSize = struct.unpack('<I', data[16:20])[0]
            cPolicies = struct.unpack('<I', data[8:12])[0]
            pos = 32
            sizePolicyData = 0
            for i in range(cPolicies):
                entry = EntryHeader().serialize(data[pos:pos+32])
                pos += 32
                currentSize = entry['cbEHBuffer']
                currentOffset = entry['cbSize']
                sizePolicyData += currentSize
                self._EntryHeader.append(entry)
                self._PolicyData.append(data[cbSize+currentOffset:cbSize+currentOffset+currentSize])

            st[8][1] = '%ds' % (pos - 32)
            st[9][1] = '%ds' % sizePolicyData

            self.unpack(data)
            return self
        except Exception as e:
            display_error('ORPC_CONTEXT_EXTENT.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.21.5 EntryHeader
###

class EntryHeader(Struct):

    st = [
        ['Signature', '<I', 0x494E414E],
        ['cbEHBuffer', '<I', 0],
        ['cbSize', '<I', 0],
        ['reserved', '<I', 0],
        ['policyID', '16s', '']
    ]

    def __init__(self, policyID=GUID()):
        Struct.__init__(self)
        self._policyID = policyID
        self.set_policyID(policyID)

    def __str__(self):
        return '[ EntryHeader: policyID=%s ]' % self._policyID


    ###
    # Getters/Setters
    ###

    def set_policyID(self, policyID):
        self._policyID = policyID
        self['policyID'] = self._policyID.pack()

    def get_policyID(self):
        return self._policyID

       
    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self._policyID = GUID().deserialize(data[16:32])
            return self
        except Exception as e:
            display_error('EntryHeader.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22 Activation Properties BLOB
###

class ActivationPropertiesBLOB(Struct):

    st = [
        ['dwSize', '<I', 0],
        ['dwReserved', '<I', 0],
        ['CustomHeader', '', ''],
        ['Property', '', '']
    ]

    def __init__(self, Header=CustomHeader(), Property=[]):
        Struct.__init__(self)
        self._CustomHeader = []
        self._Property = []
        self.set_CustomHeader(Header)
        self.set_Property(Property)

    def __str__(self):
        return '[ ActivationPropertiesBLOB: policyID=%s ]' % self._policyID


    ###
    # Getters/Setters
    ###

    def set_CustomHeader(self, CustomHeader):
        self._CustomHeader = CustomHeader
        st[2][1] = '%ds' % len(self._CustomHeader.pack())
        self['CustomHeader'] = self._CustomHeader.pack()

    def get_CustomHeader(self):
        return self._CustomHeader

    def set_Property(self, Property):
        self._Property = Property

        data = ''
        for entry in Property:
            data += entry.pack()

        st[3][1] = '%ds' % len(data)
        self['Property'] = data

    def get_Property(self):
        return self._Property

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        self['dwSize'] = len(data) - 8
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            
            header = CustomHeader().deserialize(data[8:])
            self._CustomHeader = header

            cIfs = header['cIfs']
            pclsid = header.get_pclsid()            
            st[2][1] = '%ds' % len(header.pack())

            propertiesData = ''
            pos = 8 + len(header.pack())

            self._Property = []
            for i in range(cIfs)
                if pclsid[i].get_string() == CLSID_InstantiationInfo:
                    prop = InstantiationInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_SpecialPropertiesData:
                    prop = SpecialPropertiesData(data[pos:])
                elif pclsid[i].get_string() == CLSID_InstanceInfoData:
                    prop = InstanceInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_ScmRequestInfoData:
                    prop = ScmRequestInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_ActivationContextInfoData:
                    prop = ActivationContextInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_LocationInfoData:
                    prop = LocationInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_SecurityInfoData:
                    prop = SecurityInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_ScmReplyInfoData:
                    prop = ScmReplyInfoData(data[pos:])
                elif pclsid[i].get_string() == CLSID_PropsOutInfo:
                    prop = PropsOutInfo(data[pos:])

                pos += len(prop.pack())
                propertiesData += prop.pack()
                self._Property.append(prop)

            st[3][1] = '%ds' % len(propertiesData)
            self.unpack(data)
            return self
        except Exception as e:
            display_error('ActivationPropertiesBLOB.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.1 CustomHeader
###

class CustomHeader(Struct):

    st = [
        ['totalSize',  '<I', 0],
        ['headerSize', '<I', 0],
        ['dwReserved', '<I', 0],
        ['destCtx',    '<I', 0],
        ['cIfs',       '<I', 0],
        ['classInfoClsid', '16s', ''],
        ['pclsid',     '', ''],
        ['pSizes',     '', ''],
        ['pdwReserved','<I', 0]
    ]

    def __init__(self, properties, ndrsize=8):
        Struct.__init__(self)
        self._properties = []
        self._pclsid = []
        self._pSizes = []
        self._classInfoClsid = GUID()
        self._ndrsize = ndrsize
        self.set_properties(properties)

    def __str__(self):
        return '[ CustomHeader: cIfs=%s ]' % self['cIfs']


    ###
    # Getters/Setters
    ###

    def set_properties(self, properties):
        self._properties = []

        pclsid = ''
        pSizes = ''
        headerSize = 36
        propertiesSize = 0

        for prop in self._properties:
            self._properties.append(prop)
            self._pSizes.append(len(prop.pack()))
            pSizes += struct.pack('<I', len(prop.pack()))
            clsid = None
            if isinstance(prop, InstantiationInfoData):
                clsid = CLSID(CLSID_InstantiationInfo)
            elif isinstance(prop, SpecialPropertiesData):
                clsid = CLSID(CLSID_SpecialPropertiesData)
            elif isinstance(prop, InstanceInfoData):
                clsid = CLSID(CLSID_InstanceInfoData)
            elif isinstance(prop, ScmRequestInfoData):
                clsid = CLSID(CLSID_ScmRequestInfoData)
            elif isinstance(prop, ActivationContextInfoData):
                clsid = CLSID(CLSID_ActivationContextInfoData)
            elif isinstance(prop, LocationInfoData):
                clsid = CLSID(CLSID_LocationInfoData)
            elif isinstance(prop, SecurityInfoData):
                clsid = CLSID(CLSID_SecurityInfoData)
            elif isinstance(prop, ScmReplyInfoData):
                clsid = CLSID(CLSID_ScmReplyInfoData)
            elif isinstance(prop, PropsOutInfo):
                clsid = CLSID(CLSID_PropsOutInfo)

            propertiesSize += len(prop.pack()) 
            headerSize += 16 + 4 

            self._pclsid.append(clsid)
            pclsid += clsid.pack()

        headerSize += self._ndrsize
        self['headerSize'] = headerSize
        self['totalSize']  = headerSize + propertiesSize

        st[6][1] = '%ds' % len(pclsid)
        st[7][1] = '%ds' % len(pSizes)

        self['pclsid'] = pclsid
        self['pSizes'] = pSizes
        self['cIfs']   = len(self._properties)

    def get_properties(self):
        return self._properties


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self._properties = []
            cIfs = struct.unpack('<I', data[16:20])[0]
            
            pSizesLen = 4 * cIfs
            pclsidLen = 16 * cIfs            

            st[6][1] = '%ds' % len(pclsidLen)
            st[7][1] = '%ds' % len(pSizesLen)

            self.unpack(data)
            return self
        except Exception as e:
            display_error('CustomHeader.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.1 InstantiationInfoData
###

class InstantiationInfoData(Struct):

    st = [
        ['classId', '16s', ''],
        ['classCtx', '<I', 0],
        ['actvflags', '<I', 0],
        ['fIsSurrogate', '<I', 0],
        ['cIID', '<I', 0],
        ['instFlag', '<I', 0],
        ['pIID', '', ''],
        ['thisSize', '<I', 0],
        ['clientCOMVersion', '4s', '']
    ]

    def __init__(self, classId, pIID=[], clientCOMVersion=None):
        Struct.__init__(self)
        self._classId = None
        self._pIID = None
        self._clientCOMVersion = None
        self.set_classId(classId)
        self.set_pIID(pIID)
        self.set_clientCOMVersion(clientCOMVersion)

    def __str__(self):
        return '[ InstantiationInfoData: thisSize=%s ]' % self['thisSize']


    ###
    # Getters/Setters
    ###

    def set_classId(self, classId):
        self._classId = classId
        self['classId'] = classId.pack()

    def get_classId(self):
        return self._classId

    def set_pIID(self, pIID):
        self._pIID = []        
        data = ''
        for iid in pIID:
            self._PIID.append(iid)
            data += iid.pack()

        st[6][1] = "%ds" % len(data)
        self['pIID'] = data
        self['cIID'] = len(pIID)
        self['thisSize'] = self['cIID'] + 44

    def get_pIID(self):
        return self._pIID

    def set_clientCOMVersion(self, clientCOMVersion):
        if clientCOMVersion is None:
            clientCOMVersion = COMVERSION(5,1)
        self._clientCOMVersion = clientCOMVersion
        self['clientCOMVersion'] clientCOMVersion.pack()

    def get_clientCOMVersion(self):
        return self._clientCOMVersion

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self._pIID = []
            cIID = struct.unpack('<I', data[28:32])[0]
            pIID = len(CLSID().pack()) * cIID
            st[6][1] = "%ds" % pIID
            self.unpack(data)
            self._classId = CLSID().deserialize(data[:16])
            self._clientCOMVersion = COMVERSION().deserialize(data[-4:])

            pos2pIID = 36
            for i in range(cIID):
                iid = CLSID().deserialize(data[pos2pIID:pos2pIID+16])
                self._pIID.append(iid)
                pos2pIID += len(iid.pack())

            return self
        except Exception as e:
            display_error('InstantiationInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.2 SpecialPropertiesData
###

class SpecialPropertiesData(Struct):

    st = [
        ['dwSessionId', '<I', 0],
        ['fRemoteThisSessionId', '<I', 0],
        ['fClientImpersonating', '<I', 0],
        ['fPartitionIDPresent', '<I', 0],
        ['dwDefaultAuthnLvl', '<I', 0],
        ['guidPartition', '16s', 0],
        ['dwPRTFlags', '<I', ''],
        ['dwOrigClsctx', '<I', 0],
        ['dwFlags', '<I', 0],
        ['Reserved1', '<I', 0],
        ['Reserved2', '<I', 0],
        ['Reserved3', '<I', 0],
        ['Reserved4', '<I', 0],
        ['Reserved5', '<I', 0],
        ['Reserved6', '<I', 0],
        ['Reserved7', '<I', 0],
        ['Reserved8', '<I', 0],
    ]

    def __init__(self, dwSessionId=0xFFFFFFFF, guidPartition=GUID(), flags=SPD_FLAG_USE_CONSOLE_SESSION):
        Struct.__init__(self)
        self._dwSessionId = 0
        self._guidPartition = None
        self['dwFlags'] = flags
        self.set_dwSessionId(dwSessionId)
        self.set_guidPartition(guidPartition)

    def __str__(self):
        return '[ SpecialPropertiesData: dwFlags=%s ]' % self['dwFlags']


    ###
    # Getters/Setters
    ###

    def set_dwSessionId(self, dwSessionId):
        self._dwSessionId = dwSessionId
        self['dwSessionId'] = dwSessionId

        if dwSessionId != 0xFFFFFFFF:
            self['fRemoteThisSessionId'] = 0x00000001
        else:
            self['fRemoteThisSessionId'] = 0x00000000

    def get_dwSessionId(self):
        return self._dwSessionId

    def set_guidPartition(self, guidPartition):
        self._guidPartition = guidPartition
        self['guidPartition'] = guidPartition.pack()

    def get_guidPartition(self):
        return self._guidPartition

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self._guidPartition = GUID().deserialize(self['guidPartition'])
            self._dwSessionId = self['dwSessionId']
            return self
        except Exception as e:
            display_error('SpecialPropertiesData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.3 InstanceInfoData
###

class InstanceInfoData(Struct):

    st = [
        ['fileName', '', ''],
        ['mode', '<I', 0],
        ['ifdROT', '<I', 0],  # I'm not sure this is correct 
        ['ifdStg', '<I', 0]   # I'm not sure this is correct 
    ]

    def __init__(self, fileName='', ndrsize=8):
        Struct.__init__(self)
        self._fileName = ''
        self._ndrsize = ndrsize
        self.set_fileName(fileName)

    def __str__(self):
        return '[ InstanceInfoData: fileName=%s ]' % self._fileName


    ###
    # Getters/Setters
    ###

    def set_fileName(self, fileName):
        self._fileName = fileName
        data  = fileName.encode('utf-16le')
        data += "\x00\x00"
        st[0][1] = "%ds" % len(data)
        self['fileName'] = data

    def get_fileName(self):
        return self._fileName

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self._ndrsize == 8:
            st[2][1] = '<Q'
            st[3][1] = '<Q'
        else:
            st[2][1] = '<I'
            st[3][1] = '<I'

        return data

    def deserialize(self, data):
        try:
            if self._ndrsize == 8:
                st[2][1] = '<Q'
                st[3][1] = '<Q'
            else:
                st[2][1] = '<I'
                st[3][1] = '<I'
            
            posNullByte = data.find('\x00\x00')
            if posNullByte > 0:
                st[0][1] = "%ds" % (posNullByte + 2)
            else:
                raise ValueError('Invalid data for attribute fileName.')
            self._fileName = data[:posNullByte].decode('utf-16le')
            self.unpack(data)
            return self
        except Exception as e:
            display_error('InstanceInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.4 ScmRequestInfoData
###

class ScmRequestInfoData(Struct):

    st = [
        ['pdwReserved', '<I', 0],
        ['remoteRequest', '', '']
    ]

    def __init__(self, remoteRequest=None):
        Struct.__init__(self)
        self._remoteRequest = ''
        self.set_remoteRequest(fileName)

    def __str__(self):
        return '[ ScmRequestInfoData: fileName=%s ]' % self._fileName


    ###
    # Getters/Setters
    ###

    def set_remoteRequest(self, remoteRequest):
        self._remoteRequest = remoteRequest

        if remoteRequest is None:
            st[1][1] = '0s'
            self['remoteRequest'] = ''
        else:
            st[1][1] = '%ds' % len(remoteRequest.pack())
            self['remoteRequest'] = remoteRequest.pack()

    def get_remoteRequest(self):
        return self._remoteRequest

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            remoteRequest = customREMOTE_REQUEST_SCM_INFO().deserialize(data[4:])
            self.set_remoteRequest(remoteRequest)
            self.unpack(data)
            return self
        except Exception as e:
            display_error('ScmRequestInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.4.1 customREMOTE_REQUEST_SCM_INFO
###

class customREMOTE_REQUEST_SCM_INFO(Struct):

    st = [
        ['ClientImpLevel', '<I', 2],
        ['cRequestedProtseqs', '<I', 0],
        ['pRequestedProtseqs', '0s', '']
    ]

    def __init__(self, pRequestedProtseqs=''):
        Struct.__init__(self)
        self.set_pRequestedProtseqs(pRequestedProtseqs)

    def __str__(self):
        return '[ customREMOTE_REQUEST_SCM_INFO: pRequestedProtseqs=%s ]' % self._pRequestedProtseqs


    ###
    # Getters/Setters
    ###

    def set_pRequestedProtseqs(self, pRequestedProtseqs):
        self['cRequestedProtseqs'] = len(pRequestedProtseqs) / 2
        st[2][1] = '%ds' % len(pRequestedProtseqs)
        self['pRequestedProtseqs'] = pRequestedProtseqs

    def get_pRequestedProtseqs(self):
        return self['pRequestedProtseqs']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            cRequestedProtseqs = struct.unpack('<I', data[4:8])[0]
            st[2][1] = '%ds' % (cRequestedProtseqs * 2)
            self.unpack(data)
            return self
        except Exception as e:
            display_error('customREMOTE_REQUEST_SCM_INFO.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.5 ActivationContextInfoData
###

class ActivationContextInfoData(Struct):

    st = [
        ['clientOK', '<I', 0],
        ['bReserved1', '<I', 0],
        ['dwReserved1', '<I', 0],
        ['dwReserved2', '<I', 0],
        ['pIFDClientCtx', '0s', ''],
        ['pIFDPrototypeCtx', '0s', '']
    ]

    def __init__(self, pIFDClientCtx=None, pIFDPrototypeCtx=None, ndrsize=8):
        Struct.__init__(self)
        self._pIFDPrototypeCtx = None
        self._pIFDClientCtx = None
        self.set_pIFDClientCtx(pIFDClientCtx)
        self.set_pIFDPrototypeCtx(pIFDPrototypeCtx)


    def __str__(self):
        return '[ ActivationContextInfoData: pIFDClientCtx=%s ]' % self._pIFDClientCtx


    ###
    # Getters/Setters
    ###

    def set_pIFDClientCtx(self, pIFDClientCtx):
        if pIFDClientCtx is not None:
            data = pIFDClientCtx.pack()
            st[4][1] = '%ds' % len(data)
            self['pIFDClientCtx'] = data
            self._pIFDClientCtx = pIFDClientCtx


    def get_pIFDClientCtx(self):
        return self._pIFDClientCtx

    def set_pIFDPrototypeCtx(self, pIFDPrototypeCtx):
        if pIFDPrototypeCtx is not None:
            data = pIFDPrototypeCtx.pack()
            st[5][1] = '%ds' % len(data)
            self['pIFDPrototypeCtx'] = data
            self._pIFDPrototypeCtx = pIFDPrototypeCtx

    def get_pIFDPrototypeCtx(self):
        return self._pIFDPrototypeCtx

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            pIFDClientCtx = OBJREF().deserialize(data[16:])
            self.set_pIFDClientCtx(pIFDClientCtx)
            pos = 16 + len(pIFDClientCtx.pack())

            if pos < len(data):
                pIFDPrototypeCtx = OBJREF().deserialize(data[pos:])
                self.set_pIFDPrototypeCtx(pIFDPrototypeCtx)

            self.unpack(data)
            return self
        except Exception as e:
            display_error('ActivationContextInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.6 LocationInfoData
###

class LocationInfoData(Struct):

    st = [
        ['machineName', '', 0],
        ['processId', '<I', 0],
        ['apartmentId', '<I', 0],
        ['contextId', '<I', 0]
    ]

    def __init__(self, machineName='', ndrsize=8):
        Struct.__init__(self)
        self._machineName = ''
        self._ndrsize = ndrsize
        self.set_machineName(machineName)

    def __str__(self):
        return '[ LocationInfoData: machineName=%s ]' % self._machineNamex


    ###
    # Getters/Setters
    ###

    def set_machineName(self, machineName):
        self._machineName = machineName
        data  = machineName.encode('utf-16le')
        data += "\x00\x00"
        st[0][1] = "%ds" % len(data)
        self['machineName'] = data

    def get_machineName(self):
        return self._machineName

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            posNullByte = data.find('\x00\x00')
            if posNullByte > 0:
                st[0][1] = "%ds" % (posNullByte + 2)
            else:
                raise ValueError('Invalid data for attribute machineName.')
            self._machineName = data[:posNullByte].decode('utf-16le')
            self.unpack(data)
            return self
        except Exception as e:
            display_error('LocationInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.7 SecurityInfoData
###

class SecurityInfoData(Struct):

    st = [
        ['dwAuthnFlags', '<I', 0],
        ['pServerInfo', '<I', 0],
        ['pdwReserved', '<I', 0]
    ]

    def __init__(self, ndrsize=8):
        Struct.__init__(self)
        self._ndrsize = ndrsize
        if self._ndrsize == 8:
            st[1][1] = '<Q'
            st[2][1] = '<Q'

    def __str__(self):
        return '[ SecurityInfoData ]'

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            return self
        except Exception as e:
            display_error('SecurityInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.8 ScmReplyInfoData
###

class ScmReplyInfoData(Struct):

    st = [
        ['pdwReserved', '<I', 0],
        ['remoteReply', '', '']
    ]

    def __init__(self, remoteReply=None):
        Struct.__init__(self)
        self._remoteReply = None
        self.set_remoteReplyt(remoteReply)

    def __str__(self):
        return '[ ScmReplyInfoData: remoteReply=%s ]' % self._remoteReply


    ###
    # Getters/Setters
    ###

    def set_remoteReply(self, remoteReply):
        self._remoteReply = remoteReply

        if remoteReply is None:
            st[1][1] = '0s'
            self['remoteReply'] = ''
        else:
            st[1][1] = '%ds' % len(remoteReply.pack())
            self['remoteReply'] = remoteReply.pack()

    def get_remoteReply(self):
        return self._remoteReply

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            remoteReply = customREMOTE_REPLY_SCM_INFO().deserialize(data[4:])
            self.set_remoteRequest(remoteReply)
            self.unpack(data)
            return self
        except Exception as e:
            display_error('ScmReplyInfoData.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.8.1 customREMOTE_REPLY_SCM_INFO
###

class customREMOTE_REPLY_SCM_INFO(Struct):

    st = [
        ['Oxid', '16s', ''],
        ['pdsaOxidBindings', '', ''],
        ['ipidRemUnknown', '16s', ''],
        ['authnHint', '<I', 0],
        ['serverVersion', '4s', '']
    ]

    def __init__(self, Oxid=OXID(), ipidRemUnknown=IPID(), pdsaOxidBindings=DUALSTRINGARRAY(), serverVersion=COMVERSION(5,1)):
        Struct.__init__(self)
        self._Oxid = None
        self._ipidRemUnknown = None
        self._pdsaOxidBindings = None
        self._serverVersion = None
        self.set_Oxid(Oxid)
        self.set_ipidRemUnknown(ipidRemUnknown)
        self.set_pdsaOxidBindings(pdsaOxidBindings)
        self.set_serverVersion(serverVersion)

    def __str__(self):
        return '[ customREMOTE_REPLY_SCM_INFO: Oxid=%s|ipidRemUnknown=%s ]' % (self._Oxid, self._ipidRemUnknown)


    ###
    # Getters/Setters
    ###

    def set_Oxid(self, Oxid):
        self['Oxid'] = Oxid.pack()
        self._Oxid = Oxid

    def get_Oxid(self):
        return self._Oxid

    def set_ipidRemUnknown(self, ipidRemUnknown):
        self['ipidRemUnknown'] = ipidRemUnknown.pack()
        self._ipidRemUnknown = ipidRemUnknown

    def get_ipidRemUnknown(self):
        return self._ipidRemUnknown

    def set_pdsaOxidBindings(self, pdsaOxidBindings):
        st[1][1] = '%ds' % len(pdsaOxidBindings.pack())
        self['pdsaOxidBindings'] = pdsaOxidBindings.pack()
        self._pdsaOxidBindings = pdsaOxidBindings

    def get_pdsaOxidBindings(self):
        return self._pdsaOxidBindings

    def set_serverVersion(self, serverVersion):
        self['serverVersion'] = serverVersion.pack()
        self._serverVersion = serverVersion

    def get_serverVersion(self):
        return self._serverVersion


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self._pdsaOxidBindings = DUALSTRINGARRAY().deserialize(data[16:])
            st[1][1] = '%ds' % len(self._pdsaOxidBindings.pack())
            self.unpack(data)
            self._Oxid = OXID().deserialize(self['Oxid'])
            self._ipidRemUnknown = IPID().deserialize(self['ipidRemUnknown'])
            self._serverVersion = COMVERSION().deserialize(self['serverVersion'])
            return self
        except Exception as e:
            display_error('customREMOTE_REPLY_SCM_INFO.deserialize() failed: %s' % str(e))
            return None


###
# [MS-DCOM] - 2.2.22.2.9 PropsOutInfo
###

class PropsOutInfo(Struct):

    st = [
        ['cIfs', '<I', 0],
        ['piid', '', ''],
        ['phresults', '', ''],
        ['ppIntfData', '', '']
    ]

    def __init__(self, piid=[], phresults=[], ppIntfData=[], ndrsize=8):
        Struct.__init__(self)
        self._piid = None
        self._phresults = None
        self._ppIntfData = None
        self._ndrsize = ndrsize
        if len(piid) != len(phresults) and len(piid) != len(ppIntfData):
            raise ValueError('Incorrect size parameters.')
        self['cIfs'] = len(piid)
        self.set_piid(piid)
        self.set_phresults(phresults)
        self.ppIntfData(ppIntfData)

    def __str__(self):
        return '[ PropsOutInfo: cIfs=%d ]' % self['cIfs']


    ###
    # Getters/Setters
    ###

    def set_piid(self, piid):
        self._piid = []
        data = ''
        for entry in piid:
            data += entry.pack()
            self._piid.append(entry)
        st[1][1] = '%ds' % len(data)
        self['piid'] = data


    def get_piid(self):
        return self._piid

    def set_phresults(self, phresults):
        self._phresults = []
        data = ''
        for entry in phresults:
            data += entry.pack()
            self._phresults.append(entry)
        st[2][1] = '%ds' % len(data)
        self['phresults'] = data

    def get_phresults(self):
        return self._phresults

    def set_ppIntfData(self, ppIntfData):
        self._ppIntfData = []
        data = ''
        for entry in ppIntfData:
            data += entry.pack()
            self._ppIntfData.append(entry)
        st[2][1] = '%ds' % len(data)
        self['ppIntfData'] = data

    def get_ppIntfData(self):
        return self._ppIntfData


    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            cIfs = struct.unpack('<I', data[:4])[0]
            
            self._piid = []
            self._phresults = []
            self._ppIntfData = []

            pos = 4
            st[1][1] = cIfs * 16
            st[2][1] = cIfs * 4
            st[3][1] = cIfs * 8 if self._ndrsize == 8 else cIfs * 4

            for i in range(cIfs):
                iid = IID().deserialize(data[pos:pos+16])
                self._piid.append(iid)
                pos += 16

            for i in range(cIfs):
                hresult = struct.unpack('<i', data[pos:pos+4])
                self._phresults.append(hresult)
                pos += 4

            fmt = '<I' if self._ndrsize == 4 else '<Q'
            for i in range(cIfs):

                pointer = struct.unpack(fmt, data[pos:pos+self._ndrsize])[0]
                self._ppIntfData.append(pointer)
                pos += self._ndrsize 

            self.unpack(data)
            return self
        except Exception as e:
            display_error('PropsOutInfo.deserialize() failed: %s' % str(e))
            return None



class WMILIB():
    def __init__(self):
        pass

 
    def run(self):
        pass

