#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  rdpdr.py
## Description:
##            :
## Created_On :  Mon Sep 23 2019

## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import copy
import struct
import socket
import time

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct # TODO
from libs.rdp.rdpconst import *

###
# Important API
###

def isRdprPdu(data):

    magic = struct.unpack('<H', data[:2])[0]
    if magic == RDPDR_CTYP_CORE or magic == RDPDR_CTYP_PRN:
        return True
    else:
        return False

def Id2Class(Id):

    d = {
        PAKID_CORE_SERVER_ANNOUNCE:     ServerAnnounceRequest,
        PAKID_CORE_CLIENTID_CONFIRM:    ClientAnnounceReply,
        PAKID_CORE_CLIENT_NAME:         ClientNameRequest,
        PAKID_CORE_DEVICELIST_ANNOUNCE: ClientDeviceListAnnounceRequest,
        PAKID_CORE_USER_LOGGEDON:       ServerUserLoggedOn,
        }

    if d.has_key(Id):
        return d[Id]
    else:
        None

def unserialize_rdpdr(packet, remaining_payload):

    _id = struct.unpack('<H', remaining_payload[2:4])[0]
    cls = Id2Class(_id)

    if cls:
        pdu = cls()
        pdu.deserialize(packet.payload)
        packet.append(pdu)
        packet.payload = pdu.payload

###
# Main classes
###


class SharedHeader(Struct):
    """
    2.2.1.1 Shared Header (RDPDR_HEADER)
    """

    st = [
        ['Component', '<H', 0 ],
        ['PacketId', '<H', 0 ],
    ]

    def __init__(self, component=0, packet_id=0):
        Struct.__init__(self)
        self['Component'] = component
        self['PacketId'] = packet_id
        self.payload = ''

    def __str__(self):
        return '[ RDPDRSharedHeader: Component=0x%x, PacketId=0x%x ]' % (self['Component'], self['PacketId'])

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
            print('RDPDR.SharedHeader.deserialize() failed: %s' % str(e))
            return None


class ServerAnnounceRequest(Struct):
    """
    2.2.2.2 Server Announce Request (DR_CORE_SERVER_ANNOUNCE_REQ)
    """

    st = [
        ['SharedHeader', SharedHeader, SharedHeader(RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE) ],
        ['VersionMajor', '<H', 0x0001 ],
        ['VersionMinor', '<H', 0x000c ],
        ['ClientId'    , '<L', 0 ],
        
    ]

    def __init__(self, major=0x0001, minor=0x000c, cliend_id=0):
        Struct.__init__(self)
        self['VersionMajor'] = major
        self['VersionMinor'] = minor
        self['ClientId'] = cliend_id
        self.payload = ''

    def __str__(self):
        return '[ ServerAnnounceRequest: VersionMajor=0x%x, VersionMinor=0x%x, ClientId=0x%x ]' % (self['VersionMajor'], self['VersionMinor'], self['ClientId'])

    def get_cid(self):
        return self['ClientId']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            offset = 0
            self['SharedHeader'] = SharedHeader().deserialize(data)
            offset += 4
            self['VersionMajor'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['VersionMinor'] = struct.unpack('<H', data[offset:offset+2])[0]
            offset += 2
            self['ClientId'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self.payload = data[offset:]
            return self
        except Exception as e:
            print('RDPDR.ServerAnnounceRequest.deserialize() failed: %s' % str(e))
            return None


class ClientAnnounceReply(ServerAnnounceRequest):
    """
    2.2.2.3 Client Announce Reply (DR_CORE_CLIENT_ANNOUNCE_RSP)
    """

    st = [
        ['SharedHeader', SharedHeader, SharedHeader(RDPDR_CTYP_CORE, PAKID_CORE_CLIENTID_CONFIRM) ],
        ['VersionMajor', '<H', 0x0001 ],
        ['VersionMinor', '<H', 0x000c ],
        ['ClientId'    , '<L', 0 ],
    ]

    def __str__(self):
        return '[ ClientAnnounceReply: VersionMajor=0x%x, VersionMinor=0x%x, ClientId=0x%x ]' % (self['VersionMajor'], self['VersionMinor'], self['ClientId'])


class ClientNameRequest(Struct):
    """
    2.2.2.4 Client Name Request (DR_CORE_CLIENT_NAME_REQ)
    """

    st = [
        ['SharedHeader',    SharedHeader, SharedHeader(RDPDR_CTYP_CORE, PAKID_CORE_CLIENT_NAME) ],
        ['UnicodeFlag',     '<L', 1 ], # Unicode enabled
        ['CodePage',        '<L', 0 ],
        ['ComputerNameLen', '<L', 0 ],
        ['ComputerName',    '0s', '' ],
    ]

    def __init__(self, unicode_flag=1, computername=''):
        Struct.__init__(self)
        self['UnicodeFlag'] = 1
        self['CodePage'] = 0
        self['ComputerName'] = (computername + '\0').encode('utf-16le')
        self['ComputerNameLen'] = len(self['ComputerName'])
        self.payload = ''

    def __str__(self):
        return '[ ClientNameRequest: UnicodeFlag=0x%x, ComputerName=%s [%d] ]' % (self['UnicodeFlag'], self['ComputerName'], self['ComputerNameLen'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data = Struct.serialize(self)
        data += self['ComputerName']
        return data

    def deserialize(self, data):
        try:
            offset = 0
            self['SharedHeader'] = SharedHeader().deserialize(data)
            offset += 4
            self['UnicodeFlag'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self['CodePage'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self['ComputerNameLen'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            self['ComputerName'] = data[offset:].decode('utf-16le').rstrip('\0')
            return self
        except Exception as e:
            print('RDPDR.ClientNameRequest.deserialize() failed: %s' % str(e))
            return None


class ServerUserLoggedOn(SharedHeader):
    """
    2.2.2.5 Server User Logged On (DR_CORE_USER_LOGGEDON)
    """ 

    def __init__(self):
        Struct.__init__(self)
        self['Component'] = RDPDR_CTYP_CORE
        self['PacketId'] = PAKID_CORE_USER_LOGGEDON

    def __str__(self):
        return '[ ServerUserLoggedOn ]'


class ClientDeviceListAnnounceRequest(Struct):
    """
    2.2.2.9 Client Device List Announce Request (DR_CORE_DEVICELIST_ANNOUNCE_REQ)
    """

    st = [
        ['SharedHeader',    SharedHeader, SharedHeader(RDPDR_CTYP_CORE, PAKID_CORE_DEVICELIST_ANNOUNCE) ],
        ['DeviceCount',     '<L', 0 ],
        ['DeviceList',      '0s', '' ],
    ]

    def __init__(self, device_list=None):
        Struct.__init__(self)
        if not device_list:
            self['DeviceList'] = []
            self['DeviceCount'] = 0
        else:
            self['DeviceList'] = device_list
            self['DeviceCount'] = len(device_list)

    def __str__(self):
        return '[ ClientDeviceListAnnounceRequest: DeviceCount=0x%x ]' % (self['DeviceCount'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data = Struct.serialize(self)
        for device in self['DeviceList']:
            data += device.pack()
        return data

    def deserialize(self, data):
        try:
            offset = 0
            self['SharedHeader'] = SharedHeader().deserialize(data)
            offset += 4
            self['DeviceCount'] = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            # TODO.
            return self
        except Exception as e:
            print('RDPDR.ClientDeviceListAnnounceRequest.deserialize() failed: %s' % str(e))
            return None


if __name__ == "__main__":
    
    print SharedHeader(RDPDR_CTYP_CORE, PAKID_CORE_SERVER_ANNOUNCE).deserialize('72446e4901000c0001000000'.decode('hex'))
    print ServerAnnounceRequest(0,0,0).deserialize('72446e4901000c0001000000'.decode('hex'))
    print ClientAnnounceReply(0,0,0).deserialize('7244434301000c0001000000'.decode('hex'))
    print ClientNameRequest(computername='curiosity4').pack().encode('hex')
    print "72444e4301000000000000001800000063007500720069006f007300690074007900340000000000"
    print ClientNameRequest(computername='').deserialize("72444e4301000000000000001800000063007500720069006f007300690074007900340000000000".decode('hex'))
    print ClientDeviceListAnnounceRequest()
    print ClientDeviceListAnnounceRequest().deserialize('7244414400000000'.decode('hex'))
    print ServerUserLoggedOn()
