#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  smb_deprecated.py
## Description:
##            :
## Created_On :  Wed Apr 11 19:19:16 CEST 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

"""
Note for developpers:
---------------------

This is a temporary file why we are transitionning as libsmb is being rewritten.
"""

from __future__ import with_statement

import os
import copy
import sys
import socket
import random
import logging

from struct import pack, unpack, calcsize

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.smbconst import *
from libs.newsmb.Struct import Struct

###
# Temporary copy (libsmb.py).
##

def extractNullTerminatedString(data, index=0, is_unicode=False):
    """
    Extracts a null-terminated string (incl. null character) from an SMB data
    packet. String can be OEM or Unicode.

    Return (extracted string, number of bytes processed).
    """
    null = u'\0'.encode('UTF-16LE') if is_unicode else u'\0'.encode('ASCII')

    size = len(null)
    result = ''

    for i in range(index, len(data), size):
        c = data[i:i + size]
        result += c
        if c == null:
            break

    size += len(result) - len(null)
    return (result.decode('UTF-16LE') if is_unicode else result.decode('ASCII'),
            size)

###
# OLD deprecated classes.
##


class SMBNegotiateRequestOld(Struct):
    st = [
        ['WordCount' , '<B', 0],
        ['ByteCount' , '<H', 0],
        ['Dialects'  , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['Dialects'] = data[pos:]

    def pack(self):
        dialects = self['Dialects']
        if dialects == '':
            for d in [ 'PC NETWORK PROGRAM 1.0', 'LANMAN1.0',
                       'Windows for Workgroups 3.1a', 'LM1.2X002', 'LANMAN2.1',
                       'NT LM 0.12' ]:
                # Always ascii and always null-terminated
                dialects += '\x02' + d + '\0'

        self['ByteCount'] = len(dialects)
        return Struct.pack(self) + dialects


class SMBNegotiateResponseOld(Struct):
    st = [
        ['WordCount'           , '<B', 17],
        ['DialectIndex'        , '<H', 0],
        ['SecurityMode'        , '<B', 0],
        ['MaxMpxCount'         , '<H', 0],
        ['MaxCountVCs'         , '<H', 0],
        ['MaxBufferSize'       , '<L', 0],
        ['MaxRawSize'          , '<L', 0],
        ['SessionKey'          , '<L', 0],
        ['Capabilities'        , '<L', 0],
        ['SystemTimeLow'       , '<L', 0],
        ['SystemTimeHigh'      , '<L', 0],
        ['ServerTimeZone'      , '<H', 0],
        ['EncryptionKeyLength' , '<B', 0],
        ['ByteCount'           , '<H', 0],
        ['EncryptionKey'       , '0s', ''],  # Only exists if SMB_FLAGS2_EXTENDED_SECURITY is not set
        ['DomainName'          , '0s', u''], # Only exists if SMB_FLAGS2_EXTENDED_SECURITY is not set
        ['ServerName'          , '0s', u''], # Only exists of SMB_FLAGS2_EXTENDED_SECURITY is not set
        ['ServerGuid'          , '0s', ''],  # Only exists if SMB_FLAGS2_EXTENDED_SECURITY is set
        ['SecurityBlob'        , '0s', ''],  # Only exists if SMB_FLAGS2_EXTENDED_SECURITY is set
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            # Unicode has not been negotiated yet
            if self['Capabilities'] & CAP_UNICODE:
                is_unicode = True

            pos = self.calcsize()
            if self['Capabilities'] & CAP_EXTENDED_SECURITY:
                self['ServerGuid'] = data[pos:pos + 16]
                self['SecurityBlob'] += data[pos+16:]
            else:
                self['EncryptionKey'] = data[pos:pos + self['EncryptionKeyLength']]
                pos += self['EncryptionKeyLength']
                # Must be null-terminated
                domain, length = extractNullTerminatedString(data, pos, is_unicode)
                self['DomainName'] = domain.split(u'\0')[0]
                # This is optional
                if self['ByteCount'] - self['EncryptionKeyLength'] - length  > 0:
                    servername = extractNullTerminatedString(data, pos+length, is_unicode)[0]
                    self['ServerName'] = servername.split(u'\0')[0]

    def pack(self):
        self['EncryptionKeyLength'] = len(self['EncryptionKey'])
        if self['Capabilities'] & CAP_EXTENDED_SECURITY:
            self['ByteCount'] = self['EncryptionKeyLength'] + len(self['ServerGuid']) + len(self['SecurityBlob'])
            return Struct.pack(self) + self['EncryptionKey'] + self['ServerGuid'] + self['SecurityBlob']
        else:
            if self['Capabilities'] & CAP_UNICODE:
                is_unicode = True
            else:
                is_unicode = False

            # Null terminate fields
            domainname = self['DomainName'] + u'\0'
            servername = self['ServerName'] + u'\0'
            domainname = domainname.encode('UTF-16LE') if is_unicode else domainname.encode('ASCII')
            servername = servername.encode('UTF-16LE') if is_unicode else servername.encode('ASCII')
            self['ByteCount'] = self['EncryptionKeyLength'] + len(domainname) + len(servername)
            return Struct.pack(self) + domainname + servername


class SMBTransactionRequestOld(Struct):
    st = [
        ['WordCount'           , '<B', 14], #14+SetupCount
        ['TotalParameterCount' , '<H', 0],
        ['TotalDataCount'      , '<H', 0],
        ['MaxParameterCount'   , '<H', 0],
        ['MaxDataCount'        , '<H', 0x400],
        ['MaxSetupCount'       , '<B', 0],
        ['Reserved'            , '<B', 0],
        ['Flags'               , '<H', 0],
        ['Timeout'             , '<L', 0],
        ['Reserved2'           , '<H', 0],
        ['ParameterCount'      , '<H', 0],
        ['ParameterOffset'     , '<H', 0],
        ['DataCount'           , '<H', 0],
        ['DataOffset'          , '<H', 0],
        ['SetupCount'          , '<B', 0],
        ['Reserved3'           , '<B', 0],
        ['Setup'               , '0s', ''],
        ['ByteCount'           , '0s', ''],
        ['Name'                , '0s', u''],
        ['Pad'                 , '0s', ''], #Pad to SHORT or LONG
        ['Parameters'          , '0s', ''],
        ['Pad1'                , '0s', ''], #Pad to SHORT or LONG
        ['Data'                , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            size = self['SetupCount'] * calcsize('<H')
            self['Setup'] = data[pos:pos + size]
            pos += size
            size = calcsize('<H')
            self['ByteCount'] = unpack('<H', data[pos:pos + size])[0]
            pos += size
            if is_unicode == True and (pos % 2) == 1:
                pos += 1

            name, size = extractNullTerminatedString(data, pos, is_unicode)
            self['Name'] = name.split(u'\0')[0]
            pos += size

            self['Pad'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad1'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['Data'] = data[pos:pos + size]

    def pack(self):
        self['SetupCount'] = len(self['Setup']) / calcsize('<H')
        self['WordCount'] = 14 + self['SetupCount']
        self['DataCount'] = len(self['Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = self.calcsize() + len(self['Setup']) + calcsize('<H')

        name = self['Name']
        name += u'\0'

        if self.is_unicode == True:
            name = name.encode('UTF-16LE')
            if (size % 2) == 1:
                name = '\0' + name
        else:
            name = name.encode('ASCII', 'ignore')

        size += len(name)

        if self['Pad'] == '':
            if (size % 2) == 1:
                self['Pad'] = '\0'
        size += len(self['Pad'])
        self['ParameterOffset'] = SMB_HEADER_SIZE + size
        size += len(self['Parameters'])
        if self['Pad1'] == '':
            if (size % 2) == 1:
                self['Pad1'] = '\0'
        size += len(self['Pad1'])
        self['DataOffset'] = SMB_HEADER_SIZE + size
        data = Struct.pack(self) + self['Setup'] + pack('<H', len(name) + len(self['Pad']) + len(self['Parameters']) + len(self['Pad1']) + len(self['Data'])) + name + self['Pad'] + self['Parameters'] + self['Pad1'] + self['Data']

        return data


class SMBTransactionResponseOld(Struct):
    st = [
        ['WordCount'             , '<B', 10], #10+SetupCount
        ['TotalParameterCount'   , '<H', 0],
        ['TotalDataCount'        , '<H', 0],
        ['Reserved'              , '<H', 0],
        ['ParameterCount'        , '<H', 0],
        ['ParameterOffset'       , '<H', 0],
        ['ParameterDisplacement' , '<H', 0],
        ['DataCount'             , '<H', 0],
        ['DataOffset'            , '<H', 0],
        ['DataDisplacement'      , '<H', 0],
        ['SetupCount'            , '<B', 0],
        ['Reserved2'             , '<B', 0],
        ['Setup'                 , '0s', ''],
        ['ByteCount'             , '0s', ''],
        ['Pad'                   , '0s', ''], #Pad to SHORT or LONG
        ['Parameters'            , '0s', ''],
        ['Pad1'                  , '0s', ''], #Pad to SHORT or LONG
        ['Data'                  , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            size = self['SetupCount'] * calcsize('<H')
            self['Setup'] = data[pos:pos + size]
            pos += size
            size = calcsize('<H')
            self['ByteCount'] = unpack('<H', data[pos:pos + size])[0]
            pos += size
            self['Pad'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad1'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['Data'] = data[pos:pos + size]

    def pack(self):
        self['SetupCount'] = len(self['Setup']) / calcsize('<H')
        self['WordCount'] = 10 + self['SetupCount']
        self['DataCount'] = len(self['Data'])
        if self['TotalDataCount'] == 0: #XXX: If we ever want to split SMB_COM_TRANSACTION* packets, the TotalDataCount will be != DataCount --Kostya
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = self.calcsize() + len(self['Setup']) + calcsize('<H')
        if self['Pad'] == '':
            if (size % 2) == 1:
                self['Pad'] = '\0'
        size += len(self['Pad'])
        self['ParameterOffset'] = SMB_HEADER_SIZE + size
        size += len(self['Parameters'])
        if self['Pad1'] == '':
            if (size % 2) == 1:
                self['Pad1'] = '\0'
        size += len(self['Pad1'])
        self['DataOffset'] = SMB_HEADER_SIZE + size
        data = Struct.pack(self) + self['Setup'] + pack('<H', len(self['Pad']) + len(self['Parameters']) + len(self['Pad1']) + len(self['Data'])) + self['Pad'] + self['Parameters'] + self['Pad1'] + self['Data']

        return data


class SMBSessionSetupAndXRequestOld(Struct):
    st = [
        ['WordCount'          , '<B', 12],
        ['AndXCommand'        , '<B', 0xff],
        ['AndXReserved'       , '<B', 0],
        ['AndXOffset'         , '<H', 0],
        ['MaxBufferSize'      , '<H', 0x1104],
        ['MaxMpxCount'        , '<H', 0x10],
        ['VcNumber'           , '<H', 0],
        ['SessionKey'         , '<L', 0],
        ['SecurityBlobLength' , '<H', 0],
        ['Reserved'           , '<L', 0],
        ['Capabilities'       , '<L', CAP_EXTENDED_SECURITY|CAP_STATUS32|CAP_UNICODE|CAP_LARGE_READX|CAP_LARGE_WRITEX],
        ['ByteCount'          , '<H', 0],
        ['SecurityBlob'       , '0s', ''],
        ['NativeOS'           , '0s', u''],
        ['NativeLANMan'       , '0s', u''],
        ['PrimaryDomain'      , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['SecurityBlob'] = data[pos:pos + self['SecurityBlobLength']]
            pos += self['SecurityBlobLength']
            if self.is_unicode == True and (pos % 2) == 1:
                pos += 1
            # The following strings are always null terminated
            nativeos, size = extractNullTerminatedString(data, pos, is_unicode)
            self['NativeOS'] = nativeos.split(u'\0')[0]
            pos += size
            lanman, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['NativeLANMan'] = lanman.split(u'\0')[0]

    def pack(self):
        self['SecurityBlobLength'] = len(self['SecurityBlob'])
        nativeos = self['NativeOS']
        nativelanman = self['NativeLANMan']
        primarydomain = self['PrimaryDomain']

        if self['NativeOS'] == u'':
            nativeos = u'Unix'
        if self['NativeLANMan'] == u'':
            nativelanman = u'Samba'

        nativeos      += u'\0'
        nativelanman  += u'\0'
        primarydomain += u'\0'
        pad = ''

        if self.is_unicode == True:
            if ((self.calcsize() + self['SecurityBlobLength']) % 2) == 1:
                pad = '\0'
            nativeos = nativeos.encode('UTF-16-LE')
            nativelanman = nativelanman.encode('UTF-16-LE')
            primarydomain = primarydomain.encode('UTF-16-LE')
        else:
            nativeos = nativeos.encode('ASCII')
            nativelanman = nativelanman.encode('ASCII')
            primarydomain = primarydomain.encode('ASCII')

        self['ByteCount'] = len(self['SecurityBlob']) + len(pad) + len(nativeos) + len(nativelanman) + len(primarydomain)
        data = Struct.pack(self)
        return data + self['SecurityBlob'] + pad + nativeos + nativelanman + primarydomain


class SMBSessionSetupAndXResponseOld(Struct):
    st = [
        ['WordCount'         , '<B', 4],
        ['AndXCommand'       , '<B', 0xff],
        ['AndXReserved'      , '<B', 0],
        ['AndXOffset'        , '<H', 0],
        ['Action'            , '<H', 0],
        ['SecurityBlobLength', '<H', 0],
        ['ByteCount'         , '<H', 0],
        ['SecurityBlob'      , '0s', ''],
        ['NativeOS'          , '0s', u''],
        ['NativeLANMan'      , '0s', u''],
        ['PrimaryDomain'     , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['SecurityBlob'] = data[pos:pos + self['SecurityBlobLength']]
            pos += self['SecurityBlobLength']

            # NativeOS, NativeLANMan and PrimaryDomain are not very important.
            # Unfortunately parsing this is prone to errors and implementation
            # might vary between servers so catching exceptions is fine.
            try:
                if self.is_unicode == True and (pos % 2) == 1:
                    pos += 1
                nativeos, size = extractNullTerminatedString(data, pos, is_unicode)
                self['NativeOS'] = nativeos.split(u'\0')[0]
                pos += size
                lanman, size = extractNullTerminatedString(data, pos, is_unicode)
                self['NativeLANMan'] = lanman.split(u'\0')[0]
                pos += size
                primarydomain, _ = extractNullTerminatedString(data, pos, is_unicode)
                self['PrimaryDomain'] = primarydomain.split(u'\0')[0]
            except Exception as e:
                logging.warning("Warning, parsing of the answer slightly failed: %s" % str(e))

    def pack(self):
        self['SecurityBlobLength'] = len(self['SecurityBlob'])
        nativeos      = self['NativeOS']
        nativelanman  = self['NativeLANMan']
        primarydomain = self['PrimaryDomain']

        if nativeos == u'':
            nativeos = u'Unix'
        if nativelanman == u'':
            nativelanman = u'Samba'

        nativeos      += u'\0'
        nativelanman  += u'\0'
        primarydomain += u'\0'

        pad = ''

        if self.is_unicode == True:
            if ((self.calcsize() + self['SecurityBlobLength']) % 2) == 1:
                pad = '\0'
            nativeos = nativeos.encode('UTF-16-LE')
            nativelanman = nativelanman.encode('UTF-16-LE')
            primarydomain = primarydomain.encode('UTF-16-LE')
        else:
            nativeos = nativeos.encode('ASCII')
            nativelanman = nativelanman.encode('ASCII')
            primarydomain = primarydomain.encode('ASCII')
        self['ByteCount'] = len(self['SecurityBlob']) + len(pad) + len(nativeos) + len(nativelanman) + len(primarydomain)
        data = Struct.pack(self)
        return data + self['SecurityBlob'] + pad + nativeos + nativelanman + primarydomain


class SMBTreeDisconnectRequestOld(Struct):
    st = [
        ['WordCount' , '<B', 0],
        ['ByteCount' , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBTreeDisconnectResponseOld(Struct):
    st = [
        ['WordCount' , '<B', 0],
        ['ByteCount' , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBLogoffAndXRequestOld(Struct):
    st = [
        ['WordCount'    , '<B', 2],
        ['AndXCommand'  , '<B', 0xff],
        ['AndXReserved' , '<B', 0],
        ['AndXOffset'   , '<H', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBLogoffAndXResponseOld(Struct):
    st = [
        ['WordCount'    , '<B', 2],
        ['AndXCommand'  , '<B', 0xff],
        ['AndXReserved' , '<B', 0],
        ['AndXOffset'   , '<H', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBNTTransactRequestOld(Struct):
    st = [
        ['WordCount'           , '<B', 19], #19+SetupCount
        ['MaxSetupCount'       , '<B', 0],
        ['Reserved1'           , '<H', 0],
        ['TotalParameterCount' , '<L', 0],
        ['TotalDataCount'      , '<L', 0],
        ['MaxParameterCount'   , '<L', 0],
        ['MaxDataCount'        , '<L', 0],
        ['ParameterCount'      , '<L', 0],
        ['ParameterOffset'     , '<L', 0],
        ['DataCount'           , '<L', 0],
        ['DataOffset'          , '<L', 0],
        ['SetupCount'          , '<B', 0],
        ['Function'            , '<H', 0],
        ['Setup'               , '0s', ''],
        ['ByteCount'           , '0s', ''],
        ['Pad1'                , '0s', ''],
        ['NT_Trans_Parameters' , '0s', ''],
        ['Pad2'                , '0s', ''],
        ['NT_Trans_Data'       , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            size = self['SetupCount'] * calcsize('<H')
            self['Setup'] = data[pos:pos + size]
            pos += size
            size = calcsize('<H')
            self['ByteCount'] = unpack('<H', data[pos:pos + size])[0]
            pos += size
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['NT_Trans_Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['NT_Trans_Data'] = data[pos:pos + size]

    def pack(self):
        self['SetupCount'] = len(self['Setup']) / calcsize('<H')
        self['WordCount'] = 19 + self['SetupCount']
        self['DataCount'] = len(self['NT_Trans_Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['NT_Trans_Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize() + len(self['Setup']) + calcsize('<H')
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['NT_Trans_Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        data = Struct.pack(self) + self['Setup'] + pack('<H', len(self['Pad1']) + len(self['NT_Trans_Parameters']) + len(self['Pad2']) + len(self['NT_Trans_Data'])) + self['Pad1'] + self['NT_Trans_Parameters'] + self['Pad2'] + self['NT_Trans_Data']

        return data


class SMBNTTransactResponseOld(Struct):
    st = [
        ['WordCount'             , '<B', 18], #18+SetupCount
        ['Reserved1'             , '3s', '\0' * 3],
        ['TotalParameterCount'   , '<L', 0],
        ['TotalDataCount'        , '<L', 0],
        ['ParameterCount'        , '<L', 0],
        ['ParameterOffset'       , '<L', 0],
        ['ParameterDisplacement' , '<L', 0],
        ['DataCount'             , '<L', 0],
        ['DataOffset'            , '<L', 0],
        ['DataDisplacement'      , '<L', 0],
        ['SetupCount'            , '<B', 0],
        ['Setup'                 , '0s', ''],
        ['ByteCount'             , '0s', ''],
        ['Pad1'                  , '0s', ''],
        ['NT_Trans_Parameters'   , '0s', ''],
        ['Pad2'                  , '0s', ''],
        ['NT_Trans_Data'         , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        if data is not None and len(data) < self.calcsize(): #Interim server response
            self['WordCount'] = 0
            return

        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            size = self['SetupCount'] * calcsize('<H')
            self['Setup'] = data[pos:pos + size]
            pos += size
            size = calcsize('<H')
            self['ByteCount'] = unpack('<H', data[pos:pos + size])[0]
            pos += size
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['NT_Trans_Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['NT_Trans_Data'] = data[pos:pos + size]

    def pack(self):
        self['SetupCount'] = len(self['Setup']) / calcsize('<H')
        self['WordCount'] = 18 + self['SetupCount']
        self['DataCount'] = len(self['NT_Trans_Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['NT_Trans_Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize() + len(self['Setup']) + calcsize('<H')
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['NT_Trans_Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        data = Struct.pack(self) + self['Setup'] + pack('<H', len(self['Pad1']) + len(self['NT_Trans_Parameters']) + len(self['Pad2']) + len(self['NT_Trans_Data'])) + self['Pad1'] + self['NT_Trans_Parameters'] + self['Pad2'] + self['NT_Trans_Data']

        return data


class SMBTransactionSecondaryRequestOld(Struct):
    st = [
        ['WordCount'             , '<B', 8],
        ['TotalParameterCount'   , '<H', 0],
        ['TotalDataCount'        , '<H', 0],
        ['ParameterCount'        , '<H', 0],
        ['ParameterOffset'       , '<H', 0],
        ['ParameterDisplacement' , '<H', 0],
        ['DataCount'             , '<H', 0],
        ['DataOffset'            , '<H', 0],
        ['DataDisplacement'      , '<H', 0],
        ['ByteCount'             , '<H', 0],
        ['Pad1'                  , '0s', ''],
        ['Trans_Parameters'      , '0s', ''],
        ['Pad2'                  , '0s', ''],
        ['Trans_Data'            , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['Trans_Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['Trans_Data'] = data[pos:pos + size]

    def pack(self):
        self['DataCount'] = len(self['Trans_Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['Trans_Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize()
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['Trans_Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        self['ByteCount'] = len(self['Pad1']) + len(self['Trans_Parameters']) + len(self['Pad2']) + len(self['Trans_Data'])
        data = Struct.pack(self)
        data += self['Pad1'] + self['Trans_Parameters'] + self['Pad2'] + self['Trans_Data']

        return data


class SMBNTTransactSecondaryRequestOld(Struct):
    st = [
        ['WordCount'             , '<B', 18],
        ['Reserved1'             , '3s', '\0' * 3],
        ['TotalParameterCount'   , '<L', 0],
        ['TotalDataCount'        , '<L', 0],
        ['ParameterCount'        , '<L', 0],
        ['ParameterOffset'       , '<L', 0],
        ['ParameterDisplacement' , '<L', 0],
        ['DataCount'             , '<L', 0],
        ['DataOffset'            , '<L', 0],
        ['DataDisplacement'      , '<L', 0],
        ['Reserved2'             , '<B', 0],
        ['ByteCount'             , '<H', 0],
        ['Pad1'                  , '0s', ''],
        ['NT_Trans_Parameters'   , '0s', ''],
        ['Pad2'                  , '0s', ''],
        ['NT_Trans_Data'         , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['NT_Trans_Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['NT_Trans_Data'] = data[pos:pos + size]

    def pack(self):
        self['DataCount'] = len(self['NT_Trans_Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['NT_Trans_Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize()
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['NT_Trans_Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        self['ByteCount'] = len(self['Pad1']) + len(self['NT_Trans_Parameters']) + len(self['Pad2']) + len(self['NT_Trans_Data'])
        data = Struct.pack(self)
        data += self['Pad1'] + self['NT_Trans_Parameters'] + self['Pad2'] + self['NT_Trans_Data']

        return data


class SMBEchoRequestOld(Struct):
    st = [
        ['WordCount' , '<B', 0x01],
        ['EchoCount' , '<H', 0x01],
        ['ByteCount' , '<H', 0],
        ['EchoData'  , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['EchoData'] = data[pos:]

    def pack(self):
        self['ByteCount'] = len(self['EchoData'])
        return Struct.pack(self) + self['EchoData']


class SMBEchoResponseOld(Struct):
    st = [
        ['WordCount'      , '<B', 0x01],
        ['SequenceNumber' , '<H', 0],
        ['ByteCount'      , '<H', 0],
        ['EchoData'       , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['EchoData'] = data[pos:]

    def pack(self):
        self['ByteCount'] = len(self['EchoData'])
        return Struct.pack(self) + self['EchoData']
