#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  libsmb.py
## Description:
##            :
## Created_On :  Mon Jul 12 14:16:48 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Wed Apr 11 17:42:05 CEST 2018
## Modified_By:  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

"""
Note for developpers:
---------------------

Various modules in CANVAS are using old and deprecated SMB API such as smbserver.py.
libs/newsmb/libsmb.py is the new library and should de facto be used, any other
is no more maintained.

IMPORTANT: Please note that this library is currently being rewritten.
"""

from __future__ import with_statement

import os
import copy
import sys
import socket
import random
import threading
import time
import logging
import itertools
import traceback
from datetime import datetime
from struct import pack, unpack, calcsize
from collections import OrderedDict

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libgssapi import GSSAPI, GSS_NTLMSSP, GSS_KRB5, GSS_MS_KRB5
from libs.newsmb.libntlm import NTLM
from libs.newsmb.libkrb5 import KRB5
from libs.newsmb.Struct import Struct
from libs.newsmb.smbconst import *
from libs.newsmb.serialize import *
from libs.newsmb.smb_serialize import *
from libs.newsmb.oem_string import *
from libs.newsmb.smb_string import *
from libs.newsmb.smb_deprecated import *
import libs.newsmb.smbconst as smbconst # Used in status_description

try:
    from Crypto.Hash import MD5
except ImportError:
    from libs.Crypto.Hash import MD5

################################################################################
#                                                                              #
#                              Utility functions                               #
#                                                                              #
################################################################################

def unixtime_to_smb_date(unixtime):
    """
    Convert Unix timestamp (time since Unix epoch) to SMB_DATE field.

    See page 47/MS-CIFS.
    """
    dt = datetime.fromtimestamp(unixtime)
    return ((dt.year-1980) << 9) | (dt.month << 5) | dt.day

def unixtime_to_smb_time(unixtime):
    """
    Convert Unix timestamp (time since Unix epoch) to SMB_TIME field.

    See page 47/MS-CIFS.
    """
    dt = datetime.fromtimestamp(unixtime)
    return (dt.hour << 11) | (dt.minute << 5) | dt.second


def fix_universal_path(path):
    """
    Split universal path into components (dirs/file) and return them as list.
    """
    return filter(len, path.split(u'\\'))

def assert_unicode(string):
    """
    Make sure string is unicode encoded, decode to unicode if not.
    If string is None, return None.
    """
    if string == None or isinstance(string, unicode):
        return string
    else:
        return unicode(string)

def status_description(status_code):
    """
    Return a string that corresponds to the readable name of NT status_code.
    Return Unknown status code if status_code is not found.
    """
    desc = [k for k,v in smbconst.__dict__.iteritems() if v==status_code and k.startswith('STATUS')]
    return (desc[0] if len(desc) > 0 else 'UNKNOWN_STATUS_CODE')


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


################################################################################
#                                                                              #
#                             [OLD] SMB COMMANDS                               #
#                                                                              #
################################################################################

###
# These classes are still used by the SMBPacket classes.
###

#XXX: This should be FindFileBothDirectoryInfo only
class SMBInformationStandardEntry(Struct):
    st = [
        ['NextEntryOffset'   , '<L', 0],
        ['FileIndex'         , '<L', 0],
        ['CreationTime'      , '<Q', 0],
        ['LastAccessTime'    , '<Q', 0],
        ['LastWriteTime'     , '<Q', 0],
        ['LastChangeTime'    , '<Q', 0],
        ['EndOfFile'         , '<Q', 0],
        ['AllocationSize'    , '<Q', 0],
        ['ExtFileAttributes' , '<L', 0],
        ['FileNameLength'    , '<L', 0],
        ['EaSize'            , '<L', 0],
        ['ShortNameLength'   , '<B', 0],
        ['Reserved'          , '<B', 0],
        ['ShortName'         , '24s', '\0' * 24],
        ['FileName'          , '0s', u''],
        ['FEAList'           , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=True):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            # Decoded strings may unclude terminating null in both unicode and ascii so we remove them if present
            if is_unicode == True:
                self['FileName'] = data[pos:pos + self['FileNameLength']].decode('UTF-16LE').split(u'\0')[0]
            else:
                self['FileName'] = data[pos:pos + self['FileNameLength']].decode('ASCII').split(u'\0')[0]
            pos += self['FileNameLength']
            self['FEAList'] = data[pos:pos + self['EaSize']]

    def pack(self):
        if self.is_unicode == True:
            filename = self['FileName'].encode('UTF-16LE')
        else:
            filename = self['FileName'].encode('ASCII')
            # Add terminating null if not present since it is required
            # in this case only
            if filename[-1] != '\x00':
                filename += '\x00'

        self['FileNameLength'] = len(filename)
        self['EaSize'] = len(self['FEAList'])

        data = Struct.pack(self)
        return data + filename + self['FEAList']


def parseSMBFindData(data, information_level=SMB_FIND_FILE_BOTH_DIRECTORY_INFO,
                     is_unicode=True):
    results = []
    if information_level != SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
        logging.debug('Information level not supported --Kostya')
    i = 0
    while i < len(data):
        entry = SMBInformationStandardEntry(data[i:], is_unicode=is_unicode)
        offset = entry['NextEntryOffset']
        results += [entry]
        if offset == 0:
            break
        i += offset
    return results

class SMBQueryFileBasicEntry(Struct):
    st = [
        ['CreationTime'      , '<Q', 0],
        ['LastAccessTime'    , '<Q', 0],
        ['LastWriteTime'     , '<Q', 0],
        ['LastChangeTime'    , '<Q', 0],
        ['ExtFileAttributes' , '<L', 0],
        ['Reserved'          , '<L', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class SMBQueryFileStandardEntry(Struct):
    st = [
        ['AllocationSize' , '<Q', 0],
        ['EndOfFile'      , '<Q', 0],
        ['NumberOfLinks'  , '<L', 1],
        ['DeletePending'  , '<B', 0],
        ['Directory'      , '<B', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class SMBQueryFileEAEntry(Struct):
    st = [
        ['EaSize' , '<L', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class SMBQueryFileNameEntry(Struct):
    st = [
        ['FileNameLength'    , '<L', 0],
        ['FileName'          , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            # Always unicode
            self['FileName'] = data[pos:pos+self['FileNameLength']].decode('UTF-16LE').split(u'\0')[0]

    def pack(self):
        name = self['FileName'].encode('UTF-16LE')
        self['FileNameLength'] = len(name)
        return Struct.pack(self) + name


class SMBQueryFileAllEntry(Struct):
    st = [
        ['CreationTime'      , '<Q', 0],
        ['LastAccessTime'    , '<Q', 0],
        ['LastWriteTime'     , '<Q', 0],
        ['LastChangeTime'    , '<Q', 0],
        ['ExtFileAttributes' , '<L', 0],
        ['Reserved1'         , '<L', 0],
        ['AllocationSize'    , '<Q', 0],
        ['EndOfFile'         , '<Q', 0],
        ['NumberOfLinks'     , '<L', 0],
        ['DeletePending'     , '<B', 0],
        ['Directory'         , '<B', 0],
        ['Reserved2'         , '<H', 0],
        ['EaSize'            , '<L', 0],
        ['FileNameLength'    , '<L', 0],
        ['FileName'          , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            # Always unicode
            self['FileName'] = data[pos:pos+self['FileNameLength']].decode('UTF-16LE').split(u'\0')[0]

    def pack(self):
        name = self['FileName'].encode('UTF-16LE')
        self['FileNameLength'] = len(name)
        return Struct.pack(self) + name


class SMBQueryFileAltNameEntry(Struct):
    st = [
        ['FileNameLength' , '<L', 0],
        ['FileName'       , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            length = self['FileNameLength']
            # Always unicode
            self['FileName'] = data[pos:pos + length].decode('UTF-16LE').split(u'\0')[0]

    def pack(self):
        name = self['FileName'].encode('UTF-16LE')
        self['FileNameLength'] = len(name)
        return Struct.pack(self) + name

class SMBQueryFileCompressionEntry(Struct):
    st = [
        ['CompressedFileSize'   , '<Q', 0],
        ['CompressionFormat'    , '<H', 0],
        ['CompressionUnitShift' , '<B', 0],
        ['ChunkShift'           , '<B', 0],
        ['ClusterShift'         , '<B', 0],
        ['Reserved'             , '0s', ''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

    def pack(self):
        return Struct.pack(self) + '\x00\x00\x00' # Reserved field


class SMBQueryFileStreamEntry(Struct):
    st = [
        ['NextEntryOffset'      , '<L', 0],
        ['StreamNameLength'     , '<L', 0],
        ['StreamSize'           , '<Q', 0],
        ['StreamAllocationSize' , '<Q', 0],
        ['StreamName'           , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            length = self['StreamNameLength']
            # Always unicode
            self['StreamName'] = data[pos:pos + length].decode('UTF-16LE').split('\0')[0]

    def pack(self):
        streamname = self['StreamName'].encode('UTF-16LE')
        self['StreamNameLength'] = len(streamname)
        return Struct.pack(self) + streamname


def parseSMBQueryFileInformationData(data, information_level=1022):
    results = []
    if information_level != 1022:
        logging.debug('Information level not supported --Kostya')
    i = 0
    while i < len(data):
        entry = SMBQueryFileStreamEntry(data[i:])
        offset = entry['NextEntryOffset']
        results += [entry]
        if offset == 0:
            break
        i += offset
    return results


class SMBFindFileBothDirectoryEntry(SMBInformationStandardEntry):
    pass


class SMBInformationAllocationEntry(Struct):
    st = [
        ['idFileSystem'   , '<L', 0],
        ['cSectorUnit'    , '<L', 0],
        ['cUnit'          , '<L', 0],
        ['cUnitAvailable' , '<L', 0],
        ['cbSector'       , '<H', 0],
    ]


class SMBInformationVolumeEntry(Struct):
    st = [
        ['ulVolSerialNbr' , '<L', 0],
        ['cCharCount'     , '<B', 0],
        ['VolumeLabel'    , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=True):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            # Must be null terminated
            label, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['VolumeLabel'] = label.split(u'\0')[0]

    def pack(self):
        size = len(self['VolumeLabel'])
        # Must be null-terminated, so null terminate it here
        self['VolumeLabel'] += u'\0'

        if self.is_unicode:
            label = self['VolumeLabel'].encode('UTF-16LE')
        else:
            label = self['VolumeLabel'].encode('ASCII')

        self['cCharCount'] = size
        return Struct.pack(self) +  label


class SMBQueryFsVolumeEntry(Struct):
    st = [
        ['VolumeCreationTime' , '<Q', 0],
        ['SerialNumber'       , '<L', 0],
        ['VolumeLabelSize'    , '<L', 0],
        ['Reserved'           , '<H', 0],
        ['VolumeLabel'        , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            labelsize = self['VolumeLabelSize']
            # Always unicode
            self['VolumeLabel'] = data[pos:pos+labelsize].decode('UTF-16LE').split(u'\0')[0]

    def pack(self):
        label = self['VolumeLabel'].encode('UTF-16LE')
        self['VolumeLabelSize'] = len(label)
        return Struct.pack(self) + label


class SMBQueryFsSizeEntry(Struct):
    st = [
        ['TotalAllocationUnits'     , '<Q', 0],
        ['TotalFreeAllocationUnits' , '<Q', 0],
        ['SectorsPerAllocationUnit' , '<L', 0],
        ['BytesPerSector'           , '<L', 0],
    ]


class SMBQueryFsDeviceEntry(Struct):
    st = [
        ['DeviceType'             , '<L', 0],
        ['DeviceCharacteristics'  , '<L', 0],
    ]


class SMBQueryFsAttributeEntry(Struct):
    st = [
        ['FileSystemAttributes'     , '<L', 0],
        ['MaxFileNameLengthInBytes' , '<L', 0],
        ['LengthOfFileSystemName'   , '<L', 0],
        ['FileSystemName'           , '0s', u''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            # Always unicode
            self['FileSystemName'] = data[pos:pos+self['LengthOfFileSystemName']].decode('UTF-16LE').split(u'\0')[0]

    def pack(self):
        label = self['FileSystemName'].encode('UTF-16LE')
        self['LengthOfFileSystemName'] = len(label)
        return Struct.pack(self) + label


#### SET Information levels
class SMBSetInformationStandardEntry(Struct):
    st = [
        ['CreationDate'   , '<H', 0],
        ['CreationTime'   , '<H', 0],
        ['LastAccessDate' , '<H', 0],
        ['LastAccessTime' , '<H', 0],
        ['LastWriteDate'  , '<H', 0],
        ['LastWriteTime'  , '<H', 0],
        ['Reserved'       , '10s', '\0'*10],
    ]


class SMBSetFileBasicEntry(Struct):
    st = [
        ['CreationTime'       , '<Q', 0],
        ['LastAccessTime'     , '<Q', 0],
        ['LastWriteTime'      , '<Q', 0],
        ['ChangeTime'         , '<Q', 0],
        ['ExtFileAttributes'  , '<L', 0],
        ['Reserved'           , '<L', 0],
    ]


class SMBSetFileDispositionEntry(Struct):
    st = [
        ['DeletePending' , '<B', 0],
    ]


class SMBSetFileAllocationEntry(Struct):
    st = [
        ['AllocationSize' , '<Q', 0],
    ]


class SMBSetFileEndOfFileEntry(Struct):
    st = [
        ['EndOfFile'   , '<Q', 0],
    ]


class SMBErrorResponse(Struct):
    st = [
        ['WordCount' , '<B', 0],
        ['ByteCount' , '<H', 0],
        ['ErrorData' , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['ErrorData'] = data[pos:pos+self['ByteCount']]

    def pack(self):
        self['ByteCount'] = len(self['ErrorData'])
        return Struct.pack(self) + self['ErrorData']

class SMBTreeConnectAndXRequest(Struct):
    st = [
        ['WordCount'      , '<B', 4],
        ['AndXCommand'    , '<B', 0xff],
        ['AndXReserved'   , '<B', 0],
        ['AndXOffset'     , '<H', 0],
        ['Flags'          , '<H', TREE_CONNECT_ANDX_EXTENDED_RESPONSE|TREE_CONNECT_ANDX_EXTENDED_SIGNATURES],
        ['PasswordLength' , '<H', 0],
        ['ByteCount'      , '<H', 0],
        ['Password'       , '0s', ''],
        ['Path'           , '0s', u''],
        ['Service'        , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['Password'] = data[pos:pos + self['PasswordLength']]
            pos += self['PasswordLength']

            if is_unicode == True and (pos % 2) == 1:
                pos += 1

            path, size = extractNullTerminatedString(data, pos, is_unicode)
            self['Path'] = path.split(u'\0')[0]
            pos += size
            service, _ = extractNullTerminatedString(data, pos, False) #Always ASCII
            self['Service'] = service.split(u'\0')[0]

    def pack(self):
        self['PasswordLength'] = len(self['Password'])
        path = self['Path']
        path += u'\0'

        if self.is_unicode == True:
            path = path.encode('UTF-16LE')
        else:
            path = path.encode('ASCII', 'ignore')

        service = self['Service']
        service += u'\0'
        service = service.encode('ASCII', 'ignore')

        self['ByteCount'] = len(self['Password']) + len(path) + len(service)
        data = Struct.pack(self)
        return data + self['Password'] + path + service


class SMBTreeConnectAndXResponse(Struct):
    st = [
        ['WordCount'                     , '<B', 7],
        ['AndXCommand'                   , '<B', 0xff],
        ['AndXReserved'                  , '<B', 0],
        ['AndXOffset'                    , '<H', 0],
        ['OptionalSupport'               , '<H', 0],
        ['MaximalShareAccessRights'      , '<L', 0],
        ['GuestMaximalShareAccessRights' , '<L', 0],
        ['ByteCount'                     , '<H', 0],
        ['Service'                       , '0s', u''],
        ['NativeFileSystem'              , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            service, length = extractNullTerminatedString(data, pos, False) #Always ASCII
            self['Service'] = service.split(u'\0')[0]
            pos += length

            if is_unicode == True and (pos % 2) == 1:
                pos += 1

            nativefilesystem, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['NativeFileSystem'] = nativefilesystem.split(u'\0')[0]

    def pack(self):
        #XXX: There will be an issue here if the client doesn't have TREE_CONNECT_ANDX_EXTENDED_RESPONSE|TREE_CONNECT_ANDX_EXTENDED_SIGNATURES set --Kostya
        service  = self['Service']
        service  += u'\0'
        service  = service.encode('ASCII')
        nativefilesystem = self['NativeFileSystem']
        nativefilesystem += u'\0'

        pad = ''

        if self.is_unicode == True:
            size = self.calcsize() + len(service)
            if (size % 2) == 1:
                pad = '\0'
            nativefilesystem = nativefilesystem.encode('UTF-16LE')
        else:
            nativefilesystem = nativefilesystem.encode('ASCII')

        self['ByteCount'] = len(service) + len(pad) + len(nativefilesystem)
        data = Struct.pack(self)
        return data + service + pad + nativefilesystem

class SMBNTCreateAndXRequest(Struct):
    st = [
        ['WordCount'          , '<B', 24],
        ['AndXCommand'        , '<B', 0xff],
        ['AndXReserved'       , '<B', 0],
        ['AndXOffset'         , '<H', 0],
        ['Reserved'           , '<B', 0],
        ['NameLength'         , '<H', 0],
        ['Flags'              , '<L', NT_CREATE_REQUEST_EXTENDED_RESPONSE],
        ['RootDirectoryFid'   , '<L', 0],
        ['DesiredAccess'      , '<L', SYNCHRONIZE | FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES | READ_CONTROL],
        ['AllocationSize'     , '<Q', 0],
        ['ExtFileAttributes'  , '<L', 0],
        ['ShareAccess'        , '<L', FILE_SHARE_READ | FILE_SHARE_WRITE],
        ['CreateDisposition'  , '<L', FILE_OPEN],
        ['CreateOptions'      , '<L', FILE_NON_DIRECTORY_FILE],
        ['ImpersonationLevel' , '<L', SECURITY_IMPERSONATION],
        ['SecurityFlags'      , '<B', SMB_SECURITY_EFFECTIVE_ONLY | SMB_SECURITY_CONTEXT_TRACKING],
        ['ByteCount'          , '<H', 0],
        ['Name'               , '0s', u'']
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            if is_unicode == True and (pos % 2) == 1:
                pos += 1
            name, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['Name'] = name.split(u'\0')[0]

    def pack(self):
        name = self['Name']
        name += u'\0'

        pad = ''

        if self.is_unicode == True:
            name = name.encode('UTF-16LE')
            if (self.calcsize() % 2) == 1:
                pad = '\0'
        else:
            name = name.encode('ASCII')

        self['NameLength'] = len(name) if not self.is_unicode else len(name)-2
        self['ByteCount'] = len(pad) + len(name)
        data = Struct.pack(self)
        return data + pad + name

class SMBNTCreateAndXResponse(Struct):
    st = [
        ['WordCount'                      , '<B', 42],
        ['AndXCommand'                    , '<B', 0xff],
        ['AndXReserved'                   , '<B', 0],
        ['AndXOffset'                     , '<H', 0],
        ['OplockLevel'                    , '<B', 0],
        ['Fid'                            , '<H', 0],
        ['CreateAction'                   , '<L', 0],
        ['CreateTime'                     , '<Q', 0],
        ['LastAccessTime'                 , '<Q', 0],
        ['LastWriteTime'                  , '<Q', 0],
        ['LastChangeTime'                 , '<Q', 0],
        ['ExtFileAttributes'              , '<L', 0],
        ['AllocationSize'                 , '<Q', 0],
        ['EndOfFile'                      , '<Q', 0],
        ['FileType'                       , '<H', 0],
        ['DeviceState_or_FileStatusFlags' , '<H', 0],
        ['Directory'                      , '<B', 0],
        ['VolumeGUID'                     , '16s', ''],
        ['FileId'                         , '8s', ''],
        ['MaximalAccessRights'            , '<L', 0],
        ['GuestMaximalAccessRights'       , '<L', 0],
        ['ByteCount'                      , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

class SMBOpenAndXRequest(Struct):
    st = [
        ['WordCount'        , '<B', 15],
        ['AndXCommand'      , '<B', 0xff],
        ['AndXReserved'     , '<B', 0],
        ['AndXOffset'       , '<H', 0],
        ['Flags'            , '<H', SMB_OPEN_EXTENDED_RESPONSE],
        ['DesiredAccess'    , '<H', 0],
        ['SearchAttributes' , '<H', 0],
        ['FileAttributes'   , '<H', 0],
        ['CreationTime'     , '<L', 0],
        ['OpenFunction'     , '<H', 0],
        ['AllocationSize'   , '<L', 0],
        ['Reserved'         , '<Q', 0],
        ['ByteCount'        , '<H', 0],
        ['BufferFormat'     , '<B', 4], #XXX: What is this? It's in the doc but it's weird --Kostya
        ['FileName'         , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            if is_unicode == True and (pos % 2) == 1:
                pos += 1
            filename, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        pad = ''
        name = self['FileName']
        name += u'\0'

        if self.is_unicode:
            if self.calcsize() % 2 == 1:
                pad = '\0'

            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(pad) + len(name)
        data = Struct.pack(self)
        return data + pad + name

class SMBOpenAndXResponse(Struct):
    st = [
        ['WordCount'                , '<B', 19],
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Fid'                      , '<H', 0],
        ['FileAttributes'           , '<H', 0],
        ['LastWriteTimeInSeconds'   , '<L', 0],
        ['DataSize'                 , '<L', 0],
        ['GrantedAccess'            , '<H', 0], # access rights
        ['FileType'                 , '<H', 0],
        ['DeviceState'              , '<H', 0],
        ['Action'                   , '<H', 0], # open results
        ['ServerFid'                , '<L', 0],
        ['Reserved'                 , '<H', 0],
        ['MaximalAccessRights'      , '<L', 0],
        ['GuestMaximalAccessRights' , '<L', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

class SMBOpenRequest(Struct):
    st = [
        ['WordCount'        , '<B', 2],
        ['AccessMode'       , '<H', 0],
        ['SearchAttributes' , '<H', 0],
        ['ByteCount'        , '<H', 2],
        ['BufferFormat'     , '<B', 4],
        ['FileName'         , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename, _ = extractNullTerminatedString(data, pos, is_unicode)
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        name = self['FileName']
        name += u'\0'

        if self.is_unicode:
            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(name)
        return Struct.pack(self) + name


class SMBOpenResponse(Struct):
    st = [
        ['WordCount'                , '<B', 7],
        ['Fid'                      , '<H', 0],
        ['FileAttributes'           , '<H', 0],
        ['LastModified'             , '<L', 0],
        ['FileSize'                 , '<L', 0],
        ['AccessMode'               , '<H', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data = None, is_unicode = False):
        Struct.__init__(self, data)


class SMBReadAndXRequest(Struct):
    st = [
        ['WordCount'                , '<B', 10],
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Fid'                      , '<H', 0],
        ['Offset'                   , '<L', 0],
        ['MaxCount'                 , '<H', 0],
        ['MinCount'                 , '<H', 0],
        ['Reserved'                 , '<L', 0],
        ['Remaining'                , '<H', 0],
        ['OffsetHigh'               , '0s', ''],
        ['ByteCount'                , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            # Need to take into account optional field
            # We can just ignore ByteCount since it is unused
            if self['WordCount'] == 10:
                self['OffsetHigh'] = ''
            elif self['WordCount'] == 12:
                self['OffsetHigh'] = data[pos:pos + 4]

    def pack(self):
        if self['OffsetHigh'] != '':
            self['WordCount'] = 12

        return Struct.pack(self) + self['OffsetHigh'] + pack('<H', 0x0000)

class SMBReadAndXResponse(Struct):
    st = [
        ['WordCount'                , '<B', 12],
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Remaining'                , '<H', 0],
        ['DataCompactionMode'       , '<H', 0],
        ['Reserved'                 , '<H', 0],
        ['DataLength'               , '<H', 0],
        ['DataOffset'               , '<H', 0],
        ['Reserved1'                , '10s', '\0' * 10],
        ['ByteCount'                , '<H', 0],
        ['Pad'                      , '0s', ''],
        ['Data'                     , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            self['Pad'] = data[self.calcsize():pos]
            self['Data'] = data[pos:pos+self['DataLength']]

    def pack(self):
        if self['Pad'] == '':
            pass #XXX: See 2.2.4.42.2, which is unintelligible --Kostya
        self['DataLength'] = len(self['Data'])
        self['DataOffset'] = SMB_HEADER_SIZE + self.calcsize() + len(self['Pad'])
        self['ByteCount'] = len(self['Pad']) + len(self['Data'])

        return Struct.pack(self) + self['Pad']+ self['Data']

class SMBCloseRequest(Struct):
    st = [
        ['WordCount' , '<B', 3],
        ['Fid'       , '<H', 0],
        ['LastWrite' , '<L', 0xffffffff],
        ['ByteCount' , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBCloseResponse(Struct):
    st = [
        ['WordCount' , '<B', 0],
        ['ByteCount' , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBWriteAndXRequestOld(Struct):
    st = [
        ['WordCount'                , '<B', 14],
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Fid'                      , '<H', 0],
        ['Offset'                   , '<L', 0],
        ['Reserved'                 , '<L', 0],
        ['WriteMode'                , '<H', 0],
        ['Remaining'                , '<H', 0],
        ['Reserved1'                , '<H', 0],
        ['DataLength'               , '<H', 0],
        ['DataOffset'               , '<H', 0],
        ['OffsetHigh'               , '<L', 0],
        ['ByteCount'                , '<H', 0],
        ['Pad'                      , '0s', ''],
        ['Data'                     , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            self['Pad'] = data[self.calcsize():pos]
            self['Data'] = data[pos:pos+self['DataLength']]

    def pack(self):
        if self['Pad'] == '':
            if (self.calcsize() % 2) == 1:
                self['Pad'] = '\0'
        #self['Remaining'] = len(self['Data']) #XXX: Check this for fragmented requests --Kostya
        self['DataLength'] = len(self['Data'])
        self['DataOffset'] = SMB_HEADER_SIZE + self.calcsize() + len(self['Pad'])
        self['ByteCount'] = len(self['Pad']) + len(self['Data'])

        return Struct.pack(self) + self['Pad'] + self['Data']

class SMBWriteAndXResponseOld(Struct):
    st = [
        ['WordCount'                , '<B', 6],
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Count'                    , '<H', 0],
        ['Remaining'                , '<H', 0],
        ['Reserved'                 , '<L', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBReadRequest(Struct):
    st = [
        ['WordCount'                        , '<B', 5],
        ['Fid'                              , '<H', 0],
        ['CountOfBytesToRead'               , '<H', 0],
        ['ReadOffsetInBytes'                , '<L', 0],
        ['EstimateOfRemainingBytesToBeRead' , '<H', 0],
        ['ByteCount'                        , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)



class SMBReadResponse(Struct):
    st = [
        ['WordCount'            , '<B', 5],
        ['CountOfBytesReturned' , '<H', 0],
        ['Reserved'             , '8s', '\0'*8],
        ['ByteCount'            , '<H', 3],
        ['BufferFormat'         , '<B', 1],
        ['CountOfBytesRead'     , '<H', 0],
        ['Bytes'                , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['Bytes'] = data[pos:pos+self['CountOfBytesRead']]

    def pack(self):
        self['ByteCount'] = 3 + len(self['Bytes'])
        return Struct.pack(self) + self['Bytes']



class SMBWriteRequest(Struct):
    st = [
        ['WordCount'      , '<B', 5],
        ['Fid'            , '<H', 0],
        ['Count'          , '<H', 0],
        ['Offset'         , '<L', 0],
        ['Estimate'       , '<H', 0],
        ['ByteCount'      , '<H', 3],
        ['BufferFormat'   , '<B', 1],
        ['DataLength'     , '<H', 0], # Must be the same as Count
        ['Data'           , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            self['Data'] = data[pos:]

    def pack(self):
        dlen = len(self['Data'])

        self['Count'] = dlen
        self['DataLength'] = dlen
        self['ByteCount'] = dlen + 3

        return Struct.pack(self) + self['Data']


class SMBWriteResponse(Struct):
    st = [
        ['WordCount'    , '<B', 1],
        ['Count'        , '<H', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

class SMBSetInformation2Request(Struct):
    st = [
        ['WordCount'      , '<B', 7],
        ['Fid'            , '<H', 0],
        ['CreateDate'     , '<H', 0],
        ['CreateTime'     , '<H', 0],
        ['LastAccessDate' , '<H', 0],
        ['LastAccessTime' , '<H', 0],
        ['LastWriteDate'  , '<H', 0],
        ['LastWriteTime'  , '<H', 0],
        ['ByteCount'      , '<H', 3],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBSetInformation2Response(Struct):
    st = [
        ['WordCount'    , '<B', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

class SMBQueryInformationRequest(Struct):
    st = [
        ['WordCount'    , '<B', 0],
        ['ByteCount'    , '<H', 2],
        ['BufferFormat' , '<B', 0x04],
        ['FileName'     , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename = extractNullTerminatedString(data, pos, is_unicode)[0]
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        filename = self['FileName']
        filename += u'\0'

        if self.is_unicode:
            filename = filename.encode('UTF-16LE')
        else:
            filename = filename.encode('ASCII')

        self['ByteCount'] = len(self['FileName']) + 1
        return Struct.pack(self) + filename

class SMBQueryInformationResponse(Struct):
    st = [
        ['WordCount'                , '<B', 0x0A],
        ['FileAttributes'           , '<H', 0],
        ['LastWriteTime'            , '<L', 0],
        ['FileSize'                 , '<L', 0],
        ['Reserved'                 , '10s', '\0'*10],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data = None, is_unicode = False):
        Struct.__init__(self, data)

class SMBQueryInformation2Request(Struct):
    st = [
        ['WordCount'                , '<B', 1],
        ['Fid'                      , '<H', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data = None, is_unicode = False):
        Struct.__init__(self, data)

class SMBQueryInformation2Response(Struct):
    st = [
        ['WordCount'                , '<B', 0x0B],
        ['CreateDate'               , '<H', 0],
        ['CreateTime'               , '<H', 0],
        ['LastAccessDate'           , '<H', 0],
        ['LastAccessTime'           , '<H', 0],
        ['LastWriteDate'            , '<H', 0],
        ['LastWriteTime'            , '<H', 0],
        ['FileDataSize'             , '<L', 0],
        ['FileAllocationSize'       , '<L', 0],
        ['FileAttributes'           , '<H', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data = None, is_unicode = False):
        Struct.__init__(self, data)

class SMBIoctlRequest(Struct):
    st = [
        ['WordCount'           , '<B', 14],
        ['FID'                 , '<H', 0],
        ['Category'            , '<H', 0],
        ['Function'            , '<H', 0],
        ['TotalParameterCount' , '<H', 0],
        ['TotalDataCount'      , '<H', 0],
        ['MaxParameterCount'   , '<H', 0],
        ['MaxDataCount'        , '<H', 0],
        ['Timeout'             , '<L', 0],
        ['Reserved'            , '<H', 0],
        ['ParameterCount'      , '<H', 0],
        ['ParameterOffset'     , '<H', 0],
        ['DataCount'           , '<H', 0],
        ['DataOffset'          , '<H', 0],
        ['ByteCount'           , '<H', 0],
        ['Pad1'                , '0s', ''],
        ['Parameters'          , '0s', ''],
        ['Pad2'                , '0s', ''],
        ['Data'                , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['Data'] = data[pos:pos + size]

    def pack(self):
        self['DataCount'] = len(self['Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize()
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        data = Struct.pack(self)
        data += self['Pad1'] + self['Parameters'] + self['Pad2'] + self['Data']

        return data

class SMBIoctlResponse(Struct):
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
        ['Parameters'            , '0s', ''],
        ['Pad2'                  , '0s', ''],
        ['Data'                  , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            self['Pad1'] = data[pos:self['ParameterOffset'] - SMB_HEADER_SIZE]
            pos = self['ParameterOffset'] - SMB_HEADER_SIZE
            size = self['ParameterCount']
            self['Parameters'] = data[pos:pos + size]
            pos += size
            self['Pad2'] = data[pos:self['DataOffset'] - SMB_HEADER_SIZE]
            pos = self['DataOffset'] - SMB_HEADER_SIZE
            size = self['DataCount']
            self['Data'] = data[pos:pos + size]

    def pack(self):
        self['DataCount'] = len(self['Data'])
        if self['TotalDataCount'] == 0:
            self['TotalDataCount'] = self['DataCount']
        self['ParameterCount'] = len(self['Parameters'])
        if self['TotalParameterCount'] == 0:
            self['TotalParameterCount'] = self['ParameterCount']
        size = SMB_HEADER_SIZE + self.calcsize()
        if self['Pad1'] == '':
            if (size % 4) != 0:
                self['Pad1'] = '\0' * (4 - (size % 4))
        size += len(self['Pad1'])
        self['ParameterOffset'] = size
        size += len(self['Parameters'])
        if self['Pad2'] == '':
            if (size % 4) != 0:
                self['Pad2'] = '\0' * (4 - (size % 4))
        size += len(self['Pad2'])
        self['DataOffset'] = size
        data = Struct.pack(self)
        data += self['Pad1'] + self['Parameters'] + self['Pad2'] + self['Data']

        return data

class SMBDeleteRequest(Struct):
    st = [
        ['WordCount'                , '<B', 1],
        ['SearchAttributes'         , '<H', 0],
        ['ByteCount'                , '<H', 2],
        ['BufferFormat'             , '<B', 0x04],
        ['FileName'                 , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename = extractNullTerminatedString(data[pos:], is_unicode = self.is_unicode)[0]
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        name = self['FileName']
        name += u'\0'

        if self.is_unicode:
            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(name)
        return Struct.pack(self) + name

class SMBDeleteResponse(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBCreateDirectoryRequest(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 2],
        ['BufferFormat'             , '<B', 0x04],
        ['DirectoryName'            , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            directory = extractNullTerminatedString(data[pos:], is_unicode = self.is_unicode)[0]
            self['DirectoryName'] = directory.split(u'\0')[0]

    def pack(self):
        name = self['DirectoryName']
        name += u'\0'

        if self.is_unicode:
            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(name)
        return Struct.pack(self) + name


class SMBCreateDirectoryResponse(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBDeleteDirectoryRequest(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 2],
        ['BufferFormat'             , '<B', 0x04],
        ['DirectoryName'            , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            directory = extractNullTerminatedString(data[pos:], is_unicode = self.is_unicode)[0]
            self['DirectoryName'] = directory.split(u'\0')[0]

    def pack(self):
        name = self['DirectoryName']
        name += u'\0'

        if self.is_unicode:
            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(name)
        return Struct.pack(self) + name



class SMBDeleteDirectoryResponse(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBCheckDirectoryRequest(Struct):
    st = [
        ['WordCount'    , '<B', 0],
        ['ByteCount'    , '<H', 2],
        ['BufferFormat' , '<B', 4],
        ['DirectoryName', '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            directory = extractNullTerminatedString(data[pos:], is_unicode = self.is_unicode)[0]
            self['DirectoryName'] = directory.split(u'\0')[0]

    def pack(self):
        name = self['DirectoryName']
        name += u'\0'

        if self.is_unicode:
            name = name.encode('UTF-16LE')
        else:
            name = name.encode('ASCII')

        self['ByteCount'] = 1 + len(name)
        return Struct.pack(self) + name


class SMBCheckDirectoryResponse(Struct):
    st = [
        ['WordCount'                , '<B', 0],
        ['ByteCount'                , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBFlushRequest(Struct):
    st = [
        ['WordCount'     , '<B', 1],
        ['Fid'           , '<H', 0],
        ['ByteCount'     , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBFlushResponse(Struct):
    st = [
        ['WordCount'     , '<B', 0],
        ['ByteCount'     , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBRenameRequest(Struct):
    st = [
        ['WordCount'          , '<B', 1],
        ['SearchAttributes'   , '<H', 0],
        ['ByteCount'          , '<H', 2],
        ['BufferFormat1'      , '<B', 4],
        ['OldFileName'        , '0s', u''],
        ['BufferFormat2'      , '0s', ''],
        ['NewFileName'        , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            oldname, size1 = extractNullTerminatedString(data[pos:], is_unicode=self.is_unicode)
            self['OldFileName'] = oldname.split(u'\0')[0]
            pos += size1

            self['BufferFormat2'] = data[pos]
            pos += 1

            if pos % 2:
                pos += 1

            newfilename = extractNullTerminatedString(data[pos:], is_unicode=self.is_unicode)[0]
            self['NewFileName'] = newfilename.split(u'\0')[0]


    def pack(self):
        oldfilename = self['OldFileName'] + u'\0'
        newfilename = self['NewFileName'] + u'\0'

        if self.is_unicode:
            oldfilename = oldfilename.encode('UTF-16LE')
            newfilename = newfilename.encode('UTF-16LE')
        else:
            oldfilename = oldfilename.encode('ASCII')
            newfilename = newfilename.encode('ASCII')

        pad = ''
        pos = self.calcsize() + len(oldfilename)

        if pos % 2:
            pad = '\x00'

        return Struct.pack(self) + oldfilename + '\x04' + pad + newfilename


class SMBRenameResponse(Struct):
    st = [
        ['WordCount'        , '<B', 0],
        ['ByteCount'        , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBSetInformationRequest(Struct):
    st = [
        ['WordCount'        , '<B', 8],
        ['FileAttributes'   , '<H', 0],
        ['LastWriteTime'    , '<L', 0],
        ['Reserved'         , '10s', '\0'*10],
        ['ByteCount'        , '<H', 2],
        ['BufferFormat'     , '<B', 4],
        ['FileName'         , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()

            filename = extractNullTerminatedString(data, pos, is_unicode)[0]
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        filename = self['FileName'] + u'\0'

        if self.is_unicode:
            filename = self['FileName'].encode('UTF-16LE')
        else:
            filename = self['FileName'].encode('ASCII')

        self['ByteCount'] = 1 + len(filename)
        return Struct.pack(self) + filename


class SMBSetInformationResponse(Struct):
    st = [
        ['WordCount'       , '<B', 0],
        ['ByteCount'       , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBLockingAndxRequest(Struct):
    st = [
        ['WordCount'                   , '<B', 8],
        ['AndXCommand'                 , '<B', 0xff],
        ['AndXReserved'                , '<B', 0],
        ['AndXOffset'                  , '<H', 0],
        ['Fid'                         , '<H', 0],
        ['TypeOfLock'                  , '<B', 0],
        ['NewOpLockLevel'              , '<B', 0],
        ['Timeout'                     , '<L', 0],
        ['NumberOfRequestedUnlocks'    , '<H', 0],
        ['NumberOfRequestedLocks'      , '<H', 0],
        ['ByteCount'                   , '<H', 0],
        ['Unlocks'                     , '0s', ''],
        ['Locks'                       , '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)

        if data is not None:
            pos = self.calcsize()
            unlocks = self['NumberOfRequestedUnlocks']
            locks = self['NumberOfRequestedLocks']

            if self['TypeOfLock'] & LARGE_FILES:
                size1 = pos+20*unlocks
                self['Unlocks'] = data[pos:size1]
                self['Locks'] = data[size1:size1+(20*locks)]
            else:
                size1 = pos+(10*unlocks)
                self['Unlocks'] = data[pos:size1]
                self['Locks'] = data[size1:size1+(10*locks)]

    def pack(self):
        if self['TypeOfLock'] & LARGE_FILES:
            self['NumberOfRequestedUnlocks'] = len(self['Unlocks']) / 20
            self['NumberOfRequestedLocks'] = len(self['Locks']) / 20
        else:
            self['NumberOfRequestedUnlocks'] = len(self['Unlocks']) / 10
            self['NumberOfRequestedLocks'] = len(self['Locks']) / 10


class SMBLockingAndxResponse(Struct):
    st = [
        ['WordCount'    , '<B', 2],
        ['AndXCommand'  , '<B', 0xff],
        ['AndXReserved' , '<B', 0],
        ['AndxOffset'   , '<H', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBFindClose2Request(Struct):
    st = [
        ['WordCount'    , '<B', 1],
        ['SearchHandle' , '<H', 0],
        ['ByteCount'    , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self,data)


class SMBFindClose2Response(Struct):
    st = [
        ['WordCount'  , '<B', 0],
        ['ByteCount'  , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)


class SMBNtCancelRequest(Struct):
    st = [
        ['WordCount'  , '<B', 0],
        ['ByteCount'  , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)



class Trans2FindFirst2RequestPar(Struct):
    st = [
        ['SearchAttributes'  , '<H', 0],
        ['SearchCount'       , '<H', 0],
        ['Flags'             , '<H', 0],
        ['InformationLevel'  , '<H', 0],
        ['SearchStorageType' , '<L', 0],
        ['FileName'          , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename, _ = extractNullTerminatedString(data[pos:], is_unicode=self.is_unicode)
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        filename = self['FileName'] + u'\0'
        if self.is_unicode:
            filename = self['FileName'].encode('UTF-16LE')
        else:
            filename = self['FileName'].encode('ASCII')

        return Struct.pack(self) + filename


class Trans2FindFirst2ResponsePar(Struct):
    st = [
        ['SID'            , '<H', 0],
        ['SearchCount'    , '<H', 0],
        ['EndOfSearch'    , '<H', 0],
        ['EaErrorOffset'  , '<H', 0],
        ['LastNameOffset' , '<H', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class Trans2Open2RequestPar(Struct):
    st = [
        ['Flags'            , '<H', 0],
        ['AccessMode'       , '<H', 0],
        ['Reserved1'        , '<H', 0],
        ['FileAttributes'   , '<H', 0],
        ['CreationTime'     , '<L', 0],
        ['OpenMode'         , '<H', 0],
        ['AllocationSize'   , '<L', 0],
        ['Reserved'         , '10s', '\0'*10],
        ['FileName'         , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename = extractNullTerminatedString(data, pos, is_unicode)[0]
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        filename = self['FileName'] + u'\0'
        if self.is_unicode:
            filename = filename.encode('UTF-16LE')
        else:
            filename= filename.encode('ASCII')

        return Struct.pack(self) + filename


class Trans2Open2ResponsePar(Struct):
    st = [
        ['FID'                           , '<H', 0],
        ['FileAttributes'                , '<H', 0],
        ['CreationTime'                  , '<L', 0],
        ['FileDataSize'                  , '<L', 0],
        ['AccessMode'                    , '<H', 0],
        ['ResourceType'                  , '<H', 0],
        ['NMPipeStatus'                  , '<H', 0],
        ['ActionTaken'                   , '<H', 0],
        ['Reserved'                      , '<L', 0],
        ['ExtendedAttributeErrorOffset'  , '<H', 0],
        ['ExtendedAttributeLength'       , '<L', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class Trans2SetFileInformationRequestPar(Struct):
    st = [
        ['FID'                   , '<H', 0],
        ['InformationLevel'      , '<H', 0],
        ['Reserved'              , '<H', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)


class Trans2SetPathInformationRequestPar(Struct):
    st = [
        ['InformationLevel'     , '<H', 0],
        ['Reserved'             , '<L', 0],
        ['FileName'             , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            filename = extractNullTerminatedString(data, pos, is_unicode)[0]
            self['FileName'] = filename.split(u'\0')[0]

    def pack(self):
        filename = self['FileName'] + u'\0'

        if self.is_unicode:
            filename = filename.encode('UTF16-LE')
        else:
            filename = filename.encode('ASCII')

        return Struct.pack(self) + filename


class TransQueryNMPipeInfoResponsePar(Struct):
    st = [
        ['OutputBufferSize'   , '<H', 0],
        ['InputBufferSize'    , '<H', 0],
        ['MaximumInstances'   , '<B', 0],
        ['CurrentInstances'   , '<B', 0],
        ['PipeNameLength'     , '<B', 0],
        ['PipeName'           , '0s', u''],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        self.is_unicode = is_unicode

        if data is not None:
            pos = self.calcsize()
            pipename = extractNullTerminatedString(data, pos, is_unicode)[0]
            self['PipeName'] =  pipename.split(u'\0')[0]

    def pack(self):
        pipename = self['PipeName'] + '\0'

        if self.is_unicode:
            pipename = pipename.encode('UTF-16LE')
        else:
            pipename = pipename.encode('ASCII')

        return Struct.pack(self) + pipename


class TransPeekNMPipeResponsePar(Struct):
    st = [
        ['ReadDataAvailable'   , '<H', 0],
        ['MessageBytesLength'  , '<H', 0],
        ['NamedPipeState'      , '<H', 0],
    ]


################################################################################
#                                                                              #
#               Hybrid classes between the OLD and the NEW API.                #
#                                                                              #
################################################################################

class SMBHeader(Struct):
    st = [
        ['Protocol'         , '4s', '\xFFSMB'],
        ['Command'          , '<B', 0],
        ['Status'           , '<L', 0],
        ['Flags'            , '<B', SMB_FLAGS_CASE_INSENSITIVE],
        ['Flags2'           , '<H', SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_LONG_NAMES | SMB_FLAGS2_KNOWS_EAS],
        ['PidHigh'          , '<H', 0],
        ['SecuritySignature', '8s', '\0' * 8],
        ['Unused'           , '<H', 0],
        ['TID'              , '<H', 0],
        ['PID'              , '<H', 0],
        ['UID'              , '<H', 0],
        ['MID'              , '<H', 0],
    ]

    def __init__(self, data=None, is_unicode=False):
        Struct.__init__(self, data)
        if data is None and is_unicode == True:
            self['Flags2'] |= SMB_FLAGS2_UNICODE


################################################################################
#                                                                              #
#                              [NEW] SMB TYPES                                 #
#                                                                              #
################################################################################


###
# SMB types -- They may be moved within an independant file at some point.
###

class SMBEmptyParameters(Struct):
    st = []

class SMBEmptyData(Struct):
    st = []

class SMBDialect(Struct):
    st = [
        ['BufferFormat',  "B",        0x02],
        ['DialectString', OEM_String, OEM_String("")],
    ]

class SMBDialectArray(Array):
    type = SMBDialect

class SMB_FEA(Struct):
    _attribute_value = lambda ctx: (ctx.self['AttributeValueLengthInBytes'],)

    st = [
        ['ExtendedAttributeFlag',       '<B', 0],
        ['AttributeNameLengthInBytes',  '<B', 0],
        ['AttributeValueLengthInBytes', '<H', 0],
        ['AttributeName',               OEM_String, OEM_String(u"")],
        ['AttributeValue',              OEM_Array,  OEM_Array(""), _attribute_value],
    ]

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        return super(SMB_FEA, cls).deserialize(data, context)

class SMB_FEA_Array(Array):
    type = SMB_FEA

# XXX: FEAList is raw byte data instead of dynamically serialized FEA structs.
class SMB_FEA_LIST(Struct):
    _fea_list = lambda ctx: (ctx.self['SizeOfListInBytes'],)

    st = [
        ['SizeOfListInBytes', '<I', 0],
        ['FEAList',           UCHAR_Array, UCHAR_Array(0), _fea_list]
    ]


################################################################################
#                                                                              #
#               Important classes specific to the new API:                     #
#                 SMB_Parameters, SMB_Data, SMB_Command                        #
#                                                                              #
################################################################################

SMB_Header = SMBHeader

###
# The SMB_Parameters class
###

class SMB_Parameters(Serializable):
    header_size = 1

    def __init__(self, words=""):
        if not isinstance(words, (str, Serializable)):
            msg = "'words' is not an instance of 'Serializable' or 'str'"
            raise TypeError(msg.format(words))

        self._words = words

    def __str__(self):
        if isinstance(self._words, str):
            return self.serialize().encode('hex')
        else:
            return str(self._words)

    def count(self, context=None):
        return (self.size(context) - 1) / 2

    def WordCount(self, context=None):
        return self.count(context)

    @property
    def words(self):
        return self._words

    @property
    def Words(self):
        return self._words

    def size(self, context=None):
        return len(self.serialize(context))

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if len(data) < 1:
            msg = "'data' is too short: expected at least 1 byte."
            raise DeserializationError(msg)

        # Decode 'WordCount' and wrap any exception as a DeserializationError.
        try:
            WordCount = unpack("B", data[0])[0]
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

        if len(data) - 1 < WordCount * 2:
            msg = "'data' is too short; expected at least {0} bytes."
            raise DeserializationError(msg.format(WordCount * 2))

        context.offset += 1
        try:
            obj = cls(data[1:WordCount * 2 + 1])
            context.offset += WordCount * 2
            return obj
        except:
            context.offset -= 1
            tb = traceback.format_exc()
            raise DeserializationError(tb)

    def serialize(self, context=None):
        if context is None:
            _context = SMB_SerializationContext()
        else:
            _context = copy.deepcopy(context)

        # Already account for the byte used to serialize 'WordCount'.
        # This is necessary to properly serialize 'self.words'.
        _context.offset += 1

        if isinstance(self._words, str):
            data             = self._words
            _context.offset += len(data)
        else:
            # We have a 'Serializable' object, so we try to serialize it.
            data = self._words.serialize(_context)

        if len(data) % 2 != 0:
            raise SerializationError("serialized data is not a multiple of words")

        if len(data) > 255:
            raise SerializationError("serialized data is longer than 255 bytes")

        try:
            data = pack("B", len(data) / 2) + data
        except:
            tb = traceback.format_exc()
            raise SerializationError(tb)

        # If we had a context supplied, we can now update it, as we have no
        # operations left that can fail.
        if context is not None:
            context.__dict__.update(_context.__dict__)

        return data

###
# The SMB_Data class
###

class SMB_Data(Serializable):
    header_size = 2

    def __init__(self, data="", length=None):
        if not isinstance(data, str) and not isinstance(data, Serializable):
            msg = "'data' is not an instance of 'Serializable' or 'str'"
            raise TypeError(msg)

        self._data   = data
        self._length = length

    def __str__(self):
        if isinstance(self._data, str):
            return self.serialize().encode('hex')
        else:
            return str(self._data)

    def count(self, context=None):
        return self.size() - self.header_size

    def ByteCount(self, context=None):
        return self.count(context)

    def size(self, context=None):
        return len(self.serialize(context))

    @property
    def Bytes(self):
        return self._data

    @property
    def bytes(self):
        return self._data

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if len(data) < cls.header_size:
            msg = "'data' is too short: expected at least {} bytes."
            raise DeserializationError(msg.format(cls.header_size))

        try:
            ByteCount = unpack("<H", data[:cls.header_size])[0]
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

        if len(data) - cls.header_size < ByteCount:
            msg = "'data' is too short; expected at least {0} bytes."
            raise DeserializationError(msg.format(ByteCount))

        try:
            obj = cls(data[cls.header_size:ByteCount + cls.header_size])
            context.offset += ByteCount + cls.header_size
            return obj
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

    def serialize(self, context=None):
        if context is None:
            _context = SMB_SerializationContext()
        else:
            _context = copy.deepcopy(context)

        # Already account for the word used to serialize 'ByteCount'.
        # This is necessary to properly serialize 'self.words'.
        _context.offset += self.header_size

        if isinstance(self._data, str):
            data             = self._data
            _context.offset += len(self._data)
        else:
            # We have a 'Serializable' object, so we try to serialize it.
            # It's possible this raises a 'SerializationError', so we have
            # to ensure we compensate the a-priori incremented context
            # offset and re-raise the exception.
            data = self._data.serialize(_context)

        # We have 2 bytes to encode the length; we can't do more.
        if len(data) > 65535:
            raise SerializationError("serialized data is longer than 65535 bytes")

        try:
            if self._length is not None:
                data = pack("<H", self._length) + data
            else:
                # Quick hack that might be completely incorrect on a general basis.
                # if len(data) == 3:
                #     data = pack("<H", 0)
                # else:
                data = pack("<H", len(data)) + data
        except:
            tb = traceback.format_exc()
            raise SerializationError(tb)

        # If we had a context supplied, we can now update it, as we have no
        # operations left that can fail.
        if context is not None:
            context.__dict__.update(_context.__dict__)

        return data

###
# SMB_Message acts like a template for SMB_Command
###

class SMB_Message(Serializable):
    def __init__(self, header, parameters, data):
        if not isinstance(header, SMB_Header):
            msg = "'header' is of type '{0}' instead of 'SMB_Header'"
            raise TypeError(msg.format(type(header).__name__))

        if not isinstance(parameters, SMB_Parameters):
            msg = "'parameters' is of type '{0}' instead of 'SMB_Parameters'"
            raise TypeError(msg.format(type(parameters).__name__))

        if not isinstance(data, SMB_Data):
            msg = "'data' is of type '{0}' instead of 'SMB_Data'"
            raise TypeError(msg.format(type(data).__name__))

        self._header     = header
        self._parameters = parameters
        self._data       = data

    @property
    def header(self):
        return self._header

    @property
    def parameters(self):
        return self._parameters.words

    @property
    def data(self):
        return self._data.bytes

    def offsetof_parameters(self, key=None, context=None):
        if context is None:
            context = SMB_SerializationContext()

        header_size = self._header.size(context)
        key_offset  = 0
        if key is not None:
            key_offset = self.parameters.offsetof(key, context)

        return header_size + key_offset

    def offsetof_data(self, key=None, context=None):
        if context is None:
            context = SMB_SerializationContext()

        header_size     = self._header.size(context)
        parameters_size = self._parameters.size(context)
        key_offset      = 0
        if key is not None:
            context.offset += self._data.header_size
            key_offset      = self._data.header_size
            key_offset     += self.data.offsetof(key, context)

        return header_size + parameters_size + key_offset

    def __str__(self):
        return str(self._header) + str(self._parameters) + str(self._data)

    def size(self, context=None):
        return len(self.serialize(context))

    def serialize(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        context.header     = self._header
        context.parameters = self._parameters
        context.data       = self._data

        s  = self._header.serialize(context)
        s += self._parameters.serialize(context)
        s += self._data.serialize(context)

        return s

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        start      = 0
        header     = SMB_Header.deserialize(data, context)
        start     += header.size()
        parameters = SMB_Parameters.deserialize(data[start:], context)
        start     += parameters.size()
        data       = SMB_Data.deserialize(data[start:], context)
        return cls(header, parameters, data)

    def sign(self, seq_number, session_key):
        self.header['SecuritySignature'] = pack('<Q', seq_number)
        m = MD5.new()
        m.update(session_key)
        m.update(self.serialize())
        self.header['SecuritySignature'] = m.digest()[:8]
        return self.header['SecuritySignature']

    def verify(self, seq_number, session_key):
        signature = self.header['SecuritySignature']
        self.header['SecuritySignature'] = pack('<LL', seq_number, 0)
        ### TODO ROD: verification = MD5.new(session_key + self.serialize()).digest()

        # Restore the signature so we can verify the packet twice or more.
        self.header['SecuritySignature'] = signature

        ### TODO ROD
        ####if signature != verification[:8]:     TODO
        ####    raise Exception("SIGNATURE FUBAR")


class SMB_Command(SMB_Message):
    __metaclass__ = ABCMeta

    def __init__(self, header=None, parameters=None, data=None, is_unicode=True):
        if not hasattr(self, 'parameters_type'):
            raise AbstractAttributeError(type(self), 'parameters_type')

        if not hasattr(self, 'data_type'):
            raise AbstractAttributeError(type(self), 'data_type')

        if header is None:
            header = SMB_Header(is_unicode=is_unicode)

        if parameters is None:
            parameters = self.parameters_type()

        if data is None:
            data = self.data_type()

        if not isinstance(parameters, self.parameters_type) and not isinstance(parameters, SMBEmptyParameters):
            msg = "'parameters' is of type '{0}' instead of '{1}'"
            given  = type(parameters).__name__
            wanted = self.parameters_type.__name__
            raise TypeError(msg.format(given, wanted))

        if not isinstance(data, (self.data_type, SMB_Data)) and not isinstance(data, SMBEmptyData):
            msg = "'data' is of type '{0}' instead of '{1}'"
            given  = type(data).__name__
            wanted = self.data_type.__name__
            raise TypeError(msg.format(given, wanted))

        parameters = SMB_Parameters(parameters)
        data       = SMB_Data(data)
        super(SMB_Command, self).__init__(header, parameters, data)

    @property
    def parameters(self):
        return self._parameters.words

    @parameters.setter
    def parameters(self, value):
        if not isinstance(value, self.parameters_type):
            msg = "'value' is of type '{}' instead of '{}'"
            raise TypeError(msg.format(type(value).__name__, self.parameters_type.__name__))

        self._parameters = SMB_Parameters(parameters)

    @property
    def data(self):
        return self._data.bytes

    @data.setter
    def data(self, value):
        if not isinstance(value, (self.data_type, SMB_Data)):
            msg = "'value' is of type '{}' instead of '{}'"
            raise TypeError(msg.format(type(value).__name__, self.parameters_type.__name__))

        if type(value) is SMB_Data:
            self._data = value
        else:
            self._data = SMB_Data(data)

    @property
    def status(self):
        return self.header['Status']

    def __str__(self):
        return "{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n{}\n".format(
            "HEADER",
            "======",
            str(self._header),
            "\nPARAMETERS",
            "==========",
            str(self._parameters),
            "\nDATA",
            "====",
            str(self._data)
        )

    def size(self, context=None):
        return len(self.serialize(context))

    def pack(self):
        return self.serialize()

    @classmethod
    def deserialize(cls, data, context=None):
        if not hasattr(cls, 'parameters_type'):
            raise AbstractAttributeError(type(cls), 'parameters_type')

        if not hasattr(cls, 'data_type'):
            raise AbstractAttributeError(type(cls), 'data_type')

        if context is None:
            context = SMB_SerializationContext()

        # Deserialize the message header.
        start              = 0
        header             = SMB_Header.deserialize(data, context)
        start             += header.size()
        context.header     = header

        # Deserialize the parameters.
        param_ctx            = copy.deepcopy(context)
        parameters           = SMB_Parameters.deserialize(data[start:], context)
        start               += parameters.size()
        context.parameters   = parameters
        param_ctx.parameters = parameters

        # Deserialize the data.
        data_ctx       = copy.deepcopy(context)
        data           = SMB_Data.deserialize(data[start:], context)
        context.data   = data
        param_ctx.data = data
        data_ctx.data  = data

        # Deserialize the raw parameter bytes.
        param_ctx.offset += SMB_Parameters.header_size
        if hasattr(cls, 'parameters_factory'):
            parameters = cls.parameters_factory.deserialize_parameters(parameters.words, param_ctx)
        else:
            parameters = cls.parameters_type.deserialize(parameters.words, param_ctx)
        context.parameters  = parameters
        data_ctx.parameters = parameters

        # Deserialize the raw data bytes.
        data_ctx.offset += SMB_Data.header_size
        if hasattr(cls, 'data_factory'):
            data = cls.data_factory.deserialize_data(data.bytes, data_ctx)
        else:
            data = cls.data_type.deserialize(data.bytes, data_ctx)
        context.data = data

        return cls(header, parameters, data)


################################################################################
#                                                                              #
#                             [NEW] SMB COMMANDS                               #
#                                                                              #
################################################################################


###
# SMB_COM_TRANSACTION (0x25)
# https://msdn.microsoft.com/en-us/library/ee441730.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee442061.aspx (response)
###

class SMBTransactionRequestParameters(Struct):

    _setup_count = lambda ctx: (ctx.self['SetupCount'],)

    st = [
        ['TotalParameterCount', '<H', 0],
        ['TotalDataCount',      '<H', 0],
        ['MaxParameterCount',   '<H', 255],
        ['MaxDataCount',        '<H', 255],
        ['MaxSetupCount',       '<B', 235],
        ['Reserved1',           '<B', 0],
        ['Flags',               '<H', 0],
        ['Timeout',             '<L', 0],
        ['Reserved2',           '<H', 0],
        ['ParameterCount',      '<H', 0],
        ['ParameterOffset',     '<H', 0],
        ['DataCount',           '<H', 0],
        ['DataOffset',          '<H', 0],
        ['SetupCount',          '<B', 0],
        ['Reserved3',           '<B', 0],
        ['Setup',               USHORT_Array, USHORT_Array(0), _setup_count],
    ]

class SMBTransactionRequestData(Struct):

    def _trans_parameters(ctx):
        return (ctx.parameters['ParameterCount'],)

    def _trans_data(ctx):
        return (ctx.parameters['DataCount'],)

    st = [
        # XXX: Pad0 is not explicitly present in the structure specification,
        # but described in the 'Name' field.
        ['Pad0',             SMB_Align,   SMB_AlignUnicode()],
        ['Name',             SMB_String,  None],
        ['Pad1',             SMB_Align,   SMB_AlignUnicode()],
        ['Trans_Parameters', UCHAR_Array, UCHAR_Array(0), _trans_parameters],
        ['Pad2',             SMB_Align,   SMB_Align(1)],
        ['Trans_Data',       UCHAR_Array, UCHAR_Array(0), _trans_data],
    ]

    def __init__(self, unicode_strings=True, oem_codepage='latin1'):
        super(SMBTransactionRequestData, self).__init__()

        ## XXX: set default value here, as they depend on __init__ params.
        self['Name'] = SMB_String(u'', unicode_strings, oem_codepage)


class SMBTransactionRequest(SMB_Command):
    parameters_type = SMBTransactionRequestParameters
    data_type       = SMBTransactionRequestData

class SMBTransactionResponseParameters(Struct):

    _setup_count = lambda ctx: (ctx.self['SetupCount'],)

    st = [
        ['TotalParameterCount',   '<H', 0],
        ['TotalDataCount',        '<H', 0],
        ['Reserved1',             '<H', 0],
        ['ParameterCount',        '<H', 0],
        ['ParameterOffset',       '<H', 0],
        ['ParameterDisplacement', '<H', 0],
        ['DataCount',             '<H', 0],
        ['DataOffset',            '<H', 0],
        ['DataDisplacement',      '<H', 0],
        ['SetupCount',            '<B', 0],
        ['Reserved2',             '<B', 0],
        ['Setup',                 USHORT_Array, USHORT_Array(0), _setup_count],
    ]

class SMBTransactionResponseData(Struct):

    def _trans_parameters(ctx):
        return (ctx.parameters['ParameterCount'],)

    def _trans_data(ctx):
        return (ctx.parameters['DataCount'],)

    st = [
        ['Pad1',             SMB_AlignTransParameters, SMB_AlignTransParameters(2)],
        ['Trans_Parameters', UCHAR_Array, UCHAR_Array(""), _trans_parameters],
        ['Pad2',             SMB_AlignTransData, SMB_AlignTransData(2)],
        ['Trans_Data',       UCHAR_Array, UCHAR_Array(""), _trans_data],
    ]

class SMBTransactionResponseDataFactory(object):
    @classmethod
    def deserialize_data(cls, data, context=None):
        if context is None:
            msg = "'{}' deserialization requires a 'context'"
            raise SerializationError(msg.format(cls.__name__))

        # In the case of errors, the data is empty.
        if context.header['Status'] != STATUS_SUCCESS:
            return SMBEmptyData.deserialize(data, context)

        return SMBTransactionResponseData.deserialize(data, context)

class SMBTransactionResponseParametersFactory(object):
    @classmethod
    def deserialize_parameters(cls, data, context=None):
        if context is None:
            msg = "'{}' deserialization requires a 'context'"
            raise SerializationError(msg.format(cls.__name__))

        # In the case of errors, the parameters are empty.
        if context.header['Status'] != STATUS_SUCCESS:
            return SMBEmptyParameters.deserialize(data, context)

        return SMBTransactionResponseParameters.deserialize(data, context)

class SMBTransactionResponse(SMB_Command):
    parameters_type    = SMBTransactionResponseParameters
    data_type          = SMBTransactionResponseData
    data_factory       = SMBTransactionResponseDataFactory
    parameters_factory = SMBTransactionResponseParametersFactory

###
# SMB_COM_TRANSACTION_SECONDARY (0x26)
# https://msdn.microsoft.com/en-us/library/ee441822.aspx (Request)
# https://msdn.microsoft.com/en-us/library/ee441710.aspx (No response)
###

class SMBTransactionSecondaryRequestParameters(Struct):
    st = [
        ['TotalParameterCount'   , '<H', 0],
        ['TotalDataCount'        , '<H', 0],
        ['ParameterCount'        , '<H', 0],
        ['ParameterOffset'       , '<H', 0],
        ['ParameterDisplacement' , '<H', 0],
        ['DataCount'             , '<H', 0],
        ['DataOffset'            , '<H', 0],
        ['DataDisplacement'      , '<H', 0],
    ]

class SMBTransactionSecondaryRequestData(Struct):
    st = [
        ['Pad1',             SMB_Align,   SMB_Align(4)],
        ['Trans_Parameters', UCHAR_Array, UCHAR_Array("")],
        ['Pad2',             SMB_Align,   SMB_Align(4)],
        ['Trans_Data',       UCHAR_Array, UCHAR_Array("")],
    ]

class SMBTransactionSecondaryRequest(SMB_Command):
    parameters_type = SMBTransactionSecondaryRequestParameters
    data_type       = SMBTransactionSecondaryRequestData

###
# SMB_COM_ECHO (0x2B)
# https://msdn.microsoft.com/en-us/library/ee441746.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee441626.aspx (response)
###

class SMBEchoRequestParameters(Struct):
    st = [
        ['EchoCount' , '<H', 0x01],
    ]

class SMBEchoRequestData(Struct):
    st = [
        ['EchoData',  UCHAR_Array, UCHAR_Array("")],
    ]

class SMBEchoRequest(SMB_Command):
    parameters_type = SMBEchoRequestParameters
    data_type = SMBEchoRequestData

class SMBEchoResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type = SMBEmptyData

###
# SMB_COM_TRANSACTION2 (0x32)
# - Normal  : https://msdn.microsoft.com/en-us/library/ee441652.aspx
# - Extended: https://msdn.microsoft.com/en-us/library/cc246282.aspx
###

class SMBTransaction2ResponseParameters(Struct):
    _setup_count = lambda ctx: (ctx.self['SetupCount'],)

    st = [
        ['TotalParameterCount',   '<H', 0],
        ['TotalDataCount',        '<H', 0],
        ['Reserved1',             '<H', 0],
        ['ParameterCount',        '<H', 0],
        ['ParameterOffset',       '<H', 0],
        ['ParameterDisplacement', '<H', 0],
        ['DataCount',             '<H', 0],
        ['DataOffset',            '<H', 0],
        ['DataDisplacement',      '<H', 0],
        ['SetupCount',            '<B', 0],
        ['Reserved2',             '<B', 0],
        ['Setup',                 USHORT_Array, USHORT_Array(0), _setup_count],
    ]

class SMBTransaction2ResponseData(Struct):
    _trans_parameters = lambda ctx: ctx.parameters['ParameterCount']
    _trans_data       = lambda ctx: ctx.parameters['DataCount']

    st = [
        ['Pad1',             SMB_Align,   SMB_Align(4)],
        ['Trans_Parameters', UCHAR_Array, UCHAR_Array(""), _trans_parameters],
        ['Pad2',             SMB_Align,   SMB_Align(4)],
        ['Trans_Data',       UCHAR_Array, UCHAR_Array(""), _trans_data],
    ]

class SMBTransaction2Response(SMB_Command):
    parameters_type = SMBTransaction2ResponseParameters
    data_type       = SMBTransaction2ResponseData

###
# SMB_COM_TRANSACTION2_SECONDARY (0x33)
# - Normal: https://msdn.microsoft.com/en-us/library/ee441841.aspx
###

class SMBTransaction2SecondaryRequestParameters(Struct):
    st = [
        ['TotalParameterCount',   '<H', 0],
        ['TotalDataCount',        '<H', 0],
        ['ParameterCount',        '<H', 0],
        ['ParameterOffset',       '<H', 0],
        ['ParameterDisplacement', '<H', 0],
        ['DataCount',             '<H', 0],
        ['DataOffset',            '<H', 0],
        ['DataDisplacement',      '<H', 0],
        ['FID',                   '<H', 0]
    ]

class SMBTransaction2SecondaryRequestData(Struct):
    _trans_parameters = lambda ctx: (ctx.parameters['ParameterCount'],)
    _trans_data       = lambda ctx: (ctx.parameters['DataCount'],)

    st = [
        ['Pad1',             SMB_Align,   SMB_Align(4)],
        ['Trans_Parameters', UCHAR_Array, UCHAR_Array(""), _trans_parameters],
        ['Pad2',             SMB_Align,   SMB_Align(4)],
        ['Trans_Data',       UCHAR_Array, UCHAR_Array(""), _trans_data],
    ]

class SMBTransaction2SecondaryRequest(SMB_Command):
    parameters_type = SMBTransaction2SecondaryRequestParameters
    data_type       = SMBTransaction2SecondaryRequestData

###
# SMB_COM_TREE_DISCONNECT (0x71)
# https://msdn.microsoft.com/en-us/library/ee441622.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee441823.aspx (response)
###

class SMBTreeDisconnectRequest(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBEmptyData

class SMBTreeDisconnectResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBEmptyData

###
# SMB_COM_NEGOTIATE (0x72)
# https://msdn.microsoft.com/en-us/library/ee441572.aspx
###

class SMBNegotiateRequestData(Struct):
    @staticmethod
    def _dialects_init():
        return [
            SMBDialect(DialectString=OEM_String('PC NETWORK PROGRAM 1.0')),
            SMBDialect(DialectString=OEM_String('LANMAN1.0')),
            SMBDialect(DialectString=OEM_String('Windows for Workgroups 3.1a')),
            SMBDialect(DialectString=OEM_String('LM1.2X002')),
            SMBDialect(DialectString=OEM_String('LANMAN2.1')),
            SMBDialect(DialectString=OEM_String('NT LM 0.12'))
        ]

    @staticmethod
    def _dialects(ctx):
        return ctx.data.ByteCount

    st = [
        ['Dialects', SMBDialectArray, _dialects_init, _dialects]
    ]

class SMBNegotiateRequest(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBNegotiateRequestData

class SMBNegotiateNTLanManagerResponseParameters(Struct):
    st = [
        ['DialectIndex',    '<H', 0],
        ['SecurityMode',    '<B', 0],
        ['MaxMpxCount',     '<H', 0],
        ['MaxCountVcs',     '<H', 0],
        ['MaxBufferSize',   '<L', 0],
        ['MaxRawSize',      '<L', 0],
        ['SessionKey',      '<L', 0],
        ['Capabilities',    '<L', 0],
        ['SystemTimeLow',   '<L', 0],
        ['SystemTimeHigh',  '<L', 0],
        ['ServerTimeZone',  '<H', 0],
        ['ChallengeLength', '<B', 0],
    ]

class SMBNegotiateNTLanManagerResponseData(Struct):
    pass

class SMBNegotiateNTLanManagerNonExtendedResponseData(SMBNegotiateNTLanManagerResponseData):
    _encryption_key_init = lambda ctx: (ctx.parameters['ChallengeLength'],)

    st = [
        ['Challenge',  UCHAR_Array, UCHAR_Array(""), _encryption_key_init],
        ['DomainName', SMB_String,  SMB_String(u'')],
        ['ServerName', SMB_String,  SMB_String(u'')]
    ]

class SMBNegotiateNTLanManagerExtendedResponseData(SMBNegotiateNTLanManagerResponseData):
    _server_guid   = lambda ctx: (16,)
    _security_blob = lambda ctx: (ctx.data.size() - 16,)

    st = [
        ['ServerGuid',   UCHAR_Array, UCHAR_Array(16), _server_guid],
        ['SecurityBlob', UCHAR_Array, UCHAR_Array(0), _security_blob]
    ]

class SMBNegotiateResponseFactory(object):
    @classmethod
    def deserialize_data(cls, data, context=None):
        if context is None:
            msg = "'{}' deserialization requires a 'context'"
            raise SerializationError(msg.format(cls.__name__))

        if context.parameters['Capabilities'] & CAP_EXTENDED_SECURITY:
            return SMBNegotiateNTLanManagerExtendedResponseData.deserialize(data, context)

        return SMBNegotiateNTLanManagerNonExtendedResponseData.deserialize(data, context)

class SMBNegotiateNTLanManagerResponse(SMB_Command):
    parameters_type = SMBNegotiateNTLanManagerResponseParameters
    data_type       = SMBNegotiateNTLanManagerResponseData
    data_factory    = SMBNegotiateResponseFactory

###
# SMB_COM_SESSION_SETUP_ANDX (0x73)
# - Normal  : https://msdn.microsoft.com/en-us/library/ee442101.aspx
# - Extended: https://msdn.microsoft.com/en-us/library/ff469879.aspx
###

class SMBSessionSetupAndXRequestParameters(Struct):
    pass

class SMBSessionSetupAndXRequestData(Struct):
    pass

class SMBSessionSetupAndXNonExtendedRequestParameters(SMBSessionSetupAndXRequestParameters):
    _capabilities = CAP_STATUS32     | CAP_LARGE_READX | \
                    CAP_LARGE_WRITEX | CAP_RAW_MODE

    st = [
        ['AndXCommand',        '<B', 0xff],
        ['AndXReserved',       '<B', 0],
        ['AndXOffset',         '<H', 0],
        ['MaxBufferSize',      '<H', 0x1104],
        ['MaxMpxCount',        '<H', 0x10],
        ['VcNumber',           '<H', 0],
        ['SessionKey',         '<L', 0],
        ['OEMPasswordLen',     '<H', 0],
        ['UnicodePasswordLen', '<H', 0],
        ['Reserved',           '<L', 0],
        ['Capabilities',       '<L', _capabilities]
    ]

class SMBSessionSetupAndXNonExtendedRequestData(SMBSessionSetupAndXRequestData):
    st = [
        ['OEMPassword',     OEM_Array,  OEM_Array("")],
        ['UnicodePassword', SMB_Array,  SMB_Array("", True)],
        ['Pad',             SMB_Align,  SMB_AlignUnicode()],
        ['AccountName',     SMB_String, SMB_String(u'')],
        ['PrimaryDomain',   SMB_String, SMB_String(u'')],
        ['NativeOS',        SMB_String, SMB_String(u'')],
        ['NativeLANMan',    SMB_String, SMB_String(u'')],
    ]

class SMBSessionSetupAndXExtendedRequestParameters(SMBSessionSetupAndXRequestParameters):
    _capabilities = CAP_EXTENDED_SECURITY |CAP_STATUS32 | CAP_UNICODE | \
                    CAP_LARGE_READX | CAP_LARGE_WRITEX

    st = [
        ['AndXCommand'        , '<B', 0xff],
        ['AndXReserved'       , '<B', 0],
        ['AndXOffset'         , '<H', 0],
        ['MaxBufferSize'      , '<H', 0x1104],
        ['MaxMpxCount'        , '<H', 0x10],
        ['VcNumber'           , '<H', 0],
        ['SessionKey'         , '<L', 0],
        ['SecurityBlobLength' , '<H', 0],
        ['Reserved'           , '<L', 0],
        ['Capabilities'       , '<L', _capabilities]
    ]

class SMBSessionSetupAndXExtendedRequestData(SMBSessionSetupAndXRequestData):
    _security_blob = lambda ctx: ctx.parameters['SecurityBlobLength']

    st = [
        ['SecurityBlob', UCHAR_Array, UCHAR_Array(0), _security_blob],
        ['Pad0',         SMB_Align,   SMB_AlignUnicode()],
        ['NativeOS',     SMB_String,  SMB_String(u'Unix')],
        ['NativeLANMan', SMB_String,  SMB_String(u'Samba')],
    ]

class SMBSessionSetupAndXNonExtendedRequest(SMB_Command):
    parameters_type = SMBSessionSetupAndXNonExtendedRequestParameters
    data_type       = SMBSessionSetupAndXNonExtendedRequestData

class SMBSessionSetupAndXExtendedRequest(SMB_Command):
    parameters_type = SMBSessionSetupAndXExtendedRequestParameters
    data_type       = SMBSessionSetupAndXExtendedRequestData

class SMBSessionSetupAndXRequest(SMB_Command):
    parameters_type = SMBSessionSetupAndXRequestParameters
    data_type       = SMBSessionSetupAndXRequestData

class SMBSessionSetupAndXResponseParameters(Struct):
    pass

class SMBSessionSetupAndXResponseData(Struct):
    pass

class SMBSessionSetupAndXNonExtendedResponseParameters(SMBSessionSetupAndXResponseParameters):
    st = [
        ['AndXCommand'       , '<B', 0xff],
        ['AndXReserved'      , '<B', 0],
        ['AndXOffset'        , '<H', 0],
        ['Action'            , '<H', 0]
    ]

class SMBSessionSetupAndXNonExtendedResponseData(SMBSessionSetupAndXResponseData):
    st = [
        ['Pad',             SMB_Align,        SMB_AlignUnicode()],
        ['NativeOS',        SMB_String,       None],
        ['NativeLANMan',    SMB_String,       None],
        ['PrimaryDomain',   SMB_StringPadFix, None],
    ]

class SMBSessionSetupAndXExtendedResponseParameters(SMBSessionSetupAndXResponseParameters):
    st = [
        ['AndXCommand'       , '<B', 0xff],
        ['AndXReserved'      , '<B', 0],
        ['AndXOffset'        , '<H', 0],
        ['Action'            , '<H', 0],
        ['SecurityBlobLength', '<H', 0],
    ]

class SMBSessionSetupAndXExtendedResponseData(SMBSessionSetupAndXResponseData):
    _security_blob = lambda ctx: (ctx.parameters['SecurityBlobLength'],)

    st = [
        ['SecurityBlob', UCHAR_Array, UCHAR_Array(0), _security_blob],
        ['Pad0',         SMB_Align,   SMB_AlignUnicode()],
        ['NativeOS',     SMB_String,  SMB_String(u'Unix')],
        ['NativeLANMan', SMB_String,  SMB_String(u'Samba')],
    ]

class SMBSessionSetupAndXResponseFactory(object):
    @classmethod
    def deserialize_parameters(cls, data, context=None):
        if context is None:
            msg = "'{}' deserialization requires a 'context'"
            raise SerializationError(msg.format(cls.__name__))

        if context.parameters.size() <= 1:
            return SMBEmptyParameters.deserialize(data, context)

        if context.connection.server_capabilities & CAP_EXTENDED_SECURITY and \
           context.header['Flags2'] & SMB_FLAGS2_EXTENDED_SECURITY:
            return SMBSessionSetupAndXExtendedResponseParameters.deserialize(data, context)

        return SMBSessionSetupAndXNonExtendedResponseParameters.deserialize(data, context)

    @classmethod
    def deserialize_data(cls, data, context=None):
        if context is None:
            msg = "'{}' deserialization requires a 'context'"
            raise SerializationError(msg.format(cls.__name__))

        if context.data.size() <= 2:
            return SMBEmptyData.deserialize(data, context)

        if context.connection.server_capabilities & CAP_EXTENDED_SECURITY and \
           context.header['Flags2'] & SMB_FLAGS2_EXTENDED_SECURITY:
            return SMBSessionSetupAndXExtendedResponseData.deserialize(data, context)
        return SMBSessionSetupAndXNonExtendedResponseData.deserialize(data, context)

class SMBSessionSetupAndXResponse(SMB_Command):
    parameters_type    = SMBSessionSetupAndXResponseParameters
    parameters_factory = SMBSessionSetupAndXResponseFactory
    data_type          = SMBSessionSetupAndXResponseData
    data_factory       = SMBSessionSetupAndXResponseFactory

###
# SMB_COM_LOGOFF_ANDX (0x74)
# https://msdn.microsoft.com/en-us/library/ee442167.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee441488.aspx (response)
###

class SMBLogoffAndXRequestParameters(Struct):
    st = [
        ['AndXCommand'  , '<B', 0xff],
        ['AndXReserved' , '<B', 0],
        ['AndXOffset'   , '<H', 0],
    ]

class SMBLogoffAndXRequest(SMB_Command):
    parameters_type = SMBLogoffAndXRequestParameters
    data_type       = SMBEmptyData

class SMBLogoffAndXResponseParameters(Struct):
    st = [
        ['AndXCommand'  , '<B', 0xff],
        ['AndXReserved' , '<B', 0],
        ['AndXOffset'   , '<H', 0],
    ]

class SMBLogoffAndXResponse(SMB_Command):
    parameters_type = SMBLogoffAndXResponseParameters
    data_type       = SMBEmptyData

###
# SMB_COM_WRITE_ANDX (0x2F)
# https://msdn.microsoft.com/en-us/library/ff469893.aspx (request)
# https://msdn.microsoft.com/en-us/library/ff469858.aspx (response)
###
class SMBWriteAndXRequestParameters(Struct):
    st = [
        ['AndXCommand'              , '<B', 0xff],
        ['AndXReserved'             , '<B', 0],
        ['AndXOffset'               , '<H', 0],
        ['Fid'                      , '<H', 0],
        ['Offset'                   , '<L', 0],
        ['Reserved'                 , '<L', 0xff],
        ['WriteMode'                , '<H', 0],
        ['Remaining'                , '<H', 0],
        ['Reserved1'                , '<H', 0],
        ['DataLength'               , '<H', 0],
        ['DataOffset'               , '<H', 0],
    ]

class SMBWriteAndXRequestData(Struct):
    st = [
        ['Pad',             SMB_Align,   SMB_Align(4)],
        ['Data',            UCHAR_Array, UCHAR_Array("")],
    ]

class SMBWriteAndXRequest(SMB_Command):
    parameters_type = SMBWriteAndXRequestParameters
    data_type       = SMBWriteAndXRequestData

class SMBWriteAndXResponseParameters(Struct):
    st = [
        ['WordCount'                , '<B', 6],
        ['Available'                , '<H', 0],
        ['Reserved'                 , '<L', 0],
    ]

class SMBWriteAndXResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBEmptyData

###
# SMB_COM_ECHO (0x2B)
# https://msdn.microsoft.com/en-us/library/ee441746.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee441626.aspx (response)
###
class SMBEchoRequestParameters(Struct):
    st = [
        ['EchoCount' , '<H', 0x01],
    ]

class SMBEchoRequestData(Struct):
    st = [
        ['EchoData',            UCHAR_Array, UCHAR_Array("")],
    ]

class SMBEchoRequest(SMB_Command):
    parameters_type = SMBEchoRequestParameters
    data_type = SMBEchoRequestData

class SMBEchoResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type = SMBEmptyData

###
# SMB_COM_NT_TRANSACT (0xA0)
# https://msdn.microsoft.com/en-us/library/ee441534.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee442112.aspx (response)
###

class SMBNTTransactRequestParameters(Struct):
    st = [
        ['MaxSetupCount',       '<B', 0],
        ['Reserved1',           '<H', 0],
        ['TotalParameterCount', '<L', 0],
        ['TotalDataCount',      '<L', 0],
        ['MaxParameterCount',   '<L', 0],
        ['MaxDataCount',        '<L', 0],
        ['ParameterCount',      '<L', 0],
        ['ParameterOffset',     '<L', 0],
        ['DataCount',           '<L', 0],
        ['DataOffset',          '<L', 0],
        ['SetupCount',          '<B', 0],
        ['Function',            '<H', 0],
        ['Setup',               USHORT_Array, USHORT_Array(0), lambda self: self['SetupCount']],
    ]

class SMBNTTransactRequestData(Struct):
    st = [
        ['Pad1',                SMB_Align,   SMB_Align(4)],
        ['NT_Trans_Parameters', UCHAR_Array, UCHAR_Array("")],
        ['Pad2',                SMB_Align,   SMB_Align(4)],
        ['NT_Trans_Data',       UCHAR_Array, UCHAR_Array("")],
    ]

class SMBNTTransactRequest(SMB_Command):
    parameters_type = SMBNTTransactRequestParameters
    data_type       = SMBNTTransactRequestData

class SMBNTTransactResponseParameters(Struct):
    st = [
        ['Reserved1',             UCHAR_Array, UCHAR_Array("\0\0\0")],
        ['TotalParameterCount',   '<L', 0],
        ['TotalDataCount',        '<L', 0],
        ['ParameterCount',        '<L', 0],
        ['ParameterOffset',       '<L', 0],
        ['ParameterDisplacement', '<L', 0],
        ['DataCount',             '<L', 0],
        ['DataOffset',            '<L', 0],
        ['DataDisplacement',      '<L', 0],
        ['SetupCount',            '<B', 0],
        ['Setup',                 USHORT_Array, USHORT_Array(0), lambda self: self['SetupCount']],
    ]

class SMBNTTransactResponseData(Struct):
    st = [
        ['Pad1',       SMB_Align,   SMB_Align(4)],
        ['Parameters', UCHAR_Array, UCHAR_Array("")],
        ['Pad2',       SMB_Align,   SMB_Align(4)],
        ['Data',       UCHAR_Array, UCHAR_Array("")],
    ]

class SMBNTTransactResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBNTTransactResponseData

class SMBNTTransactInterimResponse(SMB_Command):
    parameters_type = SMBEmptyParameters
    data_type       = SMBEmptyData

###
# SMB_COM_NT_TRANSACT_SECONDARY (0xA1)
# https://msdn.microsoft.com/en-us/library/ee441665.aspx (request)
# https://msdn.microsoft.com/en-us/library/ee442031.aspx (response)
###

class SMBNTTransactSecondaryRequestParameters(Struct):

    _setup_count = lambda ctx: (ctx.self['SetupCount'],)

    st = [
        ['Reserved1',             UCHAR_Array, UCHAR_Array("\0\0\0")],
        ['TotalParameterCount',   '<L', 0],
        ['TotalDataCount',        '<L', 0],
        ['ParameterCount',        '<L', 0],
        ['ParameterOffset',       '<L', 0],
        ['ParameterDisplacement', '<L', 0],
        ['DataCount',             '<L', 0],
        ['DataOffset',            '<L', 0],
        ['DataDisplacement',      '<L', 0],
        ['Reserved2',             UCHAR_Array, UCHAR_Array("\0")],
    ]

class SMBNTTransactSecondaryRequestData(Struct):
    st = [
        ['Pad1',       SMB_Align,   SMB_Align(4)],
        ['Parameters', UCHAR_Array, UCHAR_Array("")],
        ['Pad2',       SMB_Align,   SMB_Align(4)],
        ['Data',       UCHAR_Array, UCHAR_Array("")],
    ]

class SMBNTTransactSecondaryRequest(SMB_Command):
    parameters_type = SMBNTTransactSecondaryRequestParameters
    data_type       = SMBNTTransactSecondaryRequestData


################################################################################
#                                                                              #
#                     SMB_CommandFactory classe (NEW API)                      #
#                                                                              #
################################################################################

class SMB_CommandFactory(object):
    request_types = {
        SMB_COM_NEGOTIATE:              SMBNegotiateRequest,
        SMB_COM_SESSION_SETUP_ANDX:     SMBSessionSetupAndXRequest,
        SMB_COM_TREE_DISCONNECT:        SMBTreeDisconnectRequest,
        SMB_COM_LOGOFF_ANDX:            SMBLogoffAndXRequest,
        SMB_COM_TRANSACTION:            SMBTransactionRequest,
        SMB_COM_TRANSACTION2_SECONDARY: SMBTransaction2SecondaryRequest,
        SMB_COM_NT_TRANSACT:            SMBNTTransactRequest,
        SMB_COM_NT_TRANSACT_SECONDARY:  SMBNTTransactSecondaryRequest,
        SMB_COM_WRITE_ANDX:             SMBWriteAndXRequest,
        SMB_COM_ECHO:                   SMBEchoRequest,
#            SMB_COM_TREE_CONNECT_ANDX:     SMBTreeConnectAndXRequest,
#            SMB_COM_NT_CREATE_ANDX:        SMBNTCreateAndXRequest,
#            SMB_COM_OPEN_ANDX:             SMBOpenAndXRequest,
#            SMB_COM_READ_ANDX:             SMBReadAndXRequest,
#            SMB_COM_CLOSE:                 SMBCloseRequest,
#            SMB_COM_TRANSACTION2:          SMBTransactionRequest,
#            SMB_COM_TRANSACTION_SECONDARY: SMBTransactionSecondaryRequest,
#            SMB_COM_QUERY_INFORMATION:     SMBQueryInformationRequest,
#            SMB_COM_IOCTL:                 SMBIoctlRequest,
#            SMB_COM_WRITE:                 SMBWriteRequest,
#            SMB_COM_SET_INFORMATION2:      SMBSetInformation2Request,
#            SMB_COM_QUERY_INFORMATION2:    SMBQueryInformation2Request,
#            SMB_COM_DELETE:                SMBDeleteRequest,
#            SMB_COM_CREATE_DIRECTORY:      SMBCreateDirectoryRequest,
#            SMB_COM_OPEN:                  SMBOpenRequest,
#            SMB_COM_DELETE_DIRECTORY:      SMBDeleteDirectoryRequest,
#            SMB_COM_CHECK_DIRECTORY:       SMBCheckDirectoryRequest,
#            SMB_COM_FLUSH:                 SMBFlushRequest,
#            SMB_COM_RENAME:                SMBRenameRequest,
#            SMB_COM_READ:                  SMBReadRequest,
#            SMB_COM_SET_INFORMATION:       SMBSetInformationRequest,
#            SMB_COM_LOCKING_ANDX:          SMBLockingAndxRequest,
#            SMB_COM_FIND_CLOSE2:           SMBFindClose2Request,
#            SMB_COM_NT_CANCEL:             SMBNtCancelRequest, # Command has no response
        }

    response_types = {
        SMB_COM_NEGOTIATE:              (SMBNegotiateNTLanManagerResponse,),
        SMB_COM_SESSION_SETUP_ANDX:     (SMBSessionSetupAndXResponse,),
        SMB_COM_TREE_DISCONNECT:        (SMBTreeDisconnectResponse,),
        SMB_COM_LOGOFF_ANDX:            (SMBLogoffAndXResponse,),
        SMB_COM_TRANSACTION:            (SMBTransactionResponse,),
        SMB_COM_TRANSACTION2:           (SMBTransaction2Response,),
        SMB_COM_TRANSACTION_SECONDARY:  (SMBTransactionResponse,),
        SMB_COM_NT_TRANSACT:            (SMBNTTransactInterimResponse, SMBNTTransactResponse),
        SMB_COM_WRITE_ANDX:             (SMBWriteAndXResponse,),
        SMB_COM_ECHO:                   (SMBEchoResponse,)
#        SMB_COM_NT_CREATE_ANDX:        SMBNTCreateAndXResponse,
#        SMB_COM_OPEN_ANDX:             SMBOpenAndXResponse,
#        SMB_COM_READ_ANDX:             SMBReadAndXResponse,
#        SMB_COM_CLOSE:                 SMBCloseResponse,
#        SMB_COM_TREE_CONNECT_ANDX:     SMBTreeConnectAndXResponse,
#        SMB_ERROR:                     SMBErrorResponse,
#        SMB_COM_NT_TRANSACT_SECONDARY: SMBNTTransactResponse,
#        SMB_COM_QUERY_INFORMATION:     SMBQueryInformationResponse,
#        SMB_COM_IOCTL:                 SMBIoctlResponse,
#        SMB_COM_WRITE:                 SMBWriteResponse,
#        SMB_COM_SET_INFORMATION2:      SMBSetInformation2Response,
#        SMB_COM_QUERY_INFORMATION2:    SMBQueryInformation2Response,
#        SMB_COM_DELETE:                SMBDeleteResponse,
#        SMB_COM_CREATE_DIRECTORY:      SMBCreateDirectoryResponse,
#        SMB_COM_OPEN:                  SMBOpenResponse,
#        SMB_COM_DELETE_DIRECTORY:      SMBDeleteDirectoryResponse,
#        SMB_COM_CHECK_DIRECTORY:       SMBCheckDirectoryResponse,
#        SMB_COM_FLUSH:                 SMBFlushResponse,
#        SMB_COM_RENAME:                SMBRenameResponse,
#        SMB_COM_READ:                  SMBReadResponse,
#        SMB_COM_SET_INFORMATION:       SMBSetInformationResponse,
#        SMB_COM_LOCKING_ANDX:          SMBLockingAndxResponse,
#        SMB_COM_FIND_CLOSE2:           SMBFindClose2Response,
    }

    def __init__(self, is_unicode=False):
        self.is_unicode = is_unicode

    def request(self, cid, connection):
        # XXX: special cased requests with ABC for now.
        if cid == SMB_COM_SESSION_SETUP_ANDX:
            if connection.server_capabilities & CAP_EXTENDED_SECURITY:
                req = SMBSessionSetupAndXExtendedRequest()
            else:
                req = SMBSessionSetupAndXNonExtendedRequest()
        else:
            req = self.request_types[cid](is_unicode=self.is_unicode)
        req.header['Command'] = cid
        return req

    def deserialize_response(self, cid, data, context=None):
        errors = []
        #print "\n>>>>>>>>>>>>>>>> SMB_CommandFactory.deserialize_response [0x%x]\n" % cid
        for t in self.response_types[cid]:
            try:
                return t.deserialize(data, context=context)
            except SerializationError as e:
                errors.append(e)

        raise SerializationError(errors)

    def deserialize_request(self, cid, data, context=None):
        """
        Deserialize the request within data according to the cid.
        Note: Practically speaking this is mostly for debugging/testing.
        """
        errors = []
        #print "\n>>>>>>>>>>>>>>>> SMB_CommandFactory.deserialize_response [0x%x]\n" % cid
        t = self.request_types[cid]
        try:
            return t.deserialize(data, context=context)
        except SerializationError as e:
            errors.append(e)

        raise SerializationError(errors)


################################################################################
#                                                                              #
#                             SMBPacket class (OLD API)                        #
#                                                                              #
################################################################################


class SMBPacket():
    def __init__(self, data=None, command=0, tid=0, pid=0, uid=0, mid=0, server=0, is_unicode=False, header=None):
        self.header = SMBHeader(data, is_unicode)
        if data is not None:
            server = (~server) & 0x01
            command = self.header['Command']
            raw_data = data
            data = data[SMB_HEADER_SIZE:]
            is_unicode = (self.header['Flags2'] & SMB_FLAGS2_UNICODE > 0)
        else:
            self.header['Command'] = command
            self.header['TID'] = tid
            self.header['PID'] = pid
            self.header['UID'] = uid
            self.header['MID'] = mid

        smb_response = {
            SMB_ERROR:                     SMBErrorResponse,
            SMB_COM_NEGOTIATE:             SMBNegotiateResponseOld,             # Deprecated.
            SMB_COM_SESSION_SETUP_ANDX:    SMBSessionSetupAndXResponseOld,      # Deprecated.
            SMB_COM_TREE_CONNECT_ANDX:     SMBTreeConnectAndXResponse,
            SMB_COM_TREE_DISCONNECT:       SMBTreeDisconnectResponseOld,        # Deprecated.
            SMB_COM_LOGOFF_ANDX:           SMBLogoffAndXResponseOld,            # Deprecated.
            SMB_COM_NT_CREATE_ANDX:        SMBNTCreateAndXResponse,
            SMB_COM_OPEN_ANDX:             SMBOpenAndXResponse,
            SMB_COM_READ_ANDX:             SMBReadAndXResponse,
            SMB_COM_WRITE_ANDX:            SMBWriteAndXResponseOld,             # Deprecated.
            SMB_COM_CLOSE:                 SMBCloseResponse,
            SMB_COM_TRANSACTION:           SMBTransactionResponseOld,           # Deprecated.
            SMB_COM_TRANSACTION2:          SMBTransactionResponseOld,           # Deprecated.
            SMB_COM_TRANSACTION_SECONDARY: SMBTransactionResponseOld,           # Deprecated.
            SMB_COM_ECHO:                  SMBEchoResponseOld,                  # Deprecated
            SMB_COM_NT_TRANSACT:           SMBNTTransactResponseOld,            # Deprecated.
            SMB_COM_NT_TRANSACT_SECONDARY: SMBNTTransactResponseOld,
            SMB_COM_QUERY_INFORMATION:     SMBQueryInformationResponse,
            SMB_COM_IOCTL:                 SMBIoctlResponse,
            SMB_COM_WRITE:                 SMBWriteResponse,
            SMB_COM_SET_INFORMATION2:      SMBSetInformation2Response,
            SMB_COM_QUERY_INFORMATION2:    SMBQueryInformation2Response,
            SMB_COM_DELETE:                SMBDeleteResponse,
            SMB_COM_CREATE_DIRECTORY:      SMBCreateDirectoryResponse,
            SMB_COM_OPEN:                  SMBOpenResponse,
            SMB_COM_DELETE_DIRECTORY:      SMBDeleteDirectoryResponse,
            SMB_COM_CHECK_DIRECTORY:       SMBCheckDirectoryResponse,
            SMB_COM_FLUSH:                 SMBFlushResponse,
            SMB_COM_RENAME:                SMBRenameResponse,
            SMB_COM_READ:                  SMBReadResponse,
            SMB_COM_SET_INFORMATION:       SMBSetInformationResponse,
            SMB_COM_LOCKING_ANDX:          SMBLockingAndxResponse,
            SMB_COM_FIND_CLOSE2:           SMBFindClose2Response,
        }

        smb_request = {
            SMB_COM_NEGOTIATE:             SMBNegotiateRequestOld,              # Deprecated.
            SMB_COM_SESSION_SETUP_ANDX:    SMBSessionSetupAndXRequestOld,       # Deprecated.
            SMB_COM_TREE_CONNECT_ANDX:     SMBTreeConnectAndXRequest,
            SMB_COM_TREE_DISCONNECT:       SMBTreeDisconnectRequestOld,         # Deprecated.
            SMB_COM_LOGOFF_ANDX:           SMBLogoffAndXRequestOld,             # Deprecated.
            SMB_COM_NT_CREATE_ANDX:        SMBNTCreateAndXRequest,
            SMB_COM_OPEN_ANDX:             SMBOpenAndXRequest,
            SMB_COM_READ_ANDX:             SMBReadAndXRequest,
            SMB_COM_WRITE_ANDX:            SMBWriteAndXRequestOld,              # Deprecated.
            SMB_COM_CLOSE:                 SMBCloseRequest,
            SMB_COM_TRANSACTION:           SMBTransactionRequestOld,            # Deprecated.
            SMB_COM_TRANSACTION2:          SMBTransactionRequestOld,            # Deprecated.
            SMB_COM_TRANSACTION_SECONDARY: SMBTransactionSecondaryRequestOld,   # Deprecated.
            SMB_COM_ECHO:                  SMBEchoRequestOld,                   # Deprecated
            SMB_COM_NT_TRANSACT:           SMBNTTransactRequestOld,             # Deprecated.
            SMB_COM_NT_TRANSACT_SECONDARY: SMBNTTransactSecondaryRequestOld,    # Deprecated.
            SMB_COM_QUERY_INFORMATION:     SMBQueryInformationRequest,
            SMB_COM_IOCTL:                 SMBIoctlRequest,
            SMB_COM_WRITE:                 SMBWriteRequest,
            SMB_COM_SET_INFORMATION2:      SMBSetInformation2Request,
            SMB_COM_QUERY_INFORMATION2:    SMBQueryInformation2Request,
            SMB_COM_DELETE:                SMBDeleteRequest,
            SMB_COM_CREATE_DIRECTORY:      SMBCreateDirectoryRequest,
            SMB_COM_OPEN:                  SMBOpenRequest,
            SMB_COM_DELETE_DIRECTORY:      SMBDeleteDirectoryRequest,
            SMB_COM_CHECK_DIRECTORY:       SMBCheckDirectoryRequest,
            SMB_COM_FLUSH:                 SMBFlushRequest,
            SMB_COM_RENAME:                SMBRenameRequest,
            SMB_COM_READ:                  SMBReadRequest,
            SMB_COM_SET_INFORMATION:       SMBSetInformationRequest,
            SMB_COM_LOCKING_ANDX:          SMBLockingAndxRequest,
            SMB_COM_FIND_CLOSE2:           SMBFindClose2Request,
            SMB_COM_NT_CANCEL:             SMBNtCancelRequest, # Command has no response
        }

        if self.header['Status'] not in (STATUS_SUCCESS,
                                         STATUS_MORE_PROCESSING_REQUIRED,
                                         STATUS_BUFFER_OVERFLOW):
            command = SMB_ERROR

        if server == 1:
            if command in [SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2, SMB_COM_NT_TRANSACT] and data != None and len(data) == calcsize('<HB'):
                command = SMB_ERROR
            if command not in smb_response:
                command = SMB_ERROR

            # For the new SMB_Command interface, deserialize things.
            if issubclass(smb_response[command], SMB_Command):
                context   = SMB_SerializationContext(unicode_strings=is_unicode)
                self.body = smb_response[command].deserialize(raw_data, context)
            else:
                self.body = smb_response[command](data, is_unicode)
        else:
            if command not in smb_request:
                self.body = None
            else:
                # For the new SMB_Command interface, deserialize things.
                if issubclass(smb_request[command], SMB_Command):
                    parameters = smb_request[command].parameters_type()
                    data       = smb_request[command].data_type()
                    self.body  = smb_request[command](self.header, parameters, data, is_unicode)
                else:
                    self.body = smb_request[command](data, is_unicode)

    def pack(self):
        # XXX: shitty patch, as SMB_Command serializes header and body
        # together.
        if isinstance(self.body, SMB_Command):
            return self.body.serialize()

        return self.header.pack() + self.body.pack()

    def sign(self, seq_number, session_key):
        self.header['SecuritySignature'] = pack('<Q', seq_number)
        m = MD5.new()
        m.update(session_key)
        m.update(self.pack())
        self.header['SecuritySignature'] = m.digest()[:8]
        #self.header['SecuritySignature'] = pack('<LL', seq_number, 0)
        #self.header['SecuritySignature'] = MD5.new(session_key + self.pack()).digest()[:8]
        return self.header['SecuritySignature']

    def verify(self, seq_number, session_key):
        signature = self.header['SecuritySignature']
        self.header['SecuritySignature'] = pack('<LL', seq_number, 0)
        verification = MD5.new(session_key + self.pack()).digest()
        self.header['SecuritySignature'] = signature #Restore the signature so we can verify the packet twice or more

        if signature != verification[:8]:
            logging.debug('Packet signature is incorrect!') #XXX: Raise exception? --Kostya
            logging.debug('%s %s (%s)'%(signature.encode('HEX'), verification[:8].encode('HEX'), verification.encode('HEX')))
            return False
        logging.debug('Packet signature is correct!')
        return True


################################################################################
#                                                                              #
#                             Exception classes                                #
#                                                                              #
################################################################################


class SMBException(Exception):
    """
    Base class for all SMB-specific exceptions.
    """

class SMBClientException(SMBException):
    """
    Base class for all SMB client exceptions.
    """
    def __init__(self, message='', status=None):
        self.status = status
        self.message = message

    def __str__(self):
        return '%s [NTSTATUS: %x %s]' % (self.message, self.status, status_description(self.status))

class SMBServerException(SMBException):
    """
    Base class for all SMB server exceptions.
    """
    pass

class SMBConnectException(SMBClientException):
    """
    Raised when the SMB connection fails
    """
    pass

class SMBNegotiationException(SMBClientException):
    """
    Raised when the SMB negotiation exchange is not completed.
    """
    pass

class SMBSessionSetupException(SMBClientException):
    """
    Raised when the session setup exchange is not successful.
    """
    pass

class SMBTreeConnectException(SMBClientException):
    """
    Raised when the tree connect operation is not successful.
    """
    pass

class SMBNTCreateException(SMBClientException):
    """
    Raised when NTCreate fails.
    """
    pass

class SMBTransactException(SMBClientException):
    """
    Raised when a transaction operation fails.
    """
    pass

class SMBCheckDirectoryException(SMBClientException):
    """
    Raised when the check directory operation fails.
    """
    pass

class SMBDeleteException(SMBClientException):
    """
    Raised when a delete operation fails.
    """
    pass

class SMBDeleteDirectoryException(SMBClientException):
    """
    Raised when a delete directory operation fails.
    """
    pass

class SMBCloseException(SMBClientException):
    """
    Raised when a close operation fails.
    """
    pass

class SMBWriteException(SMBClientException):
    """
    Raised when a write operation fails.
    """
    pass

class SMBReadException(SMBClientException):
    """
    Raised when a read operation fails."
    """
    pass

class SMBQueryInformationException(SMBClientException):
    """
    Raised when a query information operation fails.
    """
    pass

class SMBTreeDisconnectException(SMBClientException):
    """
    Raised when a tree disconnection operation fails.
    """
    pass

class SMBLogoffException(SMBClientException):
    """
    Raised when a logoff operation fails.
    """
    pass

class SMBIOCTLException(SMBClientException):
    """
    Raised when an ioctl operation fails.
    """
    pass


################################################################################
#                                                                              #
#                             Main class: SMB                                  #
# Note: Acts like a template class, please use SMBClient or SMBServer instead. #
#                                                                              #
################################################################################

class SMB(object):
    def __init__(self, socket):
        self.s                 = socket
        self.pid               = 0
        self.uid               = 0
        self.mid               = 0
        self.fid               = 0
        self.is_unicode        = True
        self.max_smbfrag       = 0
        self.max_read          = 0x8000
        self.max_write         = 0x8000
        self.large_read        = False
        self.large_write       = False
        self.sign              = True
        self.extended_security = True
        self.session_key       = None
        self.seq_number        = 0

    def get_fid(self):
        return self.fid

    def set_fid(self, fid):
        self.fid = fid

    def set_socket_synchronous(self):
        self.s.setblocking(1)

    def set_socket_asynchronous(self):
        self.s.setblocking(0)

################################################################################
#                                                                              #
#                             Main class: SMBClient                            #
#                                                                              #
#  Currently an hybrid of SMBPacket (old) and SMB_CommandFactory (new)         #
#                                                                              #
################################################################################


class SMB_Connection(object):
    def __init__(self, capabilities=0):
        self.server_capabilities = capabilities


class SMBClient(SMB):
    """
    Fragmentation level should be: None -> No fragmentation at all
                                      1 -> Moderate fragmentation (16-byte fragments)
                                      2 -> Maximum (1-byte fragments)
    """
    def __init__(self, socket, username=None, password=None, domain=None, workstation=None, kerberos_db=None, use_krb5=False, frag_level=None, is_unicode=False):
        SMB.__init__(self, socket)
        # Make sure out input is unicode
        #(username, password, workstation, domain) = map(assert_unicode, (username, password, workstation, domain))
        # SMB search related variables
        self.sid = 0
        self.lastname = u''
        self.eos = 0
        self.username = username
        self.password = password
        self.workstation = workstation
        self.domain = domain
        self.frag_level = frag_level
        # Server variables
        self.nativeos = u''
        self.nativelanman = u''
        self.primarydomain = u''
        self.servername = u''
        # Specific to kerberos
        self.kerberos_db = kerberos_db
        self.use_krb5 = use_krb5
        self.is_unicode = is_unicode
        if frag_level != None:
            self.max_smbfrag = 16 if frag_level == 1 else 1

        self._factory            = SMB_CommandFactory(is_unicode=self.is_unicode)
        self._tree_connect_table = OrderedDict()
        self._auto_close         = False
        self._connection         = SMB_Connection()

    @classmethod
    def from_address(cls, hostname, port=445, username=None, password=None,
                     domain=None, workstation=None, kerberos_db=None,
                     use_krb5=False, frag_level=None, is_unicode=False):
        try:
            sd = socket.create_connection((hostname, port))
        except socket.error as err:
            raise SMBConnectException(status=err[0], message=err[1])
        # XXX: timeoutsocket.Timeout

        obj = cls(sd, username, password, domain, workstation, kerberos_db,
                  use_krb5, frag_level, is_unicode)
        obj._auto_close = True
        return obj

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        # Disconnect all tree connected shares.
        for tid in self._tree_connect_table:
            try:
                self.tree_disconnect(tid)
            except:
                pass

        # End the session.
        try:
            self.logoff()
        except:
            pass

        # If we own the socket object, close it.
        if self._auto_close:
            self.s.close()

    def new_context(self):
        ctx            = SMB_SerializationContext()
        ctx.connection = self._connection
        return ctx

    def new_request(self, cid, mid=None, inc_mid=True):
        req = self._factory.request(cid, self._connection)

        req.header['TID'] = self.tid
        req.header['PID'] = self.pid
        req.header['UID'] = self.uid
        if mid == None:
            req.header['MID'] = self.mid
        else:
            req.header['MID'] = mid

        if inc_mid == True:
            self.mid = (self.mid + 1) & 0xffff

        return req

    @property
    def tid(self):
        if len(self._tree_connect_table) == 0:
            return 0

        return self._tree_connect_table.keys()[-1]

    def recv(self):
        data = self.s.recv(4)
        if data == '':
            # Server closed connection
            raise socket.error('Remote end closed connection')

        _, hlen, llen = unpack('>BBH', data)
        total_length = (hlen << 16) + llen
        data = ''
        length = 0

        while length < total_length:
            chunk = self.s.recv(total_length - length)
            if chunk == '':
                raise socket.error('Remote end closed connection')
            data += chunk
            length += len(chunk)

        self.packet = SMBPacket(data, is_unicode=self.is_unicode) ### TODO
        signature = self.packet.header['SecuritySignature']
        if signature != ('\0' * 8) and self.session_key != None:
            self.packet.verify(self.seq_number + 1, self.session_key) #XXX: For the moment we ignore the result --Kostya


    def recv_raw(self, sz=0xffff):
        data = self.s.recv(sz)
        return data

    def recv_response(self):
        data = self.s.recv(4)
        if data == '':
            # Server closed connection
            raise socket.error('Remote end closed connection')

        _, hlen, llen = unpack('>BBH', data)
        total_length = (hlen << 16) + llen
        data = ''
        length = 0

        while length < total_length:
            chunk = self.s.recv(total_length - length)
            if chunk == '':
                raise socket.error('Remote end closed connection')
            data += chunk
            length += len(chunk)

        # Peek ahead to see what Command we are dealing with.
        header = SMB_Header.deserialize(data)

        # Deserialize the whole message.
        ctx     = self.new_context()
        command = self._factory.deserialize_response(header['Command'], data, ctx)
        signature = command.header['SecuritySignature']
        if signature != ('\0' * 8) and self.session_key != None:
            command.verify(self.seq_number + 1, self.session_key)

        return command

    def send(self, inc_mid=True):
        # Any modification of the pack_header must be done _before_ the signature
        # computation !#@
        if self.extended_security:
            self.packet.header['Flags2'] |= SMB_FLAGS2_EXTENDED_SECURITY

        if self.sign:
            self.packet.header['Flags2'] |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE
            if self.session_key != None:
                self.seq_number += 2
                self.packet.sign(self.seq_number, self.session_key)

        data = self.packet.pack()
        length = len(data)
        self.s.sendall(pack('>BBH', 0, (length >> 16) & 0xFF, length & 0xffff) + data)
        if inc_mid == True:
            self.mid = (self.mid + 1) & 0xffff

    def send_request(self, command):

        if self.extended_security:
            command.header['Flags2'] |= SMB_FLAGS2_EXTENDED_SECURITY

        if self.sign:
            command.header['Flags2'] |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE

            if self.session_key != None:
                self.seq_number += 2
                command.sign(self.seq_number, self.session_key)

        data   = command.serialize()
        length = len(data)
        self.s.sendall(pack('>BBH', 0, (length >> 16) & 0xFF, length & 0xffff) + data)

    def send_raw(self, data):
        self.s.sendall(data)

    def send_recv_command(self, command):
        self.send_request(command)
        return self.recv_response()

    def send_recv(self, response=True):
        try:
            self.send()
        except socket.error as err:
            raise SMBReadException(status=err[0], message=err[1])

        if not response:
            return

        try:
            self.recv()
        except socket.error as err:
            # In case of asynchronous mode we may receive this exception
            # so we translate it in the most suitable NTSTATUS error we can find.
            if err[0] == 11:
                raise SMBReadException(status=smbconst.STATUS_REQUEST_NOT_ACCEPTED, message=err[1])
            # Whatever the error is, we need to report it.
            else:
                raise SMBReadException(status=err[0], message=err[1])

    def write_frag(self, data, offset, remaining, is_first=False):
        """
        Raises SMBWriteException on failure.
        """

        self.packet = SMBPacket(None, SMB_COM_WRITE_ANDX, tid = self.tid, pid = self.pid, mid = self.mid, uid = self.uid, is_unicode=self.is_unicode)
        self.packet.body['Fid'] = self.fid
        self.packet.body['Offset'] = offset
        if is_first == True:
            self.packet.body['WriteMode'] = 8 #XXX: Replace with a constant --Kostya
        #self.packet.body['Remaining'] = remaining
        self.packet.body['Data'] = data
        self.send_recv()
        status = self.packet.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBWriteException(status=status)

    def write(self, stream):
        """
        Raises SMBWriteException on failure.
        """

        stream.seek(0, 2) #os.SEEK_END
        remaining = stream.tell()
        stream.seek(0, 0) #os.SEEK_SET

        # From [MS-SMB].pdf
        # When signing is active on a connection, then clients
        # MUST limit write lengths to the MaxBufferSize value
        # negotiated by the server, irrespective of the value of
        # the CAP_LARGE_WRITEX flag.
        # NOTE: CAP_RAW_MODE is also able to bypass the fragmentation.
        # This should be implemeted later.

        # Case 1: We have CAP_LARGE_WRITEX (and signature is disabled)
        # In this case we send as much as we want.
        if self.large_write and not self.sign:
            fragsize = remaining
        # Case 2: We either have CAP_LARGE_WRITEX and a signature
        # or no CAP_LARGE_WRITEX at all (with or without signature)
        else:
            if remaining > self.max_write:
                fragsize = self.max_write
            else:
                fragsize = remaining

        # But we may have requested a specific fragmentation!
        if self.max_smbfrag != 0 and fragsize > self.max_smbfrag:
            fragsize = self.max_smbfrag
        offset = 0
        for i in range(0, remaining, fragsize):
            frag = stream.read(fragsize)
            self.write_frag(frag, offset, remaining, i == 0)
            remaining -= len(frag)
            offset += len(frag)

    def read_frag(self, size, offset):
        """
        Raises SMBReadException on failure.
        """

        self.packet = SMBPacket(None, SMB_COM_READ_ANDX, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['Fid']        = self.fid
        self.packet.body['MaxCount']   = size
        self.packet.body['MinCount']   = size
        self.packet.body['Offset']     = offset
        self.send_recv()
        status = self.packet.header['Status']

        if status not in (STATUS_SUCCESS, STATUS_BUFFER_OVERFLOW):
            raise SMBReadException(status=status)

        return self.packet.body['Data']

    def read(self, stream, filesize=0xffffffff):
        """
        Raises SMBReadException on failure.
        """

        # Case 1: We have CAP_LARGE_READX (and signature is disabled)
        # In this case we recv as much as we want.
        if self.large_read and not self.sign:
            fragsize = filesize
        # Case 2: We either have CAP_LARGE_READX and a signature
        # or no CAP_LARGE_READX at all (with or without signature)
        else:

            if filesize > self.max_write:
                fragsize = self.max_write
            else:
                fragsize = filesize

        # But we may have requested a specific fragmentation!
        if self.max_smbfrag != 0 and fragsize > self.max_smbfrag:
            fragsize = self.max_smbfrag

        offset = 0
        status = STATUS_SUCCESS
        while (offset < filesize):
            if status != STATUS_BUFFER_OVERFLOW and (filesize - offset < fragsize):
                fragsize = filesize - offset

            frag = self.read_frag(fragsize, offset)
            status = self.packet.header['Status']

            if frag != None:
                stream.write(frag)
                offset += len(frag)
            if len(frag) < fragsize:
                break

    def negotiate(self, max_buffer_size=None):
        """
        Perform an SMB negotiation with server.
        SMBNegotiationException is raised on failure.
        """

        req = self.new_request(SMB_COM_NEGOTIATE)
        res = self.send_recv_command(req)

        self.pid           = random.randint(1, 0xfffd)
        capabilities       = res.parameters['Capabilities']
        max_size           = res.parameters['MaxBufferSize']

        if isinstance(res.data, SMBNegotiateNTLanManagerNonExtendedResponseData):
            self.primarydomain = res.data['DomainName']
            self.servername    = res.data['ServerName']

        self._connection.server_capabilities = capabilities

        # We have a design error here.
        # MaxBufferSize is not the maximum size of the payload but the maximum
        # size of the payload + various SMB headers
        # However due to the way write() is written, it's not easy to deal with
        # the fragmentation properly so the best is just to retrieve 256 (empiric
        # value). With legit servers we should always be OK.
        # We had an exception in case it happens

        if max_size <= 256:
            raise SMBNegotiationException(status=999)

        if max_size - 256 < self.max_write:
            self.max_write = max_size - 256

        if max_size - 256 < self.max_read:
            self.max_read = max_size - 256

        if capabilities & CAP_LARGE_READX:
            self.large_read = True

        if capabilities & CAP_LARGE_WRITEX:
            self.large_write = True

        if res.header['Status'] != STATUS_SUCCESS:
            raise SMBNegotiationException(status=res.header['Status'])

    def session_setup(self, username=None, password=None, kerberos_db=None, use_krb5=False):
        """
        Perform an SMB session setup exchange with server.
        SMBSessionSetupException is raised on failure.
        """

        req = self.new_request(SMB_COM_SESSION_SETUP_ANDX)

        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        if not username:
            username = self.username
        if not password:
            password = self.password
        if not kerberos_db:
            kerberos_db = self.kerberos_db
        if not use_krb5:
            use_krb5 = self.use_krb5

        # By default, it's better to use NTLM authentication
        if not use_krb5:
            auth = NTLM(username, password, self.workstation, self.domain)
            methtypes = [GSS_NTLMSSP]
        else:
            target_ip = self.s.getpeername()[0]
            target_hostname = GetHostnameUsingSMB(target_ip)
            if not target_hostname:
                raise SMBSessionSetupException(message='Authentication failed: Cannot retrieve target hostname')
            auth = KRB5(UserName=username, Password=password, DomainName=unicode(self.domain), TargetHostname=target_hostname, DbName=kerberos_db)
            methtypes = [GSS_KRB5]

        gss = GSSAPI(None, True)
        auth_token = auth.negotiate()
        if not auth_token:
            raise SMBSessionSetupException(message='Authentication failed.', status=STATUS_ACCESS_DENIED)

        if self.extended_security:
            gss.spnego_init(auth_token, methtypes)
            gss_str = gss.pack()
            req.data['SecurityBlob'] = UCHAR_Array(gss_str)
            req.parameters['SecurityBlobLength'] = len(gss_str)

        res = self.send_recv_command(req)

        self.uid          = res.header['UID']
        try:
            self.nativeos     = res.data['NativeOS']
        except:
            self.nativeos = u''
        try:
            self.nativelanman = res.data['NativeLANMan']
        except:
            self.nativelanman = u''

        status = res.header['Status']
        if status == STATUS_MORE_PROCESSING_REQUIRED:

            # The first thing we do is checking there was no error with the authentication
            try:
                result,oid,token = gss.spnego_answer(str(res.data['SecurityBlob']).decode('hex')) # TODO
            except Exception as e:
                raise SMBSessionSetupException(message='Authentication failed: %s' % str(e))

            if use_krb5 and oid != GSS_KRB5:
                raise SMBSessionSetupException(message='Authentication failed: GSS_KRB5 method of authentication was rejected.')

            if not use_krb5 and oid != GSS_NTLMSSP:
                raise SMBSessionSetupException(message='Authentication failed: GSS_NTLMSSP method of authentication was rejected.')

            # If the authentication package is NTLMSSP
            if not use_krb5:

                # At this point, a token is mandatory!
                if not len(token):
                    raise SMBSessionSetupException(message='Authentication failed: GSS_NTLMSSP expects a token being returned.')

                auth.challenge(token)
                gss = GSSAPI()
                gss.spnego_cont(auth.authenticate())

                req = self.new_request(SMB_COM_SESSION_SETUP_ANDX)
                req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
                req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
                if self.is_unicode:
                    req.header['Flags2'] |= SMB_FLAGS2_UNICODE

                gss_str = gss.pack()
                req.data['SecurityBlob'] = UCHAR_Array(gss_str)
                req.parameters['SecurityBlobLength'] = len(gss_str)

                res = self.send_recv_command(req)
                status = res.header['Status']

                if status == STATUS_SUCCESS:
                    self.uid = res.header['UID']
                    #if self.packet.header['SecuritySignature'] != '\0' * 8: #If this SecuritySignature is NULL, the server side doesn't allow SMB signature
                    if res.header['SecuritySignature'] != '\0' * 8: # TODO
                        self.session_key = auth.ExportedSessionKey
                        logging.debug('ExportedSessionKey = %s'%(self.session_key.encode('hex')))
                else:
                    raise SMBSessionSetupException(status=status)

            # IF the authentication package is KRB5 we should not be there.
            else:
                # TODO. Implement KRB5.
                raise SMBSessionSetupException(message='Authentication failed: KRB5 requires more data than expected.')

        else:
            if status == STATUS_SUCCESS:
                self.session_key = auth.ExportedSessionKey
            else:
                raise SMBSessionSetupException(status=status)


    def tree_connect(self, share, vhost=None):
        """
        Performs a tree connect operation with server.
        SMBTreeConnectException is raised on failure.
        """
        (share, vhost) = map(assert_unicode, (share, vhost))

        if vhost == None:
            vhost = self.s.getpeername()[0]

        self.packet = SMBPacket(None, SMB_COM_TREE_CONNECT_ANDX, pid=self.pid, uid=self.uid, is_unicode=self.is_unicode)
        path = u'\\\\%s\\%s' % (vhost, share)

        self.packet.body['Password'] = '\0'
        self.packet.body['Path'] = path
        self.packet.body['Service'] = u'?????'
        self.send_recv()

        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBTreeConnectException(status=status)

        # Add entries to lookup the tree connect by TID. We use the last
        # added TID as the main one for operations.
        tid = self.packet.header['TID']
        assert tid not in self._tree_connect_table
        self._tree_connect_table[tid] = share

    def nt_create(self, name = u'', desired_access=FILE_READ_DATA,
                  share_access=FILE_SHARE_READ, disposition=FILE_OPEN,
                  options=FILE_NON_DIRECTORY_FILE):
        """
        SMBNTCreateException is raised on failure.
        """
        name = assert_unicode(name)

        self.packet = SMBPacket(None, SMB_COM_NT_CREATE_ANDX, tid=self.tid,
                                pid=self.pid, mid=self.mid, uid=self.uid,
                                is_unicode=self.is_unicode)

        self.packet.body['Name'] = name
        self.packet.body['DesiredAccess'] = desired_access
        self.packet.body['ShareAccess'] = share_access
        self.packet.body['CreateDisposition'] = disposition
        self.packet.body['CreateOptions'] = options
        self.send_recv()

        status = self.packet.header['Status']
        if status == STATUS_SUCCESS:
            self.fid = self.packet.body['Fid']
        else:
            raise SMBNTCreateException(status=status)


    def transact_send_recv(self, response=True):
        """
        send_recv() function for SMB_COM_TRANSACTION* packets where the
        'Data' field can be split on several packets. We sort of cheat here
        by keeping the 1st packet and reassembling the data in the 'Data'
        field of this packet
        """
        self.packet.body['MaxDataCount'] = 0x4000
        self.send_recv(response)
        if response == False:
            return

        initial_packet = self.packet
        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBTransactException(status = status)
        reassembled_data = initial_packet.body['Data']
        while len(reassembled_data)<initial_packet.body['TotalDataCount']:
            self.recv()
            status = self.packet.header['Status']
            command = self.packet.header['Command']
            if status != STATUS_SUCCESS:
                raise SMBTransactException(status = status)
            elif command not in (SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2):
                raise SMBTransactException('Transact response packet != SMB_COM_TRANSACTION, SMB_COM_TRANSACTION2')
            if self.packet.body['DataDisplacement'] != len(reassembled_data):
                raise SMBTransactException('We do not support overlapping data in transact responses.')
            reassembled_data += self.packet.body['Data']
        initial_packet.body['Data'] = reassembled_data
        initial_packet.pack() #This will update the *Count fields
        self.packet = initial_packet

    def transact_np(self, data, name=u'\\PIPE\\', response=True):
        """
        Raises SMBTransactException on failure.
        """

        req = self.new_request(SMB_COM_TRANSACTION)

        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        req.parameters['TotalDataCount'] = len(data)
        req.parameters['MaxParameterCount'] = 0
        req.parameters['MaxDataCount'] = 16384      # TODO
        req.parameters['MaxSetupCount'] = 0

        req.parameters['ParameterCount'] = 0
        req.parameters['ParameterOffset'] = 82      # TODO
        req.parameters['DataCount'] = len(data)
        req.parameters['DataOffset'] = 82           # TODO

        setup = pack('<HH', TRANS_TRANSACT_NMPIPE, self.fid)
        req.parameters['SetupCount'] = len(setup) / 2
        req.parameters['Setup'] = USHORT_Array(setup)

        req.data['Name'] = SMB_String(name)
        req.data['Trans_Data'] = UCHAR_Array(data)

        res = self.send_recv_command(req)
        status = res.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBTransactException(status=status)

        trans_data = str(res.data['Trans_Data']).decode('hex')
        return trans_data

    def transact_wait(self, data='', name=u'\\PIPE\\', response=True):
        """
        Raises SMBTransactException on failure.
        """

        req = self.new_request(SMB_COM_TRANSACTION)

        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        req.parameters['TotalDataCount'] = len(data)
        req.parameters['MaxParameterCount'] = 0
        req.parameters['MaxDataCount'] = 16384      # TODO
        req.parameters['MaxSetupCount'] = 0

        req.parameters['ParameterCount'] = 0
        req.parameters['ParameterOffset'] = 82      # TODO
        req.parameters['DataCount'] = len(data)
        req.parameters['DataOffset'] = 82           # TODO

        setup = pack('<HH', TRANS_WAIT_NMPIPE, 0)
        req.parameters['SetupCount'] = len(setup) / 2
        req.parameters['Setup'] = USHORT_Array(setup)

        req.data['Name'] = SMB_String(name)
        req.data['Trans_Data'] = UCHAR_Array(data)

        res = self.send_recv_command(req)
        status = res.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBTransactException(status=status)

        trans_data = str(res.data['Trans_Data']).decode('hex')
        return trans_data


    def transact_peek_np(self):
        """
        Do a PEEK operation on named pipe currently open.
        Return bytes_available, message_length, np_state in a tuple.
        See pg.415/MS-CIFS.
        Raises SMBTransactException on failure.
        """

        req = self.new_request(SMB_COM_TRANSACTION)

        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        setup = pack('<HH', TRANS_PEEK_NMPIPE, self.fid)
        req.parameters['SetupCount'] = len(setup) / 2
        req.parameters['Setup'] = USHORT_Array(setup)
        req.parameters['MaxParameterCount'] = 0

        res = self.send_recv_command(req)
        status = res.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBTransactException(status=status)

        trans_parameters = str(res.data['Trans_Parameters']).decode('hex')
        to_read, message_length, np_state = unpack('<HHH', trans_parameters)
        return (to_read, message_length, np_state)

    def check_directory(self, directory):
        """
        Raises SMBCheckDirectoryException on failure.
        """

        directory = assert_unicode(directory)
        self.packet = SMBPacket(None, SMB_COM_CHECK_DIRECTORY, tid=self.tid,
                                pid=self.pid, mid=self.mid, uid=self.uid,
                                is_unicode=self.is_unicode)

        self.packet.body['DirectoryName'] = directory
        self.send_recv()

        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBCheckDirectoryException(status=status)


    def find_first(self, filename=u'\\*', response=True):
        """
        [MS-CIFS].pdf: 2.2.6.2.1 Request, 2.2.6.2.2 Response
        Raises SMBTransactException on failure.
        """
        filename = assert_unicode(filename)

        self.packet = SMBPacket(None, SMB_COM_TRANSACTION2, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['MaxParameterCount'] = 0x10
        self.packet.body['MaxDataCount'] = 0x4000
        self.packet.body['Setup'] = pack('<H', TRANS2_FIND_FIRST2)
        parameters = pack('<HHHHL', SMB_FILE_ATTRIBUTE_HIDDEN | SMB_FILE_ATTRIBUTE_SYSTEM | SMB_FILE_ATTRIBUTE_DIRECTORY,
                          0x1000, SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS, SMB_FIND_FILE_BOTH_DIRECTORY_INFO, 0)

        filename += u'\0'

        if self.is_unicode == True:
            parameters += filename.encode('UTF-16LE')
        else:
            parameters += filename.encode('ASCII')

        self.packet.body['Parameters'] = parameters
        self.transact_send_recv(response)

        if response == False:
            return None

        parameters = self.packet.body['Parameters']
        self.sid, _, self.eos, _, last_offset = unpack('<HHHHH', parameters) #SID, SearchCount, EndOfSearch, EaErrorOffset, LastNameOffset
        data = self.packet.body['Data']
        entry = SMBInformationStandardEntry(data[last_offset:], is_unicode=self.is_unicode)
        self.lastname = entry['FileName']
        return data

    def find_next(self, response=True):
        """
        [MS-CIFS].pdf: 2.2.6.3.1 Request, 2.2.6.3.2 Response
        Raises SMBTransactException on failure.
        """
        self.packet = SMBPacket(None, SMB_COM_TRANSACTION2, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['MaxParameterCount'] = 0x8
        self.packet.body['MaxDataCount'] = 0x4000
        self.packet.body['Setup'] = pack('<H', TRANS2_FIND_NEXT2)
        parameters = pack('<HHHLH', self.sid, 0x1000, SMB_FIND_FILE_BOTH_DIRECTORY_INFO, 0, SMB_FIND_CLOSE_AT_EOS | SMB_FIND_RETURN_RESUME_KEYS)

        filename = self.lastname

        # We have to null terminate this string
        if filename[-1] != u'\0':
            filename += u'\0'

        if self.is_unicode == True:
            parameters += filename.encode('UTF-16LE')
        else:
            parameters += filename.encode('ASCII')

        self.packet.body['Parameters'] = parameters
        self.transact_send_recv(response)

        if response == False:
            return None

        parameters = self.packet.body['Parameters']
        _, self.eos, _, last_offset = unpack('<HHHH', parameters) #SearchCount, EndOfSearch, EaErrorOffset, LastNameOffset
        data = self.packet.body['Data']
        entry = SMBInformationStandardEntry(data[last_offset:], is_unicode = self.is_unicode)
        self.lastname = entry['FileName']
        return data

    def dir(self, filename=u'\\*'):
        """
        Return a list of SMBInformationStandardEntry instances.
        Wraps calls to find_first and find_next until the search is over.
        The empty list is returned on failure.
        """
        results = []
        filename = assert_unicode(filename)

        try:
            data = self.find_first(filename)
            results += parseSMBFindData(data, is_unicode=self.is_unicode)
            while self.eos != 1:
                data = self.find_next()
                results += parseSMBFindData(data, is_unicode=self.is_unicode)
        except SMBException:
            pass

        return results

    def mkdir(self, name):
        """
        Make a directory with name on the server.
        Raises SMBTransactException on failure.
        """
        name = assert_unicode(name)

        self.nt_create(name=name,
                       share_access=FILE_SHARE_READ|FILE_SHARE_WRITE,
                       disposition=FILE_CREATE,
                       options=FILE_DIRECTORY_FILE)
        try:
            self.close()
        except SMBException, ex:
            logging.debug('Error during close: %s' % ex)

    def delete(self, name):
        """
        Delete file with name on the server.
        Raises SMBDeleteException on failure.
        """
        name = assert_unicode(name)
        self.packet = SMBPacket(None, SMB_COM_DELETE, tid=self.tid,
                                pid=self.pid, mid=self.mid, uid=self.uid,
                                is_unicode=self.is_unicode)

        self.packet.body['FileName'] = name
        self.send_recv()

        status = self.packet.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBDeleteException(status=status)

    def delete_directory(self, name):
        """
        Delete directory with name on the server.
        Raises SMBDeleteDirectoryException on failure.
        """
        name = assert_unicode(name)
        self.packet = SMBPacket(None, SMB_COM_DELETE_DIRECTORY, tid=self.tid,
                                pid=self.pid, mid=self.mid, uid=self.uid,
                                is_unicode=self.is_unicode)
        self.packet.body['DirectoryName'] = name
        self.send_recv()
        status = self.packet.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBDeleteDirectoryException(status=status)


    def query_file_stream_info(self, response=True):
        """
        [MS-CIFS].pdf: 2.2.6.8.1 Request, 2.2.6.8.2 Response
        Returns a list of SMBQueryFileStreamEntry instances
        Raises SMBTransactException on failure
        """
        results = []
        self.packet = SMBPacket(None, SMB_COM_TRANSACTION2, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['MaxParameterCount'] = 0x2
        self.packet.body['MaxDataCount'] = 0x220
        self.packet.body['Setup'] = pack('<H', TRANS2_QUERY_FILE_INFORMATION)
        self.packet.body['Parameters'] = pack('<HH', self.fid, 1022) #XXX: [MS-CIFS] says SMB_QUERY_FILE_STREAM_INFO is 0x109, packet dumps say 1022
        self.transact_send_recv(response)

        if response == False:
            return results

        data = self.packet.body['Data']
        results += parseSMBQueryFileInformationData(data, 1022)
        return results


    def close (self):
        """
        Raises SMBCloseException on failure.
        """
        self.packet = SMBPacket(None, SMB_COM_CLOSE, tid=self.tid, pid=self.pid,
                                mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['Fid'] = self.fid
        self.send_recv()
        status = self.packet.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBCloseException(status=status)


    def put(self, local_stream, remote_name, overwrite=False):
        """
        Raises SMBNTCreateException or SMBWriteException on failure.
        """
        remote_name = assert_unicode(remote_name)
        desired_access = SYNCHRONIZE | FILE_WRITE_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES
        if not overwrite:
            desired_access |= FILE_APPEND_DATA
        # This may raise an SMBNTCreateException
        self.nt_create(name=remote_name,
                       desired_access = desired_access,
                       share_access = 0,
                       disposition = FILE_OVERWRITE_IF,
                       options = FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE)

        # This may raise an SMBWriteException
        self.write(local_stream)

        # Don't forget to close!
        # In this case, we catch the SMBCloseException because the write was
        # successful so that the upper layer keeps working.
        try:
            self.close()
        except SMBCloseException, ex:
            logging.debug('Error during close: %s' % ex)


    def get(self, remote_name, local_stream):
        """
        local_stream is a file or StringIO
        Can raise SMBNTCreateException, SMBTransactException, SMBReadException
        """
        remote_name = assert_unicode(remote_name)
        self.nt_create(name=remote_name,
                       desired_access = READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_READ_EA | FILE_READ_DATA,
                       share_access = FILE_SHARE_READ, disposition = FILE_OPEN, options = FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE)
        try:
            streams = self.query_file_stream_info()
            filesize = 0
            for s in streams:
                if s['StreamName'] == u'::$DATA':
                    filesize = s['StreamSize']
                    break
            if filesize != 0:
                self.read(local_stream, filesize)
        finally:
            # Don't forget to close!
            try:
                self.close()
            except SMBCloseException, ex:
                logging.debug('Error during close: %s' % ex)

    def query_information(self, path):
        """
        Queries SMB server for stat information on path.
        No open FID is required, just the path.

        Return a list of file size, last write time (unix epoch),
        is_dir (boolean)
        Raises SMBQueryInformationException on failure
        """
        path = assert_unicode(path)
        self.packet = SMBPacket(None, SMB_COM_QUERY_INFORMATION, tid=self.tid,
                                pid=self.pid, uid=self.uid, mid=self.mid,
                                is_unicode=self.is_unicode)
        self.packet.body['FileName'] = path
        self.send_recv()
        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBQueryInformationException(status=status)
        is_dir = True if self.packet.body['FileAttributes'] & SMB_FILE_ATTRIBUTE_DIRECTORY else False
        return [self.packet.body['FileSize'],
                self.packet.body['LastWriteTime'], # unixtime
                is_dir]

    def tree_disconnect(self, tid=None):
        """
        Raises SMBTreeDisconnectException on failure.
        """

        if tid is None:
            tid = self.tid

        req = self.new_request(SMB_COM_TREE_DISCONNECT)

        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        req.header['TID'] = tid
        res = self.send_recv_command(req)
        status = res.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBTreeDisconnectException(status=status)

        del self._tree_connect_table[tid]

    def logoff(self):
        """
        Raises SMBLogoffException on failure.
        """
        req = self.new_request(SMB_COM_LOGOFF_ANDX)
        req.header['Flags']  = SMB_FLAGS_CASE_INSENSITIVE
        req.header['Flags2'] = SMB_FLAGS2_NT_STATUS | SMB_FLAGS2_KNOWS_EAS
        if self.is_unicode:
            req.header['Flags2'] |= SMB_FLAGS2_UNICODE

        res = self.send_recv_command(req)
        status = res.header['Status']

        if status != STATUS_SUCCESS:
            raise SMBLogoffException(status=status)

    def nt_ioctl(self, function_code, fid, is_fsctl, data=None, response=True):
        """
        Raises SMBTransactException on failure.
        """
        self.packet = SMBPacket(None, SMB_COM_NT_TRANSACT, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['Setup'] = pack('<LHBB', function_code, fid, is_fsctl, 0)
        if data != None:
            self.packet.body['NT_Trans_Data'] = data
        self.packet.body['Function'] = NT_TRANSACT_IOCTL
        self.send_recv(response)
        if response == False:
            return None
        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBTransactException(status=status)

        data = self.packet.body['NT_Trans_Data']
        return data

    def ioctl(self, response=True):
        """
        Raises SMBIOCTLException on failure.
        """
        self.packet = SMBPacket(None, SMB_COM_IOCTL, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['FID'] = self.fid
        self.packet.body['Category'] = 0x4141
        self.packet.body['Function'] = 0x4242
        self.packet.body['Parameters'] = 'C' * 0x20
        self.packet.body['Data'] = 'D' * 0x30
        self.send_recv(response)
        if response == False:
            return None
        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBIOCTLException(status=status)
        data = self.packet.body['Data']
        return data

    def get_dfs_referral(self, response=True):
        """
        Raises SMBTransactException on failure.
        """
        self.packet = SMBPacket(None, SMB_COM_TRANSACTION2, tid=self.tid, pid=self.pid, mid=self.mid, uid=self.uid, is_unicode=self.is_unicode)
        self.packet.body['MaxParameterCount'] = 0x8000
        #self.packet.body['MaxDataCount'] = 0x4000
        self.packet.body['Setup'] = pack('<H', 0x10) #TRANS2_GET_DFS_REFERRAL
        parameters = pack('<H', 0)
        parameters += 'A' * 0x1080
        self.packet.body['Parameters'] = parameters
        self.send_recv(response)
        if response == False:
            return None
        status = self.packet.header['Status']
        if status != STATUS_SUCCESS:
            raise SMBTransactException(status=status)
        return None


################################################################################
#                                                                              #
#   SMBServer  - Official SMB library for server side request handling         #
#                                                                              #
#   TODO:                                                                      #
#           a) Virtual shares (in-memory fs) not complete                      #
#           b) Replace the OLD SMBPacket API.                                  #
#                                                                              #
################################################################################


class SMBServer():
    CONN_QUEUE = 5 # Max number of connections to queue on listen socket

    def __init__(self, sock, timeout=120):
        self.s           = sock
        self.lock        = threading.Lock()
        self.shares      = {}
        self.targets     = {} # Allow anyone to connect if empty
        self.timeout     = timeout

    def listen(self, host='0.0.0.0', port=445):
        """
        Start listening for connections.
        """
        try:
            self.s.bind((host, port))
            self.s.listen(SMBServer.CONN_QUEUE)
        except Exception, ex:
            logging.debug('%s' % ex)
            raise SMBServerException('Error on bind/listen(): %s' % ex)

        logging.debug('SMBServer: listening at %s:%d' % (host, port))
        return True

    def setFileData(self, name, data=None):
        """
        Should be a NAME of the form \\share\\dirs..\\file (dirs are optional).
        This should create a virtual file with contents DATA
        in the in-memory filesystem and have it ready for sharing.
        If the file already exists, the contents will be updated.
        If data == None, the file will be removed from the virtual filesystem if present.
        """
        name = assert_unicode(name)
        # Some sanity tests for name
        if name[0] != u'\\':
            name = u'\\' + name
        tokens = fix_universal_path(name)
        if len(tokens) < 2:
            raise SMBServerException('Filename should be of the form \\\\Share\\dirs*\\file')

        share = tokens[0]
        f  = tokens[-1]

        if share not in self.shares:
            self.shares[share] = {'Type'       : 'Virtual',
                                  'Path'       : None,
                                  'FileSystem' : {}}
            logging.debug('[*] Added virtual share %s' % share)

        elif self.shares[share]['Type'] != 'Virtual':
            raise SMBServerException('Share %s is already mapped to the filesystem.')

        root = self.shares[share]['FileSystem']
        for dir in tokens[1:-1]:
            if dir not in root:
                logging.debug('[*] Added virtual directory %s' % dir)
                root[dir] = {}
            root = root[dir]

        if data == None and f in root:
            del root[file]
            logging.debug('[*] Removed virtual file %s' % name)
            # Maybe check to see if virtual directory is empty and remove it from tree
        root[f] = data
        logging.debug('[*] Added virtual file %s' % name)

    def addTarget(self, target):
        """
        Add target IP to dict of clients that are allowed to connect to us.
        """
        self.targets[target] = 1


    def removeTarget(self, target):
        """
        Remove target IP from dict of clients that are allowed to connect to us.
        """
        if target in self.targets:
            del self.targets[target]

    def accept(self):
        """
        """
        try:
            (client, address) = self.s.accept()
            client.settimeout(self.timeout)
            logging.debug('SMBServer: got connection from %s' % str(address))
        except Exception, ex:
            logging.debug('%s' % ex)
            raise SMBServerException('Error on accept(): %s' % ex)

        if self.targets:
            if not address[0] in self.targets:
                logging.debug('%s:%d is not allowed to connect to us, dropping' % address)
                client.close()

        def handler():
            logging.debug('SMBServerConnection: %s:%d' % address)
            con = SMBServerConnection(client, shares=self.shares)
            try:
                con.main_loop()
            except SMBException, ex:
                logging.debug('SMB Error: %s' % ex)
            except socket.error, ex:
                logging.debug('Socket Error: %s' % ex)
            finally:
                client.close()

        # Fire up a new thread to handle the client
        threading.Thread(target=handler).start()
        return True

    def shutdown(self):
        """
        """
        logging.debug('SMBServer: Shutting down')
        self.s.close()

    def add_share(self, share_name, path):
        """
        Add a new share (path on filesystem) as share_name
        If path == None, the share is virtual (not backed by a filesystem)
        """

        (share_name, path) = map(assert_unicode, (share_name, path))

        with self.lock:
            if share_name not in self.shares:
                self.shares[share_name] = {'Type'       : 'Virtual' if path == None else 'FS',
                                           'Path'       : path,
                                           'FileSystem' : {} if path == None else None}
                logging.debug('[*] Mapped share %s to %s.' % (share_name, path))
            else:
                logging.debug('[!] Share %s is already mapped to %s.' % (share_name, self.shares[share_name]['Path']))


    def rem_share(self, share_name):
        """
        Remove share with share_name
        """
        share_name = assert_unicode(share_name)
        with self.lock:
            if share_name in self.shares:
                del self.shares[share_name]
                logging.debug('[*] Removed share %s (was mapped to %s).' % (share_name, self.shares[share_name]['Path']))
            else:
                logging.debug('[!] Share %s is not mapped.' % share_name)


class SMBServerConnection(SMB):
    SUPPORTED_DIALECTS = ['NT LM 0.12']
    SECURITY_MODE = NEGOTIATE_ENCRYPT_PASSWORDS
    CAPABILITIES = CAP_UNICODE|CAP_STATUS32|CAP_EXTENDED_SECURITY|CAP_LARGE_FILES|CAP_NT_SMBS
    GUID = "zabcdfgertagsdfe" # Needed for NTLM auth
    MAX_BUFFER_SIZE = 65535
    MAX_MPX_COUNT = 1

    def __init__(self, socket, shares=None):
        SMB.__init__(self, socket)

        # Maps share names to directory paths on the filesystem
        self.shares = {} if shares == None else shares
        self.negotiated = False
        self.dialect_chosen = False
        self.is_unicode = False

        # The following is the main per instance data structure that maps
        # authenticated uids -> tree id connections -> shares and file ids
        # -> open file descriptors.
        # It is a dictionary with keys that correspond to authenticated user ids and
        # values that are dictionaries with keys that correspond to tree_ids and values
        # that are dictionaries with the following keys and values:
        # 'share' -> name of share corresponding to tree_id (lookup in
        #            self.shares for path)
        # 'files' -> Dictionary with elements: 'fileid' -> (file object, file name)
        # 'searches' -> Dictionary with elements: 'searchid' -> None
        self.authenticated_connections = {}

        # The following are used as per-instance unique counters
        # and auto incremented
        self.user_id = 0
        self.tree_id = 0
        self.search_id = 0
        self.file_id = 0xabcd

        ##
        self.pid = 0
        self.pid_high = 0
        self.mid = 0
        self.tid = 0
        self.uid = 0
        self.flags2 = 0

    ###
    # Helper methods
    ###

    # Override send/recv for debugging and correct parsing of packets in server mode
    def send(self):
        # Take care of flags
        self.packet.header['Flags2'] = self.flags2
        self.packet.header['Flags'] = SMB_FLAGS_REPLY
        self.packet.header['PidHigh'] = self.pid_high

        if self.sign:
            self.packet.header['Flags2'] |= SMB_FLAGS2_SMB_SECURITY_SIGNATURE
            if self.session_key != None:
                self.seq_number += 2
                self.packet.sign(self.seq_number, self.session_key)

        if self.extended_security:
            self.packet.header['Flags2'] |= SMB_FLAGS2_EXTENDED_SECURITY

        data = self.packet.pack()
        length = len(data)
        self.s.sendall(pack('>BBH', 0, (length >> 16) & 0xFF, length & 0xffff) + data)

    def recv(self):
        data = self.s.recv(4)
        if data == '':
            # Client closed connection
            raise socket.error('Client closed connection.')

        _, hlen, llen = unpack('>BBH', data)
        total_length = (hlen << 16) + llen
        data = ''
        length = 0

        while length < total_length:
            chunk = self.s.recv(total_length - length)
            if chunk == '':
                raise socket.error('Client closed connection.')

            data += chunk
            length += len(chunk)

        self.packet = SMBPacket(data, is_unicode=self.is_unicode, server=1)
        if not self.packet:
            return

        signature = self.packet.header['SecuritySignature']

        # Always record these fields as they are used by every SMB command
        self.pid = self.packet.header['PID']
        self.pid_high = self.packet.header['PidHigh']
        self.mid = self.packet.header['MID']
        # Set this here as we don't support unauthenticated connections
        self.uid = self.packet.header['UID']
        # Also save the TID even though not all SMB commands make use of it
        self.tid = self.packet.header['TID']

        if signature != ('\0' * 8) and self.session_key != None:
            #XXX: For the moment we ignore the result --Kostya
            self.packet.verify(self.seq_number + 1, self.session_key)


    def generate_session_key(self, pid):
        """
        Generate unique session id for an SMB connection.

        This should be called once per connection from negotiate()
        and sent to the client during the negotiation response.
        """
        return 0xDEADBEEF

    def generate_encryption_key(self):
        """
        Generate 8-byte encryption key used for challenge-response authentication.

        This should be called once per connection from negotiate()
        and sent to the client during the negotiation response.
        """
        return ""

    def generate_user_id(self):
        """
        Return a per-instance unique user id number.

        It corresponds to an authenticated connection.
        """
        self.user_id += 1
        self.user_id &= 0xffff

        if self.user_id == 0xffff:
            self.user_id = 0

        return self.user_id


    def generate_tree_id(self):
        """
        Return a per-instance unique tree id number.

        A simple increment-by-one scheme is used.
        """

        self.tree_id += 1
        self.tree_id &= 0xffff

        if self.tree_id == 0xffff:
            self.tree_id = 0

        return self.tree_id

    def generate_file_id(self):
        """
        Return a per-instance unique file id number.

        A simple increment-by-one scheme is used.
        """
        self.file_id += 1
        self.file_id &= 0xffff

        if self.file_id == 0xffff:
            self.file_id = 0

        return self.file_id

    def generate_search_id(self):
        """
        Return a per-instance unique search id number.

        A simple increment-by-one scheme is used.
        """
        self.search_id += 1
        self.search_id &= 0xffff

        if self.search_id == 0xfff:
            self.search_id = 0

        return self.search_id


    def _disconnect_tid(self):
        """
        Remove current TID from list of open tree ids.

        This also frees all resources (file objects/search ids) linked
        with TID.
        """
        for v in self.authenticated_connections[self.uid][self.tid]['files'].values():
            if not v['dir'] and v['file']:
               v['file'].close()

        # Remove TID
        del self.authenticated_connections[self.uid][self.tid]


    # The _valid_{uid,tid} methods do not accept any arguments because the
    # uptodate values of uid, tid are retrieved and saved in SMBServerConnection.recv()
    # automatically for every packet
    def _valid_uid(self):
        """
        Check if self.uid belongs to an authenticated connection.
        """
        return self.uid in self.authenticated_connections

    def _valid_tid(self):
        """
        Check if self.tid is current and valid.
        """
        if self.uid not in self.authenticated_connections:
            return False
        return self.tid in self.authenticated_connections[self.uid]

    def _valid_fid(self, fid):
        """
        Check if fid is valid in the context of TID.
        """
        return fid in self.authenticated_connections[self.uid][self.tid]['files']

    def _valid_sid(self, sid):
        """
        Check if sid is valid.
        """
        if self.uid not in self.authenticated_connections:
            return False
        if self.tid not in self.authenticated_connections[self.uid]:
            return False
        return sid in self.authenticated_connections[self.uid][self.tid]['searches']

    def _info_from_fid(self, fid):
        """
        Return a file info dictionary corresponding to FID.
        """
        if self.uid not in self.authenticated_connections:
            return None
        if self.tid not in self.authenticated_connections[self.uid]:
            return None
        return self.authenticated_connections[self.uid][self.tid]['files'][fid]

    def _fs_from_tid(self, tid):
        return self.shares[self.authenticated_connections[self.uid][tid]['share']]['FileSystem']

    def _path_from_tid(self):
        return self.shares[self.authenticated_connections[self.uid][self.tid]['share']]['Path']

    def _response(self, command):
        """
        Return a new SMBPacket instance (server response).
        """
        return SMBPacket(command=command, tid=self.tid, pid=self.pid, uid=self.uid,
                         mid=self.mid, server=1, is_unicode=self.is_unicode)

    ###
    # Main protocol methods
    ###

    def send_error(self, command, status):
        """
        Send an error response packet to client.
        """
        self.packet = self._response(SMB_ERROR)
        self.packet.header['Command'] = command
        self.packet.header['Status'] = status
        self.send()

    # Complete
    def smb_negotiate(self):
        """
        Perform an SMB negotiation (0x72)
        """

        if self.negotiated:
            raise SMBServerException("Client already negotiated, terminating.")

        dialects = [elem[:-1] for elem in self.packet.body['Dialects'].split('\x02') if elem != '']
        logging.debug("Client dialects: %s" % dialects)

        for idx, value in enumerate(dialects):
            if value in SMBServerConnection.SUPPORTED_DIALECTS:
                self.dialect_chosen = idx
                break

        if not self.dialect_chosen:
            raise SMBServerException("Could not negotiate mutually accepted dialect")

        self.flags2 = self.packet.header['Flags2']
        self.is_unicode = True
        self.packet = self._response(SMB_COM_NEGOTIATE)
        self.packet.body['DialectIndex'] = self.dialect_chosen

        # NT LM 0.12 specific setup
        # The bits of the SecurityMode field of the response are set based upon the values
        # of the Server.ShareLevelAuthentication, Server.PlaintextAuthenticationPolicy,
        # and Server.MessageSigningPolicy server global variables.
        # The MaxMpxCount field is set from the Server.MaxMpxCount global variable.
        # The Capabilities field is set from the Server.Capabilities global variable.
        self.packet.body['SecurityMode'] = SMBServerConnection.SECURITY_MODE
        self.packet.body['MaxMpxCount'] = SMBServerConnection.MAX_MPX_COUNT
        self.packet.body['Capabilities'] = SMBServerConnection.CAPABILITIES
        self.packet.body['MaxBufferSize'] = SMBServerConnection.MAX_BUFFER_SIZE
        self.packet.body['SessionKey'] = self.generate_session_key(self.pid)
        self.packet.body['EncryptionKey'] = self.generate_encryption_key()
        self.packet.body['ServerGuid'] = SMBServerConnection.GUID
        self.send()
        self.negotiated = True


    # Complete except for optional negotiations
    def smb_session_setup_andx(self):
        """
        Do an SMB_COM_SESSION_SETUP_ANDX exchange
        """

        # Save fields that are going to be reused
        self.flags2 = self.packet.header['Flags2']

        # Negotiate unicode, we simply accept what the client supports
        self.is_unicode = True if self.flags2 & SMB_FLAGS2_UNICODE else False

        # Optionally do more negotiations here for long filenames,
        # or nt status error codes etc
        self.uid = self.generate_user_id()
        self.authenticated_connections[self.uid] = {}
        self.packet = self._response(SMB_COM_SESSION_SETUP_ANDX)
        self.send()


    # Complete
    def smb_echo(self):
        echodata = self.packet.body['EchoData']
        echocount = self.packet.body['EchoCount']

        if echocount == 0:
            return

        if self.tid != 0xffff and (not self._valid_uid() or
                                   not self._valid_tid()):
            self.send_error(SMB_COM_ECHO, STATUS_SMB_BAD_TID)
            return

        for i in xrange(1, echocount+1):
            self.packet =self._response(SMB_COM_ECHO)
            self.packet.body['EchoData'] = echodata
            self.packet.body['SequenceNumber'] = i
            self.send()

    # Complete, only supports filesystem-backed shares
    def smb_tree_connect_andx(self):
        path = self.packet.body['Path']
        (server, share) = filter(None, path.split(u'\\'))[:2]
        service = self.packet.body['Service']
        logging.debug(u'TreeConnectAndx requested on \\\\%s\\%s' % (server, share))

        if self.packet.body['Flags'] & TREE_CONNECT_ANDX_DISCONNECT_TID:
            if self._valid_tid():
                self._disconnect_tid()

        if share not in self.shares and (service != u'A:' or service != u'?????'):
            self.send_error(SMB_COM_TREE_CONNECT_ANDX, STATUS_OBJECT_PATH_NOT_FOUND)
        else:
            self.packet = self._response(SMB_COM_TREE_CONNECT_ANDX)
            self.packet.body['Service'] = u'A:'
            # Only support shares backed by an actual filesystem for now
            self.packet.body['NativeFileSystem'] = u'canvas'
            self.packet.body['OptionalSupport'] = SMB_SUPPORT_SEARCH_BITS
            self.tid = self.generate_tree_id()
            self.packet.header['TID'] = self.tid
            self.authenticated_connections[self.uid][self.tid] = {'share' : share,
                                                                  'files' : {},
                                                                  'searches' : {}}
            self.send()

    # Complete
    def smb_tree_disconnect(self):
        self._disconnect_tid()
        self.packet = self._response(SMB_COM_TREE_DISCONNECT)
        self.send()

    # Complete except for: extra attributes (all files are opened rw)
    # search attributes (archive/system/readonly/hidden) are not taken into account
    # sharing modes are not supported
    # usage hints are not supported
    # oplocks are not supported
    def smb_open(self):
        filename = fix_universal_path(self.packet.body['FileName'])

        if len(filename) == 0:
            self.send_error(SMB_COM_OPEN, STATUS_FILE_IS_A_DIRECTORY)
            return

        path = self._path_from_tid()
        path = os.path.join(*([path] + filename))

        if not os.path.exists(path):
            self.send_error(SMB_COM_OPEN, STATUS_NO_SUCH_FILE)
            return

        if not os.path.isfile(path):
            self.send_error(SMB_COM_OPEN, STATUS_FILE_IS_A_DIRECTORY)
            return

        search_atts = self.packet.body['SearchAttributes']

        # Take care of exclusive attributes or directories
        if sum(map(lambda x: search_atts & x,
                   (SMB_SEARCH_ATTRIBUTE_DIRECTORY,
                    SMB_SEARCH_ATTRIBUTE_SYSTEM,
                    SMB_SEARCH_ATTRIBUTE_HIDDEN,
                    SMB_SEARCH_ATTRIBUTE_READONLY))):
            self.send_error(SMB_COM_OPEN, STATUS_NO_SUCH_FILE)
            return

        try:
            fsize = os.path.getsize(path)
            f = open(path, 'r+b')
        except:
            self.send_error(SMB_COM_OPEN, STATUS_ACCESS_DENIED)
            return

        self.packet = self._response(SMB_COM_OPEN)

        fid = self.generate_file_id()
        self.packet.body['Fid'] = fid
        self.packet.body['FileSize'] = fsize
        self.packet.body['AccessMode'] = 2 # read/write
        self.packet.body['FileAttributes'] = SMB_FILE_ATTRIBUTE_NORMAL
        self.packet.body['LastModified'] = int(os.stat(path).st_mtime)

        self.authenticated_connections[self.uid][self.tid]['files'][fid] = {'file' : f,
                                                                            'path' : path,
                                                                            'dir': False}
        self.send()


    # Oplocks are not supported
    # File attributes (hidden/system/readonly/archive) are not supported
    # Sharing modes are not supported
    # All files are opened read-write or created (when create_file_opt is set)
    def smb_open_andx(self):
        extended = self.packet.body['Flags'] & 0x0001

        file_exists_opt = self.packet.body['OpenFunction'] & 0x0003
        create_file_opt = self.packet.body['OpenFunction'] & 0x0010

        path = self._path_from_tid()
        filename = fix_universal_path(self.packet.body['FileName'])
        path = os.path.join(*([path] + filename))
        search_atts = self.packet.body['SearchAttributes']

        # Take care of exclusive attributes or directories
        if sum(map(lambda x: search_atts & x,
                   (SMB_SEARCH_ATTRIBUTE_SYSTEM,
                    SMB_SEARCH_ATTRIBUTE_HIDDEN,
                    SMB_SEARCH_ATTRIBUTE_READONLY))):
            self.send_error(SMB_COM_OPEN_ANDX, STATUS_NO_SUCH_FILE)
            return

        result = 1 # existed and was opened

        try:
            if create_file_opt == 0:
                if not os.path.exists(path):
                    self.send_error(SMB_COM_OPEN_ANDX, STATUS_NO_SUCH_FILE)
                    return
                elif os.path.isfile(path):
                    if file_exists_opt == 0:
                        self.send_error(SMB_COM_OPEN_ANDX, STATUS_ACCESS_DENIED)
                        return
                    elif file_exists_opt == 2:
                        f = open(path, 'r+b')
                        f.truncate(0)
                        result = 3 # existed and truncated
                        fsize = 0
                    else:
                        fsize = os.path.getsize(path)
                        f = open(path, 'r+b')
                elif os.path.isdir(path):
                    f = None
                    fsize = 0
                else:
                    self.send_error(SMB_COM_OPEN_ANDX, STATUS_DATA_ERROR)
                    return
            else:
                result = 2 # did not exist and was created
                f = open(path, 'wb')
                fsize = 0
        except:
            self.send_error(SMB_COM_OPEN_ANDX, STATUS_ACCESS_DENIED)
            return


        self.packet = self._response(SMB_COM_OPEN_ANDX)
        fid = self.generate_file_id()
        self.packet.body['Fid'] = fid
        self.authenticated_connections[self.uid][self.tid]['files'][fid] = {'file' :f,
                                                                            'path' : path,
                                                                            'dir' : os.path.isdir(path)}

        if extended:
            self.packet.body['GrantedAccess'] = 0x0002 # SMB_DA_ACCESS_READ_WRITE
            self.packet.body['Action'] = result
            self.packet.body['DataSize'] = fsize
            self.packet.body['FileAttributes'] = SMB_FILE_ATTRIBUTE_NORMAL if os.path.isfile(path) else SMB_FILE_ATTRIBUTE_DIRECTORY
            self.packet.body['LastWriteTimeInSeconds'] = int(os.stat(path).st_mtime)

        self.send()


    # Complete except: take into account maxbuffersize for client
    def smb_read_andx(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_READ_ANDX, STATUS_SMB_BAD_FID)
            return

        offset      = self.packet.body['Offset']
        offset_high = self.packet.body['OffsetHigh']

        if offset_high == '':
            offset_high = 0
        else:
            offset_high = unpack('<L', offset_high)[0]

        maxcount    = self.packet.body['MaxCount']
        offset += offset_high << 32

        # Get file object
        f = self._info_from_fid(fid)['file']

        try:
            f.seek(offset)
            data = f.read(maxcount)
        except:
            self.send_error(SMB_COM_READ_ANDX, STATUS_DATA_ERROR)
            return

        if data == '':
            self.send_error(SMB_COM_READ_ANDX, STATUS_END_OF_FILE)
            return

        self.packet = self._response(SMB_COM_READ_ANDX)
        self.packet.body['Remaining'] = 0xffff
        self.packet.body['Data'] = data
        self.send()


    # Complete but only 64bit version (wordcount = 14)
    def smb_write_andx(self):
        flush_sync = True # Default should be False
                          # We set to True to make testing easy

        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_WRITE_ANDX, STATUS_SMB_BAD_FID)
            return

        offset      = self.packet.body['Offset']
        offset_high = self.packet.body['OffsetHigh']

        if self.packet.body['WriteMode'] & WRITETHROUGH_MODE:
            flush_sync = True

        f = self._info_from_fid(fid)['file']

        count = len(self.packet.body['Data'])
        offset += offset_high << 32

        if count > 0: # 0-byte write requests are valid and must be honored
            try:
                f.seek(offset)
                f.write(self.packet.body['Data'])
                if flush_sync:
                    f.flush()
                    os.fsync(f.fileno())
            except:
                self.send_error(SMB_COM_WRITE_ANDX, STATUS_DATA_ERROR)
                return

        self.packet = self._response(SMB_COM_WRITE_ANDX)
        self.packet.body['Count'] = count
        self.packet.body['Remaining'] = 0xffff
        self.send()

    # Complete
    def smb_read(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_READ, STATUS_INVALID_HANDLE)
            return

        f = self._info_from_fid(fid)['file']
        to_read = self.packet.body['CountOfBytesToRead']
        offset = self.packet.body['Offset']

        try:
            f.seek(offset)
            data = f.read(to_read)
        except:
            self.send_error(SMB_COM_READ, STATUS_DATA_ERROR)
            return

        if data == '':
            self.send_error(SMB_COM_READ, STATUS_END_OF_FILE)

        self.packet = self._response(SMB_COM_READ)
        self.packet.body['CountOfBytesReturned'] = len(data)
        self.packet.body['CountOfBytesRead'] = len(data)
        self.packet.body['Bytes'] = data
        self.send()


    # Complete
    def smb_write(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_WRITE, STATUS_INVALID_HANDLE)
            return

        f, path = (self._info_from_fid(fid)['file'],
                   self._info_from_fid(fid)['path'])

        to_write = self.packet.body['Count']
        offset = self.packet.body['Offset']
        fsize = os.path.getsize(path)

        try:
            if offset <= fsize:
                if to_write == 0: # Truncate then seek
                    f.truncate(offset)
                f.seek(offset)
            elif offset > fsize:
                f.seek(0, 2) # End of file
                f.write('\0'*(offset-fsize))
            f.write(self.packet.body['Data'])
        except:
            self.send_error(SMB_COM_WRITE, STATUS_DATA_ERROR)
            return

        self.packet = self._response(SMB_COM_WRITE)
        self.packet.body['Count'] = to_write
        self.send()


    def smb_nt_create_andx(self):
        root_fid = self.packet.body['RootDirectoryFid']
        disposition = self.packet.body['CreateDisposition']
        create_options = self.packet.body['CreateOptions']
        filename = self.packet.body['Name']
        is_dir = False

        filename = fix_universal_path(filename)
        if create_options & FILE_DIRECTORY_FILE:
            is_dir = True

        # Determine path based on filename + root_fid if any
        if root_fid:
            if not self._valid_fid(root_fid):
                self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_INVALID_HANDLE)
                return
            path = self._info_from_fid(root_fid)['path']
        else:
            path = self._path_from_tid()

        # The path may perfectly be None, especially if the caller requires IPC$
        # The caller may connect() to IPC$ and creates() \svcsrv for example when
        # he wants to fetch the share listing or informations on files etc.
        # We do not handle for the moment these cases.
        if path is None:
            self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_OBJECT_NAME_NOT_FOUND)
            return

        path = os.path.join(*([path] + filename))

        # Determine final path based on parent flag
        if self.packet.body['Flags'] & NT_CREATE_OPEN_TARGET_DIR:
            is_dir = True
            # We need to open the parent directory of target
            path = os.path.abspath(os.path.join(path, '..'))

        if os.path.isdir(path):
            is_dir = True

        # Decide what mode to open file in, page 375/MS-CIFS
        # If is_dir = True, disposition MUST be set to FILE_CREATE, FILE_OPEN, or FILE_OPEN_IF
        try:
            if disposition == FILE_SUPERSEDE:
                if os.path.exists(path):
                    f = open(path, 'r+b')
                else:
                    f = open(path, 'wb')
            elif disposition == FILE_OPEN:
                if not os.path.exists(path):
                    self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_OBJECT_NAME_NOT_FOUND)
                    return
                if not is_dir:
                    f = open(path, 'r+b')
                else:
                    f = None
            elif disposition == FILE_CREATE:
                if os.path.exists(path):
                    self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_ACCESS_DENIED)
                    return
                if not is_dir:
                    f = open(path, 'wb')
                else:
                    f = None
                    os.mkdir(path)
            elif disposition == FILE_OPEN_IF:
                if os.path.exists(path):
                    if not is_dir:
                        f = open(path, 'r+b')
                    else:
                        f = None
                else:
                    if not is_dir:
                        f = open(path, 'wb')
                    else:
                        f = None
                        os.mkdir(path)
            elif disposition == FILE_OVERWRITE:
                if os.path.exists(path):
                    f = open(path, 'wb')
                else:
                    self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_ACCESS_DENIED)
                    return
            elif disposition == FILE_OVERWRITE_IF:
                f = open(path, 'wb')
        except:
            self.send_error(SMB_COM_NT_CREATE_ANDX, STATUS_OBJECT_NAME_NOT_FOUND)
            return


        self.packet = self._response(SMB_COM_NT_CREATE_ANDX)
        self.packet.body['CreateAction'] = disposition
        self.packet.body['EndOfFile'] = os.path.getsize(path) if not is_dir else 0
        self.packet.body['ExtFileAttributes'] = ATTR_DIRECTORY if is_dir else ATTR_NORMAL
        self.packet.body['Directory'] = 1 if is_dir else 0
        fid = self.generate_file_id()
        self.packet.body['Fid'] = fid

        self.authenticated_connections[self.uid][self.tid]['files'][fid] = {'file': f,
                                                                            'path': path,
                                                                            'dir' : is_dir}
        self.send()


    # Complete
    def smb_close(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_CLOSE, STATUS_INVALID_HANDLE)
            return

        f = self._info_from_fid(fid)

        if not f['dir']:
            f['file'].close()

        del self.authenticated_connections[self.uid][self.tid]['files'][fid]

        self.packet = self._response(SMB_COM_CLOSE)
        self.send()

    # Complete except 8.3 filenames
    # Special search attributes are not supported (delete applies to all files)
    # Wildcards in filename are not supported
    def smb_delete(self):
        path = self._path_from_tid()
        filename = self.packet.body['FileName']
        filename = fix_universal_path(filename)
        path = os.path.join(*([path] + filename))

        if not os.path.exists(path) or not os.path.isfile(path):
            self.send_error(SMB_COM_DELETE, STATUS_NO_SUCH_FILE)
            return

        try:
            os.remove(path)
        except:
            self.send_error(SMB_COM_DELETE, STATUS_ACCESS_DENIED)
            return

        self.packet = self._response(SMB_COM_DELETE)
        self.send()


    # Acknowledged but times and dates are not set as file attributes
    def smb_set_information2(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_SET_INFORMATION2, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_SET_INFORMATION2)
        self.send()


    def _query_info_levels(self, info_level, path, filename):
        """
        Crafts the appropriate info_level structure and sends a TRANS2 response.

        Both _trans2_query_path_information and _trans2_query_file_information
        make use of this method.
        """

        # Only support NT LANMAN info levels
        if info_level < 0x101:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_NOT_SUPPORTED)
            return

        closure_values = [None, False] # smb_info, error

        # info_level dispatchers
        def query_file_basic_info():
            closure_values[0] = SMBQueryFileBasicEntry()
            closure_values[0]['ExtFileAttributes'] = ATTR_NORMAL if os.path.isfile(path) else ATTR_DIRECTORY

        def query_file_standard_info():
            closure_values[0] = SMBQueryFileStandardEntry()
            closure_values[0]['AllocationSize'] = os.path.getsize(path) if os.path.isfile(path) else 0
            closure_values[0]['EndOfFile'] = os.path.getsize(path) if os.path.isfile(path) else 0
            closure_values[0]['NumberOfLinks'] = os.stat(path).st_nlink
            closure_values[0]['Directory'] = 1 if os.path.isdir(path) else 0

        def query_file_ea_info():
            closure_values[0] = SMBQueryFileEAEntry()

        def query_file_name_info():
            closure_values[0] = SMBQueryFileNameEntry()
            closure_values[0]['FileName'] = filename

        def query_file_all_info():
            closure_values[0] = SMBQueryFileAllEntry()
            closure_values[0]['ExtFileAttributes'] = ATTR_NORMAL if os.path.isfile(path) else ATTR_DIRECTORY
            closure_values[0]['AllocationSize'] = os.path.getsize(path) if os.path.isfile(path) else 0
            closure_values[0]['EndOfFile'] = os.path.getsize(path) if os.path.isfile(path) else 0
            closure_values[0]['NumberOfLinks'] = os.stat(path).st_nlink
            closure_values[0]['Directory'] = 0 if os.path.isfile(path) else 1
            closure_values[0]['FileName'] = filename

        def query_file_alt_name_info():
            closure_values[0] = SMBQueryFileAltNameEntry()

        def query_file_stream_info():
            closure_values[0] = SMBQueryFileStreamEntry()
            closure_values[0]['StreamSize'] = os.path.getsize(path) if os.path.isfile(path) else 0
            closure_values[0]['StreamName'] = u'::$DATA'

        def query_file_compression_info():
            closure_values[0] = SMBQueryFileCompressionEntry()

        def info_error():
            self.send_error(SMB_COM_TRANSACTION2, STATUS_INVALID_SMB)
            closure_values[1] = True

        try:
            # Proceed with dispatch
            {
                SMB_QUERY_FILE_BASIC_INFO:       query_file_basic_info,
                SMB_QUERY_FILE_STANDARD_INFO:    query_file_standard_info,
                SMB_QUERY_FILE_EA_INFO:          query_file_ea_info,
                SMB_QUERY_FILE_NAME_INFO:        query_file_name_info,
                SMB_QUERY_FILE_ALL_INFO:         query_file_all_info,
                SMB_QUERY_FILE_ALT_NAME_INFO:    query_file_alt_name_info,
                SMB_QUERY_FILE_STREAM_INFO2:     query_file_stream_info,
                SMB_QUERY_FILE_COMPRESSION_INFO: query_file_compression_info,
                }.get(info_level, info_error)()
        except:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_DATA_ERROR)
            closure_values[1] = True

        # No error
        if not closure_values[1]:
            self.packet = self._response(SMB_COM_TRANSACTION2)
            self.packet.body['Parameters'] = '\x00\x00'
            self.packet.body['Data'] = closure_values[0].pack()
            self.send()

    def _trans2_query_file_information(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Parameters'][0:2])[0]
        info_level = unpack("<H", self.packet.body['Parameters'][2:])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION2, STATUS_INVALID_HANDLE)
            return

        # Build and return response
        path = self._info_from_fid(fid)['path']
        filename = path.split(os.sep)[-1]
        self._query_info_levels(info_level, path, filename)


    def _trans2_query_path_information(self, response=True):
        if not response:
            return

        info_level = unpack('<H', self.packet.body['Parameters'][0:2])[0]

        path = self._path_from_tid()
        filename = extractNullTerminatedString(self.packet.body['Parameters'][6:], is_unicode=self.is_unicode)[0][:-1]
        filename = fix_universal_path(filename)
        path = os.path.join(*([path] + filename))

        if not os.path.exists(path):
            self.send_error(SMB_COM_TRANSACTION2, STATUS_NO_SUCH_FILE)
            return

        self._query_info_levels(info_level, path, filename[-1] if len(filename) > 0 else u'')


    # Only supports * wildcards or set filenames
    # Search attributes are not taken into account except for directories which
    # is probably what we want to do anyways for unix
    def _trans2_find_first2(self, response=True):
        if not response:
            return

        parameters = Trans2FindFirst2RequestPar(self.packet.body['Parameters'], is_unicode=self.is_unicode)

        # Only support this info level request
        if parameters['InformationLevel'] != SMB_FIND_FILE_BOTH_DIRECTORY_INFO:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_NOT_SUPPORTED)
            return

        # Search string
        filename = parameters['FileName']
        self.packet = self._response(SMB_COM_TRANSACTION2)
        path = self._path_from_tid()
        filename = fix_universal_path(filename)
        path = os.path.join(*([path] + filename))

        import glob
        filelist = glob.glob(path)

        if sum(map(lambda x: parameters['SearchAttributes'] & x,
                   (SMB_SEARCH_ATTRIBUTE_HIDDEN,
                    SMB_SEARCH_ATTRIBUTE_READONLY,
                    SMB_SEARCH_ATTRIBUTE_SYSTEM))):
            filelist = []

        if not parameters['SearchAttributes'] & SMB_FILE_ATTRIBUTE_DIRECTORY or (
            parameters['SearchStorageType'] == FILE_NON_DIRECTORY_FILE):
            # Remove directories from list
            filelist = filter(os.path.isfile, filelist)

        elif parameters['SearchStorageType'] == FILE_DIRECTORY_FILE or (
            parameters['SearchAttributes'] & SMB_SEARCH_ATTRIBUTE_DIRECTORY):
            # Remove files from list
            filelist = filter(os.path.isdir, filelist)

        sid = self.generate_search_id()
        response_parameters = Trans2FindFirst2ResponsePar()
        response_parameters['SID'] = sid
        response_parameters['SearchCount'] = len(filelist)
        response_parameters['EndOfSearch'] = 1

        self.packet.body['Parameters'] = response_parameters.pack()

        # extract the following into a new method
        def anon(x):
            info = SMBFindFileBothDirectoryEntry(is_unicode = self.is_unicode)
            info['EndOfFile'] = os.path.getsize(x) if os.path.isfile(x) else 0
            info['ExtFileAttributes'] = ATTR_DIRECTORY if os.path.isdir(x) else ATTR_NORMAL
            info['FileName'] = x.split(os.sep)[-1]
            info['NextEntryOffset'] = len(info.pack())

            return info

        res = ''
        try:
            info_list = map(anon, filelist)
            info_list[-1]['NextEntryOffset'] = 0x00000000
            for i in info_list:
                res += i.pack()
        except IndexError:
            pass

        self.packet.body['Data'] = res
        self.send()


    def _trans2_query_fs_information(self, response=True):
        if not response:
            return

        info_level = unpack('<H', self.packet.body['Parameters'][0:2])[0]
        self.packet = self._response(SMB_COM_TRANSACTION2)
        closure_values = [None, False] # smb_info, error

        # info_level dispatchers
        def info_allocation():
            # Let's fake a filesystem with approx 1TB free space
            closure_values[0] = SMBInformationAllocationEntry()
            closure_values[0]['cSectorUnit'] = 1024
            closure_values[0]['cUnit'] = 1024**2
            closure_values[0]['cUnitAvailable'] = 1024**2
            closure_values[0]['cbSector'] = 1024

        def info_volume():
            closure_values[0] = SMBInformationVolumeEntry()
            closure_values[0]['VolumeLabel'] = 'canvas'

        def query_fs_volume():
            closure_values[0] = SMBQueryFsVolumeEntry()
            closure_values[0]['VolumeLabel'] = 'canvas'

        def query_fs_size():
            # Let's fake a filesystem with approx 1TB free space
            closure_values[0] = SMBQueryFsSizeEntry()
            closure_values[0]['TotalAllocationUnits'] = 1024**2
            closure_values[0]['TotalFreeAllocationUnits'] = 1024**2
            closure_values[0]['SectorsPerAllocationUnit'] = 1024
            closure_values[0]['BytesPerSector'] = 1024

        def query_fs_device():
            closure_values[0] = SMBQueryFsDeviceEntry()
            closure_values[0]['DeviceType'] = 0x0007 # FILE_DEVICE_DISK

        def query_fs_attribute():
            closure_values[0] = SMBQueryFsAttributeEntry()
            closure_values[0]['FileSystemAttributes'] = FILE_CASE_SENSITIVE_SEARCH | FILE_CASE_PRESERVED_NAMES | FILE_UNICODE_ON_DISK
            closure_values[0]['MaxFileNameLengthInBytes'] = 256 # based on ext4
            closure_values[0]['FileSystemName'] = u'canvas'

        def info_error():
            closure_values[1] = True


        # Proceed with dispatch
        { SMB_INFO_ALLOCATION         : info_allocation,
          SMB_INFO_VOLUME             : info_volume,
          SMB_QUERY_FS_VOLUME_INFO    : query_fs_volume,
          SMB_QUERY_FS_SIZE_INFO      : query_fs_size,
          SMB_QUERY_FS_DEVICE_INFO    : query_fs_device,
          SMB_QUERY_FS_ATTRIBUTE_INFO : query_fs_attribute,
          }.get(info_level, info_error)()

        if closure_values[1]:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_INVALID_SMB)
            return

        self.packet.body['Data'] = closure_values[0].pack()
        self.send()


    def _trans2_create_directory(self, response=True):
        directory = extractNullTerminatedString(self.packet.body['Parameters'][4:], is_unicode=self.is_unicode)[0]
        directory = directory.split(u'\0')[0]
        path = self._path_from_tid()
        path = os.path.join(*([path] + directory))

        if os.path.exists(path):
            self.send_error(SMB_COM_TRANSACTION2, STATUS_OBJECT_NAME_COLLISION)
            return

        try:
            os.mkdir(path)
        except:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_ACCESS_DENIED)
            return

        if not response:
            return

        self.packet = self._response(SMB_COM_TRANSACTION2)
        self.send()

    def _set_file_information(self, info_level, path):
        """
        Set file attributes according to path and info_level.
        This is used by _trans2_set_file_information and
        _trans2_set_path_information.
        """
        if info_level == SMB_INFO_SET_EAS:
            pass
        else:
            dispatcher = {
                SMB_INFO_STANDARD             : SMBSetInformationStandardEntry,
                SMB_SET_FILE_BASIC_INFO       : SMBSetFileBasicEntry,
                SMB_SET_FILE_DISPOSITION_INFO : SMBSetFileDispositionEntry,
                SMB_SET_FILE_ALLOCATION_INFO  : SMBSetFileAllocationEntry,
                SMB_SET_FILE_END_OF_FILE_INFO : SMBSetFileEndOfFileEntry,
            }

            if info_level not in dispatcher:
                self.send_error(SMB_COM_TRANSACTION2, STATUS_INVALID_SMB)
                return

            data = dispatcher[info_level](self.packet.body['Data'])
            if info_level == SMB_SET_FILE_DISPOSITION_INFO and data['DeletePending'] == 1:
                # Delete file/dir
                if os.path.isfile(path):
                    os.unlink(path)
                else:
                    os.rmdir(path)


    # Acknowledged, also can delete files
    def _trans2_set_file_information(self, response=True):
        parameters = Trans2SetFileInformationRequestPar(self.packet.body['Parameters'])
        fid = parameters['FID']
        info_level = parameters['InformationLevel']

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION2, STATUS_INVALID_HANDLE)
            return

        self._set_file_information(info_level, self._info_from_fid(fid)['path'])
        if not response:
            return

        self.packet = self._response(SMB_COM_TRANSACTION2)
        self.send()

    # Acknowledged
    def _trans2_set_path_information(self, response=True):
        parameters = Trans2SetPathInformationRequestPar(self.packet.body['Parameters'])
        info_level = parameters['InformationLevel']
        filename = fix_universal_path(parameters['FileName'])

        path = self._path_from_tid()
        path = os.path.join(*([path] + filename))
        self._set_file_information(info_level, path=path)

        if not response:
            return

        self.packet = self._response(SMB_COM_TRANSACTION2)
        self.send()


    def _trans2_open2(self, response=True):
        parameters = Trans2Open2RequestPar(self.packet.body['Parameters'])
        filename = fix_universal_path(parameters['FileName'])

        path = self._path_from_tid()
        path = os.path.join(*([path] + filename))

        extended = parameters['Flags'] & 0x0001
        file_exists_opt = parameters['OpenMode'] & 0x0003
        create_file_opt = parameters['OpenMode'] & 0x0010

        result = 1 # existed and was opened

        try:
            if create_file_opt == 0:
                if not os.path.exists(path):
                    self.send_error(SMB_COM_TRANSACTION2, STATUS_NO_SUCH_FILE)
                    return
                elif os.path.isfile(path):
                    if file_exists_opt == 0:
                        self.send_error(SMB_COM_TRANSACTION2, STATUS_ACCESS_DENIED)
                        return
                    elif file_exists_opt == 2:
                        ctime = int(os.stat(path).st_ctime)
                        f = open(path, 'r+b')
                        f.truncate(0)
                        result = 3 # existed and truncated
                        fsize = 0
                    else:
                        ctime = int(os.stat(path).st_ctime)
                        fsize = os.path.getsize(path)
                        f = open(path, 'r+b')
                elif os.path.isdir(path):
                    ctime = int(os.stat(path).st_ctime)
                    f = None
                    fsize = 0
                else:
                    self.send_error(SMB_COM_TRANSACTION2, STATUS_DATA_ERROR)
                    return
            else:
                result = 2 # did not exist and was created
                f = open(path, 'wb')
                ctime = int(time.time())
                fsize = 0
        except:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_ACCESS_DENIED)
            return

        if not response:
            return

        self.packet = self._response(SMB_COM_TRANSACTION2)
        fid = self.generate_file_id()
        self.authenticated_connections[self.uid][self.tid]['files'][fid] = {'file' :f,
                                                                            'path' : path,
                                                                            'dir' : os.path.isdir(path)}

        response_parameters = Trans2Open2ResponsePar()
        response_parameters['FID'] = fid
        response_parameters['FileAttributes'] = SMB_FILE_ATTRIBUTE_NORMAL if f else SMB_FILE_ATTRIBUTE_DIRECTORY
        response_parameters['CreationTime'] = ctime if extended else 0
        response_parameters['FileDataSize'] = fsize if extended else 0
        response_parameters['AccessMode'] = 2 if extended else 0 # read/write
        response_parameters['ActionTaken'] = result

        self.packet.body['Parameters'] = response_parameters.pack()
        self.send()



    # Double check noresponse behavior/see if it applies to errors
    def smb_transaction2(self):
        response = True
        disconnect_tid_after = False

        if self.packet.body['Flags'] & TRANS_DISCONNECT_TID:
            disconnect_tid_after = True

        if self.packet.body['Flags'] & TRANS_NO_RESPONSE:
            response = False

        # Split packets not supported for now
        if self.packet.body['ParameterCount'] != self.packet.body['TotalParameterCount'] or \
           self.packet.body['DataCount'] != self.packet.body['TotalDataCount']:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_NOT_SUPPORTED)

            if disconnect_tid_after:
                self._disconnect_tid()
            return

        setup = unpack("<H", self.packet.body['Setup'])[0]

        # Pretty much complete
        subcommands = {
            TRANS2_QUERY_FILE_INFORMATION : self._trans2_query_file_information,
            TRANS2_FIND_FIRST2            : self._trans2_find_first2,
            TRANS2_QUERY_FS_INFORMATION   : self._trans2_query_fs_information,
            TRANS2_QUERY_PATH_INFORMATION : self._trans2_query_path_information,
            TRANS2_CREATE_DIRECTORY       : self._trans2_create_directory,
            TRANS2_OPEN2                  : self._trans2_open2,
            TRANS2_SET_FILE_INFORMATION   : self._trans2_set_file_information,
            TRANS2_SET_PATH_INFORMATION   : self._trans2_set_path_information,
        }

        if setup not in subcommands:
            self.send_error(SMB_COM_TRANSACTION2, STATUS_NOT_IMPLEMENTED)
        else:
            subcommands[setup](response)

        if disconnect_tid_after:
            self._disconnect_tid()

    def _trans_set_nmpipe_state(self, response=True):
        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]
        pipestate = unpack("<H", self.packet.body['Parameters'])[0]

        if not response:
            return

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()


    def _trans_query_nmpipe_state(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        #self.packet.body['Parameters'] = 0x8000 # NMPIPE STATUS
        self.send()


    def _trans_query_nmpipe_info(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]
        level = unpack("<H", self.packet.body['Parameters'])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        if level != 1:
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_PARAMETER)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        parameters = TransQueryNMPipeInfoResponsePar(is_unicode=self.is_unicode)

        self.packet.body['Parameters'] = parameters.pack()
        self.send()


    def _trans_peek_nmpipe(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        parameters = TransPeekNMPipeResponsePar()

        self.packet.body['Parameters'] = parameters.pack()
        self.send()


    def _trans_transact_nmpipe(self, response=True):
        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]

        if not response:
            return

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()

    def _trans_read_nmpipe(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()


    def _trans_write_nmpipe(self, response=True):
        if not response:
            return

        fid = unpack("<H", self.packet.body['Setup'][2:4])[0]

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_TRANSACTION, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()


    def _trans_wait_nmpipe(self, response=True):
        if not response:
            return

        pipename = self.packet.body['Name']

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()

    def _trans_call_nmpipe(self, response=True):
        priority = unpack("<H", self.packet.body['Setup'][2:4])[0]
        # Do exchange
        if not response:
            return

        self.packet = self._response(SMB_COM_TRANSACTION)
        self.send()


    def smb_transaction(self):
        response = True
        disconnect_tid_after = False

        if self.packet.body['Flags'] & TRANS_DISCONNECT_TID:
            disconnect_tid_after = True

        if self.packet.body['Flags'] & TRANS_NO_RESPONSE:
            response = False

        # Split packets not supported for now
        if self.packet.body['ParameterCount'] != self.packet.body['TotalParameterCount'] or \
           self.packet.body['DataCount'] != self.packet.body['TotalDataCount']:
            self.send_error(SMB_COM_TRANSACTION, STATUS_NOT_SUPPORTED)

            if disconnect_tid_after:
                self._disconnect_tid()
            return

        if self.packet.body['SetupCount'] > 0:
            setup = unpack("<H", self.packet.body['Setup'])[0]
        else:
            setup = None

        subcommands = {
            TRANS_SET_NMPIPE_STATE      : self._trans_set_nmpipe_state,
            TRANS_QUERY_NMPIPE_STATE    : self._trans_query_nmpipe_state,
            TRANS_QUERY_NMPIPE_INFO     : self._trans_query_nmpipe_info,
            TRANS_PEEK_NMPIPE           : self._trans_peek_nmpipe,
            TRANS_TRANSACT_NMPIPE       : self._trans_transact_nmpipe,
            TRANS_READ_NMPIPE           : self._trans_read_nmpipe,
            TRANS_WRITE_NMPIPE          : self._trans_write_nmpipe,
            TRANS_WAIT_NMPIPE           : self._trans_wait_nmpipe,
            TRANS_CALL_NMPIPE           : self._trans_call_nmpipe,
        }

        if setup not in subcommands:
            self.send_error(SMB_COM_TRANSACTION, STATUS_NOT_IMPLEMENTED)
        else:
            subcommands[setup](response)

        if disconnect_tid_after:
            self._disconnect_tid()


    def smb_query_information(self):
        path = self._path_from_tid()
        filename = fix_universal_path(self.packet.body['FileName'])
        path = os.path.join(*([path] + filename))
        self.packet = self._response(SMB_COM_QUERY_INFORMATION)

        if not os.path.exists(path):
            self.send_error(SMB_COM_QUERY_INFORMATION, STATUS_NO_SUCH_FILE)
            return
        else:
            try:
                self.packet.body['FileSize'] = os.path.getsize(path) if os.path.isfile(path) else 0
                self.packet.body['FileAttributes'] = SMB_FILE_ATTRIBUTE_DIRECTORY if os.path.isdir(path) else SMB_FILE_ATTRIBUTE_NORMAL
                self.packet.body['LastWriteTime'] = int(os.stat(path).st_mtime)
            except:
                self.send_error(SMB_COM_QUERY_INFORMATION, STATUS_DATA_ERROR)
                return

        self.send()


    def smb_query_information2(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid):
            self.send_error(SMB_COM_QUERY_INFORMATION2, STATUS_INVALID_HANDLE)
            return

        f, path = (self._info_from_fid(fid)['file'],
                   self._info_from_fid(fid)['path'])

        try:
            fsize = os.path.getsize(path) if os.path.isfile(path) else 0
        except:
            self.send_error(SMB_COM_QUERY_INFORMATION2, STATUS_DATA_ERROR)
            return


        self.packet = self._response(SMB_COM_QUERY_INFORMATION2)

        self.packet.body['FileDataSize'] = fsize
        self.packet.body['FileAttributes'] = SMB_FILE_ATTRIBUTE_DIRECTORY if os.path.isdir(path) else SMB_FILE_ATTRIBUTE_NORMAL
        self.packet.body['CreateDate'] = unixtime_to_smb_date(os.stat(path).st_ctime)
        self.packet.body['CreateTime'] = unixtime_to_smb_time(os.stat(path).st_ctime)
        self.packet.body['LastAccessDate'] = unixtime_to_smb_date(os.stat(path).st_atime)
        self.packet.body['LastAccessTime'] = unixtime_to_smb_time(os.stat(path).st_atime)
        self.packet.body['LastWriteDate'] = unixtime_to_smb_date(os.stat(path).st_mtime)
        self.packet.body['LastWriteTime'] = unixtime_to_smb_time(os.stat(path).st_mtime)

        self.send()


    def smb_create_directory(self):
        path = self._path_from_tid()
        dirname = self.packet.body['DirectoryName']
        dirname = fix_universal_path(dirname)
        path = os.path.join(*([path] + dirname))

        try:
            os.mkdir(path)
        except:
            self.send_error(SMB_COM_CREATE_DIRECTORY, STATUS_ACCESS_DENIED)
            return

        self.packet = self._response(SMB_COM_CREATE_DIRECTORY)
        self.send()


    def smb_logoff_andx(self):
        del self.authenticated_connections[self.uid]


    def smb_delete_directory(self):
        path = self._path_from_tid()
        dirname = self.packet.body['DirectoryName']
        dirname = fix_universal_path(dirname)
        path = os.path.join(*([path] + dirname))

        try:
            os.rmdir(path)
        except OSError:
            self.send_error(SMB_COM_DELETE_DIRECTORY, STATUS_DIRECTORY_NOT_EMPTY)
            logging.debug('tried to delete non-empty directory')
        except Exception, ex:
            logging.debug('rmdir error: %s' % ex)
            self.send_error(SMB_COM_DELETE_DIRECTORY, STATUS_ACCESS_DENIED)
            return

        self.packet = self._response(SMB_COM_DELETE_DIRECTORY)
        self.send()

    def smb_check_directory(self):
        directory = self.packet.body['DirectoryName']
        directory = fix_universal_path(directory)
        path = self._path_from_tid()
        path = os.path.join(*([path] + directory))

        if not os.path.isdir(path):
            self.send_error(SMB_COM_CHECK_DIRECTORY, STATUS_OBJECT_PATH_NOT_FOUND)
            return

        self.packet = self._response(SMB_COM_CHECK_DIRECTORY)
        self.send()


    def smb_flush(self):
        fid = self.packet.body['Fid']
        if not self._valid_fid(fid) and fid != 0xffff:
            self.send_error(SMB_COM_FLUSH, STATUS_INVALID_HANDLE)
            return

        if fid == 0xffff:
        # Flush everything
            for f in self.authenticated_connections[self.uid][self.tid]['files'].values():
                if not f['dir']:
                    f['file'].flush()
                    os.fsync(f['file'].fileno())
        else:
            f = self.authenticated_connections[self.uid][self.tid]['files'][fid]
            if not f['dir']:
                f['file'].flush()
                os.fsync(f['file'].fileno())

        self.packet = self._response(SMB_COM_FLUSH)
        self.send()


    def _nt_transact_ioctl(self):
        # control_code = unpack('<L', self.packet.body['Setup'][0:4])[0]
        # fid = unpack('<H', self.packet.body['Setup'][4:6])[0]
        # isfctl = self.packet.body['Setup'][6]
        # isflags = self.packet.body['Setup'][7]
        # data = self.packet.body['NT_Trans_Data']

        # Add supported ioctls here
        self.send_error(SMB_COM_NT_TRANSACT, STATUS_NOT_IMPLEMENTED)

    def smb_nt_transact(self):
        # Secondary requests are not supported
        if self.packet.body['ParameterCount'] != self.packet.body['TotalParameterCount'] or \
           self.packet.body['DataCount'] != self.packet.body['TotalDataCount']:
            self.send_error(SMB_COM_NT_TRANSACT, STATUS_NOT_SUPPORTED)

        function = self.packet.body['Function']

        subcommands = {
            NT_TRANSACT_IOCTL     : self._nt_transact_ioctl,
        }

        if function not in subcommands:
            self.send_error(SMB_COM_NT_TRANSACT, STATUS_NOT_IMPLEMENTED)
        else:
            subcommands[function]()


    def smb_rename(self):
        old_name = self.packet.body['OldFileName']
        new_name = self.packet.body['NewFileName']

        # Search attributes (in the case of directories) are inclusive
        # instead of exclusive (as implied in the spec)
        # attrs = self.packet.body['SearchAttributes']
        path = self._path_from_tid()
        do_move = False

        old_name = fix_universal_path(old_name)
        new_name = fix_universal_path(new_name)

        old_path = os.path.join(*([path] + old_name))
        new_path = os.path.join(*([path] + new_name))

        # some sanity checks
        if not os.path.exists(old_path):
            self.send_error(SMB_COM_RENAME, STATUS_NO_SUCH_FILE)
            return

        if os.path.exists(new_path):
            if os.path.isdir(new_path):
                do_move = True
            elif os.path.isfile(new_path):
                self.send_error(SMB_COM_RENAME, STATUS_OBJECT_NAME_COLLISION)
                return

        try:
            if do_move:
                import shutil
                shutil.move(old_path, new_path)
            else:
                os.rename(old_path, new_path)
        except:
            self.send_error(SMB_COM_RENAME, STATUS_ACCESS_DENIED)
            return


        self.packet = self._response(SMB_COM_RENAME)
        self.send()

    # Acknowledged
    def smb_set_information(self):
        self.packet = self._response(SMB_COM_SET_INFORMATION)
        self.send()

    # Acknowledged
    def smb_locking_andx(self):
        fid = self.packet.body['Fid']

        if not self._valid_fid(fid):
            self.send_error(SMB_COM_LOCKING_ANDX, STATUS_INVALID_HANDLE)
            return

        self.packet = self._response(SMB_COM_LOCKING_ANDX)
        self.send()


    def smb_find_close2(self):
        sid = self.packet.body['SearchHandle']
        if not self._valid_sid(sid):
            self.send_error(SMB_COM_FIND_CLOSE2, STATUS_INVALID_HANDLE)
            return

        del self.authenticated_connections[self.uid][self.tid]['searches'][sid]
        self.packet = self._response(SMB_COM_FIND_CLOSE2)
        self.send()


    def smb_nt_cancel(self):
        # No response is required
        pass


    def not_implemented(self):
        logging.debug("[!!!!!] SMB command %d not implemented" % (self.packet.header['Command']))
        self.send_error(self.packet.header['Command'], STATUS_NOT_IMPLEMENTED)


    def main_loop(self):
        """
        Read packets and dispatch on SMB commands.
        """

        dispatch = {
            SMB_COM_CREATE_DIRECTORY   : self.smb_create_directory,
            SMB_COM_DELETE_DIRECTORY   : self.smb_delete_directory,
            SMB_COM_OPEN               : self.smb_open,
            SMB_COM_CLOSE              : self.smb_close,
            SMB_COM_READ               : self.smb_read,
            SMB_COM_WRITE              : self.smb_write,
            SMB_COM_FLUSH              : self.smb_flush,
            SMB_COM_DELETE             : self.smb_delete,
            SMB_COM_RENAME             : self.smb_rename,
            SMB_COM_CHECK_DIRECTORY    : self.smb_check_directory,
            SMB_COM_QUERY_INFORMATION  : self.smb_query_information,
            SMB_COM_SET_INFORMATION    : self.smb_set_information,
            SMB_COM_SET_INFORMATION2   : self.smb_set_information2,
            SMB_COM_QUERY_INFORMATION2 : self.smb_query_information2,
            SMB_COM_LOCKING_ANDX       : self.smb_locking_andx,
            SMB_COM_ECHO               : self.smb_echo,
            SMB_COM_OPEN_ANDX          : self.smb_open_andx,
            SMB_COM_READ_ANDX          : self.smb_read_andx,
            SMB_COM_WRITE_ANDX         : self.smb_write_andx,
            SMB_COM_TRANSACTION2       : self.smb_transaction2,
            SMB_COM_TRANSACTION        : self.smb_transaction,
            SMB_COM_FIND_CLOSE2        : self.smb_find_close2,
            SMB_COM_TREE_CONNECT_ANDX  : self.smb_tree_connect_andx,
            SMB_COM_TREE_DISCONNECT    : self.smb_tree_disconnect,
            SMB_COM_NEGOTIATE          : self.smb_negotiate,
            SMB_COM_SESSION_SETUP_ANDX : self.smb_session_setup_andx,
            SMB_COM_LOGOFF_ANDX        : self.smb_logoff_andx,
            SMB_COM_NT_TRANSACT        : self.smb_nt_transact,
            SMB_COM_NT_CREATE_ANDX     : self.smb_nt_create_andx,
            SMB_COM_NT_CANCEL          : self.smb_nt_cancel,
        }

        while (True):
            self.recv()
            # Maybe the packet could not be parsed, in which case we ignore it
            if not self.packet:
                continue

            command = self.packet.header['Command']
            # Check to see if we have a negotiation packet if not yet negotiated
            if not self.negotiated:
                if command != SMB_COM_NEGOTIATE:
                    raise SMBServerException("Client did not send us a negotiation packet. Terminating.")

            if command in (SMB_COM_INVALID, SMB_COM_NO_ANDX_COMMAND):
                self.send_error(command, STATUS_SMB_BAD_COMMAND)
                continue

            # Some notes from MS-CIFS spec:
            # With three exceptions, all SMB requests sent by the client MUST have
            # valid UIDs. The exceptions are:
            #
            # SMB_COM_NEGOTIATE
            # SMB_COM_ECHO
            # SMB_COM_SESSION_SETUP_ANDX
            #
            # Also for SMB_COM_TRANSACTION:
            # UID (2 bytes): If the transaction request is being sent as a class 2 mailslot message, this
            # field MUST have a value of 0xFFFF. The mailslot receiver MAY ignore the UID in the
            # request. In all other cases, this field MUST contain a valid UID.
            if command not in (SMB_COM_NEGOTIATE,
                               SMB_COM_ECHO,
                               SMB_COM_SESSION_SETUP_ANDX) and not self._valid_uid():
                self.send_error(command, STATUS_SMB_BAD_UID)
                continue

            # With five exceptions, all SMB requests sent by the client MUST have
            # valid TIDs. The exceptions are:
            #
            # SMB_COM_NEGOTIATE
            # SMB_COM_SESSION_SETUP_ANDX
            # SMB_COM_TREE_CONNECT
            # SMB_COM_TREE_CONNECT_ANDX
            # SMB_COM_LOGOFF_ANDX
            #
            # Also for SMB_COM_TRANSACTION:
            # TID (2 bytes): If the transaction request is being sent as a class 2 mailslot message, this
            # field MUST have a value of 0xFFFF. The mailslot receiver MAY ignore the TID in the
            # request. In all other cases, this field MUST contain a valid TID. The TID MUST refer to
            # the IPC$ share
            if command not in (SMB_COM_NEGOTIATE,
                               SMB_COM_SESSION_SETUP_ANDX,
                               SMB_COM_TREE_CONNECT,
                               SMB_COM_TREE_CONNECT_ANDX,
                               SMB_COM_LOGOFF_ANDX) and not self._valid_tid():
                self.send_error(command, STATUS_SMB_BAD_TID)
                continue
            # Proceed with dispatch
            dispatch.get(self.packet.header['Command'], self.not_implemented)()

# Very useful API.
def GetHostnameUsingSMB(target_ip, force_ascii=1):
    try:
        to = (target_ip, 445)
        s = socket.socket()
        s.connect(to)
        smb = SMBClient(s)
        smb.is_unicode = True
        smb.extended_security = False
        smb.negotiate()
    except Exception as e:
        logging.warning("GetHostNameUsingSMB() failed: %s" % str(e))
        return None
    else:
        servername = unicode(smb.servername)
        hostname = servername.lower()
        if force_ascii:
            hostname = hostname.encode('ASCII')
        return hostname
