#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  rpc.py
## Description:
##            :
## Created_On :  Mon Feb 11 2019
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import struct
import socket
import logging
import time

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct # TODO
from libs.virtualization.virtualbox.ipc import ipcGuid, ipcPayload

###
# Globals
##

WAIT_FLG_NONE      = 0
WAIT_FLG_START     = 1
WAIT_FLG_TERMINATE = 2
WAIT_FLG_STDIN     = 4
WAIT_FLG_STDOUT    = 8
WAIT_FLG_STDERR    = 16

WAIT_RESULT_NONE         = 0
WAIT_RESULT_START        = 1
WAIT_RESULT_TERMINATE    = 2
WAIT_RESULT_STATUS       = 3
WAIT_RESULT_ERROR        = 4
WAIT_RESULT_TIMEOUT      = 5
WAIT_RESULT_STDIN        = 6
WAIT_RESULT_STDOUT       = 7
WAIT_RESULT_STDERR       = 8
WAIT_RESULT_NOTSUPPORTED = 9


###
# DCONNECT - Generic RPC classes
###

class Dword(Struct):

    st = [
        ['dword0', '<L', 0 ],
    ]

    """
    Example:
    --------
    01000000
    """

    def __init__(self, d=0):
        Struct.__init__(self)
        self['dword0'] = d
        self.payload = None

    def __str__(self):
        return '[ d0: %d ]' % self.get_dword0()

    ###
    # Getters/Setters
    ###

    def get_dword0(self):
        return self['dword0']

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['dword0'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class DwordDwordDword(Struct):

    st = [
        ['dword0', '<L', 0 ],
        ['dword1', '<L', 0 ],
        ['dword2', '<L', 0 ],
    ]

    """
    Example:
    --------
    01000000
    00000100
    ffffffff
    """

    def __init__(self, d0=0,d1=0,d2=0):
        Struct.__init__(self)
        self['dword0'] = d0
        self['dword1'] = d1
        self['dword2'] = d2
        self.payload = None

    def __str__(self):
        return '[ d0: %d, d1: %d, d2: %d ]' % (self.get_dword0(), self.get_dword1(), self.get_dword2())

    ###
    # Getters/Setters
    ###

    def get_dword0(self):
        return self['dword0']

    def get_dword1(self):
        return self['dword1']

    def get_dword2(self):
        return self['dword2']

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['dword0'], self['dword1'], self['dword2'] = struct.unpack('<LLL', data[off:off+12])
            off += 12
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class Qword(Struct):

    st = [
        ['qword0', '<Q', 0],
    ]

    """
    Example:
    --------
    d13900b0ea7f0000
    """

    def __init__(self):
        Struct.__init__(self)
        self.payload = None

    def __str__(self):
        return '[ q0: %x]' % self['qword0']

    ###
    # Getters/Setters
    ###

    def get_qword0(self):
        return self['qword0']

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['qword0'] = struct.unpack('<Q', data[off:off+8])[0]
            off += 8
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class Instance(Qword):

    def get_instance(self):
        return self.get_qword0()

    def __str__(self):
        flg_str = ''
        instance = self.get_instance()
        if instance & 1:
            flg_str = ' [Flg: 1]'
        return '[ instance: 0x%x%s]' % (instance & (~1), flg_str)


class SafeString(Struct):

    st = [
        ['length', '<L', 0 ],
        ['string0', str, str('') ],
    ]

    """
    Example:
    --------
    4c000000
    7b00610031003000310034006600... # u'{a1014f27-000e-4173-81ab-ecead541ca06}'
    """

    def __init__(self, s=''):
        Struct.__init__(self)
        self['string0'] = s.encode('utf-16le')
        self['length'] = len(self['string0'])
        self.payload = None

    def __str__(self):
        return '[ string: \"%s\" ]' % str(self['string0']).decode('utf-16le')

    ###
    # Getters/Setters
    ###

    def get_string(self):
        return str(self['string0'])

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['length'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['string0'] = data[off:off+self['length']]
            off += self['length']
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


class SafeStringx4(Struct):

    st = [
        ['s0', SafeString, SafeString() ],
        ['s1', SafeString, SafeString() ],
        ['s2', SafeString, SafeString() ],
        ['s3', SafeString, SafeString() ],
    ]

    """
    Example:
    --------
    06000000
        66006f006f00
    06000000
        66006f006f00
    06000000
        62006c006100
    9a000000
        5b00320037003200320033005d00[...]
    """

    def __init__(self, s0='', s1='', s2='', s3=''):
        Struct.__init__(self)
        self['s0'] = SafeString(s=s0)
        self['s1'] = SafeString(s=s1)
        self['s2'] = SafeString(s=s2)
        self['s3'] = SafeString(s=s3)
        self.payload = None

    def __str__(self):
        return '[ string0: \"%s\", string1: \"%s\", string2: \"%s\", string3: \"%s\" ]' % (self['s0'].get_string(),
                                                                                           self['s1'].get_string(),
                                                                                           self['s2'].get_string(),
                                                                                           self['s3'].get_string())

    ###
    # Getters/Setters
    ###

    def get_string0(self):
        return self['s0']

    def get_string1(self):
        return self['s1']

    def get_string2(self):
        return self['s2']

    def get_string3(self):
        return self['s3']

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['s0'] = SafeString().deserialize(data[off:])
            off += len(self['s0'].serialize())
            self['s1'] = SafeString().deserialize(data[off:])
            off += len(self['s1'].serialize())
            self['s2'] = SafeString().deserialize(data[off:])
            off += len(self['s2'].serialize())
            self['s3'] = SafeString().deserialize(data[off:])
            off += len(self['s3'].serialize())
            return self
        except Exception as e:
            return None


class DwordSafeString(Struct):

    st = [
        ['d0', '<L', 0],
        ['length', '<L', 0 ],
        ['string0', str, str('') ],
    ]

    """
    Example:
    --------
    00000000
    06000000
    720069007000
    """

    def __init__(self, d=0, s=''):
        Struct.__init__(self)
        self['d0'] = d
        self['string0'] = s.encode('utf-16le')
        self['length'] = len(self['string0'])
        self.payload = None

    def __str__(self):
        return '[ d0: %d, string: %s ]' % (self['d0'], str(self['string0']).decode('utf-16le'))

    ###
    # Getters/Setters
    ###

    def get_dword(self):
        return str(self['d0'])

    def get_string(self):
        return str(self['string0'])

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            off = 0
            self['d0'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['length'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['string0'] = data[off:off+self['length']]
            off += self['length']
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class ArrayQwords(Struct):

    st = [
        ['nr_qwords', '<L', 0 ],
        ['unknown_byte0', '<B', 1 ],
        ['qwords', list, list([]) ],
    ]

    """
    Example:
    --------
    02000000
    01
    803000b0ea7f0000
    704b00b0ea7f0000
    """

    def __init__(self, qwords=[]):
        Struct.__init__(self)
        self['qwords'] = qwords
        self['nr_qwords'] = len(qwords)
        self.payload = None

    def __str__(self):
        L = []
        qwords = self.get_qwords()
        for i in xrange(len(qwords)):
            flg_str = ''
            if qwords[i] & 1:
                flg_str = ' [Flg: 1]'
            L += [ 'qword_%d: 0x%x%s' % (i, qwords[i], flg_str) ]
        return '[ %s ]' % (', '.join(L))

    ###
    # Getters/Setters
    ###

    def get_qwords(self):
        return self['qwords']

    def set_qwords(self, qwords):
        self['qwords'] = qwords

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<L', self['nr_qwords'])
        data += '\x01'
        data += ''.join(map(lambda x: struct.pack('<Q',x&(~1)), self['qwords']))
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['nr_qwords'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['unknown_byte0'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['qwords'] = []
            for i in xrange(self['nr_qwords']):
                self['qwords'] += [ struct.unpack('<Q', data[off:off+8])[0] ]
                off += 8
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class ArrayInstances(ArrayQwords):

    def __init__(self, instances=[]):
        ArrayQwords.__init__(self, qwords=instances)

    def get_instances(self):
        return self.get_qwords()

    def set_instances(self, instances):
        self.set_qwords(instances)

    def __str__(self):
        L = []
        instances = self.get_instances()
        for i in xrange(len(instances)):
            flg_str = ''
            if instances[i] & 1:
                flg_str = ' [Flg: 1]'
            L += [ 'instance_%d: 0x%x%s' % (i, instances[i], flg_str) ]
        return '[ %s ]' % (', '.join(L))

class QwordDword(Struct):

    st = [
        ['qword0', '<Q', 0 ],
        ['dword0', '<L', 0 ],
    ]

    """
    Example:
    --------
    610d00d4727f0000
    01000000 
    """

    def __init__(self, q=0, d=0):
        Struct.__init__(self)
        self['qword0'] = q
        self['dword0'] = d
        self.payload = None

    def __str__(self):
        return '[ q=%s, d=%s ]' % (self['qword0'], self['dword0'])

    ###
    # Getters/Setters
    ###

    def get_qword(self):
        return self['qword0']

    def get_dword(self):
        return self['dword0']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<Q',self['qword0'])
        data += struct.pack('<L',self['dword0'])
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['qword0'] = struct.unpack('<Q', data[off:off+8])[0]
            off += 8
            self['dword0'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


class QwordQword(Struct):

    st = [
        ['qword0', '<Q', 0 ],
        ['qword1', '<Q', 0 ],
    ]

    """
    Example:
    --------
    f162a699b955000001333510c17f0000
    """

    def __init__(self, q0=0, q1=0):
        Struct.__init__(self)
        self['qword0'] = q0
        self['qword1'] = q1
        self.payload = None

    def __str__(self):
        return '[ q0=%s, q1=%s ]' % (self['qword0'], self['qword1'])

    ###
    # Getters/Setters
    ###

    def get_qword0(self):
        return self['qword0']

    def get_qword1(self):
        return self['qword1']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<Q',self['qword0'])
        data += struct.pack('<Q',self['qword1'])
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['qword0'] = struct.unpack('<Q', data[off:off+8])[0]
            off += 8
            self['qword1'] = struct.unpack('<Q', data[off:off+8])[0]
            off += 8
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class ArrayBytes(Struct):

    st = [
        ['nr_bytes', '<L', 0 ],
        ['unknown_byte0', '<B', 1],
        ['bytes', list, list([]) ],
    ]

    """
    Example:
    --------
    23000000
    01
    313030302034203234203237203330203436203131382031313920313236203939390a
    """

    def __init__(self):
        Struct.__init__(self)
        self.payload = None

    def __str__(self):
        return '[ bytes: %s ]' % repr(''.join(self['bytes']))

    ###
    # Getters/Setters
    ###

    def get_bytes(self):
        return self['bytes']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<L', self['nr_bytes'])
        data += '\x01'
        data += ''.join(self['bytes'])
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['nr_bytes'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['unknown_byte0'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['bytes'] = []
            for i in xrange(self['nr_bytes']):
                self['bytes'] += [ data[off:off+1] ]
                off += 1
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


class ArrayDwords(Struct):

    st = [
        ['nr_dwords', '<L', 0 ],
        ['unknown_byte0', '<B', 1],
        ['dwords', list, list([]) ],
    ]

    """
    Example:
    --------
    02000000
    01
    05000000
    05000000
    """

    def __init__(self):
        Struct.__init__(self)
        self.payload = None

    def __str__(self):
        L = []
        for i in xrange(len(self['dwords'])):
            L += [ 'dword_%d: 0x%x' % (i, self['dwords'][i]) ]
        return '[ %s ]' % ', '.join(L)

    ###
    # Getters/Setters
    ###

    def get_dwords(self):
        return self['dwords']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<L', self['nr_dwords'])
        data += '\x01'
        data += ''.join(map(lambda x: struct.pack('<L',x), self['dwords']))
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['nr_dwords'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['unknown_byte0'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['dwords'] = []
            for i in xrange(self['nr_dwords']):
                self['dwords'] += [ struct.unpack('<L', data[off:off+4])[0] ]
                off += 4
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None

class WaitForArray_Args(Struct):

    st = [
        ['waitForSize', '<L', 0 ],
        ['timeoutMS', '<L', 0 ],
        ['unknown_byte0', '<B', 0],
        ['waitForFlags', list, list([]) ],
    ]

    """
    Example:
    --------
    04000000 # waitForSize
    f4010000 # timeoutMS
    01
        01000000  # ProcessWaitForFlag_Start
        02000000  # ProcessWaitForFlag_Terminate
        08000000  # ProcessWaitForFlag_StdOut
        10000000  # ProcessWaitForFlag_StdErr
    """

    ProcessWaitFlg = {}
    ProcessWaitFlg[WAIT_FLG_NONE]      = 'FLG_NONE'
    ProcessWaitFlg[WAIT_FLG_START]     = 'FLG_START'
    ProcessWaitFlg[WAIT_FLG_TERMINATE] = 'FLG_TERMINATE'
    ProcessWaitFlg[WAIT_FLG_STDIN]     = 'FLG_STDIN'
    ProcessWaitFlg[WAIT_FLG_STDOUT]    = 'FLG_STDOUT'
    ProcessWaitFlg[WAIT_FLG_STDERR]    = 'FLG_STDERR'

    def __init__(self, timeout=0, flags=[]):
        Struct.__init__(self)
        self['waitForSize'] = len(flags)
        self['waitForFlags'] = flags
        self['timeoutMS'] = timeout
        if self['waitForSize']:
            self['unknown_byte0'] = 1
        self.payload = None

    def __str__(self):

        L = []
        for i in xrange(len(self['waitForFlags'])):

            waitforflag = ''
            if self.ProcessWaitFlg.has_key(self['waitForFlags'][i]):
                waitforflag = self.ProcessWaitFlg[self['waitForFlags'][i]]

            L += [ '%s' % waitforflag]

        s1 = 'timeout: %d (ms)' % self['timeoutMS']
        s2 = ', '.join(L)
        s3 = 'Flags: [%s]' % s2

        return '[ %s ]' % ', '.join([s1,s3])

    ###
    # Getters/Setters
    ###

    def get_flags(self):
        return self['waitForFlags']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = struct.pack('<L', self['waitForSize'])
        data += struct.pack('<L', self['timeoutMS'])
        data += '\x01'
        data += ''.join(map(lambda x: struct.pack('<L',x), self['waitForFlags']))
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['waitForSize'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['timeoutMS'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['unknown_byte0'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['waitForFlags'] = []
            for i in xrange(self['waitForSize']):
                self['waitForFlags'] += [ struct.unpack('<L', data[off:off+4])[0] ]
                off += 4
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


###
# DCONNECT - Specific RPC classes (2/3) - Args
###

# IVirtualBox

class IVirtualBox_GetMachineStates_Args(ArrayInstances):
    pass

class IVirtualBox_FindMachine_Args(SafeString):

    def __str__(self):
        return '[ iid: \"%s\" ]' % str(self['string0']).decode('utf-16le')

# IMachine

class IMachine_LockMachine_Args(QwordDword):

    def __str__(self):
        return '[ instance: 0x%x, locktype: %d ]' % (self['qword0'], self['dword0'])

class IMachine_getProperty_Args(SafeString):

    def __str__(self):
        return '[ property: \"%s\" ]' % str(self['string0']).decode('utf-16le')

# IMachineDebugger

class IMachineDebugger_getRegister_Args(DwordSafeString):

    def __str__(self):
        return '[ cpu_id: %d, register: \"%s\" ]' % (self['d0'], str(self['string0']).decode('utf-16le'))

class IMachineDebugger_loadPlugIn_Args(SafeString):

    def __str__(self):
        return '[ name: \"%s\" ]' % str(self['string0']).decode('utf-16le')

# IKeyboard

class IKeyboard_PutScancode_Args(Dword):

    def __str__(self):
        return '[ scancode: %s ]' % self.get_dword0()

# IGuest

class IGuest_CreateSession_Args(SafeStringx4):

    def __init__(self, user='', password='', domain='', session_name=''):
        SafeStringx4.__init__(self, s0=user, s1=password, s2=domain, s3=session_name)

    def __str__(self):
        return '[ user: \"%s\", password: \"%s\", domain: \"%s\", session_name: \"%s\" ]' % (self['s0'].get_string().decode('utf-16le'),
                                                                                             self['s1'].get_string().decode('utf-16le'),
                                                                                             self['s2'].get_string().decode('utf-16le'),
                                                                                             self['s3'].get_string().decode('utf-16le'))

# IGuestProcess

class IGuestProcess_WaitForArray_Args(WaitForArray_Args):
    pass

# IGuestSession

class IGuestSession_ProcessCreate_Args(Struct):

    st = [
        ['command',         SafeString, SafeString() ],
        ['argumentsSize',   '<L', 0 ],
        ['environmentSize', '<L', 0 ],
        ['flagsSize',       '<L', 0 ],
        ['timeoutMS',       '<L', 0 ],
        ['unknown_byte0',   '<B', 0],
        ['arguments',       list, list([])],
        ['unknown_byte1',   '<B', 0],
        ['environment',     list, list([])],
        ['unknown_byte2',   '<B', 0],
        ['flags',           list, list([])],
    ]

    """
    Example:
    --------
    14000000
    2f00620069006e002f0073006c00650065007000  # command: /bin/sleep

    02000000 # argumentsSize
    00000000 # environmentSize
    01000000 # flagsSize
    ffffffff # timeoutMS
    01
        14000000
        2f00620069006e002f0073006c00650065007000 # /bin/sleep
        06000000
        320030003000 # 200

    00 <-- environment
    01 <-- flags
        01000000
    """

    def __init__(self, command='', timeout=0, arguments=[], environment=[], flags=[]):
        Struct.__init__(self)
        self['command'] = SafeString(command)
        self['timeoutMS'] = timeout
        self['argumentsSize'] = len(arguments)
        self['environmentSize'] = len(environment)
        self['flagsSize'] = len(flags)
        if self['argumentsSize']: self['unknown_byte0'] = 1
        if self['environmentSize']: self['unknown_byte1'] = 1
        if self['flagsSize']: self['unknown_byte2'] = 1
        self['arguments'] = map(lambda x: SafeString(x), arguments)
        self['environment'] = map(lambda x: SafeString(x), environment)
        self['flags'] = flags
        self.payload = None

    def __str__(self):
        args_str = ','.join(map(lambda x: '\"'+x.get_string().decode('utf-16le')+'\"', self.get_arguments()))
        flags_str = ','.join(map(lambda x: '\"'+"%d" % x+'\"', self.get_flags()))
        cmd_str = self.get_command().get_string().decode('utf-16le')
        return '[ command: \"%s\", args: [%s] flags: [%s] ]' % (cmd_str, args_str, flags_str)  

    ###
    # Getters/Setters
    ###

    def get_command(self):
        return self['command']

    def get_arguments(self):
        return self['arguments']

    def get_environment(self):
        return self['environment']

    def get_flags(self):
        return self['flags']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = self['command'].serialize()
        data += struct.pack('<L', self['argumentsSize'])
        data += struct.pack('<L', self['environmentSize'])
        data += struct.pack('<L', self['flagsSize'])
        data += struct.pack('<L', self['timeoutMS'])
        if self['argumentsSize']:
            data += '\x01'
            for arg in self['arguments']:
                data += arg.serialize()
        else:
            data += '\x00'
        if self['environmentSize']:
            data += '\x01'
            for env in self['environment']:
                data += env.serialize()
        else:
            data += '\x00'
        if self['flagsSize']:
            data += '\x01'
            for flg in self['flags']:
                data += struct.pack('<L', flg)
        else:
            data += '\x00'
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['command'] = SafeString().deserialize(data[off:])
            off += len(self['command'].serialize())
            self['argumentsSize'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['environmentSize'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['flagsSize'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['timeoutMS'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4

            # Arguments
            self['unknown_byte0'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['arguments'] = []
            off2 = 0
            if self['unknown_byte0']:
                for i in xrange(self['argumentsSize']):
                    arg = SafeString().deserialize(data[off+off2:])
                    self['arguments'].append(arg)
                    off2 += len(arg.serialize())
            off += off2

            # Environment
            self['unknown_byte1'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['environment'] = []
            off2 = 0
            if self['unknown_byte1']:
                for i in xrange(self['environmentSize']):
                    env = SafeString().deserialize(data[off+off2:])
                    self['environment'].append(env)
                    off2 += len(env.serialize())
            off += off2

            # Flags
            self['unknown_byte2'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['flags'] = []
            off2 = 0
            if self['unknown_byte2']:
                for i in xrange(self['flagsSize']):
                    flag = struct.unpack('<L', data[off+off2:off+off2+4])[0]
                    self['flags'].append(flag)
                    off2 += 4

            return self
        except Exception as e:
            return None


class IGuestSession_WaitForArray_Args(WaitForArray_Args):
    pass

class IGuestProcess_Read_Args(DwordDwordDword):

    """
    Example:
    --------
    02000000  # handle     ; stderr
    00000100
    ffffffff
    """

    def __init__(self, handle=0, size_to_read=0, timeout=0):
        DwordDwordDword.__init__(self, d0=handle, d1=size_to_read, d2=timeout)

    def __str__(self):

        handle = self.get_handle()
        if handle == 0:
            handle_str = 'stdin (0)'
        elif handle == 1:
            handle_str = 'stdout (1)'
        elif handle == 2:
            handle_str = 'stderr (2)'
        else:
            handle_str = '%d' % handle

        timeout = self.get_timeout()
        timeout_str = '%d' % timeout
        if timeout == 0xffffffff:
            timeout_str = '0x%x' % timeout

        return '[ handle: %s, size_to_read: %d, timeout: %s ]' % (handle_str, self.get_size2read(), timeout_str)

    def get_handle(self):
        return self.get_dword0()

    def get_size2read(self):
        return self.get_dword1()

    def get_timeout(self):
        return self.get_dword2()

class IGuestSession_CopyTo_Args(Struct):

    st = [
        ['source',        SafeString, SafeString() ],
        ['dest',          SafeString, SafeString() ],
        ['flagsSize',     '<L', 0 ],
        ['unknown_byte0', '<B', 0],
        ['flags',         list, list([])],
    ]

    """
    Example:
    --------

    10000000                              # source: /tmp/bla
        2f0074006d0070002f0062006c006100
    12000000                              # dest: /tmp/bla2
        2f0074006d0070002f0062006c0061003200
    00000000                              # flagsSize
    00                                    # flags
    """

    def __init__(self, source, dest, flags=[]):
        Struct.__init__(self)
        self['source'] = SafeString(source)
        self['dest'] = SafeString(dest)
        self['flagsSize'] = len(flags)
        if self['flagsSize']: self['unknown_byte0'] = 1
        self['flags'] = flags
        self.payload = None

    def __str__(self):
        flags_str = ','.join(map(lambda x: '\"'+"%d" % x+'\"', self.get_flags()))
        source_str = self.get_source().get_string()
        dest_str = self.get_dest().get_string()
        return '[ source: \"%s\", dest: \"%s\", flags: [%s] ]' % (source_str, dest_str, flags_str)  

    ###
    # Getters/Setters
    ###

    def get_source(self):
        return self['source']

    def get_dest(self):
        return self['dest']

    def get_flags(self):
        return self['flags']

    ###
    # (De)Serialization API
    ###

    def serialize(self, context=None):
        data  = self['source'].serialize()
        data += self['dest'].serialize()
        data += struct.pack('<L', self['flagsSize'])
        if self['flagsSize']:
            data += '\x01'
            for flg in self['flags']:
                data += struct.pack('<L', flg)
        else:
            data += '\x00'
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['source'] = SafeString().deserialize(data[off:])
            off += len(self['source'].serialize())
            self['dest'] = SafeString().deserialize(data[off:])
            off += len(self['dest'].serialize())
            self['flagsSize'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            # Flags
            self['unknown_byte2'] = struct.unpack('<B', data[off:off+1])[0]
            off += 1
            self['flags'] = []
            off2 = 0
            if self['unknown_byte0']:
                for i in xrange(self['flagsSize']):
                    flag = struct.unpack('<L', data[off+off2:off+off2+4])[0]
                    self['flags'].append(flag)
                    off2 += 4
            return self
        except Exception as e:
            return None

###
# DCONNECT - Specific RPC classes (3/3) - Return
###

# Session

class Session_AssignRemoteMachine_Ret(QwordQword):

    def get_imachine_ptr(self, with_flag=False):
        if with_flag:
            return self.get_qword0()
        else:
            return self.get_qword0() & (~1)

    def get_imachine_flag(self):
        return self.get_qword0() & 1

    def get_iconsole_ptr(self, with_flag=False):
        if with_flag:
            return self.get_qword1()
        else:
            return self.get_qword1() & (~1)

    def get_iconsole_flag(self):
        return self.get_qword1() & 1

    def __str__(self):
        return '[ pIMachine: 0x%x [F:%d], pIConsole: 0x%x [F:%d] ]' % (self.get_imachine_ptr(), self.get_imachine_flag(), self.get_iconsole_ptr(), self.get_iconsole_flag())

# IVirtualBox

class IVirtualBox_GetMachines_Ret(ArrayInstances):
    pass

class IVirtualBox_FindMachine_Ret(Instance):
    pass

class IVirtualBox_GetMachineStates_Ret(ArrayDwords):

    def get_states(self):
        return self.get_dwords()

    def __str__(self):
        L = []
        flags = self.get_states()
        for i in xrange(len(flags)):
            L += [ 'State_%d: 0x%x' % (i, flags[i]) ]
        return '[ %s ]' % ', '.join(L)

# IMachine

class IMachine_GetAccessible_Ret(Dword):

    def __str__(self):
        return '[ isAccessible: %s ]' % bool(self.get_dword0())

    def is_accessible(self):
        return self.get_dword0()

class IMachine_GetName_Ret(SafeString):

    def __str__(self):
        return '[ name: \"%s\" ]' % self.get_string()

class IMachine_GetId_Ret(SafeString):

    def __str__(self):
        return '[ iid: \"%s\" ]' % self.get_string()

class IMachine_getProperty_Ret(SafeString):

    def __str__(self):
        return '[ value: \"%s\" ]' % self.get_string()

# IMachineDebugger

class IMachineDebugger_getRegister_Ret(SafeString):

    def __str__(self):
        return '[ RegValue: \"%s\" ]' % self.get_string()


class IMachineDebugger_loadPlugIn_Ret(SafeString):

    def __str__(self):
        return '[ plugInName: \"%s\" ]' % self.get_string()

class IMachineDebugger_detectOS_Ret(SafeString):

    def __str__(self):
        return '[ os: \"%s\" ]' % self.get_string()

# IConsole

class IConsole_GetKeyboard_Ret(Instance):
    pass

class IConsole_GetDebugger_Ret(Instance):
    pass

class IConsole_GetGuest_Ret(Instance):
    pass

# IGuest

class IGuest_CreateSession_Ret(Instance):
    pass

# IGuestProcess

class IGuestProcess_WaitForArray_Ret(Dword):

    ProcessWaitResult = {}
    ProcessWaitResult[WAIT_RESULT_NONE]         = 'None'
    ProcessWaitResult[WAIT_RESULT_START]        = 'Start'
    ProcessWaitResult[WAIT_RESULT_TERMINATE]    = 'Terminate'
    ProcessWaitResult[WAIT_RESULT_STATUS]       = 'Status'
    ProcessWaitResult[WAIT_RESULT_ERROR]        = 'Error'
    ProcessWaitResult[WAIT_RESULT_TIMEOUT]      = 'Timeout'
    ProcessWaitResult[WAIT_RESULT_STDIN]        = 'StdIn'
    ProcessWaitResult[WAIT_RESULT_STDOUT]       = 'StdOut'
    ProcessWaitResult[WAIT_RESULT_STDERR]       = 'StdErr'
    ProcessWaitResult[WAIT_RESULT_NOTSUPPORTED] = 'NotSupported'

    def __str__(self):

        waitfor_status = '%s' % self.get_dword0()
        if self.ProcessWaitResult.has_key(self.get_dword0()):
            waitfor_status = self.ProcessWaitResult[self.get_dword0()]
        return '[ WaitForStatus: %s ]' % waitfor_status

    def get_status(self):
        return self.get_dword0()

class IGuestProcess_GetExitCode_Ret(Dword):

    def __str__(self):
        return '[ exit_code: %s ]' % self.get_dword0()

class IGuestProcess_Read_Ret(ArrayBytes):

    def __str__(self):
        return '[ data: %s ]' % repr(''.join(self['bytes']))

    def get_buffer(self):
        return ''.join(self['bytes'])

class IGuestProcess_GetPID_Ret(Dword):

    def __str__(self):
        return '[ pid: %s ]' % self.get_PID()

    def get_PID(self):
        return self.get_dword0()

# IGuestSession

class IGuestSession_ProcessCreate_Ret(Instance):
    pass

class IGuestSession_CopyTo_Ret(Instance):
    pass

class IGuestSession_WaitForArray_Ret(IGuestProcess_WaitForArray_Ret):
    pass

class IGuestSession_GetId_Ret(Dword):

    def __str__(self):
        return '[ id: %s ]' % self.get_id()

    def get_id(self):
        return self.get_dword0()
