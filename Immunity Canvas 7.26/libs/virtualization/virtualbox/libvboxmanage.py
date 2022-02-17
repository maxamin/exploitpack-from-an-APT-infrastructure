#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  libvboxmanage.py
## Description:
##            :
## Created_On :  Thu Feb  7 2019
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
import logging
import time

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct # TODO
import libs.virtualization.virtualbox.rpc as vboxrpc
import libs.virtualization.virtualbox.ipc as vboxipc
from libs.virtualization.virtualbox.ipc import ipcGuid, ipcPayload
from libs.virtualization.virtualbox.ipc import IPCM_TARGET, DCONNECT_IPC_TARGETID
from libs.virtualization.virtualbox.ipc import IVIRTUALBOX_IID_v5, IVIRTUALBOX_IID_v6
from libs.virtualization.virtualbox.ipc import VBOXSVC_IID

###
# Constants
###

# IPCM
IPCM_MSG_CLASS_REQ = (1 << 24)
IPCM_MSG_CLASS_ACK = (2 << 24)
IPCM_MSG_CLASS_PSH = (4 << 24)

# IPCM - Requests
IPCM_MSG_REQ_PING                 = (IPCM_MSG_CLASS_REQ | 1)
IPCM_MSG_REQ_FORWARD              = (IPCM_MSG_CLASS_REQ | 2)
IPCM_MSG_REQ_CLIENT_HELLO         = (IPCM_MSG_CLASS_REQ | 3)
IPCM_MSG_REQ_CLIENT_ADD_NAME      = (IPCM_MSG_CLASS_REQ | 4)
IPCM_MSG_REQ_CLIENT_DEL_NAME      = (IPCM_MSG_CLASS_REQ | 5)
IPCM_MSG_REQ_CLIENT_ADD_TARGET    = (IPCM_MSG_CLASS_REQ | 6)
IPCM_MSG_REQ_CLIENT_DEL_TARGET    = (IPCM_MSG_CLASS_REQ | 7)
IPCM_MSG_REQ_QUERY_CLIENT_BY_NAME = (IPCM_MSG_CLASS_REQ | 8)

# IPCM - Acknowledgements
IPCM_MSG_ACK_RESULT               = (IPCM_MSG_CLASS_ACK | 1)
IPCM_MSG_ACK_CLIENT_ID            = (IPCM_MSG_CLASS_ACK | 2)

# IPCM - Push messages
IPCM_MSG_PSH_CLIENT_STATE         = (IPCM_MSG_CLASS_PSH | 1)
IPCM_MSG_PSH_FORWARD              = (IPCM_MSG_CLASS_PSH | 2)

# Generic
IPC_MSG_VERSION                   = 1
IPC_HDR_SIZE                      = 24
IPCM_HDR_SIZE                     = 8
DCON_OP_HDR_SIZE                  = 8

# Dconnect major opcodes
DCON_OP_SETUP                     = 1
DCON_OP_RELEASE                   = 2
DCON_OP_INVOKE                    = 3
DCON_OP_SETUP_REPLY               = 4
DCON_OP_INVOKE_REPLY              = 5

# Dconnect minor opcodes for DCON_OP_SETUP
DCON_OP_SETUP_NEW_INST_CLASSID    = 1
DCON_OP_SETUP_NEW_INST_CONTRACTID = 2
DCON_OP_SETUP_GET_SERV_CLASSID    = 3
DCON_OP_SETUP_GET_SERV_CONTRACTID = 4
DCON_OP_SETUP_QUERY_INTERFACE     = 5

# Machine States
MACHINE_STATE_NULL                = 0
MACHINE_STATE_POWEREDOFF          = 1
MACHINE_STATE_SAVED               = 2
MACHINE_STATE_TELEPORTED          = 3
MACHINE_STATE_ABORTED             = 4
MACHINE_STATE_RUNNING             = 5

# Lock Types
LOCKTYPE_SHARED                   = 1
LOCKTYPE_WRITE                    = 2

# Generic errors
E_OK                              = 0x00000000
E_ACCESSDENIED                    = 0x80070005
E_INVALID_ARG                     = 0x80070057  # "Invalid argument value"
E_OBJECT_NOT_FOUND                = 0x80BB0001  # "Object not found!"
E_NOINTERFACE                     = 0x80004002  # "No interface"
E_FACTORY_NOT_REGISTERED          = 0x80040154  # "class not registered!"
E_FAILURE                         = 0x80004005  # "Operation failed"
E_NOT_IMPLEMENTED                 = 0x80004001  # "Not implemented"
E_INVALID_VM_STATE                = 0x80BB0002  # "Invalid VM state"

# DBGF Errors
DBGF_OS_NOT_DETCTED               = 0x80bb0003  # "Failed to detect OS"

def get_status_error_as_string(status_code):
    if status_code == E_OK:
        return 'Success'
    elif status_code == E_ACCESSDENIED:
        return 'Access Denied'
    elif status_code == E_INVALID_ARG:
        return 'Invalid argument value'
    elif status_code == E_OBJECT_NOT_FOUND:
        return 'Object not found!'
    elif status_code == E_NOINTERFACE:
        return 'No such interface'
    elif status_code == E_FACTORY_NOT_REGISTERED:
        return 'Class not registered!'
    elif status_code == E_FAILURE:
        return 'Operation failed'
    elif status_code == DBGF_OS_NOT_DETCTED:
        return 'Failed to detect OS'
    elif status_code == E_INVALID_VM_STATE:
        return 'Invalid VM state'
    elif status_code == E_NOT_IMPLEMENTED:
        return 'Not implemented'
    else:
        return 'Unknown error'

class ipcMessageHeader(Struct):

    st = [
        ['mLen', '<L', IPC_HDR_SIZE ],
        ['mVersion', '<H', IPC_MSG_VERSION ],
        ['mFlags', '<H', 0 ],
        ['mTarget', ipcGuid, ipcGuid(data='\0'*16) ],
    ]

    def __init__(self, target=None, length=IPC_HDR_SIZE):
        Struct.__init__(self)
        if target:
            self['mTarget'] = target
        self['mLen'] = length

    def __str__(self):
        v = self['mVersion']
        t = self['mTarget']
        if t == IPCM_TARGET:
            t = 'IPCM_TARGET'
        elif t == DCONNECT_IPC_TARGETID:
            t = 'DCONNECT_IPC_TARGETID'
        else:
            return str(t)
        return '[ IPC_HDR: len=%d [0x%x], ver=%d, target=%s ]' % (self['mLen'], self['mLen'], v, t)

    ###
    # Getters/Setters
    ###

    def get_version(self):
        return self['mVersion']

    def set_version(self, version):
        self['mVersion'] = version

    def get_target(self):
        return self['mTarget']

    def set_target(self, target):
        self['mTarget'] = target

    def get_length(self):
        return self['mLen']

    def set_length(self, length):
        self['mLen'] = length

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['mLen'] = struct.unpack('<L', data[off:off+4])[0]
            off += 4
            self['mVersion'] = struct.unpack('<H', data[off:off+2])[0]
            off += 2
            self['mFlags'] = struct.unpack('<H', data[off:off+2])[0]
            off += 2
            self['mTarget'] = ipcGuid(data=data[off:])
            return self
        except Exception as e:
            return None


class ipcMessage(Struct):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcPayload', ipcPayload, ipcPayload('') ],
    ]

    def __init__(self, payload=ipcPayload('')):
        Struct.__init__(self)
        self['IpcPayload'] = payload

    def __str__(self):
        return '%s [ %s ]' % (self['IpcHdr'], self.get_payload())

    ###
    # Getters/Setters
    ###

    def get_header(self):
        return self['IpcHdr']

    def get_payload(self):
        return self['IpcPayload']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        data += self['IpcPayload']
        return data

    def deserialize(self, data):
        try:
            off = 0
            self['IpcHdr'] = ipcMessageHeader().deserialize(data[off:])
            off += self['IpcHdr'].calcsize()
            self['IpcPayload'] = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


class ipcmMessageHeader(Struct):

    st = [
        ['mType', '<L', 0 ],
        ['mRequestIndex', '<L', 0 ],
    ]

    dic_type_as_str = {
        IPCM_MSG_REQ_PING: 'PING_REQ',
        IPCM_MSG_REQ_FORWARD: 'FWD_REQ',
        IPCM_MSG_REQ_CLIENT_HELLO: 'CLIENT_HELLO_REQ',
        IPCM_MSG_REQ_CLIENT_ADD_NAME: 'CLT_ADD_NAME_REQ',
        IPCM_MSG_REQ_CLIENT_DEL_NAME: 'CLT_DEL_NAME_REQ',
        IPCM_MSG_REQ_CLIENT_ADD_TARGET: 'CLT_ADD_TGT',
        IPCM_MSG_REQ_CLIENT_DEL_TARGET: 'CLT_DEL_TGT',
        IPCM_MSG_REQ_QUERY_CLIENT_BY_NAME: 'QUERY_CLT_BY_NAME',
        IPCM_MSG_ACK_RESULT: 'ACK_RESULT',
        IPCM_MSG_ACK_CLIENT_ID: 'ACK_CLT_ID',
        IPCM_MSG_PSH_CLIENT_STATE: 'PSH_CLIENT_STATE',
        IPCM_MSG_PSH_FORWARD: 'PSH_FORWARD',
    }

    def __init__(self, msg_type=0, msg_req_index=0):
        Struct.__init__(self)
        self['mType'] = msg_type
        self['mRequestIndex'] = msg_req_index

    def __str__(self):
        t = self.get_type_as_string()
        idx = self['mRequestIndex']
        return '[ IPCM_HDR: type=%s, req=%d ]' % (t, idx)

    ###
    # Getters/Setters
    ###

    def get_type(self):
        return self['mType']

    def get_type_as_string(self):

        if self.dic_type_as_str.has_key(self['mType']):
            return self.dic_type_as_str[self['mType']]
        else:
            return '%x' % self['mType']

    def set_type(self, t):
        self['mType'] = t

    def get_request_index(self):
        return self['mRequestIndex']

    def set_request_index(self, r):
        self['mRequestIndex'] = r


class ipcmMessage(Struct):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader() ],
    ]

    def __init__(self, msg_type=0, msg_req_index=0, payload=None):
        Struct.__init__(self)
        self['IpcmHdr'].set_type(msg_type)
        self['IpcmHdr'].set_request_index(msg_req_index)
        self.payload = payload

    def __str__(self):
        payload_str = ''
        if self.payload:
            if isinstance(self.payload, ipcPayload):
                payload_str = str(self.payload).encode('hex')
            else:
                payload_str = str(self.payload)
        ipcm_msg_str = '%s%s' % (self['IpcHdr'], self['IpcmHdr'])
        ipcm_msg_str += '%s' % payload_str
        return ipcm_msg_str

    ###
    # Getters/Setters
    ###

    # IPC
    def get_ipc_header(self):
        return self['IpcHdr']

    def get_ipc_length(self):
        return self.get_ipc_header().get_length()

    def set_ipc_length(self, l):
        return self.get_ipc_header().set_length(l)

    # IPCM
    def get_ipcm_header(self):
        return self['IpcmHdr']

    def get_ipcm_type(self):
        return self.get_ipcm_header().get_type()

    def get_ipcm_request_index(self):
        return self.get_ipcm_header().get_request_index()

    def get_ipcm_payload(self):
        return self.payload

    def set_ipcm_payload(self, payload):
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['IpcHdr'].set_length(IPC_HDR_SIZE + IPCM_HDR_SIZE)
        data = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['IpcHdr'] = ipcMessageHeader().deserialize(data)
            off = self['IpcHdr'].calcsize()
            self['IpcmHdr'] = ipcmMessageHeader().deserialize(data[off:])
            off += self['IpcmHdr'].calcsize()
            self.payload = ipcPayload(data[off:])
            return self
        except Exception as e:
            return None


class ipcmMessageId(ipcmMessage):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader() ],
        ['Id', ipcGuid, ipcGuid(data='\0'*16) ],
    ]

    def __init__(self, msg_type, msg_req_index, msg_id, payload=None):
        ipcmMessage.__init__(self, msg_type, msg_req_index, payload=payload)
        self['Id'] = msg_id

    ###
    # Getters/Setters
    ###

    def get_id(self):
        return self['Id']

    def set_id(self, Id):
        self['Id'] = Id

    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['IpcHdr'].set_length(IPC_HDR_SIZE + IPCM_HDR_SIZE + 16)
        data = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            ipcmMessage.deserialize(self, data)
            next_data = self.get_ipcm_payload().serialize()
            self['Id'] = ipcGuid(data=next_data[:16])
            self.payload = ipcPayload(next_data[16:])
            return self
        except Exception as e:
            return None


class ipcmMessageStr(ipcmMessage):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader() ],
        ['Str', '0s', '' ],
    ]

    def __init__(self, msg_type, msg_req_index, msg_str, payload=None):
        ipcmMessage.__init__(self, msg_type, msg_req_index, payload=payload)
        self['Str'] = msg_str

    ###
    # Getters/Setters
    ###

    def get_string(self):
        return self['Str']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        string_length = len(self['Str'])
        if self['Str'][-1] != '\0':
            string_length += 1
            self['Str'] += '\0'
        self['IpcHdr'].set_length(IPC_HDR_SIZE + IPCM_HDR_SIZE + string_length)
        data = Struct.serialize(self)
        data += self['Str']
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            ipcmMessage.deserialize(self, data)
            next_data = str(self.get_ipcm_payload())
            self['Str'] = next_data
            self.payload = None
            #idx = next_data.find('\0')
            #if idx != -1:
            #    self['IpcmPayload'] = ipcPayload(payload[idx+1:])
            return self
        except Exception as e:
            return None


class ipcmMessageDword(ipcmMessage):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader() ],
        ['d0', '<L', 0 ],
    ]

    def __init__(self, msg_type, msg_req_index, msg_d0, payload=None):
        ipcmMessage.__init__(self, msg_type, msg_req_index, payload=payload)
        self['d0'] = msg_d0

    ###
    # Getters/Setters
    ###

    def get_d0(self):
        return self['d0']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        self['IpcHdr'].set_length(IPC_HDR_SIZE + IPCM_HDR_SIZE + 4)
        data = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            ipcmMessage.deserialize(self, data)
            next_data = str(self.get_ipcm_payload())
            self['d0'] = struct.unpack('<L', next_data[:4])[0]
            self.payload = ipcPayload(next_data[4:])
            return self
        except Exception as e:
            return None


###
# IPCM classes
# No exception handling for these objects.
###


# To receive IPCM_MSG_ACK_RESULT = 0x02000001
class ipcmMessageResult(ipcmMessageDword):

    def __init__(self, request_index=0, status=0, payload=None):
        ipcmMessageDword.__init__(self, msg_type=IPCM_MSG_ACK_RESULT, msg_req_index=request_index, msg_d0=status, payload=payload)

    def __str__(self):
        original_payload = self.get_payload()
        self.set_payload(ipcPayload())
        body_str = super(ipcmMessageDword, self).__str__()
        self.set_payload(original_payload)
        payload_str = ''
        if original_payload:
            if isinstance(original_payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(original_payload).encode('hex')
            else:
                payload_str = str(original_payload)
        status_str = '[ status=0x%x ]' % self.get_status()
        return body_str + status_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_status(self):
        return self.get_d0()

    def get_payload(self):
        return self.get_ipcm_payload()

    def set_payload(self, payload):
        self.set_ipcm_payload(payload)


# To receive IPCM_MSG_ACK_CLIENT_ID = 0x02000002
class ipcmMessageClientID(ipcmMessageDword):

    def __init__(self, request_index=0, client_id=0):
        ipcmMessageDword.__init__(self, msg_type=IPCM_MSG_ACK_CLIENT_ID, msg_req_index=request_index, msg_d0=client_id)

    def __str__(self):
        s = super(ipcmMessageDword, self).__str__()
        payload_str = '[ PAYLOAD: %s ]' % str(self.payload).encode('hex') if self.payload else ''
        return s + ('[ cid=%s ]' % self.get_cid()) + payload_str

    ###
    # Getters/Setters
    ###

    def get_cid(self):
        return self.get_d0()


# To send IPCM_MSG_REQ_PING = 0x01000001
class ipcmMessagePing(ipcmMessage):

    def __init__(self, request_index=0):
        ipcmMessage.__init__(self, msg_type=IPCM_MSG_REQ_PING, msg_req_index=request_index)


# To send IPCM_MSG_REQ_CLIENT_HELLO = 0x01000003
class ipcmMessageClientHello(ipcmMessage):
    '''
    Example:
    --------
    20000000
    01000000
    ffa83c75c2c80146b1158c2944da1150
        => IPCM_TARGET

    03000001
    01000000
    '''

    def __init__(self, request_index=0):
        ipcmMessage.__init__(self, msg_type=IPCM_MSG_REQ_CLIENT_HELLO, msg_req_index=request_index)

    def __str__(self):
        s = ipcmMessage.__str__(self)
        return s


# To send IPCM_MSG_REQ_CLIENT_ADD_TARGET = 0x01000006
class ipcmMessageClientAddTarget(ipcmMessageId):

    '''
    Example:
    --------
    30000000
    01000000
    ffa83c75c2c80146b1158c2944da1150
        => IPCM_TARGET
    06000001
    02000000
    ef47ca43c8eba2479679a4703218089f
        => DCONNECT_IPC_TARGETID
    '''

    def __init__(self, request_index=0, target=ipcGuid(data='\0'*16)):
        ipcmMessageId.__init__(self, msg_type=IPCM_MSG_REQ_CLIENT_ADD_TARGET, msg_req_index=request_index, msg_id=target)

    def __str__(self):
        s = super(ipcmMessageId, self).__str__()
        payload_str = ''
        if self.get_ipcm_payload():
            payload_str = '[ PAYLOAD: %s ]' % str(self.get_ipcm_payload()).encode('hex')
        return s + ('[ id=%s ]' % self.get_id()) + payload_str


# To send IPCM_MSG_REQ_QUERY_CLIENT_BY_NAME = 0x01000008
class ipcmMessageQueryClientByName(ipcmMessageStr):
    '''
    Example:
    --------
    2e000000
    01000000
    ffa83c75c2c80146b1158c2944da1150
        => IPCM_TARGET

    08000001
    03000000
    56426f785356432d362e302e3200  'VBoxSVC-6.0.2'
    '''

    def __init__(self, request_index=0, client_name='VBoxSVC-6.0.2'):
        ipcmMessageStr.__init__(self, msg_type=IPCM_MSG_REQ_QUERY_CLIENT_BY_NAME, msg_req_index=request_index, msg_str=client_name)

    def __str__(self):
        s = super(ipcmMessageStr, self).__str__()
        payload_str = '[ PAYLOAD: %s ]' % str(self.payload).encode('hex') if self.payload else ''
        return s + ('[ name=%s ]' % repr(self.get_string())) + payload_str


# To send IPCM_MSG_REQ_FORWARD = 0x01000002
class ipcmMessageReqForward(ipcmMessage):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader(msg_type=IPCM_MSG_REQ_FORWARD) ],
        ['ClientId', '<L', 0],
        ['IpcHdr2', ipcMessageHeader, ipcMessageHeader(target=DCONNECT_IPC_TARGETID) ],
    ]

    '''
    Example:
    --------

    IPC_HDR:
        64000000
        01000000
        ffa83c75c2c80146b1158c2944da1150
            => IPCM_TARGET

    IPCM_HDR:
        02000001
        04000000

    Cid:
    02000000

    IPC_HDR2:
        40000000
        01000000
        ef47ca43c8eba2479679a4703218089f
            => DCONNECT_IPC_TARGETID

    DCONNECT_HDR:
    01
    01
    0000
    01000000

    DCONNECT_ARGS:
    3f16a0d054e25b4ea1f2011cf991c38d
    f2a4a7b1b9471e4a82b207ccd5323c3f
    '''

    def __init__(self, request_index=0, client_id=0, ipcm_target=ipcGuid(data='\0'*16), payload=None):
        ipcmMessage.__init__(self, msg_type=IPCM_MSG_REQ_FORWARD, msg_req_index=request_index, payload=payload)
        self['ClientId'] = client_id
        self['IpcHdr2'] = ipcMessageHeader(target=ipcm_target)

    def __str__(self):
        original_payload = self.payload
        self.payload = ipcPayload('')
        body_str = ipcmMessage.__str__(self)
        self.payload = original_payload
        payload_str = ''
        if self.payload:
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.payload).encode('hex')
            else:
                payload_str = str(self.payload)
        cid_str = '[ Cid: %s ]' % self['ClientId']
        L  = []
        L += [ body_str ]
        L += [ cid_str ]
        L += [ str(self['IpcHdr2']) ]
        L += [ payload_str ]
        return ''.join(L)

    ###
    # Getters/Setters
    ###

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        self.payload = payload

    def get_ipc_header(self):
        return self['IpcHdr']

    def get_inner_ipc_header(self):
        return self['IpcHdr2']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        l1 = IPC_HDR_SIZE + IPCM_HDR_SIZE + 4 + IPC_HDR_SIZE
        if self.payload:
            l1 += len(self.payload)
        self.set_ipc_length(l1)
        l2 = IPC_HDR_SIZE
        if self.payload:
            l2 += len(self.payload)
        self['IpcHdr2'].set_length(l2)
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            ipcmMessage.deserialize(self, data=data)
            # next_layer starts after the IPCM header
            next_layer = str(self.get_ipcm_payload())
            off = 0
            self['ClientId'] = struct.unpack('<L', next_layer[off:off+4])[0]
            off += 4
            self['IpcHdr2'] = ipcMessageHeader().deserialize(next_layer[off:])
            off += self['IpcHdr2'].calcsize()
            self.payload = ipcPayload(next_layer[off:])
            return self
        except Exception as e:
            return None


# To send IPCM_MSG_PSH_FORWARD = 0x04000002
# Note: Exactly the same message as ipcmMessageReqForward but used in a different
#       context.
class ipcmMessagePushForward(ipcmMessageReqForward):

    st = [
        ['IpcHdr', ipcMessageHeader, ipcMessageHeader(target=IPCM_TARGET) ],
        ['IpcmHdr', ipcmMessageHeader, ipcmMessageHeader(msg_type=IPCM_MSG_PSH_FORWARD) ],
        ['ClientId', '<L', 0],
        ['IpcHdr2', ipcMessageHeader, ipcMessageHeader(target=DCONNECT_IPC_TARGETID) ],
    ]

    def __init__(self, request_index=0, client_id=0, ipcm_target=ipcGuid(data='\0'*16), payload=None):
        ipcmMessageReqForward.__init__(self, request_index=request_index, client_id=client_id, ipcm_target=ipcm_target, payload=payload)
        self['IpcmHdr'].set_type(IPCM_MSG_PSH_FORWARD)


    '''
    Example:
    --------

    IPC_HDR:
        50000000
        01000000
        ffa83c75c2c80146b1158c2944da1150
            => IPCM_TARGET

    IPCM_HDR:
        02000004
        fb66ed00

    Cid:
    02000000

    IPC_HDR2:
        2c000000
        01000000
        ef47ca43c8eba2479679a4703218089f
            => DCONNECT_IPC_TARGETID

    -- PAYLOAD --

    DCONNECT_HDR:
    04              DCON_OP_SETUP_REPLY
    00
    0000

    DCONNECT_ARGS:
    03                  ???
    906000b0ea7f0000    (instance)
    00000000            (status)
    '''


###
# DCONNECT_IPC - Header and Body
###


class DConnectOpHeader(Struct):

    st = [
        ['opcode_major', '<B', DCON_OP_SETUP ],
        ['opcode_minor', '<B', DCON_OP_SETUP_NEW_INST_CLASSID ],
        ['flags', '<H', 0 ],
        ['request_index', '<L', 0],
    ]

    def __init__(self, opcode_major=DCON_OP_SETUP, opcode_minor=DCON_OP_SETUP_NEW_INST_CLASSID, request_index=0):
        Struct.__init__(self)
        self['opcode_major'] = opcode_major
        self['opcode_minor'] = opcode_minor
        self['request_index'] = request_index

    def __str__(self):
        return '[ DCO_HDR: maj=%s, min=%s, flags=%x, req=%d ]' % (self.get_major_as_string(), self.get_minor_as_string(), self['flags'], self['request_index'])

    ###
    # Getters/Setters
    ###

    def get_major_as_string(self):
        if self['opcode_major'] == DCON_OP_SETUP:
            return 'SETUP'
        elif self['opcode_major'] == DCON_OP_RELEASE:
            return 'RELEASE'
        elif self['opcode_major'] == DCON_OP_INVOKE:
            return 'INVOKE'
        elif self['opcode_major'] == DCON_OP_SETUP_REPLY:
            return 'SETUP_REPLY'
        elif self['opcode_major'] == DCON_OP_INVOKE_REPLY:
            return 'INVOKE_REPLY'
        else:
            return '%x' % self['opcode_major']

    def get_minor_as_string(self):
        if self['opcode_major'] != DCON_OP_SETUP and self['opcode_minor'] == 0:
            return '%d' % self['opcode_minor']
        else:
            if self['opcode_minor'] == DCON_OP_SETUP_NEW_INST_CLASSID:
                return 'NEW_INST_CLASSID'
            elif self['opcode_minor'] == DCON_OP_SETUP_NEW_INST_CONTRACTID:
                return 'NEW_INST_CONTRACTID'
            elif self['opcode_minor'] == DCON_OP_SETUP_GET_SERV_CLASSID:
                return 'GET_SERV_CLASSID'
            elif self['opcode_minor'] == DCON_OP_SETUP_GET_SERV_CONTRACTID:
                return 'GET_SERV_CONTRACTID'
            elif self['opcode_minor'] == DCON_OP_SETUP_QUERY_INTERFACE:
                return 'QUERY_INTERFACE'
            else:
                return '%x (invalid)' % self['opcode_minor']

    def get_major(self):
        return self['opcode_major']

    def get_minor(self):
        return self['opcode_minor']

    def get_request_index(self):
        return self['request_index']


class DConnectOp(Struct):

    st = [
        ['msg_fwd', ipcmMessageReqForward, ipcmMessageReqForward() ],
        ['dconnect_hdr', DConnectOpHeader, DConnectOpHeader() ],
    ]

    def __init__(self, MsgFwdObj=ipcmMessageReqForward(), opcode_major=DCON_OP_SETUP, opcode_minor=DCON_OP_SETUP_NEW_INST_CLASSID, request_index=0, payload=None):
        Struct.__init__(self)
        self['msg_fwd'] = MsgFwdObj
        self['dconnect_hdr'] = DConnectOpHeader(opcode_major=opcode_major, opcode_minor=opcode_minor, request_index=request_index)
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += self['dconnect_hdr'].calcsize()
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        payload = self.payload
        self['msg_fwd'].set_payload(None)
        s = str(self['msg_fwd'])
        self.payload = payload
        payload_str = ''
        if self.payload:
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.payload).encode('hex')
            else:
                payload_str = str(self.payload)
        return s + '%s %s' % (str(self['dconnect_hdr']), payload_str)

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        return self['msg_fwd'].get_ipcm_type()

    def get_ipcm_request_index(self):
        return self['msg_fwd'].get_ipcm_request_index()

    def get_status(self):
        return 0 # TODO.

    def get_header(self):
        return self['dconnect_hdr']

    def get_major(self):
        return self.get_header().get_major()

    def get_minor(self):
        return self.get_header().get_minor()

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        self.payload = payload

    def get_forward_msg(self):
        return self['msg_fwd']

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['msg_fwd'] = ipcmMessageReqForward().deserialize(data=data)
            next_layer = str(self['msg_fwd'].get_payload())
            self['dconnect_hdr'] = DConnectOpHeader().deserialize(data=next_layer)
            self.payload = ipcPayload(next_layer[DCON_OP_HDR_SIZE:])
            return self
        except Exception as e:
            return None


###
# DCONNECT_IPC - Setup Message(s)
###

class DConnectSetupClassID(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['iid', ipcGuid, ipcGuid(data='\0'*16) ],
        ['classid', ipcGuid, ipcGuid(data='\0'*16) ],
    ]

    def __init__(self, DConnectObj, iid=ipcGuid(data='\0'*16), classid=ipcGuid(data='\0'*16), payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['iid'] = iid
        self['classid'] = classid
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 16*2
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload('')
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        args_str = '[ iid=%s, classid=%s ]' % (self['iid'], self['classid'])
        payload_str = ''
        if self.get_payload():
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.get_payload()).encode('hex')
            else:
                payload_str = str(self.get_payload())
        return body_str + args_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_iid(self):
        return self['iid']

    def get_classid(self):
        return self['classid']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['iid'] = ipcGuid(data=next_layer)
            self['classid'] = ipcGuid(data=next_layer[16:])
            self.payload = ipcPayload(next_layer[32:])
            return self
        except Exception as e:
            return None

    def pack(self):
        data = Struct.serialize(self)
        return data


class DConnectSetupQueryInterface(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['iid', ipcGuid, ipcGuid(data='\0'*16) ],
        ['instance', '<Q', 0 ],
    ]

    def __init__(self, DConnectObj, iid=ipcGuid(data='\0'*16), instance=0, payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['iid'] = iid
        self['instance'] = instance
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 16 + 8
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload('')
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        args_str = '[ iid: %s, instance: 0x%x ]' % (self['iid'], self['instance'])
        payload_str = ''
        if self.get_payload():
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.get_payload()).encode('hex')
            else:
                payload_str = str(self.get_payload())
        return body_str + args_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_iid(self):
        return self['iid']

    def get_instance(self):
        return self['instance']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['iid'] = ipcGuid(data=next_layer)
            self['instance'] = struct.unpack('<Q', next_layer[16:24])[0]
            self.payload = ipcPayload(next_layer[24:])
            return self
        except Exception as e:
            return None


###
# DCONNECT_IPC - Release Message(s)
###


class DConnectRelease(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['instance', '<Q', 0 ],
    ]

    def __init__(self, DConnectObj, instance=0, payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['instance'] = instance
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 8
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload('')
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        args_str = '[ instance: 0x%x ]' % self['instance']
        payload_str = ''
        if self.get_payload():
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.get_payload()).encode('hex')
            else:
                payload_str = str(self.get_payload())
        return body_str + args_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_instance(self):
        return self['instance']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['instance'] = struct.unpack('<Q', next_layer[0:8])[0]
            self.payload = ipcPayload(next_layer[8:])
            return self
        except Exception as e:
            return None


###
# DCONNECT_IPC - SetupReply Message(s)
###

class DConnectSetupReply(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['instance', '<Q', 0 ],
        ['status', '<L', 0 ],
    ]

    def __init__(self, DConnectObj, instance=0, status=0, payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['instance'] = instance
        self['status'] = 0
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 8 + 4
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload(ipcPayload())
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        args_str = '[ status: 0x%x, instance: 0x%x ]' % (self['status'], self['instance'])
        payload_str = ''
        if self.get_payload():
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.get_payload()).encode('hex')
            else:
                payload_str = str(self.get_payload())
        return body_str + args_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_status(self):
        return self['status']

    def get_instance(self):
        return self['instance']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['instance'] = struct.unpack('<Q', next_layer[0:8])[0]
            self['status'] = struct.unpack('<L', next_layer[8:12])[0]
            self.payload = ipcPayload(next_layer[12:])
            return self
        except Exception as e:
            return None

###
# DCONNECT_IPC - Invoke Message(s)
###

class DConnectInvoke(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['instance', '<Q', 0 ],
        ['method_index', '<H', 0 ],
    ]

    def __init__(self, DConnectObj, instance=0, method_index=0, payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['instance'] = instance
        self['method_index'] = method_index
        self.payload = payload
        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 8 + 2
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload('')
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        args_str = '[ instance: 0x%x, method_idx: %d ]' % (self['instance'], self['method_index'])
        payload_str = ''
        if self.get_payload():
            if isinstance(self.get_payload(), ipcPayload):
                payload_str = '[ PAYLOAD: %s ]' % str(self.get_payload()).encode('hex')
            else:
                payload_str = str(self.get_payload())
        return body_str + args_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_dconnect_header(self):
        return self['dconnectop']

    def get_method_index(self):
        return self['method_index']

    def set_method_index(self, method_index):
        self['method_index'] = method_index

    def get_instance(self):
        return self['instance']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += self.payload.serialize()
        return data

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['instance'] = struct.unpack('<Q', next_layer[0:8])[0]
            self['method_index'] = struct.unpack('<H', next_layer[8:10])[0]
            self.payload = ipcPayload(next_layer[10:])
            return self
        except Exception as e:
            return None


###
# DCONNECT_IPC - InvokeReply Message(s)
###


class DConnectInvokeReply(Struct):

    st = [
        ['dconnectop', DConnectOp, DConnectOp() ],
        ['status', '<L', 0 ],
    ]

    def __init__(self, DConnectObj, status=0, payload=None):
        Struct.__init__(self)
        self['dconnectop'] = DConnectObj
        self['status'] = status
        self.payload = payload

        # We must patch the Length field within the ipcmMessageReqForward object
        MsgFwdObj = DConnectObj.get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        fwd_length += 4
        if payload:
            fwd_length += len(payload)
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)

    def __str__(self):
        # Temporarily remove the underlying struct's payload
        original_payload = self['dconnectop'].get_payload()
        self['dconnectop'].set_payload(ipcPayload())
        body_str = str(self['dconnectop'])
        self['dconnectop'].set_payload(original_payload)
        payload_str = ''
        if self.get_payload():
            if isinstance(self.payload, ipcPayload):
                payload_str = '[ status: 0x%x, payload: %s ]' % (self['status'], str(self.get_payload()).encode('hex'))
            else:
                payload_str = '[ status: 0x%x ]' % self['status'] + str(self.get_payload())
        return body_str + payload_str

    ###
    # Getters/Setters
    ###

    def get_ipcm_type(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_type()

    def get_ipcm_request_index(self):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        return MsgFwdObj.get_ipcm_request_index()

    def get_status(self):
        return self['status']

    def get_payload(self):
        return self.payload

    def set_payload(self, payload):
        MsgFwdObj = self['dconnectop'].get_forward_msg()
        fwd_length  = MsgFwdObj.get_inner_ipc_header().get_length()
        if self.payload:
            fwd_length -= len(self.payload.serialize())
        if payload:
            fwd_length += len(payload.serialize())
        MsgFwdObj.get_inner_ipc_header().set_length(fwd_length)
        self.payload = payload

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        if self.payload:
            data += str(self.payload.serialize())
        return data

    def deserialize(self, data):
        try:
            self['dconnectop'] = DConnectOp().deserialize(data=data)
            next_layer = str(self['dconnectop'].get_payload())
            self['status'] = struct.unpack('<L', next_layer[:4])[0]
            self.payload = ipcPayload(next_layer[4:])
            return self
        except Exception as e:
            return None


###
# libvboxmanage's main class
###

def ipc_unserialize(data, context=None):
    '''
    Function unserializing packets the most precisely possible.
    '''

    dic = {
        IPCM_MSG_REQ_PING: ipcmMessagePing,
        IPCM_MSG_REQ_CLIENT_HELLO: ipcmMessageClientHello,
        IPCM_MSG_REQ_CLIENT_ADD_TARGET: ipcmMessageClientAddTarget,
        IPCM_MSG_REQ_QUERY_CLIENT_BY_NAME: ipcmMessageQueryClientByName,
        IPCM_MSG_REQ_FORWARD: ipcmMessageReqForward,
        IPCM_MSG_ACK_RESULT: ipcmMessageResult,
        IPCM_MSG_ACK_CLIENT_ID: ipcmMessageClientID,
        IPCM_MSG_PSH_FORWARD: ipcmMessagePushForward,
    }

    if isinstance(data, ipcPayload):
        data = str(data)

    ipchdr = ipcMessageHeader()
    ipchdr.deserialize(data)

    # IPCM object
    if ipchdr.get_target() == IPCM_TARGET:
        ipcm_message = ipcmMessage().deserialize(data)

        t = ipcm_message.get_ipcm_type()
        if dic.has_key(t):
            handler = dic[t]
            #if isinstance(data, ipcPayload):
            #    data = str(data)
            msg = handler().deserialize(data)

            if isinstance(msg, ipcmMessageReqForward) or isinstance(msg, ipcmMessagePushForward):

                dco_msg = DConnectOp(msg).deserialize(data)

                # Setup
                if (dco_msg.get_major() == DCON_OP_SETUP) and (dco_msg.get_minor() == DCON_OP_SETUP_NEW_INST_CLASSID):
                    dco_msg = DConnectSetupClassID(dco_msg).deserialize(data)

                elif (dco_msg.get_major() == DCON_OP_SETUP) and (dco_msg.get_minor() == DCON_OP_SETUP_QUERY_INTERFACE):
                    dco_msg = DConnectSetupQueryInterface(dco_msg).deserialize(data)

                # Release
                elif (dco_msg.get_major() == DCON_OP_RELEASE):
                    dco_msg = DConnectRelease(dco_msg).deserialize(data)

                # SetupReply
                elif (dco_msg.get_major() == DCON_OP_SETUP_REPLY):
                    dco_msg = DConnectSetupReply(dco_msg).deserialize(data)

                # Invoke
                elif (dco_msg.get_major() == DCON_OP_INVOKE):
                    dco_msg = DConnectInvoke(dco_msg).deserialize(data)
                    if not dco_msg:
                        logging.warn('Something weird with the parsing.')
                        return dco_msg
                    args_payload = dco_msg.get_payload()
                    if args_payload and context and context.has_key('args_parser'):
                        logging.debug("Calling parser for: %s" % str(args_payload).encode('hex'))
                        parser = context['args_parser']
                        if isinstance(args_payload, ipcPayload):
                            args_payload = str(args_payload)
                        payload = parser().deserialize(args_payload)
                        if payload:
                            dco_msg.set_payload(payload)

                # InvokeReply
                elif (dco_msg.get_major() == DCON_OP_INVOKE_REPLY):
                    dco_msg = DConnectInvokeReply(dco_msg).deserialize(data)
                    if not dco_msg:
                        logging.warn('Something weird with the parsing.')
                        return dco_msg
                    args_payload = dco_msg.get_payload()
                    if args_payload and context and context.has_key('ret_parser'):
                        logging.debug("Calling parser for: %s" % str(args_payload).encode('hex'))
                        parser = context['ret_parser']
                        if isinstance(args_payload, ipcPayload):
                            args_payload = str(args_payload)
                        payload = parser().deserialize(args_payload)
                        if payload:
                            dco_msg.set_payload(payload)

                return dco_msg

            elif isinstance(msg, ipcmMessageResult):

                payload_str = msg.get_payload()
                if not payload_str:
                    return msg

                ansobj = ipc_unserialize(payload_str)
                if not ansobj:
                    logging.warn('Something weird with the parsing.')
                    return msg

                answer_payload = ansobj.get_payload()
                if answer_payload and context and context.has_key('ret_parser'):
                    logging.debug("Calling parser for: %s" % str(answer_payload).encode('hex'))
                    parser = context['ret_parser']
                    if isinstance(answer_payload, ipcPayload):
                        answer_payload = str(answer_payload)
                    payload = parser().deserialize(answer_payload)
                    if payload:
                        ansobj.set_payload(payload)

                msg.set_payload(ansobj)
                return msg

            else:
                return msg

        return ipcm_message

    # Generic object
    else:
        ipc_message = ipcMessage().deserialize(data)
        return ipc_message


# IVirtualbox classes
dic_ivirtualbox_5_2_x = {
    'GetMachines':       {'method': 13,
                          'args'  : None,
                          'ret'   : vboxrpc.IVirtualBox_GetMachines_Ret,
                         },
    'FindMachine':       {'method': 44,
                          'args'  : vboxrpc.IVirtualBox_FindMachine_Args,
                          'ret'   : vboxrpc.IVirtualBox_FindMachine_Ret,
                         },
    'GetMachineStates':  {'method': 46,
                          'args'  : vboxrpc.IVirtualBox_GetMachineStates_Args,
                          'ret'   : vboxrpc.IVirtualBox_GetMachineStates_Ret,
                         },
}

dic_ivirtualbox_6_0_x = copy.deepcopy(dic_ivirtualbox_5_2_x)
dic_ivirtualbox_6_0_x['FindMachine']['method'] = 45
dic_ivirtualbox_6_0_x['GetMachineStates']['method'] = 47

# IMachine classes
dic_imachine_5_2_x = {
    'GetAccessible': {'method': 6,
                      'args'  : None,
                      'ret'   : vboxrpc.IMachine_GetAccessible_Ret,
                     },
    'GetName':       {'method': 8,
                      'args'  : None,
                      'ret'   : vboxrpc.IMachine_GetName_Ret,
                     },
    'GetId':         {'method': 12,
                      'args'  : None,
                      'ret'   : vboxrpc.IMachine_GetId_Ret,
                     },
    'LockMachine':   {'method': 162,
                      'args'  : vboxrpc.IMachine_LockMachine_Args,
                      'ret'   : None,
                     },
    'getProperty':   {'method': 218,
                      'args'  : vboxrpc.IMachine_getProperty_Args,
                      'ret'   : vboxrpc.IMachine_getProperty_Ret,
                     },
}

dic_imachine_6_0_x = copy.deepcopy(dic_imachine_5_2_x)
dic_imachine_6_0_x['LockMachine']['method'] = 144
dic_imachine_6_0_x['getProperty']['method'] = 200

# IConsole classes
dic_iconsole_5_2_x = {
    'GetGuest':             {'method': 5,
                             'args'  : None,
                             'ret'   : vboxrpc.IConsole_GetGuest_Ret,
                            },
    'GetKeyboard':          {'method': 6,
                             'args'  : None,
                             'ret'   : None,
                            },
    'GetDebugger':          {'method': 9,
                             'args'  : None,
                             'ret'   : vboxrpc.IConsole_GetDebugger_Ret,
                            },
}

dic_iconsole_6_0_x = copy.deepcopy(dic_iconsole_5_2_x)

# IMachineDebugger classes
dic_imachinedebugger_6_0_x = {
    'readPhysicalMemory':   {'method': 58,
                             'args'  : None,
                             'ret'   : None,
                            },
    'writePhysicalMemory':  {'method': 59,
                             'args'  : None,
                             'ret'   : None,
                            },
    'readVirtualMemory':    {'method': 60,
                             'args'  : None,
                             'ret'   : None,
                            },
    'writePhysicalMemory':  {'method': 61,
                             'args'  : None,
                             'ret'   : None,
                            },
    'loadPlugIn':           {'method': 62,
                             'args'  : vboxrpc.IMachineDebugger_loadPlugIn_Args,
                             'ret'   : vboxrpc.IMachineDebugger_loadPlugIn_Ret,
                            },
    'detectOS':             {'method': 64,
                             'args'  : None,
                             'ret'   : vboxrpc.IMachineDebugger_detectOS_Ret,
                            },
    'getRegister':          {'method': 66,
                             'args'  : vboxrpc.IMachineDebugger_getRegister_Args,
                             'ret'   : vboxrpc.IMachineDebugger_getRegister_Ret,
                            },
}

dic_imachinedebugger_5_2_x = copy.deepcopy(dic_imachinedebugger_6_0_x)
dic_imachinedebugger_5_2_x['readPhysicalMemory']['method']  = 56
dic_imachinedebugger_5_2_x['writePhysicalMemory']['method'] = 57
dic_imachinedebugger_5_2_x['readVirtualMemory']['method']   = 58
dic_imachinedebugger_5_2_x['writePhysicalMemory']['method'] = 59
dic_imachinedebugger_5_2_x['loadPlugIn']['method']          = 60
dic_imachinedebugger_5_2_x['detectOS']['method']            = 62
dic_imachinedebugger_5_2_x['getRegister']['method']         = 64

# IKeyboard classes
dic_ikeyboard_6_0_x = {
    'PutScancode':          {'method': 9,
                             'args'  : vboxrpc.IKeyboard_PutScancode_Args,
                             'ret'   : None,
                            },
}

dic_ikeyboard_5_2_x = copy.deepcopy(dic_ikeyboard_6_0_x)
dic_ikeyboard_5_2_x['PutScancode']['method'] = 7

# IGuest classes

dic_iguest_6_0_x = {
    'CreateSession':        {'method': 36,
                             'args'  : vboxrpc.IGuest_CreateSession_Args,
                             'ret'   : None,
                            },
}

dic_iguest_5_2_x = copy.deepcopy(dic_iguest_6_0_x)

# IGuestSession

dic_iguestsession_6_0_x = {
    'GetId':               {'method': 6,
                             'args'  : None,
                             'ret'   : vboxrpc.IGuestSession_GetId_Ret,
                           },
    'Close':               {'method': 35,
                             'args'  : None,
                             'ret'   : None,
                           },
    'CopyTo':              {'method': 53,
                             'args'  : vboxrpc.IGuestSession_CopyTo_Args,
                             'ret'   : vboxrpc.IGuestSession_CopyTo_Ret,
                           },
    'ProcessCreate':       {'method': 68,
                             'args'  : vboxrpc.IGuestSession_ProcessCreate_Args,
                             'ret'   : vboxrpc.IGuestSession_ProcessCreate_Ret,
                           },
    'WaitForArray':        {'method': 75,
                             'args'  : vboxrpc.IGuestSession_WaitForArray_Args,
                             'ret'   : vboxrpc.IGuestSession_WaitForArray_Ret,
                            },
}

dic_iguestsession_5_2_x = copy.deepcopy(dic_iguestsession_6_0_x)
dic_iguestsession_5_2_x['GetId']['method']         = 6
dic_iguestsession_5_2_x['Close']['method']         = 29
dic_iguestsession_5_2_x['CopyTo']['method']        = 45
dic_iguestsession_5_2_x['ProcessCreate']['method'] = 57
dic_iguestsession_5_2_x['WaitForArray']['method']  = 64

# IGuestProcess

dic_iguestprocess_6_0_x = {
    'GetPID':              {'method': 9,
                             'args'  : None,
                             'ret'   : vboxrpc.IGuestProcess_GetPID_Ret,
                           },
    'GetExitCode':         {'method': 10,
                             'args'  : None,
                             'ret'   : vboxrpc.IGuestProcess_GetExitCode_Ret,
                           },
    'WaitForArray':        {'method': 20,
                             'args'  : vboxrpc.IGuestProcess_WaitForArray_Args,
                             'ret'   : vboxrpc.IGuestProcess_WaitForArray_Ret,
                           },
    'Read':                {'method': 21,
                             'args'  : vboxrpc.IGuestProcess_Read_Args,
                             'ret'   : vboxrpc.IGuestProcess_Read_Ret,
                           },
}

dic_iguestprocess_5_2_x = copy.deepcopy(dic_iguestprocess_6_0_x)
dic_iguestprocess_5_2_x['GetExitCode']['method']   = 10
dic_iguestprocess_5_2_x['WaitForArray']['method']  = 16
dic_iguestprocess_5_2_x['Read']['method']          = 17

# Final dictionary
dic_all_classes = {
    'IConsole'           : { (5,2) : dic_iconsole_5_2_x,         (6,0) : dic_iconsole_6_0_x },
    'IVirtualBox'        : { (5,2) : dic_ivirtualbox_5_2_x,      (6,0) : dic_ivirtualbox_6_0_x },
    'IMachine'           : { (5,2) : dic_imachine_5_2_x,         (6,0) : dic_imachine_6_0_x },
    'IMachineDebugger'   : { (5,2) : dic_imachinedebugger_5_2_x, (6,0) : dic_imachinedebugger_6_0_x },
    'IKeyboard'          : { (5,2) : dic_ikeyboard_5_2_x,        (6,0) : dic_ikeyboard_6_0_x },
    'IGuest'             : { (5,2) : dic_iguest_5_2_x,           (6,0) : dic_iguest_6_0_x },
    'IGuestSession'      : { (5,2) : dic_iguestsession_5_2_x,    (6,0) : dic_iguestsession_6_0_x },
    'IGuestProcess'      : { (5,2) : dic_iguestprocess_5_2_x,    (6,0) : dic_iguestprocess_6_0_x },
}

UNIX_SOCKET_NAME_TEMPLATE = '.vbox-(.*)-ipc'

class IPC_class:

    ###
    # Default (local) handlers
    ###

    def local_send_receive(self, payload):
        '''
        Local write & read of data on the socket, returns what is read.
        '''

        try:
            self.sock.sendall(payload)
            time.sleep(0.0001)
            data = self.sock.recv(4)
            dlen = struct.unpack('<L', data)[0]
            # Theoretically we would need a loop however practically it works fine.
            data += self.sock.recv(dlen-4)
        except Exception as e:
            logging.warn('Error detected: %s' % str(e))
            return None
        else:
            return data

    def local_receive(self):
        '''
        Local read of data on the socket, returns what is read. 
        '''

        try:
            data = self.sock.recv(4)
            dlen = struct.unpack('<L', data)[0]
            # Theoretically we would need a loop however practically it works fine.
            data += self.sock.recv(dlen-4)
        except Exception as e:
            return None
        else:
            return data

    def local_find_socket(self):
        '''
        Search locally for a specific unix socket.
        '''

        dir_list = os.listdir('/tmp')
        if not dir_list:
            return None

        re_exp = re.compile(UNIX_SOCKET_NAME_TEMPLATE)
        for candidate in dir_list:
            if re_exp.search(candidate):
                try:
                    candidate_fullpath = '/tmp/%s/ipcd' % candidate
                    os.stat(candidate_fullpath)
                except:
                    continue
                else:
                    return candidate_fullpath
        return None

    def local_create_connection(self, server_address):
        '''
        Creates a socket and connects to the unix path.
        Returns 0 if successfull.
        '''

        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(1)
        try:
            self.sock.connect(server_address)
            return 0, self.sock
        except socket.error as e:
            return -1, str(e)

    def local_close_connection(self):
        '''
        Closes the unix socket.
        '''
        self.sock.close()

    def local_get_vbox_version(self):
        '''
        Retrieves the VirtualBox version using a grep like search (CORE)
        '''

        candidates_files = [ "/usr/lib/virtualbox/VBoxSVC",
                             "/usr/lib/virtualbox/components/VBoxSVCM.so" ]

        for candidate in candidates_files:
            f = open(candidate)
            s = f.read()
            f.close()

            re_exp = re.compile('VBoxSVC-[0-9]+.[0-9]+.[0-9]+[_a-zA-Z]*\0')
            ret = re_exp.search(s)
            if ret:
                res = ret.group(0)
                return res


    ###
    # Initialization API
    ###


    def __init__(self):

        # Attributes
        self.sock = None
        self.server_address = None
        self.ipcm_request_index = 0
        self.dconnect_request_index = 0
        self.client_name = None
        self.client_id = 0
        self.packet_queue= []
        self.vbox_version = None

        # Set default handlers
        self.__send_receive = self.local_send_receive
        self.__receive = self.local_receive
        self.__find_socket = self.local_find_socket
        self.__create_connection = self.local_create_connection
        self.__close_connection = self.local_close_connection
        self.__get_vbox_version = self.local_get_vbox_version

    def __del__(self):
        self.close_connection()

    def get_vbox_version_by_grep(self):
        '''
        Retrieves the VirtualBox version using a grep like search (Wrapper)
        '''
        return self.__get_vbox_version()

    def parse_vbox_version(self):

        if not self.client_name:
            return

        m = re.search(r"VBoxSVC-(?P<maj>\d+).(?P<min>\d+).(?P<release>\d+)(?P<suffix>\w+)", self.client_name)
        if m:
            self.vbox_version = {}
            self.vbox_version['maj'] = int(m.group('maj'))
            self.vbox_version['min'] = int(m.group('min'))
            self.vbox_version['release'] = int(m.group('release'))
            self.vbox_version['suffix'] = m.group('suffix')
            return
        else:
            m = re.search(r"VBoxSVC-(?P<maj>\d+).(?P<min>\d+).(?P<release>\d+)", self.client_name)
            if not m:
                return
            self.vbox_version = {}
            self.vbox_version['maj'] = int(m.group('maj'))
            self.vbox_version['min'] = int(m.group('min'))
            self.vbox_version['release'] = int(m.group('release'))
            self.vbox_version['suffix'] = ''
            return

    def start(self):
        '''
        Attempts to talk with service vboxsvc.
        Returns 0 if everything is alright.
        '''

        self.server_address = self.find_socket()
        if not self.server_address:
            logging.debug('No listening daemon found, is vbox running?')
            return -1, 'No listening daemon found'

        self.client_name = self.get_vbox_version_by_grep()
        if not self.client_name:
            logging.warn('Could not found the client\'s name, a bruteforce will be necessary...')

        self.parse_vbox_version()

        logging.debug('Connecting to %s' % self.server_address)
        return self.create_connection(self.server_address)

    def set_handlers(self, handlers):
        '''
        Allows to set handlers in order to perform syscall proxying.
        '''

        if not handlers:
            return

        if handlers.has_key('find_socket') and handlers['find_socket'] is not None:
            logging.debug('Hooked find_socket() for syscall proxying')
            self.__find_socket = handlers['find_socket']

        if handlers.has_key('create_connection') and handlers['create_connection'] is not None:
            logging.debug('Hooked create_connection() for syscall proxying')
            self.__create_connection = handlers['create_connection']

        if handlers.has_key('close_connection') and handlers['close_connection'] is not None:
            logging.debug('Hooked close_connection() for syscall proxying')
            self.__close_connection = handlers['close_connection']

        if handlers.has_key('send_receive') and handlers['send_receive'] is not None:
            logging.debug('Hooked send_receive() for syscall proxying')
            self.__send_receive = handlers['send_receive']

        if handlers.has_key('receive') and handlers['receive'] is not None:
            logging.debug('Hooked receive() for syscall proxying')
            self.__receive = handlers['receive']

        if handlers.has_key('get_vbox_version') and handlers['get_vbox_version'] is not None:
            logging.debug('Hooked get_vbox_version() for syscall proxying')
            self.__get_vbox_version = handlers['get_vbox_version']


    ###
    # High level network API
    ###

    def find_socket(self):
        '''
        Search locally for a specific unix socket (WRAPPER)
        '''
        return self.__find_socket()

    def create_connection(self, server_address):
        '''
        Creates a socket and connects to the unix path (WRAPPER)
        '''
        return self.__create_connection(server_address)

    def close_connection(self):
        '''
        Closes the unix socket (WRAPPER)
        '''
        return self.__close_connection()

    def send_receive(self, ipc_msg, context=None, fix_hdr=True):
        '''
        Sends a message and return the answer.
        The method does not have object knowledge.
        '''

        logging.debug('MSG: %s' % ipc_msg)
        payload = ipc_msg.pack()

        # Let's fix the header, this might be a temporary patch
        if fix_hdr:
            l1 = struct.unpack('<L', payload[:4])[0]
            l2 = len(payload)
            if l1 != l2:
                new_payload = struct.pack('<L', l2) + payload[4:]
                payload = new_payload

        logging.debug('Sending [%d]: %s' % (len(payload), payload.encode('hex')))
        data = self.__send_receive(payload)
        if not data:
            return None

        logging.debug("Received [%d]: %s" % (len(data), data.encode('hex')))
        ans = ipc_unserialize(data, context)

        if(ans):
            logging.debug('ANS: %s' % ans)
            return ans
        else:
            logging.warn('Empty answer!')
            return None

    def receive(self, context=None):
        '''
        Pure receiving function. If not used properly, it may block.
        '''

        data = self.__receive()
        if not data:
            return None

        logging.debug("Received [%d]: %s" % (len(data), data.encode('hex')))
        ans = ipc_unserialize(data, context)

        if(ans):
            logging.debug('ANS: %s' % ans)
            return ans
        else:
            logging.warn('Empty answer!')
            return None


    ###
    # Helpers
    ###

    def get_new_ipcm_request_id(self):
        '''
        Provides an incremental ID for requests.
        '''

        self.ipcm_request_index += 1
        return self.ipcm_request_index


    def get_new_dconnect_request_id(self):
        '''
        Provides an incremental ID for requests.
        '''

        self.dconnect_request_index += 1
        return self.dconnect_request_index

    ###
    # internal API
    ###


    ########################################################

    def get_invoke_method_by_name(self, name, version=None):
        '''
        Returns the method index corresponding to the string class.method and version.
        '''
        if not version:
            version = (self.vbox_version['maj'], self.vbox_version['min'])
        try:
            classname, methodname = name.split('.')
            logging.debug('method_idx: %s' % dic_all_classes[classname][version][methodname]['method'])
            return dic_all_classes[classname][version][methodname]['method']
        except Exception as e:
            logging.error('BUG: get_invoke_method_by_name() could not find \"%s\"' % name)
            return None

    def get_iid_by_name(self, iid, version=None):
        '''
        Returns the IID object corresponding to the iid and version.
        '''
        if not version:
            version = (self.vbox_version['maj'], self.vbox_version['min'])
        try:
            logging.debug('iid: %s' % vboxipc.dic_iid_global[version][iid])
            return vboxipc.dic_iid_global[version][iid]
        except Exception as e:
            logging.error('BUG: get_iid_by_name() could not find \"%s\"' % iid)
            return None

    def add_packet(self, new_packet):
        self.packet_queue.append(new_packet)

    def del_packet(self, packet):
        self.packet_queue.remove(packet)

    def find_packet_by_ipcm_reqidx(self, ipcm_reqidx):
        for packet in self.packet_queue:
            if packet.get_ipcm_request_index() == ipcm_reqidx:
                self.del_packet(packet)
                return packet
        return None

    def display_vbox_error(self, error_code, error_msg):
        logging.error('[vbox_proto_err: %s [err:%x]' % (error_msg, error_code))
        return

    def generic_handler(self, ans, ipcm_reqidx, answer_type=IPCM_MSG_ACK_CLIENT_ID, expecting_payload=False, expecting_class=None, payload_class=None):
        '''
        Returns either:
            -err, err_msg in case of error
            0, [ client_id ] in case of IPCM_MSG_ACK_CLIENT_ID
            0, [ status1, packet2|payload ] in case of IPCM_MSG_ACK_RESULT
        '''

        try:

            # First do we have an answer?
            if not ans:
                return -2, 'Empty answer'

            ans_ipcm_type = ans.get_ipcm_type()
            ans_ipcm_reqidx = ans.get_ipcm_request_index()

            if answer_type == IPCM_MSG_ACK_CLIENT_ID and (expecting_payload or expecting_class):
                return -3, 'BUG: Expecting a payload while requesting a type %s' % answer_type

            if ans_ipcm_reqidx == ipcm_reqidx:
                if ans_ipcm_type == IPCM_MSG_ACK_RESULT and answer_type == IPCM_MSG_ACK_CLIENT_ID:
                    return -4, 'An invalid query must have been sent! [status=%x]' % ans.get_status()

            # Is the answer a correct packet?
            if ans_ipcm_type not in [ IPCM_MSG_ACK_CLIENT_ID, IPCM_MSG_ACK_RESULT] or ans_ipcm_type != answer_type or ans_ipcm_reqidx != ipcm_reqidx:
                logging.debug('Not expecting this packet (t=%d)! Adding to queue!' % ans_ipcm_type)
                self.add_packet(ans)
                new_ans = self.receive()
                return self.generic_handler(new_ans, ipcm_reqidx, answer_type=answer_type, expecting_payload=expecting_payload, expecting_class=expecting_class)

            # At this point without any payload, we can safely return
            if not expecting_payload:
                if answer_type == IPCM_MSG_ACK_CLIENT_ID:
                    return 0, [ ans.get_cid() ]
                else:
                    return 0, [ ans.get_status(), None ]

            # In case we asked for a payload, we do not continue if the status
            # was not 0
            if answer_type == IPCM_MSG_ACK_RESULT and ans.get_status():
                return 0, [ ans.get_status(), None ]

            # OK at this point we should have rule out all the possible errors
            # without any payload consideration.

            # At this point we now need to deal with the payload. The problem is
            # that depending on the protocol the payload is either within a packet
            # Two options, either it is part of the IPCM_MSG_ACK_RESULT or it must be read on the socket

            ans2 = ans.get_payload()
            if ans2:
                ans2_payload = ans2.get_payload()
                if payload_class and ans2_payload and isinstance(ans2_payload, ipcPayload):
                    answer_payload = str(ans2_payload)
                    parsed_payload = payload_class().deserialize(answer_payload)
                    if parsed_payload:
                        ans2.set_payload(parsed_payload)

            if not ans2:
                time.sleep(0)
                ctx = None
                if payload_class:
                    # We do not know yet if the payload will be a query or an answer.
                    # Indeed this protocol is weird and allows queries within the answer.
                    # This hack allows us to have a functional parsing.
                    ctx = { 'args_parser': payload_class, 'ret_parser': payload_class }
                ans2 = self.receive(context=ctx)

            if not ans2:
                return -7, 'BUG: Never received the payload'

            if not expecting_class:
                logging.debug('Not expecting any specific class, returning the packet')
                return 0, [ 0, ans2 ]
            else:
                if isinstance(ans2, expecting_class):
                    return 0, [ 0, ans2 ]
                else:
                    return -5, 'BUG: Wrong payload within the answer!'

        except Exception as e:
            logging.error('An exception occured: %s' % str(e))
            return -1, str(e)

    ########################################################

    def send_clienthello(self):
        '''
        Sends an ipcmMessageClientHello message.
        '''

        req_num = self.get_new_ipcm_request_id()
        clienthello = ipcmMessageClientHello(request_index=req_num)
        ans = self.send_receive(clienthello)

        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_CLIENT_ID)
        if ret:
            self.display_vbox_error(ret, params)
            return -1
        else:
            return 0


    def define_target(self):
        '''
        Acquire a connection to the DCONNECT service.
        '''

        req_num = self.get_new_ipcm_request_id()
        addtarget = ipcmMessageClientAddTarget(request_index=req_num,
                                               target=DCONNECT_IPC_TARGETID)
        ans = self.send_receive(addtarget)
        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT)
        if ret:
            self.display_vbox_error(ret, params)
            return -1
        else:
            return 0


    def resolve_clientname(self, name=None):
        '''
        Retrieves a clientId when the version is correct.
        Since we may do not know this version, a small bruteforce can be attempted.
        '''

        if self.client_name:
            clt_name_candidates = [ self.client_name ]
        elif name:
            clt_name_candidates = [ name ]
        else:
            clt_name_candidates = []
            for _maj in xrange(5,7,1):
                for _min in xrange(0,3):
                    for _release in xrange(0,40):
                        for _suffix in [ "", "_Ubuntu" ]:
                            name = 'VBoxSVC-%d.%d.%d%s' % (_maj, _min, _release, _suffix)
                            clt_name_candidates += [ name ]

        for i in xrange(len(clt_name_candidates)):
            candidate_version = clt_name_candidates[i]
            req_num = self.get_new_ipcm_request_id()
            queryclient = ipcmMessageQueryClientByName(request_index=req_num,
                                                       client_name=candidate_version)
            ans = self.send_receive(queryclient)
            ret, params = self.generic_handler(ans,
                                               req_num,
                                               answer_type=IPCM_MSG_ACK_CLIENT_ID)

            if ret:
                self.display_vbox_error(ret, params)
                return -1

            else:
                self.client_name = candidate_version
                self.client_id = params[0]
                logging.debug('Found version %s and got cid: %s' % (self.client_name.rstrip('\0'), self.client_id))
                return 0

        return -2


    def dconnect_setup_newinstclassid(self, iid, classid=VBOXSVC_IID, cid=0):

        if not cid:
            cid = self.client_id

        req_num = self.get_new_ipcm_request_id()
        fwd = ipcmMessageReqForward(request_index=req_num,
                                    client_id=cid,
                                    ipcm_target=DCONNECT_IPC_TARGETID)

        decoobj = DConnectOp(fwd, request_index=self.get_new_dconnect_request_id())
        setupclassidobj = DConnectSetupClassID(decoobj, iid=iid, classid=classid)

        ans = self.send_receive(setupclassidobj)
        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT,
                                           expecting_payload=True,
                                           expecting_class=DConnectSetupReply)
        if ret:
            self.display_vbox_error(ret, params)
            return -1, None

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_setup_newinstclassid() failed: %s [err:0x%x]' % (get_status_error_as_string(status1), status1))
            return -2, None

        if not ans2:
            logging.debug('dconnect_setup_newinstclassid() not returning any payload')
            return -3, None

        status2 = ans2.get_status()
        if status2:
            logging.debug('dconnect_setup_newinstclassid() failed: %s [err:0x%x]' % (get_status_error_as_string(status2), status2))
            return -4, None

        return 0, ans2.get_instance()


    def dconnect_invoke(self, instance, method_index, arg_class=None, ret_class=None, expecting_class=DConnectInvokeReply, cid=0):

        if not cid:
            cid = self.client_id

        req_num = self.get_new_ipcm_request_id()
        fwd = ipcmMessageReqForward(request_index=req_num,
                                    client_id=cid,
                                    ipcm_target=DCONNECT_IPC_TARGETID)

        pDConnectOpobj = DConnectOp(fwd,
                                    opcode_major=DCON_OP_INVOKE,
                                    opcode_minor=0,
                                    request_index=self.get_new_dconnect_request_id())

        invoke_obj = DConnectInvoke(pDConnectOpobj, instance=instance, method_index=method_index)
        if arg_class:
            invoke_obj.set_payload(arg_class)

        ans = self.send_receive(invoke_obj)
        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT,
                                           expecting_payload=True,
                                           expecting_class=expecting_class,
                                           payload_class=ret_class)
        if ret:
            self.display_vbox_error(ret, params)
            return -1, None

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_invoke() failed: %s [err:0x%x]' % (get_status_error_as_string(status1),status1))
            return -2, None

        if not ans2:
            logging.debug('dconnect_invoke() not returning any payload')
            return -3, None

        # In some cases we may expect a DConnectInvoke which does not carry any status
        if expecting_class in [ DConnectInvokeReply, DConnectSetupReply ]:
            status2 = ans2.get_status()
            if status2:
                logging.debug('dconnect_invoke() failed: %s [err:0x%x]' % (get_status_error_as_string(status2),status2))
                return -4, None

        return 0, ans2


    def dconnect_setup_reply(self, instance, status, dconnect_request_id=0, ret_class=None, cid=0):

        if not cid:
            cid = self.client_id

        import random
        instance += random.randint(0,128)*64

        req_num = self.get_new_ipcm_request_id()
        fwd = ipcmMessageReqForward(request_index=req_num,
                                    client_id=cid,
                                    ipcm_target=DCONNECT_IPC_TARGETID)

        decoobj = DConnectOp(fwd,
                             opcode_major=DCON_OP_SETUP_REPLY,
                             opcode_minor=0,
                             request_index=dconnect_request_id)
        setupreplyobj = DConnectSetupReply(decoobj, instance=instance, status=status)

        ans = self.send_receive(setupreplyobj)
        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT,
                                           expecting_payload=True,
                                           expecting_class=DConnectInvoke,
                                           payload_class=ret_class)

        if ret:
            self.display_vbox_error(ret, params)
            return -1, None

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_setup_reply() failed: %s [err:0x%x]' % (get_status_error_as_string(status1),status1))
            return -2, None

        if not ans2:
            logging.debug('dconnect_setup_reply() not returning any payload')
            return -3, None

        return 0, ans2


    def dconnect_ivirtualbox_getmachines(self, pIVirtualBox, cid=0):

        method_index = self.get_invoke_method_by_name('IVirtualBox.GetMachines')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        status, ans = self.dconnect_invoke(instance=pIVirtualBox,
                                           method_index=method_index,
                                           ret_class=vboxrpc.IVirtualBox_GetMachines_Ret,
                                           cid=cid)
        if status:
            return status, None
        else:
            if isinstance(ans.get_payload(), vboxrpc.IVirtualBox_GetMachines_Ret):
                return 0, ans.get_payload().get_instances()
            else:
                return -1, []

    def dconnect_ivirtualbox_getmachinestates(self, pIVirtualBox, pMachines, cid=0):

        method_index = self.get_invoke_method_by_name('IVirtualBox.GetMachineStates')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        args = vboxrpc.IVirtualBox_GetMachineStates_Args(pMachines)
        status, ans = self.dconnect_invoke(instance=pIVirtualBox,
                                           method_index=method_index,
                                           arg_class=args,
                                           ret_class=vboxrpc.IVirtualBox_GetMachineStates_Ret,
                                           cid=cid)
        if status:
            return status, None
        else:
            if isinstance(ans.get_payload(), vboxrpc.IVirtualBox_GetMachineStates_Ret):
                return 0, ans.get_payload().get_states()
            else:
                return -1, []

    def dconnect_ivirtualbox_findmachine(self, pIVirtualBox, machine_iid, cid=0):

        if machine_iid != '{':
            machine_iid = '{%s}' %  machine_iid

        method_index = self.get_invoke_method_by_name('IVirtualBox.FindMachine')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        args = vboxrpc.IVirtualBox_FindMachine_Args(machine_iid)
        status, ans = self.dconnect_invoke(instance=pIVirtualBox,
                                           method_index=method_index,
                                           arg_class=args,
                                           ret_class=vboxrpc.IVirtualBox_FindMachine_Ret,
                                           cid=cid)
        if status:
            return status, None
        else:
            if isinstance(ans.get_payload(), vboxrpc.IVirtualBox_FindMachine_Ret):
                return 0, ans.get_payload().get_instance()
            else:
                return -1, []

    def dconnect_imachine_getname(self, pIMachine, cid=0):

        method_index = self.get_invoke_method_by_name('IMachine.GetName')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        status, ans = self.dconnect_invoke(instance=pIMachine,
                                           method_index=method_index,
                                           ret_class=vboxrpc.IMachine_GetName_Ret,
                                           cid=cid)
        if status:
            return status, None
        else:
            if isinstance(ans.get_payload(), vboxrpc.IMachine_GetName_Ret):
                return 0, ans.get_payload().get_string()
            else:
                return -1, []

    def dconnect_imachine_getid(self, pIMachine, cid=0):

        method_index = self.get_invoke_method_by_name('IMachine.GetId')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        status, ans = self.dconnect_invoke(instance=pIMachine,
                                           method_index=method_index,
                                           ret_class=vboxrpc.IMachine_GetId_Ret,
                                           cid=cid)
        if status:
            return status, None
        else:
            if isinstance(ans.get_payload(), vboxrpc.IMachine_GetId_Ret):
                return 0, ans.get_payload().get_string()
            else:
                return -1, []

    def dconnect_invoke_reply(self, status, dco_req_index=0, payload=None, cid=0):

        if not cid:
            cid = self.client_id

        req_num = self.get_new_ipcm_request_id()
        fwd = ipcmMessageReqForward(request_index=req_num,
                                    client_id=cid,
                                    ipcm_target=DCONNECT_IPC_TARGETID)

        pDConnectOpobj = DConnectOp(fwd,
                                    opcode_major=DCON_OP_INVOKE_REPLY,
                                    opcode_minor=0,
                                    request_index=dco_req_index)

        if payload:
            payload=ipcPayload(payload)

        invoke_obj = DConnectInvokeReply(pDConnectOpobj, status=status, payload=payload)
        ans = self.send_receive(invoke_obj)
        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT,
                                           expecting_payload=True)

        if ret:
            self.display_vbox_error(ret, params)
            return -1, None

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_invoke_reply() failed: %s [err:0x%x]' % (get_status_error_as_string(status1), status1))
            return -2, None

        return 0, None


    def dconnect_imachine_lockmachine(self, pIMachine, instance=0, locktype=1, cid=0):

        method_index = self.get_invoke_method_by_name('IMachine.LockMachine')
        if method_index is None:
            logging.error('Bug within the code!')
            return -2, None

        import random
        instance += random.randint(0,128)*64
        args = vboxrpc.IMachine_LockMachine_Args(instance, locktype)
        status, ans = self.dconnect_invoke(instance=pIMachine,
                                           method_index=method_index,
                                           arg_class=args,
                                           expecting_class=DConnectInvoke,
                                           cid=cid)
        if status:
            return status, None

        # TODO, split!
        dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
        pISession = ans.get_instance()

        self.dconnect_invoke_reply(0, dco_req_index=dco_seq_num, payload=struct.pack('<L', 1))

        return 0, pISession, dco_seq_num


    def dconnect_setup_queryinterface(self, iid, instance, request_index=0, with_pushforward=False, cid=0):

        if not cid:
            cid = self.client_id
        if not request_index:
            request_index=self.get_new_dconnect_request_id()

        req_num = self.get_new_ipcm_request_id()
        if with_pushforward:
            fwd = ipcmMessagePushForward(request_index=req_num,
                                         client_id=cid,
                                         ipcm_target=DCONNECT_IPC_TARGETID)
        else:
            fwd = ipcmMessageReqForward(request_index=req_num,
                                        client_id=cid,
                                        ipcm_target=DCONNECT_IPC_TARGETID)

        decoobj = DConnectOp(fwd,
                             opcode_major=DCON_OP_SETUP,
                             opcode_minor=DCON_OP_SETUP_QUERY_INTERFACE,
                             request_index=request_index)

        setup_obj = DConnectSetupQueryInterface(decoobj, iid=iid, instance=instance)
        ans = self.send_receive(setup_obj)

        ret, params = self.generic_handler(ans,
                                           req_num,
                                           answer_type=IPCM_MSG_ACK_RESULT,
                                           expecting_payload=True,
                                           expecting_class=DConnectSetupReply)
        if ret:
            self.display_vbox_error(ret, params)
            return -1, None

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_setup_queryinterface() failed: %s [err:0x%x]' % (get_status_error_as_string(status1), status1))
            return -2, None

        if not ans2:
            logging.debug('dconnect_setup_queryinterface() not returning any payload')
            return -3, None

        status2 = ans2.get_status()
        if status2:
            logging.debug('dconnect_setup_queryinterface() failed: %s [err:0x%x]' % (get_status_error_as_string(status2), status2))
            return -4, None

        return 0, ans2.get_instance()


    def dconnect_release(self, instance, cid=0):
        '''
        Call Release upon a specific instance.
        '''

        if not cid:
            cid = self.client_id

        req_num = self.get_new_ipcm_request_id()
        fwd = ipcmMessageReqForward(request_index=req_num,
                                    client_id=cid,
                                    ipcm_target=DCONNECT_IPC_TARGETID)

        decoobj = DConnectOp(fwd,
                             opcode_major=DCON_OP_RELEASE,
                             opcode_minor=0,
                             request_index=0)

        release_obj = DConnectRelease(decoobj, instance=instance)
        ans = self.send_receive(release_obj) # Note: Bug for now. We have a size prob.

        ret, params = self.generic_handler(ans, req_num, answer_type=IPCM_MSG_ACK_RESULT)
        if ret:
            self.display_vbox_error(ret, params)
            return -1

        status1, ans2 = params
        if status1:
            logging.debug('dconnect_release() failed: %s [err:0x%x]' % (get_status_error_as_string(status1), status1))
            return -2

        return 0


###
# vboxmanage API -- guestproperty
###

def vboxmanage_guestproperty_get(target_iid, property_name, handlers=None):
    '''
    Find a specific VM property.
    Returns (err, None) in case of error, (0, value_str) otherwise.
    '''

    logging.debug("-------- vboxmanage guestproperty get %s %s ---------" % (target_iid, property_name))

    if not target_iid:
        logging.error('Missing argument!')
        return -1, None

    value_str = None

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -2, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    ret, x = ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)
    if ret:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -7, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None


    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed: invalid payload %s' % type(payload))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    iid = ipcc.get_iid_by_name('IMACHINE_IID')
    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    method_index = ipcc.get_invoke_method_by_name('IMachine.getProperty')
    arg = vboxrpc.IMachine_getProperty_Args(s=property_name)
    status, ans = ipcc.dconnect_invoke(instance=pIMachine,
                                       method_index=method_index,
                                       arg_class=arg,
                                       ret_class=vboxrpc.IMachine_getProperty_Ret)
    if not status and hasattr(ans.get_payload(),'get_string'):
        value_str = ans.get_payload().get_string().decode('utf-16le')

    ipcc.dconnect_release(instance=pIMachine)
    ipcc.close_connection()
    return 0, value_str

###
# vboxmanage API -- controlvm
###

def vboxmanage_controlvm_keyboardputscancode(target_iid, scancodes_array=[], handlers=None):
    '''
    Injects a keystroke within the VM's session.
    Returns an error in case of problem or 0 if the injection is a success
    '''

    logging.debug("-------- vboxmanage keystroke injection! ---------")

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2

    ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3

    ret = ipcc.dconnect_release(instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_release() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -7

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed: invalid payload %s' % type(payload))
        return -7

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12

    iid = ipcc.get_iid_by_name('IMACHINE_IID')
    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -13

    # IConsole.GetKeyboard()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetKeyboard')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetKeyboard_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetKeyboard_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14

    pIKeyboard = payload.get_instance() & (~1)

    for scancodes in scancodes_array:

        for scancode in scancodes:

            # IKeyboard.PutScancode()
            method_index = ipcc.get_invoke_method_by_name('IKeyboard.PutScancode')
            arg = vboxrpc.IKeyboard_PutScancode_Args(d=scancode)
            status, ans = ipcc.dconnect_invoke(instance=pIKeyboard, method_index=method_index, arg_class=arg)
            if status:
                logging.error('IKeyboard_PutScancode() failed [err=0x%x]' % (status & 0xffffffff))
                continue
            time.sleep(0.001)

        time.sleep(0.005)

    ipcc.dconnect_release(instance=pIKeyboard)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(instance=pIConsole)
    ipcc.close_connection()
    return 0

###
# vboxmanage API -- debugvm
###

def vboxmanage_debugvm_osdetect(target_iid, handlers=None):
    '''
    Calls osdetect to return the OS type to the user
    Returns (err, None) in case of error or (0, os_version) otherwise
    '''

    logging.debug("-------- VBoxManage debugvm %s osdetect ---------" % target_iid)

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    ret, x = ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, x = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -7, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None


    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed: invalid payload %s' % type(payload))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12, None

    iid = ipcc.get_iid_by_name('IMACHINE_IID')
    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    # IConsole.GetDebugger()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetDebugger')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetDebugger_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetDebugger_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    pIMachineDebugger = payload.get_instance() & (~1)

    # pIMachineDebugger.loadPlugIn()
    method_index = ipcc.get_invoke_method_by_name('IMachineDebugger.loadPlugIn')
    arg = vboxrpc.IMachineDebugger_loadPlugIn_Args(s='all')
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger,
                                       method_index=method_index,
                                       arg_class=arg,
                                       ret_class=vboxrpc.IMachineDebugger_loadPlugIn_Ret)
    time.sleep(0.005)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -99, None

    # pIMachineDebugger.detectOS()
    method_index = ipcc.get_invoke_method_by_name('IMachineDebugger.detectOS')
    status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IMachineDebugger_detectOS_Ret)
    time.sleep(0.005)
    if status or not ans:
	logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -15, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IMachineDebugger_detectOS_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -15, None

    os_version = payload.get_string().decode('utf-16le')
    logging.debug("OS: %s" % os_version)
    ipcc.dconnect_release(instance=pIMachineDebugger)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(instance=pIConsole)
    ipcc.close_connection()
    return 0, os_version

def vboxmanage_debugvm_getregisters(target_iid, registers=[], handlers=None):
    '''
    Calls getRegisters() to return the virtual cpu's current registers
    Note: Currently fixed to CPU 0
    Returns (err, None) in case of error or (0, value) otherwise
    '''

    logging.debug("-------- vboxmanage debugvm %s getregisters $REGNAME ---------" % target_iid)

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12, None

    iid = ipcc.get_iid_by_name('IMACHINE_IID')
    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    # IConsole.GetDebugger()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetDebugger')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetDebugger_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetDebugger_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    pIMachineDebugger = payload.get_instance() & (~1)

    reg_values = {}
    for register_name in registers:

        # pIMachineDebugger.getRegister()
        method_index = ipcc.get_invoke_method_by_name('IMachineDebugger.getRegister')
        arg = vboxrpc.IMachineDebugger_getRegister_Args(d=0, s=register_name)
        status, ans = ipcc.dconnect_invoke(instance=pIMachineDebugger,
                                           method_index=method_index,
                                           arg_class=arg,
                                           ret_class=vboxrpc.IMachineDebugger_getRegister_Ret)
        # Small tempo
        time.sleep(0.001)
        if status:
            logging.error('IMachineDebugger.getRegister() failed [err=0x%x]' % (status & 0xffffffff))
            continue

        payload = ans.get_payload()
        if isinstance(payload, vboxrpc.IMachineDebugger_getRegister_Ret):
            reg_value = payload.get_string().decode('utf-16le')
            logging.debug("%s = %s" % (register_name, reg_value))
            reg_values[register_name] = reg_value
        else:
            logging.debug("Invalid register: %s" % register_name)

    # pIMachineDebugger
    ipcc.dconnect_release(instance=pIMachineDebugger)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(instance=pIConsole)
    ipcc.close_connection()
    return 0, reg_values

###
# vboxmanage API -- list
###

def vboxmanage_list_vms(handlers=None):
    '''
    Attempt to discover the list of RUNNING VMs (name,IID)
    Returns (err, None) in case of problem or (0,vms) otherwise.
    '''

    logging.debug("-------- vboxmanage list runningvms ---------")

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ret = ipcc.send_clienthello()
    ret = ipcc.define_target()
    ret = ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    ipcc.dconnect_release(instance=ptr1)

    ret, machines = ipcc.dconnect_ivirtualbox_getmachines(pIVirtualBox=ptr1)
    if ret:
        logging.error('dconnect_ivirtualbox_getmachines() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ret, machine_states = ipcc.dconnect_ivirtualbox_getmachinestates(ptr1, map(lambda x: x&(~1), machines))
    if ret:
        logging.error('dconnect_ivirtualbox_getmachinestates() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5, None

    vms = []
    for i in xrange(len(machine_states)):

        pImachine = machines[i] & (~1)
        machine_state = machine_states[i]

        method_index = ipcc.get_invoke_method_by_name('IMachine.GetAccessible')
        ret, ans = ipcc.dconnect_invoke(instance=pImachine,
                                        method_index=method_index,
                                        ret_class=vboxrpc.IMachine_GetAccessible_Ret)
        if ret:
            logging.error('dconnect_invoke() failed [err=0x%x]' % (ret & 0xffffffff))
            return -6, None

        payload = ans.get_payload()
        if not isinstance(payload, vboxrpc.IMachine_GetAccessible_Ret):
            logging.error('dconnect_invoke() failed [err=0x%x]' % (ret & 0xffffffff))
            return -6, None

        if not payload.is_accessible():
            logging.error('The machine is not accessible, skipping it!')
            continue

        ret, machine_name = ipcc.dconnect_imachine_getname(pImachine)
        if ret:
            logging.error('dconnect_imachine_getname() failed [err=0x%x]' % (ret & 0xffffffff))
            return -7, None

        logging.debug('Name: %s' % machine_name)

        ret, machine_id = ipcc.dconnect_imachine_getid(pImachine)
        if ret:
            logging.error('dconnect_imachine_getid() failed [err=0x%x]' % (ret & 0xffffffff))
            return -8, None

        logging.debug('ID: %s' % machine_id)

        vms.append({'name': machine_name.decode('utf-16le'),
                    'iid': machine_id.decode('utf-16le'),
                    'state': machine_state,})

    logging.debug('Releasing resources...')

    # Release everything
    for pMachine in machines:
        ipcc.dconnect_release(instance=pMachine)
    ipcc.dconnect_release(instance=pIVirtualBox)
    ipcc.close_connection()
    return 0, vms

def vboxmanage_list_runningvms(handlers=None):
    '''
    Attempt to discover the list of RUNNING VMs (name,IID)
    Returns (err, None) in case of problem or (0,vms) otherwise.
    '''

    logging.debug("-------- vboxmanage list runningvms ---------")

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ret = ipcc.send_clienthello()
    ret = ipcc.define_target()
    ret = ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, ptr1 = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    ipcc.dconnect_release(instance=ptr1)

    ret, machines = ipcc.dconnect_ivirtualbox_getmachines(pIVirtualBox=ptr1)
    if ret:
        logging.error('dconnect_ivirtualbox_getmachines() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ret, machine_states = ipcc.dconnect_ivirtualbox_getmachinestates(ptr1, map(lambda x: x&(~1), machines))
    if ret:
        logging.error('dconnect_ivirtualbox_getmachinestates() failed [err=0x%x]' % (ret & 0xffffffff))
        return -5, None

    vms = []
    for i in xrange(len(machine_states)):

        pImachine = machines[i] & (~1)
        machine_state = machine_states[i]

        if machine_state != MACHINE_STATE_RUNNING:
            continue

        method_index = ipcc.get_invoke_method_by_name('IMachine.GetAccessible')
        ret, ans = ipcc.dconnect_invoke(instance=pImachine,
                                        method_index=method_index,
                                        ret_class=vboxrpc.IMachine_GetAccessible_Ret)
        if ret:
            logging.error('dconnect_invoke() failed [err=0x%x]' % (ret & 0xffffffff))
            return -6, None

        payload = ans.get_payload()
        if not isinstance(payload, vboxrpc.IMachine_GetAccessible_Ret):
            logging.error('dconnect_invoke() failed [err=0x%x]' % (ret & 0xffffffff))
            return -6, None

        if not payload.is_accessible():
            logging.error('The machine is not accessible, skipping it!')
            continue

        ret, machine_name = ipcc.dconnect_imachine_getname(pImachine)
        if ret:
            logging.error('dconnect_imachine_getname() failed [err=0x%x]' % (ret & 0xffffffff))
            return -7, None

        logging.debug('Name: %s' % machine_name)

        ret, machine_id = ipcc.dconnect_imachine_getid(pImachine)
        if ret:
            logging.error('dconnect_imachine_getid() failed [err=0x%x]' % (ret & 0xffffffff))
            return -8, None

        logging.debug('ID: %s' % machine_id)

        vms.append({'name': machine_name.decode('utf-16le'),
                    'iid': machine_id.decode('utf-16le')})

    logging.debug('Releasing resources...')

    # Release everything
    for pMachine in machines:
        ipcc.dconnect_release(instance=pMachine)
    ipcc.dconnect_release(instance=pIVirtualBox)
    ipcc.close_connection()
    return 0, vms


###
# vboxmanage API -- guestcontrol
###


def vboxmanage_guestcontrol_start(target_iid, cmdline, creds=None, handlers=None):
    '''
    Calls run to execute a command on one specific VM using credentials.
    Does not wait for the end of the command therefore the session remains open
    and it is blind.
    Returns (err, None) in case of error or (0, [stdout,stderr]) otherwise
    '''

    logging.debug("-------- VBoxManage guestcontrol %s [creds] start [args/env/etc.] ---------" % target_iid)

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    ret, x = ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, x = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -7, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12, None


    # IConsole.GetGuest()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetGuest')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetGuest_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetGuest_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    pIGuest = payload.get_instance() & (~1)

    ipcc.dconnect_release(instance=pIConsole)
    ipcc.dconnect_release(instance=pIMachine)

    # IGuest::CreateSession()
    method_index = ipcc.get_invoke_method_by_name('IGuest.CreateSession')
    args = vboxrpc.IGuest_CreateSession_Args(user=creds['user'],
                                             password=creds['password'],
                                             domain=creds['domain'],
                                             session_name='toto_%s' % (os.urandom(6).encode('hex')))
    status, ans = ipcc.dconnect_invoke(instance=pIGuest,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuest_CreateSession_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuest_CreateSession_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    pIGuestSession = payload.get_instance() & (~1)


    # IGuestSession::WaitForArray()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.WaitForArray')
    args = vboxrpc.IGuestSession_WaitForArray_Args(30000, flags=[1])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_WaitForArray_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -15, None

    # IGuestSession::GetId()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.GetId')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IGuestSession_GetId_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -16, None

    # IGuestSession::ProcessCreate()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.ProcessCreate')
    args = vboxrpc.IGuestSession_ProcessCreate_Args(cmdline.split()[0], timeout=0xffffffff, arguments=cmdline.split(), environment=[], flags=[16,32])

    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_ProcessCreate_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestSession_ProcessCreate_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    pIGuestProcess = payload.get_instance() & (~1)

    # Small tempo
    time.sleep(0.01)

    # IGuestProcess::WaitForArray()

    method_index = ipcc.get_invoke_method_by_name('IGuestProcess.WaitForArray')
    args = vboxrpc.IGuestProcess_WaitForArray_Args(30000, flags=[1])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestProcess_WaitForArray_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -18, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestProcess_WaitForArray_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -18, None

    if payload.get_status() != 1:
        logging.error('The Process has not started yet!')
        return -19, None

    # IGuestProcess::GetPid()

    method_index = ipcc.get_invoke_method_by_name('IGuestProcess.GetPID')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IGuestProcess_GetPID_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -20, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestProcess_GetPID_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -20, None

    process_pid = payload.get_PID()
    ipcc.dconnect_release(instance=pIGuestProcess)
    ipcc.dconnect_release(instance=pIGuestSession)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(pIConsole)

    ipcc.close_connection()
    return 0, [process_pid]


def vboxmanage_guestcontrol_run(target_iid, cmdline, creds=None, handlers=None):
    '''
    Calls run to execute a command on one specific VM using credentials.
    Returns (err, None) in case of error or (0, [stdout,stderr]) otherwise
    '''

    logging.debug("-------- VBoxManage guestcontrol %s [creds] run [args/env/etc.] ---------" % target_iid)

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    ret, x = ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, x = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -7, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12, None


    # IConsole.GetGuest()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetGuest')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetGuest_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetGuest_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    pIGuest = payload.get_instance() & (~1)

    ipcc.dconnect_release(instance=pIConsole)
    ipcc.dconnect_release(instance=pIMachine)

    # IGuest::CreateSession()
    method_index = ipcc.get_invoke_method_by_name('IGuest.CreateSession')
    args = vboxrpc.IGuest_CreateSession_Args(user=creds['user'],
                                             password=creds['password'],
                                             domain=creds['domain'],
                                             session_name='toto_%s' % (os.urandom(6).encode('hex')))
    status, ans = ipcc.dconnect_invoke(instance=pIGuest,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuest_CreateSession_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    payload = ans.get_payload()
    pIGuestSession = payload.get_instance() & (~1)


    # IGuestSession::WaitForArray()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.WaitForArray')
    args = vboxrpc.IGuestSession_WaitForArray_Args(30000, flags=[1])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_WaitForArray_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -15, None

    # IGuestSession::GetId()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.GetId')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IGuestSession_GetId_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -16, None

    # IGuestSession::ProcessCreate()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.ProcessCreate')
    args = vboxrpc.IGuestSession_ProcessCreate_Args(cmdline.split()[0], timeout=0xffffffff, arguments=cmdline.split(), environment=[], flags=[16,32])

    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_ProcessCreate_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestSession_ProcessCreate_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    pIGuestProcess = payload.get_instance() & (~1)

    # Small tempo
    time.sleep(0.01)

    # IGuestProcess::WaitForArray()

    method_index = ipcc.get_invoke_method_by_name('IGuestProcess.WaitForArray')
    args = vboxrpc.IGuestProcess_WaitForArray_Args(30000, flags=[1])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestProcess_WaitForArray_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -18, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestProcess_WaitForArray_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -18, None

    if payload.get_status() != 1:
        logging.error('The Process has not started yet!')
        return -19, None

    # IGuestProcess::GetPid()

    method_index = ipcc.get_invoke_method_by_name('IGuestProcess.GetPID')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IGuestProcess_GetPID_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -20, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestProcess_GetPID_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -20, None

    process_pid = payload.get_PID()

    log_stdout = ''
    log_stderr = ''

    while 1:

        # IGuestProcess::WaitForArray()

        method_index = ipcc.get_invoke_method_by_name('IGuestProcess.WaitForArray')
        args = vboxrpc.IGuestProcess_WaitForArray_Args(500, flags=[1,2,8,16])
        status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                           method_index=method_index,
                                           arg_class=args,
                                           ret_class=vboxrpc.IGuestProcess_WaitForArray_Ret)
        if status:
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -21, None

        payload = ans.get_payload()
        if not isinstance(payload, vboxrpc.IGuestProcess_WaitForArray_Ret):
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -21, None

        if payload.get_status() == 2:
            break

        # IGuestProcess::Read(stdout)

        method_index = ipcc.get_invoke_method_by_name('IGuestProcess.Read')
        args = vboxrpc.IGuestProcess_Read_Args(1, 65536, 0xffffffff)
        status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                           method_index=method_index,
                                           arg_class=args,
                                           ret_class=vboxrpc.IGuestProcess_Read_Ret)
        if status:
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -22, None

        payload = ans.get_payload()
        if not isinstance(payload, vboxrpc.IGuestProcess_Read_Ret):
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -22, None

        log_stdout += payload.get_buffer()

        # IGuestProcess::Read(stderr)

        method_index = ipcc.get_invoke_method_by_name('IGuestProcess.Read')
        args = vboxrpc.IGuestProcess_Read_Args(2, 65536, 0xffffffff)
        status, ans = ipcc.dconnect_invoke(instance=pIGuestProcess,
                                           method_index=method_index,
                                           arg_class=args,
                                           ret_class=vboxrpc.IGuestProcess_Read_Ret)
        if status:
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -23, None

        payload = ans.get_payload()
        if not isinstance(payload, vboxrpc.IGuestProcess_Read_Ret):
            logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
            return -23, None

        log_stderr += payload.get_buffer()


    # IGuestProcess::GetStatus() # We dont care for now.
    # IGuestProcess::GetExitCode() # We dont care for now.

    ipcc.dconnect_release(instance=pIGuestProcess)

    #IGuestSession::Close()
    method_index = ipcc.get_invoke_method_by_name('IGuestSession.Close')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession, method_index=method_index)

    ipcc.dconnect_release(instance=pIGuestSession)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(pIConsole)

    ipcc.close_connection()
    return 0, [process_pid, log_stdout, log_stderr]


def vboxmanage_guestcontrol_copyto(target_iid, src, dst, creds=None, handlers=None):
    '''
    Copy src (host) to dst (VM) using credentials.
    Returns (err, None) in case of error or (0, XXXX) otherwise
    '''

    logging.debug("-------- VBoxManage guestcontrol %s [creds] copyto src://%s dst://%s ---------" % (target_iid,src,dst))

    ipcc = IPC_class()
    ipcc.set_handlers(handlers)
    ret, e = ipcc.start()
    if ret:
        logging.error('Failed to contact VboxSVC! [err=%s]' % str(e))
        return -1, None

    ipcc.send_clienthello()
    ipcc.define_target()
    ipcc.resolve_clientname()

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, pIVirtualBox = ipcc.dconnect_setup_newinstclassid(iid=iid)
    if ret:
        logging.error('dconnect_setup_newinstclassid() failed [err=0x%x]' % (ret & 0xffffffff))
        return -2, None

    ret, x = ipcc.dconnect_invoke(instance=pIVirtualBox, method_index=5)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -3, None

    iid = ipcc.get_iid_by_name('IVIRTUALBOX_IID')
    ret, x = ipcc.dconnect_setup_queryinterface(iid=iid, instance=pIVirtualBox)
    if ret:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (ret & 0xffffffff))
        return -4, None

    ipcc.dconnect_release(instance=pIVirtualBox)

    ret, pTargetMachine = ipcc.dconnect_ivirtualbox_findmachine(pIVirtualBox, machine_iid=target_iid)
    if ret:
        logging.error('dconnect_ivirtualbox_findmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -6, None

    pTargetMachine &= (~1)
    ret, pISession, dco_seqnum = ipcc.dconnect_imachine_lockmachine(pTargetMachine, instance=0x7f72d4000d60|1)
    if ret:
        logging.error('dconnect_imachine_lockmachine() failed [err=0x%x]' % (ret & 0xffffffff))
        return -7, None

    status, ans = ipcc.dconnect_setup_reply(0x7f72cc000f80,
                                            0,
                                            dconnect_request_id=(dco_seqnum+1),
                                            ret_class=vboxrpc.Session_AssignRemoteMachine_Ret)
    if status:
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.Session_AssignRemoteMachine_Ret):
        logging.error('dconnect_setup_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -8, None

    dco_seq_num = ans.get_dconnect_header().get_header().get_request_index()
    pIMachine = payload.get_imachine_ptr(with_flag=False)
    pIConsole = payload.get_iconsole_ptr(with_flag=False)

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.IINTERNAL_MACHINE_CONTROL_IID, instance=pIMachine)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -9, None

    status, ans = ipcc.dconnect_invoke(instance=pIMachine, method_index=3)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -10, None

    status, ans = ipcc.dconnect_invoke_reply(0, dco_req_index=dco_seq_num)
    if status:
        logging.error('dconnect_invoke_reply() failed [err=0x%x]' % (status & 0xffffffff))
        return -11, None

    status, ptr1 = ipcc.dconnect_setup_queryinterface(iid=vboxipc.ICONSOLE_IID, instance=pIConsole)
    if status:
        logging.error('dconnect_setup_queryinterface() failed [err=0x%x]' % (status & 0xffffffff))
        return -12, None

    # IConsole.GetGuest()
    method_index = ipcc.get_invoke_method_by_name('IConsole.GetGuest')
    status, ans = ipcc.dconnect_invoke(instance=pIConsole,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IConsole_GetGuest_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IConsole_GetGuest_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -13, None

    pIGuest = payload.get_instance() & (~1)

    ipcc.dconnect_release(instance=pIConsole)
    ipcc.dconnect_release(instance=pIMachine)

    # IGuest::CreateSession()
    method_index = ipcc.get_invoke_method_by_name('IGuest.CreateSession')
    args = vboxrpc.IGuest_CreateSession_Args(user=creds['user'],
                                             password=creds['password'],
                                             domain=creds['domain'],
                                             session_name='toto')
    status, ans = ipcc.dconnect_invoke(instance=pIGuest,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuest_CreateSession_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuest_CreateSession_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -14, None

    pIGuestSession = payload.get_instance() & (~1)

    # IGuestSession::WaitForArray()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.WaitForArray')
    args = vboxrpc.IGuestSession_WaitForArray_Args(30000, flags=[1])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_WaitForArray_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -15, None

    # IGuestSession::GetId()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.GetId')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       ret_class=vboxrpc.IGuestSession_GetId_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -16, None


    # IGuestSession::CopyTo()

    method_index = ipcc.get_invoke_method_by_name('IGuestSession.CopyTo')
    args = vboxrpc.IGuestSession_CopyTo_Args(src, dst, flags=[])
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession,
                                       method_index=method_index,
                                       arg_class=args,
                                       ret_class=vboxrpc.IGuestSession_CopyTo_Ret)
    if status:
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    payload = ans.get_payload()
    if not isinstance(payload, vboxrpc.IGuestSession_CopyTo_Ret):
        logging.error('dconnect_invoke() failed [err=0x%x]' % (status & 0xffffffff))
        return -17, None

    pIProgress = payload.get_instance() & (~1)

    # Small tempo
    time.sleep(1)

    ipcc.dconnect_release(pIProgress)
    ipcc.dconnect_release(instance=pIProgress)

    #IGuestSession::Close()
    method_index = ipcc.get_invoke_method_by_name('IGuestSession.Close')
    status, ans = ipcc.dconnect_invoke(instance=pIGuestSession, method_index=method_index)

    ipcc.dconnect_release(instance=pIGuestSession)
    ipcc.dconnect_release(instance=pIMachine)
    ipcc.dconnect_release(pIConsole)

    ipcc.close_connection()
    return 0, None


###
# Entry point - testing/debugging only
###

if __name__ == "__main__":
    pass
