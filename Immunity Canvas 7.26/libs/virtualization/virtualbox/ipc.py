#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  ipc.py
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
import copy

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct # TODO


###
# IPC objects
###


class ipcPayload(Struct):
    st = [
        ['payload', '0s', '' ],
    ]

    def __init__(self, payload=''):
        Struct.__init__(self)
        self['payload'] = payload

    def __str__(self):
        return self['payload']

    def __len__(self):
        return len(str(self['payload']))

    ###
    # (De)Serialization API
    ###

    def pack(self):
        return self['payload']

    def serialize(self, context=None):
        return self['payload']

    def deserialize(self, data):
        try:
            self['payload'] = data
            return self
        except Exception as e:
            return None


class ipcGuid(Struct):
    st = [
        ['m0', '<L', 0 ],
        ['m1', '<H', 0 ],
        ['m2', '<H', 0 ],
        ['m3', '8s', '\0'*8 ],
    ]

    def __str__(self):
        return '%.8x-%.4x-%.4x-%s' % (self['m0'], self['m1'], self['m2'], self['m3'].encode('hex'))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        if str(self) == str(other):
            return True
        else:
            return False


###
# Globals
###

IPCM_TARGET                   = ipcGuid(data='ffa83c75c2c80146b1158c2944da1150'.decode('hex'))
DCONNECT_IPC_TARGETID         = ipcGuid(data='ef47ca43c8eba2479679a4703218089f'.decode('hex'))
VBOXSVC_IID                   = ipcGuid(data='f2a4a7b1b9471e4a82b207ccd5323c3f'.decode('hex'))
IVIRTUALBOX_IID_v5            = ipcGuid(data='d5b97095a1f18a4410c5e12f5285adad'.decode('hex'))
IVIRTUALBOX_IID_v6            = ipcGuid(data='3f16a0d054e25b4ea1f2011cf991c38d'.decode('hex'))
ICONSOLE_IID                  = ipcGuid(data='45a62d879b4a2717bee25585105b9eed'.decode('hex'))
IMACHINE_IID_v6               = ipcGuid(data='0a4647505d263845b23eddba5fb84976'.decode('hex'))
IMACHINE_IID_v5               = ipcGuid(data='8e94cd851fa78942281e0ca7ad48cd89'.decode('hex'))

IINTERNAL_SESSION_CONTROL_IID = ipcGuid(data='4e99c3b1cdf8024d94d01aaf884751ed'.decode('hex'))
IINTERNAL_MACHINE_CONTROL_IID = ipcGuid(data='df59bccd4d4ff24c809c917601355afc'.decode('hex'))

dic_iid_common = {
    'IPCM_TARGET'                   : IPCM_TARGET,
    'DCONNECT_IPC_TARGETID'         : DCONNECT_IPC_TARGETID,
    'VBOXSVC_IID'                   : VBOXSVC_IID,
    'ICONSOLE_IID'                  : ICONSOLE_IID,
    'IINTERNAL_SESSION_CONTROL_IID' : IINTERNAL_SESSION_CONTROL_IID,
    'IINTERNAL_MACHINE_CONTROL_IID' : IINTERNAL_MACHINE_CONTROL_IID,
}

dic_iid_5_2_x = copy.deepcopy(dic_iid_common)
dic_iid_5_2_x['IVIRTUALBOX_IID'] = IVIRTUALBOX_IID_v5
dic_iid_5_2_x['IMACHINE_IID']    = IMACHINE_IID_v5

dic_iid_6_0_x = copy.deepcopy(dic_iid_common)
dic_iid_6_0_x['IVIRTUALBOX_IID'] = IVIRTUALBOX_IID_v6
dic_iid_6_0_x['IMACHINE_IID']    = IMACHINE_IID_v6

dic_iid_global = { (5,2) : dic_iid_5_2_x, (6,0) : dic_iid_6_0_x }
