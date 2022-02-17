#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  mcs.py
## Description:
##            :
## Created_On :  Thu May 23 2019

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

from libs.rdp.asn1 import ASN1Struct, ASN1TupleStruct
from libs.rdp.asn1 import mcs_per_parser, mcs_ber_parser


class DomainParameters(ASN1Struct):

    st = [
        ['maxChannelIds',    34],
        ['maxUserIds',       2],
        ['maxTokenIds',      0],
        ['numPriorities',    1],
        ['minThroughput',    0],
        ['maxHeight',        1],
        ['maxMCSPDUsize',    65535],
        ['protocolVersion',  2],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainParameters'


# With the current classes, using copies is mandatory
d = DomainParameters()
DefaultMinParameters = copy.deepcopy(d)
DefaultMaxParameters = copy.deepcopy(d)
DefaultMinParameters.st = copy.deepcopy(d.st)
DefaultMaxParameters.st = copy.deepcopy(d.st)

DefaultMinParameters['maxChannelIds'] = 1
DefaultMinParameters['maxUserIds']    = 1
DefaultMinParameters['maxTokenIds']   = 1
DefaultMinParameters['minThroughput'] = 0
DefaultMinParameters['maxHeight']     = 1
DefaultMinParameters['maxMCSPDUsize'] = 1056

DefaultMaxParameters['maxChannelIds'] = 65535
DefaultMaxParameters['maxUserIds']    = 64535
DefaultMaxParameters['maxTokenIds']   = 65535
DefaultMaxParameters['minThroughput'] = 0
DefaultMaxParameters['maxHeight']     = 1


class MCSConnectInit(ASN1Struct):
    """
    2.2.1.3 Client MCS Connect Initial PDU with GCC Conference Create Request
    """

    st = [
        ['callingDomainSelector',   '\x01'],
        ['calledDomainSelector',    '\x01'],
        ['upwardFlag',              True],
        ['targetParameters',        DomainParameters()],
        ['minimumParameters',       DefaultMinParameters],
        ['maximumParameters',       DefaultMaxParameters],
        ['userData',                ''],
    ]

    parser = mcs_ber_parser
    obj_name = 'Connect-Initial'

    def get_dict(self, asn1_obj):
        return asn1_obj

    def get_payload(self):
        return self.st[6][1]

    def set_payload(self, payload):
        self.st[6][1] = payload

    def set_target_parameters(self, target_parameters):
        self['targetParameters'] = target_parameters


class MCSConnectResp(ASN1Struct):
    """
    2.2.1.4 Server MCS Connect Response PDU with GCC Conference Create Response
    """

    st = [
        ['result',              'rt-successful'],
        ['calledConnectId',     0],
        ['domainParameters',    DomainParameters()],
        ['userData',            ''],
    ]

    parser = mcs_ber_parser
    obj_name = 'Connect-Response'
    forbidden_fields = ['userData']

    def get_result(self):
        return self['result']

    def get_dict(self, asn1_obj):
        return asn1_obj

    def get_payload(self):
        return self.st[3][1]

    def set_payload(self, payload):
        self.st[3][1] = payload

    def get_result(self):
        for k, v in self.st:
            if k == 'result':
                return v
        return None

class MCSErectDomainRequest(ASN1TupleStruct):
    """
    2.2.1.5 Client MCS Erect Domain Request PDU
    """

    st = [
        ['subHeight',    0],
        ['subInterval',  0],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'erectDomainRequest'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''


class MCSAttachUserRequest(ASN1TupleStruct):
    """
    2.2.1.6 Client MCS Attach User Request PDU
    """

    st = [
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'attachUserRequest'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''

    def get_payload(self):
        return ''


class MCSAttachUserConfirm(ASN1TupleStruct):
    """
    2.2.1.7 Client MCS Attach User Confirm PDU
    """

    st = [
        ['result'   , 'rt-successful'],
        ['initiator', 0],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'attachUserConfirm'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''

    def get_initiator(self):
        return self['initiator']


class MCSChannelJoinRequest(ASN1TupleStruct):
    """
    2.2.1.8 Client MCS Channel Join Request PDU
    """

    st = [
        ['initiator',        1001],
        ['channelId',        1001],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'channelJoinRequest'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''

class MCSChannelLeaveRequest(ASN1TupleStruct):
    """
    Sends a channelLeaveRequest.
    Note: This is experimental and not used within the code currently.
    """

    st = [
        ['channelIds',        []],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'channelLeaveRequest'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''


class MCSChannelJoinConfirm(ASN1TupleStruct):
    """
    2.2.1.9 Client MCS Channel Join Confirm PDU
    """

    st = [
        ['result'   ,     'rt-successful'],
        ['initiator',     0],
        ['requested',     0],
        ['channelId',     0],
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'channelJoinConfirm'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return ''


class MCSSendDataRequest(ASN1TupleStruct):
    """
    T 125 - p59
    """
    forbidden_fields = ['userData']

    st = [
        ['initiator'   ,    0],
        ['channelId'   ,    0],
        ['dataPriority',    'high'],
        ['segmentation',    ('\xc0', 2)], # = 0b11000000 (begin=1,end=1)
        ['userData'    ,    '']
    ]

    parser = mcs_per_parser
    obj_name = 'DomainMCSPDU'
    tuple_param0 = 'sendDataRequest'

    def __init__(self, initiator, channelId):
        ASN1TupleStruct.__init__(self)
        self['initiator'] = initiator
        self['channelId'] = channelId

    def get_payload(self):
        return self['userData']

    def set_payload(self, payload):
        self['userData'] = payload


class MCSSendDataIndication(MCSSendDataRequest):
    """
    T 125 - p60
    """
    forbidden_fields = ['userData']


if __name__ == "__main__":
    
    dp = DomainParameters()
    print dp.pack().encode('hex')
    
    ci = MCSConnectInit()
    print ci.pack().encode('hex')

    ci.set_payload(dp.pack())
    print ci.pack().encode('hex')

    cr = MCSConnectResp()
    print cr.pack().encode('hex')

    edr = MCSErectDomainRequest()
    print edr.pack().encode('hex')

    aur = MCSAttachUserRequest()
    print aur.pack().encode('hex')

    auc = MCSAttachUserConfirm()
    print auc.pack().encode('hex')

    cjr = MCSChannelJoinRequest()
    print cjr.pack().encode('hex')

    cjc = MCSChannelJoinConfirm()
    print cjc.pack().encode('hex')

    sdr = MCSSendDataRequest()
    print sdr.pack().encode('hex')
