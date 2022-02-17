#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  gcc.py
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
from libs.rdp.asn1 import gcc_per_parser, gcc_ber_parser


class ConferenceName(ASN1Struct):

    st = [
        ['numeric',      '0'],
        #['text',         ''], # OPTIONAL
        #['unicodeText',  ''], # OPTIONAL
    ]

    parser = gcc_per_parser
    obj_name = 'ConferenceName'


class Password(ASN1Struct):

    st = [
        ['numeric',      '0'],
        ['text',         ''],
        ['unicodeText',  ''],
    ]

    parser = gcc_per_parser
    obj_name = 'Password'


class NonStandardParameter(ASN1Struct):

    st = [
        ['key',  ('h221NonStandard', '0')],
        ['data', bytes('' ) ],
    ]

    parser = gcc_per_parser
    obj_name = 'NonStandardParameter'


class ConferencePriority(ASN1Struct):

    st = [
        ['priority',  ''],
        ['scheme',    (NonStandardParameter(),'b') ],
    ]

    parser = gcc_per_parser
    obj_name = 'ConferencePriority'


class ConferenceCreateRequest(ASN1TupleStruct):

    st = [
        ['conferenceName',         ConferenceName()],
        #['convenerPassword',       Password()],  # OPTIONAL
        #['password',               Password()],  # OPTIONAL
        ['lockedConference',       False],
        ['listedConference',       False],
        ['conductibleConference',  False],
        ['terminationMethod',      'automatic'],
        #['conductorPrivileges',    []],                                    # OPTIONAL
        #['conductedPrivileges',    []],                                    # OPTIONAL
        #['nonConductedPrivileges', []],                                    # OPTIONAL
        #['conferenceDescription',  ''],                                    # OPTIONAL
        #['callerIdentifier',       ''],                                    # OPTIONAL
        ['userData',               [{'value': '',
                                     'key': ('h221NonStandard', 'Duca')}]],
        #['conferencePriority',     {}],                                    # OPTIONAL
        #['conferenceMode',         ('anonymous-only',None)],               # OPTIONAL
    ]

    parser = gcc_per_parser
    obj_name = 'ConnectGCCPDU'
    forbidden_fields = ['userData']
    tuple_param0 = 'conferenceCreateRequest'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return self.st[5][1][0]['value']

    def set_payload(self, payload):
        self.st[5][1][0]['value'] = payload


class ConferenceCreateResponse(ASN1TupleStruct):

    st = [
        ['nodeID',    0],
        ['tag',       0],
        ['result',    0],
        ['userData',  ''],
    ]

    parser = gcc_per_parser
    obj_name = 'ConnectGCCPDU'
    forbidden_fields = ['userData']
    tuple_param0 = 'ConferenceCreateResponse'

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    def get_payload(self):
        return self.st[3][1][0]['value']

    def set_payload(self, payload):
        self.st[3][1][0]['value'] = payload

class ConnectGCC(ASN1Struct):

    st = [
        ['t124Identifier',  ('object', '0.0.20.124.0.1') ],
        ['connectPDU',      ''],
    ]

    parser = gcc_per_parser
    obj_name = 'ConnectData'
    forbidden_fields = ['connectPDU']
    _data = ''
    _patched_payload = ''

    def get_dict(self, asn1_obj):
        return asn1_obj

    def get_payload(self):
        '''
        Bugfix (see below).
        '''
        if len(self._patched_payload):
            return self._patched_payload

        idx = self._data.find(self.st[1][1])
        self._patched_payload = self._data[idx:]
        return self._patched_payload

    def set_payload(self, payload):
        '''
        Bugfix (see below).
        '''
        self._patched_payload = payload
        self.st[1][1] = self._patched_payload

    def deserialize(self, data):
        try:
            # IMPORTANT: A small hack is necessary here.
            # For some reason (bug?) not all the payload within self.st[1][1]
            # is the actual payload. For that reason, we keep a copy of the data
            # within self._data and later circumvent the problem within {get,set}_payload()
            self._data = data
            asn1_obj = self.parser.decode(self.obj_name, data)
            asn1_dic = self.get_dict(asn1_obj)
            self.asn1_2_st(asn1_dic)
            self.payload = self.get_payload()
            return self
        except Exception as e:
            return None

if __name__ == "__main__":

    cn = ConferenceName()
    print str(cn.pack()).encode('hex')

    p = Password()
    print str(p.pack()).encode('hex')

    np = NonStandardParameter()
    print str(np.pack()).encode('hex')

    ccr = ConferenceCreateRequest()
    print str(ccr.pack()).encode('hex')

    cgcc = ConnectGCC()
    print str(cgcc.pack()).encode('hex')
