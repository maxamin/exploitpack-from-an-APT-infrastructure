################################################################################
## File       :  asn1.py
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
import logging
import time

try:
    import asn1tools
except ImportError:
    logging.error("Cannot import asn1tools (required)")
    raise

if '.' not in sys.path:
    sys.path.append('.')

import libs.rdp as librdp
rdp_dir = os.path.dirname(librdp.__file__)
gcc_ber_parser = asn1tools.compile_files(os.path.join(rdp_dir, 'asn1', 'gcc.asn'), 'ber')
gcc_per_parser = asn1tools.compile_files(os.path.join(rdp_dir, 'asn1', 'gcc.asn'), 'per')
mcs_per_parser = asn1tools.compile_files(os.path.join(rdp_dir, 'asn1', 'mcs.asn'), 'per')
mcs_ber_parser = asn1tools.compile_files(os.path.join(rdp_dir, 'asn1', 'mcs.asn'), 'ber')


class ASN1Struct(object):
    """
    Template Class for PER/DER encoded objects.
    """

    st = []
    parser = None
    obj_name = None
    payload = ''
    forbidden_fields = []

    ###
    # Basic API
    ###

    def __str__(self):
        L = []
        for entry in self.st:
            val_str = entry[1]
            if entry[0] in self.forbidden_fields:
                val_str = '[CENSORED]'
            elif isinstance(entry[1], str):
                def is_ascii(s):
                    return all(ord(c) < 128 for c in s)
                if is_ascii(entry[1]):
                    val_str = '\"%s\"' % entry[1]
                else:
                    val_str = entry[1].encode('hex')
            L.append('%s=%s' % (entry[0], val_str))
        s = ', '.join(L)
        return '[ %s: %s ]' % (type(self).__name__, s)

    def __setitem__(self, key, item):
        for entry in self.st:
            if entry[0] == key:
                entry[1] = item
                return
        raise "Invalid key!"

    def __getitem__(self, key):
        for entry in self.st:
            if entry[0] == key:
                return entry[1]
        raise "Invalid key!"

    ###
    # Packing API
    ###

    def st_2_asn1(self):
        d = {}
        for entry in self.st:
            if isinstance(entry[1], ASN1Struct):
                dic = entry[1].st_2_asn1()
                d[entry[0]] = dic
            else:
                d[entry[0]] = entry[1]
        return d

    def pack(self):
        d = self.st_2_asn1()
        return str(self.parser.encode(self.obj_name, d))

    ###
    # Unpacking API
    ###

    def asn1_2_st(self, d):

        def find_st_entry(kname):
            for i in xrange(len(self.st)):
                key, _ = self.st[i]
                if key == kname:
                    return i
            return -1

        for key in d.keys():
            idx = find_st_entry(key)
            assert(idx != -1)
            self.st[idx] = [ key, d[key] ]

        return self.st

    def get_dict(self, asn1_obj):
        return asn1_obj

    def get_payload(self):
        raise RuntimeError("Should be implemented!")

    def set_payload(self, payload):
        raise RuntimeError("Should be implemented!")

    def deserialize(self, data):
        try:
            asn1_obj = self.parser.decode(self.obj_name, data)
            #print asn1_obj
            asn1_dic = self.get_dict(asn1_obj)
            #print asn1_dic
            self.asn1_2_st(asn1_dic)
            self.payload = self.get_payload()
            return self
        except Exception as e:
            return None


class ASN1TupleStruct(ASN1Struct):
    """
    Template Class for PER/DER encoded objects (Tuple)
    """

    tuple_param0 = ''

    ###
    # Unpacking API
    ###

    def get_dict(self, asn1_obj):
        return asn1_obj[1]

    ###
    # Packing API
    ###

    def st_2_asn1(self):
        d = {}
        for entry in self.st:
            if isinstance(entry[1], ASN1Struct):
                obj = entry[1].st_2_asn1()
                d[entry[0]] = obj
            else:
                d[entry[0]] = entry[1]
        return (self.tuple_param0, d)
