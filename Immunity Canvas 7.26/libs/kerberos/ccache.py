#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  ccache.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import os
import sys
import struct
import logging

if "." not in sys.path:
    sys.path.append(".")

import helper
import protocol as proto

###
# Packing API
###

def pack_u8(data):
    return helper.pack_u8(data)

def pack_u16(data):
    return helper.pack_u16(data, little_endian=False)

def pack_u32(data):
    return helper.pack_u32(data, little_endian=False)

def pack_bytes(data):
    return helper.pack_bytes(data)

def pack_string(s):
    size = len(s)
    out = ''
    out += helper.pack_u32(size, little_endian=False)
    out += helper.pack_bytes(s)
    return out

###
# The 'CCacheKey' subclass
###

class CCacheKey(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def get_value(self):
        return repr(self['value'])

    def get_type(self):
        return repr(self['type'])

    def pack(self):
        try:
            out = ''
            out += pack_u16(self['type'])
            out += pack_u32(len(self['value']))
            out += pack_bytes(self['value'])
            return out
        except Exception as e:
            raise ValueError("CCacheKey.pack() failed: %s" % (str(e)))

    # Returns "type_str::repr(value)"
    def __str__(self):
        return repr([self['type'],self['value']])

###
# The 'CCacheCredential' subclass
###

class CCacheTimes(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def get_value(self):
        return [ self['authtime'], self['starttime'], self['endtime'], self['renew_till'] ]

    def pack(self):
        out = ''
        try:
            out += pack_u32(self['authtime'])
            out += pack_u32(self['starttime'])
            out += pack_u32(self['endtime'])
            out += pack_u32(self['renew_till'])
            return out
        except Exception as e:
            raise ValueError("CCacheTimes.pack() failed: %s" % (str(e)))

###
# The 'CCacheAddress' subclass
###

class CCacheAddress(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def pack(self):
        out = ''
        try:
            out += pack_u16(self['type'])
            out += pack_string(self['data'])
            return out
        except Exception as e:
            raise ValueError("CCacheAddress.pack() failed: %s" % (str(e)))

###
# The 'CCacheAuthdata' subclass
###

class CCacheAuthdata(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def pack(self):
        out = ''
        try:
            out += pack_u16(self['type'])
            out += pack_string(self['data'])
            return out
        except Exception as e:
            raise ValueError("CCacheAuthdata.pack() failed: %s" % (str(e)))

###
# The 'CCacheCredential' subclass
###

class CCacheCredential(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def get_service_principal(self):
        return self['server'].get_value()

    def get_client_principal(self):
        return self['client'].get_value()

    def get_session_key(self):
        return [ int(self['key']['type']), str(self['key']['value']) ]

    def get_ticket(self):
        return self['ticket']

    def get_times(self):
        return self['times'].get_value()

    def get_flags(self):
        return int(self['tktflags'])

    # Adaptation from krb5_is_config_principal C API.
    # Any error is considered a False.
    def is_config_credential(self):
        try:
            conf_realm = self['server'].get_realm()
            conf_name = self['server']['components'][0]
            if not conf_realm == 'X-CACHECONF:':
                return False
            if not conf_name == "krb5_ccache_conf_data":
                return False
            return True
        except Exception as e:
            return False

    def pack(self):
        try:
            out = ''
            out += self['client'].pack()
            out += self['server'].pack()
            out += self['key'].pack()
            out += self['times'].pack()
            out += pack_u8(self['is_skey'])
            out += pack_u32(self['tktflags'])
            num_address = len(self['addrs'])
            out += pack_u32(num_address)
            for addr in self['addrs']:
                out += addr.pack()
            num_authdata = len(self['authdata'])
            out += pack_u32(num_authdata)
            for auth in self['authdata']:
                out += auth.pack()
            out += pack_string(self['ticket'])
            out += pack_string(self['second_ticket'])
            return out
        except Exception as e:
            raise ValueError("CCacheCredential.pack() failed: %s" % (str(e)))

###
# The 'CCachePrincipal' subclass
###

class CCachePrincipal(dict):

    def __init__(self, *args, **kwargs):
        self.update(*args, **kwargs)

    def __str__(self):
        # Classic foo/bar@domain
        if self['name_type'] in [1,2]:
            if not self['realm']:
                return '<invalid_principal:no domain>'
            if not self['components']:
                return '<invalid_principal:no components>'
            return '/'.join(self['components'])+'@'+self['realm']
        return '<invalid_principal:invalid type>'

    def get_value(self):
        return [ '/'.join(self['components']), self['name_type'], self['realm'] ]

    def get_realm(self):
        return self['realm']

    def pack(self):
        try:
            out = ''
            out += pack_u32(self['name_type'])
            out += pack_u32(len(self['components']))
            out += pack_string(self['realm'])
            for component in self['components']:
                out += pack_string(component)
            return out
        except Exception as e:
            raise ValueError("CCachePrincipal.pack() failed: %s" % (str(e)))

###
# The CCache file handling class
###

# Note: Currently this is the only class with an extraction interface.

class CCache:

    def __init__(self):
        self.data = ''
        self.out = ''
        self.idx = 0
        self.dict = {}
        self.f = None

        # Can be useful to keep.
        self.domain = None

    # Extraction routines

    def extract_u8(self):
        s = helper.extract_u8(self.data, self.idx)
        self.idx += 1
        return s

    def extract_u16(self):
        s = helper.extract_u16(self.data, self.idx, little_endian=False)
        self.idx += 2
        return s

    def extract_u32(self):
        s = helper.extract_u32(self.data, self.idx, little_endian=False)
        self.idx += 4
        return s

    def extract_bytes(self, nbr_bytes):
        s = helper.extract_bytes(self.data, self.idx, nbr_bytes)
        self.idx += nbr_bytes
        return s

    # CCache (un)packing routines

    '''
    counted_octet_string {
        uint32_t length;
        uint8_t data[length];
    };
    '''

    def unpack_string(self):
        size = self.extract_u32()
        s = self.extract_bytes(size)
        return s

    '''
    NOTE: Practically speaking, it seems to be keylen = 32 bits on version 0x504

    keyblock {
             uint16_t keytype;
             uint16_t etype;                /* only present if version 0x0503 */
             uint16_t keylen;
             uint8_t keyvalue[keylen];
    };
    '''

    def unpack_keyblock(self):

        ktype = self.extract_u16()
        keylen = self.extract_u32()
        key = self.extract_bytes(keylen)
        return CCacheKey({'type':ktype, 'value':key})

    '''
    times {
          uint32_t  authtime;
          uint32_t  starttime;
          uint32_t  endtime;
          uint32_t  renew_till;
    };
    '''

    def unpack_times(self):

        authtime = self.extract_u32()
        starttime = self.extract_u32()
        endtime = self.extract_u32()
        renew_till = self.extract_u32()
        return CCacheTimes({'authtime':authtime,
                            'starttime':starttime,
                            'endtime':endtime,
                            'renew_till':renew_till})

    '''
    address {
            uint16_t addrtype;
            counted_octet_string addrdata;
    };
    '''

    def unpack_address(self):

        addrtype = self.extract_u16()
        addrdata = self.unpack_string()
        return CCacheAddress({'type':ktype,'data':addrdata})

    '''
    authdata {
             uint16_t authtype;
             counted_octet_string authdata;
    };
    '''

    def unpack_authdata(self):

        authtype = self.extract_u16()
        authdata = self.unpack_string()
        return CCacheAuthdata({'type':authtype, 'data':authdata})

    '''
    principal {
              uint32_t name_type;           /* not present if version 0x0501 */
              uint32_t num_components;      /* sub 1 if version 0x501 */
              counted_octet_string realm;
              counted_octet_string components[num_components];
    };
    '''

    def unpack_principal(self):

        name_type = self.extract_u32()
        num_components = self.extract_u32()
        realm = self.unpack_string()
        components = []
        for component in xrange(num_components):
            s = self.unpack_string()
            components.append(s)
        return CCachePrincipal({'name_type':name_type,
                                'realm':realm,
                                'components':components})

    '''
    credential {
               principal client;
               principal server;
               keyblock key;
               times    time;
               uint8_t  is_skey;            /* 1 if skey, 0 otherwise */
               uint32_t tktflags;           /* stored in reversed byte order */
               uint32_t num_address;
               address  addrs[num_address];
               uint32_t num_authdata;
               authdata authdata[num_authdata];
               countet_octet_string ticket;
               countet_octet_string second_ticket;
    };
    '''

    def unpack_credential(self):

        creds = CCacheCredential()
        creds['client'] = self.unpack_principal()
        creds['server'] = self.unpack_principal()
        creds['key'] = self.unpack_keyblock()
        creds['times'] = self.unpack_times()
        creds['is_skey'] = self.extract_u8()
        creds['tktflags'] = self.extract_u32()
        num_address = self.extract_u32()
        creds['addrs'] = []
        for i in xrange(num_address):
            creds['addrs'].append(self.unpack_address())
        num_authdata = self.extract_u32()
        creds['authdata'] = []
        for i in xrange(num_authdata):
            creds['authdata'].append(self.unpack_authdata())
        creds['ticket'] = self.unpack_string()
        creds['second_ticket'] = self.unpack_string()
        return creds

    def unpack_credentials(self):

        creds = []
        while self.idx < len(self.data):
            creds.append(self.unpack_credential())
        return creds

    def pack_credentials(self):

        creds = self.dict['credentials']
        for cred in creds:
            self.out += cred.pack()

    '''
    ccache {
    [...]
              uint16_t headerlen;           /* only if version is 0x0504 */
              header headers[];             /* only if version is 0x0504 */
    [...]
    };

    header {
           uint16_t tag;                    /* 1 = DeltaTime */
           uint16_t taglen;
           uint8_t tagdata[taglen]
    };
    '''

    def unpack_header(self):

        sig = self.extract_u16()
        hdrlen = self.extract_u16()

        if(len(self.data[self.idx:]) < hdrlen):
            logging.error("Headers are too small...")
            return None

        remaining = hdrlen
        hdrs = []
        while remaining > 0:
            tag = self.extract_u16()
            taglen = self.extract_u16()
            tagdata = self.extract_bytes(taglen)
            hdrs.append({'tag': tag, 'data': tagdata})
            remaining -= 4 + taglen

        header = {}
        header['sig'] = sig
        header['headerlen'] = hdrlen
        header['credential_headers'] = hdrs
        return header

    def pack_headers(self):

        headerlen = self.dict['header']['headerlen']
        self.out += pack_u16(headerlen)

        hdrs = self.dict['header']['credential_headers']
        for hdr in hdrs:
            self.out += pack_u16(hdr['tag'])
            self.out += pack_u16(len(hdr['data']))
            self.out += pack_bytes(hdr['data'])

    # Main unpacking routine!
    # It builds a dictionary of data

    def unpack(self):

        self.dict['header'] = self.unpack_header()
        if self.dict['header']['sig'] != 0x504:
            raise ValueError("CCache.unpack() failed: version != 0x504")

        self.dict['primary_principal'] = self.unpack_principal()
        self.dict['credentials'] = self.unpack_credentials()

    # Main packing routine!
    # It builds a string out of the internal dictionary of data

    def pack(self):

        try:
            self.out += pack_u16(self.dict['header']['sig'])
            self.pack_headers()
            self.out += self.dict['primary_principal'].pack()
            self.pack_credentials()
            return self.out
        except Exception as e:
            logging.error("CCache.pack() failed: %s" % (str(e)))
            return None

    # CCache important functions to open/create/write ccache files

    ## Quite static right now :D
    def build_header(self, headerlen=12, sig=0x504):

        header = {}
        header['sig'] = sig
        header['headerlen'] = headerlen
        header['credential_headers'] = [{'tag': 1,
                                         'data': '\x00\x00\x00\x01\x00\x00\x00\x00'}]
        return header

    def set_header(self, client_principal, domain):

        self.domain = domain
        self.dict['header'] = self.build_header()
        self.dict['primary_principal'] = proto.PrincipalName(client_principal).export()
        self.dict['credentials'] = []

    def import_creds(self, client, server, session_key, times, tktflags=0x50000000, is_skey=0, ticket='', addrs=[], authdata=[], cut=1):

        times = CCacheTimes({'authtime': times[0],
                            'starttime': times[1],
                            'endtime': times[2],
                            'renew_till': times[3]})
        creds = CCacheCredential()
        creds['client'] = proto.PrincipalName(client).export()
        creds['server'] = proto.PrincipalName(server).export()
        creds['key'] = proto.EncryptionKey(session_key).export()
        creds['times'] = times
        creds['is_skey'] = is_skey
        creds['tktflags'] = tktflags
        creds['addrs'] = []
        creds['authdata'] = []
        if cut:
            creds['ticket'] = ticket[4:]
        else:
            creds['ticket'] = ticket
        creds['second_ticket'] = ''
        self.add_credentials(creds)

    def set_raw_data(self, data):
        self.data = data
        self.unpack()

    def open(self, filename, new=0):
        try:
            O_BINARY = getattr(os, 'O_BINARY', 0)
            self.f = os.fdopen(os.open(filename, os.O_RDWR|os.O_CREAT|O_BINARY, 0600), 'w+b')
            if new:
                self.f.truncate(0)
            else:
                self.data = self.f.read()
                if self.data:
                    self.unpack()
        except Exception as e:
            raise ValueError("CCache.open() failed: %s" % str(e))

    def write(self, fname=None, close=1):
        try:
            if not self.f:
                if not fname:
                    return
                else:
                    O_BINARY = getattr(os, 'O_BINARY', 0)
                    self.f = os.fdopen(os.open(fname, os.O_RDWR|os.O_CREAT|O_BINARY, 0600), 'wb')
            self.f.write(str(self.pack()))
            if close:
                self.f.close()
                self.f = None
        except Exception as e:
            raise ValueError("CCache.write() failed: %s" % str(e))

    # Show() related routines

    def show(self):

        s  = "===== HEADER =====\n"
        s += "%s\n" % str(self.dict['header'])
        s += "===== PRIMARY PRINCIPAL =====\n"
        s += "%s\n" % str(self.dict['primary_principal'])
        for cred in self.dict['credentials']:
            s += "===== CRED =====\n"
            s += "%s\n" % str(cred)
        logging.info(s)

    # Useful functions of the API.
    # They are mainly getters/setters

    def get_primary_principal(self):
        return str(self.dict['primary_principal'])

    def get_keys(self):
        keys = []
        creds = self.dict['credentials']
        for cred in creds:
            if cred['key']:
                keys.append(cred['key']['value'])
        return keys

    def get_servernames(self):
        srv = []
        creds = self.dict['credentials']
        for cred in creds:
            srv.append(str(cred['server']))
        return srv

    def get_tickets(self):
        tickets = []
        creds = self.dict['credentials']
        for cred in creds:
            tickets.append(cred['ticket'])
        return tickets

    # server_principal must be [ 'foo/bar', type, realm ]
    def get_credentials(self, server_principal=None):
        creds = self.dict['credentials']
        if not server_principal:
            return creds
        L = []
        given_name = server_principal[0].upper()
        given_type = server_principal[1]
        given_realm = server_principal[2].upper()
        for cred in creds:
            n,t,r = cred.get_service_principal()
            if n.upper() != given_name:
                continue
            # Logically we should check this as well.
            # But because of ms14-068 we do not. This will not prevent other
            # applications from working fine anyway.
            #if t != given_type:
            #    continue
            if r.upper() != given_realm:
                continue
            L.append(cred)
        return L

    def set_credentials(self, creds):
        self.dict['credentials'] = creds

    def add_credentials(self, creds):
        self.dict['credentials'].append(creds)

    def get_ticket(self, server_name):
        srvs = self.get_servernames()
        tickets = self.get_tickets()
        for i in xrange(len(srvs)):
            if srvs[i] == server_name:
                return tickets[i]
        return []

    def set_ticket(self, server_name, ticket):
        srvs = self.get_servernames()
        creds = self.get_credentials()
        for i in xrange(len(srvs)):
            if srvs[i] == server_name:
                creds[i]['ticket'] = ticket
        self.set_credentials(creds)
