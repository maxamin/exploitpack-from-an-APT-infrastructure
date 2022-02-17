#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  epmap_ng.py
## Description:
##            :
## Created_On :  Tue Aug 14 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

# The API is not 100% written but is currently working quite well.
# Implemented from Wireshark && [MS-RPCE].pdf
# URL: https://msdn.microsoft.com/en-us/library/cc243560.aspx

# Confirmed working with:
#    Windows 7 SP 1
#    Windows 2008 R2
#    Windows 2012 R2
#    Windows 2016

import sys
import struct
import uuid
import logging
from struct import pack, unpack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libdcerpc import RPC_C_EP_ALL_ELTS, RPC_C_VERS_ALL
from libs.newsmb.libdcerpc import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from libs.newsmb.libdcerpc import DCERPC
from libs.newsmb.Struct import Struct

###
# Constants
###

# The RPC methods
EPMAP_COM_INSERT             = 0x0
EPMAP_COM_DELETE             = 0x1
EPMAP_COM_LOOKUP             = 0x2
EPMAP_COM_MAP                = 0x3
EPMAP_COM_LOOKUP_HANDLE_FREE = 0x4
EPMAP_COM_INQ_OBJECT         = 0x5
EPMAP_COM_MGMT_DELETE        = 0x6

# PROTO ID (EptFloor class)
EPMAP_PROTO_ID_TCP_PORT         = 0x07
EPMAP_PROTO_ID_UDP_PORT         = 0x08
EPMAP_PROTO_ID_IP_ADDR          = 0x09
EPMAP_PROTO_ID_RPC_CON_LESS     = 0x0a
EPMAP_PROTO_ID_RPC_CON_ORIENTED = 0x0b
EPMAP_PROTO_ID_NETBEUI          = 0x0c
EPMAP_PROTO_ID_UUID             = 0x0d
EPMAP_PROTO_ID_NAMEDPIPE        = 0x0f
EPMAP_PROTO_ID_NAMEDPIPES       = 0x10
EPMAP_PROTO_ID_NETBIOS          = 0x11
EPMAP_PROTO_ID_HTTP             = 0x1f

###
# EPT Objects.
# No exception handling for these objects.
###


'''
http://pubs.opengroup.org/onlinepubs/9629399/toc.pdf:

Protocol Tower. The network representation of network addressing
information (e.g., RPC bindings).

typedef struct {
    unsigned32 tower_length;
    [size_is(tower_length)]
    byte tower_octet_string[];
} twr_t, *twr_p_t;
'''

class EptFloorGeneric(Struct):
    st = [
        [ 'data1', '0s', ''],
        [ 'data2', '0s', ''],
    ]

    def __init__(self, data):
        Struct.__init__(self, data1, data2)

        self['data1'] = data1
        self['data2'] = data2

    def pack(self):
        data   = self['data1']
        data  += self['data2']
        return data

class EptFloor(Struct):
    st = [
        ['lhs_length', '<H', 0 ],
        ['proto_id',   '<B', 0 ],
        ['data1',      '0s', ''],
        ['rhs_length', '<H', 0 ],
        ['data2',      '0s', ''],
    ]

    def __init__(self, data=None, proto_id=0, data1='', data2=''):
        Struct.__init__(self, data)

        if data is None:
            self['proto_id'] = proto_id
            self['lhs_length'] = 1 + len(data1)
            self['data1'] = data1
            self['rhs_length'] = 1 + len(data2)
            self['data2'] = data2

        else:
            off = 2
            self['data1'] = data[off+1:off+1+(self['lhs_length']-1)]
            off += self['lhs_length']
            self['rhs_length'] = struct.unpack('<H', data[off:off+2])[0]
            off += 2
            self['data2'] = data[off:off+self['rhs_length']]

    def get_proto_id(self):
        return self['proto_id']

    def get_data1(self):
        return self['data1']

    def get_data2(self):
        return self['data2']

    def pack(self):
        data  = struct.pack('<H', self['lhs_length'])
        data += struct.pack('B', self['proto_id'])
        data += self['data1']
        data += struct.pack('<H', self['rhs_length'])
        data += self['data2']
        return data


class EptTower(Struct):
    st = [
        ['tower_length', '<L', 0],
        ['_length',      '<L', 0],
        ['_nr_floors',   '<H', 0],
        ['floors',       '0s', ''],
    ]

    def __init__(self, data=None, floors=None):
        Struct.__init__(self, data)

        logging.debug("EptTower(%s)" % data.encode('hex')[:64])

        if data is not None:
            off = 10
            self['floors'] = []
            for i in xrange(self['_nr_floors']):
                floor = EptFloor(data=data[off:])
                self['floors'].append(floor)
                off += len(floor.pack())

        else:
            if floors is not None:
                self['floors'] = floors
                self['_nr_floors'] = len(floors)
                floors_packed = ''
                for floor in floors:
                    floors_packed += floor.pack()
                self['tower_length'] = len(floors_packed)
                self['_length'] = len(floors_packed)

    def get_floors(self):
        return self['floors']

    def pack(self):
        data  = Struct.pack(self)
        for floor in self['floors']:
            data += floor.pack()

        if (len(data) % 4) != 0:
            data += '\0' * (4 - (len(data) % 4))

        return data


'''
const long ept_max_annotation_size = 64;
typedef struct
{
    uuid_t object;
    twr_p_t tower;
    [string] char annotation[ept_max_annotation_size];
} ept_entry_t, *ept_entry_p_t;
'''

class EptAnnotation(Struct):
    st = [
        ['offset',     '<L', 0],
        ['length',     '<L', 0],
        ['annotation', '0s', ''],
    ]

    def __init__(self, data=None, annotation=''):
        Struct.__init__(self, data)

        if data is None:
            self['length'] = len(annotation) + 1
            self['annotation'] = annotation + '\0'
            # All the structure is aligned on 4 bytes
            if (len(self['annotation']) % 4) != 0:
                self['annotation'] += '\0' * (4 - (len(self['annotation']) % 4))
        else:
            off = 8
            self['annotation'] = data[off:off+self['length']]

    def pack(self):
        data  = Struct.pack(self)
        data += self['annotation']
        if (len(self['annotation']) % 4) != 0:
            data += '\0' * (4 - (len(self['annotation']) % 4))

        return data

class EptEntry(Struct):
    st = [
        ['object',     '16s', '\0'*20],
        ['tower_ptr',   '<L',  0],
        ['annotation', '0s',  ''],
        ['tower',      '0s',  ''],
    ]

    def __init__(self, data=None, tower=None, annotation=None):
        Struct.__init__(self, data)

        logging.debug("EptEntry(%s)" % data.encode('hex')[:64])

        if data is not None:
            off = 20
            annotation = EptAnnotation(data=data[off:])
            self['annotation'] = annotation
            off += len(annotation.pack())

    def get_annotation_as_str(self):
        annotation = self['annotation']
        return annotation['annotation'][:-1]

    def add_tower(self, tower):
        self['tower'] = tower

    def get_tower(self):
        return self['tower']

    def get_object(self):
        return self['object']

    def pack(self):
        data  = Struct.pack(self)
        data += self['annotation'].pack()
        return data


class EptEntryArray(Struct):
    st = [
        ['max_ents',     '<L', 0],
        ['offset',       '<L', 0],
        ['num_ents',     '<L', 0],
        ['entries',      '0s', ''],
    ]

    def __init__(self, data=None, tower=None, annotation=None):
        Struct.__init__(self, data)

        logging.debug("EptEntryArray(%s)" % data.encode('hex')[:64])

        if data is not None:

            off = 12
            self['entries'] = []
            for i in xrange(self['num_ents']):

                entry = EptEntry(data=data[off:])
                off += len(entry.pack())
                self['entries'].append(entry)

            for entry in self['entries']:
                tower = EptTower(data=data[off:])
                off += len(tower.pack())
                entry.add_tower(tower)

    def get_entries(self):
        return self['entries']

    def pack(self):
        data  = Struct.pack(self)
        for i in xrange(len(self['entries'])):
            entry = self['entries'][i]
            data += entry.pack()
        for i in xrange(len(self['entries'])):
            entry = self['entries'][i]
            tower = entry.get_tower()
            if tower:
                data += tower.pack()
        return data


###
# Handlers
# No exception handling for these objects.
###

# Opnum 2
'''
void ept_lookup(
    [in] handle_t hEpMapper,
    [in] unsigned long inquiry_type,
    [in, ptr] UUID* object,
    [in, ptr] RPC_IF_ID* Ifid,
    [in] unsigned long vers_option,
    [in, out] ept_lookup_handle_t* entry_handle,
    [in, range(0,500)] unsigned long max_ents,
    [out] unsigned long* num_ents,
    [out, length_is(*num_ents), size_is(max_ents)]
    ept_entry_t entries[],
    [out] error_status* status
);
'''

class EptLookupRequest(Struct):
    '''
    Basic implementation of the EptLookup() as we do not handle objects and such.
    '''
    st = [
        ['inquiry_type', '<L',  RPC_C_EP_ALL_ELTS],
        ['object',       '<L',  0],
        ['Ifid',         '<L',  0],
        ['vers_option',  '<L',  RPC_C_VERS_ALL],
        ['entry_handle', '20s', '\0'*20],
        ['max_ents',     '<L',  500],
    ]

    def __init__(self, data=None, inquiry_type=RPC_C_EP_ALL_ELTS, max_entries=500):
        Struct.__init__(self, data)
        if data is None:
            self['inquiry_type'] = inquiry_type
            self['max_ents'] = max_entries

    def pack(self):
        data = Struct.pack(self)
        return data

class EptLookupResponse(Struct):
    '''
    Basic parsing of the EptLookup() answers.
    '''
    st = [
        ['entry_handle', '20s', '\0'*20],
        ['num_ents',     '<L',  0],
        ['entries',      '0s',  0],
        ['status',       '<L',  0],
    ]

    def __init__(self, data=None, entries=None, status=0):
        Struct.__init__(self, data=None)
        if data is None:
            self['entries'] = entries
            self['num_ents'] = len(entries)
            self['status'] = status

        else:
            off  = 20 + 4
            entries = EptEntryArray(data=data[off:])
            self['entries'] = entries
            off += len(entries.pack())
            self['status'] = struct.unpack('<L', data[off:off+4])[0]

    def get_nr_entries(self):
        return self['num_ents']

    def get_entries(self):
        return self['entries'].get_entries()

    def pack(self):
        data  = self['entry_handle']
        data += struct.pack('<L', self['num_ents'])
        data += self['entries'].pack()
        data += struct.pack('<L', self['status'])
        return data


#######################################################################
#####
##### Exception classes
#####
#######################################################################

class EPTException(Exception):
    """
    Base class for all EPT-specific exceptions.
    """
    def __init__(self, message=''):
        self.message = message

    def __str__(self):
        return '[ EPT_ERROR: %s ]' % (self.message)

class EPTException2(Exception):
    """
    Improved version of the base class to track errors.
    """
    def __init__(self, message='', status=None):
        self.message = message
        self.status = status

    def __str__(self):
        if not self.status:
            return '[ EPT_ERROR: %s ]' % (self.message)
        else:
            return '[ EPT_ERROR: %s (0x%x) ]' % (self.message, self.status)

class EPTLookupException(EPTException):
    """
    Raised when ept_lookup() fails.
    """
    pass

class EPTLookupAccessDeniedException(EPTException2):
    """
    Raised when credentials are incorrect / or not enough.
    """
    def __init__(self):
        self.message = 'ept_lookup() failed: Access Denied.'
        self.status = 5

#######################################################################
#####
##### Main classes: EPT, EPTClient (EPTServer will not be implemented)
##### API will raise specific exceptions when errors are caught.
#######################################################################


class EPT():
    def __init__(self, host, port):
        self.host              = host
        self.port              = port
        self.is_unicode        = True
        self.policy_handle     = None
        self.uuid              = (u'e1af8308-5d1f-11c9-91a4-08002b14a0fa', u'3.0')

class EPTClient(EPT):

    def __init__(self, host, port=135):
        EPT.__init__(self, host, port)
        self.username = None
        self.password = None
        self.domain = None
        self.kerberos_db = None
        self.use_krb5 = False

    def set_credentials(self, username=None, password=None, domain=None, kerberos_db=None, use_krb5=False):
        if username:
            self.username = username
        if password:
            self.password = password
        if domain:
            self.domain = domain
        if kerberos_db:
            self.kerberos_db = kerberos_db
            self.use_krb5 = True
        else:
            if use_krb5:
                self.use_krb5 = use_krb5

    def __bind_krb5(self, connector):

        try:
            self.dce = DCERPC(connector,
                              getsock=None,
                              username=self.username,
                              password=self.password,
                              domain=self.domain,
                              kerberos_db=self.kerberos_db,
                              use_krb5=True)

            return self.dce.bind(self.uuid[0], self.uuid[1], RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        except Exception as e:
            return 0

    def __bind_ntlm(self, connector):

        try:
            self.dce = DCERPC(connector,
                              getsock=None,
                              username=self.username,
                              password=self.password,
                              domain=self.domain)

            return self.dce.bind(self.uuid[0], self.uuid[1], RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY)
        except Exception as e:
            return 0

    def __bind(self, connector):

        if self.use_krb5:
            ret = self.__bind_krb5(connector)
            if not ret:
                return self.__bind_ntlm(connector)
        else:
            ret = self.__bind_ntlm(connector)
            if not ret:
                return self.__bind_krb5(connector)
        return 1

    def bind(self):
        """
        Perform a binding with the server.
        0 is returned on failure.
        """

        connector = u'ncacn_ip_tcp:%s[%d]' % (self.host, self.port)

        ret = self.__bind(connector)
        if ret:
            return 1
        else:
            return 0

    def get_reply(self):
        return self.dce.reassembled_data

    def ept_lookup(self, max_entries=500):
        '''
        Returns an array of entries
        '''

        lookupreq = EptLookupRequest(max_entries=max_entries).pack()
        self.dce.call(EPMAP_COM_LOOKUP, lookupreq, response=True)
        data = self.get_reply()

        if not len(data):
            raise EPTLookupException('Empty data returned')

        status = unpack('<L', data[-4:])[0]
        if status != 0:
            logging.debug('ept_lookup() response status is: %x' % status)
            raise EPTLookupException('Failed with error = 0x%x' % status)

        lookupresp = EptLookupResponse(data=data)
        entries = lookupresp.get_entries()
        return entries

    def convert_entries(self, entries):
        '''
        Convert the entries into a dictionary that is compatible with EPMAP.dump()
        where EPMAP is the old interface.
        '''

        if entries is None or not len(entries):
            return None

        results = []
        for entry in entries:

            try:
                annot = entry.get_annotation_as_str()
                obj = entry.get_object()
                floors = entry.get_tower().get_floors()

                result = {}
                result['annotation'] = annot
                result['annotation length'] = len(annot) + 1         # For compatibility only.
                                                                     # This field is absolutely useless
                                                                     # and 'annotation' was even missing
                                                                     # in the previous version 

                for i in xrange(len(floors)):
                    # http://pubs.opengroup.org/onlinepubs/9629399/toc.pdf
                    # p684
                    f = floors[i]
                    proto_id = f.get_proto_id()
                    data1 = f.get_data1()
                    data2 = f.get_data2()

                    if proto_id == EPMAP_PROTO_ID_UUID:
                        major = struct.unpack('<H', data1[16:18])[0]
                        minor = struct.unpack('<H', data2[:2])[0]
                        # With two consecutive UUID, only the first one is interesting
                        if not i:
                            result['uuid'] = data1[:16]
                            result['version'] = major

                    # RPC addresses are not recorded.
                    elif proto_id in [EPMAP_PROTO_ID_RPC_CON_LESS, EPMAP_PROTO_ID_RPC_CON_ORIENTED]:
                        pass

                    elif proto_id == EPMAP_PROTO_ID_NAMEDPIPE:
                        np_str = data2.rstrip('\0')
                        result['np'] = unicode(np_str)

                    elif proto_id == EPMAP_PROTO_ID_NETBIOS:
                        netbios_str = data2.rstrip('\0')
                        result['netbios'] = unicode(netbios_str)

                    elif proto_id == EPMAP_PROTO_ID_NAMEDPIPES:
                        result['ncalrpc'] = unicode(data2.rstrip('\0'))

                    elif proto_id == EPMAP_PROTO_ID_IP_ADDR:
                        ip_str = u'%s.%s.%s.%s' % (ord(data2[0]),
                                                ord(data2[1]),
                                                ord(data2[2]),
                                                ord(data2[3]))
                        result['ip'] = ip_str

                    elif proto_id == EPMAP_PROTO_ID_TCP_PORT:
                        tcp_port = struct.unpack('>H', data2[:2])[0]
                        result['tcp'] = tcp_port

                    elif proto_id == EPMAP_PROTO_ID_UDP_PORT:
                        udp_port = struct.unpack('>H', data2[:2])[0]
                        result['udp'] = udp_port

                    # NETBEUI addresses are not recorded.
                    elif proto_id == EPMAP_PROTO_ID_NETBEUI:
                        pass

                    elif proto_id == EPMAP_PROTO_ID_HTTP:
                        http_port = struct.unpack('>H', data2[:2])[0]
                        result['http'] = http_port

                    # Do we have a parsing error? Probably not thus it's interesting
                    # to dump this proto_id. This might require an update.
                    else:
                        logging.warning('Weird proto_id: %s' % proto_id)

                result['handle'] = '\0' * 20
                results.append(result)

            except Exception as e:
                logging.warn('Parsing error, skipping current entry: %s', str(e))
                continue

        return results


#######################################################################
#####
##### Compatibility layer
#####
#######################################################################

class EPTHandle:
    def __init__(self, handle_dict=None):
        self.handle_dict = handle_dict

        if self.handle_dict == None:
            self.handle_dict = {}
            self.handle_dict['handle'] =  '\0'*20

    def getuuid(self):
        return uuid.UUID(bytes_le = self.handle_dict['uuid'])

    def getversion(self):
        return self.handle_dict.get('version')

    def get_type_info(self):
        type_info = ''

        if 'tcp' in self.handle_dict:
            type_info += u'tcp:%d:' % self.handle_dict['tcp']

        if 'udp' in self.handle_dict:
            type_info += u'udp:%d:' % self.handle_dict['udp']

        if 'netbios' in self.handle_dict:
            type_info += u'netbios:%s:' % self.handle_dict['netbios']

        if 'np' in self.handle_dict:
            type_info += u'namedpipe:%s:' % self.handle_dict['np']

        if 'http' in self.handle_dict:
            type_info += u'http:%s:' % self.handle_dict['http']

        if 'ip' in self.handle_dict:
            type_info += u'ip:%s:' % self.handle_dict['ip']

        if 'ncalrpc' in self.handle_dict:
            type_info += u'ncalrpc:%s:' % self.handle_dict['ncalrpc']

        return type_info


    def getinfo(self):
        u         = self.getuuid()
        version   = self.getversion()
        type_info = self.get_type_info()

        return u'%s:%d:%s' % (u, version, type_info)

    def getendpoint(self, ip):
        """
        Gets a nicely displayed and compatible endpoint.
        ip argument is only used when it is not provided internally, for named pipes.
        """
        if 'tcp' in self.handle_dict:
            return u'ncacn_ip_tcp:%s[%d]' % (self.handle_dict['ip'],
                                             self.handle_dict['tcp'])
        elif 'udp' in self.handle_dict:
            return u'ncacn_ip_udp:%s[%d]' % (self.handle_dict['ip'],
                                             self.handle_dict['udp'])
        elif 'np' in self.handle_dict:
            return u'ncacn_np:%s[%s]' % (ip, self.handle_dict['np'])
        elif 'http' in self.handle_dict:
            return u'ncacn_http:%s[%d]' % (self.handle_dict['ip'],
                                           self.handle_dict['http'])
        elif 'ncalrpc' in self.handle_dict:
            return u'ncalrpc:[%s]' % self.handle_dict['ncalrpc']
        else:
            return u''

    def isUUID(self, UUID):
        UUID = assert_unicode(UUID)
        return UUID == unicode(uuid.UUID(bytes_le=self.handle_dict['uuid']))

    def isRemote(self):
        return self.isHTTP() or self.isNP() or self.isTCP() or self.isUDP()

    def isTCP(self):
        return 'tcp' in self.handle_dict

    def isUDP(self):
        return 'udp' in self.handle_dict

    def isNP(self):
        return 'np' in self.handle_dict

    def isHTTP(self):
        return 'http' in self.handle_dict

    def __str__(self):
        return self.getendpoint(self.handle_dict['ip'])


#######################################################################
#####
##### A couple of useful functions for other parts of CANVAS
#####
#######################################################################

def dump(host, username=None, password=None, domain=None, kerberos_db=None, use_krb5=False):

    ept = EPTClient(host)

    # Just in case
    ept.set_credentials(
        username=username,
        password=password,
        domain=domain,
        kerberos_db=kerberos_db,
        use_krb5=use_krb5)

    if not ept.bind():
        logging.error("bind() failed.")
        return None

    entries = ept.ept_lookup()
    return ept.convert_entries(entries)

#######################################################################
#####
##### Well, the main :D
#####
#######################################################################

TARGET_IP = '192.168.50.122'

def call_every_op():

    ept = EPTClient(TARGET_IP)

    if not ept.bind():
        logging.error("bind() failed.")
        return

    for op in xrange(256):
        logging.info('Sending OP=%d' % op)
        ept.dce.call(op, "A"*200, response=True)


def main():

    call_every_op()
    results = dump(TARGET_IP)
    for res in results:
        print res

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    main()
