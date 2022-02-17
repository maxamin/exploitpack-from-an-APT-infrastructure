#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  srvsvc.py
## Description:
##            :
## Created_On :  Tue Sep 8 CEST 2015
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

# The API is not 100% written but is currently working quite well.
# Implemented from Wireshark && [MS-SRVS].pdf

# Confirmed working with:
#    Windows 2003
#    Windows 2008 R2
#    Windows 7
#    Windows 2012

import sys
import logging
from struct import pack, unpack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.libdcerpc import DCERPC, DCERPCString, DCERPCSid
from libs.newsmb.libdcerpc import RPC_C_AUTHN_WINNT, RPC_C_AUTHN_LEVEL_PKT_INTEGRITY
from libs.newsmb.Struct import Struct

###
# Constants
###

# The RPC methods
SRVSVC_COM_NET_CONN_ENUM = 8
SRVSVC_COM_NET_FILE_ENUM = 9
SRVSVC_COM_NET_FILE_GET_INFO = 10
SRVSVC_COM_NET_FILE_CLOSE = 11
SRVSVC_COM_NET_SHARE_ENUM_ALL = 15
SRVSVC_COM_NET_SHARE_GET_INFO = 16
SRVSVC_COM_NET_SRV_GET_INFO = 21
SRVSVC_COM_NET_DISK_ENUN = 23

###
# SRVSVC Objects.
# No exception handling for these objects.
###


class ResumeHandle(Struct):
    st = [
        ['RefId', '<L', 0x2006],
        ['Pointer', '<L', 0],
    ]

    def __init__(self, data=None, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)

    def pack(self):
        data = Struct.pack(self)
        return data


class NetShareInfo0(Struct):
    st = [
        ['RefID', '<L', 0x2005 ],
        ['MaxCount', '<L', 0 ]
    ]

    def __init__(self, data=None, ShareArray=[]):
        Struct.__init__(self, data)
        self.shares = []

        if data is not None:
            pos = self.calcsize()
            for i in xrange(self['MaxCount']):
                refptr = unpack('<L', data[pos:pos+4])[0]
                pos += 4
                self.shares.append({'type':-1, 'comment':''})
            for i in xrange(self['MaxCount']):
                s = DCERPCString(data=data[pos:])
                self.shares[i]['name'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
                pos += len(s.pack())
        else:
            self.shares = ShareArray
            self['MaxCount'] = len(self.shares)

    def pack(self):

        data =Struct.pack(self)
        for i in xrange(self['MaxCount']):
            data += pack('<L', 0x20010+i*4)
        for i in xrange(self['MaxCount']):
            data += DCERPCString(string=self.shares[i]['name'].encode('UTF-16LE'), is_unicode=True).pack()
        return data

    def get_shares(self):
        return self.shares

class NetShareInfo1(Struct):
    st = [
        ['RefID', '<L', 0x2005 ],
        ['MaxCount', '<L', 0 ]
    ]

    def __init__(self, data=None, ShareArray=[]):
        Struct.__init__(self, data)
        self.shares = []

        if data is not None:
            pos = self.calcsize()
            for i in xrange(self['MaxCount']):
                refptr = unpack('<L', data[pos:pos+4])[0]
                pos += 4
                stype = unpack('<L', data[pos:pos+4])[0]
                pos += 4
                self.shares.append({'type' : stype})
                refptr2 = unpack('<L', data[pos:pos+4])[0]
                pos += 4
            for i in xrange(self['MaxCount']):
                s = DCERPCString(data=data[pos:])
                self.shares[i]['name'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
                pos += len(s.pack())
                s2 = DCERPCString(data=data[pos:])
                self.shares[i]['comment'] = s2.get_string().decode('UTF-16LE').encode('ascii')[:-1]
                pos += len(s2.pack())
        else:
            self.shares = ShareArray
            self['MaxCount'] = len(self.shares)

    def pack(self):

        data =Struct.pack(self)
        for i in xrange(self['MaxCount']):
            data += pack('<L', 0x20010+i*4)
            data += pack('<L', self.shares[i]['type'])
            data += pack('<L', 0x20100+i*4)
        for i in xrange(self['MaxCount']):
            data += DCERPCString(string=self.shares[i]['name'].encode('UTF-16LE'), is_unicode=True).pack()
            data += DCERPCString(string=self.shares[i]['comment'].encode('UTF-16LE'), is_unicode=True).pack()
        return data

    def get_shares(self):
        return self.shares


class NetShareCtr(Struct):
    st = [
        ['Ctr', '<L', 0 ],
        ['RefPtr', '<L', 0x2004 ],
        ['EntriesRead', '<L', 0 ],
        ['NetShareInfo', '0s', '' ],
    ]

    def __init__(self, data=None, Level=0, Entries=[]):
        Struct.__init__(self, data)
        self.Entries = []
        self['Ctr'] = Level

        if data is not None:
            pos = 12
            if self['Ctr'] == 0:
                self['NetShareInfo'] = NetShareInfo0(data=data[pos:])
            if self['Ctr'] == 1:
                self['NetShareInfo'] = NetShareInfo1(data=data[pos:])
        else:
            self.Entries = Entries
            self['EntriesRead'] = len(Entries)
            if self['EntriesRead']:
                if self['Ctr'] == 0:
                    self['NetShareInfo'] = NetShareInfo0(ShareArray=Entries)
                if self['Ctr'] == 1:
                    self['NetShareInfo'] = NetShareInfo1(ShareArray=Entries)

    def pack(self, pack_header=1, pack_string=0, force_null_byte=1):

        data  = pack('<L', self['Ctr'])
        data += pack('<L', self['RefPtr'])
        data += pack('<L', self['EntriesRead'])
        if not self['EntriesRead']:
            data += pack('<L', 0)
        else:
            data += self['NetShareInfo'].pack()
        return data

    def get_shares(self):
        return self['NetShareInfo'].get_shares()

###
# Handlers
# No exception handling for these objects.
###

# Opnum 16
'''
NET_API_STATUS NetrShareGetInfo(
 [in, string, unique] SRVSVC_HANDLE ServerName,
 [in, string] WCHAR* NetName,
 [in] DWORD Level,
 [out, switch_is(Level)] LPSHARE_INFO InfoStruct
);
'''

class NetrShareGetInfoRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['NetName', '0s', ''],
        ['Level', '<L', 2], # TODO: level!=2
    ]
    def __init__(self, data=None, ServerName='', NetName=''):
        Struct.__init__(self, data)
        if data is not None:
            ## TODO
            pass
        else:
            self['ServerName'] = ServerName.encode('UTF-16LE')
            self['NetName'] = NetName.encode('UTF-16LE')

    def pack(self):
        if len(self['ServerName']):
            data = pack('<L', 0x20004)
            data += DCERPCString(string = self['ServerName']).pack()
        else:
            data = pack('<L', 0) # Null Ptr

        data += DCERPCString(string = self['NetName']).pack()

        data += pack('<L', self['Level'])
        return data

class NetrShareGetInfoResponse(Struct):
    st = [
        ['Level', '<L', 0],
        ['NetShareInfo', '0s', '' ],
    ]

    def __init__(self, data):
        Struct.__init__(self, data)

        if data is not None:

            pos = 0
            self['Level'] = unpack('<L', data[pos:pos+4])[0]
            pos+=4
            if self['Level']!=2:
                raise Exception("NetrShareGetInfoResponse: level %d is not supported"%self['Level'])
            self['NetShareInfo'] = NetShareInfo2(data=data[pos:])
        else:
            pass ## TODO

    def pack(self):
        pass ## TODO

    def get_info(self):
        return self['NetShareInfo'].get_info()

class NetShareInfo2(Struct):
    st = [
        ['RefID', '<L', 0x2005 ],
        ['NetName', '0s', '' ],
        ['Type', '<L', 0 ],
        ['Comment', '0s', '' ],
        ['Permission', '<L', 0 ],
        ['MaxUses', '<L', 0 ],
        ['CurrentUses', '<L', 0 ],
        ['Path', '0s', '' ],
        ['Passwd', '0s', '' ],
    ]

    def __init__(self, data=None, ShareArray=[]):
        Struct.__init__(self, data)
        self.shares = []

        if data is not None:
            pos = 0
            refptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            refptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['Type'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            refptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['Permission'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['MaxUses'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['CurrentUses'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            refptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            refptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4

            s = DCERPCString(data=data[pos:])
            self['NetName'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
            pos += len(s.pack())
            s = DCERPCString(data=data[pos:])
            self['Comment'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
            pos += len(s.pack())
            s = DCERPCString(data=data[pos:])
            self['Path'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
            pos += len(s.pack())
            s = DCERPCString(data=data[pos:])
            self['Passwd'] = s.get_string().decode('UTF-16LE').encode('ascii')[:-1]
            pos += len(s.pack())
        else:
            pass ## TODO

    def pack(self):
        pass ## TODO

    def get_info(self):
        return {'Comment':self['Comment'], 'Type':self['Type'], 'Passwd':self['Passwd'],'Path':self['Path'], 'Permission':self['Permission'], 'MaxUses':self['MaxUses'], 'CurrentUses':self['CurrentUses'], 'NetName':self['NetName']}

# Opnum 15

'''
NET_API_STATUS
     NetrShareEnum (
         [in,string,unique] SRVSVC_HANDLE ServerName,
         [in,out] LPSHARE_ENUM_STRUCT InfoStruct,
         [in] DWORD PreferedMaximumLength,
         [out] DWORD * TotalEntries,
         [in,out,unique] DWORD * ResumeHandle
     );
'''

class NetrShareEnumRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['Level', '<L', 0],
        ['NetShareCtr', '0s', ''],
        ['PrefMaxLen', '<L', 4096],
        ['ResumeHandle', '0s', '']
    ]

    def __init__(self, data=None, ServerName='', Level=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            ### TODO
            pass
        else:
            if len(ServerName):
                self['ServerName'] = ServerName.encode('UTF-16LE')
            self['Level'] = Level
            self['NetShareCtr'] = NetShareCtr(Level=Level)
            self['ResumeHandle'] = ResumeHandle()

    def pack(self):

        if len(self['ServerName']):
            data = pack('<L', 0x20004)
            data += DCERPCString(string = self['ServerName']).pack()
        else:
            data = pack('<L', 0) # Null Ptr
        data += pack('<L', self['Level'])
        data += self['NetShareCtr'].pack()
        data += pack('<L', self['PrefMaxLen'])
        data += self['ResumeHandle'].pack()
        return data


class NetrShareEnumResponse(Struct):
    st = [
        ['Level', '<L', 0],
        ['NetShareCtr', '0s', ''],
        ['TotalEntries', '<L', 0],
        ['ResumeHandle', '0s', ''],
    ]

    def __init__(self, data=None, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 4
            self['NetShareCtr'] = NetShareCtr(data=data[pos:], Level=self['Level'])
            pos += len(self['NetShareCtr'].pack())
            self['TotalEntries'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['ResumeHandle'] = ResumeHandle(data=data[pos:]).pack()
        else:
            self['NetShareCtr'] = NetShareCtr()
            self['TotalEntries'] = 0
            self['ResumeHandle'] = ResumeHandle()

    def pack(self):
        data += pack('<L', self['Level'])
        data += self['NetShareCtr'].pack()
        data += pack('<L', self['TotalEntries'])
        data += self['ResumeHandle'].pack()
        return data

    def get_shares(self):
        return self['NetShareCtr'].get_shares()

    def get_nbr_entries(self):
        return self['TotalEntries']


#######################################################################
#####
##### Exception classes
#####
#######################################################################

class SRVSVCException(Exception):
    """
    Base class for all SRVSVC-specific exceptions.
    """
    def __init__(self, message=''):
        self.message = message

    def __str__(self):
        return '[ SRVSVC_ERROR: %s ]' % (self.message)

class SRVSVCException2(Exception):
    """
    Improved version of the base class to track errors.
    """
    def __init__(self, message='', status=None):
        self.message = message
        self.status = status

    def __str__(self):
        if not self.status:
            return '[ SRVSVC_ERROR: %s ]' % (self.message)
        else:
            return '[ SRVSVC_ERROR: %s (0x%x) ]' % (self.message, self.status)

class SRVSVCShareEnumException(SRVSVCException2):
    """
    Raised when share_enum() fails.
    """
    pass

class SRVSVCShareEnumAccessDeniedException(SRVSVCException2):
    """
    Raised when credentials are incorrect / or not enough.
    """
    def __init__(self):
        self.message = 'NetrShareEnumResponse() failed: Access Denied.'
        self.status = 5

#######################################################################
#####
##### Main classes: WKSSVC, WKSSVCClient (WKSSVCServer will not be implemented)
##### API will raise specific exceptions when errors are caught.
#######################################################################

class SRVSVC():
    def __init__(self, host, port):
        self.host              = host
        self.port              = port
        self.is_unicode        = True
        self.policy_handle     = None
        self.uuid              = (u'4b324fc8-1670-01d3-1278-5a47bf6ee188', '3.0')

class SRVSVCClient(SRVSVC):

    def __init__(self, host, port=445):
        SRVSVC.__init__(self, host, port)
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

        connectionlist = []
        connectionlist.append(u'ncacn_np:%s[\\browser]' % self.host)
        connectionlist.append(u'ncacn_np:%s[\\srvsvc]' % self.host)
        connectionlist.append(u'ncacn_ip_tcp:%s[%d]' % (self.host,self.port))
        connectionlist.append(u'ncacn_tcp:%s[%d]' % (self.host,self.port))

        for connector in connectionlist:
            ret = self.__bind(connector)
            if ret:
                return 1

        return 0


    def get_reply(self):
        return self.dce.reassembled_data

    def share_get_info(self, NetName):
        data = NetrShareGetInfoRequest(ServerName='', NetName=NetName).pack()
        self.dce.call(SRVSVC_COM_NET_SHARE_GET_INFO, data, response=True)
        if len(self.get_reply()) < 4:
            raise Exception('share_get_info() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]
        if status == 0:
            resp = NetrShareGetInfoResponse(self.get_reply())
            return resp.get_info()
        else:
            raise Exception('share_get_info() failed with status=%d.'% status)

    def share_enum(self, with_comments=True):
        """
        Fetches the list of shares available on the system
        SRVSVCShareEnumException is raised on failure
        """

        Level=0
        if with_comments:
            Level=1

        try:
            data = NetrShareEnumRequest(ServerName='', Level=Level).pack()
        except Exception as e:
            raise SRVSVCShareEnumException('share_enum() failed to build the request.')

        self.dce.call(SRVSVC_COM_NET_SHARE_ENUM_ALL, data, response=True)
        if len(self.get_reply()) < 4:
            raise SRVSVCShareEnumException('share_enum() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]
        if status == 0:
            try:
                resp = NetrShareEnumResponse(self.get_reply())
                return resp.get_shares()
            except Exception as e:
                raise SRVSVCShareEnumException('share_enum() failed: Parsing error in the answer.')
        if status == 5:
            raise SRVSVCShareEnumAccessDeniedException()
        else:
            raise SRVSVCShareEnumException('share_enum() failed.', status=status)


#######################################################################
#####
##### A couple of useful functions for other parts of CANVAS
#####
#######################################################################


def srvsvc_share_enum(target_ip, username=None, password=None, domain=None, kerberos_db=None, use_krb5=False, with_comments=True):
    try:
        ssvc = SRVSVCClient(target_ip)
        ssvc.set_credentials(username, password, domain, kerberos_db, use_krb5)
        if not ssvc.bind():
            return -1, None
        shares = ssvc.share_enum(with_comments=with_comments)
        return 0, shares
    except SRVSVCShareEnumAccessDeniedException as e:
        return -e.status, None
    except Exception as e:
        logging.error('SVCSRV_ERROR: %s' % str(e))
        return -1, None


#######################################################################
#####
##### Well, the main :D
#####
#######################################################################

TARGET_IP = '10.0.0.1'
USERNAME = 'jojo1'
PASSWORD = 'foobar1234!'
DOMAIN = 'immu5.lab'

def call_every_op():

    ssvc = SRVSVCClient(TARGET_IP)
    ssvc.set_credentials(USERNAME, PASSWORD, DOMAIN)

    if not ssvc.bind():
        print "[-] bind() failed."
        sys.exit(0)

    for op in xrange(256):
        ssvc.dce.call(op, "A"*200, response=True)

def call_test_success():

    ret, shares = srvsvc_share_enum(TARGET_IP, USERNAME, PASSWORD, DOMAIN)
    if not ret:
        print shares

def call_test_failed_auth():
    ret, shares = srvsvc_share_enum(TARGET_IP, 'none', 'none', 'none')
    if ret:
        print "Failed!"

def main():

    #call_every_op()
    ret, shares = srvsvc_share_enum(TARGET_IP, USERNAME, PASSWORD, DOMAIN, with_comments=False)
    if not ret:
        print shares

if __name__ == "__main__":
    main()
