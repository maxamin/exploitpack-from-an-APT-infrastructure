#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  winreg.py
## Description:
##            :
## Created_On :  Thu Oct 15 CEST 2015
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################


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

WINREG_COM_OPEN_CLASSES_ROOT         = 0
WINREG_COM_OPEN_CURRENT_USER         = 1
WINREG_COM_OPEN_LOCAL_MACHINE        = 2
WINREG_COM_OPEN_PERFORMANCE_DATA     = 3
WINREG_COM_OPEN_USERS                = 4
WINREG_COM_BASE_REG_CLOSE_KEY        = 5
WINREG_COM_BASE_REG_CREATE_KEY       = 6
WINREG_COM_BASE_REG_DELETE_KEY       = 7
WINREG_COM_BASE_REG_DELETE_VALUE     = 8
WINREG_COM_BASE_REG_ENUM_KEY         = 9
WINREG_COM_BASE_REG_ENUM_VALUE       = 10
WINREG_COM_BASE_REG_GET_KEY_SECURITY = 12
WINREG_COM_BASE_REG_OPEN_KEY         = 15
WINREG_COM_BASE_REG_QUERY_INFO_KEY   = 16
WINREG_COM_BASE_REG_QUERY_VALUE      = 17
WINREG_COM_BASE_REG_SAVE_KEY         = 20
WINREG_COM_BASE_REG_SET_KEY_SECURITY = 21
WINREG_COM_BASE_REG_SET_VALUE        = 22
WINREG_COM_BASE_REG_GET_VERSION      = 26
WINREG_COM_OPEN_CURRENT_CONFIG       = 27
WINREG_COM_BASE_REG_SAVE_KEY_EX      = 31
WINREG_COM_OPEN_PERFORMANCE_TEXT     = 32
WINREG_COM_OPEN_PERFORMANCE_NLS_TEXT = 33
WINREG_COM_BASE_REG_DELETE_KEY_EX    = 35

# 3.1.1.5 Values

REG_NONE                = 0
REG_SZ                  = 1
REG_EXPAND_SZ           = 2
REG_BINARY              = 3
REG_DWORD               = 4
REG_DWORD_LITTLE_ENDIAN = 4
REG_DWORD_BIG_ENDIAN    = 5
REG_LINK                = 6
REG_MULTI_SZ            = 7
REG_QWORD               = 11
REG_QWORD_LITTLE_ENDIAN = 11

# 2.2.10 SECURITY_INFORMATION

OWNER_SECURITY_INFORMATION = 0x00000001
GROUP_SECURITY_INFORMATION = 0x00000002
DACL_SECURITY_INFORMATION  = 0x00000004
SACL_SECURITY_INFORMATION  = 0x00000008

# 2.4.4.1 ACE_HEADER

# AceType
ACCESS_ALLOWED_ACE_TYPE                 = 0x00
ACCESS_DENIED_ACE_TYPE                  = 0x01
SYSTEM_AUDIT_ACE_TYPE                   = 0x02
SYSTEM_ALARM_ACE_TYPE                   = 0x03
ACCESS_ALLOWED_COMPOUND_ACE_TYPE        = 0x04
ACCESS_ALLOWED_OBJECT_ACE_TYPE          = 0x05
ACCESS_DENIED_OBJECT_ACE_TYPE           = 0x06
SYSTEM_AUDIT_OBJECT_ACE_TYPE            = 0x07
SYSTEM_ALARM_OBJECT_ACE_TYPE            = 0x08
ACCESS_ALLOWED_CALLBACK_ACE_TYPE        = 0x09
ACCESS_DENIED_CALLBACK_ACE_TYPE         = 0x0A
ACCESS_ALLOWED_CALLBACK_OBJECT_ACE_TYPE = 0x0B
ACCESS_DENIED_CALLBACK_OBJECT_ACE_TYPE  = 0x0C
SYSTEM_AUDIT_CALLBACK_ACE_TYPE          = 0x0D
SYSTEM_ALARM_CALLBACK_ACE_TYPE          = 0x0E
SYSTEM_AUDIT_CALLBACK_OBJECT_ACE_TYPE   = 0x0F
SYSTEM_ALARM_CALLBACK_OBJECT_ACE_TYPE   = 0x10
SYSTEM_MANDATORY_LABEL_ACE_TYPE         = 0x11
SYSTEM_RESOURCE_ATTRIBUTE_ACE_TYPE      = 0x12
SYSTEM_SCOPED_POLICY_ID_ACE_TYPE        = 0x13

# AceFlags
OBJECT_INHERIT_ACE         = 0x01
CONTAINER_INHERIT_ACE      = 0x02
NO_PROPAGATE_INHERIT_ACE   = 0x04
INHERIT_ONLY_ACE           = 0x08
INHERITED_ACE              = 0x10
SUCCESSFUL_ACCESS_ACE_FLAG = 0x40
FAILED_ACCESS_ACE_FLAG     = 0x80

# [MS-DTYP] - 2.4.3 ACCESS_MASK

GENERIC_READ           = 0x80000000L
GENERIC_WRITE          = 0x40000000L
GENERIC_EXECUTE        = 0x20000000L
GENERIC_ALL            = 0x10000000L
MAXIMUM_ALLOWED        = 0x02000000L
ACCESS_SYSTEM_SECURITY = 0x01000000L
SYNCHRONIZE            = 0x00100000L
WRITE_OWNER            = 0x00080000L
WRITE_DACL             = 0x00040000L
READ_CONTROL           = 0x00020000L
DELETE                 = 0x00010000L

# 2.2.4 REGSAM

KEY_QUERY_VALUE        = 0x00000001
KEY_SET_VALUE          = 0x00000002
KEY_CREATE_SUB_KEY     = 0x00000004
KEY_ENUMERATE_SUB_KEYS = 0x00000008
KEY_NOTIFY             = 0x00000010
KEY_CREATE_LINK        = 0x00000020
KEY_WOW64_64KEY        = 0x00000100
KEY_WOW64_32KEY        = 0x00000200

# Error codes

ERROR_FILE_NOT_FOUND     = 0x002
ERROR_ACCESS_DENIED      = 0x005
ERROR_INVALID_HANDLE     = 0x006
ERROR_INVALID_PARAMETER  = 0x057
ERROR_BAD_PATHNAME       = 0x0a1
ERROR_ALREADY_EXISTS     = 0x0b7
ERROR_MORE_DATA          = 0x0ea
ERROR_NO_MORE_ITEMS      = 0x103
ERROR_PRIVILEGE_NOT_HELD = 0x522

###
# WINREG objects
# No exception handling for these objects.
###

# [MS-DTYP].pdf

"""
2.3.10 RPC_UNICODE_STRING
-------------------------

typedef struct _RPC_UNICODE_STRING {
 unsigned short Length;
 unsigned short MaximumLength;
 [size_is(MaximumLength/2), length_is(Length/2)]
 WCHAR* Buffer;
} RPC_UNICODE_STRING, *PRPC_UNICODE_STRING;
"""

class UnicodeString(Struct):
    st = [
        ['Length', '<H', 0],
        ['MaximumLength', '<H', 0],
        ['Buffer', '0s', ''],
    ]

    def __init__(self, data=None, string=''):
        Struct.__init__(self, data)

        if data is not None:
            pos = 4
            ptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if ptr:
                self['Buffer'] = DCERPCString(data=data[pos:])
        else:
            if not len(string):
                self['Length'] = 0
                self['MaximumLength'] = 0
                self['Buffer'] = None
            else:
                # Special case
                if string == '\x00':
                    self['Length'] = 2
                    self['MaximumLength'] = 2
                    self['Buffer'] = DCERPCString(string=string.encode('UTF-16LE'))
                else:
                    self['Length'] = 2*len(string)+2
                    self['MaximumLength'] = 2*len(string)+2
                    self['Buffer'] = DCERPCString(string=string.encode('UTF-16LE'))

    def pack(self):
        data  = Struct.pack(self)
        if not self['Buffer']:
            data += pack('<L', 0)
        else:
            data += pack('<L', 0x10004)
            data += self['Buffer'].pack()
        return data

    def set_size(self, size):
        self['MaximumLength'] = 2*size
        if self['Buffer']:
            self['Buffer']['MaximumCount'] = size

    def get_string(self):
        if self['Buffer']:
            return self['Buffer'].get_string()
        else:
            return None

"""
2.2.5 RRP_UNICODE_STRING
------------------------

typedef RPC_UNICODE_STRING RRP_UNICODE_STRING, *PRRP_UNICODE_STRING;
"""

class PrrpUnicodeString(UnicodeString):
    pass

"""
2.4.4.1.1 ACE_HEADER--RPC representation
----------------------------------------

typedef struct _ACE_HEADER {
    UCHAR AceType;
    UCHAR AceFlags;
    USHORT AceSize;
} ACE_HEADER,
*PACE_HEADER;
"""

class ACEHeader(Struct):
    st = [
        ['AceType', '<B', ACCESS_ALLOWED_ACE_TYPE],
        ['AceFlags', '<B', 0],
        ['AceSize', '<H', 20],
    ]

    def __init__(self, data=None, ace_type=ACCESS_ALLOWED_ACE_TYPE, ace_flags=0, ace_size=20):
        Struct.__init__(self, data)

        if data is None:
            self['AceType'] = ace_type
            self['AceFlags'] = ace_flags
            self['AceSize'] = ace_size

    def pack(self):
        data  = Struct.pack(self)
        return data

    def get_ace_size(self):
        return self['AceSize']

"""
2.4.4.2 ACCESS_ALLOWED_ACE
--------------------------

typedef struct AccessAllowedAce {
    ACE_HEADER ace_header;
    ACCESS_MASK Mask;
    SID Sid;
} ;
"""

class AccessAllowedACE(Struct):
    st = [
        ['Header', '0s', ''],
        ['Mask', '<L', 0],
        ['Sid', '0s', ''],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['Header'] = ACEHeader(data=data[pos:])
            pos += self['Header'].calcsize()
            self['Mask'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['Sid'] = DCERPCSid(data=data[pos-4:]) # TODO
        # else: TODO

    def pack(self):
        data  = pack('<L', self['Mask'])
        data += self['Sid'].pack()
        return data

    def get_header(self):
        return self['Header']

    def get_results(self):
        return {
            'type': ACCESS_ALLOWED_ACE_TYPE,
            'mask': self['Mask'],
            'sid': self['Sid'].get_sid(),
            }

"""
2.4.4.4 ACCESS_DENIED_ACE
-------------------------

typedef struct AccessDeniedAce {
    ACE_HEADER ace_header;
    ACCESS_MASK Mask;
    SID Sid;
} ;
"""

class AccessDeniedAce(AccessAllowedACE):

    def get_results(self):
        return {
            'type': ACCESS_DENIED_ACE_TYPE,
            'mask': self['Mask'],
            'sid': self['Sid'].get_sid(),
            }

"""
2.4.4.10 SYSTEM_AUDIT_ACE
-------------------------

typedef struct SystemAuditAce {
    ACE_HEADER ace_header;
    ACCESS_MASK Mask;
    SID Sid;
} ;
"""

class SystemAuditAce(AccessAllowedACE):

    def get_results(self):
        return {
            'type': SYSTEM_AUDIT_ACE_TYPE,
            'mask': self['Mask'],
            'sid': self['Sid'].get_sid(),
            }

"""
2.4.5.1 ACL--RPC Representation
-------------------------------

typedef struct _ACL {
    unsigned char AclRevision;
    unsigned char Sbz1;
    unsigned short AclSize;
    unsigned short AceCount;
    unsigned short Sbz2;
} ACL,
*PACL;
"""

class ACL(Struct):
    st = [
        ['AclRevision', '<B', 0],
        ['Sbz1', '<B', 0],
        ['AclSize', '<H', 0],
        ['AceCount', '<H', 0],
        ['Sbz2', '<H', 0],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        self.aces = []

        if data is not None:
            pos = self.calcsize()
            for i in xrange(self['AceCount']):
                ace_type = unpack('<B', data[pos:pos+1])[0]
                if ace_type == ACCESS_ALLOWED_ACE_TYPE:
                    ace = AccessAllowedACE(data=data[pos:])
                    self.aces += [ace]
                    pos += ace.get_header().get_ace_size()
                elif ace_type == ACCESS_DENIED_ACE_TYPE:
                    ace = AccessDeniedAce(data=data[pos:])
                    self.aces += [ace]
                    pos += ace.get_header().get_ace_size()
                elif ace_type == SYSTEM_AUDIT_ACE_TYPE:
                    ace = SystemAuditAce(data=data[pos:])
                    self.aces += [ace]
                    pos += ace.get_header().get_ace_size()
                # Unsupported yet
                else:
                    logging.warning('Currently unsupported ACE type: %s' % ace_type)
                    ace_header = ACEHeader(data=data[pos:])
                    pos += ace_header.get_ace_size()

    def get_results(self):
        return self.aces

    def pack(self):
        # TODO
        data = ''
        return data


"""
2.4.6.1 SECURITY_DESCRIPTOR--RPC Representation
-----------------------------------------------

typedef struct _SECURITY_DESCRIPTOR {
    UCHAR Revision;
    UCHAR Sbz1;
    USHORT Control;
    PSID Owner;
    PSID Group;
    PACL Sacl;
    PACL Dacl;
} SECURITY_DESCRIPTOR,
*PSECURITY_DESCRIPTOR;
"""

class SecurityDescriptor(Struct):
    st = [
        ['Revision', '<H', 0],
        ['Type', '<H', 0],
        ['Owner', '0s', ''],
        ['Group', '0s', ''],
        ['Sacl', '0s', ''],
        ['Dacl', '0s', ''],
    ]

    def __init__(self, data=None, security_descriptor=None):

        if data is not None:
            pos  = 0
            max_size = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            offset = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            actual_size = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            saved_pos = pos
            Struct.__init__(self, data[pos:])
            pos += self.calcsize()
            offset_owner = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            offset_group = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            offset_sacl = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            offset_dacl = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if offset_owner:
                self['Owner'] = DCERPCSid(data = data[saved_pos+offset_owner-4:]) # TODO
            if offset_group:
                self['Group'] = DCERPCSid(data = data[saved_pos+offset_group-4:]) # TODO
            if offset_sacl:
                self['Sacl'] = ACL(data = data[saved_pos+offset_sacl:])
            if offset_dacl:
                self['Dacl'] = ACL(data = data[saved_pos+offset_dacl:])
        else:
            Struct.__init__(self, data)

    def get_owner(self):
        if self['Owner']:
            return self['Owner'].get_sid()
        else:
            return ''

    def get_group(self):
        if self['Group']:
            return self['Group'].get_sid()
        else:
            return ''

    def get_sacl(self):
        if self['Sacl']:
            return self['Sacl'].get_results()
        else:
            return None

    def get_dacl(self):
        if self['Dacl']:
            return self['Dacl'].get_results()
        else:
            return None

    def get_results(self):
        return {
            'Owner' : self.get_owner(),
            'Group' : self.get_group(),
            'Dacl'  : self.get_dacl(),
            'Sacl'  : self.get_sacl(),
            }

    def pack(self):
        # TODO
        data = ''
        return data


# 2.4.2.4 Well-Known SID Structures

# Static SID no matter the configuration
sid2name_static = {
    'S-1-1-0' : 'EVERYONE' ,
    'S-1-2-0' : 'LOCAL' ,
    'S-1-2-1' : 'CONSOLE_LOGON' ,
    'S-1-3-0' : 'CREATOR_OWNER' ,
    'S-1-3-1' : 'CREATOR_GROUP' ,
    'S-1-3-2' : 'OWNER_SERVER' ,
    'S-1-3-3' : 'GROUP_SERVER' ,
    'S-1-3-4' : 'OWNER_RIGHTS' ,
    'S-1-5'   : 'NT_AUTHORITY' ,
    'S-1-5-1' : 'DIALUP' ,
    'S-1-5-2' : 'NETWORK' ,
    'S-1-5-3' : 'BATCH',
    'S-1-5-4' : 'INTERACTIVE',
    'S-1-5-6' : 'SERVICE',
    'S-1-5-7' : 'ANONYMOUS',
    'S-1-5-8' : 'PROXY',
    'S-1-5-9' : 'ENTERPRISE_DOMAIN_CONTROLLERS',
    'S-1-5-10' : 'PRINCIPAL_SELF',
    'S-1-5-11' : 'AUTHENTICATED_USERS' ,
    'S-1-5-12' : 'RESTRICTED_CODE' ,
    'S-1-5-13' : 'TERMINAL_SERVER_USER' ,
    'S-1-5-14' : 'REMOTE_INTERACTIVE_LOGON' ,
    'S-1-5-15' : 'THIS_ORGANIZATION' ,
    'S-1-5-17' : 'IUSR' ,
    'S-1-5-18' : 'LOCAL_SYSTEM' ,
    'S-1-5-19' : 'LOCAL_SERVICE' ,
    'S-1-5-20' : 'NETWORK_SERVICE' ,
    'S-1-5-21-0-0-0-496' : 'COMPOUNDED_AUTHENTICATION',
    'S-1-5-21-0-0-0-497' : 'CLAIMS_VALID',
    'S-1-5-32-544' : 'BUILTIN_ADMINISTRATORS' ,
    'S-1-5-32-545' : 'BUILTIN_USERS' ,
    'S-1-5-32-546' : 'BUILTIN_GUESTS',
    'S-1-5-32-547' : 'POWER_USERS' ,
    'S-1-5-32-548' : 'ACCOUNT_OPERATORS' ,
    'S-1-5-32-549' : 'SERVER_OPERATORS' ,
    'S-1-5-32-550' : 'PRINTER_OPERATORS' ,
    'S-1-5-32-551' : 'BACKUP_OPERATORS' ,
    'S-1-5-32-552' : 'REPLICATOR' ,
    'S-1-5-32-554' : 'ALIAS_PREW2KCOMPACC' ,
}

# Domain / machine dependant SID
sid2name_dynamic = {
    ('S-1-5-5' ,      ) : 'LOGON_ID',
    ('S-1-5-21', '498') : 'ENTERPRISE_READONLY_DOMAIN_CONTROLLERS',
    ('S-1-5-21', '500') : 'ADMINISTRATOR',
    ('S-1-5-21', '501') : 'GUEST',
    ('S-1-5-21', '512') : 'DOMAIN_ADMINS',
    ('S-1-5-21', '513') : 'DOMAIN_USERS',
    ('S-1-5-21', '514') : 'DOMAIN_GUESTS',
    ('S-1-5-21', '515') : 'DOMAIN_COMPUTERS',
    ('S-1-5-21', '516') : 'DOMAIN_DOMAIN_CONTROLLERS',
    ('S-1-5-21', '517') : 'CERT_PUBLISHERS',
    ('S-1-5-21', '518') : 'SCHEMA_ADMINISTRATORS',
    ('S-1-5-21', '519') : 'ENTERPRISE_ADMINS',
    ('S-1-5-21', '520') : 'GROUP_POLICY_CREATOR_OWNERS',
    ('S-1-5-21', '521') : 'READONLY_DOMAIN_CONTROLLERS',
    ('S-1-5-21', '522') : 'CLONEABLE_CONTROLLERS',
    ('S-1-5-21', '525') : 'PROTECTED_USERS',
    ('S-1-5-21', '553') : 'RAS_SERVERS',

}

def get_sid_name(sid):

    # 'S-1-5-32-549' => 'S-1-5-32'
    def get_prefix(s):
        return '-'.join(s.split('-')[:4])

    # 'S-1-5-32-549' => '549'
    def get_suffix(s):
        return '-'.join(s.split('-')[-1:])

    if sid2name_static.has_key(sid):
        return sid2name_static[sid]
    else:
        prefix = get_prefix(sid)
        suffix = get_suffix(sid)

        # TODO: fix the first case
        if sid2name_dynamic.has_key((prefix,suffix)):
            return sid2name_dynamic[(prefix,suffix)]
        else:
            return '???'

def build_permission_string(mask):
    s = ''
    if mask & GENERIC_READ:
        s += 'GR/'
    if mask & GENERIC_WRITE:
        s += 'GW/'
    if mask & GENERIC_EXECUTE:
        s += 'GX/'
    if mask & GENERIC_ALL:
        s += 'GA/'
    if mask & MAXIMUM_ALLOWED:
        s += 'MA/'
    if mask & ACCESS_SYSTEM_SECURITY:
        s += 'AS/'
    if mask & SYNCHRONIZE:
        s += 'SY/'
    if mask & WRITE_OWNER:
        s += 'WO/'
    if mask & WRITE_DACL:
        s += 'WD/'
    if mask & READ_CONTROL:
        s += 'RC/'
    if mask & DELETE:
        s += 'DE/'
    return s

# [MS-RRP].pdf

"""
2.2.9 RPC_SECURITY_DESCRIPTOR
-----------------------------

typedef struct _RPC_SECURITY_DESCRIPTOR {
    [size_is(cbInSecurityDescriptor), length_is(cbOutSecurityDescriptor)]
    PBYTE lpSecurityDescriptor;
    DWORD cbInSecurityDescriptor;
    DWORD cbOutSecurityDescriptor;
} RPC_SECURITY_DESCRIPTOR,
*PRPC_SECURITY_DESCRIPTOR;
"""

class RpcSecurityDescriptor(Struct):
    st = [
        ['lpSecurityDescriptor', '0s', ''],
        ['cbInSecurityDescriptor', '<L', 4096],
        ['cbOutSecurityDescriptor', '<L', 0]
    ]

    def __init__(self, data=None, security_descriptor=None):
        Struct.__init__(self, data)

        if data is not None:
            pos  = 0
            ptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['cbInSecurityDescriptor'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['cbOutSecurityDescriptor'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if ptr:
                self['lpSecurityDescriptor'] = SecurityDescriptor(data=data[pos:])
        else:
            self['lpSecurityDescriptor'] = security_descriptor

    def pack(self):
        data  = ''
        if not self['lpSecurityDescriptor']:
            data += pack('<L', 0)
        else:
            data += pack('<L', 0x10004)
        data += pack('<L', self['cbInSecurityDescriptor'])
        data += pack('<L', self['cbOutSecurityDescriptor'])
        return data

    def get_results(self):
        return self['lpSecurityDescriptor'].get_results()

###
# Handlers
# No exception handling for these objects.
###

# Opnum 0

"""
3.1.5.1 OpenClassesRoot
------------------------

error_status_t OpenClassesRoot(
[in, unique] PREGISTRY_SERVER_NAME ServerName,
[in] REGSAM samDesired,
[out] PRPC_HKEY phKey
);
"""

class WINREGOpenClassesRootRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenClassesRootResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 1

"""
3.1.5.2 OpenCurrentUser
------------------------

error_status_t OpenCurrentUser(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenCurrentUserRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | ACCESS_SYSTEM_SECURITY \
                             | KEY_QUERY_VALUE | KEY_SET_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenCurrentUserResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 2

"""
3.1.5.3 OpenLocalMachine
------------------------

error_status_t OpenLocalMachine(
 [in, unique] PREGISTRY_SERVER_NAME ServerName,
 [in] REGSAM samDesired,
 [out] PRPC_HKEY phKey
);
"""

class WINREGOpenLocalMachineRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenLocalMachineResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 3

"""
3.1.5.4 OpenPerformanceData
---------------------------

error_status_t OpenPerformanceData(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenPerformanceDataRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE | KEY_SET_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenPerformanceDataResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 4

"""
3.1.5.5 OpenUsers
------------------------

error_status_t OpenUsers(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenUsersRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenUsersResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 5

"""
3.1.5.6 BaseRegCloseKey
-----------------------

error_status_t BaseRegCloseKey(
 [in, out] PRPC_HKEY hKey
);
"""

class WINREGBaseRegCloseKeyRequest(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
    ]

    def __init__(self, data=None, hKey='\x00'*20, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['phKey'] = hKey

    def pack(self):
        return Struct.pack(self)

class WINREGBaseRegCloseKeyResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

# Opnum 6

"""
3.1.5.7 BaseRegCreateKey
------------------------

error_status_t BaseRegCreateKey(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpSubKey,
    [in] PRRP_UNICODE_STRING lpClass,
    [in] DWORD dwOptions,
    [in] REGSAM samDesired,
    [in, unique] PRPC_SECURITY_ATTRIBUTES lpSecurityAttributes,
    [out] PRPC_HKEY phkResult,
    [in, out, unique] LPDWORD lpdwDisposition
);
"""

class WINREGBaseRegCreateKeyRequest(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['lpSubKey', '0s', ''],
        ['lpClass', '0s', ''],
        ['dwOptions', '<L', 0],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_SET_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
        ['lpSecurityAttributes', '0s', ''],
    ]

    def __init__(self, data=None, hKey='\x00'*20, sam_access=None, keyname='test', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pass # TODO
        else:
            self['phKey'] = hKey
            self['lpSubKey'] = PrrpUnicodeString(string=keyname)
            self['lpClass'] = PrrpUnicodeString(string='')
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):
        data = self['phKey']
        data += self['lpSubKey'].pack()
        data += self['lpClass'].pack()
        data += pack('<L', self['dwOptions'])
        data += pack('<L', self['samDesired'])
        data += "\x00"*8 # TODO
        return data

class WINREGBaseRegCreateKeyResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['lpdwDisposition', '0s', ''],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['phKey'] = data[pos:pos+20]
            pos += 20
            self['lpdwDisposition'] = unpack('<L', data[pos:pos+4])
            pos += 4
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['phKey'] = hKey
            self['lpdwDisposition'] = None
            self['retvalue'] = retvalue

    def pack(self):
        data  = self['phKey']
        data += pack('<L', 0) # ptr = NULL
        data += pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 7

"""
3.1.5.8 BaseRegDeleteKey
------------------------

error_status_t BaseRegDeleteKey(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpSubKey
);
"""

class WINREGBaseRegDeleteKeyRequest(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['lpSubKey', '0s', ''],
    ]

    def __init__(self, data=None, hKey='\x00'*20, keyname='test', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pass # TODO
        else:
            self['phKey'] = hKey
            self['lpSubKey'] = PrrpUnicodeString(string=keyname)

    def pack(self):
        data = self['phKey']
        data += self['lpSubKey'].pack()
        return data

class WINREGBaseRegDeleteKeyResponse(Struct):
    st = [
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['retvalue'] = retvalue

    def pack(self):
        data = pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']

# Opnum 8

"""
3.1.5.8 BaseRegDeleteValue
--------------------------

error_status_t BaseRegDeleteValue(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpValueName
);
"""

class WINREGBaseRegDeleteValueRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['lpValueName', '0s', ''],
    ]

    def __init__(self, data=None, hKey='\x00'*20, value_name='test', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pass # TODO
        else:
            self['hKey'] = hKey
            self['lpValueName'] = PrrpUnicodeString(string=value_name)

    def pack(self):
        data  = self['hKey']
        data += self['lpValueName'].pack()
        return data

class WINREGBaseRegDeleteValueResponse(Struct):
    st = [
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['retvalue'] = retvalue

    def pack(self):
        data = pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']

# Opnum 15

"""
3.1.5.15 BaseRegOpenKey
-----------------------

error_status_t BaseRegOpenKey(
 [in] RPC_HKEY hKey,
 [in] PRRP_UNICODE_STRING lpSubKey,
 [in] DWORD dwOptions,
 [in] REGSAM samDesired,
 [out] PRPC_HKEY phkResult
);
"""

class WINREGBaseRegOpenKeyRequest(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['lpSubKey', '0s', ''],
        ['dwOptions', '<L', 0],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, hKey='\x00'*20, keyname='Software', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['phKey'] = hKey
            self['lpSubKey'] = PrrpUnicodeString(string=keyname)
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):
        data = self['phKey']
        data += self['lpSubKey'].pack()
        data += pack('<L', self['dwOptions'])
        data += pack('<L', self['samDesired'])
        return data


class WINREGBaseRegOpenKeyResponse(Struct):
    st = [
        ['phkResult', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phkResult'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phkResult']

# Opnum 16

"""
3.1.5.16 BaseRegQueryInfoKey
----------------------------

error_status_t BaseRegQueryInfoKey(
 [in] RPC_HKEY hKey,
 [in] PRRP_UNICODE_STRING lpClassIn,
 [out] PRPC_UNICODE_STRING lpClassOut,
 [out] LPDWORD lpcSubKeys,
 [out] LPDWORD lpcbMaxSubKeyLen,
 [out] LPDWORD lpcbMaxClassLen,
 [out] LPDWORD lpcValues,
 [out] LPDWORD lpcbMaxValueNameLen,
 [out] LPDWORD lpcbMaxValueLen,
 [out] LPDWORD lpcbSecurityDescriptor,
 [out] PFILETIME lpftLastWriteTime
);
"""

class WINREGBaseRegQueryInfoKeyRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['lpClassIn', '0s', ''],
    ]

    def __init__(self, data=None, handle='\x00'*20, classname='', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            #TODO
            pass
        else:
            self['hKey'] = handle
            self['lpClassIn'] = PrrpUnicodeString(string=classname)

    def pack(self):
        data  = self['hKey']
        data += self['lpClassIn'].pack()
        return data


class WINREGBaseRegQueryInfoKeyResponse(Struct):
    st = [
        ['lpClassOut', '0s', ''],
        ['lpcSubKeys', '<L', 0 ],
        ['lpcbMaxSubKeyLen', '<L', 0 ],
        ['lpcbMaxClassLen', '<L', 0 ],
        ['lpcValues', '<L', 0 ],
        ['lpcbMaxValueNameLen', '<L', 0 ],
        ['lpcbMaxValueLen', '<L', 0 ],
        ['lpcbSecurityDescriptor', '<L', 0 ],
        ['lpftLastWriteTime', '0s', '' ],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, classname='', retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['lpClassOut'] = PrrpUnicodeString(data=data[pos:])
            pos += len(self['lpClassOut'].pack())
            self['lpcSubKeys'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcbMaxSubKeyLen'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcbMaxClassLen'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcValues'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcbMaxValueNameLen'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcbMaxValueLen'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            self['lpcbSecurityDescriptor'] = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            #self['lpftLastWriteTime'] = unpack('<L', data[pos:pos+4])

        else:
            self['lpClassOut'] = PrrpUnicodeString(string=classname)
            self['retvalue'] = retvalue

    def pack(self):
        data = ''
        return data

    def get_return_value(self):
        return self['retvalue']

    def get_result(self):
        return { 'nbr_keys': self['lpcSubKeys'],
                 'nbr_values': self['lpcbMaxValueLen'],
                 'max_value_namelen': self['lpcbMaxValueNameLen'],
                 'max_value_len' : self['lpcbMaxValueLen'] }

# Opnum 9

"""
3.1.5.10 BaseRegEnumKey
-----------------------

error_status_t BaseRegEnumKey(
 [in] RPC_HKEY hKey,
 [in] DWORD dwIndex,
 [in] PRRP_UNICODE_STRING lpNameIn,
 [out] PRRP_UNICODE_STRING lpNameOut,
 [in, unique] PRRP_UNICODE_STRING lpClassIn,
 [out] PRPC_UNICODE_STRING* lplpClassOut,
 [in, out, unique] PFILETIME lpftLastWriteTime
);
"""

class WINREGBaseRegEnumKeyRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['dwIndex', '<L', 0],
        ['lpNameIn', '<L', 0],
        ['lpClassIn', '<L', 0],
        ['lpftLastWriteTime', '0s', ''],
    ]

    def __init__(self, data=None, handle='\x00'*20, index=0, name='', classname='', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            #TODO
            pass
        else:
            self['hKey'] = handle
            self['dwIndex'] = index
            self['lpNameIn'] = PrrpUnicodeString(string=classname)
            self['lpClassIn'] = PrrpUnicodeString(string=classname)
            self['lpNameIn'].set_size(256)
            self['lpClassIn'].set_size(1)
            self['lpftLastWriteTime'] = None

    def pack(self):
        data  = self['hKey']
        data += pack('<L', self['dwIndex'])
        data += self['lpNameIn'].pack()
        data += pack('<L', 0x10004)
        data += self['lpClassIn'].pack()
        data += pack('<L', 0x10008)
        data += "\x00"*8
        return data


class WINREGBaseRegEnumKeyResponse(Struct):
    st = [
        ['lpNameOut', '0s', ''],
        ['lplpClassOut', '0s', '' ],
        ['lpftLastWriteTime', '0s', '' ],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, name='', classname='', retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['lpNameOut'] = PrrpUnicodeString(data=data[pos:])
            pos += len(self['lpNameOut'].pack())
            ptr_lplpClassOut = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if ptr_lplpClassOut:
                self['lplpClassOut'] = PrrpUnicodeString(data=data[pos:])
                pos += len(self['lplpClassOut'].pack())
            ptr = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if ptr:
                self['lpftLastWriteTime'] = data[pos:pos+8]
                pos += 8
            self['retvalue'] = unpack('<L', data[pos:pos+4])[0]

        else:
            self['lpNameOut'] = PrrpUnicodeString(string=name)
            self['lplpClassOut'] = PrrpUnicodeString(string=classname)
            self['retvalue'] = retvalue

    def pack(self):
        data = ''
        # TODO
        return data

    def get_return_value(self):
        return self['retvalue']

    def get_result(self):
        name1 = self['lpNameOut'].get_string()
        if name1:
            name = name1.decode('UTF-16LE')[:-1]
        else:
            name = ''
        class1 = self['lplpClassOut'].get_string()
        if class1:
            class_name = class1.decode('UTF-16LE')[:-1]
        else:
            class_name = ''
        return { 'name': name,
                 'class': class_name }

# Opnum 10

"""
3.1.5.11 BaseRegEnumValue
-------------------------

error_status_t BaseRegEnumValue(
 [in] RPC_HKEY hKey,
 [in] DWORD dwIndex,
 [in] PRRP_UNICODE_STRING lpValueNameIn,
 [out] PRPC_UNICODE_STRING lpValueNameOut,
 [in, out, unique] LPDWORD lpType,
 [in, out, unique, size_is(lpcbData?*lpcbData:0), length_is(lpcbLen?*lpcbLen:0), range(0,
0x4000000)]
 LPBYTE lpData,
 [in, out, unique] LPDWORD lpcbData,
 [in, out, unique] LPDWORD lpcbLen
);
"""

class WINREGBaseRegEnumValueRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['dwIndex', '<L', 0],
        ['lpValueNameIn', '<L', 0],
        ['lpType', '<L', 0],
        ['lpData', '0s', ''],
        ['lpcbData', '<L', 0],
        ['lpcbLen', '<L', 0],
    ]

    def __init__(self, data=None, handle='\x00'*20, index=0, name='\x00', valnamelen=24, valbufsize=20, is_unicode=True):
        Struct.__init__(self, data)
        self.valnamelen = valnamelen
        self.valbufsize = valbufsize

        if data is not None:
            #TODO
            pass
        else:
            self['hKey'] = handle
            self['dwIndex'] = index
            #self['lpValueNameIn'] = PrrpUnicodeString(string=name)
            #self['lpValueNameIn'].set_size(5)
            self['lpType'] = REG_NONE
            self['lpData'] = DCERPCString(string='')
            self['lpData']['MaximumCount'] = valbufsize
            self['lpcbData'] = valbufsize
            self['lpcbLen'] = 0

    def pack(self):
        data  = self['hKey']
        data += pack('<L', self['dwIndex'])
        #data += self['lpValueNameIn'].pack()
        data += '0200'.decode('hex')             # TODO
        data += pack('<H', self.valnamelen+2)    # TODO
        data += '00000200'.decode('hex')         # TODO
        data += pack('<L', self.valnamelen/2+1)  # TODO
        data += '00000000'.decode('hex')         # TODO
        data += '01000000'.decode('hex')         # TODO
        data += '00000000'.decode('hex')         # TODO
        data += pack('<L', 0x10004)
        data += pack('<L', self['lpType'])
        data += pack('<L', 0x10008)
        data += self['lpData'].pack(force_null_byte=0)
        data += pack('<L', 0x1000c)
        data += pack('<L', self['lpcbData'])
        data += pack('<L', 0x10010)
        data += pack('<L', self['lpcbLen'])
        return data

class WINREGBaseRegEnumValueResponse(Struct):
    st = [
        ['lpValueNameOut', '0s', ''],
        ['lpType', '<L', 0 ],
        ['lpData', '0s', '' ],
        ['lpcbData', '<L', 0],
        ['lpcbLen', '<L', 0],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, name='', classname='', retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['lpValueNameOut'] = PrrpUnicodeString(data=data[pos:])
            pos += len(self['lpValueNameOut'].pack())
            ptr1 = unpack('<L', data[pos:pos+4])[0]
            pos += 4
            if ptr1:
                self['lpType'] = unpack('<L', data[pos:pos+4])[0]
                pos += 4
            ptr2 = unpack('<L', data[pos:pos+4])
            pos += 4
            if ptr2:
                self['lpData'] = DCERPCString(data=data[pos:], is_unicode=False)
                pos += len(self['lpData'].pack())
            ptr3 = unpack('<L', data[pos:pos+4])
            pos += 4
            if ptr3:
                self['lpcbData'] = unpack('<L', data[pos:pos+4])[0]
                pos += 4
            ptr4 = unpack('<L', data[pos:pos+4])
            pos += 4
            if ptr4:
                self['lpcbLen'] = unpack('<L', data[pos:pos+4])[0]
                pos += 4
            self['retvalue'] = unpack('<L', data[pos:pos+4])

        else:
            self['lpNameOut'] = PrrpUnicodeString(string=name)
            self['lplpClassOut'] = PrrpUnicodeString(string=classname)
            self['retvalue'] = retvalue

    def pack(self):
        data = ''
        # TODO
        return data

    def get_return_value(self):
        return self['retvalue']

    def get_result(self):
        if self['lpValueNameOut'].get_string():
            _name = self['lpValueNameOut'].get_string().decode('UTF-16LE')[:-1]
        else:
            _name = ''
        if self['lpData'].get_string():
            _value = self['lpData'].get_string()
        else:
            _value = ''
        return { 'name' : _name,
                 'value': _value,
                 'type': self['lpType'] }

# Opnum 12

"""
3.1.5.13 BaseRegGetKeySecurity
------------------------------

error_status_t BaseRegGetKeySecurity(
    [in] RPC_HKEY hKey,
    [in] SECURITY_INFORMATION SecurityInformation,
    [in] PRPC_SECURITY_DESCRIPTOR pRpcSecurityDescriptorIn,
    [out] PRPC_SECURITY_DESCRIPTOR pRpcSecurityDescriptorOut
);
"""

class WINREGBaseRegGetKeySecurityRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['SecurityInformation', '<L', OWNER_SECURITY_INFORMATION
                                    | GROUP_SECURITY_INFORMATION
                                    | DACL_SECURITY_INFORMATION
                                    | SACL_SECURITY_INFORMATION ],
        ['pRpcSecurityDescriptorIn', '0s', ''],
    ]

    def __init__(self, data=None, handle='\x00'*20, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            #TODO
            pass
        else:
            self['hKey'] = handle
            self['pRpcSecurityDescriptorIn'] = RpcSecurityDescriptor(security_descriptor=None)

    def pack(self):
        data  = self['hKey']
        data += pack('<L', self['SecurityInformation'])
        data += self['pRpcSecurityDescriptorIn'].pack()
        return data

class WINREGBaseRegGetKeySecurityResponse(Struct):
    st = [
        ['pRpcSecurityDescriptorIn', '0s', ''],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, security_descriptor=None, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['pRpcSecurityDescriptorIn'] = RpcSecurityDescriptor(data=data[pos:])
            pos += len(self['pRpcSecurityDescriptorIn'].pack())
            self['retvalue'] = unpack('<L', data[pos:pos+4])[0]
        else:
            self['pRpcSecurityDescriptorIn'] = security_descriptor
            self['retvalue'] = retvalue

    def pack(self):
        data  = self['hKey']
        data += pack('<L', self['SecurityInformation'])
        data += self['pRpcSecurityDescriptorIn'].pack()
        return data

    def get_results(self):
        return self['pRpcSecurityDescriptorIn'].get_results()

# Opnum 13

"""
3.1.5.14 BaseRegLoadKey
-----------------------
error_status_t BaseRegLoadKey(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpSubKey,
    [in] PRRP_UNICODE_STRING lpFile
);
"""

# Opnum 22

"""
3.1.5.22 BaseRegSetValue
------------------------

error_status_t BaseRegSetValue(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpValueName,
    [in] DWORD dwType,
    [in, size_is(cbData)] LPBYTE lpData,
    [in] DWORD cbData
);
"""

class WINREGBaseRegSetValueRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['lpValueName', '0s', ''],
        ['dwType', '<L', 0],
        ['lpData', '0s', ''],
        ['cbData', '<L', 0],
    ]

    def __init__(self, data=None, handle='\x00'*20, v_name='\x00', v_type=REG_NONE, v_value='\x01', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            #TODO
            pass
        else:
            self['hKey'] = handle
            self['lpValueName'] = PrrpUnicodeString(string=v_name)
            self['dwType'] = v_type
            self['lpData'] = v_value
            self['cbData'] = len(v_value)

    def pack(self):
        data  = self['hKey']
        data += self['lpValueName'].pack()
        data += pack('<L', self['dwType'])
        data += pack('<L', self['cbData'])
        data += self['lpData']
        # Mandatory padding
        if (len(data) % 4) != 0:
            data += '\0' * (4 - (len(data) % 4))
        data += pack('<L', self['cbData'])
        return data

class WINREGBaseRegSetValueResponse(Struct):
    st = [
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['retvalue'] = retvalue

    def pack(self):
        data = pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']


# Opnum 26

"""
3.1.5.24 BaseRegGetVersion
--------------------------

error_status_t BaseRegGetVersion(
    [in] RPC_HKEY hKey,
    [out] LPDWORD lpdwVersion
);
"""

class WINREGBaseRegGetVersionRequest(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
    ]

    def __init__(self, data=None, handle='\x00'*20, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            self['phKey'] = data[0:20]
        else:
            self['phKey'] = handle

    def pack(self):
        data = self['phKey']
        return data

class WINREGBaseRegGetVersionResponse(Struct):
    st = [
        ['lpdwVersion', '<L', 0 ],
        ['retvalue', '<L', 0 ],
    ]

    def __init__(self, data=None, retvalue=0, version=5, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['lpdwVersion'] = unpack('<L', data[pos:pos+4])
            pos += 4
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['lpdwVersion'] = version
            self['retvalue'] = retvalue

    def pack(self):
        data  = pack('<L', self['lpdwVersion'])
        data += pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']

    def get_version(self):
        return self['lpdwVersion']

# Opnum 27

"""
3.1.5.25 OpenCurrentConfig
--------------------------

error_status_t OpenCurrentConfig(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenCurrentConfigRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenCurrentConfigResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 31 -- DOES NOT WORK YET

"""
3.1.5.27 BaseRegSaveKeyEx
-------------------------

error_status_t BaseRegSaveKeyEx(
    [in] RPC_HKEY hKey,
    [in] PRRP_UNICODE_STRING lpFile,
    [in, unique] PRPC_SECURITY_ATTRIBUTES pSecurityAttributes,
    [in] DWORD Flags
);
"""

class WINREGBaseRegSaveKeyExRequest(Struct):
    st = [
        ['hKey', '20s', '\x00'*20],
        ['lpFile', '0s', ''],
        ['pSecurityAttributes', '0s', ''],
        ['Flags', '<L', 0],
    ]

    def __init__(self, data=None, handle='\x00'*20, filename='', is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pass # TODO
        else:
            self['hKey'] = handle
            self['lpFile'] = PrrpUnicodeString(string=filename)
            self['pSecurityAttributes'] = None
            self['Flags'] = 0

    def pack(self):
        data = self['hKey']
        data += self['lpFile'].pack()
        data += pack('<L', 0)
        data += pack('<L', self['Flags'])
        return data

class WINREGBaseRegSaveKeyExResponse(Struct):
    st = [
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            pos = 0
            self['retvalue'] = unpack('<L', data[pos:pos+4])
        else:
            self['retvalue'] = retvalue

    def pack(self):
        data = pack('<L', self['retvalue'])
        return data

    def get_return_value(self):
        return self['retvalue']

# Opnum 32

"""
3.1.5.28 OpenPerformanceText
----------------------------

error_status_t OpenPerformanceText(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenPerformanceTextRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenPerformanceTextResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']

# Opnum 33

"""
3.1.5.29 OpenPerformanceNlsText
--------------------------

error_status_t OpenPerformanceNlsText(
    [in, unique] PREGISTRY_SERVER_NAME ServerName,
    [in] REGSAM samDesired,
    [out] PRPC_HKEY phKey
);
"""

class WINREGOpenPerformanceNlsTextRequest(Struct):
    st = [
        ['ServerName', '0s', ''],
        ['samDesired', '<L', READ_CONTROL \
                             | KEY_QUERY_VALUE \
                             | KEY_NOTIFY \
                             | KEY_ENUMERATE_SUB_KEYS ],
    ]

    def __init__(self, data=None, ServerName='', sam_access=None, is_unicode=True):
        Struct.__init__(self, data)

        if not data:
            self['ServerName'] = ServerName
            if sam_access is not None:
                self['samDesired'] = sam_access

    def pack(self):

        data = ''
        if not len(self['ServerName']):
            data += pack('<L', 0)
        else:
            # TODO
            pass
        data += pack('<L', self['samDesired'])
        return data

class WINREGOpenPerformanceNlsTextResponse(Struct):
    st = [
        ['phKey', '20s', '\x00'*20],
        ['retvalue', '<L', 0 ]
    ]

    def __init__(self, data=None, hKey='\x00'*20, retvalue=0, is_unicode=True):
        Struct.__init__(self, data)

        if data is not None:
            Struct.__init__(self, data)
        else:
            self['phKey'] = hKey
            self['retvalue'] = retvalue

    def pack(self):
        return Struct.pack(self)

    def get_return_value(self):
        return self['retvalue']

    def get_handle(self):
        return self['phKey']


#######################################################################
#####
##### Exception classes
#####
#######################################################################

class WINREGException(Exception):
    """
    Base class for all WINREG-specific exceptions.
    """
    def __init__(self, message=''):
        self.message = message

    def __str__(self):
        return '[ WINREG_ERROR: %s ]' % (self.message)

class WINREGException2(Exception):
    """
    Improved version of the base class to track errors.
    """
    def __init__(self, message='', status=None):
        self.message = message
        self.status = status

    def __str__(self):
        if not self.status:
            return '[ WINREG_ERROR: %s ]' % (self.message)
        else:
            return '[ WINREG_ERROR: %s (0x%x) ]' % (self.message, self.status)

class WINREGOpenUsersException(WINREGException2):
    """
    Raised when open_users fails.
    """
    pass


class WINREGOpenLocalMachineException(WINREGException2):
    """
    Raised when open_local_machine fails.
    """
    pass

class WINREGBaseRegCloseKeyException(WINREGException2):
    """
    Raised when the cnx cannot be properly closed.
    """
    pass

class WINREGBaseRegOpenKeyException(WINREGException2):
    """
    Raised when the open_key() fails.
    """
    pass

class WINREGBaseRegQueryInfoKeyException(WINREGException2):
    """
    Raised when the query_information() fails.
    """
    pass

class WINREGBaseRegEnumKeyException(WINREGException2):
    """
    Raised when the enum_key() fails.
    """
    pass

class WINREGBaseRegEnumValueException(WINREGException2):
    """
    Raised when the enum_value() fails.
    """
    pass

class WINREGOpenCurrentUserException(WINREGException2):
    """
    Raised when the open_current_user() fails.
    """
    pass

class WINREGOpenClassesRootException(WINREGException2):
    """
    Raised when the open_classes_root() fails.
    """
    pass

class WINREGOpenPerformanceDataException(WINREGException2):
    """
    Raised when open_performance_data fails.
    """
    pass

class WINREGOpenPerformanceTextException(WINREGException2):
    """
    Raised when open_performance_text fails.
    """
    pass

class WINREGOpenPerformanceNlsTextException(WINREGException2):
    """
    Raised when open_performance_nls_text fails.
    """
    pass

class WINREGBaseRegCreateKeyException(WINREGException2):
    """
    Raised when the create_key() fails.
    """
    pass

class WINREGBaseRegDeleteKeyException(WINREGException2):
    """
    Raised when the delete_key() fails.
    """
    pass

class WINREGBaseRegGetVersionException(WINREGException2):
    """
    Raised when the get_version() fails.
    """
    pass

class WINREGBaseRegSaveKeyExException(WINREGException2):
    """
    Raised when the save_key_as_file() fails.
    """
    pass

class WINREGBaseRegSetValueException(WINREGException2):
    """
    Raised when the set_value() fails.
    """
    pass

class WINREGBaseRegDeleteValueException(WINREGException2):
    """
    Raised when the delete_value() fails.
    """
    pass

class WINREGOpenCurrentConfigException(WINREGException2):
    """
    Raised when the open_current_config() fails.
    """
    pass

class WINREGBaseRegGetKeySecurityException(WINREGException2):
    """
    Raised when the get_key_security() fails.
    """
    pass

#######################################################################
#####
##### Main classes: WINREG, WINREGClient (WINREGServer will not be implemented)
#####
#######################################################################

class WINREG():
    def __init__(self, host, port):
        self.host              = host
        self.port              = port
        self.is_unicode        = True
        self.uuid              = (u'338cd001-2244-31f1-aaaa-900038001003', u'1.0')

class WINREGClient(WINREG):

    def __init__(self, host, port=445):
        WINREG.__init__(self, host, port)
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

            return self.dce.bind(self.uuid[0], self.uuid[1])
        except Exception as e:
            return 0


    def __bind_ntlm(self, connector):

        try:
            self.dce = DCERPC(connector,
                              getsock=None,
                              username=self.username,
                              password=self.password,
                              domain=self.domain)

            return self.dce.bind(self.uuid[0], self.uuid[1])
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
        #connectionlist.append(u'ncacn_np:%s[\\browser]' % self.host)
        connectionlist.append(u'ncacn_np:%s[\\pipe\\winreg]' % self.host)

        for connector in connectionlist:
            ret = self.__bind(connector)
            if ret:
                return 1

        return 0


    def get_reply(self):
        """
        Provides the answer to a request.
        """
        return self.dce.reassembled_data


    def open_subkey(self, handle, keyname='Software', access=None):
        """
        Opens a new connexion associated with a specific KEY.
        Returns the handle associated.
        WINREGBaseRegOpenKeyException is raised on failure.
        """

        if not keyname:
            keyname = '\x00'

        try:
            data = WINREGBaseRegOpenKeyRequest(hKey=handle, keyname=keyname, sam_access=access).pack()
        except Exception as e:
            raise WINREGBaseRegOpenKeyException('open_subkey() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_OPEN_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegOpenKeyException('open_subkey() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_FILE_NOT_FOUND:
            raise WINREGBaseRegOpenKeyException('open_subkey() failed: no suck subkey.', status=status)

        if status == ERROR_INVALID_PARAMETER:
            raise WINREGBaseRegOpenKeyException('open_subkey() failed: invalid parameter.', status=status)

        if status == ERROR_ACCESS_DENIED:
            if access is not None and not access & MAXIMUM_ALLOWED:
                return self.open_subkey(handle, keyname=keyname, access=MAXIMUM_ALLOWED)
            else:
                raise WINREGBaseRegOpenKeyException('open_subkey() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegOpenKeyResponse(data=self.get_reply())
                return resp.get_handle()
            except Exception as e:
                raise WINREGBaseRegOpenKeyException('open_subkey() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegOpenKeyException('open_subkey() failed.', status=status)


    # A generic API
    def open_key(self, handle=None, predefinedkey='HKEY_CLASSES_ROOT', keyname='Software', access=None):
        """
        Gets a handle on the registry to perform other calls.
        WINREGBaseRegOpenKeyException is raised on failure.
        """

        dic = {
            'HKEY_CLASSES_ROOT': (WINREG_COM_OPEN_CLASSES_ROOT,
                                  WINREGOpenClassesRootRequest,
                                  WINREGOpenClassesRootResponse,
                                  WINREGOpenClassesRootException),
            'HKEY_CURRENT_USER': (WINREG_COM_OPEN_CURRENT_USER,
                                  WINREGOpenCurrentUserRequest,
                                  WINREGOpenCurrentUserResponse,
                                  WINREGOpenCurrentUserException),
            'HKEY_LOCAL_MACHINE': (WINREG_COM_OPEN_LOCAL_MACHINE,
                                  WINREGOpenLocalMachineRequest,
                                  WINREGOpenLocalMachineResponse,
                                  WINREGOpenLocalMachineException),
            'HKEY_PERFORMANCE_DATA': (WINREG_COM_OPEN_PERFORMANCE_DATA,
                                      WINREGOpenPerformanceDataRequest,
                                      WINREGOpenPerformanceDataResponse,
                                      WINREGOpenPerformanceDataException),
            'HKEY_USERS': (WINREG_COM_OPEN_USERS,
                           WINREGOpenUsersRequest,
                           WINREGOpenUsersResponse,
                           WINREGOpenUsersException),
            'HKEY_CURRENT_CONFIG': (WINREG_COM_OPEN_CURRENT_CONFIG,
                                    WINREGOpenCurrentConfigRequest,
                                    WINREGOpenCurrentConfigResponse,
                                    WINREGOpenCurrentConfigException),
            'HKEY_PERFORMANCE_TEXT': (WINREG_COM_OPEN_PERFORMANCE_TEXT,
                                    WINREGOpenPerformanceTextRequest,
                                    WINREGOpenPerformanceTextResponse,
                                    WINREGOpenPerformanceTextException),
            'HKEY_PERFORMANCE_NLS_TEXT': (WINREG_COM_OPEN_PERFORMANCE_NLS_TEXT,
                                    WINREGOpenPerformanceNlsTextRequest,
                                    WINREGOpenPerformanceNlsTextResponse,
                                    WINREGOpenPerformanceNlsTextException),
            }

        #OpenPerformanceText
        #OpenPerformanceNlsText

        # First of all, do we need to open a subkey? If so, the handle _must_
        # be specified.
        if handle is not None:
            return self.open_subkey(handle, keyname=keyname, access=access)

        # If the handle is None AND the predefined key is not handled, there is
        # nothing we can do.
        if not dic.has_key(predefinedkey):
            raise WINREGBaseRegOpenKeyException('open_key() failed: Invalid parameter (predefinedkey).')

        # At this point if there is an exception, it will be raised by more generic
        # API.
        req_opnum = dic[predefinedkey][0]
        req_class = dic[predefinedkey][1]
        resp_class = dic[predefinedkey][2]
        except_class = dic[predefinedkey][3]

        try:
            data = req_class(sam_access=access).pack()
        except Exception as e:
            raise except_class('open_key(\'%s\') failed to build the request.' % predefinedkey)

        self.dce.call(req_opnum, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise except_class('open_key(\'%s\') call was not correct.' % predefinedkey)

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            if access is not None and not access & MAXIMUM_ALLOWED:
                return self.open_key(handle=handle, predefinedkey=predefinedkey, keyname=keyname, access=MAXIMUM_ALLOWED)
            else:
                raise except_class('open_key(\'%s\') failed: access denied.' % predefinedkey, status=status)

        # This error appears when the user provides an invalid handle.
        if status == ERROR_INVALID_HANDLE:
            raise except_class('open_key(\'%s\') failed: invalid handle.' % predefinedkey, status=status)

        if status == ERROR_BAD_PATHNAME:
            raise except_class('open_key(\'%s\') failed: invalid path name.' % predefinedkey, status=status)

        if status == ERROR_PRIVILEGE_NOT_HELD:
            raise except_class('open_key(\'%s\') failed: privilege not held.' % predefinedkey, status=status)

        if status == 0:
            try:
                resp = resp_class(self.get_reply())
                self.handle = resp.get_handle()
                return self.handle
            except Exception as e:
                raise except_class('open_key(\'%s\') failed: parsing error in the answer.' % predefinedkey)
        else:
            raise except_class('open_key(\'%s\') failed.' % predefinedkey, status=status)

    # Specific wrappers

    def open_classes_root(self, access=None):
        return self.open_key(predefinedkey='HKEY_CLASSES_ROOT', access=access)

    def open_current_user(self, access=None):
        return self.open_key(predefinedkey='HKEY_CURRENT_USER', access=access)

    def open_local_machine(self, access=None):
        return self.open_key(predefinedkey='HKEY_LOCAL_MACHINE', access=access)

    def open_performance_data(self, access=None):
        return self.open_key(predefinedkey='HKEY_PERFORMANCE_DATA', access=access)

    def open_users(self, access=None):
        return self.open_key(predefinedkey='HKEY_USERS', access=access)

    def open_current_config(self, access=None):
        return self.open_key(predefinedkey='HKEY_CURRENT_CONFIG', access=access)

    def open_performance_text(self, access=None):
        return self.open_key(predefinedkey='HKEY_PERFORMANCE_TEXT', access=access)

    def open_performance_nls_text(self, access=None):
        return self.open_key(predefinedkey='HKEY_PERFORMANCE_NLS_TEXT', access=access)

    def close_key(self, handle):
        """
        Closes a connexion associated with a handle.
        WINREGBaseRegCloseKeyException is raised on failure.
        """

        try:
            data = WINREGBaseRegCloseKeyRequest(hKey=handle).pack()
        except Exception as e:
            raise WINREGBaseRegCloseKeyException('close_key() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_CLOSE_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegCloseKeyException('close_key() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == 0:
            try:
                resp = WINREGOpenLocalMachineResponse(self.get_reply())
                return
            except Exception as e:
                raise WINREGBaseRegCloseKeyException('close_key() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegCloseKeyException('close_key() failed.', status=status)


    def create_key(self, handle, keyname='Software'):
        """
        Creates the specified registry key.
        Returns the handle associated.
        WINREGBaseRegCreateKeyException is raised on failure.
        """

        try:
            data = WINREGBaseRegCreateKeyRequest(hKey=handle, keyname=keyname).pack()
        except Exception as e:
            raise WINREGBaseRegCreateKeyException('create_key() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_CREATE_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegCreateKeyException('create_key() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegCreateKeyException('create_key() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegCreateKeyResponse(data=self.get_reply())
                return resp.get_handle()
            except Exception as e:
                raise WINREGBaseRegCreateKeyException('create_key() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegCreateKeyException('create_key() failed.', status=status)


    def delete_key(self, handle, keyname='Software'):
        """
        Deletes the specified registry key.
        WINREGBaseRegDeleteKeyException is raised on failure.
        """

        try:
            data = WINREGBaseRegDeleteKeyRequest(hKey=handle, keyname=keyname).pack()
        except Exception as e:
            raise WINREGBaseRegDeleteKeyException('delete_key() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_DELETE_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegDeleteKeyException('delete_key() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_FILE_NOT_FOUND:
            raise WINREGBaseRegDeleteKeyException('delete_key() failed: the key doesn\'t exist.', status=status)

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegDeleteKeyException('delete_key() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegDeleteKeyResponse(data=self.get_reply())
                return
            except Exception as e:
                raise WINREGBaseRegDeleteKeyException('delete_key() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegDeleteKeyException('delete_key() failed.', status=status)


    def query_information(self, handle, classname=''):
        """
        Query informations about a specific key.
        Returns these informations
        WINREGBaseRegQueryInfoKeyException is raised on failure.
        """

        try:
            data = WINREGBaseRegQueryInfoKeyRequest(handle=handle, classname=classname).pack()
        except Exception as e:
            raise WINREGBaseRegQueryInfoKeyException('query_information() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_QUERY_INFO_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegQueryInfoKeyException('query_information() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegQueryInfoKeyException('query_information() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegQueryInfoKeyResponse(data=self.get_reply())
                return resp.get_result()
            except Exception as e:
                raise WINREGBaseRegQueryInfoKeyException('query_information() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegQueryInfoKeyException('query_information() failed.', status=status)


    def get_key_security(self, handle):
        """
        Query security information about a specific key.
        Returns these informations
        WINREGBaseRegGetKeySecurityException is raised on failure.
        """

        try:
            data = WINREGBaseRegGetKeySecurityRequest(handle=handle).pack()
        except Exception as e:
            raise WINREGBaseRegGetKeySecurityException('get_key_security() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_GET_KEY_SECURITY, data, response=True)
        #print self.get_reply().encode('hex')

        # TODO.
        if len(self.get_reply()) < 4:
            raise WINREGBaseRegGetKeySecurityException('get_key_security() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegGetKeySecurityException('get_key_security() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegGetKeySecurityResponse(data=self.get_reply())
                return resp.get_results()
            except Exception as e:
                raise WINREGBaseRegGetKeySecurityException('get_key_security() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegGetKeySecurityException('get_key_security() failed.', status=status)


    def enum_key(self, handle, index, name='', classname=''):
        """
        Query a specific subkey.
        WINREGBaseRegEnumKeyException is raised on failure.
        """

        try:
            data = WINREGBaseRegEnumKeyRequest(handle=handle,
                                               index=index,
                                               name=name,
                                               classname=classname).pack()
        except Exception as e:
            raise WINREGBaseRegEnumKeyException('enum_key() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_ENUM_KEY, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegEnumKeyException('enum_key() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegEnumKeyException('enum_key() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegEnumKeyResponse(data=self.get_reply())
                return resp.get_result()
            except Exception as e:
                raise WINREGBaseRegEnumKeyException('enum_key() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegEnumKeyException('enum_key() failed.', status=status)


    def enum_value(self, handle, index, name='', valnamelen=24, valbufsize=20):
        """
        Query a specific value.
        WINREGBaseRegEnumvalueException is raised on failure.
        """

        try:
            data = WINREGBaseRegEnumValueRequest(handle=handle,
                                                 index=index,
                                                 valnamelen=valnamelen,
                                                 valbufsize=valbufsize).pack()
        except Exception as e:
            raise WINREGBaseRegEnumValueException('enum_value() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_ENUM_VALUE, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegEnumValueException('enum_value() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegEnumValueException('enum_value() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegEnumValueResponse(data=self.get_reply())
                return resp.get_result()
            except Exception as e:
                raise WINREGBaseRegEnumValueException('enum_value() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegEnumValueException('enum_value() failed.', status=status)


    def get_version(self, handle):
        """
        Query the registry to know the version of the OS.
        WINREGBaseRegGetVersionException is raised on failure.
        """

        try:
            data = WINREGBaseRegGetVersionRequest(handle=handle).pack()
        except Exception as e:
            raise WINREGBaseRegGetVersionException('get_version() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_GET_VERSION, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegGetVersionException('get_version() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == 0:
            try:
                resp = WINREGBaseRegGetVersionResponse(data=self.get_reply())
                return resp.get_version()
            except Exception as e:
                raise WINREGBaseRegGetVersionException('get_version() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegGetVersionException('get_version() failed.', status=status)


    def save_key_as_file(self, handle, filename=''):
        """
        Save a specific key in a file.
        WINREGBaseRegSaveKeyExException is raised on failure.
        """

        try:
            data = WINREGBaseRegSaveKeyExRequest(handle=handle, filename=filename).pack()
        except Exception as e:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_SAVE_KEY_EX, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed: access denied.', status=status)

        if status == ERROR_INVALID_PARAMETER:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed: invalid parameter.', status=status)

        if status == ERROR_ALREADY_EXISTS:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed: file already exists.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegSaveKeyExResponse(data=self.get_reply())
                return
            except Exception as e:
                raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegSaveKeyExException('save_key_as_file() failed.', status=status)


    def set_value(self, handle, v_name='', v_type=0, v_value=''):
        """
        Sets a specific value with a certain type.
        WINREGBaseRegSetValueException is raised on failure.
        """

        try:
            data = WINREGBaseRegSetValueRequest(handle=handle, v_name=v_name, v_type=v_type, v_value=v_value).pack()
        except Exception as e:
            raise WINREGBaseRegSetValueException('set_value() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_SET_VALUE, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegSetValueException('set_value() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegSetValueException('set_value() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegSetValueResponse(data=self.get_reply())
                return
            except Exception as e:
                raise WINREGBaseRegSetValueException('set_value() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegSetValueException('set_value() failed.', status=status)


    def delete_value(self, handle, v_name=''):
        """
        Sets a specific value with a certain type.
        WINREGBaseRegSetValueException is raised on failure.
        """

        try:
            data = WINREGBaseRegDeleteValueRequest(hKey=handle, value_name=v_name).pack()
        except Exception as e:
            print e
            raise WINREGBaseRegDeleteValueException('delete_value() failed to build the request.')

        self.dce.call(WINREG_COM_BASE_REG_DELETE_VALUE, data, response=True)
        #print self.get_reply().encode('hex')

        if len(self.get_reply()) < 4:
            raise WINREGBaseRegDeleteValueException('delete_value() call was not correct.')

        status = unpack('<L', self.get_reply()[-4:])[0]

        if status == ERROR_ACCESS_DENIED:
            raise WINREGBaseRegDeleteValueException('delete_value() failed: access denied.', status=status)

        if status == 0:
            try:
                resp = WINREGBaseRegDeleteValueResponse(data=self.get_reply())
                return
            except Exception as e:
                raise WINREGBaseRegDeleteValueException('delete_value() failed: parsing error in the answer.')
        else:
            raise WINREGBaseRegDeleteValueException('delete_value() failed.', status=status)


#######################################################################
#####
##### A couple of useful functions for other parts of CANVAS
#####
#######################################################################

reg_type_dic = {
        REG_NONE: "NONE",
        REG_SZ: "SZ",
        REG_EXPAND_SZ: "EXPAND_SZ",
        REG_BINARY: "BINARY",
        REG_DWORD_LITTLE_ENDIAN: "DWORD",
        REG_DWORD_BIG_ENDIAN: "DWORD (BE)",
        REG_LINK: "LINK",
        REG_MULTI_SZ: "MULTI_SZ",
        REG_QWORD: "QWORD",
    }

def convert_type_to_string(t):

    if reg_type_dic.has_key(t):
        return reg_type_dic[t]
    else:
        return ""

def convert_type_from_string(t):

    values = reg_type_dic.values()
    if t in values:
        idx = values.index(t)
        return reg_type_dic.items()[idx][0]
    else:
        return None

def convert_value_from_string(t,d):

    try:
        if t == REG_NONE:
            return d
        elif t == REG_SZ or t == REG_EXPAND_SZ or t == REG_MULTI_SZ:
            return d.encode('UTF-16LE')
        elif t == REG_BINARY:
            return d
        elif t == REG_DWORD_LITTLE_ENDIAN:
            return pack('<L', int(d))
        elif t == REG_DWORD_BIG_ENDIAN:
            return pack('>L', int(d))
        elif t == REG_LINK:
            return d
        elif t == REG_QWORD:
            return pack('<Q', long(d))
        else:
            return None
    except Exception:
        return None

def convert_value_to_string(t,d):

    if t == REG_NONE:
        return ''
    elif t == REG_SZ or t == REG_EXPAND_SZ or t == REG_MULTI_SZ:
        return d.decode('UTF-16LE')
    elif t == REG_BINARY:
        return d.encode('hex')
    elif t == REG_DWORD_LITTLE_ENDIAN:
        return unpack('<L', d)[0]
    elif t == REG_DWORD_BIG_ENDIAN:
        return unpack('>L', d)[0]
    elif t == REG_LINK:
        return d
    elif t == REG_QWORD:
        return unpack('<Q', d)[0]
    else:
        return None

def is_valid_registry_type(t):

    if t in [ REG_NONE, REG_SZ, REG_EXPAND_SZ, REG_BINARY, REG_DWORD, REG_DWORD_BIG_ENDIAN,
              REG_LINK, REG_MULTI_SZ, REG_QWORD]:
        return True
    elif t in reg_type_dic.values():
        return True
    else:
        return False

#######################################################################
#####
##### Well, the main :D
#####
#######################################################################

TARGET = '10.0.0.1'
USER   = 'administrator'
PWD    = 'foobar123!'
DOMAIN = 'immu5.lab'

def test_all():
    svc = WINREGClient(TARGET)
    svc.set_credentials(USER, PWD, DOMAIN)
    if not svc.bind():
        print "[-] bind() failed."
        return

    for i in xrange(100):
        svc.dce.call(i, data="A"*60, response=True)

if __name__ == "__main__":
    test_all()
