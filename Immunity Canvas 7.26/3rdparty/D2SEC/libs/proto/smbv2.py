import time, os, sys, signal, socket, string

libpath = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-2])
if libpath not in sys.path: sys.path.append(libpath)
extlibpath = os.path.join(libpath, 'ext')
if extlibpath not in sys.path: sys.path.append(extlibpath)

import libs.ext.impacket.smb
import libs.ext.impacket.nmb

###
# SMBv2 detection, based on both metasploit & Impacket
###

class SMBv2:

    # SMB Command Codes
    SMB_COM_CREATE_DIRECTORY = 0x00
    SMB_COM_DELETE_DIRECTORY = 0x01
    SMB_COM_OPEN = 0x02
    SMB_COM_CREATE = 0x03
    SMB_COM_CLOSE = 0x04
    SMB_COM_FLUSH = 0x05
    SMB_COM_DELETE = 0x06
    SMB_COM_RENAME = 0x07
    SMB_COM_QUERY_INFORMATION = 0x08
    SMB_COM_SET_INFORMATION = 0x09
    SMB_COM_READ = 0x0A
    SMB_COM_WRITE = 0x0B
    SMB_COM_LOCK_BYTE_RANGE = 0x0C
    SMB_COM_UNLOCK_BYTE_RANGE = 0x0D
    SMB_COM_CREATE_TEMPORARY = 0x0E
    SMB_COM_CREATE_NEW = 0x0F
    SMB_COM_CHECK_DIRECTORY = 0x10
    SMB_COM_PROCESS_EXIT = 0x11
    SMB_COM_SEEK = 0x12
    SMB_COM_LOCK_AND_READ = 0x13
    SMB_COM_WRITE_AND_UNLOCK = 0x14
    SMB_COM_READ_RAW = 0x1A
    SMB_COM_READ_MPX = 0x1B
    SMB_COM_READ_MPX_SECONDARY = 0x1C
    SMB_COM_WRITE_RAW = 0x1D
    SMB_COM_WRITE_MPX = 0x1E
    SMB_COM_WRITE_MPX_SECONDARY = 0x1F
    SMB_COM_WRITE_COMPLETE = 0x20
    SMB_COM_QUERY_SERVER = 0x21
    SMB_COM_SET_INFORMATION2 = 0x22
    SMB_COM_QUERY_INFORMATION2 = 0x23
    SMB_COM_LOCKING_ANDX = 0x24
    SMB_COM_TRANSACTION = 0x25
    SMB_COM_TRANSACTION_SECONDARY = 0x26
    SMB_COM_IOCTL = 0x27
    SMB_COM_IOCTL_SECONDARY = 0x28
    SMB_COM_COPY = 0x29
    SMB_COM_MOVE = 0x2A
    SMB_COM_ECHO = 0x2B
    SMB_COM_WRITE_AND_CLOSE = 0x2C
    SMB_COM_OPEN_ANDX = 0x2D
    SMB_COM_READ_ANDX = 0x2E
    SMB_COM_WRITE_ANDX = 0x2F
    SMB_COM_NEW_FILE_SIZE = 0x30
    SMB_COM_CLOSE_AND_TREE_DISC = 0x31
    SMB_COM_TRANSACTION2 = 0x32
    SMB_COM_TRANSACTION2_SECONDARY = 0x33
    SMB_COM_FIND_CLOSE2 = 0x34
    SMB_COM_FIND_NOTIFY_CLOSE = 0x35
    # Used by Xenix/Unix 0x60 - 0x6E 
    SMB_COM_TREE_CONNECT = 0x70
    SMB_COM_TREE_DISCONNECT = 0x71
    SMB_COM_NEGOTIATE = 0x72
    SMB_COM_SESSION_SETUP_ANDX = 0x73
    SMB_COM_LOGOFF_ANDX = 0x74
    SMB_COM_TREE_CONNECT_ANDX = 0x75
    SMB_COM_QUERY_INFORMATION_DISK = 0x80
    SMB_COM_SEARCH = 0x81
    SMB_COM_FIND = 0x82
    SMB_COM_FIND_UNIQUE = 0x83
    SMB_COM_FIND_CLOSE = 0x84
    SMB_COM_NT_TRANSACT = 0xA0
    SMB_COM_NT_TRANSACT_SECONDARY = 0xA1
    SMB_COM_NT_CREATE_ANDX = 0xA2
    SMB_COM_NT_CANCEL = 0xA4
    SMB_COM_NT_RENAME = 0xA5
    SMB_COM_OPEN_PRINT_FILE = 0xC0
    SMB_COM_WRITE_PRINT_FILE = 0xC1
    SMB_COM_CLOSE_PRINT_FILE = 0xC2
    SMB_COM_GET_PRINT_QUEUE = 0xC3
    SMB_COM_READ_BULK = 0xD8
    SMB_COM_WRITE_BULK = 0xD9
    SMB_COM_WRITE_BULK_DATA = 0xDA
    # Security Share Mode (Used internally by SMB class)
    SECURITY_SHARE_MASK = 0x01
    SECURITY_SHARE_SHARE = 0x00
    SECURITY_SHARE_USER = 0x01

    # Security Auth Mode (Used internally by SMB class)
    SECURITY_AUTH_MASK = 0x02
    SECURITY_AUTH_ENCRYPTED = 0x02
    SECURITY_AUTH_PLAINTEXT = 0x00

    # Raw Mode Mask (Used internally by SMB class. Good for dialect up to and including LANMAN2.1)
    RAW_READ_MASK = 0x01
    RAW_WRITE_MASK = 0x02

    # Capabilities Mask (Used internally by SMB class. Good for dialect NT LM 0.12)
    CAP_RAW_MODE = 0x0001
    CAP_MPX_MODE = 0x0002
    CAP_UNICODE = 0x0004
    CAP_LARGE_FILES = 0x0008
    CAP_EXTENDED_SECURITY = 0x80000000

    # Flags1 Mask
    FLAGS1_PATHCASELESS = 0x08

    # Flags2 Mask
    FLAGS2_LONG_FILENAME = 0x0001
    FLAGS2_USE_NT_ERRORS = 0x4000
    FLAGS2_UNICODE = 0x8000

    def __init__(self, remote_name, remote_host, my_name = None, host_type = libs.ext.impacket.nmb.TYPE_SERVER, sess_port = 445, timeout=None):

        # The uid attribute will be set when the client calls the login() method
        self.__uid = 0
        self.__server_os = ''
        self.__server_lanman = ''
        self.__server_domain = ''
        self.__remote_name = string.upper(remote_name)
        self.__is_pathcaseless = 0
        self.__ntlm_dialect = 0
        self.__sess = None
        self.__SMBv2_available = 0
        self.__SMBv2_version = ''

        if timeout==None:
            self.__timeout = 30
        else:
            self.__timeout = timeout

        if not my_name:
            my_name = socket.gethostname()
            i = string.find(my_name, '.')
            if i > -1:
                my_name = my_name[:i]

        try:
            self.__sess = libs.ext.impacket.nmb.NetBIOSSession(my_name, remote_name, remote_host, host_type, sess_port, timeout)
        except socket.error, ex:
            raise ex
        try:
            self.__neg_session()
        except Exception, msg:
            print msg

    def __neg_session(self):
         
        PROTOS = ['PC NETWORK PROGRAM 1.0', 'LANMAN1.0', 'Windows for Zorkgroups 3.1a', \
        'LM1.2X002', 'LANMAN2.1', 'NT LM 0.12', 'SMB 2.002', 'SMB 2.???']
        SMBv2_SIG = '\xfeSMB'
      
        s = libs.ext.impacket.smb.SMBPacket()
        s.set_command(SMBv2.SMB_COM_NEGOTIATE)
        s.set_flags(0x18)
        s.set_flags2(0xc853)
        s.set_mid(0x2222)
        s.set_buffer(''.join(map(lambda x: '\x02' + x + '\x00', PROTOS)))
        self.send_smb(s)

        try:
            r = self.__sess.recv_packet(self.__timeout)
        except Exception, msg:
            print msg

        if r.get_trailer()[:4] == SMBv2_SIG:
            self.__SMBv2_available = 1
            if len(r.get_trailer()) >= 70:
                self.__SMBv2_version = '.'.join([chr(ord(r.get_trailer()[68])+0x30),chr(ord(r.get_trailer()[69])+0x30)])   
        else:
            self.__SMBv2_available = 0

    def get_smbv2_version(self):
        return self.__SMBv2_version

    def is_supported(self):
        return self.__SMBv2_available

    def send_smb(self,s):
        s.set_uid(self.__uid)
        s.set_pid(os.getpid())
        self.__sess.send_packet(s.rawData())

    def recv_packet(self):
        r = self.__sess.recv_packet(self.__timeout)
        return libs.ext.impacket.smb.SMBPacket(r.get_trailer())

    def isValidAnswer(self, s, cmd):
        while 1:
            if s.rawData():
                if s.get_command() == cmd:
                    if s.get_error_class() == 0x00 and s.get_error_code() == 0x00:
                        return 1
                    else:
                        raise SessionError, ( "SMB Library Error", s.get_error_class(), s.get_error_code())
                else:
                    break
#                    raise SessionError("Invalid command received. %x" % cmd)
#            s=self.recv_packet(None)   
        return 0

def discovery(target, port=445):
  #try:
  smbla = libs.ext.impacket.smb.SMB("*SMBSERVER", target, sess_port = port)
  smbla.login('','')
  nfo  = 'SMB port is open\n'
  nfo += 'OS : ' + smbla.get_server_os() + '\n'
  nfo += 'Version : ' + smbla.get_server_lanman() + '\n'
  nfo += 'Uptime : Host is up since ' + smbla.get_server_time() + '\n'
  nfo += 'Domain(s) : ' + smbla.get_server_domain() + '\n'
  return nfo
  #except Exception, msg:
  #print msg

def listshares(target, port=445):
  nfo = ''
  smbla = libs.ext.impacket.smb.SMB("*SMBSERVER", target, sess_port = port)
  smbla.login('anonymous','')
  for share in smbla.list_shared():
    nfo += "%s - %s\n" % (share.get_name(),share.get_comment())
  return nfo

def checkv2(target, port=445):
  smbv2 = SMBv2("*SMBSERVER", target, sess_port=port)
  if smbv2.is_supported():
    return 'SMBv2 %s detected' % smbv2.get_smbv2_version()
  return None
