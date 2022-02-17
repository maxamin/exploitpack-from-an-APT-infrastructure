#! /usr/bin/env python

import socket
import os
import xdr
import rpc
from rpc import Packer, Unpacker, UDPClient


class YPException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`

class YP_Packer(Packer):
    
    def pack_yp_bindproc_domain_req(self, domain):
        #domain
        self.pack_string(domain)
        
class YP_Unpacker(Unpacker):
    
    def unpack_yp_reply(self):
        result = self.unpack_int()
        value = self.unpack_int()
        return result   #success: 1, fail: 2
        
class YP_Client(UDPClient):

    def __init__(self, target):
        self.yp_d = { "PROGNUM": 100007, "VERSNUM": 3, "YPBINDPROC_DOMAIN": 1 }
        
        UDPClient.__init__(self, target, self.yp_d["PROGNUM"], self.yp_d["VERSNUM"])

    def addpackers(self):
        self.packer = YP_Packer()
        self.unpacker = YP_Unpacker("")

    def mkcred(self):
        import random
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(random.randint(1,99999),\
                                                      "localhost", 0, 0, [])
        return self.cred
    
    def ypbindproc_domain(self, domain):
        return self.make_call(self.yp_d["YPBINDPROC_DOMAIN"], domain,\
                              self.packer.pack_yp_bindproc_domain_req,\
                              self.unpacker.unpack_yp_reply)
    
class YPPASSWDD_Packer(Packer):
    
    def pack_yppasswd_update(self, buffer):
        #old pw
        self.pack_string("\x00")
        #new pw
        self.pack_string(buffer)
        
class YPPASSWDD_Unpacker(Unpacker):
    
    def unpack_yppasswd_reply(self):
        result = self.unpack_int()
        return result
    
class YPPASSWDD_Client(UDPClient):

    def __init__(self, target):
        self.yp_d = { "PROGNUM": 100009, "VERSNUM": 1, "YPPASSWD_UPDATE": 1 }
        
        UDPClient.__init__(self, target, self.yp_d["PROGNUM"], self.yp_d["VERSNUM"])

    def addpackers(self):
        self.packer = YPPASSWDD_Packer()
        self.unpacker = YPPASSWDD_Unpacker("")

    def mkcred(self):
        import random
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(random.randint(1,99999),\
                                                      "localhost", 0, 0, [])
        return self.cred
    
    def yppasswd_update(self, buffer):
        return self.make_call(self.yp_d["YPPASSWD_UPDATE"], buffer,\
                              self.packer.pack_yppasswd_update,\
                              self.unpacker.unpack_yppasswd_reply)
         
if __name__ == "__main__":

   pass

