#! /usr/bin/env python
"""

dtspcd Class for OS finger printing.
self.uname_d returns a dictonary in the form of:

{"hostname": "sol8db", "os": "SunOS", "version": "5.8", "arch": "sun4u"}


"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2003
#http://www.immunityinc.com/CANVAS/ for more information

VERSION="1.0"

import sys
if "." not in sys.path: sys.path.append(".")
import timeoutsocket

CHANGES="""


"""

import os
import sys
import socket
import string
import struct
import random
import select


PORT = 6112
CHANNEL_ID = 2
SPC_ABORT = 3
SPC_REGISTER = 4

class DTSPCDException(Exception):
    pass

class DTSPCDClient:
    """
    self explainatory ...
>>> import dtspcd_client
>>> d  = dtspcd_client.DTSPCDClient("192.168.10.40")
>>> d.setup()
>>> print d.get_uname()
{'arch': 'sun4u', 'hostname': 'slint', 'os': 'SunOS', 'version': '5.8'}
>>> 
    """
    
    def __init__(self, target, port=PORT, exploit=None):
        self.seq = 1
        self.target = target
        self.port = port
        self.exploit=exploit
        return 
    
    def spc_register(self, user, buf):
        return "4 " + "\x00" + user + "\x00\x00" + "10" + "\x00" + buf
    
    def spc_write(self, buf, cmd):
        self.data = "%08x%02x%04x%04x  " % (CHANNEL_ID, cmd, len(buf), self.seq)
        self.seq += 1
        self.data += buf
        if self.sck.send(self.data) < len(self.data):
            raise DTSPCDException("network problem, packet not fully sent")
        return 
        
    def spc_read(self):
        
        self.recvbuf = self.sck.recv(20)

        if len(self.recvbuf) < 20:
            raise  DTSPCDException("network problem, packet not fully read - length is %d"%len(self.recvbuf))

        self.chan = string.atol(self.recvbuf[:8], 16)
        self.cmd =  string.atol(self.recvbuf[8:10], 16)
        self.mbl =  string.atol(self.recvbuf[10:14], 16)
        self.seqrecv = string.atol(self.recvbuf[14:18], 16)

        #print "chan, cmd, len, seq: " , self.chan, self.cmd, self.mbl, self.seqrecv
        
        self.recvbuf = self.sck.recv(self.mbl)
        
        if len(self.recvbuf) < self.mbl:
            raise  DTSPCDException("network problem, packet not fully read")

        return self.recvbuf
        
    def get_uname(self):

        self.setup()
        
        self.uname_d = { "hostname": "", "os": "", "version": "", "arch": "" }

        self.spc_write(self.spc_register("root", "\x00"), SPC_REGISTER)
        
        self.resp = self.spc_read()
        try:
            self.resp = self.resp[self.resp.index("1000")+5:len(self.resp)-1]
        except ValueError: # 2000 .. AIX
            try:
                self.resp = self.resp[self.resp.index('2000') + 5 : len(self.resp) - 1]
            except ValueError:
                raise DTSPCDException("Non standard response to REGISTER cmd")

        self.resp = self.resp.split(":")
        
        self.uname_d = { "hostname": self.resp[0],\
                         "os": self.resp[1],\
                         "version": self.resp[2],\
                         "arch": self.resp[3] }

        self.spc_write("", SPC_ABORT)

        self.sck.close()

        return self.uname_d
        
    def setup(self):
        """
        Connect to the remote dtspcd server
        """
        
        #here we support CANVAS bouncing by getting our socket from the exploit object - which 
        #in turn will get it from a remote node if necessary
        if self.exploit:
            self.sck = self.exploit.gettcpsock()
        else:
            #this should never really happen, but it's here for testing purposes
            self.sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
        
        try:
            self.sck.connect((self.target, self.port))
        except timeoutsocket.Timeout, err:
            raise DTSPCDException("DTSPCDExploit, Host: " + str(self.target) + ":"\
                  + str(self.port) + " " + str(err[1]))
        except socket.error, err:
            raise DTSPCDException("DTSPCDExploit, Host: " + str(self.target) + ":"\
                  + str(self.port) + " " + str(err[1]))
        self.log("DTSCPD Client connected to %s:%d"%(self.target, self.port))
        return True 
    
    def log(self, msg):
        """
        Log a message either to an exploit's log function or just to the screen (for testing)
        """
        if self.exploit:
            self.exploit.log(msg)
        else:
            print msg

if __name__=="__main__":
    t=DTSPCDClient(sys.argv[1])
    #t.setup()
    print t.get_uname()
