from socket import *
import struct
import time

import libs.canvasos as canvasos

"""
This module will succeedd if NTP Control Messages are allowed.  Some NTP servers will only allow
these messages from localhost.

/etc/ntp.conf

# By default, exchange time with everybody, but don't allow configuration.
restrict -4 default kod notrap nomodify nopeer noquery
restrict -6 default kod notrap nomodify nopeer noquery

# Local users may interrogate the ntp server more closely.
restrict 127.0.0.1
restrict ::1
"""

class ntpdetect:
    """
    Very basic NTP client queries.  For now it can only get the time and send a control message to enumerate system information
    """
    def __init__(self):
        self.client = socket(AF_INET, SOCK_DGRAM)
        self.result = None

    def get_results(self):
        for i in range(1, 4):
            if self.result:
                return
            else:
                try:
                    self.get_control()
                except Exception, e:
                    self.log("Try %d/3 got exception: %s. (No response to NTP Control Message)"%(i, e))
    
    def get_control(self):
        """
        Send the control message and parse the response to get the system      
        """
        data = "\x16"  #flags
        data += "\x02" #flags 2 (Control Message)
        data += "\x00\x02\x00\x00\x00\x00\x00\x00\x00\x00"
        
        self.client.sendto( data, (self.host, 123))
        self.log("Sent control message")

        is_interesting = ["system"]#,"version","processor"]
        ##TODO: might not be a bad idea to add "version" and "processor" to our knowledge also
    

        data, address = self.client.recvfrom( 768 )
        if data:
            data = data[12:].split(",")
            for entry in data:
                entry = entry.replace("\r\n","")
                name, value = entry.split("=")
                name = name.lower().strip()
                if name in is_interesting:
                    self.log("NTP server system: %s"%value)
                    value = value.replace("\"","")
            
                    self.check_type(value)
        ##some servers don't like consecutive requests!
        time.sleep(3)
       
                    
    
    def check_type(self, server_type):
        """
        check the server_type string and map to a server type that CANVAS understands
        """
        self.log("Attempting to map %s to known server type"%server_type)
        types = {"Linux":["linux"],
                 "Unix":["freebsd","gentoo","unix","openbsd","redhat","netbsd","hpux"],
                 "MAC OS X":["darwin","osx", "os x"],
                 "Windows":["windows"],
                 "Solaris":["sunos"],
                 "Cisco":["cisco"]
                 }
        
        for platform in types.keys():
            for t in types[platform]:
                #print "looking for %s in '%s'"%(t, server_type.lower())
                if t in server_type.lower():
                    #print "found %s!"%platform
                    self.result = canvasos.new(platform)
                    self.result.version = server_type
                    return
        
        self.log("Could not map '%s' to known server type. Perhaps we skipped that one?"%server_type)
        
        
    def get_enum(self):

        for i in range(1, 4):
            try:
                if self.enum_server():
                    return 1
            except Exception, e:
                self.log("Try %d/3 got exception: %s.  Is NTP running?"%(i, e))
        
        return 0
           
    def enum_server(self):
        self.log("Sending NTP message to elicit response")
        
        msg = "\xDB\x00\x04\xFA\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        msg += "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        msg += "\x00\x00\x00\x00\x00\x00\x00\x00\xBE\x78\x2F\x1D\x19\xBA\x00\x00"
        self.client.sendto(msg, (self.host, 123))
        data, address = self.client.recvfrom( 1024 )
        if data:
            self.log("Got valid response from an NTP server")
            t = struct.unpack('!12I', data)[10]
            t -= 2208988800L
            self.log("NTP sync time: %s"%time.ctime(t))
            return 1
        return 0
           
    def run_ntpdetect(self):
        
        if self.get_enum():
            self.get_results()
                
            self.client.close()
            
            if self.result:
                return self.result
            else:
                return 0
                
        