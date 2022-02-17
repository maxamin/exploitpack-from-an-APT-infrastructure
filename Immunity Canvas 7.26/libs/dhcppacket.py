#!/usr/bin/env python

from dhcpconstant import *
import struct
import string
import socket
import commands
import exploitutils

class DHCPPacket:

    def __init__(self):
        self.packetData = None
        self.Options = []
        self.RawOptions = []
        self.hdr_fmt = "<BBBBLHHLLLL16s64s128s"
        
        self.Hdr = {"op":2, "htype": 1, "hlen":6, "hops": 0, "xid": 0,\
                     "secs": 0, "flags": 0, "ciaddr": 0, "yiaddr": 0,\
                     "siaddr": 0, "giaddr": 0, "chaddr": "", "sname": "",\
                     "file": ""}
        
    def isDHCPtag(self, tag):
        return DhcpOptions.has_key(tag)
 
    def getOptionbyTag(self, tag):
        for a in self.Options:
            if tag == a[0]:
                return a[1]
        return None
        
    def getOption(self, name):
        name = string.lower(name)
        
        if self.Hdr.has_key(name):
            return self.Hdr[name]

        try:
            tag = DhcpOptionsbyName[name]
        except KeyError:
            raise Exception("Tag -%s- not found on a getOption call" % name)

        return self.getOptionbyTag(tag)
    
    
    def IsPacket(self, msg_type):
        opt = self.getOption(53) # get Message Type
        if opt == None:
            return False
        return opt[1] == msg_type
                
              
    def isDiscover(self):
        return self.isPacket(1)
    
    def isOffer(self):
        return self.isPacket(2)

    def isRequest(self):
        return self.isPacket(3)

    def isDecline(self):
        return self.isPacket(4)

    def isAck(self):
        return self.isPacket(5)

    def isNAck(self):
        return self.isPacket(6)

    def isRelease(self):
        return self.isPacket(7)

    def isInform(self):
        return self.isPacket(8)

    def isForceNew(self):
        return self.isPacket(9)

    def isLeaseQuery(self):
        return self.isPacket(10)

    def printHdr(self):
        tbl = []
        tbl.append("Op     = 0x%08x" % self.Hdr["op"])
        tbl.append("Htype  = 0x%08x" % self.Hdr["htype"])
        tbl.append("Hlen   = 0x%08x" % self.Hdr["hlen"])
        tbl.append("Hops   = 0x%08x" % self.Hdr["hops"])
        tbl.append("XID    = 0x%08x" % self.Hdr["xid"])
        tbl.append("Secs   = 0x%08x" % self.Hdr["secs"])
        tbl.append("Flags  = 0x%08x" % self.Hdr["flags"])
        tbl.append("Ciaddr = 0x%08x" % self.Hdr["ciaddr"])
        tbl.append("Yiaddr = 0x%08x" % self.Hdr["yiaddr"])
        tbl.append("Siaddr = 0x%08x" % self.Hdr["siaddr"])
        tbl.append("Giaddr = 0x%08x" % self.Hdr["giaddr"])
        tbl.append("Chaddr = %s" % self.Hdr["chaddr"])
        tbl.append("Sname  = %s" % self.Hdr["sname"])
        tbl.append("File   = %s" % self.Hdr["file"])
        
        return tbl
    def addRawOption(self, tag, value, size = None):
        sz = size
        if sz == None:
            sz = len(value) 

        if sz > 0xff:
            raise Exception, "option %d's might not be bigger than 0xff (size: %d)" % (tag, sz) 

        self.RawOptions.append( "%c%c" % (tag, sz) + value )

    # add an option
    def addOption(self, name, value):
        name = string.lower(name)
        if self.Hdr.has_key(name):
            self.Hdr[name] = value
        else:
            try:
                self.Options.append( (DhcpOptionsbyName[name], value) )
            except KeyError:
                raise Exception("dhcplib doesn't recognized option: %s" % name)

    def deleteOptionbyTag(self, tag):
        for a in range(0, len(self.Options)):
            if tag == self.Options[ a ][ 0 ]:
                del self.Options[a]
                return 1
        return 0


    def Discover2Offer(self, packet):
        self.setOption("op", 2)               # Boot reply 
        self.setOption("dhcp msg type", 0x2)  # Offer
        self.setOption( "htype", packet.getOption("htype") )
        self.setOption( "xid", packet.getOption("xid"))
        self.setOption( "flags", 0x0) # Unicast
        self.setOption( "yiaddr", packet.getOption("address request"))
        self.setOption( "siaddr", self.convertIP("192.168.1.101"))
        self.setOption( "chaddr", packet.getOption("chaddr"))
        self.setOption( "address time", 0x80510100) # 1 day
        self.setOption("dhcp server id", 0x41414141)

    def Request2ACK(self, packet):
        self.setOption("op", 2)
        self.setOption( "htype", packet.getOption("htype") )
        self.setOption( "xid", packet.getOption("xid"))
        self.setOption( "flags", packet.getOption("flags")) # Unicast
        self.setOption( "yiaddr", packet.getOption("address request"))
        self.setOption( "siaddr", self.convertIP("192.168.1.101"))
        self.setOption( "chaddr", packet.getOption("chaddr"))
        self.setOption("dhcp msg type", 0x5)  # ACK
        self.setOption( "address time", 0x80510100) # 1 day
        
        
    def deleteOption(self, name):
        try:
            tag = DhcpOptionsbyName[name]
        except KeyError:
            raise Exception("Tag -%s- not found on a deleteOption call" % name)

        return self.deleteOptionbyTag(tag)
        
    # set an option: first try to set an existant, if it doesn't exist will be appended
    def setOption(self, name, value):
        name = string.lower(name)
        if self.Hdr.has_key(name):
            self.Hdr[name] = value
        else:
            try:
                tag = DhcpOptionsbyName[name]
                for ndx in range(0, len(self.Options)):
                    if self.Options[ndx][0] == tag:
                        self.Options[ndx] = (tag, value)
                        return 1                        
                self.Options.append( (DhcpOptionsbyName[name], value) )
            except KeyError:
                raise Exception("dhcplib doesn't recognized option: %s" % name)
        
        
    def printOptions(self):
        tbl = []
        for a in self.Options:
            try:
                name = DhcpOptions[ a[0] ][1]
            except KeyError:
                name = "%d" % a[0]
            
            tbl.append("%s\t = %s" % (name, str(a[1])) )
        return tbl
    
    def parseHdr(self, message):
        (self.Hdr["op"], self.Hdr["htype"], self.Hdr["hlen"], self.Hdr["hops"], self.Hdr["xid"], self.Hdr["secs"],\
         self.Hdr["flags"], self.Hdr["ciaddr"], self.Hdr["yiaddr"], self.Hdr["siaddr"], self.Hdr["giaddr"],\
         self.Hdr["chaddr"], self.Hdr["sname"], self.Hdr["file"]) = struct.unpack(self.hdr_fmt, message)
        
    def raw(self, magic = 1):        
        data = [struct.pack(self.hdr_fmt, self.Hdr["op"], self.Hdr["htype"], self.Hdr["hlen"], self.Hdr["hops"], self.Hdr["xid"], self.Hdr["secs"],\
         self.Hdr["flags"], self.Hdr["ciaddr"], self.Hdr["yiaddr"], self.Hdr["siaddr"], self.Hdr["giaddr"],\
         self.Hdr["chaddr"], self.Hdr["sname"], self.Hdr["file"])]
        
        if magic:
            data+= [MagicCookie]
        data += self.getRawOptions()
            
        return string.joinfields(data, "")
    
    def getRawOptions(self, add_end_tag = 1):        
        data = []
        for opt in self.Options:
            tag = opt[0]
            if self.isDHCPtag(tag):
                dhopt = DhcpOptions[ tag ] # we need the option info to get the Size
                try:
                    opt_data = DhcpSizeEncode[ dhopt[0] ]( opt[1] )
                except KeyError:
                    opt_data = opt[1]
            else:
                opt_data = opt[1]
            data += self.getrawoption( tag, opt_data)
        data += self.RawOptions
 
        if add_end_tag:
            data+= ["\xff"]
        return data

    def getrawoption(self, tag, data):
        if not data:
            return [chr(tag), "", ""]
        if len(data) > 0xff:
            raise Exception( "Tag %d bigger than 0xff (%d)" % (tag, len(data)) )
        return [chr(tag), chr(len(data)), data]

    def get(self, data):
        dhcp_message = data[:236]
        options = data[236:]
        ndx = options.find(MagicCookie)
        self.parseHdr(dhcp_message)
        # Do we have a magic cookie?     
        if ndx == -1:
            print "no magic cookie"
            return 0
        
        # Getting options
        # Options format:
        # [ tag ] [ len ] [  data of len size ]
        #  1 byte  1byte     len bytes
        ndx += len(MagicCookie)
        OPTION_SZ = len(options)
        
        while ndx < OPTION_SZ:
            tag = ord(options[ndx])

            if tag == 0:
                ndx += 1
            elif tag == 0xff: # end of options
                break
            else: 
                try:
                    option_size = ord(options[ndx+1])
                except IndexError:
                    raise Exception("Error on options, OptionSize is out of index on tag: %d (index: %d)" % (tag, ndx))
                    
                opt_data = ""
                if self.isDHCPtag(tag):
                    opt = DhcpOptions[tag]
                    
                    if opt[0] != ord( options[ndx+1] ):
                        pass # XXX for the future

                    try:
                        opt_data = DhcpSizeDecode[ ord(options[ndx+1]) ]( options[ndx+2: ndx+2+ option_size] )
                    except KeyError:

                        # We dont support that size yet
                        if ndx+1+ option_size < OPTION_SZ:
                            opt_data = options[ndx+2: ndx+2+ option_size]
                        else:
                            raise Exception("Error on options, OptionData is out of index on tag: %d (index: %d)" % (tag, ndx)) 
                else:
                    if ndx+1+ option_size < OPTION_SZ:
                        opt_data = options[ndx+2: ndx+2+ option_size]
                    else:
                        raise Exception("Error on options, OptionData is out of index on tag: %d (index: %d)" % (tag, ndx)) 

                self.Options.append( (tag, opt_data ) )                
                ndx+= 2+ option_size

    # Transform a string ip (x.x.x.x) into an integer
    def convertIP(self, ip):
        return str2littleendian(socket.inet_aton(ip))

    # Transform an integer IP to a string
    def intIPtostr(self, ip):
        return exploitutils.int32toIpstr(ip, 1)
    
    # Get the hardware mac address for the local interface
    def getMac(self, iface="eth0"):
        ifconf = commands.getstatusoutput("ifconfig "+ iface)
        b = string.split(ifconf[1], "\n")
        c = string.split(b[0], "HWaddr ")
        if(len(c)==2):
            mac = c[1].strip()
        else:
            mac = "00:00:00:00:00:00"
        print "Found MAC address:", mac, " for interface:", iface
        return mac
    
    
    # Convert the mac address into network order
    def convertMAC(self, mac):
        ret = ""
        tmac = mac.split(":")
        for x in tmac:
            ret += chr(int(x, 16))
        return ret
    
