#!/usr/bin/env python
##ImmunityHeader v1 
############################################################################
##
## File       :  ifaces.py
## Description:  Get the network interfaces and associated addresses from
##            :  the local system. X-platform for UNIX
## Created_On :  Fri Oct  9 22:18:38 2009
## Created_By :  Rich 
## Modified_On:  Fri Oct  9 22:42:38 2009
## Modified_By:  Rich
## (c) Copyright 2009, Immunity Inc all rights reserved.
##
############################################################################

import ctypes
import socket
import struct
import array
import fcntl
import sys
import os
import pprint

##On OS X (maybe other BSD's ?) the address family of interfaces
## is not AF_INET(0x2)/AF_INET6(0xA) but AF_LINK(0x12) & this is
## not defined in socket module so we define it here
AF_LINK   = 0x12

class NetIface(object):
    """
    Object representation of a net interface
    """
    def __init__(self, name):
        
        self.ifr_name   = name
        self.af_family  = None
        self.if_addr    = None
        self.if_hwaddr  = None
        self.if_brdaddr = None
        self.if_netmask = None
    
    def __str__(self):
        
        return "%s: %s - %s - %s [%s]"%(self.ifr_name, self.if_addr,
                                   self.if_netmask, self.if_brdaddr,
                                   self.if_hwaddr)


class Ifaces:
    """
    Cross platform code to get network interfaces on *NIX like systems
    """
    
    def __init__(self):
        """
        Set the system specific variables
        """
        ##System specific ioctls for listing intercaces
        ## Darwin values from:
        ## /Developer/SDKs/MacOSX10.6.sdk/usr/include/sys/sockio.h
        self.SIOCGIFCONF    = {"linux2" : 0x8912,
                               "linux3" : 0x8912, 
                               "darwin": ctypes.c_int32(0xc0086914L).value,
                               "sunos" : ctypes.c_int32(0xc0086914L).value,
                               }
        
        self.SIOCGIFADDR    = {"linux2" : 0x8915,
                               "linux3" : 0x8915,
                               "darwin": ctypes.c_int32(0xc0206921L).value,
                               "sunos" : ctypes.c_int32(0xc020690dL).value,
                               }
        
        self.SIOCGIFBRDADDR = {"linux2" : 0x8919,
                               "linux3" : 0x8919,
                               "darwin": ctypes.c_int32(0xc0206923L).value,
                               "sunos" : ctypes.c_int32(0xc0206913L).value,
                               }
        
        self.SIOCGIFNETMASK = {"linux2" : 0x891b,
                               "linux3" : 0x891b,
                               "darwin": ctypes.c_int32(0xc0206925L).value,
                               "sunos" : ctypes.c_int32(0xc0206916L).value,
                               }
        
        ##There is no such ioctl on darwin we have to do it via IOKitLib
        ## http://developer.apple.com/mac/library/samplecode/GetPrimaryMACAddress/
        ##        GetPrimaryMACAddress.zip
        ##Not tested on sun as yet
        self.SIOCGIFHWADDR  = {"linux2" : 0x8927,
                               "linux3" : 0x8927,
                               "sunos" : ctypes.c_int32(0xc020693cL).value,
                               }
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.valid_families = [socket.AF_INET, socket.AF_INET6, AF_LINK]
        
        self.ifaces = []
        

    def __call__(self):
        """
        Get all the interfaces on a system and populat net_iface objects
        """
        ##Find all the interfaces
        self.iface_list()
        
        ##For the found interfaces get the details
        for i in self.ifaces:
            self.get_addr(i)
            self.get_netmask(i)
            self.get_broadcast(i)
            self.get_hwaddr(i)
            
            
    def show_all(self):
        """
        print out all the known interfaces
        """
        for i in self.ifaces:
            self.show(i)
            
            
    def show(self, iface_obj):
        """
        print out the data know for the specified net_iface object
        """
        #print type(iface_obj)
        print iface_obj
        
    
    def iface_list(self):
        """
        Return a list of net_iface objects for ifaces on a system or an
         empty list on failure
        """
        ##from /usr/include/net/if.h:
        ##/* Structure used in SIOCGIFCONF request.  Used to retrieve 
        ##   interface configuration for machine (useful for programs 
        ##   which must know all networks accessible).  */
        ##
        ##struct ifconf
        ##{
        ## int ifc_len;  /* Size of buffer.  */
        ## union
        ## {
        ##  __caddr_t ifcu_buf;
        ##  struct ifreq *ifcu_req;
        ## } ifc_ifcu;
        ##};
        ##
        ## Our ioctl call returns equiv of:
        ##
        ## define ifc_buf ifc_ifcu.ifcu_buf       /* buffer address */
        ## define ifc_req ifc_ifcu.ifcu_req       /* array of structs
        ##                                           returned */

        
        ##Create an ifc structure int buffer_size; void* pointer_to_mem
        buff = array.array('c', '\xcc' * 1024)
        ifc  = struct.pack("iP", buff.buffer_info()[1], 
                                 buff.buffer_info()[0] )
        
        ##Do it ioctl call
        try:
            if_info = fcntl.ioctl(self.sock.fileno(), 
                                  self.SIOCGIFCONF[sys.platform], ifc)
        except (IOError, KeyError):
            #import traceback
            #traceback.print_exc()
            #print "Unexpected fcntl behaviour! add interfaces manually"
            return
        
        ##
        size, ptr = struct.unpack("iP", if_info)
        
        buffstr = buff.tostring()
        #pprint.pprint(buffstr)
        
        ##The structure that comes back can vary depending on platform
        ## Linux looks like:
        ##
        ## ifr_name        16bytes/"eth0"
        ## ifru_addr       16bytes/sockaddr_in for 10.1.1.1
        ## ifr_name        16bytes/"eth1"
        ## ifru_addr       16bytes/sockaddr_in for 10.1.1.2
        ## ... On 64 bits systems 32bit field -> 40 bits
        ##
        ## On BSD type systems (Including OSX) we can have:
        ##
        ## ifr_name        16bytes/"en0"
        ## ifru_addr       16bytes/sockaddr_in for 10.1.1.1
        ## ifr_name        16bytes/"en1"
        ## ifru_addr       30bytes/sockaddr_dl, sa_len = 30
        ## ....
        ## The rule being: 
        ##  - if item in ifru_addr is smaller than sizeof(sockaddr), we
        ##    pad to sizeof(sockaddr).
        ##  - if item in ifru_addr is larger, consult sa_len
        ##
        ## :(

        if os.uname()[-1] == 'x86_64' and sys.platform == "linux2":
            sizeof_struct_ifconf = 40
        elif os.uname()[-1] == 'x86_64' and sys.platform == "linux3":
            sizeof_struct_ifconf = 40
        else:
            sizeof_struct_ifconf = 32
        
        for idx in range(0, size, sizeof_struct_ifconf):
            ifconf = buffstr[idx:idx+sizeof_struct_ifconf]
            
            ## sockaddr struct is:
            ## struct sockaddr {
            ## unsigned short  sa_family;  //address family, AF_xxx
            ## char            sa_data[14];//14 bytes of protocol address
            ## };
            fmt = "<16sH14x"
            name, af_family = struct.unpack(fmt, ifconf[:struct.calcsize(fmt)])
            ##ifr_names are NULL terminated
            name = name.split('\0', 1)[0]
            
            ##On OS X interfaces seem to appear multiple times?
            if af_family in self.valid_families and not \
                name in self.found_interfaces():
                
                #interfaceList += [name]
                new_iface           = NetIface(name)
                new_iface.af_family = af_family
                self.ifaces.append(new_iface)
        
                
    def found_interfaces(self):
        """
        Return a list of names of the interfaces we currently know about
        """
        ret = []
        for iface in self.ifaces:
            ret.append(iface.ifr_name)            
        return ret
    
    
    def get_addr(self, iface_obj):
        """
        For the interface ifr_name get the interface address
        """
        try:
            ret = self._do_ioctl(iface_obj.ifr_name, 
                                 self.SIOCGIFADDR[sys.platform])
        except KeyError:
            return None
            
        if ret:
            iface_obj.if_addr = socket.inet_ntoa(ret[20:24])
        
            
    def get_netmask(self, iface_obj):
        """
        For the interface ifr_name get the netmask 
        """
        try:
            ret = self._do_ioctl(iface_obj.ifr_name, 
                                 self.SIOCGIFNETMASK[sys.platform])
        except KeyError:
            return None
        
        if ret:
            iface_obj.if_netmask = socket.inet_ntoa(ret[20:24])
            
        
    def get_broadcast(self, iface_obj):
        """
        For the interface ifr_name get the broadcast address
        """
        try:
            ret = self._do_ioctl(iface_obj.ifr_name, 
                                 self.SIOCGIFBRDADDR[sys.platform])
        except KeyError:
            return None
        
        if ret:
            iface_obj.if_brdaddr = socket.inet_ntoa(ret[20:24])
            
            
    def get_hwaddr(self, iface_obj):
        """
        For the interface ifr_name get the hardware address
        """
        if sys.platform != "darwin":
            try:
                ret = self._do_ioctl(iface_obj.ifr_name, 
                                     self.SIOCGIFHWADDR[sys.platform])
            except KeyError:
                return None
            
            if ret:
                hex_addy = ""
                for h in ret[18:24]:
                    hex_addy += "%.2x:"%(struct.unpack("B", h) )
                    
                iface_obj.if_hwaddr = hex_addy[:-1]
            
        
    def _do_ioctl(self, ifr_name, ioctl_value):
        """
        Make an ioctl call of type specified for interface name ifr_name
        Returns None on error
        """
        iface = struct.pack('256s', ifr_name)

        try:
            return fcntl.ioctl(self.sock.fileno(), 
                              ioctl_value, 
                              iface)
        except IOError:
            #import traceback
            #traceback.print_exc()
            #print "Unexpected fcntl behaviour! add interface manually"
            return None
    
        
if __name__ == "__main__":
    
    iFace = Ifaces()
    iFace()
    iFace.show_all()
