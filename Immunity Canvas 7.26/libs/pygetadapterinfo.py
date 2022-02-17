#!/usr/bin/env python
##ImmunityHeader v1 
##########################################################################
##
## File       :  pygetifaddrs.py
## Description:  Windows version of getifaddrs - which is really GetAdaptorInfo
##            :  
## Created_On :  Thur Oct  29 09:18:38 2009
## Created_By :  Rich 
## Modified_On:  Thur Oct  29 17:37:23 2009
## Modified_By:  Rich
## (c) Copyright 2009, Immunity Inc all rights reserved.
##
##########################################################################
import ctypes
import socket
from get_interfaces import Ifaces
from get_interfaces import NetIface


##Statics
MAX_ADAPTER_ADDRESS_LENGTH     = 8
MAX_ADAPTER_DESCRIPTION_LENGTH = 128
MAX_ADAPTER_NAME_LENGTH        = 256

##From ipifcons.h
MIB_IF_TYPE_OTHER              = 1
MIB_IF_TYPE_ETHERNET           = 6
MIB_IF_TYPE_TOKENRING          = 9
MIB_IF_TYPE_FDDI               = 15
MIB_IF_TYPE_PPP                = 23
MIB_IF_TYPE_LOOPBACK           = 24
MIB_IF_TYPE_SLIP               = 28

MIB_IF_ADMIN_STATUS_UP         = 1
MIB_IF_ADMIN_STATUS_DOWN       = 2
MIB_IF_ADMIN_STATUS_TESTING    = 3


##/end Statics

##Structures
class _IP_ADDR_STRING(ctypes.Structure):
    """
    C like structure for IP_ADDR_STRING structure
    
    http://msdn.microsoft.com/en-us/library/aa366068(VS.85).aspx
    """
    pass
POINTER_IP_ADDR_STRING = ctypes.POINTER(_IP_ADDR_STRING)

_IP_ADDR_STRING._fields_ = [
                        ("next"     , POINTER_IP_ADDR_STRING),
                        ("IpAddress", ctypes.ARRAY(ctypes.c_char, 16)),
                        ("IpMask"   , ctypes.ARRAY(ctypes.c_char, 16)),
                        ("Context"  , ctypes.c_ulong)
                           ]


class _IP_ADAPTER_INFO(ctypes.Structure):
    """
    C like structure for a _IP_ADAPTOR_INFO structure
    
    http://msdn.microsoft.com/en-us/library/aa366062(VS.85).aspx
    """
    pass
POINTER_IP_ADAPTER_INFO = ctypes.POINTER(_IP_ADAPTER_INFO)

_IP_ADAPTER_INFO._fields_ = [
                ("Next"              , POINTER_IP_ADAPTER_INFO),
                ("ComboIndex"        , ctypes.c_ulong),
                ("AdapterName"       , ctypes.ARRAY(ctypes.c_char,
                                      MAX_ADAPTER_NAME_LENGTH + 4)),
                ("Description"       , ctypes.ARRAY(ctypes.c_char,
                                     MAX_ADAPTER_DESCRIPTION_LENGTH + 4)),
                ("AddressLength"     , ctypes.c_uint),
                ("Address"           , ctypes.ARRAY(ctypes.c_ubyte,
                                      MAX_ADAPTER_ADDRESS_LENGTH )),
                ("Index"             , ctypes.c_ulong),
                ("Type"              , ctypes.c_uint),
                ("DhcpEnabled"       , ctypes.c_uint),
                ("CurrentIpAddress"  , POINTER_IP_ADDR_STRING),
                ("IpAddressList"     , _IP_ADDR_STRING),
                ("GatewayList"       , _IP_ADDR_STRING),
                ("DhcpServer"        , _IP_ADDR_STRING),
                ("HaveWins"          , ctypes.c_uint),
                ("PrimaryWinsServer" , _IP_ADDR_STRING),
                ("SecondaryWinsServer",_IP_ADDR_STRING),
                ("LeaseObtained"     , ctypes.c_ulong),
                ("LeaseExpires"      , ctypes.c_ulong)
                            ]


##/end Structures

class GetAdaptorInfo:
    """
    Class to access the win32 API functionality offered by GetAdaptorInfo
    
    http://msdn.microsoft.com/en-us/library/aa365917(VS.85).aspx        
    """
    def __init__(self):
        """
        Set up a Ifaces object
        """
        self.interfaces = Ifaces()
        
    def __str__(self):
        """
        Show string representation of what we know
        """
        return self.interfaces.__str__()
        
    def __call__(self):
        """
        Actually call the GetAdaptorInfo function from windll
        """
        getadaptersinfo          = ctypes.windll.iphlpapi.GetAdaptersInfo
        getadaptersinfo.restype  = ctypes.c_ulong
        getadaptersinfo.argtypes = [POINTER_IP_ADAPTER_INFO,
                                    ctypes.POINTER(ctypes.c_ulong)]
        
        adapter_list = (_IP_ADAPTER_INFO * 24)()
        buflen       = ctypes.c_ulong(ctypes.sizeof(adapter_list))
        ret          = getadaptersinfo(ctypes.byref(adapter_list[0]), 
                                       ctypes.byref(buflen))
        
        ## so we don't get the stupid long windows identifiers everywhere
        adaptor_id = 0
        
        if ret == 0:
            for adaptor in adapter_list:
                
                ##Create new interface object for the hw addr - we use a psuedo
                ## identifier rather than the long win32 one. We note it though
                ## along with the textual description incase we needs it
                interface_item = NetIface( "#%d"%(adaptor_id) )
                interface_item.misc.update( {"AdapterName" : adaptor.AdapterName,
                                            "Description"  : adaptor.Description} )
                
                #print adaptor.AdapterName
            
                ##Fake in the sa_family data for the hwaddr :)
                interface_item.family_val  = 0x11
                interface_item.family_name = "AF_PACKET"
                
                a_len = adaptor.AddressLength
                hwaddr = ""
                #print "Type",adaptor.Type
                if adaptor.Type == MIB_IF_TYPE_ETHERNET:
                    ##Ethernet
                    for x in adaptor.Address[:a_len]:
                        hwaddr += "%02x:"%(x)
                    hwaddr = hwaddr[:-1]
                    
                    interface_item.addr = {"address": hwaddr}
                
                    ##Add the NetIface object to the Ifaces container
                    self.interfaces.add(interface_item)
                
                #print "Descr",adaptor.Description
                
                ##Create new interface object for the ipv4 addr - same psuedo id
                interface_item = NetIface( "#%d"%(adaptor_id) )
                interface_item.misc.update( {"AdapterName" : adaptor.AdapterName,
                                            "Description"  : adaptor.Description} )
                #print adaptor.AdapterName 

                ipv4_addr = adaptor.IpAddressList.IpAddress
                if ipv4_addr:
                    
                    ##Fake in the sa_family data for the ipv4 addr :)
                    interface_item.family_val  = socket.AF_INET
                    interface_item.family_name = "AF_INET"
                    
                    interface_item.addr = {"address" : ipv4_addr,
                                           "dhcp" : adaptor.DhcpEnabled
                                           }
                    
                    ##Get netmask
                    ipv4_netmask = adaptor.IpAddressList.IpMask
                    if ipv4_netmask:
                        interface_item.netmask = {"address" : ipv4_netmask }
                    
                    ##Add the NetIface object to the Ifaces container
                    self.interfaces.add(interface_item)
  
                if adaptor.Index == 0:
                    break
                
                ##Inc id
                adaptor_id += 1
                
        return ret
        
        
if __name__ == "__main__":
    
    GAI = GetAdaptorInfo()
    GAI()
        