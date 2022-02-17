#!/usr/bin/env python
##ImmunityHeader v1
##########################################################################
##
## File       :  pygetifaddrs.py
## Description:  Get the network interfaces and associated addresses from
##            :  the local system. X-platform for UNIX
## Created_On :  Mon Oct  26 09:18:38 2009
## Modified_On:  Thu Nov 12 10:54:11 2009
## Modified_By:  Rich
## Modified_By:  Rich
## (c) Copyright 2009, Immunity Inc all rights reserved.
##
##########################################################################

import sys
import socket
import re
import struct
##While this looks weird and down right retarded there is a reason!!!
##In CANVAS we wrap struct so we get consistant behaviour on 32 & 64 bit
## platforms when no format specifier is supplied. To see what I am
## rambling about do a struct.calcsize() for "L","<L","@L",">L" and you
## will see :) The bug the import/reload below fixes is in ctypes where
## it does a bunch of size check and CANVAS has pulled the rug out
import os
if not os.getenv("CANVAS_RUNNING") or os.getenv("CANVAS_RUNNING").upper() == "NO":
    #print "CANVAS NOT RUNNING"
    reload(struct)

import ctypes

#from tcp_ip_structures import *
from get_interfaces import Ifaces
from get_interfaces import NetIface

DEBUG = False

##Choose correct libc for the platform
if sys.platform == "darwin":
    try:
      LIBC = ctypes.CDLL("libc.dylib")
    except OSError:
      # Fix for MacOS X El Capitan, full-path is required
      LIBC = ctypes.CDLL("/usr/lib/libc.dylib")

elif sys.platform != "win32":
    ##Big assumption true
    LIBC = ctypes.CDLL("libc.so.6")

else:
    ##Must be win32 - we don't do this yet?
    print "win32 not supported by this module"
    sys.exit(-1)

##Structures

    ##sockaddr is different on linux & bsd
if sys.platform == "darwin" or "bsd" in sys.platform:
    ##OS X & BSD
    class osockaddr(ctypes.Structure):
        """C like structure for osockaddr Stevens 3.5"""
        _fields_ = [
                   ('sa_len', ctypes.c_uint8),
                   ('sa_family', ctypes.c_uint8),
                   ('sa_data'  , ctypes.ARRAY( ctypes.c_char, 14) )
                   ]
else:
    ##Linux/cygwin
    class osockaddr(ctypes.Structure):
        """C like structure for osockaddr Stevens 3.5"""
        _fields_ = [
                   ('sa_family', ctypes.c_ushort),
                   ('sa_data'  , ctypes.ARRAY( ctypes.c_char, 14) )
                   ]

class in_addr(ctypes.Structure):
    """"C like structure for in_addr (IPV4) Stevens 6.4"""
    _fields_ = [
               ('s_addr', ctypes.c_uint)
               ]

class sockaddr_in(ctypes.Structure):
    """C like strcuture for sockaddr_in (IPV4) Steven 6.4"""
    _fields_ = [
               ('sin_len'    , ctypes.c_ubyte),
               ('sin_family' , ctypes.c_ubyte),
               ('sin_port'   , ctypes.c_ushort),
               ('sin_addr'   , in_addr ),
               ('sin_zero'   , ctypes.ARRAY(ctypes.c_char, 8))
               ]

class in6_addr(ctypes.Structure):
    """"C like structure for in_addr (IPV4) Stevens 6.4"""
    _fields_ = [
               ('s6_addr', ctypes.ARRAY( ctypes.c_ubyte, 16 ) )
               ]

class sockaddr_in6(ctypes.Structure):
    """C like strcuture for sockaddr_in6 (IPV6) Stevens ???"""
    _fields_ = [
               ('sin6_len'      , ctypes.c_ubyte),
               ('sin6_family'   , ctypes.c_ubyte),
               ('sin6_port'     , ctypes.c_ushort),
               ('sin6_flowinfo' , ctypes.c_uint),
               ('sin6_addr'     , in6_addr ),
               ('sin6_scope_id' , ctypes.c_uint)
               ]

class sockaddr_ll(ctypes.Structure):
    """C like structure for sockaddr_ll from man (7) packet
       Used to get the hardware address for Linux           """
    _fields_ = [
               ('sll_family'   , ctypes.c_ushort),
               ('sll_protocol' , ctypes.c_ushort),
               ('sll_ifindex'  , ctypes.c_int),
               ('sll_hatype'   , ctypes.c_ushort ),
               ('sll_pkttype'  , ctypes.c_ubyte),
               ('sll_halen'    , ctypes.c_ubyte),
               ('sll_addr'     , ctypes.ARRAY(ctypes.c_ubyte,8))
               ]

class sockaddr_dl(ctypes.Structure):
    """C like structure for sockaddr_dl Stevens 3.33
        Used to get the hardware address for OS X (maybe other BSD's?)"""
    _fields_ = [
               ('sdl_len'    , ctypes.c_ubyte),
               ('sdl_family' , ctypes.c_ubyte), ##AF_LINK
               ('sdl_index'  , ctypes.c_short),
               ('sdl_type'   , ctypes.c_ubyte),
               ('sdl_nlen'    , ctypes.c_ubyte),
               ('sdl_alen'   , ctypes.c_ubyte),
               ('sdl_slen'   , ctypes.c_ubyte),
               ('sdl_data'   , ctypes.ARRAY(ctypes.c_ubyte,12))
               ]

class ifa_ifu(ctypes.Union):
    """
    See ifaddrs structure for explanation
    """
    _fields_ = [
               ('ifu_broadaddr', ctypes.POINTER(osockaddr)),
               ('ifu_dstaddr'  , ctypes.POINTER(osockaddr)),
               ]

class ifaddrs(ctypes.Structure):
    """
    ifaddrs structure BUT NOT the one from Stevens this is one particular
    to getifaddrs (brilliant I know) man 3 will give you this.

    The only complicated bit is explained in the man page:

    'Depending on whether the bit IFF_BROADCAST or IFF_POINTOPOINT is set
    in ifa_flags (only one can be set at a time), either ifa_broadaddr
    will contain the broadcast address associated with ifa_addr (if
    applicable for the address family) or ifa_dstaddr will contain the
    destination address of the point-to-point interface.'

    In either case we a Union of two sockaddr pointers
    """
    pass
##Have to define outside of the class as we have a pointer to ourselves
ifaddrs._fields_=[
                 ('ifa_next'   , ctypes.POINTER(ifaddrs)),
                 ('ifa_name'   , ctypes.c_char_p),
                 ('ifa_flags'  , ctypes.c_uint),
                 ('ifa_addr'   , ctypes.POINTER(osockaddr)),
                 ('ifa_netmask', ctypes.POINTER(osockaddr)),
                 ('ifa_ifu'    , ifa_ifu), ##See above for structure
                 ('ifa_data'   , ctypes.c_void_p)
                 ]

##/end Structures

##Statics
FLAG_DICT = {
            "IFF_UP"           : 0x01,
            "IFF_BROADCAST"    : 0x02,
            "IFF_DEBUG"        : 0x04,
            "IFF_LOOPBACK"     : 0x08,
            "IFF_POINTTOPOINT" : 0x10,
            "IFF_NOTRAILERS"   : 0x20,
            "IFF_RUNNING"      : 0x40,
            "IFF_NOARP"        : 0x80,
            "IFF_PROMISC"      : 0x100,
            "IFF_ALLMULTI"     : 0x200,
            "IFF_MASTER"       : 0x400,
            "IFF_SLAVE"        : 0x800,
            "IFF_MULTICAST"    : 0x1000,
            "IFF_PORTSEL"      : 0x2000,
            "IFF_AUTOMEDIA"    : 0x4000,
            "IFF_DYNAMIC"      : 0x8000,
            "IFF_LOWERUP"      : 0x10000,
            "IFF_DORMANT"      : 0x20000
            }

##On OS X (maybe other BSD's ?) the address family of interfaces
## is not AF_INET(0x2)/AF_INET6(0xA) but AF_LINK(0x12) & this is
## not defined in socket module so we define it here
FAMILY_DICT = {
              socket.AF_INET   : "AF_INET",
              socket.AF_INET6  : "AF_INET6",
              ##Have to hardcode as os x has no socket.AF_PACKET
              ## and python doesn't have a socket.AF_LINK which os x needs
              0x11             : "AF_PACKET",
              0x12             : "AF_LINK"
              } ##More may come as and when is needed

##Device types - right now only support Ethernet
HW_DEV_DICT = {
              0x01 : "ARPHRD_ETHER"
              }

##/end Statics

class GetIfAddrsException(Exception):
    """Exception class for the GetIfAddrs class"""
    def __init__(self, value):
        self.value = value

    def __str__(self):
        return repr(self.value)

class GetIfAddrs:
    """
    Python equivilent of the getifaddrs(3) C function

    Queries all local network interfaces and gets as much information
    as is available about their various addresses, flags etc
    """

    def __init__(self):
        """
        Set up all our C-a-like structures
        """
        self.interfaces = Ifaces()
        #self.interfaces = iface_obj


    def __str__(self):
        """
        Show string representation of what we know
        """
        return self.interfaces.__str__()

    def debug(self, msg):
        """
        If global debug set, print out message

        @type msg: string
        @param msg: String to print
        """
        if DEBUG:
            print msg


    def get_flags(self, flag_int):
        """
        Return a list of strings of the flags set on an interface
        (ifa_flags)

        @type flag_int: integer
        @param flag_int: A c_int representing the bitmap of flags set

        @rtype: list
        @return: A list containing a string for each FLAG set
        """
        flags_set = []
        for flag_name, flag_value in FLAG_DICT.items():

            if flag_int & flag_value:
                flags_set.append(flag_name)

        return flags_set


    def get_family(self, osockaddr_val):
        """
        Get the sa_family type - return None if unsupported

        @type osockaddr_val: pointer
        @param osockaddr_val: A pointer to a ctypes struct of type sockaddr

        @rtype: tuple
        @return: A tuple pair, element 0: sa_family int value
                               element 1: sa_family string repr
        """
        ##Get family type and string it relates to
        try:
            family = (osockaddr_val[0].sa_family,
                      FAMILY_DICT[osockaddr_val[0].sa_family] )

        except (KeyError, ValueError):
            raise GetIfAddrsException("Unsupported sa_family")

        return family


    def get_address(self, osockaddr_val, family):
        """
        For a given osockaddr structure and sa_family return a
        dictionary representation of the information appropriate
        to the family.

        @type osockaddr_val: pointer
        @param osockaddr_val: A pointer to a ctypes struct of type sockaddr

        @type family: tuple
        @param family: A tuple pair, element 0: sa_family int value
                               element 1: sa_family string repr

        @rtype: dictionary
        @return: A dictionary containing structured address content based
                 on the sa_family type.
        """
        address  = None
        ret_dict = {}

        ##Based on sa_family create the correct structure for the address
        if family[1] == "AF_INET":
            ##IPv4
            try:
                address = ctypes.cast( osockaddr_val,
                                       ctypes.POINTER(sockaddr_in) )[0]
            except ValueError:
                return None

            ##Now convert to a string representation of the addy
            address = socket.inet_ntop(family[0],
                                struct.pack("I", address.sin_addr.s_addr))

        elif family[1] == "AF_INET6":
            ##IPv6
            try:
                address = ctypes.cast( osockaddr_val,
                                       ctypes.POINTER(sockaddr_in6) )[0]
            except ValueError:
                return None

            ret_dict["flowinfo"] = address.sin6_flowinfo
            ret_dict["scope_id"] = address.sin6_scope_id

            ##Now convert to a string representation, no sock to do this
            addy_6 = ""
            for z in address.sin6_addr.s6_addr:
                addy_6 += "%x"%( z )

            address = ""
            for z in range(0, len(addy_6), 4):
                ## regexp from pablo :) Reduces ipv6 address to shortest
                pat=("^(0*)([0-9a-f]*)")
                chunk = addy_6[z:z+4]
                chunk = re.sub(pat,r'\2',chunk)
                address += "%s:"%(chunk)
            address = address[:-1]

        elif family[1] == "AF_PACKET":
            ##Device independent physical layer address (Hardware address)
            ## gets mac for Linux
            try:
                address = ctypes.cast( osockaddr_val,
                                       ctypes.POINTER(sockaddr_ll) )[0]
            except ValueError:
                return None

            if address.sll_hatype not in HW_DEV_DICT:
                ##Unsupported hardware type - atm only care bout ethernet
                return None
            else:
                hwaddr = ""
                for z in address.sll_addr[:address.sll_halen]:
                    hwaddr += "%02x:"%(z)
                hwaddr = hwaddr[:-1]

                address = hwaddr

        elif family[1] == "AF_LINK":
            ##Gets mac for OS X (maybe other BSD's ?)
            try:
                address = ctypes.cast( osockaddr_val,
                                       ctypes.POINTER(sockaddr_dl) )[0]
            except ValueError:
                return None

            hwaddr =""
            for z in address.sdl_data[address.sdl_nlen:\
                                      address.sdl_nlen + address.sdl_alen]:
                hwaddr += "%02x:"%(z)
            hwaddr = hwaddr[:-1]
            address = hwaddr

        if address:
            ret_dict["address"]    = address

        return ret_dict


    def __call__(self):
        """
        Call the getifaddrs(3) function and process the results into a
        structured Python object of type NetIfaces

        @todo: various datas are not parsed out e.g.rx/tx_packets etc

        @rtype: integer
        @return: Return 0 on success, non-0 on failure
        """
        ifa = ctypes.POINTER(ifaddrs)()
        ifb = ctypes.POINTER(ifaddrs)()

        ifb = ifa

        gi_func = LIBC.getifaddrs
        ret = gi_func(ctypes.byref(ifa))

        self.debug( "Return from getifaddrs(): %d" % ret )

        if ret != 0 :
            self.debug("Error: getifaddrs() failed!")
            return ret

        try:
            ##Now traverse the linked list of interfaces
            while ifa:
                ##Get sa_family type
                try:
                    family = self.get_family( ifa[0].ifa_addr )
                except GetIfAddrsException, err:
                    self.debug(err)
                    ifa = ifa[0].ifa_next
                    continue

                ##Create new interface object
                interface_item = NetIface( ifa[0].ifa_name )

                ##Add in the sa_family data
                interface_item.family_val  = family[0]
                interface_item.family_name = family[1]

                ##Flags set
                interface_item.flags = self.get_flags( ifa[0].ifa_flags )

                ##Address of the interface
                interface_item.addr = self.get_address(ifa[0].ifa_addr,
                                                          family)

                ##Netmask of the interface
                interface_item.netmask = self.get_address(
                                                        ifa[0].ifa_netmask,                                                    family)

                ##Either broadcast or destination depending on flags
                if "IFF_BROADCAST" in interface_item.flags:
                    interface_item.brdaddr = self.get_address(
                                                ifa[0].ifa_ifu.ifu_broadaddr,                                            family)
                elif "IFF_POINTTOPOINT" in interface_item.flags:
                    interface_item.dstaddr = self.get_address(
                                                  ifa[0].ifa_ifu.ifu_dstaddr,
                                                  family)

                #TODO: ALL the other data fields rx/tx_packet etc etc
                ##Add the NetIface object to the Ifaces container
                self.interfaces.add(interface_item)

                ##Flick onto the next interface structure
                ifa = ifa[0].ifa_next
        finally:
            LIBC.freeifaddrs(ifb)

        return 0


if __name__ == "__main__":
    obj = GetIfAddrs()
    obj()
    print obj
