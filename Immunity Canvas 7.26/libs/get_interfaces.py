##Wrapper around both pygetifaddrs(UNIX) and pygetadapterinfo(Win32)
##  - and eventually pygetadapteraddress(>winXP giving IPv6)

import sys

class Ifaces(object):
    """
    Object of a collection of NetIface objects, each interface will have
    zero or more NetIface objects
    """
    def __init__(self):
        """
        NetIface objects are organised thus:
            
            if_names { <interface_name>  : 
                                         { <sa_family>  : NetIface_Obj,
                                           <sa_family2> : Netiface_Obj2,
                                           ....
                                         },
                       <interface_name2> :
                                         {
                                         ...
                                         },
                      ....
                      }
                                       
        So obviously interface names are unique, as are address families
        within each interface name.
        """
        ##Dict of interfaces we have
        self.if_names = {}
        
    def __iter__(self):
        """
        Return an iterator of our interface containers
        """
        return self.if_names.__iter__()
        
        
    def __str__(self):
        """
        Create a prettily formatted string of interfaces
        
        @rtype: string
        @return: Formatted string representation of what we know
        """
        ret = ""
        
        for ifn in self.if_names.keys():
            
            ret += "%s\n"%(ifn)
            net_ifaces = self.get(ifn)
            
            for ni in net_ifaces:
                ret += "%s\n"%(ni)
                
        return ret
        
        
    def create_interface(self, name):
        """
        Create a new container for an intertface to hold NetIface objects
        
        @type name: string
        @param name: Name of the interface container to create
        """
        if not self.if_names.has_key(name):
            ##First time we have seen this interface - create it
            self.if_names[name] = {}
            
            
    def add(self, netiface):
        """
        Add a netiface object to the container for interface specified
        
        @type netiface: NetIface
        @param netiface: The populated NetIface object to add
        """
        ##If it is already created we don't overwrite
        self.create_interface(netiface.name)
        
        ##Add the NetIface to the interface key on sa_family name
        self.if_names[netiface.name][netiface.family_name] = netiface
        
        
    def get(self, iface_name, family_name=None):
        """
        Retrieve the NetIface object(s) for specified interface or a
        particular address family type for an interface
        
        @type iface_name: string
        @param iface_name: Name of the interafce to get the NetIFace for
        
        @type family_name: string
        @param family_name: Optional, specific family to retrieve for
                            interface
                            
        @rtype: list
        @return: List of NetIface objects
                 (empty list on failure)
        """
        ret = []
        if not family_name:
            ##Return all NetIface objects for this interface
            try:
                for ni in self.if_names[iface_name].values():
                    
                    ret.append(ni)
            except KeyError:
                print "Unknown interface name: %s"%(iface_name)
                
        else:
            ##Return specific NetIface for address family on interface
            try:
                ret.append( self.if_names[iface_name][family_name] )
            except KeyError:
                print "Unknown interface/family name: %s"%(iface_name,
                                                           family_name)
                
        return ret
    
    def get_hwaddr(self, iface_name):
        """
        Get the hwaddr (MAC) for specified interface. Will return
        the address of the AF_PACKET or AF_LINK family
        """
        try:
            return self.if_names[iface_name]["AF_LINK"].addr["address"]
        except KeyError:
            ##Not darwin
            try:
                return self.if_names[iface_name]["AF_PACKET"].addr["address"]

            except:
                print "Unknown interface specified %s"%(iface_name)
                return "00:00:00:00:00:00"            
        

class NIContainer(object):
    """
    Basically just an iterator that holds multiple NetIfaces
    """
    def __init__(self):
        
        self.family = family
    
    def __iter__(self):
        
        return self.container.__iter__
    
    def add(self, family, netiface):
        
        self.container[family] = netiface

class NetIface(object):
    """
    Object representation of a network interface for one sa_family
    """
    def __init__(self, name):
        """
        Object representing an interface for a single sa_family
        
        @type name: string
        @param name: Name of the interface this object refers to
        """
        self.name         = name  ##String
        self.family_name  = None  ##String
        self.family_val   = None  ##Interger
        self.addr         = None  ##Dictionary 
        self.brdaddr      = None  ##Dictionary
        self.dstaddr      = None  ##Dictionary
        self.netmask      = None  ##Dictionary
        self.flags        = None  ##List
        self.misc         = {}    ##Dictionary of extra rnd stuff
        
    
    def __str__(self):
        """
        Construct a pretty representation of our info
        
        @rtype: string
        @return: A formatted representation of the interface info
        """
        ret = ""
        ##So we can line stuff up nicely
        width = 12
        
        vars_2_print = {
                       "Name"        : self.name, 
                       "Family"      :(self.family_name,self.family_val), 
                       "Addr"        : self.addr,
                       "Netmask"     : self.netmask, 
                       "Broadcast"   : self.brdaddr,
                       "Destination" : self.dstaddr,
                       "Flags"       : self.flags,
                       "Misc"        : self.misc
                       }
        
        for name, val in vars_2_print.items():
            
            ##Skip empty variables
            if not val:
                continue

            ##Family is a special case
            if name == "Family":
                ret += "\t%s%s: %s (0x%02x)\n"%(name,
                                                " "*(width-len(name)),
                                                val[0], val[1])
            else:
                ret += "\t%s%s: %s\n"%(name, " "*(width-len(name)), val)
                
        return ret
    

class GetInterfaces:
    """
    Uniform wrapper around the C functions getifaddrs(3) [*NIX]
     and GetAdaptorInfo() [Win32] - outputs Ifaces object
    """
    def __init__(self):
        """
        Set up uniform output object so we get data in a way which
        is accessible regardless of underlying platform
        """
        self.interfaces = None
        
    def __call__(self):
        """
        Lets get jiggy
        """
        if sys.platform == "win32":
            ##Windows
            import pygetadapterinfo
            get_adapter_info = pygetadapterinfo.GetAdaptorInfo()
            
            get_adapter_info()
            #print get_adapter_info
            
            self.interfaces = get_adapter_info.interfaces
            
        else:
            ##Unix/cygwin
            import pygetifaddrs
            get_if_addrs = pygetifaddrs.GetIfAddrs()
            get_if_addrs()
            #print get_if_addrs
            
            self.interfaces = get_if_addrs.interfaces
            
            
if __name__ == "__main__":
    print "Testing"
    get_interfaces = GetInterfaces()
    get_interfaces()