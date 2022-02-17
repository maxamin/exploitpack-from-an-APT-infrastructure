#! /usr/bin/env python

import socket


from MOSDEFNode import MOSDEFNode
from MOSDEFSock import MOSDEFSock
from exploitutils import *

class aixNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype               = "aixNode"
        self.capabilities           +=["Unix Shell", 'AIX', 'posix', 'VFS']
        self.shell                  = None
        self.sane_interface_number  = 32

    def findInterfaces(self):
        self.log("Calling findInterfaces")
        
        # on AIX 4.4 BSD style SIOCGIFCONF is used
        # where struct sockaddr looks like:
        #   unsigned char sa_len;
        #   unsigned char sa_family
        #   char sa_data[14];
        #        
        # this returns a variable length packed array
        # which is annoying .. we want the Linux-style
        # behavior ..
        #
        # for 4.3 BSD style use OSIOCGIFCONF
        
        vars    = self.shell.libc.getdefines()
        code    = """
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"

        struct ifreq {
          char ifr_name[16];
          // struct sockaddr
          char arg[16];
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void 
        main() 
        {
            int s;
            int i;
            int j;
            struct ifreq *ifr;
            char addr[1005];
            char * c;
            struct ifconf ifc;

            ifc.ifc_len   = 1000;
            ifc.addr      = addr;
            s             = socket(AF_INET, SOCK_STREAM, 0);          
    
            ioctl(s, 0xC0086914, &ifc); // OSIOCGIFCONF
          
            j = ifc.ifc_len;
            sendint(j);
          
            c = ifc.addr;
            i = 0;
            while (i < j) 
            {
                ifr = c;
                sendstring(ifr->ifr_name);
                c  = c+32;
                i  = i+32;
            }
            close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code, vars)
        self.shell.sendrequest(message)

        j           = self.shell.readint()/32 # sizeof struct ifreq
        interfaces  = []
        
        self.log("Reading %d interfaces from remote side (%d len bytes)" % (j, j*32))

        if j > self.sane_interface_number:
            self.log("Corruption in the network stream or not a AIX MOSDEF node!")
            return []
        
        for i in range(0, j):
            if_append = self.shell.readstring()
            # prevent duplicates ..
            if if_append not in interfaces:
                self.log("Adding interface: %s" % if_append)
                interfaces.append(if_append)

        self.shell.leave()
 
        for i in interfaces:
            ip      = self.ipFromInterface(i)
            netmask = self.netmaskFromInterface(i)
            self.interfaces.add_ip((i,ip,netmask))
            
        return interfaces

    def ipFromInterface(self,interface):
        vars            = self.shell.libc.getdefines()
        vars["ifname"]  = interface
        code            = """
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"

        #import "string","ifname" as "ifname"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        
        #include "socket.h"

        struct ifreq {
            char ifr_name[16];
            struct sockaddr_in addr;
        };
        
        void 
        main() 
        {
            int s;
            int j;
            struct ifreq ifr;
            struct sockaddr_in *sa;
          
            sa = &ifr.addr;
            s  = socket(AF_INET, SOCK_STREAM, 0);
            strcpy(ifr.ifr_name, ifname);
            ioctl(s, 0xC0286921, &ifr); // SIOCGIFADDR
            j = sa->addr;
            
            sendint(j);
            close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r   = self.shell.reliableread(4)
        IP  = socket.inet_ntoa(r)
        self.shell.leave()
        return IP
    
    def netmaskFromInterface(self,interface):
        """
        gets the netmask from an interface name using ioctl
        """
        
        vars = self.shell.libc.getdefines()
        vars["ifname"]=interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include "socket.h"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr;
        };
        
        void 
        main() 
        {
            int s;
            int j;
            struct ifreq ifr;
            struct sockaddr_in *sa;
          
            sa = &ifr.addr;
            s  = socket(AF_INET,SOCK_STREAM,0);
            strcpy(ifr.ifr_name,ifname);
            ioctl(s, 0xC0286925, &ifr); // SIOCGIFNETMASK
            j = sa->addr;
            sendint(j);
            close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r = self.shell.reliableread(4)
        netmask = str2bigendian(r)
        self.shell.leave()
        return netmask
    
    def createListener(self,addr,port):
        fd = self.shell.getListenSock(addr, port)
        if sint32(fd) < 0:
            return 0
        s = MOSDEFSock(fd, self.shell)
        s.set_blocking(0)
        s.reuse()
        return s