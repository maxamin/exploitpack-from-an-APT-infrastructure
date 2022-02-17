#! /usr/bin/env python
"""
solarisNode.py

CANVAS License

A solaris MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
import solarisMosdefShellServer
from MOSDEFSock import MOSDEFSock


class solarisNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype="solarisNode"
        self.pix="solarisMOSDEFNode"
        self.activate_text()
        self.shell=None
        self.sane_interface_number=32
        self.capabilities+=["Unix Shell", "Solaris", "posix", "VFS", "sock"]
        return
        
            
    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (UnixShellNode cannot, for example. SQL nodes cannot...)
        
        The Linux Node uses ioctl to do this - it can't be blocked by 
        chroot, etc.
        """
        
        self.log("Calling findInterfaces")
        vars = self.shell.libc.getdefines()
        code="""
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SIOCGIFCONF" as "SIOCGIFCONF"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"

        struct ifreq {
          char ifr_name[16];
          char arg[16]; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() {
          int s;
          int i;
          int j;
          struct ifreq *ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;

          ifc.ifc_len=1000;
          ifc.addr=addr;

          s=socket(AF_INET,SOCK_STREAM,0);          
          ioctl(s,SIOCGIFCONF,&ifc);
          j=ifc.ifc_len; //there are j records in the return value
          sendint(j); //send the number of records


          
          c=ifc.addr;
          i=0;
          while (i<j) {
             ifr=c;
             sendstring(ifr->ifr_name); //send the string of the interface name
             c=c+32;
             i=i+32;
          }
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        j=self.shell.readint()/32
        interfaces=[]
        self.log("Reading %d interfaces from remote side"%j)
        if j > self.sane_interface_number:
            self.log("Corruption in the network stream or not a Solaris MOSDEF node!")
            return []
        for i in range(0,j):
            interfaces.append(self.shell.readstring())
        self.shell.leave()
        #print "Interfaces: %s"%interfaces
        #now that we have all the interfaces, we need to get the ip and network
        #for each of them
        for i in interfaces:
            ip=self.ipFromInterface(i)
            netmask=self.netmaskFromInterface(i)
            self.interfaces.add_ip((i,ip,netmask))
        return interfaces

    def ipFromInterface(self,interface):
        """
        gets the ip from an interface name using ioctl
        """
        
        vars = self.shell.libc.getdefines()
        vars["ifname"]=interface
        code="""
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "int", "SIOCGIFADDR" as "SIOCGIFADDR"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include "socket.h"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa=&ifr.addr;
          s=socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          ioctl(s,SIOCGIFADDR,&ifr);
          j=sa->addr;
          sendint(j); //send the ip
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r=self.shell.reliableread(4) #read it like a buffer, although it used sendint
        IP = socket.inet_ntoa(r)
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
        #import "int", "SIOCGIFNETMASK" as "SIOCGIFNETMASK"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        
        #include "socket.h"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa=&ifr.addr;
          s=socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          ioctl(s,SIOCGIFNETMASK,&ifr);
          j=sa->addr;
          sendint(j); //send the ip
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r=self.shell.reliableread(4) #read it like a buffer, although it used sendint
        netmask = str2bigendian(r)
        self.shell.leave()
        return netmask
    
    def createListener(self,addr,port):
        fd = self.shell.getListenSock(addr, port)
        #print "XXX: got fd: %d"% fd
        if sint32(fd)<0:
            #print "XXX: return sint32 < 0"
            return 0
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s

    def fexec(self,command,args,env):
        return self.shell.fexec(command,args,env)
        
    def dir(self, directory):
        return self.shell.runcommand("ls -lat %s" % directory)

    def vfs_dir(self, directory):
        lines = self.shell.runcommand("ls -lat %s" % directory)
        out = []
        for line in lines.split("\n"):
            if line:
                t = []
                for x in line.split(" "):
                    if x:
                        t.append(x)
                if len(t) < 7:
                    continue
                out.append( (t[-1], t[4] , " ".join(t[5:7]), {"is_dir": bool(t[0][0] == "d"), "is_exe": bool(t[0].find("x")>-1)} ))
        return out
    
    def vfs_stat(self, file):
        lines = string.strip( self.shell.runcommand("ls -lat %s" % file) )
        lines = lines.split("\n")
        line = None
        if len(lines) == 1: # Is a file:
            line = lines[0]
        else:
            for a in lines:
                if a.rstrip().rsplit(" ", 1) == ".":
                    line = a
                    break
        if not line:
            return (0, 0, {"is_dir": True })
        else:
            t = []
            for x in line.split(" "):
                if x:
                    t.append(x)
            if len(t) < 7:
                print "Error: Wrong line"
                return (0, 0, {"is_dir": True })
            return (t[4] , " ".join(t[5:7]), {"is_dir": bool(t[0][0] == "d"), "is_exe": bool(t[0].find("x")>-1)} )
                
    
    def vfs_download(self, path, dest):
        ret = self.shell.download( path, dest )
        return ret
    
    def vfs_upload(self, path, dest):
        ret = self.shell.upload( path, dest )
        return ret
    

if __name__=="__main__":
    node=solarisNode()
