#! /usr/bin/env python

"""
osxNode.py

CANVAS License

A OSX MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
from MOSDEFSock import MOSDEFSock
import struct,socket

class osxNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype = "osxNode"
        self.pix = "osxMOSDEFNode"
        self.activate_text()
        self.shell = None
        self.colour='pink'
        self.capabilities=["osx", "bsd", "posix", "Unix Shell", "VFS"]

        return       
            
    def get_interesting_interface(self):
        if self.interfaces and hasattr(self.shell, "connection"):
            t = self.shell.connection.getpeername()[0]
            for child in self.interfaces.children:
                if child.ip == t:
                    return child.ip
            return self.interfaces.get_interesting() #nothing found?
        return ""

    def findInterfaces(self):
        self.log("Calling findInterfaces")
        vars = self.shell.libc.getdefines()
        
        if hasattr(self.shell, "LP64"):
            self.LP64 = self.shell.LP64
        else:
            self.LP64 = False
            
        code = """
        #include <sys/socket.h>
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"

        struct ifreq {
          char ifr_name[16];
          char sa_len;
          char arg[15];
        };
        
        struct ifconf {
          int ifc_len;
        """
        # MOSDEF aligns structs, we need this one to be packed.
        # toolazyforaddingtomosdef
        if self.LP64:
            code += """
          int ifc_addr1;
          int ifc_addr2;
          """
        else:
            code += """
          char *addr;
        """
        code += """
        };
        int max(int a, int b) {
           if( a > b) {
           return a;
           }
           else {
              return b;
           }
        }
        
        void main() 
        {
          int s;
          int i;
          int j;
          int size;
          struct ifreq *ifr;
          char addr[2005];
          char * c;
          struct ifconf ifc;

          s = socket(0x2, 0x2, 0);
          ifc.ifc_len = 2000;
        """
        if self.LP64:
            code += """
          ifc.ifc_addr2 = addr >> 32;
          ifc.ifc_addr1 = addr;
          ioctl(s, 0xc00c6924, &ifc); // SIOCGIFCONF          
            """
        else:
            code += """
          ifc.addr = addr;
          ioctl(s, 0xc0086924, &ifc); // SIOCGIFCONF
            """
        code += """
          j = ifc.ifc_len; //there are j records in the return value          
          c = addr;
          ifr = addr;
          i = 0;
          
          while (i<j) 
          {
             ifr = c;
             sendstring(ifr->ifr_name); //send the string of the interface name

             // A little twist presented by MAC OSX 10.x :>
             size= max(32, 16 + ifr->sa_len);
             
             c = c+size;
             i = i+size;
          }
          sendstring("end");
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        interfaces = {}
        while 1:
            face = self.shell.readstring()
            if face == "end":
                break
            interfaces[face] = None
        self.shell.leave()

        for i in interfaces.keys():            
            ip = self.ipFromInterface(i)
            
            if not ip:
                self.log('Skipping %s (no IP)' % i)
                continue
            
            netmask = self.netmaskFromInterface(i)
            
            self.log('%s: %s' % (i, ip))
            self.interfaces.add_ip((i, ip, netmask))

        self.activate_text()
        self.update_gui()
        self.update_pix()
        return interfaces

    def ipFromInterface(self,interface):
        """
        gets the ip from an interface name using ioctl
        """
        if hasattr(self.shell, "LP64"):
            self.LP64 = self.shell.LP64
        else:
            self.LP64 = False

        SIOCGIFADDR = 0xc0206921L
        vars = self.shell.libc.getdefines()
        
        vars["ifname"] = interface
        code=""" 
        #include <sys/socket.h>
        #include <netinet/in.h>

        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr; // I hope this is right. :> Hey, it is! :>
        };
        
        void main() 
        {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char *c;
          struct sockaddr_in *sa;

          sa = &ifr.addr;
          s = socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name, ifname);

          // SIOCGIFADDR
          if(ioctl(s,0x%X,&ifr) == 0) 
          { 
             j = sa->sin_addr_s_addr;
             sendint(j); //send the ip
          } 
          else 
          {
             sendint(0);
          }
          
          close(s);
        }
        """% SIOCGIFADDR

        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r = self.shell.reliableread(4)
        self.shell.leave()
        
        if r == '\x00\x00\x00\x00': return None
        return socket.inet_ntoa(r)

    
    def netmaskFromInterface(self,interface):
        """
        gets the netmask from an interface name using ioctl
        """
        
        SIOCGIFNETMASK = 0xc0206919L
        vars = self.shell.libc.getdefines()
        vars["ifname"] = interface
        code="""
        #include <sys/socket.h>
        #include <netinet/in.h>
    
        #import "string","ifname" as "ifname"
        #import "local","close" as "close"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","strcpy" as "strcpy"
        #import "local","sendint" as "sendint"
        

        struct ifreq {
          char ifr_name[16];
          struct sockaddr_in addr;
        };
        
        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        void main() 
        {
          int s;
          int i;
          int j;
          struct ifreq ifr;
          char addr[1005];
          char * c;
          struct ifconf ifc;
          struct sockaddr_in *sa;
          
          sa = &ifr.addr;
          s = socket(AF_INET,SOCK_STREAM,0);
          strcpy(ifr.ifr_name,ifname);
          
          if (ioctl(s,0xc0206925,&ifr) == 0) {
              j = sa->sin_addr_s_addr;
              sendint(j); //send the ip
          } else {
              sendint(0);
          }
    
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        r = self.shell.reliableread(4) #read it like a buffer, although it used sendint
        self.shell.leave()
        
        if r == '\x00\x00\x00\x00': return None
        return str2bigendian(r)

    def findHost(self):
        if not self.LP64:
            # The following doesn't work on OSX 32
            return

        return
    
        # XXX: skip for now until we figure out the new __sysctl
        #if 1:
        #    return
        
        vars = self.shell.libc.getdefines()
        self.log("Calling findHost")

        code="""
        #import "local", "sysctl" as "sysctl"
        #import "local", "mmap" as "mmap"
        #import "local", "munmap" as "munmap"
        #import "local", "debug" as "debug"
        #import "local", "sendint" as "sendint"
        
        void main() 
        {
          int mib[6];
          unsigned long i;
          unsigned long msglen;
          long *buf;
          unsigned long a;
          long addr;
          unsigned long needed;
          
          mib[0] = 4;     // CTL_NET
          mib[1] = 17;    // AF_ROUTE
          mib[2] = 0;
          mib[3] = 2;     // AF_INET
          mib[4] = 2;     // NET_RT_FLAGS
          mib[5] = 0x400; // RTF_LLINFO

          
          i=sysctl(mib, 6, 0x0, &needed, 0);
          buf = mmap(0, needed, 7, 0x1002, -1, 0);

          i=sysctl(mib, 6, buf, &needed, 0);
          i=0;
          needed= needed/4;
          
          while(i < needed) 
          {
                 //debug();
                 msglen = buf[i]>>16;
                 
                 a=i + 24;

                 addr = buf[a];
                 sendint(addr);
                 
                 a= msglen/4;
                 i= i+ a;                 
                 
          }
          sendint(0);
          munmap(buf);
        }
          
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        ips = []
        while 1:
            ret = self.shell.reliableread(4)
            if ret == "\x00\x00\x00\x00":
                break
            ips.append(socket.inet_ntoa(ret) )
        self.shell.leave()
        for a in ips:
            self.new_host(a)
    
    def createListener(self,addr,port):
        fd = self.shell.getListenSock(addr,port)
        if fd < 0:
            if fd == -1:
                self.log("Remote getListenSock failed binding")
            return 0
        s = MOSDEFSock(fd, self.shell)
        s.set_blocking(0)
        s.reuse()
        return s

    def fexec(self,command, args, env):
        return self.shell.fexec(command, args, env)
    
    def dir(self,directory):
        # we could filter out shell escape characters here...
        return self.shell.runcommand("ls -lart %s" % directory)
    
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
                return (0, 0, {"is_dir": True })
            return (t[4] , " ".join(t[5:7]), {"is_dir": bool(t[0][0] == "d"), "is_exe": bool(t[0].find("x")>-1)} )
                
    
    def vfs_download(self, path, dest):
        if not dest:
             dest = self.engine.create_new_session_output_dir(self.get_interesting_interface(), "downloaded_files")
             
        ret = self.shell.download( path, dest )
        return ret
    
    def vfs_upload(self, path, dest):
        ret = self.shell.upload( path, dest )
        return ret
    


