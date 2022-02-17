#! /usr/bin/env python
"""
bsdNode.py

CANVAS License

A bsd MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
from MOSDEFSock import MOSDEFSock
import struct

class bsdNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype="bsdNode"
        self.pix="bsdMOSDEFNode"
        self.activate_text()
        self.shell=None
        self.capabilities=["bsd", "posix", "Unix Shell", "VFS"]
    
    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (UnixShellNode cannot, for example. SQL nodes cannot...)
        
        The Linux Node uses ioctl to do this - it can't be blocked by 
        chroot, etc.
        """
        self.log("Calling findInterfaces")
        vars={}
        vars["AF_INET"]=2
        vars["SOCK_STREAM"]=1
        code="""
        #import "local","sendint" as "sendint"
        #import "local","sendstring" as "sendstring"
        #import "local","memcpy" as "memcpy"
        #import "local","strcpy" as "strcpy"
        #import "local","memset" as "memset"
        
        #import "local","close" as "close"
        #import "int", "AF_INET" as "AF_INET"
        #import "int", "SOCK_STREAM" as "SOCK_STREAM"
        #import "local","ioctl" as "ioctl"
        #import "local","socket" as "socket"
        #import "local","sysctl" as "sysctl"
        #import "local", "debug" as "debug"
        #include "socket.h"
        
        struct ifreq {
          char ifr_name[16];
          //char arg[16]; // I hope this is right. :> Hey, it is! :>
          struct sockaddr_in ifr_addr; //one member of the union
        };

        struct ifconf {
          int ifc_len;
          char * addr;
        };
        
        struct if_data {
           unsigned char ifi_type;
           unsigned char ifi_physical;
           unsigned char ifi_addrlen;
           unsigned char ifi_hdrlen;
           unsigned char ifi_link_state;
           unsigned char ifi_recvquota;
           unsigned char ifi_xmitquota;
           unsigned char ifi_datalen;
           unsigned int ifi_mtu;
           unsigned int ifi_metric;
           unsigned int ifi_baudrate;
           // ...
        };
        
        struct if_msghdr {
          unsigned short ifm_msglen;
          char version;
          char type; //ifm_type, whatever.
          int ifm_addrs;
          int ifm_flags;
          short ifm_index;
          short padding; //not in original struct, must be for alignment
          struct if_data ifm_data; 
        };
        
        struct sockaddr_dl {
          char sdl_len;
          char sdl_family;
          short sdl_index;
          char sdl_type;
          unsigned char sdl_nlen;
          unsigned char sdl_alen;
          unsigned char sdl_slen;
          char sdl_data[46];
        };
        
        void main() {
          int s; //socket for ioctl
          struct if_data *ifd;
          struct ifreq ifr;
          char buffer[1024];
          int needed;
          char * c;
          struct if_msghdr *ifm;
          char *end;
          struct ifconf ifc;
          int mib[6]; //for sysctl
          struct sockaddr_dl *sdl;
          char *p;
          char * next;
          int ret;
          char name[16];
          struct sockaddr_in *sin;
          int addr;
          int baddr;
          
          s=socket(2,1,0);
          
          mib[0]=0x4; //CTL_NET;
          mib[1]=0x11; //PF_ROUTE;
          mib[2]=0;
          mib[3]=0;
          mib[4]=0x3; //NET_RT_IFLIST;
          mib[5]=0;

          needed=1024;

          sysctl(mib,6,buffer,&needed,0,0);
 
          next=buffer;
          end=buffer+needed;
          while (next < end) {
            //loop through the buffer
            ifm=next;
            if (1) {
            //debug();
            //RTM_IFINFO=0xe
            if (ifm->type == 0xe) {
                p=ifm; //cast to char *
                p=p+16; //sizeof packet offset
                //some nutty casting here

                ifd=ifm->ifm_data;
                // eax has ifd here
                //debug();
                //The first member of ifd is: 6 22 18
                ret=ifd->ifi_datalen;
                p=p+ret;
                sdl=p;
                p=name;
                memset(p,0,16);
                memcpy(name,sdl->sdl_data,sdl->sdl_nlen);
                strcpy(ifr.ifr_name,name); //copy the name
                ret=ioctl(s,0xc0206921,&ifr); // SIOCGIFCONF
                if (ret==0) {
                    sin=ifr.ifr_addr;
                    addr=sin->addr;
                    //succeeded at getting interface address
                    ret=ioctl(s,0xc0206925,&ifr); // SIOCGIFNETMASK
                    //replace baddr by netmask in the following code mentally
                    //ret=ioctl(s,0xc0206923,&ifr); // SIOCGIFBRDADDR 
                    if (ret==0) {
                      sin=ifr.ifr_addr;
                      baddr=sin->addr;
                      }
                      else {
                      baddr=-1;
                      }
                      //succeeded at getting broadcast address
                      //send our packet of data
                      sendstring(name);
                      sendint(addr);
                      sendint(baddr);
                    
                }    
            }
            } //end if statement
            //debug();
            //increment our buffer pointer over this message
            ret=ifm->ifm_msglen;
            next=next+ret;
            //close(-2);
          }
          memset(name,0,16);
          sendstring(name); //close this request with a null string
          close(s);
        }
        """
        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        interfaces=[]
        self.log("Reading interfaces from remote side")
        while 1:
            newint=self.shell.readstring()
            if newint=="":
                break
            print "NewInterface: %s"%newint
            addr=self.shell.readint()
            netmask=self.shell.readint()
            #now we need to reverse the netmask
            netmask=str2bigendian(intel_order(netmask))
            addr = socket.inet_ntoa(struct.pack("I", addr))
            print "Addr=%s"%addr
            interfaces.append((newint,addr,netmask))
        self.shell.leave()
        print "Interfaces: %s"%interfaces
        for i in interfaces:
            self.interfaces.add_ip(i)
        return interfaces

    def createListener(self,addr,port):
        fd=self.shell.getListenSock(addr,port)
        if fd<0:
            return 0
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s

    def fexec(self,command,args,env):
        return self.shell.fexec(command,args,env)
    
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
    node=bsdNode()

