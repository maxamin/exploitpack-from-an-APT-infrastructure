#! /usr/bin/env python
#
# vim: sw=4 ts=4 expandtab
"""
linuxNode.py

CANVAS License

A linux MOSDEF node.

"""

from MOSDEFNode import MOSDEFNode
from exploitutils import *
import linuxMosdefShellServer
from MOSDEFSock import MOSDEFSock
from MOSDEF import GetMOSDEFlibc


class linuxNode(MOSDEFNode):
    def __init__(self, proctype='i386'):
        MOSDEFNode.__init__(self)
        self.nodetype     = "linuxNode"
        self.pix          = "linuxMOSDEFNode"
        self.activate_text()
        self.shell        = None
        self.hasrawsocks  = None #initialized first time hasRawSocks is called
        self.capabilities = ["linux", "Unix Shell", "posix", "VFS", "sock"]
        self.colour       = "purple"
        self.proctype     = proctype

        # proctype is set in canvasengine.py:2980
        if proctype == 'ARM9': self.capabilities.append('android')

    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (UnixShellNode cannot, for example. SQL nodes cannot...)

        The Linux Node uses ioctl to do this - it can't be blocked by
        chroot, etc.
        """

        self.log("[+] Calling findInterfaces")
        vars = self.shell.libc.getdefines()
        code="""
        #include <sys/socket.h>
        #include <sys/ioctl.h>
        #include <net/if.h>
        #include <unistd.h>

        #import "local", "sendint" as "sendint"
        #import "local", "sendstring" as "sendstring"

        void main()
        {
          int s;
          int i;
          int j;
          int ret;
          struct ifreq *ifr;
          struct ifconf ifc;
          char addr[1001];
          char *c;

          ifc.ifc_len = 1000;
          ifc.addr = addr;

          s = socket(AF_INET, SOCK_STREAM, 0);
          // some error checking
          if (s < 0)
          {
            sendint(0);
          }
          else
          {
            // some error checking
            ret = ioctl(s, SIOCGIFCONF, &ifc);
            if (ret < 0)
            {
                sendint(0);
            }
            else
            {
                j = ifc.ifc_len;
                sendint(j);
                c = ifc.addr;
                i = 0;
                while (i < j) {
                   ifr = c;
                   sendstring(ifr->ifr_name);
        """
        if self.proctype == 'x64':
            code += """
                   c = c + 40;
                   i = i + 40;
                   """
        else:
            code += """
                   c = c + 32;
                   i = i + 32;
                   """

        code += """
                }
            }
            close(s);
          }
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        if self.proctype == 'x64':
            j = self.shell.readint() / 40
        else:
            j = self.shell.readint() / 32
        if not j:
            self.log("[EE] Socket or IOCTL call failed once, retrying ...")
            self.shell.sendrequest(message)
            if self.proctype == 'x64':
                j = self.shell.readint() / 40
            else:
                j = self.shell.readint() / 32
        interfaces = []
        self.log("[+] Reading %d interfaces from remote side" % j)
        for i in range(0,j):
            iface = self.shell.readstring()
            interfaces.append(iface)
        self.shell.leave()
        for i in interfaces:
            ip      = self.ipFromInterface(i)
            netmask = self.netmaskFromInterface(i)
            self.log("[+] Found interface (%s) with IP address (%s)" % (i, ip))

            self.interfaces.add_ip((i, ip, netmask))
        return interfaces

    def hasRawSocks(self):
        """
        Overrides CANVASNode::hasRawSocks() because in the case where we are
        running as root on this remote node, then we need to be able to tell the user
        it's ok to do raw sockets. Our MOSDEFSock library can do raw sockets, which
        means we can test it that way.
        """
        #we set this the first time, to avoid constantly creating sockets
        if self.hasrawsocks!=None:
            return self.hasrawsocks
        sock=self.shell.bindraw()
        if sock!=-1:
            self.hasrawsocks=True
            self.shell.close(sock) #close it now to avoid fd leak
        else:
            self.hasrawsocks=False
        return self.hasrawsocks

    def ipFromInterface(self,interface):
        """
        gets the ip from an interface name using ioctl
        """

        vars            = self.shell.libc.getdefines()

        code = """
        #include <stdlib.h>
        #include <sys/socket.h>
        #include <sys/ioctl.h>
        #include <unistd.h>
        #include <string.h>

        #import "local", "sendint" as "sendint"
        #import "local", "mosdef_read_string" as "mosdef_read_string"

        // custom ifr struct
        struct ifreq {
            char ifr_name[16];
            struct sockaddr_in addr;
        };

        void main()
        {
            char *ifname;
            int iflen;
            int ret;
            int s;
            struct ifreq ifr;
            struct sockaddr_in *sa;

            // Read the argument over the network to optimize the compiler
            // cache.
            ifname = mosdef_read_string();
            if (ifname == NULL) {
                    sendint(0);
                    return;
            }

            iflen = strlen(ifname);

            // XXX: should check < 0 as well :P
            if (iflen > 16)
            {
                sendint(0);
            }
            else
            {
                sa = &ifr.addr;
                s = socket(AF_INET, SOCK_STREAM, 0);
                if (s < 0)
                {
                    sendint(0);
                }
                else
                {
                    // please to be codink securely
                    memset(ifr.ifr_name, 0, 16);
                    memcpy(ifr.ifr_name, ifname, iflen);
                    ret = ioctl(s, SIOCGIFADDR, &ifr);
                    if (ret < 0)
                    {
                        sendint(0);
                    }
                    else
                    {
                        sendint(1);
                        sendint(sa->sin_addr_s_addr);
                    }
                    close(s);
                }
            }

            free(ifname);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code, vars)
        #print "XXX: len message: %d" % len(message)
        self.shell.sendrequest(message)
        self.shell.writestring(interface)
        ret = self.shell.readint()
        if not ret:
            self.log("[-] Could not get IP from interface ... defaulting to 0.0.0.0")
            raw_ip = "\x00\x00\x00\x00"
        else:
            raw_ip = struct.pack('<L', self.shell.readint())
        try:
            IP = socket.inet_ntoa(raw_ip)
        except:
            self.log("[-] Exception in inet_ntoa ... defaulting to 0.0.0.0")
            IP = '0.0.0.0'
        self.shell.leave()
        return IP

    def netmaskFromInterface(self,interface):
        """
        gets the netmask from an interface name using ioctl
        """
        vars            = self.shell.libc.getdefines()

        code = """
        #include <stdlib.h>
        #include <sys/socket.h>
        #include <sys/ioctl.h>
        //#include <net/if.h>
        #include <unistd.h>
        #include <string.h>

        #import "local", "mosdef_read_string" as "mosdef_read_string"
        #import "local", "sendint" as "sendint"

        // custom ifr struct
        struct ifreq {
            char ifr_name[16];
            struct sockaddr_in addr;
        };

        void main()
        {
            char *ifname;
            int iflen;
            int ret;
            int s;
            struct ifreq ifr;
            struct sockaddr_in *sa;

            ifname = mosdef_read_string();
            if (ifname == NULL) {
                    sendint(0);
                    return;
            }

            iflen = strlen(ifname);

            // XXX: should check < 0 as well :P
            if (iflen > 16)
            {
                sendint(0);
            }
            else
            {
                sa = &ifr.addr;
                s = socket(AF_INET, SOCK_STREAM, 0);
                if (s < 0)
                {
                    sendint(0);
                }
                else
                {
                    // please to be codink securely
                    memset(ifr.ifr_name, 0, 16);
                    memcpy(ifr.ifr_name, ifname, iflen);
                    ret = ioctl(s, SIOCGIFNETMASK, &ifr);
                    if (ret < 0)
                    {
                        sendint(0);
                    }
                    else
                    {
                        sendint(1);
                        sendint(sa->sin_addr_s_addr);
                    }
                    close(s);
                }
            }

            free(ifname);
        }
        """
        self.shell.clearfunctioncache()
        message = self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        self.shell.writestring(interface)
        #print "XXX: len message: %d" % len(message)
        ret = self.shell.readint()
        if not ret:
            self.log("[-] Could not get netmask ... defaulting to /32")
            raw_mask = "\xff\xff\xff\xff"
        else:
            raw_mask = struct.pack('<L', self.shell.readint())
        netmask = str2bigendian(raw_mask)
        self.shell.leave()
        return netmask

    def createListener(self, addr, port):
        """
        Creates a listening mosdefsock on a port/interface
        """
        fd=self.shell.getListenSock(addr,port)
        devlog("linuxNode","FD returned from getListenSock=%s"%fd)
        if fd<0:
            return 0
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s

    def fexec(self,command,args,env):
        return self.shell.fexec(command,args,env)

    def dir(self,directory):
        #we could filter out shell escape characters here...
        #return self.shell.runcommand("ls -lart %s"%directory)

        #d_name = self.readstring()
        #statbuf=self.readstruct([("s","st_mode"),
        #                         ("s","st_uid"),
        #                         ("s","st_gid"),
        #                         ("l","st_size"),
        #                         ("l","st_mtime")])
        #self.files.append( (d_name, statbuf) )

        if len(directory) == 0:
            directory ="."

        S_IFMT = 0x017000
        IFDIR  = 0x4000

        UREAD  = 0x100
        UWRITE = 0x80
        UEXEC  = 0x40

        GREAD  = 0x20
        GWRITE = 0x10
        GEXEC  = 0x8

        OREAD  =  0x4
        OWRITE =  0x2
        OEXEC  =  0x1

        ret = self.shell.dodir(directory)
        if len(ret) == 0:
            return "Unknown directory: '%s'"%(directory)

        out = []
        FFLAGS = ["_", "d"]
        RFLAGS = ["_", "r"]
        WFLAGS = ["_", "w"]
        XFLAGS = ["_", "x"]

        for (filename, statbuf) in ret:
            flags = []
            flags.append( FFLAGS [bool( ( statbuf["st_mode"] & S_IFMT) == IFDIR )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & UREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & UWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & UEXEC)  )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & GREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & GWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & GEXEC)  )] )
            flags.append( RFLAGS [bool( ( statbuf["st_mode"] & OREAD)  )] )
            flags.append( WFLAGS [bool( ( statbuf["st_mode"] & OWRITE) )] )
            flags.append( XFLAGS [bool( ( statbuf["st_mode"] & OEXEC)  )] )
            out.append("%s   %6d %6d  %10d %s %s" % ("".join(flags), statbuf["st_uid"], statbuf["st_gid"],\
                                                      statbuf["st_size"], time.ctime(statbuf["st_mtime"]), filename) )
        return out

    # VFS Routines
    def vfs_dir(self, path):
        # returns (afile, st_size, st_mtime, is_dir)
        S_IFMT = 00170000
        IFDIR  = 0040000
        ret = self.shell.dodir(path)
        out = []
        for (filename, statbuf) in ret:
            isdir = bool( ( statbuf["st_mode"] & S_IFMT) == IFDIR )
            isexe = bool(statbuf["st_mode"] & 0x49 ) # User, group and other EXE
            out.append( (filename, statbuf["st_size"], statbuf["st_mtime"], {"is_dir":isdir, "is_exe": isexe} ))
        return out

    def vfs_upload(self, path, dest):
        ret = self.shell.upload(path, dest)
        return ret

    def vfs_download(self, path, dest=None):
        if not dest:
            dest = self.engine.create_new_session_output_dir(self.get_interesting_interface(), "downloaded_files")

        ret = self.download(path, dest)
        return ret

    def vfs_stat(self, path):
        ret, statbuf = self.shell.stat(path)

        if ret:
            retstat    = (0, 0, {"is_dir": True })
        else:
            # determine if it's a directory from the mode
            # I guess technically we should pull these
            # from the MOSDEFLibc
            S_IFMT         = 00170000
            S_IFSOCK       = 0140000
            S_IFLNK        = 0120000
            S_IFREG        = 0100000
            S_IFBLK        = 0060000
            S_IFDIR        = 0040000
            S_IFCHR        = 0020000
            S_IFIFO        = 0010000
            S_ISUID        = 0004000
            S_ISGID        = 0002000
            S_ISVTX        = 0001000
            m              = statbuf['st_mode']
            attr           = {}
            isexe          = bool(statbuf["st_mode"] & 0x49 ) # User, group and other EXE
            attr["is_dir"] = bool( ((m & S_IFMT) == S_IFDIR) )
            attr["is_exe"] = isexe
            retstat        = (statbuf['st_size'], statbuf['st_mtime'], attr)
        return retstat

if __name__ == "__main__":
    node = linuxNode()
