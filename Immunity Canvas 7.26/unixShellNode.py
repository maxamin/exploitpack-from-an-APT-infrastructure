#! /usr/bin/env python
"""
unixShellNode.py
"""

from CANVASNode import CrossPlatformNode
from exploitutils import *
from canvaserror import *
import socket
import re
from libs.canvasos import canvasos

"""
NOTES:
-----
maybe we could split that file in ${OS}ShellNode later...
"""

class unixShellInterfaceResolver(object):

    def __init__(self, node, ostype, proc, version):
        self.ostype = ostype
        self.proc = proc
        self.version = version
        self.node = node
        self.useiproute = False
        self.colour = "yellow"
    
    def _osresolvfunc(self, name, *args):
        funcname = "%s_%s" % (name, self.ostype)
        if not hasattr(self, funcname):
            print "no support of shell::%s for OS %s" % (name, self.ostype)
            return
        return getattr(self, funcname)(*args)

    def findInterfaces_SunOS(self):
        interfaces = []
        out, rv = self.node.shell.shellcommand("/usr/bin/netstat -i -n")
        if rv != 0:
            raise NodeCommandError("Error running netstat: %s" % out)

        for l in out.split("\n"):
            if len(l) > 2 and not l.startswith("Name"):
                iface = l.split(" ")[0].strip()
                if re.match("[a-z]+[0-9]+", iface):
                    if iface not in interfaces:
                        interfaces.append(iface)

        for i in interfaces:
            ip = self.ipFromInterface(i)
            mask = self.netmaskFromInterface(i)
            if ip and mask:
                self.node.interfaces.add_ip((i, ip, mask))

        return interfaces

    def findInterfaces_Linux(self):
        self.node.log("Calling findInterfaces")
        interfaces=[]
        release = self.version
        if not release:
            self.node.log("Can not get Linux version ???")
            return interfaces
        ver = release.split('.')
        # only tested with Linux >= 2.4
        if ver[0] < 2 or (ver[0] < 2 and ver[1] < 4):
            self.node.log("findInterfaces not tested on Linux %s" % release)
            return interfaces
        self.node.log("Reading /proc/net/dev")
        output, rv = self.node.shell.shellcommand("cat /proc/net/dev", LFkludge=True)
        self.node.log("RV=%s"%rv)
        if rv != 0:
            # Might be grsecced, so we can't read proc/net/dev. Try netlink socket with ip route2?
            procnetdev = output
            self.node.log("Reading /sbin/ip a l")
            output, rv = self.node.shell.shellcommand("/sbin/ip a l")
            self.node.log("RV=%s"%rv)
            if rv == 0:
                self.iproute2_output = output
                self.useiproute = True   
            else:            
                raise NodeCommandError("findInterfaces got error trying to read /proc/net/dev on Linux: %s, and also failed with /sbin/ip address list: %s" % (procnetdev, output))

        if self.useiproute:
            interfaces = self.interfaceNamesFromIPRoute(self.iproute2_output)
        else:
            lines = output.split('\n')
            for line in lines:
                if len(line) > 7 and line[6] == ':':
                    devlog('findInterfaces', "interface: %s" % line[:6].strip(' '))
                    interfaces.append(line[:6].strip(' '))
                    
        for interface in interfaces:
            ip = self.ipFromInterface(interface)
            netmask = self.netmaskFromInterface(interface)
            if ip and netmask:
                devlog('findInterfaces', "ip %s:%s" % (interface, ip))
                devlog('findInterfaces', "netmask %s:%x" % (interface, netmask))
                self.node.interfaces.add_ip((interface, ip, netmask))
        return interfaces

    def interfaceNamesFromIPRoute(self, output):
        rv = []
        regex = re.compile("[0-9]+: (?P<ifname>[a-zA-Z0-9]+):.*")
        for l in output.split("\n"):
            m = regex.match(l)
            if m != None:
                rv.append(m.groupdict()["ifname"])
        return rv
    
    def ipAndNetmaskFromInterfaces_Linux_iproute(self, ):
        regex = re.compile("[0-9]+: (?P<ifname>[a-zA-Z0-9]+):.*")
        inetRegex = re.compile("\s*inet (?P<ipaddr>([0-9]{1,3}\.){3}[0-9]{1,3})/(?P<mask>[0-9]{1,2}).*")
        lines = self.iproute2_output.split("\n")
        rv = {}
        
        for i,l in enumerate(lines):
            m = regex.match(l)
            if m != None:
                if i < len(lines):
                    for j in lines[i+1:]:
                        if regex.match(j) == None:
                            n = inetRegex.match(j)
                            if n != None:
                                rv[m.groupdict()["ifname"]] = (n.groupdict()["ipaddr"], ((0xffffffff << (32 - int(n.groupdict()["mask"]))) & 0xffffffff))
                                break
        
        return rv
                            
    def netmaskFromInterface_Linux_iproute(self, interface):
        return self.ipAndNetmaskFromInterfaces_Linux_iproute()[interface][1]
    
    def ipFromInterface_Linux_iproute(self, interface):
        return self.ipAndNetmaskFromInterfaces_Linux_iproute()[interface][0]

    def netmaskFromInterface_Linux_procfs(self, interface):
        if not hasattr(self, 'Linux_proc_net_route'): # trying some C static var ;)

            out , rv = self.node.shell.shellcommand("cat /proc/net/route", LFkludge=True)
            if rv != 0:
                raise NodeCommandError("Error reading /proc/net/route: %s" % out)

            self.Linux_proc_net_route = out

            lines = self.Linux_proc_net_route.split('\n')
            del lines[0]
            tmp = {}
            for line in lines:
                # we have Iface/Destination/Gateway/Flags/RefCnt/Use/Metric/Mask/MTU/Window/IRTT
                l = line.split()
                netmask = dInt("0x%s" % l[7])
                if netmask:
                    tmp[l[0]] = netmask
            self.Linux_proc_net_route = tmp

        if not self.Linux_proc_net_route: # we already tried to open it and we failed
            return None

        if not self.Linux_proc_net_route.has_key(interface):
            return None

        return self.Linux_proc_net_route[interface]

    def ipFromInterface_Linux_ifconfig(self, interface):
        """
        could be generic and work on other platform, to be tested...
        """
        output, rv = self.node.shell.shellcommand("/sbin/ifconfig %s" % interface, LFkludge=True)
        if rv != 0:
            raise NodeCommandError("Error running ifconfig: %s" % output)

        lines = output.split('\n')
        for line in lines:
            if "inet addr:" in line:
                ip = line[line.find("inet addr:")+len("inet addr:"):].split()[0]
                devlog('ipFromInterface', "<%s> has ip: %s" % (interface, ip))
                return ip
        return None

    def netmaskFromInterface_Linux_ifconfig(self, interface):
        """
        could be generic and work on other platform, to be tested...
        """
        output, rv = self.node.shell.shellcommand("/sbin/ifconfig %s" % interface, LFkludge=True)
        if rv != 0:
            raise NodeCommandError("Error running ifconfig: %s" % output)

        lines = output.split('\n')
        for line in lines:
            if "inet addr:" in line:

                netmaskstr = line[line.find(" Mask:")+len(" Mask:"):].split()[0]
                netmask = str2int32(socket.inet_aton(netmaskstr))
                devlog('netmaskFromInterface', "<%s> has netmask: %s -> %x" % (interface, netmaskstr, netmask))
                return netmask
        return None

    def ipFromInterface_SunOS_ifconfig(self, interface):
        """
        could be generic and work on other platform, to be tested...
        """
        output, rv = self.node.shell.shellcommand("/sbin/ifconfig %s" % interface, LFkludge=True)
        if rv != 0:
            raise NodeCommandError("Error running ifconfig: %s" % output)

        lines = output.split('\n')
        for line in lines:
            if "inet " in line:
                ip = line[line.find("inet ")+len("inet "):].split()[0]
                devlog('ipFromInterface', "<%s> has ip: %s" % (interface, ip))
                return ip
        return None

    def netmaskFromInterface_SunOS_ifconfig(self, interface):
        """
        could be generic and work on other platform, to be tested...
        """
        output, rv = self.node.shell.shellcommand("/sbin/ifconfig %s" % interface, LFkludge=True)
        if rv != 0:
            raise NodeCommandError("Error running ifconfig: %s" % output)

        lines = output.split('\n')
        for line in lines:
            if "inet " in line:

                netmaskstr = line[line.find(" netmask")+len(" netmask"):].split()[0]
                netmask = str2int32(socket.inet_aton("0x" + netmaskstr))
                devlog('netmaskFromInterface', "<%s> has netmask: %s -> %x" % (interface, netmaskstr, netmask))
                return netmask
        return None

    def ipFromInterface(self, interface):
        return self._osresolvfunc('ipFromInterface', interface)

    def netmaskFromInterface(self, interface):
        return self._osresolvfunc('netmaskFromInterface', interface)

    def ipFromInterface_SunOS(self, interface):
        return self.ipFromInterface_SunOS_ifconfig(interface)

    def netmaskFromInterface_SunOS(self, interface):
        return self.netmaskFromInterface_SunOS_ifconfig(interface)

    def ipFromInterface_Linux(self, interface):
        if self.useiproute:
            return self.ipFromInterface_Linux_iproute(interface)
        else:
            return self.ipFromInterface_Linux_ifconfig(interface)

    def netmaskFromInterface_Linux(self, interface):
        if self.useiproute:
            return self.netmaskFromInterface_Linux_iproute(interface)
        else:
            return self.netmaskFromInterface_Linux_ifconfig(interface)

class unixShellNode(CrossPlatformNode):
    def __init__(self):
        CrossPlatformNode.__init__(self)
        self.nodetype="UnixShellNode"
        self.pix=""
        self.activate_text()
        self.capabilities+=['Unix Shell', 'upload', 'download', 'spawn', 'VFS']
        self.sysinfo_d = {}
        self.noUname = False
        return

    def sysinfo_uname(self, val):
        tbl = {'OS': "s", 'PROC': "m", 'VERSION': "r", "ALL":"a"}
        if not tbl.has_key(val):
            return None
        
        if not self.sysinfo_d.has_key(val):
            out, rv = self.shell.shellcommand("uname -%s" % tbl[val], LFkludge=True)
            if rv != 0:
                raise NodeCommandError("uname returned nonzero %d: %s" % (rv, out))
            self.sysinfo_d[val] = out.strip()
            
        return self.sysinfo_d[val]

    def sysinfo_procfs(self, val):
        out,rv = self.shell.shellcommand("cat /proc/version")
        if rv == 0:
            self.log("Got proc/version string: %s" % out)
            self.sysinfo_d["ALL"] = out.strip()
            u = out.strip().split(" ")
            self.sysinfo_d["OS"] = u[0]
            self.sysinfo_d["VERSION"] = u[2]
            self.sysinfo_d["PROC"] = "Unknown" # Cant think of an easy way to get this without uname
        else:
            raise NodeCommandError("No uname, no proc/version. :(")
        
        return self.sysinfo_d[val]

    def sysinfo(self, val="ALL"):

        if self.sysinfo_d.has_key(val):
            return self.sysinfo_d[val]
        
        try:
            if not self.noUname:
                ret = self.sysinfo_uname(val)
        except NodeCommandError:
            self.noUname = True
        
        if self.noUname:
            ret = self.sysinfo_procfs(val)
    
        return ret

    def ostype(self):
        return self.sysinfo('OS')

    def proctype(self):
        return self.sysinfo('PROC')

    def releasetype(self):
        return self.sysinfo('VERSION')
    
    def getInfo(self):
        
        s = self.sysinfo(val="ALL")
        self.log("Got sysinfo: %s" % s)
        if len(s):
            self.uname = s
            os = canvasos()
            os.load_uname(s)
            ret = os    
            self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)
        else:
            ret = None
            
        return ret


class androidShellNode(unixShellNode):
    def __init__(self):
        unixShellNode.__init__(self)
        self.nodetype="AndroidShellNode"
        self.pix=""
        self.activate_text()
        self.capabilities+=['Unix Shell', 'upload', 'download', 'spawn']
        self.sysinfo_d = {}
        self.noUname = False
        return

    def sysinfo_uname(self, val):
        tbl = {'OS': "s", 'PROC': "m", 'VERSION': "r", "ALL":"a"}
        if not tbl.has_key(val):
            return None
        
        if not self.sysinfo_d.has_key(val):
            out, rv = self.shell.shellcommand("uname -%s" % tbl[val], LFkludge=True)
            if rv != 0:
                raise NodeCommandError("uname returned nonzero %d: %s" % (rv, out))
            self.sysinfo_d[val] = out.strip()
            
        return self.sysinfo_d[val]

    def sysinfo_procfs(self, val):
        out,rv = self.shell.shellcommand("cat /proc/version")
        if rv == 0:
            self.log("Got proc/version string: %s" % out)
            self.sysinfo_d["ALL"] = out.strip()
            u = out.strip().split(" ")
            self.sysinfo_d["OS"] = u[0]
            self.sysinfo_d["VERSION"] = u[2]
            self.sysinfo_d["PROC"] = "Unknown" # Cant think of an easy way to get this without uname
        else:
            raise NodeCommandError("No uname, no proc/version. :(")
        
        return self.sysinfo_d[val]

    def sysinfo(self, val="ALL"):

        if self.sysinfo_d.has_key(val):
            return self.sysinfo_d[val]
        
        try:
            if not self.noUname:
                ret = self.sysinfo_uname(val)
        except NodeCommandError:
            self.noUname = True
        
        if self.noUname:
            ret = self.sysinfo_procfs(val)
    
        return ret

    def ostype(self):
        return self.sysinfo('OS')

    def proctype(self):
        return self.sysinfo('PROC')

    def releasetype(self):
        return self.sysinfo('VERSION')
    
    def getInfo(self):
        
        s = self.sysinfo(val="ALL")
        self.log("Got sysinfo: %s" % s)
        if len(s):
            self.uname = s
            os = canvasos()
            os.load_uname(s)
            ret = os    
            self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)
        else:
            ret = None
            
        return ret




if __name__=="__main__":
    node = unixShellNode()

