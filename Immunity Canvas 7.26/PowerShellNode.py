#! /usr/bin/env python

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2006
# http://www.immunityinc.com/CANVAS/ for more information

"""
PowerShellNode.py - used for remote connections from psnode.ps1
"""
import logging

from MOSDEFNode import MOSDEFNode
from MOSDEFSock import MOSDEFSock
from libs.canvasos import canvasos
from exploitutils import *
from canvaserror import *


class PowerShellNode(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype = "PowerShellNode"
        self.pix = "PowerShellNode"
        self.capabilities += ["spawn", "VFS", "upload", "download", "Win32 Shell"]
        self.activate_text()
        self.colour = "cyan"

    def getHostOS(self):
        host_os = self.hostsknowledge.get_localhost().get_knowledge("OS")
        if host_os != None:
            return host_os.known
        else:
            return "Windows"

    def getInfo(self):
        os = canvasos("Windows")
        #self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)

        osinfo = self.shell.getOSInfo()
        if osinfo != None:
            if len(osinfo) > 1:
                self.hostsknowledge.get_localhost().add_knowledge("OS Version", osinfo[1], 100)
            if len(osinfo) > 2:
                self.hostsknowledge.get_localhost().add_knowledge("OS Version Number", osinfo[2], 100)
            if len(osinfo) > 0:
                self.hostsknowledge.get_localhost().add_knowledge("OS Architecture", osinfo[0], 100)
                if "32" in osinfo[0]:
                    os.arch='X86'
                elif "64" in osinfo[0]:
                    os.arch='X64'

        self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)

        psver = self.shell.getPSVersion()
        if psver != None:
            self.hostsknowledge.get_localhost().add_knowledge("POWERSHELL Version", psver, 100)
        return os

    # VFS Routines
    def vfs_dir(self, path):
        if path in ["/", "\\"]:
            out = []
            drives = self.shell.getDrives()
            for drive in drives:
                drivename = drive[0]
                drivetype = drive[1]
                out.append((drivename, 0, 0, {"is_dir": True , "is_exe": False }))
            return out
        else:
            #cut the / off the front
            path = path[1:]
            path = path.replace("/","\\")

        files = self.shell.vfs_dodir(path)
        out = []

        for f in files:
            isexe = False
            name  = f[3]
            mtime = f[2]
            size  = f[1]
            isdir = bool(f[0] & 0x10) # To check if is a directory

            if name.endswith(".exe"):
               isexe = True
            # name, size, mtime, is_dir = stat_result
            fileinfo = (name, size, mtime, {"is_dir": isdir, "is_exe": isexe })
            out.append(fileinfo)

        #print "out " + str(out)
        return out

    def vfs_stat(self, path):
        """
        Get the size and whether it's a directory or not from a path
        """
        if path:
           path = path.replace('/','\\')

        # self.log("vfs_stat(%s)" % path)
        if not len(path):
           logging.error("Missing path parameter to vfs_stat()")
           retstat = (0, 0, {"is_dir": False} )
           return retstat

        # XXX: REVIEW THIS
        if path in ["/","\\"] :
            # self.log("Root path found for vfs_stat()")
            return (0, 0, {"is_dir": True})

        if path[0] in ["/", "\\"]:
            #clean off the first / since it is not needed
            path = path[1:]

        if path and path[-1] == u"\\" and len(path) == 3:
            # self.log("vfs_stat() of a root drive - returning that it is a directory")
            # we are looking at c:\ or similar
            return (0, 0, {"is_dir": True})

        statbuf = self.shell.dostat(path)

        #print "statbuf: " + str(statbuf)
        if not statbuf:
            logging.error("Stat failed on %s" % path)
            retstat = (0, 0, {"is_dir": False})
        else:
            size    = statbuf[1]
            mtime   = statbuf[2]
            isexe   = False
            isdir   = bool(statbuf[0] & 0x10) # To check if is a directory

            if statbuf[3].lower().endswith(".exe"):
                isexe = True

            retstat = (statbuf[0], mtime, {"is_dir": isdir, "is_exe": isexe})

        return retstat

    def vfs_download(self, path, dest):
        #sets a default path if None is Dest
        if not dest:
            dest = self.engine.create_new_session_output_dir(self.get_interesting_interface(), "downloaded_files")

        if not path:
            logging.error("Missing path parameter to vfs_download()")
            # XXX: We should refactor anything that is expecting strings
            #      returned as ERRORS from functions...
            return "Path parameter missing"

        path = path.replace('/', "\\")
        path = unicode(path)
        if path[0] in [u"/", u"\\"]:
            path = path[1:] #strip off leading slash

        logging.info("Downloading %s to %s" % (path, dest))
        ret = self.shell.download(path, dest)
        logging.info("Finished Downloading %s to %s" % (path, dest))
        return ret

    def vfs_upload(self, path, dest):
        if not dest:
           logging.error("Missing path parameter to vfs_upload()")
           # XXX:
           return "Path was blank?"

        dest = unicode(dest)
        if dest[0] in [ u"/", u"\\"]:
            dest = dest[1:]
        #replace back slash
        dest = dest.replace('/','\\')

        logging.info("Uploading %s to %s" % (path, dest))
        ret = self.shell.upload(path, dest)
        logging.info("Finished Uploading %s to %s" % (path, dest))
        return ret

    def findInterfaces(self):
        logging.info("Calling findInterfaces")

        res = self.shell.findInterfaces()

        interfaces = []
        count = 0
        res = res.replace("\n", "").replace("\r", "")
        aresult = res.split(':')
        #print "<%s>" % aresult

        for line in aresult:
            #print line
            if "IP Address" in line:
               data = aresult[aresult.index(line)+1]
               data = data.strip().split(" ")
               ip_addr = data[0]
               #print "IP <%s>" % ip_addr
            if "Subnet Prefix" in line:
               data = aresult[aresult.index(line)+1]
               data = data.strip().split("(")
               data = data[1].strip().split(")")
               mask = data[0].replace("mask", "").strip()
               #print mask
               interfaces.append("#%d" % count)
               self.interfaces.add_ip(("#%d" % count, ip_addr, mask))
               count += 1

        self.activate_text()
        self.update_gui()
        self.update_pix()

        return interfaces
