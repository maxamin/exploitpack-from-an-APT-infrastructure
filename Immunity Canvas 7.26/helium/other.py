#! /usr/bin/env python
"""

other.py
"""

from threading import Thread
from threading import RLock
import time
import select

goodchars=".()~!#$%^&*()-=_/\\:"
#let's not mess up our tty
def prettyprint(instring):
    tmp=""
    for ch in instring:
       if (ch.isalnum() or ch in goodchars) and ord(ch)<127:
           tmp+=ch
       else:
           value="%2.2x" % ord(ch)
           tmp+="["+value+"]"
       
    return tmp

def str2bigendian(astring):
    """
    oppposite of istr2int
    """
    (a,b,c,d)=(ord(astring[0]),ord(astring[1]),ord(astring[2]),ord(astring[3]))
    result=d
    result=result+c*256
    result=result+b*65536
    result=result+a*16777216
    return result



def big_order(myint):
    """
    Opposite of str2bigendian
    """
    str=""
    a=chr(myint % 256)
    myint=myint >> 8
    b=chr(myint % 256)
    myint=myint >> 8
    c=chr(myint % 256)
    myint=myint >> 8
    d=chr(myint % 256)
    
    str+="%c%c%c%c" % (d,c,b,a)
    return str


def reliableSend(sock,data):
    #print "Inside reliableSend"
    #tcp only for now
    length=len(data)
    sent=0
    while sent<length:
        sent+=sock.send(data[sent:])
        time.sleep(0.001)
    #print "Done with reliableSend"
    return
    

def reliableRecv(sock,length):
    data=""
    #print "Inside reliableRecv"	
    while len(data)!=length:
        data+=sock.recv(length-len(data))
        time.sleep(0.001)
    #print "Done with reliableRecv"
    return data

id=0
def getnextid():
    global id
    id+=1
    return id

class requestHandler(Thread):
    def __init__(self,helium,request):
        Thread.__init__(self)

        self.helium=helium
        self.request=request
        return
    

class request:
    def __init__(self,id=None):
        self.type="unbound"
        if id==None:
            self.id=getnextid()
        else:
            self.id=id
        return
    
class requestack(request):
    def __init__(self,id):
        request.__init__(self,id=id)
        self.type="ack"
        
class commandRequest(request):
    def __init__(self,command):
        request.__init__(self)
        self.command=command
        self.type="command"
        return
    
    
class cwdRequest(request):
    def __init__(self,data):
        request.__init__(self)
        self.dir=data
        self.type="cwd"
        return
    
class fileRequest(request):
    def __init__(self,filename):
        request.__init__(self)
        self.filename=filename
        self.type="get"
        return
    
class putRequest(request):
    def __init__(self,filename,offset,data,totalsize):
        request.__init__(self)
        self.filename=filename
        self.type="put"
        self.offset=offset
        self.data=data
        self.totalsize=totalsize
        return
    
class response:
    def __init__(self):
        self.id=getnextid()
        self.type="unbound"
        return

class commandResponse(response):
    def __init__(self,data):
        response.__init__(self)
        
        self.type="commandresponse"
        self.data=data
        return

class fileResponse(response):
    def __init__(self,requestid,offset,data,totalsize):
        response.__init__(self)
        
        self.type="fileresponse"
        self.data=data
        self.requestid=requestid
        self.offset=offset
        self.totalsize=totalsize

class errorResponse(response):
    def __init__(self,message):
        response.__init__(self)
        self.type="errorresponse"
        self.message=message
        return
    
class responseack(response):
    def __init__(self,id):
        response.__init__(self)
        self.type="ack"
        self.id=id
        return
    
    
class resender(Thread):
    def __init__(self,myrequest,engine):
        Thread.__init__(self)
        
        self.request=myrequest
        self.engine=engine
        return
    
    def run(self):
        while not self.engine.hasAck(self.request.id):
            #print "Sending %d request!"%self.request.id
            self.engine.send(self.request)
            time.sleep(0.02) #let other thread get a chance...
            if self.engine.hasAck(self.request.id):
                break
            time.sleep(1) #one second timeout
        self.engine.removeResender(self)
        return #end thread

class reciever(Thread):
    def __init__(self,sock,engine):
        Thread.__init__(self)
        self.sock=sock
        self.engine=engine
        return
    
    
    def run(self):
        while 1:
            retlist=select.select([self.sock],[],[],None)
            if self.sock not in retlist[0]:
                return
            #otherwise, we've got something to read in
            self.engine.recv(self.sock)
    
        