#!/usr/bin/env python
import socket 
from timeoutsocket import Timeout
from internal import devlog
import random

class sockserver(object):
    """
    Sets up an TCP Server and handles connections for you in a CANVAS friendly way
    """
    def __init__(self, port=None, exploit=None):
        #externals
        self.port=port
        self.exploit=exploit 
        self.protocol="TCP"
        self.listen_host="0.0.0.0"
        #internals
        self.listen_sock=None 
        return 
    
    def log(self, msg):
        if self.exploit:
            self.exploit.log(msg)
        else:
            print msg
        return 
    
    def accept(self):
        """
        Accept one connection and handle it
        """
        devlog("rtsp","Accepting connection")
        try:
            newfd, addr =self.listen_sock.accept()
            devlog("rtsp", "Got connection from %s"%(addr,))
        except Timeout:
            self.log("Timed out waiting for connection")
            return False 
        except socket.error, msg:
            self.log("Error: %s"%msg)
            return False 
        self.handle(newfd)
        return True 
    
    def startup(self):
        """
        Returns True on successful startup.
        """
        if self.exploit:
            devlog("rtsp","Using canvas exploit to set up listener on port %d"%self.port)
            if self.protocol=="TCP":
                self.listen_sock=self.exploit.gettcplistener(self.port)
            elif self.protocol=="UDP":
                self.listen_host=self.exploit.getudplistener(self.port)
            if not self.listen_sock:
                self.log("Failed to listen on that port")
                return False 
                
        else:
            self.listen_sock=socket.socket()
            self.listen_sock.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:
                self.listen_sock.bind((self.listen_host,self.port))
                self.listen_sock.listen(5)
            except socket.error, msg:
                self.listen_sock.close()
                self.log("Could not listen on that host:port: %s:%d - %s"%(self.listen_host,self.port,msg))
                #import traceback
                #traceback.print_exc()
                return False

        #now we have a socket listening
        return True 
    
    def close(self):
        """
        Close our socket.
        """
        if self.listen_sock:
            self.listen_sock.close()
            self.listen_sock=None 
        return 
        
    def read_http_header(self, fd):
        """
        Reads the header and returns it as a single string (not structured)
        """
        ret=[]
        MAXSIZE=50000 #don't allow remote client to fill up our ram entirely
        while ret[-4:]!=list("\r\n\r\n"):
            try:
                ret+=[fd.recv(1)]
            except Timeout:
                break 
            except socket.error:
                break 
            if len(ret)>MAXSIZE:
                break 
        ret = "".join(ret)
        self.saved_headers=ret 
        return ret 
    
    def get_header_line(self, header):
        """
        Uses self.saved_headers to get a header
        returns "" on not found
        """
        lines=self.saved_headers.split("\r\n")
        length=len(header)
        for line in lines:
            if line[:length]==header:
                return line 
        return ""
    
    def get_header_value(self, header):
        """
        For CSeq: 1 returns 1 else returns ""
        """
        headerline=self.get_header_line(header)
        if not headerline:
            return ""
        ret=":".join(headerline.split(":")[1:])
        return ret 
            
class rtspserver(sockserver):
    """
    RTSP Server
    """
    def __init__(self, port=7070, exploit=None):
        sockserver.__init__(self, port,exploit)
        self.verbs=["DESCRIBE","SETUP","TEARDOWN","PLAY","PAUSE","OPTIONS","RECORD"]
        return 
    
    def get_seq(self):
        """
        need to mirror whatever client sent us
        """
        ret=int(self.get_header_value("CSeq"))
        return ret
    
    def get_describe_content(self):
        """
        Override this to send your own content file (or generate one automatically, etc)
        """
        server_body="""v=0
o=mhandley 2890844526 2890842807 IN IP4 126.16.64.4
s=SDP Seminar
i=A Seminar on the session description protocol
u=http://www.cs.ucl.ac.uk/staff/M.Handley/sdp.03.ps
e=mjh@isi.edu (Mark Handley)
c=IN IP4 224.2.17.12/127
t=2873397496 2873404696
a=recvonly
m=audio 3456 RTP/AVP 0
m=video 2232 RTP/AVP 31
m=whiteboard 32416 UDP WB
a=orient:portrait
"""     
        return (server_body, len(server_body))
        
    def handle(self, fd):
        """
        Handle one connection
        """
        done=False 
        while not done:
            header=self.read_http_header(fd)
            if not header:
                devlog("rtsp", "Timeout on recv, closing connection")
                done=True
                continue
            devlog("rtsp","Header: %s"%header)
            server_body=""
            if header[:7]=="OPTIONS":
                #options query
                fields=[]
                fields+=["RTSP/1.0 200 OK"]
                fields+=["Server: Real/5.5"]
                fields+=["Public: %s"%(",".join(self.verbs))]
                fields+=["CSeq: %d"%self.get_seq()]
                
            elif header[:8]=="DESCRIBE":
                server_body, sdp_length = self.get_describe_content()

                fields=[]
                fields+=["RTSP/1.0 200 OK"]
                fields+=["CSeq: %d"%self.get_seq()]
                fields+=["Content-Type: application/sdp"]
                fields+=["Content-length: %d"%(sdp_length)]
            elif header[:5]=="SETUP":
                fields=[]
                fields+=["RTSP/1.0 200 OK"]
                fields+=["CSeq: %d"%self.get_seq()]
                fields+=["Session: %d"%random.randint(0,5000)]
                transport_line=self.get_header_line("Transport")
                #get transport line from client
                fields+=[transport_line]
            #todo: Complete protocol
            
            data="\r\n".join(fields)+"\r\n\r\n"+server_body
    
            devlog("rtsp", "Sending %s"%data)
            fd.send(data)
            #done=True 
            #fd.close()
        return 
    
def main():
    """
    Testing
    """
    r=rtspserver()
    r.startup()
    print "Done testing rtspserver"
    return 

if __name__=="__main__":
    main()