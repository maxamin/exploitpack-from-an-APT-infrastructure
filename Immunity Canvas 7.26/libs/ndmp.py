#! /usr/bin/env python
import socket, time, struct

def getString(data):
    len=struct.unpack("!L", data[:4])[0]
    return data[4:4+len]

class NDMP_Packet:
    def __init__(self, sequence=1, timed=-1, type=0x0, Message=0, reply=0, Error=0):
        self.Sequence = sequence
        if timed == -1:
            self.Time = time.time()
        else:
            self.Time = timed
        self.Type    = type
        self.Message = Message
        self.Reply   = reply
        self.Error   = Error

    def get_raw(self):
        return ""
    
    def raw(self):
        pack = struct.pack("!L", self.Sequence)   # Sequence
        pack+= struct.pack("!L", self.Time) # Time
        pack+= struct.pack("!L", self.Type)     # Type (Request)
        pack+= struct.pack("!L", self.Message) # Message CONNECT_CLIENT_AUTH
        pack+= struct.pack("!L", self.Reply)   # Reply Sequence
        pack+= struct.pack("!L", self.Error)   # Error
        pack+= self.get_raw()
        return struct.pack("!L", 0x80000000L+len(pack)) + pack
    
    def get_createRaw(self, data):
        return
        
    def createRaw(self, data):
        (self.Sequence, self.Time, self.Type, self.Message,\
            self.Reply, self.Error)= struct.unpack("!LLLLLL", data[0:24])
        self.get_createRaw(data[24:])
        
        
class NDMP_GetServerInfo(NDMP_Packet):

    def __init__(self):
        NDMP_Packet.__init__(self)
        self.Message = 0x108
        self.Error= 2

    def get_createRaw(self, data):
        ndx=0
        
        self.CError=struct.unpack("!L", data[ndx:ndx+4])[0]
        ndx += 4
        
        self.VendorName = getString(data[ndx:])
        ndx +=4 + len(self.VendorName)+1

        self.ProductName = getString(data[ndx:])
        ndx +=4 + len(self.ProductName)+1

        self.RevisionName = getString(data[ndx:])
        ndx +=4 + len(self.RevisionName)+1
        (self.AuthNum, self.AuthType) = struct.unpack("!LL", data[ndx:ndx+8])
        
class NDMP_NotifyConnection(NDMP_Packet):

    def __init__(self):
        NDMP_Packet.__init__(self)
        self.Message = 0x502

    def get_createRaw(self, data):
        (self.ConnectedStatus,self.ProtocolVersion) = \
         struct.unpack("!LL", data[:8])
        self.Reason = getString(data[8:])

class NDMP_ConnectClientAuth(NDMP_Packet):

    # We are only supporting now text auth
    def __init__(self, authtype=3, username="", password=""):
        NDMP_Packet.__init__(self)
        self.Message = 0x901
        self.AuthType = authtype
        self.Username =username
        self.Password = password
        
    def get_raw(self):
        pack=struct.pack("!L", self.AuthType)
        pack+= struct.pack("!L", len(self.Username))+ self.Username		
        pack+= struct.pack("!L", len(self.Password))+ self.Password
        pack+=struct.pack("!L", 0x4)
        return pack
        
        

    
        

class NDMP:
    
    def __init__(self, getsock=None, covertness=0):

        self.getsock=getsock
        if getsock:
            self.node=getsock.argsDict["passednodes"][0]
        self.covertness=covertness
        

    def connect(self, host, port=10000):

        if self.getsock:
            self.s=self.getsock.gettcpsock()
        else:
            self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.Host = host
        self.Port = port 
        try:
            self.s.connect(self.Host, self.Port)
        except:
            #could not connect
            return None
        ret= self.recv_packet()
        return ret
    
    def recv_packet(self):

        len=self.s.recv(4)
        len= struct.unpack("!L", len)[0] - 0x80000000L # 0x800000000 (Last fragment)
        data= self.s.recv(len)
        p=NDMP_Packet()
        p.createRaw(data)

        if p.Message == 0x502:
            # I need to find a way to cast this (I suck at python)
            p=NDMP_NotifyConnection()
            p.createRaw(data)
            return p
        
        elif p.Message == 0x108:
            p=NDMP_GetServerInfo()
            p.createRaw(data)
            return p
            
        
    def getServerInfo(self):

        p=NDMP_Packet()
        p.Message = 0x108
        
        if self.covertness > 5:
            p.Reply=1
    
        p.Error=0x21212121
        self.s.send(p.raw())
        return self.recv_packet()
        
    def ConnectClientAuth(self, authtype, username, password):

        p=NDMP_ConnectClientAuth(authtype, username, password)

        if self.covertness > 5:
            p.Reply=1

        self.s.send(p.raw())
        return self.recv_packet()
        
        
        