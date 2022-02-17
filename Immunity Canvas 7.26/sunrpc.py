#! /usr/bin/env python

"""
SunRPC Module for CANVAS

Subject to the CANVAS License

Copywrite Immunity, Inc. 2003
"""

from exploitutils import *
import random 
import sys
import socket
import select
import timeoutsocket

def SRPCgetport(host,program,version,proto,getsock=None):
        """
        Contacts the SunRPC Portmapper
        Returns None if we couldn't get the port
        First tries UDP 111, then tries UDP to port 32771
        Then Tries TCP to port 111
       
        """
        proto=proto.upper()
        if proto=="UDP":
                proto=17
        elif proto=="TCP":
                proto=6

        #GETPORT
        procedure=3
        #program, version, protocol, port
        data=big_order(program)+big_order(version)+big_order(proto)+big_order(0)
        #try UDPrun
        portmapperprogram=100000
        portmapperversion=2
        for port in [111,32771]:
                if getsock==None:
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                else:
                        s=getsock.getudpsock()
                s.connect((host, port))
                header=SRPCCallHeaderUDP(portmapperprogram,portmapperversion,procedure)
                #UDP doesn't have a length header, or fragments, or anything like that.
                s.send(header+data)
                retList=select.select([s],[],[],2.0)
                if s not in retList[0]: 
                        #print "returning 0"
                        #print retList
                        return 0
                #print "recving"
                try:
                        response=s.recv(10000)        
                except (socket.error, timeoutsocket.Timeout):
                        return None
                if response[4:8]==big_order(1):
                        #a reply packet!
                        if response[8:12]==big_order(0):
                                #accepted!
                                return str2bigendian(response[24:28])

        #TCP IS NOT TESTED YET
        if getsock==None:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        else:
                s=getsock.gettcpsock()
        
        s.connect((host, 111))
        response=SRPCCallTCP(s,portmapperprogram,portmapperversion,procedure,data)
        if response==None:
                return None
        #ok, got it from TCP
        return str2bigendian(response[20:24])


def SRPCCallTCP(s,program,version,procedure,data):
        """
        TODO
        """
        return None

def SRPCCallHeaderUDP(program,version,procedure):
        """
        Creates the header for a SunRPC UDP Packet
        """
        
        data=""
        XID=random.randint(1,sys.maxint-1)
        data+=big_order(XID)
        data+=big_order(0) #call message type
        data+=big_order(2) #RPC Version 2
        data+=big_order(program)
        data+=big_order(version)
        data+=big_order(procedure)
        data+=big_order(0)*4 #Credentials and Verifier
        return data
        
def SRPCCallHeaderTCP(program,version,procedure):
        """
        Creates the header for a SunRPC TCP Packet
        """
        
        data=""
        XID=random.randint(1,sys.maxint-1)
        data+=big_order(XID)
        data+=big_order(0) #call message type
        data+=big_order(2) #RPC Version 2
        data+=big_order(program)
        data+=big_order(version)
        data+=big_order(procedure)
        data+=big_order(0)*4 #Credentials and Verifier
        return data
        
def SRPCCallHeaderUDP_UNIX(program,version,procedure,host,uid=0,gid=0):
        """
        Creates the header for a SunRPC UDP Packet
        """
        
        data=""
        XID=random.randint(1,sys.maxint-1)
        data+=big_order(XID)
        data+=big_order(0) #call message type
        data+=big_order(2) #RPC Version 2
        data+=big_order(program)
        data+=big_order(version)
        data+=big_order(procedure)
        #CREDS
        length=4*4+len(sunrpcstr(host))
        data+=big_order(1) #flavor AUTH_UNIX
        data+=big_order(length)
        data+=big_order(XID) #stamp
        data+=sunrpcstr(host)
        data+=big_order(uid)
        data+=big_order(gid)
        data+=big_order(0) #aux gids
        data+=big_order(0)*2 #Verifier (flavor NULL, length 0)
        return data


def sunrpc_recv_udp(sock):
        data=sock.recv(2400)
        return data
        
