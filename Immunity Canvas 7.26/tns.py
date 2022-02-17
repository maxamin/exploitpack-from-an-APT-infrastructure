#! /usr/bin/env python
"""
tns.py

Does Oracle logins and such things

Copyright Immunity, Inc. 2003

CANVAS License

"""
from exploitutils import *

notes="""
If you cannot login, status will not give you the available services
"""

def tnscmd(data):
        packet=""
        #checksum
        packet+=binstring("00 00");
        #connect packet
        packet+="\x01"
        #reserved byte
        packet+="\x00"
        #packet header checksum
        packet+=binstring("00 00")
        #version 309
        packet+="\x01\x35"
        #version compatible 300
        packet+="\x01\x2c"
        #service options
        packet+="\x00\x00"
        #session data unit size 4096
        packet+="\x10\x00"
        #max transmission data size
        packet+="\x7f\xff"
        #nt protocol charactaristics
        packet+="\x83\x08"
        #line turnaround value
        packet+="\x00\x00"
        #value of 1 in hardware
        packet+="\x01\x00"
        #length of connect data
        packet+=short2bigstr(len(data))
        #offset to connectdata 52
        packet+="\x00\x34"
        #max recievable connect data
        packet+=binstring("08 00 00 00")
        #connect flags 0
        packet+="\x08"
        #connect flags 1
        packet+="\x08"
        #trace cross facility item 1
        packet+=binstring("00 00 00 00");
        #trace cross facility item 2
        packet+=binstring("00 00 00 00");
        #trace unique connection id
        packet+=binstring("00 00 00 00 00 00 00 00");
        #pad bytes
        packet+=binstring("00 00")
        packet+=data        
        return packet

def tnsversion(sock):
        versionstring="(CONNECT_DATA=(COMMAND=VERSION))"
        packet=tnscmd(versionstring)
        tnssend(sock,packet)
        result=tnsrecv(sock)
        return result

def tnsstatus(sock):
        tnssend(sock,tnscmd("(CONNECT_DATA=(CID=(PROGRAM=)(HOST=)(USER=CANVAS))(COMMAND=STATUS)(ARGUMENTS=64)(SERVICE=CANVAS)(VERSION=135294976))"))
        data="A"*51
        result=""
        accept=tnsrecv(sock)
        while len(data)>2:
                try: 
                        data=tnsrecv(sock)
                except:
                        data=""
                result+=data
        return result

def tnsconnect(sock,host,port,localhost,
               localuser="CANVASUSER",localprogram="CANVAS.EXE"):
        
        connectdata="(DESCRIPTION=(ADDRESS_LIST=(ADDRESS=(COMMUNITY=tcp.world)(PROTOCOL=TCP)(Host=%s)(Port=%s)))(CONNECT_DATA=(SID=CMTK)(CID=(PROGRAM=%s)(HOST=%s)(USER=%s))))"%(host,port,localprogram,localhost,localuser)
        #connectdata="(DESCRIPTION=(CONNECT_DATA=(CID=(PROGRAM=)(HOST=)(USER=AppDetective))(COMMAND=status)(ARGUMENTS=64)(SERVIVE=REMOTE)(VERSION=135294976)))
        packet=tnscmd(connectdata)        

        tnssend(sock,packet)        
        result=tnsrecv(sock)
        return result

def tnssend(sock,data):
        return send_bigendian_halfword_packet(sock,data,additive=2)
        

def tnsrecv(sock):
        data=recv_bigendian_halfword_packet(sock,additive=-2)
        return data


