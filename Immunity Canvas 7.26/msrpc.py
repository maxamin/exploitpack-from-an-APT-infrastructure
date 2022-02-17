#! /usr/bin/env python
"""
All the msrpc routines you could want and more!
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from exploitutils import *
import socket, struct
import random
import dunicode
import time
import traceback
import sys

#A useful page for win32 errors
#http://www.everything2.com/index.pl?node_id=1139737


transfersyntax="8a885d04-1ceb-11c9-9fe8-08002b104860"
syntaxversion=2
BINDPACKET=chr(11)
RESPONSEPACKET=chr(0x02)

STATUS_SUCCESS=0
STATUS_BUFFER_OVERFLOW=0x80000005L
SMB_SUCCESS=0

BINDACK=chr(0x0c)
PROVIDERREJECT=chr(0x0d)

#errornumbers 
ERR1c010002="The operation number passed in the request PDU is greater than or equal to the number of operations in the interface."

# old ascii samba toggle
OLDSAMBA=0

def get_all_stubs(packets):
    """
    Takes in a list of DCE packets (as typically returned by DCE.call())
    and returns a string buffer which is the concatonation of all the stubs
    """
    ret=[]
    for p in packets:
        if hasattr(p, "stub"):
            ret+=[p.stub]
    return "".join(ret) 

def uuid2uuidstr(uuid):
    u=uuid
 
    try:
        uuidstr="%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x"%(uint32(istr2int(u[:4])),
                                                                    istr2halfword(u[4:6]),
                                                                    istr2halfword(u[6:8]),
                                                                    ord(u[8]),
                                                                    ord(u[9]),
                                                                    ord(u[10]),
                                                                    ord(u[11]),
                                                                    ord(u[12]),
                                                                    ord(u[13]),
                                                                    ord(u[14]),
                                                                    ord(u[15]))
    except:
        print "[!] WARNING: unintelligble interface ID received ... replacing with mock data"
        uuidstr = "AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE"
    return uuidstr

def uuid2data(uuidstring):
    """
    creates a uuid structure out of a string
    """
    #print "UUID=%s"%uuidstring
    data=""
    uuidstring=uuidstring.replace("-","")
    data+=intel_hex(uuidstring[:8])
    uuidstring=uuidstring[8:]
    data+=intel_hex(uuidstring[:4])
    uuidstring=uuidstring[4:]
    data+=intel_hex(uuidstring[:4])
    uuidstring=uuidstring[4:]
    data+=binstring(uuidstring)
    return data

def get_uuid(buf):
    uuid=uuid2uuidstr(buf)
    return uuid,buf[16:]


def read_raw_unicode_string(buf):
    i=0 #this makes it so that if we never find a 00 00 we use the whole buffer, basically
    for i in range(0,len(buf)/2):
        if buf[i*2]=="\x00" and buf[i*2+1]=="\x00":
            #termination of string
            break
    return buf[:i*2+2], i

def read_unicode_string(buf):
    """Given a buffer, return the first unicode string found (termed with 0000)
    and the length of the string eaten"""
    #print "unicode buf=\n%s"%prettyprint(buf)
    #i+=2 #account for termination of string
    buf,i=read_raw_unicode_string(buf)
    ret=buf[:i*2+2].replace("\x00","")
    index=i*2+2
    return ret,index

def createdcebind(uuid,versionmajor,versionminor,callid,auth=None,unicode=0):
    """
    Creates the DCE Bind packet
    """
    if auth:
        bind=DCEBind(auth)
    else:
        bind=DCEBind()
        
    bind.setVersion(versionmajor, versionminor)
    bind.setUuid(uuid)
    bind.setTransferSyntax(transfersyntax)
    
    data=bind.raw()
    return data

def msrpcbind(uuid,versionmajor,versionminor,host,port,callid,covertness=1,getsock=None):
    """
    binds to an msrpc service
    returns a tuple (ret 1 on success,socket)
    """
    
    data=createdcebind(uuid,versionmajor,versionminor,callid)
    devlog("ipv6", "host=%s"%host)
    if getsock==None:
        # XXX: IPv6 context switch
        if ":" in host:
            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        # XXX: check if this context switches ok !
        if ":" in host:
            s = getsock.gettcpsock(AF_INET6=1)
        else:
            s = getsock.gettcpsock()
    try:
        sockaddr = (host, port)
        if ":" in host:
            res = socket.getaddrinfo(host, port, socket.AF_INET6, socket.SOCK_STREAM)
            sockaddr = res[0][4]
        s.connect(sockaddr)
    except:
        return (0,None)

    #ok, now we are connected
    if covertness>5:
        #print "Covert msrpcbind - sending data one byte at a time"
        for d in data:
            s.send(d)
            time.sleep(0.2)
    else:
        s.send(data)
    #read response
    try:
        response=s.recv(60)
    except:
        print "Timeout expired"
        return (0,None)
    
    if len(response)!=60:
                    return (0,None)

    #check to see if we got an ok. :>
    if response[2]!="\x0c":
                    print "Got %d instead of 12 - not a bind_ack"%ord(response[2])
                    return (0,None)

    if response[36:38]!="\x00\x00":
                    #print "Provider reject, or some other bind error"
                    return (0,None)
    
    return (1,s)

            
def get_random_uuid():
    """returns a random string for your uuid"""
    x=random.randint(0,500000)
    return "%8.8x-ffff-ffff-ffff-ffffffffffff"%x
    
#Type for request UDP
UDPREQUEST="\x00"
UDPFRAG=0x04
UDPLAST=0x02
IDEMPOTENT=0x20
NOFACK=0x08
AUTHNONE="\x00"
def msrpcsend_udp(conn,calldata,object,ifid,ifid_ver,activity,opnum,sequence_number,idempotent=0,nofack=0,neverfinish=0):
    first=1
    last=0
    dataleft=calldata[:]
    MAXFRAGLENGTH=65400
    fragment_number=0
    while dataleft!="":
        fraglen=MAXFRAGLENGTH
        if len(dataleft)<=MAXFRAGLENGTH:
            fraglength=len(dataleft)
            last=1
        else:
            fraglength=MAXFRAGLENGTH
        
        pkt= "\x04"
        pkt+=UDPREQUEST
            
        flags1=0
        if not (first and last):
            flags1|=UDPFRAG
            if last and not neverfinish:
                flags1|=UDPLAST
        if idempotent: #act exactly one?
            flags1|=IDEMPOTENT
        if nofack:
            flags1|=NOFACK
            
        pkt+=chr(flags1)
        pkt+="\x00" #flags2
        pkt+="\x10\x00\x00" #data rep
        pkt+="\x00"
        if object!=None:
            pkt+=uuid2data(object)
        else:
            pkt+="\x00"*16 #no object
        pkt+=uuid2data(ifid)
        pkt+=uuid2data(activity)
        pkt+="\x00"*4 #boot time
        pkt+=intel_order(ifid_ver)
        pkt+=intel_order(sequence_number)
        pkt+=halfword2istr(opnum)
        interface_hint=0xffff
        activity_hint=0xffff
        pkt+=halfword2istr(interface_hint)
        pkt+=halfword2istr(activity_hint)
        pkt+=halfword2istr(fraglength)
        pkt+=halfword2istr(fragment_number)
        pkt+=AUTHNONE
        pkt+="\x00" #serial low
        pkt+=dataleft[:MAXFRAGLENGTH]
        dataleft=dataleft[MAXFRAGLENGTH:]
        conn.send(pkt) #SEND THE DCE FRAGMENT
        fragment_number+=1
    return
        
        
def msrpcsend(conn,calldata,opnum,callid,nevercomplete=0,covertness=1):
                lastfrag=0x02
                firstfrag=0x01
                #24 is for header length
                if covertness>5:
                    MAXFRAGLENGTH=50
                    #print "Covert msrpcsend"
                else:
                    MAXFRAGLENGTH=5480-24
                dataleft=calldata
                
                first=1
                last=0
                while len(dataleft)!=0:
                                fraglength=MAXFRAGLENGTH
                                if len(dataleft)<=MAXFRAGLENGTH:
                                                fraglength=len(dataleft)
                                                last=1

                                data=""
                                data+=binstring("05 00 00")
                                flags=0x00
                                if first:
                                                flags|=firstfrag
                                                first =0
                                
                                if last and not nevercomplete:
                                                flags|=lastfrag

                                data+=chr(flags)
                                data+=binstring("10 00  00 00")


                                data+=halfword2istr(fraglength+24)
                                #auth length
                                data+=binstring("0000")
                                data+=intel_order(callid)
                                data+=intel_order(fraglength+24)
                                data+=binstring("0000")
                                data+=halfword2istr(opnum)
                                data+=dataleft[:MAXFRAGLENGTH]
                                dataleft=dataleft[MAXFRAGLENGTH:]
                                conn.send(data)
                                #no recv for now
                                #conn.recv(10000)
                return

def netbios_encode(instr):
                """
                From http://www.faqs.org/rfcs/rfc1001.html
                Each 4-bit, half-octet of the NetBIOS name is treated as an 8-bit,
                right-adjusted, zero-filled binary number.  This number is added to
                value of the ASCII character 'A' (hexidecimal 41).  The resulting 8-
                bit number is stored in the appropriate byte.  The following diagram
                demonstrates this procedure:
                                
                                                                                                    0 1 2 3 4 5 6 7
                                                                                                +-+-+-+-+-+-+-+-+
                                                                                                |a b c d|w x y z|          ORIGINAL BYTE
                                                                                                +-+-+-+-+-+-+-+-+
                                                                                                                |       |
                                                                            +--------+       +--------+
                                                                            |                         |     SPLIT THE NIBBLES
                                                                            v                         v
                                                0 1 2 3 4 5 6 7           0 1 2 3 4 5 6 7
                                            +-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+
                                            |0 0 0 0 a b c d|         |0 0 0 0 w x y z|
                                            +-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+
                                                                            |                         |
                                                                            +                         +     ADD 'A'
                                                                            |                         |
                                                0 1 2 3 4 5 6 7           0 1 2 3 4 5 6 7
                                            +-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+
                                            |0 1 0 0 0 0 0 1|         |0 1 0 0 0 0 0 1|
                                            +-+-+-+-+-+-+-+-+         +-+-+-+-+-+-+-+-+
                """
                result=""
                for c in instr:
                                a=ord(c)&0x0f
                                b=(ord(c)&0xf0) >> 4
                                result+=chr(0x41+b)+chr(0x41+a)
                return result
                                
                
                
                
                
def netbios_sessionrequest(s):
    """
    Session Request used for port 139
    """
    packet=""
    
    data=""
    data+=binstring("20") #Server service
    serverstring="*SMBSERVER"
    data+=netbios_encode(serverstring+" "*(16-len(serverstring)))
    data+=binstring("00") #null terminate
    data+=binstring("20") #Server service
    serverstring="WWW"
    data+=netbios_encode(serverstring+" "*(16-len(serverstring)))
    data+=binstring("00") #Null Terminate
    
    packet+=binstring("81") #session request
    packet+=binstring("00") #add 0 to length
    packet+=short2bigstr(len(data))
    packet+=data
    try:
        s.sendall(packet)
    except:
        #connection reset by peer
        return (1, "Socket reset by peer")
    try:
        data=s.recv(4)
    except:
        #Connection reset by peer, no doubt
        data=""
            
    if data=="" or data[0]!=binstring("82"):
        errstr="Failed to negotiate a netbios session request"
        return (1, errstr)
    return (0,None)

def NetDDE_Session(s, called, calling="WIN2KCAN"):
    data="\x20%s\x00\x20%s\x00" % \
        (netbios_encode(called+" "*(15-len(called))+"\x1f"), \
         netbios_encode(calling+" "*(15-len(calling))+"\x1f") )

    s.sendall(struct.pack("!BBH", 0x81, 0x0, len(data)) + data)
    if data=="" or data[0]!=binstring("82"):
        errstr="Failed to negotiate a netbios session request"
        return (1, errstr)
    return (0,None)
    

    
def netbios(packet):
    """Adds a netbios session service to it"""
    if len(packet)<=0x10000:
        packet="\x00\x00"+short2bigstr(len(packet))+packet
    else:
        devlog("msrpc","Len packet=%d"%len(packet))
        devlog("msrpc","Big: %d"%(len(packet)-0x10000))
        packet="\x00\x10"+short2bigstr(len(packet)-0x10000)+packet
    return packet



def smb(data,command,tid,pid,uid,unicod=1):
    packet=""
    packet+=binstring("ff 53 4d 42") #smb server component
    packet+=binstring(command) #SMB Command: 
    packet+=binstring("00 00 00 00") #NT Status: Success
    packet+=binstring("18") #flags
    flags2=0x4001
    if unicod:
        flags2|=0x8000
    packet+=halfword2istr(flags2)
    #packet+=binstring("01 c0") #flags2
    packet+=binstring("00")*12 #reserverd
    packet+=tid #tree ID
    packet+=pid #process ID
    packet+=uid #user ID
    packet+=binstring("c0 00") #multiplex ID
    #tree connect andx request
    if isinstance(data, unicode):
        data = data.encode('cp1252')
    return packet+data

def smb_negotiate(s):
    """
    Negotiate an SMB session with the remote machine.
    """
    packet=""
    NEGOTIATE="0x72"
    packet+="\x00" #word count
    dialects=""
    #these must appear in order. It will chose relatively high...
    #we have to be at least at Lanman. We want to do NTLM for bouncing...
    for dialect in ["PC NETWORK PROGRAM 1.0","MICROSOFT NETWORKS 1.03",
                    "MICROSOFT NETWORKS 3.0","LANMAN1.0","LM1.2X002",
                    "Samba", "NT LANMAN 1.0", "NT LM 0.12"]:
        dialects+="\x02"+dialect+"\x00"
    
    bytecount=len(dialects)
    packet+=halfword2istr(bytecount)
    packet+=dialects
    packet=netbios(smb(packet,NEGOTIATE,"\x00\x00","\x00\x00","\x00\x00"))
    try:
        s.sendall(packet)
    except:
        #socket reset by peer
        errstr="Socket reset by peer"
        error=1
        return error,errstr, "" , "", "", ""

    data=recvnetbios(s)
        
    if data=="":
        errstr="No response received!"
        error=1
        return error,errstr,"","","",""

    data,ret=parsesmb(data)

    if ret["ntstatus"]!=0:
        error=1
        errstr="ntstatus not success: %s"%ret["ntstatus"]
        return error, errstr, "", "", "", "",""
    
    body=data
    wordcount=ord(body[0])
    dialectindex=istr2halfword(body[1:3]) #should be 7 (greater than LanMan 2.1)
    securitymode=ord(body[3]) #should be 03
    max_mpx=str2int16_swapped(body[4:6])
    max_vcs=str2int16_swapped(body[6:8])
    max_buffer_size=str2int32_swapped(body[8:12])
    max_raw_buffer=str2int32_swapped(body[12:16])
    session_key=str2int32_swapped(body[16:20])
    capabilities=str2int32_swapped(body[20:24])
    systemtime=str2int64_swapped(body[24:32])
    server_time_zone=str2int16_swapped(body[32:34])
    #print "Body=%s"%hexprint(body[30:])
    keylength=ord(body[34])
    if keylength!=8:
        print "Some kind of error with keylength...%x"%keylength
        
    #print "Keylength=%x"%keylength
    bytecount=istr2halfword(body[35:37])
    key=body[37:37+keylength]
    #print "key=%s"%hexprint(key)
    domain,index=read_unicode_string(body[37+keylength:])
    devlog("msrpc","domain=*%s* length %d"%(domain,len(domain)))
    server,index=read_unicode_string(body[37+keylength+index:])
    devlog("msrpc","Server=%s"%server)
    errstr=""
    error=0
    return error,errstr,capabilities,key,domain,server


def smb_session_setup(s,auth,capabilities, domain=""):
    """
    Send the session setup packet and recv the response
    """
    devlog("msrpc","smb_session_startup(%s,%s,%s,%s)"%(auth.username,auth.password,domain,hexprint(auth.challenge)))
    packet=""
    domain=domain.upper()
    if auth.challenge!="" and auth.challenge!=None:
        if auth.password==None:
            auth.password=""
        #key is the server nonce
        unipassword=auth.nt_key
        ansipassword=auth.lm_key
    else:
        #cleartext?
        unipassword=msunistring(auth.password)
        ansipassword=password

    #null session support
    login=auth.username
    password=auth.password
    if login==None or (login=="" and password==""):
        unipassword=""
        ansipassword=""
        domain=""
        login=""
        
    #ansi password is actually lanman when we're doing encryption...
    #print "uni Password=%s"%hexprint(unipassword)
    #print "ansi Password=%s"%hexprint(ansipassword)
    
    SESSION_SETUP="0x73"
    packet=smb(packet,SESSION_SETUP,"\x00\x00","\x00\x10","\x00\x00")
    packet+=binstring("0d") #word count
    packet+=binstring("ff") #AndX Command (No further commands)
    packet+=binstring("00") #reserved
    packet+=binstring("00 00") #andX offset
    packet+=binstring("ff ff") #max buffer
    packet+=binstring("02 00") #max MPX count
    vcnum=random.randint(1,5000)
    packet+=halfword2istr(vcnum) #vc number
    packet+=binstring("00 00 00 00") #session key
    #packet+=halfword2istr(len(password)) #ANSI password length
    packet+=halfword2istr(len(ansipassword)) #ANSI password length
    packet+=halfword2istr(len(unipassword)) #unicode password length
    packet+=binstring("00 00 00 00") #reserved
    packet+=binstring("ff 00 00 00") #capabilities


    OS="Unix"
    lanman="Samba"
    login=msunistring(login.upper())
    domain=msunistring(domain.upper())
    OS=msunistring(OS)
    lanman=msunistring(lanman)
    data=""
    data+=ansipassword
    data+=unipassword
    data+="\x00" #padding
    data+=login
    data+=domain
    data+=OS
    data+=lanman
    
    #print repr(data)

    bytecount=len(data)

    packet+=halfword2istr(bytecount)+data
    
    packet=netbios(packet)
    #error=1
    #errstr="We don't yet support logins and passwords, sorry"
    #return error,errstr,None            
    s.sendall(packet)
    data=recvnetbios(s)
    if data=="":
        errstr="No response received during session setup!"
        error=1
        return error,errstr,None,None,None,None
    data,ret=parsesmb(data)
    errval=ret["ntstatus"]
    if errval!=SMB_SUCCESS:
        #also see here: http://www.wildpackets.com/elements/misc/SMB_NT_Status_Codes.txt
        errlist=[(0x00080001,"Server reported out of memory")]
        errlist+=[(0x00050001,"Server reported Access Denied")]
        errlist+=[(0xc000006d,"Server reported Logon Failure")]
        for err in errlist:
            if errval==err[0]:
                errstr=err[1]
                error=1
                return error,errstr,None,None,None,None

        #print "Errval=%s"%errval
        errstr="Server reported error %8.8x"%long(errval)
        error=1
        return error,errstr,None,None,None,None
            
    errstr="No error"
    error=0
    
    uid=ret["uid"]
   

    # we should really just check for ascii flag in smb header
    # and now we do!
    #0x4 is "unicode supported" - 
    #if we do not support unicode...
    if not capabilities&0x4:
        devlog("msrpc","Using ASCII in smb")
        #for c in data:
        #    print "%c %d"%(c, i)
        #    i += 1
        index = 9
        c = data[index]
        os = ""
        while c != '\0':
            os += c
            index += 1
            c = data[index]
        index += 1
        c = data[index]
        lanman = ""
        while c != '\0':
            lanman += c
            index += 1
            c = data[index]
        index += 1
        c = data[index]
        domain = ""
        while c != '\0':
            domain += c
            index += 1
            c = data[index]
        index += 1
    else:
        devlog("msrpc","Using Unicode in SMB negotiation")
        #print "Data: %s"%prettyprint(data[10:])
        os,index=read_unicode_string(data[10:])
        lanman,index2=read_unicode_string(data[10+index:])
        index+=index2
        #domains a bit funny here
        domain,index=read_unicode_string(data[10+index:])
    
    devlog("msrpc","OS=*%s* lanman=*%s* domain=*%s*"%(os,lanman,domain))
    return error,errstr,uid,os,lanman,domain


def smb_ipc_connect(s,uid):
                """
                Connects to IPC$ share
                returns the Thread ID if successful
                """
                packet=""
                packet+=binstring("ff 53  4d 42") 
                packet+=binstring("75") #SMB Command Tree Connect AndX
                packet+=intel_order(0) #status 0
                packet+=binstring("08") #flags (case sensitivty off)
                
                oldsamba=OLDSAMBA

                if oldsamba: # oldsamba needs ascii
                    packet+=binstring("01 48")#flags2
                else:
                    packet+=binstring("01 c0")#flags2
                
                packet+=binstring("00 00")#process ID High
                packet+=binstring("00 00 00 00  00 00 00 00") #signature 
                packet+=binstring("00 00") #reserved
                packet+=binstring("00 00") #tree ID
                packet+=binstring("8d 2b") #process ID
                packet+=uid #User ID
                packet+=binstring(" 01 00") #multiplex ID
                #TREE CONNECT ANDX REQUEST
                packet+=binstring("04") #word count
                packet+=binstring("ff") #command- no futher commands
                packet+=binstring("00") #reserved
                packet+=binstring("00 00") #AndX offset
                packet+=binstring("00 00") #flags
                packet+=binstring("01 00") #password length

                restofpacket=""

                if oldsamba:
                    hostaddr,port = s.getpeername()
                    restofpacket+="\\\\"+hostaddr+"\\IPC$\x00"
                else:
                    restofpacket+=msunistring("IPC$")
                restofpacket+="IPC\x00"

                packet+=halfword2istr(len(restofpacket)+1) #1 is password?
                packet+=binstring("00") #password                

                packet+=restofpacket                
                packet=netbios(packet)
                s.send(packet)
                data=s.recv(1500)
                if data=="":
                        errstr="No response received during IPC$ connection!"
                        error=1
                        return error,errstr,None
                
                tid=data[28:30]
                errstr="No error"
                error=0
                return error,errstr,tid

                
def nt_createandx(s,tid,uid,pipename):
                """
                Connects to the file pipe itself
                """
                #construct the smb packet
                packet=""
                packet+=s_binary(" ff 53  4d 42") 
                packet+=s_binary("a2") #command NT Create AndX
                packet+=s_binary("00 00 00 00") #status 0
                packet+=s_binary(" 08") #flags

                oldsamba=OLDSAMBA

                if oldsamba: # oldsamba needs ascii
                    packet+=binstring("01 48")#flags2
                else:
                    packet+=binstring("01 c0")#flags2
                
                packet+=s_binary("00 00") #process ID high
                packet+=s_binary("00 00 00 00  00 00 00 00") #signature
                packet+=s_binary("00 00  ") #reserved
                packet+=tid
                packet+=s_binary("8d 2b ")
                packet+=uid
                packet+=s_binary("01 00") #multiplex ID
                #data?
                packet+=s_binary("18") #word count
                packet+=s_binary("ff") #no futher commands
                packet+=s_binary("00") #reserved
                packet+=s_binary("00 00") #andxoffset
                packet+=s_binary("00") #reserved
                packet+=halfword2istr(len(pipename)*2) #filename length *2 for unicode, but without null terminator
                packet+=s_binary("00 00 00 00") #create flags
                
                packet+=s_binary("     00 00 00 00") #root fid
                packet+=intel_order(0x0002019f) #access mask
                packet+=s_binary("00 00 00 00 00 00 00 00 ") #allocation size
                packet+=s_binary("00 00 00 00") #file attributes
                packet+=intel_order(3) #share access
                packet+=intel_order(1) #disposition
                packet+=intel_order(0) #create options
                packet+=s_binary(" 02 00 00 00") #impersonation
                packet+=s_binary("00") #security flags
                
                if oldsamba:
                    pipedata=pipename+"\x00"
                else:
                    pipedata="\x00"+msunistring(pipename)
                pipenamesize=len(pipedata)

                packet+=halfword2istr(pipenamesize)
                packet+=pipedata
                
                #add netbios header to the front of it
                packet=netbios(packet)
                
                s.send(packet)
                data=s.recv(1500)
                if data=="":
                        errstr="No response received during ntcreateandx connection!"
                        error=1
                        return error,errstr,None

                errval=data[9:9+4]

                if errval!="\x00"*4:
                        if errval==binstring("0x220000c0"):
                                errstr="Error returned was Access Denied"
                                error=1
                                return error,errstr,None
                        elif errval==binstring("0xac0000c0"):
                                errstr="Error: Pipe Not Available"
                                error=1
                                return error,errstr,None
                        elif errval==binstring("0x340000c0"):
                                errstr="Error returned was File Not Found."
                                error=1
                                return error,errstr,None
                        else:
                                errstr="Server reported error %8.8x"%intel_str2int(errval)
                                error=1
                                return error,errstr,None
                        
                fid=data[42:44]
                error=0
                errstr="No error"
                return error,errstr,fid


def treeconnect_andx(s,tid,pid,uid,path):
    if tid=="":
        tid="\x00\x00"
    if pid=="":
        pid="\x00\x00"
        
    packet=""
    #tree connect andx request
    wordcount=4
    packet+=chr(wordcount)
    packet+=binstring("ff") #no futher commands
    packet+=binstring("00") #reserved
    packet+=binstring("0000") #andx offset
    packet+=binstring("0000") #flags
    password=""+chr(0)
    packet+=halfword2istr(len(password)) #password length (0)
    data=password #password
    service="?????\x00"
    data+=msunistring(path)
    #print "YO!"
    #print "path=%s Uni=%s"%(hexprint(path),hexprint(msunistring(path)))

    data+=service
    packet+=halfword2istr(len(data)) #bytecount
    packet+=data
    TREE_CONNECT="0x75"
    packet=smb(packet,TREE_CONNECT,tid,pid,uid)
    packet=netbios(packet)
    s.sendall(packet)
    data=recvnetbios(s)
    if data=="":
        errstr="No response received during tree connection!"
        error=1
        return error,errstr,None
    data,ret=parsesmb(data)
    if ret["ntstatus"]==0xc00000ccL:
        errstr="STATUS_BAD_NETWORK_NAME"
        return 1,errstr,""
    if ret["ntstatus"]==0xc0000022L:
        errstr="STATUS_ACCESS_DENIED"
        return 1,errstr,""
    
    tid=ret["tid"]
    #print "data=%s"%hexprint(data[20:30])
    if data.find("NTFS"):
        errstr="NTFS"
    else:
        errstr="FAT"
    error=0
    return error,errstr,tid


def smb_checkdirectory(s,tid,pid,uid,directory):
    """
    Checks to see if we can access a directory in our SMB TID.
    Returns 1, "" on success, 0, failstring on failure
    """
    packet=""
    CHECK_DIR="0x10"
    
    #check directory
    wordcount=0
    packet+=chr(wordcount)


    data=""
    bufferformat=4 #ascii
    data+=chr(bufferformat) 
    data+=msunistring(directory) #+"\x00"
    
    packet+=halfword2istr(len(data)) #bytecount
    packet+=data
    #print "Checkdir 1 packet length=%d %s"%(len(packet),prettyprint(packet))
    packet=smb(packet,CHECK_DIR,tid,pid,uid)
    #print "Checkdir 2 packet length=%d %s"%(len(packet),prettyprint(packet))
    packet=netbios(packet)
    #print "Checkdir 3 packet length=%d %s"%(len(packet),prettyprint(packet))
    s.sendall(packet)
    data=recvnetbios(s)
    if data=="":
        errstr="No response received during check directory"
        success=0
        return success,errstr
    #now parse it
    data,ret=parsesmb(data)
    if ret["ntstatus"]==0xc00000ccL:
        errstr="STATUS_BAD_NETWORK_NAME"
        return 0,errstr
    if ret["ntstatus"]==0xc0000022L:
        errstr="STATUS_ACCESS_DENIED"
        return 0,errstr
    if ret["ntstatus"]==0xc0000034L:
        errstr="Name not found"
        return 0, errstr 
    if ret["ntstatus"]==0:
        errstr=""
        success=1
        return success,errstr
    else:
        #unknown error
        errstr="Server returned error: %x"%ret["ntstatus"]
        return 0, errstr

def smb_trans(param,subcommand,tid,pid,uid,fid,data,maxparam=10,maxdata=16644):
    """
    Does a Trans request
    """
    packet=""
    TRANS2="0x25"
    padlen=62%4
    if padlen==4: padlen=0
    #padding="\x00\x44\x20\x00\x44\x20\x00\x44"[:padlen]
    padding=("\x00"*9)[:padlen]
    devlog("msrpc", "Padlen=%d"%padlen)

    packet+=binstring("10") #word count
    packet+=halfword2istr(len(param)) #total param count
    packet+=halfword2istr(len(data)) #total data count
    packet+=halfword2istr(maxparam) #max param count
    packet+=halfword2istr(maxdata) #max data count
    packet+=chr(0) #max setup count
    packet+=chr(0) #reserved
    packet+=binstring("0000") #flags
    packet+=binstring("00000000") #timeout (return immediately)
    packet+=binstring("0000") #reserverd
    packet+=halfword2istr(len(param)) #param count
    setup_len=4
    name=("\\PIPE\\"+"\x00")
    #name="\x00"+msunistring("\\PIPE\\")[:-2]
    name_len=len(name)
    param_offset=63+name_len+setup_len
    #print "param_offset=%d"%param_offset
    #param_offset=0xffff
    data_offset=param_offset+len(param)
    #test this:
    #data_offset=param_offset+len(param)+padlen
    
    packet+=halfword2istr(param_offset) #param offset
    packet+=halfword2istr(len(data)) #data count (no extra data on the end)
    packet+=halfword2istr(data_offset) #data offset
    packet+=chr(2) #setup count
    packet+=chr(0) #reserved
    packet+=subcommand 

    bytecount=len(data)+padlen
    packet+=fid
    packet+=halfword2istr(bytecount) #bytecount here for some dumb reason
    packet+=name #name

    #packet+=padding
    packet+=param+data
    #padding2="\x00"*(len(packet)%8)
    #packet+=padding2
    return smb(packet,TRANS2,tid,pid,uid,unicode=0)


def smb_trans2(param,subcommand,tid,pid,uid,data,maxparam=10,maxdata=16644):
    """
    Does a Trans2 request
    
    The padding values in this function are very weird
    I'm not sure what's going on here exactly.
    
    """
    packet=""
    TRANS2="0x32"
    padlen=67%4
    if padlen==4: padlen=0
    #padding="\x00\x44\x20\x00\x44\x20\x00\x44"[:padlen]
    padding=("\x00"*9)[:padlen]
    #print "Padlen=%d"%padlen

    packet+=binstring("0f") #word count
    packet+=halfword2istr(len(param)) #param count
    packet+=binstring("0000") #total data count #WHY IS THIS ZERO!?
    packet+=halfword2istr(maxparam) #max param count
    packet+=halfword2istr(maxdata) #max data count
    packet+=chr(0) #max setup count
    packet+=chr(0) #reserved
    packet+=binstring("0000") #flags
    packet+=binstring("00000000") #timeout (return immediately)
    packet+=binstring("0000") #reserverd
    packet+=halfword2istr(len(param)) #param count
    param_offset=66+len(subcommand) #MUST BE MOD %4
    #print "param_offset=%d"%param_offset
    #param_offset=0xffff
    data_offset=param_offset+len(param)
    #test this:
    #data_offset=param_offset+len(param)+padlen
    
    packet+=halfword2istr(param_offset) #param offset
    packet+=halfword2istr(len(data)) #data count (no extra data on the end)
    packet+=halfword2istr(data_offset) #data offset
    packet+=chr(1) #setup count
    packet+=chr(0) #reserved
    packet+=subcommand #find first 2 subcommand
    bytecount=len(param)+padlen
    packet+=halfword2istr(bytecount)
    packet+=padding
    packet+=param+data
    padding2="\x00"*(len(packet)%8)
    packet+=padding2
    return smb(packet,TRANS2,tid,pid,uid)

def parsesmb(data):
    if data == "" or len(data) < 4:
        print "Weird SMB data len .. returning"
        return "",{}
    if data[:4]!="\xffSMB":
        print "Not SMB packet!"
    ret={}
    #print "Parsing SMB"
    ret["command"]=data[4]
    ret["ntstatus"]=istr2int(data[5:9])
    devlog("parsesmb","ntstatus=%x"%ret["ntstatus"])
    #print "data=%s"%prettyhexprint(data[5:9])
    error=0
    if ret["ntstatus"]==0x80000005L:
        ret["ntstatusstr"]="Buffer Overflow"
    elif ret["ntstatus"]==0xc00000ccL:
        ret["ntstatusstr"]="STATUS_BAD_NETWORK_NAME"
        error=1
    ret["flags"]=data[9]
    ret["flags2"]=data[10:12]
    ret["pid_hi"]=data[12:14]
    ret["signature"]=data[14:22]
    ret["reserved"]=data[22:24]
    ret["tid"]=data[24:26]
    ret["pid"]=data[26:28]
    ret["uid"]=data[28:30]
    ret["mid"]=data[30:32]
    
    
    #print "parsesmb Ret=%s"%ret
    devlog('parsesmb', ret)
    #is there sometimes padding here?!?!?
    return data[32:],ret

def recvnetbios(s):
    """recvs netbios data...on timeout returns "" """
    try:
        data=reliablerecv(s,4)
    except timeoutsocket.Timeout:
        return ""
    except:
        #socket died
        return ""
    
    if len(data)<4:
        #odd condition where we recv a null packet
        return ""
    length=nstr2halfword(data[2:])
    try:
        data=reliablerecv(s,length)
    except timeoutsocket.Timeout:
        return ""
    return data

def recvnetbios_server(s):
    data=reliablerecv(s,4)
    length=nstr2halfword(data[2:])
    data2=reliablerecv(s,length)
    return data+data2

def parsetrans2(data):
    ret={}
    ret["word count"]=ord(data[0])
    ret["total param count"]=istr2halfword(data[1:3])
    ret["total data count"]=istr2halfword(data[3:5])
    ret["reserved"]=data[5:7]
    ret["param count"]=istr2halfword(data[7:9])
    ret["param offset"]=istr2halfword(data[9:11])
    ret["param displacement"]=istr2halfword(data[11:13])
    ret["data count"]=istr2halfword(data[13:15])
    ret["data offset"]=istr2halfword(data[15:17])
    ret["data displacement"]=istr2halfword(data[17:19])
    ret["setup count"]=ord(data[19])
    ret["reserved2"]=data[20]
    ret["Byte Count"]=istr2halfword(data[20:22])
    #ret["padding"]=data[22] #is this always here?
    paramoffset=ret["param offset"]-32
    params=data[paramoffset:paramoffset+ret["param count"]]
    dataoffset=ret["data offset"]-32
    payload=data[dataoffset:dataoffset+ret["data count"]]
    devlog("msrpc","ret=%s"%ret)
    #print "payload=%s"%hexprint(payload)
    ret["params"]=params
    ret["payload"]=payload
    return ret

attributes_dict={}
attributes_dict[0x1]="R" #readonly
attributes_dict[0x2]="H" #hidden
attributes_dict[0x4]="S" #system
attributes_dict[0x8]="V" #volume 
attributes_dict[0x10]="D" #directory
attributes_dict[0x20]="A" #archve
attributes_dict[0x40]="O" #DEVICE
attributes_dict[0x80]="N" #Normal
attributes_dict[0x100]="T" #Temporary
attributes_dict[0x200]="s" #Sparse
attributes_dict[0x400]="r" #reparse point
attributes_dict[0x800]="c" #compressed
attributes_dict[0x1000]="O" #offline
attributes_dict[0x2000]="I" #not indexable (0 for indexible)
attributes_dict[0x4000]="E" #Encrypted
def readfileitem(data):
    """reads the file item structure right out of the data"""
    ret={}
    nextentryoffset=istr2int(data[0:4])
    dataleft=data[nextentryoffset:]
    if nextentryoffset==0:
        dataleft=""
    ret["file index"]=istr2int(data[4:8])
    ret["Created"]=data[8:16]
    ret["Last Access"]=data[16:24]
    ret["Last Write"]=data[24:32]
    ret["Last Change"]=data[32:40]
    ret["End Of File"]=istr2double(data[40:48])
    ret["Allocation Size"]=istr2double(data[48:56])
    ret["File Attributes"]=istr2int(data[56:60])
    ret["Attributes"]=""
   
    
    for a in attributes_dict.keys():
        if a & ret["File Attributes"]:
            ret["Attributes"]+=attributes_dict[a]
            
    filenamelength=istr2int(data[60:64])
    ealistlength=istr2int(data[64:68])
    shortfilenamelength=ord(data[68])
    reserved=ord(data[69])
    ret["Short Filename"],index=read_unicode_string(data[70:]) #always 24 bytes
    ret["Filename"],index=read_unicode_string(data[94:94+filenamelength])
    return ret,dataleft
    
def parsefindfirst2(params,data):
    ret={}
    #which of these are params - all of them...
    ret["Search ID"]=istr2halfword(params[0:2])
    ret["Search Count"]=istr2halfword(params[2:4])
    ret["End of Search"]=istr2halfword(params[4:6])
    ret["EA Error Offset"]=istr2halfword(params[6:8])
    ret["Last Name Offset"]=istr2halfword(params[8:10])
    #ret["Padding"]=istr2halfword(data[10:12])
    ret["items"]=[]
    dataleft=data
    while dataleft!="":
        item,dataleft=readfileitem(dataleft)
        #print "Item=%s"%item
        ret["items"].append(item)
        
    return ret

def smb_findfirst2(s,tid,pid,uid,directory):
    packet=""
    subcommand=halfword2istr(0x1) #find_first2
    data=""
    #FIND_FIRST2 Params
    data+="\x16\x00" #search attributes: include all files.
    data+=halfword2istr(512) #search count
    data+=halfword2istr(0x0006) #flags
    data+=binstring("0401") #interest
    data+=binstring("00000000") #storage type
    #data+="\x00"
    if directory in [".","",None]:
        directory="*"
    data+=msunistring(directory) #search pattern
    packet=data #add byte count to front
    data="" #no extra data
    packet=smb_trans2(packet,subcommand,tid,pid,uid,data)
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if "ntstatus" not in ret or ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        if "ntstatus" in ret:
            results=ret["ntstatus"]
        else:
            results=None
        return success,results
    ret=parsetrans2(smbdata)
    #print "Trans2 ret:%s"%ret
    findfirst2data=parsefindfirst2(ret["params"],ret["payload"])
    #print "Findfirst2data: %s"%findfirst2data
    results=findfirst2data
    success=1
    #print "trans2data=%s"%prettyprint(trans2data)
    return success,results


def smb_mkdir(s,tid,pid,uid,directory):
    """Creates a directory"""
    #print "smb_mkdir: %s"%directory
    packet=""
    subcommand="0x00" #Create Directory
    data=""
    data2=""
    #Params
    bufferformat=4 #ascii ? (really unicode?)
    data2+=chr(bufferformat)
    data2+=msunistring(directory) #create this directory
    #do we need to add padding to data2?
    
    wordcount=0
    data+=chr(wordcount)
    bytecount=len(data2)
    data+=halfword2istr(bytecount) 
    data+=data2

    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    results="Directory created"
    success=1
    return success,results

def smb_delete(s,tid,pid,uid,filename):
    """deletes a file"""
    #print "smb_delete: %s"%filename
    packet=""
    subcommand="0x06" #Delete file
    data=""
    data2=""
    #Params
    bufferformat=4 #ascii ? (really unicode?)
    data2+=chr(bufferformat)
    data2+=msunistring(filename) 
    #do we need to add padding to data2?
    
    wordcount=1
    data+=chr(wordcount)
    searchattrib=0x7
    data+=halfword2istr(searchattrib)
    bytecount=len(data2)
    data+=halfword2istr(bytecount) 
    data+=data2

    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    results="Directory created"
    success=1
    return success,results

def smb_deletedir(s,tid,pid,uid,filename):
    """deletes a file"""
    #print "smb_delete: %s"%filename
    packet=""
    subcommand="0x01" #Delete directory
    data=""
    data2=""
    #Params
    bufferformat=4 #ascii ? (really unicode?)
    data2+=chr(bufferformat)
    data2+=msunistring(filename) 
    #do we need to add padding to data2?
    
    wordcount=0
    data+=chr(wordcount)
    bytecount=len(data2)
    data+=halfword2istr(bytecount) 
    data+=data2

    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    results="Directory created"
    success=1
    
    return success,results
SMB_ACCESS_READ=0x00
SMB_ACCESS_WRITE=0x01
SMB_ACCESS_READWRITE=0x02
SMB_ACCESS_EXECUTE=0x03
SMB_SHARE_DENY_NONE=0x40
SMB_SHARE_COMPAT=0x00
SMB_OPENFUNCTION_TRUNCATE=0x02
SMB_OPENFUNCTION_CREATE=0x10

def parsesmbopenx(data):
    ret={}
    #not sure if ethereal gets this right
    ret["Word Count"]=ord(data[0])
    ret["AndXCommand"]=ord(data[1])
    ret["AndXOffset"]=istr2halfword(data[3:5])
    #reserved byte?
    ret["FID"]=data[5:7]
    #print "fid=%s"%hexprint(data[5:7])
    #... lots of other crap
    return ret
    
def smb_open_andx(s,tid,pid,uid,filename,access=SMB_ACCESS_READ,share=SMB_SHARE_COMPAT,openfunction=None):
    #print "smb_mkdir: %s"%directory
    packet=""
    subcommand="0x2d" #Open AndX
    data=""
    data2=""
    #Params
    data2+=chr(0) #padding
    data2+=msunistring(filename) #create this directory
    #do we need to add padding to data2?
    
    wordcount=15
    data+=chr(wordcount)
    data+=chr(0xff) #andX command: No further commands
    data+=chr(0x00) #reserved
    data+=halfword2istr(0) #andX offset 
    data+=halfword2istr(0) #flags
    desiredaccess=access|share
    data+=halfword2istr(desiredaccess) #desired access
    if access==SMB_ACCESS_READ:
        searchattributes=0x007 #gah, do this later
    else:
        searchattributes=0x6 #no readonly
        
    data+=halfword2istr(searchattributes) 
    data+=halfword2istr(0) #file attributes, do later
    data+=intel_order(0) #time, do later
    if openfunction==None:
        if access==SMB_ACCESS_READ:
            openfunction=1 #open file if it exists
        elif access==SMB_ACCESS_READWRITE:
            openfunction=0x0011 #open file if it exists, and create file otherwise
        elif access==SMB_ACCESS_WRITE:
            openfunction=0x0010
        else:
            openfunction=0
            print "No idea what you meant by %d in open_x"%access

    
            
        
    data+=halfword2istr(openfunction)
    data+=intel_order(0) #allocate size (?!?)
    data+="\x00"*8 #reserved

    bytecount=len(data2)
    data+=halfword2istr(bytecount) 
    #data+="\x00" #padding?? (added to data2)
    # cp1252 is windows default filesystem encoding
    data2 = data2.encode('cp1252')
    data+=data2

    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    ret=parsesmbopenx(smbdata)
    success=1
    return success,ret
    
def parse_qfi(data):
    ret={}
    #param
    #ret["EA Error Offset"]=istr2halfword(data[:2])
    #padding eats 2 bytes - we really need to split params and data better!
    ret["Created"]=data[0:8]
    #print "Created: %s"%smb_nt_64bit_time(ret["Created"])
    ret["Last Access"]=data[8:16]
    ret["Last Write"]=data[16:24]
    ret["Change"]=data[24:32]
    #print "Change: %s"%smb_nt_64bit_time(ret["Change"])
    ret["File Attributes"]=istr2int(data[32:36])
    ret["Attributes"]=""
    for a in attributes_dict.keys():
        if a & ret["File Attributes"]:
            ret["Attributes"]+=attributes_dict[a]
    #print "ret=%s"%ret
    #print "Rest of data: %s"%hexprint(data[36:])
    #4 bytes of 0's (not understood)
    ret["Allocation Size"]=istr2int(data[40:44])
    #4 bytes of 0's (not understood)
    ret["End Of File"]=istr2int(data[48:52])
    #print "End of file=%d"%ret["End Of File"]
    return ret

def smb_query_file_info(s,tid,pid,uid,fid):
    packet=""
    subcommand=halfword2istr(0x7) #QUERY_FILE_INFO
    data=""
    # Params
    data+=fid #search attributes: include all files.
    data+=halfword2istr(0x0107) #Query all information
    params=data
    data=""
    packet=smb_trans2(params,subcommand,tid,pid,uid,data)
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    ret=parsetrans2(smbdata)
    #print "Trans2 ret:%s"%ret
    qfi=parse_qfi(ret["payload"])
    #print "Findfirst2data: %s"%findfirst2data
    results=qfi
    success=1
    #print "trans2data=%s"%prettyprint(trans2data)
    return success,results    

def smb_close(s,tid,pid,uid,fid):
    """Closes a fid"""
    #print "smb_mkdir: %s"%directory
    packet=""
    subcommand="0x04" #Close
    data=""
    data2=""

    wordcount=3
    data+=chr(wordcount)
    data+=fid
    lastwrite=-1 #never
    data+=intel_order(lastwrite)
    data+=halfword2istr(0) #Byte count

    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    if ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        results=ret["ntstatus"]
        return success,results
    results="File Closed"
    success=1
    return success,results


####################################################################
#DCE STUFF

def parse_dce(data):
    """Parse a dce response"""
    """DONT USE THIS - USE THE OBJECT NICO WROTE"""
    ret={}
    ret["Version Major"]=ord(data[0])
    ret["Version Minor"]=ord(data[1])
    ret["packet_type"]=ord(data[2])
    ret["flags"]=ord(data[3])
    ret["data representation"]=istr2int(data[4:8])
    ret["frag length"]=istr2halfword(data[8:10])

    
def smbfromdcefrag(tid,uid,fid,fragpdu,fraglength):
    """
    Creates the SMB header for a DCE PDU
    """
    
    packet=""
    packet+=s_binary("ff 53  4d 42 25 00 00 00 00 08  01 c0 00 00 00 00 00 00  00 00 00 00 00 00  ");
    packet+=tid
    packet+=s_binary("8d 2b ");
    packet+=uid
    packet+=s_binary("01 00");
    packet+=s_binary(" 10 00  00 ");
    packet+=halfword2istr(fraglength)
    packet+=s_binary("00 00");
    packet+=halfword2istr(fraglength)
    packet+=s_binary("00 00 00 00 00 00 00 00 00  00 00 00 52 00 ");
    packet+=halfword2istr(fraglength)    
    packet+=s_binary("52 00 02 00");
    #/*SMB PIPE PROTOCOL*/
    packet+=s_binary("26 00"); #/*transact pipe*/
    packet+=fid
    pipestr=msunistring("\\PIPE\\")
    bytecount=len(fragpdu)+1+len(pipestr)
    packet+=halfword2istr(bytecount)
    packet+="\x00"
    packet+=pipestr
    packet+=fragpdu
    #add netbios header to the front of it
    packet=netbios(packet)
    return packet

def smb_sendbind(s,bigfrag,tid,uid,fid,covertness,unicode=0):
    #print "after dcebind"
    if covertness==1:
        maxlength=len(bigfrag)
    else:
        maxlength=5
    devlog("msrpc","maxlength=%d"%maxlength)
    left=len(bigfrag)
    sent=0
    first=1
    data=""
    while left > 0:
        if covertness==1:
            size=maxlength
        else:
            size=random.randint(2,maxlength)
        #print "sending %d bytes of %d left at offset %d"%(size,left,sent)
        frag=bigfrag[sent:sent+size]
        data=smb_writex_fromdcefrag(first,tid,uid,fid,frag,sent,left,unicode=unicode)
        #data=smbfromdcefrag(tid,uid,fid,frag,len(frag))
        s.sendall(data)
        left=left-size
        sent+=size
        first=0
        #writex response
        data=s.recv(2000) #6-10 should be 00000000 for success b00000c0 for pipe disconnected
    return data

def smbdcebind(s,tid,uid,fid,uuid,versionmajor,versionminor,callid,auth=None,covertness=1):
    """returns 1,errstring on error. 0,"" on success
    Also can throw a DCEException, errormessage on random errors it encounters.
    """
    #print "smbdcebind"
    devlog('smbdcebind', "auth: %s, tid:%s, uid:%s, fid:%s, uuid:%s" % (prettyprint(auth), prettyprint(tid), prettyprint(uid), prettyprint(fid), prettyprint(uuid)))
    unicode=1
    if auth:
        unicode=auth.isunicode
    devlog('smbdcebind', "createdcebind: %s" % createdcebind)
    bigfrag=createdcebind(uuid,versionmajor,versionminor,callid,auth=auth,unicode=unicode)
    devlog('smbdcebind', "bigfrag: %s, smb_sendbind: %s" % (prettyhexprint(bigfrag), smb_sendbind))
    smb_sendbind(s,bigfrag,tid,uid,fid,covertness,unicode=unicode)
    devlog('smbdcebind', "smb_sendbind: %s" % smb_sendbind)
    if auth:
        error,data=smb_readx(s,fid,uid,tid)
        if error:
            errstr="Error in smb_readx during bind"
            error=1
            return error,errstr
        bindAck=DCEBind_ack(auth)
        bindAck.hdrget(data)
        bindAck.get(data[bindAck.hdrsize():])
        if bindAck.ackresult==2: # failed
            raise DCEException, "DCE %s failed: Provider rejection" % keyword
        domainlist=bindAck.auth.list
        auth3=DCEAuth3(auth)
        auth3.set_auth(auth.username, auth.password)
        devlog("msrpc", "Sending auth3 packet")
        bigfrag=auth3.raw()
        smb_sendbind(s,bigfrag,tid,uid,fid,covertness)
    else:
        #data=s.recv(1500)
        error,data=smb_readx(s,fid,uid,tid)
        if error:
            devlog('smbdcebind', "Error in smb_readx during bind: %s" % error)
            errstr="Error in smb_readx during bind"
            error=1
            return error,errstr
            
        #print "Len of data is %d"%len(data)
        if data=="" or len(data)<68:
            devlog('smbdcebind', "No response received during smbdcebind connection! (len data=%d)" % len(data))
            errstr="No response received during smbdcebind connection! (len data=%d)"%len(data)
            error=1 #badness
            return error,errstr
        #print "len(data)=%d"%(len(data))
        #if data[104:106]!=binstring("0000"):
        #        return 1,"Error - most likely provider reject (0x0200): 0x%2.2x%2.2x"%(ord(data[104]),ord(data[105]))
        bindAck=DCEBind_ack()
        devlog('smbdcebind', "bindAck: %s" % bindAck)
        try:
            buf=data
            devlog('smbdcebind', "buf: \n%s" % shellcode_dump(buf))
            devlog('smbdcebind', "bindAck.hdrget: %s" % bindAck.hdrget)
            bindAck.hdrget(buf)
            devlog('smbdcebind', "bindAck.get: %s, bindAck.hdrsize: %s" % (bindAck.get, bindAck.hdrsize))
            devlog('smbdcebind', "bindAck.hdrsize= %s" % bindAck.hdrsize())
            #buf+=s.recv(bindAck.size()-bindAck.hdrsize())
            bindAck.get(buf[bindAck.hdrsize():])
            devlog('smbdcebind', "BindAck.ackresult: %d (0 for success)" % bindAck.ackresult)
            devlog("msrpc", "BindAck.ackresult=%d (0 for success)"%bindAck.ackresult)
            if bindAck.ackresult==0x200: # failed
                devlog("msrpc", "Provider rejection")
                raise DCEException, "DCE ncacn_ip_np failed: Provider rejection"
        except socket.error, msg:
            raise DCEException, "DCE ncacn_ip_np %s: %s" % ("Receiving ack failed",str(msg)) 
        except struct.error, msg:
            raise DCEException, "DCE ncacn_ip_np %s: %s" % ("Receiving ack failed",str(msg)) 
        except timeoutsocket.Timeout, msg:
            raise DCEException, "DCE ncacn_ip_np %s: %s" % ("Receiving ack failed",str(msg)) 
                    
    devlog('smbdcebind', "returning 0 (success)")
    return 0,""

MAXDCECALLFRAGLENGTH=4000
def create_dce_call(first,opnum,buffer,callid):
    lastfrag=0x02
    firstfrag=0x01
    #24 is for header length

    last=0
    if len(buffer) < MAXDCECALLFRAGLENGTH:
            last=1
            fraglength=len(buffer)
    else:
            fraglength=MAXDCECALLFRAGLENGTH

    data=""
    data+=binstring("05 00 00")
    flags=0x00
    if first:
            flags|=firstfrag
    if last:
            flags|=lastfrag
                    
    data+=chr(flags)
    data+=binstring("10 00  00 00")
    
    data+=halfword2istr(fraglength+24)
    #auth length
    data+=binstring("0000")
    data+=intel_order(callid)
    data+=intel_order(fraglength+24)
    data+=binstring("0000")
    data+=halfword2istr(opnum)
    newdata=buffer[:MAXDCECALLFRAGLENGTH]
    data+=newdata
    newoffset=len(newdata)
    
    return data,newoffset


WRITEMODE_DEFAULT=0x0
WRITEMODE_MESSAGESTART=0x8
WRITEMODE_RAW=0x04
WRITEMODE_RETURNREMAINING=0x02
WRITEMODE_WRITETHROUGH=0x01
def smb_writex(s,fid,uid,tid,pid,datatowrite,offset,writemode=WRITEMODE_DEFAULT):
    #print "smb_mkdir: %s"%directory
    packet=""
    subcommand="0x2f" #WriteX
    data=""
    data2=""

    wordcount=14
    data+=chr(wordcount)
    #write andx request start
    data+="\xff" #no further commands
    data+="\x00" #reserved
    data+=s_binary("de de ") #andx offset (blah)
    data+=fid
    data+=intel_order(offset)
    data+=intel_order(0xffffffff) #reserved
    #if offset==0:
    #    writemode|=WRITEMODE_MESSAGESTART
    data+=halfword2istr(writemode)
    bytecount=len(datatowrite)
    data+=halfword2istr(0) #remaining
    data_hi=len(datatowrite)/(1024*64)
    data_lo=len(datatowrite)%(1024*64)
    data+=halfword2istr(data_hi)
    data+=halfword2istr(data_lo)
    dataoffset=64 #static?
    data+=halfword2istr(dataoffset)
    data+=intel_order(0)
    data+=halfword2istr(bytecount+1)
    data+='\xee'
    data+=datatowrite
    devlog("msrpc","Writing %d bytes via writex"%len(datatowrite))
    
    packet=data #add byte count to front
    data="" #no extra data
    packet=smb(packet,subcommand,tid,pid,uid)  
    packet=netbios(packet)
    s.sendall(packet)
    
    smbpacket=recvnetbios(s)
    smbdata,ret=parsesmb(smbpacket)
    #Check to see if it was a successful attempt, return if not
    
    if "ntstatus" not in ret or ret["ntstatus"]!=STATUS_SUCCESS:
        success=0
        if "ntstatus" in ret:
            results=ret["ntstatus"]
        else:
            results=-1
        return success,results
    results="File Closed"
    success=1
    return success,results
    
def smb_writex_fromdcefrag(first,tid,uid,fid,frag,sent,remaining,unicode=0):
    #print "First: %s"%first
    packet=""
    packet+=s_binary("ff")+"SMB" 
    #SMB COMMAND WriteANDX
    packet+="\x2f"
    packet+=intel_order(0) #status
    packet+="\x18" #flags
    flags2=0x4807
    if unicode:
        flags2|=0x8000 #unicode flag. haters.
    packet+=halfword2istr(flags2) #"\x07\x48" #flags2
    packet+="\x00\x00" #process ID high
    packet+=s_binary("40 6d 4e f4 8c 6e 13 7b") #signature
    packet+=s_binary("00 00"); #reserved
    packet+=tid
    packet+=s_binary("8d 2b "); #process ID
    packet+=uid
    packet+=s_binary("01 00"); #multiplex ID
    
    #write andx request start
    packet+=s_binary("0e") #word count
    packet+="\xff" #no further commands
    packet+="\x00"
    packet+=s_binary("de de ") #andx offset 
    packet+=fid
    packet+=intel_order(sent) #offset
    packet+=s_binary("ff ff ff ff"); #reserved
    if first:
            packet+=s_binary("08 00");
    else:
            packet+=s_binary("00 00 ");

    
    packet+=halfword2istr(remaining) #remaining
    
    packet+=s_binary("00 00 "); #data length high (mult by 64K)
    packet+=halfword2istr(len(frag)) #data length low
    
    #/*data offset*/
    packet+=s_binary("40 00 00 00 00 00 ");
    packet+=halfword2istr(len(frag)+1)
    
    #/*padding*/
    packet+=s_binary("ee")
    packet+=frag
    #netbios header
    packet=netbios(packet)
    return packet


            

def smb_transact_fromdcefrag(first,tid,uid,fid,frag,fraglen):
    "Currently not working for some reason - the data is not being seen by ethereal!"
    packet=""
    packet+=s_binary("ff 53 4d 42")
    packet+=s_binary("25") #transaction
    packet+=s_binary("00 00 00 00") #status
    packet+=s_binary("18"); #flags
    packet+=s_binary("07 c8") #flags2
    packet+=s_binary("00 00") #processid (high)
    packet+=s_binary("40 6d 4e f4 8c 6e 13 7b") #signature
    packet+=s_binary("00 00"); #reserved
    packet+=tid
    packet+=s_binary("8d 2b "); #process ID?!?
    packet+=uid
    packet+=s_binary("01 00"); #multiplex ID
    #transaction request start
    packet+=s_binary("10") #word count WCT
    packet+=s_binary("0000") #Total Param count
    packet+=halfword2istr(fraglen) #Total Data Count
    packet+=s_binary("0000") #max param count
    packet+=halfword2istr(1024) #Max Data Count !!!!
    packet+=s_binary("00") #max setup count
    packet+=s_binary("00") #reserved
    packet+=s_binary("0000") #flags
    packet+=s_binary("00000000") #timeout, return immediately is 0
    packet+=s_binary("0000") #reserved
    packet+=s_binary("0000") #parameter count
    packet+=halfword2istr(84) #parameter offset - should we calc this?
    packet+=halfword2istr(fraglen) #data count
    packet+=halfword2istr(84) #data offset
    packet+=s_binary("02") #setup count
    packet+=s_binary("00") #reserved
    #START SMB PIPE PROTOCOL
    packet+=halfword2istr(0x26) #TransactNmPipe
    packet+=fid
    #Back to SMB...
    packet+=halfword2istr(fraglen-17) #data count ????? Where is the -17 coming from?
    packet+=s_binary("00") #some sort of unrecognized padding
    packet+=uni_from_ascii("\\PIPE\\") #automatically padded out 2 bytes
    
    #add our actual data
    packet+=frag
    
    #prepend netbios header
    packet=netbios(packet)
    return packet
            
def smb_dce_call(s,opnum,buffer,fid,uid,tid,callid):
        """
        Makes a DCE RPC call
        """
        first=1
        offset=0
        length=len(buffer)
        while offset!=length:
            frag,newoffset=create_dce_call(first,opnum,buffer[offset:offset+MAXDCECALLFRAGLENGTH],callid)
            data=smb_writex_fromdcefrag(first,tid,uid,fid,frag,0,0)
            offset+=newoffset
            first=0
            s.sendall(data)
            data=s.recv(1500)
            if data=="":
                    errstr="No response received during smb dce call connection!"
                    error=1
                    return error,errstr
            
            
        return 0,""
                
def parsereadandx(data):
    ret={}
    ret["Word Count"]=ord(data[0])
    ret["AndXCommand"]=ord(data[1])
    #reserved
    ret["AndXOffset"]=istr2halfword(data[3:5])
    ret["Remaining"]=istr2halfword(data[5:7])
    ret["Data Compaction Mode"]=istr2halfword(data[7:9])
    ret["Data Length Low"]=istr2halfword(data[11:13])
    ret["Data Offset"]=istr2halfword(data[13:15])
    ret["Data Length High"]=istr2int(data[15:19])
    #print "Data so far: %s"%ret
    payloadoffset=ret["Data Offset"]-32
    payload=data[payloadoffset:payloadoffset+ret["Data Length Low"]+ret["Data Length High"]*1024*64]
    ret["data"]=payload
    #andxoffset 
    return ret

def smb_readx(s,fid,uid, tid,maxcount=1024):
    #print "maxcount=%d"%maxcount
    packet=""
    packet+=s_binary("ff")+"SMB" 
    #SMB COMMAND ReadANDX
    packet+="\x2e"
    packet+=intel_order(0) #status
    packet+="\x18" #flags
    packet+="\x07\xc8" #flags2
    packet+="\x00\x00" #process ID high
    packet+=s_binary("40 6d 4e f4 8c 6e 13 7b") #signature
    packet+=s_binary("00 00"); #reserved
    packet+=tid
    packet+=s_binary("8d 2b "); #process ID
    packet+=uid
    packet+=s_binary("01 00"); #multiplex ID
    
    #ReadX request
    packet+="\x0c" #word count
    packet+="\xff\x00" #no further commands/reserved
    packet+="\x00\x00" #andX offset
    
    packet+=fid
    packet+=intel_order(0) #offset
    maxcountlow=maxcount
    mincount=20
    remaining=20
    highoffset=0
    bytecount=0
    packet+=halfword2istr(maxcountlow)
    packet+=halfword2istr(mincount)
    packet+=intel_order(0) #maxcount high
    packet+=halfword2istr(remaining)
    packet+=intel_order(highoffset)
    packet+=halfword2istr(bytecount)
    packet=netbios(packet)
    s.sendall(packet)
    #read result now
    try:
        smbpacket=recvnetbios(s)
    except timeoutsocket.Timeout:
        raise DCEException, "Timeout"
    
    devlog('smb_readx', "%d bytes\n%s" % (len(smbpacket), shellcode_dump(smbpacket)))
    smbdata,ret=parsesmb(smbpacket)

    #Check to see if it was a successful attempt, return if not
    if ret=={} or (uint32(ret["ntstatus"]) not in [STATUS_SUCCESS,STATUS_BUFFER_OVERFLOW]):
        errorcode=ret.get("ntstatus",-1)
        devlog("msrpc", "SMB Error in Read_AndX (%x)"%errorcode)
        error=1
        return error,errorcode
    #print "smb ret=%s"%ret
    result=parsereadandx(smbdata)
    data=result["data"]
    return 0,data
    
        
def s_dce_wordstring(mystr,nullterm=0):
    """
    turn mystr into a dce string (not null terminated)
    """
    data=""  
    #null terminate if necessary
    if nullterm and mystr[-1]!="\x00":
        mystr+="\x00"
        
    size=len(mystr)
    data+=intel_order(size)
    data+=intel_order(0)
    data+=intel_order(size)
    data+=mystr
    #data+="\x00"
    padding=4-len(data)%4
    if padding==4:
        padding=0
        
    data+="\x00"*(padding)

    return data
        
def s_fakedcepointer():
    data=""
    data+=s_binary("01000000");
    data+=s_binary("08000000");
    data+=s_binary("00000000");
    data+=s_binary("08000000");
    data+=s_binary("ABCDABCD");
    #pointers -  does it matter what these are?
    #yes, must be valid "pointers"
    data+=s_binary("ff000000");
    data+=s_binary("fe000000");
    data+=s_binary("fd000000");
    return data

def s_dce_raw_unistring(mystr):
    """
    mystr is already unicoded for us but we null terminate it
    """
    data=""  
    if len(mystr)%2!=0:
        print "Warning, your raw unicode string is not aligned!"
    size=len(mystr)/2+1
    data+=intel_order(size)
    data+=intel_order(0)
    data+=intel_order(size)
    data+=mystr+"\x00\x00"
    padding=4-len(data)%4
    if padding!=4:
        data+="\x00"*(padding)

    return data

def uni_from_ascii(mystr):

    
    ret=""
    for c in mystr: 
        ret+=c+"\x00"
    ret+="\x00\x00"
    padding=4-len(ret)%4
    if padding!=4:
        ret+="\x00"*(padding)
    return ret

def s_dce_unistring(mystr,badstring=None):
    """does a windows specific unicode transcoding

    Also does padding and null termination
    """
    ret=""
    #for c in mystr:
    #    ret+=c+"\x00"
    ret=dunicode.win32ucs2(mystr,badstring=badstring)
    return s_dce_raw_unistring(ret)

def s_dce_win2k_unistring(mystr):
    ret=""
    for c in mystr:
        ret+=c+"\x00"
    #ret=dunicode.win32ucs2(mystr,badstring=badstring)
    return s_dce_raw_unistring(ret)

def read_dce_pdu(s):
    """
    Reads a single pdu and returns the header and the body
    """
    buf=reliablerecv(s,16)
    if ((ord(buf[4]) & 0xf0) == 0x10):
        little_endian = 1
        frag_length=istr2halfword(buf[8:10])
    else: 
        little_endian = 0
        frag_length=nstr2halfword(buf[8:10])
    #print "PDU Length=%d"%frag_length
    
    buf2=reliablerecv(s,frag_length-16)
    if len(buf2)+16!=frag_length:
        print "Warning, pdu length not correct! %d != %d"%(len(buf2),frag_length)
                    
    return buf,buf2


############EPMAPPER routines
#TODO:
# Add a smartbuffer class that can do a load_long where load_long is intel_ordered
# when a variable is set and network byte order otherwise
# then use this to fix everything to handle hpux, if we ever want to.


class entryhandle:
    def __init__(self):
        self.order="intel"
        self.context="\x00"*16
        self.attributes=0
        self.tcp=None
        self.udp=None
        self.np=None
        self.ncalrpc=None
        self.http=None
        self.netbios=None
        self.ip=None
        self.version=None
                    
    def getinfo(self):
        uuidstr=uuid2uuidstr(self.uuid)
        
        typeinfo=""
        if self.tcp!=None:
            typeinfo+="tcp:%d:"%self.tcp
        if self.udp!=None:
            typeinfo+="udp:%d:"%self.udp
        if self.netbios!=None:
            typeinfo+="netbios:%s:"%self.netbios
        if self.np!=None:
            typeinfo+="namedpipe:%s:"%self.np
        if self.http!=None:
            typeinfo+="http:%s:"%self.http
        if self.ip!=None:
            typeinfo+="ip:%s:"%self.ip
        if self.ncalrpc!=None:
            typeinfo+="ncalrpc:%s:"%self.ncalrpc
                        
        return "%s:%d:%s"%(uuidstr,self.version,typeinfo)


    def getendpoint(self, ip):
        """
        Gets a nicely displayed and compatable endpoint
        ip argument is only used when it is not provided internally, for named pipes.
        """
        typeinfo = ""
        if self.tcp != None:
            return "ncacn_ip_tcp:%s[%d]" % (self.ip, self.tcp)
        elif self.udp != None:
            return "ncacn_ip_udp:%s[%d]" % (self.ip, self.udp)
        elif self.np != None:
            return "ncacn_np:%s[%s]" % (ip, self.np)
        elif self.http != None:
            return "ncacn_http:%s[%d]" % (self.ip, self.http) 
        elif self.ncalrpc != None:
            return "ncalrpc:[%s]" % self.ncalrpc
        else:
            return ""
 
    def __str__(self):
        return self.getendpoint(self.ip)
    
    def isUUID(self, UUID):
        return UUID == uuid2uuidstr(self.uuid)
    
    def isRemote(self):
        return self.isHTTP() or self.isNP() or self.isTCP() or self.isUDP()
    
    def isTCP(self):
        return self.tcp != None

    def isUDP(self):
        return self.udp != None

    def isNP(self):
        return self.np != None

    def isHTTP(self):
        return self.http != None

                                
def dce_enum_get_next(s,entry_handle,callid,covertness):
    """
    using the previous entry_handle, gets the next entry in the uuid table
    TODO: Currently all the intel_orders are assumed, wheras if the header
    was big-endian, these need to load the long in network byte order
    
    This is going to not work against HP-UX until we fix this.
    """
    RPC_C_EP_ALL_ELTS=0
    EPT_LOOKUP=2
    data=intel_order(RPC_C_EP_ALL_ELTS)
    #some unused stuff (object and interface id) and option versions (not used)
    data+=intel_order(0)*3
    data+=intel_order(entry_handle.attributes)
    #we don't covert this since it is already intel-ordered
    data+=(entry_handle.context)
    #maxents
    data+=intel_order(1)
    opnum=EPT_LOOKUP
    msrpcsend(s,data,opnum,callid,covertness=covertness)
    try:
        recvheader,recvdata=read_dce_pdu(s)
    except timeoutsocket.Timeout:
        print "Receive timed out."
        return
    #### DONE READING THE DCE PDU, now parsing the response
    
    
    if recvheader[2]!=RESPONSEPACKET:
        print "Not a response packet - something is wrong."
        return
    #print "Length of recvdata is %d"%len(recvdata)
    #skip some stuff: alloc_hint, p_cont_id, cancel_count, and padding
    recvdata=recvdata[8:]
    e_h=entryhandle()
    e_h.attributes=istr2int(recvdata[:4])
    recvdata=recvdata[4:]
    #we need to fix this so it corrects for intel_order or big_endian someday
    e_h.context=recvdata[:16]
    recvdata=recvdata[16:]    
    num_ents=istr2int(recvdata[:4])
    recvdata=recvdata[4:]
    if num_ents==0:
        return None
    #skip some more
    recvdata=recvdata[36:]    
    
    #load the annotation
    annotation_length=istr2int(recvdata[:4])
    recvdata=recvdata[4:]
    e_h.annotation=recvdata[:annotation_length]
    #here we also correct for mod 4 padding
    #print "Annotation length=%d\n"%annotation_length
    padlength=4-annotation_length%4
    if padlength==4:
        padlength=0
    recvdata=recvdata[annotation_length+(padlength):]
    #here we skip some stuff (tower lengths)?
    recvdata=recvdata[8:]
    #always intel
    #print prettyprint(recvdata)
    floors=istr2halfword(recvdata[:2])
    recvdata=recvdata[2:]
    floor=1
    #print "Floors=%d"%floors
    while floor<=floors:
        #print "floor=%d"%floor
        #this actually is an intel-short, even on hpux
        tint=istr2halfword(recvdata[:2])
        #print "Floor length = %d"%tint
        recvdata=recvdata[2:]
        if floor==1:
            e_h.uuid=recvdata[1:17]
            e_h.version=istr2halfword(recvdata[17:17+2])
        elif floor==2 or floor==3:
            pass
        else:
            address_type=ord(recvdata[0])
            #print "Address_type=%2x"%address_type

        #second tint
        recvdata=recvdata[tint:]
        tint=istr2halfword(recvdata[:2])
        recvdata=recvdata[2:]
        #print "Tint=%d"%tint
        
        recvbackup=recvdata
        if floor>3:
            if address_type==0x07:
                            e_h.tcp=nstr2halfword(recvdata)
            elif address_type==0x08:
                            e_h.udp=nstr2halfword(recvdata)
            elif address_type==0x09:
                            a=ord(recvdata[0])
                            b=ord(recvdata[1])
                            c=ord(recvdata[2])
                            d=ord(recvdata[3])
                            e_h.ip="%s.%s.%s.%s"%(a,b,c,d)
            elif address_type==0x0f:
                            index=recvdata.find("\x00")
                            if index==-1:
                                            print "No trailing null?"
                            e_h.np=recvdata[:index]
            elif address_type==0x10:
                            index=recvdata.find("\x00")
                            if index==-1:
                                            print "No trailing null?"
                            e_h.ncalrpc=recvdata[:index]
                            #print "ncalrpc=%s"%e_h.ncalrpc
            elif address_type==0x11:

                            index=recvdata.find("\x00")
                            if index==-1:
                                            print "No trailing null?"
                            e_h.netbios=recvdata[:index]
                            #print "NETBIOS! %s"%e_h.netbios
                            
            elif address_type==0x1f:
                            e_h.http=nstr2halfword(recvdata)
            else:
                            print "Unknown address type: %d (floor %d, %d bytes)\n"%(address_type,floor,tint)
        floor+=1
                                        
        recvdata=recvbackup[tint:]

    if e_h.context=="\x00"*16:
                    return None
    #finally return our entry_handle
    return e_h
                
                
def epmapperdump(host,port=135,covertness=1,getsock=None):
    """
    Dumps the table of information located on port 135
    """
    #first, bind to the epmapper service
    UUID="e1af8308-5d1f-11c9-91a4-08002b14a0fa"
    callid=0
    err,s=msrpcbind(UUID,3,0,host,port,callid,covertness=covertness,getsock=getsock)
    if err==0:
        print "Could not bind to epmapper"
        return None
    
    morestuff=1
    entry_handle=entryhandle()
    results=[]
    entrynum=1
                            
    while entry_handle!=None:
        #print "Entry: %d"%entrynum
        entry_handle=dce_enum_get_next(s,entry_handle,callid,covertness);
        if entry_handle!=None:
            results.append(entry_handle)
        callid+=1
        entrynum+=1
    s.close()
    return results


def epmappertotcp(uuidstr,host,port=135):
    """
    Gets the tcp port for a given uuid
    This is used by a few old exploits but also by the dcefuzzer
    It returns an integer (the port) on success or None on failure
    """
    results=epmapperdump(host,port)
    if results==[] or results==None:
        return None
    for e_h in results:
        # XXX: this is a plain string compare, so lower() both to make sure
        # they match even when user gives in uppercase format in an effort to
        # be fancy
        if uuid2uuidstr(e_h.uuid).lower() == uuidstr.lower():
            #print "Found UUID we were looking for..."
            if e_h.tcp!=None:
                return int(e_h.tcp)
    return None

import time
def smb_nt_64bit_time(data):
    """This is some crappy code that doesn't quite work. To be totally correct
    I'd need to know the server's time zone, which I don't.
    
    This was some seriously painful stuff
    """

    time_hi=uint32(istr2int(data[4:8]))
    time_lo=uint32(istr2int(data[0:4]))
    #print "time_lo=%u time_hi=%u"%(time_lo,time_hi)
    t=long((long(time_hi)<<32) | long(time_lo))
    #print "t=%16x %ld"%(t,t)
    secs=long(t)/10000000L
    #print "Secs=%ld %lx"%(long(secs),secs)
    nsecs=((secs) % 10000000) * 100
    secs=secs-11644473600L
    return time.ctime(secs)
    
def smb_utime(data):
    pass

def smb_datetime(data):
    #data=data[:]
    time=nstr2halfword(data[0:2])
    datestart=2
    dateend=4
    date=nstr2halfword(data[datestart:dateend])
    #print "Date=%s"%hexprint(data[datestart:dateend])
    sec=(time & 0x1f)*2
    min=(time>>5)&0x3f
    hour=(time>>11)&0x1f
    mday=date&0x1f
    mon=((date>>5)&0x0f)-1
    year=((date>>9)&0x7f)+1980-1900

    wday=0
    yday=0
    isdst=-1
    #print "Date: %s"%([year,mon,mday,hour,min,sec,wday,yday,isdst])
    import time
    asc=time.asctime((year,mon,mday,hour,min,sec,wday,yday,isdst))
    return asc
    
from libs.canvasntlm import *
    
##################################################################3
class SMB:
    """
    Encapsulates an SMB connection
    
    TODO:
        Implement the rest of CIFS, including findfirst2, read, copy, delete
        Implement some covertness
    """
    def __init__(self,host,port=139,getsock=None):
        self.host=host
        self.port=port
        self.errormsg=""
        self.covertness=1 #default is no covertness
        self.tid="\x00\x00"
        self.uid="\x00\x00"
        self.pid="\x00\x00"
        self.getsock=getsock
        self.username=""
        self.password=""
        self.os="unknown"
        self.lanman="unknown"
        self.domain=""
        self.cwd="\\"
        self.timeout=5.0
        self.s=None #our socket that holds the connection
        self.auth=None
        self.forceauth=0
        self.server=None
        return
    
    def set_timeout(self,timeout):
        self.timeout=timeout
        if self.s:
            try:
                self.s.set_timeout(timeout)
            except:
                pass # for IPv6
            
    def setUsername(self,username):
        self.username=username
        
    def setPassword(self,password):
        self.password=password

    def setPort(self,port):
        self.port=int(port)
        
    def getHash(self):
        """
        Returns the hash, which we send back to the client
        """
        #??!?!?! FIXME
        return hash
    
    def setProxyPasswords(self,LMpass,NTLMpass):
        """
        We sent the hash to a client and they gave us their password in both forms
        If you call finish_connect after this, we will use the new passwords
        instead of self.password and complete our attack
        """
        #?!?!?!
        return

    def log(self,error):
        devlog("msrpc", "SMB log: %s"%error)
        self.errormsg=error
        
    def connect(self):
        """
        SMB::connect()
        """
        self.port=int(self.port)
        if self.getsock:
            # XXX: check if this IPv6 context switches ok!
            if ":" in self.host:
                s = self.getsock.gettcpsock(AF_INET6=1)
            else:
                s = self.getsock.gettcpsock()
        else:
            # XXX: IPv6 context switcheroo
            if ":" in self.host:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:

            # XXX: do this for every connect we want ipv6 support on win32 for :(
            # XXX: ideally we port everything to multi-protocol getaddrinfo support I guess
            # XXX: but for now we'll want to keep it seperated !

            sockaddr = (self.host, self.port)
            # for ipv6 win32 semantics
            if ":" in self.host:
                res = socket.getaddrinfo(self.host, self.port, socket.AF_INET6, socket.SOCK_STREAM)
                print res
                sockaddr = res[0][4]
            ret = s.connect(sockaddr)

        except:
            #timeout typically
            #import traceback
            #traceback.print_exc(file=sys.stdout)
            ret=-1
            
        if ret==-1:
            self.log("Could not connect to target %s:%d"%(self.host,self.port))
            return 0

        if self.port==139:
            error,errstr=netbios_sessionrequest(s)
            if error:
                self.log( errstr)
                return 0
        
        error, errstr, capabilities, key, domain, server=smb_negotiate(s)
        if error:
            self.log(errstr)
            return 0

        #if the user has specified a domain, then we want to use that, otherwise we use the domain
        #specified in the SMB negotiation, which will probably be the local domain of the box
        """
        Forcing NTLMv2 is hard:
        Samba needs this in the smb.conf
        [global]
        client NTLMv2 auth = Yes
        client use spnego = no
        And you need to set your lmcompatibility to 5 on the windows server
        Then, smbclient will work normally,
        and we will replicate NTLMv2 on the protocol
        """
        if self.domain:
            domain=self.domain
        auth=NTLM()
        if self.password==None:
            self.password="" #None is not valid
        auth.password=self.password
        auth.username=self.username
        auth.domain=self.domain
        auth.challenge=key 
        auth.type=NTLMSSP_AUTH
        auth.set_ntlm_version(1)
        if capabilities&0x4:
            auth.set_unicode(1)
        else:
            auth.set_unicode(0)
        auth.raw() #generate the two values we need
        
        
        error,errstr,uid,os,lanman,domain=smb_session_setup(s,auth, capabilities, domain=domain)
        if error:
            self.log(errstr)
            return 0
        self.uid=uid
        #save this off
        self.s=s
        self.set_timeout(self.timeout) #to set the socket's timeout
        self.os=os
        self.lanman=lanman
        self.domain=domain
        self.server=server
        self.log("Connected")
        return 1

    def pipeconnect(self,pipename):
        s=self.s
        
        #self.log("UID=0x%2.2x%2.2x"%(ord(uid[0]),ord(uid[1])))
        error,errstr,tid=smb_ipc_connect(s,self.uid)
        if error:
            self.log(errstr)
            return 0
        self.tid=tid
        #self.log("TID=0x%2.2x%2.2x"%(ord(tid[0]),ord(tid[1])))

        error,errstr,fid=nt_createandx(s,tid,self.uid,pipename)
        if error:
            self.log("If error is File Not Found, then the service is not running.")
            self.log(errstr)
            return 0
        
        self.fid=fid
        return 1
    
    def trans(self,param,subcommand,data,maxparam=10,maxdata=16644):
        data=smb_trans(param,subcommand,self.tid,self.pid,self.uid,self.fid,data,maxparam,maxdata)
        if self.port==139:
            data=netbios(data)
        self.s.sendall(data)
        data=self.s.recv(1000)
        return data
    
    def trans2(self,param,subcommand,data,maxparam=10,maxdata=16644):
        data=smb_trans2(param,subcommand,self.tid,self.pid,self.uid,data,maxparam,maxdata)
        if self.port==139:
            data=netbios(data)
        self.s.sendall(data)
        data=self.s.recv(1000)
        return data
    
    def dcebind(self,interface,versionmajor,versionminor,callid):
        "binds to a DCE endpoint over this named pipe connection"
        self.auth=None
        #we only use NTLM authentication if the user has 
        #specifically requested it by setting self.forceauth
        #this is because if you try to double-auth via both SMB and DCE
        #the SMB will succeed, but you'll recieve a "Bind_Nack" from the DCE
        #server, and it will fail
        #however, SMB pipes will carry your authentication with you
        #in some rare cases, you'll want to do both
        #and in that case, set self.forceauth
        devlog("msrpc", "msrpc username: %s msrpc password: %s forceauth=%s"%(self.username,self.password,self.forceauth))
        if self.username and self.forceauth:
            self.auth=getNTLMauth(self.domain, self.server, self.username, self.password, unicode)
         
        devlog('SMB::dcebind', "interface: %s" % interface)
        error,errstr=smbdcebind(self.s,self.tid,self.uid,self.fid,interface,versionmajor,versionminor,callid,self.auth,self.covertness)
        if error:
            devlog("msrpc", "dcebind error: %s"%errstr)
            self.log("MSRPC Error: %s"%errstr)
            return 0 
        self.log("Successfully bound to %s via named pipe"%interface)
        return 1

    def dcecall(self,opnum,buffer,callid,ntlm):
        "Call a DCE function over this named pipe connection"
        devlog("msrpc","dcecall() - going for smb_dce_call()")
        smb_dce_call(self.s,opnum,buffer,self.fid,self.uid,self.tid,callid)
        try:
            error,buf=smb_readx(self.s,self.fid,self.uid, self.tid)
        except:
            raise DCEException, "DCE ncacn_np %s: %s" % ("Received packet failed", "SMB protocol failed to recv response") 

        if error:
            if error==0xc00000b0L:
                self.log("PIPE disconnected error")
            raise DCEException, "DCE ncacn_np %s: Error 0x%08x" % ("SMB transmission failed", uint32(buf) )             
        return buf
    
    def treeconnect(self,path):
        path="\\\\"+self.host+"\\"+path
        error,errstr,tid=treeconnect_andx(self.s,self.tid,self.pid,self.uid,path)
        devlog("treeconnect","Treeconnect error,errstr,tid: %s %s *%s*"%(prettyprint(error),prettyprint(errstr),prettyprint(tid)))
        if error==0:
            self.tid=tid
            return 1
        else:
            self.log(errstr)
            return 0
    
    def checkdirectory(self,directory):
        success,errstr=smb_checkdirectory(self.s,self.tid,self.pid,self.uid,directory)
        if not success:
            self.log(errstr)
        return success
    
    def dir(self,pattern="*"):
        if self.cwd=="\\":
            searchstring="*"
        else:
            searchstring=(self.cwd+"\\"+pattern).replace("\\\\","\\")
            searchstring.replace("**","*")
        devlog("msrpc", "SMB Object dir(%s->%s)"%(pattern,searchstring))

        success,results=smb_findfirst2(self.s,self.tid,self.pid,self.uid,searchstring)
        if success:
            #results is actual a dictionary of results
            results=results["items"]
        return success,results
    
    def getcwd(self):
        return self.cwd
    
    def chdir(self,directory):
        """
        Changes directory on the remote system by checking
        to see that that directory exists and then modifying our
        local copy of the directory. The server itself does not
        save state as to our current directory. That's only stored
        here on the client.
        """
        olddirectory=self.cwd 
        if directory=="..":
            self.cwd="\\"+"\\".join(self.cwd.split("\\")[:-1])
        elif directory==".":
            self.cwd=self.cwd
        else:
            self.cwd=(self.cwd+"\\"+directory).replace("\\\\","\\")
            
        success=self.checkdirectory(self.cwd)
        if not success:
            self.cwd=olddirectory
            self.log("Didn't change directory")
            return 0

        return 1

    def mkdir(self,directory):
        """Make a directory, if possible"""
        directory=self.cwd+"\\"+directory
        success,results=smb_mkdir(self.s,self.tid,self.pid,self.uid,directory)
        return success

    def fileclose(self):
        success,results=smb_close(self.s,self.tid,self.pid, self.uid,self.fid)
        if not success:
            print "Warning: Could not close file!"
        return success
    
    def get(self,filename):
        filename=self.cwd+"\\"+filename
        success,results=smb_open_andx(self.s,self.tid,self.pid,self.uid,filename)
        if success:
            self.fid=results["FID"]
        else:
            results="Could not open file"
            return 0
        
        #Query File Info
        success,results=smb_query_file_info(self.s, self.tid, self.pid, self.uid,self.fid)

        if not success:
            self.fileclose()
            return 0

        #Read Data from File
        wanted=results["End Of File"]
        devlog("msrpc","Want to grab %d bytes"%wanted)
        datalist=[] #we use a list so as not to be += O(n^2)
        while wanted>0:
            mymaxcount=wanted
            if mymaxcount>16000:
                mymaxcount=16000
            error, results=smb_readx(self.s,self.fid,self.uid, self.tid,maxcount=mymaxcount)

            if error:
                devlog("msrpc", "Error while readx-ing")
                #close request
                self.fileclose()
                return ""

            datalist+=[results]
            wanted=wanted-len(results)
            devlog("msrpc", "Read %d bytes, wanted now %d"%(len(results), wanted))
            
        data="".join(datalist)
        #close request
        #print "Read %d bytes"%len(data)
        self.fileclose()
        return data

    def put(self,source,dest=".",destfilename=""):
        """
        Puts a file on the remote server using SMB.
        This reads in the file 1024 bytes at a time, so it should be able
        to handle quite large files.
        """
        #we ignore dest for now
        if dest!=".":
            dest=self.cwd+"\\"+dest
        else:
            dest=""
        if destfilename:
            filename=dest+"\\"+destfilename
        else:
            filename=dest+"\\"+source

        success,results=smb_open_andx(self.s,self.tid,self.pid,self.uid,filename,
                                      access=SMB_ACCESS_READWRITE, 
                                      share=SMB_SHARE_DENY_NONE,
                                      openfunction=SMB_OPENFUNCTION_CREATE | SMB_OPENFUNCTION_TRUNCATE)
        if success:
            self.fid=results["FID"]
        else:
            results="Could not open file"
            return 0
        offset=0
        infile=file(source, "rb")
        infile.seek(0,2) #go to end
        length=infile.tell() #how big are you?
        infile.seek(0,0) #go back to start
        data=infile.read(1024)
        while offset!=length:
            devlog("msrpc", "Sending bytes at offset %d"%offset)
            #send up to 1024 bytes at a time
            data_to_send=data
            #should this be wrapped in try/except?
            success, results=smb_writex(self.s,self.fid,self.uid, self.tid,self.pid,data_to_send,offset)
            offset+=len(data_to_send) #nt4 needs the offset to be calculated correctly on a named pipe
            #for a given DCE call - oddly, 2000 and above don't care.
            try:
                data=infile.read(1024)
            except:
                devlog("msrpc", "Error reading data - someone truncated the file out from under us!")
                self.fileclose()
                return 0
            
            if not success:
                devlog("msrpc", "Error while writex-ing")
                #close request
                self.fileclose()
                return 0            

        infile.close() #do this explicitly now    
        devlog("msrpc", "Sent file of %d bytes"%offset)
        self.fileclose()
        return 1
    
    def unlink(self,filename):
        """delete a file or directory"""
        filename=self.cwd+"\\"+filename
                
        success, results=smb_delete(self.s,self.tid,self.pid,self.uid,filename)
        if not success:
            #maybe it's a directory...
            success, results=smb_deletedir(self.s,self.tid,self.pid,self.uid,filename)
        return success
    
            
    
    def close(self):
        """Closes the smb connection object..."""
        if self.s:
            self.s.close()
        
    def write(self,data):
        """
        Writes data to the SMB pipe
        """
        offset=0
        length=len(data)
        while offset!=length:
            data_to_send=data[offset:offset+1024]
            success, results=smb_writex(self.s,self.fid,self.uid, self.tid,self.pid,data_to_send,offset)
            offset+=len(data_to_send)
            if not success:
                devlog("msrpc", "Error while writex-ing in SMB::write()")
                #close request
                return 0
        return 

    def read(self,length):
        #print "Want to grab %d bytes"%length
        wanted=length
        datalist=[] #we use a list so as not to be += O(n^2)
        while wanted>0:
            #print "maxcount=%d"%wanted
            mymaxcount=wanted
            if mymaxcount>16000:
                mymaxcount=16000
            error, results=smb_readx(self.s,self.fid,self.uid, self.tid,maxcount=mymaxcount)
            
            if error:
                devlog("msrpc","Error while readx-ing %s"%error )
                #close request
                #self.fileclose()
                return ""
            datalist+=[results]
            wanted=wanted-len(results)
        
        data="".join(datalist)
        return data
    
######################################################################            

# MAPI CLASS
class MAPI:
    def __init__(self):
        pass
    
    def encode(self, buf):
        res=""
        for a in range(0, len(buf)):
            res+= chr( ord(buf[a]) ^ 0xa5 )
        return res
    
# NBNS Packets

class SSL_Wrapper:
    def __init__(self, s):
        try:
            self.ssl=socket.ssl(s._sock)
        except AttributeError:
            print "Cannot do ssl currently on MOSDEF sockets"
            self.ssl=None
        except socket.sslerror,msg:
            print "SSL error: %s"%msg
            self.ssl=None
        
    def recv(self, num):
        if not self.ssl:
            return ""
        return self.ssl.read(num)
    
    def send(self, buf):
        if not self.ssl:
            return
        return self.ssl.write(buf)
    
    
        
# Opcode
NBNS_QUERY       = 0x0
NBNS_REGISTRATION= 0x5
NBNS_RELEASE     = 0x6
NBNS_WACK        = 0x7
NBNS_REFRESH     = 0x8
NBNS_MULTIHOMED  = 0xF
# R 
NBNS_REQUEST     = 0
NBNS_RESPONSE    = 1

class NBNS_Packet:
    hdr_fmt_str=">HHHHHH"
    def __init__(self):
        self.transactionid=0x0 # 2
        self.flags=0x0         # 2
        self.qdcount=0x0       # 2 question
        self.ancount= 0x0      # 2 answerRR
        self.nscount=0x0       # 2 authorityRR
        self.arcount=0x0       # 2 additionalRR
        
        # components from self.flags
        self.opcode=0
        self.r=0
        self.nm_flags=0
        self.rcode=0
        self.quest = []
        self.resources=[]
    def hdrsize(self):
        return struct.calcsize(self.hdr_fmt_str)

    def set_transactionid(self, t):
        self.transactionid=t
        
    def set_qdcount(self, question):
        self.qdcount=question
        
    def set_ancount(self, answerRR):
        self.ancount= answerRR

    def set_nscount(self, authorityRR):
        self.nscount=authorityRR

    def set_arcount(self, additonalRR):
        self.arcount= additonalRR
    
    def hdrget(self, rawdata):
      (self.transactionid, self.flags,\
       self.qdcount, self.ancount,\
       self.nscount, self.arcount)=\
       struct.unpack(self.hdr_fmt_str, rawdata[0:self.hdrsize()])
 
      (self.r, self.opcode) =self._get_opcode(self.flags)
      self.nm_flags= self._get_nm_flags(self.flags)
      self.rcode=self._get_rcode(self.flags)
    
      
    def _get_opcode(self, flag):
        tmp=(flag >> 11) & 0xff
        r=(tmp>>4) & 0xf
        opcode= tmp & 0xf
        return (r, opcode)
    def _get_nm_flags(self, flag):
        return (flag >> 4) & 0x7F
        
    def _get_rcode(self, flag):
        return (flag & 0xF)

    def set_flags(self, r, opcode, nm_flags, rcode):
        tmp=0
        tmp|= rcode
        tmp|= (nm_flags << 4)
        tmp|= (((r<<4) &0x1f | opcode) << 11)
        self.flags= tmp

    def _set_flags(self, flags):
      (self.r, self.opcode) =self._get_opcode(flags)
      self.nm_flags= self._get_nm_flags(flags)
      self.rcode=self._get_rcode(flags)
        

    def set_opcode(self, opcode):
        self.opcode=opcode

    def set_nm_flags(self, nmflags):
        self.nm_flags=nmflags
        
    def set_r(self, r):
        self.r=r
                
    def createHeaderRaw(self):
       self.set_flags(self.r, self.opcode, self.nm_flags, self.rcode)
       # HHHHHH
       return struct.pack(self.hdr_fmt_str,\
       self.transactionid, self.flags,\
       self.qdcount, self.ancount,\
       self.nscount, self.arcount)
   
    def raw(self, convert=1) :
        return self.createHeaderRaw() +self.createRaw(convert) 
    
    def createRaw(self, convert):
        return ""
    
    def convert_domain(self, data, type, length=16):
        buf=""
        if length: # craft to length
            data= data + " " * (length-len(data) -1) 
            data=data[0:length-1]
            data+=chr(type)
        for a in range(0, len(data)):
            tmp=ord(data[a])
            buf+=chr( ((tmp >> 4) & 0xf) + 0x41 )
            buf+=chr( (tmp & 0xf) + 0x41 )
        return struct.pack("B", length*2)+ buf + "\0"
        
    def add_question(self, qname, qtype, qclass,type):
        self.quest.append( (qname, qtype, qclass, type) )

    # if rr_name is an integer, its an index to a question array
    def add_resource(self, rr_name, rr_type, rr_class, ttl, rdlength, rdata, type):
        self.resources.append( (rr_name, rr_type, rr_class, ttl, rdlength, rdata, type))

    def question_raw(self, convert=1):
        buf=""
        for a in self.quest:
            if convert:
                 buf+=self.convert_domain(a[0], a[3])
            else:
                 buf+=a[0]
            buf+=struct.pack("!H", a[1])
            buf+=struct.pack("!H", a[2])
        return buf
    
    def resource_raw(self, convert=1):
        buf=""
        for a in self.resources:
            # offset to question [ rr_ name ]
            if type(a[0]) == type(1): 
                # We supposed that the netbios name with everything its 0x22
                buf+= struct.pack("!H", ( 0xc000 | (a[0] * 0x22 + 12) ))
            else:
                if convert:
                    buf+=self.convert_domain(a[0], a[6]) # [type]
                else:
                    buf+=a[0]
            buf+=struct.pack("!H", a[1]) # [ rr_type ] 
            buf+=struct.pack("!H", a[2]) # [ rr_class ]	
            buf+=struct.pack("!L", a[3]) # [ ttl ]	
            buf+=struct.pack("!H", a[4]) # [ rdlength ]
            buf+=a[5]                    # [ rdata ]
        return buf	
                
                
NBNS_QT_NB     = 0x20
NBNS_QT_NBSTAT = 0x21
NBNS_QC_IN     = 0x01

class NBNS_Query(NBNS_Packet):
    def __init__(self):
        NBNS_Packet.__init__(self)

        self.set_qdcount(1)
        self.set_opcode(NBNS_QUERY)
        self.set_r(NBNS_REQUEST)
        self.set_nm_flags(0x10)
        self.set_transactionid(0x82c2)
        
    def createRaw(self, convert):
        buf=""
        buf+= self.question_raw(convert)
        buf+= self.resource_raw(convert)
        return buf

class NBNS_Register(NBNS_Packet):
    def __init__(self):
        NBNS_Packet.__init__(self)
        self.set_opcode(NBNS_REGISTRATION)
        self.set_r(NBNS_REQUEST)
        self.set_nm_flags(0x10)
        self.set_transactionid(0x82c2)
        self.set_qdcount(1)
        self.set_arcount(1)

    def createRaw(self, convert):
        buf=""
        buf+= self.question_raw(convert)
        buf+= self.resource_raw(convert)
        return buf
        
class NBNS_MultihomedRegister(NBNS_Packet):
    def __init__(self):
        NBNS_Packet.__init__(self)
        self.set_opcode(NBNS_MULTIHOMED)
        self.set_nm_flags(0x00)
        self.set_transactionid(0x82c2)
        self.set_qdcount(1)
        self.set_arcount(1)

    def createRaw(self, convert):
        buf=""
        buf+= self.question_raw(convert)
        buf+= self.resource_raw(convert)
        return buf
        
class DNS:
    def __init__(self, host="", port=137, convert=1):
        self.host=host
        self.port=port
        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
        self.convert=convert
    def set_host(self, host):
        self.host = host

    def set_port(self, port):
        self.port = port

    def query(self, queryname, qtype, qclass, type):
        p=NBNS_Query()
        p.add_question(queryname, qtype, qclass,type)
        self.s.sendto(p.raw(self.convert), (self.host, self.port))
        
class NBNS:
    def __init__(self, host="", port=137, convert=1):
        self.host=host
        self.port=port
        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
        self.convert=convert
    def set_host(self, host):
        self.host = host

    def set_port(self, port):
        self.port = port

    def query(self, queryname, qtype, qclass, type):
        p=NBNS_Query()
        p.add_question(queryname, qtype, qclass,type)
        self.s.sendto(p.raw(self.convert), (self.host, self.port))
        
# RCP Packet Classes
# DCE-RPC Information:
# http://www.opengroup.org/onlinepubs/009629399/chap12.htm

DCE_REQUEST=0
DCE_RESPONSE=2
DCE_FAIL    =3
DCE_BIND=  11
DCE_BIND_ACK=12
DCE_AUTH3= 16

class DCEPacket:
    #hdr_fmt_str="=BBBBLHHL"
    hdr_fmt_str="<BBBBLHHL"
    hdr1_fmt_str = "<BBBBL"
    hdr2_fmt_str = "<HHL"
    fmt_str=""
    def __init__(self, automatic=1, littleendian=True):
        self.version=5    # 1
        self.minor=0      # 1
        self.packettype=DCE_BIND # 1
        self.flags=0x3     #1
        self.datarepresentation=0x10 # 4
        # XXX we should FIX self.datarepresentation for big endian systems
        self.fraglength=112 # 2
        self.authlen=32     # 2
        self.callid=1       # 4
        self.littleendian = littleendian
    
    def setFlags(self, flags):
        self.flags = flags
        
    def setMinor(self, minor):
        self.minor = minor
        
    def setFraglength(self, fraglength):
        self.fraglength=fraglength

    def setCallid(self, callid):
        self.callid=callid
        
    def size(self):
        return self.fraglength
    
    def setPackettype(self, type):
        self.packettype=type

    def getPacketType(self):
        return self.packettype
        
    def setAuthlen(self, alen):
        self.authlen=alen
        
    def getAuthlen(self):
        return self.authlen
    
    def hdrsize(self):
        return struct.calcsize(self.hdr_fmt_str)

    def get(self, rawdata):
        print "*MEEP*"
        pass
    
    def hdrget(self, rawdata):
        try:
            s1 = struct.calcsize(self.hdr1_fmt_str)
            (self.version, self.minor, self.packettype, self.flags, self.datarepresentation) = \
                struct.unpack(self.hdr1_fmt_str, rawdata[0:s1])
            #print (self.version, self.minor, self.packettype, self.flags, self.datarepresentation)
            s2 = struct.calcsize(self.hdr2_fmt_str)
            (self.fraglength, self.authlen, self.callid) = \
                struct.unpack(self.hdr2_fmt_str, rawdata[s1:s1+s2])
            #print (self.fraglength, self.authlen, self.callid)
            devlog('DCEPacket::hdrget', "%s\n%s" % \
                ((self.version, self.minor, self.packettype, \
                self.flags, self.datarepresentation, \
                self.fraglength, self.authlen, self.callid), \
                shellcode_dump(rawdata[0:self.hdrsize()])))
        except TypeError:
            raise DCEException, "Invalid header in hdrget()"
        
    def raw(self) :
        #return self.createHeaderRaw() +self.createRaw() 
        devlog('DCEPacket::raw()', "createRaw() is %s" % self.createRaw)
        buf=self.createRaw() 
        buf=self.createHeaderRaw() + buf
        devlog('DCEPacket::raw()', "returning %s bytes\n%s" % (len(buf), shellcode_dump(buf)))
        return buf
        
    def createHeaderRaw(self):
        buf = struct.pack(self.hdr_fmt_str, self.version, \
                            self.minor,\
                            self.packettype,\
                            self.flags, \
                            self.datarepresentation,\
                            self.fraglength,\
                            self.authlen,\
                            self.callid)
        devlog('DCEPacket::createHeaderRaw()', "%d bytes\n%s" % (len(buf), shellcode_dump(buf)))
        return buf
    
    def createRaw():
        return ""
    
class DCEBind(DCEPacket):
    ##fmt_str="=HHLBxxxHH16sHH16sL"
    fmt_str="<HHLBxxxHH16sHH16sL"
    auth_str="BBBBL"
    def __init__(self, auth=None, autosize=1):
        DCEPacket.__init__(self)
        self.maxxmitfrag=4280   # 2 fraglength+24
        self.maxrecvfrag=4280   # 2 
        self.assocgroup= 0      # 4
        self.numctxitem= 1      # 1
        self.contextid = 0x0      # 2
        self.numtransitems=1    # 2
        self.uuid="A"*16            # 16
        self.interfacever=0     # 2
        self.interfacevermin=0 #81  # 2
        self.transfersyntax= transfersyntax #always the same. Don't get too clever here.
        self.syntaxver=0x2      # 4
        if auth:
            self.authtype= auth.auth_type() # 1
        else:
            self.authtype= 0
        self.authlevel=0x2      # 1
        self.authpadlevel= 0x0  # 1
        self.authrsrv= 0x0      # 1
        #this has to be a real context ID if we're going locally
        self.authcontextid= 763688# 4
        self.auth=auth
        self.setPackettype(DCE_BIND)
        #automagically set authlen/fraglen
        self.autosize=autosize

    def setVersion(self, ver, min):
        self.interfacever=ver
        self.interfacevermin=min 

    def setUuid(self, uuid):
        self.uuid=uuid2data(uuid)
        
    def setTransferSyntax(self, transfer):
        self.transfersyntax=uuid2data(transfer)
        
    def createRaw(self):
        buf=""
        if self.auth:  
            self.authcontextid= self.auth.get_contextid()
            self.auth.set_flag(0x3207)
            auth= self.auth.raw()
        else: 
            auth=""
        devlog('DCEBind::createRaw()', "packfmt:%s interface[ver:%s min:%s]\nuuid: %s" % \
            (self.fmt_str, self.interfacever, self.interfacevermin, shellcode_dump(self.uuid)))
        tmp = struct.pack(self.fmt_str, \
                          self.maxxmitfrag,\
                          self.maxrecvfrag,\
                          self.assocgroup,\
                          self.numctxitem,\
                          self.contextid,\
                          self.numtransitems,\
                          self.uuid,\
                          self.interfacever,\
                          self.interfacevermin,\
                          self.transfersyntax,\
                          self.syntaxver) 
        devlog('DCEBind::createRaw()', "raw pkt %d bytes\n%s" % (len(tmp), shellcode_dump(tmp)))
        buf += tmp
        if self.autosize:
            self.setAuthlen(len(auth))

            
        
        if self.auth:
            #authpadlevel=0
            buf+="\xcc"*self.authpadlevel
            buf+=struct.pack(self.auth_str, \
                        self.authtype,\
                        self.authlevel,\
                        self.authpadlevel,\
                        self.authrsrv,\
                        self.authcontextid)

        buf+= auth
        if self.autosize:
            self.setFraglength( len(buf) + self.hdrsize())     

          
        return buf

class DCEBind_ack(DCEPacket):
    fmt_str="=HHLBxxxHH16sHH16sLBBBBL"
    def __init__(self, auth=None, autosize=1):
        DCEPacket.__init__(self)
        self.maxxmitfrag=4280   # 2 fraglength+24
        self.maxrecvfrag=4280   # 2 
        self.assocgroup= 0      # 4
        self.secondaddrlen = 0   # 2 
        self.secondaddr=""      # seconaddrlen
        # PADDING (2) IF ITS NECESARY 
        self.numresult=""
        # 3 * "\0"
        self.ackresult=0x0      # 2
        self.transfersyntax=transfersyntax  # 16
        self.syntaxver=0        # 4
        self.authlevel=0x2      # 1
        self.authpadlevel= 0x0  # 1
        self.authrsrv= 0x0      # 1
        self.authcontextid= 763688# 4
        
        if auth:
            self.authtype= auth.auth_type() # 1
        else:
            self.authtype= 0
        self.auth=auth
        
        #automagically set authlen/fraglen
        self.autosize=autosize
        
    def get_authcontextid(self):
        return self.authcontextid
        
    def get(self, rawdata):
        ##hdr1="<HHLH"
        hdr1 = "<HHLH"
        idx= 0
        devlog('DCEBind_ack:get', "1> \n%s" % shellcode_dump(rawdata))
        (self.maxxmitfrag, self.maxrecvfrag, self.assocgroup, self.secondaddrlen) = \
            struct.unpack(hdr1, rawdata[idx: idx+struct.calcsize(hdr1)])
        #print (self.maxxmitfrag, self.maxrecvfrag, self.assocgroup, self.secondaddrlen)
        idx+= struct.calcsize(hdr1)
        devlog('DCEBind_ack:get', "2> rawdatalen=%d idx=%d secondaddrlen=%d" % (len(rawdata), idx, self.secondaddrlen))
        self.secondaddr= rawdata[idx: idx+self.secondaddrlen]
        devlog('DCEBind_ack:get', "secondaddr = %s" % self.secondaddr)
        idx+=self.secondaddrlen
        if idx%4:
            idx+= 4-idx%4 # 4 
        
        self.numresult=ord(rawdata[idx]) #I'm betting this is really a long, and not a byte...
        idx+=1 #increment for the one byte we used up
        devlog('DCEBind_ack:get', "numresult=%x (should be 1)"%self.numresult)
        # Why no unpack here?
        #print self.numresult
        #print "*"
        #Answer: see above. Most likely part of a long.
        idx+= 3 # FIXME? Couldt find documentation about this 3 byte 0x0
        ##hdr2="=Hxxx16sL" # xxx unknown padding
        ##hdr2="<Hxxx16sL" # xxx unknown padding
        hdr2 = ">HH16sL"

        devlog('DCEBind_ack:get', "3")
        (self.ackresult, self.ackreason, self.transfersyntax, self.syntaxver) =\
            struct.unpack(hdr2, rawdata[idx: idx+struct.calcsize(hdr2)])
        devlog('DCEBind_ack:get', "4> ackresult:%d ackreason:%d syntaxver:%d transfersyntax:\n%s" % \
            (self.ackresult, self.ackreason, self.syntaxver, shellcode_dump(self.transfersyntax)))
        
        ##hdr3="BBBBL"
        ##hdr3="<BBBBL"
        hdr3=">BBBBL"
        idx+=struct.calcsize(hdr2)
        # this might be fixed
        if self.auth and self.authlen:
            devlog('DCEBind_ack:get', "4")
            (self.authtype, self.authlevel, \
                self.authpadlevel, self.authrsrv,\
                self.authcontextid)=\
             struct.unpack(hdr3, rawdata[idx: idx+struct.calcsize(hdr3)])
            hdrsize=struct.calcsize(hdr3)
            #level should be 2, type should be 0xa.
            devlog('DCEBind_ack:get', "Hdrsize=%d type=%x level=%x context=%x"%(hdrsize,self.authtype,self.authlevel,self.authcontextid))
            idx+= hdrsize
            self.auth.get(rawdata[idx:])
        devlog('DCEBind_ack:get', "5")
        
        
        
    def setTransferSyntax(self, transfer):
        self.transfersyntax=uuid2data(transfer)
    
    def createRaw(self):
        # modified a piacere!
        return ""

class DCEAuth3(DCEPacket):
    fmt_str="=BBBBL"
    def __init__(self, auth=None, autosize=1):
        DCEPacket.__init__(self)
        if auth:
            self.authtype= auth.auth_type() # 1
        else:
            self.authtype= 0
        self.authlevel=0x2      # 1
        self.authpadlevel= 0x0  # 1
        self.authrsrv= 0x0      # 1
        self.authcontextid= 763688# 4
        self.auth=auth
        self.username=""
        self.password=""
        self.setPackettype(DCE_AUTH3)
        
        #automagically set authlen/fraglen
        self.autosize=autosize
                
    def setTransferSyntax(self, transfer):
        self.transfersyntax=uuid2data(transfer)
        
    def set_auth(self, user, password ):
        self.username=user
        self.password= password
        
    def createRaw(self):
        buf=""
        #if self.autosize:
        #    self.setAuthlen(len(auth))
        #    self.setFraglength( struct.calcsize(self.fmt_str) + self.getAuthlen())
        self.authcontextid= self.auth.get_contextid()
        #I can pretty much put any padding here?
        #and it still works?!?
        #ethereal likes it, anyways....
        padding=binstring("b8 10 b8 10") 
        buf+=padding
        
        #here's where the magic happens
        buf+= struct.pack(self.fmt_str, \
                    self.authtype,\
                    self.authlevel,\
                    self.authpadlevel,\
                    self.authrsrv,\
                    self.authcontextid)
        if self.auth:    
            #if not self.username or not self.password:
            #    raise DCEException, "Username or Password not found"
            self.auth.set_user(self.username)
            self.auth.set_password(self.password)            
            self.auth.set_auth()
            #self.auth.set_flag( 0x00020000|0x0201|0x800000|0x80000000)
            #self.auth.set_flag(0x01020000)
            self.auth.set_flag(0xa208b207L) #set the ntlm flags here
            #self.auth.set_flag( ( 0x0201 | 0x80))#0xa0888205|0x80)  &~ 0x20080000 )
            auth= self.auth.raw()            
        else: 
            auth=""

        buf+= auth
        if self.autosize:
            self.setAuthlen(len(auth))
            self.setFraglength(len(buf) +self.hdrsize())
        return buf

class DCERequest(DCEPacket):
    fmt_str="=LHH"
    fmt_after="=BBBBL"
    def __init__(self, auth=None, autosize=1):
        "auth can be, for example, an ntlm object"
        DCEPacket.__init__(self)
        self.setPackettype(DCE_REQUEST)
        
        self.allochint = 148   # 4
        self.contextid = 0     # 2
        self.opnum=0           # 2 
        self.object=""
        
        if auth:
            self.authtype= auth.auth_type() # 1
        else:
            self.authtype= 0
        
        self.authlevel=0x2      # 1
        self.authpadlevel= 0x0  # 1
        self.authrsrv= 0x0      # 1
        self.authcontextid= 763688 # 4
        self.stub = ""
        self.auth=auth        
        #automagically set authlen/fraglen
        self.autosize=autosize
        
    def set_allochint(self, allochint):
        self.allochint = allochint
        
    def set_authpadlen(self, pad):
        self.authpadlevel=pad
        
    def set_contextid(self, co):
        self.contextid=co
        
    def set_opnum(self, opnum):
        self.opnum=opnum
        
    def set_stub(self, stub):
        devlog('DCERequest::set_stub()', "setting stub:\n%s" % shellcode_dump(stub))
        self.stub=stub
        
    def createRaw(self):
        buf=""
        if self.auth:    
            auth= self.auth.get_verifier()         
            devlog("msrpc", "auth verifier=%d"%len(auth))

        else: 
            auth=""
            
        #self.allochint=0x01020304
        #self.opnum=0xffff #just for use as a marker

        self.fmt_str = "<LHH"
        devlog('DCERequest::createRaw()', "pack fmt: %s\n%s" % \
            (self.fmt_str, (self.fmt_str, self.allochint, self.contextid, self.opnum)))
        buf += struct.pack(self.fmt_str, self.allochint, self.contextid, self.opnum)

        if self.object:
            devlog('DCERequest::createRaw()', "uuid object: %s\n%s" % \
                (self.object, shellcode_dump(uuid2data(self.object))))
            buf+=uuid2data(self.object)
                    
        devlog('DCERequest::createRaw()', "stub %d bytes:\n%s" % (len(self.stub), shellcode_dump(self.stub)))
        buf+=self.stub     
        if auth:
            self.authpadlevel=12
            buf+="\xcc"*self.authpadlevel
            self.authcontextid= self.auth.get_contextid()
            devlog("msrpc", "Authtype: %x"%self.authtype)
            devlog("msrpc","Authlevel: %x"%self.authlevel)
            devlog("msrpc", "Authpad len: %x"%self.authpadlevel)
            devlog("msrpc", "Auth Context ID: %x"%self.authcontextid)
            
            buf+= struct.pack(self.fmt_after, \
                        self.authtype,\
                        self.authlevel,\
                        self.authpadlevel,\
                        self.authrsrv,\
                        self.authcontextid)

            buf+= auth
         
        if self.autosize:
            self.setAuthlen(len(auth))
            self.setFraglength(len(buf) +self.hdrsize())
            self.set_allochint(len(buf) +self.hdrsize())
                        
        devlog('DCERequest::createRaw()', "%d bytes\n%s" % (len(buf), shellcode_dump(buf)))
        return buf

class DCEResponse(DCEPacket):
    fmt_str="=LHH"
    fmt_after="=BBBBL"
    def __init__(self, auth=None, autosize=1):
        DCEPacket.__init__(self)
        self.setPackettype(DCE_REQUEST)
        
        self.allochint = 128   # 4
        self.contextid = 0     # 2
        self.opnum=0           # 2 
        self.rawdata=""
        if auth:
            self.authtype= auth.auth_type() # 1
        else:
            self.authtype= 0
        
        self.authlevel=0x2      # 1
        self.authpadlevel= 0x0  # 1
        self.authrsrv= 0x0      # 1
        self.authcontextid= 2243168 # 4
        self.stub = ""
        self.auth=auth        
        #automagically set authlen/fraglen
        self.autosize=autosize
        
        
    def set_stub(self, stub):
        devlog('DCEResponse::set_stub()', "setting stub:\n%s" % shellcode_dump(stub))
        self.stub=stub

    def get(self, rawdata):
        idx=0
        sz=struct.calcsize(self.fmt_str)
        (self.allochint, self.contextid,\
            self.opnum)= struct.unpack(self.fmt_str, \
                                    rawdata[0:sz ])
        idx+=sz
        #sz= len(rawdata) - struct.calcsize(self.fmt_str) -\
        #    struct.calcsize(self.fmt_after)- self.getAuthlen()
        #self.stub=rawdata[idx: sz]     
        #idx+=sz
        
        if self.authlen != 0:
            sz=struct.calcsize(self.fmt_after)
            (self.authtype,\
                self.authlevel,\
                self.authpadlevel,\
                self.authrsrv,\
                self.authcontextid)= struct.unpack(self.fmt_after, \
                                                rawdata[idx:idx+sz])
            idx+=sz
            
        self.rawdata=rawdata        
        self.data=rawdata[idx:]
        devlog('DCEResponse::get()', "setting stub:\n%s" % shellcode_dump(self.data))
        self.stub=self.data #don't forget this!

        
    
    
            
class DCEException(Exception):
    pass

class LocalNamedPipe:
    """
    Microsoft RPC servers respond differently over a local pipe, as
    opposed to an SMB pipe. This code is here to help with that
    situation.

    It basically does everything you would normally do over SMB, but
    using CreateFile, ReadFile, etc.
    """
    def __init__(self,getpipe=None):
        #self.getpipe is a canvasexploit object
        self.getpipe=getpipe
        self.pipe=None
        return

    def pipeconnect(self,pipe):
        "returns 0 on failure"
        #pipe is \\srvsvc or similar
        devlog("msrpc", "Opening local file as a pipe.")
        sys.stdout.flush()
        pipe=pipe.replace("\\pipe","") #no duplicate, please
        ret=self.getpipe.getpipe("\\\\.\\pipe"+pipe)
        self.pipe=ret
        if self.pipe==-1:
            return 0
        return ret

    def set_wait(self,wait):
        self.pipe.set_wait(wait)
        
    #this sucks, but whatever.
    def recv(self,size):
        return self.read(size)

    def send(self,data):
        return self.write(data)

    def sendall(self,data):
        return self.write(data)
    
    def write(self,data):
        return self.pipe.write(data)
    
    def read(self,size):
        return self.pipe.read(size)
    
    
        
class DCE:
    """
    Encapsulates a DCE connection
    
    TODO:
        Implement ip_udp and http
        Fix Bind_ack failure
        Create a DCEFail and the rest of RPC Packet
    """
    def __init__(self,UUID,version,connectionList,covertness=1,getsock=None, proxyport=None, ssl=0, domain=""):
        self.connectionList=connectionList
        self.covertness=covertness #default to no covertness
        self.username=""
        self.password=""
        self.domain=domain
        self.callid=0
        self.keyword=""
        self.domainlist=""
        self.getsock=getsock
        if getsock:
            self.node=getsock.argsDict["passednodes"][0]
        self.UUID=UUID #interface UUID
        self.ntlm=None
        self.transfersyntax=transfersyntax #always the same. Don't get cute.
        self.ssl = ssl
        self.httpport= proxyport
        version=str(version) #change real to str.
        self.versionmajor=int(version.split(".")[0])
        self.versionminor=int(version.split(".")[1])
        self.port=0
        self.sequence =0
        self.timeout=5.0
        self.localpipe=0 #true if we are using a local pipe
        self.mysmb=None
        self.forceauth=0
        if self.covertness == 10:
            self.ssl = 1
        self.packetprivacy=0
        self.object=""
        self.s=None
        return
    
    def set_timeout(self,timeout):
        self.timeout=timeout
        if self.mysmb:
            self.mysmb.set_timeout(timeout)
            
    def setUsername(self,username):
        self.username=username
        
    def setDomain(self, domain):
        self.domain=domain
    
    def getDomainList(self):
        return self.domainlist
        
    def setPassword(self,password):
        self.password=password

    def setTransferSyntax(self, transfersyntax):
        self.transfersyntax=transfersyntax

    def get_packets(self):
        """
        Returns all the packets in a row until lastfrag is sent
        """

        LAST_FRAG=0x2
        p=self.get_packet()
        packets=[p]
        while not p.flags & LAST_FRAG:
            p=self.get_packet()
            packets+=[p]
        return packets
        
    def connect(self):
        for a in self.connectionList:
            try:
                devlog("msrpc","MSRPC Connecting with: %s"%a)
                devlog('DCE::connect', "connecting with %s" % a)
                if self.attemptConnect(a):
                    devlog('DCE::connect', "attemptConnect succeeded!")
                    return a
            except DCEException, msg:
                devlog('DCE::connect', "%s: %s" % (DCEException, msg))
                #print msg
                continue
        #could not connect
        raise DCEException, "Couldn't connect to any endpoint: %s" % str(self.connectionList)
    
    def close(self):
        if self.mysmb:
            self.mysmb.close()
        else:
            if self.s:
                self.s.close()
        
    def attemptConnect(self,endpoint):
        """
        Attempts to connect to a target given a endpoint string
        The string binding is an unsigned character string composed of strings that represent the binding object UUID, the RPC protocol sequence, the network address, and the endpoint and endpoint options.
        ObjectUUID@ProtocolSequence:NetworkAddress[Endpoint,Option]
        """
        keyword=endpoint.split(":")[0] # XXX: IPv6 checked, splits first, is ok
        #print "MSRPC SPLIT KEYWORD: %s"% keyword
        host=""
        devlog('DCE::attemptConnect', "Keyword: %s Forceauth=%s" % (keyword,self.forceauth))
        if keyword=="ncacn_np":
            #host=endpoint.split(":")[1].split("[")[0]

            #XXX: changed for IPv6 compatibility
            host = endpoint[endpoint.find(":")+1:].split("[")[0]
            #print "MSRPC SPLIT HOST: %s"% host

            #XXX: no need to switch to "::1" on IPv6, localhost can stay IPv4 ;)
            if host=="localhost":
                host="127.0.0.1"
            
            #don't try to do auth locally yet...it's painful and not completed
            #TODO: We've disabled LocalNamedPipe for now...need to fix!
            if False and host=="127.0.0.1" and self.forceauth==0:
                #local connection
                mysmb=LocalNamedPipe(getpipe=self.getsock)
                pipe=endpoint.split(":")[1].split("[")[1]
                pipe=pipe.split("]")[0]

                #print "MSRPC SPLIT PIPE: %s"% pipe
                ret=mysmb.pipeconnect(pipe)
                if ret:
                    self.mysmb=mysmb
                    self.localpipe=1
                    self.s=mysmb
                    mysmb.forceauth=self.forceauth
                else:
                    return 0


        if keyword=="ncacn_np" and not self.localpipe:
            
            devlog('DCE::attemptConnect', "Host: %s" % host)
            mysmb=SMB(host,getsock=self.getsock)
            mysmb.forceauth=self.forceauth
            mysmb.set_timeout(self.timeout)
            mysmb.covertness=self.covertness
            mysmb.setUsername(self.username)
            mysmb.setPassword(self.password)
            mysmb.domain=self.domain
            mysmb.setPort(445) #try 445 first
            devlog('DCE::attemptConnect', "smb: %s" % mysmb)
            self.port=445
            result=mysmb.connect()
            if not result:
                devlog("msrpc", "Connect err: %s"%mysmb.errormsg)
                if mysmb.errormsg=="c000006d":
                    devlog("msrpc", "STATUS LOGIN FAILURE")
                mysmb.setPort(139)
                self.port=139
                result=mysmb.connect()
        
            if not result:
                return 0

            self.domain=mysmb.domain #get this back in case it changed
            #we connected, time to do an IPC connect and then connect to the pipe

            # XXX: rm redundant colon split for IPv6 semantics (shouldn't break anything I think?)
            #pipe=endpoint.split(":")[1].split("[")[1]
            pipe=endpoint.split("[")[1]
            pipe=pipe.split("]")[0]

            #print "MSRPC SPLIT PIPE: %s"% pipe

            devlog("msrpc","Connecting to pipe:%s"%pipe)
            devlog('DCE::attemptConnect', "Connecting to pipe:%s" % pipe)
            if mysmb.pipeconnect(pipe)==0:
                return 0
            devlog("msrpc","Doing DCE over SMB Bind with UUID: %s forceauth=%s"%(self.UUID,self.forceauth))
            devlog('DCE::attemptConnect', "smb.dcebind: %s" % mysmb.dcebind)
            #eventually calls smbdcebind() during this function
            #which can either return a value or throw a DCEException
            error=mysmb.dcebind(self.UUID,self.versionmajor,self.versionminor,self.callid)
            #error,errstr=smbdcebind(s,tid,uid,fid,"e33c0cc4-0482-101a-bc0c-02608c6ba218",1,0,callid)
            if not error:
                #self.log(errstr)
                return 0
            #we connected and bound to it
            devlog("msrpc", "Connection succeeded over SMB to endpoint %s"%endpoint)
            self.keyword=keyword
            self.mysmb=mysmb
            devlog('DCE::attemptConnect', "returning 1")
            return 1            
            
        elif keyword=="ncacn_ip_tcp" or keyword == "ncacn_http" or self.localpipe:
            if keyword!="ncacn_np":
                devlog("msrpc","making tcp msrpc connection")
                
                # XXX: modded so it parses both IPv6 and IPv4 endpoints
                self.ip, self.port = endpoint[endpoint.find(":")+1:].split("[")
                self.port=int(self.port.split("]")[0])

                #print "MSRPC SPLIT IP*PORT: %s*%d"% (self.ip, self.port)

                try:
                    if self.getsock:
                        # XXX: check if this switches to IPv6 context ok based on self.target?
                        #print "[XXX] CHECK IPV6 CONTEXT ON MSRPC GETTCPSOCK ..."
                        if ":" in self.ip:
                            #print "[!] MSRPC IPv6 socket ..."
                            s = self.getsock.gettcpsock(AF_INET6=1)
                        else:
                            s = self.getsock.gettcpsock()
                    else:
                        if ":" in self.ip:
                            # XXX: IPv6 context switch
                            #print "[!] MSRPC IPv6 socket ..."
                            s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
                        else:            
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
                    port = self.port
                    if keyword == "ncacn_http" and self.httpport:
                        port = self.httpport
                        #if port == 80 and self.ssl:
                            #port = 443
    
                    sockaddr = (self.ip, int(port))
                    #IPv6 code here - the : is always in an IPv6 ip address, but never in IPv4
                    if ":" in self.ip:
                        res = socket.getaddrinfo(self.ip, int(port), socket.AF_INET6, socket.SOCK_STREAM)
                        sockaddr = res[0][4]
                    ret = s.connect(sockaddr)

                    #print "MSRPC CONNECT RETURNED: %s"% ret

                    if self.ssl and keyword == "ncacn_http":
                        self.s = SSL_Wrapper(s)
                    else:
                        self.s = s
                        
                    if ret==-1:
                        raise DCEException, "DCE %s %s on port %d" % (keyword, "Connection failed",self.port)                     

                    if keyword == "ncacn_http":
                        if self.httpport:
                            ## Configuring RPC over HTTP
                            ##  http://support.microsoft.com/default.aspx?scid=kb;en-us;265340#STEPS
                            ## How it works:                    
                            ##  http://msdn.microsoft.com/library/default.asp?url=/library/en-us/dndcom/html/cis.asp
                            
                            self.s.send("RPC_CONNECT %s:%d HTTP/1.0\r\n\r\n" % (self.ip, self.port))
                            #self.s.send("RPC_CONNECT %s:593 HTTP/1.0\r\n\r\n" % self.ip)
                            #this can't be right...
                            buf=self.s.recv(0x200)
                            try:
                                if buf.split(" ", 2)[1] != "200":
                                    raise DCEException, "DCE %s:  %s" % (keyword, "HTTP Server doesn't look that proxy RPC over HTTP") 
                            except IndexError:
                                    raise DCEException, "DCE %s:  %s" % (keyword, "Protocol Error") 
    
                        else:
                            buf = self.s.recv(20)
                            if not buf.count("ncacn_http/1.0"):                            
                                    raise DCEException, "DCE %s:  %s" % (keyword, "This doesn't look like a http endpoint: %s" % buf) 
                            
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Connection failed", str(msg)) 
                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Connection failed", str(msg))
                
                devlog("msrpc", "ncacn_ip_tcp: Connected")
                #except:
                #    print "[XXX] WE GOT A PROBLEM SCOTTY!"
                #    import traceback
                #    traceback.print_exc(file=sys.stderr)
                #    pass
                #now need to send a Bind()
                if self.username or self.password:
                    self.ntlm=getNTLMauth("localhost", "*SMBServer", self.username, self.password, 1)
                    bind=DCEBind(self.ntlm)
                    bind.setUuid(self.UUID) 
                    bind.setVersion(self.versionmajor, self.versionminor)
                    bind.setTransferSyntax(self.transfersyntax)
                    try:
                        self.s.sendall(bind.raw())
                    except socket.error, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Sending bind failed", str(msg)) 
                    except timeoutsocket.Timeout, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Sending bind failed",str(msg)) 
                    # Receive a Bind_ack with the challenge
                    bindAck=DCEBind_ack(self.ntlm)
                    try:
                        buf=self.s.recv(bindAck.hdrsize())
                        bindAck.hdrget(buf)
                        buf+=self.s.recv(bindAck.size()-bindAck.hdrsize())
                        bindAck.get(buf[bindAck.hdrsize():])
                        if bindAck.ackresult==2: # failed
                            raise DCEException, "DCE %s failed: Provider rejection" % keyword
                    except socket.error, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                    except struct.error, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                    except timeoutsocket.Timeout, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                    except IndexError, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg))                     
                    
                    self.domainlist=bindAck.auth.list
                    self.ntlm.domain=self.domainlist[0][1]
                    self.ntlm.hostname=self.domainlist[1][1]
                    auth3=DCEAuth3(self.ntlm)
                    auth3.set_auth(self.username, self.password)
                    devlog("msrpc", "Sending auth3 packet")
                    bigfrag=auth3.raw()
                    #send the packet to bind with
                    try:
                        self.s.send(auth3.raw())
                    except socket.error, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Auth3 send failed",str(msg))                 
                    except timeoutsocket.Timeout, msg:
                        raise DCEException, "DCE %s %s: %s" % (keyword, "Auth3 send failed",str(msg))                    

            if not self.username and not self.password and not self.forceauth:
                bind=DCEBind()
                bind.setVersion(self.versionmajor, self.versionminor)
                bind.setUuid(self.UUID)
                bind.setTransferSyntax(transfersyntax)

                try:
                    self.s.send(bind.raw())
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Sending bind failed", str(msg)) 

                bindAck = DCEBind_ack()

                try:
                    buf=reliablerecv(self.s,bindAck.hdrsize())
                    bindAck.hdrget(buf)
                    buf+=reliablerecv(self.s,bindAck.size()-bindAck.hdrsize())
                    bindAck.get(buf[bindAck.hdrsize():])                    
                    devlog("msrpc", "TCP: bindAck.ackresult=%d"%bindAck.ackresult)
                    if bindAck.ackresult==0x200: # failed 
                        devlog("msrpc", "Bind failed on %s"%endpoint)
                        raise DCEException, "DCE %s failed: Provider rejection" % keyword
                    devlog("msrpc", "Bind succeeded on %s"%endpoint)
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 

                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 

                except struct.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 

                except IndexError, msg:
                    raise DCEException, "DCE %s %s: %s" %(keyword, "Reciving ack failed",str(msg)) 
            elif self.localpipe:
                #local pipe...
                print "Local Pipe: NTLM chosen: *%s:%s*"%(self.username,self.password)
                self.ntlm=NTLM()
                try:
                    hostname=self.node.shell.getComputerName()
                    devlog("msrpc", "Hostname chosen: %s"%hostname)
                    self.ntlm.hostname=hostname
                except AttributeError:
                    print "No GetComputerName on this shellserver..."
                    import traceback
                    traceback.print_exc()
                    
                try:
                    ret,contextid=self.node.shell.GetContextID()
                    if ret:
                        devlog("msrpc", "Context ID Acquired: %x"%contextid)
                        self.ntlm.contextid=contextid
                    else:
                        devlog("msrpc","Context ID not aquired?!?")
                except AttributeError:
                    print "No GetContextID on this shellserver..."
                    import traceback
                    traceback.print_exc()    
                    
                #ntlm=msrpc.NTLM()
                self.ntlm.type=1
                #self.ntlm.flags=0xa0088207L
                #ntlm.set_user(self.username)
                #ntlm.set_password(self.password)
                self.ntlm.set_domain(self.domain)
                #self.ntlm.set_domain("WORKGROUP")
                self.ntlm.add_security_buffer(self.ntlm.domain)
                self.ntlm.add_security_buffer(self.ntlm.hostname)
                # sending TCP Bind (we need a UUID and a transfersyntax)
                bind=DCEBind(self.ntlm)
                bind.setUuid(self.UUID) 
                bind.setVersion(self.versionmajor, self.versionminor)
                bind.setTransferSyntax(self.transfersyntax)
                try:
                    self.s.sendall(bind.raw())
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Sending bind failed", str(msg)) 
                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Sending bind failed",str(msg)) 
                # Receive a Bind_ack with the challenge
                bindAck=DCEBind_ack(self.ntlm)
                try:
                    buf=self.s.recv(bindAck.hdrsize())
                    bindAck.hdrget(buf)
                    buf+=self.s.recv(bindAck.size()-bindAck.hdrsize())
                    bindAck.get(buf[bindAck.hdrsize():])
                    if bindAck.ackresult==2: # failed
                        raise DCEException, "DCE %s failed: Provider rejection" % keyword
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                except struct.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                except IndexError, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg))                     
                
                self.domainlist=bindAck.auth.list
                auth3=DCEAuth3(self.ntlm)
                auth3.set_auth(self.username, self.password)
                devlog("msrpc", "Sending auth3 packet")
                try:
                    #for localpipes
                    #1 or 0, not a timeout
                    self.s.set_wait(1)
                except:
                    pass
                
                try:
                    self.s.send(auth3.raw())

                    try:
                        #for localpipes
                        self.s.set_wait(1)
                    except:
                        pass
                    
                except socket.error, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Auth3 send failed",str(msg))                 
                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE %s %s: %s" % (keyword, "Auth3 send failed",str(msg))                 

                #Recv final packet
                #print "recv final packet"

                #try:
                    #buf=self.s.recv(bindAck.hdrsize())
                    #bindAck.hdrget(buf)
                    #buf+=self.s.recv(bindAck.size()-bindAck.hdrsize())
                    #bindAck.get(buf[bindAck.hdrsize():])
                    #if bindAck.ackresult==2: # failed
                        #raise DCEException, "DCE %s failed: Provider rejection" % keyword
                #except socket.error, msg:
                    #raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                #except struct.error, msg:
                    #raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                #except timeoutsocket.Timeout, msg:
                    #raise DCEException, "DCE %s %s: %s" % (keyword, "Reciving ack failed",str(msg)) 
                    
            # AUTHENTICATION FINISHED.
            # How do we know if it works? 
            # The next packet we send, will failed and error message will be 0x5 (unknown)
            self.keyword = keyword
            return 1
        
        elif keyword=="ncacn_ip_udp":
            self.ip, self.port = endpoint[endpoint.find(":")+1:].split("[")
            self.port=self.port.split("]")[0]

            #print "MSRPC SPLIT IP*PORT: %s:%s"% (self.ip, self.port)

            try:
                if self.getsock:
                    # XXX: still need to context switch getudpsock for IPv6 !!!
                    if ":" in self.ip:
                        self.s = self.getsock.getudpsock(AF_INET6=1)
                    else:
                        self.s = self.getsock.getudpsock()

                    #print "Got socket from remote host"

                else:
                    if ":" in self.ip:
                        #print "[!] MSRPC IPv6 UDP Connect ..."
                        self.s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 0)
                    else:            
                        self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM, 0)            

                sockaddr = (self.ip, int(self.port))
                if ":" in self.ip:
                    res = socket.getaddrinfo(self.ip, int(self.port), socket.AF_INET6, socket.SOCK_DGRAM)
                    sockaddr = res[0][4]
                ret = self.s.connect(sockaddr)
                
                if ret==-1:
                    raise DCEException, "DCE %s %s on port %d" % (keyword, "Connection failed",self.port)                     

            except socket.error, msg:
                raise DCEException, "DCE %s %s: %s" % (keyword, "Connection failed", str(msg)) 
            except timeoutsocket.Timeout, msg:
                raise DCEException, "DCE %s %s: %s" % (keyword, "Connection failed", str(msg)) 
            self.keyword=keyword
            return 1
        elif 0:
            # XXX: this code isn't alive, if it ever comes alive again, IPv6 support it !!!
            self.ip, self.port = endpoint.split(":")[1].split("[")
            self.port=self.port.split("]")[0]
            self.addr=(self.ip, int(self.port))
            try:
                if self.getsock:
                    self.s=self.getsock.getudpsock()
                else:
                    self.s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)            
            
            except socket.error, msg:
                raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Connection failed", str(msg)) 
            except timeoutsocket.Timeout, msg:
                raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Connection failed", str(msg)) 

            if not self.username and not self.password:
                bind=DCEBind()
                bind.setUuid(self.UUID) # MAPI
                bind.setTransferSyntax(transfersyntax)
                bind.setVersion(self.versionmajor, self.versionminor)

                try:
                    self.s.sendto(bind.raw(), self.addr)
                except socket.error, msg:
                    raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Sending bind failed", str(msg)) 

                bindAck=DCEBind_ack()

                try:
                    buf=self.s.recvfrom(bindAck.hdrsize())
                    bindAck.hdrget(buf)
                    buf+=self.s.recvfrom(bindAck.size()-bindAck.hdrsize())
                    bindAck.get(buf[bindAck.hdrsize():])                    

                    if bindAck.ackresult==0x200: # failed 
                        raise DCEException, "DCE ncacn_ip_udp failed: Provider rejection"
 
                except socket.error, msg:
                    raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Receiving ack failed",str(msg)) 

                except timeoutsocket.Timeout, msg:
                    raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Receiving ack failed",str(msg)) 

                except struct.error, msg:
                    raise DCEException, "DCE ncacn_ip_udp %s: %s" % ("Receiving ack failed",str(msg)) 
            
        else:
            print "Unknown keyword: %s"%keyword
        devlog('DCE::attemptConnect', "returning 0")
        return 0

    
    def call(self,opnum,buffer, authpadlen=0, noauth=0, response=0):
        """
        Returns either a zero , one, or a list of DCE Packets that the server
        sent us as a response (if response=1)
        """
        
        #no set_wait on local pipes for calls if we don't want a response!
        devlog("msrpc","RPC call on opnum %d"%opnum)
        if hasattr(self, "s") and hasattr(self.s, "set_wait"):
            self.s.set_wait(response)

        self.callid+=1
        if not self.localpipe and self.keyword=="ncacn_np":
            #print "named pipe call selected"
            devlog("msrpc","DCE::call() self.object=%s"%self.object)
            if not noauth:
                devlog("msrpc", "Call request with ntlm")
                req=DCERequest(self.ntlm)
            else:
                req=DCERequest()		
                
            req.set_opnum(opnum)
            req.set_authpadlen(authpadlen)
            req.setCallid(self.callid)

            dataleft = buffer
            FIRST_FRAG = 0x1
            LAST_FRAG  = 0x2

            if self.covertness > 5:
                MAXFRAGLENGTH = 50
            else:
                MAXFRAGLENGTH = 4280 - 40 # (auth +structure) 
                
            if self.covertness >= 10:
                MAXFRAGLENGTH = 1
                
            last  = 0
            first = 1

            while dataleft or first:
                fraglength= MAXFRAGLENGTH
                #print "Length of dataleft=%d"%len(dataleft)
                if len(dataleft) <= MAXFRAGLENGTH:
                    fraglength = len(dataleft)
                    last =1

                flags = 0
                if first:
                    #print "FIRST FRAG"
                    flags |= FIRST_FRAG
                    first = 0
                if last:
                    #print "LAST FRAG"
                    flags |= LAST_FRAG

                if self.object:
                    devlog("msrpc", "Self.object is set!")
                    flags |= 0x80 #object is sent...
                    req.object=self.object
                    
                req.setFlags(flags)
                req.set_stub(dataleft[:MAXFRAGLENGTH])
                dataleft = dataleft[MAXFRAGLENGTH:]                
                try:
                    #reliable send here
                    self.mysmb.write(req.raw())
                except socket.error, msg:
                    raise DCEException, "DCE ncacn_ip_np %s: %s" % ("Send packet failed",str(msg)) 

            if response:
                devlog("msrpc", "Getting packet from remote side in msrpc")
                sys.stdout.flush()
                return self.get_packets()
            return 1

            #old way!
            #result=self.mysmb.dcecall(opnum,buffer,self.callid,self.ntlm)
                
            #if response:
            #    return self.get_packet(result)
            #return 1
            
        elif self.keyword=="ncacn_ip_udp":
            activity = get_random_uuid()
            msrpcsend_udp(self.s, buffer, None, self.UUID, 1, activity, 0, self.sequence, idempotent=1, nofack=1)
            self.sequence += 1
            
        elif self.localpipe or self.keyword=="ncacn_ip_tcp" or self.keyword=="ncacn_http":
            if not self.s:
                print "[*] Trying to call on a DCE object that is not connected!"
                #give it a shot
                self.connect()

                
            if not noauth:
                devlog("msrpc", "Call request with ntlm")
                req=DCERequest(self.ntlm)
            else:
                req=DCERequest()		
            
            #req.set_stub(buffer)
            req.set_opnum(opnum)
            req.set_authpadlen(authpadlen)
            req.setCallid(self.callid)

            dataleft = buffer
            FIRST_FRAG = 0x1
            LAST_FRAG  = 0x2

            if self.covertness > 5:
                MAXFRAGLENGTH = 50
            else:
                MAXFRAGLENGTH = 4280 - 40 # (auth +structure) 
                
            if self.covertness >= 10:
                MAXFRAGLENGTH = 1
                
            last  = 0
            first = 1

            while dataleft or first:
                fraglength= MAXFRAGLENGTH
                #print "Length of dataleft=%d"%len(dataleft)
                if len(dataleft) <= MAXFRAGLENGTH:
                    fraglength = len(dataleft)
                    last =1

                flags = 0
                if first:
                    #print "FIRST FRAG"
                    flags |= FIRST_FRAG
                    first = 0
                if last:
                    #print "LAST FRAG"
                    flags |= LAST_FRAG

                if self.object:
                    devlog("msrpc", "Self.object is set!")
                    flags |= 0x80 #object is sent...
                    req.object=self.object
                    
                req.setFlags(flags)
                req.set_stub(dataleft[:MAXFRAGLENGTH])
                dataleft = dataleft[MAXFRAGLENGTH:]                
                try:
                    #reliable send here
                    self.s.sendall(req.raw())		
                except socket.error, msg:
                    raise DCEException, "DCE ncacn_ip_tcp %s: %s" % ("Send packet failed",str(msg)) 

            if response:
                return self.get_packets()
            return 1
            
        elif self.keyword=="":
            devlog("msrpc", "Not connected!")
        else:
            print "Unknown keyword!"
        return 0
    
    def get_packet(self, buf=""):
        """
        Used by call() to get the response from the remote server to our 
        request
        """
        devlog('DCE::get_packet', "keyword:%s buf:\n%s" % (self.keyword, shellcode_dump(buf)))
        if self.localpipe or self.keyword=="ncacn_ip_tcp" or  self.keyword=="ncacn_http":
            #print "GET PACKET CALLED len buf=%d"%len(buf)
            p=DCEPacket()

            try:
                hdr=self.s.recv(p.hdrsize())
                devlog("msrpc", "Hdr: %s"%hexprint(hdr))
                p.hdrget(hdr)
                buf=self.s.recv(p.size()-p.hdrsize())
                #print ("Recv length of buf = %d"%len(buf))
            except socket.error, msg:
                #print "socket error"
                raise DCEException, "DCE %s %s: %s" % (self.keyword,"Receive packet failed",str(msg)) 
            except struct.error, msg:
                #print "struct error"
                raise DCEException, "DCE %s %s: %s" % (self.keyword,"Receive packet failed",str(msg)) 
            except timeoutsocket.Timeout, msg:
                #print "timeoutsocket error - buf len = %d wanted %d"%(len(buf),p.size()-p.hdrsize())
                raise DCEException, "DCE %s %s: %s" % (self.keyword,"Receive packet failed (timeout)",str(msg)) 

        elif self.keyword=="ncacn_np":

            p=DCEPacket()
            #devlog('DCE::get_packet', "keyword==ncacn_np> hdrsize=%s smb:%s smb.read:%s" % \
            #    (p.hdrsize(), self.mysmb, self.mysmb.read))
            buf=self.mysmb.read(p.hdrsize())
            devlog('DCE::get_packet', "keyword==ncacn_np> buf:\n%s" % shellcode_dump(buf))
            try:
                hdr=buf[:p.hdrsize()]
                p.hdrget(hdr)
                devlog("msrpc", "get_packet() size is %s"%p.size())
                buf=self.mysmb.read(p.size()-p.hdrsize())
            except struct.error, msg:
                raise DCEException, "DCE ncacn_np %s: %s" % ("Receive packet failed",str(msg)) 

        devlog("msrpc", "Packetype: %x"%p.getPacketType())
        if p.getPacketType()==DCE_RESPONSE:
            try:
                p=DCEResponse()
                p.hdrget(hdr)	
                p.get(buf)
            except struct.error, msg:
                raise DCEException, "DCE %s %s: %s" % (self.keyword, "Receive packet failed",str(msg)) 
            #print "returning p! p.stub=%d"%len(p.stub)
            return p
        elif p.getPacketType()==DCE_FAIL:
            ncaerrors={}
            ncaerrors[0x1c00001b]="nca_s_fault_remote_no_memory"
            ncaerrors[0x1c010003]="Unknown interface"
            ncaerrors[5]="Authentication failed"
            ncaerrors[0x1c010014]="nca_server_too_busy"
            ncaerrors[0x1c010002]="nca_op_rng_error - opnum too high!"
            devlog("msrpc", "PacketType DCE FAIL returned")
            devlog('DCE::get_packet', "DCE_FAIL> buflen=%s" % len(buf))
            assert len(buf) > 8, "buflen=%d NOT POSSIBLE" % len(buf)
            errorcode=istr2int(buf[-8:-4])
            p.errorcode=errorcode
            devlog("msrpc", "Error code: %x"%errorcode)
            if errorcode in ncaerrors:
                devlog("msrpc", "Error: %s"%ncaerrors[errorcode])
            # FAILED PACKET NOT IMPLEMENTED YET
            raise DCEException, "DCE %s %s: %s %x" % (self.keyword, "Received packet failed", "A failed packet received",errorcode) 
        return p
   

if __name__=="__main__":
    #ret=smb_nt_64bit_time(binstring("e05eae8a1b6fc401")) #should be Jul 21 2004 08:09:15
    print "Starting smb server"
    mysmbserver=SMBServer("0.0.0.0",445)
    print "Accepting"
    mysmbserver.accept()
    if 1:
        while mysmbserver.handle():
            print "Handled."
        time.sleep(1)
    print "Sleeping"
    time.sleep(10)
