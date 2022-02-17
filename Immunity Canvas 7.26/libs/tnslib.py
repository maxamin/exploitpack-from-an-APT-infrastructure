#! /usr/bin/env python
        
#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information

VERSION= "1.0"

NOTES="""
This is the basic TNS lib. It will be expanded to be able to run and parse
the full set of TNS packets in support of Oracle functionality. 
"""

import socket
import struct

# CANVAS modules
from exploitutils import *

# TNS CONNECT service options bitmask
TNS_SOPT_BROKEN_CONNECT_NOTIFY=(1<<13)
TNS_SOPT_PACKET_CHECKSUM=(1<<12)
TNS_SOPT_HEADER_CHECKSUM=(1<<11)
TNS_SOPT_FULL_DUPLEX=(1<<10)
TNS_SOPT_HALF_DUPLEX=(1<<9)
TNS_SOPT_DIRECT_IO_TO_TRANSPORT=(1<<4)
TNS_SOPT_ATTENTION_PROCESSING=(1<<3)
TNS_SOPT_CAN_RECEIVE_ATTENTION=(1<<2)
TNS_SOPT_CAN_SEND_ATTENTION=(1<<1)
# unknown option, appears set on default
TNS_SOPT_BLANK=(1)

# TNS CONNECT NT protocol characteristics bitmask
TNS_NT_HANGON_TO_LISTENER_CONNECT=(1<<15)
TNS_NT_CONFIRMED_RELEASE=(1<<14)
TNS_NT_TDU_BASED_IO=(1<<13)
TNS_NT_SPAWNER_RUNNING=(1<<12)
TNS_NT_DATA_TEST=(1<<11)
TNS_NT_CALLBACK_IO_SUPPORTED=(1<<10)
TNS_NT_ASYNC_IO_SUPPORTED=(1<<9)
TNS_NT_PACKET_ORIENTED_IO=(1<<8)
TNS_NT_CAN_GRANT_CONNECTION_TO_ANOTHER=(1<<7)
TNS_NT_CAN_HANDOFF_CONNECTION_TO_ANOTHER=(1<<6)
TNS_NT_GENERATE_SIGIO_SIGNAL=(1<<5)
TNS_NT_GENERATE_SIGPIPE_SIGNAL=(1<<4)
TNS_NT_GENERATE_SIGURG_SIGNAL=(1<<3)
TNS_NT_URGENT_IO_SUPPORTED=(1<<2)
TNS_NT_FULL_DUPLEX_IO_SUPPORTED=(1<<1)
TNS_NT_TEST_OPERATION=(1)

# TNS CONNECT flags bitmask
TNS_CONNECTFLAGS_SERVICES_REQUIRED=(1<<4)
TNS_CONNECTFLAGS_SERVICES_LINKED_IN=(1<<3)
TNS_CONNECTFLAGS_SERVICES_ENABLED=(1<<2)
TNS_CONNECTFLAGS_INTERCHANGE_IS_INVOLVED=(1<<1)
TNS_CONNECTFLAGS_SERVICES_WANTED=(1)
# unknown option, appears set on default
TNS_CONNECTFLAGS_BLANK=(1<<6)

# TNS (ethereal) packet types
TNS_TYPE_CONNECT=1
TNS_TYPE_ACCEPT=2
TNS_TYPE_ACK=3
TNS_TYPE_REFUSE = 4
TNS_TYPE_REDIRECT=5
TNS_TYPE_DATA=6
TNS_TYPE_NULL=7
TNS_TYPE_ABORT=9
TNS_TYPE_RESEND=11
TNS_TYPE_MARKER=12
TNS_TYPE_ATTENTION=13
TNS_TYPE_CONTROL=14
TNS_TYPE_MAX=19

TNS_TYPE_OFFSET = 4

class TNSCONNECT:
    def __init__(self):
        self.version=310
        self.version_compatible=300
        self.service_options=0
        self.session_data_unit_size=0x0800
        self.max_transmission_data_unit_size=0x7FFF
        self.NT_protocol_characteristics=0x0000
        self.line_turnaround_value=0
        self.value_of_1_in_hardware=0x0001
        self.connect_data_len=0
        self.connect_data_offset=0x3a
        self.max_receivable_connect_data=512
        self.connect_flags0=0
        self.connect_flags1=0
        self.trace_cross_facility1=0
        self.trace_cross_facility2=0
        self.trace_unique_connection_id=0x0000000000000000
        self.padding=0x0000000000000000
        self.connect_data=""
        return

    # attach TNS CONNECT header to connect string
    def addConnectHeader(self,cstring):   
        l=len(cstring)
        fs=("!HHHHHHHHHHLBBLLdd%ss"% l)
        ret=struct.pack(fs,self.version,self.version_compatible,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.NT_protocol_characteristics,self.line_turnaround_value,self.value_of_1_in_hardware,len(cstring),self.connect_data_offset,self.max_receivable_connect_data,self.connect_flags0,self.connect_flags1,self.trace_cross_facility1,self.trace_cross_facility2,self.trace_unique_connection_id,self.padding,cstring)
        return(ret)    
    
    def getVersionCommand(self):
        connect_string = "(CONNECT_DATA="
        connect_string +=     "(COMMAND=VERSION)"
        connect_string += ")"        
        self.connect_data += connect_string
        self.connect_data_len = len(connect_string)
        fs=("!HHHHHHHHHHLBBLLdd%ss" %self.connect_data_len)
        ret=struct.pack(fs,self.version,self.version_compatible,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.NT_protocol_characteristics,self.line_turnaround_value,self.value_of_1_in_hardware,self.connect_data_len,self.connect_data_offset,self.max_receivable_connect_data,self.connect_flags0,self.connect_flags1,self.trace_cross_facility1,self.trace_cross_facility2,self.trace_unique_connection_id,self.padding,self.connect_data)
        return(ret)
 
    def getStatusCommand(self):
        connect_string = "(CONNECT_DATA="
        connect_string +=     "(COMMAND=STATUS)"
        connect_string += ")"        
        self.connect_data += connect_string
        self.connect_data_len = len(connect_string)
        fs=("!HHHHHHHHHHLBBLLdd%ss" %self.connect_data_len)
        ret=struct.pack(fs,self.version,self.version_compatible,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.NT_protocol_characteristics,self.line_turnaround_value,self.value_of_1_in_hardware,self.connect_data_len,self.connect_data_offset,self.max_receivable_connect_data,self.connect_flags0,self.connect_flags1,self.trace_cross_facility1,self.trace_cross_facility2,self.trace_unique_connection_id,self.padding,self.connect_data)
        return(ret)

    def getDatabaseNameConnectReq(self,host,name,port):
        constr = "(DESCRIPTION="
        constr += "(ADDRESS="
        constr += "(PROTOCOL=TCP)(HOST="
        constr += host
        constr += ")(PORT=%s))"%port
        constr += "(CONNECT_DATA="
        constr += name
        constr += "(CID=(PROGRAM=C:\oracle\ora81\bin\SQLPLUSW.EXE)"
        constr += "(HOST="
        constr += "123456-FAKEMCNM"
        constr += ")(USER=noone))))"    
        self.connect_data += constr
        self.connect_data_len = len(constr)
        fs=("!HHHHHHHHHHLBBLLdd%ss" %self.connect_data_len)
        ret=struct.pack(fs,self.version,self.version_compatible,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.NT_protocol_characteristics,self.line_turnaround_value,self.value_of_1_in_hardware,self.connect_data_len,self.connect_data_offset,self.max_receivable_connect_data,self.connect_flags0,self.connect_flags1,self.trace_cross_facility1,self.trace_cross_facility2,self.trace_unique_connection_id,self.padding,self.connect_data)
        return(ret)

    def getDatabaseNameConnectReqv2(self,host,name,port):
        constr = "(DESCRIPTION="
        constr += "(ADDRESS="
        constr += "(PROTOCOL=TCP)(HOST="
        constr += host
        constr += ")(PORT=%s))"%port
        constr += "(CONNECT_DATA="
        constr += name
        constr += "(CID=(PROGRAM=C:\\Program Files\\Oracle\\jre\\1.1.7\\bin\\jrew.exe)"
        constr += "(HOST="
        constr += "JBONEPC"
        constr += ")(USER=justine))))"   
        
        self.NT_protocol_characteristics=0xa30a
        self.value_of_1_in_hardware=0x0100
        self.connect_data += constr
        self.connect_data_len = len(constr)
        fs=("!HHHHHHHHHHLBBLLHHHHd%ss" %self.connect_data_len)
        self.connect_flags0=0x41
        self.connect_flags1=0x41
        d1 = 0x0000
        d2 = 0x0e80
        d3 = 0x0003
        d4 = 0xd45f
        ret=struct.pack(fs,self.version,self.version_compatible,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.NT_protocol_characteristics,self.line_turnaround_value,self.value_of_1_in_hardware,self.connect_data_len,self.connect_data_offset,self.max_receivable_connect_data,self.connect_flags0,self.connect_flags1,self.trace_cross_facility1,self.trace_cross_facility2,d1,d2,d3,d4,self.padding,self.connect_data)
        return(ret)
    
    
    
    
class TNSDATA:
    
    #not sure what these really mean but they seem to follow some kind of pattern
    TNS_DATA_TYPE_ONE=1
    TNS_DATA_TYPE_TWO=2
    TNS_DATA_TYPE_THREE=3
    TNS_DATA_TYPE_FOUR=4
    TNS_DATA_TYPE_FIVE=5
    TNS_DATA_TYPE_SIX=6
    TNS_DATA_TYPE_SEVEN=7
    TNS_DATA_TYPE_EIGHT=8
    TNS_DATA_TYPE_NINE=9
    TNS_DATA_TYPE_SNS=0xde #really it looks like SNS are are different TNS type completely (they start with deadbeef)
    
    
    def __init__(self):
        self.data_flag=0x0000
        self.type = 0x00
        self.data = ""
        return
    
    def parseDataLayer(self,data): 
        self.data_flag = struct.unpack("H",data[:2])[0]
        if self.data_flag:
            return
        self.type = struct.unpack("B",data[2:3])[0]
        if len(data)>3:
            self.data = data[3:]
        return  
        
    def getData(self):
        l=len(self.data)
        fs=("!HB%ss"% l)
        ret=struct.pack(fs,self.data_flag,self.type,self.data)
        return(ret)
        
    def WINNT(self):
        self.type = TNSDATA.TNS_DATA_TYPE_ONE
        self.data = "\x06\x05\x04\x03\x02\x01\x00"
        self.data +="IBMPC/WIN_NT-8.1.0"
        self.data +="\x00"
        return
    
    def LESS(self,version):
        self.type = TNSDATA.TNS_DATA_TYPE_TWO
        if ((version == TNS.TNS_V9) or (version == TNS.TNS_V10)): 
            #might not have to do this distinction
            self.data ="\xb2\x00\xb2\x00\x02" 
        else:
            self.data ="\x1f\x00\x1f\x00\x00" 
        self.data +="\x02\x06\x01\x02\x02\x01\x80\x00" 
        self.data +="\x00\x00\x3c\x3c\x3c\x80\x00\x00" 
        self.data +="\x00"
        return()


    def LOGINv2(self,uname,version):
        self.type = TNSDATA.TNS_DATA_TYPE_THREE
 
        #v2 version has different packet structure - more binary before strings
        #no use of header strings
        #as far as I can tell if you do v2 now you do v2 for the password packet also
        
        self.data = "\x52\x02\x50\xd7\xd4"
        self.data += "\x02"
        
        self.data += struct.pack("B", len(uname))
        
        #somewhere in this stuff refers to offsets to strings below, or maybe overall size or something - annoying
        self.data += "\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data += "\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data += "\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data += "\x00\x00\x00\xa6\x07\xdb"
        
        self.data += "\x02\x07\x00\x00\x00\xef\x08\xdb"
        self.data += "\x02\x12\x00\x00\x00\xa5\x08\xdb"
        self.data += "\x02\x07\x00\x00\x00\xa0\x0f\x00"
        
        self.data += "\x00\x65\x09\xdb"
        self.data += "\x02\x09\x00\x00\x00\x75\x09\xdb"
        self.data += "\x02\x08\x00\x00"
        
        self.data += "\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data += "\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data += "\x00\xdc\x03\xdb"
        self.data += "\x02\x11\x00\x00\x00\xec\x03\xdb"
        
        self.data += "\x02"
        
        self.data += struct.pack("B", len(uname))
        self.data += uname  #<<username

        self.data +="\x07"
        self.data +="1234567"    #   machine name

        self.data +="\x12"
        self.data +="WORKGROUP\98765456" 
        
        self.data += "\x07"
        self.data += "noone12"
        
        self.data +="\x09"
        self.data +="3208:3744"

        self.data +="\x08"
        self.data +="jrew.exe" 

        return()



    def PWDv2(self,version,uname,encpwd):
        self.type = TNSDATA.TNS_DATA_TYPE_THREE

        self.data ="\x51\x03\x50\xd7\xd4"
        
        self.data +="\x02"
        self.data += struct.pack("B", len(uname)) #this might just be a 6 always
        self.data +="\x00\x00\x00\x3e"
        
        self.data +="\xbf\xdc"
        self.data +="\x02\x11\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data +="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        
        self.data +="\x00\xd6\xbf\xdc"

        self.data +="\x02\x07\x00\x00\x00\x15\xc1\xdc"
        self.data +="\x02\x12\x00\x00\x00\xd5\xc0\xdc"
        self.data +="\x02\x07\x00\x00\x00\xa0\x0f\x00"

        self.data +="\x00\x95\xc1\xdc"

        self.data +="\x02\x08\x00\x00\x00\xa5\xc1\xdc"
        self.data +="\x02\x08\x00\x00"

        self.data +="\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data +="\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        self.data +="\x00\x00\x00\x00\x00"

        self.data += struct.pack("B", len(uname))
        self.data +=uname  #<<username

        self.data +="\x11"
        self.data += encpwd
        self.data +="\x30"

        self.data +="\x07"
        self.data +="1234567"    #   machine name

        self.data +="\x12"
        self.data +="WORKGROUP\98765456" 

        self.data += "\x07"
        self.data += "noone12"

        self.data +="\x08"
        self.data +="208:3744"

        self.data +="\x08"
        self.data +="jrew.exe" 
   
        return()

    def PWDv1(self,version,uname,encpwd):
        self.type = TNSDATA.TNS_DATA_TYPE_THREE

        self.data ="\x73\x03"
        
        #either of these seem to work..
        #data += "\x9c\xf5\xe5"  #v8 & v9
        self.data += "\x64\x80\x53" #v10

        #just an observation, might not be necessary...
        if ((version == TNS.TNS_V8) or (version == TNS.TNS_V9)):
            self.data +="\x00" #v8 & v9
        else:
            self.data += "\x01" #v10
        
        self.data += struct.pack("B", len(uname))
        self.data +="\x00\x00\x00\x01"
        self.data += "\x01\x00" 
        
        #either of these seem to work..
        #self.data +="\x00\x90\xe4\x12" #v8 & v9
        self.data += "\x00\xa4\xe3\x12" #v10
        
        self.data += "\x00\x07\x00\x00" 
        
        #either of these seem to work..
        #self.data +="\x00\xfc\xe0\x12\x00\xac\xe6\x12" #v8 & v9
        self.data += "\x00\x10\xe0\x12\x00\xc0\xe5\x12" #v10
        
        if ((version == TNS.TNS_V9) or (version == TNS.TNS_V10)): #v9 & 10 change in format of auth packet
            self.data += struct.pack("!H",len(uname))
        else:
            self.data += "\x00" #v8
            
        self.data +=uname  #<<username
        
        self.data +="\x0d\x00\x00\x00\x0d" #length fields
        self.data +="AUTH_PASSWORD"
        self.data +="\x11\x00\x00\x00\x11" #!!! len cld this change?
        self.data += encpwd

        #just an observation, might not be necessary...
        if ((version == TNS.TNS_V8) or (version == TNS.TNS_V9)):
            self.data += "\x31" # !!! does this change?
        else:
            self.data += "\x30" # !!! does this change?
                

        self.data += "\x00\x00\x00\x00"
        
        self.data +="\x0d\x00\x00\x00\x0d" #length fields
        self.data +="AUTH_TERMINAL"

        self.data +="\x0f\x00\x00\x00\x0f"
        self.data +="123456-FAKEMCNM"    #   machine name

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x0f\x00\x00\x00\x0f"
        self.data +="AUTH_PROGRAM_NM"

        self.data +="\x0c\x00\x00\x00\x0c"
        self.data +="SQLPLUSW.EXE" 

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x0c\x00\x00\x00\x0c"
        self.data +="AUTH_MACHINE"

        self.data +="\x1a\x00\x00\x00\x1a"
        self.data +="WORKGROUP\987654-notanypc" 

        self.data +="\x00\x00\x00\x00\x00" 
        self.data +="\x08\x00\x00\x00\x08"
        self.data +="AUTH_PID"

        self.data +="\x09\x00\x00\x00\x09"
        self.data +="3208:3744"

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x08\x00\x00\x00\x08"
        self.data +="AUTH_ACL"

        self.data +="\x04\x00\x00\x00\x04"
        self.data +="4000"

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x12\x00\x00\x00\x12" 
        self.data +="AUTH_ALTER_SESSION" 

        datastr= "ALTER SESSION SET NLS_LANGUAGE= 'AMERICAN' NLS_TERRITORY= 'AMERICA' NLS_CURRENCY= '$' NLS_ISO_CURRENCY= 'AMERICA' NLS_NUMERIC_CHARACTERS= '.,' NLS_CALENDAR= 'GREGORIAN' NLS_DATE_FORMAT= 'DD-MON-RR' NLS_DATE_LANGUAGE= 'AMERICAN'  NLS_SORT= 'BINARY' TIME_ZO\xe5NE= '-05:00' NLS_DUAL_CURRENCY = '$' NLS_TIME_FORMAT = 'HH.MI.SSXFF AM' NLS_TIMESTAMP_FORMAT = 'DD-MON-RR HH.MI.SSXFF AM' NLS_TIME_TZ_FORMAT = 'HH.MI.SSXFF AM TZH:TZM' NLS_TIMESTAMP_TZ_FORMAT = 'DD-MON-RR HH.MI.SSXFF AM TZH:TZM'"
        self.data += intel_order(len(datastr))+"\xfe\xff"
        self.data += datastr

        self.data +="\x00\x00\x00\x00\x00\x00"
        return()

           
    def LOGINv1(self,uname,version):
        #long version has different packet structure - lengths are before each string

        self.type = TNSDATA.TNS_DATA_TYPE_THREE

        self.data ="\x76\x02" 
        self.data += "\x64\x90\x53" 

        self.data +="\x01" 
        self.data += struct.pack("B", len(uname))
        self.data +="\x00\x00\x00\x01\x00\x00" 
        self.data +="\x00\xe0\xd7\x12\x00\x04\x00\x00" 
        self.data +="\x00\xb0\xd5\x12\x00\x9c\xd9\x12" 
        
        if (version == TNS.TNS_V9): #v9 change in format of auth packet
            self.data += struct.pack("!H",len(uname))
        else:
            self.data += "\x00" #v8
            
        self.data +=uname  #<<username
        
        self.data +="\x0d\x00\x00\x00\x0d" #length fields
        self.data +="AUTH_TERMINAL"
        
        self.data +="\x0f\x00\x00\x00\x0f"
        self.data +="123456-FAKEMCNM"    #   machine name

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x0f\x00\x00\x00\x0f"
        self.data +="AUTH_PROGRAM_NM"

        self.data +="\x0c\x00\x00\x00\x0c"
        self.data +="SQLPLUSW.EXE" 

        self.data +="\x00\x00\x00\x00" 
        self.data +="\x0c\x00\x00\x00\x0c"
        self.data +="AUTH_MACHINE"

        self.data +="\x1a\x00\x00\x00\x1a"
        self.data +="WORKGROUP\987654-notanypc" 

        self.data +="\x00\x00\x00\x00\x00" 
        self.data +="\x08\x00\x00\x00\x08"
        self.data +="AUTH_PID"

        self.data +="\x09\x00\x00\x00\x09"
        self.data +="3208:3744"

        self.data +="\x00\x00\x00\x00"
        return()

   

    def SNS(self,version):
        #starts with 0xdeadbeef
        self.type = TNSDATA.TNS_DATA_TYPE_SNS
        self.data ="\xad\xbe\xef"
        
        self.data += "\x00\x8f" 
        self.data +="\x08\x10\x60\x00\x00\x04\x00\x00" 
        self.data +="\x04\x00\x03\x00\x00\x00\x00\x00" 
        self.data +="\x04\x00\x05\x08\x10\x60\x00\x00"
        self.data +="\x08\x00\x01\x00\x00"
        if (version == TNS.TNS_V10): #v10 NOT SURE I ACTUALLY HAVE TO MAKE THESE DISTINCTIONS?
            self.data += "\x11\xfc\xbd\xc1\xbd\xf3"
        else:
            self.data += "\x04\x80\xb2\x5d\x13\x5f" #v8 & v9?
        self.data +="\x00\x12\x00\x01"
        self.data +="\xde\xad\xbe\xef\x00\x03\x00\x00\x00" 
        self.data +="\x04\x00\x04\x00\x01\x00\x01\x00" 
        self.data +="\x02\x00\x01\x00\x03\x00\x00\x00" 
        self.data +="\x00\x00\x04\x00\x05\x08\x10\x70" 
        self.data +="\x00\x00\x02\x00\x03\xe0\xe1\x00" 
        self.data +="\x02\x00\x06\xfc\xff\x00\x02\x00" 
        self.data +="\x02\x00\x00\x00\x00\x00\x04\x00" 
        self.data +="\x05\x08\x10\x70\x00\x00\x09\x00" 
        self.data +="\x01\x00\x01\x08\x02\x03\x06\x0a" 
        self.data +="\x0c\x0b\x00\x03\x00\x02\x00\x00" 
        self.data +="\x00\x00\x00\x04\x00\x05\x08\x10" 
        self.data +="\x70\x00\x00\x03\x00\x01\x00\x03" 
        self.data +="\x01"
        return()
    
    
    
class TNSREFUSE:
    
    def __init__(self):
        self.reason_user=0
        self.reason_system=0
        self.refuse_data_len=0
        self.refuse_data=""
        return

    # parse accept header
    def parseRefuseLayer(self,rdata): 
        fs=(">BBH")
        (self.reason_user,self.reason_system,self.refuse_data_len) = struct.unpack(fs,rdata[:struct.calcsize(fs)])
        self.refuse_data = rdata[struct.calcsize(fs):struct.calcsize(fs)+self.refuse_data_len]
#        print 'refuse_data:',self.refuse_data
 #need to add code to get refuse data from following packets a la acceptdata       
        return   
    
    
    
class TNSACCEPT:
    
    def __init__(self):
        self.version=310
        self.service_options=0
        self.session_data_unit_size=0x0800
        self.max_transmission_data_unit_size=0x7FFF
        self.value_of_1_in_hardware=0x0001
        self.accept_data_length=0
        self.accept_data_offset=0x3a
        self.connect_flags0=0
        self.connect_flags1=0
        self.padding=0x0000000000000000
        self.accept_data=""
        return

    # parse accept header
    def parseAcceptLayer(self,adata): 
        fs=(">HHHHHHHBBd")
        assert len(adata) >= struct.calcsize(fs), "malformed layer2 packet: size=%d data=%s" % (len(adata), prettyhexprint(adata))
        (self.version,self.service_options,self.session_data_unit_size,self.max_transmission_data_unit_size,self.value_of_1_in_hardware,self.accept_data_length,self.accept_data_offset,self.connect_flags0,self.connect_flags1,self.padding) = struct.unpack(fs,adata[:struct.calcsize(fs)])
        #print 'accdataoffset: ',self.accept_data_offset
        self.accept_data = adata[struct.calcsize(fs):struct.calcsize(fs)+self.accept_data_length]
        #print 'acceptdata:',self.accept_data
        return   

class TNSREDIRECT:
    
    def __init__(self):
        self.data_length=0
        self.redirect_data=""
        return

    # parse accept header
    def parseRedirectLayer(self,rdata): 
#        print 'rdata',rdata
        self.data_length = struct.unpack("!H",rdata[:2])[0]
#        print 'length:',self.data_length
        self.redirect_data = rdata[2:self.data_length+2]
 #       print 'redirect_data:',self.data_length, self.redirect_data
        return   
    
    
    
class TNS:

    # TNS (ethereal) packet types
    TNS_TYPE_CONNECT=1
    TNS_TYPE_ACCEPT=2
    TNS_TYPE_ACK=3
    TNS_TYPE_REFUSE = 4
    TNS_TYPE_REDIRECT=5
    TNS_TYPE_DATA=6
    TNS_TYPE_NULL=7
    TNS_TYPE_ABORT=9
    TNS_TYPE_RESEND=11
    TNS_TYPE_MARKER=12
    TNS_TYPE_ATTENTION=13
    TNS_TYPE_CONTROL=14
    TNS_TYPE_MAX=19
    
    TNS_TYPE_OFFSET = 4
    
    """
    TNS_V9_OPTIONS=[0x09001101,0x09000000,0x09001000,9]
    TNS_V10_OPTIONS=[0x0A100200,0x0A000000,0x0A100000,10]
    TNS_V8_OPTIONS=[0x08107000,0x08000000,0x08100000,8]
    """
    TNS_V73=0x02303000
    TNS_V7=TNS_V73     # FIXME
    TNS_V8=0x08107000
    TNS_V9=0x09001101
    TNS_V10=0x0A100200
    TNS_V11=0x0b100600
    TNS_VUNKNOWN=0x0
    
    def __init__(self):
        self.packet_length=0
        self.packet_checksum=0
        self.packet_type=0
        self.reserved_byte=0
        self.header_checksum=0
        self.tns_data=""        
        return
    
    def getVSNNUM(self,info):
        #7.3 is (VSNNUM=36712448)  = 0x02303000
        #8i  is	(VSNNUM=135294976) = 0x08107000
        #9   is (VSNNUM=150999297) = 0x09001101
        import re
        res = re.search("\(VSNNUM=([0-9]{1,10})\)", info)
        if not res:
            print "can not find VSNNUM in data: %s" % prettyhexprint(info)
            return 0
        vsnstr = res.groups()[0]
        vsnnum = int(vsnstr)
        devlog('tnslib::VSNNUM', "VSNNUM=%s 0x%08x" %  (vsnstr, vsnnum))
        return vsnnum
    
    def assignVersion(self,vsnnum):
        print "VSNNUM %8.8x"%(vsnnum)
        vsnnum >>= 24
        vsnnum &= 0xff #strip off first byte
        # WARNING: assuming version=7 for vsnnum < 8
        if vsnnum < 8:
            return TNS.TNS_V7
        elif vsnnum == 8:
            return TNS.TNS_V8
        elif vsnnum == 9:
            return TNS.TNS_V9
        elif vsnnum == 10:
            return TNS.TNS_V10
        elif vsnnum == 11:
            return TNS.TNS_V11
        # something bad here
        print "unknown VSNNUM %s, can not find VERSION" % (str(vsnnum))
        return TNS.TNS_VUNKNOWN
        
        """
        if 0: #old way
            if vsnnum in TNS.TNS_V8_OPTIONS:
                return TNS.TNS_V8
            if vsnnum in TNS.TNS_V9_OPTIONS:
                return TNS.TNS_V9           
            if vsnnum in TNS.TNS_V10_OPTIONS:
                return TNS.TNS_V10
        """


    # attach TNS header data
    def addTNSHeaderv2(self,type,data):  
        print "adding header to data"
        l=len(data)
        print "size of data is %d"%l
        fs=(">HHBBH%ss"% l)
        l = struct.calcsize(fs)
        print "size of tns pkt is: %d"%l
        ret=struct.pack(fs,l,self.packet_checksum,type,self.reserved_byte,self.header_checksum,data)
        return(ret)          
    
    # attach TNS header data
    def addTNSHeader(self,type,data):   
        l=len(data)
        fs=(">HHBBH%ss"% l)
        ret=struct.pack(fs,struct.calcsize(fs),self.packet_checksum,type,self.reserved_byte,self.header_checksum,data)
        return(ret)    

    # parse accept header
    def parseTNSLayer(self,tnspkt): 
#        print 'parsing TNSPacket:',tnspkt
        fs=(">HHBBH") #header alone
        try:
            (self.packet_length,self.packet_checksum,self.packet_type,self.reserved_byte,self.header_checksum) = struct.unpack(fs,tnspkt[:struct.calcsize(fs)])
        except:
            print("error unpacking TNS packet? Packet: %s"% tnspkt)
        hdrsize = struct.calcsize(fs)
        self.tns_data = tnspkt[hdrsize:self.packet_length]
        return   
    
    def isAccept(self,data):
        type = struct.unpack("B",data[TNS_TYPE_OFFSET])
        return (type[0] == TNS_TYPE_ACCEPT)


    def isRedirect(self,data):
        type = struct.unpack("B",data[TNS_TYPE_OFFSET])
        return (type[0] == TNS_TYPE_REDIRECT)
    
    def isResend(self,data):
        type = struct.unpack("B",data[TNS_TYPE_OFFSET])
        return (type[0] == TNS_TYPE_RESEND)


   #given data, send data request
    def sendDataRequest(self,s,data):
        pkt = self.addTNSHeader(TNS_TYPE_DATA,data)
        try:
            s.sendall(pkt)
        except:
            print 'Error sending TNS Data request'
        return

    # socket, raw command    
    def sendRawCommand(self,s,cdata):
        pkt = self.buildRawCommand(cdata)
        s.sendall(pkt)        
        return

    #socket
    def recvRawData(self,s):
        rdata = []
        buf = s.recv(1024)
        while buf:
            rdata.append(buf)
            try:
                buf = s.recv(1024)
            except timeoutsocket.Timeout:
                buf = 0
        rdata="".join(rdata)
        return rdata
    
    def recvAcceptData(self,s,tnsdata):
        #print("tnsdata:%s"%tnsdata)
        #ERROR - need to include data from pkt1
        layer2 = TNSACCEPT()
        layer2.parseAcceptLayer(tnsdata)
        #accdata = ""
        
        accdata = layer2.accept_data
        #print 'accept data: ',accdata
        
        #if accept data exists and unknown flag in service options is set, accept data follows:
        if (layer2.accept_data_length > 0) and (layer2.service_options == 0x0001):

           #accept data seems to spans multiple tns data packets and goes until we recv an eof in data_flag
           self.recvTNSPkt(s)
           if (self.packet_type == TNS.TNS_TYPE_DATA):
               layer2 = TNSDATA()
               layer2.parseDataLayer(self.tns_data)
               accdata += layer2.data
               stop = layer2.data_flag
               while not stop:
                   self.recvTNSPkt(s)
                   if (self.packet_type == TNS.TNS_TYPE_DATA):
                       layer2.parseDataLayer(self.tns_data)
                       accdata += layer2.data
                       stop = layer2.data_flag      

        #print 'complete accept data: ',accdata
        return accdata


    #same as recvrawdata but check length
    def recvTNSPkt(self,s):
   #     this is a mess needs to be cleaned up
        try:
            rdata = s.recv(8)
        except:
            print("TNSLib Warning: Error recving TNS Packet (timeout?)")
            return 0

        if (len(rdata)>7):
            self.parseTNSLayer(rdata) #get packet length
        elif not rdata:
            print ("TNSLib Warning: No data recvd (FIN?)")
            return 0
        else:
            print("TNSLib Warning: Only recvd %d bytes instead of 8 byte TNS header"%len(rdata))
            return 0
        
        while len(rdata)<self.packet_length:
            try:
                buf = s.recv(1)
            except timeoutsocket.Timeout:
                buf = 0
            rdata+=buf
   
        self.parseTNSLayer(rdata)
        return 1

    
    # service options mask, nt protocol mask, connection flags, raw command
    def buildRawCommand(self, cdata, sopt=0x0000, nt=0x0000, conflags=0x00):
        pkt = ""
        
        offset = 0x0000
        
        # TNS Header
        pkt += struct.pack("!H", 0x0000) # !!! packet len
        pkt += struct.pack("!H", 0x0000) # packet checksum
        pkt += struct.pack("B", TNS_TYPE_CONNECT) # packet type
        pkt += struct.pack("B", 0x00) # reserved byte
        pkt += struct.pack("!H", 0x0000) # header checksum

        # TNS connect
        pkt += struct.pack("!H", 0x0136) # version (310)
        pkt += struct.pack("!H", 0x012C) # version compatible (300)

        pkt += struct.pack("!H", sopt) # service options bitmask
        pkt += struct.pack("!H", 0x0800) # session data unit
        pkt += struct.pack("!H", 0x7FFF) # max transmission data unit size

        pkt += struct.pack("!H", nt) # NT protocol characteristics mask
        pkt += struct.pack("!H", 0x0000) # line turnaround value
        pkt += struct.pack("!H", 0x0001) # value of 1 in hardware
        pkt += struct.pack("!H", len(cdata)) # !!! len of connect data
        pkt += struct.pack("!H", 0x0000) # !!! offset to connect data (from start of packet)
        pkt += struct.pack("!L", 0x00000200) # max receivable connect data
     
        pkt += struct.pack("B", conflags) # connect flags 0
        pkt += struct.pack("B", conflags) # connect flags 1
        pkt += struct.pack("!L", 0x00000000) # trace cross facility item 1
        pkt += struct.pack("!L", 0x00000000) # trace cross facility item 2
        pkt += struct.pack("!L", 0x00003297) # high 32 bits of 64 bit connection id
        pkt += struct.pack("!L", 0x00000000) # low 32 bits of 64 bit connection id
        
        for i in range(0, 8): # 8 bytes NUL padding
            pkt += struct.pack("B", 0x00)

        # finally add raw command data
        pkt += cdata   
       
        pktlen = len(pkt)
        # patch packet len
        pkt = stroverwrite(pkt, struct.pack("!H", pktlen), 0)
        # patch connect data offset
        offset = pktlen - len(cdata)
        pkt = stroverwrite(pkt, struct.pack("!H", offset), 26)
        return pkt
       
   #given connect data, send connect request
    def sendConnectRequest(self,s,cdata):
        pkt = self.addTNSHeader(TNS_TYPE_CONNECT,cdata)
        try:
            s.sendall(pkt)
        except:
            print 'Error sending TNS Connect request'
        return

    #given marker data, send marker packet
    def sendMarker(self,s,mdata):
        pkt = self.addTNSHeader(TNS_TYPE_MARKER,mdata)
        try:
            s.sendall(pkt)
        except:
            print 'Error sending TNS Marker packet'
        return
