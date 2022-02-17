#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

VERSION= "1.0"

import socket,struct,select
import sys

#in case we aren't using CANVAS
sys.path.append("../")
sys.path.append(".")
import timeoutsocket

def get_uint3(value):
        tmp=struct.pack("I", value)
        return  (ord(tmp[0]) + (ord(tmp[1]) << 8) + (ord(tmp[2]) << 16))
    
def pack_uint3(value):
        tmp=struct.pack("I", value)    
        return tmp[0:3]
    
def unpack_uint3(value):
        tmp=struct.unpack("ccc", value[0:3])
        return  (ord(tmp[0]) + (ord(tmp[1]) << 8) + (ord(tmp[2]) << 16))

def unpack_uint4(value):
        tmp=struct.unpack("cccc", value[0:4])
        return  (ord(tmp[0]) + (ord(tmp[1]) << 8) + (ord(tmp[2]) << 16) + (ord(tmp[3]) << 24))
        
CLIENT_LONG_PASSWORD    =1       #/* new more secure passwords */
CLIENT_FOUND_ROWS       =2       #/* Found instead of affected rows */
CLIENT_LONG_FLAG        =4       #/* Get all column flags */
CLIENT_CONNECT_WITH_DB  =8       #/* One can specify db on connect */
CLIENT_NO_SCHEMA        =16      #/* Don't allow database.table.column */
CLIENT_COMPRESS         =32      #/* Can use compression protocol */
CLIENT_ODBC             =64      #/* Odbc client */
CLIENT_LOCAL_FILES      =128     #/* Can use LOAD DATA LOCAL */
CLIENT_IGNORE_SPACE     =256     #/* Ignore spaces before '(' */
CLIENT_PROTOCOL_41      =512     #/* New 4.1 protocol */
CLIENT_INTERACTIVE      =1024    #/* This is an interactive client */
CLIENT_SSL              =2048    #/* Switch to SSL after handshake */
CLIENT_IGNORE_SIGPIPE   =4096    #/* IGNORE sigpipes */
CLIENT_TRANSACTIONS     =8192    #/* Client knows about transactions */
CLIENT_RESERVED         =16384   #/* Old flag for 4.1 protocol  */
CLIENT_SECURE_CONNECTION= 32768  #v/* New 4.1 authentication */
CLIENT_MULTI_STATEMENTS =65536   #/* Enable/disable multi-stmt support */
CLIENT_MULTI_RESULTS    =131072  #/* Enable/disable multi-results */
CLIENT_REMEMBER_OPTIONS =(1L << 31)

MAX_PACKETSIZE          =0xffffff

COM_SLEEP =       0
COM_QUIT=         1
COM_INIT_DB=      2
COM_QUERY=        3
COM_FIELD_LIST=   4
COM_CREATE_DB=    5
COM_DROP_DB =     6
COM_REFRESH =     7
COM_SHUTDOWN=     8
COM_STATISTICS=   9
COM_PROCESS_INFO=10 
COM_CONNECT=     11
COM_PROCESS_KILL=12
COM_DEBUG=       13
COM_PING=        14
COM_TIME=        15
COM_DELAYED_INSERT=16
COM_CHANGE_USER= 17
COM_BINLOG_DUMP= 18
COM_TABLE_DUMP=  19
COM_CONNECT_OUT= 20
COM_REGISTER_SLAVE= 21
COM_PREPARE    = 22
COM_EXECUTE    = 23
COM_LONG_DATA  = 24
COM_CLOSE_STMT = 25
COM_RESET_STMT = 26
COM_SET_OPTION = 27
COM_END        = 28
MYSQL_TYPE_DECIMAL  = 0
MYSQL_TYPE_TINY     = 1
MYSQL_TYPE_SHORT    = 2
MYSQL_TYPE_LONG     = 3
MYSQL_TYPE_FLOAT    = 4
MYSQL_TYPE_DOUBLE   = 5
MYSQL_TYPE_NULL     = 6
MYSQL_TYPE_TIMESTAMP= 7
MYSQL_TYPE_LONGLONG = 8
MYSQL_TYPE_INT24    = 9
MYSQL_TYPE_DATE     = 10
MYSQL_TYPE_TIME     = 11
MYSQL_TYPE_DATETIME = 12
MYSQL_TYPE_YEAR     = 13
MYSQL_TYPE_NEWDATE  = 14                      
MYSQL_TYPE_ENUM     =247
MYSQL_TYPE_SET      =248
MYSQL_TYPE_TINY_BLOB=249
MYSQL_TYPE_MEDIUM_BLOB=250
MYSQL_TYPE_LONG_BLOB=251
MYSQL_TYPE_BLOB     =252
MYSQL_TYPE_VAR_STRING=253
MYSQL_TYPE_STRING   =254
MYSQL_TYPE_GEOMETRY =255

SCRAMBLE_LENGTH_323 =8

class error(Exception):
        def __init__(self, value):
                self.value = value
        def __str__(self):
                return repr(self.value)

def store_long(value):
        return struct.pack("<L", value)
    
class MySQL:
        # commands
        def __init__(self, protocol=41, timeout=10):
                self._protocol=protocol
                self._values=[]
                self.stmt_id=-1
                self.send_type_to_server=1
                self.server_version=""
                self.fields=None
                self.rows=None
                self.debug=0
                self.affected=-1
                self.packet_length=None
                self.conn_info=("", "")
                self.timeout = timeout

        def setDebug(self):
                self.debug=1

        def unsetDebug(self):
                self.debug=0
                
        def mysql_affected_rows(self):
                return self.affected
        
        def getDebug(self):
                return self.debug
        
        def recv_packet(self, debug=0):
                #print self._s.recv(4)
                try:
                        tmp=self._s.recv(4)
                except socket.error, msg:
                        raise error("socket: " + str(msg))
                if not tmp:
                        raise error("Null Packet received. (Bad authentication?)")
                try:
                        body_length= unpack_uint3(tmp)
                except struct.error,msg:
                        raise error("struct: body_length " + str(msg))
                
                self._packet=ord(tmp[3])
                
                try:
                        buf= self._s.recv(body_length)
                except socket.error, msg:
                        raise error("socket: " + str(msg))                        
                
                if debug:
                        for a in range(0, len(buf)):
                                print "%02x" %  ord(buf[a]),
                        print ""
                if buf[0]=='\xff':
                        raise error("(%d) %s" % (struct.unpack("H", buf[1:3])[0],buf[3:]))
                return buf

        def getServerVersion(self):
                return self.server_version

        def getHost(self):
                return self.conn_info[0]

        def connect(self, conn_info):
                self.conn_info=conn_info
                try:
                        self._s=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
                        self._s.set_timeout(self.timeout)
                        self._s.connect(conn_info)
                        body_length,=struct.unpack("<L", self._s.recv(4))
                except socket.error,msg:
                        raise error("socket: " + str(msg))
                idx=0
                try:
                        b=self._s.recv(body_length)
                except socket.error, msg:
                        raise error("socket: " + str(msg))
                
                if b[0]=='\xff':
                        raise error("(%d) %s" % (struct.unpack("H", b[1:3])[0] , b[3:]))

                self.version=int(ord(b[idx]))
                idx+=1
                tmp=b[idx:].find('\0')
                self.server_version=b[idx:tmp+idx]
                idx+=tmp+1
                self.threadid,=struct.unpack("<L",b[idx:idx+4])
                idx+=4
                tmp=b[idx:].find('\0')
                self.salt=b[idx:tmp+idx]
                idx+=tmp+1
                self.capabilities,=struct.unpack("H",b[idx:idx+2])
                idx+=2
                self.charset= b[idx]
                idx+=1
                self.status= struct.unpack("H",b[idx:idx+2])
                idx+=2
                
                idx+=13

                self.salt+=b[idx:len(b)-1]
                
        def authenticate(self, user, password, db=""):
               flag=0
                #flag=  self.capabilities  & ~ self.CLIENT_SSL
               
               if db:
                       flag|=CLIENT_CONNECT_WITH_DB 

               flag|=CLIENT_LONG_FLAG   #| self.CLIENT_PROTOCOL_41
               flag|=CLIENT_INTERACTIVE   | CLIENT_LOCAL_FILES
               flag|=CLIENT_LONG_PASSWORD | CLIENT_SECURE_CONNECTION
               
               if flag & CLIENT_PROTOCOL_41:
                       buf=struct.pack("<LL", flag, MAX_PACKETSIZE) + self.charset
               else:
                       buf=struct.pack("H", flag)
                       buf+=pack_uint3(MAX_PACKETSIZE)
                       
               buf+=user+"\0"

               if not password:
                       buf+="\0"
               else:
                       result=self.scramble(password)
                       buf+=chr(len(result)) +result 
                       
                       # SCRAMBLE HERE :>
               buf+=db + "\0"
               buf= pack_uint3(len(buf)) + '\x01' + buf

               self._s.send(buf)
               return self.recv_packet()
       
        def query(self, querymsg):
                self.simple_command(COM_QUERY, querymsg)
                       
        def simple_command(self, COMMAND, querymsg,  noresponse=0):
                buf = chr(COMMAND)
                buf+= querymsg
                if self.packet_length:
                        buf= struct.pack("<L", self.packet_length) + buf
                else:
                        buf=  pack_uint3(len(buf)) +"\0" +buf
                self._s.send(buf)
                
                # response
                if noresponse:
                        return 1
                return self.recv_packet(debug=self.debug)

        def stmt_prepare(self, query):
                buf=self.simple_command(COM_PREPARE, query)
                self.stmt_id,    = struct.unpack("<L", buf[1:5])
                self.field_count,= struct.unpack("H", buf[5:7])
                self.param_count,= struct.unpack("H", buf[7:9])
        
        def stmt_bind(self, values):
                # self._values format :
                # tuple with: ( TYPE, function to store it, value )
                self._values=[]
                if len(values) != self.param_count:
                        raise error("Wrong values count, parametres must be %d" % self.param_count)
                for a in values:
                        self._values.append( (a[0],  store_long, a[1] ) )
                        #self._values.append( (0x9090,  store_long, a ) )
                # LOT OF WORK TO BEING DONE HERE
                
        def execute(self):
                if self._values==[]:
                        raise error("You have to execute stmt_bind(params) first")
                null= (self.param_count + 7/8) # this is wrong
                null=1
                buf = struct.pack("<L", self.stmt_id) #                
                
                # PARAMETERS START HERE
                #print null
                buf+= "\0" * null
                buf+= chr(self.send_type_to_server) # send_types_to_server = 1 first time
                                                    # then i suppose to change it
                for param in self._values:
                        buf+= struct.pack("H", param[0])
                for param in self._values:
                        buf+= param[1]( param[2] ) 
                        buf=self.simple_command(COM_EXECUTE, buf)                
                self.affected=ord(buf[1])
                return self.affected
        
        # did close get response?
        def stmt_close(self):
               if self.stmt_id == -1:
                       raise error("No stmt session initialized") 
               buf=struct.pack("<L", self.stmt_id)
               self.simple_command(COM_CLOSE_STMT, buf,  noresponse=1)
               
        def query(self, query):
                return self.simple_command(COM_QUERY, query)
                
        def close(self):
                # Ok, change this for a real COM_CLOSE
                self._s.close()
        def get_member(self, buf):
                idx=0
                sz=ord(buf[idx])
                idx+=1
                if sz==0:
                        return (idx, "")
                elif sz==0xfc:
                        sz,=struct.unpack("H", buf[idx:idx+2])
                        idx+=2
                elif sz==0xfd:
                        sz = unpack_uint3(buf[idx:idx+3])
                        idx+=3
                elif sz==0xfe:
                        # sz = unpack_uint8 WTF :>
                        idx+=4
                return (idx+sz, buf[idx: idx+sz])
        # Im almost sure that noir have a fancy pythonized way to parse this
        # Mental Note: Listen to noir next time :>
        def get_fields(self, buf):
                idx=0

                if self._protocol != 41:
                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        table_name=tmp[1]

                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        field_name=tmp[1]

                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        field_length=unpack_uint3(tmp[1][0:3])

                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        field_type=ord(tmp[1])
                        
                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        flag_dec=unpack_uint3(tmp[1])

                else:
                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        catalog_name  = tmp[1]

                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        db_name       = tmp[1]

                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        table_name    = tmp[1]

                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        org_name      = tmp[1]

                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        field_name    = tmp[1]

                        tmp           = self.get_member(buf[idx:])
                        idx          += tmp[0]
                        field_name    = tmp[1]

                        idx          += 3 #ignore the charset
                        field_length  = unpack_uint4(buf[idx:idx+4])
                        idx          += 4

                        field_type    = ord(buf[idx])
                        idx          += 1

                        flag_dec      = 2 #hack hack hack

                return (table_name, field_name, field_length, field_type, flag_dec)
                
        def get_rows(self, buf, col_number):
                idx=0
                rows=[]
                for a in range(0, col_number):
                        tmp=self.get_member(buf[idx:])
                        idx+=tmp[0]
                        rows.append(tmp[1])

                return rows
        
        # fetch result, sets
        # self.fields = [("tablename", "row name", length, type, flags/decimal)]
        # self.rows= [ (... values ...)]
        def fetch_result(self, buf):
                #if not len(buf)==1:
                #        raise error("result doesnt seem like a query response")
                fields=[]
                rows=[]
                col_number=ord(buf[0])
                #print type
                
                if col_number:
                        # SELECT/SHOW
                        self.affected=0
                        while 1:
                                buf=self.recv_packet()  
                                if buf[0]=='\xfe':
                                        break
                                tmp= self.get_fields(buf)
                                fields.append(tmp)
                        idx=0
                        while 1:
                                buf=self.recv_packet()
                                if buf[0]=='\xfe':
                                        break
                                tmp= self.get_rows(buf, col_number)
                                rows.append(tmp)
                else:
                        # INSERT/UPDATE
                        if len(buf) > 1:
                                self.affected=ord(buf[1])
                                #print buf[3:]
                     
                        
                self.fields=fields
                self.rows=rows
        def scramble(self, passwd):        
                #from sha import sha
                from hashlib import sha1 as sha
                result=""
                hash_stage1=sha(passwd)
                hash_stage2=sha(hash_stage1.digest())
                
                tmp=sha(self.salt)
                tmp.update(hash_stage2.digest())
                to=tmp.digest()
                s1=hash_stage1.digest()
                for a in range(0, len(to)):
                        result+= chr( ord(to[a]) ^ ord(s1[a]) )
                        
                return result
        def recv(self, size):
                (a,b,c) =select.select([self._s], [], [], None)
                if a==[]:
                        return 0
                return self._s.recv(size)
                
        
        def scramble_323(self, passwd):
                """
                   const char *message_end= message + SCRAMBLE_LENGTH_323;
                   hash_password(hash_pass,password, strlen(password));
                   hash_password(hash_message, message, SCRAMBLE_LENGTH_323);
                   randominit(&rand_st,hash_pass[0] ^ hash_message[0],
                              hash_pass[1] ^ hash_message[1]);
                   for (; message < message_end; message++)
                     *to++= (char) (floor(my_rnd(&rand_st)*31)+64);
                   extra=(char) (floor(my_rnd(&rand_st)*31));
                   while (to_start != to)
                     *(to_start++)^=extra;
                 }
                 *to= 0;
                
                """
                
                to=""
                result=""
                hash_pass=self.hash_password(passwd)
                hash_message=self.hash_password(self.salt)
                self.random_init( hash_pass[0] ^ hash_message[0], \
                                  hash_pass[1] ^ hash_message[1])
                for a in range(0, SCRAMBLE_LENGTH_323):
                        to+=   chr((int( self.my_rnd()*31)+64) & 0xff)
                extra= (int(self.my_rnd() * 31) & 0xff)
                for a in range(0, len(to)):
                        result+= chr(ord(to[a]) ^ extra)
                return result
         
