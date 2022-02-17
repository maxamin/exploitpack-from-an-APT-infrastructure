#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

# TDS library
import sys
if "." not in sys.path: sys.path.append(".")
import struct, socket, encodings
import exploitutils
from exploitutils import prettyprint
from exploitutils import prettyhexprint

from internal import devlog

# Packet type constants
TDS_QUERY    = 0x1 # 4.2 or 7.0
TDS_LOGIN    = 0x2 # 4.2 or 5.0
TDS_RPC      = 0x3
TDS_RESPONSE = 0x4
TDS_CANCEL   = 0x6
TDS_BULK     = 0x7
TDS_QUERY2   = 0xF  # 5.0
TDS_LOGIN2   = 0x10 # 7.0

# Last Packet
MORE_PACKAGE = 0x0
LAST_PACKAGE = 0x1

ENCRYPTION_MASK= 0x5A

MAX_NETWORK_QUERY = 0x7FC

def encryptPass(cpassword):
	password = ""
	for a in range(0, len(cpassword)):
		low  = (ord(cpassword[a]) ^ ENCRYPTION_MASK) >> 4
		high = (ord(cpassword[a]) ^ ENCRYPTION_MASK) << 4
		password += chr( (high | low) & 0xff)
	return password 

def reliable_recv(socket, size):
	newsize = size
	data=""
	while newsize >0:
		try:
			buf= socket.recv(newsize)
		except:
			print "recv failed"
			return ""
		newsize-= len(buf)
		data+=buf
	return data

# im sure there is a function in python somewhere, but i dunno where it is
def string2Unicode(name):
	ret = ""
	for a in name:
		ret += a + "\x00"
	return ret

def unicode2string(name):
	ret =""
	for a in range(0, len(name),2):
		ret+= name[a]
	return ret

class Packet:
	"""Superclass for all MSSQL packets """
	def __init__(self):
		self.packfmt = ">BBHL"
		self.PacketType = 0
		self.LastPacket = 0
		self.Size = 0
		self.Unknown = 0x00010000

	def getSize(self):
		return self.Size

	def getHdrSize(self):
		return struct.calcsize(self.packfmt)

	def _raw(self):
		return ""

	def get(self):
		pass
	def raw(self,last_packet=LAST_PACKAGE):
		buf= self._raw()
		self.LastPacket = last_packet # we leave it like this, for now
		self.Size = len(buf) + struct.calcsize(self.packfmt)
		return struct.pack(self.packfmt, self.PacketType, self.LastPacket, self.Size, self.Unknown) + buf


	def getHeader(self, data):
		packfmt = ">BBHHBB"
		(self.PacketType, self.LastPacket, self.Size, self.Channel, self.PacketNumber, self.Window)\
		 = struct.unpack(packfmt, data[:struct.calcsize(self.packfmt)])

	def printHeader(self):
		print (self.PacketType, self.LastPacket, self.Size, self.Channel, self.PacketNumber, self.Window)

class Response(Packet):
	"""Response packet for MSSQL packets
 MSSQL tells us the server name when we log in - we should record that somewhere

 Right now we have a BUGBUG where if the response is greater than the blocksize (split into multiple response packets)
 we fail to recover the results.
 """


	def __init__(self):
		Packet.__init__(self)
		self.unicode_locale=None
		self.tokens=[]

		self.parse_tokens= {0x21:self.parse_pass, 0x71:self.parse_pass, 0x79:self.parse_rstatus, 0x7c:self.parse_pass,\
							0x81:self.parse_0x81, 0xA0:self.parse_pass, 0xA1:self.parse_pass, 0xA4:self.parse_pass,\
							0xA5:self.parse_pass, 0xA7:self.parse_pass, 0xA8:self.parse_pass, 0xA9:self.parse_pass,\
							0xAA:self.parse_error, 0xAB:self.parse_error, 0xAC:self.parse_pass, 0xAD:self.parse_0xad,\
							0xAE:self.parse_pass, 0xD1:self.parse_0xd1, 0xD3:self.parse_pass, 0xD7:self.parse_pass,\
							0xE2:self.parse_pass, 0xE3:self.parse_0xe3, 0xE5:self.parse_error, 0xE6:self.parse_pass,\
							0xEC:self.parse_pass, 0xEE:self.parse_pass, 0xFD:self.parse_done, 0xFE:self.parse_done,\
							0xFF:self.parse_done, }

		self.tokens_names={ 0x21:"Language packet", 0x71: "Logout", 0x79: "Return Status", 0x7C: "Process ID", 0x81: "7.0 Result",\
							0xA0:"Column Name", 0xA1: "Column Info - Row Result", 0xA4:"Table names", 0xA5:"Column info",\
							0xA7:"Compute related", 0xA8: "Column Info -Compute Result", 0xA9: "Order By", 0xAA:"Error Message",\
							0xAB:"Non-error Message", 0xAC: "Output Parameters", 0xAD: "Login Acknowledgement", 0xAE: "Control",\
							0xD1:"Data - Row Result", 0xD3:"Data - Compute Result", 0xD7: "Param packet", 0xE2:"Capability packet",\
							0xE3:"Environment Change", 0xE5: "Extended Error Message", 0xE6:"DBRPC", 0xEC:"param format packet",
							0xEE:"Result Set", 0xFD:"Result Set Done", 0xFE: "Process Done", 0xFF:"Done inside Process"}

	def __iter__(self):

		return self.tokens.__iter__()

	def getTokenName(self, token_num):
            return self.tokens_names.get(token_num, '')

	def has(self, token):
		for a in self.tokens:
			if a[0] == token:
				return a
		return None

	def has_all(self,token):
		"""
    Return all the tokens that match the token value supplied - we can have more than one environment token, for example
    Returns an empty list if no tokens match
    """
		ret=[]
		for a in self.tokens:
			if a[0] == token:
				ret+=[a]
		return ret

	def get(self, data):
		idx= 0

		while 1:

			try:
				token = ord(data[idx:idx+1])
			except TypeError:
				devlog("mssql", "end of data")
				break
			idx+=1

			try:
				devlog("mssql","Parsing token %x"%token)
				idx+= self.parse_tokens[token](token, data[idx:])
			except (KeyError,TypeError): # KeyError=Unsupported token :( TypeError=killing my script
				devlog("mssql","Unsupported token %s"%token)
				break 

			if token == 0xFD or token == 0xFF:
				devlog("mssql","Found token %x - exiting token parsing"%token)
				break
		return

	# Unicode String
	def getString(self, data):
		devlog("mssql","getString: %s"%prettyprint(data[:20]))
		length= ord(data[0])

		try:
			text = data[1:1+length*2]
		except IndexError:
			raise MSSQLError("Error parsing a 8bit length -> string field")

		return (length*2+1, text)

	# resturn (bitflag, uknown, rowcount)
	def parse_done(self, token, data):
		bitflag, Uknown, RowCount = struct.unpack("<HHL", data[0:8])

		self.tokens.append((token, (bitflag, Uknown, RowCount) ))

		return 8

	# resturn (bitflag, uknown, rowcount)
	def parse_rstatus(self, token, data):
		Value = struct.unpack("<L", data[0:4])

		self.tokens.append((token, (Value) ))

		return 4

	# return: (ack, version, text, serverVer)
	def parse_0xad(self, token, data):
		length=struct.unpack("<H", data[0:2])[0]
		new_data = data[2:length+2] 
		idx=0

		ack=ord(new_data[idx: idx+1])
		idx+=1

		version = struct.unpack("<L", new_data[idx: idx+4])[0]
		idx+=4
		devlog("mssql","version=%x"%version)
		tmplength, text = self.getString(new_data[idx:])        
		idx+= tmplength
		devlog("mssql","serverVer Text=%s"%text)
		serverVer= struct.unpack("<L", new_data[idx: idx+4])[0]
		devlog("mssql","serverVer=%x"%serverVer)
		self.tokens.append((token, (ack, version, encodings.codecs.utf_16_decode(text)[0], serverVer) ))

		return length+2


	# return: (msg_number, state, lever, message, server, process)
	def parse_error(self, token, data):
		length=struct.unpack("<H", data[0:2])[0]
		new_data = data[2:length+2] 
		idx=0

		msg_number, state, lever = struct.unpack("<LBB", new_data[idx:idx+6])
		idx+=6

		tlength=struct.unpack("<H", new_data[idx:idx+2])[0]
		idx+=2

		try:
			message=new_data[ idx : idx + tlength*2] # UNICODE
		except IndexError:
			raise MSSQLError("Error parsing Error token on a Response Packet")
		idx+=tlength*2

		tmplength, server = self.getString(new_data[idx:])        
		idx+= tmplength

		tmplength, process = self.getString(new_data[idx:])        
		idx+= tmplength

		line_number=struct.unpack("<H", new_data[idx:idx+2])[0]
		idx+=2
		#print encodings.codecs.utf_16_decode(message)[0]
		self.tokens.append((token, (msg_number, state, lever, encodings.codecs.utf_16_decode(message)[0],\
									encodings.codecs.utf_16_decode(server)[0], encodings.codecs.utf_16_decode(process)[0], line_number) ))

		return length+2

	def parse_0x81(self, token, data):
		fmt = "HHHBHHHBB"
		unicode_locale=self.unicode_locale
		idx=0
		m_length = 6

		#(columns, usertype, flags, type, large_type_size, codepage, flags2, charsetid, m_length) = \

		columns = struct.unpack("<H", data[idx:idx+2])[0]    
		idx+= 2
		usertype = struct.unpack("<H", data[idx:idx+2])[0]    
		idx+= 2
		flags = struct.unpack("<H", data[idx:idx+2])[0]    
		idx+= 2

		type = ord(data[idx])
		idx+=1

		large_type_size = struct.unpack("<H", data[idx:idx+2])[0]    
		idx+= 2
		#devlog("mssql","0x81: columns: %x flags: %x type: %x usertype: %x large_type_size %x data: %s"%(columns, flags, type, usertype, large_type_size, prettyprint(data[idx:idx+20])))
		if unicode_locale==None:
			"""
      Ah, in the login packet (or other packets, I assume)
      you can get an e3 data type, which is an environment change. This can specify a unicode locale. If it does, then
      you no longer recieve a unicode codepage, etc. 
      txt is always at token[1][-1] regardless
      """
			codepage = struct.unpack("<H", data[idx:idx+2])[0]    
			idx+= 2
			flags2 = struct.unpack("<H", data[idx:idx+2])[0]    
			idx+= 2

			charsetid = ord(data[idx])
			idx+=1
			#HERE we start a normal string - could call getString
			m_length = ord(data[idx])
			idx+=1

			txt = encodings.codecs.utf_16_decode(data[idx:idx+m_length*2])[0]

			self.tokens.append((token, (columns, usertype, flags, type, large_type_size, codepage, flags, charsetid, m_length, txt) ))
		else:
			#string type
			#devlog("mssql","String type (0xe7): %s"%prettyhexprint(data[idx:idx+20]))
			templength, txt = self.getString(data[idx:])
			#devlog("mssql","Found string type %s with flags %x"%(prettyprint(txt),flags))
			idx+=templength

			m_length=0
			self.tokens.append((token, (columns, usertype, flags, type, large_type_size, txt) ))
		#else:
		#  devlog("mssql","Unknown SQL 7 type %x"%type)

		return idx+ m_length*2


	def parse_0xd1(self, token, data):
		length = struct.unpack("<H", data[0:2])[0]
		if length==0xffff: # end of column?
			return 2

		txt = data[2:length+2]

		#try:
		#self.tokens.append((token, encodings.codecs.utf_16_decode(txt)[0]))
		self.tokens.append((token, unicode2string(txt)))
		#except UnicodeDecodeError, msg:
			#raise MSSQLError, "Couldn't unicode the string(%s): %s" % (txt, str(msg))
		#except UnicodeEncodeError, msg:
			#raise MSSQLError, "Couldn't unicode the string(%s): %s" % (txt, str(msg))
		#print unicode(txt, 'utf-16', errors='replace')
		#print 
		return length+2
		#response.decode("utf-16")
		#u=unicode(response, 'utf-16', errors='replace')
		#self.tokens.append( (token, str(u.encode('cp850', 'ignore'))) )

	# tuple (new, old)  or (code_page, flags, charset) in case of collation
	def parse_0xe3(self, token, data):

		length=struct.unpack("<H", data[0:2])[0]
		new_data = data[2:2+length]
		idx=0
		env_code= ord(new_data[idx:idx+1])
		idx+=1
		if env_code == 7: # Collation Info
			tmplength= ord(new_data[idx:idx+1])
			idx+=1

			if tmplength != 5:
				raise MSSQLError("Size of collation info should be 5 (%d)" % tmplength)

			(code_page, flags, charset) = struct.unpack("<HHB", new_data[idx:idx+5])
			idx += 5

			tmplength= ord(new_data[idx:idx+1])
			idx+=1
			self.tokens.append((token, (env_code, code_page, flags, charset) ))
		#elif env_code == 5: #Unicode Locale ID
		#ones we don't care about are commented out - They're all just strings.
		#elif env_code == 6: #Unicode Comparison Style
		#  pass
		#elif env_code == 4: #Blocksize
		#  pass
		#elif env_code == 3: #Sort order
		#  pass
		#elif env_code == 2: #language
		#  pass
		#elif env_code == 1: #database
		#  pass  
		else:
			tmplength, new = self.getString(new_data[idx:])        
			idx+= tmplength


			tmplength, old = self.getString(new_data[idx:]) 
			idx+= tmplength

			self.tokens.append((token, (env_code, encodings.codecs.utf_16_decode(old)[0], encodings.codecs.utf_16_decode(new)[0] ) ))
		return length + 2

	def parse_pass(self, token, data):
		print "WOOPS, no parser yet"
		pass

class Query(Packet):
	def __init__(self):
		Packet.__init__(self)
		self.PacketType = TDS_QUERY
		self.query=""
	def setQuery(self, query):
		self.query=query
	def _raw(self):
		result = string2Unicode(self.query)
		#prettyhexprint(result)
		return result


class Login(Packet):

	def __init__(self, VERSION = "7.0"):
		Packet.__init__(self)
		self.VERSION = VERSION

		if self.VERSION == "5.0": # Version < 7.0
			self.Hostname = ""
			self.HostnameLength = 0
			self.Username = ""
			self.UsernameLength = 0
			self.Hostprocess = ""
			self.HostprocessLength = 0
			self.Magic1 = ""
			self.Bulkcopy= 0
			self.Magic2 = ""
			self.Appname = ""
			self.AppnameLength = 0
			self.Servername = ""
			self.ServernameLength = 0
			self.Magic3 = 0
			self.PasswordLength = 0
			self.Password = ""
			self.Magic4 = ""
			self.PasswordLength2 = 0 # Length + 2 :/
			self.TDSMajorVersion = 0    
			self.TDSMinorVersion = 0
			self.LibraryName = ""
			self.LibraryLength = 0
			self.MajorVersion = 0 # Program 
			self.MinorVersion = 0 # Program 
			self.Magic6 = ""
			self.Language = ""
			self.LanguageLenght = 0
			self.Magic7 = ""
			self.OldSecure = 0
			self.Encrypted = 0
			self.Magic8 = ""
			self.Secspare = ""
			self.Charset = ""
			self.CharsetLenght = 0
			self.Magic9 = ""
			self.BlockSize = ""
			self.BlockSizeLength = 0
			self.Magic10 = ""

		elif self.VERSION == "7.0":
			self.PacketType = TDS_LOGIN2   

			self.fmt ="LLLLLLBBBBLL"
			self.offsetfmt= "18H6s4H"
			self.TotalSize  = 0
			self.TDSVersion = 0x71000001
			self.PAcketSize = 0
			self.ClientProgramVersion = 0xc0c0c0c0L
			self.PID = 0x0
			self.ConnectionID = 0
			self.OptionFlag1  = 0xe0
			self.OptionFlag2  = 0x3
			self.SQLType      = 0
			self.ReservedFlag = 0
			self.TimeZone     = 0
			self.Collation    = 0

			# Offsets
			self.HostnameOffset = 0
			self.HostnameLength = 0
			self.UsernameOffset = 0
			self.UsernameLenght = 0
			self.PasswordOffset = 0
			self.PasswordLength = 0
			self.AppnameOffset  = 0
			self.AppnameLength  = 0
			self.ServerNameOffset = 0
			self.ServerNameLength = 0
			self.UnknownOffset = 0
			self.UnknownLenght = 0
			self.LibraryNameOffset = 0
			self.LibraryNameLength = 0
			self.LanguageOffset = 0
			self.LanguageName = 0
			self.DatabaseOffset = 0
			self.DatabaseLenght = 0

			# Auth info
			self.MAC = "\x20" * 6 
			self.AuthOffset = 0
			self.AuthLength = 0
			self.NextPosition = 0
			self.Unknown2 = 0

			self.Hostname   = ""
			self.Username   = ""
			self.Password   = ""
			self.Appname    = ""
			self.Servername = ""
			self.LibraryName = ""
			self.Language   = ""
			self.Database   = ""

	def _raw(self):

		# Initialization and calculation
		Hostname = string2Unicode(self.Hostname)
		Username= string2Unicode(self.Username)
		Password = string2Unicode(self.Password)
		Appname = string2Unicode(self.Appname)
		ServerName = string2Unicode(self.Servername)
		LibraryName = string2Unicode(self.LibraryName)
		Database = string2Unicode(self.Database)

		idx = 86 # Offset where the packet end

		self.HostnameOffset = idx
		self.HostnameLength = len(self.Hostname)
		idx += len(Hostname)

		self.UsernameOffset = idx
		self.UsernameLenght = len(self.Username)
		idx += len(Username)

		self.PasswordOffset = idx
		self.PasswordLength = len(self.Password)
		idx+= len(Password)

		self.AppnameOffset  = idx
		self.AppnameLength  = len(self.Appname)
		idx += len(Appname)

		self.ServerNameOffset = idx
		self.ServerNameLength = len(self.Servername)
		idx+= len(ServerName)

		self.LibraryNameOffset = idx
		self.LibraryNameLength = len(self.LibraryName)
		idx+= len(LibraryName)

		self.LanguageOffset = idx
		self.LanguageName = 0
		self.AuthOffset = idx
		self.NextPosition = idx

		self.DatabaseOffset = idx
		self.DatabaseLenght = len(self.Database)
		idx+= len(Database)

		self.TotalSize = idx

		#packing
		pkt  = ""
		pkt += struct.pack(self.fmt, self.TotalSize, self.TDSVersion, self.PAcketSize, self.ClientProgramVersion,self.PID,\
						   self.ConnectionID, self.OptionFlag1, self.OptionFlag2, self.SQLType, self.ReservedFlag,\
						   self.TimeZone, self.Collation)

		pkt+= struct.pack(self.offsetfmt, self.HostnameOffset, self.HostnameLength, self.UsernameOffset, self.UsernameLenght,\
						  self.PasswordOffset, self.PasswordLength, self.AppnameOffset, self.AppnameLength, self.ServerNameOffset,\
						  self.ServerNameLength, self.UnknownOffset, self.UnknownLenght, self.LibraryNameOffset,\
						  self.LibraryNameLength, self.LanguageOffset, self.LanguageName, self.DatabaseOffset,\
						  self.DatabaseLenght, self.MAC, self.AuthOffset, self.AuthLength, self.NextPosition,\
						  self.Unknown2)
		pkt+= Hostname 
		pkt+= Username
		pkt+= encryptPass(Password)
		pkt+= Appname
		pkt+= ServerName
		pkt+= LibraryName
		pkt+= Database

		return pkt

class MSSQLError(Exception):
    pass


class MSSQL:
	"""
  This class is used my mssql_auth to login to remote SQL servers
  """
	def __init__(self, hostname, port=1433):
		self.hostname = hostname
		self.port = port
		self.ClientName = ""
		self.login_resp = ""
		self.remoteHost = ""
		self.unicode_locale=None

	def setClientName(self, clientname="CANVAS"):
		self.ClientName = clientname

	def login(self, username, password, db="master"):
		"""
    Login will return the results of the query packet - this is needed to capture the environment you have logged into
    """

		lpacket = Login()
		lpacket.Username = username
		lpacket.Password = password
		if self.ClientName:
			lpacket.Hostname = self.ClientName
		else:
			lpacket.Hostname = exploitutils.randomstring(6)

		lpacket.Servername = str(self.hostname)
		lpacket.Database = db
		lpacket.Appname = lpacket.LibraryName = exploitutils.randomstring(6)
		try:
			self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
			try:
				self.s.connect( (self.hostname, self.port) )
				self.s.send(lpacket.raw())
			except:
				print "Connect error"
				return None
		except socket.error, msg:
			raise MSSQLError("MSSQL Error on socket: %s" % str(msg))

		resp = self.get_response()
		#resp is a Response() or None
		if resp is not None:
			tok = resp.has(0xAA) # Error Message

			if tok:
				raise MSSQLError("MSSQL Error on login: '%s'" % tok[1][3])
		else:
			raise MSSQLError("MSSQL Error on login, failed on recv.")

		tok = resp.has(0xad) # Login Acknowledgement
		if tok:
			self.login_resp= tok[1]
		tok = resp.has(0xab) # Info Message
		if tok:      
			self.remoteHost = tok[1][4]

		for token in resp.has_all(0xe3):
			"""
        Look for all environment tokens
        """
			#token[1][0] is the env_code
			env_code=token[1][0]
			olddata=token[1][1] #old
			data=token[1][2] #new
			if env_code==5:
				#save this off
				self.unicode_locale=data

		return resp

	def getHost(self):
		return self.remoteHost

	def getServerVersion(self):
		if not self.login_resp:
			return ""
		return self.login_resp[2]

	def get_response(self):
		# Get Packet Header
		resp = Response()
		resp.unicode_locale=self.unicode_locale

		try:
			hdr  = self.s.recv(resp.getHdrSize())
		except:
			print "recv failed"
			return None

		resp.getHeader(hdr)
		size= resp.getSize() 
		#data = self.s.recv(resp.getSize()-resp.getHdrSize() )

		data = reliable_recv(self.s, resp.getSize() - resp.getHdrSize())

		while resp.LastPacket !=LAST_PACKAGE: # We need to figure out this
			try:
				hdr = self.s.recv(resp.getHdrSize())
			except:
				print "recv failed"
				return ""
			resp = Response()
			resp.getHeader(hdr)
			#buf=self.s.recv(resp.getSize() - resp.getHdrSize())
			buf = reliable_recv(self.s, resp.getSize() - resp.getHdrSize())
			data += buf

		resp.get(data)
		return resp

	def query(self, sql_txt):
		"""
        Returns a Response() instance or an empty string (on failure)
        """
		q= Query()
		devlog("mssql","Query: %s"%prettyprint(sql_txt))
		if (len(sql_txt) > MAX_NETWORK_QUERY):
			#we need to packetize the query data
			ptr = sql_txt
			while (len(ptr)>=MAX_NETWORK_QUERY):
				pkt = ptr[:MAX_NETWORK_QUERY]
				q.setQuery(pkt)
				self.s.send(q.raw(MORE_PACKAGE))
				ptr = ptr[MAX_NETWORK_QUERY:]
			q.setQuery(ptr)
			self.s.send(q.raw(LAST_PACKAGE))
		else:
			q.setQuery(sql_txt)
			self.s.send(q.raw())
		resp = self.get_response()
		#resp is an instance, not a string
		#devlog("mssql","Response: %s"%prettyprint(resp))
		return resp

if __name__ == "__main__":
	if len(sys.argv) != 2:
		print "usage: %s host" % sys.argv[0]
		sys.exit(0)

	sql= MSSQL(sys.argv[1])
	try:
		sql.login("sa", "")
	except MSSQLError, msg:
		print msg
		sys.exit(0)
	print "Connected to %s version: %s" % (sql.getHost(), sql.getServerVersion())
	resp = sql.query("xp_cmdshell \"dir c:\\WINNT\\\"")
	for a in resp.tokens:
		print a[1]
