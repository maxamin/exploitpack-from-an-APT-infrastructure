#! /usr/bin/env python
import socket,struct
import crippled_des

CONN_FAILED	=0
NO_AUTH		=1
VNC_AUTH	=2
TIGHT_VNC_AUTH = 16

# Client to Server
MSGC_SETPIXELFORMAT           = 0
MSGC_FIXCOLORMAPENTRIES       = 1
MSGC_SETENCODINGS             = 2
MSGC_FRAMEBUFFERUPDATEREQUEST = 3
MSGC_KEYEVENT                 = 4
MSGC_POINTER_EVENT            = 5
MSGC_CLIENTCUTTEXT            = 6

# Server to Client
MSGS_FRAMEBUFFERUPDATE        = 0
MSGS_SETCOLORMAPENTRIES       = 1
MSGS_BELL                     = 2
MSGS_SERVERCUTTEXT            = 3

#Encodings
E_RAW            = 0
E_COPY_RECTANGLE = 1
E_RRE            = 2
E_CORRE          = 4
E_HEXTILE        = 5

class PixelFormat:
	fmt=">BBBBHHHBBBxxx"
	def __init__(self, data=""):
		if not data:
			self.bits=0
			self.depth=0
			self.bigendian=0
			self.truecolor=0
			self.redmax=0
			self.greenmax=0
			self.bluemax=0
			self.redshift=0
			self.blueshift=0
			self.greenshift=0
		else:
			self.get(data)
	def raw(self):
		return struct.pack(self.fmt, self.bits, self.depth,\
				     self.bigendian, self.truecolor,\
				     self.redmax, self.greenmax, \
				     self.bluemax, self.redshift, \
				     self.blueshift, self.greenshift)

	def get(self, data):
		(self.bits, self.depth,\
		 self.bigendian, self.truecolor,\
		 self.redmax, self.greenmax, \
		 self.bluemax, self.redshift, \
		 self.blueshift, self.greenshift) = struct.unpack(self.fmt, data)

class RFB_Server:
	def __init__(self, localhost, port=5900, version="003.003"):
		self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
		self.s.bind( (localhost, port) )
		self.s.listen(1)
		self.s.set_timeout(60*10) # ten minutes
		#self.s.accept()
		self.c,addr=self.s.accept()
		self.c.send("RFB %s\n" % version) # exchange versions

		self.version=self.c.recv(12)
		print "VERSION: %s" % self.version

	def getsock(self):
		return self.c
	
	def send_auth_type(self,type ):
		self.c.send(struct.pack(">I",type) )

	def send_cfailed(self, size, buffer):
		self.c.send(struct.pack(">I", size)+buffer)
		
class RFB_Client:
	def __init__(self, host, port=5900, version="003.003"):
		self.s=socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
		self.s.connect( (host, port) )
		self.version = version
		welcome=self.s.recv(12)
		if welcome[0:3] != "RFB":
			print "Doesnt look like a RFB (vnc) server"
			return -1
		try:
			self._version=float(welcome[4:11])
		except	ValueError:
			print "Bad Version (%s)" % welcome[4:11]
			return -1
		print welcome
		if not self.version:
			self.version = welcome[4:11]
		self.s.send("RFB %s\n" % self.version)
	
	def getsock(self):
		return self.s

	def force_no_auth(self):
		
		auth=self.s.recv(4)
		auth,=struct.unpack(">L", auth)
		return auth		
	
	def force_realvnc_auth(self):
		auth=self.s.recv(2)
		auth,=struct.unpack(">H", auth)
		self.s.send("\x01")
		authed=self.s.recv(4)
		try:
			authed,=struct.unpack(">L", authed)
		except struct.error:
			raise Exception
		
		return authed		
		
	def close(self):
		self.s.close()
		
	def authentication(self, password):
		auth=self.s.recv(4)
		auth,=struct.unpack(">I", auth)
		if auth==0:
			error_s=self.s.recv(4)
			error_s,=struct.unpack(">I", error_s)
			emsg=self.s.recv(error_s)
			print "Connection failed: %s" % emsg
			return 0
		elif auth==1:
			print "No authentication required"
			return 1
		elif auth==2:
			password= (password+ "\0" *8)[:8]
			challenge=self.s.recv(16)
			des=crippled_des.DesCipher(password)
			response=des.encrypt(challenge[:8]) + des.encrypt(challenge[8:])
			
			self.s.send(response)
			status=self.s.recv(4)
			status,=struct.unpack(">I", status)
			if status==0:
				self.s.send("\x23") # shared-flag: non zero
				self.initialization()
				return 1
			elif status==1:
				print "failed authentication"
				return 0
			elif status==2:
				print "too many"
				return 0

	def initialization(self):
		buf=self.s.recv(24)
		(self.fwidth, self.fheight, pixelformat, nlength)=struct.unpack(">HH16sI", buf)
		self.rname=self.s.recv(nlength)
		
		#(self.bbp, self.depth,self.beflag, self.tcflag, self.rmax, self.gmax, self.bmax, self.rshift, self.gshift, self.bshift)  =struct.unpack(">BBBBHHHBBBxxx", pixelformat)
		self.pixel=PixelFormat(pixelformat) 
		print "Connected to: %s"% self.rname
		print self.pixel.bits
		
	# send a cutText event
	def cutText(self, size, buf):
		cut=struct.pack(">BxxxI",6, size) 
		self.s.send(cut)
		self.s.send(buf)
		
	# encoders its a table of encoders number
	def setEncoding(self, encoders):
		
		buf = chr(MSGC_SETENCODINGS) + "\xc0"
		buf+= struct.pack(">H", len(encoders))
		for a in encoders:
			buf+= struct.pack(">L", a)
		self.s.send(buf)
	
	def FramebufferUpdateRequest(self, x, y, width, height, incremental=0):
		buf = chr(MSGC_FRAMEBUFFERUPDATEREQUEST)
		buf+= chr(incremental)
		buf+= struct.pack(">HHHH", x, y, width, height)
		self.s.send(buf)
		
		# Recv FrameBuffernow
		self.FrameBufferUpdate()
	def FrameBufferUpdate(self):
		pixel_p_byte=( self.pixel.bits + 7) >> 3		
		(msg_type, n_rectangles,)=struct.unpack("BxH", self.s.recv(4))
		#buf=self.s.recv(4)
		#print ord(buf[0]), ord(buf[1]), ord(buf[2]), ord(buf[3])
		#buf=self.s.recv(4)
		#print ord(buf[0]), ord(buf[1]ls), ord(buf[2]), ord(buf[3])
		#print n_rectangles
		print "> %d" % n_rectangles
		for a in range(0, n_rectangles):
			buf = self.s.recv(12)
			(x, y, width, height, encode)=struct.unpack(">HHHHL", buf)
			print "%d %d %d %d" % (x, y, width, height),
			if encode == E_RAW:
				sz= pixel_p_byte * width * height
				print " *RAW* %d" % sz
				buf=""
				while len(buf) < sz: 
					buf+= self.s.recv(sz)
			else: 
				print "NOT IMPLEMENTED YET"
				
	def setPixelFormat(self):		
		buf = chr(MSGC_SETPIXELFORMAT) + "\xc0\xc0\xc0"
		self.pixel.bits=24
		buf+= self.pixel.raw() 
		self.s.send(buf)

	def version(self):
		return self._version
	
	def Loop(self):
		while 1:
			msg_type=ord(self.s.recv(1))
			if msg_type == MSGS_FRAMEBUFFERUPDATE:
				print "*PLINK*"
				self.FrameBufferUpdate()
			else:
				print "Not supported yet: %d" % msg_type
