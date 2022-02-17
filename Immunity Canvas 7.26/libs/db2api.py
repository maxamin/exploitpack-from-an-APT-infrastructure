"""
db2api.py 0.5.5 - 08/10/06

(C) Immunity, Inc.

TODO:
Implement encryption.
"""

"""
db2test.py
-------
import sys
from socket import *
import struct
import db2api

DB2Packet = db2api.DB2()
DB2Packet.setUserid("db2admin")
DB2Packet.setPassword("foobar")
DB2Packet.setDB("SAMPLE")

s = socket(AF_INET,SOCK_STREAM)
s.connect(("192.168.195.137",50000))

DB2Packet.requestSession(s)
DB2Packet.replyGet(s)

if not DB2Packet.isAccepted():
    ret = DB2Packet.getErrCode()
    sys.exit(1)

print "We got in."
print
print "Version: " + DB2Packet.getVersion()
print "OS: " + DB2Packet.getOS()

DB2Packet.execImmediateStatement(s,"create table NAME (A character)")
DB2Packet.execImmediateStatement(s,"insert into NAME values ('A')")
DB2Packet.execProcedure(s,'dir > C:\\foo.txt')
DB2Packet.Disconnect(s)

-------
"""

import struct
import codecs
import sys
import socket
import errno

from socket import *
class DB2:
	"""
	We will add more codepoints when we need them.
	"""
	codepoints = {}
	codepoints["EXCSAT"] = 0x1041
	codepoints["EXTNAM"] = 0x115e
	codepoints["MGRLVLLS"] = 0x1404
	codepoints["SRVCLSNM"] = 0x1147
	codepoints["SPVNAM"] = 0x115d
	codepoints["SRVNAM"] = 0x116d
	codepoints["SRVRLSLV"] = 0x115a
	codepoints["ACCSEC"] = 0x106d
	codepoints["SECMGRNM"] = 0x1196
	codepoints["SECMEC"] = 0x11a2
	codepoints["RDBNAM"] = 0x2110
	codepoints["SECCHK"] = 0x106e
	codepoints["PASSWORD"] = 0x11a1
	codepoints["USRID"] = 0x11a0
	codepoints["ACCRDB"] = 0x2001
	codepoints["RDBRLLBCK"] = 0x2407
	codepoints["PRID"] = 0x112e
	codepoints["TYPDEFNAM"] = 0x002f
	codepoints["EXCSATRD"] = 0x1443
	codepoints["ACCSECRD"] = 0x14ac
	codepoints["SECCHKRM"] = 0x1219
	codepoints["RDBNFNRM"] = 0x2211
	codepoints["SQLCARD"] = 0x2408
	codepoints["SECCHKCD"] = 0x11a4
	
	def __init__(self):
		return
	
	dqsrss_count = 0
	environ = 0
	DRM = ""
	errcode = 0
	
	def buildEXCSAT(self, EXTNAM = "0", MGRLVLLS="0", SPVNAM = "", SRVCLSNM = "0", SRVNAM = "0", SRVRLSLV = "0"):
		BLOCK_len = 0
		EXCSAT_start = "\xD0\x41\x00"
		EXCSAT_codepoint = struct.pack('>h',0x1041)
		EXCSAT_len = 0
		
		self.dqsrss_count+=1
		
		length = len(EXCSAT_codepoint) + 2
		
		# EXTNAM(External Name)
		EXCSAT_EXTNAM_codepoint = struct.pack('>h',0x115e)

		if EXTNAM != "0":
			EXCSAT_EXTNAM_value = EXTNAM
		else:
			EXCSAT_EXTNAM_value = self.ascii2ebcdic("db2bp.exe           " + "0ABC097C000" + ("\x00" * 32) + "-0001DIEGO" + ("\x20" * 25) + "SAMPLE2 0DB2" + ("\x20"*13))
		
		if EXTNAM != "":
			EXCSAT_EXTNAM_length = struct.pack('>h', len(EXCSAT_EXTNAM_value) + len(EXCSAT_EXTNAM_codepoint) + 2)
			length += len(EXCSAT_EXTNAM_value) + len(EXCSAT_EXTNAM_codepoint) + 2
		
		
		# MGRLVLLS(Manager Levels)
		EXCSAT_MGRLVLLS_codepoint = struct.pack('>h',0x1404)

		if MGRLVLLS != "0":
			EXCSAT_MGRLVLLS_value = MGRLVLLS
		else:
			EXCSAT_MGRLVLLS_value =  "\x14\x03" + "\x00\x07" + "\x24\x07" + "\x00\x07"
			EXCSAT_MGRLVLLS_value += "\x14\x74" + "\x00\x05" 
			EXCSAT_MGRLVLLS_value += "\x24\x0F" + "\x00\x07"
			EXCSAT_MGRLVLLS_value += "\x14\x40" + "\x00\x07"
		
		if MGRLVLLS != "":
			EXCSAT_MGRLVLLS_length = struct.pack('>h',len(EXCSAT_MGRLVLLS_value)+len(EXCSAT_MGRLVLLS_codepoint)+2)
			length += len(EXCSAT_MGRLVLLS_value) + len(EXCSAT_MGRLVLLS_codepoint) + 2
		
		# SPVNAM(Supervisor Name)
		EXCSAT_SPVNAM_codepoint = struct.pack('>h',self.codepoints["SPVNAM"])
		
		if SPVNAM != "0":
			EXCSAT_SPVNAM_value = self.ascii2ebcdic(SPVNAM)
		else:
			EXCSAT_SPVNAM_value = self.ascii2ebcdic("Diego")
		
		if SPVNAM != "":
			EXCSAT_SPVNAM_length = struct.pack('>h',len(EXCSAT_SPVNAM_value)+len(EXCSAT_SPVNAM_codepoint)+2)
			length += len(EXCSAT_SPVNAM_value)+len(EXCSAT_SPVNAM_codepoint)+2

		# SRVCLSNM(Server Class Name)
		EXCSAT_SRVCLSNM_codepoint = struct.pack('>h',0x1147)
		
		if SRVCLSNM != "0":
			EXCSAT_SRVCLSNM_value = SRVCLSNM 
		else:
			EXCSAT_SRVCLSNM_value = self.ascii2ebcdic("QDB2/NT")
		
		if SRVCLSNM != "":
			EXCSAT_SRVCLSNM_length = struct.pack('>h',len(EXCSAT_SRVCLSNM_value)+len(EXCSAT_SRVCLSNM_codepoint)+2)
			length += len(EXCSAT_SRVCLSNM_value) + len(EXCSAT_SRVCLSNM_codepoint) + 2
		
		# SRVNAM(Server Name)
		EXCSAT_SRVNAM_codepoint = struct.pack('>h',0x116d)
		if SRVNAM != "0":
			EXCSAT_SRVNAM_value = SRVNAM
		else:
			EXCSAT_SRVNAM_value = self.ascii2ebcdic("C0C4C0L4")
			
		if SRVNAM != "":
			EXCSAT_SRVNAM_length = struct.pack('>h',len(EXCSAT_SRVNAM_value)+len(EXCSAT_SRVNAM_codepoint)+2)
			length += len(EXCSAT_SRVNAM_value) + len(EXCSAT_SRVNAM_codepoint) + 2
		
		# SRVRLSLV(Server Product Release Level) 
		EXCSAT_SRVRLSLV_codepoint = struct.pack('>h',0x115a)
		if SRVRLSLV != "0":
			EXCSAT_SRVRLSLV_value = SRVRLSLV
		else:
			EXCSAT_SRVRLSLV_value = self.ascii2ebcdic("SQL08025")
			
		if SRVRLSLV != "":
			EXCSAT_SRVRLSLV_length = struct.pack('>h',len(EXCSAT_SRVRLSLV_value)+len(EXCSAT_SRVRLSLV_codepoint)+2)
			length += len(EXCSAT_SRVRLSLV_value) + len(EXCSAT_SRVRLSLV_codepoint) + 2
		
		BLOCK_len = struct.pack('>h',length + len(EXCSAT_start) + 2 + 1)
		EXCSAT_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += EXCSAT_start + chr(self.dqsrss_count) + EXCSAT_len + EXCSAT_codepoint
		if EXTNAM != "":
			packet += EXCSAT_EXTNAM_length + EXCSAT_EXTNAM_codepoint + EXCSAT_EXTNAM_value

		if MGRLVLLS != "":
			packet += EXCSAT_MGRLVLLS_length + EXCSAT_MGRLVLLS_codepoint + EXCSAT_MGRLVLLS_value

		if SPVNAM != "":
			packet += EXCSAT_SPVNAM_length + EXCSAT_SPVNAM_codepoint + EXCSAT_SPVNAM_value
			
		if SRVCLSNM != "":
			packet += EXCSAT_SRVCLSNM_length + EXCSAT_SRVCLSNM_codepoint + EXCSAT_SRVCLSNM_value
		
		if SRVNAM != "":
			packet += EXCSAT_SRVNAM_length + EXCSAT_SRVNAM_codepoint + EXCSAT_SRVNAM_value
		
		if SRVRLSLV != "":
			packet += EXCSAT_SRVRLSLV_length + EXCSAT_SRVRLSLV_codepoint + EXCSAT_SRVRLSLV_value
		
		return packet
	
	def buildACCSEC(self, SECMGRNM = "", SECMEC = "0", RDBNAM = "0"):
		BLOCK_len = 0
		ACCSEC_start = "\xD0\x41\x00"
		ACCSEC_codepoint = struct.pack('>h',0x106d)
		ACCSEC_len = 0
		
		self.dqsrss_count+=1
		
		length = len(ACCSEC_codepoint) + 2
		
		ACCSEC_SECMGRNM_codepoint = struct.pack(">h",self.codepoints["SECMGRNM"])
		if SECMGRNM != "0":
			ACCSEC_SECMGRNM_value = self.ascii2ebcdic(SECMGRNM)
		else:
			ACCSEC_SECMGRNM_value = self.ascii2ebcdic("Foobar")
		
		if SECMGRNM != "":
			ACCSEC_SECMGRNM_length = struct.pack(">h",len(ACCSEC_SECMGRNM_value) + len(ACCSEC_SECMGRNM_codepoint) + 2)
			length += len(ACCSEC_SECMGRNM_value) + 2 + 2
		
		ACCSEC_SECMEC_codepoint = struct.pack('>h',0x11a2)

		if SECMEC != "0":
			ACCSEC_SECMEC_value = SECMEC
		else:
			if len(self.Password) == 0:
				""" Userid only """
				ACCSEC_SECMEC_value = struct.pack('>h',0x0004)
			else:
				""" Userid and Password """
				ACCSEC_SECMEC_value = struct.pack('>h',0x0003)
		
		if SECMEC != "":
			ACCSEC_SECMEC_length = struct.pack('>h',len(ACCSEC_SECMEC_value)+len(ACCSEC_SECMEC_codepoint) + 2)
			length += len(ACCSEC_SECMEC_value) + 2 + 2
		
		ACCSEC_RDBNAM_codepoint = struct.pack('>h',0x2110)
		if RDBNAM != "0":
			ACCSEC_RDBNAM_value = RDBNAM
		else:
			ACCSEC_RDBNAM_value = self.ascii2ebcdic((self.DB+("\x20"*(18-len(self.DB)))))
		
		if RDBNAM != "":
			ACCSEC_RDBNAM_length = struct.pack('>h',len(ACCSEC_RDBNAM_value) + 2 + 2)
			length += len(ACCSEC_RDBNAM_value) + 2 + 2
		
		BLOCK_len = struct.pack('>h',length + len(ACCSEC_start) + 2 + 1)
		ACCSEC_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += ACCSEC_start + chr(self.dqsrss_count) + ACCSEC_len + ACCSEC_codepoint
		if SECMEC != "":
			packet += ACCSEC_SECMEC_length + ACCSEC_SECMEC_codepoint + ACCSEC_SECMEC_value
		if RDBNAM != "":
			packet += ACCSEC_RDBNAM_length + ACCSEC_RDBNAM_codepoint + ACCSEC_RDBNAM_value
		
		return packet
	
	def buildSECCHK(self, SECMEC = "0", RDBNAM = "0", PASSWORD = "0", USRID = "0"):
		BLOCK_len = 0

		SECCHK_start = "\xD0\x41\x00"
		SECCHK_codepoint = struct.pack('>h',0x106e)
		SECCHK_len = 0
		
		self.dqsrss_count+=1
		
		length = len(SECCHK_codepoint) + 2
		
		SECCHK_SECMEC_codepoint = struct.pack('>h',0x11a2)

		if SECMEC != "0":
			SECCHK_SECMEC_value = SECMEC
		else:
			if len(self.Password) == 0:
				""" Userid only """
				SECCHK_SECMEC_value = struct.pack('>h',0x0004)
			else:
				""" Userid and Password """
				SECCHK_SECMEC_value = struct.pack('>h',0x0003)
		
		if SECMEC != "":
			SECCHK_SECMEC_length = struct.pack('>h',(len(SECCHK_SECMEC_value) + 2 + 2))
			length += len(SECCHK_SECMEC_value) + 2 + 2
		
		SECCHK_RDBNAM_codepoint = struct.pack('>h',0x2110)
		if RDBNAM != "0":
			SECCHK_RDBNAM_value = RDBNAM
		else:
			SECCHK_RDBNAM_value = self.ascii2ebcdic((self.DB + ("\x20"*(18-len(self.DB)))))
		
		if RDBNAM != "":
			SECCHK_RDBNAM_length = struct.pack('>h',len(SECCHK_RDBNAM_value) + 2 + 2)
			length += len(SECCHK_RDBNAM_value) + 2 + 2
		
		SECCHK_PASSWORD_codepoint = struct.pack('>h',0x11a1)
		if PASSWORD != "0":
			SECCHK_PASSWORD_value = PASSWORD
		else:
			if len(self.Password) != 0:
				SECCHK_PASSWORD_value = self.ascii2ebcdic(self.Password)
			else:
				SECCHK_PASSWORD_value = ""
				PASSWORD=""
				
		if PASSWORD != "":
			SECCHK_PASSWORD_length = struct.pack('>h',len(SECCHK_PASSWORD_value) + 2 + 2)
			length += len(SECCHK_PASSWORD_value) + 2 + 2
		
		SECCHK_USRID_codepoint = struct.pack('>h',0x11a0)
		if USRID != "0":
			SECCHK_USRID_value = USRID
		else:
			SECCHK_USRID_value = self.ascii2ebcdic(self.Userid)
		
		if USRID != "":
			SECCHK_USRID_length = struct.pack('>h',len(SECCHK_USRID_value) + 2 + 2)
			length += len(SECCHK_USRID_value) + 2 + 2
		
		BLOCK_len = struct.pack('>h',length + len(SECCHK_start) + 2 + 1)
		SECCHK_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += SECCHK_start + chr(self.dqsrss_count) + SECCHK_len + SECCHK_codepoint
		if SECMEC != "":
			packet += SECCHK_SECMEC_length + SECCHK_SECMEC_codepoint + SECCHK_SECMEC_value
		if RDBNAM != "":
			packet += SECCHK_RDBNAM_length + SECCHK_RDBNAM_codepoint + SECCHK_RDBNAM_value
		if PASSWORD != "":
			packet += SECCHK_PASSWORD_length + SECCHK_PASSWORD_codepoint + SECCHK_PASSWORD_value
		if USRID != "":
			packet += SECCHK_USRID_length + SECCHK_USRID_codepoint + SECCHK_USRID_value

		return packet
	
	def buildACCRDB(self, RDBRLLBCK = "0", CRRTKN = "0", RDBNAM = "0", PRID = "0", TYPDEFNAM = "0", PRDDTA = "0"):
		BLOCK_len = 0

		ACCRDB_start = "\xD0\x01\x00"
		ACCRDB_codepoint = struct.pack('>h',0x2001)
		ACCRDB_len = 0
		
		self.dqsrss_count+=1
		
		length = len(ACCRDB_codepoint) + 2
		
		ACCRDB_RDBRLLBCK_codepoint = struct.pack('>h',0x210f)
		if RDBRLLBCK != "0":
			ACCRDB_RDBRLLBCK_value = RDBRLLBCK
		else:
			ACCRDB_RDBRLLBCK_value = struct.pack('>h',0x2407)
		
		ACCRDB_RDBRLLBCK_length = struct.pack('>h',len(ACCRDB_RDBRLLBCK_value) + 2 + 2)
		length += len(ACCRDB_RDBRLLBCK_value) + 2 + 2
		
		ACCRDB_CRRTKN_codepoint = struct.pack('>h',0x2135)
		if CRRTKN != "0":
			ACCRDB_CRRTKN_value = CRRTKN
		else:
			ACCRDB_CRRTKN_value = (self.ascii2ebcdic("C0A8C301.E007") + "\x01\x43\x80\x22\x04\x38")
			
		ACCRDB_CRRTKN_length = struct.pack('>h',len(ACCRDB_CRRTKN_value) + 2 + 2)
		length += len(ACCRDB_CRRTKN_value) + 2 + 2
		
		ACCRDB_RDBNAM_codepoint = struct.pack('>h',0x2110)
		if RDBNAM != "0":
			ACCRDB_RDBNAM_value = RDBNAM
		else:
			ACCRDB_RDBNAM_value = self.ascii2ebcdic(self.DB + ("\x20"*(18-len(self.DB))))
		
		if RDBNAM != "":
			ACCRDB_RDBNAM_length = struct.pack('>h',len(ACCRDB_RDBNAM_value) + 2 + 2)
			length += len(ACCRDB_RDBNAM_value) + 2 + 2
		
		ACCRDB_PRID_codepoint = struct.pack('>h',0x112e)
		if PRID != "0":
			ACCRDB_PRID_value = PRID
		else:
			ACCRDB_PRID_value = self.ascii2ebcdic("SQL08025")
		ACCRDB_PRID_length = struct.pack('>h',len(ACCRDB_PRID_value) + 2 + 2)
		length += len(ACCRDB_PRID_value) + 2 + 2

		ACCRDB_TYPDEFNAM_codepoint = struct.pack('>h',0x002f)
		if TYPDEFNAM != "0":
			ACCRDB_TYPDEFNAM_value = TYPDEFNAM
		else:
			ACCRDB_TYPDEFNAM_value = self.ascii2ebcdic("QTDSQLX86")
			
		ACCRDB_TYPDEFNAM_length = struct.pack('>h',len(ACCRDB_TYPDEFNAM_value) + 2 + 2)
		length += len(ACCRDB_TYPDEFNAM_value) + 2 + 2

		ACCRDB_TYPDEFOVR_codepoint = struct.pack('>h',0x0035)
		ACCRDB_TYPDEFOVR_length = 2 + 2
		length += 2 + 2
		
		ACCRDB_TYPDEFOVR_CCSIDSBC_codepoint = struct.pack('>h',0x119c)
		ACCRDB_TYPDEFOVR_CCSIDSBC_value = struct.pack('>h',0x04e4)
		ACCRDB_TYPDEFOVR_CCSIDSBC_length = struct.pack('>h',len(ACCRDB_TYPDEFOVR_CCSIDSBC_value) + 2 + 2)
		length += len(ACCRDB_TYPDEFOVR_CCSIDSBC_value) + 2 + 2
		ACCRDB_TYPDEFOVR_length += len(ACCRDB_TYPDEFOVR_CCSIDSBC_value) + 2 + 2
		
		ACCRDB_TYPDEFOVR_CCSIDDBC_codepoint = struct.pack('>h',0x119d)
		ACCRDB_TYPDEFOVR_CCSIDDBC_value = struct.pack('>h',0x04b0)
		ACCRDB_TYPDEFOVR_CCSIDDBC_length = struct.pack('>h',len(ACCRDB_TYPDEFOVR_CCSIDDBC_value) + 2 + 2)
		length += len(ACCRDB_TYPDEFOVR_CCSIDDBC_value) + 2 + 2
		ACCRDB_TYPDEFOVR_length += len(ACCRDB_TYPDEFOVR_CCSIDDBC_value) + 2 + 2
		
		ACCRDB_TYPDEFOVR_CCSIDMBC_codepoint = struct.pack('>h',0x119e)
		ACCRDB_TYPDEFOVR_CCSIDMBC_value = struct.pack('>h',0x04e4)
		ACCRDB_TYPDEFOVR_CCSIDMBC_length = struct.pack('>h',len(ACCRDB_TYPDEFOVR_CCSIDMBC_value) + 2 + 2)
		length += len(ACCRDB_TYPDEFOVR_CCSIDMBC_value) + 2 + 2
		ACCRDB_TYPDEFOVR_length += len(ACCRDB_TYPDEFOVR_CCSIDMBC_value) + 2 + 2
		
		ACCRDB_TYPDEFOVR_length = struct.pack(">h",ACCRDB_TYPDEFOVR_length)
		
		ACCRDB_PRDDTA_codepoint = struct.pack('>h',0x2104)
		if PRDDTA != "0":
			ACCRDB_PRDDTA_value = PRDDTA
		else:
			ACCRDB_PRDDTA_value = "\x37" + self.ascii2ebcdic("SQL08025NT" + ("\x20"*16) + "db2bp.exe" + ("\x20"*11) + self.Userid + "\x00")
		
		ACCRDB_PRDDTA_length = struct.pack('>h',len(ACCRDB_PRDDTA_value) + 2 + 2)
		length += len(ACCRDB_PRDDTA_value) + 2 + 2
		
		ACCRDB_end = "\x00\x05\x21\x3b\xf1"
		length += len(ACCRDB_end)
		
		BLOCK_len = struct.pack('>h',length + len(ACCRDB_start) + 2 + 1)
		ACCRDB_len = struct.pack('>h',length)

		packet = ""
		packet += BLOCK_len
		packet += ACCRDB_start + chr(self.dqsrss_count) + ACCRDB_len + ACCRDB_codepoint 
		packet += ACCRDB_RDBRLLBCK_length + ACCRDB_RDBRLLBCK_codepoint + ACCRDB_RDBRLLBCK_value
		packet += ACCRDB_CRRTKN_length + ACCRDB_CRRTKN_codepoint + ACCRDB_CRRTKN_value
		if RDBNAM != "":
			packet += ACCRDB_RDBNAM_length + ACCRDB_RDBNAM_codepoint + ACCRDB_RDBNAM_value
		packet += ACCRDB_PRID_length + ACCRDB_PRID_codepoint + ACCRDB_PRID_value
		packet += ACCRDB_TYPDEFNAM_length + ACCRDB_TYPDEFNAM_codepoint + ACCRDB_TYPDEFNAM_value
		packet += ACCRDB_TYPDEFOVR_length + ACCRDB_TYPDEFOVR_codepoint
		packet += ACCRDB_TYPDEFOVR_CCSIDSBC_length + ACCRDB_TYPDEFOVR_CCSIDSBC_codepoint + ACCRDB_TYPDEFOVR_CCSIDSBC_value
		packet += ACCRDB_TYPDEFOVR_CCSIDDBC_length + ACCRDB_TYPDEFOVR_CCSIDDBC_codepoint + ACCRDB_TYPDEFOVR_CCSIDDBC_value
		packet += ACCRDB_TYPDEFOVR_CCSIDMBC_length + ACCRDB_TYPDEFOVR_CCSIDMBC_codepoint + ACCRDB_TYPDEFOVR_CCSIDMBC_value
		packet += ACCRDB_PRDDTA_length + ACCRDB_PRDDTA_codepoint + ACCRDB_PRDDTA_value
		packet += ACCRDB_end
		
		return packet
	
	def buildEXCSQLSET(self,PKGNAMCSN = ""):
		BLOCK_len = 0

		EXCSQLSET_start = "\xD0\x51\x00"
		EXCSQLSET_codepoint = struct.pack('>h',0x2014)
		EXCSQLSET_len = 0
		
		self.dqsrss_count+=1
		
		length = len(EXCSQLSET_codepoint) + 2
		
		EXCSQLSET_PKGNAMCSN_codepoint = struct.pack('>h',0x2113)

		if PKGNAMCSN != "":
			EXCSQLSET_PKGNAMCSN_value = PKGNAMCSN
		else:
			EXCSQLSET_PKGNAMCSN_value =  (self.DB + ("\x20"*(18-len(self.DB))))
			EXCSQLSET_PKGNAMCSN_value += ("NULLID" + ("\x20"*(18-len("NULLID"))))
			EXCSQLSET_PKGNAMCSN_value += ("SQLC2E07" + ("\x20"*(18-len("SQLC2E07"))))
			EXCSQLSET_PKGNAMCSN_value += ("\x01"*8) + "\x00" + "\x01"
		
		EXCSQLSET_PKGNAMCSN_length = struct.pack('>h',len(EXCSQLSET_PKGNAMCSN_value) + 2 + 2)
		
		length += len(EXCSQLSET_PKGNAMCSN_value) + 2 + 2
		
		BLOCK_len = struct.pack('>h',length + len(EXCSQLSET_start) + 2 + 1)
		EXCSQLSET_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += EXCSQLSET_start + chr(self.dqsrss_count) + EXCSQLSET_len + EXCSQLSET_codepoint 
		packet += EXCSQLSET_PKGNAMCSN_length + EXCSQLSET_PKGNAMCSN_codepoint + EXCSQLSET_PKGNAMCSN_value
		
		return packet
	
	def buildEXCSQLIMM(self,EXCSQLIMM = "", RDBCMTOK = ""):
		BLOCK_len = 0

		EXCSQLIMM_start = "\xd0\x51\x00"
		EXCSQLIMM_codepoint = struct.pack('>h',0x200a)
		
		self.dqsrss_count+=1

		length = len(EXCSQLIMM_codepoint) + 2
		
		EXCSQLIMM_PKGNAMCSN_codepoint = struct.pack('>h',0x2113)

		if EXCSQLIMM != "":
			EXCSQLIMM_PKGNAMCSN_value = PKGNAMCSN
		else:
			EXCSQLIMM_PKGNAMCSN_value =  (self.DB + ("\x20"*(18-len(self.DB))))
			EXCSQLIMM_PKGNAMCSN_value += ("NULLID" + ("\x20"*(18-len("NULLID"))))
			EXCSQLIMM_PKGNAMCSN_value += ("SQLC2E07" + ("\x20"*(18-len("SQLC2E07"))))
			EXCSQLIMM_PKGNAMCSN_value += ("A"*5) + "\x63" + "\x45" + "\x55" + "\x00" + "\xcb" 
		
		EXCSQLIMM_PKGNAMCSN_length = struct.pack('>h',len(EXCSQLIMM_PKGNAMCSN_value) + 2 + 2)
		length += len(EXCSQLIMM_PKGNAMCSN_value) + 2 + 2
		
		EXCSQLIMM_RDBCMTOK_codepoint = struct.pack('>h',0x2105)
		
		if RDBCMTOK != "":
			EXCSQLIMM_RDBCMTOK_value = RDBCMTOK
		else:
			EXCSQLIMM_RDBCMTOK_value = "\xf1"
		
		EXCSQLIMM_RDBCMTOK_length = struct.pack('>h',len(EXCSQLIMM_RDBCMTOK_value) + 2 + 2)
		length += len(EXCSQLIMM_RDBCMTOK_value) + 2 + 2
		
		BLOCK_len = struct.pack('>h',length + len(EXCSQLIMM_start) + 2 + 1)
		EXCSQLIMM_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += EXCSQLIMM_start + chr(self.dqsrss_count) + EXCSQLIMM_len + EXCSQLIMM_codepoint 
		packet += EXCSQLIMM_PKGNAMCSN_length + EXCSQLIMM_PKGNAMCSN_codepoint + EXCSQLIMM_PKGNAMCSN_value
		packet += EXCSQLIMM_RDBCMTOK_length + EXCSQLIMM_RDBCMTOK_codepoint + EXCSQLIMM_RDBCMTOK_value
		
		return packet
	
		
	def buildSQLSTT(self, SQLSTT="", START=""):
		BLOCK_len = 0
		
		if START != "":
			SQLSTT_start = START
		else:
			SQLSTT_start = "\xD0\x43\x00"
		
		SQLSTT_codepoint = struct.pack('>h',0x2414)
		
		self.dqsrss_count+=1
		
		length = len(SQLSTT_codepoint) + 2
		
		if SQLSTT != "":
			SQLSTT_value = SQLSTT
		else:
			# I'm not sure, but command length may be up to 5 bytes even, we will treat it as 4 bytes though.
			SQLSTT_value = """create table TEST ( "USERID" character (8)  not null, "FIRST" character (15), "LAST" character(20), primary key (USERID))"""
			
		SQLSTT_value += "\xff"		

		SQLSTT_value_length = struct.pack(">l",len(SQLSTT_value)-1)
		
		length += len(SQLSTT_value) + 4 + 1
		
		SQLSTT_len = struct.pack(">h",length)
		BLOCK_len = struct.pack(">h",length + len(SQLSTT_start) + 2 + 1)
		
		packet = ""
		packet += BLOCK_len
		packet += SQLSTT_start + chr(self.dqsrss_count)
		packet += SQLSTT_len + SQLSTT_codepoint
		packet += "\x00" + SQLSTT_value_length + SQLSTT_value
		
		return packet
			
	
	def buildRDBCMM(self):
		""" Commit unit of work. """
		RDBCMM_start = "\xd0\x01\x00"
		RDBCMM_length = struct.pack(">h",0x0004)
		RDBCMM_codepoint = struct.pack(">h",0x200e)

		BLOCK_len = struct.pack(">h",len(RDBCMM_start)+len(RDBCMM_length)+len(RDBCMM_codepoint)+2+1)
		
		packet = ""
		packet += BLOCK_len
		packet += RDBCMM_start + chr(self.dqsrss_count)
		packet += RDBCMM_length
		packet += RDBCMM_codepoint
		
		return packet
		
	def buildDISCONNECT(self):
		BLOCK_len = 0

		DISCONNECT_start = "\xD0\x05\x00"
		DISCONNECT_codepoint = struct.pack(">h",0xc004)
		
		self.dqsrss_count+=1

		length = len(DISCONNECT_codepoint) + 2
		
		BLOCK_len = struct.pack('>h',length + len(DISCONNECT_start) + 2 + 1)
		DISCONNECT_len = struct.pack('>h',length)
		
		packet = ""
		packet += BLOCK_len
		packet += DISCONNECT_start + chr(self.dqsrss_count) + DISCONNECT_len + DISCONNECT_codepoint

		return packet
	
	def requestSession(self,s):
		EXCSAT = self.buildEXCSAT()
		ACCSEC = self.buildACCSEC()
		SECCHK = self.buildSECCHK()
		ACCRDB = self.buildACCRDB()
		
		self.dqsrss_count=0
		
		s.send(EXCSAT+ACCSEC+SECCHK+ACCRDB)
		return
	
	def execProcedure(self,s,cmd,WINPATH=""):
		WINDOWS_PATH = 'c:\winnt\system32'
		PROCEDURE_NAME = "db2proc"
        
		if WINPATH != "":
			WINDOWS_PATH = WINPATH
        
		self.execImmediateStatement(s,"CREATE PROCEDURE %s (IN cmd varchar(200)) EXTERNAL NAME '%s\msvcrt!system' LANGUAGE C DETERMINISTIC PARAMETER STYLE DB2SQL" % (PROCEDURE_NAME,WINDOWS_PATH))
		self.execImmediateStatement(s,"call %s('%s')" % (PROCEDURE_NAME,cmd))

		return
	
	def execImmediateStatement(self,s,cmd,STDOUT=0,replyget=0):
		EXCSAT = self.buildEXCSAT(EXTNAM="",SRVCLSNM="",SRVNAM="",SRVRLSLV="",MGRLVLLS="\x14\xcc\x04\xe4")

		EXCSQLSET = self.buildEXCSQLSET()

		self.dqsrss_count -=1
		
		SQLLOCALE = self.buildSQLSTT(SQLSTT="""SET CURRENT LOCALE LC_CTYPE = 'en_US'""")
		
		"""
		EXCSQLIMM and SQLSTT share the same ID as we're telling the server that it 
		will `execute the immediate' (EXCSQLIMM) `statement' (SQLSTT)
		"""
		EXECIMMEDIATE = self.buildEXCSQLIMM()
		self.dqsrss_count -=1
		STATEMENT = self.buildSQLSTT(SQLSTT=cmd,START="\xd0\x03\x00")
		
		if self.environ == 0:
			if STDOUT == 0:
				self.sendPacket(s,EXCSAT+EXCSQLSET+SQLLOCALE+EXECIMMEDIATE+STATEMENT)
			else:
				print EXCSAT+EXCSQLSET+SQLLOCALE+EXECIMMEDIATE+STATEMENT
			
			""" We only send the Environment once. """
			self.environ = 1
		else:
			if STDOUT == 0:
				self.sendPacket(s,EXECIMMEDIATE+STATEMENT)
			else:
				print EXECIMMEDIATE+STATEMENT
		
		if replyget != 0:
			self.replyGet(s)
		self.sendPacket(s,self.buildRDBCMM())
		if replyget != 0:
			self.replyGet(s)
		
		return
	
	def sendPacket(self,s,packet):
		s.send(packet)
		self.dqsrss_count = 0
		return
	
	def replyGet(self, s, verbose=1):
		dic = {}
		s.settimeout(3)
		
		while 1:
			try:
				lenstr = s.recv(2)
			except timeout:
				if len(dic) != 0:
					break				
				else:
					if verbose:
						print "Invalid DRDA Protocol response."
						
					sys.exit(1)
					
			if len(lenstr) != 2:
				break
			
			length_tuple = struct.unpack(">h",lenstr[0:2])
			length = length_tuple[0] - 2
			dss = s.recv(length)
			if len(dss) != length:
				if verbose:
					print "DMA Length error in protocol"
				sys.exit(0)
			
			dss_codepoint = struct.unpack(">h",dss[6:8])
			dic[dss_codepoint[0]] = dss[4:]
			
			if dic.has_key(self.codepoints["SQLCARD"]):
				break
			
			if dic.has_key(self.codepoints["ACCSECRD"]):
				cp = self.getCodepointfromDQS(dic[self.codepoints["ACCSECRD"]],self.codepoints["SECCHKCD"])
				if cp != "":
					break
				
		if self.DRM == "":
			self.DRM = dic
		
		return dic
	
	def isAccepted(self,verbose=1):
		SECCHKCD = "\x00"
		SUGSECMEC = "\x00"
		
		if self.DRM.has_key(self.codepoints["RDBNFNRM"]) or len(self.DB) > 8:
			msg = "Invalid database name"
			if verbose:
				print msg
			self.errcode = 0xFF
			return 0
		
		if self.DRM.has_key(self.codepoints["ACCSECRD"]):
			cp = self.getCodepointfromDQS(self.DRM[self.codepoints["ACCSECRD"]],self.codepoints["SECCHKCD"])
			if cp != "":
				SECCHKCD = cp[1]
			
			cp = self.getCodepointfromDQS(self.DRM[self.codepoints["ACCSECRD"]],self.codepoints["SECMEC"])
			if cp != "":
				SUGSECMEC = cp[1]
				
		if not self.DRM.has_key(self.codepoints["SECCHKRM"]) and SECCHKCD == "\x00":
			msg = "Invalid DRDA protocol response."
			if verbose:
				print msg
			return 0
		elif SECCHKCD == "\x00":
			cp = self.getCodepointfromDQS(self.DRM[self.codepoints["SECCHKRM"]],self.codepoints["SECCHKCD"])
			if cp != "":
				SECCHKCD = cp[1]
		
		if SECCHKCD == "\x00":
			return 1
		
		msg = "Unknown DRDA response error."
		
		if SECCHKCD == "\x0E":
			msg = "Password expired."
		if SECCHKCD == "\x0F":
			msg = "Username/Password invalid."
		if SECCHKCD == "\x13":
			msg = "Username invalid."
		if SECCHKCD == "\x14":
			msg = "Username revoked."
		if SECCHKCD == "\x01":
			msg = "Security mechanism not supported."

		msg += " (Error code %s)" % repr(SECCHKCD)
		
		if verbose:
			print "Error, " + msg
		if SUGSECMEC != "\x00" and verbose:
			sys.stdout.write("Suggested method by the server: ")
			if SUGSECMEC == "\x03":
				print "Userid and password"
			elif SUGSECMEC == "\x04":
				print "Userid only"
			else:
				print "Encrypted userid and password"

		self.errcode = ord(SECCHKCD)
		return 0
	
	def getErrCode(self):
		return self.errcode
		
	def getVersion(self):
		EXCSATRD = self.DRM[self.codepoints["EXCSATRD"]]

		cp = self.getCodepointfromDQS(EXCSATRD,self.codepoints["SRVRLSLV"])
		
		if cp == "":
			print "DRDA protocol error."
			sys.exit(1)
		else:
			if cp[1] < 4:
				return ""
			version = self.ebcdic2ascii(cp[1])
			if cp[1] > 7:
				return "%s.%s.%s" % (version[4:5],version[6:7],version[7:])
			else:
				return "%s.%s" % (version[4:5],version[6:7])
		
		return ""
	
	def getOS(self):
		EXCSATRD = self.DRM[self.codepoints["EXCSATRD"]]
		
		cp = self.getCodepointfromDQS(EXCSATRD,self.codepoints["SRVCLSNM"])
		
		if cp == "":
			print "DRDA Protocol error"
			sys.exit(1)
		else:
			os = self.ebcdic2ascii(cp[1])
			if len(os) > len("QDB2/"):
				return os[5:]
		
		return ""
	
	"""
	Will return a list containing:
	l[0]: Length of l[1]
	l[1]: String owned by the given codepoint
	"""
	def getCodepointfromDQS(self,dqs,codepoint):		
		offset = 4
		length = 0
		
		block_length = len(dqs)
		
		while 1:
			length = struct.unpack(">h",dqs[offset:offset+2])
			cp = struct.unpack(">h",dqs[offset+2:offset+4])

			cp = cp[0]
			length = length[0]
			
			if cp == codepoint:
				field = dqs[offset+4:offset+length]
				val = [length-4,field]
				return val
			
			offset += length
			if offset == block_length:
				break
		
		return ""	
		
	def Disconnect(self,s):
		s.send(self.buildDISCONNECT())
		s.close()
		return
	
	def ascii2ebcdic(self,data):
		enc = codecs.getencoder('ibm037')		
		return enc(data)[0]
	
	def ebcdic2ascii(self,data):
		enc = codecs.getdecoder('ibm037')
		return enc(data)[0]
	
	def setUserid(self,userid):
		if self.errcode != 0:
			self.errcode = 0
			
		self.Userid = userid
		return
			
	def setPassword(self,password):
		if self.errcode != 0:
			self.errcode = 0
		self.Password = password
		return
			
	def setDB(self,db):
		if self.errcode != 0:
			self.errcode = 0
		if(len(db) > 8):
			""" Database can't be more than 8 bytes """
			self.errcode = 0xFF
		
		self.DB = db
		return

