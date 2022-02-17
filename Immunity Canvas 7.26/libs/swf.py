#!/usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

# SWF I/O interface


import sys
if "." not in sys.path: sys.path.append(".")

import struct, zlib, math
#from exploitutils import *

class SWF(TAGReader, TAGWriter):

    tagnames = { 0: 'END', \
             1: 'SHOWFRAME', \
             2: 'DEFINESHAPE', \
             3: 'FREECHARACTER', \
             4: 'PLACEOBJECT', \
             5: 'REMOVEOBJECT', \
             6: 'DEFINEBITS', \
             7: 'DEFINEBUTTON', \
             8: 'JPEGTABLES', \
             9: 'SETBACKGROUNDCOLOR', \
             10: 'DEFINEFONT', \
             11: 'DEFINETEXT', \
             12: 'DOACTION', \
             13: 'DEFINEFONTINFO', \
             14: 'DEFINESOUND', \
             15: 'STARTSOUND', \
             17: 'DEFINEBUTTONSOUND', \
             18:'SOUNDSTREAMHEAD', \
             19: 'SOUNDSTREAMBLOCK', \
             20: 'DEFINELOSSLESS', \
             21: 'DEFINEBITSJPEG2', \
             22: 'DEFINESHAPE2', \
             23: 'DEFINEBUTTONCXFORM', \
             24: 'PROTECT', \
             25: 'PATHSAREPOSTSCRIPT', \
             26: 'PLACEOBJECT2', \
             28: 'REMOVEOBJECT2', \
             29: 'SYNCFRAME', \
             31: 'FREEALL', \
             32: 'DEFINESHAPE3', \
             33: 'DEFINETEXT2', \
             34: 'DEFINEBUTTON2', \
             35: 'DEFINEBITSJPEG3', \
             36: 'DEFINELOSSLESS2', \
             37: 'DEFINEEDITTEXT', \
             38: 'DEFINEVIDEO', \
             39: 'DEFINESPRITE', \
             40: 'NAMECHARACTER', \
             41: 'SERIALNUMBER', \
             42: 'DEFINETEXTFORMAT', \
             43: 'FRAMELABEL', \
             45: 'SOUNDSTREAMHEAD2', \
             46: 'DEFINEMORPHSHAPE', \
             47: 'FRAMETAG', \
             48: 'DEFINEFONT2', \
             49: 'GENCOMMAND', \
             50: 'DEFINECOMMANDOBJ', \
             51: 'CHARACTERSET', \
             52: 'FONTREF', \
             56: 'EXPORTASSETS', \
             57: 'IMPORTASSETS', \
             58: 'ENABLEDEBUGGER', \
             59: 'INITACTION', \
             60: 'DEFINEVIDEOSTREAM', \
             61: 'VIDEOFRAME', \
             62:'DEFINEFONTINFO2', \
             64: 'ENABLEDEBUGGER2', \
             65: 'SCRIPTLIMITS', \
             69: 'FILEATTRIBUTES', \
             70: 'PLACEOBJECT3', \
             71: 'IMPORTASSETS2', \
             73: 'DEFINEALIGNZONES', \
             74: 'CSMTEXTSETTINGS', \
             75: 'DEFINEFONT3', \
             76: 'SYMBOLCLASS', \
             77: 'METADATA', \
             78: 'DEFINESCALINGGRID', \
             82: 'DOABCDEFINE', \
             83: 'DEFINESHAPE4', \
             84: 'DEFINEMORPHSHAPE2', \
             777: 'REFLEX', \
             1023: 'DEFINEBITSPTR' }

    def __init__(self, data):
        TAGReader.__init__(self, data)
        TAGWriter.__init__(self)
        
        self.header = {}
        self.tags = []
        self.uncompressed = ""
        self.bindata = ""

        self.readHeader(data)
        
        self.readTags(self.uncompressed[self.header["HeaderSize"]:])
        
        count = 1
        for tag in self.tags:
            #if tag["Type"] in (6,8,21,35,20,35):
            print "%03d type: %s(%X) - Size: %X - offset: %X - Data:" % (count, self.tagnames[tag["Type"]], tag["Type"], tag["DataSize"], (self.header["HeaderSize"]+tag["FileOffset"]))
            if tag["DataSize"]:
                for a in hexdump(tag["Data"][0:64]):
                    print "%s %s" % (a[0],a[1])
            count+=1
        
    def readHeader(self, data):
        if data[0] == "C":
            hCompressed = True
        else:
            hCompressed = False
        
        hSignature  = data[1:3]
        off = 3
        hVersion    = struct.unpack("<B", data[off])[0]
        off += 1
        hFileLength = struct.unpack("<L", data[off:off+4])[0]      #this's the uncompressed file length
        off += 4
        
        #From here it could be compressed
        if hCompressed:
            self.uncompressed = "F" + data[1:8] + zlib.decompress(data[8:])
            data = self.uncompressed
        else:
            self.uncompressed = data

        self.setBinary(data)
        self.setPointer(off)
        hFrameSize  = self.readRECT()
        off += int(math.ceil(( 5 + (hFrameSize[0] * 4)) / 8.0))
        hFrameRate  = struct.unpack("<H", data[off:off+2])[0]
        off += 2
        hFrameCount = struct.unpack("<H", data[off:off+2])[0]
        off += 2
        
        self.header = { "Compressed":hCompressed, \
                        "Version":hVersion, \
                        "FileLength":hFileLength, \
                        "FrameSize":hFrameSize, \
                        "FrameRate":hFrameRate, \
                        "FrameCount":hFrameCount, \
                        "HeaderSize":off }
        
        return self.header
    
    def readTags(self, data):
        off = 0
        while off < len(data):
            tag = self.readTag(data[off:])
            tag["FileOffset"] = off
            self.tags.append(tag)
            off += tag["TotalSize"]
        return self.tags
    
    def readTag(self, data):
        tmp = struct.unpack("<H", data[0:2])[0]
        type = tmp >> 6
        size = tmp & 0x003f
        off = 2
        if size == 0x3f:
            size = struct.unpack("<L", data[off:off+4])[0] #watch out!, is SIGNED
            off += 4
        data = data[off:off+size]
        
        return { "Type":type, \
                 "DataSize":size, \
                 "Data":data, \
                 "TotalSize":off+size }

    def writeTag(self, type, data, forceextra = False, datasize = None):
        if datasize == None: datasize = len(data)
        
        extra = None
        tmp = type << 6
        if datasize >= 0x3f or forceextra:
            tmp += 0x3f
            extra = datasize
        else:
            tmp += datasize
        
        res = struct.pack("<H", tmp)
        if extra: res += struct.pack("<L", extra)
        
        return res + data

#### Here we define the tag handlers ####
class TAGReader:
    def __init__(self, data):
        self.setBinary(data)
        self.setPointer(0)
    
    def getBinary(self):
        return self.binary
    
    def setBinary(self, data):
        self.binary = data
    
    def setPointer(self, ptr):
        self.ptr = ptr
    
    def read_uint(self, size):
        """read SIZE bits and decode it as an unsigned integer"""
        if   size ==  8: p = "<B"
        elif size == 16: p = "<H"
        elif size == 32: p = "<L"
        elif size == 64: p = "<Q"
        else:
            return None
        res = struct.unpack(p, self.binary[self.ptr:self.ptr+(size / 8)])[0]
        self.ptr += (size / 8)
        return res
        
    def read_sint(self, size):
        """read SIZE bits and decode it as a signed integer"""
        if   size ==  8: p = "<b"
        elif size == 16: p = "<h"
        elif size == 32: p = "<l"
        elif size == 64: p = "<q"
        else:
            return None
        res = struct.unpack(p, self.binary[self.ptr:self.ptr+(size / 8)])[0]
        self.ptr += (size / 8)
        return res

    def read_fpoint(self, size):
        """read SIZE bits and decode it as a fixed point number"""
        if   size == 16 or size == 32: 
            p = self.read_uint(size)
        else:
            return None
        integer = p >> (size/2)
        coma = (p << (size/2)) >> (size/2)
        return float("%d.%d" % (integer, coma))
    
    def readRECT(self):
        off = 0
        Nbits = int(readbits(self.binary, off, 5),2)
        off += 5
        Xmin = int(readbits(self.binary, off, Nbits),2)
        off += Nbits
        Xmax = int(readbits(self.binary, off, Nbits),2)
        off += Nbits
        Ymin = int(readbits(self.binary, off, Nbits),2)
        off += Nbits
        Ymax = int(readbits(self.binary, off, Nbits),2)
        off += Nbits
        
        self.ptr += int(math.ceil(off / 8.0))
        
        return (Nbits, Xmin, Xmax, Ymin, Ymax)
    
    def readbits(self, data, offset, nbits):
        """
        read <nbits> bits from data (binary) at offset <offset> and return a 2-base representation
        """
        
        res = ""
        offbytes = int(math.floor(offset / 8.0))
        bitoffset = offset - (offbytes * 8)
        bytes = int(math.ceil((bitoffset + nbits) / 8.0))
        data = data[offbytes:bytes+offbytes]
        for dataoffset in range(len(data)):
            byte = data[dataoffset]
            for bit in range(7,-1,-1):
                if dataoffset == 0 and bit >= (8-bitoffset):
                    continue
                res += str(divmod(ord(byte) >> bit,2)[1])
                if len(res) == nbits:
                    break
        return res
        
class TAGWriter:
    def __init__(self):
        pass

class PLACEOBJECT:
    def read(self):
        pass
    
        

######### support routines #############
def hexdump(buf):
    tbl=[]
    tmp=""
    hex=""
    i=0
    for a in buf:
        hex+="%02X "% ord(a)
        i+=1
        if ord(a) >=0x20 and ord(a) <0x7f:
            tmp+=a
        else:
            tmp+="."
        if i%16 == 0:
            tbl.append((hex, tmp))
            hex=""
            tmp=""
    tbl.append((hex, tmp))
    return tbl


f = open("test.swf","rb")
data = f.read()
swf = SWF(data)
