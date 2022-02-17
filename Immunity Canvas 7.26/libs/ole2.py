#!/usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


#OLE2 docfiles I/O lib

"""
TODO:
    respect endianess using the header (FEFF/FFFE)
    make extended SAT using SAT sectors
"""

import sys
if "." not in sys.path: sys.path.append(".")

import string
import struct
import math
import operator
from libs.ppt_io import *

class OLE2IO:
    def __init__(self):
        self.sectors      = dict()
        self.ssectors     = dict()
        self.msat         = list()
        self.sat          = dict()
        self.ssat         = dict()
        self.directory    = dict()
        self.fd           = 0

    def open(self, filename):
        self.filename     = filename

        try:
            self.fd = open(filename,"rb")
            
        except:
            raise Exception, "can't open file"
        
        data = self.fd.read()
        self.fd.close()
        
        self.openFromData(data)
    
    def openFromData(self, data):
        self.bindata = data
        self.createOLE2Header(data[0:512])
        self.createStructures()
    
    def createOLE2Header(self,data):
        self.oleheader             = OLE2Header(data)
        
        self.SectorSize            = pow(2, self.oleheader.getSectorSize())
        self.ShortSectorSize       = pow(2, self.oleheader.getShortSectorSize())
        self.SIDfirstRootDirectory = self.oleheader.getSIDfirstRootDirectory()
        self.MinimumStreamSize     = self.oleheader.getMinimumStreamSize()

    def createStructures(self):
        self.createMSAT(self.oleheader.getinitialMSAT(),
                        self.oleheader.getSIDfirstMSAT())

        self.createSAT()
        
        self.createSSAT(self.oleheader.getSIDfirstShortSectorAllocTable())

        self.readDirectory()
        
        self.ShortStreamSID  = self.directory[0].getFirstSID()
        self.ShortStreamSize = self.directory[0].getSize()
        
        self.allShortStream  = self.readStream(self.ShortStreamSID, self.ShortStreamSize)

    def readDirectory(self):
        root = self.readStream(self.SIDfirstRootDirectory)
        
        for did in range(len(root)/128):
            self.directory[did] = OLE2DirectoryEntry(root[did*128:did*128+128])

    def readStream(self,firstSID, size = -1):
        tmp = ""
        
        if firstSID >= 0:
            tmp += self.getSector(firstSID)
            nextSector = self.sat[firstSID]
            
            while True:
                if nextSector >= 0:
                    tmp += self.getSector(nextSector)
                else:
                    break
                
                nextSector = self.sat[nextSector]
                
        if size < 0:
            return tmp
        else:
            return tmp[0:size]

    def readShortStream(self,firstSID, size = -1):
        tmp = ""
        
        if firstSID >= 0:
            tmp += self.getShortSector(firstSID)
            nextSector = self.ssat[firstSID]
            
            while True:
                if nextSector >= 0:
                    tmp += self.getShortSector(nextSector)
                else:
                    break
                
                nextSector = self.ssat[nextSector]
        
        if size < 0:
            return tmp
        else:
            return tmp[0:size]

    def createSSAT(self,SSATfirstSID):
        tmp = ""

        if SSATfirstSID >= 0:
            tmp += self.getSector(SSATfirstSID)
            nextSector = self.sat[SSATfirstSID]
            
            while True:
                if nextSector >= 0:
                    tmp += self.getSector(nextSector)
                else:
                    break

                nextSector = self.sat[nextSector]

            x=0
            for offset in range(0,len(tmp),4):
                self.ssat[x] = struct.unpack("<l",tmp[offset:offset+4])[0]
                x+=1
        
    def createSAT(self):
        tmp = ""
        for sid in self.msat:
            if sid >= 0:
                tmp += self.getSector(sid)
        
        x=0
        for offset in range(0,len(tmp),4):
            self.sat[x] = struct.unpack("<l",tmp[offset:offset+4])[0]
            x+=1
    
    def createMSAT(self,initial,firstSID):
        for sid in range(109):
            self.msat.append(struct.unpack("<l",initial[sid*4:sid*4+4])[0])
            
        if firstSID >= 0:
            sector = self.getSector(firstSID)

            while True:
                for sid in range(self.SectorSize / 4):
                    self.msat.append(struct.unpack("<l",sector[sid*4:sid*4+4])[0])
                
                nextSector = self.msat.pop()
                #Last SID point to the next sector (if any)

                if nextSector >= 0:
                    sector = self.getSector(nextSector)
                else:
                    break
        
    def getSector(self,SID):
        if not self.sectors.has_key(SID):
            offset = 512 + SID * self.SectorSize
            self.sectors[SID] = self.bindata[offset:offset+self.SectorSize]

        return self.sectors[SID]

    def getShortSector(self,SID):
        sid_shortstream = SID * self.ShortSectorSize
        
        return self.allShortStream[sid_shortstream:sid_shortstream+self.ShortSectorSize]
    
    def getAllDirectory(self):
        return self.directory

    def getAllSAT(self):
        return self.sat

    def getAllSSAT(self):
        return self.ssat

    def getDirectoryByName(self, name):
        for did in self.directory:
            if self.directory[did].getName() == name:
                return self.directory[did]
        return None

    def getDirectoryByDID(self, did):
        return self.directory[did]
    
    def getMinimumStreamSize(self):
        return self.MinimumStreamSize

    def getAllShortStream(self):
        return self.allShortStream


    # Here starts writer functions

    def addDirectory(self, did, data):
        self.directory[did] = OLE2DirectoryEntry(data)
    
    def addStream(self, data, force_sat = 0, did = -1):
        if len(data) == 0:
            return None
        
        if len(data) < self.oleheader.getMinimumStreamSize() and force_sat == 0:
            #is a Short Stream
            ssid_last=-1
            for part in range(int(math.ceil(float(len(data)) / float(self.ShortSectorSize)))):
                ssid = self.getUnusedShortSector()
                if not ssid_last < 0:
                    self.ssat[ssid_last] = ssid
                else:
                    firstSID = ssid

                self.WriteShortSector(ssid, data[part*self.ShortSectorSize:(part+1)*self.ShortSectorSize])
                self.ssat[ssid] = -2
                ssid_last=ssid
        else:
            #is a Normal Stream
            sid_last=-1
            for part in range(int(math.ceil(float(len(data)) / float(self.SectorSize)))):
                sid = self.getUnusedSector()
                if not sid_last < 0:
                    self.sat[sid_last] = sid
                else:
                    firstSID = sid

                self.WriteSector(sid, data[part*self.SectorSize:(part+1)*self.SectorSize])
                self.sat[sid] = -2
                sid_last=sid
        
        if did >= 0:
            self.directory[did].setFirstSID(firstSID)
            self.directory[did].setSize(len(data))

        return firstSID
    
    def getUnusedShortSector(self):
        last=-1
        for k in self.ssat:
            #allocated, but unused sector
            if self.ssat[k] == -1:
                return k
            last=k
        return last+1

    def getUnusedSector(self):
        last=-1
        for k in self.sat:
            #allocated, but unused sector
            if self.sat[k] == -1:
                return k
            last=k
        return last+1

    def WriteShortSector(self,ssid,data):
        self.ssectors[ssid]=data
    
    def WriteSector(self,sid,data):
        self.sectors[sid]=data
    
    def getBinaryData(self):
        #Make the Short Stream
        
        self.shortStream = ""
        tmp=self.ssectors.keys()
        tmp.sort()
        max_sid=tmp.pop()
        
        for sid in range(max_sid+1):
            if self.ssectors.has_key(sid):
                self.shortStream += struct.pack(str(self.ShortSectorSize)+"s",self.ssectors[sid])
            else:
                self.shortStream += struct.pack(str(self.ShortSectorSize)+"s",operator.repeat("\x00",self.ShortSectorSize))
       
        #Add Stream and Write Short Stream SID in the Root Entry
        SIDShortStream = self.addStream(self.shortStream, 1, 0)
        
        #Make SSAT Stream
        
        self.ssatStream = ""
        tmp=self.ssat.keys()
        tmp.sort()
        max_ssat=tmp.pop()

        for sid in range(max_ssat+1):
            if self.ssat.has_key(sid):
                self.ssatStream += struct.pack("<l",self.ssat[sid])
            else:
                self.ssatStream += struct.pack("<l",-1)

        TotalSSAT = int(math.ceil(float(len(self.ssatStream)) / float(self.SectorSize)))
        SIDssatStream = self.addStream(self.ssatStream, 1)

        #Make the Directory Stream
        self.directoryStream = ""
        for did in self.directory:
            self.directoryStream += self.directory[did].getBinaryData()
        
        SIDDirectory = self.addStream(self.directoryStream, 1)

        #Calc SAT Sectors Usage (check if I need a MSAT extention)
        TotalSAT = int(math.ceil(float(len(self.sat)*4) / float(self.SectorSize)))
        
        initMSAT = ""
        if TotalSAT > 109:
            # Use extra sectors to extend the SAT
            # TODO!
            print "argh... TODO! - satStream.len=%u - SectorSize=%u - TotalSAT=%u" % ( int(len(self.sat)*4), int(self.SectorSize), int(self.TotalSAT) )
            sys.exit(255)
        else:
            #Make MSAT and Reserve space on SAT for SAT sectors
            SATChain = []
            SIDsatStream=-1
            for part in range(TotalSAT):
                sat_sid = self.getUnusedSector()
                if SIDsatStream < 0:
                    SIDsatStream = sat_sid
    
                self.sat[sat_sid] = -3        # mark sector as "used by SAT"
                initMSAT += struct.pack("<l",sat_sid)
                SATChain.append(sat_sid)

        #Fill MSAT
        for x in range(0,436 - len(initMSAT),4):
            initMSAT += struct.pack("<l",-1)  # mark as free

        #Make SAT Stream
        self.satStream = ""
        tmp=self.sat.keys()
        tmp.sort()
        max_sat=tmp.pop()

        for sid in range(max_sat+1):
            if self.sat.has_key(sid):
                self.satStream += struct.pack("<l",self.sat[sid])
            else:
                self.satStream += struct.pack("<l",-1)

        #Write SAT Sectors
        part=0
        for sid in SATChain:
            self.sectors[sid] = self.satStream[part*self.SectorSize:(part+1)*self.SectorSize]
            part+=1
        
        #Recalc Header
        self.oleheader.setTotalSectorsSAT(TotalSAT)
        self.oleheader.setSIDfirstRootDirectory(SIDDirectory)
        self.oleheader.setSIDfirstShortSectorAllocTable(SIDssatStream)
        self.oleheader.setTotalSectorsSSAT(TotalSSAT)
        self.oleheader.setinitialMSAT(initMSAT)
        
        #Sectors
        allSectors = ""
        tmp=self.sectors.keys()
        tmp.sort()
        max_sectors=tmp.pop()

        for sid in range(max_sectors+1):
            if self.sectors.has_key(sid):
                allSectors += struct.pack(str(self.SectorSize)+"s", self.sectors[sid])
            else:
                allSectors += struct.pack(str(self.SectorSize)+"s", operator.repeat("\x00",self.SectorSize))
 
        #Write all together
        return self.oleheader.getBinaryData() + allSectors

    def getStreamByName(self, name):
        mydir = self.getAllDirectory()
        doc_stream = None
        
        for did in mydir:
            secname = mydir[did].getName()

            if secname.find(name) != -1:
                if mydir[did].getSize() < self.getMinimumStreamSize():
                    doc_stream = self.readShortStream(self.getDirectoryByName(secname).getFirstSID(),self.getDirectoryByName(secname).getSize())
                else:
                    doc_stream = self.readStream(self.getDirectoryByName(secname).getFirstSID(),self.getDirectoryByName(secname).getSize())
                
                return doc_stream
    
    def exportAll(self, inp):
        print "\nexporting %s..." % inp
        
        mydir = self.getAllDirectory()
        
        for did in mydir:
            secname = mydir[did].getName()
            
            print "stream %s - size %u" % (secname, mydir[did].getSize() )
        
            doc_stream = ""
            if mydir[did].getSize() > 0:
                if isinstance(self.getDirectoryByName(secname),OLE2DirectoryEntry):
                    if mydir[did].getSize() < self.getMinimumStreamSize():
                        doc_stream = self.readShortStream(self.getDirectoryByName(secname).getFirstSID(),self.getDirectoryByName(secname).getSize())
                    else:
                        doc_stream = self.readStream(self.getDirectoryByName(secname).getFirstSID(),self.getDirectoryByName(secname).getSize())
        
                f1=open(inp+"_"+secname.strip("\x05\x01\x00\x03")+".dat","wb")
                f1.write(doc_stream)
                f1.close()
                
                if secname == "PowerPoint Document":
                    ppt = PPT(doc_stream)
                    
                    #4113 (ExOleObjStg) 
                    for data in ppt.getRecordsByType(4113):
                        doc2 = OLE2IO()
                        doc2.openFromData(data[1]["UncompressedData"])
                        
                        doc2.exportAll("4113_"+str(data[0]))

        print "all done\n"


class OLE2Header:
    def __init__(self, data):
        index = 0
        self.magic           = struct.unpack("8s",data[index:index+8])
        index = 8
        self.unique          = struct.unpack("16s",data[index:index+16])
        index = 24
        self.revision        = struct.unpack("<H",data[index:index+2])
        index = 26
        self.version         = struct.unpack("<H",data[index:index+2])
        index = 28
        self.bitorder        = struct.unpack("<H",data[index:index+2])
        index = 30
        self.sectorsize      = struct.unpack("<H",data[index:index+2])
        index = 32
        self.shortsectorsize = struct.unpack("<H",data[index:index+2])
        index = 34
        self.notused         = struct.unpack("10s",data[index:index+10])
        index = 44
        self.sectalloctable  = struct.unpack("<L",data[index:index+4])
        index = 48
        self.SIDfirstdir     = struct.unpack("<L",data[index:index+4])
        index = 52
        self.notused2        = struct.unpack("4s",data[index:index+4])
        index = 56
        self.minstreamsize   = struct.unpack("<L",data[index:index+4])
        index = 60
        self.SIDfirstshort   = struct.unpack("<l",data[index:index+4])
        index = 64
        self.shortalloctable = struct.unpack("<L",data[index:index+4])
        index = 68
        self.SIDfirstMSAT    = struct.unpack("<l",data[index:index+4])
        index = 72
        self.TotalMSAT       = struct.unpack("<L",data[index:index+4])
        index = 76
        self.initMSAT        = struct.unpack("436s",data[index:index+436])
        #First 109 SIDs

    def getMinimumStreamSize(self):
        return self.minstreamsize[0]

    def getSectorSize(self):
        return self.sectorsize[0]

    def getShortSectorSize(self):
        return self.shortsectorsize[0]
    
    def getTotalSectorsSAT(self):
        return self.sectalloctable[0]

    def getSIDfirstRootDirectory(self):
        return self.SIDfirstdir[0]

    def getTotalSectorsMSAT(self):
        return self.TotalMSAT[0]
    
    def getSIDfirstMSAT(self):
        return self.SIDfirstMSAT[0]

    def getSIDfirstShortSectorAllocTable(self):
        return self.SIDfirstshort[0]
    
    def getTotalSectorsSSAT(self):
        return self.shortalloctable[0]

    def getinitialMSAT(self):
        return self.initMSAT[0]
    
    def getBinaryData(self):
        tmp = ""
        
        tmp += struct.pack("8s",self.magic[0])
        tmp += struct.pack("16s",self.unique[0])
        tmp += struct.pack("<H",self.revision[0])
        tmp += struct.pack("<H",self.version[0])
        tmp += struct.pack("<H",self.bitorder[0])
        tmp += struct.pack("<H",self.sectorsize[0])
        tmp += struct.pack("<H",self.shortsectorsize[0])
        tmp += struct.pack("10s",self.notused[0])
        tmp += struct.pack("<L",self.sectalloctable[0])
        tmp += struct.pack("<L",self.SIDfirstdir[0])
        tmp += struct.pack("4s",self.notused2[0])
        tmp += struct.pack("<L",self.minstreamsize[0])
        tmp += struct.pack("<l",self.SIDfirstshort[0])
        tmp += struct.pack("<L",self.shortalloctable[0])
        tmp += struct.pack("<l",self.SIDfirstMSAT[0])
        tmp += struct.pack("<L",self.TotalMSAT[0])
        tmp += struct.pack("436s",self.initMSAT[0])
        
        return tmp

    def setMinimumStreamSize(self,data):
        self.minstreamsize=[data]

    def setSectorSize(self,data):
        self.sectorsize=[data]

    def setShortSectorSize(self,data):
        self.shortsectorsize=[data]

    def setTotalSectorsSAT(self,data):
        self.sectalloctable=[data]

    def setSIDfirstRootDirectory(self,data):
        self.SIDfirstdir=[data]

    def setTotalSectorsMSAT(self,data):
        self.TotalMSAT=[data]
    
    def setSIDfirstMSAT(self,data):
        self.SIDfirstMSAT=[data]

    def setSIDfirstShortSectorAllocTable(self,data):
        self.SIDfirstshort=[data]

    def setTotalSectorsSSAT(self,data):
        self.shortalloctable=[data]

    def setinitialMSAT(self,data):
        self.initMSAT=[data]


class OLE2DirectoryEntry:
    def __init__(self, data):
        self._entrytypes = {0:"Empty",
                            1:"User Storage",
                            2:"User Stream",
                            3:"LockBytes",
                            4:"Property",
                            5:"Root Storage"}
        self._nodecolors = {0:"Red",
                            1:"Black"}
        
        index = 0
        self.name            = struct.unpack("64s",data[index:index+64])
        index = 64
        self.namesize        = struct.unpack("<H",data[index:index+2])
        index = 66
        self.type            = struct.unpack("B",data[index])
        index = 67
        self.nodecolor       = struct.unpack("B",data[index])
        index = 68
        self.leftdid         = struct.unpack("<l",data[index:index+4])
        index = 72
        self.rightdid        = struct.unpack("<l",data[index:index+4])
        index = 76
        self.rootdid         = struct.unpack("<l",data[index:index+4])
        index = 80
        self.uniqueid        = struct.unpack("16s",data[index:index+16])
        index = 96
        self.userflags       = struct.unpack("<L",data[index:index+4])
        index = 100
        self.createtimestamp = struct.unpack("<Q",data[index:index+8])
        index = 108
        self.modiftimestamp  = struct.unpack("<Q",data[index:index+8])
        index = 116
        self.firstsectorSID  = struct.unpack("<l",data[index:index+4])
        index = 120
        self.streamsize      = struct.unpack("<l",data[index:index+4])
        index = 124
        self.notused         = struct.unpack("<L",data[index:index+4])

    def getName(self):
        return unicode(self.name[0][0:self.namesize[0]-2], "utf_16_le")

    def getNameSize(self):
        return self.namesize[0]

    def getType(self):
        return self._entrytypes[self.type[0]]

    def getNodeColor(self):
        return self._nodecolors[self.nodecolor[0]]

    def getLeftDID(self):
        return self.leftdid[0]

    def getRightDID(self):
        return self.rightdid[0]

    def getRootDID(self):
        return self.rootdid[0]

    def getUniqueID(self):
        return self.uniqueid[0]

    def getUserFlags(self):
        return self.userflags[0]

    def getCreateTimestamp(self):
        return self.createtimestamp[0]

    def getModificationTimestamp(self):
        return self.modiftimestamp[0]

    def getFirstSID(self):
        return self.firstsectorSID[0]

    def getSize(self):
        return self.streamsize[0]
    
    def getBinaryData(self):
        tmp = ""
        
        tmp += struct.pack("64s",self.name[0])
        tmp += struct.pack("<H",self.namesize[0])
        tmp += struct.pack("B",self.type[0])
        tmp += struct.pack("B",self.nodecolor[0])
        tmp += struct.pack("<l",self.leftdid[0])
        tmp += struct.pack("<l",self.rightdid[0])
        tmp += struct.pack("<l",self.rootdid[0])
        tmp += struct.pack("16s",self.uniqueid[0])
        tmp += struct.pack("<L",self.userflags[0])
        tmp += struct.pack("<Q",self.createtimestamp[0])
        tmp += struct.pack("<Q",self.modiftimestamp[0])
        tmp += struct.pack("<l",self.firstsectorSID[0])
        tmp += struct.pack("<l",self.streamsize[0])
        tmp += struct.pack("<L",self.notused[0])
        
        return tmp

    def setName(self,data):
        self.name=[data.encode("utf_16_le")]
        self.namesize=len(self.name)+2

    def setNameSize(self,data):
        self.namesize=[data]

    def setType(self,data):
        self.type=[data]

    def setNodeColor(self,data):
        self.nodecolor=[data]

    def setLeftDID(self,data):
        self.leftdid=[data]

    def setRightDID(self,data):
        self.rightdid=[data]

    def setRootDID(self,data):
        self.rootdid=[data]

    def setUniqueID(self,data):
        self.uniqueid=[data]

    def setUserFlags(self,data):
        self.userflags=[data]

    def setCreateTimestamp(self,data):
        self.createtimestamp=[data]

    def setModificationTimestamp(self,data):
        self.modiftimestamp=[data]

    def setFirstSID(self,data):
        self.firstsectorSID = [data]

    def setSize(self,data):
        self.streamsize=[data]

class OLE2PropertyStream:
    def __init__(self):
        self.header = dict()
        self.sections = dict()
        
    def setAllFromBinary(self, data):
        index = 0
        self.header["magic"] = struct.unpack("<H", data[index:index+2])[0]
        index = 2
        self.header["notused"] = struct.unpack("<H", data[index:index+2])[0]
        index = 4
        self.header["os"] = struct.unpack("<l", data[index:index+4])[0]
        index = 8
        self.header["classid"] = struct.unpack("16s", data[index:index+16])[0]
        index = 24
        self.header["sec_count"] = struct.unpack("<l", data[index:index+4])[0]
        
        index = 28
        for sec in range(self.header["sec_count"]):
            classid = struct.unpack("16s", data[index:index+16])[0]
            secoffset = struct.unpack("<l", data[index+16:index+20])[0]
            
            seclen = struct.unpack("<l", data[secoffset:secoffset+4])[0]
            propcount = struct.unpack("<l", data[secoffset+4:secoffset+8])[0]

            properties = dict()
            
            for prop in range(propcount):
                propid = struct.unpack("<l", data[secoffset+8+(prop*8):secoffset+12+(prop*8)])[0]
                propoffset = struct.unpack("<l", data[secoffset+12+(prop*8):secoffset+16+(prop*8)])[0]
                
                proptype = struct.unpack("<l", data[secoffset+propoffset:secoffset+propoffset+4])[0]
                
                #TODO: incomplete list
                if proptype == 0x02:
                    #VT_I2 : 2 byte signed int
                    propdata = struct.unpack("<h", data[secoffset+propoffset+4:secoffset+propoffset+6])[0]
                elif proptype == 0x03:
                    #VT_I4 : 4 byte signed int
                    propdata = struct.unpack("<l", data[secoffset+propoffset+4:secoffset+propoffset+8])[0]
                elif proptype == 0x1e:
                    #VT_LPSTR : null terminated string
                    proplen = struct.unpack("<l", data[secoffset+propoffset+4:secoffset+propoffset+8])[0]
                    #strip \x00
                    propdata = struct.unpack(str(proplen)+"s", data[secoffset+propoffset+8:secoffset+propoffset+8+proplen])[0].strip("\x00")
                elif proptype == 0x40:
                    #VT_FILETIME : FILETIME
                    propdata = struct.unpack("8s", data[secoffset+propoffset+4:secoffset+propoffset+12])[0]
                elif proptype == 0x47:
                    #VT_CF : Clipboard format
                    proplen = struct.unpack("<l", data[secoffset+propoffset+4:secoffset+propoffset+8])[0]
                    propdata = struct.unpack(str(proplen)+"s", data[secoffset+propoffset+8:secoffset+propoffset+8+proplen])[0]
                else:
                    #unsupported
                    propdata = None
            
                properties[propid] = {"propoffset":propoffset, \
                                   "proptype":proptype, \
                                   "propdata":propdata}

            self.sections[sec] = {"classid":classid, \
                                  "secoffset":secoffset, \
                                  "seclen":seclen, \
                                  "propcount":propcount, \
                                "properties":properties}
            
            #next section
            index += 8
            
    def getPropertyById(self,section,propid):
        return self.sections[section].properties[propid]

    def setPropertyDataById(self,section,propid,data):
        self.sections[section]["properties"][propid]["propdata"] = data
    
    def addProperty(self,section,propid,proptype,data):
        self.sections[section]["properties"][propid]={"proptype":proptype, \
                                                      "propdata":data}

    def getAllBinary(self):
        res = ""

        # header
        res += struct.pack("<H", self.header["magic"])
        res += struct.pack("<H", self.header["notused"])
        res += struct.pack("<l", self.header["os"])
        res += struct.pack("16s", self.header["classid"])
        res += struct.pack("<l", self.header["sec_count"])
        
        #start from inside to outside
        sections_bin = ""
        properties_list_bin = ""
        for (secnum,section) in self.sections.iteritems():
            properties_bin = ""

            secoffset = 8 + (len(section["properties"])*8)

            for (propid,prop) in section["properties"].iteritems():
                proptype = prop["proptype"]

                propdata = struct.pack("<l", proptype)
                
                #TODO: incomplete list
                if proptype == 0x02:
                    #VT_I2 : 2 byte signed int
                    propdata += struct.pack("<h", prop["propdata"])
                elif proptype == 0x03:
                    #VT_I4 : 4 byte signed int
                    propdata += struct.pack("<l", prop["propdata"])
                elif proptype == 0x1e:
                    #VT_LPSTR : null terminated string
                    proplen = struct.pack("<l", len(prop["propdata"]) + 1)
                    propdata += proplen + struct.pack(str(len(prop["propdata"]) + 1)+"s", \
                                                     prop["propdata"] + chr(0))
                elif proptype == 0x40:
                    #VT_FILETIME : FILETIME
                    propdata += struct.pack("8s", prop["propdata"])
                elif proptype == 0x47:
                    #VT_CF : Clipboard format
                    proplen = struct.pack("<l", len(prop["propdata"]))
                    propdata += proplen + \
                             struct.pack(str(len(prop["propdata"]))+"s", prop["propdata"])
                else:
                    #unsupported
                    propdata += None
                
                properties_list_bin += struct.pack("<l", propid)
                properties_list_bin += struct.pack("<l", secoffset)
                
                properties_bin += propdata
                
                secoffset += len(propdata)
            
            #section length
            sections_bin += struct.pack("<l", len(properties_list_bin) + len(properties_bin) + 8)
            #property count
            sections_bin += struct.pack("<l", len(section["properties"]))
            #property offsets
            sections_bin += properties_list_bin
            #property data
            sections_bin += properties_bin
        
        #add sections to the result
        secoffset = 28 + len(self.sections)*20
        for (secnum,section) in self.sections.iteritems():
            res += struct.pack("16s", section["classid"])
            res += struct.pack("<l", secoffset)
            
            secoffset += len(sections_bin[secnum])
            
        res += sections_bin
        
        return res
        