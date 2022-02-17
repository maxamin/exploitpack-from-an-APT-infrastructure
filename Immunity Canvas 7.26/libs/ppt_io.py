#!/usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

# PPT I/O interface


import sys
if "." not in sys.path: sys.path.append(".")

import struct, zlib

class PPT:
    def __init__(self, data):
        self.records = dict()
        self.structure = dict()
        self.rec_counter = 0
        self.bindata = data
        self.readRecords(data)
    
    def readRecords(self,data,parent = -1):
        offset = 0
        
        while offset+8 <= len(data):
            header = data[offset:offset+8]
            
            recVersion  = struct.unpack("<H", header[0:2])[0] & 0x000f
            recInstance = struct.unpack("<H", header[0:2])[0] & 0xfff0
            recType     = struct.unpack("<H", header[2:4])[0]
            recSize     = struct.unpack("<L", header[4:8])[0]
            
            recData  = struct.unpack(str(recSize)+"s", data[offset+8:offset+8+recSize])[0]
            
            buff = str()
            #ExOleObjStg (4113) comes compressed with LZW
            if recType == 4113:
                buff = zlib.decompress(recData[4:])
            
            self.records[self.rec_counter]={"Version":recVersion, \
                                 "Instance":recInstance, \
                                 "Type":recType, \
                                 "Size":recSize, \
                                 "Data":recData, \
                                 "UncompressedData":buff, \
                                 "Parent":parent}

            offset += 8 + recSize
            self.rec_counter += 1
            
            #traverse childs
            if recVersion == 0xf:
                #Container
                self.readRecords(recData,self.rec_counter-1)
            
    def getRecordsByType(self, recType):
        tmp = []
        for (recnum,recdata) in self.records.iteritems():
            if recdata["Type"] == recType:
                tmp.append( ( recnum, recdata ))
        
        return tmp

    def getRecordByNum(self, recNum):
        return self.records[recNum]
    
    def getAllRecords(self):
        return self.records
