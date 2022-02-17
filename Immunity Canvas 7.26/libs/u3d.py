#!/usr/bin/env python
##ImmunityHeader v1 
###############################################################################
## File       :  u3d.py
## Description:  
##            :  
## Created_On :  Tue Oct 20 11:11:49 2009
## Created_By :  Pablo Sole
## Modified_On:  
## Modified_By:  
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################

from struct import *

def myprint(string):
    if "dump_print" in globals().keys() and globals()["dump_print"]:
        f=open(globals()["dump_print"],"ab")
        f.write(string+"\n")
        f.close()
    print string

class U3D():
    def __init__(self, dump=None):
        self.file_structure=Block(blocktype=0x00443355)
        self.declarations=[self.file_structure]
        self.continuations=[]
        self.setDump(dump)
    
    def setDump(self, dump):
        self.dump=dump
        global dump_print
        dump_print=dump
        
    def addDeclaration(self, block=None):
        if block == None:
            block = Block()
        self.declarations.append(block)
        return block
    
    def addContinuation(self, block=None):
        if block == None:
            block = Block()
        self.continuations.append(block)
        return block

    def read(self, buf):
        #file structure
        self.file_structure.read(buf)
        pos=self.file_structure.getSize()
        
        #declarations
        while pos < self.file_structure.child_structure.dec_size:
            block=Block()
            block.read(buf[pos:])
            pos+=block.getSize()
            self.declarations.append(block)
        
        #continuations
        while pos < len(buf):
            block=Block()
            block.read(buf[pos:])
            pos+=block.getSize()
            self.continuations.append(block)
        
        return pos
        
    def write(self):
        dec_size=0
        for dec in self.declarations:
            dec_size+=dec.getSize()
        
        file_size=dec_size
        for con in self.continuations:
            file_size+=con.getSize()
        
        self.file_structure.child_structure.dec_size=dec_size
        self.file_structure.child_structure.file_size=file_size
        
        buf=""
        for dec in self.declarations:
            buf+=dec.write()
        for con in self.continuations:
            buf+=con.write()
            
        return buf
    
    def prettydump(self,tab=0):
        myprint( "%sDeclarations"%(" "*(tab*4)))
        for dec in self.declarations:
            dec.prettydump(tab+1)
        myprint( "%sContinuations"%(" "*(tab*4)))
        for con in self.continuations:
            con.prettydump(tab+1)

class ModifierChain():
    def __init__(self, parent_block, name="", mod_type=0, attributes=0, box=(0,0,0,0,0,0), sphere=(0,0,0,0), modifiers=None):
        if modifiers==None: modifiers=[]
        self.parent_block=parent_block
        self.name=name
        self.mod_type=mod_type
        self.attributes=attributes
        self.box=box
        self.sphere=sphere
        self.modifiers=modifiers
    
    def prettydump(self, tab):
        myprint( "%sModifierChain Block, Name=%s"%(" "*(tab*4), self.name))
        for mod in self.modifiers:
            mod.prettydump(tab+1)
    
    def write(self):
        buf=""
        
        tmp=U3DString(self.name)
        buf+=tmp.write()
        buf+=pack("<L", self.mod_type)
        buf+=pack("<L", self.attributes)
        if self.attributes & 0x1:
            for tmp in self.sphere:
                buf+=pack("<f", tmp)
        if self.attributes & 0x2:
            for tmp in self.box:
                buf+=pack("<f", tmp)
        
        buf+="\x00"*((len(buf)+3)/4*4 - len(buf)) #align to 32bits
        
        buf+=pack("<L",len(self.modifiers))
        
        for mod in self.modifiers:
            buf += mod.write()
        
        return buf
    
    def read(self, buf):
        pos=0
        
        tmp=U3DString()
        tmp.read(buf)
        self.name=tmp.data
        pos+=tmp.getSize()
        
        self.mod_type=unpack("<L",buf[pos:pos+4])[0]
        pos+=4
        self.attributes=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        
        if self.attributes & 0x1:
            self.sphere=[]
            for tmp in range(0,4):
                self.sphere.append(unpack("<f", buf[pos:pos+4])[0])
                pos+=4
        
        if self.attributes & 0x2:
            self.box=[]
            for tmp in range(0,6):
                self.box.append(unpack("<f", buf[pos:pos+4])[0])
                pos+=4
        
        pos=(pos+3)/4*4
        
        count=unpack("<L",buf[pos:pos+4])[0]
        pos+=4
        self.modifiers=[]
        for tmp in range(0,count):
            block=Block()
            block.read(buf[pos:])
            self.modifiers.append(block)
            pos+=block.getSize()
        
        return pos
        
    def getSize(self):
        size=len(self.name)+2 #U3DString
        size+=calcsize("<LL")
        if self.attributes & 0x1: size+=calcsize("<LLLL")
        if self.attributes & 0x2: size+=calcsize("<LLLLLL")
        size=(size+3)/4*4
        size+=calcsize("<L")
        for tmp in self.modifiers:
            size+=tmp.getSize()
        return size
        
class FileStructureBlock():
    def __init__(self, parent_block, ver_minor=0, ver_major=0, profile=0, dec_size=None, file_size=None, charset=106, scaling=0.0):
        self.parent_block=parent_block
        self.ver_minor=ver_minor
        self.ver_major=ver_major
        self.profile=profile
        self.dec_size=dec_size
        self.file_size=file_size
        self.charset=charset
        self.scaling=scaling

    def prettydump(self, tab):
        myprint( "%sFileStructure Block"%(" "*(tab*4)))
        myprint( "%sFile Size=%d"%(" "*(tab*4), self.file_size))
        myprint( "%sDeclarations Size=%d"%(" "*(tab*4), self.dec_size))
        
    def write(self):
        #Set Defaults
        if self.dec_size == None:  self.dec_size =self.parent_block.getSize()
        if self.file_size == None: self.file_size=self.parent_block.getSize()
        
        buf=""
        
        buf+=pack("<H", self.ver_major)
        buf+=pack("<H", self.ver_minor)
        buf+=pack("<L", self.profile)
        buf+=pack("<L", self.dec_size)
        buf+=pack("<Q", self.file_size)
        buf+=pack("<L", self.charset)
        if self.profile & 0x8: #Defined units
            buf+=pack("<d", self.scaling)
        
        return buf
    
    def read(self, buf):
        pos=0
        
        self.ver_major=unpack("<H", buf[pos:pos+2])[0]
        pos+=2
        self.ver_minor=unpack("<H", buf[pos:pos+2])[0]
        pos+=2
        self.profile=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        self.dec_size=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        self.file_size=unpack("<Q", buf[pos:pos+8])[0]
        pos+=8
        self.charset=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        if self.profile & 0x8: #Defined units
            self.scaling=unpack("<d", buf[pos:pos+8])[0]
    
        return pos
            
    def getSize(self):
        size=calcsize("<HHLLQL")
        if self.profile & 0x8: #Defined units
            size+=calcsize("<d")
        return size

                 
class Block():
    def __init__(self, blocktype=None, data="", metadata=None):
        self.blocktype=blocktype
        self.data=data
        if metadata==None:
            metadata=Metadata()
        self.metadata=metadata
        self.child_structure=self.initChild(self.blocktype)
    
    def initChild(self, blocktype):
        child=None
        if blocktype == 0x00443355:
            child=FileStructureBlock(parent_block=self)
        if blocktype == 0xFFFFFF14:
            child=ModifierChain(parent_block=self)
        return child

    def setBlocktype(self, blocktype):
        self.blocktype=blocktype
        self.child_structure=self.initChild(self.blocktype)
    
    def write(self):
        if self.child_structure != None:
            self.data = self.child_structure.write()
        
        #Set Defaults
        if self.data == None:     self.data=""
        if self.metadata == None or len(self.metadata.keys) == 0:
            metadata_data=""
        else:
            metadata_data=self.metadata.write()
        
        if self.blocktype == None:raise Exception, "You must provide the blocktype field"
        
        buf  = ""
        buf += pack("<L",self.blocktype)
        buf += pack("<L",len(self.data))
        buf += pack("<L",len(metadata_data))
        buf += self.data
        buf += "\x00"*( ((len(self.data)+3)/4*4) - len(self.data)) #padding
        buf += metadata_data
        buf += "\x00"*( ((len(metadata_data)+3)/4*4) - len(metadata_data)) #padding
        
        return buf

    def read(self, buf):
        pos=0
        
        self.blocktype=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        
        datalen=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        
        metadatalen=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        
        self.data=buf[pos:pos+datalen]
        pos+=((datalen+3)/4*4) #padding
        
        if metadatalen == 0:
            self.metadata=None
        else:
            self.metadata=Metadata()
            self.metadata.read(buf[pos:pos+metadatalen])
        
        pos+=((metadatalen+3)/4*4) #padding
        self.setBlocktype(self.blocktype)
        
        if self.child_structure != None:
            self.child_structure.read(self.data)
        
        return pos

    def getSize(self):
        if self.child_structure != None:
            datasize=self.child_structure.getSize()
        else:
            datasize=len(self.data)
        if self.metadata != None:
            metadatasize=self.metadata.getSize()
        else:
            metadatasize=0
        return calcsize("<LLL")+((datasize+3)/4*4)+((metadatasize+3)/4*4)
    
    def prettydump(self, tab):
        myprint( "%sBlock (type=0x%x)"%(" "*(tab*4), self.blocktype))
        if self.metadata:
            metadata_size=self.metadata.getSize()
        else:
            metadata_size=0
        myprint( "%sData Size=0x%x, Metadata Size=0x%x"%(" "*(tab*4), len(self.data), metadata_size))
        if self.child_structure:
            self.child_structure.prettydump(tab+1)
        else:
            dump_size=0x120
            tabbed_hexdump(tab+1, self.data[0:dump_size])
            if len(self.data) > dump_size:
                myprint( "%s=========== INCOMPLETE DUMP ================="%" "*((tab+1)*4))
        if metadata_size:
            self.metadata.prettydump(tab)

class Metadata():
    def __init__(self, keys=None, values=None, attribs=None):
        if keys==None: keys=[]
        if values==None: values=[]
        if attribs==None: attribs=[]
        self.keys=keys
        self.values=values
        self.attribs=attribs
    
    def prettydump(self, tab):
        myprint( "%sMetadata"%(" "*(tab*4)))
        tab+=1
        c=0
        while True:
            if len(self.keys) > c: key=self.keys[c]
            else: key="UNKNOWN"
            if len(self.values) > c: value=self.values[c]
            else: value="UNKNOWN"
            if len(self.attribs) > c: attrib=self.attribs[c]
            else: attrib=0
            
            if key=="UNKNOWN" and value=="UNKNOWN" and attrib==0:
                break
            
            if attrib & 0x0 == 0:
                myprint( "%skey=%s, attrib=0x%x, value=%s"%(" "*(tab*4),key,attrib,value))
            else:
                myprint( "%skey=%s, attrib=0x%x, value:"%(" "*(tab*4),key,attrib))
                tabbed_hexdump(tab,value)
            c+=1
        
    def read(self, buf):
        pos=0
        
        keycount=unpack("<L", buf[pos:pos+4])[0]
        pos+=4
        
        self.keys=[]
        self.values=[]
        self.attribs=[]
        
        for c in range(0,keycount):
            attribs=unpack("<L", buf[pos:pos+4])[0]
            pos+=4
            
            key_instr=U3DString()
            key_instr.read(buf[pos:])
            pos+=key_instr.getSize()
            
            if attribs & 0x0 == 0:
                value_instr=U3DString()
                value_instr.read(buf[pos:])
                pos+=value_instr.getSize()
                value=value_instr.data
            else:
                valuesize=unpack("<L", buf[pos:pos+4])[0]
                pos+=4
                value=buf[pos:pos+valuesize]
                pos+=valuesize
            
            self.keys.append(key_instr.data)
            self.values.append(value)
            self.attribs.append(attribs)
        
        return pos
    
    def write(self):
        buf=""
        
        if len(self.keys) == 0:
            return buf
        
        buf+=pack("<L", len(self.keys))
        
        for x in range(0,len(self.keys)):
            key=self.keys[x]
            
            if x >= len(self.values):
                value=""
            else:
                value=self.values[x]
            if x >= len(self.attribs):
                attribs=0
            else:
                attribs=self.attribs[x]
            
            buf+=pack("<L", attribs)
            
            key_instr=U3DString()
            key_instr.data=key
            buf+=key_instr.write()
            
            if attribs & 0x0 == 0:
                value_instr=U3DString()
                value_instr.data=value
                buf+=value_instr.write()
            else:
                buf+=pack("<L",len(value))
                buf+=value
        
        return buf
    
    def getSize(self):
        tmp=self.write()
        
        return len(tmp)
        
        
class U3DString():
    def __init__(self, data=None):
        self.data=data
    
    def read(self, buf):
        pos=0
        
        length=unpack("<H", buf[pos:pos+2])[0]
        pos+=2
        
        self.data=buf[pos:pos+length]
        pos+=length
        
        return pos
    
    def write(self):
        buf=""
        
        buf+=pack("<H", len(self.data))
        buf+=self.data
        
        return buf
    
    def getSize(self):
        return len(self.data)+calcsize("<H")

def tabbed_hexdump(tab,buf):
    tbl=[]
    tmp=""
    hex=""
    i=0
    for a in buf[:]:
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
    
    for t in tbl:
        myprint( "%s%-48s %s"%(" "*(tab*4),t[0],t[1]))
