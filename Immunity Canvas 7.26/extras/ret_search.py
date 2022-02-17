#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys

if sys.platform not in ["cygwin", "win32"]: # Vista?
    print "the registry portion of this module only runs on M$ platform"
    print "You should be able to still look at files in directories you've mounted/copied though"
    #sys.exit(1)

from MOSDEF import pelib
from MOSDEF.mosdefutils import intel_order
import pywintypes

try:
    import win32api
    import win32con
except:
    print "No win32api installed."
    
class PETREE:
    def __init__(self,filename=None):
        self.badbytes=""
        self.clear()
        self.filename=filename #starting filename
        self.imports={}
        
    def clear(self):
        
        self.searchstring="\xff\xd3"
        self.filename=None
        #self.imports={} #dictionary of our imports (1/0 depending on whether we've done them)
        self.sections={} #dictionary of all loaded sections
        self.imagebases={} #dictionary of all image bases sorted by name
        return 
    
    def setbadbytes(self,badbytes):
        self.badbytes=badbytes
        print "Badbytes length %d"%len(self.badbytes)
        
    def openPE(self,rawdata):
        myMZ = pelib.MZ()
        idx=0
        myMZ.get(rawdata[idx:idx+myMZ.getSize()])
        myPE = pelib.PE()
        myPE.get(rawdata, myMZ.getPEOffset())	
        
        return myPE

    def getuuids(self):
        """
        for each UUID in the registry, find the file, and if it's unique, load it
        requires win32api
        
        HKLM\Software\Microsoft\Internet Explorer\ActiveX Compatability\
        If they have the 0x400 bit set, they're "killed"
        
        
        """
        uuidsdone={}
        reg=win32api.RegConnectRegistry(None,win32con.HKEY_CLASSES_ROOT)
        key=win32api.RegOpenKeyEx(reg,"CLSID")
        subkey="Hi"
        i=1
        while subkey!="":
            try:
                subkey=win32api.RegEnumKey(key,i)
                #print "Subkey=%s"%subkey
            except pywintypes.error:
                #end of registry just throws a lame exception
                subkey=""
                continue
            try:
                new_subkey=win32api.RegOpenKeyEx(key,subkey)
                print "Got new subkey for %s"%subkey
                subkey2=win32api.RegOpenKeyEx(new_subkey,"InprocServer32")
                print "Got InprocServer subkey"
                value=win32api.RegEnumValue(subkey2,0)
                print "Value = %s"%(value,)
                
                dllname=value[1].lower()
                print "Dllname=%s"%dllname
                if dllname.count("exe") or dllname.count("dll"):
                    print "Clearing"
                    self.clear()
                    print "Doing file"
                    self.dofile(dllname)
                    print "Doing all imports"            
                    self.doallimports()
                else:
                    print "Not a dll or exe!"
            except pywintypes.error:
                #import traceback
                #traceback.print_exc(file=sys.stdout)
                pass
                #print "No InprocServer subkey..."
            i+=1
        print "Done with getuuids"    
        print "Done DLLS: %s"%(self.imports,)
        
        sys.exit(1)
        
    def dofile(self,filename):
        import time, os
        filename=filename.lower()
        systemroot="c:\\WINDOWS" #os.environ.get("%systemroot%","")
        filename=filename.replace("%systemroot%",systemroot)
        if self.imports.get(filename,0):
            print "Skipping %s - already done"%filename
            return 
        print "dofile doing %s"%filename
        found=0
        i=0
        #print "Path= %s"%sys.path
        #hardcore little open file routine
        while not found and i<len(sys.path):
            fullfilename=os.path.join(sys.path[i],filename)
            i+=1
            try:
                #print "Looking for %s"%fullfilename
                rawdata=file(fullfilename,"rb").read()
                found=1
            except: 
                pass

        if not found:
            print "COULD NOT FIND FILE %s"%filename
            return []
            #sys.exit(1)
        myPE=self.openPE(rawdata)
        sections=myPE.Sections
        for section in sections.keys():
            imagebase=myPE.IMGOPThdr.ImageBase
            virtualaddress=sections[section].VirtualAddress
            pointer=sections[section].PointerToRawData
            size=sections[section].SizeOfRawData            
            print "Section name: %s pointer=%x size=%x"%(section,pointer,size)
            data=rawdata[pointer:pointer+size]
            found=data.find(self.searchstring)
            if found!=-1:
                #now we need to make sure there are no bad bytes
                addy=imagebase + virtualaddress + found
                allgood=1
                for c in intel_order(addy):
                    if self.badbytes.count(c):
                        allgood=0
                if allgood:
                    print "Badstring: %s"%self.badbytes
                    print "Address: %x"%addy
                    print "Found searchstring in data at reachable address!"
                    print "We're done, baby"
                    sys.exit(1)
                    time.sleep(500)
        #print "Sections: %s"%sections
        self.sections[filename]=sections      
        #print "self.sections=%s"%self.sections      
        imports=myPE.Imports.keys()            
        self.imagebases[filename]=myPE.IMGOPThdr.ImageBase
        self.imports[filename]=1 #done!
        return imports
 
    def addimports(self,imports):
        for i in imports:
            if i not in self.imports:
                self.imports[i]=0
                print "Import: %s"%i 
    
    def setfilename(self,filename):
        self.filename=filename
    
    def doallimports(self):
        print "Doing all imports"
        done=0
        while not done:
            done=1
            for i in self.imports.keys():
                if not self.imports[i]:
                    done=0
                    print "Doing %s"%i
                    self.addimports(self.dofile(i))
        return 
    
    def run(self):
        if self.filename:
            imports=self.dofile(self.filename)
            self.addimports(imports)

        for i in self.imports:
            print "Found: %s"%i
            
        #print "Sections: %s"%self.sections
        for sectionname in self.sections.keys():
            sections=self.sections[sectionname]    
            for s in sections.keys():
                name=s       
                imagebase=self.imagebases[sectionname]
                startaddy=imagebase+sections[s].VirtualAddress
                endaddy  =imagebase+sections[s].VirtualAddress+sections[s].VirtualSize
                print "Section name: %s %s start=%x end=%x"%(sectionname, name, startaddy, endaddy)                

def usage():
    print "Usage: ret_search.py -f FILENAME.EXE | -c "
    print "-f FILENAME.EXE will be looked in for imports and recursively searched"
    print "-c will load all UUIDS in the registry"
    sys.exit(1)
    
def main(argv):
    sys.path.append("C:\\WINDOWS\\system32")      
    if len(sys.argv)==1:
        usage()
    try:        
        import getopt, re
        opts, args = getopt.getopt(sys.argv[1:], 'f:cA')
    except getopt.GetoptError:
        usage()
    
    opcodesfile=""
    elftype=0
    outputfile=""
    myPETREE=PETREE()
    getuuids=0
    for opt, value in opts:
        if opt == ('-c'):
            print "Doing UUID check"
            getuuids=1
            
        if opt == ("-f"):
            print "Loading file"
            myPETREE.setfilename(value)
        if opt == ("-A"):
            #upper case ascii only
            badchars=""
            uppercase=""
            print "Upper case ascii mode enabled."
            for i in range(ord("A"),ord("Z")+1):
            #for i in range(0,255):
                uppercase+=chr(i)
            uppercase+="\xb9\xfb\xfc\xfd\xfe" #these are tricky
            uppercase+="\x00" #if last char, I believe
            
            for i in range(0,256):
                if chr(i) not in uppercase:
                    badchars+=chr(i)
            myPETREE.setbadbytes(badchars)
    
    if getuuids:
        myPETREE.getuuids()
    else:
        myPETREE.run()
    
if __name__ == "__main__":
    main(sys.argv)
