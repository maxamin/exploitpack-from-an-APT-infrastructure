#! /usr/bin/env python

"""
dcemarshall.py

All the software you need to marshall and unmarshall 
data in DCE-RPC format (ndr).

Copyright Immunity, Inc. 2005

Under CANVAS license

"""
import sys
if "." not in sys.path:
    sys.path.append(".")
from exploitutils import *
from copy import copy
from copy import deepcopy

def getdcewchar(buf):
    size,buf=getint(buf)
    zero,buf=getint(buf)
    if zero!=0:
        print "Why are we demarshalling %x instead of zero in a wchar_t string?"%zero
    maxsize,buf=getint(buf)
    value=buf[:size*2]
    #print "Found string: %s"%prettyprint(self.value)
    buf=buf[size*2:]
    if size & 1: #if size is odd
        buf=buf[2:] #eat two more bytes to make it mod 4
    return value,buf

class primarytype:
    def __init__(self,value=None,attributes=[],amarshall=None):
        self.value=value
        self.attributes=attributes
        self.marshaller=amarshall
    
    def setvalue(self,value):
        self.setvalue=value
        
    def marshall(self):
        return ""
    
class dceint(primarytype):
    def __init__(self,value=None,attributes=[],amarshall=None):
        primarytype.__init__(self,value,attributes,amarshall)

    def marshall(self):
        #print "dceint marshall: %s"%prettyprint("%s"%self.value)
        return intel_order(self.value)
    
    def demarshall(self,buf):
        ret=istr2int(buf)
        self.value=ret
        return buf[4:]

class dcebyte(primarytype):
    def __init__(self,value=0,amarshall=None):
        primarytype.__init__(self,value,[],amarshall)
        
    def marshall(self):
        return chr(self.value)
    

class dceshort(primarytype):
    def __init__(self,value=0,amarshall=None):
        primarytype.__init__(self,value,[],amarshall)
        
    def marshall(self):
        return halfword2istr(self.value)    
    
        
class dcepointer(primarytype):
    def __init__(self,value=None,attributes=[],amarshall=None):
        primarytype.__init__(self,value,attributes,amarshall)

    def marshall(self):
        if self.value==None:
            return "\x00"*4 # a null pointer
        else:
            ret=""
            #print "Self.attributes in dcepointer.marshall=%s"%self.attributes
            if "unique" in self.attributes:
                ptr=self.marshaller.getptr()
                #print "Found unique pointer: %x"%ptr
                ret+=intel_order(ptr)
            ret+=self.value.marshall()
            return ret

class char_t(primarytype):
    """
    A [string] char_t *
    if you marshall a None or a 0 we treat that as a null pointer
    """
    def __init__(self,value=None,attributes=[],marshall=None):
        primarytype.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #print "char_t marshall: %s"%prettyprint("%s"%self.value)
        if self.value in [None,0]:
            return "\x00"*4 # a null pointer
        else:
            ret=""
            if "pointer" in self.attributes:
                ptr=self.marshaller.getptr()
                ret+=intel_order(ptr)
            if self.value[-1:]!="\x00":
                self.value+="\x00" #add null if missing
            size=len(self.value)
            ret+=intel_order(size)+intel_order(0)+intel_order(size)
            #must pad to 4 bytes
            value=pad4(self.value)
            ret+=value
            return ret
        
    def demarshall(self,buf):
        #I don't believe this is implemented yet - placeholder for now
        self.value,buf=getdcechar(buf)
        return buf
    
class wchar_t(primarytype):
    """
    A [string] wchar_t *
    if you marshall a None or a 0 we treat that as a null pointer
    """
    def __init__(self,value=None,attributes=[],marshall=None):
        primarytype.__init__(self,value,attributes,marshall)
        
    def marshall(self):
        #print "wchar_t marshall: %s"%prettyprint("%s"%self.value)
        if self.value in [None,0]:
            return "\x00"*4 # a null pointer
        else:
            ret=""
            if "pointer" in self.attributes:
                ptr=self.marshaller.getptr()
                ret+=intel_order(ptr)
            if self.value[-2:]!="\x00\x00":
                self.value+="\x00\x00" #add null if missing
            size=len(self.value)/2
            ret+=intel_order(size)+intel_order(0)+intel_order(size)
            #must pad to 4 bytes
            value=pad4(self.value)
            ret+=value
            return ret
        
    def demarshall(self,buf):
        self.value,buf=getdcewchar(buf)
        return buf
        
class dcearray(primarytype):
    """value is a list of items in our array. Must all be the same"""
    def __init__(self,value=[],attributes=[],marshall=None,subtype=""):
        primarytype.__init__(self,value,attributes,marshall)
        self.subtype=subtype
        self.starlevel=0
        self.staticsize=0
        
    def marshall(self):
        ret=""
        if not self.staticsize:
            #prepend the size if we are a size_of(variable)
            ret+=intel_order(len(self.value))
            #else we are probabably byte[8] or somesuch
        #handle starlevel here?
        if type(self.value)==type(""):
            #if we are a string
            ret+=self.value
        else:
            for item in self.value:
                ret+=item.marshall()
        #pad it to mod 4
        ret=pad4(ret)
        return ret
    
    def demarshall(self,buf):
        ret,buf=getint(buf) #get number of items in array
        #print "Number of items in array: %x"%ret
        if self.starlevel>0:
            #print "Eating up pointers for %d bytes"%(4*ret)
            #print "Buffer before pointers: \n%s"%prettyhexprint(buf)            
            #we are actually a pointer to our type, not our type directly
            buf=buf[4*ret:]
        #print "Buffer after pointers: \n%s"%prettyhexprint(buf)
        #print "Getting subtype:%s"%self.subtype
        for i in range(0,ret):
            newinstance=self.marshaller.getinstance(self.subtype)
            buf=newinstance.demarshall(buf)
            #print "Adding new instance: %s"%newinstance.value
            self.value+=[newinstance]
        return buf
    
class dcetype(primarytype):
    """
    Encapsulates a DCE struct/union that has been defined in an IDL file
    """
    def __init__(self,defList,attributes=[],amarshall=None):
        """
        example defList:
                     
        TYPE: ['struct', 
                   'TYPE_5', 
                    [   [[], 'long', 0, 'info_level'], 
                        [[['switch_is', 'info_level']], 'USER_INFO', 0, 'element_91']
                    ]
                   ]

        """
        primarytype.__init__(self,defList,attributes,amarshall)

        self.switchval=0 #switchval is the switch value for unions
        #members is a list of our members in order, as tuples
        self.members=[] #attributelist, type, pointerlevel, name
        self.membernames=[] #just a list of the names
        self.values={} #keyed on member names
        self.datatype=defList[0]
        if self.datatype=="struct":
            #print "deflist=%s"%defList
            self.name=defList[1]
            self.members=defList[2]
        elif self.datatype=="union":
            #print "deflist=%s"%defList
            self.attributes=defList[0]
            self.name=defList[1]
            self.members=defList[2]
        else:
            print "Not sure what datatype this is...failing: %s"%self.datatype
        for m in self.members:
            self.membernames.append(m[3])
        return
    
    def marshall(self):
        """
        Create a DCE copy of self
        """
        ret=""
        if self.datatype=="union":
            ret+=intel_order(self.switchval)

        for member in self.members:
            name=member[3]
            value=self.values[name]
            starval=member[2]
            attributes=member[0]
            devlog('dcetype::marshall()', "Marshalling %s.%s"%(self.datatype,name))
            if starval: #and "unique" in attributes:
                ptr=self.marshaller.getptr()
                #print "Found unique pointer: %x for member %s"%(ptr,name)
                ret+=intel_order(ptr)
            ret+=value.marshall()
        return ret
        
    def setmember(self,member,value):
        if member not in self.membernames:
            print "ERROR: %s not in membernames %s"%(member,self.membernames)
        self.values[member]=value
        
    def demarshall(self,buf):
        for member in self.members:
            attributes=member[0]
            name=member[3]
            datatype=member[1]
            instance=self.marshaller.getinstance(datatype)
            self.values[name]=instance
            #if "unique" in attributes:
            #    buf=buf[4:]
            #print "Attributes: %s"%attributes
            #print "Demarshalling: %s:%s with buf: \n%s"%(datatype,name,prettyhexprint(buf))
            buf=instance.demarshall(buf)
        return buf
    
class dcemarshaller:
    """Marshalls types"""
    def __init__(self):
        self.parsedList=[]
        self.typeDict={}
        self.ptr=0x44444444
        self.wchar_t=wchar_t
        self.dceint=dceint
        self.dcebyte=dcebyte
        
    def getptr(self):
        self.ptr+=1
        return self.ptr
    
    def define(self,typestr):
        """
        takes in an IDL type string and sets up internal structures to define these
        massive parser action happens here
        """
        #first, lex+parse the data
        import tidlparse
        parsedList=tidlparse.parse(typestr)
        #print "parsedList: %s"%parsedList
        #print "Length is %s"%len(parsedList)
        #for a in parsedList:
        #    print "TYPE: %s"%a
        self.parsedList=parsedList
        for a in parsedList:
            ourtype=dcetype(a,amarshall=self)
            self.typeDict[a[1]]=ourtype
        #load the defaults
        self.typeDict["wchar_t"]=self.wchar_t()
        self.typeDict["long"]=self.dceint()
        
    def getinstance(self,instname):
        """
        Looks internally for a class which defines a particular structure
        or type and then returns that
        """
        basetype=self.typeDict[instname]
        #print "Basetype=%s"%basetype.membernames
        ret=deepcopy(basetype)
        return ret

    def unistring(self,value):
        return msunistring(value)
    
    def longvalue(self,value):
        return intel_order(value)
    
    def get(self,typestr,value):
        """
        marshalls the data class as type typestr
        returns a string
        """
        data=""
        starlevel=typestr.count("*")
        mytype=typestr.replace("*","").strip().split(" ")[-1]
        unique=typestr.count("unique")
        print "Starlevel=%s type=%s"%(starlevel,mytype)
        if unique:
            data+=intel_order(self.getptr())
        if starlevel>0:

            if value==None: #null pointer
                data+=intel_order(0)

        if mytype in ["long","DWORD"]:
            data+=self.longvalue(value)
        elif mytype in ["wchar_t"]:
            if value!=None:
                data+=self.unistring(value)
        else:
            data+=value.marshall()
        return data
    
def main():
    marshaller=dcemarshaller()
    marshaller.define("""
    
typedef struct  {
   [string] [unique] wchar_t *wkui0_username;
} WKSTA_USER_INFO_0;

typedef struct {
  long num_entries;
  [size_is(num_entries)] [unique] WKSTA_USER_INFO_0 * u_i_0;  
} USER_INFO_0_CONTAINER;

typedef [switch_type(long)] union {  
  [case(0)] USER_INFO_0_CONTAINER * u_i_0_c;  
  /* [case(1)] WKSTA_USER_INFO_1 * user_info1;    */
} USER_INFO;
        
typedef   struct {
  long info_level;
  [switch_is(info_level)] USER_INFO element_91; 
} TYPE_5;

        """)
    type5=marshaller.getinstance("TYPE_5")
    ui0=marshaller.getinstance("WKSTA_USER_INFO_0")
    username=wchar_t()
    username.setvalue("A"*50+"\x00\x00")
    #username.setvalue(None) #null pointer
    ui0c=marshaller.getinstance("USER_INFO_0_CONTAINER")
    ui0c.setmember("u_i_0",dcepointer(None)); #null pointer
    ui0c.setmember("num_entries",dceint(0));
    user_info=marshaller.getinstance("USER_INFO")
    user_info.setmember("u_i_0_c",ui0c)
    type5.setmember("info_level",dceint(0));
    type5.setmember("element_91",user_info); #null pointer
    
    
    data=""
    data+=wchar_t(None,["unique"],marshaller).marshall()
    data+=type5.marshall()
    #prefered max length
    data+=dceint(1000,[],marshaller).marshall()
    data+=dceint(0,["unique"],marshaller).marshall()
    print "Returned data of length %d"%len(data)
    print "data:\n%s"%prettyhexprint(data)
    return 

if __name__=="__main__":
    main()

