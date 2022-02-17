#! /usr/bin/env python
"""
ctypes.py

A C type library for MOSDEF
"""


class ctype:
    """
    A C type carries a lot of information.
    If it is a structure, it carries any members it may have.
    It can carry its size.
    If it is a pointer, it says so, and it carries the type it points to.
    """
   
    def __init__(self):
        self.name="Unknown"
        self.size=0
        self.align=4

    def getstacksize(self):
        #pad to mod 4 for stupid winsock
        size=self.getsize()
        #print "Size=%d"%size
        pad=4-size%self.align
        if pad!=4:
            size+=pad
        #print "padded size=%d"%size
        return size
    
    def getsize(self):
        return self.size    
    
    def getname(self):
        return self.name
    
class cint(ctype):
    def __init__(self):
        ctype.__init__(self)
        self.name="int"
        self.size=4
        self.signed=1
    
    # following LLP64 ...
    def setattr(self,attrlist):
        """attrlist is short, unsigned, long, etc"""
        long_size = 0
        for i in attrlist:
            # trickery to support 'long long'
            if i == 'long':
                long_size += 4
            elif i=="short":
                self.size=2
            elif i=="unsigned":
                self.signed=0
            elif i=="signed":
                self.signed=1
            else:
                print "unrecognized attribute for int %s"%i
        if long_size:
            self.size = long_size
        return
    
class cchar(cint):
    def __init__(self):
        cint.__init__(self)
        self.size=1
        
    def gettypestr(self):
        if self.signed:
            signed="signed"
        else:
            signed="unsigned"
        return "%s char"%signed

class cstructure(ctype):
    def __init__(self,members,incomplete=0):
        ctype.__init__(self)
        self.name="struct"
        self.label="Unknown"
        self.incomplete=incomplete
        self.members={}
        offset=0
        #print "Members=%s"%members
        #need to put all the members into their offsets...

        # handle 64 bit alignment needs in struct ...
        pad_flags   = {}
        pad_count   = 0
        last_name   = ''
        last_sz     = 0
        for t in members:
            # trickery son
            if t[0].getsize() == 8 and t[0].name in ['pointer', 'int']:
                if last_name:
                    # if this guy is 8, and the last member was misaligned, last member needs pad
                    if last_sz % 8:
                        pad_flags[last_name] = True
                        #print "XXX: padding out %s" % last_name
                        last_sz += (8 - last_sz % 8)
            last_name = t[1]
            last_sz  += t[0].getsize()
            # init to False ...
            pad_flags[t[1]] = False
           
        for t in members:
            myctype=t[0]
            name=t[1]

            #print "name=%s"%name
            #print "myctype=%s"%myctype
            #print "offset=%s"%offset
            self.members[name]=(myctype,offset)
            offset+=myctype.getsize()
            # align on 8 if needed
            if name in pad_flags and pad_flags[name] == True:
                #print "XXX: padding %s with %d bytes" % (name, 8 - offset % 8)
                offset += (8 - offset % 8)
                    
        self.size=offset
    
    def iscomplete(self):
        if self.incomplete:
            return 0
        return 1
    
    def getmembertype(self,member):
        return self.members[member][0]        
    
    def getmemberoffset(self,member):
        if member not in self.members:
            return -1
        offset=self.members[member][1]
        return offset
        

class cunion(ctype):
    """
    Unions have members but all members are at the same offset
    """
    def __init__(self,members):
        """members is a list of our members in (name,type) format"""
        ctype.__init__(self)

class cpointer(ctype):
    """
    Points to another object. To implement +=expr
    we can do:
        c=cpointer()
        expr*c.getpointedtype().getsize()
    """
    def __init__(self,totype):
        ctype.__init__(self)
        self.name="pointer"
        self.totype=totype #also a ctype
        self.size=4
    
    def setattr(self,attrlist):
        self.totype.setattr(attrlist)

    def getpointedtype(self):
        return self.totype
    
    def getitemsize(self):
        return self.totype.size
    
    def gettypestr(self):
        return "pointer to %s"%self.totype.gettypestr()
    
class cpointer64(ctype):
    """
    Points to another object. To implement +=expr
    we can do:
        c=cpointer()
        expr*c.getpointedtype().getsize()
    """
    def __init__(self,totype):
        ctype.__init__(self)
        self.name   = "pointer"
        self.totype = totype #also a ctype
        self.size   = 8
     
    def setattr(self, attrlist):
        self.totype.setattr(attrlist)

    def getpointedtype(self):
        return self.totype
    
    def getitemsize(self):
        return self.totype.size
    
    def gettypestr(self):
        return "pointer to %s"%self.totype.gettypestr()
    
class carray(ctype):
    def __init__(self,itemtype,itemnumber):
        ctype.__init__(self)
        self.name="array"
        self.numberofitems=int(itemnumber)
        self.sizeofitem=itemtype.getsize()
        self.totype=itemtype
    
    def gettypestr(self):
        return "array of %d %s's"%(self.numberofitems,self.totype.gettypestr())
    
    def getsize(self):
        """
        Returns the total size of the array
        """
        return self.numberofitems*self.sizeofitem
    
    def getoffset(self,itemnumber):
        return self.sizeofitem*itemnumber
    
    def getitemsize(self):
        return self.sizeofitem


class cglobal(ctype):
    def __init__(self,itemtype):
        ctype.__init__(self)
        self.name="global"
        self.totype=itemtype
        self.label=""
        self.size=itemtype.getsize()
    
    def getstacksize(self):
        return 0
    
    def setLabel(self,label):
        self.label=label

class varcache:
    """
    Caches types as they are defined
    """
    def __init__(self):
        self.typecache={}
        self.typecache["int"]=cint()
        self.typecache["short"]=cint()
        self.typecache["short"].size=2
        self.typecache["long"]=cint()
        self.typecache["long"].size=4
        self.typecache["char"]=cchar()
        self.typecache["void"]=cint() #whatever.
        self.typecache['long long']         = cint()
        self.typecache['long long'].size    = 8
    
    def addtype(self,typestr,type):
        self.typecache[typestr]=type
        return
    
    def hastype(self,typestr):
        if typestr in self.typecache.keys():
            return 1
        else:
            return 0
        
    def gettype(self,typestr):
        """
        Turns a string into a type class
        can we handle:
        struct davestruct ** dave
        a pointer to a pointer to a davestruct
        how to do this:
            split it into tokens and have them be token-strings
            (we can enforce spaces between * for example, but that would hide
            our true token-ized nature)
            
        """
        if isinstance(typestr,ctype):
            #it's not a string, it's a ctype. Our job is done!
            return typestr
        
        struct=0
        array=0
        typename=""
        pointer=0
        totype=None
        if typestr in self.typecache.keys():
            return self.typecache[typestr]
        else:
            print "UNKNOWN TYPE: %s"%typestr
            return None
    
    def getAllTypes(self):
        #return all the types we have in a list
        ret=[]
        for t in self.typecache.keys():
            ret+=[(t,self.typecache[t])]
        #print "Returning %s"%ret
        return ret
        
        
if __name__=="__main__":
    a=carray(cchar(),5000)
    #a=cglobal(cpointer(cint()))
    print a.getsize()
