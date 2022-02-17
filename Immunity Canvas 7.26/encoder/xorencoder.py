#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import struct
import sys
if "." not in sys.path:
    sys.path.append(".")
                                                                                
from MOSDEF import mosdef
from exploitutils import *

class simpleXOR:
        """
        A simple XOR encoder
        """
        def __init__(self, key=None):
                self.badstring = ""
                self.key = key
                #load edi with current place
                self.getipff="\xeb\x03\x5f\xeb\x05\xe8\xf8\xff\xff\xff" #call,jmp
                self.getipnoff="\xd9\xee\xd9\x74\x24\xf4\x5f\x83\xc7\x0a" #fnstenv
                self.subesp=0
                
        def setbadstring(self, badstring):
                self.badstring = badstring

        def setKey(self, key):
                self.key = key

        def getkey(self):
                return self.key        
                
        def compile_encoder(self, size):
                """
                Generates the encoder based on the badstring
                """

                # XXX: little kludge fix for some ff vs. 0a situations
                if '\xff' not in self.badstring:
                    devlog("encoder", "Using normal xor decoder")
                    self.getip = "\xeb\x03\x5f\xeb\x05\xe8\xf8\xff\xff\xff" # jmp/call
                else:
                    if "\x0a" in self.badstring:
                        raise Exception, "Warning: ff and 0a in badstring for xor encoder....failing"
                    devlog("encoder","Using fnsetenv xor decoder: self.badstring=%s"%prettyprint(self.badstring))
                    self.getip = "\xd9\xee\xd9\x74\x24\xf4\x5f\x83\xc7\x0a" # fnstenvAA

                prepre=''
                #print "XOR ENCODER: SUBESP=%d"%self.subesp
                if self.subesp:
                        #print "Using add"
                        prepre="add $-%s,%%esp\n"%(hex(self.subesp))
                        if hasbadchar(mosdef.assemble(prepre,"X86"),self.badstring):
                                #print "Using subl"
                                prepre="subl $%s,%%esp\n"%hex(self.subesp)
                                if hasbadchar(mosdef.assemble(prepre,"X86"),self.badstring):
                                        #print "Using xor"
                                        # add a variable xorkey solution      
                                        xorkeys=[0x41424344, 0x45464748] #ABCD!
                                        for xorkey in xorkeys:
                                            if not hasbadchar(struct.pack("<L", self.subesp^xorkey), self.badstring):
                                                break
                                        prepre="movl $0x%8.8x,%%eax\n"%xorkey
                                        prepre+="xorl $0x%8.8x,%%eax\n"%uint32(self.subesp^xorkey)
                                        prepre+="subl %eax,%esp\n"

                pre=""
                
                #first we do a two-step to load the size.
                if size < 0x80:
                        pre="""
        pushl $SIZE
        popl %ecx
                        """
                elif size < 0x100:
                        pre="""
        xorl %ecx,%ecx
        movb $SIZE,%cl
                        """
                else:
                        #print "big size!"
                        pre="movl $SIZE,%ecx\n" 
                        #if that didn't work (which it won't) we try XORL 
                        if hasbadchar(mosdef.assemble(pre.replace("SIZE",str(size)),"X86"),self.badstring):
                                #print "Using xor"
                                # add a variable xorkey solution
                                xorkeys=[0x41424344, 0x45464748] #ABCD!
                                for xorkey in xorkeys:
                                    if not hasbadchar(struct.pack("<L", size^xorkey), self.badstring):
                                        break
                                pre="movl $0x%8.8x,%%ecx\n"%xorkey
                                pre+="xorl $0x%8.8x,%%ecx\n"%uint32(size^xorkey)
                #print pre.replace("SIZE",str(size))
                #print "PRE=%s"%hexprint(mosdef.assemble(pre.replace("SIZE",str(size)),"X86"))

                code="start:\n"+pre +"""
        leal end-start(%edi),%edi
encode:
        xorb $KEY,(%edi)
        incl %edi
        loop encode
end:
                """

                code=code.replace("SIZE", hex(size))
                code=code.replace("KEY", hex(self.key))
                #print "code=%s"%code
                bin=mosdef.assemble(code, "X86")

                #here we have a small loop to allow us to replace different parts of the
                #code with other fragments to avoid bad bytes
                #first try just subtracting one to leal line. This line has a \x0d in it by default
                #which is bad.
                replace_list=[("leal end-start(%edi),%edi","leal end-start-1(%edi),%edi\ninc %edi")]
                #then try adding 40 to get away from control characters here - we then subtract and xchange with eax
                replace_list+=[("leal end-start(%edi),%edi","leal end-start+40(%edi),%eax\nsub $40, %eax\nxchg %eax, %edi")]
                #add a variation to handle \x80 as a badchar
                replace_list+=[("encode:\n        xorb $%s,(%%edi)" % hex(self.key),"incb -6(%%edi)\nencode:\n.byte 0x7f\n.byte 0x37\n.byte %s\n" % hex(self.key) )]
                i=0
                while hasbadchar(bin, self.badstring):
                    if i>(len(replace_list)-1):
                        #failed, sorry. :<
                        break 
                    replace_key=replace_list[i][0]
                    replace_value=replace_list[i][1]
                    devlog("encoder", "Trying to replace %s with %s"%(replace_key,replace_value))
                    code2=code.replace(replace_key, replace_value)
                    bin=mosdef.assemble(code2, "X86")
                    devlog("encoder", "Bin resulting from that: %s"%prettyhexprint(bin))
                    i+=1
                    
                if prepre:
                    subbin=mosdef.assemble(prepre,"X86")
                else:
                    subbin=""
                return subbin+self.getip + bin
        
        def xoR(self, data, key):
                ret=""
                for a in range(0, len(data)):
                        ret += chr( ord(data[a]) ^ key)
                return ret

        def force_encode(self, data):
                key = 0
                encodeshellcode=""
                while not encodeshellcode:
                        self.key = key
                        if key > 255:
                                return ""
                        encodeshellcode = self.encode(data)
                        key = key + 1
                        
                return encodeshellcode
        
        def encode(self, data):
                #print "Encoder using key %s"%hex(self.key)
                encoder=self.compile_encoder(len(data))
                if hasbadchar(encoder,self.badstring):
                        devlog("encoder", "Encoder has bad character")
                        devlog("encoder", "Encoder: %s"%hexprint(encoder))
                        devlog("encoder", "Badstring: %s"%hexprint(self.badstring))
                        devlog("encoder", "Intersection: %s"%hexprint(intersection(self.badstring,encoder)))
                        return ""
                xored=self.xoR(data, self.key)
                ret = encoder+xored
                if hasbadchar(ret,self.badstring):
                        return ""
                return ret

        def find_key(self,rawshellcode):
                cnt = 0xff
                while cnt:
                        self.key=cnt
                        shellcode = self.encode(rawshellcode)
                        if shellcode != "":
                            break
                        else:
                            cnt -= 1
                return cnt    

def main():
        x=simpleXOR(0xa5)
        x.encode("\x90\x90\x90\x90"*50)

if __name__ == "__main__":
        main()
