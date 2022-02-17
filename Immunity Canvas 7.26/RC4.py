#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

#a naive RC4 implementation
#sinan.eren@immunityinc.com
#beta 0.2

import array
import struct

class RC4:
    def __init__(self):
        pass
    
    def RC4_new(self):
        """typedef struct rc4_key_st
        {
        RC4_INT x,y;
        RC4_INT data[256];
        } RC4_KEY;
        """
        #x, y, data
        return [ 0, 0, array.array("I", []) ]
        
    def RC4_set_key(self, keydata):
        self.key = self.RC4_new()
        self.data = array.array("B", [])
        self.dlen = len(keydata)
        self.id1 = self.id2 = 0
        self.key[0] = self.key[1] = 0
        
        i = 0
        for each in keydata:
            self.data.insert(i, ord(each))
            i += 1
            
        for i in range(0, 256):
            self.key[2].insert(i, i)

        for i in range(0, 256, 4):
            self.RC4_SK_LOOP(i+0)
            self.RC4_SK_LOOP(i+1)
            self.RC4_SK_LOOP(i+2)
            self.RC4_SK_LOOP(i+3)
        return self.key
    
    def RC4_SK_LOOP(self, n):
        tmp = self.key[2][n]
        self.id2 = (self.data[self.id1] + tmp + self.id2) & 0xff
        self.id1 += 1
        if self.id1 == self.dlen:
            self.id1 = 0
        self.key[2][n] = self.key[2][self.id2]
        self.key[2][self.id2] = tmp
        
    def RC4_LOOP(self, ind, outd, i):
        self.key[0] = (self.key[0] + 1) & 0xff
        tx = self.key[2][self.key[0]]
        self.key[1] = (tx + self.key[1]) & 0xff
        self.key[2][self.key[0]] = ty = self.key[2][self.key[1]]
        self.key[2][self.key[1]] = tx
        outd[i] = self.key[2][(tx+ty) & 0xff] ^ ind[i]

    def RC4_update(self, key, inbuf):
        self.key = key
        inlen = len(inbuf)
        indata = array.array("B", [])
        i = 0
        for each in inbuf:
            indata.insert(i, ord(each))
            i += 1
            
        outdata = array.array("B", indata.tolist())
        
            
        i = inlen >> 3
        l = 0
        #8 byte at a time
        if i:
            while 1:
                self.RC4_LOOP(indata, outdata, l+0)
                self.RC4_LOOP(indata, outdata, l+1)
                self.RC4_LOOP(indata, outdata, l+2)
                self.RC4_LOOP(indata, outdata, l+3)
                self.RC4_LOOP(indata, outdata, l+4)
                self.RC4_LOOP(indata, outdata, l+5)
                self.RC4_LOOP(indata, outdata, l+6)
                self.RC4_LOOP(indata, outdata, l+7)
                l += 8
                
                i -= 1
                if not i:
                    break

                
        #do the reminder bytes inlen%8
        i = inlen & 0x7
        if i:
            while 1:
                self.RC4_LOOP(indata, outdata, l+0)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+1)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+2)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+3)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+4)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+5)
                i -= 1
                if not i: break
                self.RC4_LOOP(indata, outdata, l+6)
                i -= 1
                if not i: break
                
        return outdata.tostring()
    
if __name__ == "__main__":
    
    d = RC4()
    key = d.RC4_set_key("0123456789123456")
    enc = d.RC4_update(key, "A"*3912)
    
    print "checking if encrypted text decryptes successfully."
    a = RC4()
    key = a.RC4_set_key("0123456789123456")
    print a.RC4_update(key, enc)
