#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from exploitutils import *

try:
    import libs.Crypto.Cipher.DES as DES

except:
    pass

class MSSnetwork:

    __mss_fd = None
    __mss_desKey = ""
    __mss_doDes = 0
    __mss_DESENCRYPT = None
    __mss_DESDECRYPT = None

    def set_des(self, key, desMode=DES.DES_CBC_MODE):
        self.__mss_doDes = 1
        self.__mss_desKey = key
        self.__mss_DESENCRYPT = DES.DES(self.__mss_desKey, mode=desMode)
        self.__mss_DESDECRYPT = DES.DES(self.__mss_desKey, mode=desMode)
        # XXX testing
        # self.__mss_DESDECRYPT = self.__mss_DESENCRYPT

    def get_desKey(self):
        return self.__mss_desKey

    def get_desObjKey(self):
        return self.__mss_DESENCRYPT.desObjKey

    def get_desMode(self):
        return self.__mss_DESENCRYPT.Mode

    def get_doDes(self):
        return self.__mss_doDes

    def set_fd(self, fd):
        self.__mss_fd = fd

    def get_fd(self):
        return self.__mss_fd

    def desCrypt(self, block):
        "DES encrypt a block of data"

        # XXX .. re-init to 0
        #self.__mss_DESENCRYPT = des.DES(self.__mss_desKey, mode=1)

        if (len(block) % 8):
            #print "[XXX] possible problem, block not aligned .. fixing !!!"
            while (len(block) % 8):
                block += "P" # pad with nul bytes

        print "[!] incoming plaintext:"
        for c in block:
            print "%02X "% ord(c),
        print "\n"

        ciphertext = ""
        if self.__mss_DESENCRYPT.Mode == DES.DES_ECB_MODE:
            ciphertext = []
            # when in ECB mode you have to do 8 blocks yourself
            cipherblock = []
            for c in block:
                cipherblock.append(c)
                if len(cipherblock) == 8:
                    ciphertext.append(self.__mss_DESENCRYPT.encrypt("".join(cipherblock)))
                    cipherblock = []
            # back to string
            ciphertext = "".join(ciphertext)
        else:
            # CBC mode
            ciphertext = self.__mss_DESENCRYPT.encrypt(block) # needs to be mod 8

        print "[!] outgoing ciphertext: "
        for c in ciphertext:
            print "%02X "% ord(c),
        print "\n"
        return ciphertext

    def desDecrypt(self, ciphertext):
        "DES decrypt a block of data"

        # XXX .. re-init to 0
        #self.__mss_DESDECRYPT = des.DES(self.__mss_desKey, mode=1)

        # tie into des module
        print "[!] incoming ciphertext: "
        for c in ciphertext:
            print "%02X "% ord(c),
        print "\n"

        plaintext = ""
        if self.__mss_DESDECRYPT.Mode == DES.DES_ECB_MODE:
            plaintext = []
            # when in ECB mode you have to do 8 blocks yourself
            plainblock = []
            for c in ciphertext:
                plainblock.append(c)
                if len(plainblock) == 8:
                    plaintext.append(self.__mss_DESDECRYPT.decrypt("".join(plainblock)))
                    plainblock = []
            # back to string
            plaintext = "".join(plaintext)
        else:
            # CBC mode
            plaintext = self.__mss_DESDECRYPT.decrypt(ciphertext)

        print "[!] returning plaintext: "
        for c in plaintext:
            print "%02X "% ord(c),
        print "\n"
        #print plaintext
        return plaintext

    def sendrequest(self, request):
        """
        sends a request to the remote shellcode

        XXX: actual des DECRYPT in win32MosdefShellserver.py 'decode'

        """

        try:
            devlog('shellserver::sendrequest', "Sending Request (%d bytes)" % len(request))
        except TypeError:
            devlog('shellserver::sendrequest', "FATAL: Sending Request of Non-String? (type: %s)" % type(request))

        self.requestsize = len(request)
        request = self.int2str32(len(request)) + request
        #print "R: "+prettyprint(request)
        self.enter() #threading support added. :>
        self.node.parentnode.send(self.connection, request)
        devlog('shellserver::sendrequest', "Done sending request")
        return

    def reliableread(self, length):
        """
        reliably read off our stream without being O(N). If you just
        do a data+=tmp, then you will run into serious problems with large
        datasets
        """
        data = ""
        datalist = []
        readlength = 0

        # length of 0 means read untill MOSDEF EOF is received
        # the first 1024 byte block has its first 4 bytes set
        # as the actual len of the block .. this to solve being
        # essentially blind .. when the first 4 bytes == 0 .. it's EOF

        if length == -1:
            import struct
            self.log("reliable read got length 0, assuming MOSDEF EOF mode ..")
            while 1:
                # readfromfd will send 1024 byte blocks
                tmp = self.node.parentnode.recv(self.connection, 1024)
                if tmp == "":
                    self.log("Connection broken?!?")
                    break
                # str2int32 derives endianness from self.Endianness .. handy
                linelen = self.str2int32(tmp[:4])
                #print "MOSDEF EOF LINELEN: %d\n"% linelen
                if not linelen:
                    # means we got EOF
                    break
                tmp = tmp[4:]
                datalist.append(tmp[:linelen])
        else:
            # normal operation
            while readlength < length:
                tmp = self.node.parentnode.recv(self.connection, length - readlength)
                if tmp == "":
                    self.log("Connection broken?!?")
                    break
                readlength += len(tmp)
                datalist.append(tmp)

        data="".join(datalist)
        return data

    def readword(self):
        """ read one word off our stream"""
        data=self.reliableread(4)
        return self.str2int32(data)

    def short_from_buf(self, buf):
        return istr2halfword(buf)

    def readshort(self):
        data=self.reliableread(2)
        return self.short_from_buf(data)

    def readbuf(self, size):
        return self.reliableread(size)

    def writeint(self, word):
        data=intel_order(word)
        # need to make reliable
        self.node.parentnode.send(self.connection, data)
        return

    def writebuf(self, buf):
        # need to make reliable
        self.node.parentnode.send(self.connection, buf)
        return

    def writestring(self, string):
       self.writeint(len(string))
       self.writebuf(string)
       return

    def readstruct(self, args):
        ret = {}
        for typestr, member in args:
            if typestr == "i":
                ret[member] = self.readint()
            elif typestr == "l":
                ret[member] = self.readlong()
            elif typestr == "s":
                ret[member] = self.readshort()
        return ret

    def readint(self, signed=False):
        i = self.readword()
        if signed:
            return sint32(i)
        else:
            return uint32(i)

    def readlonglong(self, signed=False):
        data    = self.reliableread(8)
        i       = self.str2int64(data)
        if signed == True:
            return sint64(i)
        else:
            return sint64(i)

    def readlong(self, signed=False):
        if not hasattr(self,"LP64"):
            self.LP64 = False
        if   self.LP64:
            return self.readlonglong(signed)
        else:
            return self.readint(signed)


    def readblock(self):
        """
        Reads one block at a time...<int><buf>
        """
        data = []
        tmp = ""
        wanted = self.readint() #the size we are recieving
        devlog('shellserver::readblock()', "wanted=%d" % wanted)
        while wanted > 0:
            devlog('shellserver::readblock()', "before recv %d" % wanted)
            tmp=self.node.parentnode.recv(self.connection, wanted)
            devlog('shellserver::readblock()', "after recv %d" % len(tmp))
            if tmp == "":
                print "Connection broken?"
                break
            devlog('shellserver::readblock()', "data+=%s" % prettyprint(tmp))
            data.append(tmp)
            wanted -= len(tmp)
        return "".join(data)

    def readstring(self):
        """
        This string reader completely sucks and needs to change to be O(1)

        Ok, fixed.
        """
        return self.readblock()

