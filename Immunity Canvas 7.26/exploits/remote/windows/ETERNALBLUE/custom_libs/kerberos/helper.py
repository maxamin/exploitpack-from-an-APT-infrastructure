#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  helper.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import os
import sys
import struct
import hmac
import hashlib
import time
import logging
import socket
import select
from fractions import gcd
from datetime import datetime

try:
    from Crypto.Cipher import ARC4
    from Crypto.Cipher import AES
    from Crypto.Hash import HMAC, SHA
except ImportError:
    logging.error("kerberos.helper: Cannot import Crypto (required)")
    raise


###
# Sockets
###

# For some reason there is a slight difference between sending a packet
# on both the UDP and the TCP services. For this reason we abstract everything
# within convenient functions.

KERBEROS_PORT = 88

class KerberosSocket:

    def __init__(self, ip, port=KERBEROS_PORT, use_tcp=False, timeout=2):
        self.use_tcp = use_tcp
        self.ip = ip
        self.port = port
        self.timeout = timeout

    def __send_udp(self, frame):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.sendto(frame, (self.ip, self.port))
            s.setblocking(0)
            ready = select.select([s], [], [], self.timeout)
            data = None
            if ready[0]:
                data = s.recv(4096)
            s.close()
            return data
        except Exception as e:
            logging.error("KerberosSocket.__send_udp() failed: %s" % str(e))
            return None

    def __send_tcp(self, frame):
        try:
            s = socket.socket()
            s.settimeout(self.timeout)
            s.connect((self.ip, self.port))
            size = struct.pack('>L', len(frame))
            s.send(size + frame)
            data = s.recv(4096)
            s.close()
            return data[4:]
        except Exception as e:
            logging.error("KerberosSocket.__send_tcp() failed: %s" % str(e))
            return None

    def send(self, frame):
        if self.use_tcp:
            return self.__send_tcp(frame)
        else:
            return self.__send_udp(frame)

def krb5_send_frame(frame, ip, port=KERBEROS_PORT, use_tcp=False, timeout=2):
    """
    All in one function sending a packet to the KDC and returning its answer.
    """
    krb_sock = KerberosSocket(ip, port=port, use_tcp=use_tcp)
    return krb_sock.send(frame)

def krb5_get_kdc_ip(domain, timeout=2):
    """
    Simple function to locate a KDC using the DNS (domain in fqdn).
    """
    try:
        dom, host, ip_list = socket.gethostbyname_ex(domain)
        for ip in ip_list:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                s.connect((ip, KERBEROS_PORT))
            except Exception as e:
                continue
            else:
                s.close()
                return ip
    except Exception as e:
        return None


###
# Times
###

# Dealing with time is a pita. Here is a quick and dirty solution to solve
# many issues. It's not perfect but does the job.
# Tiny adaptation from:
# http://stackoverflow.com/questions/4770297/python-convert-utc-datetime-string-to-local-datetime

def timestamp_from_utc_to_local(utc_timestamp):
    now_timestamp = time.time()
    offset = datetime.fromtimestamp(now_timestamp) - datetime.utcfromtimestamp(now_timestamp)
    return utc_timestamp + int(offset.total_seconds())

###
# Bitstring
###

# Shitty BitString object doesn't have (or am I missing something?) any convertion
# method
# http://sourceforge.net/p/pyasn1/mailman/pyasn1-users/thread/alpine.LNX.2.00.1205101941230.22251@cray.glas.net/

def BitString2Integer(obj):
    i = 0
    for bit in obj:
        i = i << 1 | bit
    return i

###
# Crypto API
###

# Various constants

AES_BLOCK_SIZE    = 16
AES_128_KEYLENGTH = 16
AES_256_KEYLENGTH = 32
ARCFOUR_KEYLENGTH = 16

# Etypes for crypto operations

ETYPE_NULL                    = 0
ETYPE_DES_CBC_CRC             = 1
ETYPE_DES_CBC_MD4             = 2
ETYPE_DES_CBC_MD5             = 3
ETYPE_DES3_CBC_MD5            = 5
ETYPE_OLD_DES3_CBC_SHA1       = 7
ETYPE_SIGN_DSA_GENERATE       = 8
ETYPE_DSA_SHA1                = 9
ETYPE_RSA_MD5                 = 10
ETYPE_RSA_SHA1                = 11
ETYPE_RC2_CBC                 = 12
ETYPE_RSA                     = 13
ETYPE_RSAES_OAEP              = 14
ETYPE_DES_EDE3_CBC            = 15
ETYPE_DES3_CBC_SHA1           = 16
ETYPE_AES128_CTS_HMAC_SHA1_96 = 17 # supported
ETYPE_AES256_CTS_HMAC_SHA1_96 = 18 # supported
ETYPE_ARCFOUR_HMAC_MD5        = 23 # supported
ETYPE_ARCFOUR_HMAC_MD5_56     = 24
ETYPE_CAMELLIA128_CTS_CMAC    = 25
ETYPE_CAMELLIA256_CTS_CMAC    = 26

# Ctypes for integrity check
# TODO.

#KERB_CHECKSUM_HMAC_MD5 (-138)


##
# Generic subfunctions
##

def __krb5_nfold(s, n):
    """
    Translated from krb5int_nfold() in src/lib/crypto/krb/nfold.c
    (krb5 package, ubuntu) to python
    (Most of) the comments of the original author are left.
    Link: https://tools.ietf.org/html/rfc3961
    """
    _in = [ ord(x) for x in s]
    inbits = len(s)
    outbits = n

    # first compute lcm(n,k)
    lcm = inbits * outbits / gcd(inbits, outbits)

    # now do the real work
    out = [ 0 for i in xrange(outbits) ]
    byte = 0

    # this will end up cycling through k lcm(k,n)/k times, which
    # is correct
    for i in range(lcm-1,-1,-1):

        # compute the msbit in k which gets added into this byte
        # first, start with the msbit in the first, unrotated byte
        msbit = (inbits<<3)-1
        # then, for each byte, shift to the right for each repetition
        msbit += ((inbits<<3)+13)*(i/inbits)
        # last, pick out the correct byte within that shifted repetition
        msbit += (inbits-(i%inbits))<<3
        msbit %= (inbits<<3)

        # pull out the byte value itself
        _a = int(_in[((inbits-1)-(msbit>>3)) % inbits])<<8
        _b = int(_in[((inbits)-(msbit>>3))%inbits])
        byte += (( _a | _b ) >> ((msbit&7)+1)) & 0xff

        # do the addition
        byte += out[ i % outbits]
        out[i%outbits] = byte & 0xff

        # keep around the carry bit, if any
        byte >>= 8

    # if there's a carry bit left over, add it back in
    if byte:
        for i in range(outbits-1,-1,-1):

            # do the addition
            byte += out[i]
            out[i] = byte & 0xff

            # keep around the carry bit, if any
            byte >>= 8

    return ''.join(map(lambda x: chr(x), out))

def __krb5_encrypt_block(key, block):

    enctype, inkey = key
    # AES-X is always a 16 bytes block cipher
    if enctype in [ ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_AES256_CTS_HMAC_SHA1_96 ]:
        return __aes_encrypt_block(inkey, block)

    # RC4 or unimplemented block ciphers should trigger an exception
    raise ValueError("__krb5_encrypt_block: type %d is not implemented!" % enctype)

def __krb5_get_blocksize(etype):

    # AES-X is always a 16 bytes block cipher
    if etype in [ ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_AES256_CTS_HMAC_SHA1_96 ]:
        return AES_BLOCK_SIZE

    # RC4 or unimplemented block ciphers should trigger an exception
    raise ValueError("__krb5_get_blocksize: type %d is not implemented!" % etype)

def __krb5_derive(key, salt):
    """
    Translated from derive_random_rfc3961() in src/lib/crypto/krb/derive.c
    (krb5 package, ubuntu) to python
    Link: https://tools.ietf.org/html/rfc3961
    """
    enctype, inkey = key
    blocksize = __krb5_get_blocksize(enctype)
    keybytes = len(inkey)

    # Initialize the input block.
    if len(salt) == blocksize:
        block = salt
    else:
        block = __krb5_nfold(salt, blocksize)

    # Loop encrypting the blocks until enough key bytes are generated.
    n = 0
    outrnd = ''
    while (n < keybytes):
        block = __krb5_encrypt_block(key, block)
        if (keybytes - n) <= blocksize:
            outrnd += block[0:keybytes - n]
        outrnd += block
        n += blocksize

    return outrnd[0:keybytes]

def __krb5_get_keylength(etype):

    if etype == ETYPE_AES128_CTS_HMAC_SHA1_96:
        return AES_128_KEYLENGTH

    if etype == ETYPE_AES256_CTS_HMAC_SHA1_96:
        return AES_256_KEYLENGTH

    # RC4 or unimplemented block ciphers should trigger an exception
    raise ValueError("__krb5_get_keylength: type %d is not implemented!" % etype)

def __krb5_random_to_key(etype, rnd_str):

    key_size = __krb5_get_keylength(etype)
    if len(rnd_str) < key_size:
        raise ValueError("__krb5_random_to_key: Insufficient string length for encryption type %d" % etype)
    return rnd_str[0:key_size]

##
# CRC32 backend
##

__crc_table = []
__CRC_GEN=0xEDB88320

def __krb5_crc_init_table():
    poly = __CRC_GEN
    for i in xrange(256):
        crc = i
        for j in xrange(8):
            if crc & 1:
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
        __crc_table.append(crc)
    return

def __krb5_crc_update(data, crc):
    for c in data:
        crc = __crc_table[(crc ^ ord(c))&0xff] ^ (crc >> 8)
    return crc & 0xFFFFFFFF

def __krb5_compute_crc(data):
    if not len(__crc_table):
        __krb5_crc_init_table()
    crc = __krb5_crc_update(data, 0)
    return struct.pack('BBBB',
        (crc >> 0) & 0xff,
        (crc >> 8) & 0xff,
        (crc >> 16) & 0xff,
        (crc >> 24) & 0xff)

##
# RC4 backend
##

def __krb5_encrypt_arc4(key, mode, data):
    mode_str = struct.pack("<L", mode)
    h1 = hmac.new(key[1])
    h1.update(mode_str)
    K1 = h1.digest()
    data = os.urandom(8) + data
    h2 = hmac.new(K1)
    h2.update(data)
    checksum_hdr = h2.digest()
    h3 = hmac.new(K1)
    h3.update(checksum_hdr)
    K3 = h3.digest()
    return checksum_hdr + ARC4.new(K3).encrypt(data)

def __krb5_decrypt_arc4(key, mode, enc_data):
    mode_str = struct.pack("<L", mode)
    h1 = hmac.new(key[1])
    h1.update(mode_str)
    K1 = h1.digest()
    h3 = hmac.new(K1)
    h3.update(enc_data[0:16])
    K3 = h3.digest()
    return ARC4.new(K3).decrypt(enc_data[16:])[8:]

##
# AES backend
# Note: This will need to be refactored a bit the day we implement 3DES and stuff as well.
##

def __padding(s, padsize):
    padlen = (padsize - (len(s) % padsize)) % padsize
    return s + chr(0)*padlen

def __aes_encrypt_block(inkey, plaintext):

    const_IV = chr(0) * AES_BLOCK_SIZE

    # If the plaintext is a single block, ECB is enough as the IV
    # is a vector of 0 (thus neutral element in the XOR operation)
    # Note: Logically speaking we should throw an exception instead so this
    # code is probably temporary until we figure out if it should be kept as this
    # or not.
    if len(plaintext) <= AES_BLOCK_SIZE:
        obj = AES.new(inkey, AES.MODE_ECB)
        ciphertext = obj.encrypt(__padding(plaintext, AES_BLOCK_SIZE))
        return ciphertext

    # If the plaintext is 17 bytes long or more, CBC_CTS can be used.
    obj = AES.new(inkey, AES.MODE_CBC, const_IV)
    ciphertext = obj.encrypt(__padding(plaintext, AES_BLOCK_SIZE))
    n = len(plaintext) % AES_BLOCK_SIZE
    nbr_missing_bytes = 0 if not n else AES_BLOCK_SIZE - n
    L1 = [ ciphertext[AES_BLOCK_SIZE*i:AES_BLOCK_SIZE*i+AES_BLOCK_SIZE] for i in xrange(len(ciphertext)/AES_BLOCK_SIZE) ]
    L2 = L1[:-2]
    penultimate = L1[-1]
    ultimate = L1[-2][:-nbr_missing_bytes] if nbr_missing_bytes else L1[-2]
    L2 += [ penultimate ] + [ ultimate ]
    return ''.join(L2)

def __aes_decrypt_block(inkey, ciphertext):

    const_IV = chr(0) * AES_BLOCK_SIZE

    # If the ciphertext is a single block, ECB is enough as the IV
    # is a vector of 0 (thus neutral element in the XOR operation)
    # Note: Logically speaking we should throw an exception instead so this
    # code is probably temporary until we figure out if it should be kept as this
    # or not.
    if len(ciphertext) <= AES_BLOCK_SIZE:
        obj = AES.new(inkey, AES.MODE_ECB)
        plaintext = obj.decrypt(ciphertext)
        return plaintext

    # If the ciphertext is 17 bytes long or more, CBC_CTS can be used.
    n = len(ciphertext) % AES_BLOCK_SIZE
    nbr_missing_bytes = 0 if not n else (AES_BLOCK_SIZE - n)
    L1 = [ ciphertext[AES_BLOCK_SIZE*i:AES_BLOCK_SIZE*i+AES_BLOCK_SIZE] for i in xrange(len(ciphertext)/AES_BLOCK_SIZE) ]
    last_chunk = ciphertext[len(ciphertext)/16*16:]
    if last_chunk:
        L1 += [ last_chunk ]

    penultimate = L1[-2]
    ultimate = L1[-1]

    # decode the first part
    obj = AES.new(inkey, AES.MODE_CBC, const_IV)
    p1 = obj.decrypt(''.join(L1[:-2]))

    # decode the penultimate
    obj = AES.new(inkey, AES.MODE_ECB)
    p2 = obj.decrypt(penultimate)

    if nbr_missing_bytes:
        recovered_penultimate = ultimate + p2[-nbr_missing_bytes:] + penultimate
    else:
        recovered_penultimate = ultimate + penultimate

    if len(L1) == 2:
        new_iv = const_IV
    else:
        new_iv = L1[-3]
    obj = AES.new(inkey, AES.MODE_CBC, new_iv)
    p3 = obj.decrypt(recovered_penultimate)

    if nbr_missing_bytes:
        return p1 + p3[:-nbr_missing_bytes]
    else:
        return p1 + p3

def __krb5_encrypt_aes(key, mode, data):

    __padsize = 1
    __hmac_output_size = 12

    ki = __krb5_derive(key, struct.pack('>IB', mode, 0x55))
    ke = __krb5_derive(key, struct.pack('>IB', mode, 0xAA))

    confounder = '\x00' * AES_BLOCK_SIZE
    #confounder = get_random_bytes(AES_BLOCK_SIZE)

    plaintext = confounder + __padding(data, __padsize)
    hmac = HMAC.new(ki, plaintext, SHA).digest()
    return __aes_encrypt_block(ke, plaintext) + hmac[:__hmac_output_size]

def __krb5_decrypt_aes(key, mode, data):

    __padsize = 1
    __hmac_output_size = 12

    ki = __krb5_derive(key, struct.pack('>IB', mode, 0x55))
    ke = __krb5_derive(key, struct.pack('>IB', mode, 0xAA))

    ciphertext = data[:-__hmac_output_size]
    hmac1 = data[-__hmac_output_size:]

    plaintext = __aes_decrypt_block(ke, ciphertext)
    hmac2 = HMAC.new(ki, plaintext, SHA).digest()[:__hmac_output_size]

    if(hmac1 != hmac2):
        raise ValueError('The payload has an invalid hmac!')

    return plaintext[AES_BLOCK_SIZE:]


##
# Frontend API -- The only API to be called outside (except for test files)
##

def krb5_generate_random_key(etype):
    """
    Dumb function to generate a random key
    """
    if etype == ETYPE_ARCFOUR_HMAC_MD5:
        key_length = ARCFOUR_KEYLENGTH
    elif etype == ETYPE_AES128_CTS_HMAC_SHA1_96:
        key_length = AES_128_KEYLENGTH
    elif etype == ETYPE_AES256_CTS_HMAC_SHA1_96:
        key_length = AES_256_KEYLENGTH
    else:
        raise ValueError("krb5_generate_random_key: Not implemented for type %d!" % etype)

    return [etype, os.urandom(key_length)]

def krb5_string_to_key(etype, password, salt='', nbr_iter=4096):

    # https://tools.ietf.org/html/rfc4757 (String2Key)
    if etype == ETYPE_ARCFOUR_HMAC_MD5:
        # Basically it's an NTLM hash
        return hashlib.new('md4', password.encode('utf-16le')).digest()

    # https://tools.ietf.org/html/rfc3962
    elif etype in [ ETYPE_AES128_CTS_HMAC_SHA1_96, ETYPE_AES256_CTS_HMAC_SHA1_96 ]:
        # We use a PRF
        seed = hashlib.pbkdf2_hmac('sha1', password, salt, nbr_iter, dklen=__krb5_get_keylength(etype))
        k = __krb5_random_to_key(etype, seed)
        val = __krb5_derive([etype, k], 'kerberos')
        return val

    else:
        raise ValueError("krb5_string_to_key: Encryption type %d is not implemented!" % etype)

def krb5_encrypt(key, mode, data):

    etype = key[0]
    if etype == ETYPE_ARCFOUR_HMAC_MD5:
        return __krb5_encrypt_arc4(key, mode, data)
    elif etype == ETYPE_AES128_CTS_HMAC_SHA1_96:
        return __krb5_encrypt_aes(key, mode, data)
    elif etype == ETYPE_AES256_CTS_HMAC_SHA1_96:
        return __krb5_encrypt_aes(key, mode, data)
    else:
        raise ValueError("krb5_encrypt: Encryption type %d is not implemented!" % etype)

def krb5_decrypt(key, mode, data):

    etype = key[0]
    if etype == ETYPE_ARCFOUR_HMAC_MD5:
        return __krb5_decrypt_arc4(key, mode, data)
    elif etype == ETYPE_AES128_CTS_HMAC_SHA1_96:
        return __krb5_decrypt_aes(key, mode, data)
    elif etype == ETYPE_AES256_CTS_HMAC_SHA1_96:
        return __krb5_decrypt_aes(key, mode, data)
    else:
        raise ValueError("krb5_decrypt: Decryption type %d is not implemented!" % etype)


###
# (Un)packing API.
###

def endian_str(little_endian=True):
    if little_endian:
        return '<'
    else:
        return '>'

# Unpacking

def extract_u8(data, index):
    try:
        b = struct.unpack('<B', data[index:index+1])[0]
        index += 1
        return b
    except Exception as e:
        logging.error("kerberos.helper: extract_u8() failed: %s" % str(e))
        raise ValueError()

def extract_u16(data, index, little_endian=True):
    try:
        s = struct.unpack(endian_str(little_endian)+'H', data[index:index+2])[0]
        index += 2
        return s
    except Exception as e:
        logging.error("kerberos.helper: extract_u16() failed: %s" % str(e))
        raise ValueError()

def extract_u32(data, index, little_endian=True):
    try:
        i = struct.unpack(endian_str(little_endian)+'L', data[index:index+4])[0]
        index += 4
        return i
    except Exception as e:
        logging.error("kerberos.helper: extract_u32() failed: %s" % str(e))
        raise ValueError()

def extract_u64(data, index, little_endian=True):
    try:
        i = struct.unpack(endian_str(little_endian)+'Q', data[index:index+8])[0]
        index += 8
        return i
    except Exception as e:
        logging.error("kerberos.helper: extract_u64() failed: %s" % str(e))
        raise ValueError()

def extract_bytes(data, index, nbr_bytes):
    try:
        s = data[index:index+nbr_bytes]
        index += nbr_bytes
        return s
    except Exception as e:
        logging.error("kerberos.helper: extract_bytes(%d) failed: %s" % (nbr_bytes,str(e)))
        raise ValueError()

# Packing

def pack_u8(data):
    try:
        out = struct.pack('<B', data)
        return out
    except Exception as e:
        logging.error("kerberos.helper: pack_u8() failed: %s" % str(e))
        raise ValueError()

def pack_u16(data, little_endian=True):
    try:
        out = struct.pack(endian_str(little_endian)+'H', data)
        return out
    except Exception as e:
        logging.error("kerberos.helper: pack_u16() failed: %s" % str(e))
        raise ValueError()

def pack_u32(data, little_endian=True):
    try:
        out = struct.pack(endian_str(little_endian)+'L', data)
        return out
    except Exception as e:
        logging.error("kerberos.helper: pack_u32() failed: %s" % str(e))
        raise ValueError()

def pack_u64(data, little_endian=True):
    try:
        out = struct.pack(endian_str(little_endian)+'Q', data)
        return out
    except Exception as e:
        logging.error("kerberos.helper: pack_u64() failed: %s" % str(e))
        raise ValueError()

def pack_bytes(data):
        out = data
        return out
