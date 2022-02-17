#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  libwincreds.py
## Description:
##            :
## Created_On :  Fri Jun 29 CEST 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

'''
Notes
-----

- Most of the code is inspired from https://github.com/moyix/creddump
- Some password derivation function are implemented thanks to the excellent
  Openwall's documentation at https://openwall.info/wiki/john
'''

import os
import sys
import struct
import logging
import binascii

if "." not in sys.path:
    sys.path.append(".")

try:
    from Crypto.Hash import MD4
    from Crypto.Hash import MD5
    from Crypto.Hash import SHA256
    from Crypto.Hash import HMAC
    from Crypto.Hash import SHA
    from Crypto.Cipher import ARC4
    from Crypto.Cipher import DES
    from Crypto.Cipher import AES
    from Crypto.Protocol.KDF import PBKDF2
except ImportError:
    logging.error("Cannot import Crypto (required)")
    raise

MSCASH2_DEFAULT_ITER=10240

# Permutation matrix necessary to unscramble the syskey
p = [ 0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3,
      0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7 ]

# Constants used
ascii_str = "!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
numeric_str = "0123456789012345678901234567890123456789\0"

odd_parity = [
    1, 1, 2, 2, 4, 4, 7, 7, 8, 8, 11, 11, 13, 13, 14, 14,
    16, 16, 19, 19, 21, 21, 22, 22, 25, 25, 26, 26, 28, 28, 31, 31,
    32, 32, 35, 35, 37, 37, 38, 38, 41, 41, 42, 42, 44, 44, 47, 47,
    49, 49, 50, 50, 52, 52, 55, 55, 56, 56, 59, 59, 61, 61, 62, 62,
    64, 64, 67, 67, 69, 69, 70, 70, 73, 73, 74, 74, 76, 76, 79, 79,
    81, 81, 82, 82, 84, 84, 87, 87, 88, 88, 91, 91, 93, 93, 94, 94,
    97, 97, 98, 98,100,100,103,103,104,104,107,107,109,109,110,110,
    112,112,115,115,117,117,118,118,121,121,122,122,124,124,127,127,
    128,128,131,131,133,133,134,134,137,137,138,138,140,140,143,143,
    145,145,146,146,148,148,151,151,152,152,155,155,157,157,158,158,
    161,161,162,162,164,164,167,167,168,168,171,171,173,173,174,174,
    176,176,179,179,181,181,182,182,185,185,186,186,188,188,191,191,
    193,193,194,194,196,196,199,199,200,200,203,203,205,205,206,206,
    208,208,211,211,213,213,214,214,217,217,218,218,220,220,223,223,
    224,224,227,227,229,229,230,230,233,233,234,234,236,236,239,239,
    241,241,242,242,244,244,247,247,248,248,251,251,253,253,254,254
]

###
# Small functions
###

def str_to_key(s):
    '''
    NOTE: From creddump.py https://github.com/moyix/creddump
    '''

    key = []
    key.append( ord(s[0])>>1 )
    key.append( ((ord(s[0])&0x01)<<6) | (ord(s[1])>>2) )
    key.append( ((ord(s[1])&0x03)<<5) | (ord(s[2])>>3) )
    key.append( ((ord(s[2])&0x07)<<4) | (ord(s[3])>>4) )
    key.append( ((ord(s[3])&0x0F)<<3) | (ord(s[4])>>5) )
    key.append( ((ord(s[4])&0x1F)<<2) | (ord(s[5])>>6) )
    key.append( ((ord(s[5])&0x3F)<<1) | (ord(s[6])>>7) )
    key.append( ord(s[6])&0x7F )
    for i in range(8):
        key[i] = (key[i]<<1)
        key[i] = odd_parity[key[i]]
    return "".join(chr(k) for k in key)


def rid_to_key(rid):

    s1 = struct.pack('<L', rid)
    s1 += s1[:3]

    s2 = s1[3] + s1[:3]
    s2 += s2[:3]

    return str_to_key(s1), str_to_key(s2)

###
# API - Password derivations algorithms used in Windows
###

def ComputeLM(password=''):
    """
    Compute the LM hash of a password.
    """

    data = 'KGS!@#$%'
    password = password.upper()
    if len(password) > 14:
        password = password[:14]
    elif len(password) < 14:
        password += '\0' * (14-len(password))

    p1 = password[:7]
    p2 = password[7:]
    d1 = DES.new(str_to_key(p1), DES.MODE_ECB)
    d2 = DES.new(str_to_key(p2), DES.MODE_ECB)
    return d1.encrypt(data) + d2.encrypt(data)

def ComputeNTLM(password=''):
    """
    Compute the NTLM hash of a password.
    """
    digest = MD4.new(password.encode('utf-16le')).digest()
    return digest

def ComputeMSCash1(password, user='Administrator'):
    """
    Compute the MSCashv1 hash of the password. The username is used as a salt.
    https://openwall.info/wiki/john/MSCash
    Note: For Windows XP/2003 and below
    """
    h1 = ComputeNTLM(password)
    return MD4.new(h1 + user.lower().encode('utf-16-le')).digest()

def ComputeMSCash2(password, user='Administrator', iterations=MSCASH2_DEFAULT_ITER):
    """
    Compute the MSCashv2 hash of the password. The username is used as a salt.
    https://openwall.info/wiki/john/MSCash2
    Note: For Windows 7/2008 and after
    """

    # The number of iterations is always a multiple of 1024
    # http://blog.gentilkiwi.com/tag/nliterationcount

    if iterations > MSCASH2_DEFAULT_ITER:
        iterations &= (~0x3ff)

    elif iterations < MSCASH2_DEFAULT_ITER:
        iterations <<= 10

    dcc_hash = ComputeMSCash1(password, user)
    return PBKDF2(password=dcc_hash,
                  salt=user.lower().encode('utf-16-le'),
                  dkLen=16,
                  count=iterations,
                  prf=lambda p,s: HMAC.new(p,s,SHA).digest())

###
# API - Credential extraction API
###

def ExtractSysKey(JD, Skew1, GBG, Data):
    '''
    The 4 parameters are each 'Class' content (of 'Classlength' length) of the keys
    "HKLM\SYSTEM\$CONTROLSET\Control\Lsa\$NAME" where:
        - $NAME is 'JD', 'Skew1', 'GBG' or 'Data'
        - $CONTROLSET is the 'ControlSet' selected. The suffix is read in the
          value "HKLM\SYSTEM\SELECT\Current"
    This functions returns the permuted concatenation of these 4 parameters.
    '''

    scrambled_syskey = JD + Skew1 + GBG + Data
    if len(scrambled_syskey) != 16:
        logging.error('Incorrect values as we can\'t be using more than 16 bytes')
        return None

    syskey = ''.join([ scrambled_syskey[p[i]] for i in xrange(len(scrambled_syskey)) ])
    return syskey


def DecryptHashFromSamDomainAccount(syskey, rid, F, V, password_type='NT'):
    '''
    syskey:  must be returned by ExtractSysKey()
    rid:     the RID of the user (e.g. 500 for Administrator)
    F:       the value of "SAM\Domains\Account\F" (user independant)
    V:       the value of "SAM\Domains\Account\$RID\V" (user dependant)

    Returns the encrypted hash ('NT' or 'LM') for a specific user (rid)
    '''

    # First let's check the parameters
    if len(syskey) != 16:
        logging.error('Invalid parameters: syskey must be 16 bytes long.')
        return (-1, None)

    if password_type not in ['NT', 'LM']:
        logging.error('Invalid parameters: password_type must either be NT or LM.')
        return (-2, None)

    if len(F) < 0xa0:
        logging.error('Invalid parameters: F is not long enough.')
        return (-3, None)

    # We need to extract two pieces
    f1 = F[0x70:0x80]
    f2 = F[0x80:0xA0]

    # Depending on the type of password required, let's compute some parameters
    if password_type == 'LM':
        password_str = "LMPASSWORD\0"
    else:
        password_str = "NTPASSWORD\0"

    rc4_key = MD5.new(f1 + ascii_str + syskey + numeric_str).digest()
    bootkey = ARC4.new(rc4_key).encrypt(f2)

    '''
    Open 'SAM\Domains\Account\Users'
    For each 'SAM\Domains\Account\Users\$RID  (ie $RID != 'Names')
        do
            + READ V[0xa0] if it is 20 then READ offset = V[0x9c:0xa0] (4 bytes)
                                          + READ ENC_LM = V[offset+4:offset+20]  (16 bytes)
            + READ V[0xac] if it is 20 then READ offset (if necessary) and
                   EITHER
                    READ ENC_NTLM = V[offset+24:offset+24+16] IF there is an LM stored
                   OR
                    READ ENC_NTLM = V[offset+8:offset+8+16]   IF there is no LM stored
        done
    '''

    try:
        LMisAvailable = (V[0xa0] == '\x14')
        NTisAvailable = (V[0xac] == '\x14')
        hash_offset = struct.unpack("<L", V[0x9c:0xa0])[0] + 0xCC
    except:
        logging.error('V buffer is too short to be valid.')
        return (-4, None)

    logging.debug('LMisAvailable = %s, NTisAvailable = %s' % (LMisAvailable,NTisAvailable))
    if not LMisAvailable and not NTisAvailable:
        logging.debug('No hash to extract within this buffer.')
        return (0, '')

    if password_type == 'NT':

        if not NTisAvailable:
            logging.debug('No NT hash to extract within this buffer.')
            return (0, '')

        if LMisAvailable:
            hash_offset += 24
        else:
            hash_offset += 8

    else:

        if not LMisAvailable:
            logging.debug('No LM hash to extract within this buffer.')
            return (0, '')

        hash_offset += 8

    # Extract the encrypted hash.
    encrypted_hash = V[hash_offset:hash_offset+16].encode('hex')
    logging.debug('Encrypted hash is %s' % encrypted_hash)

    #Perform the final decryption of the hash
    (des_k1,des_k2) = rid_to_key(rid)
    d1 = DES.new(des_k1, DES.MODE_ECB)
    d2 = DES.new(des_k2, DES.MODE_ECB)

    md5 = MD5.new()
    md5.update(bootkey[:0x10] + struct.pack("<L",rid) + password_str)
    rc4_key = md5.digest()

    rc4 = ARC4.new(rc4_key)
    obfkey = rc4.encrypt(encrypted_hash.decode('hex'))
    h = d1.decrypt(obfkey[:8]) + d2.decrypt(obfkey[8:])
    return (0, h)


def DecryptPolSecretEncryptionKey(encrypted_polsecretkey, syskey):
    """
    Decrypt the encrypted version of polsecretkey stored within:
    HKLM\\Security\\Policy\\PolSecretEncryptionKey.

    Note: Only usable for Windows XP and below. Windows 7 and above are not
    using the same obfuscation.

    Implementation based on CSecrets::DecryptPrimaryKey from:
    https://www.passcape.com/index.php?section=docsys&cmd=details&id=23
    """

    md5 = MD5.new()

    # Checking the syskey size
    if len(syskey) < 16:
        logging.error('The syskey must have a size of at least 16 bytes.')
        return (-1, None)

    # Checking the encrypted_polsecretkey size
    if len(encrypted_polsecretkey) < 76:
        logging.error('The encrypted_polsecretkey must be at least 76 bytes long.')
        return (-2, None)

    d1 = encrypted_polsecretkey[60:60+16]
    d2 = encrypted_polsecretkey[12:60]

    md5.update(syskey[:16])
    for i in range(1000):
        md5.update(d1)

    K = md5.digest()
    rc4 = ARC4.new(K)
    return rc4.decrypt(d2)[16:32]


def DecryptPolSecret(secret, key):
    """
    Decrypt each PolSecret using the key provided.
    The key must absolutely have a length of 16 bytes.
    """

    # First of all, do we have a 16 bytes key?
    if len(key) != 16:
        logging.error('Incorrect key size: %d (!= 16)' % len(key))
        return ''

    # Preparing the encrypted blocks
    enc_blocks = [ secret[8*i:8*i+8] for i in xrange(len(secret)/8) ]

    # Preparing the encryption keys
    i = 0
    enc_keys = []
    nr_missing_keys = len(enc_blocks) - len(enc_keys)
    while nr_missing_keys > 0:
        offset = 2*(i%2)
        tmp_keys = [ key[offset+7*j:offset+7*j+7] for j in xrange(2) ]
        enc_keys += tmp_keys
        nr_missing_keys -= len(tmp_keys)
        i += 1

    # Decrypting the blocks
    decrypted_blocks = ''
    for i in xrange(len(enc_blocks)):
        des = DES.new(str_to_key(enc_keys[i]), DES.MODE_ECB)
        decrypted_blocks += des.decrypt(enc_blocks[i])

    crypt_len, revision = struct.unpack('<LL', decrypted_blocks[:8])

    # Last sanity checks
    if revision != 1:
        logging.error('Incorrect revision: %d (expected 1)' % revision)
        return ''

    # Finally we remove the first chunk and the padding
    return decrypted_blocks[8:][:crypt_len]


def LsaEncryptDecrypt(data, key1, key2, nr_iter=1000):
    """
    Starting with Windows 7 and above, PolSecretEncryptionKey is not used anymore
    and instead keys are stored (encrypted) within PolEkList.

    The same function is used to decrypt PolEkList's only value and the secrets
    whereas on XP/2003 and before, both DecryptPolSecretEncryptionKey() and
    DecryptPolSecret() were used.
    """

    # Sanity check, likely to be useless though.
    if len(key2) != 32:
        logging.warn('LsaEncryptDecrypt(): key2 does not have 32 bytes, the function may fail to deliver a satisfying result.')

    h = SHA256.new()
    h.update(key1)
    for i in xrange(nr_iter):
        h.update(key2)
    sym_key = h.digest()

    cipher = AES.new(sym_key, AES.MODE_ECB)
    cleartext = ''
    for i in xrange(len(data)/16):
        what = data[16*i:16*i+16]
        # If the block is full of \0 we are dealing with an encrypted buffer anymore.
        # This happens with Secrets (not with PolEkList's value)
        if what == '\0'*16:
            break
        cleartext += cipher.decrypt(what)

    return cleartext


def DecryptMsCashV1(encrypted_data, lmkey, hmac_key):
    """
    Decrypts an MSCASHv1 entry (Windowx XP/2003 and before).
    """

    hm = HMAC.new(lmkey, hmac_key)
    dec_key = hm.digest()
    rc4 = ARC4.new(dec_key)
    return rc4.decrypt(encrypted_data)


def DecryptMsCashV2(encrypted_data, lmkey, iv):
    """
    Decrypts an MSCASHv2 entry (Windowx 7/2008 and above).
    """

    # Restricting lmkey to its first 16 bytes (=128 bits) forces the use of AES-128.
    aes = AES.new(lmkey[:16], AES.MODE_CBC, iv)

    if len(encrypted_data) % 16:
        # Some implementations fill with \0 if the length is not a multiple of 16
        # before decrypting it. However it does not make any real sense in a
        # decrypting context and should be considered suspicious.
        logging.warning('Attempting to decrypt data whose length is not multiple of 16!')

    decrypted_data = ''
    for i in xrange(len(encrypted_data)/16):
        decrypted_data += aes.decrypt(encrypted_data[16*i: 16*i+16])

    return decrypted_data


if __name__ == "__main__":

    pass
