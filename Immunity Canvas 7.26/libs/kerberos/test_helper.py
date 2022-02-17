#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_helper.py
## Description:
##            :
## Created_On :  Mon Dec  8 22:49:19 PST 2014
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
import hashlib
import logging

if "." not in sys.path:
    sys.path.append(".")

import helper

##
# CRC32 tests.
# The CRC used in the kerberos API is defined here:
# http://www.ietf.org/rfc/rfc3961.txt
##

def test_CRC():

    ret = True

    crc1 = "33bc3273".decode('hex')
    crc2 = helper.__krb5_compute_crc("foo")
    if crc1 != crc2:
        logging.error("CRC(\'foo\') failed.")
        ret = False

    crc1 = "d6883eb8".decode('hex')
    crc2 = helper.__krb5_compute_crc("test0123456789")
    if crc1 != crc2:
        logging.error("CRC(\'test0123456789\') failed.")
        ret = False

    crc1 = "f78041e3".decode('hex')
    crc2 = helper.__krb5_compute_crc("MASSACHVSETTS INSTITVTE OF TECHNOLOGY")
    if crc1 != crc2:
        logging.error("CRC(\'MASSACHVSETTS INSTITVTE OF TECHNOLOGY') failed.")
        ret = False

    return ret

##
# PBKDF2 tests (SHA-1)
# This primitive is python based and we rely a lot on it
##

def test_PBKDF2():

    ret = True

    # AES-128
    h1 = hashlib.pbkdf2_hmac('sha1', 'password', "ATHENA.MIT.EDUraeburn", 1200, dklen=16)
    h2 = "5c08eb61fdf71e4e4ec3cf6ba1f5512b".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'password\') failed.")
        ret = False

    h1 = hashlib.pbkdf2_hmac('sha1', "X"*64, "pass phrase equals block size", 1200, dklen=16)
    h2 = "139c30c0966bc32ba55fdbf212530ac9".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'XXX...\') failed.")
        ret = False

    h1 = hashlib.pbkdf2_hmac('sha1', "X"*65, "pass phrase exceeds block size", 1200, dklen=16)
    h2 = "9ccad6d468770cd51b10e6a68721be61".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'XXX...\') failed.")
        ret = False

    # AES-256
    h1 = hashlib.pbkdf2_hmac('sha1', 'password', "ATHENA.MIT.EDUraeburn", 1200, dklen=32)
    h2 = "5c08eb61fdf71e4e4ec3cf6ba1f5512ba7e52ddbc5e5142f708a31e2e62b1e13".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'password\') failed.")
        ret = False

    h1 = hashlib.pbkdf2_hmac('sha1', "X"*64, "pass phrase equals block size", 1200, dklen=32)
    h2 = "139c30c0966bc32ba55fdbf212530ac9c5ec59f1a452f5cc9ad940fea0598ed1".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'XXX...\') failed.")
        ret = False

    h1 = hashlib.pbkdf2_hmac('sha1', "X"*65, "pass phrase exceeds block size", 1200, dklen=32)
    h2 = "9ccad6d468770cd51b10e6a68721be611a8b4d282601db3b36be9246915ec82a".decode('hex')
    if h1 != h2:
        logging.error("pbkdf2(SHA1, \'XXX...\') failed.")
        ret = False

    return ret

###
# n_fold primitive is absolutely mandatory
# https://tools.ietf.org/html/rfc3961#appendix-A
#
# Note: Since it's such a sensitive (=prone to bugs) primitive to write, we go
# through all the testvectors.
###

def test_NFOLD():

    ret = True

    h1 = helper.__krb5_nfold("012345", 64/8)
    h2 = "be072631276b1955".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'012345\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("password", 56/8)
    h2 = "78a07b6caf85fa".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'password\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("Rough Consensus, and Running Code", 64/8)
    h2 = "bb6ed30870b7f0e0".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'Rough Consensus, and Running Code\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("password", 168/8)
    h2 = "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'password\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("MASSACHVSETTS INSTITVTE OF TECHNOLOGY", 192/8)
    h2 = "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'MASSACHVSETTS INSTITVTE OF TECHNOLOGY\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("Q", 168/8)
    h2 = "518a54a215a8452a518a54a215a8452a518a54a215".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'Q\') failed.")
        ret = False

    h1 = helper.__krb5_nfold("ba", 168/8)
    h2 = "fb25d531ae8974499f52fd92ea9857c4ba24cf297e".decode('hex')
    if h1 != h2:
        logging.error("n_fold(\'ba\') failed.")
        ret = False

    return ret


##
# AES tests.
# All the AES based primitives used in Kerberos were created in this RFC:
# https://tools.ietf.org/html/rfc3962#appendix-B
##

def test_AES():

    ret = True

    # AES-128 krb5_string_to_key()

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES128_CTS_HMAC_SHA1_96, 'password', salt="ATHENA.MIT.EDUraeburn", nbr_iter=1200)
    h2 = "4c01cd46d632d01e6dbe230a01ed642a".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES128, \'password\') failed.")
        ret = False

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES128_CTS_HMAC_SHA1_96, 'X'*64, salt="pass phrase equals block size", nbr_iter=1200)
    h2 = "59d1bb789a828b1aa54ef9c2883f69ed".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES128, \'XXXX..(64)\') failed.")
        ret = False

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES128_CTS_HMAC_SHA1_96, 'X'*65, salt="pass phrase exceeds block size", nbr_iter=1200)
    h2 = "cb8005dc5f90179a7f02104c0018751d".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES128, \'XXXX..(65)\') failed.")
        ret = False

    # AES-256 krb5_string_to_key()

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES256_CTS_HMAC_SHA1_96, 'password', salt="ATHENA.MIT.EDUraeburn", nbr_iter=1200)
    h2 = "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES128, \'password\') failed.")
        ret = False

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES256_CTS_HMAC_SHA1_96, 'X'*64, salt="pass phrase equals block size", nbr_iter=1200)
    h2 = "89adee3608db8bc71f1bfbfe459486b05618b70cbae22092534e56c553ba4b34".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES128, \'XXXX..(64)\') failed.")
        ret = False

    h1 = helper.krb5_string_to_key(helper.ETYPE_AES256_CTS_HMAC_SHA1_96, "X"*65, salt="pass phrase exceeds block size", nbr_iter=1200)
    h2 = "d78c5c9cb872a8c9dad4697f0bb5b2d21496c82beb2caeda2112fceea057401b".decode('hex')
    if h1 != h2:
        logging.error("krb5_string_to_key(AES256, \'XXX..(65)\') failed.")
        ret = False

    # AES-128 CBC-CTS

    inkey = '636869636b656e207465726979616b69'.decode('hex')

    # Encrypt

    p1 = "4920776f756c64206c696b65207468652047656e6572616c2047617527732043".decode('hex')
    c1 = helper.__aes_encrypt_block(inkey, p1)
    c2 = '39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584'.decode('hex')
    if c1 != c2:
        logging.error("__aes_encrypt_block(\'(32 bytes)\') failed.")
        ret = False

    p2 = "4920776f756c64206c696b65207468652047656e6572616c20476175277320".decode('hex')
    c1 = helper.__aes_encrypt_block(inkey, p2)
    c2 = 'fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5'.decode('hex')
    if c1 != c2:
        logging.error("__aes_encrypt_block(\'(31 bytes)\') failed.")
        ret = False

    p3 = "4920776f756c64206c696b652074686520".decode('hex')
    c1 = helper.__aes_encrypt_block(inkey, p3)
    c2 = 'c6353568f2bf8cb4d8a580362da7ff7f97'.decode('hex')
    if c1 != c2:
        logging.error("__aes_encrypt_block(\'(17 bytes)\') failed.")
        ret = False

    p1 = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c".decode('hex')
    c1 = helper.__aes_encrypt_block(inkey, p1)
    c2 = "97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5".decode('hex')
    if c1 != c2:
        logging.error("__aes_encrypt_block(\'(47 bytes)\') failed.")
        ret = False

    # Decrypt

    c1 = '97687268d6ecccc0c07b25e25ecfe584b3fffd940c16a18c1b5549d2f838029e39312523a78662d5be7fcbcc98ebf5'.decode('hex')
    p1 = helper.__aes_decrypt_block(inkey, c1)
    p2 = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c".decode('hex')
    if p1 != p2:
        logging.error("__aes_decrypt_block(\'(47 bytes)\') failed.")
        ret = False

    c1 = '39312523a78662d5be7fcbcc98ebf5a897687268d6ecccc0c07b25e25ecfe584'.decode('hex')
    p1 = helper.__aes_decrypt_block(inkey, c1)
    p2 = "4920776f756c64206c696b65207468652047656e6572616c2047617527732043".decode('hex')
    if p1 != p2:
        logging.error("__aes_decrypt_block(\'(32 bytes)\') failed.")
        ret = False

    c1 = '97687268d6ecccc0c07b25e25ecfe58439312523a78662d5be7fcbcc98ebf5a84807efe836ee89a526730dbc2f7bc8409dad8bbb96c4cdc03bc103e1a194bbd8'.decode('hex')
    p1 = helper.__aes_decrypt_block(inkey, c1)
    p2 = "4920776f756c64206c696b65207468652047656e6572616c20476175277320436869636b656e2c20706c656173652c20616e6420776f6e746f6e20736f75702e".decode('hex')
    if p1 != p2:
        logging.error("__aes_decrypt_block(\'(128 bytes)\') failed.")
        ret = False

    c1 = 'fc00783e0efdb2c1d445d4c8eff7ed2297687268d6ecccc0c07b25e25ecfe5'.decode('hex')
    p1 = helper.__aes_decrypt_block(inkey, c1)
    p2 = "4920776f756c64206c696b65207468652047656e6572616c20476175277320".decode('hex')
    if p1 != p2:
        logging.error("__aes_decrypt_block(\'(31 bytes)\') failed.")
        ret = False

    return ret

def test_ARCFOUR_HMAC_MD5():

    ret = True

    # AP-REP - encrypted part
    data  = '1818972775e7b9d7d782e06736f7f776e20c595a7dfb7e9241b784e19a1bc5a9'
    data += '3b844b4bd99398d25427b236ea459605b77ee701dc789aa856f5bc0d6481f4ed'
    data += '96759c8c9472ba8d9ba4edec5c44466fbf057934a2e28ee153709b6989c6e771'
    data += 'f9c26edb76eabb8ab1060be5e788718ef66e154f18124db08c1f40a6ebb34506'
    data += '53624938834cfae22e90f4958e218a52ffe7378db5cf5d0b2a1011eee41a4119'
    data += '0fdd4b61b449ce3ecff7e04fd2f50640f4ead69932d05703700202370ec92e08'
    data += '70c56eb7b38af602c5160b698fb16c9f6af7c46ab1436e367f283b6e00f2c316'
    data += 'a28f3a5040024df39cfa72ccba1749ca40693c1fc290'

    mode = 8
    user_password = 'barbar1234!'
    inkey = helper.krb5_string_to_key(helper.ETYPE_ARCFOUR_HMAC_MD5, user_password)
    plaintext = helper.krb5_decrypt([helper.ETYPE_ARCFOUR_HMAC_MD5, inkey], mode, data.decode('hex'))

    if 'IMMU8.COM' not in plaintext.upper():
        logging.error("krb5_decrypt(\'ARC4\') failed.")
        ret = False

    return ret

def test_ETYPE_AES128_CTS_HMAC_SHA1_96():

    ret = True

    # AP-REP - encrypted part
    data  = '65dc8f31e8b9b0d03c8ddee424f4953d6d1bf0cb7da5e5ca8101aab3c541e09d'
    data += 'd15c48359d7c3f21d43e1e669d3564c8faaf62b65b10962cb68f92830884534c'
    data += '208395d8c9639ab77bde7dbe0ca1a281f86e082d39af13588bf4f7dfc115a2ce'
    data += 'c74aae357a71c62c368b333b2c34d42a650ec828011c8f2af5dd50a75007b17c'
    data += '4088b118d84dd442f1107b475946e6ed6dc5bb13156c2884782b6dff48421899'
    data += '55b9c0360582f4f36b7110da90413968ea6e60f00b6ef4bfdc6bbf4455c2bb77'
    data += 'a3aef34698efb1bbe704b84bd46233f7725f13d746d78cd6611be9cf7a5f1309'
    data += '9607d395acad8b3d07a25077446004ec91a92a51bf8672c038ef'

    mode = 3
    user_password = 'barbar1234!'
    salt = 'IMMU8.COMAdministrator'
    inkey = helper.krb5_string_to_key(helper.ETYPE_AES128_CTS_HMAC_SHA1_96, user_password, salt=salt)
    plaintext = helper.krb5_decrypt([helper.ETYPE_AES128_CTS_HMAC_SHA1_96, inkey], mode, data.decode('hex'))

    if 'IMMU8.COM' not in plaintext.upper():
        logging.error("krb5_decrypt(\'AES128\') failed.")
        ret = False

    return ret

def test_ETYPE_AES256_CTS_HMAC_SHA1_96():

    ret = True

    # AP-REP - encrypted part
    data  = '7be139219ddbb4c6ce9def67537fd03cc902f31bd045c3006b67e0eaea44fb92'
    data += 'a9b34a9fdcbcb84ffafe6607119712191815e3ab4721562716b8aac1074e7e86'
    data += '622ef8f55e8f2396304a0b555f6eb1c3122f9834bbc3475d338c0f00f74cfef7'
    data += '5924da081f5308bf1c257d50749a64d06331a325e5a071b50352bbef24917ec4'
    data += '6a5bba5f81cf207d93112e23d7e24ad6fb823690733c9ff1910401dffc8335a7'
    data += '2d5fa22e8e9a0f02dbde885b4e720d2f190ec99f328149eb0edfd659b211eb1a'
    data += '2a72c961374072591cd1e696a33706696576f998deb1d83189b7ef38063311e8'
    data += '76b64ab36860d51d6c4afc59ac2738808a6636b6c2ddeca484c632fd537af57d'
    data += 'eab7b68de815157e7483'

    mode = 3
    user_password = 'barbar1234!'
    salt = 'IMMU8.COMAdministrator'
    inkey = helper.krb5_string_to_key(helper.ETYPE_AES256_CTS_HMAC_SHA1_96, user_password, salt=salt)
    plaintext = helper.krb5_decrypt([helper.ETYPE_AES256_CTS_HMAC_SHA1_96, inkey], mode, data.decode('hex'))

    if 'IMMU8.COM' not in plaintext.upper():
        logging.error("krb5_decrypt(\'AES256\') failed.")
        ret = False

    # AP-REP - encrypted part (protected)
    data  = '42cb26dd664b327e942b62c5aeffe1ecd6d23e57de23456880dad922ca948f09'
    data += '844de4fa3120de542792f8c80352d1994e9a3d68aa050983c81351bc90012ceb'
    data += '93b8354890b174b756e592471ea643d1063356cca8f79e35dbe62c8a8dba2122'
    data += 'f93b9fa8398c48ce0c47f424cac7830fd744fe0698794eb5c693cdf86cceb36d'
    data += '01297dfef9a8ba8bf2a70f3de39f7faba21c0008a790b637bd305832dcdfa05b'
    data += '7d6bdad35c5c327896ee7cf08532baa9aa5985ea31be35ad5910cf37f08a8cb2'
    data += 'ade19bb22920f96c0a856222dc255759e94b5faf21f11fcb13efff324a1235be'
    data += '221f18750aa0cf711be766649d68a1b91ddb6dd37833973a280768bb6c2a97aa'
    data += 'e6aadd7bf752a12f255bf01614c7344b40c01441774000bbebc136075d49c79e'
    data += '2d0737ba8fce23cc0851ab1c17cf3bdbb1e4250657818d8f96cb2fc0c169bafc'
    data += '72b4fc12b58d73f0637b49031d18d446302a32f32619437fd4062a3dd7228c53'
    data += '8a10fe0b3570b06156e2ef849c05b12c2c64a199b802ae7d04c41c3bfe574ea2'
    data += 'b8ded6977b5f52c36e1ba21bce17f59d94a3076a88da66f44ace698af524fd68'
    data += '99cc3d25ac69e2465e101d7f4f5d6b322e9d2105a336b2d77c9ac3feb2e7fca6'
    data += 'dbf924e3b4a628adc9baf5122c8fbcecdca7f3e0f7e819cc5211ed9daba0f2f9'
    data += '72947cf21da892e7d591a05064d33be6f76450ad1b0ab11b3d2708bcff8ee9f9'
    data += 'ad5c7dd2ec2b2b94d7638ef46a2fc1fa434dfd144f2fca1d553e6a71291e01e7'
    data += '8488a5b593caa3f7ebc9aaa3bb28c7f7bdcf5811513084fe257613af0f91b5a1'
    data += 'eec0906656bf314ceea16aa617750d0dacc1333dda69f57af8cad899dc9351cd'
    data += '502d2d643736abb52748502332e64b5ca9bb788de6f94e3409361c6c5d220076'
    data += '2f9d0fb8431d3c766d390263ac8c57634f96c69b649a9c5352daae92b4b2b40b'
    data += 'cd4de79db17449fea3349cd4d7860d09e5081194b2345c6e6001222c6a3cb765'
    data += 'f108ddc3e32dad264044ad7a749f1251404645026ca48ab785afdbc1afb78c70'
    data += '89ef6776a8394f782b68ae3817763319c7c927c50fc021763cf7a680ecf7e56e'
    data += 'b359573eebf1f35d1a611fd7516db9e65aba9430ebb79b2752942c0a40406a99'
    data += '09f9f1187959cc2270bcc4c14aa629a380e3819f5e7fb9a4916a524c5805738a'
    data += '1cd7c450226dee36e332507a9016c50b08b1fc21ddaadd090997b39b72c48e96'
    data += '24eecab9f69818ef02fec1f128d6fcbd394afb565b0e236567607a4265f8a297'
    data += 'eda5d5d7785f9739506fc350aabb4e25d5bd9b52750291034fb1b6a80583faf0'
    data += '00da10b62be4b4adc16f94cf85cd2583210eb16ae75fac244f6589b8d541d8b0'
    data += '994a8ee08a2372f4c108a03fc44fc0157d11d7'

    key = [helper.ETYPE_AES256_CTS_HMAC_SHA1_96, '9f13be8a6a89a4d23c0008340ec660c9c40716f2a096782e4010ae18d87cddc7'.decode('hex')]
    mode = 2
    plaintext = helper.krb5_decrypt(key, mode, data.decode('hex'))

    if 'IMMU8.COM' not in plaintext.upper():
        logging.error("krb5_decrypt(\'AES256\') failed.")
        ret = False

    return ret


# Throwing the tests.

if __name__ == "__main__":

    logging.basicConfig(level=logging.INFO)

    status = True
    ret = test_NFOLD(); status &= ret
    ret = test_CRC(); status &= ret
    ret = test_PBKDF2(); status &= ret # AES
    ret = test_AES(); status &= ret
    ret = test_ARCFOUR_HMAC_MD5(); status &= ret
    ret = test_ETYPE_AES128_CTS_HMAC_SHA1_96(); status &= ret
    ret = test_ETYPE_AES256_CTS_HMAC_SHA1_96(); status &= ret

    if status:
        logging.info("Success!")

    sys.exit(status)
