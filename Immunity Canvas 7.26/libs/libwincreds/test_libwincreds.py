#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  test_libwincreds.py
## Description:
##            :
## Created_On :  Fri Jun 29 CEST 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import os
import sys
import struct
import logging
import binascii

if "." not in sys.path:
    sys.path.append(".")

import libs.libwincreds.libwincreds as libwincreds

password_list = [ 'foofoo123', 'foo', 'X!' ]
test_vectors = []

###
# First test vector: Windows 7 (x64) [ LM disabled ]
###

test_vector_win7 = {}
test_vector_win7['Name']  = 'Windows 7 (x64)'
test_vector_win7['JD']    = 'a202b774'.decode('hex')
test_vector_win7['Skew1'] = '9d7bde64'.decode('hex')
test_vector_win7['GBG']   = '5cca42df'.decode('hex')
test_vector_win7['Data']  = 'd6a1abcd'.decode('hex')

test_vector_win7['syskey'] = '5c7b9db7dfcaa174a2de02d6ab42cd64'.decode('hex')
test_vector_win7['Users'] = []

F = ''
F += '020001000000000020e461ac3e04ca01'
F += '3d000000000000000080a60affdeffff'
F += '00000000000000000000000000000080'
F += '00cc1dcffbffffff00cc1dcffbffffff'
F += '0000000000000000f003000000000000'
F += '00000000000000000100000003000000'
F += '01000000000001000100000038000000'
F += 'd57a7df0ede62fb88826b1073ed437ec'
F += 'c9e6f41002d1fde57dd16faf7939dcae'
F += '5586326e73ec8bf5322eeeda7c1feb59'
F += '00000000000000000100000038000000'
F += '70f0ea509276b59b87f3be23afa68822'
F += '3f3eedef9c4a28f08ffa8bc5e8809186'
F += 'f1f574559ea57c13dac5ce11554dcab9'
F += '00000000000000000300000000000000'
test_vector_win7['F'] = F.decode('hex')

V  = ''
V += '00000000bc00000002000100bc000000'
V += '1a00000000000000d800000000000000'
V += '00000000d80000006c00000000000000'
V += '44010000000000000000000044010000'
V += '00000000000000004401000000000000'
V += '00000000440100000000000000000000'
V += '44010000000000000000000044010000'
V += '00000000000000004401000000000000'
V += '000000004401000015000000a8000000'
V += '5c010000080000000100000064010000'
V += '04000000000000006801000014000000'
V += '000000007c0100000400000000000000'
V += '80010000040000000000000001001480'
V += '9c000000ac0000001400000044000000'
V += '020030000200000002c0140044000501'
V += '01010000000000010000000002c01400'
V += 'ffff1f00010100000000000507000000'
V += '0200580003000000000014005b030200'
V += '01010000000000010000000000001800'
V += 'ff070f00010200000000000520000000'
V += '20020000000024004400020001050000'
V += '0000000515000000774d4fa29da7cc2e'
V += '8789c0ecf40100000102000000000005'
V += '20000000200200000102000000000005'
V += '2000000020020000410064006d006900'
V += '6e006900730074007200610074006f00'
V += '720066004200750069006c0074002d00'
V += '69006e0020006100630063006f007500'
V += '6e007400200066006f00720020006100'
V += '64006d0069006e006900730074006500'
V += '720069006e0067002000740068006500'
V += '200063006f006d007000750074006500'
V += '72002f0064006f006d00610069006e00'
V += 'ffffffffffffffffffffffffffffffff'
V += 'ffffffffff0001000102000007000000'
V += '03000100030001003245a7755b74be86'
V += '004ef6a71826c71c0300010003000100'

user1 = {}
user1['name'] = 'Administrator'
user1['rid'] = 500
user1['v'] = V.decode('hex')
user1['h'] = '31d6cfe0d16ae931b73c59d7e0c089c0'.decode('hex')

V  = ''
V += '00000000bc00000002000100bc000000'
V += '0600000000000000c400000000000000'
V += '00000000c40000000000000000000000'
V += 'c40000000000000000000000c4000000'
V += '0000000000000000c400000000000000'
V += '00000000c40000000000000000000000'
V += 'c40000000000000000000000c4000000'
V += '0000000000000000c400000000000000'
V += '00000000c40000000000000000000000'
V += 'c40000000800000001000000cc000000'
V += '0400000000000000d000000014000000'
V += '00000000e40000000400000000000000'
V += 'e8000000040000000000000001001480'
V += '9c000000ac0000001400000044000000'
V += '020030000200000002c0140044000501'
V += '01010000000000010000000002c01400'
V += 'ff070f00010100000000000507000000'
V += '02005800030000000000240044000200'
V += '010500000000000515000000774d4fa2'
V += '9da7cc2e8789c0ece903000000001800'
V += 'ff070f00010200000000000520000000'
V += '20020000000014005b03020001010000'
V += '00000001000000000102000000000005'
V += '20000000200200000102000000000005'
V += '200000002002000066006f006f000000'
V += '01020000070000000300010003000100'
V += '94f6ff50f2b201dcb797d2303b0c8a3d'
V += '0300010003000100'

user2 = {}
user2['name'] = 'foo'
user2['rid'] = 1001
user2['v'] = V.decode('hex')
user2['h'] = 'ac8e657f83df82beea5d43bdaf7800cc'.decode('hex')

V  = ''
V += '00000000b000000002000100b0000000'
V += '0a00000000000000bc00000000000000'
V += '00000000bc0000007000000000000000'
V += '2c01000000000000000000002c010000'
V += '00000000000000002c01000000000000'
V += '000000002c0100000000000000000000'
V += '2c01000000000000000000002c010000'
V += '00000000000000002c01000000000000'
V += '000000002c0100000000000000000000'
V += '2c010000080000000100000034010000'
V += '04000000000000003801000004000000'
V += '000000003c0100000400000000000000'
V += '40010000040000000000000001001480'
V += '90000000a00000001400000044000000'
V += '020030000200000002c0140044000501'
V += '01010000000000010000000002c01400'
V += 'ffff1f00010100000000000507000000'
V += '02004c0003000000000014001b030200'
V += '01010000000000010000000000001800'
V += 'ff070f00010200000000000520000000'
V += '2002000000001800ff070f0001020000'
V += '00000005200000002402000001020000'
V += '00000005200000002002000001020000'
V += '00000005200000002002000047007500'
V += '65007300740000004200750069006c00'
V += '74002d0069006e002000610063006300'
V += '6f0075006e007400200066006f007200'
V += '20006700750065007300740020006100'
V += '63006300650073007300200074006f00'
V += '2000740068006500200063006f006d00'
V += '700075007400650072002f0064006f00'
V += '6d00610069006e000102000007000000'
V += '03000100030001000300010003000100'

user3 = {}
user3['name'] = 'Guest'
user3['rid'] = 501
user3['v'] = V.decode('hex')
user3['h'] = ''

V  = ''
V += '00000000d400000002000100d4000000'
V += '1c00000000000000f00000001c000000'
V += '000000000c0100006a00000000000000'
V += '78010000000000000000000078010000'
V += '00000000000000007801000000000000'
V += '00000000780100000000000000000000'
V += '78010000000000000000000078010000'
V += '00000000000000007801000000000000'
V += '00000000780100000000000000000000'
V += '78010000080000000100000080010000'
V += '04000000000000008401000014000000'
V += '00000000980100000400000000000000'
V += '9c010000040000000000000001001480'
V += 'b4000000c40000001400000044000000'
V += '020030000200000002c0140044000501'
V += '01010000000000010000000002c01400'
V += 'ffff1f00010100000000000507000000'
V += '0200700004000000000014005b030200'
V += '01010000000000010000000000001800'
V += 'ff070f00010200000000000520000000'
V += '2002000000001800ff070f0001020000'
V += '00000005200000002402000000002400'
V += '44000200010500000000000515000000'
V += '774d4fa29da7cc2e8789c0ecea030000'
V += '01020000000000052000000020020000'
V += '01020000000000052000000020020000'
V += '48006f006d006500470072006f007500'
V += '70005500730065007200240048006f00'
V += '6d006500470072006f00750070005500'
V += '73006500720024004200750069006c00'
V += '74002d0069006e002000610063006300'
V += '6f0075006e007400200066006f007200'
V += '200068006f006d006500670072006f00'
V += '75007000200061006300630065007300'
V += '7300200074006f002000740068006500'
V += '200063006f006d007000750074006500'
V += '72000000010200000700000003000100'
V += '03000100f7a7bb40b2b0f09c23fafb7f'
V += 'b5d5c4c50300010003000100'

user4 = {}
user4['name'] = 'HomeGroupUser$'
user4['rid'] = 1002
user4['v'] = V.decode('hex')
user4['h'] = 'fbf771d2c9a40e91e9f78412a8e7c962'.decode('hex')

test_vector_win7['Users'].append(user1)
test_vector_win7['Users'].append(user2)
test_vector_win7['Users'].append(user3)
test_vector_win7['Users'].append(user4)

###
# Add the testvectors
###

test_vectors.append(test_vector_win7)

###
# Second test vector: hashing algorithms
###

user_credentials0a = {}
user_credentials0a['username'] = 'Administrator'
user_credentials0a['ntlm'] = '275dff3d254899893bd1f6e94e6b14ff'
user_credentials0a['password'] = 'foobar123!'

user_credentials0b = {}
user_credentials0b['username'] = 'Administrator'
user_credentials0b['lm'] = 'aad3b435b51404eeaad3b435b51404ee'
user_credentials0b['ntlm'] = '31d6cfe0d16ae931b73c59d7e0c089c0'
user_credentials0b['password'] = ''

user_credentials1 = {}
user_credentials1['username'] = 'Administrator'
user_credentials1['ntlm'] = ''
user_credentials1['mscash1'] = '71957eddb7c527c9a7888bf654884a26'
user_credentials1['mscash2'] = '94d5ae2ff982d2c8ddf9b1f76fe33f6b'
user_credentials1['password'] = 'foobar123!'

user_credentials2 = {}
user_credentials2['username'] = 'jojo1'
user_credentials2['ntlm'] = ''
user_credentials2['mscash1'] = '6f59aef4c7d75ec6206ccea168e18073'
user_credentials2['mscash2'] = 'b39b7895d7f6aa39eb345e8deb8b1537'
user_credentials2['password'] = 'foobar123!'

user_credentials3 = {}
user_credentials3['username'] = 'jojo1'
user_credentials3['ntlm'] = ''
user_credentials3['mscash1'] = ''
user_credentials3['mscash2'] = '390fa9793b1699d85d27b604a6123e89'
user_credentials3['password'] = 'foobar123!'
user_credentials3['iter'] = 7

user_credentials4 = {}
user_credentials4['username'] = 'Administrator'
user_credentials4['ntlm'] = ''
user_credentials4['mscash1'] = ''
user_credentials4['mscash2'] = 'fb21b30fafd75ac8a8d55a77a96743a9'
user_credentials4['password'] = 'foobar123!'
user_credentials4['iter'] = 7

user_credentials5 = {}
user_credentials5['username'] = 'jojo1'
user_credentials5['ntlm'] = ''
user_credentials5['mscash1'] = ''
user_credentials5['mscash2'] = '3ee15edfc9188928ceee2e1c8ca22125'
user_credentials5['password'] = 'foobar123!'
user_credentials5['iter'] = 31000

user_credentials = [ user_credentials0a, user_credentials0b, user_credentials1, user_credentials2, user_credentials3, user_credentials4, user_credentials5 ]

###
# Perform the actual tests.
###


#'foofoo123'

def test_decryption():

    print "====== test_decryption ======"
    print 'Found %d testvectors' % len(test_vectors)
    for i in xrange(len(test_vectors)):
        test_vector = test_vectors[i]
        print 'Test #%d \'%s\'' % (i,test_vector['Name'])

        try:

            syskey = libwincreds.ExtractSysKey(test_vector['JD'],
                                 test_vector['Skew1'],
                                 test_vector['GBG'],
                                 test_vector['Data'])

            if syskey != test_vector['syskey']:
                print "\t=> syskey is incorrect (expected: %s, got %s)" % (test_vector['syskey'], syskey)
                return False
            else:
                print "\t=> syskey test: [OK]"

            for user in test_vector['Users']:

                ret, h = libwincreds.DecryptHashFromSamDomainAccount(syskey, user['rid'], test_vector['F'], user['v'], password_type='NT')
                if ret != 0:
                    print "\t=> NT hash decryption failed for user: %s [rid=%d]" % (user['name'],user['rid'])
                    return False

                if h != user['h']:
                    print "\t=> NT hash decryption failed for user: %s [rid=%d]" % (user['name'],user['rid'])
                    print "\t\t{expected: %s, got: %s}" % (user['h'].encode('hex'), h.encode('hex'))
                    return False

                print "\t=> NT hash decryption for user %s [rid=%d]: [OK]" % (user['name'],user['rid'])

            return True

        except Exception as e:
            print "Unexpected bug: %s" % (str(e))
            return False


def test_password():

    print "====== test_password ======"
    for p in password_list:
        h = libwincreds.ComputeNTLM(p)
        for user in test_vector_win7['Users']:
            if h == user['h']:
                print "Password match for user \'%s\': [OK]" % user['name']
                return True
    return False

def test_hash_functions():

    print "====== test_hash_functions ======"
    print 'Found %d testvectors' % len(user_credentials)

    for i in xrange(len(user_credentials)):

        creds = user_credentials[i]
        for key in [ 'lm', 'ntlm', 'mscash1', 'mscash2']:

            if creds.has_key(key) and creds[key]:

                valid_hash = creds[key].decode('hex')
                computed_hash = ''

                if key == 'lm':
                    computed_hash = libwincreds.ComputeLM(creds['password'])

                elif key == 'ntlm':
                    computed_hash = libwincreds.ComputeNTLM(creds['password'])

                elif key == 'mscash1':
                    computed_hash = libwincreds.ComputeMSCash1(creds['password'],
                                                               user=creds['username'])

                elif key == 'mscash2':
                    iterations = libwincreds.MSCASH2_DEFAULT_ITER
                    if creds.has_key('iter'):
                        iterations = creds['iter']
                    computed_hash = libwincreds.ComputeMSCash2(creds['password'],
                                                               user=creds['username'],
                                                               iterations=iterations)

                else:
                    print 'FATAL: Invalid hash type for user %s within the testcase: %s' % (creds['username'], key)
                    sys.exit(1)

                print "Test %d: %s hash for u/p = %s/%s" % (i,
                                                            key,
                                                            creds['username'],
                                                            creds['password'])

                if valid_hash != computed_hash:
                    print 'FATAL: Invalid %s hash for user %s according to testcase: %s != %s' % (key,
                                                                                                  creds['username'],
                                                                                                  computed_hash.encode('hex'),
                                                                                                  valid_hash.encode('hex'))
                    return False

    return True



if __name__ == "__main__":


    ret = test_hash_functions()
    if not ret:
        print "BUG DETECTED! Must be patched immediately."
        sys.exit(1)


    ret = test_decryption()
    if not ret:
        print "BUG DETECTED! Must be patched immediately."
        sys.exit(1)

    ret = test_password()
    if not ret:
        print "BUG DETECTED! Must be patched immediately."
        sys.exit(1)
