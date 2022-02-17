#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  smbclient.py
## Description:
##            :
## Created_On :  Mon Jul 12 14:17:04 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Thu Apr 12 11:31:36 CEST 2018
## Modified_By:  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import logging
import socket
import cStringIO

if '.' not in sys.path:
    sys.path.append('.')

import libs.newsmb.libsmb as libsmb
from libs.newsmb.libsmb import GetHostnameUsingSMB

USER='administrator'
PWD='foobar123!'
DOMAIN='immu5.lab'
TARGET='10.0.0.1'

test_vectors = [ { 'description': 'SMB+NTLM', 'use_kerberos': False, 'kerberos_db': None },
                 { 'description': 'SMB+KRB', 'use_kerberos': False, 'kerberos_db': None },
                 { 'description': 'SMB+KRB', 'use_kerberos': False, 'kerberos_db': None }
               ]

def do_test(test_nr):

    sockaddr = (TARGET, 445)
    s = socket.socket()
    s.connect(sockaddr)
    u = USER
    p = PWD
    d = DOMAIN
    smb = libsmb.SMBClient(s, u, p, d)
    smb.is_unicode = True
    #smb.max_smbfrag = 1
    smb.negotiate()
    if not test_vectors[test_nr]['use_kerberos']:
        smb.session_setup(use_krb5=False)
    else:
        smb.session_setup(kerberos_db=test_vectors[test_nr]['kerberos_db'], use_krb5=True)

    smb.tree_connect(u'C$')
    target_host = GetHostnameUsingSMB(TARGET)

    print "[+] Listing files on %s (%s)" % (TARGET, '.'.join([target_host,DOMAIN]).upper())
    files = smb.dir(u'\\*')
    for f in files:
        print "\t -> %s" % f['FileName']

    smb.tree_disconnect()
    smb.logoff()

if __name__ == "__main__":

    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    for i in xrange(3):
        print '[+] Test %d: %s' % (i, test_vectors[i]['description'])
        do_test(i)
