#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  smbserver.py
## Description:
##            :
## Created_On :  Thu Oct 21 12:19:40 2010
## Created_By :  Chris
## Modified_On:  Thu Apr 12 14:17:57 CEST 2018
## Modified_By:  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import logging
import socket as sock

if "." not in sys.path:
    sys.path.append('.')

import libs.newsmb.libsmb as libsmb

SHARES = {u'LALA' : u'/tmp/lala', 'IPC$':None}

if __name__ == '__main__':

    if len(sys.argv) > 1 and sys.argv[1] == '-v':
        logger = logging.getLogger()
        logger.setLevel(logging.DEBUG)

    try:
        s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
        s.setsockopt(sock.SOL_SOCKET, sock.SO_REUSEADDR, 1)
        server = libsmb.SMBServer(s)
        for k,v in SHARES.items():
            server.add_share(k, v)

        server.listen()
        while server.accept() == True:
            pass
    except Exception, ex:
        import traceback
        traceback.print_exc()
        server.shutdown()
