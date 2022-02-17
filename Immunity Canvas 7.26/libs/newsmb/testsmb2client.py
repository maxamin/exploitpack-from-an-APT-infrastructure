#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  testsmb2client.py
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
if '.' not in sys.path:
    sys.path.append('.')
    
import socket
import libs.newsmb.libsmb2 as libsmb2
from libs.newsmb.smbconst import *

sockaddr = ('10.0.0.1', 445)
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect(sockaddr)

smb = libsmb2.SMB2Client(s, username='jojo1', password='foobar1234!', domain='immu5.lab')
smb.negotiate()
smb.session_setup()
smb.tree_connect('IPC$')
fid = smb.create('browser', GENERIC_READ|GENERIC_WRITE, 0, FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN, 0x00400040)
if fid:
    smb.close(fid)
smb.tree_disconnect()
smb.logoff()
s.close()
