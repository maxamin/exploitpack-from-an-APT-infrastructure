#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  smbioctl.py
## Description:
##            :
## Created_On :  Thu Oct 28 09:58:55 2010
## Created_By :  Kostya Kortchinsky
## Modified_On:  Fri Oct 29 13:11:15 2010
## Modified_By:  Kostya Kortchinsky
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
###############################################################################

import sys
from struct import pack

if '.' not in sys.path:
    sys.path.append('.')

from libs.newsmb.smbconst import *
from libs.newsmb.libsmb import SMBClient

NT_TRANSACT_IOCTL = 0x0002

if __name__ == '__main__':
    from socket import socket
    #import cStringIO
    sockaddr = ('192.168.2.107', 445)
    s = socket()
    s.connect(sockaddr)
    u = u'kostya'
    p = u'basrules'
    smb = SMBClient(s, u, p)
    smb.is_unicode = True
    smb.negotiate()
    smb.session_setup()
    if False:
        smb.tree_connect(u'Empty')
        smb.nt_create(name = u'sourcefile.bin\0', desired_access=0x20089, share_access=0x5, disposition=0x1, options=0x200044)
        source_fid = smb.fid
        smb.nt_create(name = u'destinationfile.bin\0', desired_access=0x30197, share_access=0x0, disposition=0x5, options=0x44)
        destination_fid = smb.fid
        """
        status, data = smb.nt_ioctl(0x140078, source_fid, True, '')
        print 'ResumeKey=%s, LeakedData=%s'%(data[:24].encode('hex'),data[-4:].encode('hex'))
        """
        for i in range(0,0x2000):
            data = pack('<L', i) + ('\0' * 20) #24 byte CopychunkResumeKey
            data += pack('<LL', 1, 0) #ChunkCount, Reserved
            data += pack('<QQLL', 0, 0, 0x400, 0) #SourceOffset, DestinationOffset, CopyLength, Reserved
            data = smb.nt_ioctl(0x1440f2, destination_fid, True, data)
            if data is not None:
                data = data.encode('hex')
                print '%08x: %s'%(i, data)
                break
        """
        for i in range(0x90000,0x14f000,4):
            status, data = smb.nt_ioctl(i, source_fid, False, 'A' * 0x800)
            if status != 0xc0000010 and status != 0xc00000bb:
                print '%6x'%(i)
        """
    else:
        smb.tree_connect(u'IPC$')
        smb.get_dfs_referral()
