#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  display_packet.py
## Description:
##            :
## Created_On :  Mon Feb 11 2019
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import os
import sys
import logging

if '.' not in sys.path:
    sys.path.append('.')

import libs.virtualization.virtualbox.libvboxmanage as vboxmanage
import libs.virtualization.virtualbox.rpc as vboxrpc
from libs.virtualization.virtualbox.ipc import ipcPayload

def display_packet(pkt):

    logging.debug(pkt)
    ipcobj = vboxmanage.ipc_unserialize(pkt.decode('hex'), context=None)
    print "%s" % (ipcobj)


if __name__ == "__main__":

    Log = logging.getLogger()
    Log.setLevel(logging.INFO)

    if len(sys.argv) < 2:
        logging.error('Usage: %s packet [verbose]' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 2 and sys.argv[2] == 'verbose':
        Log.setLevel(logging.DEBUG)

    try:
        display_packet(sys.argv[1])
    except Exception as e:
        logging.error('Err: %s' % str(e))
