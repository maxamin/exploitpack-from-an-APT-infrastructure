#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_spy2.py
## Description:
##            :
## Created_On :  Fri Feb 22 2019
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import struct
import socket
import logging
import time
import ptrace.debugger
import signal
import subprocess

if '.' not in sys.path:
    sys.path.append('.')

import libs.virtualization.virtualbox.libvboxmanage as vboxmanage

def main():

    if len(sys.argv) < 2:
        logging.error('Usage: %s TARGET_FILE' % sys.argv[0])
        sys.exit(1)

    try:
        f = open(sys.argv[1])
        packets = f.readlines()
        f.close()
    except:
        logging.error('Wrong file: %s' % sys.argv[1])
        sys.exit(1)

    for packet in packets:

        try:
            packet_obj = vboxmanage.ipc_unserialize(packet[:-1].decode('hex'))
            logging.info(packet_obj)
        except Exception as e:
            pass

 
if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    main()
