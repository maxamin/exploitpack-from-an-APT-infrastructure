#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_copyto.py
## Description:
##            :
## Created_On :  Fri Mar 22 2019
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

if '.' not in sys.path:
    sys.path.append('.')

import libs.virtualization.virtualbox.libvboxmanage as vboxmanage

###
# Entry point - testing/debugging only
###

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if len(sys.argv) < 3:
        logging.error('Usage: %s IID src dst' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 4:
        if sys.argv[4] == 'verbose':
            logger.setLevel(logging.DEBUG)

    creds = {'user':'foo',
             'password': 'foo',
             'domain': ''
            }

    ret, x = vboxmanage.vboxmanage_guestcontrol_copyto(sys.argv[1], sys.argv[2], sys.argv[3], creds)
    print ret, x
