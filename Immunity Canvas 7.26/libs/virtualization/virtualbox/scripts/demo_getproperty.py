#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_getproperty.py
## Description:
##            :
## Created_On :  Thu Feb  20 2019
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

    if len(sys.argv) < 2:
        logging.error('Usage: %s IID' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 2:
        if sys.argv[2] == 'verbose':
            logger.setLevel(logging.DEBUG)

    for name in [ '/VirtualBox/HostInfo/VBoxVerExt', '/VirtualBox/GuestInfo/OS/Product' ]:

        ret, value = vboxmanage.vboxmanage_guestproperty_get(sys.argv[1], name)
        if not ret:
            logging.info('%s: \"%s\"' % (name, value))
