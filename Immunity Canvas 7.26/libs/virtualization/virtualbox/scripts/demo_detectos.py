#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_detectos.py
## Description:
##            :
## Created_On :  Mon Mar 11 2019
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
        logging.error('Usage: %s TARGET_IID' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 2:
        if sys.argv[2] in ['verbose','debug']:
            logger.setLevel(logging.DEBUG)

    target_iid = sys.argv[1]
    ret, os_version = vboxmanage.vboxmanage_debugvm_osdetect(target_iid)
    if not ret:
        logging.info('OS: %s' % os_version)
