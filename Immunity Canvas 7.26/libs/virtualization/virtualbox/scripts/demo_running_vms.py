#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_running_vms.py
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

    if len(sys.argv) >= 2:
        logger = logging.getLogger()
        if sys.argv[1] == 'verbose':
            logger.setLevel(logging.DEBUG)

    ret, vms = vboxmanage.vboxmanage_list_runningvms()
    if not ret:
        for vm in vms:
            logging.info('\"%s\" {%s}' % (vm['name'], vm['iid']))
