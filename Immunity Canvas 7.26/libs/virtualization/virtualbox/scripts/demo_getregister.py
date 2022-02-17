#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_getregister.py
## Description:
##            :
## Created_On :  Thu Mar  7 2019
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
    # Note: Since r7 is an invalid register this should produce an error!
    reg_names  = [ "rip", "rax", "rbx", "rcx", "rdx", "rsp", "rbp", "r7", "cs", "ds", "fs", "gs" ]
    ret, regs = vboxmanage.vboxmanage_debugvm_getregisters(target_iid, registers=reg_names)
    if not ret:
        for reg_name in reg_names:
            if regs.has_key(reg_name):
                logging.info('%s: %s' % (reg_name, regs[reg_name]))
