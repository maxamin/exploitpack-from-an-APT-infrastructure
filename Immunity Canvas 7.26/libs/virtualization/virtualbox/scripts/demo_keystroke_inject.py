#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  demo_keystroke_injection.py
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

single = {
    'Esc'   : 0x01,
    'Tab'   : 0x0f,
    '['     : 0x1a,
    ']'     : 0x1b,
    'Enter' : 0x1c,
    'LCtrl' : 0x1d,
    'LShift': 0x2a,
    '\\'    : 0x2b,
    'LAlt'    : 0x38,
    'SpaceBar': 0x39,
    'F1' : 0x3b, 'F2' : 0x3c, 'F3': 0x3d,
    'F4' : 0x3e, 'F5' : 0x3f, 'F6': 0x40,
    'F7' : 0x41, 'F8' : 0x42, 'F9': 0x43,
    'F10': 0x44, 'Del': 0x53,
    'q': 0x10, 'w': 0x11, 'e' : 0x12,
    'r': 0x13, 't': 0x14, 'y' : 0x15,
    'u': 0x16, 'i': 0x17, 'o' : 0x18,
    'p': 0x19, 'a': 0x1e, 's' : 0x1f,
    'd': 0x20, 'f': 0x21, 'g' : 0x22,
    'h': 0x23, 'j': 0x24, 'k' : 0x25,
    'l': 0x26, ';': 0x27, '\'': 0x28,
    'z': 0x2c, 'x': 0x2d, 'c' : 0x2e,
    'v': 0x2f, 'b': 0x30, 'n' : 0x31,
    'm': 0x32, ',': 0x33, '.' : 0x34,
    '/': 0x35, '-': 0x0c, '=' : 0x0d,
    '`': 0x29,
    '1': 0x02, '2': 0x03, '3': 0x04,
    '4': 0x05, '5': 0x06, '6': 0x07,
    '7': 0x08, '8': 0x09, '9': 0x0a,
    '0': 0x0b,
}

double = {
    '!' : 0x02,
    '@' : 0x03,
    '#' : 0x04,
    '$' : 0x05,
    '%' : 0x06,
    '^' : 0x07,
    '&' : 0x08,
    '*' : 0x09,
    '(' : 0x0a,
    ')' : 0x0b,
    '_' : 0x0c,
    '+' : 0x0d,
    '{' : 0x1a,
    '}' : 0x1b,
    ':' : 0x27,
    '"' : 0x28,
    '~' : 0x29,
    '|' : 0x2b,
    '<' : 0x33,
    '>' : 0x34,
    '?' : 0x35,
}

def prepare_ascii_string(s):
    L1 = list(s)
    L2 = []

    for elt in L1:

        if elt == '\n':
            code = single['Enter']
            L2.append(code)
            L2.append(code|0x80)

        elif elt == '\t':
            code = single['Tab']
            L2.append(code)
            L2.append(code|0x80)

        elif elt == ' ':
            code = single['SpaceBar']
            L2.append(code)
            L2.append(code|0x80)

        elif single.has_key(elt):
            code = single[elt]
            L2.append(code)
            L2.append(code|0x80)

        elif ord(elt) >= ord('A') and ord(elt) <= ord('Z'):
            code = single[elt.lower()]
            L2.append(0x2a)
            L2.append(code)
            L2.append(code|0x80)
            L2.append(0xaa)

        # We need to use the shift
        elif double.has_key(elt):
            code = double[elt]
            L2.append(0x2a)
            L2.append(code)
            L2.append(code|0x80)
            L2.append(0xaa)

        else:
            logging.error("[-] Unhandled code: %.2x" % ord(elt))
            continue

    return L2

def infect_test(target_iid_str):

    scancodes = []
    scancodes.append(prepare_ascii_string('echo \"test\"\n'))
    return vboxmanage.vboxmanage_controlvm_keyboardputscancode(target_iid_str, scancodes_array=scancodes)

if __name__ == "__main__":

    logger = logging.getLogger()
    logger.setLevel(logging.INFO)

    if len(sys.argv) < 2:
        logging.error('Usage: %s IID' % sys.argv[0])
        sys.exit(1)

    if len(sys.argv) > 2:
        if sys.argv[2] == 'verbose':
            logger.setLevel(logging.DEBUG)

    ret = infect_test(sys.argv[1])
    if not ret:
        logging.info('Success!')
    else:
        logging.info('Failed! [err:%x]' % ret)
