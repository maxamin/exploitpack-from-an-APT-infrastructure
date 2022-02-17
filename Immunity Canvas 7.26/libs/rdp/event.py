#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  event.py
## Description:
##            :
## Created_On :  Mon Sep  9 2019

## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import copy
import struct
import socket
import time

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct
from libs.rdp.rdpconst import *

class SlowPathInputEvent(Struct):
    """
    2.2.8.1.1.3.1.1 Slow-Path Input Event (TS_INPUT_EVENT)
    """
    st = [
        ['eventTime',         '<L', INPUT_EVENT_SYNC],
        ['messageType',       '<H', 0],
        ['slowPathInputData', '0s', ''],
    ]

    def __init__(self, message_type):
        Struct.__init__(self)
        self['messageType'] = message_type

    def __str__(self):
        return '[ SlowPathInputEvent: messageType=%x ]' % (self['messageType'])

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = Struct.serialize(self)
        return data

    def deserialize(self, data):
        try:
            self.unpack(data)
            self['slowPathInputData'] = data[self.calcsize():]
            return self
        except Exception as e:
            return None


class KeyboardEvent(SlowPathInputEvent):
    """
    2.2.8.1.1.3.1.1.1 Keyboard Event (TS_KEYBOARD_EVENT)
    """

    def __init__(self, flags, scancode):
        SlowPathInputEvent.__init__(self, INPUT_EVENT_SCANCODE)
        self.keyboardFlags = flags
        self.keyCode = scancode
        self.pad2Octets = 0

    def __str__(self):
        return '[ KeyboardEvent: keyboardFlags=%x, keyCode=%x ]' % (self.keyboardFlags, self.keyCode)

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = SlowPathInputEvent.serialize(self)
        data += struct.pack('<H', self.keyboardFlags)
        data += struct.pack('<H', self.keyCode)
        data += struct.pack('<H', self.pad2Octets)
        return data

    def deserialize(self, data):
        try:
            SlowPathInputEvent.deserialize(self, data)
            data = self['slowPathInputData']
            self.keyboardFlags = struct.unpack('<H', data[0:2])[0]
            self.keyCode = struct.unpack('<H', data[2:4])[0]
            return self
        except Exception as e:
            return None

class MouseEvent(SlowPathInputEvent):
    """
    2.2.8.1.1.3.1.1.3 Mouse Event (TS_POINTER_EVENT)
    """

    def __init__(self, flags, x=0, y=0):
        SlowPathInputEvent.__init__(self, INPUT_EVENT_MOUSE)
        self.pointerFlags = flags
        self.xPos = x
        self.yPos = y

    def __str__(self):
        return '[ MouseEvent: pointerFlags=%x, x=%x, y=%x ]' % (self.pointerFlags, self.xPos, self.yPos)

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = SlowPathInputEvent.serialize(self)
        data += struct.pack('<H', self.pointerFlags)
        data += struct.pack('<H', self.xPos)
        data += struct.pack('<H', self.yPos)
        return data

    def deserialize(self, data):
        try:
            SlowPathInputEvent.deserialize(self, data)
            data = self['slowPathInputData']
            self.pointerFlags = struct.unpack('<H', data[0:2])[0]
            self.xPos = struct.unpack('<H', data[2:4])[0]
            self.yPos = struct.unpack('<H', data[4:6])[0]
            return self
        except Exception as e:
            return None


class SynchronizeEvent(SlowPathInputEvent):
    """
    2.2.8.1.1.3.1.1.5 Synchronize Event (TS_SYNC_EVENT)
    """

    def __init__(self, flags):
        SlowPathInputEvent.__init__(self, INPUT_EVENT_SYNC)
        self.toggleFlags = flags
        self.pad2Octets = 0

    def __str__(self):
        return '[ SynchronizeEvent: toggleFlags=%x ]' % (self.toggleFlags)

    ###
    # (De)Serialization API
    ###

    def pack(self):
        data  = SlowPathInputEvent.serialize(self)
        data += struct.pack('<H', self.pad2Octets)
        data += struct.pack('<L', self.toggleFlags)
        return data

    def deserialize(self, data):
        try:
            SlowPathInputEvent.deserialize(self, data)
            data = self['slowPathInputData']
            self.pad2Octets = struct.unpack('<H', data[0:2])[0]
            self.toggleFlags = struct.unpack('<L', data[2:6])[0]
            return self
        except Exception as e:
            return None


if __name__ == "__main__":
    
    spie = SlowPathInputEvent(INPUT_EVENT_SYNC)
    d1 = spie.pack()
    print d1.encode('hex')
    
    ke = KeyboardEvent(0x4000, 0x1e)
    d2 = ke.pack()
    print d2.encode('hex')

    ke = KeyboardEvent(0,0).deserialize(d2)
    print ke
