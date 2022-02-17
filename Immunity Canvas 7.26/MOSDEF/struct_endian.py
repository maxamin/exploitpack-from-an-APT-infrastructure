#! /usr/bin/env python

import struct

class struct_endian:
    """
    a struct.struct hook with endian facilities
    """
    
    __default_endian = 'little'
    __endian_list = ['big', 'little']
    __endian_fmt  = {'big': ">", 'little': "<"}
    __endian_rfmt  = {'>': "big", '<': "little"}
    
    def __init__(self, endian = None):
        if endian not in self.__endian_list:
            endian = self.__default_endian
        self.set_endian(endian)
    
    def __repr__(self):
        return "<struct_endian instance in %s endian>" % self._endian.upper()
    
    def __fmt(self, fmt):
        if fmt[0] not in '@=<>!':
            fmt = self.__endian_fmt[self._endian] + fmt
        return fmt
    
    def set_endian(self, endian):
        if endian in self.__endian_rfmt.keys():
            endian = self.__endian_rfmt[endian]
        self._endian = endian
    
    def get_endian(self):
        return self._endian
    
    def switch_endian(self):
        self._endian = self.__endian_list[(self.__endian_list.index(self._endian) + 1) % 2]
    
    def pack(self, fmt, *args):
        return struct.pack(self.__fmt(fmt), *args)
    
    def unpack(self, fmt, *args):
        return struct.unpack(self.__fmt(fmt), *args)
    
    def calcsize(self, fmt, *args):
        return struct.calcsize(self.__fmt(fmt), *args)


__struct_endian_little = struct_endian('little')
__struct_endian_big    = struct_endian('big')

little_pack   = __struct_endian_little.pack
little_unpack = __struct_endian_little.unpack
big_pack   = __struct_endian_big.pack
big_unpack = __struct_endian_big.unpack

