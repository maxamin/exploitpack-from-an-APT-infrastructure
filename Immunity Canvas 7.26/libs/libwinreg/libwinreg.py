#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  libwinreg.py
## Description:
##            :
## Created_On :  Wed Dec 12 2018
## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import struct
import logging
from struct import pack, unpack

if '.' not in sys.path:
    sys.path.append('.')

from libs.libwinreg.Struct import Struct

###
# Constants
###

LWR_BASEBLOCK_SIGNATURE   = 'regf'
LWR_BASEBLOCK_SIZE        = 4096
LWR_HIVEBIN_SIGNATURE     = 'hbin'
LWR_INDEXLEAF_SIGNATURE   = 'li'
LWR_FASTLEAF_SIGNATURE    = 'lf'
LWR_HASHLEAF_SIGNATURE    = 'lh'
LWR_KEYNODE_SIGNATURE     = 'nk'
LWR_KEYVALUE_SIGNATURE    = 'vk'
LWR_KEYSECURITY_SIGNATURE = 'sk'

###
# LIBWINREG Objects.
# No exception handling for these objects.
###

class BaseBlock(Struct):

    st = [
        ['Signature', '4s', LWR_BASEBLOCK_SIGNATURE ],
        ['PrimarySeqNumber', '<L', 0 ],
        ['SecondarySeqNumber', '<L', 0 ],
        ['LastWrittenTimestamp', '<Q', 0 ],
        ['MajorVersion', '<L', 0 ],
        ['MinorVersion', '<L', 0 ],
        ['FileType', '<L', 0 ],
        ['FileFormat', '<L', 0 ],
        ['RootCellOffset', '<L', 0 ],
        ['HiveBinsDataSize', '<L', 0 ],
        ['ClusteringFactor', '<L', 0 ],
        ['FileName', '64s', '\0'*64 ],
        ['Reserved1', '396s', '\0'*396 ],
        ['Checksum', '<L', 0 ],
        ['Reserved2', '3576s', '\0'*3576 ],
        ['BootType', '<L', 0 ],
        ['BootRecover', '<L', 0 ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

        # A parsing against an invalid stream does not make sense
        if self['Signature'] != LWR_BASEBLOCK_SIGNATURE:
            raise ValueError('Data provided is not a BaseBlock')

    def calcsize(self):
        return LWR_BASEBLOCK_SIZE

    def get_name(self):
        name = self['FileName'].decode("utf-16").encode("latin-1")
        if name[-1] == '\0':
            name = name[:-1]
        return name

    def get_rootcell_offset(self):
        return self['RootCellOffset']

    def get_version(self):
        return (self['MajorVersion'], self['MinorVersion'])

    def get_hivebins_datasize(self):
        return self['HiveBinsDataSize']

    def pack(self):
        data = Struct.pack(self)
        data += '\0' * (4096-Struct.calcsize())
        return data


class IndexLeaf(Struct):

    st = [
        ['Signature', '2s', LWR_INDEXLEAF_SIGNATURE ],
        ['NumberOfElements', '<H', 0 ],
        ['ListElements', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_INDEXLEAF_SIGNATURE:
                raise ValueError('IndexLeaf: Data provided is not a IndexLeaf')

            offset = 4
            if self['NumberOfElements'] and len(data[offset:]) < 4*self['NumberOfElements']:
                raise ValueError('IndexLeaf: Does not provide enough data')

            self['ListElements'] = []
            for i in xrange(self['NumberOfElements']):
                self['ListElements'].append({'offset':data[offset:offset+4]})
                offset += 4

    def __str__(self):
        s  = "IndexLeaf:\n"
        s += "    - NumberOfElements: %s\n" % self['NumberOfElements']
        return s

    def get_elements(self):
        return self['ListElements']

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def calcsize(self):
        return self['Size']

    def is_valid(self):
        return self['Signature'] == LWR_INDEXLEAF_SIGNATURE


class HashLeaf(Struct):

    st = [
        ['Signature', '2s', LWR_HASHLEAF_SIGNATURE ],
        ['NumberOfElements', '<H', 0 ],
        ['ListElements', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_HASHLEAF_SIGNATURE:
                raise ValueError('IndexLeaf: Data provided is not a IndexLeaf')

            offset = 4
            if self['NumberOfElements'] and len(data[offset:]) < 8*self['NumberOfElements']:
                raise ValueError('IndexLeaf: Does not provide enough data')

            self['ListElements'] = []
            for i in xrange(self['NumberOfElements']):
                self['ListElements'].append({'offset':struct.unpack('<L', data[offset:offset+4])[0],
                                             'hash':struct.unpack('<L', data[offset+4:offset+8])[0]})
                offset += 8

    def __str__(self):
        s  = "HashLeaf:\n"
        s += "    - NumberOfElements: %s\n" % self['NumberOfElements']
        return s

    def get_elements(self):
        return self['ListElements']

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def calcsize(self):
        return self['Size']

    def is_valid(self):
        return self['Signature'] == LWR_HASHLEAF_SIGNATURE

class FastLeaf(Struct):

    st = [
        ['Signature', '2s', LWR_FASTLEAF_SIGNATURE ],
        ['NumberOfElements', '<H', 0 ],
        ['ListElements', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_FASTLEAF_SIGNATURE:
                raise ValueError('FastLeaf: Data provided is not a FastLeaf')

            offset = 4
            if self['NumberOfElements'] and len(data[offset:]) < 8*self['NumberOfElements']:
                raise ValueError('FastLeaf: Does not provide enough data: %d vs %d' % (len(data[offset:]), 8*self['NumberOfElements']))

            self['ListElements'] = []
            for i in xrange(self['NumberOfElements']):
                key_node_offset = struct.unpack('<L', data[offset:offset+4])[0]
                name_hint = data[offset+4:offset+8].rstrip('\0')
                self['ListElements'].append({'offset':key_node_offset, 'hint':name_hint})
                offset += 8

    def get_elements(self):
        return self['ListElements']

    def __str__(self):
        s  = "FastLeaf:\n"
        s += "    - NumberOfElements: %s\n" % self['NumberOfElements']
        #s += "    - %s\n" % self['ListElements']
        return s

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def is_valid(self):
        return self['Signature'] == LWR_FASTLEAF_SIGNATURE


class KeyNode(Struct):

    st = [
        ['Signature', '2s', LWR_KEYNODE_SIGNATURE ],
        ['Flags', '<H', 0 ],
        ['LastWrittenTimestamp', '<Q', 0 ],
        ['AccessBits', '<L', 0 ],
        ['Parent', '<L', 0 ],
        ['NumberOfSubkeys', '<L', 0 ],
        ['NumberOfVolatileSubkeys', '<L', 0 ],
        ['SubkeysListOffset', '<L', 0 ],
        ['VolatileSubkeysListOffset', '<L', 0 ],
        ['NumberOfKeyValues', '<L', 0 ],
        ['KeyValuesListOffset', '<L', 0 ],
        ['KeySecurityOffset', '<L', 0 ],
        ['ClassNameOffset', '<L', 0 ],
        ['LargestSubkeyNameLength', '<L', 0 ],
        ['LargestSubkeyClassNameLength', '<L', 0 ],
        ['LargestValueNameLength', '<L', 0 ],
        ['LargestValueDataSize', '<L', 0 ],
        ['WorkVar', '<L', 0 ],
        ['KeyNameLength', '<H', 0 ],
        ['ClassNameLength', '<H', 0 ],
        ['KeyNameString', '0s', 0 ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_KEYNODE_SIGNATURE:
                raise ValueError('Data provided is not a KeyNode')

            offset = self.calcsize()
            if self['KeyNameLength']:
                self['KeyNameString'] = data[offset:offset+self['KeyNameLength']]

    def get_keyname(self):
        return self['KeyNameString']

    # Subkeys
    def get_number_of_subkeys(self):
        return self['NumberOfSubkeys']

    def get_subkeys_offset(self):
        return self['SubkeysListOffset']

    # Values
    def get_number_of_values(self):
        return self['NumberOfKeyValues']

    def get_values_offset(self):
        return self['KeyValuesListOffset']

    # Classes
    def get_class_offset(self):
        return self['ClassNameOffset']

    def get_class_size(self):
        return self['ClassNameLength']

    def __str__(self):
        s  = "KeyNode:\n"
        s += "    - Flags: %s\n" % self['Flags']
        s += "    - AccessBits: %s\n" % self['AccessBits']
        s += "    - Parent: %s\n" % self['Parent']
        s += "    - NumberOfSubkeys: %s\n" % self['NumberOfSubkeys']
        s += "    - NumberOfVolatileSubkeys: %s\n" % self['NumberOfVolatileSubkeys']
        s += "    - NumberOfKeyValues: %s\n" % self['NumberOfKeyValues']
        s += "    - KeyNameString: %s\n" % self['KeyNameString']
        return s

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def is_valid(self):
        return self['Signature'] == LWR_KEYNODE_SIGNATURE


class KeyValue(Struct):

    st = [
        ['Signature', '2s', LWR_KEYVALUE_SIGNATURE ],
        ['NameLength', '<H', 0 ],
        ['DataSize', '<L', 0 ],
        ['DataOffset', '<L', 0 ],
        ['DataType', '<L', 0 ],
        ['Flags', '<H', 0 ],
        ['Spare', '<H', 0 ],
        ['ValueNameString', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_KEYVALUE_SIGNATURE:
                raise ValueError('KeyValue: Data provided is not a KeyValue')

            offset = self.calcsize()
            if self['NameLength']:
                self['ValueNameString'] = data[offset:offset+self['NameLength']]

    def __str__(self):
        s  = "KeyValue:\n"
        s += "    - Name: %s\n" % self['ValueNameString']
        s += "    - DataType: %s\n" % self['DataType']
        s += "    - DataSize: %s\n" % self['DataSize']
        s += "    - DataOffset: %s\n" % self['DataOffset']
        s += "    - Flags: %s\n" % self['Flags']
        return s

    def get_data_offset(self):
        """
        Returns the data offset
        """
        return self['DataOffset']

    def get_data_size(self):
        """
        Returns the data size
        """
        return self['DataSize']

    def get_data_type(self):
        """
        Returns the data type (important for the RID).
        """
        return self['DataType']

    def get_name(self):
        """
        Returns the Value's name.
        """
        return self['ValueNameString']

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def is_valid(self):
        return self['Signature'] == LWR_KEYVALUE_SIGNATURE


class KeySecurity(Struct):

    st = [
        ['Signature', '2s', LWR_KEYSECURITY_SIGNATURE ],
        ['Reserved', '<H', 0 ],
        ['Flink', '<L', 0 ],
        ['Blink', '<L', 0 ],
        ['ReferenceCount', '<L', 0 ],
        ['SecurityDescriptorSize', '<L', 0 ],
        ['SecurityDescriptor', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:

            # A parsing against an invalid stream does not make sense
            if self['Signature'] != LWR_KEYSECURITY_SIGNATURE:
                raise ValueError('KeySecurity: Data provided is not a KeySecurity')

            offset = self.calcsize()
            if self['SecurityDescriptorSize']:
                self['SecurityDescriptor'] = data[offset:offset+self['SecurityDescriptorSize']]

    def __str__(self):
        s  = "KeySecurity:\n"
        s += "    - Flink: %s\n" % self['Flink']
        s += "    - Blink: %s\n" % self['Blink']
        s += "    - SecurityDescriptorSize: %s\n" % self['SecurityDescriptorSize']
        return s

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def is_valid(self):
        return self['Signature'] == LWR_KEYSECURITY_SIGNATURE

list_of_classes = [ IndexLeaf, HashLeaf, FastLeaf, KeyNode, KeyValue, KeySecurity ]

class Cell(Struct):

    st = [
        ['Size', '<L', 4 ],
        ['Data', '0s', '' ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)
        self.offset = 0

        if data is None:
            # TODO
            raise RuntimeError('Not implemented!')
        else:
            if self['Size'] > 0x80000000:
                self['Size'] = (-self['Size']) & 0xffffffff
            d = data[4:self['Size']]
            if d:
                for cls in list_of_classes:
                    try:
                        c = cls(data=d)
                    except Exception as e:
                        continue
                    if c.is_valid():
                        self['Data'] = c
                        break

            if not self['Data']:
                self['Data'] = d

    def __str__(self):
        if type(self['Data']) in list_of_classes:
            s  = " + [off=%s] %s\n"
            s %= (self.get_offset(),
                  str(self['Data']))

        else:
            s  = " + [off=%s] Data :\n"
            s += "    - Length: %s\n"
            s += "    - Content: %s\n\n"
            s %= (self.get_offset(),
                  len(self['Data']),
                  self['Data'].encode('hex'))
        return s

    def get_size(self):
        return self['Size']

    def get_data(self):
        return self['Data']

    def get_offset(self):
        return self.offset

    def set_offset(self, offset):
        self.offset = offset

    def pack(self):
        data =Struct.pack(self)
        if self['Data']:
            data += self['Data'].pack()
        return data

    def calcsize(self):
        return self['Size']


class HiveBinHeader(Struct):

    st = [
        ['Signature', '4s', LWR_HIVEBIN_SIGNATURE ],
        ['Offset', '<L', 0 ],
        ['Size', '<L', 0 ],
        ['Reserved', '<Q', 0 ],
        ['Timestamp', '<Q', 0 ],
        ['Spare', '<L', 0 ],
    ]

    def __init__(self, data=None):
        Struct.__init__(self, data)

    def __str__(self):
        s  = "---( Header\n\n"
        s += " + Offset: %d\n" % self['Offset']
        s += " + Size: %d\n" % self['Size']
        return s

    def pack(self):
        data =Struct.pack(self)
        return data

    def get_offset(self):
        return self['Offset']

    def get_size(self):
        return self['Size']

    def get_signature(self):
        return self['Signature']

class HiveBin(Struct):

    st = [
        ['Header', '0s', '' ],
        ['Cells', '0s', '' ],
    ]

    def __init__(self, data=None, hdr=None, cells=[]):
        Struct.__init__(self, data)

        if data is None:
            self['Header'] = hdr
            self['Cells'] = cells
        else:
            self['Header'] = HiveBinHeader(data=data)
            # There is no point in continuing the parsing if the header is incorrect.
            if not self['Header'] or not self.is_valid():
                return
            hdr_size = self['Header'].calcsize()
            offset = hdr_size

            self['Cells'] = []
            while 1:
                cell = Cell(data=data[offset:])
                cell.set_offset(offset)
                self['Cells'].append(cell)
                offset += cell.calcsize()
                if offset >= self['Header'].get_size():
                    break

    def get_cells(self):
        """
        Returns the number of cells within the Hive.
        """
        return self['Cells']

    def get_offset(self):
        """
        Returns the relative address of the data.
        """
        return self['Header'].get_offset()

    def get_size(self):
        """
        Returns the size of the Hive.
        """
        return self['Header'].get_size()

    def is_valid(self):
        return self['Header'].get_signature() == LWR_HIVEBIN_SIGNATURE

    def __str__(self):
        s  = "====== [ HiveBin ] ======\n\n"
        s += str(self['Header'])
        s += "\n---( Cells\n\n"
        s += " + Number of cells: %s\n\n" % len(self['Cells'])
        for cell in self['Cells']:
            s += str(cell)
        return s

    def pack(self):
        if not self['Header']:
            return ''
        data  = self['Header'].pack()
        for cell in self['Cells']:
            data += cell.pack()
        return data

###
# Main class. This is what should be used by underlying modules.
###

class WinRegParser:

    def __init__(self, fname):
        """
        Initialization of the class
        """

        self.fname = fname

        try:
            f = open(fname)
            self.data = f.read()
            f.close()
        except Exception as e:
            raise RuntimeError('Could not read file %s' % self.fname)

        self.basic_block = BaseBlock(data=self.data)
        if not self.basic_block:
            raise RuntimeError('BaseBlock() failed!')

        self.bins_length = self.basic_block.get_hivebins_datasize()
        self.rootcell_offset = self.basic_block.get_rootcell_offset()
        self.rootcell = None


    def find_hivebin_from_offset(self, offset):
        """
        Find the Hive for a specific offset.
        Note: This is mostly to find cells within that hbin.
        """

        bins_length = self.basic_block.get_hivebins_datasize()
        # Fast path (empirical)
        # ---------
        #
        # The binary format is fairly dumb. Indeed the size of the hbins is not
        # constant therefore there is no bijection between the offset and the
        # location of the hbin.
        # Empirically it seems that hbins have size multiple of PAGE_SIZE therefpre
        # we bf slightly the possible location of the hbin if the assumption is 
        # satisfied (which works practically speaking).

        if offset > 4096:

            off = self.basic_block.calcsize() + offset - offset%4096
            for i in xrange(256):

                hb = HiveBin(data=self.data[off:])
                if not hb.is_valid():
                    off -= 4096
                    continue

                if offset >= hb.get_offset() and offset < (hb.get_offset() + hb.get_size()):
                    return hb
                else:
                    break

        # Slow path (dump)
        # ---------
        #
        # We go from hbin to hbin based on the size until the offset is found.
        # It's basically a complete enumeration.
        # Pros:
        # - Cannot miss the hbin
        # - Fast enough for small .reg files (SAM, SECURITY)
        # Cons:
        # - Not practicall (several minutes) for a SYSTEM level size of .reg

        remaining_bytes = bins_length
        off = self.basic_block.calcsize()

        while 1:
            hb = HiveBin(data=self.data[off:])
            if offset >= hb.get_offset() and offset < (hb.get_offset() + hb.get_size()):
                return hb

            off += hb.get_size()
            remaining_bytes -= hb.get_size()

            if remaining_bytes == 0:
                break

        return None

    def find_cell_from_offset(self, offset):
        """
        Find the Cell for some specific offset.
        """

        hive_bin = self.find_hivebin_from_offset(offset)
        if not hive_bin:
            return None

        for cell in hive_bin.get_cells():
            if cell.get_offset() == (offset-hive_bin.get_offset()):
                return cell
        return None

    def get_rootcell(self):
        """
        Find the rootcell
        """

        if self.rootcell:
            return self.rootcell
        else:
            self.rootcell = self.find_cell_from_offset(self.rootcell_offset)
            return self.rootcell


    def get_subkeys(self, keynode):
        """
        For a given keynode, returns the list of subkeys (or sub-keynodes) as cells.
        """

        if type(keynode) != KeyNode:
            raise ValueError("get_subkeys() called with a non keynode object")

        subkeys_offset = keynode.get_subkeys_offset()

        cell_array = self.find_cell_from_offset(subkeys_offset)
        elts = cell_array.get_data().get_elements()
        cells = []
        for elt in elts:
            cell = self.find_cell_from_offset(elt['offset'])
            cells.append(cell)
        return cells

    def get_values(self, keynode):
        """
        For a given keynode, returns the list of subkeys (or sub-keynodes) as cells.
        """

        if type(keynode) != KeyNode:
            raise ValueError("get_values() called with a non keynode object")

        nr_values = keynode.get_number_of_values()

        values_offset = keynode.get_values_offset()
        cell_array = self.find_cell_from_offset(values_offset)

        d = cell_array.get_data()
        L = [ struct.unpack('<L', d[4*i:4*i+4])[0] for i in xrange(nr_values) ]
        return [ self.find_cell_from_offset(elt) for elt in L ]


    def get_keynode_by_name(self, name, parent=0):
        """
        Get a Key Node (directory) object based on the path.
        """

        if name == '\\':
            return self.get_rootcell()

        if name[0] == '\\':
            _name = name[1:]
        else:
            _name = name

        dir_list = _name.split('\\')
        current_parent_cell = self.get_rootcell()
        current_child_cell = None

        for directory in dir_list:

            found = 0
            subkeys = self.get_subkeys(current_parent_cell.get_data())
            for subkey in subkeys:
                if subkey.get_data().get_keyname() == directory:
                    found=1
                    current_child_cell = subkey
                    current_parent_cell = subkey
                    break

            if not found:
                return None

        return current_child_cell

    def get_keyvalue_by_name(self, parentnode, value_name):
        """
        Get a Key Node (directory) object based on the path.
        """

        vals = self.get_values(parentnode)
        for val in vals:
            if value_name == val.get_data().get_name():
                return val
        return None

    def get_rawdata_from_keyvalue(self, keyvalue):
        """
        Returns the data for a specific keyvalue as a string.
        Note: get_data_from_keyvalue returns it as (converted_obj, type)
        """

        data_offset = keyvalue.get_data_offset()
        data_size = keyvalue.get_data_size()

        in_offset = ((data_size & 0x80000000) == 0x80000000)
        data_size &= 0x7fffffff

        if in_offset:
            if data_size > 4:
                raise RuntimeError('get_rawdata_from_keyvalue(): error a negative offset with a size > 4')
            return struct.pack('<L', data_offset)[:data_size]
        else:
            cell = self.find_cell_from_offset(data_offset)
            return cell.get_data()[:data_size]

    def get_class_from_keynode(self, keynode):
        """
        Returns the class (which is data) for a specific keynode.
        """

        class_offset = keynode.get_class_offset()
        class_size = keynode.get_class_size()

        in_offset = ((class_size & 0x80000000) == 0x80000000)
        class_size &= 0x7fffffff

        if in_offset:
            if class_size > 4:
                raise RuntimeError('get_class_from_keynode(): error a negative offset with a size > 4')
            return struct.pack('<L', class_offset)[:class_size]
        else:
            cell = self.find_cell_from_offset(class_offset)
            return cell.get_data()[:class_size]


###
# This library is not meant to be used as a standalone file.
###


if __name__ == "__main__":

    pass
