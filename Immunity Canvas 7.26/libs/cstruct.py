#!/usr/bin/python

import struct
import yaml
from collections import OrderedDict
from abc import ABCMeta, abstractmethod, abstractproperty

class CStructLoader(object):
    def __init__(self, f, arch):
        self._file    = f
        self._arch    = arch
        self._yaml    = None
        self._version = None

    @property
    def arch(self):
        return self._arch

    @arch.setter
    def arch(self, value):
        self._arch = value

    @property
    def version(self):
        return self._version

    @version.setter
    def version(self, value):
        self._version = value

    def load(self, name, version=None):
        arch = self._arch

        if arch is None:
            raise ValueError("Architecture unspecified")

        if version is None:
            version = self._version
            if version is None: version = '*'

        if self._yaml is None:
            self._yaml = yaml.load(self._file)

        if name not in self._yaml:
            msg = "'{}' database has no structure '{}'"
            raise KeyError(msg.format(self._file.name, name))

        if 'arch' not in self._yaml[name]:
            msg = "'{}' database structure '{}' has no 'arch' key"
            raise KeyError(msg.format(self._file.name, name))

        if arch not in self._yaml[name]['arch']:
            msg = "'{}' database structure '{}' has no architecture '{}'"
            raise KeyError(msg.format(self._file.name, name, arch))

        if 'version' not in self._yaml[name]['arch'][arch]:
            msg = "'{}' database structure '{}' has no 'version' key"
            raise KeyError(msg.format(self._file.name, name))

        if version not in self._yaml[name]['arch'][arch]['version']:
            msg = "'{}' database structure '{}' arch '{}' has no version '{}'"
            raise KeyError(msg.format(self._file.name, name, arch, version))

        struct = self._yaml[name]['arch'][arch]['version'][version]
        return CStruct(name, arch, version, struct, self)

    @staticmethod
    def type_serialize(type, arch=None):
        if arch is None: arch = self._arch

        if arch is None:
            raise ValueError("Architecture unspecified")

        x86_64_map = {
            'char'              : 'b',    'signed char'     : 'b',
            'unsigned char'     : 'B',    'bool'            : '?',
            '_Bool'             : '?',    'short'           : '<h',
            'signed short'      : '<h',   'unsigned short'  : '<H',
            'int'               : '<i',   'signed int'      : '<i',
            'signed'            : '<i',   'unsigned int'    : '<I',
            'unsigned'          : '<I',   'long'            : '<q',
            'signed long'       : '<q',   'unsigned long'   : '<Q',
            'long long'         : '<q',   'signed long long': '<q',
            'unsigned long long': '<Q',   'float'           : '<f',
            'double'            : '<d',
            'uint8_t'           : 'B',    'uint16_t'        : '<H',
            'uint32_t'          : '<I',   'uint64_t'        : '<Q',
            'size_t'            : '<Q',
            # XXX: hack; support typedef later.
            'SHORT'             : '<h',
            'USHORT'            : '<H',
            'DWORD'             : '<I',
            'ULONG'             : '<I',
        }


        x86_map = {
            'char'              : 'b',    'signed char'     : 'b',
            'unsigned char'     : 'B',    'bool'            : '?',
            '_Bool'             : '?',    'short'           : '<h',
            'signed short'      : '<h',   'unsigned short'  : '<H',
            'int'               : '<i',   'signed int'      : '<i',
            'signed'            : '<i',   'unsigned int'    : '<I',
            'unsigned'          : '<I',   'long'            : '<i',
            'signed long'       : '<i',   'unsigned long'   : '<I',
            'float'             : '<f',
            'double'            : '<d',
            'uint8_t'           : 'B',    'uint16_t'        : '<H',
            'uint32_t'          : '<I',
            'size_t'            : '<I',
            # XXX: hack; support typedef later.
            'SHORT'             : '<h',
            'USHORT'            : '<H',
            'DWORD'             : '<I',
            'ULONG'             : '<I',
        }



        if arch == 'x86-64':
            if '*' in type:
                return '<Q'
            elif 'enum' in type:
                return '<i'

            if type in x86_64_map:
                return x86_64_map[type]

        elif arch == 'x86':
            if type in x86_map:
                return x86_map[type]

            if '*' in type:
                return '<I'
            elif 'enum' in type:
                return '<i'
        else:
            raise NotImplementedError("Unsupported architecture")


        raise NotImplementedError("Unsupported type '{}'".format(type))

class CStruct(object):
    def __init__(self, name, arch, version, struct, loader, bindings=None):
        if bindings is None: bindings = {}

        self._struct     = struct
        self._name       = name
        self._arch       = arch
        self._version    = version
        self._loader     = loader

        self._member_map = {}
        self._bindings   = bindings
        self._values     = {}
        self._raw_data   = None
        self._unbound    = set()

        for member in self.members:
            if 'name' not in member: continue
            self._member_map[member['name']] = member

        self._recalculate_sizes()
        self._recalculate_offsets()

    def _recalculate_sizes(self):
        for member in self.members:
            if 'type' not in member:
                continue

            type = member['type']
            if not self._is_struct(type):
                continue

            name = type.split()[1]
            try:
                nested = self._loader.load(name, self._bindings.get(name, '*'))
            except KeyError:
                self._unbound.add(name)
                continue

            member['size'] = nested.size

    def _recalculate_offsets(self):
        offset  = 0
        unbound = False
        for member in self.members:
            if 'offt' in member:
                member['offset'] = member['offt']
            else:
                member['offset'] = offset

            if member.get('name', None) in self._unbound:
                unbound = True
                offset  = member
            elif not unbound:
                offset += member['size']

    def items(self):
        for member in self.members:
            if 'name' not in member: continue
            yield (member['name'], self.get(member['name']))

    @property
    def bindings(self):
        return dict(self._bindings)

    @property
    def members(self):
        return self._struct['members']

    @property
    def size(self):
        if len(self._unbound) != 0:
            msg = "struct '{0}' has unbound members '{1}'"
            raise RuntimeError(msg.format(self._name, ", ".join(self._unbound)))

        if 'size' in self._struct:
            return self._struct['size']

        return sum(member['size'] for member in self.members)

    def _is_struct(self, type):
        return type.startswith('struct') and '*' not in type

    def bind(self, name, version):
        if name not in self._member_map:
            msg = "struct '{0}' has no member '{1}'"
            raise AttributeError(msg.format(self._name, name))

        member  = self._member_map[name]
        type    = member['type']

        if not self._is_struct(type):
            msg = "member '{}' is not a nested structure"
            raise AttributeError(msg.format(name))

        self._bindings[name] = version
        if name in self._unbound: self._unbound.remove(name)

        self._values = {}
        self._recalculate_sizes()
        self._recalculate_offsets()

    def __getitem__(self, name):
        return self.get(name)

    def __setitem__(self, name, value):
        self.set(name, value)

    def get(self, name):
        if name in self._values:
            return self._values[name]

        offset = self.offsetof(name)
        size   = self.sizeof(name)
        t      = self.typeof(name)

        # Nested structure, we need to load it.
        if self._is_struct(t):
            name = t.split()[1]
            return self._loader.load(name, self._bindings.get(name, '*'))

        # Special case empty/variable arrays and so on.
        if size == 0: return ""

        # Default to 0 if there is no deserialization data.
        if self._raw_data is None:
            return 0

        # Use raw deserialization data.
        fmt = CStructLoader.type_serialize(t, self._arch)
        return struct.unpack(fmt, self._raw_data[offset:offset+size])[0]

    def _nested_iter(self, name):
        cur      = self
        cur_name = self._name

        member_name_it = iter(name.split('.'))
        for member_name in member_name_it:
            if not isinstance(cur, CStruct):
                msg = "struct '{0}' is not a nested struct"
                raise TypeError(msg.format(cur_name))

            if member_name not in cur._member_map:
                msg = "struct '{0}' has no member '{1}'"
                raise KeyError(msg.format(cur._name, name))

            yield cur._member_map[member_name]

            if member_name in self._unbound:
                break

            if "." in name:
                cur       = cur.get(member_name)
                cur_name += "." + member_name

        if next(member_name_it, None) is not None:
            msg = "'{0}.{1}' is unbound"
            raise RuntimeError(msg.format(self._name, member_name))

    def set(self, name, value):
        # Get the deepest member of the nested iterator.
        # We currently don't care for the result -- this is for validation.
        for member in self._nested_iter(name):
            pass

        self._values[name] = value

    def __str__(self):
        s = "struct {} {{\n".format(self._name)
        for member in self.members:
            if 'name' not in member: continue
            s += '[0x{0:x}]'.format(member['offset'])
            s += "\t" + member['type'] + "\t" + member['name'] + ";\n"
        s += "}\n"

        return s

    def deserialize(self, data):
        if len(data) < self.size:
            msg = "'data' needs to be at least {0} bytes long"
            raise ValueError(msg.format(self.size))

        self._raw_data = data[:self.size]
        self._values   = {}

    def serialize(self):
        if len(self._unbound) != 0:
            msg = "struct '{0}' has unbound members"
            raise RuntimeError(msg.format(self._name))

        # Initialize a byte array from either raw deserialized data or with
        # default 0 bytes.
        if self._raw_data is not None:
            b = bytearray(self._raw_data)
        else:
            b = bytearray(self.size)

        # Create a view for in-place replacement.
        v = memoryview(b)

        # Enumerate over all member values, and replace them.
        for name, value in self._values.items():
            offset  = self.offsetof(name)
            size    = self.sizeof(name)
            t       = self.typeof(name)

            if size == 0: continue
            fmt = CStructLoader.type_serialize(t, self._arch)
            try:
                v[offset:offset+size] = struct.pack(fmt, value)
            except:
                pass
        return str(b)

    def offsetof(self, name):
        offset = 0
        for member in self._nested_iter(name):
            if isinstance(member['offset'], (int, long)):
                #
                # This is a small hack in order to allow creation of partial structs
                #
                if "offt" in member:
                    offset = member['offt']
                else:
                    offset += member['offset']
            else:
                msg = "'{0}.{1}' is unbound"
                raise RuntimeError(msg.format(self._name, member['offset']['name']))

        return offset

    def sizeof(self, name=None):
        if name is None:
            return self.size

        # Validate and find the target member of 'name'.
        member = None
        for member in self._nested_iter(name):
            pass

        return member['size']

    def typeof(self, name):
        # Validate and find the target member of 'name'.
        member = None
        for member in self._nested_iter(name):
            pass

        return member['type']

    def valueof(self, name):
        member = None
        for member in self._nested_iter(name):
            pass

        if 'value' in member:
            return member['value']

        return None

if __name__ == '__main__':
    import unittest

    class EternalblueStructTests(unittest.TestCase):
        def setUp(self):
            self._handle = file('eternalblue.yaml', 'r')
            self.loader  = CStructLoader(self._handle, "x86-64")

        def tearDown(self):
            self._handle.close()

        def test_LIST_ENTRY(self):
            list_entry = self.loader.load("LIST_ENTRY")

            # Size tests.
            self.assertEqual(list_entry.size, 16)
            self.assertEqual(list_entry.sizeof('Flink'), 8)
            self.assertEqual(list_entry.sizeof('Blink'), 8)

            # Offset tests.
            self.assertEqual(list_entry.offsetof('Flink'), 0)
            self.assertEqual(list_entry.offsetof('Blink'), 8)

        def test_NETBUFFER(self):
            srvnet_buffer = self.loader.load("NETBUFFER")

            self.assertEqual(srvnet_buffer.offsetof('Flags'), 16)
            self.assertEqual(srvnet_buffer.offsetof('list'),  32)
            self.assertEqual(srvnet_buffer.offsetof('pnetBuffer'), 48)
            self.assertEqual(srvnet_buffer.offsetof('pMdl1'), 64)
            self.assertEqual(srvnet_buffer.offsetof('nbssSize'), 80)
            self.assertEqual(srvnet_buffer.offsetof('pMdl2'), 96)
            self.assertEqual(srvnet_buffer.offsetof('pSrvNetWskStruct'), 0x58)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1'), 112)

            self.assertEqual(srvnet_buffer.offsetof('Mdl1.Next'), 112)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.Size'), 120)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.MdlFlags'), 122)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.Process'), 128)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.MappedSystemVa'), 136)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.StartVa'), 144)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.ByteCount'), 152)
            self.assertEqual(srvnet_buffer.offsetof('Mdl1.ByteOffset'), 156)
            self.assertEqual(srvnet_buffer.offsetof('Mdl2'), 160)

        def test_MDL(self):
            mdl = self.loader.load("MDL")

            self.assertEqual(mdl.size, 48)
            self.assertEqual(mdl.offsetof('Next'), 0)
            self.assertEqual(mdl.offsetof('Size'), 8)
            self.assertEqual(mdl.offsetof('MdlFlags'), 10)
            self.assertEqual(mdl.offsetof('Process'), 16)
            self.assertEqual(mdl.offsetof('MappedSystemVa'), 24)
            self.assertEqual(mdl.offsetof('StartVa'), 32)
            self.assertEqual(mdl.offsetof('ByteCount'), 40)
            self.assertEqual(mdl.offsetof('ByteOffset'), 44)

        def test_ERESOURCE(self):
            res = self.loader.load("ERESOURCE")

            self.assertEqual(res.offsetof('SystemResourcesList'), 0)
            self.assertEqual(res.offsetof('OwnerTable'), 16)
            self.assertEqual(res.offsetof('ActiveCount'), 24)
            self.assertEqual(res.offsetof('Flag'), 26)
            self.assertEqual(res.offsetof('SharedWaiters'), 32)
            self.assertEqual(res.offsetof('ExclusiveWaiters'), 40)
            self.assertEqual(res.offsetof('OwnerEntry'), 48)
            self.assertEqual(res.offsetof('ActiveEntries'), 64)
            self.assertEqual(res.offsetof('ContentionCount'), 68)
            self.assertEqual(res.offsetof('NumberOfSharedWaiters'), 72)
            self.assertEqual(res.offsetof('NumberOfExclusiveWaiters'), 76)
            self.assertEqual(res.offsetof('Reserved2'), 80)
            self.assertEqual(res.offsetof('Address'), 88)
            self.assertEqual(res.offsetof('SpinLock'), 96)

            self.assertEqual(res.size, 104)

        def test_NETCONNECTION(self):
            netconn = self.loader.load("NETCONNECTION")

            self.assertEqual(netconn.offsetof('List'), 160)
            self.assertEqual(netconn.offsetof('pPool'), 264)
            self.assertEqual(netconn.offsetof('isClosed'), 283)
            self.assertEqual(netconn.offsetof('isWskConnection'), 284)
            self.assertEqual(netconn.offsetof('pSrvNetEndpoint'), 352)
            self.assertEqual(netconn.offsetof('SpinLock'), 464)
            self.assertEqual(netconn.offsetof('ppFuncs'), 472)

    suite = unittest.TestLoader().loadTestsFromTestCase(EternalblueStructTests)
    unittest.TextTestRunner(verbosity=2).run(suite)
