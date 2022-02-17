import traceback
from serialize import *
from smb_serialize import *

class OEM_Array(Serializable):
    def __init__(self, s, oem_codepage='latin1'):
        self._oem_codepage = oem_codepage

        # For the 'str' and 'unicode' types in Python 2.x, we attempt to
        # convert the unicode string to the 'oem_codepage' provided.
        if isinstance(s, basestring):
            self._s = s.encode(oem_codepage, errors='strict')
        else:
            raise TypeError("Expected 'str' or 'unicode' type for 's'")

    def _verify_encoding(self, s, encoding):
        s.decode(encoding).encode(encoding)

    def __len__(self):
        return len(self._s)

    def __str__(self):
        return self._s

    def __repr__(self):
        s = "{}('{}', oem_codepage='{}')"
        return s.format(type(self).__name__, unicode(self), self._oem_codepage)

    def __unicode__(self):
        return self._s.decode(self._oem_codepage)

    @property
    def length(self):
        return len(self._s)

    def size(self, context=None):
        return len(self.serialize())

    def serialize(self, context=None):
        if context is not None:
            context.offset += len(self._s)

        return self._s

    @classmethod
    def deserialize(cls, data, length, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if not isinstance(context, SMB_SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SMB_SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        try:
            obj = cls('', context.oem_codepage)
            obj._s = data[:length]
            obj._verify_encoding(obj._s, context.oem_codepage)
            context.offset += length
            return obj
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

class OEM_String(OEM_Array):
    def __init__(self, s, oem_codepage='latin1', terminator='\0'):
        super(OEM_String, self).__init__(s, oem_codepage)
        self._terminator = terminator.encode(oem_codepage, 'strict')

    def serialize(self, context=None):
        data = super(OEM_String, self).serialize(context) + self._terminator
        if context is not None:
            context.offset += len(self._terminator)
        return data

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if not isinstance(context, SMB_SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SMB_SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        # Base the length on the terminating 0-byte or 0-word.
        idx = data.find('\0')
        if idx == -1:
            raise DeserializationError("Expected '\\0'-byte in 'data'")

        obj = super(OEM_String, cls).deserialize(data, idx, context)
        context.offset += 1
        return obj
