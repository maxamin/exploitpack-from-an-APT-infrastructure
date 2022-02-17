import traceback
from serialize import *
from smb_serialize import *
from smbconst import SMB_FLAGS2_UNICODE

class SMB_Array(Serializable):
    def __init__(self, s, unicode_strings=True, oem_codepage='latin1'):
        self._unicode_strings = unicode_strings
        self._oem_codepage    = oem_codepage

        # For the 'basestring' type in Python 2.x, we attempt to convert the
        # basestring string to the 'oem_codepage' provided in case we do not
        # have unicode strings.  Otherwise, we convert it to unicode.
        if isinstance(s, basestring):
            if unicode_strings:
                self._s = s.encode('utf-16-le', errors='strict')
            else:
                self._s = s.encode(oem_codepage, errors='strict')
        else:
            raise TypeError("Expected 'str' or 'unicode' type for 's'")

    def _verify_encoding(self, s, encoding):
        return s.decode(encoding).encode(encoding)

    def __len__(self):
        return len(unicode(self))

    def __str__(self):
        return self._s

    def __unicode__(self):
        if self._unicode_strings:
            return self._s.decode('utf-16-le')
        else:
            return self._s.decode(self._oem_codepage)

    @property
    def length(self):
        return len(self)

    def size(self, context=None):
        return len(self.serialize(context))

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

        if context.header is not None:
            unicode_strings = context.header['Flags2'] & SMB_FLAGS2_UNICODE
        else:
            unicode_strings = context.unicode_strings

        if unicode_strings and length % 2 != 0:
            raise DeserializationError("'data' should contain multiple words, not bytes")

        try:
            obj    = cls('', unicode_strings, context.oem_codepage)
            obj._s = data[:length]
            if unicode_strings:
                obj._verify_encoding(obj._s, 'utf-16-le')
            else:
                obj._verify_encoding(obj._s, context.oem_codepage)

            context.offset += length
            return obj
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

class SMB_String(SMB_Array):
    def serialize(self, context=None):
        if self._unicode_strings:
            data = super(SMB_String, self).serialize(context) + '\0\0'
            if context is not None:
                context.offset += 2
        else:
            data = super(SMB_String, self).serialize(context) + '\0'
            if context is not None:
                context.offset += 1

        return data

    @classmethod
    def deserialize(cls, data, context=None):
        if context is None:
            context = SMB_SerializationContext()

        #print "SMB_String.deserialize()", len(data), data.encode('hex')[:20]

        if not isinstance(context, SMB_SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SMB_SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        if context.header is not None:
            unicode_strings = context.header['Flags2'] & SMB_FLAGS2_UNICODE
        else:
            unicode_strings = context.unicode_strings

        # Base the length on the terminating 0-byte or 0-word.
        if unicode_strings:
            idx = data.find('\0\0')
            while idx != -1 and idx % 2 != 0:
                idx = data.find('\0\0', idx + 1)

            if idx == -1:
                """
                We might be in the bug context of Windows 2008 R2. In this case,
                for whatever reason, the server is ending the SMB_STRING with a
                null byte and not a short null.
                """
                idx = data.find('\0\0')
                if (idx != -1 and idx == len(data)-2):
                    idx += 1
                else:
                    raise DeserializationError("Expected '\\0\\0'-word in 'data'")

        else:
            idx = data.find('\0')
            if idx == -1:
                raise DeserializationError("Expected '\\0'-byte in 'data'")

        obj = super(SMB_String, cls).deserialize(data, idx, context)
        context.offset += 1 + int(unicode_strings)
        return obj

class SMB_StringPadFix(SMB_String):
    @classmethod
    def deserialize(cls, data, context=None):
        if not context.unicode_strings:
            return super(SMB_StringPadFix, cls).deserialize(data, context)

        # For unicode strings, we can have erronic input data that misses
        # a trailing 0-byte.  We compensate for this by adding one if we
        # fail to deserialize the string.
        try:
            return super(SMB_StringPadFix, cls).deserialize(data, context)
        except DeserializationError as e:
            if data[-1] != '\0' or len(data) % 2 == 0:
                raise

        # We've gotten an exception here, so we try again with an extra
        # 0-byte.
        data = data + '\0'
        obj  = super(SMB_StringPadFix, cls).deserialize(data, context)

        # We accounted for one byte that wasn't there, remove it.
        context.offset -= 1
        return obj

class SMB_Align(Serializable):
    def __init__(self, number):
        self._number = number
        self._pad    = None

    def __str__(self):
        if self._pad is None:
            return 'unknown'

        s = ("\\x" + c.encode('hex') for c in self._pad)
        return "'{}'".format("".join(s))

    def serialize(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        # This can happen if the object was deserialized.  We use the
        # bytes we got again, but do keep the offset in mind in case
        # it changed and we do not need padding.
        if self._pad is not None:
            pad = self._pad + "\0" * self._number
        else:
            pad = "\0" * self._number

        self._pad = pad[0:self.pad_count(context.offset)]

        context.offset += len(self._pad)
        return self._pad

    def size(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        # If we have a cached value (because this object has been either
        # serialized or deserialized), we use it here.
        if self._pad is not None:
            #print "RETURNING: ", len(self._pad)
            #context.offset += len(self._pad)
            return len(self._pad)

        pad = self.pad_count(context.offset)
        #context.offset += pad
        return pad

    def pad_count(self, offset):
        return (self._number - offset % self._number) % self._number

    @classmethod
    def deserialize(cls, data, context=None):
        #print "SMB_Align.deserialize(off=%d)" % (context.offset), data.encode('hex')[:20]
        if context is None:
            context = SMB_SerializationContext()

        obj      = cls(context.default._number)
        obj._pad = data[:obj.pad_count(context.offset)]

        return obj

class SMB_AlignTransParameters(Serializable):
    def __init__(self, number):
        self._number = number
        self._pad    = None

    def __str__(self):
        if self._pad is None:
            return 'unknown'

        s = ("\\x" + c.encode('hex') for c in self._pad)
        return "'{}'".format("".join(s))

    def serialize(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        # This can happen if the object was deserialized.  We use the
        # bytes we got again, but do keep the offset in mind in case
        # it changed and we do not need padding.
        if self._pad is not None:
            pad = self._pad + "\0" * self._number
        else:
            pad = "\0" * self._number

        self._pad = pad[0:self.pad_count(context.offset)]

        context.offset += len(self._pad)
        return self._pad

    def size(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        # If we have a cached value (because this object has been either
        # serialized or deserialized), we use it here.
        if self._pad is not None:
            #print "RETURNING: ", len(self._pad)
            return len(self._pad)

        pad = self.pad_count(context.offset)
        return pad

    def pad_count(self, ctx):
        return ctx.parameters['ParameterOffset'] - ctx.offset

    @classmethod
    def deserialize(cls, data, context=None):
        #print "SMB_AlignParameters.deserialize(off=%d)" % (context.offset), data.encode('hex')[:20]
        obj      = cls(context.default._number)
        obj._pad = data[:obj.pad_count(context)]
        return obj

class SMB_AlignTransData(SMB_AlignTransParameters):

    def pad_count(self, ctx):
        return ctx.parameters['DataOffset'] - ctx.offset

class SMB_AlignUnicode(SMB_Align):
    def __init__(self):
        super(SMB_AlignUnicode, self).__init__(2)

    def serialize(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if not context.unicode_strings:
            return ''

        return super(SMB_AlignUnicode, self).serialize(context)

    def size(self, context=None):
        if context is None:
            context = SMB_SerializationContext()

        if not context.unicode_strings:
            return 0

        return super(SMB_AlignUnicode, self).size(context)
