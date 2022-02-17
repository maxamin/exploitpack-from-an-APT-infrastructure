from abc import ABCMeta, abstractmethod, abstractproperty
from error import *
from pprint import pformat

class DeserializationError(Exception):
    pass

class SerializationError(Exception):
    pass

class Serializable(object):
    __metaclass__ = ABCMeta

    @abstractmethod
    def serialize(self, context):
        pass

    @classmethod
    @abstractmethod
    def deserialize(self, data, context):
        pass

    @abstractmethod
    def size(self):
        pass

class SerializationContext(object):
    def __init__(self, obj=None, offset=0):
        self.self   = obj
        self.offset = offset

    def reset(self):
        self.self   = None
        self.offset = 0

class Array(Serializable):
    __metaclass__ = ABCMeta

    def __init__(self, objects, count=None):
        if not hasattr(self, 'type'):
            raise AbstractAttributeError(type(self), 'type')

        if not issubclass(self.type, Serializable):
            raise TypeConfusionError('type', self.type, Serializable)

        for o in objects:
            if not isinstance(o, self.type):
                raise TypeConfusionError(o, type(o), self.type)

        if count is not None:
            self._objects = list(objects)[:count]
        else:
            self._objects = list(objects)

    def __len__(self):
        return len(self._objects)

    def __str__(self):
        return "{}({})".format(type(self).__name__, pformat(self._objects))

    def size(self, context=None):
        return len(self.serialize(context))

    def serialize(self, context=None):
        if context is None:
            context = SerializationContext()

        if not isinstance(context, SerializationContext):
            raise(CanvasTypeError('context', type(context), SerializationContext))

        return ''.join(o.serialize(context) for o in self._objects)

    @classmethod
    def deserialize(cls, data, length, context=None):

        if not hasattr(cls, 'type'):
            raise AbstractAttributeError(cls, 'type')

        if not issubclass(Serializable, cls.type):
            raise TypeConfusionError('type', cls.type, Serializable)

        if context is None:
            context = SerializationContext()

        if not isinstance(context, SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        objects = []
        while length > 0:
            obj = self.type.deserialize(data, context)
            objects.append(obj)

        try:
            return cls(objects)
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

class UCHAR_Array(Serializable):
    def __init__(self, s):
        if isinstance(s, (int, long)):
            self._s = "\0" * s
        elif isinstance(s, str):
            self._s = s
        else:
            raise TypeError("'s' is not of type 'str' or 'int'")

    def __len__(self):
        return len(self._s)

    def __str__(self):
        return self._s.encode('hex')

    def size(self, context=None):
        return len(self.serialize(context))

    def serialize(self, context=None):
        if context is not None:
            context.offset += len(self._s)
        return self._s

    @classmethod
    def deserialize(cls, data, length, context=None):

        if context is not None and not isinstance(context, SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        try:
            obj = cls(data[:length])
            # ROD: That's a bug in ronald's code, the context.offset is also incremented elsewhere.
            #if context is not None:
            #    context.offset += length
            return obj
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)

class USHORT_Array(Serializable):
    def __init__(self, s):
        if isinstance(s, (int, long)):
            self._s = "\0\0" * s
        elif isinstance(s, str):
            if len(s) % 2 != 0:
                raise ValueError("'s' should contain multiple words, not bytes")

            self._s = s
        else:
            raise TypeError("'s' is not of type 'str' or 'int'")

    def __len__(self):
        return len(self._s) / 2

    def __str__(self):
        return self._s.encode('hex')

    def size(self, context=None):
        return len(self.serialize(context))

    def serialize(self, context=None):
        if context is not None:
            context.offset += len(self._s)
        return self._s

    @classmethod
    def deserialize(cls, data, length, context=None):

        if context is not None and not isinstance(context, SerializationContext):
            msg = "'context' is of type '{0}' instead of 'SerializationContext'"
            raise(DeserializationError(msg.format(type(context).__name__)))

        try:
            obj = cls(data[:length])
            # ROD: That's a bug in ronald's code, the context.offset is also incremented elsewhere.
            #if context is not None:
            #    context.offset += length
            return obj
        except:
            tb = traceback.format_exc()
            raise DeserializationError(tb)
