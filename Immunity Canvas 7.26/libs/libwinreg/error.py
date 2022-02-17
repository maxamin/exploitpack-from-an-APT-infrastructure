class TypeConfusionError(TypeError):
    def __init__(self, name, name_type, expected_type):
        msg = "'{0}' is of type '{1}' instead of '{2}'"
        msg = msg.format(name, name_type.__name__, expected_type.__name__)
        super(TypeConfusionError, self).__init__(msg)

class AbstractAttributeError(TypeError):
    def __init__(self, cls, name):
        msg = "Can't instantiate abstract class '{0}' with abstract attribute '{1}'"
        msg = msg.format(cls.__name__, name)
        super(AbstractAttributeError, self).__init__(msg)
