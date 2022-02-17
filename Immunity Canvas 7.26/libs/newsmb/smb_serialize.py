from serialize import SerializationContext

class SMB_SerializationContext(SerializationContext):
    def __init__(self, offset=0, unicode_strings=True, oem_codepage='latin1'):
        super(SMB_SerializationContext, self).__init__(offset)

        self.connection      = None
        self.unicode_strings = unicode_strings
        self.oem_codepage    = oem_codepage
        self.header          = None
        self.parameters      = None
        self.data            = None
