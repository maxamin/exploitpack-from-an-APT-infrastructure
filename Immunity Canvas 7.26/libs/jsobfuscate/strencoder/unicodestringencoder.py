# Not working yet

from libs.jsobfuscate.strencoder.stringencoder import StringEncoder

class UnicodeStringEncoder(StringEncoder):

    def __init__(self):
        StringEncoder.__init__(self)
        self.name = "Unicode String Encoder"

        self._needQuotes = True


    def _doEncode(self, string):

        tmp = []
        bufsize = len(string)
        for c in range(0, len(string)):
            tmp.append("%%u00%02x" % (ord(string[c])))
        return "".join(tmp)


    def _doGetDecoderCode(self, srcVar, dstVar):

        code = """
            %s=unescape(%s);
        """ % (dstVar,srcVar)

        return code

