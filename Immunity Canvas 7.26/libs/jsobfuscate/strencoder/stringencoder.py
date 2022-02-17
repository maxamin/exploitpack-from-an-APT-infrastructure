import sys
if '.' not in sys.path: sys.path.append('.')

from libs.jsobfuscate.namegenerator import RandomNameGenerator

class StringEncoder:
    
    def __init__(self):
        self.name = "String Encoder supperclass"
        self.nextEncoder = None

        # Text to encode
        self.cleanText=""

        self._varNameGen = RandomNameGenerator()

        self.dstVarName = ""

        self._needQuotes = False

    # Encodes a string and saves the encoded result on
    # a var with name dstVarName.
    # returns a script with this code
    # ej ret value: "myVar = '0x410x410x41'"
    def encode(self, buff):
        tmp = self._doEncode(buff)

        if self.nextEncoder:
            tmp = self.nextEncoder.encode(tmp)

        return tmp

    
    def getJavascriptCode(self):

        code = ""

        # Gen our random var names
        srcVarName = self._varNameGen.genRandomName()
        #dstVarName = self._varNameGen.genRandomName()

        # Encoded string code

        if self._getNeedQuotes():
            code += """
                %s = \"%s\";\n
            """ % (srcVarName,self.encode(self.cleanText))
        else:
            code += """
                %s = %s;\n
            """ % (srcVarName,self.encode(self.cleanText))

        code += self._getDecoderCode(srcVarName, self.dstVarName)

        return code


    # Returns the decoder javascript code, wich will get encoded data
    # from srcVar and store decoded data at dstVar
    # this call is recursive to all encoders setted
    def _getDecoderCode(self, srcVar, dstVar):

        code = ""

        # Append other decoder codes
        if self.nextEncoder:
            code += self.nextEncoder._getDecoderCode(srcVar, dstVar)

            # set the next source as destination
            code += "%s = %s;" % (srcVar, dstVar)

        code += self._doGetDecoderCode(srcVar, dstVar)

        return code

    # Returns the decoder code, wich will get the encoded
    # data from a variable called srcVarName
    def getDecoderCode(self, srcVarName, dstVarName):
        print "Not implemented"
    


    # Does the actual encoding
    def _doEncode(self,buf):
        print "Must be implemented by children classes"


    def _doGetDecoderCode(self, srcVar, dstVar):
        print "Not implemented"


    # Determines if the string returned by _doEncode needs
    # to be quoted in the js code
    def _getNeedQuotes(self):
        if self.nextEncoder:
            return self.nextEncoder._getNeedQuotes()
        else:
            return self._needQuotes
