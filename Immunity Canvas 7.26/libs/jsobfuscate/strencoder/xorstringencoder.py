
from libs.jsobfuscate.strencoder.stringencoder import StringEncoder

class XORStringEncoder(StringEncoder):

    def __init__(self):
        StringEncoder.__init__(self)

        self.name = "XOR String Encoder"
        self.key = 0x0A # Default XOR key

        # Variable from where our decoder is supposed to get
        # the xor key from
        self.xorKeyVar = "xorkey"


    def setXORKey(self, key):
        self.key = key

    
    def setXORKeyVariable(self, varName):
        self.xorKeyVar = varName


    def _doEncode(self, string):

        code = []
        for i in string:
            code += [chr( ord( i ) ^ self.key)]

        code = "".join(code)

        return code


    def _doGetDecoderCode(self, srcVar, dstVar):

        code = """
            %s = "";
            for(i=0;i<%s.length;i++)
            {
                %s += String.fromCharCode( %s^%s.charCodeAt(i) );
            }
        """ % (dstVar,srcVar,dstVar,self.xorKeyVar,srcVar)

        return code

