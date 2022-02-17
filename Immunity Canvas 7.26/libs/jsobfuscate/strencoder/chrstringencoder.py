
from libs.jsobfuscate.strencoder.stringencoder import StringEncoder

class ChrStringEncoder(StringEncoder):

    def __init__(self):
        StringEncoder.__init__(self)
        self.name = "Unicode String Encoder"
    

    def _doEncode(self, buf):
        """
        Build an array of the ordinals like [1,2,3,4]
        """
        code = []

        for i in buf:
            code += ["%d" % ord(i)]

        code = ",".join(code)

        final_code = "[%s]" % code

        return final_code


    def _doGetDecoderCode(self,srcVar,dstVar):
        
        code = """
            %s = "";
            for(i=0;i<%s.length;i++)
            {
               %s += String.fromCharCode( %s[i] );
            }
        """ % (dstVar,srcVar,dstVar,srcVar)

        return code

