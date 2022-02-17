import random
from libs.jsobfuscate.strencoder.stringencoder import StringEncoder

class BracketStringEncoder(StringEncoder):


    # JS ways to get fixed strings
    _basicStringMap = {
        'NaN'         : ["(+[][[]]+[])"],
        'false'       : ["(![]+[])","(![])","(!1)"],
        'true'        : ["(!![]+[])","(!![])","(!!1)"],
        'undefined'   : ["([][[]]+[])"],
        'Infinity'    : ["((+!+[])/(+[])+[])"],
       }

    def __init__(self):

        StringEncoder.__init__(self)
        self.name = "Bracket String Encoder"

        # Ways to access string items
        # Not compatible with ie
        self._bracketsArrayAccessor = "[%d]"         
        # Standard
        self._charAtArrayAccessor = ".charAt(%d)"   
        # Cool
        self._replaceCharAtVar = "a" # TODO randomize this
        self._replaceCharAtAccessor = "[" + self._replaceCharAtVar + "](%d)"

        self._arrayAccessor = self._charAtArrayAccessor
        #self._arrayAccessor = self._replaceCharAtAccessor

        # The higher, more data will be encoded
        self._encodeProbability = .8

        # The lower, less unencoded chunks will remain
        self._maxUnencodedLength = 4

        # This forces that our encoded result is
        # a string itself, the decoder then is a
        # javascript interpreter like eval(), Function(), etc
        # If it's False, the encoded data is javascript code
        #
        # Basically turn it ON if you wanna encode it again,
        # and turn it off if u don't
        self.returnCodeAsString = True

        # Set up the alphabet
        self._alphabet = self._buildAlphabet(self._basicStringMap)


        # It's possible to make an iterative process for alphabet building, 
        # we could, using the letters learned from the last step, call another
        # js function and add the return to our db
        # Here are some examples, BUT this ones vary on different versions of
        # js, so they're not useful
        #
        #   # Second stage
        #   filterString = b._buildString("filter",alphabet)
        #   b.basicStringMap["function filter() {\n    [native code]\n}"] = ["([][%s]+[])"%filterString]
        #   alphabet = b._buildAlphabet(b.basicStringMap)

        #   # Third stage
        #   filterString = b._buildString("sort",alphabet)
        #   b.basicStringMap["..."] = ["([][%s]+[])"%filterString]


    # Builds a string using the alphabet
    def _buildString(self, buf,alphabet):

        code = ""

        i = 0
        while i <= len(buf)-1:

            # Will we encode?
            if random.random() <= self._encodeProbability and buf[i] != "\\" and buf[i] in alphabet.keys() and len(alphabet[buf[i]]) > 0:
                code += alphabet[buf[i]][0] + "+" # TODO: if there's more than one possiblility randomize it (or select the best?)
                i += 1

            # We won't encode this chars
            else:

                # How many will be left unencoded?
                if buf[i] == "\\":   # We don't want a \ to be the last char
                    count = random.randint(2,self._maxUnencodedLength)
                else:
                    count = random.randint(1,self._maxUnencodedLength)


                # Are we exceeding buff size?
                if i + count >= len(buf):
                    count = len(buf)-i

                while buf[i+count-1] == "\\":
                    count += 1

                if self.returnCodeAsString:
                    code += "\\\"%s\\\" + " % buf[i:i+count]
                else:
                    code += "\"%s\" + " % buf[i:i+count]
                i +=count


        # Remove last "+"
        code = code[:-3]

        return code


    # Build an alphabet using strings returned by js engine
    def _buildAlphabet(self, stringMap):
        
        alphabet = {}

        for basicString in stringMap.keys():
            for letter in basicString:

                # Initialize letter array if u need to
                if not letter in alphabet:
                    alphabet[letter] = []

                # Check for all the alternatives
                for option in stringMap[basicString]:
                    alphabet[letter] += [option + self._arrayAccessor % basicString.find(letter)]

        return alphabet


    def _printAlphabet(self, alphabet):
        print "-"*100
        for letter in alphabet:
            for option in alphabet[letter]:
                print letter + "\t" + option



    def _doEncode(self, buf):

        buf = buf.replace("\\","\\\\")
        buf = buf.replace("\"","\\\"")
        buf = buf.replace("'","\\\'")
        buf = buf.replace("\n","\\n")
        code = self._buildString(buf, self._alphabet)
        if self.returnCodeAsString:
            code = "\"%s\"" % code
        return code


    def _doGetDecoderCode(self,srcVar,dstVar):

        if self.returnCodeAsString:

            # TODO: leave specify the interpreter method to use 

            if self.nextEncoder:
                code = """
                    %s = eval(eval(%s));
                """ % (dstVar,srcVar)
            else:
                code = """
                    %s = eval(%s);
                """ % (dstVar,srcVar)

        else:
            if self.nextEncoder:
                code = """
                    %s = eval(%s);
                """ % (dstVar,srcVar)
            else:
                code = """
                    %s = %s;
                """ % (dstVar,srcVar)
        return code

