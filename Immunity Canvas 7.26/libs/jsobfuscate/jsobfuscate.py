#!/usr/bin/pyhton

import sys
if '.' not in sys.path: sys.path.append('.')

from libs.jsobfuscate.strencoder import *
from libs.jsobfuscate.strencoder.stringencoderfactory import *
from libs.jsobfuscate.namegenerator import *
from libs.jsobfuscate.interpreter import *
from libs.jsobfuscate.jsutils import *


class JSObfuscator:
    
    def __init__(self):

        # Generate Random XOR Key or let the user specify it?
        self._useRandomXORKey = True
        
        # Regenerate XOR key on each call to obfuscate?
        self._regenerateXORKey = True 

        # Default XOR Key
        self._xorKeyInUse = 0xA
        if self._useRandomXORKey:
            self.regenerateXORKey()
        
        # Set out name generation strategy
        self._nameGen = RandomNameGenerator()

        # Retrieve XOR key from the cookie?
        self._xorKeyFromCookie = False
        self._cookieVarName = ""

        self._jsUtils = JSUtils()


    def xorKeyFromCookie(self, cookieVarName):
        self._xorKeyFromCookie = True
        self._cookieVarName = cookieVarName

    def regenerateXORKey(self):
        self._xorKeyInUse = random.randint(0x1,0xFF)

        
    def useRandomXORKey(self,useRandomXORKey=True):
        self._useRandomXORKey = useRandomXORKey




    # Fixes XOR Key value to the supplied one
    # disables XOR key regeneration and randomization
    def setXORKey(self, xorKey):
        self._regenerateXORKey = False
        self._useRandomXORKey = False
        self._xorKeyInUse = xorKey


    def getXORKey(self):
        return self._xorKeyInUse

    def obfuscate(self,cleanCode):

        # Regenerate XOR key, if needed
        if self._regenerateXORKey and self._useRandomXORKey:
            self.regenerateXORKey()

        print "XORing using %d key" % self._xorKeyInUse

        # Set up variable names
        xorKeyVar = self._nameGen.genRandomName()
        var = self._nameGen.genRandomName()

        # Set up the encoder and interpreter
        #myEncoder = StringEncoderFactory.getChainedEncoderPlus(self._xorKeyInUse,xorKeyVar,var)
        myEncoder = StringEncoderFactory.getDefaultChainedEncoder(self._xorKeyInUse,xorKeyVar,var)
        myEncoder.cleanText = cleanCode
        interpreter = randomJSInterpreter()
        interpreter.setStringCode(var, True)

        # Build the js
        code = ""

        if self._xorKeyFromCookie:
            code += self._jsUtils.getCookieVar(self._cookieVarName,xorKeyVar)
        else:
            code += "%s = %s;\n" % (xorKeyVar,self._xorKeyInUse)

        code +=  myEncoder.getJavascriptCode()
        code += interpreter.getJSCode()

        return code



