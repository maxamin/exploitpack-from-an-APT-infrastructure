from libs.jsobfuscate.strencoder.chrstringencoder import *
from libs.jsobfuscate.strencoder.xorstringencoder import *
from libs.jsobfuscate.strencoder.bracketstringencoder import *
from libs.jsobfuscate.strencoder.bracketstringencoder import *

class StringEncoderFactory:

    # Returns an chain of encoder like:
    # XorEncoder -> ChrEncoder
    #
    # xorKey     : Xor key value to use
    # xorKeyVar  : js variable name where value will be stored
    # text       : string containing valid javascript code to be encoded
    # retVarName : var where the decoded text will be stored 

    def getDefaultChainedEncoder(xorKey,xorKeyVar,retVarName):

        # Create a Chr encoder
        myChrEncoder = ChrStringEncoder()

        # Create a XOR encoder
        myXOREncoder = XORStringEncoder()
        myXOREncoder.setXORKey(xorKey)
        myXOREncoder.setXORKeyVariable(xorKeyVar)
        myXOREncoder.dstVarName = retVarName

        # Chain them all!
        myXOREncoder.nextEncoder = myChrEncoder # xor->chr

        return myXOREncoder

    # Static methods
    getDefaultChainedEncoder = staticmethod(getDefaultChainedEncoder)                


    # Returns an chain of encoder like:
    # BracketEncoder -> XorEncoder -> ChrEncoder
    #
    # xorKey     : Xor key value to use
    # xorKeyVar  : js variable name where value will be stored
    # text       : string containing valid javascript code to be encoded
    # retVarName : var where the decoded text will be stored 

    def getChainedEncoderPlus(xorKey,xorKeyVar,retVarName):

        # Create a Chr encoder
        myChrEncoder = ChrStringEncoder()

        # Create a XOR encoder
        myXOREncoder = XORStringEncoder()
        myXOREncoder.setXORKey(xorKey)
        myXOREncoder.setXORKeyVariable(xorKeyVar)

        # Create a Bracket Encoder
        myBracketEncoder = BracketStringEncoder()
        myBracketEncoder.returnCodeAsString = False
        myBracketEncoder.dstVarName = retVarName

        # Chain them all!
        myBracketEncoder.nextEncoder = myXOREncoder  # bracket->xor
        myXOREncoder.nextEncoder = myChrEncoder      # bracket->xor->chr
        return myBracketEncoder

    # Static methods
    getChainedEncoderPlus = staticmethod(getChainedEncoderPlus)                

