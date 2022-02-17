import random
from libs.jsobfuscate.namegenerator import RandomNameGenerator

"""
Example Usage:

code before use of function wrappers:

    jscode = "eval("alert('hola')")

code using function wrappers:

    jscode = " WRAP_EVAL("alert('hola')") "
    
    wrapper = FunctionWrapperFactory.rndFuncWrapper("eval", "WRAP_EVAL")

    newjscode = wrapper.getCode()
    newjscode = wrapper.patchCode(jscode)


and this will generate something like:

    liz_xg08 = eval
    liz_xg08("alert('hola')")

or 

    $3kj$_gxdrs2 = new Function( "ln7ckj6qxhfra",unescape("%u0065%u0076%u0061%u006c")+"(ln7ckj6qxhfra);")
    $3kj$_gxdrs2("alert('hola')")

or

    pxbda4eh_f7 = new Function( "zv7y6nf92k","eval(zv7y6nf92k);")
    pxbda4eh_f7("alert('hola')")

"""

class FunctionWrapper():

    def __init__(self, realName, replaceName, numArgs=1):
        self._realName = realName
        self._replaceName = replaceName
        self._numArgs = numArgs
        self._rndGen = RandomNameGenerator()
        

    def getCode(self):
        print "Not implemented"

    # Simple search & replace patch, if u need something more elaborated
    # just override it
    def patchCode(self, code):
        newCode = code.replace(self._replaceName,self._newName)
        return newCode


# Does not really wraps the function, it just leave it as it is
# useful for debugging
class FakeFunctionWrapper(FunctionWrapper):

    def getCode(self):
        return ""

    def patchCode(self, code):
        newCode = code.replace(self._replaceName,self._realName)
        return newCode


class RenamerFunctionWrapper(FunctionWrapper):

    def __init__(self, realName, replaceName,numArgs=1):
        FunctionWrapper.__init__(self, realName, replaceName,numArgs)
        self._newName = self._rndGen.genRandomName()

    def getCode(self):
        code = "%s = %s;\n" % (self._newName, self._realName)
        return code


class NewFunctionWrapper(FunctionWrapper):

    def __init__(self, realName, replaceName,numArgs=1):
        FunctionWrapper.__init__(self, realName, replaceName,numArgs)
        self._newName = self._rndGen.genRandomName()
        self._argNames = []
        self._genArgNames()


    def _genArgNames(self):
        for i in range(self._numArgs):
            self._argNames += [self._rndGen.genRandomName()]


    def getCode(self):

        code = "%s = new Function( " % self._newName

        for i in range(self._numArgs):
            code += "\"" + self._argNames[i] + "\","

        code  += self._buildFunctionCall()
        code += ");\n"

        return code

    def _buildFunctionCall(self):

        code  = "\"" + self._realName + "("

        for i in range(self._numArgs):
            code += self._argNames[i] + ","
        code = code[:-1]

        code += ");\""

        return code


    def patchCode(self, code):
        newCode = code.replace(self._replaceName,self._newName)
        return newCode


class UEncodedNewFunctionWrapper(NewFunctionWrapper):

    def _buildFunctionCall(self):

        # Build out call to the real function
        code = "unescape(\""
        code +=  self._uencode(self._realName)
        code += "\")+\"("
        for i in range(self._numArgs):
            code += self._argNames[i] + ","
        code = code[:-1]
        code += ");\""

        return code

    def _uencode(self, string):
        tmp = []
        bufsize = len(string)
        for c in range(0, len(string)):
            tmp.append("%%u00%02x" % (ord(string[c])))
        return "".join(tmp)



class FunctionWrapperFactory:

    # Factory method 
    # Returns an instance of a random function wrapper
    def rndFuncWrapper(realName, replaceName, numArgs=1):
        # avaiable wrappers
        wrappers = [UEncodedNewFunctionWrapper, NewFunctionWrapper, RenamerFunctionWrapper]
        wrapper = random.choice(wrappers)

        return wrapper(realName,replaceName,numArgs)

    rndFuncWrapper = staticmethod(rndFuncWrapper)


    # Factory method 
    # Returns a instance of a fakeFunctionWrapper, only useful for debugging
    def fakeFuncWrapper(realName, replaceName, numArgs=1):

        return FakeFunctionWrapper(realName,replaceName,numArgs)

    fakeFuncWrapper = staticmethod(fakeFuncWrapper)
