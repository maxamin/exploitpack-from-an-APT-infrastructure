import random
from libs.jsobfuscate.namegenerator import RandomNameGenerator
from libs.jsobfuscate.funcwrapper import *

class JSInterpreter:
    def __init__(self):
        self._stringCode = ""
        self._storeVarName = None
        self._isVarName=False
        self._varNameGen = RandomNameGenerator()

        self._funcWrapperBuilder = FunctionWrapperFactory.rndFuncWrapper
        #self._funcWrapperBuilder = FunctionWrapperFactory.fakeFuncWrapper # <- No function wrapping

    def setStringCode(self,stringCode, isVarName=False):
        self._stringCode = stringCode
        self._isVarName=isVarName

    def setStoreVariable(self, storeVarName):
        self._storeVarName = storeVarName

    def getJSCode(self):
        print "Uninplemented"
    

    
class evalJSInterpreter(JSInterpreter):
    
    def getJSCode(self):
        ret = ""

        wrapper = self._funcWrapperBuilder("eval","WRAP_EVAL")
        ret += wrapper.getCode()

        if self._storeVarName:
            ret += "%s = " % _self._storeVarName

        if self._isVarName:
            ret += "WRAP_EVAL(%s);\n" % self._stringCode
        else:
            ret += "WRAP_EVAL(\"%s\");\n" % self._stringCode

        ret = wrapper.patchCode(ret)

        return ret


class functionJSInterpreter(JSInterpreter):

     def getJSCode(self):

        ret = ""
        
        funcName = self._varNameGen.genRandomName()

        if self._isVarName:
            ret += "%s = new Function(%s);\n" % (funcName,self._stringCode)
        else:
            ret += "%s = new Function(\"%s\");\n" % (funcName,self._stringCode)

        if self._storeVarName:
            ret += "%s = " % self._storeVarName

        ret += "%s();\n" % funcName
        return ret


class docWriteJSInterpreter(JSInterpreter):

    def getJSCode(self):

        ret = ""
        wrapper = self._funcWrapperBuilder("document.write","WRAP_DOC_WRITE")
        ret += wrapper.getCode()

        if self._isVarName:
            ret += "WRAP_DOC_WRITE(\"<scrip\"+\"t>\" + %s + \"<\\/scr\"+\"ipt>\")" % self._stringCode
        else:
            ret += "WRAP_DOC_WRITE(\"<scr\"+\"ipt>%s<\\/scr\"+\"ipt>\")" % self._stringCode

        ret = wrapper.patchCode(ret)
        return ret

    def setStoreVariable(self,storeVarName):
        raise Exception("docWriteJSInterpreter can't return values.")

    
class setTimeoutJSInterpreter(JSInterpreter):

    def getJSCode(self):
        
        ret = ""
        wrapper = self._funcWrapperBuilder("setTimeout","WRAP_SET_TIMEOUT",2)
        ret += wrapper.getCode()

        if self._isVarName:
            ret += "WRAP_SET_TIMEOUT(%s,0);" % self._stringCode
        else:
            ret += "WRAP_SET_TIMEOUT(\"%s\",0);" % self._stringCode

        ret = wrapper.patchCode(ret)
        return ret

    def setStoreVariable(self,storeVarName):
        raise Exception("setTimeoutJSInterpreter can't return values.")

    


class randomJSInterpreter(JSInterpreter):
    
    def __init__(self):
        JSInterpreter.__init__(self)

        # You must set this if you need to get the result of the expression
        # ie: you want to evaluate "he"+"llo"+" world" and get the resulting string
        self._requireReturnValues = False

        self._allMethods = [evalJSInterpreter,functionJSInterpreter,docWriteJSInterpreter,setTimeoutJSInterpreter]
        self._retMethods = [evalJSInterpreter,functionJSInterpreter]


    def getJSCode(self):

        # Select one metho randomly
        method = None
        if self._requireReturnValues:
            method = random.choice(self._retMethods)
        else:
            method = random.choice(self._allMethods)

        myMethod = method()
        if self._requireReturnValues:
            myMethod.setStoreVariable(self._storeVarName)
        myMethod.setStringCode(self._stringCode, self._isVarName)

        return myMethod.getJSCode()
        

    def requireReturnValues(self, requiere):
        if not requiere and self._storeVarName:
            raise Exception("We have a store var name, we can't relax this restriction")
        self._requireReturnValues = requiere


    def setStoreVariable(self,storeVarName):
        if not self._requireReturnValues:
            raise Exception("Can't set return value variable, set requiereReturnValue if u need it")



