# Library with useful javascript functions


from libs.jsobfuscate.namegenerator import *

class JSUtils:

    def __init__(self):
        self._nameGen = RandomNameGenerator()


    # Simple javascript routine that parse document.cookie
    # and stores on resultVarName the value of cookieVarName
    def getCookieVar(self, cookieVarName, resultVarName):

       code = """

        COOKIE = document.cookie;
        START = COOKIE.indexOf("CVARNAME=") + LEN;
        END = COOKIE.indexOf(";", START);
        if (END == -1) END = COOKIE.length;

        RESULTVARNAME = parseInt(COOKIE.substring(START,END));
       """

       code = code.replace("COOKIE", self._nameGen.genRandomName())
       code = code.replace("START", self._nameGen.genRandomName())
       code = code.replace("END", self._nameGen.genRandomName())
       code = code.replace("LEN", str(len(cookieVarName)+1))
       code = code.replace("CVARNAME", cookieVarName)
       code = code.replace("RESULTVARNAME", resultVarName)

       return code
