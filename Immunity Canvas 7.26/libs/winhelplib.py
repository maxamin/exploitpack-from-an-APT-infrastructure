#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2008
#http://www.immunityinc.com/CANVAS/ for more information

import sys
if "." not in sys.path:
    sys.path.append(".")

# Models a winhelp file object
# mainly used to generate winhelp files sources
# wich needs to be compiled later

class WinHelpFile:

    def __init__(self):
    
        # File sections content
        self.options=[]
        self.files=[]
        self.configs=[]

        # add a default lang option to English US
        self.addOption("LCID","0x409 0x0 0x0")
        self.addOption("REPORT","Yes")
        
    # Add an item to Option section
    def addOption(self, name, value):
        self.options+=[[name, value]]

    # Useful shortcut
    def addOutputFileOption(self, value):
        self.addOption("HLP",value)

    # Add a file to be included, must be rtf
    def addFile(self, filename):
        self.files+=[filename]
    
    # Add a macro
    def addMacro(self, macro):
        self.configs+=[macro]
  
    # useful shortcut
    def addExecFileMacro(self, cmd, args,hide=True):

        if hide:
            self.addMacro("ExecFile(\"%s\",\"%s\",SW_HIDE)" % (cmd, args))
        else:
            self.addMacro("ExecFile(\"%s\",\"%s\")" % (cmd, args))

 
    # useful shortcut
    # Executes a command as an arg of cmd.exe /C
    def addExecCmdMacro(self, cmd,hide=True):

        if hide:
            self.addMacro("ExecFile(\"cmd.exe\",\"/C %s\",SW_HIDE)" % cmd)
        else:
            self.addMacro("ExecFile(\"cmd.exe\",\"/C %s\")" % cmd)

    def getRaw(self):

        raw = ""
        raw += "[OPTIONS]\n"
        
        for option in self.options:
            raw+="%s=%s\n" % (option[0],option[1])
        raw +="\n" 

        raw += "[FILES]\n"
        for file in self.files:
            raw+="%s\n" % file
        raw +="\n" 
     
        raw += "[CONFIG]\n"
        for config in self.configs:
            raw+="%s\n" % config

        return raw
     

if __name__ == '__main__':

    # Sample usage

    myhelp = WinHelpFile()
    myhelp.addFile("template.rtf") # an empty rtf would be fine
    myhelp.addOutputFileOption("test.hlp")
    myhelp.addExecFileMacro("calc.exe","")

    print myhelp.getRaw()


