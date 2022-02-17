#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
shellcodeGenerator.py

Generates shellcode given a number of parameters. Uses MOSDEF
"""

import sys
if "." not in sys.path:
    sys.path.append(".")

import random
import urllib
from MOSDEF import mosdef
from exploitutils import *

class shellfunc:
    """Encapsulates a reusable fragment of code, for shellcode generator authors. (Not high
    level external-to-shellcode-generator bits, those are "handlers")
    Gets inserted into the code during finalize(), with it's named label (per the mapping
    of names to instances of shellfunc in shellcodeGenerator::functions).
    There's no specific calling convention for shellfuncs, so it's up to you to read the
    fine source of the one you're gonna call to establish how it might or might not work.
    When writing shellfuncs, remember that there is no label namespace scoping, so your 
    labels must be unique across not only your shellfunc, but also any one who might ever
    use you :/ Maybe choose a unique-ish prefix for your labels huh?
    """
    def __init__(self):
        self.code=""
        self.docs=""
        self.required=[] #other functions we need
        self.imports=[] #imports we need
        self.longs=[] #longs we need (integer variables)
        return

class shellcodeGenerator:
    """
    You don't call finalize directly - you call get() which calls finalize().
    """
    def __init__(self, arch = "Unknown"):
        #attr is used to store all of our options
        self.attrs=[]
        self.debug=0
        self.handlers={}
        self.handlers["addcode"]=self.addcode
        self.arch = arch
        self.code=""
        self.functions={}
        self.hasfunctions=[]
        self.imports = []
        self.longs = [] 
        self.funccode=""
        self.prefix=""
        self.exitcode=""
        self.postfix=""
        self.variables={}
        self.varOrder=[]
        self.uninitializedVariables={}
        self.uninitializedVarOrder = []
        self.finalized = False
        # if we dont want to include any imports etc. but want a pure standalone
        # MOSDEF assemble of an attribute set this to true
        self.standalone=0
        self.reset()
        self.initfuncs()

    def reset(self):
        #reset our binary shellcode string but keep all our other options
        self.value=""

    def initfuncs(self):
        """Sets up the self.functions dictionary mapping function names to shellfunc instances.
        Subclases should provide their own implementation"""
        pass

    def requireFunctions(self,required):
        """Pass in a list of functions required, which may recursively require
        other functions. Adds these to self.funccode, imports, longs."""

        rdone=0

        if type(required) != list:
            required = [required]
        rneeded=len(required)
        while rdone<rneeded:
            for r in required:
                if r not in self.functions:
                    print "PROBLEM: requested %s function but we don't have it! (we have: %s )"%(r,self.functions)
                for r2 in self.functions[r].required:
                    if r2 not in required:
                        required+=[r2]
                        rneeded+=1
                rdone+=1
        #ok, now required has every function we actually need.
        for r in required:
            if r in self.hasfunctions:
                #we already have this one
                continue
            self.imports+=self.functions[r].imports
            self.funccode+=self.functions[r].code
            #self.longs+=self.functions[r].longs
            # This is a bit ghetto
            for l in self.functions[r].longs:
                self.addVariable(l, long, 0)
            self.hasfunctions+=[r]
        return    

    def getcode(self):
        return self.code

    def addcode(self, args):
        raise RuntimeError("Unimplemented!")
        return self.assemble(args[0])

    def assemble(self, code):
        raise RuntimeError("Unimplemented")
        bincode = mosdef.assemble(code, self.arch)
        #self.dump(bincode)
        self.value += bincode
        return bincode

    def binaryPrefix(self,prefix):
        raise RuntimeError("Unimplemented")
        self.value=prefix+self.value
        return

    def addAttr(self, attr, args = {}):
        devlog('shellcodeGenerator::addAttr', "adding %s code" % attr)
        """
        Add an attribute and its list of arguments
        returns the ID (list entry) of the attr
        """
        #print "[shellcode build] adding attribute %s"%attr
        self.attrs.append((attr,args))
        return len(self.attrs)

    def removeAttr(self,id):
        del self.attr[id]

    # XXX ???
    def addbinary(self,binvalues):
        raise RuntimeError("Unimplemented")
        self.value+=binvalues

    def addraw(self, rawcode):
        raise RuntimeError("Unimplemented")
        rawcode = str(rawcode)
        for char in rawcode:
            self.code  += ".byte 0x%02x" % ord(char)

    def hasVariable(self, vname):
        """Returns true if we have a variable called vname already, False otherwise."""
        return self.variables.has_key(vname) or self.unitializedVariables.has_key(vname)

    def addVariable(self, vname, vtype=None, value=None, comment=None, padding=4):
        """Adds a variable to the shellcode, which will be allocated a label vname, and will 
        be located in the shellcode's postfix section. 

         vname (str): Name of variable
         vtype (obj): Type object for the variable
         value      : optional Value to initialise the variable to, can be an array for multiple values.
         comment    : optional comment, can be array also
         padding (int): defaults to 4, causes things to be padded to 4 byte boundaries.

        Alternatively, pass in:
         vname (dict): vname : (vtype, value) or (vtype, value, comment)
         (padding as above)

        Passing in a value will cause it to be initialised to a known value. Not passing in
        a value (or passing None) will leave it unitialised, and you will get a value from remote memory. 
        For unintialized strings, pass an integer length as the value. 
        This has the benefit of reducing the size of the shellcode because we dont send 
        unitialised values, so use sparingly when you're space constrained. 

        Valid types are long, int (for byte/chr values, will be truncated to 0xff)
        or str, (ie, pass the type object str, int or long). Negative numeric values aren't valid.
        If you pass in the value for a string, and its last byte is a null, this gets replaced with
        and explicit .byte 0x00

        Pass in a padding width to cause it to pad out after the variable.
        Optionally, vname can be a dict of names and values, which will be added together, then
        padded only after the end of all the values.

        If you pass in multiple values, and any one of them is initialized, then all of them will be
        explicitly initialised to zero, so as to not surprise you.

        Note that this function is not endian-ness aware, so ensure all values are in an appropriate
        byte order for the host.

        Variable names must be unique, and adding one with the same name as a previous one
        will result in the old one being silently discarded. You can use hasVariable() to test for 
        the existance of one first, if you want.
        """
        vtypeMap={long:".long", str:".urlencoded", int:".byte", None:""}

        if type(vname) != dict:
            vname = {vname:[(vtype, value, comment)]}

        bytes = 0

        #print vname
        for var in vname.iterkeys():
            uninit = True
            code = ""

            for vtype, values, comments in vname[var]:
                if type(values) != list:
                    values = [values]
                if type(comments) != list:
                    comments = [comments]
                #print "%s: %s %s %s" % (var, vtype, values, comments)    
                if vtype not in vtypeMap.keys():
                    raise ValueError("Valid types are: %s" % ",".join(vtypeMap.keys()))



                for i, value in enumerate(values):
                    #print "%s[%d]: %s" % (var, i, value)
                    if value != None:
                        uninit = False

                    if vtype in [long, int] and value != None:
                        if value < 0:
                            raise ValueError("addVariable got passed a negative value %s: %s, which is probably not what you meant" % (var, value))                

                    if vtype == long:
                        if value == None:
                            value = 0
                        code += "%s 0x%08x" % (vtypeMap[vtype], value)
                        bytes += 4
                    elif vtype == str:
                        if type(value) != str:
                            value = "z" * value

                        nullterm = False
                        if value[-1] == "\x00":
                            value = value[:-1]
                            nullterm = True

                        value = urllib.quote(value)

                        code += "%s \"%s\"" % (vtypeMap[vtype], value)
                        bytes += len(value)    

                        if nullterm:
                            code += "\n.byte 0x00"
                            bytes += 1

                    elif vtype == int:
                        if value == None:
                            value = 0
                        else:
                            if value > 0xff:
                                devlog("shellcode", "Warning, truncating value %s: 0x%08x to 0x%02x" % (var, value, value))
                        code += "%s 0x%02x" % (vtypeMap[vtype], value)
                        bytes += 1
                    elif vtype == None:
                        code = ""
                try: 
                    if comments[i] != None:
                        code += " // %s" % comments[i]
                except IndexError:
                    pass
                code += "\n"

            topad = bytes % padding
            #print "Code: %s Have %d bytes, must pad to %d, adding %d bytes" % (code, bytes, padding, topad)
            if topad != 0:
                for i in range(0,topad):
                    code += ".byte 0x00 // padding\n"
                    bytes += 1
            #print "Adding %s: (init:%s)  %s" % (var, uninit, code)
            if uninit:
                if var in self.varOrder:
                    raise ValueError("Duplicate variable label in both uninitialised and initialised lists: " + var)
                self.uninitializedVariables[var] = (code, bytes)
                self.uninitializedVarOrder.append(var)
            else:
                if var in self.uninitializedVarOrder:
                    raise ValueError("Duplicate variable label in both uninitialised and initialised lists: " + var)
                self.variables[var] = (code, bytes) 
                self.varOrder.append(var)

    def finalize(self):
        """Called to merge in functions, variables and other shared assembly components,
        then assembles everything, and updates self.value. Subclasses should append to prefix, code
        funccode, exitcode and postfix as necesasry, then call us.

        builds code like this:

        startsploit:
            self.prefix
            self.code
            self.funccode
        exit:
            self.exitcode
        postfix:
            self.postfix
            variables
        endmark:

        unless self.standalone is true, in which case you get only

        startsploit:
            self.code
        endsploit:

        """
        if self.finalized:
            return self.value

        self.finalized=True
        
        if isinstance(self, nonMOSDEFShellcodeGenerator):
            # self.value is already set by the handler() calls.
            return self.value

                # standalone attribute, we want a untouched MOSDEF assembly
        if self.standalone:
            self.code = "startsploit:\n" + self.code + "\nendsploit:\n"
            #print "CODE is %s"%self.code #this line is for debugging
            bin=mosdef.assemble(self.code,self.arch)
            self.value = bin
            return bin


        #now do variables

        for var in uniqlist(self.varOrder):
            self.postfix += "%s: \n%s\n" % (var, self.variables[var][0])

        uninitLen = 0
        for var in uniqlist(self.uninitializedVarOrder):
            self.postfix += "%s: \n%s\n" % (var, self.uninitializedVariables[var][0])
            uninitLen += self.uninitializedVariables[var][1]


        self.code="startsploit:\n"+self.prefix+self.code+self.funccode
        self.code+="exit:\n"+self.exitcode+"\npostfix:\n"+self.postfix+"\nendmark:\n"

        devlog("shellcode", "Compiling code:\n" + self.code)
        #if debug:
        #file("code.s","w").write(self.code)
        bin=mosdef.assemble(self.code,self.arch)
        assert bin, "MOSDEF failed to compile the code"

        # Chop off unitialised variables to save space.
        if uninitLen > 0:
            self.value = bin[:-uninitLen]
        else:
            self.value = bin

        return self.value

    def get(self):
        for a in self.attrs:
            name = a[0]
            args = a[1]
            assert name in self.handlers.keys(), "\"%s\" not in handler list of %s" % (name, self)
            self.handlers[name](args)

        self.finalize()
        return self.value

    def dump(self, mode = None):
        if not hasattr(self, 'value'):
            return "can not dump shellcode, call get() first!"
        if self.arch in ["PPC", "SPARC", "MIPS"]:
            mode = "RISC"
        msg = "shellcode size: %d\n" % len(self.value)
        msg += shellcode_dump(self.value, mode = mode)
        return msg

class nonMOSDEFShellcodeGenerator(shellcodeGenerator):
    """By inheriting from this, we can indicate to shellcodeGenerator that we're supplying our own
    raw bytes of shellcode, not being assembled by MOSDEF, eg the linux/mipsel and linux/ppc shellcode generators
    """
    pass