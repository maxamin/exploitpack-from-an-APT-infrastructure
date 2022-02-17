#! /usr/bin/env python

import sys
import types
import re

#for devlog, etc 
if "." not in sys.path: sys.path.append(".")
from internal import *

#from mosdefutils import *

# TODO: if ... elif ... [else ... endif]
# TODO: check with .S

class CPPError(Exception):
    def __init__(self, message, lineno = None):
         self.args = (message,)
         self.msg = message
         self.lineno = lineno
    def __str__(self):
         m = "\n"
         if self.lineno:
             m += "at line %d: " % self.lineno
         m += self.msg
         return m

class includeError(CPPError):
    pass

class macroError(CPPError):
    pass

class ifdefError(CPPError):
    pass

class Line:
    def __init__(self, line, lineno = None):
        self.line = line
        self.lineno = lineno
    def __str__(self):
        return self.line

def LoadLines(buffer, lineno = None, sep = '\n'):
    out = []
    index = 0
    lineno = None
    for line in buffer.split(sep):
        if not lineno:
            lineno = index
            index += 1
        out += [Line(line, lineno)]
    return out

def warn(msg):
    sys.stderr.write(msg + '\n')

def addcomment(table, comment, delim):
    table += ["%s %s" % (delim, comment)]
    pass

def cpreprocess(cdata, vars, defines, remoteresolver):
    return preprocess(cdata, vars, defines, remoteresolver, delim = "//")

def preprocess(data, vars, defines, remoteresolver, delim = None):
    """
    Preprocess the data to be compatible with GNU's C preprocessor (so we can
    cross compile code from CANVAS/GNU and vice versa)
    """
    devlog("cpp", "Preprocessing: %s with vars=%s and defines=%s"%(data,vars,str(defines)[:10]))
    
    # assert type(remoteresolver) == types.InstanceType
    if delim == None:
        delim = remoteresolver.delim
    ndata = []
    macros = {}
    constants = defines

    #we keep track of the original variables, and we don't replace these the way we would
    #a constant in our code, since they are handle by MOSDEF itself!
    #oldvars = vars.copy()
    #now we don't do this, because defines is a different thing than vars.
    
    included = []
    stmts = []
    lines = LoadLines(data)

    # XXX: to properly support nested ifdefs we need to keep track of levels
    levelCount = 0

    while lines != []:
        eline = lines[0]
        line = str(eline)
        #print "[%d]" % len(line),line

        # XXX: ordering changed to match #if(n)def before #else and #endif

        # #if(n)def
        m = re.match("^[ \t\r]*#[ \t\r]*(ifdef|ifndef)[ \t\r]+([a-zA-Z_]\w*)[ \t\r]*", line)
        if m:
            define = m.group(2)
            isdef = remoteresolver.defines.has_key(define)
            if m.group(1) == "ifndef":
                isdef = not isdef

            # XXX: increase level count only when we're in False mode
            if levelCount:
                levelCount += 1

            # XXX: nesting fix
            if isdef == False and not levelCount:
                stmts += [(define, isdef)]
                levelCount = 1        
            elif isdef == True and not levelCount:
                stmts += [(define, isdef)]

            del lines[0]
            ndata += [""]
            continue
                
        # #else
        m = re.match("^[ \t\r]*#[ \t\r]*else[ \t\r]*", line)
        if m:

            # XXX: nesting fix
            if levelCount:
                levelCount -= 1
            if not levelCount:
                stmts[-1] = (stmts[-1][0], not stmts[-1][1])
                # XXX: if #else is False, we set levelCount to 1 for another False block to ignore
                if stmts[-1][1] == False:
                    # checked .. seems ok
                    #print "XXX: check me, setting block to False in #else match !!!"
                    levelCount = 1
                
            del lines[0]
            ndata += [""]
            continue
        
        # #endif
        m = re.match("^[ \t\r]*#[ \t\r]*endif[ \t\r]*", line)
        if m:

            if levelCount:
                levelCount -= 1

            assert len(stmts), "#endif but no #if(def)"

            # XXX: nesting fix
            if not levelCount:
                del stmts[-1]

            del lines[0]
            ndata += [""]
            continue

        # XXX: nesting fix .. any False if(n)def block is ignored untill #else
        # XXX: we know we're in a False block when levelCount is > 0

        if levelCount:
            # XXX: nesting fix, ignore lines as long as the levelCount is at >= 1
            #print "Skipping line: .."
            #print lines[0]
            del lines[0]
            ndata += [""]
            continue
                    
        # inside stmt
        if len(stmts):
            cond = stmts[-1]
            if not cond[1]:
                ndata += [""]
                del lines[0]
                continue
        
        # //comment (no macroed)
        m = re.match("^[ \t\r]*[/]{2}(.*)$", line)
        if m:
            # XXX check if that works
            #ndata += [line]
            addcomment(ndata, m.group(1), delim)
            del lines[0]
            continue
        
        # macros
        macroed = 0
        for macro in macros.keys():
            m = re.search('(%s[ \t\r]*\([ \t\r]*%s[ \t\r]*\))' % (macro[0], macro[1]), line)
            if not m:
                continue
            lines[0] = Line(re.sub('(%s[ \t\r]*\([ \t\r]*%s[ \t\r]*\))' % (macro[0], macro[1]), macros[macro], line), \
                eline.lineno)
            macroed = 1
            break
        if macroed:
            continue
        
        # #include
        m = re.match("^[ \t\r]*#[ \t\r]*include[ \t\r]+(<[\w]+[\w/]*\.h>)", line)
        
        if m:
            include = m.group(1)
        
            if include in included:
                #raise includeError, ("#include %s already included." % include, eline.lineno)
                devlog("cpp", "#include %s already included line %s." % (include, eline.lineno))
                del lines[0]
                continue
            included += [include]
            if not remoteresolver.localfunctions.has_key(include):
                raise includeError, ("#include %s not found." % include, eline.lineno)
            includecode = remoteresolver.localfunctions[include][1]
            addcomment(ndata, "including %s" % include, delim)
            #lines = includecode.split('\n') + lines[1:]
            lines = LoadLines(includecode, eline.lineno) + lines[1:]
            continue
        
        # #define macro
        # KLUDGEd to allow macros such "#define IGNORE(.*)"
        #rxp="^[ \t\r]*#[ \t\r]*define[ \t\r]+([a-zA-Z_]\w*)[ \t\r]*\((\w[\w ,]*)\)([ \t\r]+(.*)[ \t\r]*|[ \t\r]*)[//.*]?"
        rxp="^[ \t\r]*#[ \t\r]*define[ \t\r]+([a-zA-Z_]\w*)[ \t\r]*\(([\w.*]*[\w ,]*)\)([ \t\r]+(.*)[ \t\r]*|[ \t\r]*)[//.*]?"
        m = re.match(rxp, line)
        if m:
            r = m.groups()
            if r[:2] in macros.keys():
                raise macroError, ("macro <%s> already defined: %s\n" % (r[:2], macros[r[:2]]), eline.lineno)
            if not r[2]:
                macros[r[:2]] = ""
            else:
                macros[r[:2]] = r[2]
            if macros[r[:2]] != "":
                addcomment(ndata, "def macro %s(%s)=%s" % (r[0], r[1], r[2]), delim)
            else:
                addcomment(ndata, "def macro %s(%s)" % (r[0], r[1]), delim)
            del lines[0]
            continue
        
        # #define constant
        m = re.match("^[ \t\r]*#[ \t\r]*define[ \t\r]+([a-zA-Z_]\w*)(?:[ \t\r]+(\"[\w/]+\"|[\w/]+)|[ \t\r]*)", line)
        if m:
            define = m.group(1)
            value = m.group(2)
            if remoteresolver.defines.has_key(define):
                warn("Warning: define %s already defined (value=%s)" % (define, remoteresolver.defines[define]))
            addcomment(ndata, "def constant %s=%s" % (define, value), delim)
            # integer values need to be set as an int, not a string
            #try:
            #    value = int(value)
            #except:
            #    pass
            ##many constants are hex numbers
            #try:
            #    value = int(value,16)
            #except:
            #    pass
            remoteresolver.defines[define] = value
            #always string
            constants[define] = value
            del lines[0]
            continue
        
        # #undef
        m = re.match("^[ \t\r]*#[ \t\r]*undef[ \t\r]+([a-zA-Z_]\w*)[ \t\r]*", line)
        if m:
            define = m.group(1)
            for macro in macros.keys():
                if macro[0] == define:
                    addcomment(ndata, "undef macro %s(%s)" % (macro[0], macro[1]), delim)
                    del macros[macro]
                    del lines[0]
                    continue
            if not remoteresolver.defines.has_key(define):
                warn("Warning: define %s NOT yet defined" % define)
            else:
                addcomment(ndata, "undef %s = %s" % (define, remoteresolver.defines[define]), delim)
                del remoteresolver.defines[define]
            del lines[0]
            continue
        
        # constants
        if not re.match("^[ \t\r]*#", line):
            macroed = 0
            for constant in constants.keys():
                #we don't want to change constants that are really MOSDEF variables
                #in the code - this causes quoting and lexing problems (see below)

                # XXX: this breaks pre-processing on SYS_function replace
                # XXX: for Solaris/SPARC .. think about what we want to do
                # XXX: commenting it out for now ..

                #if constant in oldvars:
                #    continue
                
                #we do this after the above check because this is a string search
                #and the above check is a hash lookup, and theoretically faster
                if not constant in line:
                    continue
                
                

                # XXX borderpattern should be review. it is what could borders a defined constant.
                #PROT_READ|PROT_EXEC - need | as well.
                borderpattern = " \t\r();,$|\[\]="
                # XXX while re.match(..., re.S) for multiline? but the core cpp parse lines.

                m = re.match("(.*[%s])%s([%s\n].*)" % (borderpattern, constant, borderpattern), line)
                if not m and constant=="NULL":
                    devlog("cpp", "Constant is NULL and did not find in line: %s"%line)
                    
                if not m:
                    continue
                
                #set our quote character to be nothing for integers and so on
                #mosdef variables also get passed into here, so we're going
                #to have to handle arbitrary data, essentially
                quote = ''

                # XXX: how does this deal with newlines in a string ? see solution below
                #if type(constants[constant]) == type(""): # good catch bas! \o/
                #    quote = '"'

                #XXX: is there something that i am missing here?

                lines[0] = Line(m.group(1) + quote + str(constants[constant]) + quote + m.group(2), eline.lineno)
                macroed = 1
                break
            if macroed:
                continue
        
        # #warn
        m = re.match("^[ \t\r]*#[ \t\r]*(?:warn|warning)[ \t\r]+\"(.*)\"[ \t\r]*", line)
        if m:
            warn("WARNING: %s" % m.group(1))
            addcomment(ndata, "warning: %s" % m.group(1), delim)
            del lines[0]
            continue
        
        # nothing to do on line
        ndata += [line]
        del lines[0]
    
    if len(stmts):
        print stmts
        while len(stmts):
            print "ERROR: unfinished #if %s" % stmts[-1][0]
            del stmts[-1]
        raise ifdefError, ("missing closing condition (generally #endif)", )
    out="\n".join(ndata)
    devlog("cpp", "Returning preprocessed code: %s"%out)
    return out 

if __name__=="__main__":
    print "no direct standalone execution, use this module via MOSDEF cc.py."
