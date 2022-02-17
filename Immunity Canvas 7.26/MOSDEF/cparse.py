#! /usr/bin/env python

"""
references:
-----------

http://en.wikipedia.org/wiki/C_syntax
http://en.wikipedia.org/wiki/Operators_in_C_and_C++

cparse should at least parse K&R C, then ANSI.

"""

from spark import GenericScanner, GenericASTBuilder, GenericASTTraversal

from mosdefutils import *
from mosdefctypes import *
import urllib #Our assembler understands urllib.quote() strings in certain areas
import sys
if "MOSDEF" not in sys.path: sys.path.append("MOSDEF")
# TODO: replace uint32() and long() with a function compatible for 64bits proc

# FIXME: this code already is in mosdefutils
def old_dInt(sint):
    #print "cparse/dInt %d" % sint
    """
    Turns sint into an int, hopefully
    python's int() doesn't handle negatives with base 0 well
    """
    s=str(sint)
    if s[0:2]=="0x":
        return long(s,0)
    else:
        try:
            if s.count("."): #5.0, for exampleb
                return long(float(sint))  
            return long(s)
        except ValueError:
            import traceback
            traceback.print_stack()
            print "Invalid literal for long? *%s*"%s
            return long(s)


class Token:
        def __init__(self, type, attr=None, lineno='???'):
            self.type = type
            self.attr = attr
            self.lineno = lineno
        
        def __cmp__(self, o):
            return cmp(self.type, o)
        ###
        def __repr__(self):
            return str(self.type)
        #So we can use this as a leaf - see release notes for SPARK
        def __getitem__(self, i):
            raise IndexError


class CScanner(GenericScanner):
        """
        Scans for a minimized version of C code. Anything not recognized is a "label"
        """
        def __init__(self):
            self.tokens=[]
            GenericScanner.__init__(self)
            self.lineno=1
            
        def tokenize(self, input):
            self.tokens = []
            GenericScanner.tokenize(self, input)
            return self.tokens
        
        ###EVERYTHING ELSE
        #control statements
        def t_while(self,s):
            r'while\b'
            t=Token(type='while',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_if(self,s):
            r'if\b'
            t=Token(type='if',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_else(self,s):
            r'else\b'
            t=Token(type='else',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        #reserved types
        def t_char(self,s):
            r'char\b'
            t=Token(type='char',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_int(self,s):
            r'int\b'
            t=Token(type='int',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_unsigned(self,s):
            r'unsigned\b'
            t=Token(type='unsigned',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_signed(self,s):
            r'signed\b'
            t=Token(type='signed',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_long(self,s):
            r'long\b'
            t=Token(type='long',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_short(self,s):
            r'short'
            t=Token(type='short',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        #def t_for(self,s):
        #    r'for'
        #    t=Token(type='FOR',attr=s,lineno=self.lineno)
        #    self.tokens.append(t)
        
        def t_void(self,s):
            r'void'
            t=Token(type='void',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_struct(self,s):
            r'struct'
            t=Token(type='struct',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        #others
        def t_as(self,s):
            r'as'
            t=Token(type='as',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_include(self,s):
            r'\#include'
            t=Token(type='#include',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_import(self,s):
            r'\#import'
            t=Token(type='#import',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_return(self,s):
            r'return'
            t=Token(type='return',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_newline(self,s):
            r'[\n]'
            t=Token(type='newline',attr=s,lineno=self.lineno)
            self.tokens.append(t)
            self.lineno+=1
        
        def t_default(self,s):
            r'[a-zA-Z_][a-zA-Z0-9_]*'
            #print "Default Matched: *%s*"%s
            if s=="for":
                t=Token(type='for',attr=s,lineno=self.lineno)
            elif s=="do":
                t=Token(type='do',attr=s,lineno=self.lineno)
            else:
                t=Token(type='name',attr=s,lineno=self.lineno)
            self.tokens.append(t)   
        
        def t_comment(self,s):
            r'//.*?\n'
            self.lineno+=1
        
        def t_whitespace(self, s):
            r'\s+'
            self.lineno+=s.count("\n")
        
        def t_star(self,s):
            #these are used in front of calls, but we can just ignore them...
            r'\*'
            pass
        
        def t_decnumber(self, s):
            r'(?!0x)\d+'
            t = Token(type='decnumber', attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_hexnumber(self,s):
            r'0x[a-fA-F0-9]+'
            t = Token(type='hexnumber', attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_colon(self,s):
            r':'
            t = Token(type=':', attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_dollarsign(self,s):
            r'\$'
            t=Token(type='$',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_comma(self,s):
            r','
            t=Token(type=',',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_lparen(self,s):
            r'\('
            t=Token(type='(',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_rparen(self,s):
            r'\)'
            t=Token(type=')',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_plus(self,s):
            r'\+'
            t=Token(type='+',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_minus(self,s):
            r'\-'
            t=Token(type='-',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_semicolon(self,s):
            r';'
            t=Token(type=';',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_equal(self,s):
            r'='
            t=Token(type='=',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_lt(self,s):
            r'<'
            t=Token(type='<',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_slash(self,s):
            r'/'
            t=Token(type='/',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_percent(self,s):
            r'%'
            #print "FOUND PERCENT"
            t=Token(type='%',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_gt(self,s):
            r'>'
            t=Token(type='>',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_xor(self,s):
            r'\^'
            t=Token(type='^',attr=s,lineno=self.lineno)
            self.tokens.append(t)
         
        def t_bang(self,s):
            r'!'
            t=Token(type='bang',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_quotedstring(self,s):
            r'".*?"'
            t=Token(type='quotedstring',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_quotedchar(self,s):
            r'\'(?:.|\\([0abfnrtv\\]|x[a-fA-F0-9]{1,2}))\''
            t=Token(type='quotedchar',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_includepath(self,s):
            r'</*[a-zA-Z0-9_./]+\.h>|"/*[a-zA-Z0-9_./]+\.h"'
            t=Token(type='includepath',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_leftbracket(self,s):
            r'\{'
            t=Token(type='{',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_rightbracket(self,s):
            r'\}'
            t=Token(type='}',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_leftsquarebracket(self,s):
            r'\['
            t=Token(type='[',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_rightsquarebracket(self,s):
            r'\]'
            t=Token(type=']',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_ampersand(self,s):
            r'\&'
            t=Token(type='ampersand',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_pipe(self,s):
            r'\|'
            t=Token(type='pipe',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_asterisk(self,s):
            r'\*'
            t=Token(type='asterisk',attr=s,lineno=self.lineno)
            self.tokens.append(t)
        
        def t_dot(self,s):
            r'\.'
            t=Token(type='.',attr=s,lineno=self.lineno)
            self.tokens.append(t)

#common bugs when writing these things
# forgetting a space such as: blah::= 
#
class cparser(GenericASTBuilder):
        def p_start(self, args):
            '''
            file_input ::= file_contents
            file_contents ::= file_contents stmt 
            file_contents ::= file_contents newline
            file_contents ::=
            stmt ::= directive 
            stmt ::= functiondeclare
            stmt ::= structdefine
            stmt ::= incompletestructdefine
            
            controlstatement ::= if whitespace ( rightvalue ) controlblock 
            controlstatement ::= if whitespace ( rightvalue ) codeblock whitespace else whitespace codeblock
            controlstatement ::= while whitespace ( rightvalue ) controlblock
            controlstatement ::= do whitespace codeblock while ( rightvalue ) whitespace ;
            controlstatement ::= for whitespace ( whitespace rightvalue whitespace ; whitespace rightvalue whitespace ; whitespace rightvalue whitespace ) controlblock

            statements ::= insidestmt ; whitespace statements
            statements ::= insidestmt ; 
            statements ::= controlstatement whitespace statements
            statements ::=
            functiondeclare ::= typedef whitespace name ( argumentlist ) codeblock
            codeblock ::= whitespace blockstart whitespace statements whitespace blockend whitespace 
            blockstart ::= {
            blockend ::= }
            controlblock ::= codeblock
            controlblock ::= statements
            
            insidestmt ::= structdefine
            insidestmt ::= incompletestructdefine
            insidestmt ::= variabledeclare
            insidestmt ::= functioncall
            insidestmt ::= rightvalue
            insidestmt ::= return rightvalue whitespace
            insidestmt ::= return whitespace
            
            
            op ::= asterisk
            op ::= /
            op ::= +
            op ::= %
            op ::= -
            op ::= < <
            op ::= > >
            op ::= ~
            op ::= ^
            op ::= pipe pipe
            op ::= pipe
            op ::= <
            op ::= = =
            op ::= >
            op ::= bang =
            op ::= ampersand
            op ::= ampersand ampersand
            
            leftvalue ::= asterisk name
            leftvalue ::= name
            leftvalue ::= number
            leftvalue ::= name [ rightvalue ]
            leftvalue ::= name . name
            leftvalue ::= name - > name
            
            rightvalue ::= number
            rightvalue ::= quotedstring
            rightvalue ::= quotedchar
            rightvalue ::= functioncall
            rightvalue ::= name
            rightvalue ::= ampersand name
            rightvalue ::= name [ rightvalue ]
            rightvalue ::= name . name
            rightvalue ::= ampersand name . name
            rightvalue ::= name - > name
            rightvalue ::= rightvalue op rightvalue
            rightvalue ::= leftvalue = rightvalue
            rightvalue ::= asterisk name
            
            functioncall ::= name ( functioncallarglist )
            functioncallarglist ::= arg
            functioncallarglist ::= arg , functioncallarglist
            functioncallarglist ::= 
            arg ::= rightvalue
            variabledeclare ::= variabledefine
            variabledefine ::= argdeclare arrayvals
            arrayvals ::= [ number ]
            arrayvals ::=
            whitespace ::= newline
            whitespace ::= whitespace newline
            whitespace ::= 
            
            structdefine ::= struct name { whitespace structarglist whitespace } ;
            incompletestructdefine ::= struct name ; 
            structarglist ::= variabledefine ; whitespace structarglist
            structarglist ::=
            
            
            argumentlist ::= argdeclare
            argumentlist ::= argumentlist , argdeclare
            argumentlist ::= void
            argumentlist ::= 
            
            argdeclare ::= typedef name
            typedef ::= char asterisklist
            typedef ::= int asterisklist
            typedef ::= void asterisklist
            typedef ::= signed typedef
            typedef ::= unsigned typedef
            typedef ::= short asterisklist
            typedef ::= short int asterisklist
            typedef ::= long asterisklist
            typedef ::= long int asterisklist
            typedef ::= struct name asterisklist 
            asterisklist ::= asterisk asterisklist
            asterisklist ::= 
            
            type ::= name
            directive ::= importdirective
            directive ::= includedirective
            includedirective ::= #include includepath
            importdirective ::= #import quotedstring , quotedstring as quotedstring 
            number ::= hexnumber
            number ::= decnumber 
            number ::= - number 
            
            '''
        
        def typestring(self, token):
            return token.type
        
        def error(self, token):
            #self.parse(tokens,debug=1)
            errmsg = "[cparse] Syntax error at `%s' of type %s (line %s)\n" % (token.attr, token.type,token.lineno)
            if token.attr=="\n":
                errmsg += "Usually this means a missing semicolon.\n"
            errmsg+=""
            sys.stderr.write(errmsg)
            raise SystemExit


class vartree:
        """
        This class is a tree to hold variables in and maps them to labels
        The top level is the global level
        When queried, we return the lowest variable
        Currently it only handles one level of tree-ness, which is lame, but if we need it
        later we can flesh it out
        """
        TODO = """
        well we should rewrite all that crap to at least consum less memory.
        idea: init(self, level = -1)
                  self.level = level + 1
                  self.tree = {}
              down(self):
                  self.level += 1
                  self.tree[self.level] = []
              up(self): # check self.level > 0
                  del self.tree[self.level]
                  self.level -= 1
              getvar(self, varname):
                  for level in range(self.level, 0, -1):
                      if hasvar(self.tree[level], varname):
                           return self.tree[level][varname]
        """
        def __init__(self, defines = {}):
            self.tree={}
            self.tree['globals'] = {'defines': defines, 'variables': {}, 'functions': {}}
            self.current = "globals"
            self.currentfunction = None
            self.esps=[0] #last esp is current frame's offset
        
        def addvar(self,label,varname,type):
            """
            Addvar needs to handle arguments to functions as well as 
            variables declareed on the stack
            """
            varsize=type.getstacksize()
            #print "Addvar: %s %s %s"%(label,varname,type)
            if str(label).count("in")==0: #local stack variable
                location=self.esps[-1]+varsize
                self.esps[-1]+=varsize #add to esp...very important!!!
            else:
                location=label #argument in0, in1, etc
            self.tree[self.current]["variables"][varname]=(label,type,location)
        
        def addfunction(self,label,functionname):
            #functions are really globals in the assembly we generate
            #we might want to consider using self.tree['globals'] instead...
            self.tree['globals']["functions"][functionname]=label
            if label == None:
                self.currentfunction = functionname
            devlog("cparse","Adding function %s"%functionname)
        
        def getcurrentfunction(self):
            return self.currentfunction
        
        # XXX XXX XXX
        #
        # note about up/down
        #
        # actually we change esp between each block
        # that's a big BUG imo
        #
        # we should change it only between functionblock, but in any case in funcsubblock.
        #
        # one method to know esp size is to parse all the blocks in the func before to init esp
        # at the top of func, and dont touching esp inside subblocks.
        #
        # XXX XXX XXX
        
        def down(self,label):
            "called when a block starts"
            #
            # when you enter a new block, you must have access to previous vars
            # sometimes you could (non-ANSI) overwrite namespace with the same name in the current block
            #
            # what we do here is to copy the tree namespace in a subblock
            # up() will only delete it.
            #
            # BUZZILA ISSUE #2 (06/21/06 submitted by bas)
            # fix not tested
            previous = self.current
            self.current+="."+label
            self.esps.append(0) #the last esp is here
            self.tree[self.current] = {}
            self.tree[self.current]['variables'] = self.tree[previous]['variables'].copy()
            self.tree[self.current]['functions'] = self.tree[previous]['functions'].copy()
            self.tree[self.current]['link'] = previous
            #print "dn: prev=%s current=%s" % (previous, self.current)
        
        def up(self):
            next = self.tree[self.current]['link']
            #print "up: next=%s current=%s tree_len=%d" % (next, self.current, len(self.tree))
            del self.tree[self.current]
            self.current = next
            del self.esps[-1] # pop off the frame
        
        def getvar(self,variable):
            #what are the valid results for current here?
            #number, global, local?
            #print "Getvar: %s"%variable
            if IsInt(variable):
                #location doesn't really exist
                # XXX UnboundLocalError: local variable 'label' referenced before assignment
                return (label,"number",int(variable,0),None)
            
            # XXX XXX XXX XXX
            # XXX XXX XXX XXX
            # word...
            # XXX XXX XXX XXX
            # XXX XXX XXX XXX
            #we got here because we have a real variable somewhere in memory
            current=self.current
            while current!="":
                next=".".join(current.split(".")[:-1])
                #print "while current=%s next=%s vars=%s" % (current, next, self.tree[current]["variables"])
                if self.tree[current]["variables"].has_key(variable):
                    #return array, variable type, variable address
                    label,type,address=self.tree[current]["variables"][variable]
                    return (label,current,type,address)
                current=next
            
            # search in global included defines
            if self.tree['globals']['defines'].has_key(variable):
                return (None, 'number', self.tree['globals']['defines'][variable], None)
 
            #perhaps the user wants to treat a function as a function pointer
            #i.e. char *p; p=func;
            devlog("cparse","Looking for %s"%variable)
            devlog("cparse","Functions list %s"%self.tree[self.current]['functions'])
            
            if self.tree['globals']['functions'].has_key(variable):
                devlog("cparse","Found function pointer for %s"%variable)
                return (variable, 'function pointer', self.tree['globals']['functions'][variable], None)
 
            #sOME KIND OF ERROR
            #print "cparse::getvar() variable=%s can't find variable" % variable
            return (None,None,None,None)


#we're actually defining another language here as we go along
#GETPC - generates the code that puts the current location of eip in %ebx
# on x86, this is just call getip:
#Calling a function. On RISC we need to know the arguments place(0-6), on x86, we just push
# pusharg argplace, argument
#archalign aligns to words on sparc and does nothing on x86


class ilgenerate(GenericASTTraversal):
        """
        this class is initialized supposing sizeof(void *)=4
        you have to pass pointersize=8 on 64bits proc
        """
        
        #__bt = {'0':'\0', 'a':'\a', 'b':'\b', 't':'\t', 'n':'\n', 'v':'\v', 'f':'\f', 'r':'\r', '\\':'\\'}
        __bt = {'n':'\n', '\\':'\\'}
        
        def __init__(self,ast,vars,remoteresolver=None,imported=None,pointersize=4, not_libc = 1):
            #dictionary to hold variables
            #vars is all the variables...
            #assert type(vars) == type({}) # XXX commented for now...
            self.vars=vars
            self.labels={}
            self.redoList={}
            self.pointersize=pointersize
            self.value=""
            self.suffix="" #for functions and stuff
            self.currentMN=""
            self.currentAL=[]
            self.currentVL=[]
            self.vartree=vartree(vars)
            self.newlabel=0
            self.variableresolver=None
            self.vartypes={}
            self.stacksize=0
            self.varcache=varcache()
            self.argumentlist=None
            self.stackalign=self.pointersize
            self.lastloaded=None
            #used for statements before we have a function
            self.value2=""
            if imported:
                self.importedlocals=imported
            else:
                self.importedlocals={}
            import random
            self.cookie=random.randint(1,500000)+random.randint(1,500000)+random.randint(1,500000)
            
            self.setRemoteResolver(remoteresolver)
            
            GenericASTTraversal.__init__(self, ast)
            if imported==None and not_libc:
                self.value+="GETPC\n"
                #we always call main, which takes no args
                # ^^^ WHY? please explain...
                self.value+="call main\n"
                # vvv should not be reached, some SYS_exit() would be better.
                self.value+="rem <SHOULD NOT BE REACHED>\n"
                self.value+="ret 0\n"
                self.value+="rem </SHOULD NOT BE REACHED>\n"
            else:
                #print "imported - no need to do anything special for GETPC"
                pass
            
            self.argsize=0 #argsize of current function
            self.postorder()
        
        def get(self):
            return self.value+self.suffix
        
        def logerror(self,message):
            print "CPARSE ERROR: %s"%message
            raise LookupError, message
        
        def gettypes(self):
            return self.varcache.getAllTypes()
        
        def getTypeSize(self,type):
            return type.getsize()
            
        def setVariableResolver(self,resolver):
            self.variableresolver=resolver
        
        def getLocalVariable(self,variable):
            devlog("cparse", "getLocalVariable: variable=%s vars= %s defines=%s"%(variable, str(self.vars)[:50], str(self.remoteresolver.defines)[:10]))
            assert self.vars.has_key(variable), "variable %s not defined." % variable
            return self.vars[variable]
            
        def setRemoteResolver(self,resolver):
            self.remoteresolver=resolver
        
        def getRemoteFunctionCached(self,functionname):
            if self.remoteresolver==None:
                self.logerror("No remote function resolver for a remote cache!")
            return self.remoteresolver.getRemoteFunctionCached(functionname)
        
        def addToRemoteFunctionCache(self,functionname):
            if self.remoteresolver==None:
                self.logerror("No remote function resolver for a remote cache!")
            return self.remoteresolver.addToRemoteFunctionCache(functionname)
        
        def getRemoteFunction(self,functionname):
            if self.remoteresolver==None:
                self.logerror("No remote function resolver!")

            return self.remoteresolver.getremote(functionname)
        
        def getLabel(self):
            self.newlabel+=1
            return "LABEL%d_%d"%(self.newlabel,self.cookie)
        
        def addfunction(self,label,function):
            self.vartree.addfunction(label,function)
        
        def addvariable(self,label,variable,type):
            self.vartree.addvar(label,variable,type)
        
        def setcurrentfunction(self,function):
            #self.vartree.setfunction(function)
            #don't have a label for addfunction
            self.addfunction(None,function)
        
        def getcurrentfunction(self):
            return self.vartree.getcurrentfunction()
        
        def allocateStackSpace(self,size):
            tmp=self.stacksize
            self.stacksize+=size
            #self.alignstack() #urg.
            return tmp
        
        def alignstack(self):
            """even x86 hates having it unaligned"""
            # XXX 4? pointersize?
            pad=4-self.stacksize%self.stackalign
            self.stacksize+=pad
            return
        
        def loadarg(self,argname):
            """
            for any given value, load it into the accumulator
            """
            #print "loadarg(%s)"%argname
            if IsInt(argname):
                value="loadconst %s\n"%argname
                return value
            #print "getvar is", self.vartree.getvar, "self is", self
            (label,current, arg,location)=self.vartree.getvar(argname)
            if current==None:
                self.logerror("Could not find variable *%s*"%argname)
            if label == None and location == None and current == 'number':
                value = "rem %s\nloadint %s\n" % (argname, arg)
                return value
            devlog("cparse", "loading argument: %s"%current)
            if current == "function pointer":
                #p=func; <--load a function pointer
                value =  "rem Loading function pointer %s\n"%label
                value += "loadglobaladdress %s\n"%label
                return value 
            
            #print "[%s] arg [%s]"%(current,arg)
            argtype=arg
            #print "Argtype=%s current=%s"%(argtype,current)
            assert hasattr(argtype, 'getname'), "wrong 'arg' returned by getvar(%s)" % argname
            if argtype.getname()=="array":
                out="rem Loading array address for %s\n"%argname
                out+="loadlocaladdress %s\n"%(location)
                return out
            
            if argtype.getname()=="global":
                if argtype.totype.getname()=="array":
                    return "loadglobaladdress %s\n"%(label)
                else:
                    #global argument, need to set up a LABLE-geteip(%ebx) type device
                    # on solaris we just use add %o7, label-called+4, register
                    # register is determined by argnum
                    # we actually need to mov it into eax then push it
                    # here is GCC pushing a short
                    #0x8048339 <main+19>:	movswl 0xfffffffe(%ebp),%eax
                    #0x804833d <main+23>:	push   %eax
                    #0x804833e <main+24>:	call   0x804830c <func>
                    #print "global argument: %s: %s"%(arg,location)
                    mystr="loadglobaladdress %s\n"%(label)
                    mystr+="derefaccum %s\n"%arg.getsize()
                    return mystr
            
            else:
                #local argument
                # on x86 we need to push the stackoffset
                # on sparc we need to ld [ %sp + argnum*4], %l0
                #print "local argument: %s: %s"%(arg,location)
                if arg.getname()=="array":
                    astr= "loadlocaladdress %s\n"%(location)
                else:
                    #not an array
                    astr="rem loading local: %s\n"%argname
                    loadsize=self.getTypeSize(arg)
                    self.lastloaded=arg
                    #print "Loading %s of size %d"%(argname,loadsize)
                    astr+="loadlocal %s %s\n"%(location,loadsize)
                return astr
        
        def pusharg(self,argname,argnum):
            """
            For any given argument, figure out how to push it onto the argument stack
            """
            #print "pusharg: %s"%argname
            tmp=self.loadarg(argname)
            #arg just loads eax/l0 into the argument list
            tmp+="arg %d\n"%argnum
            return tmp
        
        def pushargfromaccumulator(self,argnum):
            tmp="arg %d\n"%argnum
            return tmp
        
        def resolveArgList(self):
            """
            takes the current argument list and gets the arguments for it as space on the stack
            or as a register or whatever
            """
            #print "IN RESOLVE ARG LIST"
            if self.argumentlist==None:
                return
            i=0
            for arg in self.argumentlist.args:
                #print "Node.name=%s node.type=%s"%(arg[1],arg[0])
                name=arg[1]
                type=self.varcache.gettype(arg[0])
                #need to somehow get a ctype from the arg[0] (which is a string 
                #representation of it)
                #valid values are, for example, char, unsigned char, int, unsigned int, struct structtype, char *, struct structtype *, unsigned int * etc
                #print "Adding arg of type %s"%type
                #we reserve the variable lables: in0-256 as input variables
                self.addvariable("in%d"%i,name,type)
                i+=1
                #self.addvariable(addr,node.name,node.type)       
        
        #########################################
        def n_type(self,node):
            node.attr=node[0].attr
        
        def n_op(self,node):
            node.exprType="op"
            node.attr=""
            for n in node:
                node.attr+=n.attr
        
        def n_ampersand(self,node):
            node.exprType="ampersand"
        
        def n_pipe(self,node):
            node.exprType="pipe"
        
        def n_controlblock(self, node):
            node.exprType="controlblock"
            node.attr=node[0].attr
        
        def n_controlstatement(self,node):
            #does the ELSE statements with a tiny bit of optimization - null ELSE statements
            #are discarded
            node.exprType="controlstatement"
            node.attr=""
            elselen=10
            #print "controlstatement:", node[0].attr
            if node[0].attr in ["while","if"]:
                startlabel=self.getLabel()
                endlabel=self.getLabel()
                node.attr+="rem Found if/while statement - using %s as label\n"%startlabel
                node.attr+="labeldefine %s\n"%startlabel
                node.attr+=node[3].attr #testcase
                if node[0].attr=="if" and len(node)==elselen and node[elselen-1].attr!="":
                    elselabel=self.getLabel()
                    node.attr+="jumpiffalse %s\n"%elselabel
                else:
                    node.attr+="jumpiffalse %s\n"%endlabel
                node.attr+=node[5].attr #codeblock
                if node[0].attr=="while":
                    node.attr+="jump %s\n"%startlabel
                if node[0].attr=="if" and len(node)==elselen and node[elselen-1].attr!="":
                    node.attr+="rem ELSE\n"
                    #end of if statement
                    node.attr+="jump %s\n"%endlabel
                    #beginnging of else statement
                    node.attr+="labeldefine %s\n"%elselabel
                    node.attr+=node[elselen-1].attr #else code
                    #print "End of if/while - %s"%endlabel
                node.attr+="labeldefine %s\n"%endlabel
            elif node[0].attr=="do":
                startlabel = self.getLabel()
                node.attr += "rem Found do/while statement - using %s as label\n" % startlabel
                node.attr += "labeldefine %s\n" % startlabel
                node.attr += "rem DO [CODE] ... \n"
                node.attr += node[2].attr # codeblock
                node.attr += "rem DO ... WHILE [condition]\n"
                node.attr += node[5].attr # testcase
                node.attr += "jumpiftrue %s\n" % startlabel
                node.attr += "rem DO ... [out of loop]\n"
            elif node[0].attr=="for":
                startlabel=self.getLabel()
                conditionlabel=self.getLabel()
                endlabel=self.getLabel()
                node.attr+="rem Found FOR loop - using %s as label\n"%startlabel
                node.attr+="labeldefine %s\n"%startlabel
                node.attr+=node[4].attr #initialize first thing i=0
                node.attr+="rem condition statement follows\n"
                node.attr+="labeldefine %s\n"%conditionlabel
                node.attr+=node[8].attr #i<1
                node.attr+="jumpiffalse %s\n"%endlabel
                node.attr+="rem condition statement finish\n"
                node.attr+=node[15].attr #codeblock
                node.attr+="rem new assignment statement\n"
                node.attr+=node[12].attr #i=i+1
                node.attr+="rem new assignment statement finish\n"                
                node.attr+="jump %s\n"%conditionlabel
                node.attr+="labeldefine %s\n"%endlabel
                node.attr+="rem FOR ... [out of loop]\n"
            else:
                print "Node attribute *%s* unrecognized in cparse"%node[0].attr
        
        def n_structdefine(self,node):
            node.attr=""
            name=node[1].attr
            structarglist=node[4].arglist
            cstruct=cstructure(structarglist)
            #print "Adding %s, %s"%(name,cstruct)
            self.varcache.addtype(name,cstruct)
        
        def n_structarglist(self,node):
            node.attr=""
            node.arglist=[]
            if len(node)==4:
                node.arglist+=[(node[0].type,node[0].name)]
                node.arglist+=node[3].arglist
        
        def n_rightvalue(self,node):
            #TODO: add ampersand support...
            node.exprType="rightvalue"
            node.attr=""
            #print "rightvalue type: %s"%node[0].type 
            if node[0].type=="number":
                #loads eax with the integer
                number=long(node[0].attr,0) #should this be uint32?
                node.attr="loadint %d\n"%number
            elif node[0].type=="quotedstring":
                #globals don't get a size - they don't modify esp
                var=node[0].attr[1:-1]
                varname="string: %s"%var

                # handle quoted chars inside quoted string (var)
                qi = 0
                _var = []

                # XXX: if last char is '\\' this blows up with index error
                # remember, technically speaking this does it correctly as
                # we SHOULD take in "cd c:\\" escaping backwards slashes
                # this is a work around..but on "cd c:\n" you'd technically
                # have to go "cd c:\\n"

                while qi < len(var):
                    # fix: check if qi == len(var)-t
                    if var[qi] == '\\' and qi != len(var)-1 and var[qi+1] in self.__bt:
                        _var.append(self.__bt[var[qi+1]])
                        qi += 1
                    else:
                        _var.append(var[qi])
                    qi += 1                
                var = ''.join(_var)

                #print urllib.quote(var)

                (mylabel,current, arg,location)=self.vartree.getvar(varname)

                if location==None:

                    #new string constant
                    mylabel=self.getLabel()
                    jmplabel=self.getLabel()
                    #print "Jmplabel=%s mylabel=%s"%(jmplabel,mylabel)
                    mycglobal=cglobal(carray(cchar(),len(var)+1))
                    mycglobal.setLabel(mylabel)
                    self.addvariable(mylabel,varname,mycglobal)
                    node.attr+="jump %s\n"%jmplabel
                    node.attr+="labeldefine %s\n"%mylabel
                    node.attr+="urlencoded %s\n"%urllib.quote(var)
                    node.attr+="databytes 0\n"
                    node.attr+="archalign\n"
                    #we jump here over our string...
                    node.attr+="labeldefine %s\n"%jmplabel
                
                #actually load the address into the accumulator
                node.attr+="loadglobaladdress %s\n"%mylabel
            
            elif node[0].type=="functioncall":
                #eax should already be loaded with the results after our call
                node.attr=node[0].attr
            
            elif node[0].type=="ampersand" and len(node)>2:
                #&name.name (structure member deref)
                #structure .
                member=node[3].attr
                (label,current, arg,location)=self.vartree.getvar(node[1].attr)
                offset=arg.getmemberoffset(member)
                if offset==-1:
                    print "Did not find member %s!"%member
                    raise SystemError
                #with a structure member, first load the local location
                node.attr+="loadlocaladdress %s\n"%location
                #then add the offset
                #node.attr+="debug\n"
                node.attr+="addconst %s\n"%offset
                #now accumulator is pointing to member
            
            elif node[0].type=="name":
                #need to load a variable
                #can be one of three things - a normal variable, or an array reference!
                #or it can also be a structure dereference!
                #or node[0].attr is string of "None" for a null pointer passed in via #import "string" 
                if len(node)>1:
                    if node[1].type==".":
                        #structure .
                        member=node[2].attr
                        varname=node[0].attr
                        (label,current, arg,location)=self.vartree.getvar(varname)
                        assert arg, "arg is None for varname.member=%s.%s" % (varname, member)
                        assert hasattr(arg, 'getmemberoffset'), \
                            "arg.getmemberoffset not existant for varname.member=%s.%s" % (varname, member)
                        offset=arg.getmemberoffset(member)
                        if offset==-1:
                            print "Did not find member %s!"%member
                            raise SystemError
                        #with a structure member, first load the local location
                        if location==None:
                            print "******Did not find variable %s"%varname
                        node.attr+="loadlocaladdress %s\n"%location
                        #then add the offset
                        #node.attr+="debug\n"
                        node.attr+="addconst %s\n"%offset
                        membersize=arg.getmembertype(member).getsize()
                        #if we're talking about an array, we want to
                        #have a pointer to the array in accum
                        #if we're talking about a structure, we want a
                        #pointer to the structure
                        #if we're talking about an int or char, we want to load
                        #that.
                        #BUGBUG:
                        #this is a bug, but we'll figure out what it really
                        #needs to be later...a new member in the ctypes perhaps?
                        if membersize<=4:
                            node.attr+="derefaccum %s\n"%membersize
                    elif node[1].type=="-" and node[2].type==">":
                        #pointer to structure deref
                        member=node[3].attr
                        varname=node[0].attr
                        (label,current, arg,location)=self.vartree.getvar(varname)
                        if location==None:
                            print "******Did not find variable %s"%varname
                        assert arg, "arg is None for varname->member=%s->%s" % (varname, member)
                        node.attr+="loadlocaladdress %s\n"%location
                        node.attr+="derefaccum %s\n"%arg.getsize()
                        offset=arg.totype.getmemberoffset(member)
                        if offset==-1:
                            print "Did not find member %s!"%member
                            raise SystemError
                        node.attr+="addconst %s\n"%offset

                        #see BUGBUG above
                        membersize=arg.totype.getmembertype(member).getsize()
                        if membersize<=4:
                            node.attr+="derefaccum %s\n"%membersize
                    else:
                        node.attr=""
                        #array
                        #print "We found an array..."
                        (label,current, arg,location)=self.vartree.getvar(node[0].attr)
                        size=arg.getitemsize()
                        node.attr+=node[2].attr
                        node.attr+="multiply %d\n"%size
                        node.attr+="accumulator2index\n"
                        node.attr+=self.loadarg(node[0].attr)
                        # XXX: derefs need size handling too on p[0] = p2[0] type stuff on big endian systems
                        node.attr+="derefwithindex %d\n"% size
                        
			if node[1].type=="isarray":
                            #print "NAME IS AN ARRAY DEREF!"
                            index=int(node[1].attr)
                            #print "INDEX=%s"%index
                            sizeoftype=4 #HARDCODED until we get a real type system
                            #right now this only works for integer indexes
                            #we also need to handle variables...
                            if index!=0:
                                node.attr+="addconst %d\n"%(index * sizeoftype) 
                else:
                    #normal variable
                    #the issue here is that if we load a pointer, we want to store that pointer
                    #data type so we can += it properly
                    #devlog("MOSDEF","Is this a NULL pointer? %s"%node[0].attr)
                    if node[0].attr=="None":
                        #we are a pointer type, but the user passed in None as our pointer
                        #so we load a null pointer here
                        node.attr="loadint %d\n"%0
                    else:    
                        node.attr=self.loadarg(node[0].attr) #normal variable                            
                        node.lastloaded=self.lastloaded
            
            elif node[0].type=="leftvalue":
                #print "leftvalue = %s"%node[0].attr
                #print "node[1].attr= %s"%node[1].attr
                #print "node[2].attr= %s"%node[2].attr
                op=node[1].attr
                #We need to add addition and subtraction here...
                if op=="=":
                    #print "Found = assign expression"
                    node.attr=node[2].attr+node[0].attr
                else:
                    print "Don't understand op = %s in leftvalue"%op
            elif node[0].type=="rightvalue":
                #rightvalue op rightval
                op=node[1].attr
                #print "rightvalue found op= ->%s<-"%op
                if op=="+":
                    node.attr+="rem found + operator\n"
                    #a=b+c
                    node.attr+=node[2].attr #load "c" to accum
                    try:
                        lastarg=node[0].lastloaded
                        if lastarg!=None:
                            name=lastarg.name
                            node.attr+="rem lastloaded=%s\n"%name
                            if name=="pointer":
                                totype=lastarg.totype
                                size=totype.size
                                node.attr+="rem size of pointer argument %s: %d\n"%(name,size)
                                node.attr+="multiply %d\n"%size   
                        else:
                            node.attr+="rem lastloaded=None\n" 
                    except AttributeError:
                        pass
                    
                    node.attr+="pushaccum\n" #save "c" to stack (for better code, use register as bottom of stack)
                    node.attr+=node[0].attr #load "b" into accum
                    node.attr+="poptosecondary\n" #pop "c" to a secondary register
                    node.attr+="addsecondarytoaccum\n" #add secondary register to accumultator
                elif op=="-":
                    node.attr=""
                    node.attr+=node[2].attr
                    node.attr+="pushaccum\n" #save to secondary register
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="subtractsecondaryfromaccum\n" 
                elif op=="%":
                    node.attr=""
                    node.attr+=node[2].attr
                    node.attr+="pushaccum\n" #save to secondary register
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="modulussecondaryfromaccum\n" 
                elif op=="/":
                    node.attr=""
                    node.attr+=node[2].attr
                    node.attr+="pushaccum\n" #save to secondary register
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="dividesecondaryfromaccum\n" 
                elif op in ["<",">","!=","=="]:
                    node.attr=""
                    node.attr+=node[2].attr
                    node.attr+="pushaccum\n" #save to secondary register
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="compare\n"  #sets flag registers
                    if op=="<":
                        node.attr+="setifless\n"
                    elif op==">":
                        node.attr+="setifgreater\n"                        
                    elif op=="!=":
                        node.attr+="setifnotequal\n"
                    elif op=="==":
                        node.attr+="setifequal\n"
                elif op=="&&":
                    node.attr=""
                    node.attr+="rem && found\n"
                    node.attr+=node[0].attr #first arg
                    #accumulator is either true or 0 
                    node.attr+="pushaccum\n" #save accumulator from first arg
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a zero to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifequal\n" #set accum=1 if node[0]==false
                    node.attr+="pushaccum\n" #push this value for later
                    #stack = [ node[0] is true ]

                    node.attr+="rem node[2].attr start\n"
                    node.attr+=node[2].attr #second arg
                    node.attr+="rem node[2].attr end\n"

                    node.attr+="pushaccum\n" #save
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a zero to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifequal\n" #accum has our value
                    
                    node.attr+="poptosecondary\n" #pop original value to a secondary register
                    #stack = [] 
                    node.attr+="addsecondarytoaccum\n" #add them together, if we have 1, someone was false
                    node.attr+="rem final compare to key value here \n"
                    #now we compare the result of that with our key value
                    node.attr+="pushaccum\n" #save
                    #stack = [node[0] is true + node[2] is true]
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a value into accumulator to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifequal\n" #if everyone was true, then our accum at this point will be 0, and hence, we set if==0
                    
                elif op=="||":
                    node.attr=""
                    node.attr+=node[0].attr #first arg
                    node.attr+="pushaccum\n" #save 
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a zero to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifnotequal\n" #accum has our value
                    node.attr+="pushaccum\n" #push this value for later
                    
                    node.attr+=node[2].attr #second arg
                    node.attr+="pushaccum\n" #save
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a zero to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifnotequal\n" #accum has our value
                    node.attr+="poptosecondary\n" #pop original value to a secondary register
                    node.attr+="addsecondarytoaccum\n" #add them together, if we have 0, we are false
                    #now we compare the result of that with 0
                    node.attr+="pushaccum\n" #save
                    node.attr+="poptosecondary\n" #pop to a secondary register
                    node.attr+="loadint 0\n" #load a zero into accumulator to compare with
                    node.attr+="compare\n"  #sets flag registers
                    node.attr+="setifnotequal\n" #accum has our final value
                    
                elif op=="<<":
                    node.attr=node[2].attr 
                    node.attr+="pushshiftreg\n" #push %ecx
                    node.attr+="pushaccum\n" #push %eax
                    node.attr+=node[0].attr #load value
                    node.attr+="poptoshiftreg\n" #pop %ecx
                    node.attr+="shiftleft\n" #SHL %cl, %eax
                    node.attr+="poptoshiftreg\n"#pop %ecx
                elif op==">>":
                    node.attr=node[2].attr 
                    node.attr+="pushshiftreg\n" #push %ecx
                    node.attr+="pushaccum\n" #push %eax
                    node.attr+=node[0].attr #load value
                    node.attr+="poptoshiftreg\n" #pop %ecx
                    node.attr+="shiftright\n" #SHR %cl, %eax
                    node.attr+="poptoshiftreg\n"#pop %ecx
                elif op=="&":
                    node.attr=node[2].attr
                    node.attr+="pushaccum\n"
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n"
                    node.attr+="andaccumwithsecondary\n"
                elif op=="^":
                    node.attr=node[2].attr
                    node.attr+="pushaccum\n"
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n"
                    node.attr+="xoraccumwithsecondary\n"
                elif op=="|":
                    node.attr=node[2].attr
                    node.attr+="pushaccum\n"
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n"
                    node.attr+="oraccumwithsecondary\n"
                elif op=="*":
                    node.attr=node[2].attr
                    node.attr+="pushaccum\n"
                    node.attr+=node[0].attr
                    node.attr+="poptosecondary\n"
                    node.attr+="multaccumwithsecondary\n"
                else:
                    print "ERROR: op %s not recognized"%op
            
            elif node[0].type=="asterisk":
                #dereference a pointer
                node.attr=""
                argname=node[1].attr
                node.attr+=self.loadarg(argname)
                node.lastloaded=self.lastloaded
                (label,current, arg,location)=self.vartree.getvar(argname)
                node.attr+="derefaccum %s\n"%arg.totype.getsize()
            elif node[0].type=="ampersand":
                #this is likely only moderately correct.
                node.attr=""
                argname=node[1].attr
                (label,current, arg,location)=self.vartree.getvar(argname)
                if location==None:
                    print "Fatal Error!!! Did not find variable %s"%argname
                node.attr+="loadlocaladdress %s\n"%location
            else:
                print "ERROR? rightvalue type = %s"%node[0].type
        
        def n_leftvalue(self,node):
            #load whatever's in the accumulator into the variable
            argname=node[0].attr
            #print "loading variable %s"%argname
            #print "leftvalue(%s)"%argname
            ispointer=0
            if argname=="*":
                #pointer deref
                argname=node[1].attr
                ispointer=1
            #print "Argname=%s"%argname
            (label,current, arg,location)=self.vartree.getvar(argname)
            if current==None:
                self.logerror("Could not find variable %s"%argname)
            #print "[%s] arg [%s]"%(current,arg)
            
            if current=="globals":
                #print "Current is globals..."
                node.attr="accumulator2memoryglobal %s %s\n"%(arg[0], self.getTypeSize(arg[1]))
            elif current=="number":
                #this is weird - should this ever happen?!? I think all
                #numbers should be rightvalues
                #print "leftvalue found number=%s"%arg
                node.attr="loadint %s\n"%(arg)
            else:
                #print "Length of node is %s"%len(node)
                if len(node)==4:
                    #print "Length of node is 4..."
                    if node[1].attr=="[":
                        #we are an array that we are loading. Such as j[1]=1, etc.
                        #we need to store off the accumulator into a temporary variable
                        #We put the index into the array in the accumulator
                        node.attr=""
                        node.attr+="storeaccumulator\n"
                        node.attr+=node[2].attr #load the accumulator with the result of the expression
                        #now we need to multiply by the size of our variable
                        node.attr+="multiply %d\n"%arg.getitemsize()
                        node.attr+="accumulator2index\n"
                        argload=self.loadarg(argname)
                        node.attr+=argload
                        node.attr+="storewithindex %d\n"%arg.totype.getsize() #from the stored accumulator
                    elif node[1].attr=="-" and node[2].attr==">":
                        #print "Pointer to a structure deref"
                        
                        #something like: name->name = 44;
                        member=node[3].attr
                        varname=node[0].attr
                        node.attr="rem pointer %s->%s deref\n"%(varname,member)
                        node.attr+="storeaccumulator\n" #save off eax for later
                        
                        #now load the address we want to store into
                        (label,current, arg,location)=self.vartree.getvar(varname)
                        if location==None:
                            print "******Did not find variable %s"%varname
                        node.attr+="loadlocaladdress %s\n"%location #
                        node.attr+="derefaccum %s\n"%arg.getsize()
                        offset=arg.totype.getmemberoffset(member)
                        if offset==-1:
                            print "Did not find member %s!"%member
                            raise SystemError
                        node.attr+="addconst %s\n"%offset
                        #the address of the variable we want to save into is now in the accumulator
                        
                        membersize=arg.totype.getmembertype(member).getsize()
                            
                        #now store into that address
                        node.attr+="accumulator2index\n" #load edx with our actual address
                        node.attr+="loadint 0\n" #index is 0
                        node.attr+="storewithindex %d\n"%membersize #from the stored accumulator                            
                        node.attr+="rem Done with store.\n"
                    else:
                        print "Unknown 4 length in leftvalue!"
                else:
                    if ispointer:
                        node.attr=""
                        node.attr+="storeaccumulator\n"
                        node.attr+="loadint 0\n" #index is 0
                        node.attr+="accumulator2index\n"
                        argload=self.loadarg(argname)
                        node.attr+=argload
                        node.attr+="storewithindex %d\n"%arg.totype.getsize() #from the stored accumulator
                    elif arg.name=="struct":
                        membername=node[2].attr
                        offset=arg.getmemberoffset(membername)
                        size=arg.getmembertype(membername).getsize()
                        node.attr="rem Saving into struct member %s\n"%membername
                        node.attr+="accumulator2memorylocal %s %s\n"%(location-offset,size)
                    else:
                        #we are a normal variable to load
                        node.attr=""
                        node.attr+="rem Saving into normal variable name=%s \n"%argname
                        node.attr+="accumulator2memorylocal %s %s\n"%(location, self.getTypeSize(arg))
        
        def n_statements(self,node):
            node.attr=""
            for n in node:
                #print "Type=%s"%n.type
                if n.type not in ["whitespace",";","return"]:
                    node.attr+=n.attr
            return
        
        def n_insidestmt(self,node):
            #print "insidestatement: %s"%node[0].type
            node.attr=""
            if node[0].type=="functioncall":
                node.attr+=node[0].attr
            elif node[0].type=="leftvalue":
                node.attr+=node[0].attr
            elif node[0].type=="rightvalue":
                #print "print len(node)=%d node[0].attr=%s"%(len(node),node[0].attr)
                #node.value2+=node[0].attr
                node.attr=node[0].attr
            elif node[0].type=="return":
                # XXX wtf... XXX
                if len(node)>1 and node[1].type!="whitespace":
                    node.attr+=node[1].attr
                here_just_jump_to_epilog_and_remove_that_code = True
                if here_just_jump_to_epilog_and_remove_that_code:
                    node.attr += "rem   <BROKEN EPILOG> from return_in_statement\n"
                    if self.stacksize:
                        node.attr+="freestackspace %d\n"%self.stacksize
                    argsize=self.argsize*self.pointersize
                    node.attr+="functionpostlude %s\n" % argsize # XXX
                    node.attr+="ret %s\n"%argsize
                    node.attr += "rem   </BROKEN EPILOG>\n"
                else:
                    epilog_addr = self.getcurrentfunction()
                    assert epilog_addr
                    node.attr += "jump %s_epilog\n" % epilog_addr
            
            else:
                #print "HAVE NO IDEA WHAT KIND OF INSIDESTMT THAT IS! %s"%node[0].type
                pass
        
        def n_quotedchar(self, node):
            node.type="number"
            attr = node.attr[1:-1]
            if len(attr) == 1:
                node.attr = str(ord(attr))
            elif len(attr) == 2:
                if attr[0] == '\\' and attr[1] in self.__bt:
                    node.attr = str(ord(self.__bt[attr[1]]))
                else:
                    raise AssertionError
            elif attr[:2] == "\\x":
                node.attr = "0%s" % attr[1:]
            else:
                raise AssertionError
        
        def n_number(self,node):
            node.exprType="number"
            node.attr=node[0].attr
            if len(node)>1:
                #account for - signs
                node.attr+=node[1].attr
        
        def n_arg(self,node):
            node.exprType="arg"
            node.type="arg"
            node.attr=node[0].attr
        
        def n_blockstart(self,node):
            #starts a block, and if there is an argument list, resolves that into variables
            #print "Block started"
            label=self.getLabel()
            self.vartree.down(label)
            if self.argumentlist!=None:
                self.resolveArgList()
                self.argumentlist=None
        
        def n_blockend(self,node):
            self.vartree.up()
        
        def n_arrayvals(self,node):
            if len(node)>0:
                node.attr=node[1].attr
                node.type="isarray"
                return
            node.attr=None
            node.type="isnotarray"
            return
        
        def n_argdeclare(self,node):
            """
            Creates a ctype object from our node, since our node must be a valid 
            ctype
            """
            node.exprType="argdeclare"
            typedef_node=node[0]
            name_node=node[1]
            if typedef_node.type=="struct":
                node.myctype=typedef_node.myctype
                node.argname=typedef_node.attr
            elif typedef_node.type=="ctype":
                node.myctype=node[0].myctype
                node.argname=node[1].attr
            else:
                print "SOME WACKY KIND OF ARGDECLARE ARGS %s"%typedef_node.type 
            return
        
        def n_variabledeclare(self,node):
            
            #print "Variable declare found"
            #print "Allocated: %d"%node[0].size
            #now that we know what it is, we need to add this to the current function's size
            addr=self.allocateStackSpace(node[0].size)
            self.addvariable(addr,node[0].name,node[0].type)
        
        def n_variabledefine(self,node):
            #should not allocate stack space when used as part of a 
            #struct structtype { }; !!!
            
            #print "Variable declare found"
            
            isarray=0
            type=node[0].myctype
            name=node[0].argname
            
            #print "TYPE: %s"%node[0].myctype
            #print "name: %s"%node[0].argname
            if node[1].type=="isarray":
                isarray=1
                #print "Array found!"
                #print "node[2].attr=%s"%node[2].attr
                arraysize=int(node[1].attr)
                #print "arraysize=%d"%arraysize
                type=carray(type,arraysize)
            
            node.type=type
            node.name=name
            #varsize=node.type.getsize()
            varsize=node.type.getstacksize() #getstacksize is aligned properly!
            #print "%s is type %s with size %s"%(name,type,varsize)
            
            node.size=varsize
            
            return #ooooh, done!
        
        def n_functioncallarglist(self,node):
            #print "Arglist found"
            node.exprType="functioncallarglist"
            node.attr=[]
            for n in node:
                if n.type=="arg":
                        node.attr+=[n.attr]
                if n.type=="functioncallarglist":
                        node.attr+=n.attr
            #print "Functioncallarglist: %s"%node.attr
        
        def n_functioncall(self,node):
            node.attr=""
            #print "Functioncall"
            functionname=node[0].attr
            arglist=node[2]
            length=len(arglist.attr)
            devlog("cparse::functioncall", "Function call %s (%d args)" % (functionname, length))
            #print "length", length, arglist.attr
            if length:
                devlog("cparse::functioncall", "<%d ARGS>" % (length - 1))
                for i in range(length-1,-1,-1):
                    devlog("cparse::functioncall", "ARGS#%d: %s" % (i, arglist.attr[i]))
                    #self.value2+=self.pusharg(arglist.attr[i],i)
                    #print "%s"%arglist.attr
                    #node.attr+="".join(arglist.attr) #a list?!?
                    node.attr+=arglist.attr[i] #a list?!?
                    node.attr+=self.pushargfromaccumulator(i)
                devlog("cparse::functioncall", "</%d ARGS>" % (length - 1))
            
            #print "Functionname is %s"%functionname
            #if this is a remote function, then we need to call it the hard way
            # with mov LABEL-geteip(%ebx), %eax
            # call eax
            # but if this is a local function
            # we can just call it
            (label,current,var,location)=self.vartree.getvar(functionname)
            if current==None or var==None:
                #we have a local function call
                node.attr+="call %s %s\n" % (functionname, length)
            else:
                #global function pointer
                #load a word from the offset from the LABEL-geteip(%ebx)
                #devlog("cparse","Loading global...%s"%var.label)
                node.attr+="loadglobaladdress %s\n"%(var.label)
                node.attr+="derefaccum %s\n"%(var.totype.getsize())
                #call the accumulator %eax or %l0
                node.attr+="callaccum\n"
        
        def n_file_contents(self,node):
            node.attr=""
            if len(node)>0:
                for n in node:
                    node.attr+=n.attr
        
        def n_file_input(self,node):
            self.value+=node[0].attr
        
        def n_stmt(self,node):
            #print "Statement found"
            node.attr=node[0].attr
        
        def n_directive(self,node):
            node.attr=node[0].attr
        
        def n_codeblock(self,node):
            node.attr=node[3].attr
        
        def n_functiondeclare(self,node):
            name=node[2].attr
            argsize=node[4].argsize*self.pointersize
            self.setcurrentfunction(name)
            
            node.attr=""
            node.attr+="\nrem\nrem Found function declare %s (stack = %d)\nrem\n"%(name,self.stacksize)
            node.attr+="\nlabeldefine %s\n"%name
            # PROLOG
            node.attr+="functionprelude\n"
            if self.stacksize!=0:
                node.attr+="getstackspace %d\n"%self.stacksize
            
            # BODY
            node.attr+=node[6].attr
            
            # EPILOG
            node.attr += "rem   <EPILOG of %s>\n" % name
            #node.attr += "labeldefine %s_epilog\n" % name
            if self.stacksize!=0:
                node.attr+="freestackspace %d\n"%self.stacksize
            node.attr+="functionpostlude %s\n" % argsize
            #print "Type [4] is %s"%node[4].type
            #this is totally bunk right here - wait no its not
            #ok
            #we need to revisit args once more
            node.attr+="ret %s\n"%argsize # XXX argsize should not be cleaned here but in postlude
            node.attr += "rem <end of %s> (end of epilog)\n" % name
            self.stacksize=0
        
        def n_asterisklist(self,node):
            node.asterisklength=1
            if len(node):
                node.asterisklength+=node[1].asterisklength
        
        def n_typedef(self,node):
            """
            typedef ::= name
            typedef ::= signed typedef
            typedef ::= unsigned typedef
            typedef ::= short typedef
            typedef ::= long typedef
            typedef ::= struct typedef
            typedef ::= typedef *
            """
            self.exprType="typedef"
            
            if len(node)==1:
                node.type="name"
                node.attr=node[0].attr
                node.myctype=self.varcache.gettype(node.attr)
                return
            
            node.type="ctype"            
            #print "node[1].type=%s"%node[1].type
            if node[1].type=="asterisklist":
                pointerlength=node[1].asterisklength
                #print "pointerlist length=%d"%pointerlength
                
                node.totype=node[0].attr
                node.myctype=self.varcache.gettype(node.totype)
                pointerlength=pointerlength-1
                for i in range(0,pointerlength):
                    node.myctype=cpointer(node.myctype)
                return
            
            if node[0].type in ["long","short","signed","unsigned"]:
                #some kind of integer
                attr=[]
                node.myctype=cint()
                for n in node:
                    if n.type in ["long","short","signed","unsigned"]:
                        attr.append(n.type)
                    if n.type=="ctype":
                        node.myctype=n.myctype
                node.myctype.setattr(attr)
                
                
            if node[0].type=="struct":
                structname=node[1].attr
                #print "Getting struct: %s"%structname
                myctype=self.varcache.gettype(structname)
                if myctype==None:
                    print "WACKY ERROR: No %s in cache!"%structname
                else:
                    pointerlength=node[2].asterisklength-1
                    for i in range(0,pointerlength):
                        myctype=cpointer(myctype)
                    node.myctype=myctype
            return
        
        def n_argumentlist(self,node):
            #print "***argumentlist"
            node.args=[]
            node.argsize=0
            
            for n in node:
                if n.type=="argdeclare":
                    type=n.myctype
                    name=n.argname
                    node.argsize+=1
                    #print "%s: %s"%(type,name)
                    node.args+=[(type,name)]
                elif n.type=="argumentlist":
                    #print "Previous node's size is %d"%node[0].argsize
                    node.argsize+=n.argsize
                    node.args+=n.args
                else:
                    #print "What kind of type of argumentlist is %s"%n.type
                    pass
            #print "new args=%s"%(node.args)
            #set this so when we start a block we can resolve all the variables
            #print "Self.argumentlist..."
            self.argumentlist=node
            self.argsize=node.argsize
            #we globalize this so that you can call return X; and we still know it...
            #print "argsize=%s"%self.argsize
            return 
        
        def n_includedirective(self,node):
            #include a C header file
            node.attr=""
            
            if node[1].attr[0] == '"':
                #[1:-1] is to strip off the quotes
                includename = node[1].attr[1:-1]
            else:
                includename = node[1].attr
            
            if includename not in self.importedlocals:
                #print "includename not found %s"%includename
                self.importedlocals[includename]=1
                value,suffix=self.remoteresolver.getlocal(includename,self.importedlocals)
            else:
                #print "includename found: %s"%includename
                #print "self.varcache=%s"%self.varcache.getAllTypes()
                value,suffix=self.remoteresolver.getlocal(includename,self.importedlocals)
                #I don't understand why this is the same as the other case! But
                #it only works this way...
                #already imported this...
                #hmm...this isn't right.
                #return
            
            #suffix is a list of the new types
            for t in suffix:
                typestr,atype=t
                #print "Finding %s in typecache"%typestr
                if not self.varcache.hastype(typestr):
                    #print "Adding %s to typecache"%typestr
                    self.varcache.addtype(typestr,atype)
        
        def n_importdirective(self,node):
            
            TODO = """
            ok this is a core function, hard to play with that.
            imo we shouldn't every importname to self.vartree, but some self.vartreecache
            and if a call to self.vartree.getvar(varname) raise some AttributeError exception,
            then we get the var from self.vartreecache, and add content to node.postattr string.
            at the end, on self.get(), we return node.attr + node.postattr
            so we only link piece of code reached and save space and compilation errors.
            """
            #[1:-1] is to strip off the quotes
            importtype=node[1].attr[1:-1]
            importname=node[3].attr[1:-1]
            importdest=node[5].attr[1:-1]
            importlabel=self.getLabel()
            node.attr=""
            #print "Import directive found %s:%s:%s:%s"%(importtype,importname,importdest,importlabel)
            node.attr+="rem Import directive found %s:%s:%s:%s\n"%(importtype,importname,importdest,importlabel)
            #if importtype=="remote":
            #    print "REMOTE IMPORT: %s"%importname
            #    if self.getRemoteFunctionCached(importname):
            #        #we've already found this function
            #        return
            
            #ok, now we need to add a global variable
            node.attr+="labeldefine %s\n"%importlabel
            
            if importtype=="remote":
                #a remote is a remote function pointer
                #win32 function pointers are given to us in msvcrt.dll|functionname style (notice the pipe)
		
                mycglobal=cglobal(cpointer(cint()))
                mycglobal.setLabel(importlabel)
                self.addvariable(importlabel,importdest,mycglobal)
                
                node.attr+="longvar %s\n"%uint32fmt(self.getRemoteFunction(importname))
                self.addToRemoteFunctionCache(importname)
                
            elif importtype=="string":
                #eh?
                var=self.getLocalVariable(importname)
                if var in [None,0]:
                    #null pointer - treat as integer
                    mycglobal=cglobal(cint())
                    mycglobal.setLabel(importlabel)
                    self.addvariable(importlabel,importdest,mycglobal)
                    node.attr+="longvar %s\n"%uint32fmt(0) #null is always 0, we assume

                else:

                    #globals don't get a size - they don't modify esp
                    mycglobal=cglobal(carray(cchar(),len(var)+1))
                    mycglobal.setLabel(importlabel)
                    self.addvariable(importlabel,importdest,mycglobal)
                    node.attr+="urlencoded %s\n"%urllib.quote(var)
                    node.attr+="databytes 0\n"
                    node.attr+="archalign\n"
                
            elif importtype=="int":
                mycglobal=cglobal(cint())
                mycglobal.setLabel(importlabel)
                var=self.getLocalVariable(importname)
                if type(var) not in [type(0), type(0L)]:
                    #string type as integer?!
                    devlog("cparse","Found non-integer type for integer variable! %s=%s"%(importname,var))
                self.addvariable(importlabel,importdest,mycglobal)
                try:
                    node.attr+="longvar %s\n"%uint32fmt(var)
                except TypeError, emsg:
                    raise SystemExit, "unable to find integer \"%s\"" % importname
                
            elif importtype=="local":
                if self.remoteresolver==None:
                    print "Cannot do local importation when remoteresolver is None!"
                else:
                    #prevent dual-importation
                    if importname not in self.importedlocals:
                        
                        self.importedlocals[importname]=1
                        #print "import", importname,"========================================================"
                        value,suffix=self.remoteresolver.getlocal(importname,self.importedlocals)
                        node.attr+=value+suffix
			#print "VALUE:",value
			#print "SUFIX:",suffix
                        #self.suffix+=suffix
            else:
                
                print "Import type unknown: %s"%importtype


def preprocess(data):
        return data

def scan(data):
        myscanner=CScanner()
        tokens = myscanner.tokenize(data)
        return tokens

def parse(tokens):
        from ast import AST
        parser = cparser(AST,'file_input')
        tree=parser.parse(tokens)
        return tree

def dummyfunctionresolver(function):
        return 0x01020304

def dummyvariableresolver(variable):
        return "BOB"

def generate(tree,vars,remoteresolver=None):
        generator=ilgenerate(tree,vars,remoteresolver)
        return generator

def showtree(node, depth=0):
        if hasattr(node, 'attr'):
            print "%2d" % depth, " "*depth, '<<'+node.type+'>>',
            try:
                if len(node.attr) > 50:
                        print node.attr[:50]+'...'
                else: 
                        print node.attr
            except:
                print ""
                print "Error: attr=%s"%str(node.attr)
        else:
            print "%2d" %depth, "-"*depth, '<<'+node.type+'>>'
            for n in node._kids:
                showtree(n, depth+1)


def __crap():
        # TODO stop being dumb
        #      think a bit more modular
        #      use MOSDEFlibc.
        vars={} # XXX buggy var! (only win32|linux intel it seems)
        vars["dir"]="./"
        vars["command"]="/usr/bin/id"
        vars["argument"]="-a"
        vars["filename"]="/etc/passwd"
        vars["cmdexe"]="cmd.exe"
        vars["stdin"]=0xfff1
        vars["stdout"]=0xfff2
        vars["handle"]=0x07cc
        vars["bufsize"]=5000
        vars["socketfd"]=4
        vars["filefd"]=5
        vars["envname"]="COMSTAT"
        vars["AF_INET"]=2
        vars["SOCK_STREAM"]=1
        vars["ifname"]="lo"
        vars["port"]=9999
        import socket
        vars["addr"]=intel_str2int(socket.inet_aton("127.0.0.1"))
        vars["option"]=2 #SO_REUSEADDR
        vars["arg"]=1
        vars["sock"]=1
        vars["level"]=1 #SOL_SOCKET
        vars["length"]=1000
        vars["fd"]=155
        vars["timeout"]=1
        vars["ip"]=0x7f000001
        vars["hDomain"]=1
        vars["LPCSTRING"]="A"
        vars["PAYLOAD"]="A"
        vars["readfd"]=1
        vars["servername"]=None

def main(target, files, debug = 0):
    import mosdef
    #import profile
    
    for filename in files:
        
        try:
            data=open(filename).read()
        except:
            data=open("MOSDEF/"+filename).read()
        
        #Typecheck is basically useless since we do real checking when we generate it...
        #print "Doing typecheck"
        #typecheck=typecheck(tree)
        
        # opening remoteresolver module
        rr = mosdef.getremoteresolver(target['os'], target['proc'])
        
        vars = rr.vars
        # add your vars here now.
        vars["servername"]=None
        

        data = mosdef.preprocess(data, vars,{}, rr)
        
        tokens=scan(data)
        #print tokens
        #print "-"*50
        
        tree=parse(tokens)
        #print "-"*50
        
        #print "Showing tree"
        #showtree(tree)
        #print "-"*50
        
        #print "Doing Generation of Code"
        import time
        start=time.clock()
        '''
        x=generate(tree,vars,remoteresolver=rr)
        #         generator=ilgenerate(tree,vars,remoteresolver)

        code=x.get()
        '''
        iltime=time.clock()
        bytecodes = rr.compile(data)
        '''
        print "-"*50
        print "IL code: \n%s"%(code)
        #transform into AT&T style x86 assembly
        #then run through at&t x86 assembler
        #then done!
        #write our code to a temporary file for analysis.
        file("temp.il","w").write(code)
        il2proc = __import__("il2%s" % target['proc'].lower())
        asm = getattr(il2proc, 'generate')(code)
        '''
        asmtime=time.clock()
        '''
        print "ASM: %s"%asm
        #f=file("%s%s.s" % (target['os'], target['proc'].lower()),"wb")
        #f.write(asm)
        #f.close()
        
        bytecodes=mosdef.assemble(asm,target['proc'].upper())
        '''
        bytestime=time.clock()
        assert bytecodes, "Why is bytecodes None?"
        
        #loop for solaris
        #bytecodes= "\x10\x80\x00\x00\x01\x00\x00\x00"+bytecodes
        
        if target['os'].lower() == "linux":
            filename=filename.replace(".c","")+".exe"
            print "Making file: %s"%(filename)
            if debug:
                bytecodes = '\xcc' + bytecodes
            import makeexe
            makeexe.makelinuxexe(bytecodes, filename)
        
        print "Shellcode is %d bytes"%len(bytecodes)    
        print "Start: %f iltime:%f asmtime:%f bytestime:%f"%(start,iltime,asmtime,bytestime)

if __name__=="__main__":
    import sys
    
    list = {}
    list['win32']    = {'proc':"X86", 'os':"Win32"}
    list['linx86'] = {'proc':"X86", 'os':"Linux"}
    list['solsparc'] = {'proc':"SPARC", 'os':"Solaris"}
    list['bsdx86']   = {'proc':"X86", 'os':"bsd"}
    list['macosx']   = {'proc':"PPC", 'os':"osx"}
    
    def usage():
        print "Usage: %s [-d] <target> [file0.c file1.c ...]" % sys.argv[0]
        print "  targets:", list.keys()
        sys.exit(1)
    
    flist = ["test.c"]
    debug = 0
    while "-d" in sys.argv:
        debug = 1
        sys.argv.remove("-d")
    if len(sys.argv) < 2:
        usage()
    if len(sys.argv) > 2:
        flist = sys.argv[2:]
    
    if not list.has_key(sys.argv[1]):
        print "target not supported"
        usage()
    
    main(list[sys.argv[1]], flist, debug)
    
    #profile.run("main()","cparsestats")
    #import pstats
    #p = pstats.Stats("cparsestats")
    #p.strip_dirs().sort_stats(-1).print_stats()
    #p.sort_stats('time').print_stats()
    #p.sort_stats('calls').print_stats()
    #p.sort_stats('cumulative').print_stats()

