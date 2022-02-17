#!/usr/bin/env python

"""
cparse2.py - the C parser (second generation) for MOSDEF

This converts it to the intermediate language that then goes through
the assembler. It also will remotely resolve any needed symbols.

This requires pylex/yacc, the modified version of which we already
ship with. This version has a broken parser mode, which we just avoid
using.

"""
VERSION="1"
import sys, urllib, os

if "." not in sys.path: sys.path.append(".")
import lex2 as lex
import yacc2 as yacc
existing_lex_tables={}
existing_parse_tables={}
TABLE_PREFIX="MOSDEF%s"%(os.sep) #CANVAS
#TABLE_PREFIX="" #Standalone MOSDEF

from vartree import vartree
from mosdefutils import *
import mosdef, mosdefctypes

from internal import devlog

if "MOSDEF" not in sys.path: sys.path.append("MOSDEF")

def getClexer():
    """
	Returns a lexer for use for parsing MOSDEF C
	"""
    #debug is zero here for no debugging, one if you want debugging
    debug=0
    global VERSION
    global TABLE_PREFIX
    ##Rich todo - support canvas being run from non root dir , same for the arch parsers
    #canvas_root_directory=
    lex_table_name="%scp2_lextab_v%s"%(TABLE_PREFIX, VERSION)

    myclex=cLex()
    global existing_lex_tables
    lexer=lex.lex(myclex , debug, optimize=1, lextab=lex_table_name, pass_the_pickle=existing_lex_tables)
    existing_lex_tables=lexer.pass_the_pickle
    return lexer

class cLex(object):
    """
	Our lexer class
	"""
    #String constant - double quotes
    t_SCONST = r'\".*?\"'
    #Char constant - single quotes on single char
    t_CCONST = r'\'(?:.|\\([0abfnrtv\\]|x[a-fA-F0-9]{1,2}))\''

    # Floating literal
    t_FCONST = r'((\d+)(\.\d+)(e(\+|-)?(\d+))? | (\d+)e(\+|-)?(\d+))([lL]|[fF])?'

    # Delimeters
    t_LBRACKET  = r'\['
    t_RBRACKET  = r'\]'
    t_LPAREN    = r'\('
    t_RPAREN    = r'\)'
    t_LBRACE    = r'\{'
    t_RBRACE    = r'\}'
    t_COMMA     = r','
    t_PERIOD    = r'\.'
    t_EQUAL     = r'='
    t_SEMI      = r';'
    t_COLON     = r':'
    #t_ELLIPSIS  = r'\.\.\.'
    t_STAR      = r'\*'
    t_PERCENT   = r'\%'
    t_SUBTRACT  = r'\-'
    t_PLUS      = r'\+'
    t_DOLLAR    = r'\$'
    t_GTHAN     = r'>'
    t_LTHAN     = r'<'
    t_POUND     = r'\#'
    t_HYPHEN    = r'-'
    #t_HYPHEN    = r'\-'
    t_HEXNUMBER = r'0x[a-fA-F0-9]+'
    t_DECNUMBER = r'(?!0x)\d+'
    t_AMPERSAND = r'&'
    t_BANG = r'\!'
    t_PIPE = r'\|'
    t_CARET = r'\^'
    t_FSLASH = r'\/'
    t_TILDA = r'~'
    #Need to have seperate tokens for these otherwise the lexer identifies them as single tokens
    t_ARROW = r'\->'
    t_EQUIV = r'=='
    t_NOT_EQ = r'\!='
    t_L_SHIFT = r'<<'
    t_R_SHIFT = r'>>'
    t_AND = r'&&'
    t_OR = r'\|\|'
    t_GT_EQ = r'>='
    t_LT_EQ = r'<='
    t_INC = r'\+\+'
    t_DEC = r'\-\-'

    """
    If you got this:
    lex: Fatal error. Unable to compile regular expression rules. unbalanced parenthesis
    then that means you have r'#' instead of r'\#', for example.
    """

    #special purpose rule to ignore whitespace
    t_ignore=" \t\x0c"


    constants = ("SCONST","CCONST", "HEXNUMBER", "DECNUMBER", "QUOTEDSTRING", "QUOTEDCHAR")

    deliminators = ("LBRACKET", "RBRACKET", "LPAREN", "RPAREN", "LBRACE", "RBRACE",
                    "COMMA", "PERIOD", "SEMI", "COLON", "STAR", "PERCENT",
                    "SUBTRACT", "PLUS", "NEWLINE", "DOLLAR","GTHAN","LTHAN","POUND",
                    "HYPHEN", "AMPERSAND", "EQUAL", "BANG", "PIPE", "CARET", "FSLASH",
                    "TILDA","ARROW", "EQUIV", "NOT_EQ", "L_SHIFT", "R_SHIFT", "AND",
                    "GT_EQ", "LT_EQ", "INC", "DEC", "OR", "COMMENT")

    #literals = ("ID", "FCONST", "ICONST", "HCONST")
    literals = ("ID", "FCONST")

    #this tuple lists the ones we define in the ID parser function p_ID()
    others = ("AS","IMPORT","INCLUDE","CHAR","INT","VOID","SIGNED","UNSIGNED","STRUCT","LONG","SHORT", "INCLUDEPATH")
    others += ("IF","DO","WHILE","FOR","ELSE","VARIABLENAME","RETURN", "NULL", "STRUCT_MEMBER","BREAK")

    def __init__(self):
        """
        This function is responsible for setting up the tokens tuple.
        """
        self.tokens = self.constants+self.literals+self.deliminators+self.others

        ###Reserved words - put here with help of hotspot optimisation - lets only build the dictionary once ....
        self.valdict={}

        vallist=["char","int","void","signed","unsigned","as","import","include","short","struct","long"]
        vallist+=["if","do","while","for","else","return"]
        vallist+=["break"]

        for a in vallist:
            self.valdict[a]=a.upper()

        self.vartree = vartree() #this will be overwritten by the parser if we have one!
        return

    def t_NEWLINE(self,t):
        r'\n+'
        t.lineno += t.value.count("\n")
        return

    def t_COMMENT(self, t):
        ##Skip comment lines beginning with '//' and ending with a NEWLINE
        r'//.*?\n'
        t.lineno += 1


    def t_error(self,t):
        print "Illegal character %s" % repr(t.value[0])
        t.lexer.skip(1)

    def set_vartree(self, newvartree):
        self.vartree=newvartree
        return

    def t_ID(self,t):
        #
        #Many types of Identifiers so we have to choose which we are: variable, inbuilt func,
        #     declaration etc. Return the appropriate token type
        #
        r'[.]?[A-Za-z_]+[\w_]*'

        #valdict={}

        #vallist=["char","int","void","signed","unsigned","as","import","include","short","struct","long"]
        #vallist+=["if","do","while","for","else","return"]

        #for a in vallist:
            #valdict[a]=a.upper()

        value = t.value
        #print "ID value is : %s"%value

        if value in self.valdict.keys():
            ##Return uppercase version of the token value as it was found in our valuelist above
            #print "Found %s in reserved word list"%(valdict[value])
            t.type=self.valdict[value]
            return t

        varret=self.vartree.getvar(value)
        if varret[3]!=None:
            #we did have it in the vartree!
            #print "Variable identified in vartree"
            t.type="VARIABLENAME"
        elif value == 'NULL':
            ##Special case for NULL ??? -------------------is this right TODO
            t.type="number"
            t.type="VARIABLENAME"
        elif value[0] ==".":
            ##Special case for structure members ......
            t.type="STRUCT_MEMBER"
            ##And remove proceeding '.' DOT from member name
            t.value=value[1:]

        else:
            #print "Output ID"
            t.type = "ID"
        #print t.type
        return t

    def t_INCLUDEPATH(self, t):
        #Include path can be <foo.h> or "foo.h", but either we want to return a consistent
        # token not an t_ID for one (with angle brackets) and a
        # t_SCONST for the other (with quotes)
        r'</*[a-zA-Z0-9_./]+\.h>|"/*[a-zA-Z0-9_./]+\.h"'

        #remove quotoes from start & end
        if t.value[0] == '"':
            t.value=t.value[1:-1]
        return t

def testLexer():
    filename=None
    if len(sys.argv)>1:
        filename=sys.argv[1]
    else:
        print "Usage: cparse2.py <filename>"
        sys.exit(1)

    #print "Testing lexer on %s"%filename
    #print "_"*70
    myLexer=getClexer()

    data=file(filename, "r").read()

    myLexer.input(data)
    while 1:
        token=myLexer.token()
        #print "Token=%s" % (token)
        if not token: break
    #print "_"*70+"\n"+"Tested lexer"


    #Rich 02/10/08 - show vartree
    #myLexer.module.vartree.dump_tree()

    return

#End Lexer routines
#############################################3
#parser routines

class cthing(object):
    """
    Holder for things you use as p[0]
    """
    def __init__(self, value=None):
        ##This holds any IL generated
        if not value:
            self.value=[]
        else:
            self.value=value

        ##If we are good and fill this in for each cthing we use we actual stand
        ## a chance of seeing the route we have taken through the forest of p_* functions
        self.passed_from=[]

        ##This will also help us to choose branching in the functions as we will
        ## have a 'type' associated with the p[*] arguments. Types should be named
        ## after the function the p[0] came from e.g. p[0] returned from p_number
        ## should have cthing.type="number"
        self.type=""

#import traceback
import random
class CParse2(object):
    """
    Our parser for MOSDEF-C
    """
    def set_lexer(self):
        ##get a fresh lexer
        self.lexer=getClexer()
        self.tokens = self.lexer.lextokens.keys()

        self.tokenizer = self.lexer.module
        self.tokenizer.set_vartree(self.vartree)

        ##special escaped characters
        self.__bt = {'n':'\n', '\\':'\\'}

    def __init__(self, not_libc=1, imported=None, pointersize=4, remoteresolver=None, vars=None, LP64=False):

        ##Set the name of the parse table we read/write to disk
        global VERSION
        global TABLE_PREFIX

        if remoteresolver:
            remoteresolver.parse_table_name="%scp2_parsetab_v%s"%(TABLE_PREFIX, VERSION)

        #print "cparse2 using LP64=",LP64,"with pointersize=",pointersize

        #set up a namespace we share with our lexer
        self.vartree=vartree()
        self.set_lexer()

        self.not_libc=not_libc
        self.value= [] #join this with "" to get the intermediate language!
        self.do_prelude=False
        self.chunk_count=0

        ##break exit
        self.lastloopstmt = []

        #For use in p_decalrefunction - atm
        self.pointersize=pointersize
        self.arglist_len=0 #Once finished with this must get reset to 0
        self.argumentlist=[]  #Likewise need to blank this list when we exit the function
        self.stacksize=0
        self.func_stackspace=0 #reset to 0 after func declared
        self.lastloaded=None
        self.LP64=LP64

        self.new_label=0
        random.seed()
        self.cookie=random.randint(1,500000)+random.randint(1,500000)+random.randint(1,500000)

        self.nest(vars, imported,remoteresolver)

    def nest(self, vars, imported, remoteresolver=None):
        """
        Sets up our environment, this needs to be called for each nested parse operation that requires
        new vars||resolver||imported i.e when #imports are used in mosdef.py compile/compile_to_IL methods
        """
        if imported:
            self.importedlocals=imported
        else:
            self.importedlocals={}

        if remoteresolver:
            ##set new resolver
            self.setRemoteResolver(remoteresolver)

        self.vars=vars
        self.varcache=mosdefctypes.varcache()

        if not imported and self.not_libc:
            self.do_prelude=True

    ###-----------General Functions -------------------------

    def get_cthing(self, thing_type=None, parents=None, value=None):
        """
        generate a new cthing object for a p_* function
        """
        if not parents:
            parents = []
        ##Work out who called us, so we can use that's functions name automagically
        #Removed cuz its slow
        #if not thing_type:
            ##print "no name passed in, working it out"
            ##name_of_calling_function=traceback.extract_stack()[-2][2]
            #name_of_calling_function="Breakme"
            ###Get rid of p_ prefix
            #thing_type=name_of_calling_function[2:]

        new=cthing(value)
        new.type=thing_type
        new.passed_from=[thing_type]
        new.passed_from.extend(parents)

        #devlog('cparse2','New cthing object for %s'%(thing_type))

        return new

    def graft_cthing(self, old ,new=None, thing_type=None):
        """
        This joins two cthings together so as to create a lineage of where a
        'current' cthing has come from. It maintains the passed_from chain easily.
        NOTE: variable name in the OLD cthing overide variables in the NEW if both old & new are passed in
        e.g.
        p[0]=self.graft_cthing(p[1])
        or
        p[0]=self.get_cthing()
        self.graft_cthing(p[1], p[0])
        """

        if not new:
            ###No new cthing passed in so we just swap out the type of the old one
            #Removed cuz its slow
            ##calling_func=traceback.extract_stack()[-2][2]
            #calling_func="breakme"
            #old.type=calling_func[2:]
            old.type=thing_type
            ###Add in the new node to the history
            old.passed_from=[thing_type]+old.passed_from

        else:
            ##Prefix new history to old
            old.passed_from=new.passed_from+old.passed_from
        #devlog('cparse2','cthings grafted, family tree looks like: %s'%(old.passed_from))
        return old

    def logerror(self,message):
        print "CPARSE2 ERROR: %s"%message
        raise LookupError, message

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
        devlog("remote", "Get remote function: %s"%functionname)
        if self.remoteresolver==None:
            self.logerror("No remote function resolver!")
#		try:
        return self.remoteresolver.getremote(functionname)
#		except Exception, err:
#			print "YYYYY[%s] %s"%(err, dir(self.remoteresolver))
#			traceback.print_tb()

    def getLocalVariable(self,variable):
        devlog("cparse2", "getLocalVariable: variable=%s vars= %s defines=%s"%(variable, str(self.vars)[:50], str(self.remoteresolver.defines)[:10]))
        assert self.vars.has_key(variable), "variable %s not defined." % variable
        return self.vars[variable]


    def setcurrentfunction(self, fn):
        """
        Set up the vartree for our new function
        """
        self.addfunction(None, fn)

    def addfunction(self, label, fn):
        self.tokenizer.vartree.addfunction(label, fn)

    def addvar(self, label, v_name, v_type):
        self.tokenizer.vartree.addvar(label, v_name, v_type)

    def getvar(self, v_name):
        value=self.tokenizer.vartree.getvar(v_name)
        return value

    def dumpvars(self):
        ##Dump out the entire var tree for debugging
        self.tokenizer.vartree.dump_tree()

    def allocate_stack_space(self, size):
        ##Total stackspace
        tmp=self.stacksize
        self.stacksize+=size
        ##Stackdpace for this function, reset to 0 at end of p_functiondeclare
        self.func_stackspace+=size

        return tmp

    def get_label(self):
        """
        Generate new unique function label for use in vartree
        """
        self.new_label+=1
        lbl="LABEL%d_%d"%(self.new_label, self.cookie)
        devlog("cparse2","New Label looks like: %s"%(lbl))
        return lbl

    def get_endlabel(self):
        if self.lastloopstmt == []:
            return self.get_label()
        else:
            return self.lastloopstmt.pop()

    def gettypes(self):
        return self.varcache.getAllTypes()

    def getTypeSize(self,type):
        return type.getsize()

    def loadarg(self,argname):
        """
        for any given value, load it into the accumulator
        """
        devlog("cparse2","loadarg(%s)"%argname)
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
        devlog("cparse2", "loading argument: %s"%current)
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

    def arg_to_register(self, argnum):
        """
        This is useful when the calling conventions of the target architecture
        call for passing function arguments in registers instead of the stack.

        In that case, and assuming that the value we want to pass has been
        loaded in the register that is considered by mosdef as the accumulator
        (r13 for amd64), argnum should be used to keep a count and determine
        which register to use next.

        From amd64 ABI:
        The next available register of the sequence %rdi, %rsi, %rdx, %rcx, %r8
        and %r9 is used. Using this scheme, rdi corresponds to argnum = 0,
        rsi to argnum = 1 and so on.
        """
        return "argtoreg %d\n" % argnum

    def pushargfromaccumulator(self, argnum):
        return "arg %d\n" % argnum

    def resolveArgList(self):
        """
        takes the current argument list and gets the arguments for it as space on the stack
        or as a register or whatever
        """
        if len(self.argumentlist)==0:
            return
        i=0
        for arg in self.argumentlist:
            #print "Node.name=%s node.type=%s"%(arg[1],arg[0])
            name=arg[1]
            type=self.varcache.gettype(arg[0])
            #need to somehow get a ctype from the arg[0] (which is a string
            #representation of it)
            #valid values are, for example, char, unsigned char, int, unsigned int, struct structtype, char *, struct structtype *, unsigned int * etc
            #print "*****************************Adding arg of type %s"%type
            #we reserve the variable lables: in0-256 as input variables
            self.addvar("in%d"%i,name,type)
            i+=1
    ###-----------Parser Logic Functions----------------------

    def p_error(self, p):
        raise AssertionError, "Error parsing C data at symbol %s" % p

    #yacc.py takes the first thing and parses from there, it appears
    ##Meaning - DON'T MOVE p_statementlist or p_statement below other
    ## parse logic functions as you get a truck load of 'Symbol unreachable' errors
    def p_statementlist(self, p):
        '''statementlist : statement
           statementlist : statement statementlist
           statementlist :
        '''
        #self.value=[]
        try:
            if hasattr(p[1],"value"):
                tmp=[''.join(p[1].value)]
                self.value.insert(0,''.join(tmp ))
                self.chunk_count-=1

        except IndexError:
            print "***Blank source file"

        if self.do_prelude and self.chunk_count == 0:

            prelude='''GETPC
call main
rem <SHOULD NOT BE REACHED>
ret 0
rem </SHOULD NOT BE REACHED>
'''
            self.value.insert(0, prelude)


    def p_statement(self, p):
        '''
        statement : directive
        statement : functiondeclare
        statement : structdefine SEMI
        statement : incompletestructdefine
        '''
        p[0]=self.get_cthing(thing_type="statement")
        if hasattr(p[1],"value"):

            p[1].value=''.join(p[1].value)
            p[0].value=p[1].value
            self.chunk_count+=1

    ##DONT MOVE THE ABOVE TWO METHODS BELOW HERE ########################

    ##All other parser methods can go below here.....
    def p_arg(self, p):
        """
        arg : rightvalue
        arg :
        """
        if len(p) > 1:
            p[0]=self.graft_cthing(p[1],thing_type="arg")

    def p_arrayvals(self, p):
        #number can be negative - we should error out on that case here
        """
        arrayvals : LBRACKET number RBRACKET
        arrayvals :
        """
        if len(p)>1:
            p[0]=self.get_cthing(thing_type="arrayvals")
            ##Use the arraysize attribute to test for 'arrayness' later on
            ## - instead of setting type to "isarray" as was done in cparse.py
            p[0].arraysize=int(p[2].value[0])
            devlog("cparse2","ARRAY LENGTH: %s"%p[0].arraysize)
        else:
            p[0]=None

    def p_argumentlist(self, p):
        #argument list that is passed into a function
        """
        argumentlist : argdeclare
        argumentlist : argumentlist COMMA argdeclare
        argumentlist : VOID
        argumentlist :
        """
        p[0]=self.get_cthing(thing_type="argumentlist")
        p[0].arglist=[]

        ##How many args do we have and what tyes are they etc
        if len(p) == 1:
            ##No args given e.g. main()
            pass

        elif len(p) >2:
            ##More than one arg given in comma sep list
            p[0].arglist+= p[1].arglist
            p[0].arglist+=[(p[3].ctype, p[3].v_name)]

        elif p[1] == 'void':
            ##VOID type as in 'int main(void)'
            #p[0].arglist+=[(p[1], 'void')]
            pass

        else:
            ##Each induvidual arg
            p[0].arglist+=[(p[1].ctype, p[1].v_name)]

        self.arglist_len=len(p[0].arglist)
        self.argumentlist=p[0].arglist

    def p_argdeclare(self, p):
        """
        argdeclare : typedef ID
        """
        p[0]=self.graft_cthing(p[1],thing_type="arg")
        #print "NAME:%s"%p[2]
        p[0].v_name=p[2]

    def p_asterisklist(self, p):
        """
        asterisklist : STAR asterisklist
        asterisklist :
        """
        ##Essentially do any stars appear after the var type and before the name
        p[0]=self.get_cthing("asterisklist")
        p[0].asterisklength=1

        if len(p) == 3:
            p[0].asterisklength+=p[2].asterisklength

    def p_blockstart(self, p):
        """
        blockstart : LBRACE
        """
        label=self.get_label()
        self.tokenizer.vartree.down(label)

        ##Do we have any arguments passed in?
        if self.arglist_len!=0:
            self.resolveArgList()
            self.argumentlist=[]

    def p_blockend(self, p):
        """
        blockend : RBRACE
        """
        self.tokenizer.vartree.up()

    def p_codeblock(self, p):
        #"""
        #codeblock : LBRACE statementslist RBRACE
        #"""
        """
        codeblock : blockstart statementslist blockend
        """
        ##Check for empty code block
        if not p[2]:
            p[0]=self.get_cthing(thing_type="codeblock")
            p[0].stackspace=0 #initialize this to empty because we have nothing to add here.
        else:
            ##Automagically add in the generated code from the statementslist
            ## and maintain family tree
            p[0]=self.graft_cthing(p[2],thing_type="codeblock")
            ##Define the stacksize required
            p[0].stackspace=self.func_stackspace

        #print "*Returning [%s] from codeblock"%(''.join(p[0].value))

    def p_controlstatement(self, p):
        """
        controlstatement : IF LPAREN rightvalue RPAREN controlblock
        controlstatement : IF LPAREN rightvalue RPAREN codeblock ELSE codeblock
        controlstatement : WHILE LPAREN rightvalue RPAREN controlblock
        controlstatement : DO codeblock WHILE LPAREN rightvalue RPAREN SEMI
        controlstatement : FOR LPAREN rightvalue SEMI rightvalue SEMI rightvalue RPAREN controlblock
        controlstatement : BREAK SEMI
        """

        #does the ELSE statements with a tiny bit of optimization - null ELSE statements
        #are discarded
        elselen=8
        optimise_else=False
        full_else=False

        if p[1]=="if" and len(p) == elselen and len(p[elselen-1].value)==0:
            #We have any empty else statement so optimise and chop it off
            devlog("cparse2","Empty else clause found, optimising...")
            optimise_else=True
        elif p[1]=="if" and len(p) == elselen:
            devlog("cparse2","Full else clause found, NOT optimising...")
            full_else=True


        p[0]=self.get_cthing(thing_type="controlstatement") #Note: exprType is now just a name that is autogenerated by get_cthign

        if p[1] in ["while","if"]:
            startlabel=self.get_label()
            endlabel=self.get_label()
            p[0].value+="rem Found if/while statement - using %s as label\n"%startlabel
            p[0].value+="labeldefine %s\n"%startlabel
            p[0].value+=p[3].value #testcase

            if p[1]=="while":
                #overwrite previous endlabel
                endlabel = self.get_endlabel()

            ##If statements
            if full_else:
                ##Essentially for if/else constructs where the else codeblock isn't empty do this
                elselabel=self.get_label()
                p[0].value+="jumpiffalse %s\n"%elselabel
            #elif optimise_else:
            else:
                ##Empty else statements are optimised out to just if satements
                p[0].value+="jumpiffalse %s\n"%endlabel
            p[0].value+=p[5].value #codeblock

            #Jump back for while loops
            if p[1]=="while":
                p[0].value+="jump %s\n"%startlabel

            ##Else statements
            if full_else and not optimise_else:
                p[0].value+="rem ELSE\n"
                #end of if statement
                p[0].value+="jump %s\n"%endlabel
                #beginnging of else statement
                p[0].value+="labeldefine %s\n"%elselabel
                p[0].value+=p[7].value #else code
                #print "End of if/while - %s"%endlabel

            p[0].value+="labeldefine %s\n"%endlabel

        elif p[1]=="break":
            if self.lastloopstmt == []:
                tolabel = self.get_label()
                self.lastloopstmt.append(tolabel)
            else:
                tolabel = self.lastloopstmt[0]
            p[0].value += "rem Found break statement, exiting to %s\n" % tolabel
            p[0].value += "jump %s\n" % tolabel

        ##Do/While loops
        elif p[1]=="do":
            startlabel = self.get_label()
            endlabel = self.get_endlabel()
            p[0].value += "rem Found do/while statement - using %s as label\n" % startlabel
            p[0].value += "labeldefine %s\n" % startlabel
            p[0].value += "rem DO [CODE] ... \n"
            p[0].value += p[2].value # codeblock
            p[0].value += "rem DO ... WHILE [condition]\n"
            p[0].value += p[5].value # testcase
            p[0].value += "jumpiftrue %s\n" % startlabel
            p[0].value+="labeldefine %s\n"%endlabel
            p[0].value += "rem DO ... [out of loop]\n"

        ##For loops
        elif p[1]=="for":
            startlabel=self.get_label()
            conditionlabel=self.get_label()
            endlabel=self.get_endlabel()
            p[0].value+="rem Found FOR loop - using %s as label\n"%startlabel
            p[0].value+="labeldefine %s\n"%startlabel
            p[0].value+=p[3].value #initialize first thing i=0
            p[0].value+="rem condition statement follows\n"
            p[0].value+="labeldefine %s\n"%conditionlabel
            p[0].value+=p[5].value #i<1
            p[0].value+="jumpiffalse %s\n"%endlabel
            p[0].value+="rem condition statement finish\n"
            p[0].value+=p[9].value #codeblock
            p[0].value+="rem new assignment statement\n"
            p[0].value+=p[7].value #i=i+1
            p[0].value+="rem new assignment statement finish\n"
            p[0].value+="jump %s\n"%conditionlabel
            p[0].value+="labeldefine %s\n"%endlabel
            p[0].value+="rem FOR ... [out of loop]\n"
        else:
            print "Node attribute *%s* unrecognized in cparse"%p[1]

    def p_controlblock(self, p):
        """
        controlblock : codeblock
        controlblock : insidestatement SEMI
        """
        ##Graft cthing here ?
        p[0]=self.graft_cthing(p[1],thing_type="controlblock")

    def p_directive(self, p):
        '''
        directive : importdirective
        directive : includedirective
        '''
        p[0]=self.graft_cthing(p[1],thing_type="directive")

    def p_functiondeclare(self, p):
        """
        functiondeclare : typedef ID LPAREN argumentlist RPAREN codeblock
        """
        z=self.get_cthing(thing_type="functiondeclare")
        #typedef is ignored since we always just return ACCUMULATOR
        z.name = p[2] #ID
        devlog("cparse2", "functiondeclare: %s"%z.name)
        devlog("cparse2","Function Arglist looks like: %s Len:%d"%(p[4].arglist, self.arglist_len) )

        z.argsize=self.arglist_len*self.pointersize

        #Add to the vartree
        self.setcurrentfunction(z.name)

        ##Codeblock
        cb_stackspace=p[6].stackspace #codeblock
        devlog("cparse2", "Found function declare %s (function stack = %d)"%(z.name,cb_stackspace) )
        z.value+=["\nrem\nrem Found function declare %s (stack = %d)\nrem\n"%(z.name,cb_stackspace)]
        z.value+=["\nlabeldefine %s\n"%z.name]
        # PROLOG
        z.value+=["functionprelude\n"]

        if cb_stackspace:
            z.value+=["getstackspace %d\n"%cb_stackspace]

        z.value+=p[6].value #codeblock

        # EPILOG
        z.value+=["rem   <EPILOG of %s>\n" % z.name]
        #node.attr += "labeldefine %s_epilog\n" % name
        if cb_stackspace:
            z.value+=["freestackspace %d\n"%cb_stackspace]
        z.value+=["functionpostlude %s\n" % z.argsize]

        #we need to revisit args once more
        z.value+=["ret %s\n"%z.argsize] # XXX argsize should not be cleaned here but in postlude
        z.value+=["rem <end of %s> (end of epilog)\n" % z.name]


        ##Reset per function variables
        self.arglist_len=0
        self.argumentlist=[]
        self.func_stackspace=0

        p[0] = z
        return

    def p_functioncall(self, p):
        """
        functioncall : ID LPAREN functioncallarglist RPAREN
        functioncall : varname LPAREN functioncallarglist RPAREN
        """

        def use_args_stack(length):
            if length: #If we have args - use them
                devlog("cparse2", "<%d ARGS>" % (length - 1))
                for i in range(length-1, -1, -1):
                    devlog("cparse2", "ARGS#%d: %s" % (i, arglist.value[i]))
                    p[0].value += arglist.value[i] #a list?!?
                    p[0].value += self.pushargfromaccumulator(i)
                devlog("cparse2", "</%d ARGS>" % (length - 1))

        def use_args_reg(length):
            if length:
                devlog("cparse2", "<%d ARGS>" % (length - 1))
                for i in range(length-1, -1, -1):
                    devlog("cparse2", "ARGS#%d: %s" % (i, arglist.value[i]))
                    p[0].value += arglist.value[i]
                    p[0].value += self.arg_to_register(i)
                devlog("cparse2", "</%d ARGS>" % (length - 1))

        #TODO take out the varname and do a proper global check
        p[0]=self.get_cthing(thing_type="functioncall")

        # What type of name have we been called with? imports have cthings
        try:
            # variable name - so a cthing
            functionname=p[1].value[0]
        except AttributeError:
            # ID so a string
            functionname=p[1]

        arglist=p[3]
        length=len(arglist.value)
        devlog("cparse2", "Function call %s (%d args)" % (functionname, length))

        # print "Functionname is %s"%functionname
        # if this is a remote function, then we need to call it the hard way
        # with mov LABEL-geteip(%ebx), %eax
        # call eax
        # but if this is a local function
        # we can just call it
        (label,current,var,location)=self.getvar(functionname)

        # devlog("cparse2","functioncall: var=%r"%(type(var)))

        if current == None or var == None:
            # we have a local function call
            use_args_stack(length) # process arguments
            p[0].value+="call %s %s\n" % (functionname, length)
        elif not hasattr(var,"label"):
            # we have a function pointer
            use_args_stack(length) # process arguments
            devlog("cparse2", "Local function pointer found")
            # need to dereference this and call it
            p[0].value+=self.loadarg(functionname)
            # p[0].value+="loadlocaladdress %s\n"%(var.label)
            p[0].value+="derefaccum %s\n"%(var.totype.getsize())
            # call the accumulator %eax or %l0
            p[0].value+="callaccum\n"
        else:

            # global function pointer
            # we need to check for osx/intel(32,64) 16-byte stack alignment
            # probably not the best place to put this

            import osxremoteresolver, linuxremoteresolver

            osx_fix = linux_fix = False

            if isinstance(self.remoteresolver, (osxremoteresolver.x86osxremoteresolver,
                                                osxremoteresolver.x64osxremoteresolver)):
                osx_fix = True

            elif isinstance(self.remoteresolver, (linuxremoteresolver.x86linuxremoteresolver,
                                                  linuxremoteresolver.x64linuxremoteresolver,
                                                  linuxremoteresolver.arm9linuxremoteresolver)):
                linux_fix = True

            # save stack pointer so that we can restore it later
            if osx_fix or linux_fix: p[0].value += "save_stack\n"

            # align the stack at the proper boundary before the function call for OSX and ARM Linux EABI
            # currently that is 16 bytes for OSX and 8 bytes for ARM Linux
            if osx_fix or isinstance(self.remoteresolver, (linuxremoteresolver.arm9linuxremoteresolver,
                                                           linuxremoteresolver.x64linuxremoteresolver)):
                p[0].value += "alignstack_pre %d\n" % length

            # x64 calling conventions use registers for argument passing
            # Also ARM
            if isinstance(self.remoteresolver, (osxremoteresolver.x64osxremoteresolver,
                                                linuxremoteresolver.x64linuxremoteresolver,
                                                linuxremoteresolver.arm9linuxremoteresolver)):
                use_args_reg(length)
            else:
                use_args_stack(length)

            # load a word from the offset from the LABEL-geteip(%ebx)
            p[0].value+="loadglobaladdress %s\n"%(var.label)
            p[0].value+="derefaccum %s\n"%(var.totype.getsize())
            # call the accumulator %eax or %l0
            p[0].value+="callaccum\n"

            # clean up after the call (stack alignment, stack restore)
            if osx_fix or linux_fix: p[0].value+="restore_stack\n"

    def p_functioncallarglist(self, p):
        """
        functioncallarglist : arg COMMA functioncallarglist
        functioncallarglist : arg
        functioncallarglist :
        """
        p[0]=self.get_cthing(thing_type="functionacallarglist")

        if len(p) > 2:
            ##arglist
            devlog("cparse2","Function arglist found %s"%(p[1].value))
            p[0].value+=[p[1].value]
            p[0].value+=p[3].value
        elif len(p) == 2:
            if p[1]:
                devlog("cparse2","Function argument found %s"%(p[1].value))
                p[0].value+=[p[1].value]

        #print "Functioncallarglist: %s"%p[0].value

    def p_importdirective(self, p):
        '''
        importdirective : POUND IMPORT SCONST COMMA SCONST AS SCONST
        '''
        #e.g. #import "local","memcpy" as "memcpy"
        #     #import "remote", "kernel32.dll|loadlibrarya" as "loadlibrarya"
        #According to nico: 12:59:39 < nico> is used for local and remote methods ???

        #From cparse.py
        TODO = """
             ok this is a core function, hard to play with that.
             imo we shouldn't every importname to self.vartree, but some self.vartreecache
             and if a call to self.vartree.getvar(varname) raise some AttributeError exception,
             then we get the var from self.vartreecache, and add content to node.postattr string.
             at the end, on self.get(), we return node.attr + node.postattr
             so we only link piece of code reached and save space and compilation errors.
             """
        #[1:-1] is to strip off the quotes
        importtype=p[3][1:-1]
        importname=p[5][1:-1]
        importdest=p[7][1:-1]
        importlabel=self.get_label()

        devlog("cparse2","#import found, type: %s name: %s dest: %s label: %s"%(importtype, importname, importdest, importlabel))

        p[0]=self.get_cthing(thing_type="importdirective")
        p[0].value+="rem Import directive found %s:%s:%s:%s\n"%(importtype,importname,importdest,importlabel)

        #ok, now we need to add a global variable
        p[0].value+="labeldefine %s\n"%importlabel


        if importtype=="remote":
            #print "import REMOTE", importname,"*************************************************************"
            #a remote is a remote function pointer
            #win32 function pointers are given to us in msvcrt.dll|functionname style (notice the pipe)
            devlog("cparse2", "Remote Import: %s"%importname)
            mycglobal=mosdefctypes.cglobal(mosdefctypes.cpointer(mosdefctypes.cint()))
            mycglobal.setLabel(importlabel)
            self.addvar(importlabel,importdest,mycglobal)


            p[0].value+="longvar %s\n"%uint32fmt(self.getRemoteFunction(importname))
            self.addToRemoteFunctionCache(importname)
            devlog("cparse2","%s"%(repr(p[0].value)))

        elif importtype == 'remote64':
            # add a RESOLVED_f LABEL instance/var ...
            cint = mosdefctypes.cint()
            cint.setattr(['unsigned', 'long', 'long'])
            mycglobal = mosdefctypes.cglobal(mosdefctypes.cpointer64(cint))
            mycglobal.setLabel(importlabel)
            self.addvar(importlabel, importdest, mycglobal)
            p[0].value += 'longlongvar %s\n' % uint64fmt(self.getRemoteFunction(importname))
            self.addToRemoteFunctionCache(importname)
            devlog('cparse2', '%s' % (repr(p[0].value)))

        elif importtype=="string":
            #eh?
            var=self.getLocalVariable(importname)
            if var in [None,0]:
                #null pointer - treat as integer
                mycglobal=mosdefctypes.cglobal(mosdefctypes.cint())
                mycglobal.setLabel(importlabel)
                self.addvar(importlabel,importdest,mycglobal)
                p[0].value+="longvar %s\n"%uint32fmt(0) #null is always 0, we assume

            else:
                #globals don't get a size - they don't modify esp
                mycglobal=mosdefctypes.cglobal(mosdefctypes.carray(mosdefctypes.cchar(),len(var)+1))
                mycglobal.setLabel(importlabel)
                self.addvar(importlabel,importdest,mycglobal)
                p[0].value+="urlencoded %s\n"%urllib.quote(var)
                p[0].value+="databytes 0\n"
                p[0].value+="databytes 0\n"
                p[0].value+="archalign\n"

        elif importtype=="int":
            mycglobal=mosdefctypes.cglobal(mosdefctypes.cint())
            mycglobal.setLabel(importlabel)
            var=self.getLocalVariable(importname)
            if type(var) not in [type(0), type(0L)]:
                #string type as integer?!
                devlog("cparse2","Found non-integer type for integer variable! %s=%s"%(importname,var))
            self.addvar(importlabel,importdest,mycglobal)
            try:
                p[0].value+="longvar %s\n"%uint32fmt(var)
            except TypeError, emsg:
                raise SystemExit, "unable to find integer \"%s\"" % importname

        elif importtype == 'long long':
            cint = mosdefctypes.cint()
            cint.setattr(['unsigned', 'long', 'long'])
            mycglobal = mosdefctypes.cglobal(cint)
            mycglobal.setLabel(importlabel)
            var = self.getLocalVariable(importname)
            # no specific python type for long long here ...
            if type(var) not in [type(0), type(0L)]:
                devlog('cparse2', 'Found non-integer type for integer variable! %s=%s' % (importname,var))
            self.addvar(importlabel, importdest, mycglobal)
            try:
                p[0].value += 'longlongvar %s\n' % uint64fmt(var)
            except TypeError, emsg:
                raise SystemExit, 'unable to find integer \"%s\"' % importname

            #self.dumpvars()

        elif importtype=="local":
            devlog("cparse2", "Local import found: %s"%importname)
            if self.remoteresolver==None:
                print "Cannot do local importation when remoteresolver is None!"
            else:
                #prevent dual-importation
                if importname not in self.importedlocals:

                    self.importedlocals[importname]=1
                    value,suffix=self.remoteresolver.getlocal(importname,self.importedlocals)

                    #print "VALUE:",value
                    #print "SUFIX:",suffix
                    p[0].value+=value
                    p[0].value+=suffix

        else:

            devlog("cparse2", "Import type unknown: %s"%importtype)


    def p_includedirective(self, p):
        #Can look like #include <hi.h> or #include "hi.h"
        '''
        includedirective : POUND INCLUDE INCLUDEPATH
        '''
        includename=p[3]
        devlog("cparse2","Include found: %s"%(includename))

        p[0]=self.get_cthing(thing_type="includedirective")

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

    def p_incompletestructdefine(self, p):
        """
        incompletestructdefine : STRUCT ID SEMI
        """

    def p_insidestatement(self, p):
        """
        insidestatement : return
        insidestatement : structdefine
        insidestatement : variabledeclare
        insidestatement : rightvalue
        insidestatement : functioncall
        """
        try:
            p[0]=self.graft_cthing(p[1],thing_type="insidestatement")
            #print "****------*Returning [%s] from insidestatement: tree: %s"%(''.join(p[0].value), p[0].passed_from)

        except AttributeError:
            print "p[1] '%s' has no IL generated?"%(p[1])
            p[0]=self.get_cthing(thing_type="insidestatement")

    def p_leftvalue(self, p):
        """
        leftvalue : varname
        """
        ##load whatever's in the accumulator into the variable
        argname=p[1].value[0]
        devlog("cparse2", "Leftvalue loading name %s"%argname)

        (label,current, arg,location)=self.getvar(argname)
        if current==None:
            devlog("cparse2","Could not find variable %s"%argname)
            self.logerror("Could not find variable %s"%argname)

        p[0]=self.get_cthing(thing_type="leftvalue")

        if current=="globals":
            p[0].value+="accumulator2memoryglobal %s %s\n"%(arg, arg.getsize())
            #print "*Returning [%s] from lefttvalue"%(''.join(p[0].value))
            return

        if p[1].type == "varname": #Done
            #Local variable
            p[0].value+="rem Saving into normal variable name=%s \n"%argname
            p[0].value+="accumulator2memorylocal %s %s\n"%(location, arg.getsize())

        elif p[1].type == "pointer": #Done
            #Pointer
            p[0].value+="storeaccumulator\n"
            p[0].value+="loadint 0\n" #index is 0
            p[0].value+="accumulator2index\n"
            argload=self.loadarg(argname)
            p[0].value+=argload
            p[0].value+="storewithindex %d\n"%arg.totype.getsize() #from the stored accumulator

        elif p[1].type == "structure": #TODO - WHERE DOES type struct COME FROM?
            membername=p[1].value[1]
            offset=arg.getmemberoffset(membername)
            size=arg.getmembertype(membername).getsize()
            p[0].value+="rem Saving into struct member %s\n"%membername
            p[0].value+="accumulator2memorylocal %s %s\n"%(location-offset,size)

        elif p[1].type == "array": #Done
            devlog("cparse2", "Doing the array dance")
            #we are an array that we are loading. Such as j[1]=1, etc.
            #we need to store off the accumulator into a temporary variable
            #We put the index into the array in the accumulator
            p[0].value+="storeaccumulator\n"
            p[0].value+=p[1].value[2].value #load the accumulator with the result of the expression
            #now we need to multiply by the size of our variable
            p[0].value+="multiply %d\n"%arg.getitemsize()
            p[0].value+="accumulator2index\n"
            argload=self.loadarg(argname)
            p[0].value+=argload
            p[0].value+="storewithindex %d\n"%arg.totype.getsize() #from the stored accumulator

        elif p[1].type == "arrow_deref" or p[1].type == "dot_deref": #TODO testing
            #print "Pointer to a structure deref"
            #something like: name->name = 44;
            member=p[1].value[1]
            varname=p[1].value[0]
            p[0].value+="rem pointer %s->%s deref\n"%(varname,member)
            p[0].value+="storeaccumulator\n" #save off eax for later

            #now load the address we want to store into
            (label,current, arg,location)=self.vartree.getvar(varname)
            if location==None:
                print "******Did not find variable %s"%varname
            p[0].value+="loadlocaladdress %s\n"%location #
            p[0].value+="derefaccum %s\n"%arg.getsize()
            offset=arg.totype.getmemberoffset(member)
            if offset==-1:
                print "Did not find member %s!"%member
                raise SystemError
            p[0].value+="addconst %s\n"%offset
            #the address of the variable we want to save into is now in the accumulator

            membersize=arg.totype.getmembertype(member).getsize()

            #now store into that address
            p[0].value+="accumulator2index\n" #load edx with our actual address
            p[0].value+="loadint 0\n" #index is 0
            p[0].value+="storewithindex %d\n"%membersize #from the stored accumulator
            p[0].value+="rem Done with store.\n"

        else:
            print "UNKNOWN LEFTVALUE TYPE: %s"%(p[1].type)
            self.logerror("UNKNOWN LEFTVALUE TYPE: %s"%(p[1].type))

        #print "Returning [%s] from lefttvalue"%(''.join(p[0].value))

    def p_number(self, p):
        ##DO WE ONLY SUPPORT INTEGERS ?????
        """
        number : HEXNUMBER
        number : DECNUMBER
        number : FCONST
        number : SUBTRACT number
        """
        p[0]=self.get_cthing(thing_type="number")

        if len(p)==3:
            #negative value
            #p[0]=-1*p[2]
            p[0].value.append(str(-1*int(p[2].value[0])))
        else:
            #positive
            p[0].value.append(p[1])

    def p_op(self, p):
        """
        op : PLUS
        op : SUBTRACT
        op : STAR
        op : PERCENT
        op : GTHAN
        op : LTHAN
        op : R_SHIFT
        op : L_SHIFT
        op : AMPERSAND
        op : AND
        op : NOT_EQ
        op : PIPE
        op : OR
        op : TILDA
        op : CARET
        op : FSLASH
        op : EQUIV
        op : GT_EQ
        op : LT_EQ
        op : INC
        op : DEC
        """
        p[0]=p[1]
        return


    def p_quotedchar(self, p):
        """
        quotedchar : CCONST
        """
        p[0]=self.get_cthing(thing_type="number")

        ##Strip off the single quotes
        attr = p[1][1:-1]

        ##Qualify what type of single char we are dealing with
        if len(attr) == 1:
            ##just a single char e.g. 'A'
            p[0].value.append(str(ord(attr)))

        elif len(attr) == 2:
            ##escaped char: '\n' or '\\'
            if attr[0] == '\\' and attr[1] in self.__bt:
                p[0].value.append(str(ord(self.__bt[attr[1]])))
            else:
                raise AssertionError

        elif attr[:2] == "\\x":
            ##Hex char e.g. '\x41"
            p[0].value.append("0%s"% attr[1:])
        else:
            raise AssertionError

    def p_quotedstring(self, p):
        """
        quotedstring : SCONST
        """
        p[0]=self.get_cthing(thing_type="quotedstring")
        p[0].value+=p[1]

    def p_functionname(self, p):
        """
	functionname : ID
	"""
        functionname = p[1]
        p[0]=self.get_cthing(thing_type="functionname")
        p[0].value = functionname
        return

    def p_rightvalue(self, p):
        """
        rightvalue : number
        rightvalue : varname
        rightvalue : quotedstring
	rightvalue : quotedchar
        rightvalue : functioncall
        rightvalue : reference
        rightvalue : leftvalue EQUAL rightvalue
        rightvalue : rightvalue op rightvalue
        rightvalue : functionname
        """
        p[0]=self.get_cthing(thing_type="rightvalue")

        devlog("cparse2", "rightvalue type: %s value: %s"%(p[1].type, p[1].value))
        if p[1].type=="number":
            #loads eax with the integer
            number=long(p[1].value[0],0) #should this be uint32?
            p[0].value+="loadint %d\n"%number
            ##We also need to add this in to enable us to do array dereferencing later (see line 992ish)
            ## rightvalue numbers will get this attribute but its only referenced when
            ## know we have an array on the rhs (brackets and all that jazz)
            p[0].stringint=number

        elif p[1].type == "varname":  #Done - though NULL may suck
            #normal variable
            #the issue here is that if we load a pointer, we want to store that pointer
            #data type so we can += it properly

            if p[1].value==["NULL"]:
                #we are a pointer type, but the user passed in None as our pointer
                #so we load a null pointer here
                p[0].value+="rem NULL\n"
                p[0].value+="loadint %d\n"%0
            else:
                p[0].value+=self.loadarg(p[1].value[0]) #normal variable
                ##TODO - make sure lastloaded stuff works
                p[0].lastloaded=self.lastloaded
        ##----------------------------------------------------------------------

        elif p[1].type=="leftvalue": #Done
            #op=p[2].value
            op=p[2]
            #We need to add addition and subtraction here...
            if op=="=":
                p[0].value+=p[3].value
                p[0].value+=p[1].value
                #print "leftvalue = %s"%p[1].value
                #print "p[2]: %s"%p[2]
                #print "p[3].value= %s"%''.join(p[3].value)
            else:
                print "Don't understand op = %s in leftvalue"%op

        elif p[1].type=="rightvalue": #Done
            #rightvalue op rightval
            op=p[2]
            #print "rightvalue found op= ->%s<-"%op
            if op=="+": #TODO - lastloaded??
                p[0].value+="rem found + operator\n"
                #a=b+c
                p[0].value+=p[3].value #load "c" to accum
                try:
                    lastarg=p[1].lastloaded
                    if lastarg!=None:
                        name=lastarg.name
                        p[0].value+="rem lastloaded=%s\n"%name
                        if name=="pointer":
                            totype=lastarg.totype
                            size=totype.size
                            p[0].value+="rem size of pointer argument %s: %d\n"%(name,size)
                            p[0].value+="multiply %d\n"%size
                    else:
                        p[0].value+="rem lastloaded=None\n"
                except AttributeError, err:
                    devlog("cparse2","Atrributeerror in type rightvalue: [%s]"%(err))

                p[0].value+="pushaccum\n" #save "c" to stack (for better code, use register as bottom of stack)
                p[0].value+=p[1].value #load "b" into accum
                p[0].value+="poptosecondary\n" #pop "c" to a secondary register
                p[0].value+="addsecondarytoaccum\n" #add secondary register to accumultator

            #elif op=="++": #Doesn't work yet
                ###Increment by one
                ##(a++)  == (a=a+1) == (a=b+c where a==b and c==1 )
                #p[0].value+="rem found ++ operator\n"
                #p[0].value+="loadint %d\n"%(long(1,0)) #load c into accum

                #p[0].value+="pushaccum\n" #save "c" to stack (for better code, use register as bottom of stack)

                #p[0].value+=self.loadarg(p[1].value[0]) #load "b" into accum
                #p[0].lastloaded=self.lastloaded

                #p[0].value+="poptosecondary\n" #pop "c" to a secondary register
                #p[0].value+="addsecondarytoaccum\n" #add secondary register to accumultator


            elif op=="-":
                p[0].value+=p[3].value
                p[0].value+="pushaccum\n" #save to secondary register
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="subtractsecondaryfromaccum\n"
            elif op=="%":
                p[0].value+=p[3].value
                p[0].value+="pushaccum\n" #save to secondary register
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="modulussecondaryfromaccum\n"
            elif op=="/":
                p[0].value+=p[3].value
                p[0].value+="pushaccum\n" #save to secondary register
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="dividesecondaryfromaccum\n"
            elif op=="*":
                p[0].value=p[3].value
                p[0].value+="pushaccum\n"
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n"
                p[0].value+="multaccumwithsecondary\n"
            elif op in ["<",">","!=","=="]:
                p[0].value+=p[3].value
                p[0].value+="pushaccum\n" #save to secondary register
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="compare\n"  #sets flag registers
                if op=="<":
                    p[0].value+="setifless\n"
                elif op==">":
                    p[0].value+="setifgreater\n"
                elif op=="!=":
                    p[0].value+="setifnotequal\n"
                elif op=="==":
                    p[0].value+="setifequal\n"
            ##Only works for Integers, distinguish between ints & floats based types perhaps?
            elif op in [">=", "<="]:
                #rudimentary support of >-= and <=  -- just inc or dec the comparison value
                #we are not checking for overflows
                if op=="<=":
                    #print "**********************%s%s"%(p[1].value, type(p[1].value))
                    comp_val="addconst 1\n"
                    op_val="setifless\n"        ## of the number value ?? work with floats??
                elif op==">=":
                    comp_val="subconst 1\n"
                    op_val="setifgreater\n"

                p[0].value+=p[3].value
                p[0].value+=comp_val
                p[0].value+="pushaccum\n" #save to secondary register
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="compare\n"  #sets flag registers

                p[0].value+=op_val
            ##################################
            elif op=="&&":
                p[0].value+="rem && found\n"
                p[0].value+=p[1].value #first arg
                #accumulator is either true or 0
                p[0].value+="pushaccum\n" #save accumulator from first arg
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a zero to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifequal\n" #set accum=1 if node[0]==false
                p[0].value+="pushaccum\n" #push this value for later
                #stack = [ p[1] is true ]

                p[0].value+="rem node[2].attr start\n"
                p[0].value+=p[3].value #second arg
                p[0].value+="rem node[2].attr end\n"

                p[0].value+="pushaccum\n" #save
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a zero to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifequal\n" #accum has our value

                p[0].value+="poptosecondary\n" #pop original value to a secondary register
                #stack = []
                p[0].value+="addsecondarytoaccum\n" #add them together, if we have 1, someone was false
                p[0].value+="rem final compare to key value here \n"
                #now we compare the result of that with our key value
                p[0].value+="pushaccum\n" #save
                #stack = [p[1] is true + p[3] is true]
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a value into accumulator to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifequal\n" #if everyone was true, then our accum at this point will be 0, and hence, we set if==0

            elif op=="||":
                p[0].value+=p[1].value #first arg
                p[0].value+="pushaccum\n" #save
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a zero to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifnotequal\n" #accum has our value
                p[0].value+="pushaccum\n" #push this value for later

                p[0].value+=p[3].value #second arg
                p[0].value+="pushaccum\n" #save
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a zero to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifnotequal\n" #accum has our value
                p[0].value+="poptosecondary\n" #pop original value to a secondary register
                p[0].value+="addsecondarytoaccum\n" #add them together, if we have 0, we are false
                #now we compare the result of that with 0
                p[0].value+="pushaccum\n" #save
                p[0].value+="poptosecondary\n" #pop to a secondary register
                p[0].value+="loadint 0\n" #load a zero into accumulator to compare with
                p[0].value+="compare\n"  #sets flag registers
                p[0].value+="setifnotequal\n" #accum has our final value

            elif op=="<<":
                p[0].value=p[3].value
                p[0].value+="pushshiftreg\n" #push %ecx
                p[0].value+="pushaccum\n" #push %eax
                p[0].value+=p[1].value #load value
                p[0].value+="poptoshiftreg\n" #pop %ecx
                p[0].value+="shiftleft\n" #SHL %cl, %eax
                p[0].value+="poptoshiftreg\n"#pop %ecx
            elif op==">>":
                p[0].value=p[3].value
                p[0].value+="pushshiftreg\n" #push %ecx
                p[0].value+="pushaccum\n" #push %eax
                p[0].value+=p[1].value #load value
                p[0].value+="poptoshiftreg\n" #pop %ecx
                p[0].value+="shiftright\n" #SHR %cl, %eax
                p[0].value+="poptoshiftreg\n"#pop %ecx
            elif op=="&":
                p[0].value=p[3].value
                p[0].value+="pushaccum\n"
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n"
                p[0].value+="andaccumwithsecondary\n"
            elif op=="^":
                p[0].value=p[3].value
                p[0].value+="pushaccum\n"
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n"
                p[0].value+="xoraccumwithsecondary\n"
            elif op=="|":
                p[0].value=p[3].value
                p[0].value+="pushaccum\n"
                p[0].value+=p[1].value
                p[0].value+="poptosecondary\n"
                p[0].value+="oraccumwithsecondary\n"

            else:
                print "ERROR: op %s not recognized"%op

        elif p[1].type=="quotedstring":#Done
            #globals don't get a size - they don't modify esp
            #Grab the chars minus the quotes
            var=''.join(p[1].value[1:-1])
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

            (mylabel,current, arg,location)=self.vartree.getvar(varname)

            if location==None:
                #new string constant
                mylabel=self.get_label()
                jmplabel=self.get_label()
                #print "Jmplabel=%s mylabel=%s"%(jmplabel,mylabel)
                mycglobal=mosdefctypes.cglobal(mosdefctypes.carray(mosdefctypes.cchar(),len(var)+1))
                mycglobal.setLabel(mylabel)
                self.addvar(mylabel,varname,mycglobal)
                p[0].value+="jump %s\n"%jmplabel
                p[0].value+="labeldefine %s\n"%mylabel
                p[0].value+="urlencoded %s\n"%urllib.quote(var)
                p[0].value+="databytes 0\n"
                p[0].value+="databytes 0\n"
                p[0].value+="archalign\n"
                #we jump here over our string...
                p[0].value+="labeldefine %s\n"%jmplabel

            #actually load the address into the accumulator
            p[0].value+="loadglobaladdress %s\n"%mylabel

        elif p[1].type=="functioncall": #Done
            #eax should already be loaded with the results after our call
            p[0].value+=p[1].value  #add in cthing history/parent stuff here TODO


        elif p[1].type == "ampersand_struct": #Done ? TODO TEST!
            #&name.name (structure member deref)
            member=p[1].value[1]
            (label,current, arg,location)=self.vartree.getvar(p[1].value[0])
            offset=arg.getmemberoffset(member)
            if offset==-1:
                print "Did not find member %s!"%member
                raise SystemError
            #with a structure member, first load the local location
            p[0].value+="loadlocaladdress %s\n"%location
            #then add the offset
            p[0].value+="addconst %s\n"%offset
            #now accumulator is pointing to member

        ##----------------------------------------------------------------------
        #need to load a variable
        #can be one of four things - a normal variable, an array reference,
        #or a structure dereference!
        #or p[1].value is string of "None" for a null pointer passed in via #import "string"
        elif p[1].type == "structure": ##TODO TEST lots
            #structure
            membername=p[1].value[1]
            structname=p[1].value[0]
            (label,current, arg,location)=self.vartree.getvar(structname)
            assert arg, "arg is None for varname.member=%s.%s" % (structname, membername)
            assert hasattr(arg, 'getmemberoffset'), \
                   "arg.getmemberoffset not existant for varname.member=%s.%s" % (structname, membername)
            offset=arg.getmemberoffset(membername)
            if offset==-1:
                print "Did not find member %s!"%membername
                raise SystemError
            #with a structure member, first load the local location
            if location==None:
                print "******Did not find variable %s"%structname
            p[0].value+="loadlocaladdress %s\n"%location
            #then add the offset
            #node.attr+="debug\n"
            p[0].value+="addconst %s\n"%offset
            membersize=arg.getmembertype(membername).getsize()
            #if we're talking about an array, we want to
            #have a pointer to the array in accum
            #if we're talking about a structure, we want a
            #pointer to the structure
            #if we're talking about an int or char, we want to load
            #that.
            #BUGBUG:
            #this is a bug, but we'll figure out what it really
            #needs to be later...a new member in the ctypes perhaps?
            if membersize<=self.pointersize:
                p[0].value+="derefaccum %s\n"%membersize
        elif p[1].type == "arrow_deref" or p[1].type == "dot_deref":
            #pointer to structure deref  str_ptr->i=66;
            member=p[1].value[1]
            varname=p[1].value[0]
            (label,current, arg,location)=self.vartree.getvar(varname)
            if location==None:
                print "******Did not find variable %s"%varname
            assert arg, "arg is None for varname->member=%s->%s" % (varname, member)
            p[0].value+="loadlocaladdress %s\n"%location
            p[0].value+="derefaccum %s\n"%arg.getsize()
            offset=arg.totype.getmemberoffset(member)
            if offset==-1:
                print "Did not find member %s!"%member
                raise SystemError
            p[0].value+="addconst %s\n"%offset

            #see BUGBUG above
            membersize=arg.totype.getmembertype(member).getsize()
            if membersize<=self.pointersize:
                p[0].value+="derefaccum %s\n"%membersize

        elif p[1].type == "array" or p[1].type == "ampersand_array":
            #print "We found an array...%s (%s)"%(p[1].value[0], ''.join(p[1].value[2].value))
            (label,current, arg,location)=self.vartree.getvar(p[1].value[0])
            size=arg.getitemsize()
            devlog("cparse2", "IL from the rightvalue evaluation of the array %s"%(''.join(p[1].value[0])))

            p[0].value+=p[1].value[2].value
            p[0].value+="multiply %d\n"%size
            p[0].value+="accumulator2index\n"
            p[0].value+=self.loadarg(p[1].value[0])
            # XXX: derefs need size handling too on p[0] = p2[0] type stuff on big endian systems
            p[0].value+="derefwithindex %d\n"% size

            ##&array[9] support
            if p[1].type == "ampersand_array":
                print "NAME IS AN ARRAY DEREF! %s"%(p[1].value[0])
                index=int(p[1].value[2].stringint)
                print "INDEX=%s"%index
                sizeoftype=4 #HARDCODED until we get a real type system
                #right now this only works for integer indexes
                #we also need to handle variables...
                if index!=0:
                    p[0].value+="addconst %d\n"%(index * sizeoftype)

        elif p[1].type=="pointer": #Done
            #dereference a pointer
            argname=p[1].value[0]
            p[0].value+=self.loadarg(argname)
            p[0].lastloaded=self.lastloaded
            (label,current, arg,location)=self.vartree.getvar(argname)

            p[0].value+="derefaccum %s\n"%arg.totype.getsize()

        elif p[1].type=="ampersand": #Done

            argname=p[1].value[0]
            (label,current, arg, location)=self.vartree.getvar(argname)
            if location==None:
                print "Fatal Error!!! Did not find variable %s"%argname
                sys.exit(-1)

            p[0].value+="loadlocaladdress %s\n"%location

        elif p[1].type=="functionname":
            #assigning a function pointer
            functionname = p[1].value
            p[0].value+="loadglobaladdress %s\n"%functionname

        else:
            devlog("cparse2", "***ERROR: unknown rightvalue type = %s"%p[1].type)

        #print "*Returning [%s] from rightvalue"%(''.join(p[0].value))

    def p_reference(self, p):
        """
        reference : AMPERSAND VARIABLENAME
        reference : AMPERSAND VARIABLENAME STRUCT_MEMBER
		reference : AMPERSAND VARIABLENAME LBRACKET rightvalue RBRACKET
        """
        #reference : reference PERIOD VARIABLENAME
        if len(p) == 3:
            ##Normal variable - &var
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            devlog("cparse2", "AMPERSAND Name: %s"%p[2])
            tmp.value+=[p[2]]
            p[0]=self.graft_cthing(tmp, thing_type="ampersand")

        elif len(p) == 4:
            ##Structure - &strct.var
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            devlog("cparse2", "AMPERSAND STRUCT Name.member: %s.%s"%(p[2],p[3]))
            tmp.value+=[p[2], p[3]]
            p[0]=self.graft_cthing(tmp, thing_type="ampersand_struct")

        elif len(p) == 6:
            ##Dereferenced array &array[8]
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            devlog("cparse2", "AMPERSAND ARRAY Name[index]: %s[%s]"%(p[2],p[4]))

            #Arrays - p[0].value=[varname_str, '[', integer_index, ']' ]
            ##p[1].value[0] as that object has already been through above and is
            ## encapsulated in a cthing so if we don't do .value[0] it's 2 layers deep.
            tmp.value+=[p[2], p[3], p[4], p[5]]
            p[0]=self.graft_cthing(tmp, thing_type="ampersand_array")

        else:
            print "Error: Unknown structure format"
            SystemError

    def p_return(self, p):
        """
		return : RETURN
		return : RETURN rightvalue
		"""
        p[0]=self.get_cthing(thing_type="return")
        if len(p) > 2:
            ##We are actually returning a value so add the IL gen'd in rightvalue
            p[0].value+=p[2].value
        here_just_jump_to_epilog_and_remove_that_code = True
        if here_just_jump_to_epilog_and_remove_that_code:
            p[0].value+="rem   <BROKEN EPILOG> from return_in_statement\n"
            ##Did we reserve space on the stack? If so free it
            if self.stacksize:
                p[0].value+="freestackspace %d\n"%self.stacksize
            argsize=self.arglist_len*self.pointersize
            p[0].value+="functionpostlude %s\n" % argsize # XXX
            p[0].value+="ret %s\n"%argsize
            p[0].value+="rem   </BROKEN EPILOG>\n"
        else:
            epilog_addr = self.vartree.getcurrentfunction()
            assert epilog_addr
            p[0].value+="jump %s_epilog\n" % epilog_addr

    def p_statementslist(self, p):
        """
        statementslist : statements statementslist
        statementslist :
        """
        if len(p) == 3:
            p[0]=self.graft_cthing(p[1],thing_type="statementlist")
            if p[2]: ##As sometimes it may be empty
                p[0].value+= p[2].value
            #print "*Returning [%s] from statementslist"%(''.join(p[0].value))

    def p_statements(self, p):
        """
        statements : controlstatement
        statements : insidestatement SEMI
        """
        p[0]=self.graft_cthing(p[1],thing_type="statements")
        #print "*Returning [%s] from statements"%(''.join(p[0].value))

    def p_structdefine(self, p):
        """
        structdefine : STRUCT ID LBRACE structarglist RBRACE
        """
        p[0]=self.get_cthing(thing_type="structdefine")
        devlog("cparse2", "Defining structure named: %s"%(p[2]))
        v_name=p[2]
        structarglist=p[4].arglist
        #print "arglist - %s"%(structarglist)
        cstruct=mosdefctypes.cstructure(structarglist)
        #print "Adding %s, %s"%(v_name,cstruct)
        self.varcache.addtype(v_name,cstruct)

    def p_structarglist(self, p):
        #structures can be empty, or they can be a list of variables and/or structures
        """
        structarglist : structmemberdeclare SEMI structarglist
        structarglist :
        """
        p[0]=self.get_cthing(thing_type="structarglist")
        p[0].arglist=[]
        if len(p)==4:
            p[0].arglist+=[(p[1].ctype,p[1].v_name)]
            p[0].arglist+=p[3].arglist

    def p_structmemberdeclare(self, p):
        """
        structmemberdeclare : typedef ID arrayvals
        structmemberdeclare : typedef VARIABLENAME arrayvals
        """
        tmp=self.graft_cthing(p[1],thing_type="structmember")
        #print "NAME:%s"%p[2]
        tmp.v_name=p[2]
        devlog("cparse2", "Structmemberdeclare: %s"%repr(p[1]))
        ctype=p[1].ctype

        ##Is it an array?
        if p[3]:
            #yes
            devlog("cparse2", "structmemberdeclare (array)")
            p[0]=self.graft_cthing(tmp,thing_type="structmemberarray")
            #ctype needs to be done here as we need to know what type array is pointing to
            p[0].ctype=mosdefctypes.carray(ctype,p[3].arraysize)
            p[0].v_name=p[1].v_name
            #print "Array of size %d found!"%(p[2].arraysize)

        else:
            #no - inherits ctype, v_name etc from p[1]
            p[0]=tmp

        #Store the var size for both vars & arrays
        p[0].size=p[0].ctype.getstacksize()

    def p_typedef(self, p):
        #Returns a mosdefctype instance NOT a cthing
        """
        typedef : CHAR asterisklist
        typedef : INT asterisklist
        typedef : VOID asterisklist
        typedef : SIGNED typedef
        typedef : UNSIGNED typedef
        typedef : SHORT asterisklist
        typedef : SHORT INT asterisklist
        typedef : LONG asterisklist
        typedef : LONG INT asterisklist
        typedef : LONG LONG asterisklist
        typedef : LONG LONG INT asterisklist
        typedef : STRUCT ID asterisklist
        """
        #Get the C Type the string is pertaining to except if its VOID
        p[0]=self.get_cthing(thing_type="typedef")


        #print 'XXX: ' + repr(p)

        ##Filter out the INT stuff
        if p[2] == 'int':
            devlog("cparse2", "getting rid of extraneous INT")
            p[2] = p[3]

        if len(p) >= 4 and p[3] == 'int':
            devlog('cparse2', 'getting rid of extraneous INT after LONG LONG')
            p[3] = p[4]

        if p[1].lower() in ["signed","unsigned"]:
            ##Don't create new object grab ctype that has already been
            ## defined along with any attributes already set on it
            p[0].ctype=p[2].ctype
            p[0].ctype.setattr([p[1].lower()])
            devlog("cparse2", "Setting attribute:%s on %s"%(p[1].lower(), p[0].ctype ))

        #elif p[1].lower() in ['void']: #Void
            #p[0].ctype=mosdefctypes.cvoid()
            #return

        elif p[1].lower() in ['struct']: #Structures

            structname=p[2]
            devlog( "cparse2", "Getting struct: %s"%structname)
            myctype=self.varcache.gettype(structname)
            if myctype==None:
                print "WACKY ERROR: No %s in cache!"%structname
            else:
                pointerlength=p[3].asterisklength-1
                for i in range(0,pointerlength):
                    if self.pointersize == 4:
                        myctype=mosdefctypes.cpointer(myctype)
                    if self.pointersize == 8:
                        myctype=mosdefctypes.cpointer64(myctype)

                p[0].ctype=myctype

        elif type(p[2]) != type('') and p[2].asterisklength >1 : #Pointers
            #[NOTE:vars have asterisklength of 1, pointer >1, due to accumulaotr used in p_asterisklist]

            #Pointer - need to know what ctype it points to which we have already instantiated
            for x in range(0, p[2].asterisklength-1):
                ##TODO 27/10/08 check this is right....
                if self.pointersize == 4:
                    p[0].ctype=mosdefctypes.cpointer(self.varcache.gettype(p[1].lower()))
                if self.pointersize == 8:
                    p[0].ctype=mosdefctypes.cpointer64(self.varcache.gettype(p[1].lower()))

            devlog("cparse2", "Pointer declared %s -> %s (Pointer Size: %d)" % (p[0].ctype,
                                                                                p[0].ctype.totype,
                                                                                self.pointersize))

        elif (type(p[2]) == type('')
              and p[1] == 'long'
              and p[2] == 'long'
              and p[3].asterisklength > 1):
            for x in range(0, p[3].asterisklength-1):
                p[0].ctype = mosdefctypes.cpointer64(self.varcache.gettype('long long'))
            devlog('cparse2', 'XXX: long long * %s -> %s' % (p[0].ctype,p[0].ctype.totype))

        elif p[1].lower() in ["long","short"]:

            attributes = [p[1].lower()]

            if (type(p[2]) == type('')
                    and p[2].lower() in ['long']):
                devlog('cparse2', 'XXX: long long!')
                attributes.append(p[2].lower())

            elif p[1].lower() == 'long' and self.LP64:
                devlog('cparse2', 'XXX: long of 8 bytes!')
                attributes.append('long')

            ##Create new int object
            p[0].ctype = mosdefctypes.cint()
            p[0].ctype.setattr(attributes)

            devlog("cparse2", "Setting attribute:%s on %s"%(p[1].lower(), p[0].ctype ))

        else:
            #Standard types (int, char etc)
            #Whether this is an array is sorted out in p_variabledefine
            p[0].ctype=self.varcache.gettype(p[1].lower())

        devlog("cparse2", "Variable declared %s"%(p[0]))

    def p_variabledeclare(self, p):
        """
        variabledeclare : variabledefine
        """
        notes="""
             This function needs to modify the lexer and our name space in order to
             correctly have it output VARIABLENAME tokens in the future
             """
        addr=self.allocate_stack_space(p[1].size)
        self.addvar(addr, p[1].v_name, p[1].ctype)
        p[0]=p[1]

        #print "%s"%repr(p[:])
        #varname=p.value

        #Return var: type, name
        #p[0]=p[1]

    def p_variabledefine(self, p):
        """
        variabledefine : argdeclare arrayvals
        """
        #ctype of the variable, or type pointed to by array
        ctype=p[1].ctype

        ##Is it an array?
        if p[2]:
            #yes
            p[0]=self.graft_cthing(p[2],thing_type="variabledefine")
            #ctype needs to be done here as we need to know what type array is pointing to
            p[0].ctype=mosdefctypes.carray(ctype,p[2].arraysize)
            p[0].v_name=p[1].v_name
            #print "Array of size %d found!"%(p[2].arraysize)

        else:
            #no - inherits ctype, v_name etc from p[1]
            p[0]=self.graft_cthing(p[1],thing_type="variabledefine")

        #Store the var size for both vars & arrays
        p[0].size=p[0].ctype.getstacksize()

        devlog("cparse2","cthing contents: %s %s %s %s %d"%(p[0].v_name, p[0].type, p[0].ctype, p[0].passed_from, p[0].size))

    def p_varname(self, p):
        """
        varname : VARIABLENAME
        varname : STAR VARIABLENAME
        varname : varname STRUCT_MEMBER
        varname : varname ARROW ID
        varname : varname ARROW VARIABLENAME
        varname : varname LBRACKET rightvalue RBRACKET
        varname : LPAREN STAR VARIABLENAME RPAREN STRUCT_MEMBER
        """
        p[0]=self.get_cthing(thing_type="varname")

        ##Returns a list, contents varies depending on type but be aware indexing
        ## will be needed to access item. See leftvalue/rightvalue for examples
        if len(p)==2:
            #Basic varname - p[0].value=["varname string"]
            devlog("cparse2", "Variable Name: %s"%p[1])
            ##Create new cthing as ID/VARIABLE name doesn't return a cthing but a string
            tmp=self.get_cthing(thing_type='VARIABLENAME') #name = so it looks like it was created in VARIABLENAME
            tmp.value+=[ p[1] ]
            p[0]=self.graft_cthing(tmp,thing_type="varname")

        elif len(p) == 3 and p[1] == "*":
            #* pointer stuff - p[0].value=[  "varname string"]
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            tmp.value+=[p[2]]
            ##We need to change the types of these cthings from varname so as we can
            ##distinguish them in rightvalue
            devlog("cparse2", "Pointer Name: %s"%p[2])
            p[0]=self.graft_cthing(tmp, thing_type="pointer")

        elif len(p) == 3:
            ##Structure.member p[0].value =[ "structname", "membername(without dot)"]
            structname=p[1].value[0]
            membername=p[2]
            devlog("cparse2", "Struct reference: %s%s"%(structname, membername))
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            ##p[1].value[0] as that object has already been through above and is
            ## encapsulated in a cthing so if we don't do .value[0] it's 2 layers deep.
            tmp.value+=[structname, membername]

            p[0]=self.graft_cthing(tmp, thing_type="structure")

        elif len(p) == 4:
            ##Structure dereference ptr->arg p[0].value=[]
            structname=p[1].value[0]
            member=p[3]
            devlog("cparse2", "Struct pointer arrow deref looks like: %s%s%s"%(structname, p[2], member))

            tmp=self.get_cthing(thing_type='VARIABLENAME')
            ##p[1].value[0] as that object has already been through above and is
            ## encapsulated in a cthing so if we don't do .value[0] it's 2 layers deep.
            tmp.value+=[p[1].value[0], p[3]]

            #Do a similar sym_name thing here for array ??  save doing len & str compares
            p[0]=self.graft_cthing(tmp, thing_type="arrow_deref")

        elif len(p) == 5:
            #Arrays - p[0].value=[cthing(), '[', cthing(), ']' ]
            devlog("cparse2", "Array Name: %s"%p[1].value[0])
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            ##p[1].value[0] as that object has already been through above and is
            ## encapsulated in a cthing so if we don't do .value[0] it's 2 layers deep.
            tmp.value+=[p[1].value[0], p[2], p[3], p[4]]
            #Do a similar sym_name thing here for array ??  save doing len & str compares
            p[0]=self.graft_cthing(tmp, thing_type="array")
            #print "SENDING ARRAY: %s"%(p[0].value)

        elif len(p) ==6:
            #Dot struct derefs - (*struct_ptr).member
            structname=p[3]
            member=p[5]
            devlog("cparse2", "Struct pointer dot deref looks like: %s%s%s%s.%s"%(p[1],p[2],structname, p[4], member))
            tmp=self.get_cthing(thing_type='VARIABLENAME')
            ##p[1].value[0] as that object has already been through above and is
            ## encapsulated in a cthing so if we don't do .value[0] it's 2 layers deep.
            tmp.value+=[p[3], p[5]]

            #Do a similar sym_name thing here for array ??  save doing len & str compares
            p[0]=self.graft_cthing(tmp, thing_type="dot_deref")

        else:
            ##TODO - throw proper error!
            print "++++++++NOT SUPPORTED YET++++++++"

    #END C PARSER CLASS

def getCparser(target_os, target_proc, target_version=None, vars=None, code=None, defines={}):
    """
    Call this with an OS type, cpu type and a dictionary of relevant variables to
	get a parser & yaccer back, or pass in c code and get the IL back
    """
    ##Get our remote resolver
    rr=mosdef.getremoteresolver(target_os, target_proc, target_version)

    ##Initialise our lexer logic and lex, as well as our parser logic
    if target_proc.upper() in ['X64']:
        pointersize = 8
    else:
        pointersize = 4

    parser=CParse2(remoteresolver=rr, vars=vars, pointersize=pointersize)

    ##Preproccess the code
    code = mosdef.preprocess(code, vars, defines, rr, delim = "//")

    ##initialise yacc and write the generated tables to disk
    global existing_parse_tables
    yaccer=yacc.yacc(module=parser,debug=0,write_tables=1,method="LALR",optimize=1, tabmodule=rr.parse_table_name, pass_the_pickle=existing_parse_tables)
    existing_parse_tables=yaccer.pass_the_pickle

    ##Make lex and yacc speak to each other
    if code:
        yaccer.parse(code, lexer=parser.lexer)
        ##Return the IL
        return "".join(parser.value)
    else:
        return parser, yaccer

def generate_parse_tables(tab_os=None, tab_cpu=None, tab_code=None, tab_ver=None, dump=False, remove_previous_tables=True):
    """
    Generate all the parse tables we need for super fast parsing
    but making sure the tables reflect the current grammar and parser
    versions. Shipping parse tables statically will just cause a world
    of pain
    """
    ##Remove any copies of the previous tables found
    tab_list=["cp2_parsetab_v%s"%(VERSION), "x86_parsetab", "ppc_parsetab", "sparc_parsetab", "tidl_parsetab", "cp2_lextab_v%s"%(VERSION), "x86_lextab", "ppc_lextab", "sparc_lextab" ]
    for f in tab_list:
        try:
            os.unlink("MOSDEF%s%s.py"%(os.sep, f))
        except OSError:
            pass
        try:
            os.unlink("MOSDEF%s%s.pyc"%(os.sep, f))
        except OSError:
            pass

        try:
            os.unlink("MOSDEF%s%s.pckl"%(os.sep, f))
        except OSError:
            pass

    ##Have we specified a specific os/cpu to generate for - or do we want to do them all?
    if not tab_os or not tab_cpu:
        os_cpu_list=[
            ["Win32","X86"],
            ['Win64','X64'],
            ["Linux","X86"],
            ["Linux","ppc"],
            ["Solaris","sparc"],
            ["Solaris","X86"],
            ["OSX","ppc"],
            ["OSX","x86"],
            ["AIX", "ppc", '5.1'],
            ["AIX", "ppc", '5.2'],
        ]
        ##Should this also work ?? ["IRIX","mips"],["AIX", "rs6000", '5.1']
    else:
        os_cpu_list=[ [tab_os, tab_cpu, tab_ver] ]

    print "Generating parse tables for: %s"%(os_cpu_list),

    ##Use test code, or supplied code?
    if not tab_code:
        tab_code="""
                //comment
                void main()
                {
                int i;
                }
                """
    ##For each OS/CPU/VERSION set hit up the parser so as the parse tables are generated
    GEN_CODE={} #store the generated codes here in IL,ASM,BYTECODE order
    for target in os_cpu_list:

        tab_os=target[0]
        tab_cpu=target[1]
        if len(target) == 3:
            ##AIX has versions that need to be specified
            tab_ver=target[2]
        else:
            tab_ver=None

        ##ID for this set of code
        CODE_KEY="%s%s%s"%(tab_os,tab_cpu,tab_ver)

        ##Kick the parser so as the tables are generated for the os/cpu/version
        width=80

        il=getCparser(tab_os, tab_cpu, tab_ver, code=tab_code)

        ##KLUDGE : URGGH fix properly soon
        if tab_cpu.lower() == "powerpc":
            tab_cpu="ppc"

        ##AND now assemble
        il2proc = __import__('il2%s' % tab_cpu.lower())
        asm = il2proc.generate(il)


        bytecodes=mosdef.assemble(asm,tab_cpu.upper())
        GEN_CODE[CODE_KEY]=[il,asm,bytecodes]

        ##Do we want a pretty print out of what we made?
        if dump:
            print "\nOS: %s CPU:%s Ver: %s"%(tab_os, tab_cpu, tab_ver)
            print "="*width
            print "\nIL:%s\n"%il

            print "ASM:%s\n"%asm

            print "BYTECODE:"
            x=0
            for byte in bytecodes:
                print "0x%02x"%(ord(byte)),
                x+=5
                if x == width:
                    print "\n",
                    x=0

            print "\n"
            print "="*width


        ##CANVAS ONLY REMOVE FOR MOSDEF-------------------------------v
        ##Generate the tidl parse tables (lex tables phail atm)
        tidl_data="""
typedef struct {
[unique] [string] [size_is(4)] wchar_t * wkui0_username;
[unique] [string] [size_is(4)] wchar_t * wkui0_username2;
} bob;
"""
        from libs import tidlparse
        tidlparse.parse(tidl_data)


    return GEN_CODE

if __name__ == "__main__":

    #if MOSDEF is failing try: rm MOSDEF/*tab.pckl
    if len(sys.argv) >1:
        try:
            fd=open(sys.argv[1], "r")
            code=fd.read()
            fd.close()
        except Exception, err:
            print "Error opening specified code file: %s"%(err)
    else:
        code=None

    generate_parse_tables(dump=True, tab_code=code, tab_os='Win32', tab_cpu='X86')
    #generate_parse_tables(dump=False)
