#! /usr/bin/env python
import os
import sys
if "MOSDEF" not in sys.path: sys.path.append("MOSDEF")

class asmlex:
    """
    The base class for all the assembly lexer's. 
    
    This has to define lots of different internal variables that will
    get parsed by lex.py
    
    """
    tconsts = ["byte", "word", "short", "long", 'longlong', "ascii", "urlencoded"]
    deliminators_init = ("LBRACKET", "RBRACKET", "LPAREN", "RPAREN", "LBRACE", "RBRACE",
                         "COMMA", "PERIOD", "SEMI", "COLON", "ELLIPSIS", "STAR", "PERCENT",
                         "SUBTRACT", "PLUS", "NEWLINE", "DOLLAR")
    literals_init = ("ID", "FCONST", "SCONST", "ICONST", "HCONST", "TCONST", "REGISTER")
    operators = ()
    # reserved words
    reserved = ("OPCODE", 'BARRELSHIFT', "NOARGOPCODE", "ANNUL")
    reserved_dict = {}

    # Delimeters
    t_LBRACKET  = r'\['
    t_RBRACKET  = r'\]'
    t_LPAREN    = r'\('
    t_RPAREN    = r'\)'
    t_LBRACE    = r'\{'
    t_RBRACE    = r'\}'
    t_COMMA     = r','
    t_PERIOD    = r'\.'
    t_SEMI      = r';'
    t_COLON     = r':'
    t_ELLIPSIS  = r'\.\.\.'
    t_STAR      = r'\*'
    t_PERCENT   = r'\%'
    t_SUBTRACT  = r'\-'
    t_PLUS      = r'\+'
    t_DOLLAR    = r'\$'

    t_ignore=" \t\x0c"
    
    # Integer literal
    t_ICONST = r'([-+])?\d+'
    t_HCONST = r'([-+])?0x([\da-fA-F])+'
    
    # Floating literal
    t_FCONST = r'((\d+)(\.\d+)(e(\+|-)?(\d+))? | (\d+)e(\+|-)?(\d+))([lL]|[fF])?'
    
    # String literal
    """the first try at this doesn't work because it generates this bug:
        File "MOSDEF/lex.py", line 297, in realtoken
        m = self.lexre.match(lexdata,lexpos)
        RuntimeError: maximum recursion limit exceeded
        I believe removing it means we can't have multi-line strings with \ at the end
        , but that's a small price to pay for it actually working. The failure we
        were getting was:
            .urlencoded "%0AA...<long>"
        I wasn't able to cut this into a nice easy to reproduce problem, but
        removing the \\\n support is the fix, for now
    """
    #t_SCONST = r'\"([^?\\\n]|(\\.))*?\"'
    t_SCONST = r'\".*?\"'
    
    def __init__(self):
        self._init_internal_var('literals')
        self._init_internal_var('deliminators')
        self.tokens = self.reserved +  self.literals + self.operators + self.deliminators
        #initalize this dict of our reserved words (types, etc)
        for r in self.reserved:
            self.reserved_dict[r.lower()] = r
    
    def _init_internal_var(self, varname):
        varname_init = '%s_init' % varname
        if not hasattr(self, varname_init):
            print "Weird error in asmscan.py - couldn't find %s_init"%varname
            return
        if hasattr(self, varname):
            setattr(self, varname, getattr(self, varname_init) + getattr(self, varname))
        else:
            setattr(self, varname, getattr(self, varname_init))
    
    def t_NEWLINE(self,t):
        r'\n+'
        #print "ASM NEWLINE"
        t.lineno += t.value.count("\n")
        #t.type = "NEWLINE"
        #return t
    
    # ASM style Comments
    def t_comment(self,t):
        r'[!;]+.*\n'
        #print "ASM COMMENT", t.type
        t.lineno += t.value.count('\n')
        t.type = "NEWLINE"
        return t
    
    # Preprocessor directive (ignored)
    def t_preprocessor(self,t):
        r'\#(.)*?\n'
        #print 'ASM PREPROCESSOR LINE'
        t.lineno += 1
    
    def t_TCONST(self, t):
        r'\.(byte|word|short|long|ascii|urlencoded)'
        #print "ASM TCONST", t.value
        t.type = "TCONST"
        return t
    
    def t_error(self,t):
        print "Illegal character %s" % repr(t.value[0])
        t.skip(1)

try:
    from engine import CanvasConfig as config
    TABLE_PREFIX="MOSDEF%s"%(os.sep)
except ImportError:
    ##For Standalone MOSDEF
    print "Standalone MOSDEF"
    config={"cparse_version":"2"}
    TABLE_PREFIX=""
    
import lex, lex2
existing_lextab={}
def getlexer(procname, debug=0):
    
    #if config["cparse_version"] == "2":    
    #    import lex2 as lex
    #else:
    #    import lex
    
    mod =__import__('%sscan' % procname, level=-1)
    lexname = '%slex' % procname
    assert hasattr(mod, lexname), "error trying to get %s lexer" % procname
    
    lex_table_name="%s%s_lextab"%(TABLE_PREFIX,procname)
    
    proclex = getattr(mod, lexname)
    if config["cparse_version"] == "2":
        global existing_lextab
        lexer=lex2.lex(proclex(), debug, optimize=1, lextab=lex_table_name, pass_the_pickle=existing_lextab)
        existing_lextab=lexer.pass_the_pickle
        return lexer
    else:
        #return lex.lex(proclex(), debug, optimize=1, lextab=lex_table_name)
        return lex.lex(proclex(), debug)

