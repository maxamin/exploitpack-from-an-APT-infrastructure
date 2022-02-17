#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
tidllex.py

A type parser for idl. Only parsers structs and so forth.
"""

import sys, os
sys.path.append(".")

from engine import CanvasConfig as config
if config["cparse_version"] == "2":
    from MOSDEF import lex2 as lex
    existing_lex_tables={}
else:
    from MOSDEF import lex

class tidllex:
    def __init__(self):
        #reserved words
        self.reserved = ( "INT", "CHAR", "TYPEDEF", "STRUCT","UNION")
        
        self.literals=("ID","UUIDNUM","FCONST","SCONST","ICONST")
        self.operators=()
        
        # Delimeters
        self.t_LBRACKET  = r'\['
        self.t_RBRACKET  = r'\]'
        self.t_LPAREN    = r'\('
        self.t_RPAREN    = r'\)'
        self.t_LBRACE    = r'\{'
        self.t_RBRACE    = r'\}'
        self.t_COMMA     = r','
        self.t_PERIOD    = r'\.'
        self.t_SEMI      = r';'
        self.t_COLON     = r':'
        self.t_ELLIPSIS  = r'\.\.\.'
        self.t_STAR     = r'\*'

        self.deliminators=("LBRACKET","RBRACKET","LPAREN","RPAREN","LBRACE","RBRACE","COMMA","PERIOD","SEMI",
                      "COLON","ELLIPSIS","STAR",)
        self.tokens = self.reserved +  self.literals + self.operators + self.deliminators+("TYPENAME",)
        self.typenames=["wchar_t","char","int","long","DWORD","short","byte"]

        self.t_ignore=" \t\x0c"
        
        # Integer literal
        self.t_ICONST = r'\d+([uU]|[lL]|[uU][lL]|[lL][uU])?'
        
        # Floating literal
        self.t_FCONST = r'((\d+)(\.\d+)(e(\+|-)?(\d+))? | (\d+)e(\+|-)?(\d+))([lL]|[fF])?'
        
        # String literal
        self.t_SCONST = r'\"([^\\\n]|(\\.))*?\"'
        
    
        self.reserved_dict= {}
        #initalize this dict of our reserved words (types, etc)
        for r in self.reserved:
            self.reserved_dict[r.lower()]=r
        return    
    
    def t_NEWLINE(self,t):
        r'\n+'
        t.lineno += t.value.count("\n")
    
    # C style Comments (do we need prepended space?)
    def t_comment(self,t):
        r' /\*(.|\n)*?\*/'
        t.lineno += t.value.count('\n')
    
    # Preprocessor directive (ignored)
    def t_preprocessor(self,t):
        r'\#(.)*?\n'
        t.lineno += 1
    
    def t_UUIDNUM(self,t):
        r'[\dA-Fa-f]{8,8}-[\dA-Fa-f]{4,4}-[\dA-Fa-f]{4,4}-[\dA-Fa-f]{4,4}-[\dA-Fa-f]{12,12}'
        return t
        
    def t_ID(self,t):
        r'[A-Za-z_][\w_]*'
        #print "self.typenames=%s"%self.typenames
        if t.value in self.typenames:
            #print "Found typename"
            t.type="TYPENAME"
        else:
            t.type = self.reserved_dict.get(t.value,"ID")
        #print "t.value=%s t.type=%s"%(t.value,t.type)
        return t    
    
    def t_error(self,t):
        print "Illegal character %s" % repr(t.value[0])
        try:
            t.lexer.skip(1)
        except:
            t.skip(1)

def getlexer():

    lex_table_name="MOSDEF%stidl_lextab"%(os.path.sep)
    
    mylexer=tidllex()
    
    return (lex.lex(mylexer,debug=0,optimize=0),mylexer)
    ##USING LEXTABLE BUGS OUT HERE ??? WHY ??? RICH TODO
    #return (lex.lex(mylexer,debug=0,optimize=1, lextab=lex_table_name),mylexer)
    #global existing_lex_tables
    #lexer=lex.lex(mylexer,debug=0, optimize=1, lextab=lex_table_name, pass_the_pickle=existing_lex_tables)
    #existing_lex_tables=lexer.pass_the_pickle
    #return (lexer,mylexer)


if __name__ == "__main__":
    newlex,lexbase=getlexer()
    data="""
    
typedef struct  {
   [string] [unique] wchar_t * wkui0_username;
} WKSTA_USER_INFO_0;

    """

    data2="""
    
typedef struct  {
   [string] [unique] wchar_t * wkui0_username;
} WKSTA_USER_INFO_0;

typedef struct {
  long num_entries;
  [size_is(num_entries)] [unique] WKSTA_USER_INFO_0 * u_i_0;  /*type_10*/
} USER_INFO_0_CONTAINER;

typedef [switch_type(long)] union {  
  [case(0)] USER_INFO_0_CONTAINER * u_i_0_c;  
  /* [case(1)] WKSTA_USER_INFO_1 * user_info1;   */
} USER_INFO;
        
typedef   struct {
  long info_level;
  [switch_is(info_level)] USER_INFO element_91; /*was TYPE_8*/
} TYPE_5;

    """
    
    data="""
        typedef   struct {
              long element_581;
              short element_582;
              short element_583;
              [size_is(8)] byte *element_584;
              } TYPE_33;
    """
    newlex.input(data)
    while 1:
        token=newlex.token()
        print "Token=%s"%token
        if not token: break
   
