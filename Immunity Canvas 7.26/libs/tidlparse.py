#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
tidlparse.py

A type IDL parser for CANVAS

Should parse snippet below and put it into a class we can get an instance class from later for DCE calls.

typedef struct {
uint32 job_time;
uint32 days_of_month;
uint8 days_of_week;
uint8 flags;
unistr *command;
} atsvc_JobInfo;
"""

import sys
if "." not in sys.path: sys.path.append(".")
from libs import tidllex

class tidlparse:
    def __init__(self):
        self.value=[]
        self.lexer,self.lexbase=tidllex.getlexer()
        self.tokens=self.lexer.lextokens.keys()
    
    def p_file(self, p):
        'file : typedefslist '
        #print "%s |||| %s |||| %s"%(p[1],p[3],p[4])
        self.value=p[1]
        
    def p_typedefslist(self, p):
        """typedefslist : typedefs typedefslist
            typedefslist : typedefs 
            typedefslist : empty
        """
        #print "typdefslist"
        if len(p)==3:
            p[0]=[p[1]]+p[2]
        else:
            p[0]=[p[1]]
        
    def p_typedefs(self,p):
        """typedefs : TYPEDEF attributelist STRUCT LBRACE typelist RBRACE ID SEMI
            typedefs : TYPEDEF attributelist UNION LBRACE typelist RBRACE ID SEMI
        """
        #print "Found type named %s"%p[6]
        #print "p[2]=%s"%p[2]
        if p[2]=="struct":
            p[0]=[p[2],p[6],p[4]]
            if p[6] not in self.lexbase.typenames:
                self.lexbase.typenames+=[p[-2]]        
        else:
            #union
            p[0]=[p[3],p[7],p[5]]
            if p[7] not in self.lexbase.typenames:
                self.lexbase.typenames+=[p[-2]]                    
                
    def p_typelist_1(self,p):
        'typelist : dcetype SEMI'
        #print "typelist_1"
        p[0]=[p[1]]
        #print "typelist_1: %s"%p[0]
        
    def p_typelist_2(self,p):
        'typelist : dcetype SEMI typelist'
        #print "Typelist_2"
        p[0]=[p[1]]+p[3]
        #print "typelist_2: %s"%p[0]
        
    def p_typelist_3(self,p):
        'typelist : empty'
        
    def p_dcetype(self,p):
        """dcetype :  TYPENAME starlist ID
            dcetype :  attributelist TYPENAME starlist ID"""
        if len(p)==5:
            p[0]=[p[1],p[2],p[3],p[4]]
            #print "p_type of type %s: %s"%(p[2],p[4])
        elif len(p)==4:
            p[0]=[[],p[1],p[2],p[3]]            
        return 
        
    def p_attributelist(self, p):
        """attributelist : attribute attributelist
            attributelist : 
        """
        #print "Attributelist"
        if len(p)==1: #empty case
            p[0]=[]
        elif len(p)==3:
            p[0]=[p[1]]+p[2]
        else:
            p[0]=[p[1]] #first attribute
            
    def p_attribute(self,p):
        """attribute : LBRACKET ID RBRACKET
            attribute : LBRACKET ID LPAREN ID RPAREN RBRACKET
            attribute : LBRACKET ID LPAREN TYPENAME RPAREN RBRACKET
            attribute : LBRACKET ID LPAREN ICONST RPAREN RBRACKET
        """
        #size_is(number) or size_is(variable)
        if len(p)<5:
            p[0]=p[2]
        else:
            #size_is, etc
            p[0]=[p[2],p[4]]
        
    def p_starlist(self,p):
        """starlist : STAR starlist
            starlist : 
        """
        #print "Starlist: length %d %s"%(len(p),p[1])
        if len(p)==1: #empty case
            p[0]=0
        elif len(p)==3:
            p[0]=1+p[2]
        else:
            p[0]=1 #number of stars
        
    def p_empty(self,p):
        'empty : '
        p[0]=None
    
    def p_error(self,t):
        print "Whoa. We're hosed at symbol %s"%t
 
#import profile
# Build the grammar

import os
from engine import CanvasConfig as config
existing_parsetables={}
def getparser():
    
    parser=tidlparse()
    lexer=parser.lexer
    
    if config["cparse_version"] == "2":
        from MOSDEF import yacc2 ##use PLY 2.5 not 1.4 - now we can do LALR
        ##Get existing parsetable for optimisation
        global existing_parsetables
        yaccer=yacc2.yacc(module=parser,method='LALR',debug=0,write_tables=1, optimize=1, tabmodule="MOSDEF%stidl_parsetab"%(os.path.sep))
        ##Save the unpickled parse table to the canvasengine so as other parses can grab it in future
        existing_parsetables=yaccer.pass_the_pickle
    else:
        from MOSDEF import yacc
        yaccer=yacc.yacc(module=parser,method='SLR',debug=0,write_tables=0, tabmodule="MOSDEF%stidl_parsetab"%(os.path.sep))
    
    return parser,yaccer,lexer
    
def parse(data):
    parser,newyacc,lexer=getparser()
    newyacc.parse(data,debug=0,lexer=lexer)
    return parser.value

    
if __name__ == "__main__":
    data2="""
    typedef struct {
   [unique] [string] [size_is(4)] wchar_t * wkui0_username;
   [unique] [string] [size_is(4)] wchar_t * wkui0_username2;
   } bob;
    """
    data="""
    
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
        typedef struct {
              long element_581; 
              long element_582; 
              short element_583; 
              [size_is(8)]  byte * element_584; 
        } TYPE_33 ;
    """
    ret=parse(data)
    print ret
