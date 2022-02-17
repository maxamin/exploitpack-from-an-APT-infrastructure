#! /usr/bin/env python

TODO = """
add here * related to idornumber from riscparse
"""

from mosdefutils import *
import urllib
import struct

class asmparse:
    
    def __init__(self, runpass=1):
        self.length = 0
        self.runpass = runpass

    def newlabel(self,labelname):
        if self.runpass==1:
            #print "newlabel: %s at %s"%(labelname,self.length)
            self.labelinfo[labelname]=self.length
        else:
            pass
        return
    
    def resolvelabel(self,label):
        #print "resolvelable: %s"%label
        if label=="./":
            #special purpose label - current location
            return self.length
        
        if self.runpass>1:
            ret=self.labelinfo.get(label)
            if ret==None:
                #can't decide if zero is better than ./ here
                #return 0
                return self.length+10
        else:
            #print "first pass...no label resolution"
            #ret=0
            return self.length+10
        #print "resolved %s to %s"%(label,ret)
        return ret
    
    def p_linelist_with_line(self, p):
        'linelist : line'
    
    def order_longlong(self, longlongint):
        return struct.pack('>Q', longlongint)

    def order_long(self, longint):
        return big_order(longint)
    
    def order_word(self, word):
        return int2str16(word)
    
    def p_line_with_TCONST(self, p):
        '''line : TCONST ID
           line : TCONST number
           line : TCONST SCONST'''
        #.globl start,
        #print "p_line_with_TCONST: %s"%p[1]
        if p[1] in [".word", ".short"]:
            #might have some alignment issues here on SPARC/etc
            newvalue=self.order_word(p[2])
            self.value+=[newvalue]
            self.length+=len(newvalue)
        elif p[1]==".long":
            self.value+=[self.order_long(p[2])]
            self.length+=4
        elif p[1] == '.longlong':
            self.value  +=[self.order_longlong(p[2])]
            self.length += 8
        elif p[1]==".urlencoded":
            #again, need to review for alignment issues
            encoded = p[2][1:-1]
            encoded = urllib.unquote(encoded)
            self.value+=[encoded]
            self.length+=len(encoded)
        elif p[1]==".ascii":
            #and again - alignment!
            ascii = p[2][1:-1]
            self.value+=[ascii]
            self.length+=len(ascii)
        elif p[1]==".byte":
            #this is pretty much guaranteed to have alignment issues
            #but we don't want to mess with it, do we? We have to
            #trust the user on this.
            self.value+=[chr(int(p[2]))]
            self.length+=1
        else:
            print "Did not understand..."
            raise AssertionError, "WARNING: Didn't understand directive %s" % str(p[1])
    
    def p_line_of_label(self, p):
        'line : ID COLON'
        #label of form "start:" or ".local:"
        #devlog("riscparse","Found label %s"%p[1])
        self.newlabel(p[1])
    
    def p_line_of_newline(self, p):
        'line : NEWLINE'
        pass
    
    def p_number(self, p):
        '''number : HCONST
           number : ICONST
           number : SUBTRACT HCONST
           number : PLUS HCONST
           number : SUBTRACT ICONST
           number : PLUS ICONST
           '''
        if len(p)==2:
            p[0]=long(p[1],0)
        else:
            if p[1]=="+":
                p[0]=long(p[2],0)
            else:
                p[0]=-long(p[2],0)
    
    def p_error(self, p):
        raise AssertionError, "Whoa. We're hosed at symbol %s" % p


