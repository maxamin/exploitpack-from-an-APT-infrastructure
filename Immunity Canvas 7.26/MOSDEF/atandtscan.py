#! /usr/bin/env python
from spark import GenericScanner


class Token:
        def __init__(self, type, attr=None, lineno='???'):
                self.type = type
                self.attr = attr
                self.lineno = lineno

        def __cmp__(self, o):
                return cmp(self.type, o)
        ###
        def __repr__(self):
                return "line: %s "%self.lineno+str(self.type)+":"+str(self.attr)
        
        #So we can use this as a leaf - see release notes for SPARK
        def __getitem__(self, i):	raise IndexError

class LineScanner(GenericScanner):
        def __init__(self):
                GenericScanner.__init__(self)
                self.lineno=1
        
        def tokenize(self, input):
                self.tokens = []
                lines=input.split("\n")
                for line in lines:
                        #if self.lineno in range(65,75):
                        #        print "LINE: %s"%line
                        #remove inline comments
                        line=line.split(" //")[0]
                        GenericScanner.tokenize(self, line)
                        self.lineno+=1

                        t=Token(type='NEWLINE',lineno=self.lineno)
                        self.tokens.append(t)
                return self.tokens


#for setting the t_mnemonic line below
#note that popl must come before pop, and so on.
#this generates the correct string, don't modify it manually.
#Contact dave if you think this needs fixing.
if 0:
        import x86opcodes
        l=x86opcodes.getAllMnemonics()
        l.sort()
        l.reverse()
        print "r'(%s)((?=[ ])|(?=$))'"%"|".join(l)

        
class ATTScanner(LineScanner):
        """
        Scans for AT&T assembly code. Anything not recognized is a "label"
        """
        def __init__(self):
                LineScanner.__init__(self)
        

        ####OPCODES!

        def t_mnemonic(self,s):
                r'(xorl|xorb|xor|xchg|test|subl|sub|stosw|stosl|stosb|sidt|shrl|shr|shll|shl|sgdt|setne|setna|setle|setl|setge|setg|sete|setc|setbe|setb|setae|seta|scasw|scasl|scasb|ror|ret|repne|repe|rep|pushw|pushl|pushad|push|popl|popad|pop|orl|orb|or|not|nop|neg|mul|movzwl|movzbl|movw|movsw|movsl|movsb|movl|movb|mov|loopz|loopnz|loopne|loope|loop|lodsw|lodsl|lodsd|lodsb|leave|leal|lea|jz|js|jpo|jpe|jp|jo|jnz|jns|jnp|jno|jnle|jnl|jnge|jng|jne|jnc|jnbe|jnb|jnae|jna|jmp|jle|jl|jge|jg|jecxz|je|jcxz|jc|jbe|jb|jae|ja|int3|int|insw|insl|insb|incw|incl|incb|inc|idivl|imul|farret|div|decl|decb|dec|cwd|cmpw|cmpsw|cmpsl|cmpsb|cmpl|cmpb|cmp|cltd|cld|cdql|cdq|call|andl|andb|and|addl|addb|add|syscall)((?=[ ])|(?=$))'
                #r'cltd((?=[ ])|(?=$))'
                #see above to set this line - must be in a particular order, so don't add them manually.
                t=Token(type='mnemonic',attr=s,lineno=self.lineno)
                self.tokens.append(t)
                

        def t_default(self,s):
                r'[a-zA-Z_][a-zA-Z0-9_]+'
                #print "Default Matched: *%s*"%s
                t=Token(type='name',attr=s,lineno=self.lineno)
                self.tokens.append(t)   
        
        def t_whitespace(self, s):
                r'\s+'
                pass
        
        def t_star(self,s):
                #these are used in front of calls, but we can just ignore them...
                r'\*'
                pass
        
        def t_decnumber(self, s):
                r'[+-]?(?!0x)\d+'
                t = Token(type='decnumber', attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_hexnumber(self,s):
                r'[+-]?0x[a-fA-F0-9]+'
                t = Token(type='hexnumber', attr=s,lineno=self.lineno)
                self.tokens.append(t)
                
        def t_colon(self,s):
                r':'
                t = Token(type=':', attr=s,lineno=self.lineno)
                self.tokens.append(t)
        
        def t_reg(self,s):
                r'%(eax|ebx|ecx|edx|esi|edi|esp|ebp|ax|bx|cx|al|ah|bl|bh|cl|ch|dl|dh|di|dx|si)'
                t=Token(type='reg',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_segreg(self,s):
                r'%(fs):'
                t=Token(type='segreg',attr=s,lineno=self.lineno)
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

                
        def t_quotedstring(self,s):
                r'".*?"'
                t=Token(type='quotedstring',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_urlencodeddefine(self,s):
                r'\.urlencoded'
                t=Token(type='urlencodeddefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)
                   
        def t_asciizdefine(self,s):
                r'\.asciz'
                t=Token(type='asciizdefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_asciidefine(self,s):
                r'\.ascii'
                t=Token(type='asciidefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)

                  
        def t_longdefine(self,s):
                r'\.long'
                t=Token(type='longdefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_shortdefine(self,s):
                r'\.short'
                t=Token(type='shortdefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_bytedefine(self,s):
                r'\.byte'
                t=Token(type='bytedefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)
                
        def t_globaldefine(self,s):
                r'\.globl'
                t=Token(type='globaldefine',attr=s,lineno=self.lineno)
                self.tokens.append(t)

        def t_comment(self,s):
                r'[ \r\t]*(\#|//).*'
                pass
        
class strwreadline:
        """
        Wraps a string up to be able to do a readline so you can tokenize it
        """
        def __init__(self,s):
                self.str=s
                self.current=self.str
                
        def readline(self,size=0):
                print "Max Readline Size=%d"%size
                index=self.current.find("\n")
                if index==-1:
                        tmp=self.current
                        self.current=""
                        print "tmp=%s"%tmp
                        return tmp
                else:
                        #print "Index=%d"%index
                        tmp=self.current[:index]
                        tmp=tmp.strip()+"\n"
                        #clear comments
                        #print "tmp=%s"%tmp
                        if tmp[0:3]=="//":
                                tmp="\n"
                        self.current=self.current[index+1:]
                        #print "Returning %s"%tmp
                        return tmp
        
def scan(f):

        myscanner=ATTScanner()
        mystr=strwreadline(f)
        tokens=myscanner.tokenize(f)
        return tokens


if __name__=="__main__":
        try:
                data=file("test.s").read()
        except:
                data=open("MOSDEF/test.s").read()
        ret=scan(data)
        print ret
        
