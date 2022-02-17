#! /usr/bin/env python

import string
import urllib
from mosdefutils import *


# function can be overwritten later
class ProcGenerate:
    def __init__(self, pointersize):
        self.initialized = False
        self.alignlen = 0
        self.pointersize = pointersize
        self.f_dict = {}
        self.R_dict = {}
    
    def prepare_dict(self):
        for n in dir(self):
            if n[0:2] == "t_":
                self.f_dict[n[2:]] = getattr(self, n)
            elif n[0:2] == "R_":
                self.R_dict[n] = getattr(self, n)
        self.initialized = True
    
    def generate(self, data):
        if not self.initialized:
            self.prepare_dict()
        
        self.out = ""
        assert type(data) == type("")
        
        #fd = open("out.il", "a")
        #fd.write("!!! NEWIL:\n\n" + data)
        #fd.close()
        
        lines=data.split("\n")
        for line in lines:
            # FIXME can we have ZeroDivisionError here?
            if line=="":
                continue
            args=line.split(" ")
            assert self.f_dict.has_key(args[0]), "no key <%s>" % args[0]
            self.f_dict[args[0]](args[1:])
        
        for reg_macro in self.R_dict.keys():
            if reg_macro in self.out:
                self.out = self.out.replace(reg_macro, self.R_dict[reg_macro])
        
        #fd = open("out.s", "a")
        #fd.write("!!! NEWASM:\n\n" + out)
        #fd.close()
        #print "ASM = %s"%out
        
        return self.out
    
    #---------------------
    # common instr/macros
    #---------------------
    
    def t_rem(self, args):
        self.out += "! %s\n"%(" ".join(args))
    
    def t_labeldefine(self, args):
        self.out += "%s:\n" % args[0]
    
    def t_asm(self, args):
        self.out += " ".join(args) + "\n"
    
    def t_ascii(self, args):
        self.alignlen += len(string.join(args)) % self.pointersize
        self.out += ".ascii \"%s\"\n" % " ".join(args)
    
    def t_longvar(self, args):
        self.out += ".long %s\n" % uint32fmt(args[0]) # 32/64?
    
    def t_databytes(self, args):
        assert not int(args[0]) >> 8, "BYTE VALUE OUTSIDE BYTE 0-255 RANGE ! (%x)" % int(args[0])
        self.alignlen += 1
        self.out += ".byte %d\n" % int(args[0])
    
    def t_urlencoded(self, args):
        self.alignlen += len(urllib.unquote(string.join(args))) % self.pointersize
        self.out += ".urlencoded \"%s\"\n" % " ".join(args)
    
    def t_archalign(self, padchar = ["A"]):
        self.alignlen %= self.pointersize
        if self.alignlen:
            self.out += ".ascii \"" + string.join(padchar) * self.alignlen + "\"\n"
            self.alignlen = 0

class IL2Proc:
    def __init__(self):
        pass
    
    def generate(self, data):
        lines=data.split("\n")
        out = []
        try:
            for line in lines:
                if line=="":
                    continue
                words=line.split(" ")
                try:
                    out += self.__class__.__dict__[ "_" + words[0] ](self, words)
                except KeyError:
                    print "IL tag not known: %s" % str(words)
                    
        except ZeroDivisionError:
            print out    
        return "".join(out)

    def _labeldefine(self, words):
        pass
    def _compare(self, words):
        pass
    def _loadlocal(self, words):
        pass
    def _storewithindex(self, words):
        pass
    def _poptosecondary(self, words):
        pass
    def _derefaccum(self, words):
        pass
    def _jump(self, words):
        pass
    def _accumulator2index(self, words):
        pass
    def _oraccumwithsecondary(self, words):
        pass
    def _derefwithindex(self, words):
        pass
    def _setifless(self, words):
        pass
    def _xoraccumwithsecondary(self, words):
        pass
    def _ascii(self, words):
        pass
    def _subtractsecondaryfromaccum(self, words):
        pass
    def _addconst(self, words):
        pass
    def _jumpiftrue(self, words):
        pass
    def _multaccumwithsecondary(self, words):
        pass
    def _subconst(self, words):
        pass
    def _setifnotequal(self, words):
        pass
    def _ret(self, words):
        pass
    def _loadint(self, words):
        pass
    def _call(self, words):
        pass
    def _asm(self, words):
        pass
    def _rem(self, words):
        pass
    def _addsecondarytoaccum(self, words):
        pass
    def _functionpostlude(self, words):
        pass
    def _urlencoded(self, words):
        pass
    def _dividesecondaryfromaccum(self, words):
        pass
    def _setifequal(self, words):
        pass
    def _loadlocaladdress(self, words):
        pass
    def _archalign(self, words):
        pass
    def _shiftright(self, words):
        pass
    def _pushaccum(self, words):
        pass
    def _jumpiffalse(self, words):
        pass
    def _multiply(self, words):
        pass
    def _arg(self, words):
        pass
    def _poptoshiftreg(self, words):
        pass
    def _longvar(self, words):
        pass
    def _callaccum(self, words):
        pass
    def _pushshiftreg(self, words):
        pass
    def _getstackspace(self, words):
        pass
    def _freestackspace(self, words):
        pass
    def _databytes(self, words):
        pass
    def _modulussecondaryfromaccum(self, words):
        pass
    def _loadglobaladdress(self, words):
        pass
    def _loadglobal(self, words):
        pass
    def _functionprelude(self, words):
        pass
    def _shiftleft(self, words):
        pass
    def _GETPC(self, words):
        pass
    def _accumulator2memorylocal(self, words):
        pass
    def _debug(self, words):
        pass
    def _andaccumwithsecondary(self, words):
        pass
    def _setifgreater(self, words):
        pass
    def _storeaccumulator(self, words):
        pass