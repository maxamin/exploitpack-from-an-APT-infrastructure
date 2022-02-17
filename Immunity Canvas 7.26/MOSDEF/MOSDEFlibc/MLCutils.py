#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
if "." not in sys.path: sys.path.append(".")
try:
    from MOSDEF.mosdefutils import *
except ImportError:
    ##Standalone MOSDEF
    from mosdefutils import *

class MLCendian:
    """
    a class that prepare endianness functions for a specific processor
    """
    # TODO add more func here, or a func dispatcher, i.e.: endianorder(func, args)
    #      to handle shorts, arrays
    
    _order = None
    _dispatchdict = {'little': str2littleendian, 'big': str2bigendian}
    
    def __init__(self):
        #print "INITIALIZING MLCendian: %s"%self.Endianness.lower()
        self._order = self.Endianness.lower()
        assert self._order in self._dispatchdict.keys(), "Endianness must be ['big', 'little']"
        
        # NOTE: MOSDEF integer are signed longs, but the following htons/htonl should be correct.
        
        if self._order == 'little':
            #print "[!] using MLC hton*"            
            self.localfunctions["htons"] = ("c", """
            int htons(unsigned short int value)
            {
                unsigned short ret;
                unsigned short ret2;
                
                ret = value & 0xff; // needed because MOSDEF doesn't handle well short type
                ret = ret << 8;
                ret2 = value & 0xff00; // needed because MOSDEF doesn't handle well short type
                ret2 = ret2 >> 8;
                ret = ret + ret2;
                
                return ret;
            }
            """)
            self.localfunctions["htonl"] = ("c", """
            int htonl(unsigned int value)
            {
                unsigned int ret;
                unsigned int ret2;
                unsigned int ret3;
                unsigned int ret4;
                
                //ret = value & 0x000000ff; // useful?
                ret = value << 24;
                ret2 = value & 0x0000ff00;
                ret2 = ret2 << 8;
                ret3 = value & 0x00ff0000;
                ret3 = ret3 >> 8;
                //ret4 = value & 0xff000000; // useful?
                ret4 = value >> 24;
                ret=ret+ret2+ret3+ret4;
                
                return ret;
            }
            """)
        else:
            self.localfunctions["htons"] = ("c", """
            int
            htons(unsigned short int value)
            {
                return value;
            }
            """)
            
            self.localfunctions["ntohs"] = ("c", """
            int
            ntohs(unsigned short int value)
            {
                return value;
            }
            """)
            
            self.localfunctions["htonl"] = ("c", """
            int
            htonl(unsigned int value)
            {
                return value;
            }
            """)
            
            self.localfunctions["ntohl"] = ("c", """
            int
            ntohl(unsigned int value)
            {
                return value;
            }
            """)
    
    def endianorder(self, str):
        """
        return the 4chars string in an endian-ordered long
        """
        assert hasattr(self, 'Endianness'), "class must contain self.Endianness to be able to use self.endianorder()"
        #if not self._order:
        #    self._order = self.Endianness.lower()
        #    assert self._order in self._dispatchdict.keys(), "Endianness must be ['big', 'little']"
        return self._dispatchdict[self._order](str)


class MLCdefines:
    """
    the main important class, that prepares internal values for the whole module
    here we provide the main important functions too: setdefine() and getdefines()
    """
    
    # where we store our #define, kind of 'global' for all the class
    # should not be modified with 'local's var by functions
    # to use it, a function has to call getdefines(), then can modify that dict.
    
    def __init__(self):
        #print "INITIALIZING MLCDefines"
        #MLCendian.__init__(self) # we do this explicitly later
        self.ro_defines = antifloatdict()	# local, Read-Only
        self.ro_defines['__MOSDEF__'] = True	# -D__MOSDEF__ internally defined by MOSDEF compiler
    
    def getdefine(self, name):
        """
        return the value of a define name
        """
        
        if not self.ro_defines.has_key(name):
            return None
        return self.ro_defines[name]
    
    def getdefines(self):
        """
        return a copy of the read-only internal #defines dictionary.
        the returned dictionary can be modified and deleted by any function
        (we wont modify the internal read-only #defines dictionary)
        """
        
        return self.ro_defines.copy()
    
    def setdefine(self, name, value = None, force_define_with_lowercases = False):
        """
        add a name:value entry to the internal read-only dictionary of #defines
        """
        
        if len(name) > 4 and (name[:2] == "__" and name[-2:] == "__"):
            pass
        elif not force_define_with_lowercases and not name.isupper():
            print "can not add [%s] define (name has to be uppercase)" % name
            return
        __valkludge = {None: 0, True: 1, False: 0} # None for NULL
        if value in __valkludge.keys():
            valuename = str(value)
            value = __valkludge[value]
        else:
            try:
                valuename = uint32fmt(value)
            except ValueError:
                valuename = str(value)
        devlog('MLCdefines::setdefine()', "adding %s = %s" % (name, valuename))
        # XXX when will ppl help me on that?!@!@#$!@#%$!@#%
        self.ro_defines[name] = value
        setattr(self, name, value)    # XXX need to be checked
        """
        if hasattr(self, name):
            try:
                delattr(self, name)
            except AttributeError:
                print name, getattr(self, name)
                pass
        """
    
    def unsetdefine(self, name):
        if self.ro_defines.has_key(name):
            del self.ro_defines[name]
    
    def setdefines(self, dict, force_define_with_lowercases = 0):
        """
        a macro that calls setdefine() for each entry in the dictionary provided in argument
        """
        
        for name in dict.keys():
            self.setdefine(name, dict[name], force_define_with_lowercases)
    
    def setdefinealias(self, aliasname, realname):
        self.setdefine(aliasname, self.getdefine(realname), force_define_with_lowercases = True)
    
    def _init_defines(self):
        """
        called once all the class is loaded to initialize internal read-only dictionary of #defines
        only used by GetMOSDEFlibc()
        """
        
        # init_shortcut_vars() is a kind of hack, isn't it?
        if hasattr(self, 'init_shortcut_vars'):
            self.init_shortcut_vars()
        for name in dir(self):
            obj = getattr(self, name)
            if not callable(obj):
                if name.isupper():
                    self.setdefine(name, obj)
                elif name[:4] == "SYS_":
                    self.setdefine(name, obj, force_define_with_lowercases = True)
                elif len(name) > 4 and (name[:2] == "__" and name[-2:] == "__"):
                    self.setdefine(name, obj, force_define_with_lowercases = True)
                #delattr(self, name)
    
    def _init_syscall_table(self):
        """
        if we have some _syscall_table[version] dictionary, here we add it in our main dictionary
        """
        
        if not hasattr(self, '_syscall_table'):
            return
        
        if self.version not in self._syscall_table.keys():
            return
        
        syscall_table_defines = {}
        for syscall in self._syscall_table[self.version].keys():
            syscallname = syscall
            if syscall[:4] != 'SYS_':
                syscallname = 'SYS_' + syscall
            syscall_table_defines[syscallname] = self._syscall_table[self.version][syscall]
        self.setdefines(syscall_table_defines, force_define_with_lowercases = True)
    
    def _init_defines_aliases(self):
        if not hasattr(self, '_aliases_table'):
            return
        for entry in self._aliases_table:
            (aliasname, realname) = entry
            self.setdefinealias(aliasname, realname)
    
    def patch_defines_with_values(self, codetext, definenames_list):
        assert type(definenames_list) == type([]), "expecting a list for definenames"
        for name in definenames_list:
            value = "%s" % self.ro_defines[name]
            devlog('MLCdefines::patch_defines_with_values', "%s -> %s" % (name, value))
            codetext = codetext.replace(name, value)
        return codetext
     
    def getlocalfunctions(self):
        return self.localfunctions.copy()


class MLCutils(MLCdefines, MLCendian):
    
    _MLCutils_initialized = False
    
    def __init__(self):
        if self._MLCutils_initialized:
            return
        self._MLCutils_initialized = True
        MLCdefines.__init__(self)
        if hasattr(self, 'Endianness'):
            MLCendian.__init__(self)
    
    def __str__(self):
        if not hasattr(self, '_names'):
            return "<MOSDEFlibc unknown instance>"
        if not self._names['version']:
            vers = ""
        else:
            vers = "(%s)" % self._names['version']
        return "<MOSDEFlibc %s%s/%s instance>" % (self._names['os'], vers, self._names['proc'])
    
    def postinit(self):
        """
        POST initialize the class
        """
        MLCdefines._init_defines(self)
        MLCdefines._init_syscall_table(self)
        MLCdefines._init_defines_aliases(self)
        if hasattr(self, '_names'):
            for key in ['os', 'proc']:
                if self._names.has_key(key):
                    self.setdefine("__%s__" % self._names[key])
                    self.setdefine("__%s__" % self._names[key].lower())
                    self.setdefine("__%s__" % self._names[key].upper())
    
