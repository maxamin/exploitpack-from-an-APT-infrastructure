"""
Vartree is used by cparse2.py
"""

import sys
if "." not in sys.path: sys.path.append(".")

from mosdefutils import *

from internal import *

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
        def __init__(self, defines = {}, debug=True):
            self.tree={}
            self.tree['globals'] = {'defines': defines, 'variables': {}, 'functions': {}}
            self.current = "globals"
            self.currentfunction = None
            self.esps=[0] #last esp is current frame's offset
            
            if debug:
                self.debug=True
                self.tree_all_debug={}
        
        def addvar(self,label,varname,type):
            """
                Addvar needs to handle arguments to functions as well as 
                variables declareed on the stack
            """
            if type!=None:
                varsize=type.getstacksize()
            else:
                print "addver %s type is None!"%varname
                varsize=0 
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
            devlog("cparse2","Adding function %s"%functionname)
        
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
            if self.debug:
                ##Add into the dict that has all the functions in otherwise we loose it when up() is called
                self.tree_all_debug[self.current]=self.tree[self.current]
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
            ##devlog("cparse2","Looking for %s"%variable)
            ##devlog("cparse2","Functions list %s"%self.tree[self.current]['functions'])
        
            if self.tree['globals']['functions'].has_key(variable):
                ##devlog("cparse2","Found function pointer for %s"%variable)
                return (variable, 'function pointer', self.tree['globals']['functions'][variable], None)
        
            #sOME KIND OF ERROR
            #print "cparse::getvar() variable=%s can't find variable" % variable
            return (None,None,None,None)

        def dump_tree(self):
                """
                Return a copy of the variable and print to screen if required
                """
                if 1:
                        self.tree_all_debug["globals"]=self.tree[self.current]
                        print "Variable Tree Structure:"
                        print "-"*70
                        for id in self.tree_all_debug:
                                print id
                                
                                for type in self.tree_all_debug[id]:
                                        print "\t %s"%(type)
                                        
                                        for var in self.tree_all_debug[id][type]:
                                                
                                                if type == 'link':
                                                        print "\t\t %s"%(self.tree_all_debug[id][type])
                                                        break
                                                else:
                                                        print "\t\t %s - %s"%(var,self.tree_all_debug[id][type][var])
                                print "\n"
                        print "-"*70
                
                return self.tree_all_debug
