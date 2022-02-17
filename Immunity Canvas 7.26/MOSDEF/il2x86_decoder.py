#! /usr/bin/env python
"""
Converts a IL file (or buffer) into AT&T syntax x86
"""

from mosdefutils import *
from atandtparse import assemble

def checkfilter(ilstr,filter):
    """
    Checks our il against our filter
    """
    d="\n".join(ilstr)
    x=assemble(d)
    ret=filter(x.value)
    if not ret:
        print "Failed: %s -> %s"%(ilstr,prettyprint(x.value))
    else:
        print "Success: %s"%prettyprint(x.value)
    return ret


from x86opcodes import reglist, reglist2, reglist3, reglist4, reglist5, allshortregs
usableregs=reglist[:]

usableregs.remove("%esp") #don't use ESP
usableregs.remove("%rsp")

from random import randint

def get_byte_var(areg):
    """
    %eax -> %al
    """
    ret=""
    ret="%%%sl"%areg[2]
    return ret

byteregs=["%eax","%ebx","%ecx","%edx"]
def not_byte_reg(areg):
    if areg not in byteregs:
        return 1
    return 0

def get_random_byte_reg():
    return byteregs[randint(0,3)]

class smart_register_allocator:
    """
    A weird little assembler thing - keeps track of which variables
    are in which registers...
    """
    def __init__(self,filter):
        self.unallocated_regs=usableregs[:]
        self.variable_dict={}
        self.allocate("GETPC",reg="%ebx")
        self.unallocated_regs.remove("%ebx")
        self.filter=filter
        #if we're in a loop, we don't allocate ecx
        self.inloop=0
        #two variables we emit when we emit our final teststring
        self.prelude=""
        self.postlude=""
        #saving state
        self.saved_variable_dict={}
        self.saved_unallocated_regs=[]
        self.saved_prelude=""
        self.saved_postlude=""
        self.swapped=[]
        return

    def clear(self):
        """Clears our prelude and postlude to begin testing"""
        self.prelude=""
        self.postlude=""
        self.swapped=[]
        return
    
    def save_state(self):
        self.saved_variable_dict=self.variable_dict.copy()
        self.saved_unallocated_regs=self.unallocated_regs[:]
        self.saved_prelude=self.prelude
        self.saved_postlude=self.postlude
        self.saved_swapped=self.swapped[:]
        return
    
    def restore_state(self):
        self.variable_dict=self.saved_variable_dict.copy()
        self.unallocated_regs=self.saved_unallocated_regs[:]
        self.prelude=self.saved_prelude
        self.postlude=self.saved_postlude
        self.swapped=self.saved_swapped[:]
        return
    
    def getstr(self,teststr):
        "prepends our prelude, postends our postlude..."
        return "%s\n%s\n%s\n"%(self.prelude,teststr,self.postlude)

    def try_emit(self,teststr):
        """
        test to see if the string will pass...
        This also tests the prelude and postlude
        """
        realstr=self.getstr(teststr)
        print "Try_emit Looking at teststr: %s"%realstr
        return checkfilter([realstr],self.filter)
        
    def free_var(self,var):
        """
        mov a register from our allocated list into our unallocated list
        and remove the name from variabledict
        """
        reg=self.variable_dict[var]
        del self.variable_dict[var]
        self.unallocated_regs+=[reg]
        return
    
    def pick_free_reg(self):
        """
        pick a free register and return it
        """
        #pick a random register
        num=randint(0,len(self.unallocated_regs)-1)
        #print "num=%d"%num
        reg=self.unallocated_regs[num]
        #remove it from our unallocated list, cause we're using it
        self.unallocated_regs.remove(reg)
        return reg
        
    def copy_var(self,var1,var2):
        """
        copy var1 to var2 - allocate var2 if it doesn't exist.
        All variables are 32 bits
        """
        if var1 not in self.variable_dict.keys():
            print "Error %s not in variable_dict"%var1
            return []
        reg1=self.variable_dict[var1]
        if var2 in self.variable_dict.keys():
            reg2=self.variable_dict[var2]
        else:
            reg2=self.allocate(var2)
        teststr="mov %s, %s\n"%(reg1,reg2)
        ret=self.try_emit(teststr)
        if ret:
            return self.getstr(teststr)
        print "No such luck in copy_var"
        return []

    def get_or_allocate(self,variable):
        if variable in self.variable_dict.keys():
            return self.variable_dict[variable]
        else:
            return self.allocate(variable)
        
    def allocate(self,variable,reg=""):
        """
        """
        print "Creating %s variable..."%variable
        if reg:
            reg2=reg
        else:
            reg2=self.pick_free_reg()
        self.variable_dict[variable]=reg2
        
        return reg2
    
    def set_int(self,variable,value):
        self.clear()
        value=dInt(value)
        reg=self.variable_dict[variable]
        #first try simple mov
        teststr="mov $%s, %s\n"%(uint32fmt(value),reg)
        ret=self.try_emit(teststr)
        if ret:
            return self.getstr(teststr)
        
        clear1="xor %s, %s\n"%(reg,reg)
        clear2="and $0, %s\n"%(reg)
        clear3="or $-1, %s\ninc %s\n"%(reg, reg)
        clear4="shl $32 , %s\n"%reg
        clear5="sub %s, %s\n"%(reg,reg)
        success=0
        for clear in [clear1,clear2,clear3,clear4,clear5]:
            ret=self.try_emit(clear)
            if ret:
                success=1
                break
        if not success:
            print "Could not clear %s"%reg
            return
        self.prelude=clear
        #now do setint itself
        for opcode in ["add","or"]:
            teststr="%s $%s, %s\n"%(opcode,uint32fmt(value),reg)
            ret=self.try_emit(teststr)
            if ret:
                return self.getstr(teststr)
        teststr="%s\nsub $%s, %s\n"%(clear,uint32fmt(-value),reg)
        ret=self.try_emit(teststr)
        if ret:
            return self.getstr(teststr)
            
        print "Could not set_int!"
        return "ERROR set_int %s %s\n"%(variable,value)
        
    def insertlabel(self,label):
        self.clear()
        teststr="%s:\n"%label
        return self.getstr(teststr)
    
    def increment(self,var):
        self.clear()
        #todo - switch vars if it fails
        reg=self.variable_dict[var]
        teststr1="inc %s\n"%reg
        teststr2="add $1, %s\n"%reg
        teststr3="sub $-1, %s\n"%reg
        for teststr in [teststr1,teststr2,teststr3]:
            ret=self.try_emit(teststr)
            if ret:
                return self.getstr(teststr)
        print "FAILED ON INCREMENT %s"%var
        raise SystemError
    
    def add(self,var,value):
        #todo - switch vars if it fails
        self.clear()
        try:
            value=dInt(value)
            teststr="add $%s, %s\n"%(uint32fmt(value),self.variable_dict[var])
        except:
            #two values,
            var2=value
            teststr="add %s, %s\n"%(self.variable_dict[var],self.variable_dict[var2])
        return self.getstr(teststr)
    
    def get_var_from_reg(self,reg):
        for var in self.variable_dict.keys():
            if self.variable_dict[var]==reg:
                return var
        print "SERIOUS ERROR in get_var_from_reg(%s)"%reg
        return None #serious error
    
    def swap_vars(self,var1,var2):
        """
        swap two variables
        """
        print"Swap_vars(%s,%s)"%(var1,var2)
        reg1=self.variable_dict[var1]
        reg2=self.variable_dict[var2]
        self.variable_dict[var1]=reg2
        self.variable_dict[var2]=reg1
        self.prelude+="xchg %s, %s\n"%(reg1,reg2)
        return 
    
    def swap_with_reg(self,var,reg):
        """swap a variable into a register
        returns assembly that will do this """
        if reg in self.unallocated_regs:
            self.unallocated_regs.remove(reg)
        else:
            old_var=self.get_var_from_reg(reg)
            if old_var==None:
                print "Whoa: old_var is none - someone didn't add a register to the unallocated list!"
                print "Trying to get register %s"%reg
                print "Unallocated registers: %s"%self.unallocated_regs
            return self.swap_vars(old_var,var)
        old_reg=self.variable_dict[var]
        self.unallocated_regs.append(old_reg)
        self.variable_dict[var]=reg
        teststr="xchg %s, %s\n"%(reg,old_reg)
        self.prelude+="xchg %s, %s\n"%(reg,old_reg)
        if self.inloop:
            #print "Adding postlude to swap registers back"
            #if we're in a loop, we need to swap these back!
            #self.postlude="xchg %s, %s\n"%(reg,old_reg)+self.postlude
            self.swapped+=[(var,reg)]
        return 
            
    def swap_with_byte_reg(self,var):
        """Always swaps with eax for now"""
        reg=get_random_byte_reg()
        self.swap_with_reg(var,reg)
        return reg
    
    def swap_with_random_reg(self,var):
        out=""
        myreglist=reglist[:]
        if self.inloop:
            #don't swap with ecx when inside a loop
            myreglist.remove("%ecx") 
        reg=myreglist[randint(0,len(myreglist)-1)]
        self.swap_with_reg(var,reg)
        #if we're in a loop, we need to swap things back after 
        #we've done our operation - so we need a "postlude"
        return reg
    
    def getbyte(self,source,var):
        """
        Gets one byte from our source register - essentially is a 
        movb (%esi), %var
        
        Of course, we can't support moving a byte into %esi - there's no %sl
        
        """
        self.clear()

        var_reg=get_byte_var(self.get_or_allocate(var))
        if not_byte_reg(var_reg):
            new_reg=self.swap_with_byte_reg(var)
            var_reg=get_byte_var(new_reg)
        source_reg=self.variable_dict[source]
        self.save_state()
        for i in range(0,14): #random number of tries. I liked 14.
            teststr="movb (%s), %s\n"%(source_reg,var_reg)
            ret=self.try_emit(teststr)
            if ret:
                return self.getstr(teststr)
            self.restore_state()
            var_reg=self.swap_with_byte_reg(var)
            var_reg=get_byte_var(var_reg)            
            source_reg=self.swap_with_random_reg(source)
        return None

    def store_byte(self,source,dest):
        """
        does a storb %src, (%dst)
        """
        self.clear()
        source_reg=get_byte_var(self.variable_dict[source])
        dest_reg=self.variable_dict[dest]
     
        if not_byte_reg(source_reg):
            new_reg=self.swap_with_byte_reg(source)
            source_reg=get_byte_var(new_reg)
        for i in range(0,14): #random number of tries. I liked 14.
            teststr="movb %s, (%s)\n"%(source_reg,dest_reg)
            print "Teststr= %s"%teststr
            ret=self.try_emit(teststr)
            if ret:
                ret=self.getstr(teststr)
                print "returning %s"%ret
                return ret
            source_reg=self.swap_with_byte_reg(source)
            source_reg=get_byte_var(source_reg)            
            dest_reg=self.swap_with_random_reg(dest)
        return None

    def and_byte(self,var,value):
        self.clear()
        var_reg=get_byte_var(self.variable_dict[var])
        try:
            value=dInt(value)
            teststr="andb $%s, %s\n"%(uint8fmt(value),self.variable_dict[var])
        except:
            #two values,
            var2=value
            teststr="andb %s, %s\n"%(self.variable_dict[var],self.variable_dict[var2])
            
        return [teststr]
    
    def shl(self,var,bits):
        self.clear()
        var_reg=self.variable_dict[var]
        bits=dInt(bits)
        teststr="shl $%s, %s\n"%(bits,var_reg)
        ret=self.try_emit(teststr)
        if ret:
            return self.getstr(teststr)
        return None
    
    def startloop(self,var,loopname):
        self.clear()
        self.inloop=1
        reg=self.variable_dict[var]
        out=""
        if reg!="%ecx":
            self.swap_with_reg(var,"%ecx")
        teststr="%s:\n"%loopname
        #no checking here
        return self.getstr(teststr)
    
    def loop(self,loopto):
        self.clear()
        ret=""
        #var_reg=self.variable_dict[variable]
        var_reg="%ecx"
        testloop="loop %s\n"%loopto
        teststr1="dec %s\ntest %s, %s\njnz %s\n"%(var_reg,var_reg,var_reg,loopto)
        for teststr in [teststr1, testloop]:
            #we can't test this because we don't store the whole buffer
            #and hence, we have no idea what loop is going to look like
            trystr="%s:\n%s"%(loopto,teststr)
            ret=self.try_emit(trystr)
            if ret:
                self.inloop=0 #end loop
                return self.getstr(teststr)
        print "Could not figure out how to do the loop..."
        return None
        
def generate(data,filter):
    """
    data is our IL
    filter is our filter function
    """
    out=[]
    lines=data.split("\n")
    #get our smart register allocator we will be storing state in
    reg_alloc=smart_register_allocator(filter)
    
    try:
        for line in lines:
            if line=="":
                continue
            print "Line: %s"%line
            line=line.replace("  "," ") #no doubles
            words=line.split(" ")
            out+=["// %s\n"%words]
            if words[0]=="GETPC":
                #this is 5 bytes
                d=[]
                d+=["call RESERVED_getpc\n"]
                d+=["RESERVED_getpc:\n"]
                d+=["pop %ebx\n"]
                ret=checkfilter(d,filter)
                if not ret:
                    print "checkfilter failed on GETPC"
                else:
                    print "Checkfilter success on GETPC"
                out+=d
            elif words[0]=="rem":
                #comment
                out+=[" //%s\n"%(" ".join(words[1:]))]
            elif words[0]=="asm":
                out+=[" ".join(words[1:])+"\n"]
            elif words[0]=="debug":
                out+=["int3\n"]
            ###############
            #When we start - we assume our getpc is in ebx and the end of our decoder is in esi (start of encoded shellode)
            #we automatically have a variable "source" 
            #We also have a variable "dest" pointing at the same place
            #################
            
            if words[0]=="getvariable":
                #no need to return anything here
                varname=words[1]
                print "Allocating new variable %s"%varname            
                reg_alloc.allocate(varname)
            elif words[0]=="setvariable":
                #set a variable to an integer value or other variable
                varname=words[1]
                value=words[2]
                print "Setting variable %s to %s"%(varname,value)
                out+=reg_alloc.set_int(varname,value)
            elif words[0]=="getbyte":
                #getbyte <variable name | new variable name>
                #implicitly loads from source
                source=words[1]
                variable=words[2]
                #get a byte from our source register
                #need to do the equivelent of movb (%esi), %
                out+=reg_alloc.getbyte(source,variable)
            elif words[0]=="startloop":
                var=words[1]
                loopname=words[2]
                out+=reg_alloc.startloop(var,loopname)
            elif words[0]=="endloop":
                #loop variable labeltoloopto
                loopto=words[1]
                out+=reg_alloc.loop(loopto)
            elif words[0]=="andb":
                #andb variable 0x0f (or whatever)
                var=words[1]
                var2=words[2]
                out+=reg_alloc.and_byte(var,var2)
            elif words[0]=="shl":
                #shl variable bits
                var=words[1]
                bits=words[2]
                out+=reg_alloc.shl(var,bits)
            elif words[0]=="increment":
                #increment variable_name
                var=words[1]
                out+=reg_alloc.increment(var)
            elif words[0]=="storb":
                #storb variable 
                #loads variable's lower byte into *(dest)
                source=words[1]
                dest=words[2]
                out+=reg_alloc.store_byte(source,dest)
            elif words[0]=="add":
                #add var1 var2
                #var2=var1+var2
                var1=words[1]
                var2=words[2]
                out+=reg_alloc.add(var1,var2)
            elif words[0]=="insertlabel":
                #insertlabel label
                label=words[1]
                out+=reg_alloc.insertlabel(label)
            elif words[0]=="copyvar":
                #copyvar var1 var2
                #also allocates var2
                #var2=var1
                var1=words[1]
                var2=words[2]
                out+=reg_alloc.copy_var(var1,var2)
            else:
                print "WARNING ERROR IN IL: %s"%words[0]
          
    except ZeroDivisionError:
        print out
    #print "".join(out)
    return "".join(out)
            
            
def lowercheck(astr):
    """
    Check to see if the string is entirely lowercase
    and also neg any null bytes
    """
    if astr.lower()!=astr:
        return 0
    if "\x00" in astr:
        return 0
    return 1
            

if __name__=="__main__":
    import sys
    filename="MOSDEF/testfiles/auto_decoder.il"
    if len(sys.argv) > 1:
        filename = sys.argv[1]
    data=open(filename).read()
    print "-"*50
    generated_data=generate(data,lowercheck)
    print "x86 code: \n%s"%(generated_data)
    #transform into AT&T style x86 assembly
    #then run through at&t x86 assembler
    import atandtparse
    x=atandtparse.assemble(generated_data)
    bytes=x.value
    if bytes.lower() == bytes:
        print "SUCCESS"
        print "Result: %s\n%d bytes\n"%(prettyprint(bytes),len(bytes))
    else:
        print "Not all lowercase, sorry"
    #then done!
