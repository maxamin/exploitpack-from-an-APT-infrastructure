#! /usr/bin/env python



t1=[]
#AC=LODS BYTE PTR DS:[ESI] 20 starts AND instruction 
t1.append("\xac\x20")
#ADD DWORD PTR DS:[EAX],004100B9
t1.append("\x81\x00")
#SBB AH,BYTE PTR DS:[EAX]
t1.append("\x1a\x20")
#92: XCHG EAX,EDX 01 starts ADD
t1.append("\x92\x01")
#1e is push DS, 20 is AND ...
t1.append("\x1e\x20")
#AND BYTE PTR ES:[eax] ah
t1.append("\x26\x20")
#AND BYTE PTR DS:[EAX],AH
t1.append("\x20\x20")
#AND DWORD PTR DS:[EAX],ESP
t1.append("\x21\x20")
#EATS A BYTE
#mov BYTE PTR DS:[EDX],0xNEXTBYTE
t1.append("\xc6\x02")
#XOR BYTE PTR DS:[EAX],AH
t1.append("\x30\x20")
#60:PUSHAD 01 ADD DWORD PTR DS:[ECX]+word],%edi
t1.append("\x60\x01")
#CMP [EAX],ESP
t1.append("\x39\x20")
#52: PUSH EDX, 01 ADD WORD....
t1.append("\x52\x01")
#LEA EAX,[EAX]
t1.append("\x8d\x00")
#JGE +1
t1.append("\x7d\x01")
#POP DWORD PTR DS:[EAX]
t1.append("\x8f\x00")
#NOP ADD BYTE PTR (addr word)...
t1.append("\x90\x00")
#SBB BYTE PTR DS:[EAX],AH
t1.append("\x18\x20")
#SBB DWORD PTR DS:[EAX],ESP
t1.append("\x19\x20")
#SBB AL,20
t1.append("\x1c\x20")
#SBB EAX,BYTEBYTEBYTE0x20
t1.append("\x1d\x20")
#AND AH,DS:[EAX]
t1.append("\x22\x20")
#ADC ESP,DWORD PTR DS:[EAX]
t1.append("\x13\x20")
#ADC AL,20
t1.append("\x14\x20")
#FADD QWORD PTR DS:[EDX]
t1.append("\xdc\x02")
#AND AH,BYTE PTR DS:[ECX]
t1.append("\x22\x21")
#POPAD - ADD DWORD PTR DS:[ecx+WORD]
t1.append("\x61\x01")
#CMP ah, BYTE PTR [EAX]
t1.append("\x3a\x20")
#push ebx, ADD DWORD PTR DS:[ECX+WORD],%edi
t1.append("\x53\x01")
#popfd , ADD
t1.append("\x9d\x00")
#JLE +1
t1.append("\x7e\x01")
#JS +1
t1.append("\x78\x01")

#a0 - mov byte ptr [word]
#a4 - movs [edi],[esi]
#includes up to 0xbf
#a6 cmps [esi],[edi]
#a8 is test al, 00!
#b0 is mov al, 00!
#b1 mov cl 00
#b2 dl
#b3 bl
#b4 ah
#b5 ch
#b6 Dh
#b7 bh
#b8 movl eax,0x00414100
#b9 ecx
#ba edx
#bb ebx
#bc esp
#bd ebp
#be esi
#bf edi
for i in range(0xa0,0xc0):
    t1.append(chr(i)+"\x00")



unitrans=[]

#does not include 0x80
for i in range(0,0x80):
    unitrans.append("\x00"+chr(i))

top=0xc0


t=0
#does not include top
for i in range(0x80,top):
    unitrans.append("\xc2\x00"+t1[t])
    t+=1

t=0
#does not include 0x100
for i in range(top,0x100):
    unitrans.append("\xc3\x00"+t1[t])
    t+=1

def cstyleprint(instring):
    tmp="\""
    startstring=""
    #startstring="unicodeloop+="
    i=1
    #print "%s" % startstring
    for ch in instring:
        tmp+= "\\x%2.2x" % (ord(ch))
        if i  % 8 ==0:
            tmp+= "\"\n%s\"" % (startstring) 
        i+=1
        
    tmp+="\""        
    return tmp

def prettyprint(instring):
    tmp=""
    for ch in instring:
        value="%2.2x" % ord(ch)
        tmp+="["+value+"]"
       
    return tmp


def win32ucs2(instring,badstring=None):
    """ XP SP0 has one badstring, but SP1 seems to have another."""
    ret=""
    if badstring==None:
        badstring="\x81\x8d\x8f\x90\x9d"
    for c in instring:
        o=ord(c)
        #why isn't 81 transformed? See uniout for more information on this.
        if o>0x80 and o<0xa0 and c not in badstring:
            d=unitrans[ord(c)]
            if len(d)>2:
                d=d[2:]
        else:
            d=c+"\x00"
        ret+=d
    return ret

#this stuff happens.
if __name__ == '__main__':

    print "Printing out the list"

    print unitrans
    for i in range(0,0x100):
        print cstyleprint(unitrans[i])

    print cstyleprint(unitrans[0x89])
    print cstyleprint(win32ucs2("ABCD\x80\x94"))


