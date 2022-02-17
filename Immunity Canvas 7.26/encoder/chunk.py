#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from MOSDEF import mosdef
import atandtscan
import atandtparse

#TODO:
#    - Make it work for jmp +-offset
#    - when loop $offset where offset>127 < offset replace it
#	for a dec ecx; jmp $offset


# chunksize(shellc, wsize, jsize, arch=)
# This function split shellcode in "wsize", adding some jmp +jsize at the
# end of every chunk
#   shellc= Shellcode to chunkize
#   wsize = size of chunk
#   jsize = hole size

# I BEG GOD that no one ever try to read this function
# it might affect their mental health
def chunkize(shellc, wsize, jsize, arch="X86"):
        MAXINTELOPCODE=9

        if jsize > 127:
                print "Sorry, this chunksize version only support jmp rel8 (%d) " % jsize
                return ""
        data= atandtparse.atandtpreprocess(shellc)
        tokens=atandtscan.scan(data)
        tree=atandtparse.parse(tokens)
        x=atandtparse.x86generate(tree)
        #print x.metadata
        idx=0 # memory index
        i=0   # instruction 
        labels={}
        mark={}
        result=""
        chunk=""
        ilength=0
        maxchunk= wsize -2 # 2==sizeof("jmp jsize")

        # look for labels
        for a in range(0, len(x.metadata)):
                if x.metadata[a]["type"]== "label":
                        labels[x.metadata[a]["label"] ]=x.metadata[a]
                                
                                                      
        for a in range(0, len(x.metadata)):

                if x.metadata[a].has_key("length"):
                        ilength=x.metadata[a]["length"]   # instruction size
                        tmp    =x.value[i:i+ilength]    # intruction itself
                        i     += ilength                

                elif x.metadata[a]["type"] == "label":
                        name=x.metadata[a]["label"]
                        # only for possitive "labeled" jmp
                        if mark.has_key( name):
                                # ok... this is the NASTYest of the whole function (if nastyest exist on english dictionary)
                                tmp2= mosdef.assemble("%s $%d"% (mark[name][2], idx- mark[name][0] -2), arch)
                                result= result[:mark[name][0]] + tmp2 + result[mark[name][0]+ len(tmp2):]
                        # for negative values, we update this
                        x.metadata[a]["offset2"]=idx
                        labels[x.metadata[a]["label"]] = x.metadata[a]
                        continue

                else:
                        print "Error: mnemonic without length: %s" % str(x.metadata[a])

                if x.metadata[a].has_key("jumpto"):
                        # is int ?
                        where= x.metadata[a]["jumpto"]

                        # USE LABELS :D (offset mucks everything up!)
                        if type(where) == type(0) :
                                pass
                                # make things work with integer
                     
                        elif labels.has_key(where):

                                # Negative jmp with a label WORKING!!!
                                if labels[where]["offset"] < x.metadata[a]["offset"]:
                                        noff= labels[where]["offset2"] - idx
                                        tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - ilength), arch)

                                        if ilength+len(chunk) > maxchunk:
                                                tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)-jsize - (maxchunk - len(chunk))), arch)

                                        # it might be possible that size change
                                        # jmp 127, so we will check that
                                        if len(tmp) > ilength:
                                                tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)), arch)
                                        ilength=len(tmp)

                                else:
                                        # POSSITIVE jmp
                                        # We take the maximun possible size
                                        #                   jmp value
                                        psize= (x.metadata[a]["offset"] -labels[where]["offset"]) * (wsize + jsize) / wsize
                                        # and then, if its smaller, we will padd with \90                                                        
                                        maxop= len( mosdef.assemble("%s $%d"% (x.metadata[a]["type"], psize ), arch))
                                        tmp= "\x90" * maxop 
                                        ilength=len(tmp)
                                        bu=idx

                                        if ilength + len(chunk) > maxchunk:
                                                #      nops                  chunk
                                                bu+= (maxchunk- len(chunk)) + jsize
                                                
                                        mark[x.metadata[a]["jumpto"]]=(bu, maxop, x.metadata[a]["type"])
                                        
                if ilength+len(chunk) > maxchunk:
                        result+=chunk+ "\x90" * (maxchunk - len(chunk)) + \
                              mosdef.assemble("jmp $%d" % jsize, arch) 
                        result+= "A" * jsize # THIS IS FOR TEST POURPOSE ONLY
                        idx+= (maxchunk - len(chunk)) # padding 
                        idx+= jsize # hole size
                        idx+= 2     # near jmp
                        chunk=tmp
                        idx+=ilength

                else: 
                        chunk+= tmp 
                        idx+=   ilength

        return result + chunk

class ChunkException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`

#   shellc= Shellcode to chunkize
#   wsize = table with size of chunk
#   jsize = table with hole size

def chunkizeT(shellc, wsizeT, jsizeT, arch="X86", overwrite=1):
        MAXINTELOPCODE=9
        
        if len(wsizeT) != len(jsizeT) :
                raise ChunkException, "chunk and hole tables has to be of the same size"
        data= atandtparse.atandtpreprocess(shellc)
        tokens=atandtscan.scan(data)
        tree=atandtparse.parse(tokens)
        x=atandtparse.x86generate(tree)
        #print x.metadata
        idx=0 # memory index
        i=0   # instruction 
        labels={}
        mark={}
        result=""
        chunk=""
        ilength=0
        wsize= wsizeT.pop(0)
        jsize= jsizeT.pop(0)
        maxchunk= wsize -2 # 2==sizeof("jmp jsize")
        
        # look for labels
        for a in range(0, len(x.metadata)):
                if x.metadata[a]["type"]== "label":
                        labels[x.metadata[a]["label"] ]=x.metadata[a]
                                
                                                      
        for a in range(0, len(x.metadata)):

                if x.metadata[a].has_key("length"):
                        ilength=x.metadata[a]["length"]   # instruction size
                        tmp    =x.value[i:i+ilength]    # intruction itself
                        i     += ilength                

                elif x.metadata[a]["type"] == "label":
                        name=x.metadata[a]["label"]
                        # only for possitive "labeled" jmp
                        if mark.has_key( name):
                                # ok... this is the NASTYest of the whole function (if nastyest exist on english dictionary)
                                tmp2= mosdef.assemble("%s $%d"% (mark[name][2], idx- mark[name][0] -2), arch)
                                result= result[:mark[name][0]] + tmp2 + result[mark[name][0]+ len(tmp2):]
                        # for negative values, we update this
                        x.metadata[a]["offset2"]=idx
                        labels[x.metadata[a]["label"]] = x.metadata[a]
                        continue

                else:
                        print "Error: mnemonic without length: %s" % str(x.metadata[a])

                if x.metadata[a].has_key("jumpto"):
                        # is int ?
                        where= x.metadata[a]["jumpto"]

                        # USE LABELS :D (offset mucks everything up!)
                        if type(where) == type(0) :
                                pass
                                # make things work with integer
                     
                        elif labels.has_key(where):

                                # Negative jmp with a label WORKING!!!
                                if labels[where]["offset"] < x.metadata[a]["offset"]:
                                        noff= labels[where]["offset2"] - idx
                                        tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - ilength), arch)

                                        if ilength+len(chunk) > maxchunk:
                                                tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)-jsize - (maxchunk - len(chunk))), arch)

                                        # it might be possible that size change
                                        # jmp 127, so we will check that
                                        if len(tmp) > ilength:
                                                tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)), arch)
                                        ilength=len(tmp)

                                else:
                                        # POSSITIVE jmp
                                        # We take the maximun possible size
                                        #                   jmp value
                                        psize= (x.metadata[a]["offset"] -labels[where]["offset"]) * (wsize + jsize) / wsize
                                        # and then, if its smaller, we will padd with \90                                                        
                                        maxop= len( mosdef.assemble("%s $%d"% (x.metadata[a]["type"], psize ), arch))
                                        tmp= "\x90" * maxop 
                                        ilength=len(tmp)
                                        bu=idx

                                        if ilength + len(chunk) > maxchunk:
                                                #      nops                  chunk
                                                bu+= (maxchunk- len(chunk)) + jsize
                                                
                                        mark[x.metadata[a]["jumpto"]]=(bu, maxop, x.metadata[a]["type"])
                                        
                if ilength+len(chunk) > maxchunk:
                        result+=chunk+ "\x90" * (maxchunk - len(chunk)) + \
                              mosdef.assemble("jmp $%d" % jsize, arch) 
                        if overwrite:
                                result+= "A" * jsize # THIS IS FOR TEST POURPOSE ONLY
                        idx+= (maxchunk - len(chunk)) # padding 
                        idx+= jsize # hole size
                        idx+= 2     # near jmp
                        chunk=tmp
                        idx+=ilength
                       
                        try:
                                wsize= wsizeT.pop(0)
                                jsize= jsizeT.pop(0)
                                maxchunk= wsize -2

                        except IndexError, msg:
                                raise ChunkException, "Shellcode is too long for the provided chunks: %s" % str(wsize)

                else: 
                        chunk+= tmp 
                        idx+=   ilength

        return result + chunk

if __name__=="__main__":
        import sys
        import makeexe
        if len(sys.argv) != 2:
                print "%s <filename.s>"% sys.argv[0]
                sys.exit(0)
        data=open(sys.argv[1]).read()
        data=chunkizeT(data, [20,200], [16,16])
        makeexe.makelinuxexe(data, "a.out")
