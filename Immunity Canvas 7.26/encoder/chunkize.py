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
                
    # NOTE FOR TOMORROW: 
    #  - Fijate que los marks[] se ponen por name, y en el caso de exit, se setea 2 veces,
    #     pero una sola es la correcta, en cuanto a lo demas, parece que todo se ajusta :D
    #     ya veremos maniana.
    for a in range(0, len(x.metadata)):

        if x.metadata[a].has_key("length"):
            ilength=x.metadata[a]["length"]   # instruction size
            tmp    =x.value[i:i+ilength]    # intruction itself
            i     += ilength                
        elif x.metadata[a]["type"] == "label":
            name=x.metadata[a]["label"]
            # only for possitive "labeled" jmp
            if mark.has_key( name):
                for step in mark[name]:
                    # ok... this is the NASTYest of the whole function (if nastyest exist on english dictionary)
                    tmp2= mosdef.assemble("%s $%d"% (step[2], idx- step[0] -2), arch)
                    tmp2= tmp2 + "\x90" * ( step[1]-len(tmp2))
                    #print "\nset %s mark: %d to %d " % (name,step[3], step[3]+len(tmp2))
                    #for pt in range(0, len(result)):
                    #        print "[%d]" % pt + hex(ord(result[pt])), 
                        #tmp2="B" * len(tmp2)
                    result= result[:step[3]] + tmp2 + result[step[3]+ len(tmp2):]
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
                # make things work with integer
                pass
            elif labels.has_key(where):
                # Negative jmp with a label WORKING!!!
                if labels[where]["offset"] < x.metadata[a]["offset"]:
                    noff= labels[where]["offset2"] - idx
                    tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - ilength), arch)
                    #if ilength+len(chunk) > maxchunk:
                    if len(tmp)+len(chunk) > maxchunk:        
                        tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)-jsize - (wsize - len(chunk))), arch)
                    # it might be possible that size change
                    # jmp 127, so we will check that
                    #if len(tmp) > ilength:
                    #        tmp= mosdef.assemble("%s $%d" % (x.metadata[a]["type"], noff - len(tmp)), arch)
                    #        print "(%d)" % (noff - len(tmp))
                    ilength=len(tmp)
                else:
                    
                    # POSITIVE jmp
                    # We take the maximum possible size
                    #                   jmp value
                    # ORIGINAL
                    psize= (x.metadata[a]["offset"] -labels[where]["offset"]) * (wsize + jsize) / wsize
                    # and then, if its smaller, we will padd with \90                                                        
                    maxop= len( mosdef.assemble("%s $%u"% (x.metadata[a]["type"], psize ), arch))

                    ts=len(result)+len(chunk)
                    ilength=maxop
                    tmp="@"* ilength
                    bu=idx
                    if ilength + len(chunk) > maxchunk:
                        bu+= (maxchunk- len(chunk)) + jsize
                        ts+= (wsize- len(chunk))
                    if mark.has_key(x.metadata[a]["jumpto"]):
                        mark[x.metadata[a]["jumpto"]].append((bu, maxop, x.metadata[a]["type"], ts))
                    else:
                        mark[x.metadata[a]["jumpto"]]= [(bu, maxop, x.metadata[a]["type"], ts)]                                                
                    
        if ilength+len(chunk) > maxchunk:
            result+=chunk+ "\x90" * (maxchunk - len(chunk)) + \
                mosdef.assemble("jmp $%d" % jsize, arch) 
                #+ "A" * jsize # THIS IS FOR TEST POURPOSE ONLY
            idx+= (maxchunk - len(chunk)) # padding 
            idx+= jsize # hole size
            idx+= 2     # near jmp
            chunk=tmp
            idx+=ilength
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
    data=chunkize(data, 20, 16)
    makeexe.makelinuxexe(data, "a.out")
