#!/usr/bin/env python


def genlist(o):
        lo = []
        for x in o:
                w = o[x]
                lo.append([w.size, w.type, w.obj])
        
        lo.sort(lambda x, y: cmp(x[0],y[0]))
        return lo
        
        
def printinfo(ko, lim=0):
        o = genlist(ko)
        cut = len(o)-lim
        to = o[-lim:len(o)]
        for x in to:
                print "Size: ", x[0], x[1], "Data:", x[2]
        return


# put this code in your code
# from sizer import scanner
# import alx_memprofiler
#objs = scanner.Objects() # this goes when you want to start gathering info
#printinfo(gobjs, 10) # this goes when you want to dump data up to that point
