#! /bin/env python

# generic function wrapper for CANVAS

class fWrap:
    def __init__(self, f, alterFunc = None):
        self.alter = alterFunc
        self.f = f

    def __call__(self, *args, **kwargs):
        # examine and alter args here
        if self.alter != None:
            args, kwargs = self.alter(args, kwargs)  
        ret = self.f(*args, **kwargs)
        # postlude here if you want it
        return ret

# example usage

def exampleAlterFunc(a, k):
    print "ALTERING: Args, Kwargs: ", a, k
    aList = list(a) # unfreeze the tuple to list
    sList = []
    for c in a[0]:
        if c == 'L': c = 'I'
        if c == 'l': c = 'i'
        sList.append(c)   
    aList[0] = "".join(sList)
    a = tuple(aList) # freeze the list to tuple
    print "ALTERED?: Args, Kwargs: ", a, k
    return a, k
        
# example
if __name__ == "__main__":
    import struct
    import __builtin__
    __builtin__.__dict__['CANVASPack'] = fWrap(struct.pack, alterFunc = exampleAlterFunc)
    # have alterFunc change 'l' to 'i' and 'L' to 'I' for
    # 32 bit consistency accross the board.
    s = CANVASPack("<L", 4)
    for c in s: 
        print "\\x%.2x"%ord(c),
    print '\n'
    s = CANVASPack(">L", 4)
    for c in s: 
        print "\\x%.2x"%ord(c),
    print '\n'
    s = CANVASPack("=L", 4)
    for c in s: 
        print "\\x%.2x"%ord(c),
    print '\n'
    
