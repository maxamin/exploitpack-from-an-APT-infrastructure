#!/usr/bin/env python
"""
bmp.py - a library for creating simple BMP files
"""
#Copywrite Immunity, Inc. 2006-2007
#Under CANVAS License
import string, struct, sys
try:
    from internal import devlog
except:
    def devlog(arg1, arg2):
        return 

def normalizergb_file(x, y, infile, outfile, alpha=3):
    """
    Convert from GBR to RGB line by line in the files
    Does this backwards in order to flip it at the same time
    """

    linesize=x*alpha 
    infile.seek(-linesize, 2)  #seek to the end of the file
    for i in xrange(0, y):
        data=infile.read(linesize) #will read one line
        data=normalizergb(x , 1, data, alpha=alpha) #rework line into RGB
        outfile.write(data) #write that line to our output file#write that line to our output file#write that line to our output file
        try:
            infile.seek(-(linesize*2), 1) #seek backwards 2 lines
        except IOError:
            #we're done
            break 
    return 

def normalize_no_change(x, y, infile, outfile, alpha=3):
    """
    Use this when not converting into raw format. We don't need
    to flip or normalize it, because it's already in BMP format.
    """
    infile.seek(0)
    devlog("bmp", "normalize_no_change: (should be zero) infile.tell()=%d"%infile.tell())
    linesize=x*alpha 
    devlog("bmp", "normalize_no_change: linesize=%s"%linesize)
    size=0
    for i in xrange(0, y):
        try:
            data=infile.read(linesize) #will read one line
        except IOError, msg:
            devlog("bmp","IOError: We're done: %s"%msg)
            break #we're done
        size+=len(data)
        devlog("bmp", "size: %s"%size)
        outfile.write(data) #write that line to our output file#write that line to our output file#write that line to our output file
    devlog("bmp", "Wrote %d bytes to file"%size)
    return 

def normalizergb(x,y,data,alpha=3):
    """
    Windows screengrabs are in BGRA order, and need to be flipped
    Set alpha=3 for no alpha, 4 for alpha
    """
    #can't do self.log here
    #print "Normalizing RGB for win32" 

    ret=[]
    length=len(data)
    if length%alpha!=0:
        devlog("screengrab","Very strange - is not mod %s clean!"%alpha)

    for i in range(0,y):
        #for each scanline

        for j in range (0,x):
            #for each pixel

            #print "Doing: %s:%s"%(i,j)
            b=data[x*i*alpha +alpha*j+0]
            g=data[x*i*alpha +alpha*j+1]
            r=data[x*i*alpha +alpha*j+2]

            ret+=[r,g,b]
    data="".join(ret)
    #print "Returning %s"%len(data)
    return data

def verticleflip(x,y,data,alpha=3):
    """
    Windows screenshots need to be flipped vertically
    alpha=4 for alpha byte as well
    """
    print "Flipping Screenshot Vertically"
    i=0
    ret=[]
    length=len(data)
    if length%alpha!=0:
        devlog("screengrab","Very strange - is not mod %s clean!"%alpha)

    while i<length:
        line=data[i:i+x*alpha]
        ret=[line]+ret
        i+=x*alpha
    return "".join(ret)

class BMP:
    def __init__(self):
        self.fmt_filehdr = "<HLHHL"
        self.fmt_info = "<LLLHHLLLLLL"
        self.fmtrgb = "BBBB"
        
        #our main data package
        self.data=""
        
        # File hdr
        self.type = 0x4d42 #always BM
        self.size = 0
        self.reserved1 = self.reserved2 = 0
        self.offset = struct.calcsize( self.fmt_filehdr )
        self.offset +=struct.calcsize( self.fmt_info ) 
        #we no longer use fmtrgb since we are 24 bits
        #self.offset+= struct.calcsize( self.fmtrgb )
        #self.offset=self.offset*8 #this is in bits in the documentation

        # Info file hdr
        self.biSize= self.biWidth = self.biHeight =\
            self.biPlanes = self.biBitCount = self.biCompression =\
            self.biSizeImage = self.biXPelsPerMeter = self.biYPelsPerMeter =\
            self.biClrUsed = self.biClrImportant = 0

        # RGBQUAD
        self.rgbBlue = 0
        self.rgbGreen = 0
        self.rgbRed = 0
        self.rgbReserved = 0

    def getBMPfromraw(self, hor, vert, rawmem):
        """
        Creates a header for a bitmap file as defined
        by hor, vert, and rawmem. Set rawmem to ""
        if you just want to get the header.
        """
        #size of file header in bytes
        self.biSize = struct.calcsize(self.fmt_info)      
        #print "biSize=%d"%self.biSize
        self.biPlanes = 1
        self.biBitCount = 24
        self.biCompression = 0
        self.biHeight = vert
        self.biWidth  = hor
        self.biSizeImage = 0 #hor*vert*3

        #size of the file in bytes
        self.size=hor*vert*3+self.biSize+struct.calcsize(self.fmt_filehdr)

        bmp = [] 
        bmp.append( struct.pack( self.fmt_filehdr, self.type, self.size,\
                                 self.reserved1, self.reserved2, self.offset) )

        bmp.append( struct.pack( self.fmt_info, self.biSize, self.biWidth,\
                                 self.biHeight, self.biPlanes, self.biBitCount,\
                                 self.biCompression, self.biSizeImage,\
                                 self.biXPelsPerMeter, self.biYPelsPerMeter,\
                                 self.biClrUsed, self.biClrImportant) )

        #this shouldn't matter in 24 bit mode
        #bmp.append( struct.pack(self.fmtrgb, self.rgbBlue, self.rgbGreen,\
        #           self.rgbRed, self.rgbReserved) )
        #now append our file data
        bmp.append( rawmem )
        self.data=string.joinfields(bmp, "")
        return self.data

def main(args):
    """
    Tester function that checks to see if we can convert
    a raw image to a BMP
    """
    if len(args)< 2:
        print "Usage: bmp.py filename x:y"
        sys.exit(1)
    filename=args[0]
    x,y=args[1].split(":")
    x=int(x)
    y=int(y)
    infile=file(filename,"rb")
    outfile=file(filename+".bmp","wb")
    mybmp=BMP()
    data=mybmp.getBMPfromraw(int(x), int(y),"")
    outfile.write(data)
    normalize_no_change(x, y, infile, outfile)
    outfile.close()
    infile.close()
    return 

if __name__=="__main__":
    main(sys.argv[1:])