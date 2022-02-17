# X11 XWD to BMP format converter
# Only TrueColor and DirectColor are supported. (No grayscale or pseudocolor support)
# Author: Oren

import struct

def xwdToBmp(input_filename, output_filename):
    buf=file(input_filename, 'rb').read()
    pos=0
    HeaderSize=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    FileVersion=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    if FileVersion !=7:
        raise Exception('Unsupported FileVersion: %r'%FileVersion)
    PixmapFormat=struct.unpack(">L", buf[pos:pos+4])[0]
    if PixmapFormat!=2:
        raise Exception("Not implemented PixmapFormat:%r", PixmapFormat)
    pos+=4
    PixmapDepth=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    PixmapWidth=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    PixmapHeight=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    XOffset=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    ByteOrder=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BitmapUnit=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BitmapBitOrder=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BitmapPad=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BitsPerPixel=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BytesPerLine=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    VisualClass=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    RedMask=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    GreenMask=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BlueMask=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    BitsPerRgb=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    NumberOfColors=struct.unpack(">L", buf[pos:pos+4])[0]
    pos+=4
    ColorMapEntries=struct.unpack(">L", buf[pos:pos+4])[0]
    pos=HeaderSize
    pos+=ColorMapEntries*12

    if VisualClass not in [5,4]:
        raise Exception('Unsupported VisualClass:%r'%VisualClass)
    if NumberOfColors!=256:
        raise Exception('Unsupported NumberOfColors:%r'%NumberOfColors)
    if BitsPerPixel==32:
        pixelwidth=4
    elif BitsPerPixel==24:
        pixelwidth=3
    else:
        raise Exception('Unsupported BitsPerPixel:%r'%BitsPerPixel)
    width=PixmapWidth
    height=PixmapHeight
    bmp='\x00'*4+'\x36\x00\x00\x00'+'\x28\x00\x00\x00'
    bmp+=struct.pack("<L",width)
    bmp+=struct.pack("<L",height)
    bmp+='\x01\x00'
    bmp+='\x18\x00'
    bmp+='\x00'*4

    def getoffset(mask, size, ByteOrder):
        if not ByteOrder:
            if mask==16711680:
                return 2
            if mask==65280:
                return 1
            if mask==255:
                return 0
        if ByteOrder:
            if mask==16711680:
                return 0
            if mask==65280:
                return 1
            if mask==255:
                return 2
        raise Exception("Unsupported mask(%r) or size(%r) or ByteOrder(%r)"%(mask, size, ByteOrder))
    red_offset=getoffset(RedMask, BitsPerPixel, ByteOrder)
    green_offset=getoffset(GreenMask, BitsPerPixel, ByteOrder)
    blue_offset=getoffset(BlueMask, BitsPerPixel, ByteOrder)
    bitbmp=[]
    for y in xrange(height):
        pos0=pos
        pos+=XOffset*pixelwidth
        ybitbmp=[]
        for x in xrange(width):
            try:
                if pixelwidth==3:
                    ybitbmp.append(buf[pos+blue_offset]+buf[pos+green_offset]+buf[pos+red_offset])
                else:
                    ybitbmp.append(buf[pos+blue_offset]+buf[pos+green_offset]+buf[pos+red_offset])
            except Exception:
                raise Exception('More data expected. Y: %r X: %r pos:%r len(buf):%r'%(y, x,pos, len(buf)))
            pos+=pixelwidth
        ybitbmp=''.join(ybitbmp)
        while len(ybitbmp)%4:
            ybitbmp+='\x00'
        bitbmp.append(ybitbmp)
        pos=pos0+BytesPerLine
    bitbmp.reverse()
    bitbmp=''.join(bitbmp)
    size=len(bitbmp)
    bmp+=struct.pack("<L",size)
    bmp+='\x13\x0B\x00\x00'
    bmp+='\x13\x0B\x00\x00'
    bmp+='\x00\x00\x00\x00'
    bmp+='\x00\x00\x00\x00'
    bmp+=bitbmp
    size=len(bmp)+6
    bmp='BM'+struct.pack("<L",size)+bmp #header+size
    file(output_filename, 'wb').write(bmp)

if __name__=='__main__':
    # Testing script... Will try to convert al .xwd files to .xwd.bmp in current directory.
    from os import listdir
    import traceback
    files = [f for f in listdir('.') if 'xwd'== f[-3:]]
    for f in files:
        print
        print 'File',f
        try:
            xwdToBmp(f, f+'.bmp')
        except:
            traceback.print_exc()
