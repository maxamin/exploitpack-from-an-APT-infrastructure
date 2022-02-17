#!/usr/bin/env python
##
##  movie.py
##
## $Id: movie.py,v 1.6 2005/08/15 12:28:00 euske Exp $

import sys
from swf import SWFParser
from mp3 import MP3Reader, MP3Storage
from rfb import RFBMovieConverter
from image import IMG_LOSSLESS, IMG_VIDEOPACKET
stderr = sys.stderr
lowerbound = max
upperbound = min


##  SWFInfo
##
class SWFInfo:

  """
  SWFInfo holds information about headers and mp3 data
  in a SWF file. The values of this object are changed
  as parsing goes on.
  """
  
  def __init__(self, filename=None):
    self.filename = filename
    self.compression = None
    self.clipping = None
    self.framerate = None
    self.scaling = None
    self.blocksize = None
    self.swf_version = None
    self.width = None
    self.height = None
    self.mp3 = None
    return

  def __repr__(self):
    return '<SWFInfo: filename=%r, compression=%r, clipping=%r, framerate=%r, scaling=%r, blocksize=%r, swf_version=%r, mp3=%r>' % \
           (self.filename, self.compression, self.clipping, self.framerate, self.scaling, self.blocksize, self.swf_version, self.mp3)

  def set_defaults(self, w0, h0): # size in pixels
    # THIS MUST BE CALLED BEFORE MovieOutputStream.open()
    if not self.clipping:
      self.clipping = (0,0,w0,h0)
    if self.scaling:
      (w0,h0) = (int(w0*self.scaling), int(h0*self.scaling))
    if self.width != None and (self.width != w0 or self.height != h0):
      print >>stderr, 'Warning: movie size already set: %dx%d' % (self.width, self.height)
    elif self.width == None:
      (self.width, self.height) = (w0, h0)
      print >>stderr, 'Output movie size: %dx%d' % (self.width, self.height)
    if not self.framerate:
      self.framerate = 12.0
    if not self.blocksize:
      self.blocksize = 32
    return

  def set_framerate(self, framerate):
    if self.framerate != None and self.framerate != framerate:
      print >>stderr, 'Warning: movie framerate is overridden.'
      return      
    self.framerate = float(framerate)
    return

  def set_swf_version(self, swf_version):
    self.swf_version = swf_version
    return

  def set_mp3header(self, isstereo, mp3samplerate, mp3sampleskip):
    if not self.mp3:
      self.mp3 = MP3Storage()
    self.mp3.set_stereo(isstereo)
    self.mp3.set_sample_rate(mp3samplerate)
    self.mp3.set_initial_skip(mp3sampleskip)
    return

  def reg_mp3blocks(self, fp, length=None, nsamples=None, seeksamples=None):
    if not self.mp3:
      self.mp3 = MP3Storage()
    MP3Reader(self.mp3).read_mp3file(fp, length, nsamples, seeksamples)
    return

  def generate_html(self):
    if self.filename.endswith('.swf'):
      outfname = self.filename.replace('.swf','.html')
    else:
      outfname = self.filename+'.html'
    fp = file(outfname, 'w')
    fp.write('<html>\n<body>\n')
    fp.write('<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000" width="%d" height="%d"\n' %
             (self.width, self.height))
    fp.write(' codebase="http://download.macromedia.com/pub/shockwave/cabs/flash/swflash.cab#version=%d,0,0,0">\n' %
             self.swf_version)
    fp.write('<param name="movie" value="%s">\n' % self.filename)
    fp.write('<param name="play" value="true">\n')
    fp.write('<param name="loop" value="true">\n')
    fp.write('<param name="quality" value="high">\n')
    fp.write('<embed src="%s" width="%d" height="%d"\n' % (self.filename, self.width, self.height))
    fp.write(' play="true" align="" loop="true" quality="high" type="application/x-shockwave-flash"\n')
    fp.write(' pluginspage="http://www.macromedia.com/go/getflashplayer"></embed>\n')
    fp.write('</object>\n')
    fp.write('</body>\n</html>\n')
    fp.close()
    return

  
##  MovieContainer
##
class MovieContainer:
  
  """
  MovieContainer holds all frame images of a movie.
  """
  
  def __init__(self, info):
    self.info = info
    self.nframes = 0
    self.parsers = []
    return

  # get frame
  def get_frame(self, i):
    (images, othertags) = ([], [])
    for (n,parser) in self.parsers:
      if i < n:
        (images, othertags) = parser.parse_frame(i)
        break
      i -= n
    return (i/self.info.framerate, images, othertags)
  
  def parse_vnc2swf(self, fname, read_mp3=False, debug=False):
    parser = VNC2SWF_Parser(self, read_mp3, debug=debug)
    parser.open(fname)
    nframes = len(parser.framepos)
    self.parsers.append( (nframes, parser) )
    self.nframes += nframes
    return self

  def parse_vncrec(self, fname, debug=False):
    parser = RFBMovieConverter(self, debug=debug)
    parser.open(fname)
    nframes = len(parser.frameinfo)
    self.parsers.append( (nframes, parser) )
    self.nframes += nframes
    return self



##  VNC2SWF_Parser
##
class VNC2SWF_Parser(SWFParser):

  """
  VNC2SWF_Parser parses a SWF file which is specifically
  created by vnc2swf. This does not support a generic
  Flash file.
  """

  def __init__(self, movie, read_mp3=False, debug=False):
    SWFParser.__init__(self, debug)
    self.movie = movie
    self.read_mp3 = read_mp3
    self.video1_cid = None
    return

  def parse_header(self):
    SWFParser.parse_header(self)
    (x,width, y,height) = self.rect
    print >>stderr, 'Input movie: version=%d, size=%dx%d, framerate=%dfps, frames=%d, duration=%.1fs.' % \
          (self.swf_version, width/20, height/20, self.framerate,
           self.framecount, self.framecount/float(self.framerate))
    self.movie.info.set_framerate(self.framerate)
    self.movie.info.set_defaults(width/20, height/20)
    return

  def parse_frame(self, i):
    self.image1 = {}
    self.shape1 = None
    self.images = []
    self.othertags = []
    SWFParser.parse_frame(self, i)
    return (self.images, self.othertags)

  def do_tag0(self, tag, length):
    return

  def do_unknown_tag(self, tag, length):
    data = self.read(length)
    self.othertags.append((tag, data))
    return
  
  def do_tag1(self, tag, length):
    # ShowFrame
    if self.debug:
      print >>stderr, 'ShowFrame'
    return
  
  def do_tag9(self, tag, length):
    # SetBackgroundColor
    bgcolor = self.readrgb()
    if self.debug:
      print >>stderr, 'BGColor:', bgcolor
    return
  
  def do_tag20(self, tag, length):
    # DefineBitsLossless
    cid = self.readui16()
    fmt = self.readui8()
    width = self.readui16()
    height = self.readui16()
    length -= 7
    tablesize = 0
    if fmt == 3:
      tablesize = self.readui8()+1
      length -= 1
    if fmt == 5: # RGB
      data = self.read(length)
      if self.debug:
        print >>stderr, 'DefineBitsLossless:', cid, fmt, width, height, len(data)
      self.image1[cid] = (width, height, (IMG_LOSSLESS, data))
    return
  
  def do_tag32(self, tag, length):
    # DefineShape3
    sid = self.readui16()
    rect = self.readrect()
    (fillstyles, linestyles) = self.read_style(3)
    shape = self.read_shape(3, fillstyles, linestyles)
    if fillstyles:
      cid = fillstyles[0][3]
      if self.debug:
        print >>stderr, 'Shape', sid, cid, rect, shape, fillstyles, linestyles
      self.shape1 = (sid, cid)
    return

  def do_tag26(self, tag, length):
    # PlaceObject2
    flags = self.readui8()
    depth = self.readui16()
    (sid, matrix, ratio, name) = (None, None, None, None)
    if flags & 2:
      sid = self.readui16()
    matrix = None
    if flags & 4:
      matrix = self.readmatrix()
    #assert not (flags & 8)
    if flags & 16:
      ratio = self.readui16()
    if flags & 32:
      name = self.readstring()
    #assert not (flags & 64)
    #assert not (flags & 128)
    if self.debug:
      print >>stderr, 'Place', flags, depth, sid, matrix
    if not sid or sid == self.video1_cid:
      # ignore video frame
      return
    if self.shape1 and matrix:
      (sid0,cid) = self.shape1
      if sid0 == sid and cid in self.image1:
        (scalex,scaley, rot0,rot1, transx,transy) = matrix
        data = self.image1[cid]
        del self.image1[cid]
        self.images.append(((transx/20, transy/20), data))
        self.shape1 = None
    return
  
  def do_tag28(self, tag, length):
    # RemoveObject2
    depth = self.readui16()
    if self.debug:
      print >>stderr, 'RemoveObject', depth
    return

  def scan_tag60(self, tag, length):
    # DefineVideoStream
    if self.video1_cid:
      print >>stderr, 'DefineVideoStream already appeared.'
      return
    cid = self.readui16()
    frames = self.readui16()
    width = self.readui16()
    height = self.readui16()
    flags = self.readui8() # ignore this.
    codec = self.readui8() # must be ScreenVideo
    if codec == 3:
      self.video1_cid = cid
      if self.debug:
        print >>stderr, 'DefineVideoStream', cid, frames, width, height, flags, codec
    return
  def do_tag60(self, tag, length):
    return
  
  def do_tag61(self, tag, length):
    # VideoFrame
    stream_id = self.readui16()
    if self.video1_cid != stream_id: return # Video ID does not match
    framenum = self.readui16()
    self.setbuff()
    (frametype, codecid) = self.readbits(4), self.readbits(4)
    if codecid != 3: return # must be ScreenVideo
    (blockwidth, imagewidth) = self.readbits(4), self.readbits(12)
    (blockheight, imageheight) = self.readbits(4), self.readbits(12)
    blockwidth = (blockwidth+1)*16
    blockheight = (blockheight+1)*16
    if self.debug:
      print >>stderr, 'VideoFrame', framenum, frametype, ':',  blockwidth, imagewidth, blockheight, imageheight
    hblocks = (imagewidth+blockwidth-1)/blockwidth
    vblocks = (imageheight+blockheight-1)/blockheight
    for y in xrange(0, vblocks):
      for x in xrange(0, hblocks):
        length = self.readub16()
        if length:
          data = self.read(length)
          x0 = x*blockwidth
          y0 = imageheight-(y+1)*blockheight
          w = upperbound(blockwidth, imagewidth-x0)
          h = blockheight
          if y0 < 0:
            h += y0
            y0 = 0
          self.images.append( ((x0,y0), (w,h,(IMG_VIDEOPACKET,data))) )
    return
  
  def scan_tag18(self, tag, length):
    # SoundStreamHead
    if not self.read_mp3: return
    flags1 = self.readui8()
    flags2 = self.readui8()
    playrate = (flags1 & 0x0c) >> 2
    if not (flags1 & 2): return
    # playbacksoundsize is given
    playstereo = flags1 & 1
    compression = (flags2 & 0xf0) >> 4
    if compression != 2: return
    # must be mp3
    samplerate = (flags2 & 0x0c) >> 2
    if samplerate == 0: return
    samplerate = [0,11025,22050,44100][samplerate]
    if not (flags2 & 2): return
    # streamsoundsize is given
    streamstereo = flags2 & 1
    avgsamplecount = self.readui16()
    latseek = self.readui16()
    self.movie.info.set_mp3header(streamstereo, samplerate, latseek)
    if self.debug:
      print >>stderr, 'SoundStreamHeader', flags1, flags2, avgsamplecount, latseek
    return
  def do_tag18(self, tag, length):
    return
  
  def scan_tag19(self, tag, length):
    # SoundStreamBlock
    if not self.read_mp3: return
    nsamples = self.readui16()
    seeksamples = self.readsi16()
    self.movie.info.reg_mp3blocks(self.fp, length-4, nsamples, seeksamples)
    if self.debug:
      print >>stderr, 'SoundStreamBlock', nsamples, seeksamples
    return
  def do_tag19(self, tag, length):
    return
  

# main
if __name__ == '__main__':
  info = SWFInfo()
  movie = MovieContainer(info).parse_vnc2swf(sys.argv[1], read_mp3=True, debug=True)
  print movie.nframes, info
