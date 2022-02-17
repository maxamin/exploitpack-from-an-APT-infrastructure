#!/usr/bin/env python
##
##  output.py
##
## $Id: output.py,v 1.10 2005/08/23 21:35:18 euske Exp $

import sys, zlib
from swf import SWFWriter
from image import *
stderr = sys.stderr
lowerbound = max
upperbound = min


##  SWFScreen
##
class SWFScreen:

  """
  SWFScreen is a framebuffer which is temporarily used
  for movie construction.
  """
  
  def __init__(self, x0, y0, w, h, scaling=None):
    (self.x0, self.y0, self.width, self.height) = (x0, y0, w, h)
    self.scaling = scaling
    if scaling:
      (self.out_width, self.out_height) = (int(w*scaling), int(h*scaling))
    else:
      (self.out_width, self.out_height) = (w, h)
    self.buf = create_image(w, h)
    self.out_buf = None
    return
  
  def __repr__(self):
    return '<SWFScreen: %dx%d at (%d, %d), output=%dx%d>' % \
           (self.width, self.height, self.x0, self.y0, self.out_width, self.out_height)

  def prepare_image(self):
    # do proper scaling
    if self.scaling:
      self.out_buf = scale_image(self.buf, self.scaling)
    else:
      self.out_buf = self.buf
    return

  def get_image(self, x, y, w, h):
    #assert 0 <= x and 0 <= y, (x,y)
    return crop_image(self.out_buf, (x, y, w, h))

  # returns True if the image is actually painted.
  def paint_image(self, x0, y0, w, h, (format, data)):
    x0 -= self.x0
    y0 -= self.y0
    if not (w and h and 0 < x0+w and x0 < self.width and 0 < y0+h and y0 < self.height):
      return False
    if format == IMG_SOLID:
      # fill color
      solid_fill(self.buf, (x0, y0, w, h), data)
      return True
    if format == IMG_RAW:
      # raw buffer (RGB or RGBX)
      if len(data) == (w*h*3):
        img = create_image_from_string_rgb(w, h, data)
      elif len(data) == (w*h*4):
        img = create_image_from_string_rgbx(w, h, data)
      else:
        assert 0
    elif format == IMG_LOSSLESS:
      # image defined by DefineBitsLossless (XRGB)
      data = zlib.decompress(data)
      assert len(data) == (w*h*4)
      img = create_image_from_string_xrgb(w, h, data)
    elif format == IMG_VIDEOPACKET:
      # image defined by SCREENVIDEOPACKET (BGR)
      data = zlib.decompress(data)
      assert len(data) == (w*h*3)
      img = create_image_from_string_bgr_flipped(w, h, data)
    else:
      assert 0, 'illegal image format: %d' % format
    # sometime the pasted image doesn't fit in the screen, but just let it out.
    paste_image(self.buf, img, (x0, y0))
    return True


##  SWFBlockScreen
##
class SWFBlockScreen(SWFScreen):

  """SWFBlockScreen is a blockized SWFScreen."""
  
  def __init__(self, x0, y0, w, h, block_w, block_h, scaling=None):
    SWFScreen.__init__(self, x0, y0, w, h, scaling=scaling)
    self.block_w = block_w
    self.block_h = block_h
    if scaling:
      (w,h) = (int(w*scaling), int(h*scaling))
    self.hblocks = (w+self.block_w-1)/self.block_w
    self.vblocks = (h+self.block_h-1)/self.block_h
    return


##  SWFShapeScreen
##
class SWFShapeScreen(SWFBlockScreen):

  """
  SWFShapeScreen is a SWFScreen which consists of
  overlapping objects of images. This is used by SWFShapeStream.
  """
  
  MAPBLOCKSIZE = 4
  
  class SWFShapeRef:
    def __init__(self, depth, count):
      self.depth = depth
      self.count = count
      return
    def __repr__(self):
      return '(%d,%d)' % (self.depth, self.count)

  def __init__(self, x0, y0, w, h, scaling=None):
    SWFBlockScreen.__init__(self, x0, y0, w, h, self.MAPBLOCKSIZE, self.MAPBLOCKSIZE,
                            scaling=scaling)
    self.map = None
    self.current_depth = 1
    self.last_depth = 1
    return
  
  def initmap(self):
    self.map = [ [None]*self.hblocks for i in xrange(self.vblocks) ]
    return

  def next_frame(self):
    self.last_depth = self.current_depth
    return

  # x0,y0,w,h: output rectangle (scaled)
  def place_object(self, added, x0, y0, w, h, replaced):
    x0 -= self.x0
    y0 -= self.y0
    if x0+w <= 0 or self.out_width <= x0 or y0+h <= 0 or self.out_height <= y0:
      return
    x1 = upperbound((x0+w)/self.block_w+1, self.hblocks)
    y1 = upperbound((y0+h)/self.block_h+1, self.vblocks)
    x0 = lowerbound(x0/self.block_w, 0)
    y0 = lowerbound(y0/self.block_h, 0)
    depth0 = self.last_depth
    for y in xrange(y0, y1):
      line = self.map[y]
      for x in xrange(x0, x1):
        obj0 = line[x]
        if not obj0 or obj0.depth < depth0:
          depth0 = -1
          break
      if depth0 == -1: break
    else:
      return

    obj1 = SWFShapeScreen.SWFShapeRef(self.current_depth, (x1-x0)*(y1-y0))
    self.current_depth += 1
    # find completely covered objects (whose ref==0).
    for line in self.map[y0:y1]:
      for x in xrange(x0, x1):
        obj0 = line[x]
        if obj0:
          obj0.count -= 1
          if obj0.count == 0:
            replaced[obj0.depth] = 1
        line[x] = obj1
    
    added.append((obj1.depth, x0*self.block_w, y0*self.block_h, (x1-x0)*self.block_w, (y1-y0)*self.block_h))
    return


##  SWFVideoScreen
##
class SWFVideoScreen(SWFBlockScreen):
  
  """
  SWFVideoScreen is a SWFScreen which consists of a grid of
  blocks. This is used by SWFVideoStream.
  """

  def __init__(self, x0, y0, w, h, block_w, block_h, scaling=None):
    SWFBlockScreen.__init__(self, x0, y0, w, h, block_w, block_h,
                            scaling=scaling)
    return

  def init_blocks(self):
    self.block_changed = [ [True]*self.hblocks for i in xrange(self.vblocks) ]
    self.block_image = [ [None]*self.hblocks for i in xrange(self.vblocks) ]
    return

  # must return a string!
  def get_block_change(self, x, y):
    '''get change of block (x,y)'''
    if not self.block_changed[y][x]:
      return ''
    x0 = x*self.block_w
    y0 = self.out_height-(y+1)*self.block_h
    # if the block is partial, the player also expects a partial image.
    w = upperbound(self.block_w, self.out_width-x0)
    h = self.block_h
    if y0 < 0:
      h += y0
      y0 = 0
    # for some reason y-axis is filpped in VideoPacket. (BGR)
    # so we flip it in advance so that it can go back correctly...
    data = convert_image_to_string_rgb_flipped(self.get_image(x0, y0, w, h))
    hval = hash(data)
    if self.block_image[y][x] == hval:
      return ''
    self.block_changed[y][x] = False
    self.block_image[y][x] = hval
    data = ''.join([ data[i+2]+data[i+1]+data[i] for i in xrange(0, len(data), 3) ])
    return data
  
  def paint_image(self, x0, y0, w, h, data):
    if not SWFScreen.paint_image(self, x0, y0, w, h, data): return False
    x0 -= self.x0
    y0 -= self.y0
    #assert w and h and 0 < x0+w and x0 < self.out_width and 0 < y0+h and y0 < self.out_height
    if self.scaling:
      (x0,y0,w,h) = (int(x0*self.scaling), int(y0*self.scaling),
                     int(w*self.scaling), int(h*self.scaling))
    x1 = upperbound((x0+w-1)/self.block_w+1, self.hblocks)
    y1 = upperbound((self.out_height-y0)/self.block_h+1, self.vblocks)
    x0 = lowerbound(x0/self.block_w, 0)
    y0 = lowerbound((self.out_height-(y0+h-1))/self.block_h, 0)
    for line in self.block_changed[y0:y1]:
      for x in xrange(x0, x1):
        line[x] = True
    return True
  

##################################################################

##  MovieOutputStream
##
class MovieOutputStream:

  """
  MovieOutputStream is an abstract class which produces
  some external representation of a movie (either to a file or to a display).
  This is used for generating SWF files or playing movies on the screen.
  """
  
  def __init__(self, info, debug=False):
    self.debug = debug
    self.info = info
    self.output_frames = 0
    return

  def open(self):
    return
  
  def set_keyframe(self):
    return
  
  def paint_frame(self, (t, images, othertags)):
    raise NotImplementedError
  
  def next_frame(self):
    self.output_frames += 1
    return
  
  def close(self):
    if self.debug:
      print >>stderr, 'stream: close'
    return

  def preserve_frame(self):
    return None
  
  def recover_frame(self, img):
    raise NotImplementedError


##  SWFOutputStream
##
class SWFOutputStream(MovieOutputStream):

  """
  SWFOutputStream is a MovieOutputStream which produces a SWF file.
  """

  swf_version = None

  def __init__(self, info, debug=False):
    assert info.filename, 'Filename not specified!'
    MovieOutputStream.__init__(self, info, debug)
    self.info.set_swf_version(self.swf_version)
    self.writer = None
    return

  def open(self):
    MovieOutputStream.open(self)
    print >>stderr, 'Creating movie: %r: version=%d, size=%dx%d, framerate=%s, compression=%s' % \
          (self.info.filename, self.info.swf_version,
           self.info.width, self.info.height,
           self.info.framerate, self.info.compression)
    self.writer = SWFWriter(self.info.filename, self.swf_version,
                            (0,self.info.width*20, 0,self.info.height*20),
                            self.info.framerate, self.info.compression)
    # Write BGColor
    self.writer.start_tag()
    self.writer.writergb((255,255,255))
    self.writer.end_tag(9)
    # add mp3 header (if any)
    if self.info.mp3:
      # write SoundStreamHeader
      assert self.info.mp3.isstereo != None, 'mp3 isstereo is not set.'
      assert self.info.mp3.sample_rate != None, 'mp3 sample_rate is not set.'
      self.writer.start_tag()
      MP3_RATE = {11025:1, 22050:2, 44100:3}
      rate = MP3_RATE[self.info.mp3.sample_rate]
      self.writer.writeui8(rate << 2 | 2 | int(self.info.mp3.isstereo))
      self.writer.writeui8(rate << 2 | (2<<4) | 2 | int(self.info.mp3.isstereo))
      self.writer.writeui16(int(self.info.mp3.sample_rate / self.info.framerate))
      # the first seeksamples, mp3.seek_frame should be preformed in advance.
      self.writer.writeui16(self.info.mp3.seeksamples)
      self.writer.end_tag(18)
    self.othertags = []
    return

  def next_frame(self):
    MovieOutputStream.next_frame(self)
    # add other unknown tags
    for (tag, data) in self.othertags:
      self.writer.start_tag()
      self.writer.write(data)
      self.writer.end_tag(tag)
    # ShowFrame
    self.writer.start_tag()
    self.writer.end_tag(1)
    self.othertags = []
    return

  def write_mp3frames(self, frameid=None):
    # add mp3 frames (if any)
    if frameid == None:
      frameid = self.output_frames
    if self.info.mp3:
      t = (frameid+1) / self.info.framerate
      (nsamples, seeksamples, mp3frames) = self.info.mp3.get_frames_until(t)
      # SoundStreamBlock
      self.writer.start_tag()
      self.writer.writeui16(nsamples)
      self.writer.writeui16(seeksamples)
      self.writer.write(''.join(mp3frames))
      self.writer.end_tag(19)
    return

  def close(self):
    MovieOutputStream.close(self)
    if self.writer:
      self.writer.start_tag()
      self.writer.end_tag(0)
      self.writer.write_file(self.output_frames)
      self.writer = None
    return

  
##  SWFShapeStream
##
class SWFShapeStream(SWFOutputStream):

  """
  SWFShapeStream produces a SWF file with a set of overlapped
  shapes with lossless images.
  """
  
  swf_version = 5                       # SWF5

  def open(self):
    SWFOutputStream.open(self)
    (x,y,w,h) = self.info.clipping
    self.screen = SWFShapeScreen(x, y, w, h, scaling=self.info.scaling)
    self.set_keyframe()
    self.tmp_objs = []
    self.replaced = {}
    return
  
  # add shape object
  def add_object(self, img, depth, x, y):
    (w,h) = imgsize(img)
    data = zlib.compress(convert_image_to_string_xrgb(img))
    if self.debug:
      print >>stderr, 'add_object:', depth, (x,y,w,h), len(data)
    # DefineBitsLossless
    self.writer.start_tag()
    image_id = self.writer.newid()
    self.writer.writeui16(image_id)
    self.writer.writeui8(5)             # fmt=5
    self.writer.writeui16(w)
    self.writer.writeui16(h)
    self.writer.write(data)
    self.writer.end_tag(20, True) # forcelong because of flashplayer's bug
    # DefineShape3
    self.writer.start_tag()
    shape_id = self.writer.newid()
    self.writer.writeui16(shape_id)
    self.writer.writerect((20, w*20+20, 20, h*20+20))
    self.writer.write_style(3, [(0x43,None,None,None,image_id,(20,20,None,None,0,0))], [])
    self.writer.write_shape(3, [(0,(20,20)),(1,(w*20,0)),(1,(0,h*20)),(1,(-w*20,0)),(1,(0,-h*20))], fillstyle=1)
    self.writer.end_tag(32)
    # PlaceObject2
    self.writer.start_tag()
    self.writer.writeui8(2|4)
    self.writer.writeui16(depth)
    self.writer.writeui16(shape_id)
    self.writer.writematrix((None, None, None, None, x*20, y*20))
    self.writer.end_tag(26)
    return

  # remove shape object
  # if you leave objects on the screen, it gets verry slow.
  def remove_object(self, depth):
    if self.debug:
      print >>stderr, 'remove_object:', depth
    # RemoveObject2
    self.writer.start_tag()
    self.writer.writeui16(depth)
    self.writer.end_tag(28)
    return

  def paint_frame(self, (t, images, othertags)):
    self.othertags.extend(othertags)
    for ((x0,y0), (w,h,data)) in images:
      if self.debug:
        print >>stderr, 'paint:', (x0,y0), (w,h)
      if self.screen.paint_image(x0, y0, w, h, data):
        # do not attempt to create another shape object if
        # its entire area is already covered by other objects which are
        # going to be created.
        if self.info.scaling:
          (x0,y0,w,h) = (int(x0*self.info.scaling), int(y0*self.info.scaling),
                         int(w*self.info.scaling), int(h*self.info.scaling))
        self.screen.place_object(self.tmp_objs, x0, y0, w, h, self.replaced)
    return

  def next_frame(self):
    self.screen.prepare_image()
    addobjs = []
    for (depth,x0,y0,w,h) in self.tmp_objs:
      if depth in self.replaced:
        # if the object is completely covered by another object which is
        # placed within the same frame, do nothing.
        del self.replaced[depth]
      else:
        addobjs.append((depth,x0,y0,w,h))
    # Remove completely overriden objects.
    for depth in self.replaced.iterkeys():
      self.remove_object(depth)
    for (depth,x0,y0,w,h) in addobjs:
      # Image & Shape & Place tags.
      self.add_object(self.screen.get_image(x0, y0, w, h), depth, x0, y0)
    self.screen.next_frame()
    self.tmp_objs = []
    self.replaced = {}
    SWFOutputStream.next_frame(self)
    return
  
  def set_keyframe(self):
    self.screen.initmap()
    return
  

##  SWFVideoStream
##
class SWFVideoStream(SWFOutputStream):

  """
  SWFVideoStream produces a SWF file with a video object.
  """
  
  swf_version = 7                       # SWF7

  def __init__(self, info, debug=False):
    SWFOutputStream.__init__(self, info, debug)
    return
  
  def open(self):
    SWFOutputStream.open(self)
    (x,y,w,h) = self.info.clipping
    self.screen = SWFVideoScreen(x, y, w, h, self.info.blocksize, self.info.blocksize,
                                 scaling=self.info.scaling)
    self.video_object = self.writer.newid()
    # write DefineVideoStream
    assert not self.writer.fpstack
    pos0 = self.writer.fp.tell()
    self.writer.start_tag()
    self.writer.writeui16(self.video_object) # video char
    self.mangle_pos = pos0 + 4
    # XXX:
    # Here we need to put the number of the frames in this video object.
    # However, we can't tell this right now. So we put a tentative number
    # and change it later on.
    self.writer.writeui16(0)            # must be changed later.
    self.writer.writeui16(self.screen.out_width)
    self.writer.writeui16(self.screen.out_height)
    self.writer.writeui8(0)             # smoothing off
    self.writer.writeui8(3)             # SCREENVIDEO
    self.writer.end_tag(60)
    # PlaceObject2
    self.writer.start_tag()
    self.writer.writeui8(2|4)
    self.writer.writeui16(1)            # depth
    self.writer.writeui16(self.video_object) # video char
    self.writer.writematrix((None, None, None, None, 0, 0))
    self.writer.end_tag(26)
    self.set_keyframe()
    self.painted = False
    return

  def paint_frame(self, (t, images, othertags)):
    self.othertags.extend(othertags)
    for ((x0,y0), (w,h,data)) in images:
      if self.debug:
        print >>stderr, 'paint:', (x0,y0), (w,h)
      if self.screen.paint_image(x0, y0, w, h, data):
        self.painted = True
    return

  def next_frame(self):
    if self.is_keyframe or self.painted:
      r = []
      changed = self.is_keyframe
      self.screen.prepare_image()
      for y in xrange(self.screen.vblocks):
        for x in xrange(self.screen.hblocks):
          data = self.screen.get_block_change(x, y)
          r.append(data)
          if data:
            changed = True
      if changed:
        # write VideoFrame tag
        self.writer.start_tag()
        self.writer.writeui16(self.video_object) # video char
        self.writer.writeui16(self.output_frames)
        # SCREENVIDEOPACKET
        if self.is_keyframe:
          self.writer.writebits(4, 1)
          self.is_keyframe = False
        else:
          self.writer.writebits(4, 2)
        self.writer.writebits(4, 3) # screenvideo codec
        self.writer.writebits(4, self.screen.block_w/16-1)
        self.writer.writebits(12, self.screen.out_width)
        self.writer.writebits(4, self.screen.block_h/16-1)
        self.writer.writebits(12, self.screen.out_height)
        self.writer.finishbits()
        for blocks in r:
          if blocks:
            data = zlib.compress(''.join(blocks))
            self.writer.writeub16(len(data))
            self.writer.write(data)
          else:
            self.writer.writeub16(0)
        self.writer.end_tag(61)
        # PlaceObject2
        # For some reason we need to set the RATIO to the current frame number every time.
        # This is not documented!
        self.writer.start_tag()
        self.writer.writeui8(17)
        self.writer.writeui16(self.video_object)
        self.writer.writeui16(self.output_frames)
        self.writer.end_tag(26)
    SWFOutputStream.next_frame(self)
    return

  def set_keyframe(self):
    self.screen.init_blocks()
    self.is_keyframe = True
    return

  def close(self):
    assert not self.writer.fpstack
    self.writer.fp.seek(self.mangle_pos) # mangle this
    self.writer.writeui16(self.output_frames) # set the number of frames into DefineVideoStream tag.
    self.writer.fp.seek(0, 2) # go back
    SWFOutputStream.close(self)
    return


##  MovieBuilder
##
class MovieBuilder:

  """
  MovieBuilder arranges a set of partial images to construct
  a consistent image of each frame. It provides a proper sequence of images
  to a MovieOutputStream object.
  """

  # src: MovieContainer, stream: MovieOutputStream
  def __init__(self, movie, stream, kfinterval=0, mp3seek=False, verbose=True, pinterval=50, debug=False):
    self.movie = movie
    self.stream = stream
    self.debug = debug
    self.verbose = verbose
    self.mp3seek = mp3seek
    self.kfinterval = kfinterval
    self.pinterval = pinterval
    return

  def start(self):
    self.frameid = -1
    self.preserved = {}
    if self.movie.info.mp3:
      self.movie.info.mp3.seek_frame(0)
    self.stream.open()
    return
  
  def step(self):
    if self.debug:
      print >>stderr, 'step: %d -> %d' % (self.frameid, self.frameid+1)
    self.frameid += 1
    self.stream.paint_frame(self.movie.get_frame(self.frameid))
    if ((self.frameid % self.pinterval) == 0 and 
        self.frameid not in self.preserved):
      img = self.stream.preserve_frame()
      if img:
        self.preserved[self.frameid] = img
        if self.debug:
          print >>stderr, 'preserve: %d' % self.frameid
    return

  def seek(self, frameid):
    if self.debug:
      print >>stderr, 'seek: %d -> %d' % (self.frameid, frameid)
    if frameid == 0:
      self.frameid = -1
      self.step()
      if self.movie.info.mp3 and self.mp3seek:
        self.movie.info.mp3.seek_frame(0)
    elif frameid == self.frameid+1:
      self.step()
    else:
      if frameid < self.frameid:
        prev = 0
        image = None
        for (fid,img) in self.preserved.iteritems():
          if fid <= frameid and prev <= fid:
            (prev, image) = (fid, img)
        if image:
          self.stream.recover_frame(image)
          self.stream.set_keyframe()
      else:
        prev = self.frameid
      # replay the sequences.
      if self.debug:
        print >>stderr, 'range:', prev, frameid
      self.frameid = prev
      for fid in xrange(prev, frameid):
        self.step()
      if self.movie.info.mp3 and self.mp3seek:
        self.movie.info.mp3.seek_frame(frameid / self.movie.info.framerate)
    if self.kfinterval and (frameid % self.kfinterval) == 0:
      self.stream.set_keyframe()
    return
  
  def finish(self):
    self.stream.close()
    return

  def build(self, frames=None):
    if not frames:
      frames = range(self.movie.nframes)
    self.start()
    for frameid in frames:
      self.seek(frameid)
      if self.debug:
        print >>stderr, 'next_frame'
      if self.verbose:
        stderr.write('.'); stderr.flush()
      if self.movie.info.mp3:
        if self.mp3seek:
          self.stream.write_mp3frames(frameid)
        else:
          self.stream.write_mp3frames()
      self.stream.next_frame()
    self.finish()
    if self.verbose:
      print >>stderr, '%d frames written (duration=%.1fs)' % \
            (len(frames), len(frames)/self.movie.info.framerate)
    return
