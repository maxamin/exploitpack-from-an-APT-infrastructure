#!/usr/bin/env python
##
##  rfb.py
##
## $Id: rfb.py,v 1.10 2005/08/15 12:28:00 euske Exp $

import sys, time, socket
from struct import pack, unpack
from crippled_des import DesCipher
from image import IMG_SOLID, IMG_RAW
stderr = sys.stderr
lowerbound = max


# Exceptions
class RFBError(Exception): pass
class RFBAuthError(RFBError): pass
class RFBProtocolError(RFBError): pass



##  RFBFrameBuffer
##
class RFBFrameBuffer:

  def init_screen(self, width, height, name):
    #print >>stderr, 'init_screen: %dx%d, name=%r' % (width, height, name)
    raise NotImplementedError

  def set_converter(self, convert_pixels, convert_color1):
    self.convert_pixels = convert_pixels
    self.convert_color1 = convert_color1
    return

  def process_pixels(self, x, y, width, height, data):
    #print >>stderr, 'process_pixels: %dx%d at (%d,%d)' % (width,height,x,y)
    raise NotImplementedError
  
  def process_solid(self, x, y, width, height, data):
    #print >>stderr, 'process_solid: %dx%d at (%d,%d), color=%r' % (width,height,x,y, color)
    raise NotImplementedError

  def update_screen(self, t):
    #print >>stderr, 'update_screen'
    raise NotImplementedError
  
  def close(self):
    return
  

##  RFBProxy
##
class RFBProxy:
  "Abstract class of RFB clients."

  def __init__(self, fb=None, preferred_encoding=(5,0), debug=0):
    self.fb = fb
    self.debug = debug
    self.preferred_encoding = preferred_encoding
    return

  FASTEST_FORMAT = (32, 8, 1, 1, 255, 255, 255, 24, 16, 8)
  def preferred_format(self, bitsperpixel, depth, bigendian, truecolour,
                       red_max, green_max, blue_max,
                       red_shift, green_shift, blue_shift):
    # should return 10-tuple (bitsperpixel, depth, bigendian, truecolour,
    #   red_max, green_max, blue_max, red_shift, green_shift, blue_shift)
    if self.fb:
      self.fb.set_converter(lambda data: data,
                            lambda data: unpack('BBBx', data))
    return self.FASTEST_FORMAT
  
  def send(self, s):
    "Send data s to the server."
    raise NotImplementedError

  def recv(self, n):
    "Receive n-bytes data from the server."
    raise NotImplementedError

  def recv_relay(self, n):
    "Same as recv() except the received data is also passed to self.relay.recv_framedata."
    return self.recv(n)

  def write(self, n):
    return
  
  def request_update(self):
    "Send a request to the server."
    raise NotImplementedError
  def finish_update(self):
    if self.fb:
      self.fb.update_screen(time.time())
    return
  
  def init(self):
    # send: client protocol version
    self.send('RFB 003.008\x0a')
    # recv: server protocol version
    self.server_version = self.recv(12)
    if self.debug:
      print >>stderr, 'server_version: %r' % self.server_version
    return self

  def getpass(self):
    raise NotImplementedError

  def auth(self):

    # vnc challange & response auth
    def crauth():
      p = self.getpass()
      if not p:
        raise RFBError('Auth cancelled')
      # from pyvncviewer
      des = DesCipher((p+'\x00'*8)[:8])
      challange = self.recv(16)
      if self.debug:
        print >>stderr, 'challange: %r' % challange
      response = des.encrypt(challange[:8]) + des.encrypt(challange[8:])
      if self.debug:
        print >>stderr, 'response: %r' % response
      self.send(response)
      # recv: security result
      (result,) = unpack('>L', self.recv(4))
      return result

    server_result = 0
    if self.server_version.startswith('RFB 003.003'):
      # protocol 3.3
      # recv: server security
      (server_security,) = unpack('>L', self.recv(4))
      if self.debug:
        print >>stderr, 'server_security: %r' % server_security
      if server_security == 1:
        server_result = 0
      elif server_security == 2:
        server_result = crauth()
      else:
        raise RFBProtocolError('Unsupported server security type: %d' % server_security)
    else:
      # protocol 3.7 or 3.8
      # recv: multiple server securities
      (nsecurities,) = unpack('>B', self.recv(1))
      server_securities = self.recv(nsecurities)
      if self.debug:
        print >>stderr, 'server_securities: %r' % server_securities
      # must include None or VNCAuth
      if '\x01' in server_securities:
        # None
        self.send('\x01')
        if self.server_version.startswith('RFB 003.008'):
          # Protocol 3.8: must recv security result
          (server_result,) = unpack('>L', self.recv(4))
        else:
          server_result = 0
      elif '\x02' in server_securities:
        # VNCAuth
        self.send('\x02')
        server_result = crauth()
    # result returned.
    if self.debug:
      print >>stderr, 'server_result: %r' % server_result
    if server_result != 0:
      # auth failed.
      if self.server_version.startswith('RFB 003.008'):
        (reason_length,) = unpack('>L', self.recv(4))
        reason = self.recv(reason_length)
      else:
        reason = server_result
      raise RFBAuthError('Auth Error: %s' % reason)
    # negotiation ok.
    # send: always shared.
    self.send('\x01')
    return self

  def start(self):
    # server info.
    server_init = self.recv(24)
    (self.width, self.height, pixelformat, namelen) = unpack('>HH16sL', server_init)
    self.name = self.recv(namelen)
    (bitsperpixel, depth, bigendian, truecolour,
     red_max, green_max, blue_max,
     red_shift, green_shift, blue_shift) = unpack('>BBBBHHHBBBxxx', pixelformat)
    if self.debug:
      print >>stderr, 'Server Encoding:'
      print >>stderr, ' width=%d, height=%d, name=%r' % (self.width, self.height, self.name)
      print >>stderr, ' pixelformat=', (bitsperpixel, depth, bigendian, truecolour)
      print >>stderr, ' rgbmax=', (red_max, green_max, blue_max)
      print >>stderr, ' rgbshift=', (red_shift, green_shift, blue_shift)
    # setformat
    self.send('\x00\x00\x00\x00')
    # 32bit, 8bit-depth, big-endian(RGBX), truecolour, 255max
    (bitsperpixel, depth, bigendian, truecolour,
     red_max, green_max, blue_max,
     red_shift, green_shift, blue_shift) = self.preferred_format(bitsperpixel, depth, bigendian, truecolour,
                                                                 red_max, green_max, blue_max,
                                                                 red_shift, green_shift, blue_shift)
    self.bytesperpixel = bitsperpixel/8
    pixelformat = pack('>BBBBHHHBBBxxx', bitsperpixel, depth, bigendian, truecolour,
                       red_max, green_max, blue_max,
                       red_shift, green_shift, blue_shift)
    self.send(pixelformat)
    self.write(pack('>HH16sL', self.width, self.height, pixelformat, namelen))
    self.write(self.name)
    if self.fb:
      self.fb.init_screen(self.width, self.height, self.name)
    self.send('\x02\x00' + pack('>H', len(self.preferred_encoding)))
    for e in self.preferred_encoding:
      self.send(pack('>l', e))
    return self
  
  def loop1(self):
    self.request_update()
    c = self.recv_relay(1)
    if not c: return False
    if c == '\x00':
      (nrects,) = unpack('>xH', self.recv_relay(3))
      if self.debug:
        print >>stderr, 'FrameBufferUpdate: nrects=%d' % nrects
      for rectindex in xrange(nrects):
        (x0, y0, width, height, t) = unpack('>HHHHl', self.recv_relay(12))
        if self.debug:
          print >>stderr, ' %d: %d x %d at (%d,%d), type=%d' % (rectindex, width, height, x0, y0, t)
        if t == 0:
          # RawEncoding
          l = width*height*self.bytesperpixel
          data = self.recv_relay(l)
          if self.debug:
            print >>stderr, ' RawEncoding: len=%d, received=%d' % (l, len(data))
          if self.fb:
            self.fb.process_pixels(x0, y0, width, height, data)
        elif t == 1:
          # CopyRectEncoding
          raise RFBProtocolError('unsupported: CopyRectEncoding')
        elif t == 2:
          # RREEncoding
          (nsubrects,) = unpack('>L', self.recv_relay(4))
          bgcolor = self.recv_relay(self.bytesperpixel)
          if self.debug:
            print >>stderr, ' RREEncoding: subrects=%d, bgcolor=%r' % (nsubrects, bgcolor)
          if self.fb:
            self.fb.process_solid(x0, y0, width, height, bgcolor)
          for i in xrange(nsubrects):
            fgcolor = self.recv_relay(self.bytesperpixel)
            (x,y,w,h) = unpack('>HHHH', self.recv_relay(8))
            if self.fb:
              self.fb.process_solid(x0+x, y0+y, w, h, fgcolor)
            if 2 <= self.debug:
              print >>stderr, ' RREEncoding: ', (x,y,w,h,fgcolor)
        elif t == 4:
          # CoRREEncoding
          (nsubrects,) = unpack('>L', self.recv_relay(4))
          bgcolor = self.recv_relay(self.bytesperpixel)
          if self.debug:
            print >>stderr, ' CoRREEncoding: subrects=%d, bgcolor=%r' % (nsubrects, bgcolor)
          if self.fb:
            self.fb.process_solid(x0, y0, width, height, bgcolor)
          for i in xrange(nsubrects):
            fgcolor = self.recv_relay(self.bytesperpixel)
            (x,y,w,h) = unpack('>BBBB', self.recv_relay(4))
            if self.fb:
              self.fb.process_solid(x0+x, y0+y, w, h, fgcolor)
            if 2 <= self.debug:
              print >>stderr, ' CoRREEncoding: ', (x,y,w,h,fgcolor)
        elif t == 5:
          # HextileEncoding
          if self.debug:
            print >>stderr, ' HextileEncoding'
          (fgcolor, bgcolor) = (None, None)
          for y in xrange(0, height, 16):
            for x in xrange(0, width, 16):
              w = min(width-x, 16)
              h = min(height-y, 16)
              c = ord(self.recv_relay(1))
              assert c < 32
              if c & 1:
                # Raw
                l = w*h*self.bytesperpixel
                data = self.recv_relay(l)
                if self.fb:
                  self.fb.process_pixels(x0+x, y0+y, w, h, data)
                if 2 <= self.debug:
                  print >>stderr, '  Raw:', l
                continue
              if c & 2:
                bgcolor = self.recv_relay(self.bytesperpixel)
              if c & 4:
                fgcolor = self.recv_relay(self.bytesperpixel)
              if self.fb:
                self.fb.process_solid(x0+x, y0+y, w, h, bgcolor)
              if not c & 8:
                # Solid
                if 2 <= self.debug:
                  print >>stderr, '  Solid:', repr(bgcolor)
                continue
              nsubrects = ord(self.recv_relay(1))
              if c & 16:
                # SubrectsColoured
                if 2 <= self.debug:
                  print >>stderr, '  SubrectsColoured:', nsubrects, repr(bgcolor)
                for i in xrange(nsubrects):
                  color = self.recv_relay(self.bytesperpixel)
                  (xy,wh) = unpack('>BB', self.recv_relay(2))
                  if self.fb:
                    self.fb.process_solid(x0+x+(xy>>4), y0+y+(xy&15), (wh>>4)+1, (wh&15)+1, color)
                  if 3 <= self.debug:
                    print >>stderr, '   ', repr(color), (xy,wh)
              else:
                # NoSubrectsColoured
                if 2 <= self.debug:
                  print >>stderr, '  NoSubrectsColoured:', nsubrects, repr(bgcolor)
                for i in xrange(nsubrects):
                  (xy,wh) = unpack('>BB', self.recv_relay(2))
                  if self.fb:
                    self.fb.process_solid(x0+x+(xy>>4), y0+y+(xy&15), (wh>>4)+1, (wh&15)+1, fgcolor)
                  if 3 <= self.debug:
                    print >>stderr, '  ', (xy,wh)
        elif t == 16:
          # ZRLEEncoding
          raise RFBProtocolError('unsupported: ZRLEEncoding')
        else:
          raise RFBProtocolError('Illegal encoding: 0x%02x' % t)
      self.finish_update()
    elif c == '\x01':
      (first, ncolours) = unpack('>xHH', self.recv_relay(11))
      if self.debug:
        print >>stderr, 'SetColourMapEntries: first=%d, ncolours=%d' % (first, ncolours)
      for i in ncolours:
        self.recv_relay(6)

    elif c == '\x02':
      if self.debug:
        print >>stderr, 'Bell'

    elif c == '\x03':
      (length, ) = unpack('>3xL', self.recv_relay(7))
      data = self.recv_relay(length)
      if self.debug:
        print >>stderr, 'ServerCutText: %r' % data

    else:
      print >>stderr, 'Ignored msg=%r' % c

    return True

  def loop(self):
    while self.loop1():
      pass
    self.finish_update()
    return self

  def close(self):
    if self.fb:
      self.fb.close()
    return


##  RFBNetworkClient
##
class RFBNetworkClient(RFBProxy):
  
  def __init__(self, host, port, fb=None, preferred_encoding=(0,5), debug=0):
    RFBProxy.__init__(self, fb=fb, preferred_encoding=preferred_encoding, debug=debug)
    self.host = host
    self.port = port
    self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return

  def init(self):
    self.sock.connect((self.host, self.port))
    print >>stderr, 'Connected: %s:%d, preferred_encoding=%s' % (self.host, self.port, self.preferred_encoding)
    return RFBProxy.init(self)

  def recv(self, n):
    buf = []
    # windows doesn't have MSG_WAITALL, so we emulate it.
    while n:
      x = self.sock.recv(n)
      if not x: break
      buf.append(x)
      n -= len(x)
    return ''.join(buf)

  def send(self, s):
    return self.sock.send(s)
    
  def getpass(self):
    import getpass
    return getpass.getpass('Password for %s:%d: ' % (self.host, self.port))

  def request_update(self):
    if self.debug:
      print >>stderr, 'FrameBufferUpdateRequest'
    self.send('\x03\x01' + pack('>HHHH', 0, 0, self.width, self.height))
    return

  def close(self):
    RFBProxy.close(self)
    self.sock.close()
    return


##  RFBNetworkClientForRecording (vncrec equivalent)
##
class RFBNetworkClientForRecording(RFBNetworkClient):
  
  def __init__(self, host, port, fname, preferred_encoding=(5,0), debug=0):
    RFBNetworkClient.__init__(self, host, port, fb=None, preferred_encoding=preferred_encoding, debug=debug)
    print >>stderr, 'Creating vncrec: %r: vncLog0.0' % fname
    self.fp = file(fname, 'wb')
    self.write('vncLog0.0')
    # disguise data (security=none)
    self.write('RFB 003.003\x0a')
    self.write('\x00\x00\x00\x01')
    self.updated = True
    return

  def write(self, x):
    self.fp.write(x)
    return

  def request_update(self):
    if self.updated:
      self.updated = False
      t = time.time()
      self.write(pack('>LL', int(t), (t-int(t))*1000000))
      RFBNetworkClient.request_update(self)
    return
  
  def finish_update(self):
    self.updated = True
    return
  
  def recv_relay(self, n):
    data = self.recv(n)
    self.write(data)
    return data

  def close(self):
    RFBNetworkClient.close(self)
    self.fp.close()
    return


##  RFBFileParser
##
class RFBFileParser(RFBProxy):
  
  def __init__(self, fname, fb=None, debug=0):
    RFBProxy.__init__(self, fb=fb, debug=debug)
    if self.fb:
      self.fb.change_format = False
    self.fp = file(fname, 'rb')
    self.fname = fname
    return

  def preferred_format(self, bitsperpixel, depth, bigendian, truecolour,
                       red_max, green_max, blue_max,
                       red_shift, green_shift, blue_shift):
    if (bitsperpixel, depth, bigendian, truecolour,
        red_max, green_max, blue_max,
        red_shift, green_shift, blue_shift) == self.FASTEST_FORMAT:
      return RFBProxy.preferred_format(self, bitsperpixel, depth, bigendian, truecolour,
                                       red_max, green_max, blue_max,
                                       red_shift, green_shift, blue_shift)
    elif self.fb:
      if bigendian:
        endian = '>'
      else:
        endian = '<'
      try:
        length = {8:'B', 16:'H', 32:'L'}[bitsperpixel]
      except KeyError:
        raise 'invalid bitsperpixel: %d' % bitsperpixel
      unpackstr = endian + length
      nbytes = bitsperpixel / 8
      bits = {1:1, 3:2, 7:3, 15:4, 31:5, 63:6, 127:7, 255:8}
      try:
        e = 'lambda p: (((p>>%d)&%d)<<%d, ((p>>%d)&%d)<<%d, ((p>>%d)&%d)<<%d)' % \
            (red_shift, red_max, 8-bits[red_max],
             green_shift, green_max, 8-bits[green_max],
             blue_shift, blue_max, 8-bits[blue_max])
      except KeyError:
        raise 'invalid {red,green,blue}_max: %d, %d or %d' % (red_max, green_max, blue_max)
      getrgb = eval(e)
      unpack_pixels = eval('lambda data: unpack("%s%%d%s" %% (len(data)/%d), data)' % (endian, length, nbytes))
      unpack_color1 = eval('lambda data: unpack("%s", data)' % unpackstr)
      self.fb.set_converter(lambda data: ''.join([ pack('>BBB', *getrgb(p)) for p in unpack_pixels(data) ]),
                            lambda data: getrgb(unpack_color1(data)[0]))
    return (bitsperpixel, depth, bigendian, truecolour,
            red_max, green_max, blue_max,
            red_shift, green_shift, blue_shift)

  def seek(self, pos):
    self.fp.seek(pos)
    return
  def tell(self):
    return self.fp.tell()

  def init(self):
    self.curtime = 0
    version = self.fp.read(9)
    print >>stderr, 'Reading vncrec file: %s, version=%r...' % (self.fname, version)
    if version != 'vncLog0.0':
      raise RFBProtocolError('Unsupported vncrec version: %r' % version)
    return RFBProxy.init(self)
  
  def recv(self, n):
    x = self.fp.read(n)
    if len(x) != n:
      raise EOFError
    return x

  def send(self, s):
    return

  def auth(self):
    if self.server_version.startswith('RFB 003.003'):
      # protocol 3.3
      # recv: server security
      (server_security,) = unpack('>L', self.recv(4))
      if self.debug:
        print >>stderr, 'server_security=%r' % server_security
      if server_security == 2:
        # skip challenge+result (dummy)
        self.recv(20)
    else:
      RFBProxy.auth(self)
    return self

  def request_update(self):
    (sec, usec) = unpack('>LL', self.recv(8))
    self.curtime = sec+usec/1000000.0
    return
  
  def finish_update(self):
    if self.fb:
      self.fb.update_screen(self.curtime) # use the file time instead
    return

  def loop(self, endpos=0):
    try:
      while self.loop1():
        if endpos and endpos <= self.tell(): break
    except EOFError:
      self.finish_update()
    return self

  def close(self):
    RFBProxy.close(self)
    self.fp.close()
    return


##  RFBConverter
##
class RFBConverter(RFBFrameBuffer):

  def __init__(self, info, debug=0):
    self.debug = debug
    self.info = info
    return

  def init_screen(self, width, height, name):
    print >>stderr, 'VNC Screen: size=%dx%d, name=%r' % (width, height, name)
    self.info.set_defaults(width, height)
    self.images = []
    self.t0 = 0
    return

  def process_pixels(self, x, y, width, height, data):
    self.images.append( ((x, y), (width, height, (IMG_RAW, self.convert_pixels(data)))) )
    return
  
  def process_solid(self, x, y, width, height, data):
    self.images.append( ((x, y), (width, height, (IMG_SOLID, self.convert_color1(data)))) ) 
    return

  def calc_frames(self, t):
    if not self.t0:
      self.t0 = t
    return int((t - self.t0) * self.info.framerate)+1


##  RFBMovieConverter
##
class RFBMovieConverter(RFBConverter):

  def __init__(self, movie, debug=0):
    RFBConverter.__init__(self, movie.info, debug)
    self.movie = movie
    self.frameinfo = []
    return

  def process_pixels(self, x, y, width, height, data):
    if self.processing:
      RFBConverter.process_pixels(self, x, y, width, height, data)
    return
  
  def process_solid(self, x, y, width, height, data):
    if self.processing:
      RFBConverter.process_solid(self, x, y, width, height, data)
    return

  def update_screen(self, t):
    if not self.processing:
      frames = RFBConverter.calc_frames(self, t)
      done = False
      while len(self.frameinfo) < frames:
        if done:
          self.frameinfo.append((self.beginpos, -1))
        else:
          endpos = self.rfbparser.tell()
          self.frameinfo.append((self.beginpos, endpos))
          if self.debug:
            print >>stderr, 'scan:', self.beginpos, endpos
          self.beginpos = endpos
          done = True
    return

  def open(self, fname, debug=0):
    self.processing = False
    self.rfbparser = RFBFileParser(fname, self, debug)
    self.rfbparser.init().auth().start()
    self.beginpos = self.rfbparser.tell()
    self.rfbparser.loop()
    return

  def parse_frame(self, i):
    (pos, endpos) = self.frameinfo[i]
    if self.debug:
      print >>stderr, 'seek:', i, pos, endpos
    self.rfbparser.seek(pos)
    self.images = []
    self.processing = True
    self.rfbparser.loop(endpos)
    return (self.images, [])
  

##  RFBStreamConverter
##
class RFBStreamConverter(RFBConverter):
  
  def __init__(self, info, stream, debug=0):
    RFBConverter.__init__(self, info, debug)
    self.stream = stream
    return
  
  def init_screen(self, width, height, name):
    RFBConverter.init_screen(self, width, height, name)
    self.stream.open()
    self.nframes = 0
    return
  
  def update_screen(self, t):
    frames = RFBConverter.calc_frames(self, t)
    if self.nframes < frames:
      self.stream.paint_frame((t, self.images, []))
      self.images = []
      while self.nframes < frames:
        self.nframes += 1
        self.stream.next_frame()
    return
  
  def close(self):
    self.stream.close()
    return
