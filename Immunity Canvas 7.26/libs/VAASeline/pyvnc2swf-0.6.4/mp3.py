#!/usr/bin/env python
##
##  mp3.py
##
## $Id: mp3.py,v 1.7 2005/08/19 03:14:42 euske Exp $

import sys
from struct import pack, unpack
stderr = sys.stderr


##  MP3Storage
##
class MP3Storage:

  def __init__(self, debug=False):
    self.debug = debug
    self.isstereo = None
    self.bit_rate = None
    self.sample_rate = None
    self.initial_skip = 0
    self.frames = []
    #
    self.played_samples = 0
    self.playing_frame = 0
    self.seeksamples = 0
    return

  def __repr__(self):
    return '<MP3Storage: isstereo=%r, bit_rate=%r, sample_rate=%r, initial_skip=%r, frames=%d>' % \
           (self.isstereo, self.bit_rate, self.sample_rate, self.initial_skip, len(self.frames))

  def set_stereo(self, isstereo):
    if self.isstereo == None:
      self.isstereo = isstereo
    elif self.isstereo != isstereo:
      print >>stderr, 'mp3: isstereo does not match!'
    return

  def set_bit_rate(self, bit_rate):
    if self.bit_rate == None:
      self.bit_rate = bit_rate
    elif self.bit_rate != bit_rate:
      print >>stderr, 'mp3: bit_rate does not match! %d, %d' % (self.bit_rate, bit_rate)
    return
  
  def set_sample_rate(self, sample_rate):
    if self.sample_rate == None:
      self.sample_rate = sample_rate
    elif self.sample_rate != sample_rate:
      print >>stderr, 'mp3: sample_rate does not match!'
    return

  def set_initial_skip(self, initial_skip):
    if initial_skip:
      self.initial_skip = initial_skip
    return

  def add_frame(self, nsamples, frame):
    self.frames.append((nsamples, frame))
    return

  def needsamples(self, t):
    return int(self.sample_rate * t) + self.initial_skip

  def get_frames_until(self, t):
    # write mp3 frames
    # Before:
    #   MP3 |----|played_samples
    #   SWF |-------|-----|needsamples(t)
    #             prev   cur.
    #
    # After:
    #                ->|  |<- next seeksamples
    #   MP3 |----------|played_samples
    #   SWF |-------|-----|needsamples(t)
    #             prev   cur.
    needsamples = self.needsamples(t)
    nsamples = 0
    frames = []
    while self.playing_frame < len(self.frames):
      (samples,data) = self.frames[self.playing_frame]
      if needsamples <= self.played_samples+nsamples+samples: break
      nsamples += samples
      frames.append(data)
      self.playing_frame += 1
    seeksamples = self.seeksamples
    self.played_samples += nsamples
    self.seeksamples = needsamples-self.played_samples # next seeksample
    return (nsamples, seeksamples, frames)

  def seek_frame(self, t):
    needsamples = self.needsamples(t)
    self.played_samples = 0
    for (i,(samples,data)) in enumerate(self.frames):
      if needsamples <= self.played_samples+samples: break
      self.played_samples += samples
      self.playing_frame = i
    self.seeksamples = needsamples-self.played_samples
    return


##  MP3Reader
##
class MP3Reader:

  """
  read MPEG frames.
  """
  
  def __init__(self, storage):
    self.storage = storage
    return

  def read(self, n):
    if self.length != None:
      if self.length <= 0:
        return ''
      self.length -= n
    return self.fp.read(n)
  
  BIT_RATE1 = [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320]
  BIT_RATE2 = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160]
  SAMPLE_RATE1 = [44100, 48000, 32000]
  SAMPLE_RATE2 = [22050, 24000, 16000]
  SAMPLE_RATE25 = [11025, 12000, 8000]
  def read_mp3file(self, fp, length=None, totalsamples0=None, seeksamples=None, verbose=False):
    """parameter seeksamples is ignored."""
    self.fp = fp
    self.length = length
    totalsamples = 0
    while 1:
      x = self.read(4)
      if not x: break
      if x.startswith('TAG'):
        # TAG - ignored
        data = x[3]+self.read(128-4)
        if verbose:
          print >>stderr, 'TAG', repr(data)
        continue
      elif x.startswith('ID3'):
        # ID3 - ignored
        id3version = x[3]+fp.read(1)
        flags = ord(fp.read(1))
        s = [ ord(c) & 127 for c in fp.read(4) ]
        size = (s[0]<<21) | (s[1]<<14) | (s[2]<<7) | s[3]
        data = fp.read(size)
        if verbose:
          print >>stderr, 'ID3', repr(data)
        continue
      h = unpack('>L', x)[0]
      assert (h & 0xffe00000L) == 0xffe00000L, '!Frame Sync: %r' % x
      version = (h & 0x00180000L) >> 19
      assert version != 1
      assert (h & 0x00060000L) == 0x00020000L, '!Layer3'
      protected = not (h & 0x00010000L)
      b = (h & 0xf000) >> 12
      assert b != 0 and b != 15, '!Bit_rate'
      if version == 3:                      # V1
        bit_rate = self.BIT_RATE1[b]
      else:                                 # V2 or V2.5
        bit_rate = self.BIT_RATE2[b]
      self.storage.set_bit_rate(bit_rate)
      s = (h & 0x0c00) >> 10
      assert s != 3, '!Mp3'
      if version == 3:                      # V1
        sample_rate = self.SAMPLE_RATE1[s]
      elif version == 2:                    # V2
        sample_rate = self.SAMPLE_RATE2[s]
      elif version == 0:                    # V2.5
        sample_rate = self.SAMPLE_RATE25[s]
      self.storage.set_sample_rate(sample_rate)
      nsamples = 1152
      if sample_rate <= 24000:
        nsamples = 576
      pad = (h & 0x0200) >> 9
      channel = (h & 0xc0) >> 6
      self.storage.set_stereo(1-(channel/2))
      joint = (h & 0x30) >> 4
      copyright = bool(h & 8)
      original = bool(h & 4)
      emphasis = h & 3
      if version == 3:
        framesize = 144000 * bit_rate / sample_rate + pad
      else:
        framesize = 72000 * bit_rate / sample_rate + pad
      if verbose:
        print >>stderr, 'Frame: bit_rate=%dk, sample_rate=%d, framesize=%d' % \
              (bit_rate, sample_rate, framesize)
      data = x+self.read(framesize-4)
      self.storage.add_frame(nsamples, data)
      totalsamples += nsamples
    if totalsamples0:
      assert totalsamples == totalsamples0
    return


if __name__ == "__main__":
  s = MP3Storage(True)
  MP3Reader(s).read_mp3file(file(sys.argv[1]))
  s.start_playing()
  for t in (0, 0.1, 0.2, 0.3, 0.4):
    (nsample,seeksample,frames)=s.get_frames_until(t)
    print t, (nsample,seeksample,len(''.join(frames)))
