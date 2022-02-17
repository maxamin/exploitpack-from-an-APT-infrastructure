#!/usr/bin/env python
##
##  edit.py
##
## $Id: edit.py,v 1.8 2005/08/19 03:14:42 euske Exp $

import sys, re
from movie import SWFInfo, MovieContainer
from output import SWFVideoStream, SWFShapeStream, MovieBuilder
stderr = sys.stderr


# range2list: converts strings like "1,5-8" to [1,5,6,7,8].
class RangeError(ValueError): pass
def range2list(s, n0, n1, step=1):
  PAT_RANGE = re.compile(r'^([0-9]*)-([0-9]*)$')
  r = []
  for i in s.split(','):
    i = i.strip()
    if not i: continue
    if i.isdigit():
      n = int(i)
      if n0 <= n and n <= n1:
        r.append(n)
      else:
        raise RangeError('%d: must be in %d...%d' % (n,n0,n1))
    else:
      m = PAT_RANGE.match(i.strip())
      if not m:
        raise RangeError('%r: illegal number' % i)
      b = n0
      if m.group(1):
        b = int(m.group(1))
      e = n1
      if m.group(2):
        e = int(m.group(2))
      if e < b:
        (b,e) = (e,b)
      if b < n0:
        raise RangeError('%d: must be in %d...%d' % (b,n0,n1))
      if n1 < e:
        raise RangeError('%d: must be in %d...%d' % (e,n0,n1))
      r.extend(xrange(b,e+1,step))
  return r


# reorganize
def reorganize(info, moviefiles,
               range_str='-', step=1,
               is_video=False, kfinterval=0, 
               mp3seek=True, mp3skip=0):
  movie = MovieContainer(info)
  if is_video:
    stream = SWFVideoStream(info)
  else:
    stream = SWFShapeStream(info)
  for fname in moviefiles:
    if fname.endswith('.swf'):
      # vnc2swf file
      movie.parse_vnc2swf(fname, True)
    elif fname.endswith('.vnc'):
      # vncrec file
      movie.parse_vncrec(fname)
  r = range2list(range_str, 0, movie.nframes-1, step)
  if movie.info.mp3:
    movie.info.mp3.set_initial_skip(mp3skip)
  builder = MovieBuilder(movie, stream, mp3seek=mp3seek, kfinterval=kfinterval)
  builder.build(r)
  info.generate_html()
  return


# main
def main(argv):
  import getopt
  def usage():
    print >>stderr, '''usage: edit.py
    [-d] [-c] [-V] [-f|-F frames] [-a mp3file] [-r framerate]
    [-S mp3sampleskip] [-C WxH+X+Y] [-B blocksize] [-K keyframe]
    [-R framestep] [-s scaling]
    -o outfile.swf file1 file2 ...

    Specify one output filename from the following:
      *.swf: generate a reorganized and/or augmented movie.
      *.png|*.bmp: save snapshots of given frames as "X-nnn.png"
      *.mp3: extract an MP3 audio stream from a movie.
      
    -d: debug mode.
    -c: compression.
    -V: generate a movie in ScreenVideo format. (Flash version7 or above only)
    -f(-F) frames: frames to extract. e.g. 1-2,100-300,310,500-
       -F disables seeking audio.
    -R framestep: frame resampling step (default: 1)
    -s scaling: scale factor (default: 1)
    -a filename: attach MP3 file(s). (multiple files can be specified)
    -r framerate: override framerate.
    -B blocksize: (Video mode only) blocksize of video packet (must be a multiple of 16)
    -K keyframe: keyframe interval
    -S N: skip the first N samples of the sound when the movie starts.
    -C WxH+X+Y: crop a specific area of the movie.
    '''
    sys.exit(2)
  try:
    (opts, args) = getopt.getopt(argv, 'dr:o:VcHa:S:C:B:K:f:F:R:s:')
  except getopt.GetoptError:
    usage()
  #
  debug = 0
  info = SWFInfo()
  range_str = '-'
  step = 1
  is_video = False
  kfinterval = 0
  mp3skip = 0
  mp3seek = True
  for (k, v) in opts:
    if k == '-d':
      debug += 1
    elif k == '-r':
      info.set_framerate(float(v))
    elif k == '-o':
      info.filename = v
    elif k == '-a':
      fp = file(v)
      print 'Reading mp3 file: %s...' % v
      info.reg_mp3blocks(fp)
      fp.close()
    elif k == '-S':
      mp3skip = int(v)
      assert 0 <= mp3skip
    elif k == '-C':
      m = re.match(r'^(\d+)x(\d+)\+(\d+)\+(\d+)$', v)
      if not m:
        print >>stderr, 'Invalid clipping specification:', v
        usage()
      x = map(int, m.groups())
      info.clipping = (x[2],x[3], x[0],x[1])
    elif k == '-B':
      blocksize = int(v)
      assert 0 < blocksize and blocksize <= 256 and blocksize % 16 == 0
      info.blocksize = blocksize
    elif k == '-K':
      kfinterval = int(v)
    elif k == '-V':
      is_video = True
    elif k == '-c':
      info.compression = True
    elif k == '-f':
      range_str = v
    elif k == '-F':
      range_str = v
      mp3seek = False
    elif k == '-R':
      step = int(v)
      mp3seek = False
    elif k == '-s':
      info.scaling = float(v)
  if not args:
    print >>stderr, 'Specify at least one input movie.'
    usage()
  if not info.filename:
    print >>stderr, 'Specify exactly one output file.'
    usage()
  try:
    reorganize(info, args,
               range_str, step=step,
               is_video=is_video, kfinterval=kfinterval, 
               mp3seek=mp3seek, mp3skip=mp3skip)
  except RangeError, e:
    print >>stderr, 'RangeError:', e
  return

if __name__ == "__main__": main(sys.argv[1:])
