#!/usr/bin/env python
##
##  play.py
##
## $Id: play.py,v 1.5 2005/08/19 03:14:42 euske Exp $

import sys
import pygame
from movie import SWFInfo, MovieContainer
from output import SWFScreen, MovieOutputStream, MovieBuilder
lowerbound = max
upperbound = min
stderr = sys.stderr


##  PygameMoviePlayer
##
class PygameMoviePlayer(MovieOutputStream):

  """
  A simple movie player using Pygame.
  """

  font_size = 24

  def __init__(self, movie, debug=False):
    MovieOutputStream.__init__(self, movie.info, debug)
    self.builder = MovieBuilder(movie, self, debug)
    self.movie = movie
    return

  # MovieOuputStream methods
  
  def open(self):
    MovieOutputStream.open(self)
    # open window
    (x,y,w,h) = self.info.clipping
    self.imagesize = ( int(w*(self.info.scaling or 1)), int(h*(self.info.scaling or 1)) )
    self.screen = SWFScreen(x, y, w, h)
    (self.winwidth, self.winheight) = self.imagesize
    self.font = pygame.font.SysFont(pygame.font.get_default_font(), self.font_size)
    (fw1,fh1) = self.font.size('00000  ')
    (fw2,fh2) = self.font.size('[>]  ')
    self.panel_x0 = 0
    self.panel_x1 = fw1
    self.panel_x2 = fw1+fw2
    self.panel_y0 = self.winheight
    self.panel_y1 = self.winheight + fh1/2
    self.panel_h = fh1
    self.panel_w = lowerbound(64, self.winwidth-fw1-fw2-4)
    self.slide_h = fh1/2
    self.slide_w = 8
    self.actualwidth = self.panel_w+fw1+fw2+4
    self.window = pygame.display.set_mode((self.actualwidth, self.winheight+self.panel_h))
    self.playing = True
    return

  def paint_frame(self, (t, images, othertags)):
    for ((x0,y0), (w,h,data)) in images:
      self.screen.paint_image(x0, y0, w, h, data)
    return

  def preserve_frame(self):
    img = pygame.Surface(self.screen.buf.get_size())
    img.blit(self.screen.buf, (0,0))
    return img

  def recover_frame(self, img):
    self.screen.buf.blit(img, (0,0))
    return

  # additional methods

  def show_status(self):
    f = self.current_frame
    n = self.movie.nframes
    s = '%05d' % f
    self.window.fill((0,0,0), (0, self.panel_y0, self.actualwidth, self.panel_h))
    self.window.blit(self.font.render(s, 0, (255,255,255)), (0, self.panel_y0))
    if self.playing:
      self.window.blit(self.font.render('[>]', 0, (0,255,0)), (self.panel_x1, self.panel_y0))
    else:
      self.window.blit(self.font.render('[||]', 0, (255,0,0)), (self.panel_x1, self.panel_y0))
    self.window.fill((255,255,255), (self.panel_x2, self.panel_y1, self.panel_w, 1))
    x = self.panel_x2 + self.panel_w*f/n - self.slide_w/2
    y = self.panel_y1 - self.slide_h/2
    self.window.fill((255,255,255), (x, y, self.slide_w, self.slide_h))
    return

  def update(self):
    surface = self.screen.buf
    if self.info.scaling:
      # rotozoom is still very unstable... it causes segfault :(
      # instead we use scale.
      #surface = pygame.transform.rotozoom(surface, 0, self.scaling)
      surface = pygame.transform.scale(surface, self.imagesize)
      surface.set_alpha()
    self.window.blit(surface, (0,0))
    self.show_status()
    pygame.display.update()
    return

  def toggle_playing(self):
    self.playing = not self.playing
    if self.playing and self.movie.nframes-1 <= self.current_frame:
      self.current_frame = 0
    return

  def seek(self, goal):
    self.current_frame = upperbound(lowerbound(goal, 0), self.movie.nframes-1)
    self.builder.seek(self.current_frame)
    self.playing = False
    self.update()
    return

  def play(self):
    drag = False
    loop = True
    ticks0 = 0
    self.current_frame = 0
    self.builder.start()
    while loop:
      if self.playing:
        events = pygame.event.get()
      else:
        events = [pygame.event.wait()]
      for e in events:
        if e.type in (pygame.MOUSEBUTTONDOWN, pygame.MOUSEMOTION):
          (x,y) = e.pos
          if (e.type == pygame.MOUSEBUTTONDOWN and y < self.panel_y0):
            # the screen clicked
            self.toggle_playing()
          elif (self.panel_y0 < y and (e.type == pygame.MOUSEBUTTONDOWN or drag)):
            # slide bar dragging
            drag = True
            (x,y) = e.pos
            self.seek((x-self.panel_x2)*self.movie.nframes/self.panel_w)
        elif e.type == pygame.MOUSEBUTTONUP:
          drag = False
        elif e.type == pygame.KEYDOWN:
          if e.key in (13, 32): # space or enter
            self.toggle_playing()
          elif e.key in (113, 27): # 'q'uit, esc
            loop = False
          elif e.key == 275: # right
            self.current_frame += 1
            self.seek(self.current_frame)
          elif e.key == 276: # left
            self.current_frame -= 1
            self.seek(self.current_frame)
          else:
            print >>stderr, 'Unknown key:', e
        elif e.type == pygame.QUIT:
          # window close attmpt
          loop = False
      if self.playing:
        self.builder.seek(self.current_frame)
        if self.movie.nframes-1 <= self.current_frame:
          # reach the end.
          self.playing = False
        else:
          self.current_frame += 1
          ticks1 = pygame.time.get_ticks()
          d = lowerbound(int(1000.0/self.info.framerate), ticks0-ticks1)
          ticks0 = ticks1
          pygame.time.wait(d)
        self.update()
      # loop end
    self.builder.finish()
    return
  

# play
def play(fnames, framerate=12):
  info = SWFInfo()
  info.framerate = framerate
  movie = MovieContainer(info)
  for fname in fnames:
    print 'Reading:', fname
    if fname.endswith('.swf'):
      # vnc2swf file
      movie.parse_vnc2swf(fname)
    elif fname.endswith('.vnc'):
      # vncrec file
      movie.parse_vncrec(fname)
  player = PygameMoviePlayer(movie)
  player.play()
  return

#
if __name__ == "__main__":
  play(sys.argv[1:])
