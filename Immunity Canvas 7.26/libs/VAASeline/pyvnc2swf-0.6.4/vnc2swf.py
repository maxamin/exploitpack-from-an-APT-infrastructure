#!/usr/bin/env python
##
##  vnc2swf.py
##
## $Id: vnc2swf.py,v 1.9 2005/08/23 22:04:37 euske Exp $

import sys, os, time, socket, re
import Tkinter, tkFileDialog, tkMessageBox
from tkSimpleDialog import Dialog
from struct import pack, unpack

from movie import SWFInfo
from output import SWFShapeStream, SWFVideoStream
from rfb import RFBError, RFBNetworkClient, RFBNetworkClientForRecording, RFBStreamConverter
stderr = sys.stderr


##  tkPasswordDialog
##
class tkPasswordDialog(Dialog):

  def __init__(self, title, prompt, parent=None):
    if not parent:
      parent = Tkinter._default_root
    self.prompt = prompt
    Dialog.__init__(self, parent, title)
    return
  
  def destroy(self):
    self.entry = None
    Dialog.destroy(self)
    return
  
  def body(self, master):
    w = Tkinter.Label(master, text=self.prompt, justify=Tkinter.LEFT)
    w.grid(row=0, padx=5, sticky=Tkinter.W)
    self.entry = Tkinter.Entry(master, name="entry", show="*")
    self.entry.grid(row=1, padx=5, sticky=Tkinter.W+Tkinter.E)
    return self.entry
  
  def validate(self):
    self.result = self.entry.get()
    return 1


##  RFBNetworkClientWithTkMixin
##
class RFBNetworkClientWithTkMixin:

  def tk_init(self, root):
    self.root = root
    self.doloop = True
    return

  def interrupt(self):
    self.doloop = False
    return

  def loop(self):
    self.doloop = True
    self.sock.settimeout(0.1)
    while self.doloop:
      self.root.update()
      try:
        if not self.loop1(): break
      except socket.timeout:
        pass
    self.finish_update()
    return self

  def getpass(self):
    return tkPasswordDialog('Login',
                            'Password for %s:%d' % (self.host, self.port),
                            self.root).result

class RFBNetworkClientWithTk(RFBNetworkClientWithTkMixin, RFBNetworkClient): pass
class RFBNetworkClientForRecordingWithTk(RFBNetworkClientWithTkMixin, RFBNetworkClientForRecording): pass


##  VNC2SWFWithTk
##
class VNC2SWFWithTk:

  TYPES = { 'SWF(Shape)':'shape', 'SWF(Video)':'video', 'VNCRec':'vnc' }

  def __init__(self, info, outtype='shape', host='127.0.0.1', port=5900,
               preferred_encoding=(0,), subprocess=None, debug=0):
    self.info = info
    self.debug = debug
    self.preferred_encoding = preferred_encoding
    self.subprocess = subprocess
    self.client = None
    self.root = Tkinter.Tk()
    self.root.wm_protocol('WM_DELETE_WINDOW', self.quit)
    frame1 = Tkinter.Frame(master=self.root)
    frame2 = Tkinter.Frame(master=self.root)
    self.rfbserver = Tkinter.Entry(master=frame1)
    self.rfbserver.insert(0, '%s:%d' % (host, port))
    self.rfbserver.pack(side=Tkinter.LEFT, expand=1)
    self.toggle = Tkinter.Button(master=frame1, state="disabled")
    self.toggle.pack(side=Tkinter.LEFT, expand=1)
    self.savetype = Tkinter.StringVar()
    revtype = dict([ (v,k) for (k,v) in self.TYPES.iteritems() ])
    self.savetype.set(revtype[outtype])
    self.savemenu = apply(Tkinter.OptionMenu, (frame2, self.savetype,)+tuple(self.TYPES.keys()))
    self.savemenu.pack(side=Tkinter.LEFT, expand=1)
    self.saveas = Tkinter.Button(master=frame2, text='Save As...', command=self.set_filename)
    self.saveas.pack(side=Tkinter.LEFT, expand=1)
    frame1.pack(fill=Tkinter.X)
    frame2.pack(fill=Tkinter.X)
    self.doquit = False
    if self.info.filename:
      self.set_filename(self.info.filename)
    return

  def run(self):
    self.status()
    Tkinter.mainloop()
    return

  def quit(self):
    if self.client:
      self.client.interrupt()
      self.doquit = True
    else:
      self.root.destroy()
    return

  def status(self):
    if not self.info.filename:
      self.root.title('vnc2swf: Select file')
      self.toggle.config(text='Start')
      self.toggle.config(state="disabled")
    elif not self.client:
      self.root.title('vnc2swf: Ready')
      self.toggle.config(text='Start')
      self.toggle.config(state="normal")
      self.toggle.config(background='#80ff80')
      self.toggle.config(activebackground='#00ff00')
      self.toggle.config(command=self.record)
    else:
      self.root.title('vnc2swf: Recording')
      self.toggle.config(text='Stop')
      self.toggle.config(state="normal")
      self.toggle.config(background='#ff8080')
      self.toggle.config(activebackground='#ff0000')
      self.toggle.config(command=self.client.interrupt)
    return
  
  def set_filename(self, filename=None):
    outtype = self.TYPES[self.savetype.get()]
    if outtype in ('shape','video'):
      filename = filename or tkFileDialog.asksaveasfilename(
        master=self.root, title='vnc2swf saveas', defaultextension=".swf",
        filetypes=[("Macromedia Flash Files", "*.swf"), ("All Files", "*")])
      if filename:
        self.info.filename = filename
        self.saveas.config(text=os.path.basename(filename))
    elif outtype == 'vnc':
      filename = filename or tkFileDialog.asksaveasfilename(
        master=self.root, title='vnc2swf saveas', defaultextension=".vnc",
        filetypes=[("VNCRec Files", "*.vnc"), ("All Files", "*")])
      if filename:
        self.info.filename = filename
        self.saveas.config(text=os.path.basename(filename))
    self.status()
    self.root.update()
    return
  
  def record(self):
    s = self.rfbserver.get()
    m = re.match(r'^([^:/]+)(:(\d+))?', s)
    if not m:
      tkMessageBox.showerror('vnc2swf: error', 'Invalid address: %r' % s)
      return
    (host, port) = (m.group(1), int(m.group(3) or '5900'))
    assert self.info.filename
    outtype = self.TYPES[self.savetype.get()]
    if outtype == 'vnc':
      self.client = RFBNetworkClientForRecordingWithTk(host, port, self.info.filename,
                                                       preferred_encoding=self.preferred_encoding)
    else:
      assert outtype in ('shape', 'video')
      if outtype == 'shape':
        stream = SWFShapeStream(self.info)
      else:
        stream = SWFVideoStream(self.info)
      self.client = RFBNetworkClientWithTk(host, port, RFBStreamConverter(self.info, stream),
                                           preferred_encoding=self.preferred_encoding)
    self.client.tk_init(self.root)
    try:
      self.client.init().auth().start()
      if self.debug:
        print 'start recording'
      if self.subprocess:
        self.subprocess.start()
      self.status()
      self.client.loop()
      if self.debug:
        print 'stop recording'
      if self.subprocess:
        self.subprocess.stop()
      if outtype in ('shape', 'video'):
        self.info.generate_html()
    except socket.error, e:
      print >>stderr, e
      tkMessageBox.showerror('vnc2swf: Socket error', str(e))
    except RFBError, e:
      print >>stderr, e
      tkMessageBox.showerror('vnc2swf: RFB protocol error', str(e))
    self.client.close()
    self.client = None
    self.status()
    if self.doquit:
      self.root.destroy()
    return


def vnc2swf(info, outtype='shape', host='127.0.0.1', port=5900,
            preferred_encoding=(0,), subprocess=None, debug=0):
  if outtype in ('shape','video'):
    if outtype == 'shape':
      stream = SWFShapeStream(info)
    else:
      stream = SWFVideoStream(info)
    converter = RFBStreamConverter(info, stream)
    client = RFBNetworkClient(host, port, converter,
                              preferred_encoding=preferred_encoding)
  else:
    client = RFBNetworkClientForRecording(host, port, info.filename,
                                          preferred_encoding=preferred_encoding)
  try:
    client.init().auth().start()
    if debug:
      print 'start recording'
    if subprocess:
      subprocess.start()
    try:
      client.loop()
    except KeyboardInterrupt:
      pass
    if debug:
      print 'stop recording'
    if subprocess:
      subprocess.stop()
    client.close()
    if outtype in ('shape','video'):
      info.generate_html()
  except socket.error, e:
    print >>stderr, 'Socket error:', e
  except RFBError, e:
    print >>stderr, 'RFB error:', e
  return


# Subprocess management
class Subprocess:
  
  def __init__(self, s):
    self.args = s.split(' ')
    self.pid = 0
    return
  
  def start(self):
    self.pid = os.fork()
    if self.pid == 0:
      os.execvp(self.args[0], self.args)
      sys.exit(1)
    return
  
  def stop(self):
    import signal
    os.kill(self.pid, signal.SIGINT)
    os.waitpid(self.pid, 0)
    return


# main
# ./vnc2swf.py -S 'arecord -t wav -c 1 -r 22050 out.wav' -n -o out.swf 
def main(args):
  import getopt
  def usage():
    print ("usage: vnc2swf.py [-d] [-n] [-o filename] [-t {shape|video|vnc}]" \
           " [-e encoding] [-C clipping] [-r framerate] [-S subprocess] [host [port]]")
    sys.exit(2)
  try:
    (opts, args) = getopt.getopt(sys.argv[1:], "dno:t:e:C:r:S:E:")
  except getopt.GetoptError:
    usage()
  (debug, console, outtype, subprocess) = (0, False, None, None)
  (host, port, preferred_encoding) = ('127.0.0.1', 5900, (0,))
  info = SWFInfo()
  for (k, v) in opts:
    if k == "-d": debug = True
    elif k == "-n": console = True
    elif k == "-t": outtype = v
    elif k == '-e': preferred_encoding = tuple([ int(i) for i in v.split(',') ])
    elif k == "-S": subprocess = Subprocess(v)
    elif k == '-o':
      info.filename = v
    elif k == "-C":
      m = re.match(r'^(\d+)x(\d+)\+(\d+)\+(\d+)$', v)
      if not m:
        print >>stderr, 'Invalid clipping specification:', v
        usage()
      x = map(int, m.groups())
      info.clipping = (x[2],x[3], x[0],x[1])
    elif k == "-r":
      info.framerate = int(v)
  if not outtype:
    if info.filename:
      if info.filename.endswith('.vnc'):
        outtype = 'vnc'
      elif info.filename.endswith('.swf'):
        outtype = 'shape'
    else:
      outtype = 'shape'
  if outtype not in ('shape','video','vnc'):
    print 'Please specify the output type or file extension.'
    usage()
  if 1 <= len(args):
    host = args[0]
  if 2 <= len(args):
    port = int(args[1])
  if console:
    if not info.filename:
      print 'Please specify the filename.'
      usage()
    vnc2swf(info, outtype, host, port,
            preferred_encoding=preferred_encoding,
            subprocess=subprocess,
            debug=debug)
  else:
    VNC2SWFWithTk(info, outtype, host, port,
                  preferred_encoding=preferred_encoding,
                  subprocess=subprocess,
                  debug=debug).run()

if __name__ == "__main__": main(sys.argv[1:])
