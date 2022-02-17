pyvnc2swf
README
$Id: README.txt,v 1.10 2005/08/23 22:04:37 euske Exp $

by Yusuke Shinyama


This is a preliminary version of pyvnc2swf.
pyvnc2swf is a vnc2swf implementation written in Python.
It should run on Unix/Linux/OSX/Windows.


Prerequisites:
  * Python-2.3 or newer (www.python.org)
  * Pygame-1.6 or newer (www.pygame.org)
  * A VNC server (Xvnc, OSXVnc, WinVNC or x11vnc)

New features:
  * Entirely rewritten from scratch.
  * Multi-platform.
  * Simple GUI with Tk.
  * vncrec format support.


  vnc2swf.py can generate three different types of output:
  SWF(shape), SWF(video) and VNCRec. Both SWF(shape) and
  SWF(video) is Macromedia flash format and therefore directly
  playable from the browser. The difference is that SWF(video) is
  normally smaller than SWF(shape), but generating SWF files
  on-the-fly is slow (generating SWF(video) is even slower).
  Sometimes Python does not catch up with the screen update.
  However this is a matter of convenience in fact, since you can
  always convert a SWF(shape) into SWF(video) file after recording
  using edit.py program.

  Now here comes another output format: VNCRec. This is much faster
  to generate and you still have the same quality.  But it's not
  directly playable from a web browser. So you need to convert a
  VNCRec file (.vnc) into a SWF file using edit.py.

  In short...
    Convenience:  VNCRec     < SWF(shape) < SWF(video)
    Speed:        SWF(video) < SWF(shape) < VNCRec


Recording:

  (from terminal)

    0. Start a VNC server.
    1. Launch vnc2swf.py from the command line.

       $ vnc2swf.py -n -o filename [-t {shape|video|vnc}] [host [port]]
       (Both -n and -o options are REQUIRED. 
        As default, it tries to connect to localhost:5900)

	-o filename: output filename
	-e encodings: preferred VNC encoding (comma-separated, default="5,4,0")
	-S subprocess: command name to run during recording.
	-n: console mode (no GUI)
	-t: output type (either "shape", "video" or "vnc").
	-r framerate: specify the framerate. default=12fps.
	-C geometry: specify the recording area.
	    Geometry should be as form of WxH+X+Y.

    2. You might need to type the password to connect the server.
    3. Press Ctrl-C to stop recording.

  (from GUI)
    0. Start a VNC server.
    1. Launch vnc2swf.py (no argument)
    2. Press "Save as..." button to specify a filename to save.
    3. Select the output type.
    4. Press "Start" button.
    5. You might need to type the password to connect the server.
    6. Press "Stop" button and close.


Editing:

  $ edit.py -o outfile.swf infile.swf

    Combine one or more .vnc or .swf file(s) into a SWF file.
    Options are similar to those of edit_vnc2swf.
    
     -c: generate a compressed movie.
     -V: use video mode (supported by Flash Player ver.7 or above)
     -f frames: select frames to output.
     -F frames: select frames to output without seeking audio.
     -a mp3file: attach mp3 files.
        (NOTE: do not use "variable bitrate" (VBR) mp3 files,
               as the Flash player doesn't support them!)
     -r framerate: specify the framerate.
     -s scaling: specify the scaling ratio with a fraction.
     -C geometry: clip the movie. Geometry should be as form of WxH+X+Y.
     -R framestep: speficy frame resampling.
     -S n: Skip the first n frames of the given mp3 file. 
           This is useful when the recorded audio is a bit off from the movie.
     -B blocksize: Set the blocksize of flash video format. default:32


Playing: (Pygame required)

  $ play.py file1.vnc
     or
  $ play.py file1.swf


BUGs:
 * noises with non-multiple scaling (e.g. 0.7)

TODOs:
 * Documentation.
 * Neat GUI.
 * authoring function.
