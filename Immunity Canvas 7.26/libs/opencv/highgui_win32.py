#!/usr/bin/env python
# highgui_win32
# Copyright (c) 2009, David Bolen
# All rights reserved.

"""
highgui_win32

UI background window thread implementation for Windows, since OpenCV doesn't
support it natively.  Wraps (and is safe for import * from) the following
OpenCV functions:

    cvStartWindowThread
    cvNamedWindow
    cvDestroyWindow
    cvDestroyAllWindows
    cvShowImage
    cvSetMouseCallback
    cvCreateTrackbar
    cvWaitKey

If cvStartWindowThread is not called, the other functions are just pass
through to their normal wrappers in the opencv.highgui module.  However,
once cvStartWindowThread is called, those functions execute calls to the
equivalent opencv.highgui methods from within a background thread, and that
thread maintains an event loop, calling cvWaitKey periodically.

By default, calls are synchronized with the window thread, so for example
a foreground call to cvShowImage won't return until the window thread has
called the actual cvShowImage method.

There is latency added by the synchronization due to the round trip thread
context switching.  Callers requiring the least impact to the foreground
thread can set the optional cvStartWindowThread 'synchronized' parameter to
False, but should appreciate that access to function parameters by the
window thread may be delayed.  For example, the foreground should not
immediately manipulate an image used as a parameter to cvShowImage.  Memory
usage may also be slightly higher if many commands by the foreground thread
are enqueued before being executed by the window thread.
"""

import sys
import time
import traceback
from threading import Thread
from Queue import Queue, Empty
from ctypes import windll
from functools import wraps
import highgui as hg

#
# --------------------------------------------------------------------------
#

def threadmethod(func):
    """Wraps a method so that it is executed within the image thread"""

    @wraps(func)
    def execute(self, *args, **kwargs):
        self.cmds.put((func, (self,)+args, kwargs))
        if self.synchronized:
            return self.result.get()
    return execute


class ImageThread(Thread):

    def __init__(self, synchronized=True):
        Thread.__init__(self)
        self.cmds = Queue()   # Requests functions to run in image thread
        self.result = Queue() # Result from functions called
        self.keys = Queue()   # Holds recent keys from image thread for WaitKey
        self.synchronized = synchronized
        self.stopping = False
        self._have_windows = False  # True if some windows have been created

    def run(self):
        while 1:
            if self.stopping:
                hg.cvDestroyAllWindows()
                return

            try:

                # Check for a new command request
                try:
                    (self.func,
                     self.args,
                     self.kwargs) = self.cmds.get_nowait()
                except Empty:
                    self.func = None

                # Execute function if requested
                if self.func:
                    try:
                        rc = self.func(*self.args, **self.kwargs)
                    except Exception, e:
                        rc = None
                        sys.stderr.write('ImageThread exception - ignoring:')
                        traceback.print_exc()
                    if self.synchronized:
                        self.result.put(rc)

                # Service the OpenCV event loop - buffer recent keys for
                # possible use by the foreground thread, but bound it to a
                # a small number in case WaitKey isn't called by the thread.
                #
                # Note: This is very CPU-inefficient if we haven't created
                # a window, so only bother if we've seen one created
                if self._have_windows:
                    rc = hg.cvWaitKey(5)
                    if rc >= 0:
                        if self.keys.qsize() >= 10:
                            self.keys.get()
                        self.keys.put(rc)
                else:
                    # Yield CPU to prevent CPU burn
                    time.sleep(0.01)

            except:
                sys.stderr.write('ImageThread exception - shutting down:')
                traceback.print_exc()

    def join(self, *args, **kwargs):
        # Given we never exit, assume that someone waiting for us to complete
        # is actually an indication that we should shut down
        self.stopping = True
        return Thread.join(self, *args, **kwargs)

    def _ensurewindow(self, name, foreground=False):
        if not (self.stopping or hg.cvGetWindowHandle(name)):
            # First image, or window closed manually - open window
            hg.cvNamedWindow(name)
            # Bring to front same as if the foreground thread had created it
            if foreground:
                windll.user32.SetForegroundWindow(hg.cvGetWindowHandle(name)) 
            self._have_windows = True
       

    #
    # HighGUI methods (run in image thread)
    #

    @threadmethod
    def NamedWindow(self, name, foreground=True):
        self._ensurewindow(name, foreground)

    @threadmethod
    def DestroyWindow(self, name):
        hg.cvDestroyWindow(name)

    @threadmethod
    def DestroyAllWindows(self):
        hg.cvDestroyAllWindows()

    @threadmethod
    def ShowImage(self, name, image):
        hg.cvShowImage(name, image)

    @threadmethod
    def SetMouseCallback(self, name, callback, param=None):
        hg.cvSetMouseCallback(name, callback, param)

    @threadmethod
    def CreateTrackbar(self, tb_name, win_name, value, count, on_change=None):
        return hg.cvCreateTrackbar(tb_name, win_name, value, count, on_change)

    def WaitKey(self, wait=0):
        # Note that this runs in caller's thread
        try:
            result = self.keys.get(timeout=wait/1000.0 if wait > 0 else None)
        except Empty:
            result = -1
            
        return result

    #
    # Convenience methods
    #

    @threadmethod
    def show(self, name, image, callback=None, foreground=True):
        self._ensurewindow(name, foreground)
        hg.cvShowImage(name, image)
        if callback is not None:
            hg.cvSetMouseCallback(name, callback, image)


#
# --------------------------------------------------------------------------

#
# Module global instance of the Image thread and support for creating it
#

_image_thread = None

def cvStartWindowThread(synchronized=True):
    global _image_thread

    if _image_thread is None or not _image_thread.isAlive():
        _image_thread = ImageThread(synchronized)
        _image_thread.start()

    return _image_thread

#
# Wrapper functions using thread if present, falling back to original functions.
#

def if_imagethread(method, original):
    """Run method in image thread if present, otherwise original"""

    def execute(*args, **kwargs):
        if _image_thread:
            func = getattr(_image_thread, method)
        else:
            func = original
        return func(*args, **kwargs)

    # Raw CFUNCTYPE wrappers don't have __name__, so fudge a bit
    setattr(execute, '__name__', (getattr(original, '__name__', None) or
                                  'cv' + method))
    setattr(execute, '__doc__', getattr(original, '__doc__'))
    return execute


cvNamedWindow       = if_imagethread('NamedWindow',       hg.cvNamedWindow)
cvDestroyWindow     = if_imagethread('DestroyWindow',     hg.cvDestroyWindow)
cvDestroyAllWindows = if_imagethread('DestroyAllWindows', hg.cvDestroyWindow)
cvShowImage         = if_imagethread('ShowImage',         hg.cvShowImage)
cvSetMouseCallback  = if_imagethread('SetMouseCallback',  hg.cvSetMouseCallback)
cvCreateTrackbar    = if_imagethread('CreateTrackbar',    hg.cvCreateTrackbar)
cvWaitKey           = if_imagethread('WaitKey',           hg.cvWaitKey)

#
#
# --------------------------------------------------------------------------
#

__all__ = [x for x in locals().keys() if x.startswith('cv')]
