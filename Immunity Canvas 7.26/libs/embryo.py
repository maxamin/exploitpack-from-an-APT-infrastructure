#!/usr/bin/env python
# ----------------------------------------------------------------------------
# embryo
# Copyright (c) 2007 Alex Holkner
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#  * Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
#  * Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in
#    the documentation and/or other materials provided with the
#    distribution.
#  * Neither the name of embryo nor the names of its
#    contributors may be used to endorse or promote products
#    derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# ----------------------------------------------------------------------------

'''Minimal GUI tools for user feedback.

This module provides a small number of GUI functions for Windows, Linux and
Mac OS X -- just enough to warn the user that they don't have the full GUI
toolkit required installed.

To display a message box, with an optional cancel button::

    import embryo
    result = embryo.message_box('The message', 'Message title',
        cancel_button=False)

The result is True if the OK button was pressed, otherwise False.  To open a
web page in the user's default web browser::

    embryo.open_url('http://code.google.com/p/pyembryo')

There are also some convenience functions for checking for common packages::

    result = embryo.check_pyglet(version='1.0alpha2')
    result = embryo.check_pygame(version='1.7')
    result = embryo.check_pyopengl(version='2.0')
    result = embryo.check_numeric(version='24.2')
    result = embryo.check_numpy(version='1.0')

The version attribute is optional, if omitted, any version is acceptable.  The
result is True if the package is installed (in which case no feedback to the
user is given), or False if not (in which case the user was directed to the
project's home page).
'''

__docformat__ = 'restructuredtext'
__version__ = '$Id$'

try:
    # If ctypes is not present, DefaultEmbryo will be used
    import ctypes
except:
    pass

import os
import re
import subprocess
import sys
import platform

if platform.system() == "Darwin":
    import objc
    from AppKit import *
    from Foundation import *

class DefaultEmbryo(object):
    def message_box(self, text, title, cancel_button):
        import textwrap
        print '\n'.join(textwrap.wrap('%s: %s' % (title, text)))
        if cancel_button:
            print
            print 'Press Enter to continue, or Ctrl+C to cancel.',
            try:
                raw_input()
                return True
            except KeyboardInterrupt:
                print
                return False

    def open_url(self, url):
        pass

class CarbonEmbryo(DefaultEmbryo):
    kCFStringEncodingUTF8 = 0x08000100

    kAlertStopAlert = 0
    kAlertNoteAlert = 1
    kAlertCautionAlert = 2
    kAlertPlainAlert = 3

    def __init__(self):
        self._carbon = self._load_framework('Carbon')

    def _load_framework(self, name):
        from ctypes.util import find_library
        path = find_library(name)
        return ctypes.cdll.LoadLibrary(path)

    def _cfstring(self, text):
        return self._carbon.CFStringCreateWithCString(None,
            text.encode('utf8'), self.kCFStringEncodingUTF8)

    def _pascalstring(self, text):
        import struct
        return struct.pack('256p', text)

    def message_box(self, text, title, cancel_button):
        class AlertStdAlertParamRec(ctypes.Structure):
            _pack_ = 1
            _fields_ = [
                ('movable', ctypes.c_char),
                ('helpButton', ctypes.c_char),
                ('filterProc', ctypes.c_void_p),
                ('defaultText', ctypes.c_int32),
                ('cancelText', ctypes.c_int32),
                ('otherText', ctypes.c_int32),
                ('defaultButton', ctypes.c_int16),
                ('cancelButton', ctypes.c_int16),
                ('position', ctypes.c_uint16)
            ]
        hit = ctypes.c_int16()
        params = AlertStdAlertParamRec()
        params.defaultText = -1
        if cancel_button:
            params.cancelText = -1
            params.cancelButton = 2
        params.defaultButton = 1
        self._carbon.StandardAlert(self.kAlertPlainAlert,
            self._pascalstring(title), self._pascalstring(text),
            ctypes.byref(params), ctypes.byref(hit))
        return hit.value == 1

    def open_url(self, url):
        urlstr = self._cfstring(url)
        urlref = self._carbon.CFURLCreateWithString(None, urlstr, None)
        self._carbon.LSOpenCFURLRef(urlref, None)
        self._carbon.CFRelease(urlref)
        self._carbon.CFRelease(urlstr)

#
# Carbon API has been deprecated in 10.8
# We just provide here a quick workaround for a native message box using Cocoa
#
class CocoaEmbryo(DefaultEmbryo):

    def message_box(self, text, title, cancel_button):
        alert = NSAlert.alloc().init()
        alert.setMessageText_(title)
        alert.setInformativeText_(text)
        alert.setAlertStyle_(NSInformationalAlertStyle)
        alert.addButtonWithTitle_("Ok")
        alert.addButtonWithTitle_("Cancel")
        NSApp.activateIgnoringOtherApps_(True)
        pressed = alert.runModal()

        return pressed == 1000

    def open_url(url):
        nurl = NSURL.URLWithString(url)
        NSWorkspace.defaultWorkspace().openURL_(nurl)

class GtkEmbryo(DefaultEmbryo):
    GTK_MESSAGE_INFO = 0
    GTK_BUTTONS_OK = 1
    GTK_DIALOG_MODAL = 1
    GTK_BUTTONS_OK_CANCEL = 5
    GTK_MESSAGE_ERROR = 3
    GTK_RESPONSE_OK = -5

    def __init__(self):
        self._gtk = self._load_library('gtk-x11-2.0')

    def _load_library(self, name):
        from ctypes.util import find_library
        path = find_library(name)
        return ctypes.cdll.LoadLibrary(path)

    def message_box(self, message, title, cancel_button):
        argc = ctypes.c_int(0)
        self._gtk.gtk_init(ctypes.byref(argc), None)

        buttons = self.GTK_BUTTONS_OK
        if cancel_button:
            buttons = self.GTK_BUTTONS_OK_CANCEL

        self._gtk.gtk_message_dialog_new.argtypes = [ctypes.c_void_p,
                      ctypes.c_int,
                      ctypes.c_int,
                      ctypes.c_int,
                      ctypes.c_char_p]
        self._gtk.gtk_message_dialog_new.restype = ctypes.c_void_p

        dialog = ctypes.c_void_p(self._gtk.gtk_message_dialog_new(None, self.GTK_DIALOG_MODAL,
            self.GTK_MESSAGE_ERROR, buttons, message))
        self._gtk.gtk_window_set_title(dialog, title)
        response = self._gtk.gtk_dialog_run(dialog)
        self._gtk.gtk_widget_destroy(dialog)

        return response == self.GTK_RESPONSE_OK

    def open_url(self, url):
        browser = os.getenv('BROWSER')
        subprocess.Popen([browser, url])

class Win32Embryo(DefaultEmbryo):
    MB_TASKMODAL = 8192
    MB_ICONEXCLAMATION = 48
    MB_OKCANCEL = 1
    IDOK = 1
    SW_SHOWNORMAL = 1

    def __init__(self):
        self._user32 = self._load_library('user32')
        self._shell32 = self._load_library('shell32')

    def _load_library(self, name):
        from ctypes.util import find_library
        path = find_library(name)
        return ctypes.windll.LoadLibrary(path)

    def message_box(self, message, title, cancel_button):
        flags = self.MB_TASKMODAL | self.MB_ICONEXCLAMATION
        if cancel_button:
            flags |= self.MB_OKCANCEL
        self._user32.MessageBoxW.argtypes = [ctypes.c_int,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint]
        result = self._user32.MessageBoxW(0, message, title, flags)
        return result == self.IDOK

    def open_url(self, url):
        self._shell32.ShellExecuteW.argtypes = [ctypes.c_int,
            ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
            ctypes.c_wchar_p, ctypes.c_int]
        self._shell32.ShellExecuteW(0, u'open', url, None, None,
            self.SW_SHOWNORMAL)

_embryo_class = {
    'darwin': CocoaEmbryo,
    'linux2': GtkEmbryo,
    'linux3' : GtkEmbryo,
    'win32': Win32Embryo,
    'cygwin': Win32Embryo,
}.get(sys.platform, DefaultEmbryo)

_embryo = None
def _get_embryo():
    global _embryo
    if not _embryo:
        try:
            _embryo = _embryo_class()
        except:
            _embryo = DefaultEmbryo()
    return _embryo

def message_box(text, title=None, cancel_button=False):
    '''Display a message box and wait for the user to dismiss it.

    If `cancel_button` is True, the message box will contain an OK and a
    Cancel button.  Otherwise, it will only show an OK button.

    The return value is True if OK was selected, otherwise False if Cancel was
    chosen or the dialog was otherwise closed.
    '''
    if title is None:
        title = sys.argv[0]
    return _get_embryo().message_box(text, title, cancel_button)

# setuptools version parsing
_component_re = re.compile(r'(\d+ | [a-z]+ | \.| -)', re.VERBOSE)
_replace = {'pre':'c', 'preview':'c','-':'final-','rc':'c','dev':'@'}.get

def _parse_version_parts(s):
    for part in _component_re.split(s):
        part = _replace(part,part)
        if not part or part=='.':
            continue
        if part[:1] in '0123456789':
            yield part.zfill(8)    # pad for numeric comparison
        else:
            yield '*'+part

    yield '*final'  # ensure that alpha/beta/candidate are before final

def parse_version(s):
    parts = []
    for part in _parse_version_parts(s.lower()):
        if part.startswith('*'):
            if part<'*final':   # remove '-' before a prerelease tag
                while parts and parts[-1]=='*final-': parts.pop()
            # remove trailing zeros from each series of numeric parts
            while parts and parts[-1]=='00000000':
                parts.pop()
        parts.append(part)
    return tuple(parts)


def open_url(url):
    '''Launch a URL in the user's default web browser.'''
    return _get_embryo().open_url(url)

def _show_package_missing(name, url, version):
    if version is None:
        message = '''
This program requires %(name)s, but this has not been installed.  Press OK
to open the %(name)s home page at %(url)s, or Cancel to quit.
'''.strip().replace('\n', ' ') % \
          dict(name=name, url=url)
    else:
        message = '''
This program requires %(name)s version %(version)s or later, but no version is
currently installed.  Press OK to open the %(name)s home page at %(url)s, or
Cancel to quit.'''.strip().replace('\n', ' ') % \
          dict(name=name, url=url, version=version)

    if message_box(message, 'This program requires %s' % name, True):
        open_url(url)

def _show_package_version(name, url, version, found):
    message = '''
This program requires %(name)s version %(version)s or later, but you currently
have version %(found)s installed.  Press OK to open the %(name)s home page at
%(url)s, or Cancel to quit.'''.strip().replace('\n', ' ') % \
        dict(name=name, url=url, version=version, found=found)

    if message_box(message, 'This program requires %s %s' % (name, version),
            cancel_button=True):
        open_url(url)

def check_package(package, version_func, requested_version, name, url):
    '''Check that a requested package is installed.

    If the requested version (or later) is not found, a message is displayed
    to the user directing them to the package home page.

    :Parameters:
        `package` : str
            Name of the package to attempt to import
        `version_func` : lambda(module) returning str
            Function that, given imported module, returns package version as a
            string.
        `requested_version` : str
            Minimum version required, or None
        `name` : str
            Name of the package as displayed to the user
        `url` : str
            Package home page

    :rtype: bool
    :return: True if the requested version is installed, otherwise False.
    '''
    try:
        module = __import__(package)
        if requested_version is not None:
            found = version_func(module)
            if parse_version(found) < parse_version(requested_version):
                _show_package_version(name, url, requested_version, found)
                return False
    except ImportError:
        _show_package_missing(name, url, requested_version)
        return False
    return True

def check_pyglet(version=None):
    '''Check that pyglet is installed, optionally with a version check.
    '''
    return check_package('pyglet', lambda pyglet: pyglet.version, version,
        'pyglet', 'http://www.pyglet.org')

def check_pygame(version=None):
    '''Check that PyGame is installed, optionally with a version check.
    '''
    def _ver(module):
        import pygame.version
        return pygame.version.ver
    return check_package('pygame', _ver, version,
        'PyGame', 'http://www.pygame.org')

def check_pyopengl(version=None):
    '''Check that PyOpenGL is installed, optionally with a version check.
    '''
    return check_package('OpenGL', lambda OpenGL: OpenGL.__version__, version,
        'PyOpenGL', 'http://pyopengl.sourceforge.net/')

def check_numeric(version=None):
    '''Check that Numeric is installed, optionally with a version check.
    '''
    return check_package('Numeric', lambda Numeric: Numeric.__version__,
        version, 'Numeric', 'http://numpy.scipy.org/')

def check_numpy(version=None):
    '''Check that NumPy is installed, optionally with a version check.
    '''
    return check_package('numpy', lambda numpy: numpy.__version__,
        version, 'NumPy', 'http://numpy.scipy.org/')


