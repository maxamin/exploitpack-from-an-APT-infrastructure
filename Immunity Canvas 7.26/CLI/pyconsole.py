#!/usr/bin/env python
#
#   pyconsole.py
#
#   Copyright (C) 2004-2006 by Yevgen Muntyan <muntyan@math.tamu.edu>
#   Portions of code by Geoffrey French.
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU Lesser General Public version 2.1 as
#   published by the Free Software Foundation.
#
#   See COPYING file that comes with this distribution for full text
#   of the license.
#

# This module 'runs' python interpreter in a TextView widget.
# The main class is Console, usage is:
# Console(locals=None, banner=None, completer=None, use_rlcompleter=True, start_script='') -
# it creates the widget and 'starts' interactive session; see the end of
# this file. If start_script is not empty, it pastes it as it was entered from keyboard.
#
# Console has "command" signal which is emitted when code is about to
# be executed. You may connect to it using console.connect or console.connect_after
# to get your callback ran before or after the code is executed.
#
# To modify output appearance, set attributes of console.stdout_tag and
# console.stderr_tag.
#
# Console may subclass a type other than gtk.TextView, to allow syntax highlighting and stuff,
# e.g.:
#   console_type = pyconsole.ConsoleType(moo.edit.TextView)
#   console = console_type(use_rlcompleter=False, start_script="import moo\nimport gtk\n")
#
# This widget is not a replacement for real terminal with python running
# inside: GtkTextView is not a terminal.
# The use case is: you have a python program, you create this widget,
# and inspect your program interiors.

# this was modified to use our internal immterm widget ...

import gtk
import gtk.gdk as gdk
import gobject
import pango
import gtk.keysyms as _keys
import code
import sys
import keyword
import re
import time
import gui.immterm

from threading import Lock


_STDOUT = sys.stdout
_STDERR = sys.stderr

# commonprefix() from posixpath
def _commonprefix(m):
    "Given a list of pathnames, returns the longest common leading component"
    if not m: return ''
    prefix = m[0]
    for item in m:
        for i in range(len(prefix)):
            if prefix[:i+1] != item[:i+1]:
                prefix = prefix[:i]
                if i == 0:
                    return ''
                break
    return prefix

class _ReadLine(object):

    class Output(object):
        def __init__(self, console, tag_name):
            object.__init__(self)
            self.tag_name = tag_name
            self.console = console

        def write(self, text):
            #_STDOUT.write('*** write to %s -- %s\n' % (self.tag_name, text))
            if text:
                self.console.line_output(text)
            return len(text)

        def flush(self):
            #_STDOUT.write('*** flush called ***')
            while gtk.events_pending():
                gtk.main_iteration(False)
            return

    class History(object):
        def __init__(self):
            object.__init__(self)
            self.items = ['<<<ENDOFHIST>>>', '']
            self.ptr = 0

        def commit(self, text):
            if text:
                self.items.append(text)
            self.ptr = 0

        def raw_get(self, index):
            line = ''
            try:
                if self.ptr + index: # skip the 0 index for both directions ...
                    line = self.items[self.ptr + index]
            except:
                return self.items[0] # end of hist
            self.ptr += index
            return line

    def __init__(self):
        object.__init__(self)

        self._stdout = _ReadLine.Output(self, "stdout")
        self._stderr = _ReadLine.Output(self, "stderr")

        self.ps = ''
        self.in_raw_input = False
        self.run_on_raw_input = None
        self.tab_pressed = 0
        self.history = _ReadLine.History()
        self.nonword_re = re.compile("[^\w\._]")

        # for special interaction
        self.interactbuf = []
        self.interactmode = False
        self.did_raw_input = False

        self.connect_event('newline-input-event', self.newline_input_event)

    def newline_input_event(self, term, line):
        self.history.commit(line)
        if self.interactmode == True:
            self.interactbuf.append(line)
        else:
            self.do_raw_input(line)

    def raw_input(self, ps=None):
        #print '*** raw_input called (ps: %s, %s)' % (repr(ps), hasattr(self, 'line_output'))
        if ps:
            self.line_output(ps)
        return

    def do_raw_input(self, text):
        print '*** do_raw_input override me ***'
        pass

    def fileno(self):
        return 0

    def readline(self):
        line = ''
        if len(self.interactbuf):
            self.interactbuf.reverse()
            line = self.interactbuf.pop()
            self.interactbuf.reverse()
        return line

    def isactive(self):
        while gtk.events_pending():
            gtk.main_iteration(False)
        if len(self.interactbuf):
            return True
        else:
            return False

import cli

BANNER = ''
BANNER += ' _____ _____ _____ _____ _____ _____ \n'
BANNER += '|     |  _  |   | |  |  |  _  |   __|\n'
BANNER += '|   --|     | | | |  |  |     |__   |\n'
BANNER += '|_____|__|__|_|___|\___/|__|__|_____|\n'
BANNER += '         *** XMLRPC cmdline v0.1 *** \n'

# this class was modded for CANVAS Interpreter Specifics
class _Console(_ReadLine, cli.CommandLineInterface):
    def __init__(self, locals=None, banner=None,
                 completer=None, use_rlcompleter=True,
                 start_script=None, engine=None):

        cli.CommandLineInterface.__init__(self)
        _ReadLine.__init__(self)
        self.fromgui = True

        self.locals["__console__"] = self
        if engine:
            self.locals['__engine__'] = engine

        self.start_script = start_script
        self.completer = completer
        if not banner:
            self.banner = BANNER
        else:
            self.banner = banner
        self.saved_stdout = None
        self.saved_stderr = None
        self.saved_stdin  = None

        if not self.completer and use_rlcompleter:
            try:
                import rlcompleter
                self.completer = rlcompleter.Completer()
            except ImportError:
                pass

        if self.python == False:
            self.ps1 = "<<<CANVAS>>> "
        else:
            self.ps1 = ">>> "
        self.cmd_buffer = ''

        self.ps2 = "... "
        self.active_prompt = self.ps1
        self.run_on_raw_input = start_script

    def do_raw_input(self, text):
        #print '*** do_raw_input(%s) ***' % text

        if self.cmd_buffer:
            cmd = self.cmd_buffer + "\n" + text
        else:
            cmd = text

        self.saved_stdout, self.saved_stderr = sys.stdout, sys.stderr

        sys.stdout, sys.stderr = self._stdout, self._stderr

        self.active_prompt = self.ps1
        cmd = self.filter_line(cmd)

        # this is normal interactive mode
        if self.python == True:
            self.ps1 = ">>> "
            if cmd and self.runsource(cmd):
                self.cmd_buffer = cmd
                self.active_prompt = self.ps2
            else:
                self.cmd_buffer = ''
                self.active_prompt = self.ps1
        else:
            self.ps1 = "<<<CANVAS>>> "
            if cmd and self.runscript(cmd):
                self.cmd_buffer = cmd
                self.active_prompt = self.ps2
            else:
                self.cmd_buffer = ''
                self.active_prompt = self.ps1

        sys.stdout, sys.stderr = self.saved_stdout, self.saved_stderr

        self.raw_input(self.active_prompt)

    def do_command(self, code):
        try:
            eval(code, self.locals)
        except SystemExit:
            raise
        except:
            self.showtraceback()

    def runcode(self, code):
        self.do_command(code)

    def exec_command(self, command):
        print '*** exec_command(%s) called ***'
        return

    def complete_attr(self, start, end):
        try:
            obj = eval(start, self.locals)
            strings = dir(obj)

            if end:
                completions = {}
                for s in strings:
                    if s.startswith(end):
                        completions[s] = None
                completions = completions.keys()
            else:
                completions = strings

            completions.sort()
            return [start + "." + s for s in completions]
        except:
            return None

    def complete(self, text):
        if self.python == False:
            # the canvas shell command list ...
            # a simplified completer for our simple shell
            commands = ['load',
                        'suicide',
                        'help',
                        'unload',
                        'flushlog',
                        'interfaces',
                        'list',
                        'pyshell',
                        'interact',
                        'listeners',
                        'runmodule',
                        'bind',
                        'close',
                        'nodes',
                        'listenernodes',
                        'types']
            commands.sort()
            completions = []
            for word in commands:
                if text == word[:len(text)]:
                    completions.append(word)
            return completions
        elif self.completer:
            completions = []
            i = 0
            try:
                while 1:
                    s = self.completer.complete(text, i)
                    if s:
                        completions.append(s)
                        i = i + 1
                    else:
                        completions.sort()
                        return completions
            except NameError:
                return None

        dot = text.rfind(".")
        if dot >= 0:
            return self.complete_attr(text[:dot], text[dot+1:])

        completions = {}
        strings = keyword.kwlist

        if self.locals:
            strings.extend(self.locals.keys())

        try: strings.extend(eval("globals()", self.locals).keys())
        except: pass

        try:
            exec "import __builtin__" in self.locals
            strings.extend(eval("dir(__builtin__)", self.locals))
        except:
            pass

        for s in strings:
            if s.startswith(text):
                completions[s] = None
        completions = completions.keys()
        completions.sort()
        return completions


def ReadLineType(t=gui.immterm.ImmTerm):
    class readline(t, _ReadLine):
        def __init__(self, *args, **kwargs):
            t.__init__(self)
            _ReadLine.__init__(self, *args, **kwargs)

    gobject.type_register(readline)
    return readline

def ConsoleType(t=gui.immterm.ImmTerm):
    class console_type(t, _Console):
        __gsignals__ = {
            'command' : (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, (object,))
          }

        def __init__(self, *args, **kwargs):
            if gtk.pygtk_version[1] < 8:
                gobject.GObject.__init__(self)
            else:
                # print '*** initing widget ****'
                t.__init__(self)
            _Console.__init__(self, *args, **kwargs)

        def do_realize(self):
            gui.immterm.ImmTerm.do_realize(self)
            self.raw_input(self.active_prompt)

        def key_press_event(self, widget, event):
            #_STDERR.write('*** key_press_event (History: %s) ***\n' % hasattr(self, 'history'))
            # override key up and key down ...
            tab_pressed = self.tab_pressed
            self.tab_pressed = 0
            hist_direction = { gtk.keysyms.Up : -1, gtk.keysyms.Down : 1 }
            if event.keyval in hist_direction:
                if hasattr(self, 'history') == True and self.interactmode == False:
                    line = self.history.raw_get(hist_direction[event.keyval])
                    if line != '<<<ENDOFHIST>>>':
                        self.line_output('\r' + self.active_prompt + line)
                        self.input_buffer = line
                        self.input_pos = len(self.input_buffer)
                return True
            elif event.keyval == gtk.keysyms.Tab:
                #print '*** TAB pressed (%s) ***' % self.input_buffer
                self.tab_pressed = tab_pressed + 1
                start = ''
                word = self.input_buffer
                nonwords = re.compile("[^\w\._]").findall(self.input_buffer)
                #print '*** nonwords: ' + repr(nonwords)
                if nonwords:
                    last = self.input_buffer.rfind(nonwords[-1]) + len(nonwords[-1])
                    start = self.input_buffer[:last]
                    word = self.input_buffer[last:]
                completions = self.complete(word)
                #print '*** completions: ' + repr(completions)
                if completions:
                    prefix = _commonprefix(completions)
                    if prefix != word:
                        self.input_buffer = start + prefix
                        self.input_pos = len(self.input_buffer)
                        self.line_output('\r' + self.active_prompt + start + prefix)
                    elif self.tab_pressed > 1 and completions:
                        #print '*** tab_pressed > 1, print all completions ***'
                        # XXX: this needs proper alignment ..
                        self.tab_pressed = 0
                        self.input_buffer = ''
                        self.input_pos = 0
                        self.line_output('\n' + '    '.join(completions) + '\n')
                        self.line_output(self.active_prompt)
                return True
            else:
                return gui.immterm.ImmTerm.key_press_event(self, widget, event)

        def do_command(self, code):
            return _Console.do_command(self, code)

    if gtk.pygtk_version[1] < 8:
        gobject.type_register(console_type)

    return console_type

ReadLine = ReadLineType()
Console = ConsoleType()

def _create_widget(start_script, engine=None):
    try:
        console_type = ConsoleType() # defaults to ImmTerm
        console = console_type(banner='',
                               use_rlcompleter=False,
                               start_script=start_script,
                               engine=engine)
    except ImportError:
        console = Console(banner='',
                          use_rlcompleter=False,
                          start_script=start_script)
    return console

def _make_window(start_script="from gtk import *\n"):
    window = gtk.Window()
    window.set_title("pyconsole.py")
    swin = gtk.ScrolledWindow()
    swin.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_ALWAYS)
    window.add(swin)
    console = _create_widget(start_script)
    swin.add(console)
    window.set_default_size(500, 400)
    window.show_all()

    if not gtk.main_level():
        window.connect("destroy", gtk.main_quit)
        gtk.main()

    return console

if __name__ == '__main__':
    import sys
    import os
    sys.path.insert(0, os.getcwd())
    _make_window(sys.argv[1:] and '\n'.join(sys.argv[1:]) + '\n' or None)
