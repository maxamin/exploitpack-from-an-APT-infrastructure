#!/usr/env/bin python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2009
#

import os, getopt, sys
import pygtk, gobject
from threading import Lock

pygtk.require("2.0")
import gtk
import gtk.glade

import gui.pyconsole

class d2sec_masspwngui:
  def delete_event(self, widget, event, data=None):
    gtk.main_quit()
    return False  
  
  def __init__(self):
    self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
    self.window.set_title("D2SEC MASS PWN GUI")
    self.window.connect("delete_event", self.delete_event)
    self.window.set_border_width(1)
    self.window.set_icon_from_file("gui/d2.ico")
    self.window.set_size_request(800, 500)

    box = gtk.VBox(False, 0)
    self.window.add(box)
    box.show()
    
    console = gui.pyconsole._create_widget('')
    box.pack_start(console, True, True, 0)
    console.show()

    separator = gtk.HSeparator()
    box.pack_start(separator, False, True, 0)
    separator.show()

    button = gtk.Button("Quit", )
    button.connect("clicked", lambda w: gtk.main_quit())

    box.pack_start(button, False, False, 0)
    button.show()

    self.window.set_position(gtk.WIN_POS_CENTER_ALWAYS)
    self.window.show_all()

  def main(self):
    gtk.main()

if __name__ == "__main__":
  gui = d2sec_masspwngui()
  gui.main()
