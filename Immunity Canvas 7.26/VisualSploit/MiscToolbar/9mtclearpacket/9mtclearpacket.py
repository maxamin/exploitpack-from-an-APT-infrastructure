#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information


import sys
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar
from gettext import gettext as N_


class Toolobject(VisualToolbar):
  NAME = "clearpacket"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "clearpacket.ico"
  button_label = N_("Clear the exploit packet")
  button_tooltip = N_("Clear the exploit packet")
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20


  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
  
  def Help(self):
    return N_("Removes all buffers from the exploit packet")
        
