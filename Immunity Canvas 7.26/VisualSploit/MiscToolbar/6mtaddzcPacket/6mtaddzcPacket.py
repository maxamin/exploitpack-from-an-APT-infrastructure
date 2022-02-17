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
  NAME = "addzcpacket"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "addzcpacket.ico"
  button_label = "Add cPacket"
  button_tooltip = N_("Add a cPacket")
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20


  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
  
  def Help(self):
    return "addzcpacket: Add a Program Flow to your framework, Adding extra program\n\
flow is disabled in VS version 1.0"
        
