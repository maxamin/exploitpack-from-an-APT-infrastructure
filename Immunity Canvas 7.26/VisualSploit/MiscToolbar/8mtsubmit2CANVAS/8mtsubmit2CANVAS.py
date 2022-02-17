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


class Toolobject(VisualToolbar):
  NAME = "submit2CANVAS"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "submit.ico"
  button_label = "Submit to CANVAS"
  button_tooltip = "Submit your exploit to CANVAS World Service"
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20


  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
  
  def Help(self):
    return "Submits your exploit to the CANVAS WORLD SERVICE [currently disabled]"
        
