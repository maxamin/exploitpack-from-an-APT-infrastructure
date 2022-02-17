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
  NAME = "calculator"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "calculator.ico"
  button_label = N_("Calculator")
  button_tooltip = N_("Show a useful calculator")
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20


  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
  
  def Help(self):
    return N_("Shows a useful calculator")
        
