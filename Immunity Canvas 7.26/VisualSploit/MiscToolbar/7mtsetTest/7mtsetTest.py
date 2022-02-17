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
  NAME = "setTest"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "setTest.ico"
  button_label = "setTest"
  button_tooltip = "Set Test String for test()"
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20
  setflag=0
  deftest=False


  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
  
  def Help(self):
    return "Add a test routine for your exploit."
        
  def setArg(self,args):
    self.setflag=1
    if args.has_key('teststring'):
      self.teststring= args['teststring']
    else:
      self.teststring=""
    if args.has_key('checkbutton1'):
      self.deftest=args['checkbutton1']
    else:
      self.deftest=False
    print "deftest %s" %self.deftest
  
  def setDialog(self,dialog,args):
    if self.setflag == 1:
      teststring=dialog.get_widget('teststring')
      teststring.set_text(self.teststring)
      deftest=dialog.get_widget('checkbutton1')
      if self.deftest==True:
        deftest.set_active(True)
      else:
        deftest.set_active(False)
    else:
      teststring=dialog.get_widget('teststring')
      teststring.set_text(args['teststring'])
      deftest=dialog.get_widget('checkbutton1')
      if self.deftest==True:
        deftest.set_active(True)
      else:
        deftest.set_active(False)
  
  def Show(self):
    pass

    
      
  def preparedialog(self,widget,platlist,xpacket):
    pass
  
  def createPython(self):
    return  ""