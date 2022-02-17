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
  NAME = "plFailed"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "plFailed.ico"
  button_label = "Add FAILED"
  button_tooltip = "Add FAILED"
  button_private_tooltip = "Private"
  button_signal = None
  color = "red"
  objectcomments = None
  size = 20
  fdlist=[]
  buf=[]
  NumberofXp =1
  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('printmsg'):
      self.printmsg = args['printmsg']
    
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
    printmsg=dialog.get_widget('printmsg')
    printmsg.set_text(str(self.printmsg))
    
    
  def Show(self):
    return 'FAILED "%s"' %self.printmsg
  
  def Help(self):
    return "The failed object allows you to add error messages to IF/ELSE logic.\n\
\n\
e.g.\n\
\n\
1. IF data contains \"250\" send data ELSE FAILED \"error\\n\""
  
  def preparedialog(self,arga,argb):
    pass
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    if paddingfromrow > 0:
      self.buf.append(padding+'self.log("%s")' % self.printmsg)
      self.buf.append(padding+'self.setInfo("%s attacking %s:%d (failed!)"%(self.name,self.host,self.port), showlog=True)')
      self.buf.append(padding+'return 0\n')
    else:
      self.buf.append(padding+'self.log("%s")' % self.printmsg)
      self.buf.append(padding+'self.setInfo("%s attacking %s:%d (failed!)"%(self.name,self.host,self.port), showlog=True)')
      self.buf.append(padding+'return 0\n')
    return  self.buf

  
  def save(self):
    savedic={}
    savedic['printmsg']=self.printmsg
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('printmsg'):
      self.printmsg = args['printmsg']
      
  
  
  
    
