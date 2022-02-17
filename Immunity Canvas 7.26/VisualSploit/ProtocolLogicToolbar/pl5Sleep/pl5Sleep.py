#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information


import sys
import gtk
import string
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar


class Toolobject(VisualToolbar):
  NAME = "plSleep"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "plSleep.ico"
  button_label = "Add sleep"
  button_tooltip = "Add sleep"
  button_private_tooltip = "Private"
  button_signal = None
  color = "red"
  size = 20
  fdlist=[]
  objectcomments = None
  buf=[]
  boxargs={}
  object=None
  NumberofXp =1
  objectlist=[]
  sleepseconds=""

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('sleepseconds'):
      self.sleepseconds = args['sleepseconds']
    
    
    
  
  def setDialog(self,widget,cpacket,badchars,fdlist,xpacketlist):
    sleepseconds=widget.get_widget('sleepseconds')
    sleepseconds.set_text(str(self.sleepseconds))
    
  
  def preparedialog(self,widget,cpacket):
    sleepseconds=widget.get_widget('sleepseconds')
    sleepseconds.set_text(str(self.sleepseconds))
    
  
  def Show(self):
    return "sleep(%s)" % self.sleepseconds
  
  def Help(self):
    return "The sleep object will pause the execution flow of your exploit for n seconds.\n\
You can use this object for situations where you need to a specific timing for your exploit to succeed.\n\
\n\
e.g.\n\
\n\
1. connect localhost:25\n\
2. send \"HELO localhost\\n\"\n\
3. sleep 5\n\
4. recv data"
  

  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    if paddingfromrow > 0: 
      self.buf.append(padding+"time.sleep(%s)\n" % self.sleepseconds)
    else:
      self.buf.append("time.sleep(%s)\n" % self.sleepseconds)
      
    return  self.buf

  
  def save(self):
    savedic={}
    savedic['sleepseconds']=self.sleepseconds
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('sleepseconds'):
      self.sleepseconds = args['sleepseconds']
      
    
  
