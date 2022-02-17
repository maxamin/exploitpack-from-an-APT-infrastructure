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
  NAME = "plElse"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "plElse.ico"
  button_label = "Add ELSE"
  button_tooltip = "Add ELSE"
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
    pass
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
    pass
    
    
  def Show(self):
    return "ELSE:"
  
  def Help(self):
    return "The IF/ELSE objects allow you to control the execution flow of your\n\
exploit with basic logical conditioning. There are three basic conditions:\n\
\n\
CONTAINS: check if data contains a substring.\n\
EQUAL: check if data is equal to a string.\n\
NOT EQUAL: check if data is not equal to a string.\n\
\n\
e.g.\n\
\n\
1. connect localhost:25\n\
2. send \"HELO localhost\\n\"\n\
3. recv data\n\
4. IF \"received data\" CONTAINS \"250\"\n\
5. print \"OK!\\n\"\n\
6. else\n\
7. failed \"NOT OK!\\n\""

  
  def preparedialog(self,arga,argb):
    pass
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    if paddingfromrow > 0:
      self.buf.append(padding+'else:')
    else:
      self.buf.append('else:')
    return  self.buf

  
  def save(self):
    savedic={}  
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    
  
  
  
    
