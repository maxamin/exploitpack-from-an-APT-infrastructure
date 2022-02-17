#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunitysec.com/CANVAS/ for more information


import sys
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar


class Toolobject(VisualToolbar):
  NAME = "open"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "open.ico"
  button_label = "Add Open()"
  button_tooltip = "Add Open(filename) to Program Flow"
  button_private_tooltip = "Private"
  button_signal = None
  color = "red"
  size = 20
  objectcomments = None
  fdlist=[]
  buf=[]
  NumberofXp =1

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    self.fopen = args['fopen']
    try:
      self.cfd = args['fdlist']
    except:
      pass
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
    
    fopen=dialog.get_widget('fopen')
    fopen.set_text(self.fopen)

    #self.cfd = fd
    
    
  def Show(self):
    return "create(%s)" % self.fopen

  def Help(self):
    return "The create object is used for client-side exploit development. It opens\n\
a file and allows you to write and read data into it.\n\
\n\
e.g.\n\
\n\
1. Filename: exploit.xxx will create a file named exploit.xxx in the current directory"

  
  def preparedialog(self,arga,argb,argc):
    pass
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    #print "MY OBJECT PADDING %s" %padding
    if paddingfromrow > 0:
      self.buf.append(padding+'FD_%s = open("%s","w")' % (self.cfd,self.fopen))
      self.buf.append(padding+'self.log("%s Created!")' % self.fopen)
    else:
      self.buf.append('FD_%s = open("%s","w")' % (self.cfd,self.fopen))
      self.buf.append('self.log("%s Created!")' % self.fopen)
    return  self.buf

  
  def save(self):
    savedic={}
    savedic['fopen']=self.fopen
    savedic['cfd']=self.cfd
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('fopen'):
      self.fopen = args['fopen']
     
    if args.has_key('cfd'):
      self.cfd = args['cfd']
  
  def getHost(self):
    return self.fopen
  
