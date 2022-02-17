#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import gtk
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar
from gettext import gettext as N_

PLAINSTRING=N_("Just send a string")

class Toolobject(VisualToolbar):
  NAME = "Free"
  INDEXED = "HEAPEXERCISE"

  GLADE_DIALOG = "dialog.glade2"
  filexpm = "64free.ico"
  button_label = N_("Add Free()")
  button_tooltip = N_("Add Free() to connection packet")
  button_private_tooltip = "Private"
  button_signal = None
  color = "cyan"
  size = 20
  boxargs={}
  xpacket2send=None
  cfd=None
  fdlist=[]
  objectcomments = None
  xpacketlist=[]
  buf=[]
  NumberofXp =1
  sendstring=""
  FREE = 1

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('preparexpacket' ) and args['preparexpacket'] != PLAINSTRING:
      self.xpacket2send = args['preparexpacket']
    
    if args.has_key('preparefd'):
      self.cfd = args['preparefd']
    
    if args.has_key('sendstring'):
      self.sendstring= args['sendstring']
    
    
  def Show(self):
    if self.xpacket2send == None:
      return N_("Free(Nothing to send)")
    else:
      return N_("Free(Chunk %s)") %self.xpacket2send
  
  def Help(self):
    return "Once you created a socket with CONNECT object you are able to send and receive data on it.\n\
The send dialog allows you to choose which data to send: this can be either a string or a previously \n\
created buffer.\n\
e.g. if we're exploiting a SMTPD which has an overflow in the handling of the RCPT command \n\
you would add three send objects:\n\
1. \"HELO localhost\\n\"\n\
2. \"MAIL FROM: email@address.heh\\n\"\n\
3. \"RCPT TO: \" + exploit buffer"
  

    
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacket):
    self.fdlist = fdlist
    self.xpacketlist = xpacket
    #sendstring=dialog.get_widget('sendstring')
    #sendstring.set_text(self.sendstring)
    hboxpreparexpacket = dialog.get_widget("hbox4")    
    #hboxpreparefd = dialog.get_widget("hbox5") 
    
    preparexpacket = gtk.combo_box_new_text()
    hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
    #preparefd = gtk.combo_box_new_text()
    #hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    
    
    preparexpacket.show()
    #preparefd.show()
    #basic edition == silent sockets
    
    if len(self.fdlist) == 0:
      preparexpacket.append_text(N_('No Chunk to Free yet'))
    else:
      preparexpacket.append_text(N_('Select Chunk to Free'))
      
    for a in fdlist:
        preparexpacket.append_text( str(self.fdlist.index(a) + 1) )
    print self.fdlist    
 
    try:
      preparexpacket.set_active(int(self.boxargs['preparexpacket']))
    except:
      preparexpacket.set_active(0)
    
    
    preparexpacket.connect('changed', self.changedp)
    #preparefd.connect('changed', self.changedf)
  
  def preparedialog(self,widget,xpacketlist,fdlist):
    self.fdlist=fdlist
    self.xpacketlist = xpacketlist
    #sendstring=widget.get_widget('sendstring')
    #sendstring.set_text(self.sendstring)
    hboxpreparexpacket = widget.get_widget("hbox4")    
    #hboxpreparefd = widget.get_widget("hbox5") 
    
    preparexpacket = gtk.combo_box_new_text()
    hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
    #preparefd = gtk.combo_box_new_text()
    #hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    
    
    preparexpacket.show()
    #basic edition == silent sockets
    #preparefd.show()
    
    if len(fdlist) == 0:
      preparexpacket.append_text(N_('No Chunk to free yet'))
    else:
      preparexpacket.append_text(N_('Select Chunk to free'))
    for a in fdlist:
        preparexpacket.append_text( str(fdlist.index(a) + 1) )
      
    preparexpacket.set_active(0)
    
    preparexpacket.connect('changed', self.changedp)
  
  def changedp(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()
        
        self.boxargs['preparexpacket']=model[index][0]
        self.setArg(self.boxargs)
        return

  def changedf(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()
        
        self.boxargs['preparefd']=model[index][0]
        self.setArg(self.boxargs)
        return
      
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    rbuf=r'self.log("sending buffer of length %s..." % str(len(xpacket'
    cfd = int(self.xpacket2send)
    if paddingfromrow > 0:
      self.buf=[]
      self.buf.append('read_buf = FD_1.send(struct.pack("LL", %s, var_alloc_%d))'% (self.FREE, cfd))
      self.buf.append('time.sleep(1)')
      self.buf.append('self.log("doFree(%d) -> 0x%%08x" %% var_alloc_%d)' % (cfd, cfd))
      
    else:
      self.buf=[]
      self.buf.append('read_buf = FD_1.send(struct.pack("LL", %s, var_alloc_%d))'% (self.FREE, cfd))
      self.buf.append('time.sleep(1)')
      self.buf.append('self.log("doFree(%d) -> 0x%%08x" %% var_alloc_%d)' % (cfd, cfd))

    return  self.buf

   
  
  def save(self):
    savedic={}
    if self.xpacket2send == None:
      savedic['sendstring']=self.sendstring
    else:
      savedic['xpacket2send']=self.xpacket2send
    savedic['cfd']=self.cfd
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('xpacket2send'):
      self.xpacket2send = args['xpacket2send']
    if args.has_key('sendstring'):
      self.sendstring= args['sendstring']
      
    if args.has_key('cfd'):
      self.cfd = args['cfd']
