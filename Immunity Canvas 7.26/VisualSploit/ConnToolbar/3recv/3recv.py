#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information

import sys
import gtk
if "." not in sys.path:
  sys.path.append(".")
from toolbar import VisualToolbar


class Toolobject(VisualToolbar):
  NAME = "recv"
  INDEXED = "COMMONTCP"
    
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "recv.ico"
  button_label = "Add recv()"
  button_tooltip = "Add recv()"
  button_private_tooltip = "Private"
  button_signal = None
  color = "green"
  size = 20
  boxargs={}
  cfd=None
  objectcomments = None
  fdlist=[]
  xpacketlist=[]
  buf=[]
  NumberofXp =1
  

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('rcvbuf' ) :
      self.rcvbuf = args['rcvbuf']
    
    if args.has_key('preparefd'):
      self.cfd = args['preparefd']
      
    
    
  
  def Show(self):
    #return "recv(%d)" %int(self.rcvbuf)
    #basic
    return "Receive Data"

  def Help(self):
    return "As most protocols require two-way communication, the recv object allows\n\
you to receive data. This allows you to construct protocol handshakes, \n\
clear pending data off of the socket, or do simple banner checks. You \n\
can add simple logic controlling the flow of your exploit using the \n\
IF/ELSE objects (see IF/ELSE help for specific examples).\n\
\n\
e.g.\n\
\n\
1. add a connect to localhost:25\n\
2. send \"HELO localhost\\n\"\n\
3. recv data\n\
4. IF data CONTAINS \"250\" send exploit ELSE show error message"

  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
    self.fdlist=fdlist
    rcvbuf=dialog.get_widget('rcvbuf')
    rcvbuf.set_text(str(self.rcvbuf))
    
    
    hboxpreparefd = dialog.get_widget("hbox5") 
    preparefd = gtk.combo_box_new_text()
    hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    #preparefd.show()
    #basic edition == silent sockets
    
    if len(self.fdlist) == 0:
      preparefd.append_text('No FD to use yet')
    else:
      preparefd.append_text('Select FD to use')
    for a in self.fdlist:
        preparefd.append_text(str(self.fdlist.index(a) + 1))
    
    try:
      preparefd.set_active(int(self.boxargs['preparefd']))
    except:
      preparefd.set_active(0)
    
    preparefd.connect('changed', self.changedf)
    
  def preparedialog(self,widget,xpacketlist,fdlist):
    self.fdlist=fdlist
    hboxpreparefd = widget.get_widget("hbox5") 
    preparefd = gtk.combo_box_new_text()
    hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    #preparefd.show()
    #basic edition == silent sockets
    if len(fdlist) == 0:
      preparefd.append_text('No FD to use yet')
    else:
      preparefd.append_text('Select FD to use')
    for a in fdlist:
        preparefd.append_text(str(fdlist.index(a) + 1))
    preparefd.set_active(0)
    preparefd.connect('changed', self.changedf)
  
  def changedf(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()
        
        self.boxargs['preparefd']=model[index][0]
        self.setArg(self.boxargs)
        return
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    if paddingfromrow==0:
      padding=""
    else:
      padding="    " * int(multiplier)
    self.buf=[]

    #self.buf.append(padding+'recv_buf=FD_%s.recv(%s)'% (self.cfd,self.rcvbuf))
    #basic edition == silent sockets, receive 5000
    #self.buf.append(padding+'recv_buf=FD_1.recv(%s)'% self.rcvbuf)
    self.buf.append(padding+'recv_buf=FD_1.recv(5000)')
    #self.buf.append(padding+'self.log("received: %s." %recv_buf)')
    self.buf.append(padding+'self.log("received: %d bytes."%len(recv_buf))')
    self.buf.append(padding+'self.log("Bytes received: %s"%prettyprint(recv_buf))')
      
    return  self.buf

     
  def save(self):
    savedic={}
    savedic['rcvbuf']=self.rcvbuf
    savedic['cfd']=self.cfd
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('rcvbuf'):
      self.rcvbuf = args['rcvbuf']
      
    if args.has_key('cfd'):
      self.cfd = args['cfd']