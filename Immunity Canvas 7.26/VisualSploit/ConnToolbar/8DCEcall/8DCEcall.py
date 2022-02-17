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


class Toolobject(VisualToolbar):
  NAME = "DCEcall"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "dcecall.ico"
  button_label = "Add DCEcall()"
  button_tooltip = "Add DCEcall() to connection packet"
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
  functionnumber=""
  
  

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('preparexpacket' ) :
      self.xpacket2send = args['preparexpacket']
    
    if args.has_key('preparefd'):
      self.cfd = args['preparefd']
      
    
    if args.has_key('functionnumber'):
      self.functionnumber= args['functionnumber']
    
    
  def Show(self):
    if self.xpacket2send == None:
      return "call(No buffer selected)"
    else:
      return "call(Buffer %s)" %self.xpacket2send
    
  
  def Help(self):
    helpstr ="""Once you created a DCE object with DCE CONNECT object you are able to make DCE Calls on it."""
    return helpstr
  

    
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacket):
    self.fdlist = fdlist
    self.xpacketlist = xpacket
    self.model =  cpacket.get_model()
    self.objectlist=[] #reset object list
    functionnumber=dialog.get_widget('functionnumber')
    functionnumber.set_text(self.functionnumber)
    hboxpreparexpacket = dialog.get_widget("hbox4")    
    hboxpreparefd = dialog.get_widget("hbox5") 
    
    preparexpacket = gtk.combo_box_new_text()
    hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
    preparefd = gtk.combo_box_new_text()
    hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    
    
    preparexpacket.show()
    preparefd.show()
    
    if len(self.xpacketlist) == 0:
      preparexpacket.append_text('No Buffer selected yet')
    else:
      preparexpacket.append_text('Select Buffer')
    for a in self.xpacketlist:
        preparexpacket.append_text(str(self.xpacketlist.index(a) + 1))
    
    preparefd.append_text("Select DCEconnect")
    for a in self.model:
      if a[2].NAME == "DCEconnect":
        self.objectlist.append(a[2])
        preparefd.append_text(a[2].NAME+" #%s" %str(a[2].getNumber()))
        preparefd.connect('changed', self.changedf,a[2])
        for b in a.iterchildren():
          self.ChildrenRow(b,preparefd)
 
    try:
      preparexpacket.set_active(int(self.boxargs['preparexpacket']))
    except:
      preparexpacket.set_active(0)
    try:
      preparefd.set_active(int(self.boxargs['preparefd']))
    except:
      preparefd.set_active(0)
    
    preparexpacket.connect('changed', self.changedp)
  
  def ChildrenRow(self,row,preparefd):
    if row.iterchildren():
      for b in row.iterchildren():
        if b[2].NAME == "DCEconnect":
          preparefd.append_text(b[2].NAME+" #%s" %str(b[2].getNumber()))
          preparefd.connect('changed', self.changedf,b[2])
        self.ChildrenRow(b,preparefd)
    else:
      print "Error getting children row"
    
  
  def preparedialog(self,widget,xpacketlist,fdlist):
    self.objectlist=[] #reset object list
    self.fdlist=fdlist
    self.xpacketlist = xpacketlist
    self.model=self.cpacketlist[0].get_model() #warning if more than one cpacket
    functionnumber=widget.get_widget('functionnumber')
    functionnumber.set_text(self.functionnumber)
    hboxpreparexpacket = widget.get_widget("hbox4")    
    hboxpreparefd = widget.get_widget("hbox5") 
    
    preparexpacket = gtk.combo_box_new_text()
    hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
    preparefd = gtk.combo_box_new_text()
    hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
    
    preparexpacket.show()
    preparefd.show()
    
    if len(xpacketlist) == 0:
      preparexpacket.append_text('No Buffer selected yet')
    else:
      preparexpacket.append_text('Select Buffer')
    for a in xpacketlist:
        preparexpacket.append_text(str(xpacketlist.index(a) + 1))

    preparefd.append_text("Select DCEconnect")
    for a in self.model:
      if a[2].NAME == "DCEconnect":
        self.objectlist.append(a[2])
        preparefd.append_text(a[2].NAME+" #%s" %str(a[2].getNumber()))
        preparefd.connect('changed', self.changedf,a[2])
        for b in a.iterchildren():
          self.ChildrenRow(b,preparefd)
    
    preparexpacket.set_active(0)
    preparefd.set_active(0)
    
    preparexpacket.connect('changed', self.changedp)
    
  def changedp(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()
        self.boxargs['preparexpacket']=model[index][0]
        self.setArg(self.boxargs)
        return

  def changedf(self, combobox,dceconnect):
        self.dceconnectobj = dceconnect        
        model = combobox.get_model()
        index = combobox.get_active()
        self.boxargs['preparefd']=model[index][0]
        self.setArg(self.boxargs)
        return
      
  
  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    dceconnnumber= self.cfd.split("#")[1]
    if paddingfromrow > 0:
        self.buf=[]
        self.buf.append(padding+"pkt=self.createxPacket%s()" % self.xpacket2send)
        self.buf.append(padding+"self.targetfunction=%s" %str(self.functionnumber))
        self.buf.append(padding+"ret = self.dce%s.call(self.targetfunction, pkt,response=self.response)" %dceconnnumber)
    else:
        self.buf=[]
        self.buf.append("pkt=self.createxPacket%s()" % self.xpacket2send)
        self.buf.append("self.targetfunction=%s" %str(self.functionnumber))
        self.buf.append("ret = self.dce%s.call(self.targetfunction, pkt,response=self.response)" %dceconnnumber)
        
    return  self.buf

   
  
  def save(self):
    savedic={}
    if self.xpacket2send == None:
      savedic['functionnumber']=self.functionnumber
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
    if args.has_key('functionnumber'):
      self.functionnumber= args['functionnumber']
      
    if args.has_key('cfd'):
      self.cfd = args['cfd']