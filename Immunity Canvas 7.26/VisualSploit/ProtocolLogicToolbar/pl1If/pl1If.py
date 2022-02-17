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
  NAME = "plIf"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "plIf.ico"
  button_label = "Add IF"
  button_tooltip = "Add IF"
  button_private_tooltip = "Private"
  button_signal = None
  color = "red"
  size = 20
  fdlist=[]
  buf=[]
  boxargs={}
  object=None
  objectcomments = None
  NumberofXp =1
  objectlist=[]

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    if args.has_key('entry1'):
      self.against = args['entry1']
    if args.has_key('object'):
      self.object = self.boxargs['object']
    if args.has_key('action'):
      self.action = self.boxargs['action']
    
    
  
  def setDialog(self,widget,cpacket,badchars,fdlist,xpacketlist):
    against=widget.get_widget('entry1')
    against.set_text(str(self.against))
    hboxprepareobjs = widget.get_widget("hbox5") 
    hboxprepareaction = widget.get_widget("hbox4") 
    model = cpacket.get_model()
    #if the setdialog is called from a loaded object
    self.model = model
    prepareobjs = gtk.combo_box_new_text()
    prepareaction = gtk.combo_box_new_text()
    hboxprepareobjs.pack_start(prepareobjs,expand=True, padding=0)
    hboxprepareaction.pack_start(prepareaction,expand=True, padding=0)
    prepareobjs.show()
    prepareobjs.append_text('Change Object?')
    prepareaction.show()
    prepareaction.append_text('Select Action')
    prepareaction.append_text('CONTAINS')
    prepareaction.append_text('EQUAL')
    prepareaction.append_text('NOT EQUAL')
    prepareaction.connect('changed', self.changeaction)
    try:
      prepareobjs.set_active(self.object.index(self.boxargs['object'])+1)
    except:
      prepareobjs.set_active(0)
    try:
      prepareaction.set_active(self.action.index(self.boxargs['action'])+1)
    except:
      prepareaction.set_active(0)
      
    self.objectlist=[]
    for a in model:
      
      
      if a[2].NAME == "recv":
        self.objectlist.append(a[2])
        prepareobjs.append_text(a[2].NAME+" #%s" %str(a[2].getNumber()))
        prepareobjs.connect('changed', self.changeobjs)
        for b in a.iterchildren():
          self.ChildrenRow(b,prepareobjs)
  
  def ChildrenRow(self,row,prepareobjs):
    if row.iterchildren():
      for b in row.iterchildren():
        if b[2].NAME == "recv":
          prepareobjs.append_text(b[2].NAME+" #%s" %str(b[2].getNumber()))
          prepareobjs.connect('changed', self.changeobjs)
        self.ChildrenRow(b,prepareobjs)
    else:
      print "Error getting children row"
 
  def preparedialog(self,widget,cpacket):
    
    
    hboxprepareobjs = widget.get_widget("hbox5")
    hboxprepareaction = widget.get_widget("hbox4") 
    model = cpacket.get_model()
    #if the setdialog is called from a loaded object
    self.model = model
    prepareobjs = gtk.combo_box_new_text()
    prepareaction = gtk.combo_box_new_text()
    hboxprepareobjs.pack_start(prepareobjs,expand=True, padding=0)
    hboxprepareaction.pack_start(prepareaction,expand=True, padding=0)
    
    prepareobjs.show()
    prepareobjs.append_text('Select Object')
    prepareaction.show()
    prepareaction.append_text('Select Action')
    prepareaction.append_text('CONTAINS')
    prepareaction.append_text('EQUAL')
    prepareaction.append_text('NOT EQUAL')
    prepareaction.connect('changed', self.changeaction)
    
    try:
      prepareobjs.set_active(self.object.index(self.boxargs['object'])+1)
    except:
      prepareobjs.set_active(0)
    
    try:
      prepareaction.set_active(self.action.index(self.boxargs['action'])+1)
    except:
      prepareaction.set_active(0)
    self.objectlist=[]    
    for a in model:  
     if a[2].NAME == "recv":
        self.objectlist.append(a[2])
        prepareobjs.append_text(a[2].NAME+" #%s" %str(a[2].getNumber()))
        prepareobjs.connect('changed', self.changeobjs)
        for b in a.iterchildren():
          self.ChildrenRow(b,prepareobjs)
  
    
  def changeobjs(self, combobox):
    model = combobox.get_model()
    self.index = combobox.get_active()
    self.boxargs['object']=model[self.index][0]
    self.setArg(self.boxargs)
    return  
  
  def changeaction(self, combobox):
    model = combobox.get_model()
    self.index = combobox.get_active()
    self.boxargs['action']=model[self.index][0]
    self.setArg(self.boxargs)
    return  
  
  def Show(self):
    return "IF(%s) %s %s" % (self.object,self.action,self.against)
  
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

  def createPython(self,paddingfromrow):
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    if paddingfromrow > 0:
      if self.action == "CONTAINS":
        self.buf.append(padding+'if recv_buf.find("%s") > -1:' %self.against)
      elif self.action=="EQUAL":
        self.buf.append(padding+'if recv_buf=="%s":' %self.against)
      elif self.action=="NOT EQUAL":
        self.buf.append(padding+'if recv_buf!="%s":' %self.against)
    else:
        if self.action == "CONTAINS":
          self.buf.append('if recv_buf.find("%s") > -1:' %self.against)
        elif self.action=="EQUAL":
          self.buf.append('if recv_buf=="%s":' %self.against)
        elif self.action=="NOT EQUAL":
          self.buf.append('if recv_buf!="%s":' %self.against)
      
    return  self.buf

  
  def save(self):
    savedic={}
    savedic['object']=self.object
    savedic['against']=self.against
    savedic['action']=self.action
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
      
    if args.has_key('against'):
      self.against = args['against']
      
    if args.has_key('action'):
      self.action = args['action']
    
    if args.has_key('object'):
      self.object = args['object']
  
  
  
    
