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
  NAME = "DCEconnect"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "dceconnect.ico"
  button_label = "Add DCE connect()"
  button_tooltip = "Add DCE connect() to Program Flow"
  button_private_tooltip = "Private"
  button_signal = None
  color = "red"
  objectcomments = None
  size = 20
  fdlist=[]
  buf=[]
  NumberofXp =1
  checkusername= False
  checkpassword = False

  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    self.size =size
        
  def setArg(self,args):
    self.connecttoh = args['connecttoh']
    self.connecttop = args['connecttop']
    self.username = args['username']
    self.password = args['password']
    self.namedpipe = args['namedpipe']
    self.uuid = args['uuid']
    self.uuidversion = args['uuidversion']
    self.checkusername = args['checkusername']
    self.checkpassword = args['checkpassword']
    try:
      self.cfd = args['fdlist']
    except:
      pass
  
  def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
    connecttoh=dialog.get_widget('connecttoh')
    connecttop=dialog.get_widget('connecttop')
    uuid=dialog.get_widget('uuid')
    uuid.set_text(self.uuid)
    uuidversion=dialog.get_widget('uuidversion')
    uuidversion.set_text(self.uuidversion)
    username=dialog.get_widget('username')
    password=dialog.get_widget('password')
    namedpipe=dialog.get_widget('namedpipe')
    checkusername=dialog.get_widget('checkusername')
    checkpassword=dialog.get_widget('checkpassword')
    checkusername.set_active(self.checkusername)
    checkpassword.set_active(self.checkpassword)
    username.set_sensitive(self.checkusername)
    password.set_sensitive(self.checkpassword)
    connecttoh.set_text(self.connecttoh)
    connecttop.set_text(str(self.connecttop))
    username.set_text(self.username)
    password.set_text(self.password)
    namedpipe.set_text(self.namedpipe)
    checkusername.connect('toggled', self.changes,username)
    checkpassword.connect('toggled', self.changes,password)
    #self.cfd = fd
    
    
  def Show(self):
    return "DCEconnect(%s:%d)" % (self.connecttoh,int(self.connecttop))
  
  def Help(self):
    helpstr="""The DCE Connect object allows you to connect to a remote host via DCE.
    It returns a DCE object which you can use later with DCE Call object"""
    return helpstr

  def preparedialog(self,dialog,argb,argc):
    username=dialog.get_widget('username')
    password=dialog.get_widget('password')
    checkusername=dialog.get_widget('checkusername')
    checkpassword=dialog.get_widget('checkpassword')
    username.set_sensitive(self.checkusername)
    password.set_sensitive(self.checkpassword)
    checkusername.connect('toggled', self.changes,username)
    checkpassword.connect('toggled', self.changes,password)
    
  def changes(self,event,entry):
    entry.set_sensitive(event.get_active())
    
  def get_dceval(self):
    tmp={}
    tmp['uuid']=self.uuid
    if self.username:
      tmp['username']=self.username
    if self.password:
      tmp['password']=self.password
    return tmp
    
  def buildConn(self):
    padding="    "
    templatebuf = [padding+'def buildConnectionList(self):\n']
    exec 'tmp = """%s"""'
    templatebuf+= [padding*2+'connectionList= ["ncacn_np:'+tmp+'[%s]"' % self.namedpipe +tmp+'elf.host ]\n']
    templatebuf+= [padding*2+'return self.connectionList\n\n']
    return templatebuf
  
  def createPython2(self,paddingfromwor):
    pass
  
  def createPython(self,paddingfromrow):
    #for now, we manage sockets silently
    multiplier = str(paddingfromrow+1)
    padding="    " * int(multiplier)
    self.buf=[]
    tmp = r"%s"

    if paddingfromrow > 0:
      #self.buf.append(padding+'connectionList= ["ncacn_np:'+tmp+'[%s]"' % self.namedpipe +tmp+'elf.host ]\n')
      self.buf.append(padding+'connectionList= ["%s" ]\n' % self.namedpipe)
      self.buf.append(padding+'self.dce%s = self.DCEconnect("%s","%s", connectionList,"%s", "%s")\n'%(self.NumberofXp,self.uuid,self.uuidversion,self.username,self.password))
      
    else:
      #self.buf.append('connectionList= ["ncacn_np:'+tmp+'[%s]"' % self.namedpipe +tmp+'elf.host ]\n')
      self.buf.append('connectionList= ["%s" ]\n' % self.namedpipe)
      self.buf.append('self.dce%s = self.DCEconnect("%s","%s", connectionList,"%s", "%s")\n'%(self.NumberofXp,self.uuid,self.uuidversion,self.username,self.password))
      
    return  self.buf

  
  def save(self):
    savedic={}
    savedic['hostname']=self.connecttoh
    savedic['port']=self.connecttop
    savedic['username']=self.username
    savedic['password']=self.password
    savedic['namedpipe']=self.namedpipe
    savedic['checkusername']=self.checkusername
    savedic['checkpassword']=self.checkpassword
    savedic['uuid']=self.uuid
    savedic['uuidversion']=self.uuidversion
    savedic['cfd']=self.cfd
    if self.objectcomments:
      savedic['comment']=self.objectcomments.replace("\n","\\n")
    return savedic
  
  def load(self,args):
    if args.has_key('comment'):
      tmp = args['comment']
      self.objectcomments=tmp.replace("\\n","\n")
    if args.has_key('hostname'):
      self.connecttoh = args['hostname']
    if args.has_key('uuid'):
      self.uuid = args['uuid'].replace("\\n","\n")
    if args.has_key('uuidversion'):
      self.uuidversion = args['uuidversion']
      
    if args.has_key('username'):
      self.username = args['username']
    if args.has_key('password'):
      self.password = args['password']
    if args.has_key('checkusername') == "True":
      self.checkusername = True
    else:
      self.checkusername = False
    if args.has_key('checkpassword') == "True":
      self.checkpassword = True
    else:
      self.checkpassword = False
    if args.has_key('namedpipe'):
      self.namedpipe = args['namedpipe']
    
    if args.has_key('port'):
      self.connecttop = args['port']
      
    if args.has_key('cfd'):
      self.cfd = args['cfd']
  
  def getHost(self):
    return self.connecttoh
  
  def getPort(self):
    return self.connecttop

  
    
