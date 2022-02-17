#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
sys.path.append(".")
sys.path.append("../")

from internal import *

class VisualToolbar:
  NAME = "NONAME" # Name for the toolbar
  GLADE_DIALOG = "dialog.glade2" # dialog to be used

  def __init__(self):
    self.name = "NONAME"   # Name of the Xpacket buffer
    self.filexpm= None
    self.button_label = "NONAME"
    self.button_tooltip = "NOTIP"
    self.button_private_tooltip = "NOTIP"
    self.button_signal = None
    #self.color = "blue" # default color
    #self.size  = 20      # default size
    NumberofXp = 1
    link=False
    objectcomments = None
    self.mosdefplatlist={"Win32": "X86", "Solaris":"SPARC", "OSX":"PPC", "Linux":"X86"}

  # return the real platform for mosdef.assemble()
  def getMOSDEFPlatform(self):
    return self.mosdefplatlist[self.arch]

  # set the essential values for every toolobject
  def setEssential(self,arch, badchars,cpacketlist,xpacketlist,fdlist):
    if arch:
      self.arch=arch
    else:
      pass
    if badchars:
      self.badchars=badchars
    else:
      pass
    if cpacketlist:
      self.cpacketlist=cpacketlist
    else:
      pass
    if xpacketlist:
      self.xpacketlist=xpacketlist
    else:
      pass
    if fdlist:
      self.fdlist=fdlist
    else:
      pass
    
  
  # create an xml file with the given properties
  def save(self):
    print "You have to define save() for this object"
  
  # load the object based on the xmldata  
  def load(self, args):
    print "You have to define load() for this object"
  
  # This function gets the information from the dialogbox and fill the object with it
  def setArg(self, arguments):
    print "You have to define setArg() for this object"
  
  #This function shows toolobject args
  def Show(self):
    print "You have to define Show() for this object"

  # this is no mandatory
  def preparedialog(self,dialog,argb,argc,badchars,arch):
    pass
  
  def setDialog(self):
    print "You have to define setDialog() for this object"
 # def __str__(self):
 #   return self.Show()
  
  def createPython(self):
    print "You have to define createPython() for this object"

  def setNumber(self,xpacket):
    model = xpacket.get_model()
  
    try:
      xpacketobjs = [ r[3] for r in model ]
      for a in xpacketobjs:
        if a.NAME == self.NAME:
          self.NumberofXp = self.NumberofXp +1
      return self.NumberofXp
    except:
      for p in model:
        if p[2].NAME == self.NAME:
          self.NumberofXp = self.NumberofXp +1
        for b in p.iterchildren():
          if b[2].NAME == self.NAME:
            self.NumberofXp = self.NumberofXp +1
          self.getChildrenRow(b)
      return self.NumberofXp
    
    
  
    
  def getChildrenRow(self,row):
    if row.iterchildren():
      for b in row.iterchildren():
        if b[2].NAME == self.NAME:
          self.NumberofXp = self.NumberofXp +1
        self.getChildrenRow(b)
    else:
      print "Error getting children row"
        
    
  def getNumber(self):
    return self.NumberofXp
  
  def setLink(self,link,instance):
    if link == True:
      self.instance=instance
      self.link=True
    else:
      self.link=False
      
  
  def getLinkState(self):
    return self.link
  
  def linkedObj(self):
    return self.instance
  
  def getSize(self):
    return int(self.objsize)

  
    
  def setObjectComments(self,comments):
    devlog("vs", "setObjectComments called: %s"%repr(comments))
    #[DEV] vs: setObjectComments called: {'commententry': 'sxcvasdfv\n'}

    if comments.has_key('commententry'):
      self.objectcomments=comments['commententry']
      #Need to figure out how to make this next line work...
      #can you even do this on a row of a GTK.tree?
      #self.set_tooltip(self.objectcomments)
      return True
    return False 
  
  def getObjectComments(self):
    """
    Returns the comments someone has set, if any
    """
    devlog("vs", "getObjectComments: %s"%self.objectcomments)
    if self.objectcomments:
      return self.objectcomments
    else:
      return None
    
    
  
  
class FakeCallback:
  def __init__(self):
    self.ip = "127.0.0.1"
    self.port = "2222"
    self.argsDict={}
    
    
