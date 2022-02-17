#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information


import sys
import gtk
sys.path.append(".")
from toolbar import VisualToolbar
from gettext import gettext as N_


class Toolobject(VisualToolbar):
  NAME = "setComments"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "comments.ico"
  button_label = N_("Set Comments")
  button_tooltip = N_("Set exploit documentation")
  button_private_tooltip = "Private"
  button_signal = None
  setflag=0
  
  
  
  
 
  
  
  
  
  def __init__(self):
    VisualToolbar.__init__(self)


  def setSize(self, size):
    pass
  
  def Help(self):
    return N_("Set Comments: this fills in the exploit documentation header and CANVAS\n\
exploit properties which are required to run your exploit from CANVAS.")
    
  def setArg(self,args):
    self.setflag=1
    if args.has_key('sploitcomments'):
      self.sploitcomments = args['sploitcomments']
    else:
      self.sploitcomments=""
    if args.has_key('description'):
      self.description = args['description']
    else:
      self.description=""
    if args.has_key('proptype') and args["proptype"]!="":
      self.proptype = args['proptype']
    else:
      self.proptype="Exploit"
    if args.has_key('repeatability'):
      self.repeatability = args['repeatability']
    else:
      self.repeatability=""
    if args.has_key('propversion') and args["propversion"] != "":
      self.propversion = args['propversion']
    else:
      self.propversion="Windows"
    if args.has_key('references'):
      self.references = args['references']
    else:
      self.references=""
    if args.has_key('propsite') and args["propsite"] != "":
      self.propsite = args['propsite']
    else:
      self.propsite="Remote"
    if args.has_key('datepublic'):
      self.datepublic = args['datepublic']
    else:
      self.datepublic=""
    if args.has_key('name'):
      self.name = args['name']
    else:
      self.name=""
    if args.has_key('version'):
      self.version = args['version']
    else:
      self.version=""
  
  
  def setDialog(self,dialog,args):
    if self.setflag == 1:
      sploitcomments=dialog.get_widget('sploitcomments')
      scommentbuffer=gtk.TextBuffer()
      scommentbuffer.set_text(self.sploitcomments)
      sploitcomments.set_buffer(scommentbuffer)
      description=dialog.get_widget('description')
      description.set_text(self.description)
      proptype=dialog.get_widget('proptype')
      proptype.set_text(self.proptype)
      repeatability=dialog.get_widget('repeatability')
      repeatability.set_text(self.repeatability)
      propversion=dialog.get_widget('propversion')
      propversion.set_text(self.propversion)
      references=dialog.get_widget('references')
      references.set_text(self.references)
      propsite=dialog.get_widget('propsite')
      propsite.set_text(self.propsite)
      datepublic=dialog.get_widget('datepublic')
      datepublic.set_text(self.datepublic)
      name=dialog.get_widget('name')
      name.set_text(self.name)
      version=dialog.get_widget('version')
      version.set_text(self.version)

    else:
      sploitcomments=dialog.get_widget('sploitcomments')
      scommentbuffer=gtk.TextBuffer()
      scommentbuffer.set_text(args['sploitcomments'])
      sploitcomments.set_buffer(scommentbuffer)
      description=dialog.get_widget('description')
      description.set_text(args['description'])
      proptype=dialog.get_widget('proptype')
      proptype.set_text(args['proptype'])
      repeatability=dialog.get_widget('repeatability')
      repeatability.set_text(args['repeatability'])
      propversion=dialog.get_widget('propversion')
      propversion.set_text(args['propversion'])
      references=dialog.get_widget('references')
      references.set_text(args['references'])
      propsite=dialog.get_widget('propsite')
      propsite.set_text(args['propsite'])
      datepublic=dialog.get_widget('datepublic')
      datepublic.set_text(args['datepublic'])
      name=dialog.get_widget('name')
      name.set_text(args['name'])
      version=dialog.get_widget('version')
      version.set_text(args['version'])
    
  
      
  def Show(self):
    pass

    
      
  def preparedialog(self,widget,platlist,xpacket):
    pass
  
  def createPython(self):
    return  ""
    
  
  
    
  
  
