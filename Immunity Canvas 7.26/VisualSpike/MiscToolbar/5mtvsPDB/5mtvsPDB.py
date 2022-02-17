#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information


import sys
import pygtk
import gtk,gtk.glade
import getopt
import signal, os
import string
sys.path.append(".")
sys.path.append("./PDB")
sys.path.append("./PDB/client")
from toolbar import VisualToolbar

# clientwrapper
import clientwrapper
# command line interface
import cli
# main PDB class
dbgCore = clientwrapper.client()


class pdb(cli.clientCore):
    def __init__(self):
        cli.clientCore.__init__(self, dbgCore)
        # inherit from global STATES
        self.connected = 0
        signal.signal(signal.SIGINT, self.breakHandler)
        return
    
    def initPdb(self,host,port):
        if self.connected:
            dbgCore.sock.close()
        if self.logfile != "": 
            self.logfd.close()
        self.__init__()
        self.host = host
        self.port = port
        # connect it
        line = "Connecting (%s:%d)\n"%(host,port) 
        self.writeLine(line)
        dbgCore.connectClient(host, port)
        self.connected = 1
        # init symopt dict
        self.symoptDict = dbgCore.dbgGetSymoptDict()
        # we do this here, because we're not connected at clientCore init
        self.eventCore.eventStringMap = dbgCore.dbgGetEvents()
        self.CONNECTED = 1
        print "Fetching processes..."
        self.ListActiveProcesses()
        return

    def ListActiveProcesses(self):
        pList = dbgCore.dbgListActiveProcesses()
        gladefile=gtk.glade.XML("./MiscToolbar/vsPDB/dialog.glade2","pdb_pslist")
        self.psdialog = gladefile.get_widget("pdb_pslist")
        vbox = gladefile.get_widget("vbox3")
        sw = gtk.ScrolledWindow()
        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
        pstree=gtk.TreeView()
        pstreemodel=gtk.ListStore(int, str)
        pstree.set_model(pstreemodel)
        pstree.set_headers_visible(True)
        pscell=gtk.CellRendererText()
        psname=gtk.TreeViewColumn("PID", pscell, text=0)
        psid=gtk.TreeViewColumn("Process", pscell, text=1)
        pstree.append_column(psname)
        pstree.append_column(psid)
        pstree.set_search_column(0)
        psname.set_sort_column_id(0)
        psid.set_sort_column_id(0)
        pstree.connect("button_press_event",self.pstreeclicked)
        
        sw.add(pstree)
        sw.show()
        vbox.pack_start(sw,expand=True, padding=0)
        #vbox.show()
        pstree.show()
        #fill the pstree with fetched ps
        for ps in pList:
            tmp=ps.split(" ",1)
            name=tmp[0]
            tmp=tmp[1].replace(")","").split(" ",1)
            id=tmp[1]
            #        print "NAME: %s ID: %s" %(name,id)
            iter = pstreemodel.append()        
            pstreemodel.set_value(iter, 0, int(id))
            pstreemodel.set_value(iter, 1, name)

        response = self.psdialog.run()

        # if response anything else than OK, we dont do anything
        self.psdialog.hide()
        if response == gtk.RESPONSE_OK:
            psselection=pstree.get_selection()
            model, iter = psselection.get_selected()
            pid = model.get_value(iter,0)
            name = model.get_value(iter,1)
            print "not dclick: attach this %s %s" %(pid,name)
            cmd="at"
            self.handleCommand(cmd,name)
            cmd="sm"
            args="jmp %ebx"
            self.handleCommand(cmd,args)
        return 

    def pstreeclicked(self,widget,event):
        psselection = widget.get_selection()
        model, iter = psselection.get_selected()
        if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
            pid = model.get_value(iter,0)
            name = model.get_value(iter,1)
            print "dclick: attach this %s %s" %(pid,name)
            self.psdialog.destroy()
            cmd="at"
            self.vspdb.handleCommand(cmd,name)
           
    def breakHandler(self, signum, frame):
        if self.HALTED:
            print "Already halted"
        else:
            raise Exception, "Break it"

      
class Toolobject(VisualToolbar):
  NAME = "vsPDB"
  GLADE_DIALOG = "dialog.glade2"
  filexpm = "vsPDB.ico"
  button_label = "vsPDB"
  button_tooltip = "Connect to PDB host"
  button_private_tooltip = "Private"
  button_signal = None
  setflag=0
  symoptDict = {}
  vspdb=pdb()
  
  
  
  def __init__(self):
    VisualToolbar.__init__(self)
    


  def setSize(self, size):
    pass
    
  def setArg(self,args):
    self.setflag=1
    if args.has_key('entry1'):
      self.hostname = args['entry1']
    else:
      self.hostname=""
    if args.has_key('entry2'):
      self.port = args['entry2']
    else:
      self.port=""
    

  def Connect(self):
      self.vspdb.initPdb(self.hostname,int(self.port))
      return
      
  
  def setDialog(self,dialog,args):
    if self.setflag == 1:
      hostname=dialog.get_widget('entry1')
      hostname.set_text(self.hostname)
      port=dialog.get_widget('entry2')
      port.set_text(self.port)
      
    else:
      hostname=dialog.get_widget('entry1')
      hostname.set_text(args['entry1'])
      port=dialog.get_widget('entry2')
      port.set_text(args['entry2'])
            
  
  
   
  def Show(self):
    pass

  def preparedialog(self,widget,platlist,xpacket):
    pass
  
  def createPython(self):
    return  ""

  def Help(self):
    return "Connects to a PDB host (a remote debugger that aids in gathering target information)."
    
  
  
    
  
  
