#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information

##NOTE: For the buffer overflow buttons to appear set an environmental 
##      variable 'VS_BUFFER' to any value & relevant buttons will appear

import pygtk
import gtk,gtk.glade
import os
import errno
import sys
import string
import gobject

import gettext
for module in (gettext,gtk.glade):
        module.bindtextdomain('visualspike', 'VisualSpike/locale')
        module.textdomain('visualspike')

N_=gettext.gettext

#import time
sys.path.append(".")
#sys.path.append("../")
sys.path.append("./exploits")
sys.path.append("./libs")
sys.path.append("./VisualSpike")

#mostly for devlog
from internal import * 

from gui.defaultgui import defaultgui
#import hostKnowledge

import canvasengine
import hostKnowledge
from gui import gui_queue
import exploitutils
from exploitutils import dInt, dInt_n
import libxdialog
from MOSDEF.mosdefutils import *

import pango

# gtk.input_add is now deprecated
try:
        gtk_input_add_hook = gobject.io_add_watch
except:
        gtk_input_add_hook = gtk.input_add


def get_pixel_height(widget, text):
        """
    Gets the pixel height of some text - we use this to calculate
    how large our boxes are when we place them into the liststore

    You cannot pass a ListStore object into this - it needs to be
    a widget.
    """
        context = widget.get_pango_context()
        metrics = context.get_metrics(context.get_font_description())
        newlinecount=text.count("\n")
        scale=metrics.get_ascent() + metrics.get_descent()
        scale=scale*2 #get bigger
        height = pango.PIXELS( scale * newlinecount)+3
        #print "Calculated height as %s"%height
        return height

class VSKnowledge(hostKnowledge.interfaceLine):
        def __init__(self, iface="eth0", ip=None, netmask=32):
                self.tag =""
                self.exploit_name =""
                self.value = 0
                self.iface = iface
                ifc=[]
                ifc.append(ip)
                ifc.append(iface)
                ifc.append(netmask)
                hostKnowledge.interfaceLine.__init__(self,ifc,0,1,65535,self)

        def add_knowledge(self, tag, exploit_name, value):
                self.tag = tag
                self.exploit_name = exploit_name
                self.value = value


def progress_timeout(pbobj):
        new_val = pbobj.listenerbar.get_fraction() + 0.01
        if new_val > 1.0:
                new_val = 0.0
        pbobj.listenerbar.set_fraction(new_val)
        return True

from automater import *   

class appgui(defaultgui):
        TARGETS = [
                ('MY_TREE_MODEL_ROW', gtk.TARGET_SAME_WIDGET, 0),
                ('text/plain', 0, 1),
                ('TEXT', 0, 2),
                ('STRING', 0, 3),
        ]

        def __init__(self):
                defaultgui.__init__(self)

                self.exp=None
                self.gladefile= "VisualSpike/maingui.glade"
                windowname="fstwindow"
                self.mainscnwin=None
                self.gui_queue = gui_queue.gui_queue(self)
                gtk_input_add_hook(self.gui_queue.get_event_socket(), gtk.gdk.INPUT_READ, self.clearqueue)
                self.resetPrj()
                self.wTree=gtk.glade.XML (self.gladefile,windowname)
                self.fstwindow = self.wTree.get_widget(windowname)
                self.newprojectname={'entry1':"vsploit_exploit"}
                self.wizprojectname={'entry1':"vsploit_exploit"}
                dic = {'gtk_main_quit': gtk.main_quit, 
                       'on_quit1_activate': self.on_quit1_activate,
                       'on_NewButton_clicked': self.preNewWorkspace,
                       'on_LoadButton_clicked': self.loadFilechooser,
                       'on_WizardButton_clicked': self.showWizard_start,
                       'on_new1_activate': self.preNewWorkspace,
                       'on_open1_activate': self.loadFilechooser,
                       'on_about1_activate': self.on_about1_activate,
                       'on_fstwindow_destroy': self.destroy,}
                self.wTree.signal_autoconnect(dic)
                self.XMLRPCport=8889
                self.setupXMLRPCSocket()
                self.debugger_thread=None
                self.calculator_window=None
                self.saved_args = {}
                return 

        def setupXMLRPCSocket(self):
                """
        Listen for XML-RPC requests on a socket
        """
                import SimpleXMLRPCServer
                import threading
                host="0.0.0.0"
                if self.XMLRPCport==0:
                        return 
                try:
                        server = SimpleXMLRPCServer.SimpleXMLRPCServer((host, self.XMLRPCport),allow_none=True)
                except:
                        #sometimes on old Python's allow_none doesn't exist.
                        print "No allow_none - not doing XML-RPC socket"
                        return False 
                devlog("vs", "Set up XMLRPC Socket on %s port %d"%(host, self.XMLRPCport))
                debugger_object=debugger_instance(self)
                server.register_instance(debugger_object)
                #start new thread.
                dt=debugger_thread(server, debugger_object)
                dt.start()
                self.debugger_thread=dt 
                self.debugger=debugger_object

                return True

        def clearqueue(self, source, condition):
                return self.gui_queue.clearqueue()

        def gui_queue_append(self, command, args):
                print "QUEUE: %s %s" % (command, str(args))
                self.gui_queue.append(command, args)
                return 1

        def registerNewExploit(self, exploit):
                exploit.setGTKModel(self, None, None)

        def listener_log(self, wTree2, message):
                if not wTree2:
                        return
                wid = wTree2.get_widget("listenerview")
                listenerbar = wTree2.get_widget("listenerbar")
                buffer = wid.get_buffer()
                iter = buffer.get_end_iter()

                #check to see if it can be displayed, and if not ,escape it.
                #this prevents annoying GTK errors
                try:
                        message.decode("utf8")
                except UnicodeDecodeError:
                        #the replace will make it prettier - but not perfect
                        message=message.encode("string_escape").replace("\\n","\n")

                #message = exploitutils.iso8859toascii(message) # a temporal and nasty solution

                try:
                        wid.get_buffer().insert(iter, message, len(message))
                except:
                        wid.get_buffer().insert(iter, message)
                buffer = wid.get_buffer()
                mark = buffer.create_mark("end", buffer.get_end_iter(), False)
                wid.scroll_to_mark(mark, 0.05, True, 0.0, 1.0)  



        def handle_gui_queue(self, text, object):

                gtk.gdk.threads_enter()
                print "<%s> %s" % (text, str(object)) 
                if text=="logmessage" or text=="debugmessage":
                        self.log(object[0])
                elif text=="update listener info":            
                        print "Progress: %d" % object[0].progress
                        if object[0].progress == -1:
                                pass 
                                #not sure abotut the next two lines of code, but it says "Owned" when we have no shell, so that's not right.
                                #self.listener.check()
                                #print "Owned!"

                elif text=="addLine":
                        self.listener = object[0]
                        self.listener.set_engine(self.engine)
                elif text =="do_listener_shell":
                        self.do_listener_shell(object[0])
                elif text == "shellwindow log":
                        shellwindow = object[0]
                        text = object[1]

                        self.listener_log(shellwindow, text)
                        #banana= shellwindow.get_widget("image3")
                        #banana.hide()
                        gobject.source_remove(self.timer)

                        listenerbar=shellwindow.get_widget("listenerbar")
                        self.destroy_progress(shellwindow,None)
                        self.listenerbar.set_fraction(1.0)

                        self.destroy_progress(shellwindow,None)
                        listenerbar.set_text("Done!")

                else:
                        print text, str(object)

                gtk.gdk.threads_leave()

        def input_add(self, fd, activity, callback):
                try:
                        fno = fd.fileno()
                except :
                        return
                result = gtk_input_add_hook(fd, activity, callback)
                print "Result: %s" % str(result)
                return result

        def input_remove(self, id):
                gtk.input_remove(id)

        def get_input_read(self):
                return gtk.gdk.INPUT_READ

        def do_listener_shell(self, shell):
                self.log("Doing a Listener-Shell")
                wTree =  gtk.glade.XML ( self.gladefile,"listener-shell")
                listenershell = wTree.get_widget("listener-shell")
                listenerview = wTree.get_widget("listenerview")
                listenerrun = wTree.get_widget("listenerrun")
                #banana = wTree.get_widget("image3")
                #banana.hide()
                #os.chdir("..")

                dic = {"on_listenerrun_clicked": (self.listenerdialog_runcommand, wTree, shell) }
                wTree.signal_autoconnect(dic)
                textbuffer = gtk.TextBuffer()
                #need to fill in buffer , before setting in the view
                textbuffer.set_text("")
                listenerview.set_buffer(textbuffer)
                return 

        def threads_enter(self):
                gtk.gdk.threads_enter()

        def threads_leave(self):
                gtk.gdk.threads_leave()

        def listenerdialog_runcommand(self, wid, wTree2, id):
                #def listenerdialog_runcommand(self, wTree2, wid):
                self.listenerprogressbar(None,wTree2)
                #banana = wTree2.get_widget("image3")
                #pixbufanim = gtk.gdk.PixbufAnimation("VisualSpike/banana.gif")
                #banana.set_from_animation(pixbufanim)
                #banana.show()
                command = wTree2.get_widget("listenerentry").get_text()
                result = self.engine.runcommand(id, wTree2, command)
                return 

        def play(self, txt):
                print txt

        def on_quit1_activate(self, event):
                gtk.main_quit()

        def on_about1_activate(self, event):
                self.wTree2 = gtk.glade.XML (self.gladefile, "aboutwindow")

        def msgBox(self,msg):
                msgboxdialog = gtk.glade.XML (self.gladefile,"msgbox")
                msglabel = msgboxdialog.get_widget("label18")        
                try:
                        what = msg.get_name()
                        if what == "GtkButton" and msg.get_label() != "Button24":
                                msglabel.set_text(N_("Badchars: Badchars are so-called 'bad characters'.\n\
These are characters that are filtered out by the protocol and as such are not allowed in\n\
your exploit data (payload or otherwise). Common badchars are newlines and nul bytes."))
                        else:
                                msglabel.set_text("Target Managing Help")
                except:
                        msglabel.set_text(msg)


                msgbox = msgboxdialog.get_widget("msgbox")
                response = msgbox.run()
                msgbox.hide()

        def showWizard_start(self,event):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard_start")
                wizard_start = wizdialog.get_widget("wizard_start")
                response = wizard_start.run()
                wizard_start.hide()
                if response == gtk.RESPONSE_OK:
                        self.showWizard1()

        def showWizard1(self):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard1")
                wizard1 = wizdialog.get_widget("wizard1")
                entry1=wizdialog.get_widget('entry1')
                entry1.set_text(self.wizprojectname['entry1'])

                if self.arch=="Win32":
                        arch=wizdialog.get_widget('win32')
                        arch.set_active(True)
                elif self.arch=="Linux":
                        arch=wizdialog.get_widget('linux')
                        arch.set_active(True)
                elif self.arch=="Solaris":
                        arch=wizdialog.get_widget('solaris')
                        arch.set_active(True)
                elif self.arch=="OSX":
                        arch=wizdialog.get_widget('osx')
                        arch.set_active(True)


                response = wizard1.run()
                wizard1.hide()
                if response == gtk.RESPONSE_OK:
                        wizard1data = self.getfromdialog(wizdialog)
                        self.wizprojectname['entry1']=wizard1data['entry1']
                        if wizard1data['win32'] == True:
                                self.arch ="Win32"
                        elif wizard1data['linux'] == True:
                                self.arch = "Linux"
                        elif wizard1data['solaris'] == True:
                                self.arch = "Solaris"
                        elif wizard1data['osx'] == True:
                                self.arch = "OSX"
                        try:
                                os.makedirs("Projects/"+self.wizprojectname['entry1'])
                        except OSError, err:
                                pass
                        self.showWizard2()
                elif response== gtk.RESPONSE_REJECT:
                        self.showWizard_start(None)

                elif response==gtk.RESPONSE_HELP:
                        help="Please choose a name for your new project.\n\
                            This name will be used by CANVAS as your exploit name \n\
                            once you finish with it.\nAlso, pick your desired Arch.\n\
                            This is the target architecture of computer where exploit will run.\n\
                            You will be able to change it later if necessary."
                        self.msgBox(help)
                        self.showWizard1()


        def showWizard2(self):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard2")
                wizard2 = wizdialog.get_widget("wizard2")
                callbackip=wizdialog.get_widget('callbackip')
                callbackip.set_text(str(self.callbackip))
                callbackport=wizdialog.get_widget('callbackport')
                callbackport.set_text(str(self.callbackport))

                response = wizard2.run()
                wizard2.hide()
                if response == gtk.RESPONSE_OK:
                        wizard2data = self.getfromdialog(wizdialog)
                        devlog("vs", "Wizard 2 Data: %s"%repr(wizard2data))
                        self.callbackip = wizard2data['callbackip']
                        self.callbackport = wizard2data['callbackport']
                        print "####" + str(self.callbackport)
                        self.showWizard3()
                elif response == gtk.RESPONSE_REJECT:
                        self.showWizard1()

                elif response==gtk.RESPONSE_HELP:
                        help="You will need to provide callback information at this step\n\
                            We reffer with callback to the machine which is currently attacking the target\n\
                            The machine which will be waiting for the exploit to connects back.\n\
                            In most cases, the callback machine is right this one where you are running VisualSpike"
                        self.msgBox(help)
                        self.showWizard2()


        def showWizard3(self):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard3")
                wizard3 = wizdialog.get_widget("wizard3")
                sploitcomments=wizdialog.get_widget('sploitcomments')
                scommentbuffer=gtk.TextBuffer()
                scommentbuffer.set_text(self.doc['sploitcomments'])
                sploitcomments.set_buffer(scommentbuffer)
                description=wizdialog.get_widget('description')
                description.set_text(self.doc['description'])
                proptype=wizdialog.get_widget('proptype')
                proptype.set_text(self.doc['proptype'])
                repeatability=wizdialog.get_widget('repeatability')
                repeatability.set_text(self.doc['repeatability'])
                propversion=wizdialog.get_widget('propversion')
                propversion.set_text(self.doc['propversion'])
                references=wizdialog.get_widget('references')
                references.set_text(self.doc['references'])
                propsite=wizdialog.get_widget('propsite')
                propsite.set_text(self.doc['propsite'])
                datepublic=wizdialog.get_widget('datepublic')
                datepublic.set_text(self.doc['datepublic'])
                name=wizdialog.get_widget('name')
                name.set_text(self.doc['name'])
                version=wizdialog.get_widget('version')
                version.set_text(self.doc['version'])

                response = wizard3.run()
                wizard3.hide()
                if response == gtk.RESPONSE_OK:
                        wizard3data = self.getfromdialog(wizdialog)
                        self.doc={'sploitcomments':wizard3data['sploitcomments'],
                                  'description':wizard3data['description'],
                                  'proptype':wizard3data['proptype'],
                                  'repeatability':wizard3data['repeatability'],
                                  'propversion':wizard3data['propversion'],
                                  'references':wizard3data['references'],
                                  'propsite':wizard3data['propsite'],
                                  'datepublic':wizard3data['datepublic'],
                                  'name':wizard3data['name'],
                                  'version':wizard3data['version']
                                  }
                        self.showWizard_finish()
                elif response == gtk.RESPONSE_REJECT:
                        self.showWizard2()

                elif response==gtk.RESPONSE_HELP:
                        help="Although it is not necesary for functionality, it is recommended that\n\
you correctly document your exploit. First, insert the header comments\n\
your exploit will have. Then fill in the DOCUMENTATION\n\
fields. Once again, you do not need to fill in all the fields.\n\
\n\
Finally, you need to set your exploit's properties.\n\
Exploits's PROPERTIES are VERY IMPORTANT if you are planning to use\n\
your exploit with CANVAS.\n\
Exploit's Properties are used by CANVAS at loading time,\n\
for populating the tools\exploits tree\n"


                        self.msgBox(help)
                        self.showWizard3()


        def showWizard4(self):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard4")
                wizard4 = wizdialog.get_widget("wizard4")
                teststring=wizdialog.get_widget('teststring')
                teststring.set_text(str(self.teststring['teststring']))

                response = wizard4.run()
                wizard4.hide()
                if response == gtk.RESPONSE_OK:
                        wizard4data = self.getfromdialog(wizdialog)
                        self.teststring['teststring'] = wizard4data['teststring']
                        self.showWizard_finish()
                elif response == gtk.RESPONSE_REJECT:
                        self.showWizard3()

        def showWizard_finish(self):
                wizdialog = gtk.glade.XML (self.gladefile,"wizard_finish")
                wizard_finish = wizdialog.get_widget("wizard_finish")
                response = wizard_finish.run()
                wizard_finish.hide()
                #set the global projectname
                self.newprojectname={'entry1':str(self.wizprojectname['entry1'])} 
                if response == gtk.RESPONSE_OK:
                        self.NewWorkspace(self.newprojectname)
                elif response == gtk.RESPONSE_REJECT:
                        self.showWizard3()

        def newproject(self):
                ndialog = gtk.glade.XML (self.gladefile,"newprojectdialog")
                newdialog = ndialog.get_widget("newprojectdialog")
                response = newdialog.run()
                newdialog.hide()
                if response == gtk.RESPONSE_OK:
                        self.newprojectname = self.getfromdialog(ndialog)
                        self.callbackip = self.newprojectname['callbackip']
                        self.callbackport = self.newprojectname['callbackport']
                        if self.newprojectname['win32'] == True:
                                self.arch ="Win32"
                        elif self.newprojectname['linux'] == True:
                                self.arch = "Linux"
                        elif self.newprojectname['solaris'] == True:
                                self.arch = "Solaris"
                        elif self.newprojectname['osx'] == True:
                                self.arch = "OSX"
                        if self.newprojectname['remote'] == True:
                                self.xtype = "remote"
                        if self.newprojectname['msrpc'] == True:
                                self.xtype = "msrpc"
                                self.dceval={}
                                self.uuidversion=""
                                self.targetfunction=0x00
                        if self.newprojectname['clientside'] == True:
                                self.xtype = "clientside"
                        try:
                                os.makedirs("VisualSpike/Projects/"+self.newprojectname['entry1'])
                        except OSError, err:
                                if err.errno == errno.EEXIST:
                                        if os.path.isdir("VisualSpike/Projects/"+self.newprojectname['entry1']):
                                                print "Project already exists"
                                                if self.newprojectname['entry1'] == "vsploit_exploit":
                                                        pass
                                                else:
                                                        self.msgBox("Project already exists\nI will continue anyway...")
                                                #self.newproject()
                                        else:
                                                print "Name exists but it is not a project directory"
                                                self.msgBox("Name exists but it is not a project directory")
                                                self.newproject()
                        self.NewWorkspace(self.newprojectname)
                        return

        def preNewWorkspace(self,event):
                #disable new project name dialog
                if self.savestatus == True:
                        ndialog = gtk.glade.XML (self.gladefile,"savedialog")
                        newdialog = ndialog.get_widget("savedialog")
                        response = newdialog.run()
                        newdialog.hide()
                        if event.get_name() == 'new2':
                                self.resetPrj()
                        if response == gtk.RESPONSE_OK:
                                self.saveState(False)
                                self.resetPrj()
                                self.newproject()
                        else:
                                self.newproject()
                else:
                        self.newproject()
                #make it fast
                #self.NewWorkspace(None)

        def resetPrj(self):
                self.pathv="VisualSpike" + os.path.sep
                self.exp=None #otherwise it uses reload() and uses old data
                self.savestatus=False
                self.Toolbar = {}
                self.mToolbar = {}
                self.cToolbar = {}
                self.plToolbar = {}
                self.xpacketlist=[]
                self.cpacketlist=[]
                self.xpacketobjs={}
                self.cpacketobjs={}
                self.objpos=[]
                self.tmpobjdic=[]
                self.host="127.0.0.1"
                self.port=80
                self.defaultarget="0x00000000"
                self.teststring={'teststring':"test string"}
                self.fdlist= {}
                self.arch="Win32"
                self.xtype="remote"
                self.targets={}
                self.targetid=0
                self.callbackip="0.0.0.0"
                self.callbackport=5555
                self.platlist=["X86", "SPARC", "PPC"]
                self.badcharentry=[]
                self.teststring={'checkbutton1':False,
                                 'teststring':"NosTestString"}
                self.doc={'sploitcomments':"Insert your header comments here",
                          'description':"",
                          'proptype':"",
                          'repeatability':"",
                          'propversion':"",
                          'references':"",
                          'propsite':"",
                          'datepublic':"",
                          'name':"",
                          'version':""
                          }
                return


        def NewWorkspace(self, newprojectname):
                self.savestatus=True
                self.fstwindow.hide()
                if self.mainscnwin!=None:
                        self.mainscnwin.hide() #when projects already exists,hide until we get the new scnwin

                self.wTree3 = gtk.glade.XML (self.gladefile, "scnwindow")
                dic_newWorkspace = {'gtk_main_quit': gtk.main_quit, 
                                    'on_quit1_activate': self.on_quit1_activate,
                                    'on_new2_activate': self.preNewWorkspace,
                                    'on_about3_activate': self.on_about1_activate,
                                    'on_quit2_activate': self.on_quit1_activate,
                                    'on_save2_activate': self.saveState,
                                    'on_open2_activate': self.loadFilechooser,
                                    'on_load_as_xpackets1_activate': self.loadFilechooser,
                                    'on_scnwindow_destroy': self.destroy,
                                    'on_et1String_activate': self.helpmenu,
                                    'on_et2Nopsled_activate': self.helpmenu,
                                    'on_et3EIP_activate': self.helpmenu,
                                    'on_et4Integer_activate': self.helpmenu,
                                    'on_et5Jump_activate': self.helpmenu,
                                    'on_et6Shellcode_activate': self.helpmenu,
                                    'on_et7Assembly_activate': self.helpmenu,
                                    'on_et8Pad2Length_activate': self.helpmenu,
                                    'on_et9BChunk_activate': self.helpmenu,
                                    'on_et91FChunk_activate': self.helpmenu,
                                    'on_ct1connect_activate': self.helpmenu,
                                    'on_ct2send_activate': self.helpmenu,
                                    'on_ct3recv_activate': self.helpmenu,
                                    'on_ct4open_activate': self.helpmenu,
                                    'on_ct5write_activate': self.helpmenu,
                                    'on_ct6read_activate': self.helpmenu,
                                    'on_ct7DCEconnect_activate': self.helpmenu,
                                    'on_ct8DCEcall_activate': self.helpmenu,
                                    'on_ptpl1If_activate': self.helpmenu,
                                    'on_ptpl2Else_activate': self.helpmenu,
                                    'on_ptpl3Print_activate': self.helpmenu,
                                    'on_ptpl4Failed_activate': self.helpmenu,
                                    'on_ptpl5Sleep_activate': self.helpmenu,
                                    'on_mt1mtcodeExploit_activate': self.helpmenu,
                                    'on_mt2mtRunExploit_activate': self.helpmenu,
                                    'on_mt3mtsetComments_activate': self.helpmenu,
                                    'on_mt4mtaddxPacket_activate': self.helpmenu,
                                    'on_mt5mtvsPDB_activate': self.helpmenu,
                                    'on_mt6mtaddzcPacket_activate': self.helpmenu,
                                    'on_mt7mtsetTest_activate': self.helpmenu,
                                    'on_mt8mtsubmit2CANVAS_activate': self.helpmenu,
                                    'on_mt9mtclearpacket_activate':self.helpmenu,

                                    }

                self.wTree3.signal_autoconnect(dic_newWorkspace)
                self.mainscnwin = self.wTree3.get_widget("scnwindow")
                self.mainscnwin.maximize()
                self.mainscnwin.set_title("Immunity VisualSpike - Project: "+self.newprojectname['entry1'])
                self.buffermenug = gtk.glade.XML(self.gladefile,"menu15")
                self.buffermenuwidget=self.buffermenug.get_widget("menu15")
                delete_buffer=self.buffermenug.get_widget("delete_buffer1")
                delete_buffer.connect("activate", self.delete_buffer)
                object_comments=self.buffermenug.get_widget("object_comments1")
                object_comments.connect("activate", self.ObjectComment)
                self.separator1=self.buffermenug.get_widget("separator1")
                self.separator1.hide()
                self.add_target=self.buffermenug.get_widget("add_target1")
                self.add_target.connect("activate", self.addtarget)

                self.add_target.hide()
                edit_buffer=self.buffermenug.get_widget("edit_buffer1")
                edit_buffer.hide() # not in this version
                self.debug = self.wTree3.get_widget("textview1")
                self.exploitlog = self.wTree3.get_widget("textview2")
                self.connectionlog = self.wTree3.get_widget("textview3")
                hbox_xpacket = self.wTree3.get_widget("hbox6")
                self.sw2 = gtk.ScrolledWindow()
                self.sw2.set_policy(gtk.POLICY_AUTOMATIC,gtk.POLICY_NEVER)
                self.hboxxpacket=gtk.HBox(homogeneous=False, spacing=0)
                self.hboxxpacket.show()
                self.sw2.add_with_viewport(self.hboxxpacket)
                self.sw2.show()
                hbox_xpacket.pack_start(self.sw2,expand=True, padding=0)
                self.hboxcpacket = self.wTree3.get_widget("hbox5")
                hbox_xpacket.set_homogeneous(False)
                self.hboxcpacket.set_homogeneous(True)
                self.addcpacket(None)
                #if we dont came from loadfilechooser, then we want a xpacket created by dfault
                if newprojectname:
                        self.addxpacket(None)
                #self.scnwindow = self.wTree.get_widget("scnwindow")

                self.createToolbar()
                #dicwtree3 = {'on_button1_clicked': self.addxpacket}
                #self.wTree3.signal_autoconnect(dicwtree3)
                button1 = self.wTree3.get_widget("button1")
                button1.connect("drag_data_received", self.receiveCallbacktrashbin)
                button1.drag_dest_set(gtk.DEST_DEFAULT_MOTION |gtk.DEST_DEFAULT_HIGHLIGHT |gtk.DEST_DEFAULT_DROP,self.TARGETS, gtk.gdk.ACTION_MOVE)

        def helpmenu(self,event):
                clase = __import__(event.get_name()[2:]) 
                tool = clase.Toolobject()
                self.msgBox(tool.Help())


        def __LoadToolbar(self, toolbarname, toolbarinstance = None, subpathname = None, misc = False):
                if not subpathname:
                        subpathname = toolbarname
                for name in sorted(os.listdir(self.pathv + subpathname)):
                        if name in ["CVS"] or name[0] == '.' or not os.path.isdir(self.pathv + subpathname):
                                continue
                        if self.xtype!="msrpc" and name in ["7DCEconnect","8DCEcall"]: #if not an msrpc exploit, we dont need dce objects
                                continue
                        if self.xtype=="msrpc" and name in ["1connect","2send","3recv"]:
                                continue  #no connect/send/recv if the project is msrpc

                        ##Hide the heap related buttons if heap env var
                        ## not set
                        if not os.getenv("VS_BUFFER") and name in ["61doallocate", "62dooverwrite", "63memleak", "64free"]:
                                continue
                        
                        try:
                                sys.path.append(self.pathv + subpathname + os.path.sep + name)
                                clase = __import__(name) 
                                if misc:
                                        self.misctoolbarOrder(clase, name)
                                else:
                                        self.toolbarOrder(clase, name, toolbarinstance, toolbarname)
                        except ImportError, msg:
                                print msg
                                continue


        def createToolbar(self):
                self.visualsploittoolbar = self.wTree3.get_widget("toolbar2")
                self.visualsploittoolbar.set_style(gtk.TOOLBAR_ICONS)
                self.visualsploittoolbar.set_show_arrow(False)
                self.vstoolbartooltips = gtk.Tooltips()
                self.misctoolbartooltips = gtk.Tooltips()
                self.misctoolbar = self.wTree3.get_widget("toolbar3")
                self.misctoolbar.set_style(gtk.TOOLBAR_ICONS)
                self.misctoolbar.set_show_arrow(False)
                self.conntoolbar = self.wTree3.get_widget("toolbar4")
                self.conntoolbar.set_style(gtk.TOOLBAR_ICONS)
                self.conntoolbar.set_show_arrow(False)
                self.pltoolbar = self.wTree3.get_widget("toolbar5")
                self.pltoolbar.set_style(gtk.TOOLBAR_ICONS)
                self.pltoolbar.set_show_arrow(False)

                self.__LoadToolbar("ExploitToolbar", self.Toolbar)
                self.__LoadToolbar("ConnToolbar", self.cToolbar)
                self.__LoadToolbar("ProtocolLogicToolbar", self.plToolbar)
                self.__LoadToolbar("MiscToolbar", misc = True)


        def toolbarOrder(self,clase,x,thetoolbar,toolbarpath):
                # Here we create the misc toolbar based on the .py
                thetoolbar[ clase.Toolobject.NAME ] = ( clase, x )
                # Fill the toolbar with the plug-in's object
                iconw = gtk.Image() 
                iconw.set_from_file(self.pathv+"./%s/%s/%s" % (toolbarpath,x, clase.Toolobject.filexpm ))
                toolbarbutton = gtk.ToolButton(iconw,clase.Toolobject.NAME)
                if toolbarpath == "ExploitToolbar":
                        toolbarbutton.set_tooltip(self.vstoolbartooltips,clase.Toolobject.button_tooltip)
                        self.visualsploittoolbar.insert(toolbarbutton,-1)
                        toolbarbutton.connect("drag_data_get", self.sendCallback)
                elif toolbarpath == "ConnToolbar":
                        toolbarbutton.set_tooltip(self.misctoolbartooltips,clase.Toolobject.button_tooltip)
                        self.conntoolbar.insert(toolbarbutton,-1)
                        toolbarbutton.connect("drag_data_get", self.sendCallback)
                elif toolbarpath == "ProtocolLogicToolbar":
                        toolbarbutton.set_tooltip(self.misctoolbartooltips,clase.Toolobject.button_tooltip)
                        self.pltoolbar.insert(toolbarbutton,-1)
                        toolbarbutton.connect("drag_data_get", self.sendCallbackpl)
                toolbarbutton.drag_source_set(gtk.gdk.BUTTON1_MASK, self.TARGETS, gtk.gdk.ACTION_MOVE)
                toolbarbutton.set_use_drag_window(True)
                toolbarbutton.show()
                iconw.show()


        def misctoolbarOrder(self,clase,x):
                # Here we create the misc toolbar based on the .py
                self.mToolbar[ clase.Toolobject.NAME ] = ( clase, x )
                # Fill the toolbar with the plug-in's object
                iconw = gtk.Image() 
                iconw.set_from_file("VisualSpike/MiscToolbar/%s/%s" % (x, clase.Toolobject.filexpm ))
                toolbarbutton = gtk.ToolButton(iconw,clase.Toolobject.NAME)
                toolbarbutton.set_tooltip(self.misctoolbartooltips,clase.Toolobject.button_tooltip)
                self.misctoolbar.insert(toolbarbutton,-1)
                toolbarbutton.show()
                iconw.show()

                devlog("vs", "Toolbar button label: %s"%toolbarbutton.get_label())

                if toolbarbutton.get_label() == "addxpacket":
                        toolbarbutton.connect("clicked",self.addxpacket)
                elif toolbarbutton.get_label() == "addzcpacket":
                        toolbarbutton.connect("clicked",self.addcpacket)
                elif toolbarbutton.get_label() == "codeExploit":
                        toolbarbutton.connect("clicked",self.generateVsploitCode)
                elif toolbarbutton.get_label() == "RunExploit":
                        toolbarbutton.connect("clicked",self.runExploit)
                elif toolbarbutton.get_label() == "submit2CANVAS":
                        toolbarbutton.connect("clicked",self.submit2CANVAS)
                elif toolbarbutton.get_label() == "clearpacket":
                        toolbarbutton.connect("clicked",self.clearpacket)
                elif toolbarbutton.get_label() == "calculator":
                        toolbarbutton.connect("clicked",self.calcWindow)
                elif toolbarbutton.get_label() == "setComments":
                        toolbarbutton.connect("clicked",self.setComments)
                        try: 
                                (clase, directory) = self.mToolbar["setComments"]
                                self.toolcomment = clase.Toolobject()
                        except KeyError:
                                print "COULD NOT INSTANCIATE TOOL OBJECT"
                elif toolbarbutton.get_label() == "setTest":
                        toolbarbutton.connect("clicked",self.setTest)
                        try:
                                (clase, directory) = self.mToolbar["setTest"]
                                self.toolteststring = clase.Toolobject()
                        except KeyError:
                                print "COULD NOT INSTANCIATE TOOL OBJECT"
                elif toolbarbutton.get_label() == "vsPDB":
                        toolbarbutton.connect("clicked",self.initPDB)
                        try:
                                (clase,directory) = self.mToolbar["vsPDB"]
                                self.vsPDB = clase.Toolobject()
                        except KeyError:
                                print "COULD NOT INSTANCIATE TOOL OBJECT"
                else:
                        pass

        def submit2CANVAS(self,event):
                print "not yet =)"
                self.msgBox("Submit to CANVAS WORLD SERVICE is currently disabled at version 1.0")

        def clearpacket(self,event):
                """remove buffers from every exploit packet"""
                dlg=gtk.MessageDialog(type=gtk.MESSAGE_QUESTION,buttons=gtk.BUTTONS_OK_CANCEL,message_format="Are you sure you want to clear all?")
                resp=dlg.run()
                dlg.destroy()
                if resp==gtk.RESPONSE_OK:
                        for a in self.xpacketlist:
                                a.get_model().clear()
                                self.ModBufSize(a)
                                self.ModBuf2pad(a)





        def listenerprogressbar(self,event,wTree):
                self.listenerbar = wTree.get_widget("listenerbar")
                self.timer = gobject.timeout_add (300, progress_timeout, self)
                self.listenerbar.set_text("Please wait...executing")
                #self.listenerbar.pulse()


        #there is a bug destroying the progressbar where timer is over other thread
        def destroy_progress(self, widget, data=None):
                # print "SELF.TIMER %s" %str(self.timer)
                gobject.source_remove(self.timer)
                self.timer = 0


        def initPDB(self,event):
                (clase, directory) = self.mToolbar["vsPDB"]
                wTree4=gtk.glade.XML (self.pathv+ "./MiscToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                dialog = wTree4.get_widget("dialog1")
                try:
                        self.vsPDB.setDialog(wTree4,self.options) #if we already have this
                except:
                        pass 
                if dialog == None:
                        print "ERROR"
                response = dialog.run()
                        # if response anything else than OK, we dont do anything
                dialog.hide()
                if response == gtk.RESPONSE_OK:
                        self.options = self.getfromdialog(wTree4)
                        self.vsPDB.setArg(self.options)
                        self.vsPDB.Connect()

        def setComments(self,event):
                (clase, directory) = self.mToolbar["setComments"]
                wTree4=gtk.glade.XML (self.pathv+"./MiscToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                dialog = wTree4.get_widget("dialog1")
                self.toolcomment.setDialog(wTree4,self.doc)
                #print self.toolcomment
                if dialog == None:
                        print "ERROR"
                response = dialog.run()
                # if response anything else than OK, we dont do anything
                dialog.hide()
                if response == gtk.RESPONSE_OK:
                        self.doc = self.getfromdialog(wTree4)
                        devlog("vs", "Setting documentation string to %s"%self.doc)
                        self.toolcomment.setArg(self.doc)
                return 

        def setTest(self,event):
                (clase, directory) = self.mToolbar["setTest"]
                wTree4=gtk.glade.XML (self.pathv+"./MiscToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                dialog = wTree4.get_widget("dialog1")
                self.toolteststring.setDialog(wTree4,self.teststring)
                if dialog == None:
                        print "ERROR"
                response = dialog.run()
                        # if response anything else than OK, we dont do anything
                dialog.hide()
                if response == gtk.RESPONSE_OK:
                        self.teststring = self.getfromdialog(wTree4)
                        self.toolteststring.setArg(self.teststring)



        def addxpacket(self,event):
                if len(self.xpacketlist) > 3:
                        print "More xpackets? edit me"
                else:
                        xpacketvbox = gtk.VBox(homogeneous=False, spacing=0)
                        xpacketvbox.show()
                        sw = gtk.ScrolledWindow()
                        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)

                        #self.hboxxpacket.pack_start(xpacketvbox,expand=True, padding=15)
                        self.hboxxpacket.pack_start(xpacketvbox,expand=False, padding=15)
                        #self.sw.add(xpacketvbox)
                        self.xpacketlist[len(self.xpacketlist):] = [gtk.TreeView()]
                        self.xpacketmodel = gtk.ListStore(str, str, int, gobject.TYPE_PYOBJECT)
                        self.xpacketlist[-1].set_model(self.xpacketmodel)
                        self.xpacketlist[-1].set_headers_visible(True)
                        self.xpcell = gtk.CellRendererText()
                        self.xpcolumn = gtk.TreeViewColumn(N_(' Buffer ')+str(len(self.xpacketlist)), self.xpcell, text=0, background=1, height=2)
                        self.xpcolumn.set_fixed_width(100)
                        self.xpacketlist[-1].append_column(self.xpcolumn)
                        sw.add(self.xpacketlist[-1])
                        sw.show()

                        xpacketvbox.pack_start(sw,expand=True, padding=0)
                        self.xpacketlist[-1].show()
                        self.xpacketlist[-1].enable_model_drag_source( gtk.gdk.BUTTON1_MASK,
                                                                       self.TARGETS,
                                                                       gtk.gdk.ACTION_DEFAULT|
                                                                       gtk.gdk.ACTION_MOVE)
                        self.xpacketlist[-1].enable_model_drag_dest(self.TARGETS, gtk.gdk.ACTION_DEFAULT)
                        self.xpacketlist[-1].connect("drag_data_received", self.receiveCallbackxpacket)
                        self.xpacketlist[-1].connect("drag_data_get", self.sendCallbackxpacket)
                        self.xpacketlist[-1].connect("button_press_event",self.rowclickxpacket)
                        self.badcharentry[len(self.badcharentry):] = [gtk.Entry(max=255)]
                        self.badcharentry[-1].set_text("")
                        self.badcharentry[-1].show()
                        badhvox = gtk.HBox(homogeneous=False, spacing=0)
                        badhvox.show()
                        badhvox.pack_start(self.badcharentry[-1],expand=False, padding=0)
                        helpimage = gtk.Image()
                        helpimage.set_from_file(self.pathv+"./pixmaps/help.ico")
                        helpimage.show()
                        button = gtk.Button()
                        button.set_image(helpimage)
                        button.connect("clicked", self.msgBox)
                        button.show()
                        badhvox.pack_end(button,expand=False,padding=0)
                        xpacketvbox.pack_start(badhvox,expand=False, padding=0)

        def addcpacket(self,event):
                if len(self.cpacketlist) < 1: 
                        self.cpacketlist[len(self.cpacketlist):] = [gtk.TreeView()]
                        sw = gtk.ScrolledWindow()
                        sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_AUTOMATIC)
                        self.cpacketmodel = gtk.TreeStore(str,str,gobject.TYPE_PYOBJECT)
                        self.cpacketlist[-1].set_model(self.cpacketmodel)
                        self.cpacketlist[-1].set_headers_visible(True)
                        self.cpcell = gtk.CellRendererText()
                        if len(self.cpacketlist) == 1:
                                self.cpcolumn=gtk.TreeViewColumn(N_("Program Flow  "),self.cpcell, text=0)
                        else:
                                self.cpcolumn=gtk.TreeViewColumn(N_("Program Flow %s")%str(len(self.cpacketlist)),self.cpcell, text=0)
                        #self.cpcolumn.set_fixed_width(300)
                        #self.cpcolumn.set_max_width(100)
                        self.cpacketlist[-1].append_column(self.cpcolumn)
                        self.cpcell=gtk.CellRendererText()
                        #we are not showing socket info in basic edition
                        #self.cpcolumn=gtk.TreeViewColumn("Info",self.cpcell,text=1)
                        #self.cpacketlist[-1].append_column(self.cpcolumn)
                        sw.add(self.cpacketlist[-1])
                        sw.show()
                        self.hboxcpacket.pack_start(sw,expand=True, padding=0)
                        self.cpacketlist[-1].show()
                        self.cpacketlist[-1].enable_model_drag_source( gtk.gdk.BUTTON1_MASK,
                                                                       self.TARGETS,gtk.gdk.ACTION_MOVE)
                        self.cpacketlist[-1].enable_model_drag_dest(self.TARGETS, gtk.gdk.ACTION_MOVE)
                        self.cpacketlist[-1].connect("drag_data_received", self.receivedcallbackcpacket)
                        self.cpacketlist[-1].connect("drag_data_get", self.sendCallbackcpacket)
                        self.cpacketlist[-1].connect("button_press_event",self.rowclickcpacket)

                        #model=self.liststore

                else:
                        print "Having more than one Program Flow is currently disabled at V1.0"

        def delxpacket(self,event,packetlist):
                #Nothing is created, nothing is lost, all is transformed
                #packetlist.hide()
                pass





        def receiveCallbacktrashbin(self,widget, context, x, y, selection, targetType,time):
                pass

        def getfromdialog(self, widget):
                """get values from dialogs"""

                arguments = {}
                # Lets get the objects list in the widget
                widgetlist = widget.get_widget_prefix("")        
                for a in widgetlist:
                        name = a.name

                        if type(a) == gtk.SpinButton:
                                arguments[name] = int(a.get_value())
                        elif type(a) in [gtk.CheckButton, gtk.RadioButton, gtk.ComboBoxEntry ]:
                                arguments[name] = a.get_active()
                        elif type(a)== gtk.Entry:
                                arguments[name] = a.get_text()
                        elif type(a) == gtk.ComboBox:
                                try:
                                        #pyGTK 2.6, I believe.
                                        if hasattr(a, 'get_active_text'):
                                                # gtk.ComboBox.get_active_text
                                                # NOTE: This method is available in PyGTK 2.6 and above
                                                # NOTE: that you can only use this function with combo
                                                # boxes constructed with the gtk.combo_box_new_text() function.
                                                text = a.get_active_text()
                                        else:
                                                text = a.get_model().get_value(a.get_active_iter(),0)
                                        arguments[name]=text
                                except:
                                        pass # Python 2.4?

                        elif type(a) == gtk.TextView:
                                asmbuffer=a.get_buffer()
                                start_iter, end_iter=asmbuffer.get_bounds()
                                arguments[name]=asmbuffer.get_text(start_iter,end_iter,include_hidden_chars=True)
                                #print arguments[name]

                return arguments





        #toolbar buttons sendcallback
        def sendCallback(self,widget, context, selection, targetType, eventTime):

                str = "1@"+widget.get_label()


                selection.set(selection.target, 8, str)

        def sendCallbackpl(self,widget, context, selection, targetType, eventTime):

                str = "2@"+widget.get_label()
                selection.set(selection.target, 8, str)





        def sendCallbackxpacket(self,widget, context, selection, targetType, eventTime):
                xpacketselection = widget.get_selection()
                model, iter = xpacketselection.get_selected()
                #if there is a better way of doing that, please let me know
                data = "0@"+str(self.xpacketlist.index(widget))+"@"+str(model.get_value(iter, 0)) +"@"+str(model.get_value(iter, 1))+"@"+str(model.get_value(iter, 2))
                #data format: fromwhere@packetlist.index@name@color@size
                # fromwhere != 0 toolbar
                # fromwhere not !=0 other widget
                selection.set(selection.target, 8, data)


        def sendCallbackcpacket(self,widget, context, selection, targetType, eventTime):
                xpacketselection = widget.get_selection()
                model, iter = xpacketselection.get_selected()
                #if there is a better way of doing that, please let me know
                data = "0@"+str(self.cpacketlist.index(widget))+"@"+str(model.get_value(iter, 0)) +"@"+str(model.get_value(iter, 1))
                selection.set(selection.target, 8, data)


        def setDefaultTarget(self, eip):
                self.targets[0]=["default target",eip]    
                return 

        def receiveCallbackxpacket(self,widget, context, x, y, selection, targetType,time):
                #badchar = self.get_badchars(self.badcharentry)
                selectiondata = selection.data.split("@")
                drophere = widget.get_dest_row_at_pos(x, y)
                liststore = widget.get_model()

                if selectiondata[0] !="0":
                        try: 
                                (clase, directory) = self.Toolbar[selection.data[2:]]
                                tool = clase.Toolobject()
                                tool.gui=self
                        except KeyError:
                                print "<DEBUG>: Apparently, someone is trying to drop something that is not on the Toolbar (%s)" % str(selection.data)
                                debug = "<DEBUG>: Apparently, someone is trying to drop something that is not on the Toolbar (%s)" % str(selection.data)
                                self.debugme(debug,self.debug)
                                return
                # HERE IS WHERE WE RUN THE DIALOG, we know how to get the dialog by using:
                #
                # path = "ExploitToolbar/%s/%s" % directory, clase.GLADE_DIALOG
                #

                        wTree4=gtk.glade.XML (self.pathv+"./ExploitToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                        dic = {'on_button2_clicked': (self.showHelpFromObject,tool)
                               }
                        wTree4.signal_autoconnect(dic)
                        try:
                                badchardetected=wTree4.get_widget('badchardetected')  #we try to get badchardetected from toolx dialogs
                                badchars = self.get_badchars(self.badcharentry,widget)
                                checkbadchar = wTree4.get_widget('checkbadchar')
                                checkbadchar.connect('changed',self.badcharDetect,badchars,badchardetected)
                        except:
                                pass
                        if hasattr(tool, "INDEXED"):
                                if not self.fdlist.has_key(tool.INDEXED):
                                        self.fdlist[ tool.INDEXED ] = []
                                fdlist = self.fdlist[ tool.INDEXED ]
                        else:
                                fdlist = []

                        dialog = wTree4.get_widget("dialog1")
                        tool.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                        tool.preparedialog(wTree4,self.platlist,widget,self.get_badchars(self.badcharentry,widget),self.arch)
                        if dialog == None:
                                print "ERROR"
                        response = dialog.run()

                        # if response anything else than OK, we dont do anything
                        dialog.hide()
                        if response == gtk.RESPONSE_OK:
                                ret_from_dialog = self.getfromdialog(wTree4)
                                if tool.NAME == "EIP" or tool.NAME == "Integer":
                                        try:
                                                v=int(ret_from_dialog["value"],16)
                                        except ValueError:
                                                self.msgBox("Incorrect value for %s" % tool.NAME)
                                                return -1
                                tool.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                                tool.setArg(ret_from_dialog)
                                NumberofXp=tool.setNumber(widget)
                                if tool.NAME =="EIP":
                                        eip=tool.getDefaultTarget()
                                        if eip=="0x":
                                                devlog("eip", "User failed to enter in an EIP")
                                                eip="0x0"
                                        eip=dInt(eip)
                                        devlog("eip", "Setting EIP to: %x"%eip)
                                        self.setDefaultTarget(eip)

                                if drophere:
                                        path, position = drophere
                                        iter = liststore.get_iter(path)
                                        if (position == gtk.TREE_VIEW_DROP_BEFORE
                                            or position == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE):
                                                #newcolor= "#%06x" % (int(tool.color[1:], 16) + 0x10*int(NumberofXp))

                                                percent=0.05*int(NumberofXp)

                                                color = int(tool.color[1:], 16)

                                                blue = color  & 0xff
                                                green = (color >> 8) & 0xff
                                                red = (color >> 16) & 0xff
                                                if blue * (1+percent) > 255:
                                                        nblue = 255
                                                else:
                                                        nblue = blue * (1+percent)
                                                if green * (1+percent) > 255:
                                                        ngreen = 255
                                                else:
                                                        ngreen= green * (1+percent)
                                                if red * (1+percent) > 255:
                                                        nred = 255
                                                else:
                                                        nred= red * (1+percent)

                                                newcolor= "#%02x%02x%02x" % (nred, ngreen, nblue)
                                                showtext=tool.Show()
                                                alltext= tool.NAME+" #%s\n"%str(NumberofXp)+showtext
                                                height = get_pixel_height(widget, alltext)
                                                liststore.insert_before(iter, [alltext,newcolor,int(height),tool])



                                        elif (position == gtk.TREE_VIEW_DROP_AFTER
                                              or position == gtk.TREE_VIEW_DROP_INTO_OR_AFTER):

                                                percent=0.05*int(NumberofXp)
                                                color = int(tool.color[1:], 16)
                                                blue = color  & 0xff
                                                green = (color >> 8) & 0xff
                                                red = (color >> 16) & 0xff
                                                if blue * (1+percent) > 255:
                                                        nblue = 255
                                                else:
                                                        nblue = blue * (1+percent)
                                                if green * (1+percent) > 255:
                                                        ngreen = 255
                                                else:
                                                        ngreen= green * (1+percent)
                                                if red * (1+percent) > 255:
                                                        nred = 255
                                                else:
                                                        nred= red * (1+percent)
                                                newcolor= "#%02x%02x%02x" % (nred, ngreen, nblue)
                                                alltext=tool.NAME+" #%s\n"%str(NumberofXp)+tool.Show()
                                                height=get_pixel_height(widget, alltext)
                                                liststore.insert_after(iter, [alltext,newcolor,height,tool])

                                else:
                                        percent=0.05*int(NumberofXp)

                                        color = int(tool.color[1:], 16)

                                        blue = color  & 0xff
                                        green = (color >> 8) & 0xff
                                        red = (color >> 16) & 0xff
                                        if blue * (1+percent) > 255:
                                                nblue = 255
                                        else:
                                                nblue = blue * (1+percent)
                                        if green * (1+percent) > 255:
                                                ngreen = 255
                                        else:
                                                ngreen= green * (1+percent)
                                        if red * (1+percent) > 255:
                                                nred = 255
                                        else:
                                                nred= red * (1+percent)

                                        newcolor= "#%02x%02x%02x" % (nred, ngreen, nblue)
                                        alltext=tool.NAME+" #%s\n"%str(NumberofXp)+tool.Show()
                                        iter = liststore.append()        
                                        height = get_pixel_height(widget, alltext)
                                        liststore.set_value(iter, 0, alltext)

                                        liststore.set_value(iter, 1, newcolor)            
                                        liststore.set_value(iter, 2, height)
                                        liststore.set_value(iter,3,tool)

                                i=0
                                for a in liststore:
                                        i=i+1
                                        if a[3] == tool:
                                                iter = liststore.get_iter(i-1)

                                if tool.NAME =="Jump":
                                        tool.getOffset()
                                        alltext=tool.NAME+" #%s\n"%str(NumberofXp)+tool.Show()
                                        liststore.set_value(iter, 0, alltext)
                                elif tool.NAME == "Pad2Length":
                                        tool.getPad()
                                        alltext=tool.NAME+" #%s\n"%str(NumberofXp)+tool.Show()
                                        liststore.set_value(iter, 0, alltext)



                else:
                        #else, we are dropping from a xpacket 

                        xpacketselection = self.xpacketlist[int(selectiondata[1])].get_selection()
                        model, iter = xpacketselection.get_selected()
                        tool = model.get_value(iter,3)

                        if tool.NAME =="Jump":
                                tool.getOffset()
                        elif tool.NAME == "Pad2Length":
                                tool.getPad()

                        if tool.NAME =="EIP":
                                eip=tool.getDefaultTarget()
                                if eip=="0x": eip="0x0" #check for non-used EIP value
                                eip=dInt(eip)
                                devlog("eip", "2: Setting EIP to: %x"%eip)
                                self.setDefaultTarget(eip)
                        alltext=selectiondata[2]
                        height=get_pixel_height(widget,alltext)
                        if drophere:
                                path, position = drophere
                                iter = liststore.get_iter(path)
                                if (position == gtk.TREE_VIEW_DROP_BEFORE
                                    or position == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE):

                                        liststore.insert_before(iter, [alltext,selectiondata[3],height,tool])

                                else:
                                        liststore.insert_after(iter, [alltext,selectiondata[3],height,tool])
                        else:
                                liststore.append([alltext,selectiondata[3],height,tool])

                        if context.action == gtk.gdk.ACTION_MOVE:
                                context.finish(True, True, time)
                self.ModBufSize(widget)
                self.ModBuf2pad(widget)
                #if the object is linked, get the new values
                if tool.getLinkState() == True:
                        object=tool.linkedObj()
                        self.ModLinkedObj(object,widget.get_model())
                self.CheckObjsInTree(widget.get_model())
                return


        def CheckObjsInTree(self,model):
                """check the objects positions inside exploit packet
        if any change happens, then we check linked objs"""
                self.tmpobjdic=[] #this is a list, not a dict?
                for a in model:
                        #should we get rid of the : here?
                        #ok, changed to .append () to make life easier
                        self.tmpobjdic.append(a[3])
                for a in self.tmpobjdic:
                        if a.getLinkState() == True:
                                if a not in self.objpos:
                                        devlog("checkobjsintree", "We've linked to an object that has been removed - i.e. some jump used to point to us, but is now deleted")
                                        continue
                                if self.tmpobjdic.index(a) != self.objpos.index(a):

                                        object=a.linkedObj()
                                        self.ModLinkedObj(object,model)
                self.objpos=self.tmpobjdic


        def ModLinkedObj(self,object,model):
                """mod runtime linked/linkers objs"""
                i=0
                for a in model:
                        i=i+1
                        if a[3] == object and a[3].NAME == "Jump":
                                iter = model.get_iter(i-1)
                                object.getOffset()
                                alltext=object.NAME+" #%s\n"%str(object.getNumber())+object.Show()
                                model.set_value(iter, 0, alltext)
                        elif a[3] == object and a[3].NAME == "Pad2Length":
                                iter = model.get_iter(i-1)
                                object.getPad()
                                alltext=object.NAME+" #%s\n"%str(object.getNumber())+object.Show()
                                model.set_value(iter, 0, alltext)



        def ModBufSize(self,treeview):
                """we iterate the liststore to get all objects size
        and set the buffer size runtime"""
                for a in self.xpacketlist:
                        i=0
                        bufsize=0
                        treeviewcolumn = a.get_column(0)
                        model=a.get_model()
                        for b in model:
                                bufsize+=b[3].getSize()
                        packet = self.xpacketlist.index(a)+1
                        treeviewcolumn.set_title(N_(" Buffer %s - Size %s bytes") %(str(packet),str(bufsize)))

        def ModBuf2pad(self,treeview):
                """ modify pad2len if any linked treeview"""
                for a in self.xpacketlist:
                        i=0
                        treeviewcolumn = a.get_column(0)
                        model=a.get_model()
                        for x in model:
                                i=i+1
                                if x[3].NAME=="Pad2Length":
                                        pad2len=x[3]
                                        buffer2pad=x[3].getBuffer().split(" ")[1]

                                        for b in self.xpacketlist:
                                                bufsize2pad=0
                                                acolumn = b.get_column(0)
                                                try:
                                                        if str(buffer2pad) == str(acolumn.get_title().split(" ")[2]):
                                                                packet2pad = b
                                                                model2pad = b.get_model()
                                                                for objects2pad in model2pad:
                                                                        bufsize2pad+=objects2pad[3].getSize()
                                                                iter2pad = model.get_iter(i-1)
                                                                if pad2len.padbytes < bufsize2pad:
                                                                        pad2len = bufsize2pad
                                                                pad2len.getPad()
                                                                alltext=pad2len.NAME+" #%s\n"%str(pad2len.getNumber())+pad2len.Show()
                                                                model.set_value(iter2pad, 0, alltext)
                                                except:
                                                        pass


                        #i=0
                        #second pass, we
                        #for c in model:
                                #i=i+1
                                #if c[3].NAME=="Pad2Length":
                                        #if str(c[3].getBuffer()) != str(treeviewcolumn.get_title().split("-")[0][:-1]):
                                                #print "buffer a paddear %s" % str(c[3].getBuffer())
                                                #print "buffer actual %s" % str(treeviewcolumn.get_title().split("-")[0][:-1])
                                                ##if c[3].getBuffer() == treeview:
                                                #iter = model.get_iter(i-1)
                                                #if c[3].padbytes < bufsize:
                                                        #c[3].padbytes = bufsize
                                                #c[3].getPad()
                                                #alltext=c[3].NAME+" #%s\n"%str(c[3].getNumber())+c[3].Show()
                                                #model.set_value(iter, 0, alltext)



        #receivecallbackcpacket is still a testing function
        def receivedcallbackcpacket(self,treeview, drag_context, x, y,selection, info, eventtime):
                #print "received %s" %selection.data
                selectiondata = selection.data.split("@")
                if selectiondata[0] !="0":
                        #print "from cTOOLBAR"
                        if selectiondata[0] == "1":
                                try: 
                                        #print "selection.data %s" %selection.data[2:]
                                        (clase, directory) = self.cToolbar[selection.data[2:]]
                                except KeyError:
                                        print "<DEBUG>: Apparently, someone is trying to drop something that is not on the cPacket Toolbar (%s)" % str(selection.data[2:])
                                        debug = "<DEBUG>: Apparently, someone is trying to drop something that is not on the cPacket Toolbar (%s)" % str(selection.data[2:])
                                        self.debugme(debug,self.debug)
                                        return
                                tool = clase.Toolobject()
                                tool.gui=self 
                                wTree5=gtk.glade.XML (self.pathv+"./ConnToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                                dic = {'on_button2_clicked': (self.showHelpFromObject,tool),
                                       }
                                wTree5.signal_autoconnect(dic)
                                dialog = wTree5.get_widget("dialog1")
                                if hasattr(tool, "INDEXED"): 
                                        if not self.fdlist.has_key( tool.INDEXED):
                                                self.fdlist[ tool.INDEXED ] = []
                                        fdlist = self.fdlist[ tool.INDEXED ] 
                                        if hasattr(tool, "INDEX_ADD"):
                                                self.fdlist[ tool.INDEXED ].append( "%d" % (len(self.fdlist[ tool.INDEXED ])+1) )
                                else:
                                        fdlist= []
                                #if tool.NAME == "connect" or tool.NAME == "open":
                                        #a new connect, a new fd
                                        #print "este es el len %s" %len(self.fdlist)
                                        #self.fdlist[len(self.fdlist):] = str(len(self.fdlist) + 1)

                                tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                tool.preparedialog(wTree5,self.xpacketlist, fdlist)

                                if dialog == None:
                                        print "ERROR"
                                response = dialog.run()
                                # if response is cancel, we should remove the fd
                                dialog.hide()
                                if response == gtk.RESPONSE_OK:
                                        ret_from_dialog = self.getfromdialog(wTree5)
                                        #print ret_from_dialog
                                        
                                        ret_from_dialog['fdlist'] = len(fdlist)
                                        tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                        tool.setArg(ret_from_dialog)
                                        NumberofCp=tool.setNumber(treeview)
                                        if tool.NAME == "connect" or tool.NAME == "open":
                                                #make global host and port
                                                #if name == open, then host would be filename
                                                self.host = tool.getHost()
                                                try:
                                                        self.port = tool.getPort()
                                                except:
                                                        pass
                                        if tool.NAME == "DCEconnect":
                                                self.dceval=tool.get_dceval()



                                        model = treeview.get_model()

                                        if not treeview.get_dest_row_at_pos(x, y) == None:
                                                target_path, drop_position = treeview.get_dest_row_at_pos(x, y)
                                                model, source = treeview.get_selection().get_selected()
                                                target = model.get_iter(target_path)
                                                #print "source %s" %source
                                                #print "target %s" %target
                                                #print "dropped into something"
                                                iter=self.insert_row(model,target,tool.Show()+" #%s"%str(NumberofCp),"FD: %s" %tool.cfd,tool,drop_position,target_path,treeview)
                                        else:
                                                #print "dropped into nothing"
                                                iter=self.insert_row(model,None,tool.Show()+" #%s"%str(NumberofCp),"FD: %s" %tool.cfd,tool,drop_position=None,target_path=None,treeview=None)
                                else:
                                        #we pressed cancel
                                        if hasattr(tool, "INDEXED") and hasattr(tool, "INDEX_ADD"):
                                                #remove the unused fd
                                                if self.fdlist.has_key(tool.INDEXED):
                                                        if self.fdlist[tool.INDEXED]:
                                                                self.fdlist[tool.INDEXED].pop(-1)
                                                #self.fdlist[len(self.fdlist)-1:len(self.fdlist)] = []
                        elif selectiondata[0] =="2":
                                #print "comes from protocol logic"
                                try: 
                                        #print "selection.data %s" %selection.data[2:]
                                        (clase, directory) = self.plToolbar[selection.data[2:]]
                                except KeyError:
                                        print "<DEBUG>: Apparently, someone is trying to drop something that is not on the cpacket Toolbars (%s)" % str(selection.data[2:])
                                        debug = "<DEBUG>: Apparently, someone is trying to drop something that is not on the cPacket Toolbars (%s)" % str(selection.data[2:])
                                        self.debugme(debug,self.debug)
                                        return
                                tool = clase.Toolobject()
                                wTree5=gtk.glade.XML (self.pathv+"./ProtocolLogicToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                                dic = {'on_button2_clicked': (self.showHelpFromObject,tool),
                                       }
                                wTree5.signal_autoconnect(dic)
                                dialog = wTree5.get_widget("dialog1")
                                if hasattr(tool, "INDEXED"): 
                                        if not self.fdlist.has_key( tool.INDEXED):
                                                self.fdlist[ tool.INDEXED ] = []
                                        fdlist = self.fdlist[ tool.INDEXED ] 
                                        if hasattr(tool, "INDEX_ADD"):
                                                self.fdlist[ tool.INDEXED ].append( "%d" % (len(self.fdlist[ tool.INDEXED ])+1) )
                                else:
                                        fdlist= []
                                
                                #print "preparedialog"
                                #tool.preparedialog(wTree5,self.xpacketlist,self.fdlist)
                                tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                tool.preparedialog(wTree5,treeview)
                                #print "dialogo de %s preparado" %tool.NAME

                                if dialog == None:
                                        print "ERROR"
                                response = dialog.run()
                                # if response is cancel, we should remove the fd
                                dialog.hide()
                                if response == gtk.RESPONSE_OK:
                                        ret_from_dialog = self.getfromdialog(wTree5)
                                        #print ret_from_dialog
                                        tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                        ret_from_dialog['fdlist'] = len(fdlist)
                                        tool.setArg(ret_from_dialog)
                                        NumberofCp=tool.setNumber(treeview)
                                        if tool.NAME == "connect" or tool.NAME == "open":
                                                #make global host and port
                                                self.host = tool.getHost()
                                                self.port = tool.getPort()
                                        if tool.NAME == "DCEconnect":
                                                self.dceval=tool.get_dceval()


                                        model = treeview.get_model()

                                        if not treeview.get_dest_row_at_pos(x, y) == None:
                                                target_path, drop_position = treeview.get_dest_row_at_pos(x, y)
                                                model, source = treeview.get_selection().get_selected()
                                                target = model.get_iter(target_path)
                                                #print "source %s" %source
                                                #print "target %s" %target
                                                #print "dropped into something"
                                                #self.insert_row(model,target,tool.Show()+" #%s"%str(NumberofCp),"",tool,drop_position)
                                                iter=self.insert_row(model,target,tool.Show(),"",tool,drop_position,target_path,treeview)
                                        else:
                                                #print "dropped into nothing"
                                                #self.insert_row(model,None,tool.Show()+" #%s"%str(NumberofCp),"",tool,None)
                                                iter=self.insert_row(model,None,tool.Show(),"",tool,None,None,treeview)

                                else:
                                        #we pressed cancel
                                        if hasattr(tool, "INDEXED") and hasattr(tool, "INDEX_ADD"):
                                                #remove the unused fd
                                                if self.fdlist.has_key(tool.INDEXED):
                                                        # This should always be True
                                                        if self.fdlist[tool.INDEXED]:
                                                                self.fdlist[tool.INDEXED].pop(-1)                                                
                else:

                        model = treeview.get_model()
                        if not treeview.get_dest_row_at_pos(x, y) == None:
                                target_path, drop_position = treeview.get_dest_row_at_pos(x, y)
                                model, source = treeview.get_selection().get_selected()
                                target = model.get_iter(target_path)
                                print "target iter %s" %target
                                print "source iter %s" %source
                                if not model.is_ancestor(source, target):
                                        self.treeview_copy_row(treeview, model, source, target, drop_position)
                                        if (drop_position == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE or drop_position == gtk.TREE_VIEW_DROP_INTO_OR_AFTER):
                                                treeview.expand_row(target_path, open_all=False)
                                                drag_context.finish(success=True, del_=True, time=eventtime)
                                else:
                                        drag_context.finish(success=False, del_=False, time=eventtime)


        def rowclickxpacket(self,widget,event):
                """
        Sets self.tool to be the widget that was clicked.
        """
                xpacketselection = widget.get_selection()
                model, iter = xpacketselection.get_selected()
                try:
                        tool2 = model.get_value(iter,3)
                        tool2.gui=self 
                        self.tool = tool2
                        self.iter = iter
                        self.model = model
                        
                except:
                        tool2=None 
                        pass

                if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
                        #iter might not be a GtkTreeIter here? Why?
                        #BUGBUG: need to check for this case and figure out what to do about it.
                        selection = model.get_value(iter,0)
                        try: 
                                (clase, directory) = self.Toolbar[tool2.NAME]
                        except KeyError:
                                print "ERROR: %s" % tool2.NAME
                                return
                        wTree4=gtk.glade.XML (self.pathv+"./ExploitToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                        dic = {'on_button2_clicked': (self.showHelpFromObject,tool2),
                               }
                        wTree4.signal_autoconnect(dic)
                        try:
                                badchardetected=wTree4.get_widget('badchardetected')  #we try to get badchardetected from toolx dialogs
                                badchars = self.get_badchars(self.badcharentry,widget)
                                checkbadchar = wTree4.get_widget('checkbadchar')
                                checkbadchar.connect('changed',self.badcharDetect,badchars,badchardetected)
                        except:
                                pass

                        if hasattr(tool2, "INDEXED"):
                                if not self.fdlist.has_key(tool2.INDEXED):
                                        self.fdlist[ tool2.INDEXED ] = []
                                fdlist = self.fdlist[ tool2.INDEXED ]
                        else:
                                fdlist = []
                        dialog = wTree4.get_widget("dialog1")

                        if dialog == None:
                                print "ERROR"
                        #tool = clase.Toolobject()
                        tool2.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                        tool2.setDialog(wTree4,widget,self.get_badchars(self.badcharentry,widget),self.arch)
                        response = dialog.run()
                        # if response anything else than OK, we dont do anything
                        dialog.hide()
                        if response == gtk.RESPONSE_OK:
                                ret_from_dialog = self.getfromdialog(wTree4)
                                tool2.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                                tool2.setArg(ret_from_dialog)
                                NumberofXp=tool2.getNumber()
                                showtext=tool2.Show()
                                alltext= tool2.NAME+" #%s\n"%str(NumberofXp)+showtext
                                height=get_pixel_height(widget, alltext)
                                model.set_value(iter, 0, alltext)
                                model.set_value(iter,2,height)
                                if tool2.NAME == "Jump":
                                        tool2.getOffset()
                                        alltext= tool2.NAME+" #%s\n"%str(NumberofXp)+tool2.Show()
                                        model.set_value(iter, 0, alltext)
                                        model.set_value(iter, 2, height)
                                        #liststore.set_value(iter,3,tool2)
                                elif tool2.NAME == "Pad2Length":
                                        tool2.getPad()
                                        alltext=tool2.NAME+" #%s\n"%str(NumberofXp)+tool2.Show()
                                        model.set_value(iter, 0, alltext)
                                        height=get_pixel_height(widget, alltext)
                                        model.set_value(iter,2,height)
                                #if the object is linked, get the new values

                                if tool2.getLinkState() == True:
                                        object=tool2.linkedObj()
                                        self.ModLinkedObj(object,widget.get_model())

                elif event.button == 3 and event.type == gtk.gdk.BUTTON_PRESS:
                        self.tree = widget
                        self.buffermenuwidget.popup(None, None, None, event.button, event.time)
                        try:

                                if tool2!=None and tool2.NAME == "EIP":
                                        self.separator1.show()
                                        self.add_target.show()
                                        eip=tool2.getDefaultTarget()
                                        devlog("eip", "3: Setting EIP to: %x"%eip)
                                        self.setDefaultTarget(eip)

                                else:
                                        self.separator1.hide()
                                        self.add_target.hide()
                        except:
                                pass
                #modify the displayed size of the whole buffer at header title
                self.ModBufSize(widget)
                self.ModBuf2pad(widget)
                return 


        def addtarget(self,event):
                addtargetdialog = gtk.glade.XML (self.gladefile,"addtargetdialog")
                targetbox= addtargetdialog.get_widget("targetbox")
                targetmenug = gtk.glade.XML(self.gladefile,"targetmenu")
                targetmenuwidget=targetmenug.get_widget("targetmenu")
                sw = gtk.ScrolledWindow()
                sw.set_policy(gtk.POLICY_NEVER, gtk.POLICY_NEVER)
                targettree=gtk.TreeView()
                targettreemodel=gtk.ListStore(int, str, str)
                targettree.set_model(targettreemodel)
                targettree.set_headers_visible(True)
                targetcell=gtk.CellRendererText()
                targetid=gtk.TreeViewColumn("Id", targetcell, text=0)
                targetname=gtk.TreeViewColumn("Target", targetcell, text=1)
                targetvalue=gtk.TreeViewColumn("Address", targetcell, text=2)
                targettree.append_column(targetid)
                targettree.append_column(targetname)
                targettree.append_column(targetvalue)
                targettree.set_search_column(0)
                targetid.set_sort_column_id(0)
                targetname.set_sort_column_id(0)
                targetvalue.set_sort_column_id(0)
                sw.add(targettree)
                sw.show()
                targetbox.pack_start(sw,expand=True, padding=0)
                targettree.show()
                delete_target=targetmenug.get_widget("delete_target1")
                delete_target.connect("activate", self.delete_target,targettree,addtargetdialog)
                targettree.connect("button_press_event",self.targettree_click,targetmenuwidget,addtargetdialog,delete_target)
                self.fillTargetTree(self.targets,targettree)
                targetentry = addtargetdialog.get_widget("addtargetdialog")
                managetargethelp=addtargetdialog.get_widget("button24")
                managetargethelp.connect("clicked", self.msgBox)
                response = targetentry.run()
                targetentry.hide()

                if response == gtk.RESPONSE_OK:
                        targetdata = self.getfromdialog(addtargetdialog)
                        if targetdata['targetlabel'] and targetdata['targetlabel'] !="default target":            
                                self.targetid+=1
                                self.targets[self.targetid]=[targetdata['targetlabel'],targetdata['targetaddy']]
                        elif targetdata['targetlabel'] == "default target":
                                self.log("Error: default target is a reserved target label")



        def fillTargetTree(self,targets,tree):
                model=tree.get_model()
                model.clear()
                i=0
                for a in targets:
                        iter = model.append()
                        model.set_value(iter,0,i)
                        model.set_value(iter,1,targets[i][0])
                        model.set_value(iter,2,targets[i][1])
                        i=i+1


        def targettree_click(self,tree,event,targetmenuwidget,targetdialog,delete_target):
                targetselection = tree.get_selection()
                self.model, self.iter = targetselection.get_selected()
                try:
                        id = self.model.get_value(self.iter,0)
                        target = self.model.get_value(self.iter,1)
                        addy = self.model.get_value(self.iter,2)
                except:
                        pass
                if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
                        if id == 0:
                                targetlabel=targetdialog.get_widget("targetlabel")
                                targetaddy=targetdialog.get_widget("targetaddy")
                                targetaddy.set_sensitive(False)
                                targetlabel.set_sensitive(False)
                                targetlabel.set_text(target+" -Not Editable-")
                                targetaddy.set_text(addy+" -Not Editable-")
                                self.log("You can not edit default target here")
                        else:
                                targetlabel=targetdialog.get_widget("targetlabel")
                                targetaddy=targetdialog.get_widget("targetaddy")
                                targetaddy.set_sensitive(True)
                                targetlabel.set_sensitive(True)
                                targetlabel.set_text(target)
                                targetaddy.set_text(addy)
                                self.setTargetsFromTree(tree)

                elif event.button == 3 and event.type == gtk.gdk.BUTTON_PRESS:
                        targetmenuwidget.popup(None, None, None, event.button, event.time)

        def delete_target(self,event,tree,targetdialog):
                try:
                        target = self.model.get_value(self.iter,1)
                        addy = self.model.get_value(self.iter,2)
                        id = self.model.get_value(self.iter,0)
                        if id == 0:
                                self.log("You can not remove default target")
                        else:
                                del self.targets[id]
                                self.log("Removing %s:%s from target list" % (target,addy))
                                self.model.remove(self.iter)
                                self.setTargetsFromTree(tree)


                except:
                        self.log("Error: Could not remove target")



        def setTargetsFromTree(self,tree):
                """get the new targets from liststore @ EIP -> manage targets"""
                model=tree.get_model()
                self.targetid=0
                self.targets={}
                for a in model:
                        self.targets[self.targetid]=[a[1],a[2]] 
                        self.targetid+=1

        def delete_buffer(self,event):
                try:
                        self.log("Removing %s" % self.tool)
                        self.model.remove(self.iter)
                except:
                        self.log("Error: Could not remove buffer")
                self.ModBufSize(self.tree)
                self.ModBuf2pad(self.tree)

        def ObjectComment(self,event):
                try:
                        window = gtk.glade.XML (self.gladefile,"ObjectCommentsDialog")
                        commentdialog = window.get_widget("ObjectCommentsDialog")
                        commententry=window.get_widget("commententry")
                        if self.tool.getObjectComments():
                                commentsbuffer=gtk.TextBuffer()
                                commentsbuffer.set_text(self.tool.getObjectComments())
                                commententry.set_buffer(commentsbuffer)
                        response = commentdialog.run()
                        commentdialog.hide()
                        if response == gtk.RESPONSE_OK:
                                commentdata = self.getfromdialog(window)
                                self.tool.setObjectComments(commentdata)
                except:
                        print "Please be sure to select an object first"




        def rowclickcpacket(self,widget,event):
                xpacketselection = widget.get_selection()
                self.model, iter = xpacketselection.get_selected()
                if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
                        selection = self.model.get_value(iter,0)
                        tool2 = self.model.get_value(iter,2)

                        if tool2.NAME[0:2]=="pl":
                                try: 
                                        (clase, directory) = self.plToolbar[tool2.NAME]
                                except KeyError:
                                        print "error!"
                                wTree4=gtk.glade.XML (self.pathv+"./ProtocolLogicToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")
                        else:
                                try: 
                                        (clase, directory) = self.cToolbar[tool2.NAME]
                                except KeyError:
                                        return
                                wTree4=gtk.glade.XML (self.pathv+"./ConnToolbar/%s/%s" % (directory, clase.Toolobject.GLADE_DIALOG), "dialog1")

                        dic = {'on_button2_clicked': (self.showHelpFromObject,tool2),
                               }
                        wTree4.signal_autoconnect(dic)
                        dialog = wTree4.get_widget("dialog1")

                        if dialog == None:
                                print "ERROR"
                                
                        if hasattr(tool2, "INDEXED"):
                                if not self.fdlist.has_key(tool2.INDEXED):
                                        self.fdlist[ tool2.INDEXED ] = []
                                fdlist = self.fdlist[ tool2.INDEXED ]
                        else:
                                fdlist = []
                                
                        #tool = clase.Toolobject()
                        tool2.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                        tool2.setDialog(wTree4,widget,self.get_badchars(self.badcharentry,widget), fdlist, self.xpacketlist)
                        response = dialog.run()
                        # if response anything else than OK, we dont do anything
                        dialog.hide()
                        if response == gtk.RESPONSE_OK:
                                ret_from_dialog = self.getfromdialog(wTree4)
                                tool2.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                                tool2.setArg(ret_from_dialog)
                                NumberofXp=tool2.getNumber()

                                if tool2.NAME[0:2]=="pl":
                                        self.model.set_value(iter,0,tool2.Show())
                                else:
                                        self.model.set_value(iter,0,tool2.Show()+" #%s" % str(NumberofXp))
                                if tool2.NAME == "connect" or tool2.NAME == "open":
                                        #a new connect, a new fd
                                        #make global host and port
                                        self.host = tool2.getHost()
                                try:
                                        self.port = tool2.getPort()
                                except:
                                        pass
                                #Connection or Protocol Logic?
                                try:
                                        self.model.set_value(iter,1,"FD: %s" %tool2.cfd)
                                except:
                                        self.model.set_value(iter,1,"")
                                self.model.set_value(iter,2,tool2)
                                #self.insert_row(model,None,tool2.Show(),"FD: %s" %tool2.cfd,tool2,None)

                elif event.button == 3 and event.type == gtk.gdk.BUTTON_PRESS:
                        self.buffermenuwidget.popup(None, None, None, event.button, event.time)
                        self.tool = self.model.get_value(iter,2)
                        self.iter=iter #quick fix
                        #delete_buffer=self.buffermenug.get_widget("delete_buffer1")
                        #edit_buffer=self.buffermenug.get_widget("edit_buffer1")

        def debugme(self,dprint,widget, color='black'):
                logbuffer = widget.get_buffer()
                enditer = logbuffer.get_end_iter()
                dprint = str(dprint)+"\n"
                if color != 'black':
                        tag = logbuffer.create_tag()
                        tag.set_property("foreground", color)
                        self.logwindow.insert_with_tags(logbuffer.get_end_iter(), message, tag)
                else:
                        try:
                                logbuffer.insert(enditer, dprint, len(dprint))
                        except:
                                logbuffer.insert(enditer, dprint)
                mark = logbuffer.create_mark("end", logbuffer.get_end_iter(), False)
                widget.scroll_to_mark(mark, 0.05, True, 0.0, 1.0)

        def destroy(self, widget, data=None):
                """
        Called when the GUI is closed - also halts the debugger thread so we can close cleanly.
        """
                if self.debugger_thread:
                        self.debugger_thread.halt()
                return gtk.main_quit()

        def insert_row(self,model,parent,firstcolumn,secondcolumn,object,drop_position,target_path,treeview):
                if drop_position == None:
                        new=model.append(parent=parent,row=None)
                        model.set_value(new,0,firstcolumn)
                        model.set_value(new,1,secondcolumn)
                        model.set_value(new,2,object)
                        return new

                else:
                        if drop_position == gtk.TREE_VIEW_DROP_BEFORE:
                                new = model.insert_before(parent=None, sibling=parent, row=None)
                                model.set_value(new,0,firstcolumn)
                                model.set_value(new,1,secondcolumn)
                                model.set_value(new,2,object)
                                treeview.expand_row(target_path, open_all=False)
                                return new
                        elif drop_position == gtk.TREE_VIEW_DROP_AFTER:
                                new = model.insert_after(parent=None, sibling=parent, row=None)
                                model.set_value(new,0,firstcolumn)
                                model.set_value(new,1,secondcolumn)
                                model.set_value(new,2,object)
                                treeview.expand_row(target_path, open_all=False)
                                return new
                        elif drop_position == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE:
                                new = model.prepend(parent=parent, row=None)
                                model.set_value(new,0,firstcolumn)
                                model.set_value(new,1,secondcolumn)
                                model.set_value(new,2,object)
                                treeview.expand_row(target_path, open_all=False)
                                return new
                        elif drop_position == gtk.TREE_VIEW_DROP_INTO_OR_AFTER:
                                new = model.append(parent=parent, row=None)
                                model.set_value(new,0,firstcolumn)
                                model.set_value(new,1,secondcolumn)
                                model.set_value(new,2,object)
                                treeview.expand_row(target_path, open_all=False)
                                return new



        def treeview_copy_row(self,treeview, model, source, target, drop_position):
                source_row = model[source]
                if drop_position == gtk.TREE_VIEW_DROP_INTO_OR_BEFORE:
                        new = model.prepend(parent=target, row=source_row)
                elif drop_position == gtk.TREE_VIEW_DROP_INTO_OR_AFTER:
                        new = model.append(parent=target, row=source_row)
                elif drop_position == gtk.TREE_VIEW_DROP_BEFORE:
                        new = model.insert_before(parent=None, sibling=target, row=source_row)
                        treeiter = model.remove(source)
                elif drop_position == gtk.TREE_VIEW_DROP_AFTER:
                        new = model.insert_after(parent=None, sibling=target, row=source_row)
                        treeiter = model.remove(source)
                for n in range(model.iter_n_children(source)):
                        child = model.iter_nth_child(source, n)
                        self.treeview_copy_row(treeview, model, child, new,gtk.TREE_VIEW_DROP_INTO_OR_BEFORE)
                        source_is_expanded = treeview.row_expanded(model.get_path(source))
                        if source_is_expanded:
                                treeview_expand_to_path(treeview, model.get_path(new))



        def generateVsploitCode(self,event):

                padding = " " * 4
                try:
                        os.makedirs("./fuzzers/SPIKESCRIPTS/"+self.newprojectname['entry1'])
                except OSError, err:
                        pass
                libxdialog.generateDefaultDialog("./fuzzers/SPIKESCRIPTS/%s/" % self.newprojectname['entry1'],self.port,self.host,self.targets)
                savepath = "./fuzzers/SPIKESCRIPTS/%s/%s.py" % (self.newprojectname['entry1'],self.newprojectname['entry1'])


                f=open(savepath, 'wb+')
                #generate header code
                header_code=self.generateHdr()
                for a in header_code:
                        f.write(a)
                header_code = self.generateGivenHdr()
                for a in header_code:
                        f.write(a)

                class_code=self.generateExploitClass(padding)
                for a in class_code:
                        f.write(a)
                if self.xtype=="msrpc":
                        dceconnectcall_code=self.buildDCEcode(padding)
                        for a in dceconnectcall_code:
                                f.write(a)


                listener_code=self.generateNeededListenerTypes(padding)
                for a in listener_code:
                        f.write(a)
                #write generate shellcode 
                createshell_code=self.generateCreateShellcodexpacket(padding)
                for a in createshell_code:
                        f.write(a)

                #write xpacket code
                xpacket_code=self.generateXpacket(padding)
                for a in xpacket_code:
                        f.write(a)
                        
                #write cpacket code
                run_code=self.generateSetSpike(padding)
                for a in run_code:
                        f.write(a)
                        
                run_code=self.generateRun(padding)
                for a in run_code:
                        f.write(a)
                        
                #write runontarget support code
                test_code=self.generateRunOnTarget(padding)
                for a in test_code:
                        f.write(a)

                        
                __main___code=self.generate___name___(padding)
                for a in __main___code:
                        f.write(a)
                #self.generateCpacket(padding,f)
                f.close()

                print "Making %s" %savepath
                self.log("Wrote %s" %savepath)
                if event == 1:
                        pass
                else:
                        self.msgBox("Your exploit has been written into %s" %savepath)
                return 

        def calcWindow(self, event):
                """
        Called when the user pressed the calculator button
        Displays a simple calculator for the user to use for hex conversion
        and offset calculation.
        """
                #first check to see if we already have the Window instantiated
                #when the window is "closed" it is really hidden for future use
                if self.calculator_window:
                        self.calculator_window.show()
                        return

                #otherwise, instantiate it by going into the glade file
                wTree = gtk.glade.XML (self.gladefile,"calculator")
                self.calculator_wTree=wTree
                self.calculator_window = wTree.get_widget("calculator")
                dic = {'on_calculator_delete_event': self.calculator_hide,
                       'on_calc_expression_button_clicked': self.calculator_calc_expression,
                       }
                wTree.signal_autoconnect(dic)

                self.calculator_window.show()
                return 

        def calculator_hide(self,event, w):
                self.calculator_window.hide()
                return True

        def calculator_calc_expression(self,event):
                """
        Callback when the user clicks the equal sign in the calculator
        """
                expression_widget=self.calculator_wTree.get_widget("calc_expression")
                badchars_widget=self.calculator_wTree.get_widget("calculator_bad_bytes")
                expression=expression_widget.get_text()
                try:
                        exec("ret="+expression)
                except:
                        import traceback
                        traceback.print_exc(file=sys.stderr)
                        ret="Failed to parse expression"

                ret=str(ret)
                badcharstring=badchars_widget.get_text()
                badchars=badcharstring.decode("string_escape")
                """
        try:
            exec("badchars=\""+badcharstring+"\"")
        except Exception, i:
            #we need a better way to do error logging here...
            ret+=" (Badchars string not parsed due to exception: %s)" % i
            badchars=""
        """    
                #searchstring=exploitutils.searchpattern(4*256,badchars=badchars)
                #do I have to intel_order(ret) ?
                if dInt_n(ret)!=None:
                        offset=exploitutils.getsearchpatternoffset(dInt(ret),badchars=badchars)
                        if offset!=-1:
                                ret+=" (offset found: %d)"%offset
                result=self.calculator_wTree.get_widget("calculator_result")

                result.set_text(ret)
                return

        def regenerateExploitCode(self):
                """
        Regenerates the .py so it can be reloaded and then reloads it
        """
                #remove the pyc
                try:
                        modulec = "./fuzzers/SPIKESCRIPTS/%s/%s.pyc" % (self.newprojectname['entry1'],self.newprojectname['entry1'])
                        os.remove(modulec) 
                except:
                        pass
                self.generateVsploitCode(1)
                newpath="./fuzzers/SPIKESCRIPTS/%s" % self.newprojectname['entry1'] 
                if newpath not in sys.path: sys.path.append(newpath)

                if self.exp:
                        reload(self.exp)
                else:
                        self.exp = __import__("%s" % self.newprojectname['entry1'])
                return 

        def runExploit(self,event):
                """
        Runs the attack against the remote server
        """
                args = {}
                self.regenerateExploitCode()

                self.log("Running Exploit...")
                #self.engine = canvasengine.canvasengine(self)
                #node = self.engine.localnode
                #self.log( "CALLBACK IP %s" %self.callbackip)
                rdialog = gtk.glade.XML (self.gladefile,"rundialog")
                #if len(self.targets) > 0:
                        #runtargets=rdialog.get_widget("runtargets")
                        #targetlist=rdialog.get_widget("targetlist")
                        #targetlist.show()
                        ##targetcontainer = gtk.VBox(homogeneous=False, spacing=0)
                        #targetcombo = gtk.combo_box_new_text()
                        #runtargets.pack_start(targetcombo,expand=True,padding=0)
                        ##targetcombo.pack.start(targetcombo,expand=True, padding=0)
                        #targetcombo.show()
                        #for a in self.targets:
                                #if type(self.targets[a][1]) == long:
                                        #targetcombo.append_text(str(a)+"- ['%s' = 0x%08x]" % (self.targets[a][0], self.targets[a][1]) )
                                #else:
                                        #targetcombo.append_text(str(a)+"- ['%s' = 0x%08x]" % (self.targets[a][0], dInt(self.targets[a][1])) )

                                ## 0- ['default target' =  '0x41424433']

                        #targetcombo.set_active(0)
                print "----"
                print self.saved_args
                
                if self.saved_args.has_key("host"):
                        host = rdialog.get_widget("host")        
                        host.set_text(str(self.saved_args["host"]))
                if self.saved_args.has_key("port"):                
                        port = rdialog.get_widget("port")
                        port.set_value(float(self.saved_args["port"]))
                if self.saved_args.has_key("linemode"):
                        lmode=rdialog.get_widget("linemode")
                        lmode.set_active( self.saved_args["linemode"] )

                #hboxprepareobjs = rdialog.get_widget("vbox21") 
                #prepareobjs = gtk.combo_box_new_text()
                #hboxprepareobjs.pack_start(prepareobjs,expand=True, padding=0)
                #prepareobjs.show()
                #prepareobjs.append_text('Select Interface')
                #if self.callbackip != "":
                        #prepareobjs.append_text(self.callbackip)
                        #prepareobjs.set_active(1)
                #else:
                        #prepareobjs.set_active(0)

                #for a in node.interfaces.children:
                        #if self.callbackip !=a.ip:
                                #prepareobjs.append_text(a.ip)
                                #self.log("WARNING: you have entered a callback ip that is not between your INTERFACES listing. Be sure you really \
#want to do this")
                        #else:
                                #pass
                        #prepareobjs.connect('changed', self.changeobjs)

                rundialog = rdialog.get_widget("rundialog")
                response = rundialog.run()
                rundialog.hide()
                if response == gtk.RESPONSE_OK:
                        rundialogset = self.getfromdialog(rdialog)
                        
                        #try:
                        #        #exploit version is equal the combobox index
                        #        args["version"] = targetcombo.get_active()
                        #except:
                        #        args["version"] = 0
                        #if combobox never changed, we still need to know the active value
                        #model = prepareobjs.get_model()
                        #index = prepareobjs.get_active()
                        #self.localhost=model[index][0]
                        #devlog("vs", "Localhost= %s"%self.localhost)
                        #self.localport = rundialogset['callbackport']
                        #print "###>" + str(rundialogset['callbackport'])
                else:
                        #we're out
                        return 

                #for a in node.interfaces.children:
                        #devlog("Is %s == %s"%(a.ip, self.localhost))
                        #if a.ip == self.localhost:
                                #self.log("Yes - so set our callback interface to it")
                                #self.engine.set_callback_interface(a)



                #self.generateVsploitCode(event)

                #k=VSKnowledge("eth0")
                #k.interface =  str(rundialogset['host'])
                #self.engine.set_target_host( k )
                #callback = hostKnowledge.interfaceLine(("1", "192.168.1.100",0xffffffff),None,0,0, self.engine )
                
                sys.path.append("./fuzzers/SPIKESCRIPTS/%s" % self.newprojectname['entry1'] ) 
                if self.exp:
                        reload(self.exp)
                else:
                        self.exp = __import__("./fuzzers/SPIKESCRIPTS/%s/%s" % (self.newprojectname['entry1'],self.newprojectname['entry1']))
                spk = self.exp.spikefile()
                #args["version"] = str(self.doc['version'])
                #args["host"] = str(rundialogset['host'])
                #args["port"] = self.port
                newargs = {}
                for a in rundialogset.keys():
                        if rundialogset[a] in (None, ""):
                                del rundialogset[a]
                                
                #print "saved"
                #print self.saved_args
                #print "rundialog"                
                #print rundialogset
                self.saved_args = rundialogset #save a copy in case we are using automater
                spk.argsDict = rundialogset
                print spk.argsDict
                spk.run()
                
                return 


        #def runExploitFromEngine(self, args):
        #        ret=canvasengine.runExploit(self.engine, self.exp, args)
        #        return ret 
        def changeobjs(self,combobox):
                model = combobox.get_model()
                self.index = combobox.get_active()
                self.localhost=model[self.index][0]

                return

        def log(self, text):
                """For now, just prints text to the screen"""
                print text
                self.debugme( text, self.debug )
                return 

        def get_badchars(self,widget,xpacket):
                try:
                        badchar=widget[self.xpacketlist.index(xpacket)].get_text()
                        return badchar
                except:
                        pass
                #failure!
                return None 

        def badcharDetect(self,object,badchars,badchardetected):
                """tell us if any entered char is a bad char"""
                try:
                        tmp=badchars.decode('string_escape')
                        exec 'compare = "'+object.get_text()+'"'
                        for a in tmp:
                                if compare.find(a) > -1:
                                        self.log("Warning: Badchar detected in object - Please Remove it")
                                        badchardetected.set_label("Warning: Badchar \"%s\" detected\nPlease remove it from the buffer." %a.replace("\\","\\\\"))
                                        badchardetected.show()
                                else:
                                        badchardetected.set_label("\n")
                except:
                        pass

        def showHelpFromObject(self,event,tool):
                self.msgBox(tool.Help())




        # visualsploit template functions

        def generateHdr(self):
                templatebuf = ["#! /usr/bin/env python\n\n"]
                templatebuf+= ['#Proprietary CANVAS / SPIKE source code - use only under the license agreement\n']
                templatebuf+= ['#specified in LICENSE.txt in your CANVAS distribution\n']
                templatebuf+= ['#Copyright Immunity, Inc, 2002-2010\n']
                templatebuf+= ['#http://www.immunityinc.com/CANVAS/ for more information\n\n']
                templatebuf+= ["#"+self.doc['sploitcomments'].replace("\n","\n#")+"\n"]
                templatebuf+= ["import sys, getopt\n"]
                templatebuf+= ['sys.path.append(".")\n']
                templatebuf+= ['sys.path.append("../../")\n']

                templatebuf+= ["import os\n"]
                #templatebuf+= ["import getopt\n"]
                templatebuf+= ["import socket\n"]
                templatebuf+= ["import sys\n"]
                templatebuf+= ["import struct\n"]
                templatebuf+= ["\n# CANVAS modules\n"]
                templatebuf+= ["from exploitutils import *\n"]
                templatebuf+= ["import canvasengine\n"]
                templatebuf+= ["from tcpexploit import *\n"]
                templatebuf+= ["from fuzzers.spike import *\n"]
                if 0:
                        if self.xtype == "msrpc":
                                templatebuf+= ["from msrpc import *\n"]
                                templatebuf+= ["from msrpcexploit import msrpcexploit\n"]
                        elif self.xtype == "clientside":
                                templatebuf+= ["from httpclientside import httpclientside\n"]
                        templatebuf+= ["from encoder import addencoder\n"]
                        templatebuf+= ["from shellcode import shellcodeGenerator\n"]
                        if self.arch.replace("\n","").replace("\r","") == "Win32":
                                templatebuf+= ["from shellcode import win32shell\n"]
                        templatebuf+= ["import canvasengine\n"]
                #templatebuf+= ["from canvasengine import socket_save_list\n"]
                templatebuf+= ["import time\n"]
                #templatebuf+= ["from socket import *\n"]
                templatebuf+= ["from MOSDEF import mosdef \n"]
                templatebuf+= ["from MOSDEF.mosdefutils import *\n\n"]

                return templatebuf

        def generateGivenHdr(self):
                templatebuf= ['NAME= "%s"\n'% self.doc['name']]
                templatebuf+= ['DESCRIPTION= "%s"\n' % self.doc['description']]
                templatebuf+= ['VERSION= "%s"\n' % str(self.doc['version'])]
                if 0:
                        # Documentation given by the Wizard
                        templatebuf+= ['DOCUMENTATION = {}\n']
                        templatebuf+= ['DOCUMENTATION["Date public"]="%s"\n' % self.doc['datepublic']]
                        templatebuf+= ['DOCUMENTATION["Repeatability"]="%s"\n' % self.doc['repeatability']]
                        templatebuf+= ['DOCUMENTATION["References"] = "%s"\n' % self.doc['references']]
                        # Properties 
                        templatebuf+= ['\nPROPERTY = {}\n']
                        #todo: add combo for type, radio for site
                        try:        
                                templatebuf+= ['PROPERTY["TYPE"]= "%s"\n' % self.doc['proptype']]
                                templatebuf+= ['PROPERTY["SITE"]=  "%s"\n' % self.doc['propsite']]
                        except:
                                templatebuf+= ['PROPERTY["TYPE"]= "Exploit"\n']
                                templatebuf+= ['PROPERTY["SITE"]=  "Remote"\n']
        
                        if self.arch.replace("\n","").replace("\r","") == "Win32":
                                templatebuf+= ['PROPERTY["ARCH"]= [ ["Windows"] ]\n']
                        else:
                                templatebuf+= ['PROPERTY["ARCH"]= [ ["%s"] ]\n' % self.arch.replace("\n","").replace("\r","")]
                        templatebuf+= ['PROPERTY["VERSION"]= ["%s"]\n' % self.doc['propversion']]
                        #templatebuf+= ['GTK2_DIALOG="dialog.glade2"\n']
        
                return templatebuf

        def generateExploitClass(self,padding):
                templatebuf = []
                #templatebuf= ["targets = {\n"]
                #for a in self.targets:
                #        templatebuf+=[padding+'%s:["%s",%s],\n' % (str(a),self.targets[a][0],self.targets[a][1])] 
                #templatebuf+= [padding+'}\n']
                if self.xtype == "remote":
                        templatebuf+= ["class spikefile:\n"]
                        templatebuf+= [padding+"def __init__(self):\n"]
                        #templatebuf+= [padding*2+"canvasexploit.__init__(self)\n"]
                elif 0: # self.xtype == "msrpc":
                        templatebuf+= ["class theexploit(msrpcexploit):\n"]
                        templatebuf+= [padding+"def __init__(self):\n"]
                        templatebuf+= [padding*2+"msrpcexploit.__init__(self)\n"]
                        templatebuf+= [padding*2+'self.UUID="%s"\n' %self.dceval['uuid']]
                        if self.dceval.has_key('username') and self.dceval.has_key('password'):
                                templatebuf+= [padding*2+'self.username="%s"\n' %self.dceval['username']]
                                templatebuf+= [padding*2+'self.password="%s"\n' %self.dceval['password']]
                        templatebuf+= [padding*2+'self.uuidversion="%s"\n' %self.uuidversion]
                        templatebuf+= [padding*2+'self.targetfunction=%s\n' %self.targetfunction]
                elif 0: #self.xtype == "clientside":
                        templatebuf+= ["class theexploit(httpclientside):\n"]
                        templatebuf+= [padding+"def __init__(self):\n"]
                        templatebuf+= [padding*2+"httpclientside.__init__(self)\n"]
                templatebuf+= [padding*2+"# localhost and localport\n"]
                #not used, I think.
                templatebuf+= [padding*2+'self.argsDict = {}\n']
                templatebuf+= [padding*2+'self.engine   = None\n']
                #templatebuf+= [padding*2+"self.callbackip = \"%s\"\n" % self.callbackip]
                templatebuf+= [padding*2+"self.localhost           = \"%s\"\n" % self.callbackip]
                templatebuf+= [padding*2+"self.host                = \"127.0.0.1\"\n"]
                templatebuf+= [padding*2+"self.port                = 80\n"]
                templatebuf+= [padding*2+'self.protocol            = "TCP"\n']
                templatebuf+= [padding*2+'self.ipver               = "IPv4"\n']
                templatebuf+= [padding*2+'self.currentfuzzvariable = 0\n']
                templatebuf+= [padding*2+'self.currentstring       = 0\n']
                templatebuf+= [padding*2+'self.sleeptime           = 0.2\n']
                #templatebuf+= [padding*2+'self.oldstyle=False\n']
                templatebuf+= [padding*2+'self.threshold           = 1\n']
                templatebuf+= [padding*2+'self.maxlength           = None\n']
                templatebuf+= [padding*2+'self.usessl              = False\n']
                templatebuf+= [padding*2+'self.clientmode          = False\n']
                templatebuf+= [padding*2+'self.multicast           = False\n']
                templatebuf+= [padding*2+'self.linemode            = False\n']
                
                
                
                #templatebuf+= [padding*2+"self.targets = targets\n"]
                templatebuf+= [padding*2+"self.callbackport = %s\n" % str(self.callbackport)]
                templatebuf+= [padding*2+"self.localport = %s\n" % str(self.callbackport)]
                templatebuf+= [padding*2+"self.covertness = 0\n"]        
                templatebuf+= [padding*2+"self.version = 0\n"]
                templatebuf+= [padding*2+'self.badstring = ""\n']
                templatebuf+= [padding*2+"self.connectionList = []\n"]

                #templatebuf+= [padding*2+"self.setInfo(DESCRIPTION)\n"]
                #templatebuf+= [padding*2+"self.setInfo(VERSION)\n"]
                templatebuf+= [padding*2+"self.name = NAME\n"]

                for a in self.xpacketlist:
                        packet=self.xpacketlist.index(a)+1
                        badchr=self.get_badchars(self.badcharentry,a)
                        try:
                                badstring = str(badchr).decode('string_escape')
                        except ValueError:
                                print "WARNING: Bad badstring when trying to decode %s"%badchr
                                badstring = ""
                        badchrpacket = "self.xpacket%sbadchars=%r\n" % (str(packet), badstring)
                        templatebuf+=[padding*2+badchrpacket]
                        #xpacketbuf = "xpacket%sbuf=self.createxPacket%s()\n" % (str(self.xpacketlist.index(a)+1),str(self.xpacketlist.index(a)+1))
                        #templatebuf+=[padding*2+xpacketbuf]
                templatebuf+=[padding*2+"return\n\n"]

                return templatebuf

        #def generateBuildConnectionList(self,padding):
        #    templatebuf = [padding+'def buildConnectionList(self):\n']
        #    templatebuf+= [padding*2+'self.connectionList= ["ncacn_np:%s[\\ROUTER]"% (self.host), "ncacn_np:%s[\\srvsvc]"% (self.host)]\n']
        #    templatebuf+= [padding*2+'return self.connectionList\n\n']
        #    return templatebuf

        def generateNeededListenerTypes(self,padding):
                templatebuf=[padding+"def neededListenerTypes(self):\n"]
                templatebuf+=[padding*2+"return [canvasengine.WIN32MOSDEF]\n\n"]

                return templatebuf

        def generateCreateShellcodexpacket(self,padding):

                templatebuf=[]

                for a in self.xpacketlist:
                        model = a.get_model()
                        createshell = "def createShellcodexPacket%s(self):\n" % str(self.xpacketlist.index(a)+1)
                        templatebuf+=[padding+createshell]
                        #templatebuf+=[padding*2+"host=self.callbackip\n"]
                        #templatebuf+=[padding*2+"port=self.callbackport\n"]
                        templatebuf+=[padding*2+"badstring = self.xpacket%sbadchars\n" % str(self.xpacketlist.index(a)+1)]
                        for p in model:
                                if p[3].NAME=="Shellcode":
                                        retcreateshell =  p[3].createPython()
                                        templatebuf+= [padding*2 + (padding*2).join( retcreateshell) ]
                                        #templatebuf+=[padding*2+"return %s\n" %retcreateshell]

                return templatebuf

        def generateXpacket(self,padding):
                templatebuf=[]

                for a in self.xpacketlist:
                        model = a.get_model()
                        templatebuf += [padding+"def createxPacket%s(self, spk):\n" % str(self.xpacketlist.index(a)+1)]
                        templatebuf+=[padding*2+"buf = '' \n"]

                        for p in model:
                                print ">>"+ p[3].NAME
                                if p[3].NAME=="Shellcode":
                                        templatebuf+=[padding*2+"buf+=self.createShellcodexPacket%s()\n" %str(self.xpacketlist.index(a)+1)]
                                else:
                                        codebuf = p[3].createPython()                    
                                        for q in codebuf:
                                                templatebuf+= [padding*2+q]
                        templatebuf+=[padding*2+"return buf\n"]
                templatebuf+="\n"
                return templatebuf
        
        def generateRun(self,padding):
                templatebuf=[padding+"def usage(self):\n"]
                templatebuf+=[padding*2+"print('usage')\n"]
                templatebuf+=[padding+"\n"]
                templatebuf+=[padding+"def getargs(self):\n"]
                #self.host           = self.target.interface
                templatebuf+=[padding*2+"self.host           = self.argsDict.get('host', self.host)\n"]
                templatebuf+=[padding*2+"self.target = self.host\n"]                
                templatebuf+=[padding*2+"self.port = self.argsDict.get('port', self.port)\n"]
                templatebuf+=[padding*2+"self.protocol = self.argsDict.get('protocol', self.protocol)\n"]
                templatebuf+=[padding*2+"self.ipver    = self.argsDict.get('ipver', self.ipver)\n"]
                templatebuf+=[padding*2+"self.currentfuzzvariable = self.argsDict.get('currentfuzzvariable', self.currentfuzzvariable)\n"]
                templatebuf+=[padding*2+"self.currentstring = self.argsDict.get('currentstring', self.currentstring)\n"]
                templatebuf+=[padding*2+"self.sleeptime = self.argsDict.get('sleeptime', self.sleeptime)\n"]
                templatebuf+=[padding*2+"self.threshold = self.argsDict.get('threshold', self.threshold)\n"]
                templatebuf+=[padding*2+"self.maxlength = self.argsDict.get('maxlength', self.maxlength)\n"]
                templatebuf+=[padding*2+"self.usessl = self.argsDict.get('usessl', self.usessl)\n"]
                templatebuf+=[padding*2+"self.clientmode = self.argsDict.get('clientmode', self.clientmode)\n"]
                templatebuf+=[padding*2+"self.multicast = self.argsDict.get('multicast', self.multicast)\n"]                
                templatebuf+=[padding*2+"self.linemode = self.argsDict.get('linemode', self.linemode)\n"]                
                templatebuf+=[padding*2+"\n"]
                templatebuf+=[padding+"def run(self):\n"]
                templatebuf+=[padding*2+"self.getargs()\n"]
                templatebuf+=[padding*2+"self.run_on_target()\n"]
                templatebuf+=[padding*2+"\n"]
                return templatebuf

        
        def generateRunOnTarget(self,padding):
                templatebuf =[padding*1+"""def run_on_target(self):\n"""]
                # ipver="IPv4", currentfuzzvariable=0, currentstring=0, sleeptime=0.2, linemode=False, oldstyle=False, threshold=1, maxlength=None, usessl=False, clientmode=False, multicast=False 
                templatebuf+=[padding*2+"""stamp = get_current_time()\n"""]
                templatebuf+=[padding*2+"""print "Running script %s against %s:%d"%(self.name, self.host, self.port)\n"""]
                templatebuf+=[padding*2+"""#deal with MAXLENGTH\n"""]
                templatebuf+=[padding*2+"""if self.maxlength:\n"""]
                templatebuf+=[padding*3+"""print "Setting maxlength to %d" % self.maxlength\n"""]
                templatebuf+=[padding*3+"""for tstring in strings:\n"""]
                templatebuf+=[padding*4+"""if len(tstring) > self.maxlength:\n"""]
                templatebuf+=[padding*5+"""strings.remove(tstring)\n"""]
                templatebuf+=[padding*2+"""#end deal with MAXLENGTH\n"""]
                templatebuf+=[padding*2+"""timeout=0.5\n"""]
                templatebuf+=[padding*2+"""spk=spike()\n"""]
                templatebuf+=[padding*2+"""spk.current_fuzz_variable = self.currentfuzzvariable\n"""]
                templatebuf+=[padding*2+"""spk.current_string = self.currentstring\n"""]
                templatebuf+=[padding*2+"""connect_fail = 0\n"""]
                templatebuf+=[padding*2+"""if self.protocol=="UDP":\n"""]
                templatebuf+=[padding*3+"""prot=socket.SOCK_DGRAM\n"""]
                templatebuf+=[padding*2+"""elif self.protocol=="TCP":\n"""]
                templatebuf+=[padding*3+"""prot=socket.SOCK_STREAM\n"""]
                templatebuf+=[padding*3+"""\n"""]
                templatebuf+=[padding*2+"""if self.ipver=="IPv4":\n"""]
                templatebuf+=[padding*3+"""family=socket.AF_INET\n"""]
                templatebuf+=[padding*2+"""elif self.ipver=="IPv6":\n"""]
                templatebuf+=[padding*3+"""family=socket.AF_INET6\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*2+"""if self.clientmode:\n"""]
                templatebuf+=[padding*3+"""#we get our socket now and bind it to our listening port and ip\n"""]
                templatebuf+=[padding*3+"""listensock=getudplistener(port)\n"""]
                templatebuf+=[padding*3+"""listensock.set_timeout(None)\n"""]
                templatebuf+=[padding*3+"""if not listensock:\n"""]
                templatebuf+=[padding*4+"""print "Could not listen on that host and port!"\n"""]
                templatebuf+=[padding*4+"""return 0\n"""]
                templatebuf+=[padding*3+"""if self.multicast:\n"""]
                templatebuf+=[padding*4+"""#multiaddress='239.255.255.250'\n"""]
                templatebuf+=[padding*4+"""#multiaddress='225.100.100.100'\n"""]
                templatebuf+=[padding*4+"""devlog("spike", "Setting up multicast listener on %s" % self.multicast)\n"""]
                templatebuf+=[padding*4+"""mreq = struct.pack('4sl', socket.inet_aton(self.multicast), socket.INADDR_ANY)\n"""]
                templatebuf+=[padding*4+"""listensock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)\n"""]
                templatebuf+=[padding*3+"""s=listensock\n"""]
                templatebuf+=[padding*4+"""\n"""]
                templatebuf+=[padding*2+"""try:\n"""]
                templatebuf+=[padding*3+"""while not spk.done and connect_fail < self.threshold:\n"""]
                templatebuf+=[padding*4+"""devlog("spike","Spike is at %d %d"%(spk.current_fuzz_variable,spk.current_string))\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""self.setspike(spk)\n"""]
                #templatebuf+=[padding*4+"""parse_spk(spk, lines, oldstyle=oldstyle)\n"""]
                templatebuf+=[padding*4+"""#now our spike is all set up\n"""]
                templatebuf+=[padding*4+"""#should use dictionary lookups here\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""if not self.clientmode:\n"""]
                templatebuf+=[padding*5+"""devlog("spike", "Not in clientmode - getting tcp socket")\n"""]
                templatebuf+=[padding*5+"""#get our socket if we are not in clientmode\n"""]
                templatebuf+=[padding*5+"""s=socket.socket(family, prot)\n"""]
                templatebuf+=[padding*5+"""s.set_timeout(timeout)\n"""]
                templatebuf+=[padding*5+"""\n"""]
                templatebuf+=[padding*5+"""\n"""]
                templatebuf+=[padding*4+"""if self.clientmode:\n"""]
                templatebuf+=[padding*5+"""devlog("spike", "In clientmode: protocol=%s" % self.protocol)\n"""]
                templatebuf+=[padding*5+"""if self.protocol=="TCP":\n"""]
                templatebuf+=[padding*6+"""s=listensock.accept()\n"""]
                templatebuf+=[padding*6+"""data=s.recv(5000)\n"""]
                templatebuf+=[padding*5+"""elif self.protocol=="UDP":\n"""]
                templatebuf+=[padding*6+"""print "Waiting for UDP packet"\n"""]
                templatebuf+=[padding*6+"""data,addr=listensock.recvfrom(5000)\n"""]
                templatebuf+=[padding*6+"""print "Data: %r"%data\n"""]
                templatebuf+=[padding*6+"""\n"""]
                templatebuf+=[padding*5+"""\n"""]
                templatebuf+=[padding*4+"""else:\n"""]
                templatebuf+=[padding*5+"""\n"""]
                templatebuf+=[padding*5+"""try:\n"""]
                templatebuf+=[padding*6+"""s.connect((self.host, self.port))\n"""]
                templatebuf+=[padding*5+"""except:\n"""]
                templatebuf+=[padding*6+"""#import traceback\n"""]
                templatebuf+=[padding*6+"""#traceback.print_exc(file=sys.stderr)\n"""]
                templatebuf+=[padding*6+"""stamp = get_current_time()\n"""]
                templatebuf+=[padding*6+"""print "%s Failed to connect to %s:%d ...exiting"%( stamp, self.target, self.port)\n"""]
                templatebuf+=[padding*6+"""print "Protocol: %s" % self.protocol\n"""]
                templatebuf+=[padding*6+"""print "Spike was at %d %d"%(spk.current_fuzz_variable,spk.current_string)\n"""]
                templatebuf+=[padding*6+"""print "Out of a maximum of %d %d"%(spk.max_fuzz_variable-1, spk.max_fuzz_string)\n"""]
                templatebuf+=[padding*6+"""print "Last Gotten String (%d): %s"%(len(spk.last_got_string),prettyprint(spk.last_got_string))\n"""]
                templatebuf+=[padding*6+"""print "Connection Failure #%d (Threshold: %d)" % ( connect_fail, self.threshold )\n"""]
                templatebuf+=[padding*6+"""connect_fail += 1\n"""]
                templatebuf+=[padding*2+"""\n"""]
                templatebuf+=[padding*6+"""spk.clear_data()\n"""]
                templatebuf+=[padding*6+"""continue\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""if self.usessl:\n"""]
                templatebuf+=[padding*5+"""#HANDLE SSL HERE\n"""]
                templatebuf+=[padding*5+"""settings=HandshakeSettings()\n"""]
                templatebuf+=[padding*5+"""settings.minKeySize=512 #some servers have a very small key\n"""]
                templatebuf+=[padding*5+"""settings.maxVersion=(3,1) #servers hate it when you are TLSv1.1\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*5+"""devlog("spike","Doing TLS Connection")\n"""]
                templatebuf+=[padding*5+"""try:\n"""]
                templatebuf+=[padding*6+"""connection=TLSConnection(s)\n"""]
                templatebuf+=[padding*6+"""connection.handshakeClientCert(settings=settings)\n"""]
                templatebuf+=[padding*6+"""s=connection\n"""]
                templatebuf+=[padding*5+"""except TLSAbruptCloseError:\n"""]
                templatebuf+=[padding*6+"""print "TLS Abrupt Close Error"\n"""]
                templatebuf+=[padding*6+"""connect_fail += 1\n"""]
                templatebuf+=[padding*6+"""spk.clear_data()\n"""]
                templatebuf+=[padding*6+"""continue\n"""]
                templatebuf+=[padding*5+"""except socket.error:\n"""]
                templatebuf+=[padding*6+"""print "Connection failed to SSL server"\n"""]
                templatebuf+=[padding*6+"""import traceback\n"""]
                templatebuf+=[padding*6+"""traceback.print_exc(file=sys.stderr)\n"""]
                templatebuf+=[padding*6+"""connect_fail +=1\n"""]
                templatebuf+=[padding*6+"""spk.clear_data()\n"""]
                templatebuf+=[padding*6+"""continue\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""if connect_fail >= self.threshold:\n"""]
                templatebuf+=[padding*5+"""stamp = get_current_time()\n"""]
                templatebuf+=[padding*5+"""print "%s Connection failure threshold reached, perhaps you should check the debugger." % stamp\n"""]
                templatebuf+=[padding*5+"""sys.exit(1)\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""value=str(spk.value)\n"""]
                templatebuf+=[padding*4+"""if self.protocol=="UDP":\n"""]
                templatebuf+=[padding*5+"""value=value[:65500]\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*4+"""try:\n"""]
                templatebuf+=[padding*5+"""if self.linemode:\n"""]
                templatebuf+=[padding*6+"""devlog("spike", "Linemode chosen")\n"""]
                templatebuf+=[padding*6+"""try:\n"""]
                templatebuf+=[padding*7+"""#wait for response\n"""]
                templatebuf+=[padding*7+"""data=s.recv(5000)\n"""]
                templatebuf+=[padding*7+"""devlog("spike", "Banner Data=%s"%prettyprint(data))\n"""]
                templatebuf+=[padding*6+"""except timeoutsocket.Timeout:\n"""]
                templatebuf+=[padding*7+"""pass\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*6+"""#split into lines\n"""]
                templatebuf+=[padding*6+"""datalines=value.split("\\n")\n"""]
                templatebuf+=[padding*6+"""for line in datalines:\n"""]
                templatebuf+=[padding*7+"""#send line\n"""]
                templatebuf+=[padding*7+"""devlog("spike","Sending %s"%prettyprint(line))\n"""]
                templatebuf+=[padding*7+"""s.sendall(line+"\\n")\n"""]
                templatebuf+=[padding*7+"""#wait for response\n"""]
                templatebuf+=[padding*7+"""data=s.recv(5000)\n"""]
                templatebuf+=[padding*7+"""devlog("spike", "Data=%s"%prettyprint(data))\n"""]
                templatebuf+=[padding*5+"""else:\n"""]
                templatebuf+=[padding*6+"""#not linemode\n"""]
                templatebuf+=[padding*6+"""devlog("spike","Sending %s"%prettyprint(value[:256]))\n"""]
                templatebuf+=[padding*6+"""if self.usessl:\n"""]
                templatebuf+=[padding*7+"""try:\n"""]
                templatebuf+=[padding*8+"""#send is the same as sendall()\n"""]
                templatebuf+=[padding*8+"""ret=s.send(value)\n"""]
                templatebuf+=[padding*8+"""print "Sent %s data"%ret\n"""]
                templatebuf+=[padding*7+"""except TLSAbruptCloseError:\n"""]
                templatebuf+=[padding*8+"""print "TLS Abrupt Close Error"\n"""]
                templatebuf+=[padding*8+"""connect_fail += 1\n"""]
                templatebuf+=[padding*6+"""else:\n"""]
                templatebuf+=[padding*7+"""if self.clientmode and self.protocol=="UDP":\n"""]
                templatebuf+=[padding*8+"""ret=listensock.sendto(value,addr)\n"""]
                templatebuf+=[padding*7+"""else:\n"""]
                templatebuf+=[padding*8+"""ret=s.sendall(value)\n"""]
                templatebuf+=[padding*5+"""if not (self.clientmode and self.protocol=="UDP") :\n"""]
                templatebuf+=[padding*6+"""s.close()\n"""]
                templatebuf+=[padding*4+"""except socket.error, message:\n"""]
                templatebuf+=[padding*5+"""stamp = get_current_time()\n"""]
                templatebuf+=[padding*5+"""print "%s Error: %s" % ( stamp, message )\n"""]
                templatebuf+=[padding*4+"""except timeoutsocket.Timeout:\n"""]
                templatebuf+=[padding*5+"""pass\n"""]
                templatebuf+=[padding*4+"""time.sleep(self.sleeptime)\n"""]
                templatebuf+=[padding*4+"""spk.increment()\n"""]
                templatebuf+=[padding*2+"""except KeyboardInterrupt:\n"""]
                templatebuf+=[padding*3+"""stamp = get_current_time()\n"""]
                templatebuf+=[padding*3+"""print "%s Interrupted. Spike was at %d %d" % ( stamp, spk.current_fuzz_variable,spk.current_string )\n"""]
                templatebuf+=[padding*3+"""print "Out of a maximum of %d %d" % ( spk.max_fuzz_variable-1, spk.max_fuzz_string)\n"""]
                templatebuf+=[padding*3+"""print "Last Gotten String (%d): %s" % ( len(spk.last_got_string),prettyprint(spk.last_got_string))\n"""]
                templatebuf+=[padding*2+"""print "%s Fuzzing has finished" % stamp\n"""]
                templatebuf+=[padding*1+"""\n"""]
                                               
                return templatebuf


        def buildDCEcode(self,padding):
                templatebuf=[padding+"def DCEconnect(self,uuid, uuidversion, connectionList, username, password):\n"]
                #templatebuf+=[padding*2+'connectionList= ["ncacn_np:'+tmp+'[%s]"' % self.namedpipe +tmp+'elf.host ]')
                templatebuf+=[padding*2+'myDCE = DCE(uuid, uuidversion, connectionList, covertness = self.covertness, getsock=self)\n']
                templatebuf+=[padding*2+'myDCE.setUsername(username)\n']
                templatebuf+=[padding*2+'myDCE.setPassword(password)\n']
                templatebuf+=[padding*2+'try:\n']
                templatebuf+=[padding*3+'map=myDCE.connect()\n']
                templatebuf+=[padding*3+'if not map:\n']
                templatebuf+=[padding*4+'self.raiseError("Could not connect to remote server - service is not running or the host is firewalled.")\n']
                templatebuf+=[padding*2+'except DCEException, msg:\n']
                templatebuf+=[padding*3+'self.log(msg)\n']
                templatebuf+=[padding*3+'return 0\n']
                templatebuf+=[padding*2+'self.log("attacking %s" % map)\n']
                templatebuf+=[padding*2+'return myDCE\n']
                return templatebuf


                
        def generateSetSpike(self,padding):
                templatebuf=[padding+"def setspike(self, spk):\n"]
                #templatebuf+=[padding*2+"self.localhost=self.callback.ip\n"]
                #templatebuf+=[padding*2+"self.localport=self.callback.port\n"]
                for a in self.cpacketlist:
                        model = a.get_model()
                        for p in model: #parent rows
                                paddingfromrow=0
                                codebuf = p[2].createPython(paddingfromrow)
                                for q in codebuf:
                                        templatebuf+=[padding*2+q+"\n"]
                                for b in p.iterchildren(): #parent has children?
                                        paddingfromrow = 1
                                        codebuf = b[2].createPython(paddingfromrow)
                                        for q in codebuf:
                                                templatebuf+=[padding*2+q+"\n"]
                                        templatebuf2=self.paddingFromRow(b,paddingfromrow,padding) #more childrens?
                                        try:
                                                for a in templatebuf2:
                                                        templatebuf+=a
                                        except:
                                                print "iterating cpacket..."

                #templatebuf+=[padding*2+"if self.ISucceeded():\n"]
                #templatebuf+=[padding*3+'self.setInfo("%s attacking %s:%d (succeeded!)" % (self.name, self.host, self.port))\n']
                #templatebuf+=[padding*3+"return 1\n"]
                #templatebuf+=[padding*2+'self.setInfo("%s attacking %s:%d (failed!)" % (self.name, self.host, self.port))\n']
                #templatebuf+=[padding*2+"return 0\n"]

                return templatebuf

        def paddingFromRow(self,row,paddingfromrow,padding):
                if row.iterchildren():
                        for b in row.iterchildren():
                                paddingfromrow = paddingfromrow +1
                                templatebuf=[]
                                codebuf = b[2].createPython(paddingfromrow)
                                for q in codebuf:
                                        templatebuf+=[padding*2+q+"\n"]
                                templatebuf2=self.paddingFromRow(b,paddingfromrow,padding)
                                try:
                                        for a in templatebuf2:
                                                templatebuf+=a
                                except:
                                        print "iterating cpacket..."
                                return templatebuf
                else:
                        print "Error getting pad from row status"

        def generate___name___(self,padding):
                #templatebuf=["\nif __name__== '__main__':\n"]
                templatebuf =[padding*3+"""\n"""]
                templatebuf+=[padding*0+"""def usage(name, msg):\n"""]
                templatebuf+=[padding*1+"""print msg\n"""]
                templatebuf+=[padding*1+"""print "-" * 0x10\n"""]
                templatebuf+=[padding*1+"""print "python %s -t -p [-P -I -F -S -s -T -M -L -c -m -l]" % name\n"""]
                templatebuf+=[padding*1+"""print "-t      Host"\n"""]
                templatebuf+=[padding*1+"""print "-p      Port"\n"""]
                templatebuf+=[padding*1+"""print "-P      Protocol"\n"""]
                templatebuf+=[padding*1+"""print "-I      IP version"\n"""]
                templatebuf+=[padding*1+"""print "-F      Current Fuzz variable"\n"""]
                templatebuf+=[padding*1+"""print "-S      Current String"\n"""]
                templatebuf+=[padding*1+"""print "-s      Sleep time"\n"""]
                templatebuf+=[padding*1+"""print "-T      Threshold"\n"""]
                templatebuf+=[padding*1+"""print "-M      Maximun Length"\n"""]
                templatebuf+=[padding*1+"""print "-L      Use SSL"\n"""]
                templatebuf+=[padding*1+"""print "-c      Client IP to Listen to"\n"""]
                templatebuf+=[padding*1+"""print "-m      Multicast IP"\n"""]
                templatebuf+=[padding*1+"""print "-l      Line mode On"\n"""]
                templatebuf+=[padding*1+"""sys.exit(-1)\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*0+"""if __name__ == '__main__':\n"""]
                templatebuf+=[padding*1+"print \"Running SPIKE %s\" % sys.argv[0]\n"]
                templatebuf+=[padding*1+"""try:\n"""]
                templatebuf+=[padding*2+"""opts, args = getopt.getopt(sys.argv[1:], "t:p:I:P:F:S:s:T:M:L:c:m:l")\n"""]
                templatebuf+=[padding*1+"""except getopt.GetoptError, info:\n"""]
                templatebuf+=[padding*2+"""usage(sys.argv[0], "Error in arguments: %s" % info)\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*1+"""args = {}\n"""]
                templatebuf+=[padding*1+"""i = 0\n"""]
                templatebuf+=[padding*1+"""for o, a in opts:\n"""]
                templatebuf+=[padding*2+"""#print "Parsing arg: %s"%o\n"""]
                templatebuf+=[padding*2+"""if o == "-t":\n"""]
                templatebuf+=[padding*3+"""args['host'] = a\n"""]
                templatebuf+=[padding*3+"""i+=1\n"""]
                templatebuf+=[padding*2+"""elif o == "-p":\n"""]
                templatebuf+=[padding*3+"""args['port'] = int(a)\n"""]
                templatebuf+=[padding*3+"""i+=1\n"""]
                templatebuf+=[padding*2+"""elif o == "-P":\n"""]
                templatebuf+=[padding*3+"""args['protocol'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-I":\n"""]
                templatebuf+=[padding*3+"""args['ipver'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-F":\n"""]
                templatebuf+=[padding*3+"""args['currentfuzzvariable'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-S":\n"""]
                templatebuf+=[padding*3+"""args['currentstring'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-s":\n"""]
                templatebuf+=[padding*3+"""args['sleeptime'] = float(a)\n"""]
                templatebuf+=[padding*2+"""elif o == "-T":\n"""]
                templatebuf+=[padding*3+"""args['threshold'] = int(a)\n"""]
                templatebuf+=[padding*2+"""elif o == "-M":\n"""]
                templatebuf+=[padding*3+"""args['maxlength'] = int(a)\n"""]
                templatebuf+=[padding*2+"""elif o == "-L":\n"""]
                templatebuf+=[padding*3+"""args['usessl'] = True\n"""]
                templatebuf+=[padding*2+"""elif o == "-c":\n"""]
                templatebuf+=[padding*3+"""args['clientmode'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-m":\n"""]
                templatebuf+=[padding*3+"""args['multicast'] = a\n"""]
                templatebuf+=[padding*2+"""elif o == "-l":\n"""]
                templatebuf+=[padding*3+"""args['linemode'] = True\n"""]
                templatebuf+=[padding*1+"""if i < 2:\n"""]
                templatebuf+=[padding*2+"""usage(sys.argv[0], "Need host and port")\n"""]
                templatebuf+=[padding*1+"""\n"""]
                templatebuf+=[padding*1+"""print args\n"""]
                templatebuf+=[padding*1+"""sp = spikefile()\n"""]
                templatebuf+=[padding*1+"""sp.argsDict = args\n"""]
                templatebuf+=[padding*1+"""sp.run()\n"""]
                
                return templatebuf


        def saveState(self,event):
                #print "Saved VisualSpike/Projects/%s/%s.vsp" %(self.newprojectname['entry1'],self.newprojectname['entry1'])
                self.log("Saved VisualSpike/Projects/%s/%s.vsp" %(self.newprojectname['entry1'],self.newprojectname['entry1']))
                savepath = "VisualSpike/Projects/%s/%s.vsp" % (self.newprojectname['entry1'],self.newprojectname['entry1'])
                f = open(savepath,"w") 
                f.write("#VisualSpike Project File\n#http://www.immunityinc.com/\n")
                f.write("rNAME=%s\n" % self.newprojectname['entry1'])
                f.write('callbackip="%s"\n' % self.callbackip)
                f.write('callbackport=%s\n' % str(self.callbackport))
                f.write('sploitcomments="%s"\n' % self.doc['sploitcomments'].replace("\n","\\n"))
                f.write('description="%s"\n' % self.doc['description'])
                f.write('proptype="%s"\n' % self.doc['proptype'])
                f.write('repeatability="%s"\n' % self.doc['repeatability'])
                f.write('propversion="%s"\n' % self.doc['propversion'])
                f.write('arch="%s"\n' %self.arch)
                f.write('references="%s"\n' %self.doc['references'])
                f.write('propsite="%s"\n' %self.doc['propsite'])
                f.write('datepublic="%s"\n' %self.doc['datepublic'])
                f.write('name="%s"\n' %self.doc['name'])
                f.write('version="%s"\n' %self.doc['version'])
                f.write('teststring="%s"\n' %self.teststring['teststring'])
                f.write('usetest="%s"\n' %self.teststring['checkbutton1'])
                f.write('xtype="%s"\n' %self.xtype)
                i=0
                for a in self.targets:
                        f.write('*-%s=%s:%s\n' %(str(i),str(self.targets[a][0]),str(self.targets[a][1]))) 
                        i=i+1
                for a in self.xpacketlist:
                        model = a.get_model()
                        f.write("--BEGIN--\n")
                        badchars=self.get_badchars(self.badcharentry,a)
                        f.write('.+="%s"\n' %badchars)
                        for p in model:
                                saveme=p[3].save()
                                f.write("++%s\n" %p[3].NAME)
                                for a in saveme.keys():
                                        f.write("**%s=%s\n" % (a, saveme[a]) )
                        f.write("---END---\n")

                for a in self.cpacketlist:
                        model = a.get_model()
                        f.write("--START--\n")

                        for p in model:
                                saveme=p[2].save()
                                if p[2].NAME[0:2] == "pl":
                                        f.write("..%s&childrenstatus=0\n" %p[2].NAME)

                                else:
                                        f.write("+.%s&childrenstatus=0\n" %p[2].NAME)
                                for a in saveme.keys():
                                        f.write("**%s=%s\n" % (a, saveme[a]) )


                                childrenstatus=0
                                for b in p.iterchildren():
                                        saveme=b[2].save()
                                        if b[2].NAME[0:2] == "pl":
                                                f.write("..%s&childrenstatus=1\n" %b[2].NAME)
                                        else:
                                                f.write("+.%s&childrenstatus=1\n" %b[2].NAME)
                                        for a in saveme.keys():
                                                f.write("**%s=%s\n" % (a, saveme[a]) )
                                        self.getChildrenRow(b,f,childrenstatus=1)

                        f.write("--STOP--\n")
                f.close()
                self.msgBox("Project successfully saved")

        def getChildrenRow(self,row,f,childrenstatus):
                if row.iterchildren():
                        for b in row.iterchildren():
                                saveme=b[2].save()
                                if b[2].NAME[0:2] == "pl":

                                        f.write("..%s&childrenstatus=%s\n" %(b[2].NAME,str(childrenstatus+1)))
                                else:
                                        f.write("+.%s&childrenstatus=%s\n" %(b[2].NAME,str(childrenstatus+1)))

                                for a in saveme.keys():
                                        f.write("**%s=%s\n" % (a, saveme[a]) )

                                self.getChildrenRow(b,f,childrenstatus+1)
                else:
                        print "yuck"


        def loadEnv(self,event,filename):
                lines=[]
                f = open(filename,"r")
                for a in range(1,20):
                        lines.append(f.readline())
                #name, callbackip,callbackport
                self.log("Loading Name...")
                (tag,val) = lines[2].split("=",1)
                val=val.replace("\r","")
                self.newprojectname={'entry1': val.replace("\n","")} 
                self.log("Loading callbackip...")        
                (tag,val) = lines[3].split("=",1)
                val=val.replace("\r","")
                self.callbackip=val.replace("\n","")
                self.callbackip=self.callbackip.replace("\"","")
                self.log("Loading callbackport...")
                (tag,val) = lines[4].split("=",1)
                val=val.replace("\r","")
                self.callbackport=val.replace("\n","")

                #load DOCUMENTATION
                self.log("Loading Exploit Documentation...")
                (tag,val) = lines[5].split("=",1)
                val=val.replace("\r","")
                self.doc['sploitcomments']=val.replace("\\n","\n")
                self.doc['sploitcomments']=self.doc['sploitcomments'].replace("\"","")
                (tag,val) = lines[6].split("=",1)
                val=val.replace("\r","")
                self.doc['description']=val.replace("\n","")
                self.doc['description']=self.doc['description'].replace("\"","")
                (tag,val) = lines[7].split("=",1)
                val=val.replace("\r","")
                self.doc['proptype']=val.replace("\n","")
                self.doc['proptype']=self.doc['proptype'].replace("\"","")
                (tag,val) = lines[8].split("=",1)
                val=val.replace("\r","")
                self.doc['repeatability']=val.replace("\n","")
                self.doc['repeatability']=self.doc['repeatability'].replace("\"","")
                (tag,val) = lines[9].split("=",1)
                val=val.replace("\r","")
                self.doc['propversion']=val.replace("\n","")
                self.doc['propversion']=self.doc['propversion'].replace("\"","")
                (tag,val) = lines[10].split("=",1)
                #val=val.replace("\r","")
                self.arch= string.strip(val.replace("\n",""))
                self.log("Loading Arch %s" % self.arch)
                self.arch=self.arch.replace("\"","")
                (tag,val) = lines[11].split("=",1)
                val=val.replace("\r","")
                self.doc['references']=val.replace("\n","")
                self.doc['references']=self.doc['references'].replace("\"","")
                (tag,val) = lines[12].split("=",1)
                val=val.replace("\r","")
                self.doc['propsite']=val.replace("\n","")
                self.doc['propsite']=self.doc['propsite'].replace("\"","")
                (tag,val) = lines[13].split("=",1)
                val=val.replace("\r","")
                self.doc['datepublic']=val.replace("\n","")
                self.doc['datepublic']=self.doc['datepublic'].replace("\"","")
                (tag,val) = lines[14].split("=",1)
                val=val.replace("\r","")
                self.doc['name']=val.replace("\n","")
                self.doc['name']=self.doc['name'].replace("\"","")
                (tag,val) = lines[15].split("=",1)
                val=val.replace("\r","")
                self.doc['version']=val.replace("\n","")
                self.doc['version']=self.doc['version'].replace("\"","")
                self.toolcomment.setArg(self.doc)

                #load teststring
                self.log("Loading TestString...")
                (tag,val) = lines[16].split("=",1)
                val=val.replace("\r","")
                self.teststring['teststring']=val.replace("\n","")
                self.teststring['teststring']=self.teststring['teststring'].replace("\"","")
                (tag,val) = lines[17].split("=",1)
                val=val.replace("\r","")
                self.teststring['checkbutton1']=val.replace("\n","")
                self.teststring['checkbutton1']=self.teststring['checkbutton1'].replace("\"","")
                self.toolteststring.setArg(self.teststring)
                (tag,val) = lines[18].split("=",1)
                val=val.replace("\r","")
                self.xtype=val.replace("\n","").replace("\"","")
                if self.xtype=="msrpc":
                        self.dceval={}
                        self.uuidversion=""
                        self.targetfunction=0x00

        def loadState(self,event,filename):
                lines=[]
                f = open(filename,"r")
                dicc_obj={}

                toolx_name=""
                toolc_name=""
                toolpl_name=""
                for line in f:
                        type=line[:2]

                        value=line[2:].replace("\r","")
                        #print value

                        if type == "*-":
                                (tag,val) = value.split("=",1)
                                val=val.replace("\r","")
                                val=val.replace("\n","")
                                val=val.split(":")
                                self.targets[int(tag)]=[val[0],val[1]]


                        if type=="**":
                                (tag, val) = value.split("=", 1)
                                # It appears that integer values from
                                # testshellcode sometimes are saved up as float
                                # im assuming regional settings issues?
                                # quick fix backward compat.
                                if tag == "finish_character" or tag == "start_character" :
                                        if "." in val:
                                                val = val.split(".")[0]
                                        
                                dicc_obj[tag] = val[:-1]
                                

                        elif toolx_name:
                                self.log("Loading xPacket buffer: %s..." %toolx_name)
                                toolx_name = toolx_name.replace("\r", "")
                                (clase, directory) = self.Toolbar[toolx_name]
                                tool = clase.Toolobject()
                                dicc_obj['badchars'] = self.badchars
                                dicc_obj['arch']=self.arch
                                if hasattr(tool, "INDEXED"):
                                        if not self.fdlist.has_key(tool.INDEXED):
                                                self.fdlist[ tool.INDEXED ] = []
                                        fdlist = self.fdlist[ tool.INDEXED ]
                                else:
                                        fdlist = []
                                tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist,fdlist)
                                tool.load(dicc_obj)
                                showtext=tool.Show()
                                NumberofXp=tool.setNumber(self.xpacketlist[-1])
                                alltext= tool.NAME+" #%s\n"%str(NumberofXp)+showtext
                                height=get_pixel_height(self.xpacketlist[-1],alltext)
                                iter = liststore.append()
                                liststore.set_value(iter, 0, alltext)
                                newcolor= "#%06x" % (int(tool.color[1:], 16) + 0x10*int(NumberofXp))
                                liststore.set_value(iter, 1, tool.color)
                                liststore.set_value(iter, 2,height)
                                liststore.set_value(iter,3,tool)
                                toolx_name = "" #reseting vars
                                dicc_obj = {}
                                self.ModBufSize(self.xpacketlist[-1]) # set the buffer size
                                self.ModBuf2pad(self.xpacketlist[-1])
                        elif toolc_name:
                                #print "esta tool %s tiene status %s" %(toolc_name,str(childrenstatus))
                                self.log("Loading cPacket object %s..." %toolc_name)
                                toolc_name = toolc_name.replace("\r", "")
                                (clase, directory) = self.cToolbar[toolc_name]
                                tool = clase.Toolobject()
                                if hasattr(tool, "INDEXED"):
                                        if not self.fdlist.has_key(tool.INDEXED):
                                                self.fdlist[ tool.INDEXED ] = []
                                        fdlist = self.fdlist[ tool.INDEXED ]
                                else:
                                        fdlist = []
                                
                                tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                tool.load(dicc_obj)
                                if hasattr(tool, "INDEXED") and hasattr(tool, "INDEX_ADD"):
                                        # A new connect, a new fd
                                        
                                        self.fdlist[tool.INDEXED].append( len(self.fdlist[tool.INDEXED]) + 1)
                                        
                                        #make global host and port
                                if hasattr(tool, "getHost"):
                                        self.host = tool.getHost()
                                if hasattr(tool, "getPort"):
                                        self.port = tool.getPort()
                                        
                                if tool.NAME == "DCEconnect":
                                        self.dceval=tool.get_dceval()

                                #NumberofXp=tool.setNumber(self.xpacketlist[-1])
                                if childrenstatus =="0": # is a parent!
                                        dicc_childstat ={}
                                        NumberofCp=tool.setNumber(self.cpacketlist[-1])
                                        #print "Insert row here...line 2069"
                                        iter=self.insert_row(model,None,tool.Show()+" #%s" %str(NumberofCp),"FD: %s" %tool.cfd,tool,None,None,None)
                                        dicc_childstat['1']=iter
                                else:
                                        parent=dicc_childstat['%s'%str(childrenstatus)]
                                        NumberofCp=tool.setNumber(self.cpacketlist[-1])
                                        #print "Insert row here, line 2075"
                                        iter=self.insert_row(model,parent,tool.Show()+" #%s" %str(NumberofCp),"FD: %s" %tool.cfd,tool,None,None,None)
                                        dicc_childstat['%s'%str(int(childrenstatus)+1)]=iter




                                toolc_name = "" #reseting vars
                                dicc_obj = {}
                        else:
                                if toolpl_name:
                                        self.log("Loading Protocol Logic object %s..." %toolpl_name)
                                        toolpl_name = toolpl_name.replace("\r", "")
                                        (clase, directory) = self.plToolbar[toolpl_name]
                                        tool = clase.Toolobject()
                                        if hasattr(tool, "INDEXED"):
                                                if not self.fdlist.has_key(tool.INDEXED):
                                                        self.fdlist[ tool.INDEXED ] = []
                                                fdlist = self.fdlist[ tool.INDEXED ]
                                        else:
                                                fdlist = []

                                        tool.setEssential(self.arch,None,self.cpacketlist,self.xpacketlist, fdlist)
                                        tool.load(dicc_obj)
                                        #NumberofXp=tool.setNumber(self.xpacketlist[-1])
                                        if childrenstatus =="0": # is a parent!
                                                dicc_childstat ={}
                                                iter=self.insert_row(model,None,tool.Show(),"",tool,None,None,None)
                                                dicc_childstat['1']=iter
                                        else:
                                                parent=dicc_childstat['%s'%str(childrenstatus)]
                                                iter=self.insert_row(model,parent,tool.Show(),"",tool,None,None,None)
                                                dicc_childstat['%s'%str(int(childrenstatus)+1)]=iter

                                        toolpl_name = "" #reseting vars
                                        dicc_obj = {}


                        if line[:9] == "--BEGIN--":

                                self.addxpacket(None)
                                liststore=self.xpacketlist[-1].get_model()



                        elif line[:9] == "--START--":
                                self.addcpacket(None)
                                model=self.cpacketlist[-1].get_model()
                        elif type == "++" :
                                toolx_name = value[:-1]

                        elif type == "+.":
                                tempa=value.split("&",1)
                                toolc_name = tempa[0]
                                childrenstatus=tempa[1][:-1].split("=",1)
                                childrenstatus=childrenstatus[1].replace("\r","")


                        elif type == "..":
                                tempa=value.split("&",1)
                                toolpl_name = tempa[0]
                                childrenstatus=tempa[1][:-1].split("=",1)
                                childrenstatus=childrenstatus[1].replace("\r","")



                        elif type ==".+":
                                self.log("Loading Badchars...")
                                self.badcharentry[-1].set_text(value[2:-2])
                                self.badchars=value[2:-2]          



                f.close()
                self.log("Project loaded successfully.")

        def loadAsXpackets(self,event,filename):
                lines=[]
                f = open(filename,"r")
                for a in range(1,4):
                        lines.append(f.readline())

                self.log("Loading Name...")
                (tag,val) = lines[2].split("=",1)
                val=val.replace("\r","")
                self.newprojectname={'entry1': val.replace("\n","")} 
                dicc_obj={}
                toolx_name=""

                for line in f:
                        type=line[:2]

                        value=line[2:].replace("\r","")
                        #print value

                        if type=="**":
                                (tag, val) = value.split("=", 1)

                                dicc_obj[tag] = val[:-1]

                        elif toolx_name:
                                self.log("Loading xPacket buffer: %s..." %toolx_name)
                                toolx_name = toolx_name.replace("\r", "")
                                (clase, directory) = self.Toolbar[toolx_name]
                                tool = clase.Toolobject()
                                dicc_obj['badchars'] = self.badchars
                                dicc_obj['arch']=self.arch
                                if hasattr(tool, "INDEXED"):
                                        if not self.fdlist.has_key(tool.INDEXED):
                                                self.fdlist[ tool.INDEXED ] = []
                                        fdlist = self.fdlist[ tool.INDEXED ]
                                else:
                                        fdlist = []

                                tool.setEssential(self.arch,self.get_badchars(self.badcharentry,widget),self.cpacketlist,self.xpacketlist, fdlist)
                                tool.load(dicc_obj)
                                showtext=tool.Show()
                                NumberofXp=tool.setNumber(self.xpacketlist[-1])
                                alltext= tool.NAME+" #%s\n"%str(NumberofXp)+showtext
                                height=get_pixel_height(self.xpacketlist[-1],alltext)
                                iter = liststore.append()
                                liststore.set_value(iter, 0, alltext)
                                newcolor= "#%06x" % (int(tool.color[1:], 16) + 0x10*int(NumberofXp))
                                liststore.set_value(iter, 1, tool.color)
                                liststore.set_value(iter, 2,height)
                                liststore.set_value(iter,3,tool)
                                if tool.NAME =="EIP":
                                        self.targets[0]=["default target",tool.getDefaultTarget()]
                                toolx_name = "" #reseting vars
                                dicc_obj = {}
                                self.ModBufSize(self.xpacketlist[-1])
                                self.ModBuf2pad(self.xpacketlist[-1])

                        if line[:9] == "--BEGIN--":

                                self.addxpacket(None)
                                liststore=self.xpacketlist[-1].get_model()


                        elif line[:9] == "--START--":
                                self.addcpacket(None)
                                model=self.cpacketlist[-1].get_model()
                        elif type == "++" :
                                toolx_name = value[:-1]

                        elif type == "+.":
                                tempa=value.split("&",1)
                                toolc_name = tempa[0]
                                childrenstatus=tempa[1][:-1].split("=",1)
                                childrenstatus=childrenstatus[1]


                        elif type == "..":
                                tempa=value.split("&",1)
                                toolpl_name = tempa[0]
                                childrenstatus=tempa[1][:-1].split("=",1)
                                childrenstatus=childrenstatus[1]



                        elif type ==".+":
                                self.log("Loading Badchars...")
                                self.badcharentry[-1].set_text(value[2:-2])
                                self.badchars=value[2:-2]          



                f.close()
                self.log("Project loaded successfully.")

        def loadFilechooser(self,event):
                if event.get_name() == "LoadButton" or event.get_name() == "open1" or event.get_name() == "open2":
                        try:
                                self.mainscnwin.hide()
                                self.xpacketlist=[]
                                self.cpacketlist=[]
                        except:
                                pass
                filechooserdialog = gtk.glade.XML (self.gladefile, "filechooserdialog1")
                filechooser = filechooserdialog.get_widget("filechooserdialog1")
                path = os.getcwd()+ os.path.dirname("/VisualSpike/Projects/")
                filechooser.set_current_folder(path)
                filter = gtk.FileFilter()
                filter.set_name("VSP Files")
                filter.add_pattern("*.vsp")
                filechooser.add_filter(filter)

                response = filechooser.run()
                filechooser.hide()
                if response == gtk.RESPONSE_OK:
                        filename = filechooser.get_filename()
                        newprojectname={}
                        # we need xtype before going on
                        lines=[]
                        f = open(filename,"r")
                        for a in range(1,20):
                                lines.append(f.readline())
                        (tag,val) = lines[2].split("=",1)
                        val=val.replace("\r","")
                        self.newprojectname={'entry1': val.replace("\n","")} 
                        (tag,val) = lines[18].split("=",1)
                        val=val.replace("\r","")
                        self.xtype=val.replace("\n","").replace("\"","")
                        f.close()
                        if event.get_name() == "load_as_xpackets1":
                                self.loadAsXpackets(None,filename)
                        else:
                                self.NewWorkspace(None)
                                self.loadEnv(None,filename)
                                self.loadState(None,filename)

                return

def pre_flight_checks():
        ##Check the python version, if the license has been agreed and generate parse tables
        canvasengine.license_check()

pre_flight_checks()
app=appgui()
gtk.gdk.threads_init()
gtk.gdk.threads_enter()
gtk.main()




