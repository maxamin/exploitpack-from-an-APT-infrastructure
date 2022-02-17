#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
newgui.py - a test file for the new gui
"""

#import gc
import os
import sys
import time
import gobject
import cairo

#for translations
from gettext import gettext as _
import gettext
gettext.bindtextdomain("CANVAS",localedir = "gui/locale/")
gettext.textdomain("CANVAS")

TODO = """
remove COMMENTED_CODE
"""

COMMENTED_CODE = """
sys.path.append("/usr/local/lib/python2.3/site-packages/")

#This program requires GTK 1.2
#make sure the python in your current path can use GTK 1.2 - check to make sure
#/usr/bin/python and /usr/local/bin/python are the same if you have problems
#on one account and not on others.


def try_import():
    import sys
    '''tries to import gtk and if successful, returns 1'''
    print "Attempting to load gtk...Path=%s"%sys.path
    # To require 1.2
    try:
        import pygtk
        pygtk.require("2.0")
    except:
        print "pyGTK not found. You need GTK 2 to run this."
        print "Did you \"export PYTHONPATH=/usr/local/lib/python2.2/site-packages/\" first?"
        print "Perhaps you have GTK2 but not pyGTK, so I will continue to try loading."
        
        
    try:
        import gtk,gtk.glade
        import atk,pango #for py2exe
        import gobject
    except:
        import traceback,sys
        traceback.print_exc(file=sys.stdout)
        print "I'm sorry, you apparantly do not have GTK2 installed - I tried"
        print "to import gtk, gtk.glade, and gobject, and I failed."
        print "Please contact Immunity CANVAS Support and let them know what version you have"
        return 0
    return 1

if not try_import():
    site_packages=0
    #for k in sys.path:
    #    if k.count("site-packages"):
    #        print "existing site-packages path %s found\n"%k
    #        site_packages=1
    if site_packages == 0:
        from stat import *
        print "no site-packages path set, checking.\n"
        check_lib = [ "/usr/lib/python2.2/site-packages/",
                        "/usr/local/lib/python2.2/site-packages/",
                        "/usr/local/lib/python2.3/site-packages/" ]
        for k in check_lib:
            try:
                path=os.path.join(k,"pygtk.py")
                #print "Path=%s"%path
                if open(path)!=None:
                    print "appending", k
                    sys.path=[k]+sys.path
                    if try_import():
                        break
            except:
                pass
    if not try_import():
        sys.exit(0)
        
import gtk,gtk.glade
import atk,pango #for py2exe
import gobject
"""

from localNode import localNode
#this imports devlog
from internal import *

#this gets rid of devlog when not debugging gui 
#def devlog(*astr):
#    pass

import threading

# NEW gui graphing class
from gui.WorldMap import canvasgraph
from hostKnowledge import hostKnowledge

#### START CODE

localNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X ...          X",
    "X .........    X",
    "X .........    X",
    "X              X"
    ]

pythonNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X .......      X",
    "X ........     X",
    "X .    ...     X",
    "X ........     X",
    "X .......      X",
    "X ..           X",
    "X ..           X",
    "X ..           X",
    "X ..           X",
    "X ..           X",
    "X              X"
    ]

scriptNodeXPM= [
 "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X     ....     X",
    "X    ......    X",
    "X   ..    ..   X",
    "X    ..    ..  X",
    "X     ..       X",
    "X      ..      X",
    "X       ..     X",
    "X  ..    ..    X",
    "X  ..     ..   X",
    "X   ..  ...    X",
    "X    ....      X"
    ]

Win32MOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X              X",
    "X .          . X",
    "X .          . X",
    "X .     .    . X",
    "X ..   ..   .. X",
    "X ............ X",
    "X   ..   ..    X",
    "X   ..   ..    X",
    "X              X",
    "X              X"
    ]


Win32MOSDEFNodeBUSYXPM = [
    "16 12 3 1",
    "  c blue",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X              X",
    "X .          . X",
    "X .          . X",
    "X .     .    . X",
    "X ..   ..   .. X",
    "X ............ X",
    "X   ..   ..    X",
    "X   ..   ..    X",
    "X              X",
    "X              X"
    ]

Win64MOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X              X",
    "X .          . X",
    "X .          . X",
    "X .     .    . X",
    "X ..   ..   .. X",
    "X ............ X",
    "X   ..   ..    X",
    "X   ..   ..    X",
    "X              X",
    "X              X"
    ]

Win64MOSDEFNodeBUSYXPM = [
    "16 12 3 1",
    "  c blue",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X              X",
    "X .          . X",
    "X .          . X",
    "X .     .    . X",
    "X ..   ..   .. X",
    "X ............ X",
    "X   ..   ..    X",
    "X   ..   ..    X",
    "X              X",
    "X              X"
    ]

linuxMOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X ..   . .     X",
    "X ..    .      X",
    "X ..   . .     X",
    "X ..           X",
    "X ..           X",
    "X ...          X",
    "X ..........   X",
    "X ..........   X",
    "X              X",
    "X              X"
    ]


bsdMOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X ..........   X",
    "X ..       .   X",
    "X ..      ..   X",
    "X .. . .. .    X",
    "X ..     .     X",
    "X ..      ..   X",
    "X ..      ..   X",
    "X ..........   X",
    "X              X",
    "X              X"
    ]


bsdbusyNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X              X",
    "X              X",
    "X ..........   X",
    "X ..       .   X",
    "X ..      ..   X",
    "X .. . .. .    X",
    "X ..     .     X",
    "X ..      ..   X",
    "X ..      ..   X",
    "X ..........   X",
    "X              X",
    "X              X"
    ]


solarisMOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X     ...      X",
    "X   .......    X",
    "X  ..     ..   X",
    "X  ..          X",
    "X  ..          X",
    "X   ..         X",
    "X    ..        X",
    "X     ..       X",
    "X  .   ...     X",
    "X  ..   ...    X",
    "X  ........    X",
    "X    ...       X"
    ]

osxMOSDEFNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c white",
    "X     ...      X",
    "X   .......    X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X  ..     ..   X",
    "X   .......    X",
    "X     ...      X"
    ]

SQLNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c orange",
    "X c white",
    "X     ...      X",
    "X   .......    X",
    "X  ..     ..   X",
    "X  ..          X",
    "X  ..          X",
    "X   ..         X",
    "X    ..        X",
    "X     ..       X",
    "X  .   ...     X",
    "X  ..   ...    X",
    "X  ........    X",
    "X    ...       X"
    ]



EmbeddedHostXPM = [
    "16 12 3 1",
    "  c white",
    ". c orange",
    "X c white",
    "X   .........  X",
    "X   .........  X",
    "X   ..         X",
    "X   ..         X",
    "X   ..         X",
    "X   ..         X",
    "X   .........  X",
    "X   .........  X",
    "X   ..         X",
    "X   ..         X",
    "X   .........  X",
    "X   .........  X"
    ]

JavaHostXPM = [
    "16 12 3 1",
    "  c white",
    ". c orange",
    "X c white",
    "X   .........  X",
    "X   .........  X",
    "X      ..      X",
    "X      ..      X",
    "X      ..      X",
    "X      ..      X",
    "X      ..      X",
    "X      ..      X",
    "X   .. ..      X",
    "X   .. ..      X",
    "X   .....      X",
    "X    ....      X"
    ]


PowerShellNodeXPM = [
    "16 12 3 1",
    "  c white",
    ". c darkred",
    "X c blue",
    "X .......      X",
    "X ........     X",
    "X .    ...     X",
    "X ........     X",
    "X .......      X",
    "X ..    ...    X",
    "X ..   .....   X",
    "X ..  ..   ..  X",
    "X ..    ..     X",
    "X ..  .   ..   X",
    "X ..  ......   X",
    "X ..   ...     X"
    ]


import gtk
pythonNodePB = gtk.gdk.pixbuf_new_from_xpm_data(pythonNodeXPM)
scriptNodePB = gtk.gdk.pixbuf_new_from_xpm_data(scriptNodeXPM)
localNodePB = gtk.gdk.pixbuf_new_from_xpm_data(localNodeXPM)
Win32MOSDEFNodePB = gtk.gdk.pixbuf_new_from_xpm_data(Win32MOSDEFNodeXPM)
Win32MOSDEFNodePBBUSY = gtk.gdk.pixbuf_new_from_xpm_data(Win32MOSDEFNodeBUSYXPM)
linuxMOSDEFNodePB = gtk.gdk.pixbuf_new_from_xpm_data(linuxMOSDEFNodeXPM)
solarisMOSDEFNodePB = gtk.gdk.pixbuf_new_from_xpm_data(solarisMOSDEFNodeXPM)
bsdbusyNodeXPMPB = gtk.gdk.pixbuf_new_from_xpm_data(bsdbusyNodeXPM)
bsdMOSDEFNodeXPMPB = gtk.gdk.pixbuf_new_from_xpm_data(bsdMOSDEFNodeXPM)
SQLNodeXPMPB = gtk.gdk.pixbuf_new_from_xpm_data(SQLNodeXPM)
osxMOSDEFNodeXPMPB = gtk.gdk.pixbuf_new_from_xpm_data(osxMOSDEFNodeXPM)
EmbeddedHostPB = gtk.gdk.pixbuf_new_from_xpm_data(EmbeddedHostXPM)
JavaHostXPMPB = gtk.gdk.pixbuf_new_from_xpm_data(JavaHostXPM)
PowerShellNodePB = gtk.gdk.pixbuf_new_from_xpm_data(PowerShellNodeXPM)

text_to_PB={}
text_to_PB[""]=None
text_to_PB["LocalNode"]=localNodePB
text_to_PB["Win32MOSDEFNode"]=Win32MOSDEFNodePB
text_to_PB["Win32MOSDEFNodeBUSY"]=Win32MOSDEFNodePBBUSY

text_to_PB['Win64MOSDEFNode']       = Win32MOSDEFNodePB
text_to_PB['Win64MOSDEFNodeBUSY']   = Win32MOSDEFNodePBBUSY

text_to_PB["PythonNode"]=pythonNodePB
text_to_PB["ScriptNode"]=scriptNodePB
text_to_PB["linuxMOSDEFNode"]=linuxMOSDEFNodePB
text_to_PB["solarisMOSDEFNode"]=solarisMOSDEFNodePB
text_to_PB["Win32Host"]=Win32MOSDEFNodePB
text_to_PB["LinuxHost"]=linuxMOSDEFNodePB
text_to_PB["SolarisHost"]=solarisMOSDEFNodePB
text_to_PB["bsdMOSDEFNode"]=bsdMOSDEFNodeXPMPB
text_to_PB["bsdbusyMOSDEFNode"]=bsdbusyNodeXPMPB
text_to_PB["SQLNode"]=SQLNodeXPMPB
text_to_PB["osxNode"]=osxMOSDEFNodeXPMPB
text_to_PB["osxMOSDEFNode"]=osxMOSDEFNodeXPMPB 
text_to_PB["EmbeddedHost"]=EmbeddedHostPB
text_to_PB["JavaNode"]=JavaHostXPMPB
text_to_PB["PowerShellNode"]=PowerShellNodePB

def treeview_expand_to_path(treeview, path):
    """Expand row at path, expanding any ancestors as needed.

    This function is provided by gtk+ >=2.2, but it is not yet wrapped
    by pygtk 2.0.0."""
    if path==None:
        return
    for i in range(len(path)):
        treeview.expand_row(path[:i+1], open_all=False)

def get_sorted_iterator(model,lineobj,current):
    """
    Takes in an interface (1.1.1.1) and returns an interator you should place this
    after. Obviously this is potentially O(N)...welcome to bubblesort!
    """
    sort_obj=lineobj.get_sort_value()
    devlog("get_sorted_iterator","sortable object looking for something greater than: %s"%sort_obj)
    myiter=current
    if model.iter_has_child(myiter):
        #if we didn't have any children, so we just return the 
        #parent host KnowledgeContainer. Otherwise we go down the list.
        nextiter=model.iter_children(myiter)
        while nextiter!=None:
            #we have some children
            obj=model.get_value(nextiter,0) #get the object contained here
            value=obj.get_sort_value()
            devlog("get_sorted_iterator","sortable obj found: %s"%value)
            if value >= sort_obj:
                devlog("get_sorted_iterator","Found a larger object: %s < %s"%(sort_obj,value))
                #we found the next thing...
                return myiter
            #otherwise...
            myiter=nextiter
            nextiter=model.iter_next(myiter)
    if myiter==None:
        devlog("Serious error in newgui: myiter==None! Looking for value: %s"%sort_obj)
    devlog("get_sorted_iterator","Found no larger object")
    return myiter

def findobj_sibling(model, searchobj, current):
    """
    Finds an object in a tree, but looks at siblings as well
    Useful when there IS no root object, so model.get_iter_root()
    returns the first object.
    
    Used in canvasguigtk2.py for Exploit tree, as opposed to the 
    Knowledge tree, which does have a single root iter.
    """
    myiter=current
    while myiter:
        obj=findobj(model,searchobj, myiter)
        if obj:
            return obj
        myiter=model.iter_next(myiter)
    return None

def findobj(model,searchobj,current):
    #devlog("newgui::findobj(%s,%s,%s)"%(current,searchobj,current))
    myiter=current

    try:
        row=model.get_value(myiter,0)
    except:
        print "Serious NodeTree Error: myiter is not a object!!=%s"%myiter
        import traceback
        traceback.print_exc(file=sys.stderr)
        devlog("Exiting findobject with None")
        return None
    #devlog("row[0]=%s searchobj=%s"%(row,searchobj))
    
    if row==searchobj:
        #print "Found! - returning %s"%(myiter)
        #devlog("Exiting findobj with %s"%myiter)
        return myiter
    else:
        if model.iter_has_child(myiter):
            childiter=model.iter_children(myiter)
            while childiter!=None:
                myiter=findobj(model,searchobj,childiter)
                if myiter!=None:
                    #devlog("Exiting findobj with %s"%myiter)
                    return myiter
                childiter=model.iter_next(childiter)

    #print "Not found!"
    #devlog("Exiting findobject with None")
    return None

# this class is used to map connections
# between known hosts, thus splitting off
# 'known' networks deduced from traceroutes

class TargetGui:
    """ graph known networks from known hosts using traceroute onto a world map """
    
    def __init__(self, targetWidget, engine=None):
        self.nodeLines = None
        self.eventbutton = 3
        self.engine = engine
        self.last_target_line = None
        self.target_line = None
        self.graph=None
        
        # XXX: engine code ...
        self.target_hosts_init = self.engine.target_hosts
        
        self.canvas = targetWidget

        # init the map layover ...
        #map_path = 'WorldMap' + os.sep + 'nasa_map.png'
        map_path = os.path.join('gui','WorldMap','nasa_map.png')
        try:
            map = cairo.ImageSurface.create_from_png(map_path)
        except AttributeError:
            self.engine.log("You don't have a modern pycairo, so we can't do mapping...")
            return  #did not work
        self.graph = canvasgraph.MapCanvas(map)
        self.graph.set_size_request(map.get_width(), map.get_height())

        self.graph._text = 'CANVAS Target Map'

        # reconnect the default button press handler
        self.graph.disconnect(self.graph.handlerid)
        self.graph.connect('button-press-event', self.on_graph_line_press)
       
        # link in the graph widget to the target widget
        self.canvas.add_with_viewport(self.graph)
        
        # show it
        self.canvas.show_all()
    
    def update_targets(self):
        """ updates the engine's target line list """

        targets = []
        for host_key in self.graph.hosts.keys():
            host = self.graph.hosts[host_key]
            if host['target'] == True:
                if host['target_line']:
                    targets.append(host['target_line'])
                    
            # walk any children
            for c_key in host['children'].keys():
                c_host = host['children'][c_key]
                if c_host['target'] == True:
                    if c_host['target_line']:
                        targets.append(c_host['target_line'])
                        
        first = False
        for target in targets:
            if first == False:
                self.engine.set_target_host(target)
                first = True
            else:
                self.engine.set_additional_target_host(target)
        
        return

    def on_graph_line_press(self, obj, event):
        """ Similar to our line_press for traditional menu stuff, but for graphs """
        
        x = event.x
        y = event.y
        self.eventbutton = event.button
        
        #print "XXX: TARGET FRAME -> button press (x: %d, y: %d)"% (event.x, event.y)
        # check if we have a callback handler for this map click in any known hosts
        for host_key in self.graph.hosts.keys():
            host = self.graph.hosts[host_key]
            
            host_x = host['x']
            host_y = host['y']
            if x in range(host_x, host_x+5) and y in range(host_y, host_y+5):
                handler = host['click_handler']
                ip = host['ip']
                
                # if we want button specific actions .. do it here
                if event.button == 1:
                    # XXX: engine call from gui code .. but will do
                    
                    if host['target'] == False:
                        host['target_line'] = hostKnowledge(ip, None)
                        host['target'] = True
                    else:
                        if host['target_line']:
                            if self.engine.unset_target_host(host['target_line']) != False:
                                host['target'] = False
                                host['target_line'] = None
                            else:
                                print "[X] could not unset target .. likely set as primary target ? reverting to initial values .. "
                                # back up to target_hosts backup
                                host['target'] = False
                                host['target_line'] = None
                                self.engine.set_target_host(self.target_hosts_init[0])

                    # update the object in the list
                    self.graph.hosts[host_key] = host
                    # update the targeting in the gui
                    self.update_targets()
                    self.graph.redraw()
                    continue
                
                if event.button == 2:
                    # you can set click handler to be anything .. good for glueing in your own non-canvas modules ;)
                    if handler:
                        handler()
                    continue
                
                if event.button == 3:
                    # handle any available additional hosts for that city location
                    item_handlers = {}
                    if len(host['children']):
                        for ip in host['children']:
                            # this is where the actual activate handler function is set
                            item_handlers[ip] = self.pull_down_targeting
                        # show the menu
                        self.graph.pop_up_menu(item_handlers, event.button, event.time)
                    else:
                        print "[X] No additional hosts available for this location .."
                    continue
                                    
        return
    
    def pull_down_targeting(self, obj, ip):
        """ handles pull down targeting """
         
        # we dont need to draw shizit for this, but we do need to set the target_line for unsets
        p_key = None
        host = None
        for key in self.graph.hosts.keys():
            p_host = self.graph.hosts[key]
            if len(p_host['children']):
                if ip in p_host['children'].keys():
                    print "[!] found parent host for child ip: %s"% ip
                    p_key = key
                    host = p_host['children'][ip]
        
        # operate on found child host
        if host['target'] == False:
            host['target_line'] = hostKnowledge(ip, None)
            host['target'] = True
        else:
            if host['target_line']:
                if self.engine.unset_target_host(host['target_line']) != False:
                    host['target'] = False
                    host['target_line'] = None
                else:
                    print "[X] could not unset target .. likely set as primary target ? reverting to initial values .. "
                    # back up to target_hosts backup
                    host['target'] = False
                    host['target_line'] = None
                    self.engine.set_target_host(self.target_hosts_init[0])
                    
        # update the object in the list
        self.graph.hosts[p_key]['children'][ip] = host
        # update the targeting in the engine list
        self.update_targets()
        return
    
    # XXX: dummy placeholder for menu testing
    def bogus(self, obj, event):
        print "HANDLED MENU ACTIVATE!"
        print repr(obj)
        print repr(event)
        return
    
class nodegui:
    def __init__(self,nodetree,local,engine, WorldMapFrame=None):
        self.engine = engine
        self.local = local
        
        if WorldMapFrame:
            self.targetGraph = TargetGui(WorldMapFrame, self.engine)
            
        self.init_app(nodetree, local)
        
    def set_engine(self,engine):
        self.engine=engine


    def addNode(self,node):
        devlog('nodegui::addNode', "called with parent %s" % node.parent)
        #recursively go through and set up the node tree from the start node
        p=self.addLine(node)
         
        self.addLine(node.interfaces)
        for interface in node.interfaces.get_children():
            self.addLine(interface)
            for listeners in interface.get_children():
                self.addLine(listeners)
                
        self.addLine(node.hostsknowledge)        
        for host in node.hostsknowledge.get_children():
            self.addLine(host)
            for c in host.get_children():
                print "add knowledge",c
                self.addLine(c)
                

        self.addLine(node.connected_nodes)
        for n in node.connected_nodes.get_children():
            self.addNode(n)
        #print "nodegui::addNode leaving"
        #self.nodetree.set_cursor(p)
        treeview_expand_to_path(self.nodetree, p)
        return

    def addLineTest(self,a,b):
        import hostKnowledge
        #lineObj=hostKnowledge.knowledgePrimitive(self.local,"ifids","known"*500,100)
        for i in range(0,500):
            lineObj2=hostKnowledge.knowledgePrimitive(self.local,"tag","known",100)
            self.addLine(lineObj2)
            self.delete(lineObj2)
        
    def addLine(self,lineobj):
        """
        Adds a new line to our node tree - this is used for all the lines and should only
        be called from the main thread. We check to make sure we're in the main thread
        and devlog(all) if we are not (since this is a serious error)!
        
        We take in a lineobj which is determined to have a parent (or be the root node).
        """
        #print "In addLine"
        #gc.collect()
        threadid=threading.currentThread()
        #devlog("all","threadid=%s"%threadid)
        if "Main" not in str(threadid):
            devlog("BUG - someone called newgui::addLine from a non-Main thread currentthread: %s"%threadid)
        
        #print "newgui::addLine"
        #no duplicates
        devlog('newgui::addLine', "%s" % lineobj.get_text())

        start=self.model.get_iter_first()
        if start!=None and findobj(self.model,lineobj,start):
            devlog('newgui::addLine', "returning without doing anything")
            return 
        
        #we reset the line object's engine right here. This should not
        #be necessary, but it also doesn't hurt
        lineobj.set_engine(self.engine)
        #print "\naddLine(%s)"%lineobj
        if lineobj.parent==None:
            devlog('newgui::addLine', "lineobj.parent==None!")
            if lineobj != self.local:
                #this is probably a serious error that should be sent to all!
                devlog('newgui::addLine', "Not our LocalNode - returning...")
                return 
            #it IS our local node
            myiter=self.model.insert_after(None,None)
        else:
            #somehow find the parent node in the tree 
            parentobj=lineobj.parent
            devlog('newgui::addLine', "Finding parent: %s"%parentobj)
            #for line in tree, if line[0]==parentobj, return line
            #http://www.pygtk.org/pygtk2`tutorial/sec-TreeModelInterface.html
            #start is set at the top of this whole function
            myiter=findobj(self.model,parentobj,start)
            myvalue=None
            if myiter:
                myvalue=self.model.get_value(myiter,0)
                devlog('newgui::addLine', "Found parent: %s"%myvalue)
            if myiter==None:
                devlog('newgui::addLine', "{Not adding}")
                return 

            parentiter=myiter
            devlog("newgui::addLine","Parent iter type: %s"%parentiter)
            typestr=str(lineobj)
            devlog("newgui::addLine","Adding type: %s"%typestr)
            if  hasattr(lineobj,"get_sort_value"):
                #if we are a hostknowledge or other sortable type, we want to be inserted in a particular order!
                devlog("newgui::addLine","Adding sortable object: %s: %s"%(typestr,lineobj.get_sort_value()))
                siblingiter=get_sorted_iterator(self.model, lineobj, myiter)
                if siblingiter==None:
                    devlog("newgui::addLine","Sibling iter was none...")
                else:
                    devlog("newgui::addLine","Sibling iter was %s..."%str(self.model.get_value(siblingiter,0)))                    
                if siblingiter==parentiter:
                    #clear this so it doens't get all confused. You can't be both my sibling
                    #and my parent, see?
                    siblingiter=None 
                myiter=self.model.insert_after(parentiter,siblingiter,row=None)
            else:
                #parent, but no sibling (since we are the only thing in the list or are not sortable)
                myiter=self.model.insert_after(parentiter,None,row=None)

        lineobj.gui=self
        pix=lineobj.get_pix()
        #print "Pix=%s"%pix
        if pix!=None:
            pix=text_to_PB[pix]
        if pix=="":
            pix=None
        #print "before 0"
        self.model.set_value(myiter,0,lineobj) #NOT A VISIBLE COLUMN (since text=0 has never been set)
        #print "before 1"
        self.model.set_value(myiter,1,pix) #Set the icon in the first column
        #print "before 2"
        self.model.set_value(myiter,2,lineobj.get_text()[:150]) #set the text in the first column
        #print "Before get_path"
        ret=self.model.get_path(myiter)
        #print "End of addLine"
        
        # update the world map with any new host lines
        if isinstance(lineobj, hostKnowledge) and self.targetGraph.graph:
            self.targetGraph.graph.add_host(lineobj)
            self.targetGraph.graph.redraw()
            
        return ret

    
    def delete(self, line):
        "Delete a line from our node tree"
        #debugging information
        #gc.collect()
        
        threadid=threading.currentThread()
        if "Main" not in str(threadid):
            devlog("threading","BUG - someone called newgui::delete from non-main thread: Currentthread: %s"%threadid)
        
        if  isinstance(line,  hostKnowledge) and self.targetGraph.graph:
            self.targetGraph.graph.del_host(line.interface)
            self.targetGraph.graph.redraw()
        
        treestore=self.model
        start=treestore.get_iter_first()
        from_parent=findobj(treestore,line,start)

        if from_parent==None:
            #print "From parent is None! Why?"
            return 
        iter = treestore.iter_children(from_parent)
        while iter:
            treestore.remove(iter)
            iter = treestore.iter_children(from_parent)
        if from_parent:
            treestore.remove(from_parent)
        else:
            print "No parent to that line?"
        return
    
    def update_object(self,object):
        #print "Update_object"
        #gc.collect()
        start=self.model.get_iter_first()
        myiter=findobj(self.model,object,start)
        if myiter==None:
            #error!
            return 
        pix=object.get_pix()
        #print "Pix=%s"%pix
        if pix!=None:
            pix=text_to_PB[pix]
        if pix=="":
            pix=None
        #print "update 0 %s %s"%(myiter,object)
        self.model.set_value(myiter,0,object) #NOT A VISIBLE COLUMN (since text=0 has never been set)
        #print "update 1"
        self.model.set_value(myiter,1,pix) #Set the icon in the first column
        #print "udpate 2"
        self.model.set_value(myiter,2,object.get_text()[:150]) #set the text in the first column
        #print "row changed"
        self.model.row_changed(self.model.get_path(myiter),myiter)
        #print "return update"
        #TODO: we need to force an expose event to the treeview now, somehow!
        return
    
    def init_app (self,nodetree,local):
        "Initialise the application."
        self.local=local
        self.nodetree=nodetree
        nodetree.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        #set up columns

        #this "text=X" is the column number
        cellpb = gtk.CellRendererPixbuf()
        cell = gtk.CellRendererText()


        columne = gtk.TreeViewColumn("Expander")
        columni = gtk.TreeViewColumn("Icon", cellpb, pixbuf=1)
        columnn = gtk.TreeViewColumn("Node", cell)
        columnn.add_attribute(cell, 'text', 2) #column 2 is in "Name" but is a text column
        
        self.nodetree.append_column(columne)
        self.nodetree.append_column(columni)
        self.nodetree.append_column(columnn)
        

        model=gtk.TreeStore(gobject.TYPE_PYOBJECT,gtk.gdk.Pixbuf,gobject.TYPE_STRING)
        self.nodetree.set_model(model)
        self.model=model
        
        self.addNode(local)
        self.local=local
        return

    def on_selected(self, selected_text, secondary_text=None):
        """
        Pretends like we got a menu_response on each of the selected 
        objects in our tree
        
        The first object gets selected_text and the rest get secondary_text
        unless its set to None
        """
        if secondary_text==None:
            secondary_text=selected_text
        objList=[]
        model,paths=self.nodetree.get_selection().get_selected_rows()
        #get all the objects we have
        for path in paths:
            #path is really a "tuple" but we convert it to a string
            iter=model.get_iter(path) 
            if iter:
                objList+=[model.get_value(iter,0)]
                
        #now for each object, pass it the "menu option" from selected_text
        first=True
        for lineObj in objList:
            if first:
                lineObj.menu_response(None, selected_text)
                first=False 
            else:
                lineObj.menu_response(None, secondary_text)
        return 
        
        
    def line_press(self, obj, event):
        """
        This handles right-mouse clicks on our newgui nodetree
        """
        #print "newgui::Line Press called"
        iter=None
        if event.button == 3:
            model,paths=self.nodetree.get_selection().get_selected_rows()
            for path in paths:
                #path is really a "tuple" but we convert it to a string
                iter=model.get_iter(path) 
                break
            #model,iter=self.nodetree.get_selection().get_selected()
            if iter==None:
                #print "weird - nothing was selected, yet we got a right-click"
                return

            x=int(event.x)
            y=int(event.y)
            try:
                path, col, colx, celly= obj.get_path_at_pos(x,y)
            except TypeError:
                return
            obj.grab_focus()
            obj.set_cursor(path, col, 0)
            nodetext=model.get_value(iter,2)
            lineobj=model.get_value(iter,0)
            menulines=lineobj.get_menu()
            if menulines==[]:
                #print "Nothing in menu...returning"
                return
            else:
                #print "Something in menu of %s: %s"%(nodetext,menulines)
                pass
            
            mymenu=gtk.Menu()
            for l in menulines:
                mline=gtk.MenuItem(_(l))
                mline.connect("activate", lineobj.menu_response, l)
                mline.show()
                mymenu.append(mline)
            #print nodetext, str(event)
            mymenu.show()
            mymenu.popup(None,None, None,event.button, event.time)
            
def quit(args):
    gtk.main_quit()
    return

    
if __name__ == '__main__':

    local=localNode()
    #do splashscreen here maybe
    gladefile="newgui.glade"
    window="window1"
    import gtk.glade
    wTree = gtk.glade.XML (gladefile, window)
    nodetree=wTree.get_widget("nodeview")
    nodetree.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
    mygui=nodegui(nodetree,local,None)    
    #window1 must be the main app window!!!
    dic = {"on_quit_button_clicked"        : quit,
           "on_window1_destroy" : (quit),
           #"on_nodeview_button_press_event":mygui.line_press,
           "on_nodeview_button_press_event":mygui.addLineTest,
           }
    window=wTree.get_widget("window1") # sure there must be another way
    wTree.signal_autoconnect (dic)

    #import time
    #time.sleep(10)
    #hmmm
    try:
        gtk.threads_init()
    except:
        print "No threading was enabled when you compiled pyGTK!"
        sys.exit(1)
    gtk.threads_enter()
    gtk.main ()
    gtk.threads_leave()
