#!/usr/bin/env python
##ImmunityHeader v1 
###############################################################################
## File       :  MeatMarket.py
## Description:  New NodeManager graphic canvas
##            :  
## Created_On :  Wed Aug 12 15:39:40 2009
## Created_By :  Rich
## Modified_On:  Thur Oct 15 14:45:00 2009
## Modified_By:  AlexM
## Modified_On:  Tue Aug 14 11:03:20 2012
## Modified_By:  miguel
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
##Reimplementation of the canvasgraph.py stuff Bas did using the super-sexy-swinging-sounds of gaphas (http://gaphor.devjavu.com/browser/gaphas) 
##MeatMarket name represents the rethink of our knowledge display system to include 'MeatNode' items as well as 'CyberNode' (lololol) items

import sys
import os
import math
import re

#for translations
from gettext import gettext as _
import gettext
gettext.bindtextdomain("CANVAS",localedir = "gui/locale/")
gettext.textdomain("CANVAS")

from engine.config import canvas_root_directory
p=os.path.join(canvas_root_directory,"gui") 
#insert this at the beginning in case they already have gaphas installed,
#because we want them to load OUR gaphas, not the system gaphas.
sys.path.insert(0, os.path.abspath(p))

from internal import devlog

import gobject, gtk, gtk.glade
gtk_glade_hook = gtk.glade
import cairo
import gaphas
from gaphas import canvas
from gaphas import util
from gaphas import tool
from exploitutils import orderIPlist

##Our own little gaphas extensions etc
from gaphas import gaphas_extras

#replicated from canvasguigtk2.py :<
def get_glade_file():
    canvas_gui_style="default"
    __glade_file = "canvasgui2_%s.glade" % canvas_gui_style
    #following will fail on Unicode paths on Windows (:<)
    #moddir = os.path.dirname(sys.modules[__name__].__file__)
    moddir=os.path.join(os.path.abspath(u'.'),u"gui")
    __glade_file = os.path.join(moddir, __glade_file)
    return __glade_file

class MeatMarket:
    """
    Overall class using gaphas underneath to do all the difficult and smart drawing stuff
    Here we make more complex primitives available to represent CANVAS relevent things
    in a pretty way.
    """
    
    def __init__(self, gtk_element_to_embed_to, engine, maingui):
        """
        Set up our Gaphas canvas - be careful not to confuse a gaphas canvas with Immunity CANVAS :)
        
        gtk_element_to_embed_to - an initialised gtk window in which to add our gaphas canvas
        """
        ##This is the Immunity CANVAS engine where the data we are visualising resides
        self.engine=engine
        
        ##This is the rest of the GTK gui
        self.maingui=maingui
        
        ##Dictionary to hold our gaphas object id and the node identifier mappings
        ## allows us to complete all our edge drawing operations - keyed on CanvasNode name
        self.node_to_ui_obj_dict={}
        
        ##list mapping which nodes are joined to which, a tuple of gaphas object id's and the linking line object id
        self.node_links=[]
        
        self.selected_nodes=[]
        
        ##Where does our initial element (localhost) start - all placement after this is relative to this
        self.initial_x=70
        self.initial_y=70
        
        ##Grid layout sizes - how do we space elements when we are choosing where to place em?
        self.grid_x=140
        self.grid_y=140
        
        ##Zoom level - goes between -10 and 10 as keeping it at infinite zoom/unzoom seemed to cause problems...
        self.zoom_level = 0
        
        self.gaphas_view = view = gaphas.view.GtkView()
        
        ##Join keypresses for zooming in and out
        view.connect('key-press-event', self.on_key_press)
        
        ##Toolchain - What do we want pre built gaphas code to do for us?
        tool = gaphas.tool.ToolChain(view)        ##Tool container
        tool.append(gaphas.tool.HoverTool())  ##Let us know when items have mouse hover
        
        menu_tool = MenuTool()
        menu_tool.MeatMarket = self 
        #tool.append(gaphas.tool.PanTool()) ##Middle button move canvas
        #tool.append(gaphas.tool.RubberbandTool()) ##Group selection
        tool.append(menu_tool)       ##Selection of elements and dragging  + menu pop ups
        view.tool = tool
        
        ##Get the actual gaphas canvas to paint onto
        view.canvas = gaphas.Canvas()
        
        ##Set background to black - we are way more ninja this way
        view.modify_bg(gtk.STATE_NORMAL, gtk.gdk.color_parse('#000'))
        view.show()
        
        ##embed the canvas
        self.gaphas_tab=gtk_element_to_embed_to
        self.gaphas_tab.add(view)
                     
        ##Initialise our localnode in the gui
        self.lNode = self.add_node(self.engine.localnode, selected=True, undeletable=True)
        self.selected_nodes.append(self.lNode)
    
    def on_key_press(self, widget, event):
        """
        When the MeatMarket canvas is focussed how do we want to interpret key presses
        """
        if event.keyval in [gtk.keysyms.plus, gtk.keysyms.equal, gtk.keysyms.KP_Add]:
            if self.zoom_level < 8:
                self.gaphas_view.zoom(1.2)
                self.zoom_level += 1
                return True
        
        elif event.keyval in [gtk.keysyms.minus, gtk.keysyms.KP_Subtract]:
            if self.zoom_level > -15:
                self.gaphas_view.zoom(1.0/1.2)
                self.zoom_level -= 1
                return True
        
        return False
    
    def add_node(self, node, selected=False, undeletable=False):
        """
        Add a new node to our display
        """
        title = node.getname()
        nIP   = node.get_interesting_interface()
        nType = node.nodetype
        # get the username
        whoami = ''
        if hasattr(node, "shell") and hasattr(node.shell, "whoami_username") and node.shell.whoami_username:
            whoami = node.shell.whoami_username

        cNode = NodeItem(node, self.maingui, self, name=title, ip=nIP, node_type=nType, create_selected=selected, undel=undeletable, whoami=whoami)
        self.gaphas_view.canvas.add(cNode)
        
        ##Add it to our dictionary
        self.node_to_ui_obj_dict[title]=cNode
        
        ##Where do we want to thing to appear
        if node.parent:
            par = self.node_to_ui_obj_dict[node.parent.parent.getname()]
            ##Get the position of the parent
            p_pos_x = par.x_pos
            p_pos_y = par.y_pos
            
            ##If we have a parent we want to place ourselves one row beneath it, and to the right of any existing children
            ## we do that by applying multipliers to the grid size values
            
            ##How far right do we want to be
            x = p_pos_x + (self.grid_x * par.last_child_x_pos)
            y = p_pos_y + self.grid_x
            par.last_child_x_pos += 1
            
            #move the node
            cNode.matrix.translate(x , y)
            
            cNode.x_pos = x
            cNode.y_pos = y
            cNode.last_child_x_pos = 0
            
        else:
            cNode.matrix.translate(self.initial_x, self.initial_y)
            cNode.x_pos = self.initial_x
            cNode.y_pos = self.initial_y
            cNode.last_child_x_pos = 0
        
        cNode.request_update()
        
        if node.parent:
            # node.parent is a nodesList .. the actual node is nodesList.parent :>
            src = self.node_to_ui_obj_dict[node.parent.parent.getname()]
            self.connect_nodes(src, cNode)
        
        self.gaphas_view.queue_draw_refresh()

        return cNode
    
    def connect_nodes(self, parent, child):
        """
        Take two gaphas objects (NodeItems) and connect them with a line.
        """
        connector = gaphas_extras.connect_nodes(self.gaphas_view, parent, child)
        self.node_links.append((parent, child, connector))
        parent.child_gaphas_nodes.append(child)
    
    def node_removal(self, node):
        """
        Takes a GAPHAS node, finds all its children & connectors, removes them
        from the GAPHAS canvas, and cleans up all the dictionaries etc where they
        are registered
        """
        ##Find all the gaphas items children and connectors, remove from the 
        ## gaphas canvas and pass back a list of canvasNodes for the caller to
        ## remove from the engine
        children_to_kill = self.find_node_children(node)
        for item in children_to_kill:
            self.gaphas_view.canvas.remove(item)
            try:
                ##remove from canvas to gaphas mapping dictionary
                del self.node_to_ui_obj_dict[item.node.getname()]
            except AttributeError:
                ##Connector lines have no node attribute so just skip 
                pass
            except KeyError:
                ##can't find that item?
                devlog("gui", "Could not find item to delete: %s"%item.node.getname())
                pass 
        ##If that node was currently selected AND there was no other node
        ## selected we should selected localNode
        if len(self.gaphas_view.selected_items) == 0:
            self.gaphas_view.select_item(self.lNode)

    def find_node_children(self, node):
        """
        This finds all the children (and their children etc) and connecting edges
        of a supplied node, it also deletes the associations between these nodes and 
        their edges from the node_links dictionary.
        
        It finally returns the list of node + children + connector gaphas items
        to delete 
        BUT DOES NOT DO THE DELETE THEM FROM GAPHAS CANVAS
        this is left to the caller
        """
        things_to_remove=[node]
        positions_to_delete=[]
        
        for edge_triple in self.node_links:
            src, dst, conn = edge_triple
            
            ##Check for childrens children ..... first          
            if src in node.child_gaphas_nodes :
                things_to_remove+=self.find_node_children(src)
            elif dst in node.child_gaphas_nodes:
                things_to_remove+=self.find_node_children(dst)

            ##Now add the connector item between us and parent to remove list
            if node == dst:
                things_to_remove.append(conn)
                positions_to_delete.append(self.node_links.index(edge_triple))
                
        ##Now remove the effected triples from our node link list
        adjuster=0 #to account for the fact our list keeps getting shorter as u iterate
        for pos in positions_to_delete:
            del self.node_links[pos-adjuster]
            adjuster+=1

        return things_to_remove
    
    def remove_canvas_node(self, canvasNode):
        """
        Method for external code to remove nodes from the gaphas canvas, i.e. when you delete a node from the commandline you 
        need to remove it from the canvas view
        
        Returns:
                False for failure
                True on success 
        """
        try:
            gItem = self.node_to_ui_obj_dict[canvasNode.getname()]
        except KeyError:
            print "Node %s not found on node view canvas"%(canvasNode.getname())
            return False
        
        ##Find all the gaphas items children and connectors, remove from the 
        ## gaphas canvas and pass back a list of canvasNodes for the caller to
        ## remove from the engine
        self.node_removal(gItem)
        
        return True
    
    
    def move_nodeui_to_absolute(self, node_ui, new_x, new_y):
        """
        Moves a NodeUI to an absolute place in the View
        
        TODO: Should this really be using the canvas.get_matrix_i2c() ?
        There's some confusion in my head regarding whether we want to use gaphas view projections or gaphas canvas projections.
        Right now we use gaphas view projections, but this seems to be less correct.
        """
        isinstance(node_ui, NodeItem) #help WingIDE
        
        devlog("gui", "Absolute move of %s requested to %s, %s"%(node_ui.node.getname(), new_x, new_y))
        i2v = self.gaphas_view.get_matrix_i2v(node_ui)
        x, y = i2v.transform_point(0,0)
        devlog("gui", "Node %s moving from: x=%s, y=%s"%(node_ui.node.getname(), x, y))
        node_ui.matrix.translate(-x,-y) #move me to origin
        node_ui.matrix.translate(new_x,new_y) #move me to where I need to go

        ##update and show this node (queued requests are delayed gratification 
        ##here, so we go for immediate action)                    
        self.gaphas_view.canvas.request_update(node_ui) 
        
        node_ui.x_pos=new_x
        node_ui.y_pos=new_y               

class NodeItem(gaphas_extras.ConnectableCircle):
    """
    This is the primative via which all CANVAS nodes are displayed
    
    We superclass an already done circle drawer from gaphas
    """
    
    def __init__(self, node, maingui, MM, name="none", ip="0.0.0.0", node_type="NoNodeType", radius=40, offset=5, create_selected=False, undel=False, whoami=''):
        """
        Initialise our node visual element with default values
        """
        super(NodeItem, self).__init__(radius, offset)
        
        ##Set easy access colour palette
        self.PALETTE = gaphas_extras.PALETTE
        
        self.radius = radius
        self.name   = "ID: %s"% name        
        self.type   = node_type
        self.node   = node  #actual canvasnode instance
        # we get the username as paramater because that this take a bit of time
        self.whoami = whoami.strip().replace('\x00', '')
        
        selected_ip = self.node.interfaces.get_callback_interface()
        if not selected_ip:
            ##No interface on this not is selected - stick with a default
            self.ip=ip 
        else:
            ##IP shown in the node now reflects the curerrently selected callback interface for that node ....
            self.ip = str(selected_ip)
        
        self.maingui=maingui #The canvasguigtk2 thingamabob
        
        self.MM=MM  ##reference to the MeatMarketclass so we can call back into it
        self.view = MM.gaphas_view
        
        self.create_selected=create_selected
        self.undel=undel
        
        self.node_colour = self.getNodeColour()
        self.fontsize = 12 
        
        self.w=radius*3
        self.h=radius*3
        
        self.square_inside = self._calc_sq_in_box()
        
        self.arg_to_callable = None
        self.x_pos=0 #two vars for displaying on views
        self.y_pos=0
        
        self.child_gaphas_nodes = []
    
    def getNodeColour(self):
        """
        For a passed in node, get its nodetype and thus it's colour from the NodeColours dictionary
        above. If no node of that type can be found in the dictionary return a default colour.
        
        OUT: RGB triplet 
        """
        default_colour="red2" #default if we can't find the colour in our dictionary
        
        try:
            return self.PALETTE[self.node.colour.lower()]
        except KeyError:
            return self.PALETTE[default_colour.lower()]

    def _calculate_width(self, cr, txt):
        """
        Calculate the and width of our text at the surrent contexts settings
        """
        pad = 1
        
        w, h = gaphas.util.text_extents(cr, txt)
        #print "TEXT EXTENTS",w, h
        
        if w > (self.square_inside - pad) or h > (self.square_inside - pad):
            return 0
        else:
            return 1
            
        
    def auto_size_text(self, cr, text, x, y):
        """
        Iterate until the supplied text fits in the width of our box
        then print it at the supplied co-ordinates
        """
        ##Calculate the biggest fintsize this text can be
        fontsize=self.fontsize
        while 1:
            if self._calculate_width(cr, text):
                break
            
            else:
                ##Too big - reduce fontsize and try again
                fontsize -= 1
                cr.set_font_size(fontsize)
        
        ##print it at supplied co-ordinates
        gaphas.util.text_align(cr, x, y, text, align_x=0, align_y=0)
        
        ##Restore our prefered font size
        cr.set_font_size(self.fontsize)
                
        return
        
    def _calc_sq_in_box(self):
        """
        Calculate the size of the biggest square we can fit in our circle so as we can see if
        the extents of our text is outside of this 
        
        Put a sq in a circle and us pythagorus of an equalateral triangle to find the size of the
        edge of the square: 2X ^2 = Hyp^2
        
        """
        hyp=pow( (2*self.radius), 2)        
        side=math.sqrt(float(hyp)/float(2))
        
        return side
        
        
    def draw(self, context):
        """
        Draw the ellipse.
        
        I believe you'll want to be in the GKT context for this?
        """
        cr = context.cairo
        
        if self.create_selected:
            self.view.select_item(self)
            self.create_selected=False        
        
        selected = self.node in self.MM.engine.passednodes
        
        if selected :
            cr.set_source_rgba(self.node_colour[0], self.node_colour[1], self.node_colour[2], 0.70)
            gaphas.util.path_ellipse(cr, 0, 0, 2 * self.radius - 4, 2 * self.radius - 4)
            cr.fill_preserve()
            cr.stroke()
            
            cr.set_source_rgba(self.node_colour[0]*1.1, self.node_colour[1]*1.1, self.node_colour[2]*1.1, 0.9)        
            gaphas.util.path_ellipse(cr, 0, 0, 2 * self.radius + 4, 2 * self.radius + 4 )
            cr.stroke()      
            
        else:
            cr.set_source_rgba(self.node_colour[0], self.node_colour[1], self.node_colour[2], 0.45)
            gaphas.util.path_ellipse(cr, 0, 0, 2 * self.radius, 2 * self.radius)
            cr.fill_preserve()
            cr.stroke()
        
        ##Add the node name
        if selected :
            cr.set_source_rgba(1, 1, 1, 1)
        else:
            cr.set_source_rgba(1, 1, 1, 0.7)
        
        # Select the font
        cr.select_font_face('Sans', cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
        cr.set_font_size(self.fontsize)
        
        #gaphas.util.text_align(cr, 0, -20, self.name, align_x=0, align_y=0)
        self.auto_size_text(cr, self.name, 0, -20)
        
        if self.type != 'LocalNode' and self.type != 'NoNodeType' and self.whoami: 
            # add current_user in the node
            cr.set_source_rgba(60, 100, 60, 1)
            cr.select_font_face('Sans', cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
            cr.set_font_size(self.fontsize - 1)
            node_user = self.whoami
            # only username in windows
            node_user = node_user if '\\' not in node_user else node_user.split('\\')[1] 
            # rename computername to system only in windows
            node_user = node_user if node_user[-1] != '$' else 'SYSTEM'
            node_user = '[%s]' % node_user.upper()
            self.auto_size_text(cr, node_user, 0, -35)

            # restore font type
            if selected :
                cr.set_source_rgba(1, 1, 1, 1)
            else:
                cr.set_source_rgba(1, 1, 1, 0.7)

            cr.select_font_face('Sans', cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_NORMAL)
            cr.set_font_size(self.fontsize)

        #gaphas.util.text_align(cr, 0, 0, self.ip, align_x=0, align_y=0)
        self.auto_size_text(cr, self.ip, 0, 0)
        #gaphas.util.text_align(cr, 0, 15, self.type, align_x=0, align_y=0)
        self.auto_size_text(cr, self.type, 0, 15)
        
        ##Add the "selected" string, if selected
        if selected :
            #hmm, ideally we'd be able to determine primary versus secondary selected nodes here
            #but we can't for now.
            cr.set_source_rgba(0.9, 0.9, 0.9, 0.9)
            cr.select_font_face('Sans', cairo.FONT_SLANT_NORMAL, cairo.FONT_WEIGHT_BOLD)
            cr.set_font_size(self.fontsize)
                
            #gaphas.util.text_align(cr, 0, -20, self.name, align_x=0, align_y=0)
            self.auto_size_text(cr, "(selected)", 0, 30)
    
    def intersect(self, alpha):
        radius = math.pow(math.cos(alpha)/(self.w/2.), 2) + math.pow(math.sin(alpha)/(self.h/2.), 2)
        radius = 1/math.pow(radius, 0.5)
        point = (math.cos(alpha)*radius, math.sin(alpha)*radius)
        return (radius, point)
        
    
    def setup_canvas(self):
        super(NodeItem, self).setup_canvas()
        h1, h2 = self._handles

        self.center=h1
        
        for h in self._handles:
            h.movable = False
            h.visible = False
    
    def right_click(self, event, cNode):
        """
        What to do on a right click - invoked from a gaphas tool.
        
        To get which item has been click the tool uses:
        """
        devlog("gui", "right click for node:%s"%(self.name))
        self.response_view = self.view
        self.response_cNode = cNode
        
        host_submenu      = [_("Set as target host"),_("Set as additional target host"),
                             _("View all knowledge"), 
                             _("Forget this host knowledge"),
                             _("Save host to file"), _("Add note to host"), 
                             {_("Knowledge"):self.generate_knowledge_menu} ]
        #{"Knowledge":[{"pop":["a"]},"g","p"]}
        
        host_selected_submenu = [_("Unset as targeted host"), _("View all knowledge"),
                                 _("Forget this host knowledge"),
                                 _("Save host to file"), _("Add note to host"), 
                                 {_("Knowledge"):self.generate_knowledge_menu}]
        
        interface_submenu = [_("Set as callback interface"), {"Active Listeners":self.generate_listener_list_menu}, _("Check for listener connection")]
        interface_selected_submenu = [{_("Active Listeners"):self.generate_listener_list_menu}, _("Check for listener connection")]
        
        ##Get the knowledge we know for hosts and interfaces as these are all lines in the menu
        ## each then has a submenu attached
        hostlines, interfacelines = self.get_dynamic_menu_content()
        
        ##Get the base menu items that are static and pre-constructed using glade
        menu = self.get_rightclick_menu_glade()
        
        ##Build the dynamic menu contents (hosts and interfaces we have knowledge of)
        insert_pos = 2
        selected_icon = gtk.STOCK_GO_FORWARD
        
        ##Find which hosts/interface are selected
        host_selected_list=[]
        
        ##order ascending ip addresses ipv4 first then ipv6
        hostline_ordered_list = orderIPlist( hostlines.keys() )
        for h in hostline_ordered_list:
            if hostlines[h][1]:
                host_selected_list.append(hostline_ordered_list.index(h)+insert_pos)
                
            ##Append hostname after the ip address if we have it - we have space in the menu so we may as well use it
            n=hostlines[h][0].get_knowledge("DNSName")
            if n:
                ##And remove all the crap prepended/appended to the hostknowledge - this should realy be a preseperated dict or summin - hostknowledge needs an overhaul
                domain = n.known_text
                ##Skip localhost
                if not domain.replace(" ","") == "localhost" and not domain.replace(" ","") == "Pending":    
                    hostline_ordered_list[hostline_ordered_list.index(h)] += "  [ %s ]"%(domain)
                    
            ##Replace the Knowledge entry in the submenu list with this hosts hostknowledge
            
        
        menu = self.build_submenu(menu, hostline_ordered_list, host_submenu, insert_pos, host_selected_list, selected_icon, host_selected_submenu)
        
        insert_pos = len(hostlines.keys()) + 4
        interface_selected_list=[]
        interfaceline_ordered_list = interfacelines.keys()
        interfaceline_ordered_list.sort()
        for i in interfaceline_ordered_list:            
            if interfacelines[i][1]:
                interface_selected_list.append(interfaceline_ordered_list.index(i)+insert_pos)
                
        menu = self.build_submenu(menu, interfaceline_ordered_list, interface_submenu, insert_pos, interface_selected_list, selected_icon, interface_selected_submenu)
        
        #TODO must walk to arbitrary submenu depth and assign callback function - pass callback func to submenu gen?
        ##For each item in a submenu set the right click response to the
        ## same method which parses what label was clicked and takes action accordingly
        for mi in menu.get_children():

            ##Get the element of the top level clicked to get the submenu

            ##seperators do not need anything
            label = getattr( mi.child, "get_label", None)
            if not label:
                #print "seperator - continuing"
                continue            
            label = label()
            ##As we got smart earlier and added in a dns name we need to remove it otherwise we won't match in our container
            #label = label[:label.find("[")].replace(" ","")
            if label.find("[") != -1:
                label = label[:label.find("[")].replace(" ","")
            if hostlines.has_key( label ):
                #print "%s is a host"%(label)
                top_level_item = hostlines[label][0]
            elif interfacelines.has_key( label ):
                #print "%s is an interface"%(label)
                top_level_item = interfacelines[label][0]
            else:
                ##This are our preconstructed Knowledge and Interface menus
                #print "Other %s"%(label)
                top_level_item = "pre_constructed"
                            
            ##Now get the associated submenu
            sm = mi.get_submenu()
            
            ##Now for each submenu entry set the response method
            try:
                for smi in sm.get_children():                     
                    smi.connect("activate", self.get_rightclick_response, smi.child.get_label(), top_level_item) ##Context and Cnode are so we can update the gaphas gaphas once we have changed the text in a node (if we do)
    
            except AttributeError:
                continue
                
        menu.popup(None, None, None, event.button, event.time)
        
    def generate_listener_list_menu(self, line, interface):
        """
        Generator function for build_submeu - returns a list if a submenu is desired or None if not
        
        This grabs the list of listeners on a current interface
        """
        for interface_obj in self.node.interfaces.get_children():

            if interface_obj._text == interface:
                ret_listener = []

                for listener in interface_obj.get_children():

                    str_rep = listener.text
                    if listener.argsDict.has_key("fromcreatethread") and listener.argsDict.get("fromcreatethread"):
                        str_rep += " (fromcreatethread)"
                    ##ret_listener.append(str_rep)
                    ret_listener.append({str_rep: self.get_active_listener_submenu})
                    
                if len(ret_listener) >0:
                    return ret_listener
                else:
                    return None

        return None
    
    def get_active_listener_submenu(self, listener_txt, b):
        """
        Generator function for a list of actions that can be taken on a listener
        """
        al_submenu = ["Kill listener"]
        
        ##Get the listener object so we can see if fromcreatethread is set or not
        listener = self.get_listener_obj_from_string(listener_txt)

        return al_submenu
        
    def generate_knowledge_menu(self, line, host_ip):
        """
        Generator function for build_submeu - returns a list if a submenu is desired or None if not
        
        This grabs all the knowledge data associated with the host IP
        """
        knowledge_to_show = ["OS","Language","SMBServer","SMBDomain","TCPPorts", "UDPPorts", "MACADDRESS", "Users", "Note"]
        
        ##As we got smart earlier and added in a dns name we need to remove it otherwise we won't match in our container
        hostname_there=host_ip.find("[")
        if hostname_there != -1:
            host_ip = host_ip[:host_ip.find("[")].replace(" ","")
        
        knowledge = self.node.hostsknowledge.get_known_host(host_ip)
        
        if not knowledge:
            knowledge = None

        else:
            knowledge_items = knowledge.get_all_knowledge_as_list()
            knowledge=[]
            
            # AlexM 10/15/09
            # We have a visual buffer width of 50, to make it pretty we need to break up long lists. This tells the GUI to look for multiple lists
            for item in knowledge_items:
                if re.search("TCPPorts[0-9]", item.tag):
                    knowledge_to_show.append(item.tag)
            
            for item in knowledge_items:
                
                ##Do we wanna show this knowledge
                if item.tag not in knowledge_to_show:
                    continue
                
                str_rep = "%s: %s "%(item.tag, item.known_text[:50])

                knowledge.append(str_rep)
            knowledge.sort()
        
        return knowledge
        
    
    def check_for_connection(self, interface_ip):
        """
        Prod each listener on the interface with the magic to kick start the called back node if it has been started on a child node
        """    
        for interface_obj in self.node.interfaces.get_children():
            try:
                if interface_ip._text == interface_obj._text :
                    
                    #print "MATCH",interface_obj._text,"**",interface_obj.listeners_that_are_listening,interface_obj.get_children()
                    for listener in interface_obj.get_children():
                        self.maingui.gui_queue_append("check_listener_for_connection", [listener])
            except AttributeError:
                ##If we don't have any listners get_children returns None which obviously has no _text attribute 
                pass

    
    def get_rightclick_menu_glade(self):
        """
        Grab a base menu made in glade - has the static items for the knowledge
        and interface menu's done already and pretty pictures as well
        """
        dname       = "meatmarket_rightclick"
        wTree2      = gtk_glade_hook.XML(get_glade_file(),dname)
        menu      = wTree2.get_widget(dname)
        
        return menu
    
    def build_submenu(self, menu, menu_items, submenu_items, insert_pos, selected_pos=[], selected_icon=None, selected_submenu=None, higher_level_item=None, do_connect_subitem = False):
        """
        Given a base menu, a list of menuitems, and a list of submenuitems
        create a submenu structure at the specified position in the menu. Each
        new line in the menu has the same submenu elements.
        e.g.     =menu=
                    |-MenuItem 1
                           |-Submenu1
                           |-Submenu2
                           |-.....
                    |-MenuItem 2
                           |-Submenu1
                           |-Submenu2
                           |-.....
                    |....
        
        Optionally a list of selected positions can be specifed, this can have either/both an icon associated to show selection and a different
        submenu than unselected menu lines. ATM selected icon must be a stock item string
        
        if submenu_items has dictionary then this creates a further submenu and so on - if the attribute of the dict is a callable we use it as a
        generator function which creates a list, if its an iterable its just iterated.
        
        click callback is the click response fucntion that is connected to all leaf nodes (nodes node producing another submenu - meaning that can be clicked casuing an action)
        """
        for line in menu_items:
            ##A line for our menu named by the host/interface
            menuitem    = gtk.ImageMenuItem(line)
            
            ## if selected add the specified icon
            if insert_pos in selected_pos and selected_icon:
                img = gtk.image_new_from_stock(selected_icon, 1)
                menuitem.set_image(img)
            
            
            ##If a different item has been selected for a submenu and we're selected swap out and use that submenu
            if type(selected_submenu) != type(None) and insert_pos in selected_pos:
                submenu_to_use = selected_submenu
            else:
                ##reset to standard submenu
                submenu_to_use = submenu_items
                
            ##Is our submenu a a static list or a callable so dynamic content can be created for this entry?
            if callable(submenu_to_use):
                submenu_to_use = submenu_to_use(line, higher_level_item)

            #print "SUBMENU TO USE",submenu_to_use,type(submenu_to_use)
                
            if submenu_to_use:
                
                ##Make a menu container for the submenu
                submenu_cont   = gtk.Menu() 
                submenu_cont.show()
                    
                ##Now add in the correct lines for that submenu
                for subitem in submenu_to_use :

                    if type(subitem) == type({}):
                        ##dictionaries denote the submenu is a submenu itself - the key is use for the line entry - the value should be a list which we call ourselves with
                        ## iterate on ourselves basically
                        sub_sub = self.build_submenu(submenu_cont, subitem.keys(), subitem.values()[0], 0 , higher_level_item=line, do_connect_subitem = True )
                    else:
                        submenuItem = gtk.MenuItem(subitem)
                        submenuItem.show()
                        submenu_cont.append(submenuItem)
                        
                        ##Now for each submenu entry set the response method if that
                        ## has been requested - need this as no way to look for
                        ## existing handlers it seems ??
                        if do_connect_subitem:
                            submenuItem.connect("activate", self.get_rightclick_response, subitem, line) 
                    
                ##Attach the submenu to our menu
                menuitem.set_submenu(submenu_cont)
            else:
                ##If the item was suppose to have a submenu but doesn't dim it (unless it's selected)
                if insert_pos not in selected_pos:
                    menuitem.set_sensitive(False)
            
                
            menuitem.show()
            
            ##Finally add it to the right click menu proper at the desired position
            menu.append(menuitem)
            menu.reorder_child(menuitem,insert_pos)
            insert_pos += 1
            
        return menu
        
        
    def get_dynamic_menu_content(self):
        """ 
        This method gets all the hosts / interfaces currently in our knowledge base
         - our menus are dynamically built because this knowledge changes.
        """
        #print "regen_menus"
        # reset menus - keyed on textual representation - used as the menu entry line
        hostmenu      = {}
        interfacemenu = {}
        
        # Knowledge then all host knowledge
        for knowledge_obj in self.node.hostsknowledge.get_children():                
            
            hostmenu[knowledge_obj._text[6:]] = [knowledge_obj, knowledge_obj.activated]
            
        # Interfaces then all interfaces
        for interface_obj in self.node.interfaces.get_children():
            interfacemenu[interface_obj._text] = [ interface_obj, interface_obj.activated] 
                          
        return hostmenu, interfacemenu
    
    def get_rightclick_response(self, obj, item, last_clicked_host):
        """
        This is the function that is called whenever an item in our right click menu
        is clicked - what happens depends on what the text of the item is that is clicked
        """
        #print "Clicked: %s <%s>"%(item, last_clicked_host)
        #TODO cleanup up the last clicked host crap
        self.last_clicked_host = last_clicked_host
        self.last_clicked_interface = last_clicked_host
        
        if item == _("Browse filesystem"):
            self.maingui.gui_queue_append("browse_filesystem", [self.node])

        elif item == _("Listener Shell"):
            self.maingui.gui_queue_append("do_listener_shell", [self.node])
            
        elif item == _("Add new host"):
            self.maingui.gui_queue_append("add host", [self])
            
        elif item == _("Add interface"):
            self.maingui.gui_queue_append("add interface", [self.node.interfaces])
         
        elif item == _("Add hosts from file"):
            #pop up a dialog box and select the file (from the gui)
            self.maingui.gui_queue_append("Add hosts from file", [self])            
         
        #Depreciate by session support
        #elif item == "Load all hosts":
            #self.node.hostsknowledge.restore_state(self.MM.engine.OUTPUT_DIR)
            
        elif item == _("Forget all knowledge"):
            pass #has this ever been implemented??
        #??
        
        ##From hostKnowledge.hostKnowledge
        elif item == _("Set as target host"):
            self.last_clicked_host.additional=False
            self.last_clicked_host.set_as_target()
            
        elif item == _("Set as additional target host"):
            #don't set as additional host if we already are
            #either a primary or secondary host
            if not self.last_clicked_host.activated:
                self.last_clicked_host.additional=True 
                self.last_clicked_host.set_as_target()
                
        elif item ==_( "Unset as targeted host"):
            #only do this is we are the secondary target since we 
            #always have at least ONE target selected
            if self.last_clicked_host.additional:
                self.last_clicked_host.unset_as_target()
                
        elif item == _("View all knowledge"):
            #pop-a-box to view all of the knoweldge in it's dirty detail
            self.view_hosts_knowledge(self.last_clicked_host)
                
        elif item == _("Forget this host knowledge"):
            if self.last_clicked_host.interface=="127.0.0.1":
                self.last_clicked_host.engine.log("Don't try to delete the loopback interface, please")
            else:
                
                if self.last_clicked_host.engine.target_hosts[0] == self.last_clicked_host:
                    self.last_clicked_host.engine.set_target_host("127.0.0.1")
                elif self.last_clicked_host in self.last_clicked_host.engine.target_hosts:
                    self.last_clicked_host.engine.unset_target_host(self.last_clicked_host)

                self.last_clicked_host.parent.delete(self.last_clicked_host)                
        elif item== _("Save host to file"):
            self.last_clicked_host.save_state()
            #print "POPOPOP",self.node.hostsknowledge.get_all_known_hosts()

        elif item == _("Add note to host"):
            self.maingui.gui_queue_append("add note to host", [self.last_clicked_host])
                
        elif item == _("Connect to MOSDEF Service"):
            self.maingui.gui_queue_append("load host from file", [self.last_clicked_host])
        
        elif item == _("Set as callback interface"):
            self.last_clicked_interface.set_as_callback()
            self.ip = str(self.node.interfaces.get_callback_interface())   
            self.maingui.gui_queue_append("request_update",[self.response_view.canvas, self.response_cNode])
            
        elif item == _("Check for listener connection"):
            self.check_for_connection(self.last_clicked_interface)
            
        elif item == _("Kill listener"):
            ##Find the listener object from its description
            listener = self.get_listener_obj_from_string(last_clicked_host)
            
            if listener:
                listener.closeme()
                self.MM.engine.log("Killed Listener \"%s\"" % listener.text)
                listener.parent.delete(listener)
                
            
        #else:
        #    print "Unknown item: ",obj, item, last_clicked_host

            
    def get_listener_obj_from_string(self, listener_string_name):
        """
        From the string name of a listener, find the listener object
        """
        for interface_obj in self.node.interfaces.get_children():
            for listener in interface_obj.get_children():
                
                if listener.text in listener_string_name:
                    return listener
                
        ##Couldn't find it ?
        return None
                
            
    def request_update(self):
        self.maingui.gui_queue_append("request_update",[self.MM.gaphas_view.canvas, self])
        
    def select_single_node(self, node):
        """
        Add a node to CANVAS engine
        """
        #print "Adding", self.node
        self.MM.engine.set_first_node(node.node)
        
    def append_nodes(self):
        """
        Add additional ourselves as an additional node to the list
        """
        #print "appending",self.node
        self.MM.engine.append_node(self.node)
        
    def deselect_node(self):
        """
        Unselect the CANVASNode in the engine
        """
        #print "unselecting %s"%self.node
        #self.node.unselect()
        self.MM.engine.remove_node(self.node)
                
    def delete_node(self, view):
        """
        remove node from CANVAS engine
        """
        ##double check
        ret=self.pop_are_you_sure_box()
        
        if ret:
            ##remove from engine
            self.node.close_node_clean_gui()
            
        return ret
        
    def pop_are_you_sure_box(self):
        """
        What to do when we check version and find we are out of date
        """
        dname       = "are_you_sure_dialog"
        wTree2      = gtk_glade_hook.XML(get_glade_file(),dname)
        dialog      = wTree2.get_widget(dname)
        
        question=wTree2.get_widget("msg_txt")
        question.set_text("Are you sure you want to delete\n node %s and all its children?"%(self.name))
        
        response=dialog.run()
        
        if response==gtk.RESPONSE_OK:
            ret = True
        else:
            ret = False
        
        dialog.destroy() 
        
        return ret        
        
    def open_listener_shell(self, view):
        """
        Open up a listner shell window for the node
        """
        self.maingui.gui_queue_append("do_listener_shell", [self.node])
        
    def open_browser_window(self, view):
        """
        Open up a filesystem browser
        """
        self.maingui.gui_queue_append("browse_filesystem", [self.node])
        
    def view_hosts_knowledge(self, host):
        """
        Show all of the knowledge a node knows about a hosts in a pretty pop up window
        """
               
        knowledge = self.node.hostsknowledge.get_known_host(host.interface)
        
        if knowledge:
            kb = knowledge.get_all_knowledge_as_text()
            dname = "all_knowledge_dialog"
            wTree2 = gtk_glade_hook.XML(get_glade_file() ,dname)
            tBuf=gtk.TextBuffer()
            tBuf.set_text(kb)
            
            dialog = wTree2.get_widget(dname)
            dialog.set_title("All knowledge about host %s from %s"%(host.interface, self.name))
            
            ##UPDATE TITLE WITallH HOST IP
            kb_display=wTree2.get_widget("kb_txt")
            kb_display.set_buffer(tBuf)
            
            response=dialog.run()
                
            dialog.destroy()
            return
            
        else:
            devlog("gui", "No knowledge to show :( ")

class MenuTool(gaphas.tool.ItemTool):
    """
    Extension of the ItemTool from gaphas
    This deals with selecting, deleting, moving the node etc and conveys what we
    want to do back to the particular node that has been clicked on
    """
        
    def on_button_press(self, event):
        """
        Overide the default click handler for the tool
        """
        devlog("gui", "on_button_press in nodeview. Event.button=%s"%event.button)
        view = self.view
        
        ##What Node has been clicked in our display - gaphas does all the co-ordinate mapping for us !! YAY
        cNode = view.get_item_at_point((event.x, event.y))
        
        ##cNode == None indicates the underlying gaphas canvas has been clicked
        if not cNode:
            del view.selected_items
            return True
        
        ##We do not want to select the connector items
        if getattr(cNode, "is_connector", False):
            return False
        
        if event.button in self._buttons:
            ##This is our left click event - we call into the prebuilt gaphas tool for our selection stuff and then call the leftclick handler
            ## of our node object to convey selection/deselection up into the CANVAS engine
            
            ##select / move node - call into the ItemTool super class for this
            ret = super(MenuTool, self).on_button_press(event)
            
            if len(view.selected_items) == 1:
                ##Single node selected (left click on node)
                for n in view.selected_items:
                    cNode.select_single_node(n)
                
            elif cNode not in view.selected_items:
                ##Single node UNselected (ctrl left click on node that was previously selected)
                cNode.deselect_node()
            
            else:
                ##Multiple nodes selected (ctrl left click on node that was previously UNselected while another node was also already selected)
                for n in view.selected_items:
                    n.append_nodes()
            
            view.queue_draw_refresh()
            
            return ret
            
        elif event.button == 3:
            ##right click menu
            cNode.right_click(event, cNode)           
            return True
        
        return False
    
    def on_key_press(self, event):
        """
        Capture relevant keyboard input
        """
        devlog("gui",'on_key_press: ' + str(gtk.gdk.keyval_name(event.keyval)) + " " +str(event.keyval))
        view = self.view
        ret=False 
        ##If delete has been pressed delete the selected node(s)
        if gtk.gdk.keyval_name(event.keyval) == "Delete":
            
            for n in view.selected_items:                
                ##Is this a special undeletable node - like localnode?
                if n.undel:
                    devlog("gui", "Cannot delete this node - its SPECIAL!")
                    continue
                
                try:
                    ##Check if user REALLY wants to delete it
                    ret = n.delete_node(view)
                except Exception, err:
                    devlog("gui", "fake node")
                    #this is weird...let's print this out
                    import traceback
                    traceback.print_exc(file=sys.stdout)
                    
                ##If they answered no to 'are you sure?' just wait for next keystroke
                if not ret:
                    continue 
                    
                ##Visually remove all its connecting lines, children & the node itself
                n.MM.node_removal(n)
                
        
        ##If 'ENTER' or 'L' pressed on focussed node open a listner shell
        elif gtk.gdk.keyval_name(event.keyval) == 'Return' or gtk.gdk.keyval_name(event.keyval) == 'l':
            
            for n in view.selected_items:
                try:
                    ##inform the canvas engine++++
                    n.open_listener_shell(view)
                except Exception:
                    print "fake node"            
        
        ##If 'SPACE' or 'B' pressed on focussed node open a filesystem browser window
        elif gtk.gdk.keyval_name(event.keyval) == 'space' or gtk.gdk.keyval_name(event.keyval) == 'b':
            
            for n in view.selected_items:
                
                ##Does the underlying CANVAS node type have the browse capabilities?
                if not "VFS" in n.node.capabilities:
                    
                    dname       = "are_you_sure_dialog"
                    wTree2      = gtk_glade_hook.XML(get_glade_file(),dname)
                    dialog      = wTree2.get_widget(dname)
                    
                    question=wTree2.get_widget("msg_txt")
                    question.set_text("Nodes of type %s do not have the \ncapabilities to browse their filesystem\n"%(n.node.nodetype))
                    dialog.set_title("No VFS Capabilities")
                    
                    response=dialog.run()
                    
                    dialog.destroy() 
                    
                    return 
                
                ##inform the canvas engine++++
                n.open_browser_window(view)
