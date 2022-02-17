##ImmunityHeader v1
###############################################################################
## File       :  ad_browser.py
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
"""
Browser window - used by the GUI class to put a browser window
on the screen and update it.

The icons were taken from the FlatIcon website:
http://www.flaticon.com/

"""

import time
from threading import Thread
import gtk, gobject
import os
from canvaserror import *
import logging

def get_icon_path(iconname):
    moddir = os.path.join(os.path.abspath(u'.'),u"gui", u"pixmaps")
    __icon_file = os.path.join(moddir, iconname)
    return __icon_file


class ad_object(object):
    """
    Contains the data we need to display.
    Abstraction of an system inside an AD network.
    It could either be a computer, a user (normal or admin)
    """
    def __init__(self):
        self.name           = None
        self.os             = None
        self.fullname       = None
        self.attr           = {"is_domaincontroller": False, "is_computer": False, "is_admin": False, "is_group": False, "is_adUser": False, "is_localAdmin": False}
        self.fullpath       = None
        return

    def __str__(self):
        """
        Convert to a string object
        """
        return "%s %s %s %r (%s)" % (self.name, self.os, self.fullname, self.attr, self.fullpath)

    def __eq__(self, fo):
        #todo - replace this with something that automatically generates
        #this statement
        ret = (self.name==fo.name) and (self.fullname==fo.fullname) \
            and (self.os == fo.os) and (self.is_computer() == fo.is_computer())
        return ret

    def getFullHostName(self):
        ret = map(lambda x: x.split("="), self.fullpath.split(","))
        cn = None
        dc = []
        for t, v in ret:
            if t == "CN" and not cn:
                cn = v
            elif t == "DC":
                dc.append( v )
        return cn +"."+ ".".join(dc)

    def set_group(self, group):
        self.attr["is_group"] = group

    def is_group(self):
        return self.attr["is_group"]

    def set_computer(self, isdir):
        self.attr["is_computer"] = isdir

    def is_computer(self):
        return self.attr["is_computer"]

    def set_domaincontroller(self, isdir):
        self.attr["is_domaincontroller"] = isdir

    def is_domaincontroller(self):
        return self.attr["is_domaincontroller"]

    def set_admin(self, isexe):
        self.attr["is_admin"] = isexe

    def is_admin(self):
        return self.attr["is_admin"]
    
    def set_localAdmin(self, isexe):
        self.attr["is_localAdmin"] = isexe

    def is_localAdmin(self):
        return self.attr["is_localAdmin"]    
    
    def set_adUser(self, isexe):
        self.attr["is_adUser"] = isexe

    def is_adUser(self):
        return self.attr["is_adUser"]    

    def getIcon(self):
        try:
            if self.is_domaincontroller():
                return self.__get_icon__("ad_dc.png")
            else:
                if self.is_group():
                    return self.__get_icon__("group.png")
                else:
                    if self.is_admin():
                        return self.__get_icon__("administrator.png")
                    else:
                        if self.is_localAdmin():
                            return self.__get_icon__("localAdmin.png")
                        else:
                            if self.is_computer():
                                return self.__get_icon__("ad_computer.png")                        
                            return self.__get_icon__("user.png")
        except gobject.GError:
            return None

    def __get_icon__(self, name):
        return gtk.gdk.pixbuf_new_from_file(get_icon_path(name))


class ADbrowser_actor( Thread ):
    """
    Runs AD browser actions in a new thread - this keeps slow
    things from blocking our GUI. We then format the results
    and pass them back to a ADbrowser_window object for displaying
    Available actions:
      o obtain Local users
      o obtain Domain users
      o obtain Computers

    """
    def __init__(self, browser, sep, engine, node = None):
        Thread.__init__(self)
        self.browser    = browser
        self.sep        = sep
        self.engine     = engine
        self.node       = node

        self.__action_list = ("obtain_users", "obtain_computers", "obtain_ADusers", "obtain_ADuserDetails","psexec", "check4PSadmin", "DLExecute","localAdmin")
        return


    def set_action(self, action, args):
        """
        takes in an action and a argument dictionary

        Then will set up our internal state and get ready to run
        this on the node in our run() function
        """
        self.action     = action
        self.args       = args
        return


    def run(self):
        """
        We are a new thread so we run a Node.<something> to
        accomplish what the ADbrowser_window wanted.
        """
        if self.action in self.__action_list:
            return getattr(self, self.action)(  )
        else:
            raise Exception, "Action (%s) not in action list" % self.action

    def DLExecute(self):
        fo = self.args["ad_obj"]
        runpow =  self.engine.getModuleExploit("ad_dlexecute_psmosdef")
        #runpow.target = self.node.new_host(ip, add=0)
        p = self.node.parentnode.interfaces.get_callback_interface()
        if p:
            ip   = p.ip
            port = p.listeners_that_are_listening[0][1]
        else:
            logging.error("Fail to find a proper listener")
            return False
        runpow.argsDict["Computer"] = fo.name
        runpow.argsDict["callback_host"] = ip
        runpow.argsDict["callback_port"] = port
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret    = runpow.run()


    def check4PSadmin(self):
        logging.warn('Checking if Remote PS Admin avaialble')
        fo = self.args["ad_obj"]
        runpow =  self.engine.getModuleExploit("ad_check4PSadmin")

        """
        The path should be a machine, we need to refresh it
        """

        self.path   = self.args["ad_obj"].name
        runpow =  self.engine.getModuleExploit("ad_check4PSadmin")
        runpow.argsDict["computer"] = self.path
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret    = runpow.run()
        isAdmin = runpow.result
        if isAdmin:
            a.set_localAdmin(True)
        self.data   = ret
        self.browser.gui.gui_queue_append("browser_handler",
                                          [self.browser,
                                          "obtain_users_action",
                                           self])
        


    def obtain_users(self):
        """
        The path should be a machine, we need to refresh it
        """

        self.path   = self.args["ad_obj"].name
        runpow =  self.engine.getModuleExploit("ad_getlocalusers")
        runpow.argsDict["computer"] = self.path
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret    = runpow.run()
        users  = runpow.result
        if users:

            ret = []
            for user in users:
                a       = ad_object()
                a.fullpath = self.args["ad_obj"].fullpath
                a.name  = user[0].strip()  # User Name
                a.path  = self.path + self.sep + a.name # Path allow us to keep better track
                if user[1] != "User":
                    a.set_group( True )
                if user[3] == "Administrators":
                    a.set_admin(True)
                a.os = user[3]  # Group Name
                a.fullname = user[2]  # Last login
                ret                         += [a]
            self.data   = ret
            self.browser.gui.gui_queue_append("browser_handler",
                                              [self.browser,
                                              "obtain_users_action",
                                               self])
    def obtain_ADusers(self):
        """
        The path should be a domain contoller, we need to refresh it
        """

        self.path   = self.args["ad_obj"].name
        runpow =  self.engine.getModuleExploit("ad_getdomainusers")
        runpow.argsDict["computer"] = self.path
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.argsDict["adBrowser"] = True
        runpow.link(self)
        ret    = runpow.run()
        users  = runpow.result
        if users:

            ret = []
            for user in users:
                a          = ad_object()
                a.fullpath = self.args["ad_obj"].fullpath
                a.name  = user[0].strip()  # User Name
                a.path  = self.path + self.sep + a.name
                if user[1] == "Administrator":
                    a.set_admin(True)
                a.os       = user[2]  # Group Membership
                a.fullname = user[1]  # Class
                a.attr["is_adUser"] = True
                a.attr["is_computer"] = False
                ret                         += [a]
            self.data   = ret
            self.browser.gui.gui_queue_append("browser_handler",
                                              [self.browser,
                                              "obtain_users_action",
                                               self])
    def localAdmin(self):

        logging.info('Checking..this might take awhile')
        #self.path   = self.args["ad_obj"].name
        runpow =  self.engine.getModuleExploit("ad_adminhunter")
        """
        The path should be a user in ""
        """
        self.path   = self.args["ad_obj"].path

        quotedusername = '"' + self.args["ad_obj"].name.strip() + '"'        
        runpow.argsDict["user"] = quotedusername
        runpow.argsDict["adBrowser"] = True
        runpow.argsDict["computer"] = '""'
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret = runpow.run()
        adminHunterresults = runpow.result
        logging.info ("Systems where user %s is admin:" %quotedusername)
        logging.info (str(adminHunterresults))
        if adminHunterresults:
            ret = []
            for computer in adminHunterresults:               
                if str(computer) != "['']":
                    a          = ad_object()
                    a.fullpath = self.args["ad_obj"].fullpath
                    a.name  = computer[0].strip()  # system Name
                    a.path  = self.path + self.sep + self.name 
                    ##a.set_admin(True)
                    a.os       = "  Results from Admin Hunter"  # Group Membership
                    a.fullname = quotedusername + "is a local admin" # Class
                    a.attr["is_computer"] = True
                    a.attr["is_localAdmin"] = True    
                    ret += [a]
            if ret:
                self.data   = ret
                self.browser.gui.gui_queue_append("browser_handler",
                                                  [self.browser,
                                                  "localAdmin_action",
                                                   self])

    def obtain_ADuserDetails(self):
        logging.warn('Checking User Details')
        fo = self.args["ad_obj"]
        runpow =  self.engine.getModuleExploit("ad_getuserdetails")
        """
        The path should be a user
        """
        self.path   = self.args["ad_obj"].name
        runpow.argsDict["user"] = self.path
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret    = runpow.run()
        logging.info ("Details for user %s" %self.path)
        logging.info (runpow.result)
    
    def obtain_computers(self):
        runpow =  self.engine.getModuleExploit("ad_getcomputers")
        runpow.argsDict["passednodes"] = [ self.node ]
        runpow.link(self)
        ret = runpow.run()
        ret = []
        self.path   = ""
        for computer in runpow.result:
            base_path   = self.sep
            fo = ad_object()
            fo.name     = computer[0].strip()
            fo.path     = fo.name
            fo.os       = computer[1].strip()
            fo.fullpath = fo.fullname = computer[2].strip()
            if "Domain Controllers" in str(fo.fullname):
                fo.attr["is_domaincontroller"] = True
                fo.attr["is_computer"] = True
            else:
                fo.attr["is_computer"] = True

            ret += [fo]
        self.data = ret
        self.browser.gui.gui_queue_append("browser_handler",
                                          [self.browser,
                                          "obtain_computers_action",
                                           self])

# == Adding right-click
# 1- Make a class that inherit from RightClickAD
# 2- overwrite MENU string and the run function
# 3- Add your new class to the adbrowser_window.menulist list on the __init_ of adbrowser_window

class RightClickAD:
    MENU = ""

    def getMenu(self):
        return self.MENU

    def run(self):
        pass

    def isRequired(self, ad_obj):
        return True


class check4PSadmin(RightClickAD):
    MENU = "Check for access to remote PowerShell"
    def run(self, obj, item):
        (adwin, adobj) = item
        adwin.check4PSadmin(adobj)

    def isRequired(self, ad_obj):
        return ad_obj.is_computer()

class DLExecute(RightClickAD):
    MENU = "Get shell through remote PowerShell"
    def run(self, obj, item):
        (adwin, adobj) = item
        adwin.DLExecute(adobj)

    def isRequired(self, ad_obj):
        return ad_obj.is_computer()


class obtain_ADuserDetails (RightClickAD):
    MENU = "Get more details on an ad user"
    def run(self, obj, item):
        (adwin, adobj) = item
        adwin.obtain_ADuserDetails(adobj)

    def isRequired(self, ad_obj):
        return ad_obj.is_adUser()
    
class localAdmin (RightClickAD):
    MENU = "Check Admin rights on any system in the domain for user"
    def run(self, obj, item):
        (adwin, adobj) = item
        adwin.localAdmin(adobj)

    def isRequired(self, ad_obj):
        return ad_obj.is_adUser()

class adbrowser_window:
    """
    Holds state for the file browser.

    Threading is very important here - many routines will
    operate in the GUI thread and cannot throw exceptions
    or block!

    """
    def __init__(self, node, gui, engine, wTree):
        self.node           = node
        self.gui            = gui
        self.engine         = engine
        self.wTree          = wTree
        self.directory_dict = {}
        self.status         = ""
        self.menulist       = [check4PSadmin, DLExecute, obtain_ADuserDetails,localAdmin]
        self.sep            = "/"
        # connect signals
        sig_dic        = {
            "on_ad_treeview_button_press_event" : self.on_ad_treeview_button_press_event,
        }

        self.wTree.signal_autoconnect(sig_dic)
        #GUI stuff
        self.view           = self.wTree.get_widget("ad_treeview")

        if not self.view:
            logging.warning("Error on the Glade file inside AD browser")

        #if we want different columns dynamically based
        #on node type, then we need to do that here
        #which would be very cool!
        self.model  = gtk.TreeStore(gobject.TYPE_PYOBJECT,
                                    gtk.gdk.Pixbuf,
                                    gobject.TYPE_STRING,
                                    gobject.TYPE_STRING,
                                    gobject.TYPE_STRING) # Name, OS, Full Name
        self.view.set_headers_visible(True)
        self.view.set_model(self.model)
        # Icon:
        render_pixbuf = gtk.CellRendererPixbuf()
        column        = gtk.TreeViewColumn("T", render_pixbuf, pixbuf=1)
        self.view.append_column(column)

        # Name
        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("Name", renderer, text=2)
        column.set_resizable(True)
        self.view.append_column(column)

        # OS
        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("OS/Group", renderer , text=3)
        column.set_resizable(True)
        self.view.append_column(column)

        # Full Machine Name
        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("Full Name/Last Login", renderer , text=4)
        column.set_resizable(True)
        self.view.append_column(column)

        self.view.show()


        #toplevel insert with our base path
        self.refresh_computers()
        return

    def refresh_computers(self):
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("obtain_computers", {"ad_obj": None})
        b.start()

    # Treeview button press handler
    def on_ad_treeview_button_press_event(self, obj, event):
        iter = None

        if event.type == gtk.gdk._2BUTTON_PRESS:
            # Some doble-click on a machine. Obtain the list of users.
            model, iter = self.view.get_selection().get_selected()
            if iter == None:
                return

            ad_obj   = model.get_value(iter, 0) # ad_browser object
            if ad_obj.is_domaincontroller():
                self.obtain_ADusers( ad_obj )
            else:
                if ad_obj.is_computer():
                    self.obtain_users( ad_obj )
                       

        elif event.button == 3:
            # RIGHT CLICK
            model,paths = self.view.get_selection().get_selected_rows()
            for path in paths:
                iter=model.get_iter(path)
                break
            if iter==None:
                #logging.warn("Nothing was selected, yet we got a right click")
                return

            x=int(event.x)
            y=int(event.y)
            try:
                path, col, colx, celly= obj.get_path_at_pos(x,y)
            except TypeError:
                return
            obj.grab_focus()
            obj.set_cursor(path, col, 0)
            fo = model.get_value(iter,0)
            # Activating right click objects
            mymenu = gtk.Menu()
            for rclass in self.menulist:
                robj = rclass()
                if robj.isRequired(fo):
                    mline=gtk.MenuItem( robj.getMenu() )
                    mline.connect( "activate", robj.run, (self , fo) )
                    mline.show()
                    mymenu.append(mline)
            mymenu.show()
            mymenu.popup(None,None, None,event.button, event.time)
        return


    def browser_handler(self, name , args):
        """
        This function is called from the gui_queue
        It dispatches functions off to go do real work in the GUI
        """
        if hasattr(self, name):
            f   = getattr(self, name)
            f(args)
        else:
            logging.warning("Error on the AD browser handler : %s" % name)

        return

    # == Call Action Threads ==
    def DLExecute(self, ad_obj):
        self.update_status_bar("Trying to execute DLExecute to %s" % ad_obj.name )
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("DLExecute", {"ad_obj": ad_obj})
        b.start()

    def check4PSadmin(self, ad_obj):
        self.update_status_bar("Checking to see if PowerShell node has Remote PS admin access to %s" % ad_obj.name )
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("check4PSadmin", {"ad_obj": ad_obj})
        b.start()

    def obtain_users(self, ad_obj):
        self.update_status_bar("Obtaining users from %s" % ad_obj.name )
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("obtain_users", {"ad_obj": ad_obj})
        b.start()

        return

    def obtain_ADusers(self, ad_obj):
        self.update_status_bar("Obtaining users from %s" % ad_obj.name )
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("obtain_ADusers", {"ad_obj": ad_obj})
        b.start()

        return
    
    def obtain_ADuserDetails(self, ad_obj):
        self.update_status_bar("Obtaining users details for %s" % ad_obj.name )
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("obtain_ADuserDetails", {"ad_obj": ad_obj})
        b.start()

        return
    
    def localAdmin(self, ad_obj):
        self.update_status_bar("searching to find systems where user is an admin %s" % ad_obj.name )
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        b   = ADbrowser_actor(self, self.sep, self.engine, self.node)
        b.set_action("localAdmin", {"ad_obj": ad_obj})
        b.start()

        return    

    # == Manage the internal dictionary that all the objects tree ==
    def get_iter(self,path):
        return self.directory_dict.get(path)

    def has_iter(self,path):
        return self.directory_dict.has_key(path)

    def save_iter(self, iter, path):
        self.directory_dict[path]   = iter
        return

    def removetree(self, path):
        if path[-1] != "/":
                path += "/"
        for k in self.directory_dict.keys():
            if k.find(path) == 0 and k != "/": # avoid removing "/"
                iter = self.directory_dict[ k ]
                if iter:
                    self.model.remove( iter )
                    del self.directory_dict[k]


    def remove_path(self, args, path=None):
        """
        We refreshed a path, but it's gone.
        """
        if not path:
            actor   = args[0]
            path    = actor.path

        my_iter  = self.get_iter(path)
        if not my_iter:
            return

        self.model.remove(my_iter)
        del self.directory_dict[path]
        return


    def insert_new_fo(self, fo, parent=None):
        if parent==None:
            parent  = self.get_iter(fo.path)

        #now we insert a new one
        new_iter= self.model.insert_after(parent,
                                         sibling=None,
                                         row=[fo, fo.getIcon(), fo.name, fo.name, fo.os, fo.fullname])
        if fo.path==self.sep:
            path=""
        else:
            path=fo.path
        self.save_iter(new_iter, path + self.sep + fo.name)
        return

    # == Called from GUI queue ==
    def obtain_computers_action(self, args):
        ad_actor   = args[0]
        path       = ad_actor.path
        data       = ad_actor.data
        if path == self.sep: # XXX
            parent  = self.model.get_iter_from_string("0") #root
        else:
            parent  = self.get_iter(path)

        for fo in data:
            new_iter    = self.model.insert_after(parent=None,
                                        sibling=None,
                                        row=[fo, fo.getIcon(),  fo.name, fo.os, fo.fullname]) # name, time, size
            # This should happen only on root theoretically
            self.save_iter(new_iter, fo.name)


    def obtain_users_action(self, args):
        ad_actor   = args[0]
        path       = ad_actor.path
        data       = ad_actor.data
        if path == self.sep: # XXX
            parent  = self.model.get_iter_from_string("0") #root
        else:
            parent  = self.get_iter(path)

        for ad_object in data:
            newpath = path + self.sep + ad_object.name.strip()
            if self.has_iter(newpath):
                ad_old = self.model.get_value( self.get_iter(newpath), 0 )
                if ad_object == ad_old:
                    continue
                self.remove_path({}, path=newpath)
            newrow = [ad_object, ad_object.getIcon() , ad_object.name, ad_object.os, ad_object.fullname]


            new_iter= self.model.insert_after(parent,
                                              sibling = None,
                                              row = newrow)
            if path == self.sep:
                path=""
            self.save_iter(new_iter, newpath)

        if path == "":
            path="Root directory"
        self.update_status_bar("Refreshed Active Directory")
        return

    def obtain_ADusers_action(self, args):
        ad_actor   = args[0]
        path       = ad_actor.path
        data       = ad_actor.data

        if path == self.sep: # XXX
            parent  = self.model.get_iter_from_string("0") #root
        else:
            parent  = self.get_iter(path)
        for ad_object in data:
            newpath = path + self.sep + ad_object.name.strip()
            if self.has_iter(newpath):
                ad_old = self.model.get_value( self.get_iter(newpath), 0 )

                if ad_object == ad_old:
                    continue
                self.remove_path({}, path=newpath)
            newrow = [ad_object, ad_object.getIcon() , ad_object.name, ad_object.os, ad_object.fullname]


            new_iter= self.model.insert_after(parent,
                                              sibling = None,
                                              row = newrow)
            if path == self.sep:
                path=""

            self.save_iter(new_iter, newpath)

        if path == "":
            path="Root directory"
        self.update_status_bar("Refreshed Active Directory")
        return

    def localAdmin_action(self, args):
        ad_actor   = args[0]
        path       = ad_actor.path.strip()
        data       = ad_actor.data
        base_path  = self.sep # XXX

        if path == self.sep: # XXX
            parent  = self.model.get_iter_from_string("0") #root
        #should be a child
        else:
            parent  = self.get_iter(path) # get_iter fails, cause path is not complete

        for ad_object in data:          
            newpath =  path + self.sep + ad_object.name.strip()
            if self.has_iter(newpath):
                ad_old = self.model.get_value( self.get_iter(newpath), 0 )
                if ad_object == ad_old:
                    continue
                self.remove_path({}, path=newpath)
                
            newrow = [ad_object, ad_object.getIcon() , ad_object.name, ad_object.os, ad_object.fullname]

            new_iter= self.model.insert_after(parent,
                                              sibling = None,
                                              row = newrow)
            
            
            if path == self.sep:
                path=""    
            self.save_iter(new_iter, newpath)

        if path == "":
            path="Root directory"        
        self.update_status_bar("Retrieved systems where user is admin")
        return
    
    def update_status_bar(self, message):
        """
        This gets called from the GUI thread context.

        It updates the status bar at the bottom of the Browser window.
        """
        if type(message)==type([]):
            message=u"".join(message)

        self.status     = message
        wid=self.wTree.get_widget("status_bar")
        if wid:
            wid.set_text(self.status)
        return
