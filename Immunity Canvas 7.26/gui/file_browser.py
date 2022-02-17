##ImmunityHeader v1
###############################################################################
## File       :  file_browser.py
## Description:
##            :
## Created_On :  Wed Sep  2 21:17:45 2009
## Created_By :  Justin Seitz
## Modified_On:  Wed Sep  2 21:44:11 2009
## Modified_By:  Justin Seitz
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
"""
Browser window - used by the GUI class to put a browser window
on the screen and update it.

If you don't see the icons on the file browser download them from:
 http://icon-theme.freedesktop.org/releases
"""

import time
from threading import Thread
import gtk, gobject
import urllib, os
from canvaserror import *
from internal import devlog

import logging

Current_Todo="""


"""


class file_object(object):
    """
    Contains the data we need to display. The main role you see here
    is to abstract out all the different OS "files" issues. Linux
    for example has links, and you have named pipes and other things
    on various operating systems. But this object only cares about such
    things in the sense that they need to get displayed on the screen
    and treated by the browser window.
    """
    def __init__(self):
        self.name           = None
        self.date_modified  = None
        self.size           = None
        self.path           = None
        self.attr           = {"is_dir": False, "is_exe": False}
        return

    def __str__(self):
        """
        Convert to a string object
        """
        ret=""
        ret+="%s %s %s %s %r"%(self.name, self.date_modified, self.size, self.path, self.attr)
        return ret

    def equals(self, fo):
        #todo - replace this with something that automatically generates
        #this statement
        ret = (self.name==fo.name) and (self.date_modified==fo.date_modified) \
            and (self.size == fo.size) and (self.path==fo.path) and (self.is_dir() == fo.is_dir())
        #print "%s==%s :%s"%(self.name, fo.name, ret)
        return ret

    def set_dir(self, isdir):
        self.attr["is_dir"] = isdir

    def is_dir(self):
        return self.attr["is_dir"]

    def set_exe(self, isexe):
        self.attr["is_exe"] = isexe

    def is_exe(self):
        return self.attr["is_exe"]

    ##### End File_Object class
    def getIcon(self):
        try:
            if self.is_dir():
                return self.__get_folder_icon()
            else:
                if self.is_exe():
                    return self.__get_exe_icon()
                return self.__get_file_icon()
        except gobject.GError:
            return None

    def __get_folder_icon(self):
        return gtk.icon_theme_get_default().load_icon("gtk-directory", 16, 0)

    def __get_exe_icon(self):
        try:
            ret=gtk.icon_theme_get_default().load_icon("binary", gtk.ICON_SIZE_MENU, 0)
        except:
            #this is a backtrack 3 bug - they don't have that icon available.
            ret=gtk.icon_theme_get_default().load_icon("text-x-generic", gtk.ICON_SIZE_MENU, 0)
        return

    def __get_file_icon(self):
        return gtk.icon_theme_get_default().load_icon("text-x-generic", gtk.ICON_SIZE_MENU, 0)


class file_manip(object):
    def split_path(self, full_path):
        """
        Returns "/" from "/tmp"
        """
        name    = full_path.split(self.sep)[-1]
        path    = full_path.split(self.sep)[:-1]
        path    = self.sep.join(path)
        if path == "":
            path    = self.sep #root
        return path , name

    def full_path(self, my_file_object):
        """
        Joins a file object to get the full path
        """
        if my_file_object.path == "":
            #this is a root file (aka "/")
            return my_file_object.name
        elif my_file_object.path == self.sep:
            #we're in the root directory
            return self.sep+my_file_object.name
        #otherwise we are a normal file
        ret = my_file_object.path+self.sep+my_file_object.name
        return ret

class browser_actor(Thread, file_manip):
    """
    Runs browser actions in a new thread - this keeps slow
    things from blocking our GUI. We then format the results
    and pass them back to a browser_window object for displaying
    """
    def __init__(self, browser, sep, engine):
        Thread.__init__(self)
        self.browser    = browser
        self.sep        = sep
        self.engine     = engine
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
        accomplish what the browser_window wanted.
        """
        node    = self.browser.node

        if self.action == "refresh path":
            """
            If path is a directory, refresh it
            """
            self.path   = self.args["path"]
            devlog("file_browser", "Refreshing path: %s"%self.path)
            #we first need to check to see if this is a directory
            #if it's not a directory, then all we need to do is stat it
            #is check to see if it has changed
            stat_result = node.vfs_stat(self.path)
            if not stat_result:
                #print "File does not exist? %s"%self.path
                #that file does not exist!
                self.browser.gui.gui_queue_append("browser_handler",
                                                  [self.browser,
                                                   "remove_path",
                                                   self])
                return

            st_size, st_mtime, attr = stat_result

            if attr["is_dir"] is True:
                #this command may take a while
                devlog("filebrowser", "Getting a file list for %s"%self.path)
                filelist    = node.vfs_dir(self.path)
                #print "File list (%s) = %s" % (self.path, filelist)
                ret=[]
                for afile in filelist:
                    # stat the file to get our info.
                    # This might take a lot of time as well

                    if type( afile ) == type(""):
                        stat_result   = node.vfs_stat(self.path + self.sep + afile)
                        st_size, st_mtime, attr = stat_result
                    else:
                        (afile, st_size, st_mtime, attr) = afile
                        stat_result = True

                    if afile in (".", ".."):
                        continue

                    if not stat_result:
                        #file gone?!?
                        continue
                    #set this up
                    a                           = file_object()
                    a.path                      = self.path
                    a.name                      = afile
                    if type(st_mtime) == type(""):
                        a.date_modified             = st_mtime
                    else:
                        a.date_modified             = time.ctime(st_mtime)

                    a.size                      = st_size
                    a.set_dir( attr["is_dir"] )     # True/False
                    if "is_exe" in  attr.keys():
                        a.set_exe(attr["is_exe"])
                    #now add this to our list
                    ret                         += [a]

                # Now we have a list of files
                # we need to do a for each file get a STAT on
                # that file and store that data in some kind of structure
                # which is what we return to the browser_window
                # object
                self.data   = ret
                # ok, we're back
                self.browser.gui.gui_queue_append("browser_handler",
                                                  [self.browser,
                                                   "refreshed_path",
                                                   self])

            else:
                # we are a file, not a directory
                devlog("filebrowser", "Downloading file: %s"%self.path )
                self.browser.gui.gui_queue_append("browser_handler",
                                   [self.browser,
                                    "update_status_bar",
                                    "Downloading file %s"%self.path])

                path, name          = self.split_path(self.path)
                fo                  = file_object()
                fo.date_modified    = st_mtime
                fo.size             = st_size
                fo.name             = name
                fo.path             = path
                fo.set_dir( attr["is_dir"])

                if "is_exe" in  attr.keys():
                    fo.set_exe(attr["is_exe"])

                if 0:
                    d_mod = self.engine.getModuleExploit( "download" )
                    d_mod.argsDict["source"] = self.path
                    d_mod.argsDict["passednodes"] += [node]
                    d_mod.link(self)
                    ret = d_mod.run()
                else:
                    #using VFS for downloads now
                    ret = node.vfs_download(self.path, None)

                self.data           = [fo]
                self.browser.gui.gui_queue_append("browser_handler",
                                                  [self.browser,
                                                   "update_status_bar",
                                                   "Downloaded file %s"%self.path])

        elif self.action == "upload":
            self.path       = self.args["path"]
            self.uploadpath = self.args["uploadpath"]
            stat_result = node.vfs_stat(self.path)
            if not stat_result:
                logging.error("Error: File does not exist? (%s)" % self.path)
                return

            st_size, st_mtime, attr = stat_result
            if attr["is_dir"]:
                if self.path[-1] != "/":
                    self.path += "/"
            else:
                self.path, name = self.split_path(self.path)

            node.vfs_upload( self.uploadpath, self.path )
            self.browser.gui.gui_queue_append("browser_handler",
                                              [self.browser,
                                               "refreshed_file",
                                               self])

TARGET_TYPE_URI_LIST = 80
dnd_list = [ ( 'text/uri-list', 0, TARGET_TYPE_URI_LIST ) ]

class browser_window(file_manip):
    """
    Holds state for the file browser.

    Threading is very important here - many routines will
    operate in the GUI thread and cannot throw exceptions
    or block!

    """
    def __init__(self, node, gui, engine, wTree):
        if "win32api" in node.capabilities:
            self.sep = "\\"
        else:
            self.sep            = "/"

        self.node           = node
        self.gui            = gui
        self.engine         = engine
        self.wTree          = wTree
        self.directory_dict = {}
        self.status         = ""
        # ICON Theme:
        self.icontheme      = gtk.icon_theme_get_default()
        self.menulist       = [ "Download", "Upload" ]

        #GUI stuff
        self.view           = self.wTree.get_widget("file_treeview")
        if not self.view:
            logging.critical("Error inside our glade file - file_treeview")

        # connect signals only after having initialized self.view
        sig_dic        = {
            "on_file_treeview_button_press_event" : self.on_file_treeview_button_press_event,
            "on_file_treeview_drag_data_received" : self.on_file_treeview_drag_data_received,
            "on_file_treeview_drag_data_get"      : self.on_file_treeview_drag_data_get
                         }

        self.wTree.signal_autoconnect(sig_dic)
        self.view.drag_dest_set( gtk.DEST_DEFAULT_MOTION |
                                 gtk.DEST_DEFAULT_HIGHLIGHT | gtk.DEST_DEFAULT_DROP,
                                 dnd_list, gtk.gdk.ACTION_COPY)
        self.view.drag_source_set(gtk.gdk.BUTTON1_MASK, dnd_list, gtk.gdk.ACTION_COPY)

        #if we want different columns dynamically based
        #on node type, then we need to do that here
        #which would be very cool!
        self.model  = gtk.TreeStore(gobject.TYPE_PYOBJECT,
                                    gtk.gdk.Pixbuf,
                                    gobject.TYPE_STRING,
                                    gobject.TYPE_STRING,
                                    gobject.TYPE_STRING) # name, time, size
        self.view.set_headers_visible(True)
        self.view.set_model(self.model)
        # Icon:
        render_pixbuf = gtk.CellRendererPixbuf()
        column        = gtk.TreeViewColumn("T", render_pixbuf, pixbuf=1)
        self.view.append_column(column)

        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("Name", renderer, text=2)
        column.set_resizable(True)
        self.view.append_column(column)

        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("Size", renderer , text=3)
        column.set_resizable(True)
        self.view.append_column(column)

        renderer    = gtk.CellRendererText()
        column      = gtk.TreeViewColumn("Time", renderer , text=4)
        column.set_resizable(True)
        self.view.append_column(column)

        self.view.show()
        #toplevel insert with our base path
        base_path   = self.sep # XXX (windows needs this to change)
        fo = file_object()
        fo.attr["is_dir"] =True

        fo.name=base_path
        fo.path=""

        new_iter    = self.model.insert_after(parent=None,
                                sibling=None,
                                row=[fo, fo.getIcon(),  base_path, "", ""]) # name, time, size
        self.save_iter(new_iter, base_path)

        #on initialization we want to load the root path
        logging.info("Loading root paths...")
        self.refresh_path(base_path)

        return

    def split_path(self, full_path):
        """
        Returns "/" from "/tmp"
        """
        name    = full_path.split(self.sep)[-1]
        path    = full_path.split(self.sep)[:-1]
        path    = self.sep.join(path)
        if path == "":
            path    = self.sep #root
        return path , name

    # Taken from: http://faq.pygtk.org/index.py?req=show&file=faq23.031.htp
    def get_file_path_from_dnd_dropped_uri(self, uri):
        path = urllib.url2pathname(uri) # escape special chars
        path = path.strip('\r\n\x00') # remove \r\n and NULL

        # get the path to file
        if path.startswith('file:\\\\\\'): # windows
                path = path[8:] # 8 is len('file:///')
        elif path.startswith('file://'): # nautilus, rox
                path = path[7:] # 7 is len('file://')
        elif path.startswith('file:'): # xffm
                path = path[5:] # 5 is len('file:')
        return path

    def on_file_treeview_drag_data_get( self,  widget, context, selection, target_type, timestamp):
        if target_type == TARGET_TYPE_URI_LIST:
            path, name = self.split_path( os.tmpnam() )

            s = widget.get_selection()
            model, iter = s.get_selected()
            fo = model.get_value(iter,0)
            if fo.path==self.sep:
                pp=""
            else:
                pp=fo.path
            try:
                self.node.vfs_download(pp + self.sep + fo.name, path + self.sep + fo.name)
            except NodeCommandError, msg:
                self.update_status_bar("Error: %s" % str(msg) )

            uri = 'file://' + path[1:] + self.sep + fo.name
            #b.set_action("refresh path", {"path":  pp + self.sep + fo.name, "downloadpath":name})
            #b.start()

            selection.set (selection.target, 8, uri)
            print uri

    def on_file_treeview_drag_data_received(self, widget, context, x, y, selection, target_type, timestamp):
        if target_type == TARGET_TYPE_URI_LIST:
                uri = selection.data.strip()
                uri_splitted = uri.split() # we may have more than one file dropped
                for uri in uri_splitted:
                        ospath = self.get_file_path_from_dnd_dropped_uri(uri)
                        x=int(x)
                        y=int(y)

                        try:
                            rpath, col, colx, celly= widget.get_path_at_pos(x,y)
                        except:
                            pass
                        widget.grab_focus()
                        widget.set_cursor(rpath, col, 0)

                        model,paths = self.view.get_selection().get_selected_rows()
                        for p in paths:
                            #path is really a "tuple" but we convert it to a string
                            iter=model.get_iter(p)

                        fo = model.get_value(iter,0)
                        if fo.path==self.sep:
                            pp=""
                        else:
                            pp=fo.path

                        b   = browser_actor(self, self.sep, self.engine)
                        b.set_action("upload", {"path":  pp + self.sep + fo.name, "uploadpath":ospath})
                        b.start()


    def menu_response(self, obj, item):
        (name, fo) = item
        if name == "Download":
            newpath = self.full_path(fo)
            self.refresh_path(newpath)

        elif name == "Upload":
            self.path_upload( self.full_path(fo) )

    # def __delattr__(self, name):
    #     print "NAME: ", name

    def __del__(self):
        # FIX: issue#152
        # I couldn't found the root cause of bug
        # but during the tests to find it, it was found that
        # overwriting this magic method the bug was no longer
        # to reproduce
        pass

    # treeview button press handler .. needs to check for dir type
    def on_file_treeview_button_press_event(self, obj, event):
        # XXX: needs to check if type is dir !
        i = None
        if event.type == gtk.gdk._2BUTTON_PRESS:
            #
            # BUGBUG: Sometimes we get no self.view (it's not defined yet?!?) - why? (Repro: Win32 File Browser)
            #         Keep an eye open as this shouldn't happen anymore
            #
            model, i = self.view.get_selection().get_selected()
            if i == None:
                return
            my_fo   = model.get_value(i, 0)
            newpath = self.full_path(my_fo)
            self.refresh_path(newpath)

        elif event.button == 3:
            model,paths = self.view.get_selection().get_selected_rows()
            for path in paths:
                #path is really a "tuple" but we convert it to a string
                i = model.get_iter(path)
                break
            #model,iter=self.nodetree.get_selection().get_selected()
            if i == None:
                #print "weird - nothing was selected, yet we got a right-click"
                return

            x = int(event.x)
            y = int(event.y)
            try:
                path, col, colx, celly = obj.get_path_at_pos(x, y)
            except TypeError:
                return
            obj.grab_focus()
            obj.set_cursor(path, col, 0)
            #nodetext=model.get_value(iter, 2)
            fo = model.get_value(i, 0)

            mymenu = gtk.Menu()
            for l in self.menulist:
                mline = gtk.MenuItem( l )
                mline.connect("activate", self.menu_response, (l, model.get_value(i, 0)))
                mline.show()
                mymenu.append(mline)
            #print nodetext, str(event)
            mymenu.show()
            mymenu.popup(None, None, None,event.button, event.time)

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
            print "Error with name in browser: %s"%name

        return

    def refresh_path(self, path):
        self.update_status_bar("Refreshing %s" % path)
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        b   = browser_actor(self, self.sep, self.engine)
        b.set_action("refresh path", {"path": path})
        b.start()
        return

    def path_upload(self, path):
        #now we need to start a thread that does node.dir()
        #and passes the results back to us
        #dictionary used for GTK actions
        actiondict={}
        actiondict["localfolder"]=gtk.FILE_CHOOSER_ACTION_SELECT_FOLDER
        #local dialogs are here
        action=actiondict.get( "local",gtk.FILE_CHOOSER_ACTION_OPEN)
        chooser = gtk.FileChooserDialog(title="Choose file to upload",action=action,
                                            buttons=(gtk.STOCK_CANCEL,gtk.RESPONSE_CANCEL,gtk.STOCK_OPEN,gtk.RESPONSE_OK))
        ret=chooser.run()
        uploadpath = ""

        if ret==gtk.RESPONSE_OK:
            uploadpath=chooser.get_filename()
            chooser.destroy()
        else:
            #assume cancel was clicked
            chooser.destroy()
            return

        b   = browser_actor(self, self.sep, self.engine)
        b.set_action("upload", {"path": path, "uploadpath": uploadpath})
        b.start()
        return

    def get_iter(self,path):
        return self.directory_dict.get(path)

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
            #not in our cache? Already deleted?
            return

        self.model.remove(my_iter)
        del self.directory_dict[path]
        return


    def get_parent_from_fo(self, fo):
        """

        """

    def insert_new_fo(self, fo, parent=None):
        if parent==None:
            parent  = self.get_iter(fo.path)

        #now we insert a new one
        new_iter= self.model.insert_after(parent,
                                         sibling=None,
                                         row=[fo, fo.getIcon(), fo.name, fo.size, fo.date_modified]) # name,

        if fo.path==self.sep:
            path=""
        else:
            path=fo.path
        self.save_iter(new_iter, path+self.sep+fo.name)
        return

    def refreshed_file(self, args):
        """
        Someone called refresh_path, but it turned out to be
        a file.
        """
        actor   = args[0]

        if actor.action == "refresh path":
            data    = actor.data
            path    = actor.path
            fo=data[0]
            fo_iter = self.get_iter(path)
            old_fo   = self.model.get_value(fo_iter, 0)
            if old_fo.equals(fo):
                #it's already in there, so no need to do anything
                return

            devlog("file_browser","Removing and inserting FO: %s->%s"%(str(old_fo),str(fo)))
            #otherwise, we need to remove the old one from the tree
            self.model.remove(fo_iter)
            #now put a new one in
            self.insert_new_fo(fo)
            self.update_status_bar("Downloaded *%s*"%path)

        elif actor.action == "upload":
            path    = actor.uploadpath
            self.update_status_bar("Uploaded *%s*" % path)

        ##OLD ROOTKIT
        elif actor.action == "hide":
            path    = actor.path
            self.update_status_bar("Hid: *%s*" % path)

    def refreshed_path(self, args):
        """
        A browser_actor has returned data to us and we can now
        display it for the user.
        """
        actor   = args[0]
        path    = actor.path
        data    = actor.data
        #how do we get the parent object here from path?

        if path == "/": # XXX
            #if path in self.directory_dict.keys():
            #    return
            parent  = self.model.get_iter_from_string("0") #root
        else:
            parent  = self.get_iter(path)

        self.removetree( path )


        for file_object in data:
            new_iter= self.model.insert_after(parent,
                                             sibling=None,
                                             row=[file_object, file_object.getIcon() , file_object.name, file_object.size, file_object.date_modified]) # name,
            if path==self.sep:
                path=""
            self.save_iter(new_iter, path + self.sep + file_object.name)

        if path == "":
            path = "root directory"
        self.update_status_bar("Refreshed *%s*" % path)
        logging.info("Refreshed %s" % path)
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
