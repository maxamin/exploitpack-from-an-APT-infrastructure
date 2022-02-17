#! /usr/bin/env python

"""
hostknowledge.py - contains a fuzzy logic representation of what I know about a host
"""

#for uint32
from exploitutils import *

#for saving/loading hosts
import cPickle
from threading import Thread

#for translations
from gettext import gettext as _
import gettext
gettext.bindtextdomain("CANVAS",localedir = "gui/locale/")
gettext.textdomain("CANVAS")

import os.path
import socket
import time
import sys
import copy

from canvaserror import *

import logging


class lineList:
    def __init__(self, parent):
        self.parent          = parent
        self.children        = []
        self._text           = ""
        self._activated_text = ""
        self.pix             = ""
        self.gui             = None
        self.engine          = None
        self.activated       = 0
        self.amselected      = self.activated # XXX
        self.activate_text()

        #text depends on our activation state, so we cannot pickle it
        self.text            = ""
        self.pickledefaults  = {"text": "Just Unpickled", "parent": None,
                                "gui": None, "activated": 0, "amselected": 0,
                                "_activated_text": "", "engine": None}

    def __getstate__(self):
        """
        We don't want to show the "(current callback)" part if we've
        just unpickled, because it's untrue, so we manually set self.text here in
        our pickle dictionary.
        """
        self.pickledefaults["text"] = self._text
        dontpickle = self.pickledefaults.keys()
        newdict = filterdict(dontpickle, self.__dict__)

        for key in dontpickle:
            newdict[key] = self.pickledefaults[key]

        return newdict

    def set_all_parents(self, obj):
        self.parent = obj
        self.gui    = obj.gui
        self.engine = obj.engine

        for c in self.children:
            c.set_all_parents(self)

    def old__setstate__(self, state):
        """
        takes in a tuple state from the pickle operation
        """
        p, c, t, pix    = state
        self.parent     = p
        self.children   = c
        self.text       = t
        self.pix        = pix
        self.engine     = None
        self._text      = t
        self.activated  = 0
        self.amselected = 0
        self.gui        = None

    def activate_text(self):
        """
        Construct self.text which is the line shown by the GUI
        """

        if self.activated:
            self.text = self._text + self._activated_text
        else:
            self.text = self._text

    def get_pix(self):
        return self.pix

    def update_pix(self):
        """
        used to set a different picture if we're busy, etc
        """
        pass


    def get_text(self):
        return self.text

    def get_children(self):
        return self.children

    def get_menu(self):
        """
        Gets a list of strings which will be made into a menu
        """
        return []

    def menu_response(self, widget, astring):
        pass

    def add(self, child):
        self.children += [child]
        child.parent = self

    def delete(self, child):
        """
        Deletes a child line from the GUI

        Should be safe to call from any thread since we just use gui_queue. Of course
        this means the actual delete may get postponed until the Main thread runs.
        This may not be what you really intended, but there's no easy way around it. We
        could sleep() to trigger the main thread, I guess.
        """
        try:
            index = self.children.index(child)
        except ValueError:
            devlog("hostKnowledge", "child is not in the list of children????")
            return

        del self.children[index]

        if self.engine:
            if self.gui:
                self.engine.gui.gui_queue_append("deleteLine", [ child ])
                time.sleep(0.1)

            if isinstance(child, hostKnowledge):
                self.engine.new_event('host deleted', {'node' : self.parent.getname(),
                                                       'ip'   : child.interface})

    def update_gui(self):
        """
        It's perfectly ok to call this from any thread - update_gui just
        adds to the gui_queue such that the GUI updates whatever line we are
        """

        #check to see if this has changed because we may have recently become
        #activated or loaded from a pickle
        self.activate_text()

        if self.gui:
            #self.gui is a newgui reference. We don't want to call this directly
            #self.gui.update_object(self) #never do this because of threading issues
            devlog("gui","Updating gui for %s %s"%(self.text,self.pix))
            self.engine.update(self)
        else:
            pass

        if self.parent and self.parent != self:
            self.parent.update_gui()

    def set_engine(self, engine):
        self.engine = engine

from libs.dnslookup import dnslookup
from exploitutils import check_reserved

class hostKnowledge(lineList):
    """
    A list of knowledge primitives. Contained within a knowledgeContainer
    """
    def __init__(self, interface, parent, doDNS=True, resolved_from=None):
        """
        The goal of resolved_from is to provide a place to store a virtual
        host. For example, if you do CANVASNode.new_host("www.cnn.com"),
        then resolved_from will be "www.cnn.com", even though everything
        else will work by ip address internally. There are some cases where
        you want the hostname you used to resolve this IP address - web
        exploits in particular.
        """

        self.additional    = False

        if not resolved_from:
            self.resolved_from = interface
        else:
            self.resolved_from = resolved_from

        #interface is the interface from the current node. 127.0.0.1 is, of course, the localhost
        devlog("hostKnowledge", "interface=%s"%interface)

        if interface == None:
            print "Interface is set to none, which should not happen!"
            import traceback
            traceback.print_exc(file=sys.stderr)
            sys.exit(1)

        lineList.__init__(self,parent)

        # XXX: ipv6 mod
        if ":" in interface:
            pass
        else:
            # XXX: end
            #not IPv6 - so doing IPv4 resolution
            if doDNS:
                try:
                    interface2 = socket.gethostbyname(interface)
                except Exception:
                    interface2 = "127.0.0.2" #ERROR

                interface = interface2 #swap them

        self.interface = interface

        ##OK now we have an interface set lets try and get a DNS and add it to the knowledgebase if its not a private range
        #TODO CHECK COVERTNESS ?

        if (not check_reserved(interface)
                and interface != "::1"
                and interface != ":::1"
                and doDNS):
            lookup = dnslookup(self)
            lookup.start()
            lookup.join()

        self.pix                               = ""
        self._activated_text                   = " (current target)"
        self.pickledefaults["_activated_text"] = self._activated_text
        self._text                             = "Host: %s" % self.interface
        self.activate_text()


    def __str__(self):
        return "%s" % self._text

    def get_sort_value(self):
        return self.interface

    def get_pix(self):
        for c in self.children:
            #knowledge about the OS is used to set our icon
            known = str(c.known)

            if c.tag!="OS":
                continue

            #we don't differentiate versions yet
            if known.count("Windows"):
                return "Win32Host"
            elif known.count("Linux"):
                return "LinuxHost"
            elif known.count("Solaris"):
                return "SolarisHost"
            elif known.count("Embedded"):
                return "EmbeddedHost"

    def get_knowledge(self, tag, defaultret=None):
        """
        Get information from the hostKnowledge - we return an object, not a string
        O(N) operation here - could be fixed with a dictionary
        """
        for c in self.children:
            if c.tag == tag:
                return c
        return defaultret

    def get_all_knowledge_as_text(self):
        """
        Every so often you'll want to get all the knowledge in easy
        to print out form, and this is how
        """
        return "\n".join(map(str, self.children))


    def get_all_knowledge_as_list(self):
        """
        Every so often you'll want to get all the knowledge in easy
        to print out form, and this is how
        """
        return [c for c in self.children]

    def get_menu(self):
        """
        Get menu strings for hostKnowledge - select as target, etc
        """
        menu = ["Forget this host knowledge", "Save host to file","Add note to host"]
        #if we're not already a target, let's add these options to the front
        if not self.activated:
            menu = ["Set as additional target host"] + menu
        menu = ["Set as target host"] + menu

        if self.additional:
            menu+=["Unset as targeted host"]
        if self.get_knowledge("MOSDEFService",None):
            #we have a MOSDEFService installed on this box, so we should offer the user the ability
            #to connect to it
            menu+=["Connect to MOSDEF Service"]
        return menu

    def set_as_target(self,t=1):
        """
        Sets or unsets myself as a target and updates
        the engine and gui to know such a thing - doesn't
        actually remove from the engine's self.target_hosts list

        You probably should not be calling this directly. This is for the
        engine to use.
        """
        self.activated=t
        self.activate_text()
        self.update_gui()
        self.update_engine()

    def unset_as_target(self):
        """
        Remove myself from the engine's target_hosts list
        and unset myself as an additional target or target.


        You probably should not be calling this directly. This is for the
        engine to use.
        """
        self.additional = False

        if self.engine:
            self.engine.unset_target_host(self)

        self.set_as_target(0)

    def update_engine(self):
        if self.engine:
            if self.activated:
                if self.additional:
                    #additional target
                    self.engine.set_additional_target_host(self)
                else:
                    #primary target
                    self.engine.set_target_host(self)

    def save_state(self):
        """
        Uses pickle to save this HostKnowledge object to a file

        We don't want to save self.parent though, since that will include a lot of
        information we don't need. We don't want to save self.gui or self.engine either.
        We don't need activated or amselected. These would in fact be bad to store.

        We do want self.children, which is all our knowledge (if we have any)

        These saves are per sesion and go in the session directory in "SavedState"
        """
        self.pickledefaults["activated"]=self.activated

        if self.parent:
            node=self.parent.parent #get our parent node for its name
            nodename=node.get_name()
        else:
            nodename="standalone"
        hostname=nodename+"_"+self.interface #construct a unique name

        ##Saved Hosts goes in the appropriate directory for the current session
        dirname  = self.engine.create_new_session_output_dir("SavedState", subdir="Hosts")
        filename = os.path.join(dirname, hostname)

        try:
            cPickle.dump(self,file(filename,"wb"))
            self.engine.log( "Saved state of %s to %s"%(hostname, filename))
        except Exception, err:
            self.engine.log( "Problem saving state of host %s: %s"%(hostname, err) )

    def menu_response(self, widget, astring):
        """
        Handles all the menu responses (sent to us a string such as "Save to File")
        """
        #print "Got %s"%astring
        if astring==_("Set as target host"):
            self.additional=False
            self.set_as_target()
        elif astring==_("Set as additional target host"):
            #don't set as additional host if we already are
            #either a primary or secondary host
            if not self.activated:
                self.additional=True
                self.set_as_target()
        elif astring==_("Unset as targeted host"):
            #only do this is we are the secondary target since we
            #always have at least ONE target selected
            if self.additional:
                self.unset_as_target()
        elif astring==_("Forget this host knowledge"):
            if self.interface=="127.0.0.1":
                self.engine.log(_("Don't try to delete the loopback interface, please"))
            else:
                self.parent.delete(self)
        elif astring==_("Save host to file"):
            #print "Not yet supported, sorry"
            if 1:
                self.save_state()

        elif astring==_("Add note to host"):
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add note to host", [self])
        else:
            print "Unknown string in menu_response: %s"%astring

    def forget(self, tag):
        """
        Forgets a tag, if we have it
        returns True if we've found it, false if it was not here
        """

        for c in self.children:
            if c.tag == tag:
                self.delete(c)

                if self.engine:
                    self.engine.new_event('knowledge deleted', {'tag'  : tag,
                                                                'node' : self.parent.parent.getname(),
                                                                'host' : self.interface,})
                return True
        return False

    def replace_knowledge(self,tag,knowledge,percentage,invisible=0):
        """
        If knowledge is already known replaces it, otherwise, adds it
        """
        for c in self.children:
            if c.tag == tag:
                if not c.invisible and self.engine:
                    self.engine.deleteLine(c)

                c.known      = knowledge
                c.known_text = knowledge
                c.percentage = percentage
                c.invisible  = invisible

                if not invisible and self.engine:
                    self.engine.addLine(c)

                c.update_gui()

                if self.engine:
                    self.engine.new_event('knowledge replaced', {'tag'        : tag,
                                                                 'knowledge'  : knowledge,
                                                                 'percentage' : percentage,
                                                                 'node'       : self.parent.parent.getname(),
                                                                 'host'       : self.interface,})
                return c

        return self.add_knowledge(tag,knowledge,percentage,invisible=invisible)

    def add_knowledge(self, tag, knowledge, percentage, invisible=0):
        "adds knowledge but does not replace it"
        devlog('hostKnowledge::add_knowledge', "%s %s %s"%(tag,knowledge,invisible))

        for c in self.children:
            if tag == c.tag:
                #we already know something about this - we need to adjust it,
                #but for now we'll replace it
                devlog('hostKnowledge::add_knowledge',"replacing %s knowledge in gui"%tag)
                return self.replace_knowledge(tag,knowledge,percentage,invisible)

        thing=knowledgePrimitive(self, tag, knowledge,percentage)
        thing.invisible=invisible
        self.add(thing)

        if self.engine and not invisible:
            devlog('hostKnowledge::add_knowledge',"adding %s knowledge to gui"%tag)
            self.engine.addLine(thing)
        else:
            devlog('hostKnowledge::add_knowledge',"Not adding %s knowledge to gui. Self.engine: %s"%(tag,self.engine))

        thing.update_gui()
        self.update_gui()

        if self.engine:
            self.engine.new_event('knowledge added', {'tag'        : tag,
                                                      'knowledge'  : knowledge,
                                                      'percentage' : percentage,
                                                      'node'       : self.parent.parent.getname(),
                                                      'host'       : self.interface,})
        return thing

    def add_to_knowledge(self, tag, newknowledge):
        "adds a fact to a knowledge line (such as a port)"
        #print "add_to_knowledge(%s,%s)"%(tag,newknowledge)
        knowledge=self.get_knowledge(tag)
        if knowledge==None:
            #add it anew
            #print "add knowledge about to be called"
            self.add_knowledge(tag,newknowledge,100)
            return
        #print "knowledge.known=%s"%knowledge.known
        knowledge.known+=newknowledge
        knowledge.known=uniquelist(knowledge.known)
        #print "Replace knowledge about to be called"
        self.replace_knowledge(tag,knowledge.known,100)

        return

    def open_tcpport(self,port):
        "Returns 1 if the port is open on this host, else, zero"
        #quick TCP function
        ports=self.get_knowledge("TCPPORTS",[])
        #I have no idea why ports would not be a list
        #but if it's not, we don't want to error out
        if not ports or type(ports) != type([]):
            return 0

        if port in ports:
            return 1
        return 0

    def add_note(self,note):
        self.replace_knowledge("Note",note,100)

    def get_note(self):
        ret = self.get_knowledge("Note","")
        if ret: ret = ret.known
        return ret

    def add(self, thing):
        lineList.add(self, thing)


class knowledgeContainer(lineList):
    """
    A list of hosts we know about, typically my parent is a Node, my children are hostKnowledge objects
    """
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text = "Knowledge"

    def get_menu(self):
        #return ["Add new host", "Forget all knowledge", "Load host from file", "Load all hosts"]
        return ["Add new host", "Forget all knowledge", "Add hosts from file"]

    def save_state_all(self):
        """
        For each host in this container save it's state
        """
        for host in self.children:
            host.save_state()

    def restore_state(self, session_dir, state_type, prefix="", superseed_existing=True):
        """
        Now loads state from the specified session dir
        """
        dirname = os.path.join(session_dir, "SavedState",state_type)

        try:
            hostlist=os.listdir(dirname)
        except:
            self.engine.log( "No Saved State to load" )
            return

        ##Delete existing host knowledge -
        ## Rich : right this is so much nasier than it has to be as the knowledge base was seemingly not designed with doing anything more than adding or deleting a singleton
        ##        the delete metjhod in linelist alters self.children, thus breaking any for loop - but deletes based on object ID so we have to loop until we are complete
        ##        - GOD DAMN FILTHY but its the only way as the rest of the code relies on the self.children modification ...... this whole knowledgebase needs recoding to be designed and scalable etc etc
        while len(self.children) >0:
            for x in self.children:
                self.delete(x)

        for f in hostlist:
            #skip all hosts that don't start with 0_ for localNode
            if prefix and f[:len(prefix)]!=prefix:
                #print "did not match prefix: Prefix=*%s* f[:len(prefix)]=*%s*"%(prefix,f[:len(prefix)])
                continue
            try:
                self.engine.log( "Restoring host state of: %s"%(f) )

                newhost=cPickle.load(file(os.path.join(dirname,f)))
            except (IOError, EOFError), err:
                ##Not a good pickle
                logging.error("Could not load host '%s' because '%s' - Probably not a not a pickle file" % (f, err))
                continue

            #set up all the children to have the correct parent again
            newhost.set_all_parents(self.parent.hostsknowledge)
            # We do not want to perform dns resolution on session import
            self.parent.add_host(newhost, lookup=False)

            ##Retarget previously targetted host upon restore
            if newhost.activated:
                newhost.additional=False
                newhost.set_as_target()

            for x in newhost.children:
                ##Now force the classic view to show this knowledge
                self.engine.addLine(x)

        return

    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Add new host":
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add host", [self])
        #if astring=="Load host from file":
        if astring == "Add hosts from file":
            #pop up a dialog box and select the file (from the gui)
            self.gui.engine.gui.gui_queue_append("Add hosts from file", [self])

        #Depreciated with session support
        #if astring=="Load all hosts":
            #self.restore_state()

    def get_all_known_hosts(self):
        """
        returns a list of all the hosts I know about
        This is used by the engine to maintain uniqueness
        of the hosts in the container
        """
        return [c.interface for c in self.children]

    def forget(self, tag):
        """
        Forgets information from  a tag in our localhost
        """
        localhost = self.get_localhost()
        localhost.forget(tag)

    def get_first_known_host(self):
        if not self.children: return None
        return self.children[0]

    def get_localhost(self):
        """
        Returns the local host in this container - essentially 127.0.0.1
        """
        #should always exist
        return self.get_known_host("127.0.0.1")

    def get_known_host(self, ip):
        """
        Returns a hostKnowledge or None if none found that matched that ip
        """
        for c in self.children:
            if c.interface==ip:
                return c
        return None

    def add(self, data):
        lineList.add(self, data)


class knowledgePrimitive(lineList):
    """
    Each host has many of these
    """
    def __init__(self,parent, tag, known, percentage):
        lineList.__init__(self, parent)
        self.tag        = tag
        self.known      = known
        self.percentage = percentage
        self.invisible  = 0
        known_text      = str_from_object(self.known)
        devlog("hostKnowledge", "Known Text: %s"%known_text)

        self.all_text="" #used only when we call self.get_all_text()
        self.known_text=known_text #just the portion of text we use for the known value

        self._text="Known: %s: %s <%s%%>"%(self.tag, self.known_text ,self.percentage)

    def __str__(self):
        self._text="Known: %s: %s <%s%%>"%(self.tag, self.known_text ,self.percentage)
        return self._text

    def old__getstate__(self):
        """used for pickling"""
        state=(lineList.__getstate__(self),self.tag,self.known,self.percentage,self.invisible,self.text)
        return state


    def get_known_text(self):
        """
        Returns only the text for the known string - not the percentage of certainty.
        Has to handle the case when our known is a list or a string, essentially
        """
        known=str_from_object(self.known)
        devlog("hostKnowledge","get_known_text returning: %s"%known)
        self.known_text=known
        return known

    def get_text(self):
        """
        Gets the text representation of this known value, including the percentage
        of certainty, and then formats it for the screen. Also assigns some internal
        variables for use by people hooking this object.

        If all you want to use is the known text for parsing or whatever, we also have
        get_known_text() available, which will just return the known text.

        Also see "get_all_text()" which does not restrict the length of the known text to
        50 characters (and self.all_text).
        """
        known=self.get_known_text()
        #self.text is truncated to fit into a screen nicely.
        self.text="Known: %s: %s <%s%%>"%(self.tag, str(known)[:50],self.percentage)
        #self.all_text is used by some people who want to parse text instead of access the self.known object directly.
        self.all_text="Known: %s: %s <%s%%>"%(self.tag, str(known),self.percentage)
        return self.text

    def get_all_text(self):
        """
        Calls self.get_text() to set internal variables, then returns self.all_text - a longish
        representation of what we know.
        """
        self.get_text()
        return self.all_text

    def get_menu(self):
        return ["Forget this knowledge", "Print knowledge"]

    def menu_response(self, widget, astring):
        if astring=="Forget this knowledge":
            #done in self.parent.delete() - should be thread safe
            #self.gui.engine.gui.gui_queue_append("deleteLine",[self])
            self.parent.delete(self)
        elif astring=="Print knowledge":
            self.engine.log("Knowledge: %s"%self.get_all_text())

class interfaceLine(lineList):
    def __init__(self, ifc, nat, startport, endport, parent):
        lineList.__init__(self,parent)
        self.interface = ifc[0]
        self.ip        = ifc[1]
        self.netmask   = nmask = ifc[2]

        # ideally the following check shouldn't exist
        # but there is a discrepancy in the format of the ifc list
        # localNode defines netmask to be a string and pretty much
        # all the other nodes use numeric netmasks
        if isinstance(nmask, (int, long)):
            res = ''
            res += '%d.' % ((nmask & 0xff000000) >> 24)
            res += '%d.' % ((nmask & 0xff0000) >> 16)
            res += '%d.' % ((nmask & 0xff00) >> 8)
            res += '%d' % (nmask & 0xff)
            nmask = res

        self._text="%s  %s (%s)" % (self.interface, self.ip, nmask)
        self.activate_text()
        self.isNAT=nat
        #for NAT's these can be a smaller range of portforwarded ports
        self.startport=startport
        self.endport=endport
        self._activated_text = " (current callback)"
        self.pickledefaults["_activated_text"]=self._activated_text

        self.pickledefaults["children"]= []
        self.pickledefaults["parent"]= None
        self.pickledefaults["activated"]= self.activated

        ##For state save/restore
        self.listeners_that_are_listening = []


    def __str__(self):
        """
        Return the IP - possibly would be better to return a "%s %s %s"%(self.ip,self.netmask,self.isNAT) or something...
        """
        return str(self.ip)

    def isSpecial(self):
        """
        Return true if we are a special kind of interface (NAT, for example)
        The other kind of special interface is one that's not local to a LocalNode.

        If this returns True, the engine will not choose a different interface
        when doing auto-interface selection.
        See canvasengine::autoListener()
        """
        if self.isNAT:
            return True
        if self.parent.parent.nodetype!="LocalNode":
            return True
        return False

    def get_menu(self):
        return ["Set as callback interface"]

    def set_as_callback(self,t=1):
        self.activated=t
        self.activate_text()
        self.update_gui()
        self.update_engine()

    def unset_as_callback(self):
        self.set_as_callback(0)

    def update_engine(self):
        if self.engine:
            self.engine.set_callback_interface(self)

    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring==_("Set as callback interface"):
            self.set_as_callback()

    def getListenerBySock(self,sock):
        #print "in getListenerBySock for listener %s"%self.text
        #print "Number of listeners: %s"%len(self.children)
        for c in self.children:
            #print "Comparing %s to %s"%(sock,c.sock)
            if sock==c.sock:
                return c
        return None

    def save_state(self):
        """
        Uses pickle to save this interface object to a file

        We don't want to save self.parent though, since that will include a lot of
        information we don't need. We don't want to save self.gui or self.engine either.
        We don't need activated or amselected. These would in fact be bad to store.

        We do want self.children, which is all our knowledge (if we have any)

        These saves are per sesion and go in the session directory in "SavedState"
        """
        ##Make sure we don't pickle the children ...... this gets reset on multiple saves for some reason?
        self.pickledefaults["children"] = []
        self.pickledefaults["_activated_text"]=self._activated_text
        self.pickledefaults["activated"]= self.activated

        if self.parent:
            node=self.parent.parent #get our parent node for its name
            nodename=node.get_name()
        else:
            nodename="standalone"
        ifacename=nodename+"_"+self._text.replace(" ","_") #construct a unique name

        ##Saved Hosts goes in the appropriate directory for the current session
        dirname  = self.engine.create_new_session_output_dir("SavedState", subdir="Interfaces")
        filename = os.path.join(dirname, ifacename)

        try:
            cPickle.dump(self,file(filename,"wb"))
            self.engine.log( "Saved state of %s to %s"%(ifacename, filename))
        except Exception, err:
            self.engine.log( "Problem saving state of host %s: %s"%(ifacename, err) )

class interfacesList(lineList):
    """
    Parent is usually a CANVASNode
    """
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text="Interfaces"
        self.activate_text()

    def all_ips(self):
        """
        Returns a list of the ip addresses
        """
        return [inter.ip for inter in self.children]

    def all_interfaces(self):
        """
        Returns a list of the ip interfaces
        """
        return [inter.interface for inter in self.children]

    def all_interface_objects(self):
        return self.children

    def get_ip(self,ip):
        """
        If we can find an interface in our list that matches
        that IP, return it, otherwise return None
        """
        devlog("hostKnowledge", 'interfacesList::get_ip', "ip = %s" % ip)
        for interfs in self.children:
            devlog("hostKnowledge", 'interfacesList::get_ip', "intefs=%s %s"%(interfs.interface,interfs.ip))
            if ip==interfs.ip:
                devlog("engine", 'interfacesList::get_ip', "Found...%s"%ip)
                return interfs
        return None

    def get_interface(self, iface):
        for child in self.children:
            if iface == child.interface:
                return child
        return None

    def get_interesting(self):
        """
        Will return the first interesting interface it finds (as a string)
        This is used by the CANVAS Nodes to make their display more
        useful to the user
        """
        ret=""
        for child in self.children:
            if child.ip not in ["127.0.0.1", "0.0.0.0"]:
                return child.ip
        return "" #nothing found?

    def get_callback_interface(self):
        """
        Returns the current callback interface object
        """
        for child in self.children:
            if child.activated:
                return child
        return None #nothing found?

    def add_ip(self,ifc,nat=0,startport=1,endport=65535):
        """
        An ifc (interface, ip, netmask) is given to me, I make it an object and then add it to my children
        and update the model
        """
        interface=interfaceLine(ifc,nat,startport,endport,self)

        # We shouldnt be adding interfaces that already exist in the host knowledge
        for x in self.children:
            if x == interface:
                devlog("hostKnowledge", "Found interface: %s NOT adding again!"%(interface))
                return

        self.add(interface)

        if self.engine:
            self.engine.addLine(interface)

            interface = ifc[0]
            ip        = ifc[1]
            netmask   = ifc[2]

            self.engine.new_event('interface added', {'interface' : interface,
                                                      'ip'        : ip,
                                                      'netmask'   : netmask,
                                                      'NAT'       : True if nat else False,
                                                      'node'      : self.parent.getname()})

    def get_last(self, addrType=None):
        """Pass in an addrType to get the last ipv4 or ipv6 interface, otherwise you get the last interface, whatever it is"""
        #strange error condition
        if self.children==[]:
            return None

        if addrType == None:
            return self.children[-1]
        else:
            if addrType not in ["ipv4", "ipv6"]:
                raise CANVASError("Valid addrType values are 'ipv4' or 'ipv6'")

            for i in reversed(self.children):
                if addrType == "ipv4":
                    if "." in i.ip:
                        return i
                elif addrType == "ipv6":
                    if ":" in i.ip:
                        return i

    def get_menu(self):
        return ["Add interface"]

    def menu_response(self, widget, astring):
        #print "Got %s"%astring
        if astring=="Add interface":
            if self.gui:
                #self.gui is newgui.
                self.gui.engine.gui.gui_queue_append("add interface", [self])

    def restore_state(self, session_dir, prefix="", superseed_existing=True, engine=None):
        dirname = os.path.join(session_dir, "SavedState","Interfaces")

        if not engine:
            engine = self.engine

        try:
            iflist=os.listdir(dirname)
        except:
            engine.log("No Saved State to load in %s"%(dirname))
            return

        #engine.log("Deleting current interface state..")
        for intface in self.children:
            self.engine.deleteLine(intface)
            ##Close any listners present
            for lner in intface.children:
                lner.closeme()

            try:
                lner.parent.delete(lner)
            except:
                pass

        self.children = []

        self.parent.interfaces = self

        for f in iflist:
            #skip all hosts that don't start with 0_ for localNode
            if prefix and f[:len(prefix)]!=prefix:
                #print "did not match prefix: Prefix=*%s* f[:len(prefix)]=*%s*"%(prefix,f[:len(prefix)])
                continue
            try:
                engine.log( "Restoring interface state of: %s"%(f) )

                newiface=cPickle.load(file(os.path.join(dirname,f)))
            except (TypeError), err:
                ##Not a good pickle
                engine.log( "Could not load host '%s' because '%s' - Not a pickle file?"%(f, err) )
                continue

            ##Add this new interface to ourselves (the list of interfaces for this node) & to the classic gui
            self.add(newiface)
            if engine:
                engine.addLine(newiface)

            ##if we don't copy the listener list we end up in an infinite loop condition as the start_listener method appends new
            ## listners to the list :(
            listeners_to_restart = copy.deepcopy(newiface.listeners_that_are_listening)
            newiface.listeners_that_are_listening = []

            ##if the restore interface had a listener when it was saved - restart it
            for l in listeners_to_restart:

                l_type           = l[0]
                port             = l[1]
                fromcreatethread = l[2]
                engine.log( "Restarting listener port:%s type:%s fromcreatethread: %s"%( port, l_type, fromcreatethread))
                #this needs to be done in a new thread or we can block while doing this, killing our gui
                newthread=Thread(target=engine.start_listener, args=(newiface,l_type,port,fromcreatethread))
                newthread.start()

            if newiface.activated:
                engine.set_callback_interface(newiface)

            #set up all the children to have the correct parent again
            #newiface.set_all_parents(self.parent.interfaces)


        return

class nodesList(lineList):
    def __init__(self,parent):
        lineList.__init__(self,parent)
        self._text="Connected Nodes"
        self.activate_text()


def main():
    myhostKnowledge=hostKnowledge("12.34.56.79",None)
    myhostKnowledge.save_state()

if __name__=="__main__":
    main()
