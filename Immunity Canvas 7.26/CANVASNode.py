#! /usr/bin/env python

"""
CANVASNode.py - your basic node

TODO:
    Add XML RPC interface so commandline nodes can use it, for example. That way
    we can link everyone together. It'll be great! :>
"""
from hostKnowledge import hostKnowledge #a list of knowledgePrimitives (A=B and percent of truth)
from hostKnowledge import knowledgeContainer #basically, a list of hosts I know about
from hostKnowledge import knowledgePrimitive #the primitives themselves
from hostKnowledge import interfacesList #a list of interface objects
from hostKnowledge import nodesList #a list of nodes
from hostKnowledge import lineList #our base class
from internal import *
from Nodes.NodeUtils import NodePrompt
import os
from canvaserror import *
import sniffer
import sys

import threading
import time
import logging



# for node-killing upon deletion
from engine import CanvasConfig
import socket
from MOSDEFSock import MOSDEFSock

#nodes are going to need to lock, and nodes that support threading need to lock
#on a per-thread basis




class CANVASNode(lineList, NodePrompt):
    """
    This is the parent class of all our CANVAS Nodes
    You should probably not be instantiating this yourself. If
    that's what you're doing, you probably want a LocalNode instance.
    """
    def __init__(self,parent=None):
        self.interfaces=None
        self.nodetype="CANVAS Node"
        self.nodeID=0
        lineList.__init__(self,parent)
        self.parentnode=None
        if parent:
            self.parentnode=parent.parent
            #Auto set engine
            self.engine=self.parentnode.engine


        self.hostsknowledge=knowledgeContainer(self)
        #hostsknowledge(self) is me
        self.amselected=0
        self.selectnum=0
        self.new_host("127.0.0.1")
        self.interfaces=interfacesList(self)

        self.connected_nodes=nodesList(self)
        self.peerAddress="Unknown"
        self.parent=None
        self.nextID=0
        #for testing.
        #self.new_host("192.168.1.101")
        self.shell=None #shell for nodes that need them
        self.async=0 #not async by default
        self.started=0
        self.capabilities=[]
        self.busy=0
        self.listener_type = None

        self.colour="white"
        self.base_rightclick_menu=["Select as first node",
                                   "Select as additional node",
                                   "Unselect",
                                   "Select all child nodes",
                                   "Unselect all child nodes",
                                   "Close this node",
                                   "Listener Shell"]
        self.base_leftclick_menu=["Knowledge",
                                  "Interfaces"]
        ##Rich mod - required because previously impossible to traverse node structures
        ## downward. This whole thing is a massive freakin mess and needs to die
        self.child_nodes = []

        return

    def __str__(self):
        return "%s: %s" % (self.nodetype, self.get_name())

    def hasRawSocks(self):
        #only LocalNodes with Linux as Root have raw socks
        return False

    def getRawSock(self, interface, protocol):
        """
        Returns None on failure
        """
        if not self.hasRawSocks:
            return None

        if self.shell:
            #we return a "quickrawsock" object here in order to make the api always "sock.send"
            return sniffer.quickrawsock(self.shell.bindraw(interface, protocol),self)

        #otherwise we are a Node that does not have a Shell which does support raw sockets----probably the LocalNode
        sock=sniffer.bindraw(interface, protocol)
        return sock


    def setbusy(self,busy):
        """
        Setting the node to busy is used by the shellserver to offer the GUI a
        chance to show the user something is happening (via the Node flashing blue).
        """
        #use this to find out why setbusy doesn't work
        devlog("canvasnode","CANVASNode %s setbusy(%s)"%(self.get_name(),busy))
        self.busy=busy
        self.update_pix()
        self.update_gui()

    def add_local_ifs_to_hostlist(self):
        """
        In several cases we need to re-initialize our hostlist to add hosts
        """
        allips=self.interfaces.all_ips()
        devlog("CANVASNode","All IPS: %s"%allips)
        for newhost in allips:
            devlog("CANVASNode","Adding interface %s to our host list"%newhost)
            self.add_host(newhost)
        return

    def startup(self):
        """Assumes shell is our shelllistener and starts up it - used by
        new listener connections
        """
        devlog('CANVASNode::startup', "called")
        if self.shell and not self.shell.started:
            devlog('CANVASNode::startup', "self.shell.startup()")
            self.shell.startup()
        if not self.started:
            devlog('CANVASNode::startup', "self.findInterfaces() %s" % self.findInterfaces)
            #calling findinterfaces again...
            try:
                self.findInterfaces()
            except NodeCommandError, i:
                self.log("Error during findInterfaces: %s" % i)

            self.findHost()
            #now we need to add all our interfaces to our host-list as hosts
            self.add_local_ifs_to_hostlist()

        self.started=1
        self.update_gui()

    def decode(self,data):
        """no decode by default, but override this later..."""
        devlog('CANVASNode::decode', "Default decode called")
        return data

    def getname(self):
        "returns a string that represents the name of the node"
        ret=""
        if self.parentnode!=None:
            ret = "%s->%s"%(self.parentnode.getname(),self.nodeID)
            if hasattr(self, "shell") and hasattr(self.shell, "pid") and self.shell.pid:
                ret += " PID: %s"%self.shell.pid

        else:
            ret = "%s"%self.nodeID
        return ret

    #Little shimmy here
    def get_name(self):
        return self.getname()

    def setPeerAddress(self,address):
        self.peerAddress=address

    def findHost(self):
        # TODO
        """
        Nodes automagically add possible target hosts
        """
        return []

    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (for example, SQL nodes cannot..., UnixShellNode could)
        """
        devlog("CANVASNode","findInterfaces stub called...")
        return []

    def get_host_by_ip(self,ip):
        # TODO
        return None

    def merge_hostKnowledge(self,newhost):
        """new host is a hostknowledge object to add to our list
        if it already exists, we merge it
        """
        if self.get_known_host(newhost.interface):
            print "Todo: merge known host with new host"
        else:
            self.add_hostKnowledge(newhost)
        return

    def add_hostKnowledge(self,newhost):
        """Adds a hostknowledge class to our list"""
        self.hostsknowledge.add(newhost)

        self.hostsknowledge.update_gui()
        if self.engine:
            self.engine.addLine(newhost)
        return newhost

    def add_host(self, newhost, lookup=True):

        if type(newhost) == type(""):
            #newhost is a string
            #duplicate check
            a=self.get_known_host(newhost)
            if a:
                return a
            newhost = hostKnowledge(newhost, self, doDNS=lookup) #not anymore
        else:
            ##dupe check
            a=self.get_known_host(newhost.interface)
            if a:
                return a

        self.add_hostKnowledge(newhost)

        return newhost

    def new_host(self,ip,add=1,resolved_from=None):
        """We know something about a new host!"""

        ##Stop 0.0.0.0 being added as that's just plain stupid
        if ip == "0.0.0.0":
            self.log("0.0.0.0 is not a valid target address, changing to 127.0.0.1")
            ip = "127.0.0.1"

        # XXX: check for ipv6 compliance
        devlog('CANVASNode::new_host', "(%s)" % ip)
        for c in self.hostsknowledge.children:
            if c.interface == ip:
                #we already know about that host
                return c

        if resolved_from:
            newhost = hostKnowledge(ip, self, doDNS=False, resolved_from=resolved_from)
        else:
            newhost = hostKnowledge(ip, self)

        newhost.engine = self.engine

        if add:
            self.add_hostKnowledge(newhost)

            if self.engine:
                self.engine.new_event("new host", {
                    "ip"            : ip,
                    "resolved_from" : newhost.resolved_from,
                    "node"          : self.getname(),
                    })

        return newhost

    def forget(self, tag):
        """
        Forget something from localhost
        """
        c=self.hostsknowledge.get_localhost()
        c.forget(tag)
        return

    def clear_knowledge(self):
        # Reset any hosts we have found up to now
        self.hostsknowledge.children = None
        # re-initialize the interfaces
        self.init_me(True)
        # add local interface to our list
        self.add_local_ifs_to_hostlist()
        return

    def get_known_host(self,ip):
        "always returns a host for 127.0.0.1 - that host always exists"
        c=self.hostsknowledge.get_known_host(ip)
        if c:
            return c

        if ip=="127.0.0.1":
            return self.new_host("127.0.0.1") #always have this
        return None

    def get_all_known_hosts(self):
        return self.hostsknowledge.get_all_known_hosts()

    def get_first_known_host(self):
        return self.hostsknowledge.get_first_known_host()

    #def get_menu(self):
    def get_rightclick_menu(self, newgui_obj):

        if "VFS" in self.capabilities and "Browse filesystem" not in self.base_rightclick_menu:
            self.base_rightclick_menu+=["Browse filesystem"]

        self.menu_handler=newgui_obj

        return self.base_rightclick_menu

    #def menu_response(self, widget, astring):
    def get_rightclick_response(self, widget, astring):

        if astring=="Select as first node":
            self.engine.set_first_node(self)
        elif astring=="Select as additional node":
            self.engine.append_node(self)
        elif astring=="Close this node":
            self.close_node_clean_gui()

        elif astring == "Browse filesystem":
            self.engine.gui.gui_queue_append("browse_filesystem", [self])

        elif astring == "Listener Shell":
            self.engine.gui.gui_queue_append("do_listener_shell", [self])

    def get_leftclick_menu(self, new_gui_obj):
        """ controls the base menu for a graphed node left click """

        self.new_gui=new_gui_obj #so the response can call into newgui methods

        # reset menu
        menu = []
        # Knowledge then all host knowledge
        menu.append(self.base_leftclick_menu[0])
        for knowledge in self.hostsknowledge.get_children():
            menu.append(knowledge.text)

        # Interfaces then all interfaces
        menu.append(self.base_leftclick_menu[1])
        for interface in self.interfaces.get_children():
            menu.append(interface.text)

        return menu

    def get_leftclick_response(self, obj, item):
        """ the menu response for line object compatibility """
        print "WOOOSH",obj,item
        if item == self.base_leftclick_menu[0]:
            # pass through to the actual menu_response we want
            return self.new_gui.menu_handler(self.hostsknowledge).popup(None, None, None, 0, 0)
        if item == self.base_leftclick_menu[1]:
            return self.new_gui.menu_handler(self.interfaces).popup(None, None, None, 0, 0)
        # walk the Knowledge list for a handler match
        for host in self.hostsknowledge.get_children():
            if host.text == item:
                return self.new_gui.menu_handler(host).popup(None, None, None, 0, 0)
        # walk the Interfaces list for a handler match
        for interface in self.interfaces.get_children():
            if interface.text == item:
                return self.new_gui.menu_handler(interface).popup(None, None, None, 0, 0)

        return


    def close_node_clean_gui(self, kill_kids=True):
        """
        Shutdown the node and clean up our gui, for ourselves, our children, their
        children etc
        """
        ##Nodes to which we are a parent
        kids = self.child_nodes
        aggressive_shutdown = True

        self.closeself()

        if self.parent:
            logging.info("Deleting Node from GUI (%s) " % (self))
            self.parent.delete(self)

        if self.parentnode:
            self.parentnode.child_nodes.remove(self)
            self.engine.new_event('node deleted', {'node' : self.getname()})

        ##If we are closing the node that is the first node, then select
        ##the localnode instead
        ##and unselect us as a node regardless
        if self.amselected:
            if self.selectnum == 0:
                self.engine.set_first_node(self.engine.localnode)
            self.unselect()

        ##Unless otherwise stated remove all our children, and their children...
        if kill_kids:
            ##Recurse into ourselves for each child to get their children
            for kid in kids:
                logging.info("Killing child %s (%s)" % (kid, kid.getname()))
                kid.close_node_clean_gui()

        # NOTE: this doesn't handle the case when a node is hung.
        # tell the child node to close its socket
        def close_lambda(__shell, __fd):
            _shell = __shell
            _fd = __fd

            # NOTE: commented out because we're trying to see if we can't eliminate
            # all of the TIME_WAITs from every node.
            def c():
                _shell.close(_fd)

            return c

        # base case - this is a node that we have a direct connection to
        if not isinstance(self.shell.connection, MOSDEFSock):
            devlog("canvasnode", "shutting down socket connection directly.")
            # NOTE: these comments have been left in for describing our rationale for
            # implementing disconnections in the way we did.

            # print "CANVASNode: first, closing the fd %s from self.shell" % (self.shell.fd)
            # NOTE: if you enable this then something like:
            # TCP    192.168.1.108:49201    siliconvalley:5555     FIN_WAIT_2
            # will show up on the Node's host.
            #self.shell.close(self.shell.fd)

            devlog("canvasnode", "now shutting down and subsequently closing socket on our end")
            try:
                self.shell.connection.shutdown(socket.SHUT_RDWR)
                self.shell.connection.close()
            except socket.error as e:
                devlog("canvasnode", "encountered error on local socket close:%s" % (str(e)))
            finally:
                self.shell.connection = None

        # inductive case - this is a node that we've pivoted through
        # another node

        else:
            # NOTE: these comments have been left in for describing our rationale for
            # implementing disconnections in the way we did.

            # devlog("canvasnode", "shutting down socket connection for child %s, fd %s." % (str(self.shell), (str(self.shell.fd))))
            # original:
            # self.shell.close(self.shell.fd)
            # NOTE: if you enable this then something like:
            # tcp        0      0 ubuntu:57318            saito:5555              FIN_WAIT2
            # will show up on the Node's host.

            # tell the parent node to close the socket yielded
            # by the call to accept()
            devlog("canvasnode", "shutting down socket connection for parent %s, fd %s." % (str(self.parentnode.shell), (str(self.shell.connection.fd))))

            # NOTE: Even with *only* this patch, we still wind up with:
            # TCP    192.168.1.108:5555     ubuntu:57320           TIME_WAIT
            # on the pivoting host.

            # original:
            # self.parentnode.shell.close(self.shell.connection.fd)
            parent_closer = threading.Thread(target=close_lambda(self.parentnode.shell, self.shell.connection.fd))
            parent_closer.start()
            parent_closer.join(1)


        ##Remove ourselves from the nodeList
        try:
            self.engine.nodeList.remove(self)
        except ValueError:
            devlog("Could not remove %s from nodelist!"%repr(self))


    def get_interesting_interface(self):
        """
        Gets the first interesting (non-localhost) interface
        from our list of interfaces, or returns empty string
        if no interfaces are found.
        """
        interfacename=""
        if self.interfaces:
            interfacename=self.interfaces.get_interesting()
        return interfacename


    def activate_text(self):
        interfacename=self.get_interesting_interface()

        try:
            id_str = self.getname()
        except AttributeError:
            ##The node doesn't have a parent
            id_str = self.nodeID

        if self.amselected:
            self.text="%s %s ID(%s) [Selected: %s]"%(interfacename, self.nodetype, id_str, self.selectnum)
        else:
            self.text="%s %s ID(%s)"%(interfacename, self.nodetype, id_str)

    def appended(self,index):
        """we were just selected from the GUI"""
        #if self.amselected:
        #    print "just return"
        #    self.selectnum=index
        #    return self.selectnum
        self.amselected=1
        self.selectnum=index
        self.activate_text()
        self.update_gui()
        self.update_engine()
        return index

    def unselect(self):
        self.amselected=0
        self.activate_text()
        self.update_gui()
        self.update_engine()

    def update_engine(self):
        if self.engine:
            pass

    def __del__(self):
        self.log("delete function has been called on %s" % self.getname())

    def runcommand(self, command, LFkludge=False): # KLUDGE for shelllistener::runcommand
        # MOSDEF will crash and burn if we pass unicode string
        try:
            command = command.encode('ASCII')
        except UnicodeError:
            self.log('runcommand: Could not encode %s to ASCII, aborting..' % command)
            return None

        if self.shell:
            try:
                return self.shell.runcommand(command, LFkludge)
            except:
                return self.shell.runcommand(command)
        else:
            return os.popen4(command)[1].read()

    def getcwd(self):
        return self.shell.getcwd()

    def unlink(self,filename):
        return self.shell.unlink(filename)

    def rmdir(self,filename):
        return self.shell.rmdir(filename)

    def spawn(self,filename):
        return self.shell.dospawn(filename)

    def dir(self, directory):
        return self.shell.dodir(directory)

    def download(self,source,dest):
        if self.shell:
            return self.shell.download(source,dest)
        else:
            raise NodeCommandUnimplemented("Node lacks a self.shell, so downloading unimplemented")

    def upload(self,source,dest=".",destfilename=None):
        if self.shell:
            return self.shell.upload(source,dest,destfilename)
        else:
            raise NodeCommandUnimplemented("Node lacks a self.shell, so uploading unimplemented.")

    def newNode(self,node):
        """Adds a new node to my list"""
        devlog("Calling newNode with nextID=%s"%self.nextID)
        self.connected_nodes.add(node)
        node.gui=self.gui
        node.engine=self.engine

        node.nodeID = self.nextID

        self.nextID+=1
        node.parentnode=self
        node.parent=self.connected_nodes
        node.activate_text()

        return

    def log(self, message, show=1):
        if self.shell:
            self.shell.log(message)
        elif show:
            print "[C (node has noshell)] " + message

    def closeself(self):
        if self.engine.callback_interface in self.interfaces.all_interface_objects():
            devlog("canvasnode","Found a callback interface in our interfaces - resetting it to localNode")
            self.engine.reset_callback_interface()

    def interact(self):
        #if one of us has an engine, let's both use that.
        assert self.shell, "self.shell missing ..."
        if not self.engine and self.shell.engine:
            self.engine=self.shell.engine
        if not self.shell.engine and self.engine:
            self.shell.engine=self.engine
        self.shell.interact()

    def getMatchingInterface(self,ip):
        """
        If we can find an interface locally that matches
    -    that IP, return it,
        otherwise return None
        """
        ret=self.interfaces.get_ip(ip)
        return ret

    def islocal(self,ip):
        """Checks to see if an ip is local to our interfaces"""
        if ip=="127.0.0.1":
            return 1
        for localip in self.interfaces.all_ips():
            if ip==localip:
                return 1

        return 0

    def getallips(self):
        """
        Returns a list of our IP's from our list of interfaces
        Returns an empty list if we don't have a list of interfaces
        """
        if not self.interfaces:
            return []
        return self.interfaces.all_ips()



################################################################################################
    #some documentation on node communications!

    #the trick here is that if we are a node, but not the localnode, and we want to do something
    #we have to get that request to the node
    #additionally, if we are a listener, we need to be able to check to see if
    #someone has connected back to us. The truly painful part is implementing
    #timouts, but with MOSDEF we should be ok
    #this obviously does not support truly asynchronous protocols

    #some usage cases
    #so L->M->P
    #we want to send a MOSDEF message to P. So P asks M to send a message to it
    #and M asks L to send a message to it. So L runs "M.send(fd,shellcodeM)"
    #and shellcodeM instructs M to send shellcodeP to P via a send(fdP,shellcodeP)

    #sock in the following calls is a type of object that makes sense to my parent node
    #for localnode, or pythonnode ,that means socket objects
    #for MOSDEF nodes, that means integer or file handle objects

    #someone may someday ask what the difference is between CANVAS's way and stack swapping
    #in terms of node communications, we both have simple synchronous push->pull protocols
    #however, canvas also supports push->pull-pull-pull where you don't know the size of
    #subsequent pulls. And, of course, CANVAS supports push only communications (the default).

    #the problem with this is that you can't support two way pipes - real asynchronous
    #communication is necessary for things like tcp-tunelling, unless you have some
    #polling going on, which is lame.

    #This requires threads to do properly
    # meaning a thread-enabled MOSDEF
    # meaning a pythonnode
    # actually, if A-B-C-D then all of them must be thread enabled for D to set up
    # an asych tunnel

    #so we have a few types of node connections
    #1. localsock (local node)
    #2. remotesock (python nodes)
    #3. fd (mosdef nodes)

    #there is one major time when this is important even without tunnelling - listeners
    #a listener is essentially a tcp tunnel. In order to check to see if a listener
    #has been connected to, we need to poll on that socket every time we get Isucceeded()
    #or at the end of the exploit. If we got a connection, we initialize the listener,
    #and pass it down the line.

    #however, if we have an asynchronous connection to the Node the listener is on
    #we don't need to poll. We'll receieve a message directly from the node saying a connection
    #was made.

    #The other question is this : do we want to support remoted shellservers, and if so, how.
    # a remoted shellserver would be entirely controlled by a pythonnode, and would thus gain
    # the advantages of being asynchronous, even when a MOSDEF node was between localnode
    # and the end node.
    # so L->M->P->P. This setup would allow a the last two PythonNodes to communicate
    # asnyrounously, without any messages going inbetween L and and P nodes.
    #we can table this for now and say that all shellservers are local, and they communicate
    #remotely with their host

    #The other issue is what if you have A->B and A->C and both B and C are active. You don't
    #Want B waiting for C to finish a transmit before it can start, so if A is an asynchronous
    #node, it can wait on both at once. Otherwise, it can only do one at a time.

    #so there are three major things that affect the architecture
    #1. shellserver message send/recv
    #2. listener polling
    #3. Asynchronous communications (listener/tunneling/shellserver)
    def send(self,sock,message):
        """
        sock is any object that supports send(). Here we send a message to another node.
        """

    def recv(self,sock,length):
        """
        Recv data from another node
        """

    def isactive(self, sock, timeout):
        """
        Check to see if the node has anything waiting for us

        """

class CrossPlatformNode(CANVASNode):
    """A special case for a Node that is cross platform, such as a PHP ScriptNode or JavaNode. These nodes implement a MOSDEF like interface
    with limited capabilities, but sometimes we need to do things that depend on the underlying OS. During startup, these nodes attempt
    to determine their host OS, and provide a standard interface for us to query this info."""

    def getInfo(self):
        """This function should query the Node, build a canvasos object, and put it in the knowledge tree as "OS". If the node
        is a Unix, and supports running Unix Shell commands, then this should also add "Unix Shell" to self.capabilities.
        """
        os = self.shell.getPlatformInfo()
        if os != None:
            self.hostsknowledge.get_localhost().add_knowledge("OS", os, 100)

            if os.isUnix():
                self.capabilities.append("Unix Shell")
            elif os.base == "Windows":
                self.capabilities.append("Win32 Shell")

        return os

    def getHostOS(self):
        host_os = self.hostsknowledge.get_localhost().get_knowledge("OS")

        if host_os == None:
            host_os = self.getInfo()
        else:
            host_os = host_os.known

        if host_os != None:
            return host_os
        else:
            raise NodeCommandError("Unable to determine underlying host OS")

    def isOnAUnix(self):
        """Shortcut for getting our OS knowledge and checking if we're on unix"""
        if not hasattr(self, 'isunix'):
            self.isunix = self.getHostOS().isUnix()

        return self.isunix

    def findInterfaces(self):
        """This function should provide a standard interface to get the interface list from a cross platform node"""
        if "Unix Shell" in self.capabilities:
            x = self.getHostOS()
            from unixShellNode import unixShellInterfaceResolver
            u = unixShellInterfaceResolver(self, x.base, x.arch, x.version)
            return u._osresolvfunc('findInterfaces')
        elif "Win32 Shell" in self.capabilities:
            from win32Node import win32ShellInterfaceResolver
            u = win32ShellInterfaceResolver(self)
            return u.findInterfaces()
        else:
            # vector to something else.
            raise NodeCommandUnimplemented("CrossPlatformNode doesn't have a findInterfaces vector for this OS yet :(")
