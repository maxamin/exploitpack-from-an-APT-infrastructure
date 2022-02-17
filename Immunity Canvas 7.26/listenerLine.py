#! /usr/bin/env python

"""

listenerLine.py

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""

import sys #for flush
from hostKnowledge import lineList
from exploitutils import *
from internal import devlog

class fakeListenerLine:
    """A fake class for the commandline versions"""
    def __init__(self,ip,port):
        self.ip                  = ip
        self.original_port       = port
        self.port                = port
        self.argsDict            = {}
        self.http_proxy_endpoint = None
        
    def __str__(self):
        return "fakeListenerLine: %s:%d"%(self.ip, self.port)
        
class listenerLine(lineList):
    """
    This class handles the listeners you want to put onto a socket - in general it needs to only store a tiny bit of state
    and the few callbacks it has are what canvas exploits need to know when they succeeded
    
    Its parent is an interfaceLine (see hostKnowledge.py)
    
    """
    def __init__(self,type, port, id, gtkid, sock, log, parent, fromcreatethread=False):
        self.current_listener=0 # when parent's parent is ourself, we need that before to initialize ourself!
        lineList.__init__(self,parent)
        self.type=type
        
        self.original_port = port

        # self.port will be overwritten and set as the http_proxy tunnel port
        # in the case of HTTP(S) listeners
        #
        # This is done in order to present a convenient way to clientsides
        # (self.callback.port will point to the tunnel port)
        #
        # We always keep the original in self.original_port
        self.port = port
        self.http_proxy_endpoint = None
        
        if parent:
            self.ip=parent.ip
            self.parent.add(self) #add me to their child list
        else:
            self.ip="0.0.0.0"

        self.initstring = ""
        self.id=id
        self.sock=sock
        self.log=log
        self.gtkID=gtkid

        self.text = "%s on %s:%d" % (self.type, self.ip, self.port)
        
        self.engine=None
        self.busy=0
        self.current_exploit=None
        self.argsDict={}
        self.lastnewnode=None
        self.totalnodes=[]
        self.silres=[] # This is only useful for SILICA
        
        ##For state saved to be restored - NAT as well ?
        self.fromcreatethread = fromcreatethread
        self.pickledefaults["fromcreatethread"]= fromcreatethread

        if self.fromcreatethread: self.argsDict['fromcreatethread'] = True
        
    def __str__(self):
        return self.text


    def set_http_endpoint(self, http_endpoint):
        """
        Sets a http endpoint which should be a proxyThread instance
        (see canvasengine.py) to this listenerLine instance.

        This is used for HTTP/HTTPS MOSDEF.
        """
        self.http_proxy_endpoint = http_endpoint

        if http_endpoint:
            self.port = http_endpoint.server_port

            self.text = "%s (%s) on %s:%d (proxy to port %d)" % \
                        (self.type, "HTTPS" if http_endpoint.ssl else "HTTP",
                         self.ip, self.port, self.original_port)
        else:
            # Restore old description
            self.port = self.original_port
            self.text = "%s on %s:%d" % (self.type, self.ip, self.port)
        
    def isSpecial(self):
        """
        Returns true if we are a NAT or other special interface'd listener
        """
        if self.parent:
            if self.parent.isSpecial:
                return True
        return False
    
    def getID(self):
        return self.id

    def getGtkID(self):
        return self.gtkID
    
    def getSocket(self):
        return self.sock
    
    def setEngine(self,engine):
        self.engine=engine
        
    def get_menu(self):
        devlog("listenerLine","Listener ArgsDict=%s"%self.argsDict)
            
        if self.busy != 0:
            busy = ["Clear busy flag"]
        else:
            busy = []
            
        return ["Set as current listener", "Check for connection", "Kill Listener"] + busy

    def activate_text(self):
        if self.current_listener:
            self.text="%s (current listener)"%self.text
        else:
            # nuffin yet
            return
    
    def set_as_listener(self,t=1):
        self.current_listener=t
        self.activate_text()
        self.update_gui()
        #self.update_engine()        
        
    def unset_as_listener(self):
        self.set_as_listener(0)
            
    def menu_response(self, widget, astring):
        if astring=="Set as current listener":
            self.set_as_listener()
            
        elif astring == "Kill Listener":
            self.closeme()
            self.engine.log("Killed Listener \"%s\"" % self.text)
            self.parent.delete(self)
        
        elif astring == "Clear busy flag":
            self.busy = 0
                
        elif astring == "Check for connection":
            print "Check for connection menu clicked"
            self.gui.engine.gui.gui_queue_append("check_listener_for_connection", [self])
            
    def informClient(self):
        """
        Called when the exploit has succeeded in generating a callback
        """
        if self.current_exploit:
            self.log("Informed client %s they succeeded in getting a callback"%self.current_exploit.name)
            self.current_exploit.succeeded=1
        else:
            self.log("Listener did not have a current exploit to inform about callback")
        return
    
    def check(self):
        """
        checks to see if we got a connectback, useful for MOSDEF nodes
        
        This is not called at all from localNode callbacks...they're handled
        by an event loop.
        """
        devlog("ListenerLine","Checking for connectback on remote socket")
        sys.stdout.flush()
        active=1
        try:
            if not self.sock.isactive():
                devlog("ListenerLine","Socket not active - returning 0")
                return 0
        except:
            #not a mosdefsock
            pass
        # accept() should return signed int (i.e. sint32())
        # but it can also return a MOSDEFSock
        #it returns a tuple, of course
        a,blah=self.sock.accept()
        if a == -1:
            devlog("ListenerLine", "check returning 0 for listenerLine")
            return 0
        else:
            #now the listener needs to inform the client it was successful
            #and then start up a new Node on that callback
            devlog("ListenerLine","Starting new node from listener line!")
            sys.stdout.flush()
            newnode=self.engine.new_node_connection(self,a)
            devlog("ListenerLine","self.engine.new_node_connection returned %s"%newnode)
            if newnode:
                self.lastnewnode=newnode
                #can't be storing global list of all nodes in random listeners!
                #self.totalnodes+=[newnode]

        return 1

    def closeme(self):
        self.sock.close()
        
        if self.engine.gui and self.gtkID != -1:
            self.engine.gui.input_remove(self.gtkID)
                
        # Tear down associated HTTP Proxy threads ...
        if self.http_proxy_endpoint and self.engine:
            try:
                self.http_proxy_endpoint.halt_gracefully()
                self.engine.proxy_threads.remove(self.http_proxy_endpoint)
            except Exception, ex:
                self.log('Error on HTTP proxy endpoint shutdown: %s' % ex)

        if self.http_proxy_endpoint:
            self.parent.listeners_that_are_listening.remove([self.type, self.original_port, self.fromcreatethread])
        else:
            self.parent.listeners_that_are_listening.remove([self.type, self.port, self.fromcreatethread])
            
        self.engine.new_event('killed listener', {'node'             : self.parent.parent.parent.getname(),
                                                  'ip'               : self.parent.ip,
                                                  'interface'        : self.parent.interface,
                                                  'type'             : self.type,
                                                  'port'             : self.original_port,
                                                  'fromcreatethread' : self.fromcreatethread})
