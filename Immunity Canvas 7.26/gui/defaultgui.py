#! /usr/bin/env python
"""
defaultgui.py - implements the default GUI class which has everything the
CANVAS engine needs when there is no actual gui running
"""

class fakenodegui:
    def __init__(self):
        pass
    
    def update_object(self,object):
        pass
    
from threading import Thread

import gobject
import select

class listenerhandler(Thread):
    """
    Handles listener startup requests when you are not running in a real gui - threads and just
    waits for a connection
    """
    def __init__(self,fd,callback):
        Thread.__init__(self)
        self.setDaemon(1) #no waiting for us to die
        self.fd=fd #our file descriptor we listen on - really a socket object
        self.callback=callback
        
    def run(self):
        
        while 1:
            #we are already listening on self.fd, which is really a socket object
            if hasattr(self.fd, "block_until_active"):
                #this is mostly used by HTTP_MOSDEF "sockets"
                self.fd.block_until_active()
            else:
                ret=select.select([self.fd],[],[]) #no timeout , we block here
            self.callback(self.fd, gobject.IO_IN)
            
                
class defaultgui:
    def __init__(self,handle_callbacks=1):
        self.localip="127.0.0.1"
        self.knownhosts=[]
        self.nodegui=fakenodegui()
        self.handle_callbacks=handle_callbacks

    
    def setLocalIP(self,IP):
        """
        Sets the local IP in the entry box for display and also in our local storage
        """
        self.localip=IP
        return
    
    def gui_queue_append(self,command,args):
        if command=="logmessage":
            print args[0],
        return
    
    def addknownhost(self,host,os,status):
        self.knownhosts.append((host,os,status))
    
    def get_input_read(self):
        return gobject.IO_IN
    
    def input_add(self,fd,activity,callback):
        if self.handle_callbacks:
            newh=listenerhandler(fd,callback)
            #I'm uncertain as to what the proper thread thing to do here is...
            #Phil has a certain wrapper he uses, but I want to make sure we use it properly. 
            #TODO: look into wrapping this with phil's thread wrapper
            newh.start() #let the thread do its thing
    
    def play(self,soundname):
        """
        default gui doens't make sounds
        """
        pass
        
    def out_of_date_action(self, at_current_ver, msg):
        """
        What to do when we check version and find we are out of date
        """
        pass
        
