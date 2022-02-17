#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
gui_queue.py

Does what we need to do to avoid threading issues on both Linux and Windows

You can include this file and use it without knowing anything about gtk
"""


TODO = """
recode/split that class
- class thread_queue
- class gui_queue(thread_queue)

we can use threads in commandline as well.
"""

import sys
import random
import socket
import time
import timeoutsocket
from threading import RLock

import logging


# DEBUG_LOOP is checked by clearqueue
# If it is set, gui_queue event handling is suspended because the gtk event
# loop is not running. This flag only makes sense in developer builds.
# debug.py is not included in release builds and therefore DEBUG_LOOP will
# be False
DEBUG_LOOP = False
try:
    from debug import query_restart
    DEBUG_LOOP = True
except ImportError:
    pass

class gui_queue:
    """wakes up the gui thread which then clears our queue"""
    def __init__(self, gui, listenport=0):
        """If listenport is 0, we create a random port to listen on"""
        self.mylock = RLock()
        self.myqueue = []
        if listenport == 0:
            self.listenport=random.randint(1025, 10000)
        else:
            self.listenport=listenport
        logging.info("Local GUI Queue listening on port %s" % self.listenport)
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", self.listenport))
        self.listensocket=s
        self.listensocket.listen(300) #listen for activity.
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        #time.sleep(15)
        self.gui=gui
        self.useconnect=0
        if not self.useconnect:
            s.connect(("127.0.0.1",self.listenport))
            self.s=s
            self.readconn,addr=self.listensocket.accept()
        return

    def terminate(self):
        self.s.close()
        return

    def get_event_socket(self):
        if self.useconnect:
            return self.listensocket
        else:
            return self.readconn

    def append(self,command,args):
        """
        Append can be called by any thread
        """
        #print "about to aquire..."
        self.mylock.acquire()
        self.myqueue.append((command,args))
        if self.useconnect:
            #this won't work on a host with a ZoneAlarm firewall or no internet connectivity...
            s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            #small timeout will wake up the gui thread, but not
            #cause painful pauses if we are already in the gui thread.
            #important to note that we use timeoutsocket and it
            #is already loaded.
            s.set_timeout(0.01)
            #wakey wakey!
            #print "Connecting to port %d"%self.listenport
            try:
                s.connect(("localhost",self.listenport))
            except:
                #ignore timeouts
                pass
        else:
            self.s.send("A") #just send a byte
        #print "About to release"
        self.mylock.release()
        return

    def clearqueue(self):
        """
        Clearqueue is only called by the main GUI thread
        Don't forget to return 1
        """
        #print "Clearing queue"
        #clear this...TODO: add select call here.

        if DEBUG_LOOP and query_restart(): return

        if self.useconnect:
            newconn,addr=self.listensocket.accept()
        else:
            self.readconn.recv(1)
        for i in self.myqueue:
            (command,args)=i
            try:
                #any error in this thread is deadly, so we
                #catch and print them all!
                self.gui.handle_gui_queue(command, args)
            except:
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
        self.myqueue=[]
        return 1

    def handle_gui_queue(self, command, args):
        """
        Callback the gui_queue uses whenever it recieves a command for us.
        command is a string
        args is a list of arguments for the command
        """
        gtk.threads_enter()
        #print "handle_gui_queue"
        if command=="addLine":
            #print "addLine called in canvasguigtk2.py"
            obj=args[0]
            self.addLine(obj)
        else:
            logging.error("Did not recognize action to take %s: %s" % (command, args))
        #print "Done handling gui queue"
        gtk.threads_leave()
        return 1

    def gui_queue_append(self, command, args):
        "Called by other classes to add to our list of things to do"
        self.gui_queue.append(command, args)
        return 1
