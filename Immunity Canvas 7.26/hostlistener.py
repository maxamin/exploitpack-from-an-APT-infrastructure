#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
hostlistener.py

Every host can have multiple listeners running at once

An exploit needs to be one of these too
"""

TODO = """
- use thread_queue class
- split gui/non-gui code
"""

import sys
import time
from internal import *

import canvastimer
import logging


class hostlistener:
    def __init__(self,id=0,type="Unknown",GtkID=0,logfunction=None):
        """
        connection is our tcp socket
        """
        self.parent=None
        self.initstring=""
        self.id=id
        self.progress=0
        self.info=""
        self.type=type
        self.GtkID=GtkID
        self.logfunction=logfunction
        self.gtkModel=None # a pointer to our place in the host-list
        self.gtkIter=None
        self.gui=None #our gui...no gtk stuff in this file!
        self.engine=None #for callbacks, if we need to
        self.covertness=1 #not covert by default
        self.filename=""
        self.action=""
        self.start_time = self.iCurrentTime()
        self.end_time = ""
        self.children=[] #list of all our child hostlisteners
        return

    def setCovertness(self,covertness):
        self.covertness=covertness
        return

    def setEngine(self,engine):
        self.engine=engine
        return

    def isBusy(self):
        return 1

    def getSocket(self):
        return None

    def getProgress(self):
        return self.progress

    def nextProgress(self):
        self.setProgress(self.progress+20)

    def setProgress(self, progress):
        """
        Set the progress bar. Should be an integer or float between 0 and 100
        -1 means failure (red bar)
        """
        self.progress=float(progress)
        name=""
        if hasattr(self, "name"):
            name=self.name
        if self.gui:
            devlog("gui::exploittree", "Updating progress in %s to %s"%(name,progress))
            self.gui.gui_queue_append("update listener info",[self])
        else:
            devlog("gui::exploittree", "NOT (no gui) Updating progress in %s to %s"%(name,progress))

        return

    def registerNewShell(self,newshell):
        if self.engine:
            self.engine.registerNewShellListener(newshell)
        return

    def setGtkID(self,id):
        self.GtkID=id

    def getGtkID(self):
        return self.GtkID

    def setId(self,id):
        self.id=id
        return

    def setGTKModel(self,gui,model,myiter):
        self.gui=gui
        self.gtkModel=model
        self.gtkIter=myiter
        return

    def getSocket(self):
        return None

    def getId(self):
        return self.id

    def getID(self):
        return self.getId()

    def getInfo(self):
        return self.info

    def setInfo(self,info, showlog=debug_enabled):
        #print "setInfo(%s)"%info
        self.info=info
        if self.gui:
            self.gui.gui_queue_append("update listener info",[self])
        else:
            if showlog:
                self.log("ID: %s Setinfo: > %s <"%(self.id,info))
            #self.gui.setListenerInfo(self)
        time.sleep(0.001)
        return

    def setInfoExt(self, info, msg = None):
        if msg:
            info += ": " + msg
        self.setInfo(info)

    def setInfoDone(self, msg = None):
        self.setInfoExt("Done", msg)

    def setInfoFailed(self, msg = None):
        self.setInfoExt("Failed", msg)

    def getInfo(self):
        return self.info

    def setType(self,type):
        self.type=type

    def getType(self):
        return self.type

    def closeme(self):
        #nothing
        return

    def log(self, message, enter="\n"):
        """
        Uses self.logfunction if one is defined, else tries engine log function
        or else tries stdout

        Deprecated
        """

        """
        if self.logfunction:
            return self.logfunction(message)

        if self.engine==None:
            sys.stdout.write("[C] " + str(message) + enter)
        else:
            #print "Default logfunction entered: %s"%message
            self.engine.log("[C] " + message)
        return
        """

        m = logging.info
        if ("[-]" or "[EE]") in message:
            m = logging.error
        elif "[!]" in message:
            m = logging.warning

        message = message.replace("[-] ", "").replace("[!] ", "").replace("[+] ", "").replace("[ii] ", "").replace("[EE] ", "")
        m(message)

    def debuglog(self, message, enter="\n"):
        if self.engine== None:
            sys.stdout.write("[debug] " + str(message) + enter)
        else:
            self.engine.debuglog(message)
        return

    def link(self,copyfrom,nodes=None):
        """Links self to copyfrom...

        This is a super-important function.

        Notes: We don't copy port over. If you want to move the port, you'll have to do that manually!
        """

        #first set up the parent and child links
        self.parent=copyfrom
        #also need to set self.children
        if hasattr(copyfrom, "children"):
            if self not in copyfrom.children:
                copyfrom.children+=[self]
                if hasattr(copyfrom, "engine") and copyfrom.engine:
                    copyfrom.engine.addExploitLine(self)

        try:
            #we have to do a real copy here, cause otherwise
            #setting copyfrom.argsDict[y]=z will change ours!
            for x in copyfrom.argsDict:
                if x not in ["port"]:
                    #we dont copy ports over
                    self.argsDict[x]=copyfrom.argsDict[x]
        except:
            pass

        #for specified nodes
        if nodes!=None:
            self.argsDict["passednodes"]=nodes
        try:
            self.logfunction=copyfrom.logfunction
        except:
            pass

        try:
            self.engine=copyfrom.engine
        except:
            pass

        try:
            self.target=copyfrom.target
            self.callback=copyfrom.callback

        except:
            pass

        try:
            self.covertness=copyfrom.covertness
        except:
            pass


        if hasattr(copyfrom, "state"):
            #if the copyfrom is halted already, let's halt us too!
            self.state=copyfrom.state

        if hasattr(copyfrom, "maxthreads"):
            self.maxthreads=copyfrom.maxthreads

        if hasattr(copyfrom, "callback"):
            self.callback=copyfrom.callback

        if hasattr(copyfrom, "gui"):
            self.gui=copyfrom.gui

        ##Rich mod for supporting the new datatab we need to do the following when we link
        if hasattr(copyfrom, "dataviewcolumnsfunction"):
            self.dataviewcolumnsfunction=copyfrom.dataviewcolumnsfunction

        if hasattr(copyfrom, "dataviewinfofunction"):
            self.dataviewinfofunction=copyfrom.dataviewinfofunction

        return

    def iCurrentTime(self):
        return canvastimer.CurrentTime()

    def getStartTime(self):
        return self.start_time

    def getEndTime(self):
        self.end_time = self.iCurrentTime()
        return self.end_time

    def setAction(self, t):
        self.action = t

    def getAction(self):
        return self.action
