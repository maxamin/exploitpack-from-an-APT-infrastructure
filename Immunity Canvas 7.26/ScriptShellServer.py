#! /usr/bin/env python

"""
CANVAS Scripting shell server for Scripting languages like PHP and Python and whatnot
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information


from shellserver import shellserver
from exploitutils import *
import time
import os
import socket
from phplistener import phplistener

class phpshellserver( phplistener): 
     """
     PHP Shell Listener
     """
     
     def __init__(self,connection,node,logfunction=None):
          #shellserver.__init__(self,connection,node,type="Active",logfunction=logfunction)
          self.arch="x86"
          self.order=intel_order
          self.unorder=istr2int
          self.connection=connection
          self.node=node
          self.node.shell=self
          self.started= 0 
          self.logfunction = logfunction
          self.engine=node.engine
          return
     
     def startup(self):
          """
          Start this process...
          """
          if self.started:
               return
          self.log("Startup PHP Script Shell Server...")
          self.started=1
          phplistener.__init__(self,self.connection,logfunction=self.logfunction)
          phplistener.startup(self)
          print self.node.shell
          self.log("Set up shell listener")
          #ok, now our mainloop code is running over on the other side
          self.log("Set up PHP shell server")
          #self.sendrequest(mainloop)
          self.node.getInfo()

          return 1