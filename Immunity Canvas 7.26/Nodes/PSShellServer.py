#! /usr/bin/env python

"""
CANVAS shell server for Powershell
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2015
#http://www.immunityinc.com/CANVAS/ for more information


from shellserver import shellserver
from exploitutils import *
import time
import os
import socket
from Nodes.powershelllistener import powershelllistener
import logging

class psshellserver(powershelllistener):
     """
     PowerShell Shell Server
     """

     def __init__(self,connection,node,shell_id,logfunction=None):
          self.arch       = "PowerShell"
          self.order      = intel_order
          self.unorder    = istr2int
          self.connection = connection
          self.node       = node
          self.node.shell = self
          self.shell_id   = shell_id
          self.started    = 0
          self.logfunction= logfunction
          self.engine     = node.engine
          # If shell_id is None we must take it from callback and also the mosdef_type
          # because in this case we are skipping the universal_mosdef_loader 
          # from canvasengine.
          if not self.shell_id: 
                if not self.correctType():
                   raise Exception('Something went wrong with the listener type')
          return

     def startup(self):
          """
          Start this process...
          """
          if self.started:
               return

          logging.info("Startup PowerShell Shell Server...")
          self.started=1
          powershelllistener.__init__(self,self.connection,logfunction=self.logfunction)
          powershelllistener.startup(self)
          logging.info("Set up shell listener")
          #ok, now our mainloop code is running over on the other side
          logging.info("Set up PowerShell shell server")
          #self.sendrequest(mainloop)
          self.node.getInfo()
          return 1

     def close(self):
          if self.connection != None:
               self.connection.close()
               self.connection = None
     
     def correctType(self):
          # Check mosdef type
          # Don't need this if 
          # we use Universal Listener
          try:
                data = ""
                while len(data)!=4:
                      data += self.connection.recv(1)
          except:
                #catching timeouts and socket.error here
                logging.error("Failed to get any data when reading listener_type for powershell mosdef listener")
                return False

          if len(data) != 4:
                logging.error("Failed to get enough data when reading listener_type for powershell mosdef listener")
                return False
          
          listener_type = str2int32(data)
          if listener_type != 23:
                logging.error("Failed because this is a different mosdef listener type")
                return False

          #ok, now get ID number
          try:
                data = ""
                while len(data)!=4:
                      data += self.connection.recv(1)
          except:
                logging.error("Failed to get any data when reading ID for powershell mosdef listener")
                return False

          if len(data) != 4:
                logging.error("Failed to get enough data when reading ID for powershell mosdef listener")
                return False

          shell_id = str2int32(data)
          logging.info("Found mosdeftype: %s, ID: %x"%(listener_type, shell_id))
          return True
