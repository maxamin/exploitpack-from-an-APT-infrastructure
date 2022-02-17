#! /usr/bin/env python

"""
CANVAS win32 shell server
Uses MOSDEF for dynmanic assembly component linking

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

#or whatever you've used as your trojan filename locally
#This file needs to exist in CWD locally
from sqllistener import mysqllistener
from sqllistener import mssqllistener

from libs import mysqllib as mysqllib
from libs import mssql    as mssql

class mysqlshellserver( mysqllistener): 
     """
     SQL Shell Listener
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

     def startup(self):
          """
          """
          if self.started:
               return
          #self.log("Startup...")

          mysqllistener.__init__(self,self.connection,logfunction=self.logfunction)
          print self.node.shell
          print "Set up shell listener"
          #ok, now our mainloop code is running over on the other side
          self.log("Set up MySQL shell server")
          #self.sendrequest(mainloop)
          self.started=1
          return 1

class mssqlshellserver( mssqllistener): 
     """
     SQL Shell Listener
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

     def sql_command( self, sql_statement ):

          try:
               resp = self.m.query( sql_statement )

               if not resp:
                    #returns an empty string on failure
                    #typically, recv failed
                    return "Failed to get SQL Command Executed"

               for a in resp.tokens:
                    if a[0] == 0xd1:
                         result+= str(a[1]) + "\n"
                    elif a[0] == 0xAA or a[0] == 0xAB:
                         result=a[1][3]
                    elif a[0] == 0x81: #TDS 7+ results
                              #tds results...
                         print "Token type 0x81"
                         result=a[1][-1]
                    else:
                         devlog("mssql", "Token type not needed %x"%a[0])

          except mssql.MSSQLError, msg:
               result=str(msg) 

          return result


     def startup(self):
          """
          """
          if self.started:
               return
          #self.log("Startup...")

          mssqllistener.__init__(self,self.connection,logfunction=self.logfunction)
          #print self.node.shell
          print "Set up shell listener"
          #ok, now our mainloop code is running over on the other side
          self.log("Set up MSSQL shell server")
          #self.sendrequest(mainloop)
          self.started=1
          self.node.capabilities += ["mssql"]
          return 1

     def dir(self, directory):
          self.shell.dodir(directory)


