#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.mssql
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'MSSQL (Null) Auth Connect': ['Authentication without a pass', 'mssql_auth'],
    'MS SQL Resolver Stack Overflow': ['MSSQL Resolver Stack Overflow (MS02-056)', 'mssqlresolvestack'],
  }

  def exploit(self, target, port):
    try:
      output = appli.mssql.ping(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if output <> None:
      info   = "ServerName   \t: %s\nInstanceName  \t: %s\nIsClustered    \t: %s\nVersion         \t: %s"%(output["ServerName"],
        output["InstanceName"],
        output["IsClustered"],
        output["Version"])
      self.db.db_unique_vuln(self.victim, self.service, 'MSSQL', 'autopwn_mssql', info)
      info = info.split('\n')
      for i in info:
        self.log.debug('%s' % i)
    self.list_exploits()
