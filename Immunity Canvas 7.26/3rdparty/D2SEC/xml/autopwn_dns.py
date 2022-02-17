#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import proto.dns2
import xmlrpclib

class run(autopwn.run):

  def exploit(self, target, port):
    try:
      nfo = proto.dns2.checkopen(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if nfo == 2:
      self.log.error('DNS %s timeout.' % self.target)
    elif nfo == True:
      bla = 'Open DNS server - Public configuration, no domain restrictions'
      self.log.info("%s" % bla)
      self.db.db_unique_info(self.victim, self.service, 'DNS', 'autopwn_dns', bla)
