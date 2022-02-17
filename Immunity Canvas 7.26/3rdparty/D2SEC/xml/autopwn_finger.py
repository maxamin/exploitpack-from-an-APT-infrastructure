#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import proto.finger
import xmlrpclib

class run(autopwn.run):

  def exploit(self, target, port):
    try:
      finger = proto.finger.getinfo(target)
      self.log.info('Information leaking through FINGER')
      self.log.debug('%s' % finger)
      self.db.db_unique_vuln(self.victim, self.service, 'FINGER', 'autopwn_finger', finger)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
