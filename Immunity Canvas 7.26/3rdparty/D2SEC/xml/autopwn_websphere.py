#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.websphere
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
  }

  def exploit(self, target, port):
    result = ''
    discovery = [
      appli.websphere.ibm_console,
      appli.websphere.snoop,
    ]
    self.log.info('Websphere server scan %s:%s' % (target, port))
    try:
      for fct in discovery:
        infos = fct(target, port)
        if infos:
          for info in infos:
            result += '%s' % info
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.db.db_unique_info(self.victim, self.service, 'Websphere Server Scanner', 'autopwn_websphere', result)
    self.log.debug('%s' % result)
