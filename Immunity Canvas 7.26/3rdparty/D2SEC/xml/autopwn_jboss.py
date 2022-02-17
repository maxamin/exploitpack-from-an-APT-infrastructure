#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.jboss
import xmlrpclib

class run(autopwn.run):

  def exploit(self, target, port):
    result = ''
    discovery = [
      appli.jboss.server_info,
      appli.jboss.jmx_console,
      appli.jboss.web_invoker,
      appli.jboss.vulnerabilities,
    ]
    self.result = ''
    self.log.info('Jboss server scan %s:%s' % (target, port))
    try:
      for fct in discovery:
        infos = fct(target, port)
        if infos:
          for info in infos:
            result += '%s' % info
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.db.db_unique_info(self.victim, self.service, 'JBoss Server Scanner', 'autopwn_jboss', result)
    self.log.debug('%s' % result)
