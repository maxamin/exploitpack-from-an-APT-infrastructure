#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import autopwn
import appli.coldfusion
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Coldfusion': ['ColdFusion Directory Traversal Vulnerability', 'CF_directory_traversal'],
  }

  def exploit(self, target, port):
    result = ''
    discovery = [
      appli.coldfusion.solr_service_info,
    ]
    self.log.info('Coldfusion server scan %s:%s' % (target, port))
    try:
      for fct in discovery:
        infos = fct(target, port)
        if infos:
          for info in infos:
            result += '%s' % info
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.db.db_unique_info(self.victim, self.service, 'Coldfusion Server Scanner', 'autopwn_coldfusion', result)
    self.log.debug('%s' % result)
    self.list_exploits()
