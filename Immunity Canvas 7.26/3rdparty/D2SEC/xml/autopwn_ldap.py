#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import autopwn

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'PADL nss_ldap': ['PADL nss_ldap Local Information Disclosure Vulnerability', 'd2sec_nssldap'],
    'IBM Z/OS LDAP server': ['[0 Day] IBM Z/OS Version 1 Release 4 LDAP Server DoS', 'd2sec_zosldap'],
  }

  def exploit(self, target, port):
    self.list_exploits()
