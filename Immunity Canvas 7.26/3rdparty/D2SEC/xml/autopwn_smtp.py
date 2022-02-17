#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import net.banner
import proto.smtp
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'IMail': ['IMail SMTPD32 Stack Overflow', 'imail_rcptoverflow'],
    'MailEnable Service, Version: 0-1.54-': ['MailEnable SMTP Stack Overflow', 'mailenable'],
  }

  def exploit(self, target, port):
    banner = ''
    try:
      banner = net.banner.bannergrab(target, port)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if banner:
      self.db.db_unique_info(self.victim, self.service, 'SMTP Banner', 'autopwn_smtp', banner)
      self.log.debug('%s' % banner)
    self.log.info('Check if SMTP server is open')
    try:
      result = proto.smtp.testrelay(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.db.db_unique_vuln(self.victim, self.service, 'SMTP Relay', 'autopwn_smtp', result)
    result = result.split('\n')
    for r in result:
      self.log.debug('%s' % r)
    # TODO : fingerprint
    self.check_exploits(banner)
