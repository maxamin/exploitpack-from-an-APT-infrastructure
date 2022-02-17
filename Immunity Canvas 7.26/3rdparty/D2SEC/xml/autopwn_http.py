#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import re
import autopwn
import proto.http
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
  }

  def http_headers(self, target, port):
    try:
      http = proto.http.apihttp(target, port)
      self.log.info('List headers')
      if port == 443:
        http.use_https(1)
      http.cnx = http.connect()
      resp = http.request('GET', '/')
      nfo = http.get_info_header(resp)
      http.cnx.close()
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    headers = ''
    for h,v in nfo.items():
      #if 'Server' in h:
      #  continue
      self.log.debug('%s: %s' % (h, v))
      headers += '%s: %s\n' % (h, v)
    self.db.db_unique_info(self.victim, self.service, 'HTTP Headers', 'autopwn_http', headers)

  def path_disclosure(self, target, port):
    self.log.info('Test path disclosure')
    http = proto.http.apihttp(target, port)
    http.setparam('Accept', 'text/html')
    http.setparam('Cookie', 'PHPSESSID=123@@123')
    try:
      http.cnx = http.connect()
      resp = http.request('GET', '/')
      body = resp.read()
      http.cnx.close()
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    path = re.findall('<b>Warning</b>:  session_start\(\)(.*)<b>(.*)</b> on line', body)
    if len(path) > 0:
      self.log.debug('Path disclosure: %s ' % path[0][1])
      self.db.db_unique_vuln(host=self.victim, service=service, title='Path disclosure', module='autopwn_http', vuln_desc=path[0][1])
    else:
      self.log.debug('Not path disclosure')

  def exploit(self, target, port):
    # Headers
    self.http_headers(target, port)
    if port != 80:
      return
    self.log.info('Fingerprint http server')
    server = proto.http.fingerprint(target, port)
    self.log.debug('Version: %s' % server)
    if server != 'Unknown':
      self.db.db_unique_info(self.victim, self.service, 'HTTP Fingerprint', 'autopwn_http', server) 
    # Test path disclosure
    self.pathdisclosure(target, port)
    # TODO : Create urls listing
    # TODO : URL Bruteforce

