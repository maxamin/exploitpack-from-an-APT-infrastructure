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

  def exploit(self, target, port):
    try:
      http = proto.http.apihttp(target, port)
      http.setparam('Host', 'http://google.com')
      http.setparam('User-Agent', 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.14) Firefox/3.0.14')
      http.setparam("Accept", "text/html")
      http.cnx = http.connect()
      data = http.request('GET', '/').read()
      http.cnx.close()
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    reg = re.findall("<title>(.*)</title>", data)
    if len(reg) > 0:
      title = reg[0]
      # UTF-8 Title ?
      reg = re.findall("([^\x00-\x7f]+)", title)
      if reg:
        title = ''.join(map(lambda c: '\\%s' % hex(ord(c))[2:].zfill(2), title))
      res = "Title: %s\n" % title
      info = self.db.db_unique_info(self.victim, self.service, 'SQUID', 'autopwn_squid', 'Proxy UP (get http://google.com):\n%s' % res)
