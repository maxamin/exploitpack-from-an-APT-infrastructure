#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.webdav
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
  }

  def exploit(self, target, port):
    result = ''
    try:
      self.log.info('Webdav discovery')
      result = appli.webdav.discovery(target, port)
      if result:
        nfo = 'Webdav enabled - Type: %s' % result
        self.log.debug(nfo)
        self.db.db_unique_info(self.victim, self.service, 'Webdav discovery', 'autopwn_webdav', nfo)
      else:
        self.log.debug('Webdav not enabled')
        return
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return

    propfind = []
    try:
      self.log.info('Webdav PROPFIND Method')
      propfind = appli.webdav.propfind_content(target, port)
      if propfind[0] == 401:
        self.log.debug('Authentication required')
        return
      else:
        if propfind:
          self.log.debug(propfind[2])
          self.db.db_unique_info(self.victim, self.service, 'Webdav PROPFIND Method', 'autopwn_webdav', propfind[2])
        else:
          self.log.error('PROPFIND Method forbidden ?')
          return 
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return

    self.log.info('Website content via Webdav')
    data = ''
    nfo = appli.webdav.propfind_parse_href(propfind[2])
    for url in nfo:
      data += 'http://%s:%d%s\n' % (target, port, url)
    if data:
      self.db.db_unique_vuln(self.victim, self.service, 'Website content via Webdav', 'autopwn_webdav', data)
      data = data.split('\n')
      for d in data: 
        if d: self.log.debug(d) 
    
    
