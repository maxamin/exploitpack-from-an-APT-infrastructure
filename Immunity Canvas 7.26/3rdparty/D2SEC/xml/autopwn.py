#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

class run:

  CANVAS_EXPLOITS = {}

  def __init__(self, log, db, victim, service):
    self.log = log
    self.db = db
    self.victim = victim
    self.service = service

  def check_exploits(self, banner):
    exp = []
    for ident, module in self.CANVAS_EXPLOITS.items():
      if ident in banner[0]:
        exp.append(module)
    if exp:
      for e in exp:
        data = ', '.join(e)
        self.db.db_unique_info(self.victim, self.service, 'Available Canvas exploits', '', data)
        self.log.info('%s' % data)
    else:
      self.log.info('Not available Canvas exploits')

  def list_exploits(self):
    data = ''
    self.log.info('Available Canvas exploits')
    for ident, module in self.CANVAS_EXPLOITS.items():
      data += ''.join('\t%s (module %s)\n' % (module[0], module[1]))
    self.log.debug('%s' % data)
    self.db.db_unique_info(self.victim, self.service, 'Available Canvas exploits', '', data)

  def bannergrab(self, proto):
    pass

  def exploit(self, target, port):
    pass
