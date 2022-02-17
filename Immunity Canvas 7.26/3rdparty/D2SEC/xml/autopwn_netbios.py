#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import autopwn

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Microsoft Windows RPC Locator': ['Microsoft Windows RPC Locator locator.exe Stack Overflow', 'ms03_001'],
    'Microsoft Windows Workstation Service RPC': ['Microsoft Windows Workstation Service RPC Stack Overflow', 'ms03_049'],
    'Microsoft Windows LsaSs RPC': ['Microsoft Windows LsaSs RPC lsasrv.dll Stack Overflow', 'ms04_011_lsass'],
    'Microsoft Windows NetDDE RPC': ['Microsoft Windows NetDDE RPC netdde.exe Stack Overflow', 'ms04_031'],
    'Microsoft Windows PnP RPC': ['Microsoft Windows PnP umpnpmgr.dll RPC Stack Overflow', 'ms05_039'],
  }

  def exploit(self, target, port):
    self.list_exploits()
