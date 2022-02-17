#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2012
#

import autopwn
import appli.tomcat
import xmlrpclib

class run(autopwn.run):

  CANVAS_EXPLOITS = {
    'Apache Struts2 < 2.2.0': ['Apache Struts2 remote command execution vulnerability', 'd2sec_struts'],
    'Apache Struts2 < 2.3.1': ['Apache Struts2 remote command execution vulnerability', 'd2sec_struts2'],
    'Apache Struts2 < 2.3.1.1': ['Apache Struts2 remote command execution vulnerability', 'd2sec_struts3'],
  }

  def exploit(self, target, port):
    self.list_exploits()
