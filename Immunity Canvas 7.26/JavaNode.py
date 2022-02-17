#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
JavaNode.py - used for remote connections from javaNode.jar
"""

from CANVASNode import CrossPlatformNode
from exploitutils import *
from canvaserror import *
from unixShellNode import unixShellInterfaceResolver

class JavaNode(CrossPlatformNode):
    def __init__(self):
        CrossPlatformNode.__init__(self)
        self.nodetype="JavaNode"
        self.pix="JavaNode"
        self.capabilities +=  ["upload","download"]
        self.activate_text() 
        self.colour="coffee"
    
