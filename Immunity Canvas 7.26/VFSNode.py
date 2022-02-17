#! /usr/bin/env python
"""
VFSNode.py

Longer term this node will do things like offer endpoints (ftp, smb, etc)
that you can use to browse this locally, caching data where possible so as
not to hit the network

"""

from CANVASNode import CANVASNode
from exploitutils import *

class VFSNode(CANVASNode):
    def __init__(self):
        CANVASNode.__init__(self)
        self.nodetype="VFSNode"
        self.pix=""
        self.activate_text()
        #self.findInterfaces()
        #self.findLocalHosts()
        self.capabilities=["VFS", "upload", "download"]
    
    def dir(self, directory="."):
        return self.shell.dodir(directory)

    def cd(self, directory):
        return self.shell.chdir(directory)
    
    def getcwd(self):
        return self.shell.getcwd()
    
    def mkdir(self, directory):
        return self.shell.mkdir(directory)
    
    
if __name__=="__main__":
    node=VFSNode()

