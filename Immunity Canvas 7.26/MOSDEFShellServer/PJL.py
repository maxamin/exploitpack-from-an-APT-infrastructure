"""
PJL Shell Server
"""

import sys

if '.' not in sys.path:
    sys.path.append('.')
from libs import pjllib
from MOSDEFShellServer import MSSgeneric

class PJL(MSSgeneric):
    def __init__(self,
                 device,
                 node,
                 logfunction = None):
        MSSgeneric.__init__(self,"HP")
        
        self.node                   = node
        if self.node:
            self.node.shell         = self
        self.device                 = device
        
        self.startup_inited         = False
        self.startup_finish         = False
        self.started                = False
        self.log                    = logfunction
        
        self.doxor                = False

        self.currentprocess=None
        self.cached_comspec=""

        return

    def startup(self):
        self.log('PJL ShellServer ... booting')

        if self.startup_inited == True:
            while self.startup_finish == False:
                self.log('Waiting for startup to finish ...')
                time.sleep(1)
            return True

        if hasattr(self.device, 'set_timeout') == True:
            self.device.set_timeout(120)

        self.startup_inited = True
        # do startup here

        # done
        self.startup_finish = True
        self.started        = True

        self.log('PJL ShellServer ... Started')
        return True

    def dodir(self, path):
        out = []
        if (path == "/"):
            
            # Get Unit names
            f = pjllib.PJLInfoFILESYSCommand()
            f.issue(self.device)
            units = f.getUnitNames()

            for unit in units:
                out.append(unit)
        else:
            dir = pjllib.PJLFSDIRLISTCommand(path.lstrip("/"))
            dir.issue(self.device)

            dirs  = dir.getDirs()
            files = dir.getFiles()

            for dir in dirs:
               out.append( (dir, 0, 0, {"is_dir":True, "is_exe": False }) )

            for file in files: 
               out.append( (file, 0, 0, {"is_dir":False, "is_exe": False }) )

        return out

