#! /usr/bin/env python
# PCL library

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

#if "." not in sys.path: sys.path.append(".")
#import struct, socket, encodings
#import exploitutils
#from exploitutils import prettyprint
#from exploitutils import prettyhexprint
#
#from internal import devlog

import re
import sys
import socket
from internal import devlog

class PJLCommand:

    PJL_START   = "\033%-12345X"
    PJL_FINISH  = "\033%-12345X\r\n"

    buffer = ""

    def __init__(self):
        self.buffer = self.PJL_START

    def issue(self, device):
        device.send(self.getRaw())
        ret = self.readResponse(device)
        device.send(self.PJL_FINISH)
        return ret

    def getRaw(self):
        return self.buffer# + self.PJL_FINISH

    def readResponse(self, device):
        return device.recv()


class PJLInfoIDCommand(PJLCommand):

    def __init__(self):
        PJLCommand.__init__(self)

    def getRaw(self):
        return self.buffer + "@PJL INFO ID" + "\r\n"

    def readResponse(self, device):
        buf = device.recv()
        match = re.search("@PJL.*\r\n\"(.*)\"\r\n", buf)
        return match.group(1)



class PJLInfoFILESYSCommand(PJLCommand):

    def __init__(self):
        PJLCommand.__init__(self)
        self.unitNames = []
       
    def getRaw(self):
        return self.buffer + "@PJL INFO FILESYS" + "\r\n"

    def readResponse(self, device):
        buf = device.recv()

        # Parse response
        match = re.search("@PJL INFO FILESYS \[(.) TABLE\]\r\n.*", buf)
        n = int(match.group(1)) -1

        match = re.search("@PJL.*\r\n.*\r\n" + "(.*)\r\n" * n, buf)
       
        for i in range(1,n+1):
            self.parseLine(match.group(i))

        return buf

    def parseLine(self, line):
        # TODO: parse more info from units
        #re.search(" *(..) *([^ ]*) *([^ ]*) *([^ ]*) *([^ ]*).*", line)
        match = re.search(" *(..).*", line)
        self.unitNames.append(match.group(1))

    def getUnitNames(self):
        return self.unitNames


class PJLFSDIRLISTCommand(PJLCommand):

    def __init__(self, path):
        PJLCommand.__init__(self)
        self.path = path
        self.files = []
        self.dirs = []
 
    def getRaw(self):
        return self.buffer + "@PJL FSDIRLIST NAME = \"" + self.path + "\" ENTRY=1 COUNT=1000" + "\r\n"

    def readResponse(self, device):
        buf = device.recv()
        if not buf:
            return 0
        lines =  buf.split("\r\n");
        for line in lines:
            match = re.search("(.*) *TYPE=(.*)", line)
            if match != None:
                name = match.group(1).strip()
                type =  match.group(2).strip()
                if type == "DIR":
                    if (name != "." and name != ".."):
                        self.dirs.append(name)
                else :
                    self.files.append(name)

        return len(self.dirs) + len(self.files)

    def getDirs(self):
        return self.dirs

    def getFiles(self):
        return self.files


class PJLDevice:
    """Class to connect and send commands to PCL enabled devices"""

    PJL_ENDSEQUENCE =   "\x0c"
    #PJL_ENDSEQUENCE =   "\r\n\x0c"

    def __init__(self, port=9100, exploit=None):
        self.port = port 
        self.hostname = ""
        self.exploit=exploit

    def connect(self):
        if self.exploit:
            self.s=self.exploit.gettcpsock()
        else:
            self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            self.s.connect( (self.hostname, self.port) )

        except:
            devlog("PJLDevice","Connect Error")
            return None

        return 1
        

    def send(self, buffer):
        self.s.send(buffer)

    def recv(self):
        buf = ""
        data = ""

        try:
            while data != self.PJL_ENDSEQUENCE:
                data  = self.s.recv(1)
                buf += data
        except:
            print "recv failed"
            return None
        
        return buf

    
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "usage: %s host" % sys.argv[0]
        sys.exit(0)


    p = PJLDevice()
    p.hostname  = sys.argv[1]
    p.connect()

    #print "Model: ", PJLInfoIDCommand().issue(p)

    #f = PJLInfoFILESYSCommand()
    #f.issue(p)
    #print "Units: ", f.getUnitNames()



    dir = PJLFSDIRLISTCommand("0:")
    print dir.issue(p)

    print "Dirs :", dir.getDirs()
    print "Files:", dir.getFiles()

