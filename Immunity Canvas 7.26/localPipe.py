#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
Classes for doing named pipe access locally
"""

import sys
from internal import *

#this is here for local named pipe access on win32. Mostly
#for testing exploits locally, since you'll not be doing this remotely
try:
    from win32file import *
    from win32pipe import *
except:
    pass

from exploitutils import *

class localPipe:
    """
    Uses a pipe locally
    """
    def __init__(self,pipename):

        fd=CreateFile(pipename,GENERIC_READ | GENERIC_WRITE,
                      0, None, OPEN_EXISTING,
                      FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED, 0)
                
        self.fd=fd
        self.name=pipename
        self.buf=""
        self.Transact=self.write
        
    def write(self,data):
        print "Writing to named pipe...%s"%hexprint(data)
        ret=WriteFile(self.fd,data)
        #add transactnamedpipe here...
        #ret=CallNamedPipe(self.name,data,40000,0)
        #self.buf=ret
        if ret not in ["",-1]:
            #0 on success?
            return 0
        return -1
        
    def read(self,size):
        if self.buf:
            ret=self.buf[:size]
            self.buf=self.buf[size:]
            return ret
            
        import time
        #size=20000
        #time.sleep(0.1)
        (ret,data)=ReadFile(self.fd,size)
        if not ret:
            print "Read from named pipe: %s %s"%(ret,prettyprint(data))
            return str(data)
        return ""
        

import win32MosdefShellServer as wm

class MOSDEFPipe:
    "used for win32 nodes"
    def __init__(self,shell):
        self.pipename=""
        self.shell=shell
        self.fd=-1
        self.buf=""
        self.wait=1
        return
    
    def open(self,pipename):
        self.pipename=pipename
        self.fd=self.shell.CreateFile(pipename,wm.GENERIC_READ | wm.GENERIC_WRITE,
                                      0, None, wm.OPEN_EXISTING,
                                      wm.FILE_ATTRIBUTE_NORMAL)
        if self.fd!=-1:
            ret=self.shell.SetNamedPipeHandleState(self.fd,wm.PIPE_READMODE_MESSAGE,None,None)
        
        devlog("pipe fd=0x%x"%self.fd)
        return self.fd!=-1
        
        
    def set_wait(self,wait):
        self.wait=wait
        if not wait:
            devlog("Setting pipe %x to no-wait"%self.fd)
            ret=self.shell.SetNamedPipeHandleState(self.fd,wm.PIPE_READMODE_BYTE | wm.PIPE_NOWAIT,None,None)
        else:
            devlog("Setting pipe %x to wait"%self.fd)
            ret=self.shell.SetNamedPipeHandleState(self.fd,wm.PIPE_READMODE_MESSAGE,None,None)
        return ret
    
       
    def Transact(self,inbuf):
        "success is non-zero"
        if not self.wait:
            devlog("using writefile")
            sys.stdout.flush()
            ret=self.shell.writetofd(self.fd,inbuf)
        else:
            devlog("Using transactnamedpipe")
            sys.stdout.flush()
            ret=0
            if self.fd!=-1:
                (ret,outbuf)=self.shell.TransactNamedPipe(self.fd, inbuf)
            if ret:
                devlog("Received %d bytes into outbuf"%len(outbuf))
                #print "Buf: \n%s"%prettyhexprint(outbuf)
                self.buf+=outbuf
            else:
                devlog("TransactNamedPipe failed.")
        sys.stdout.flush()
        return ret    

    def read(self,size):
        if self.fd==-1:
            print "Warning: localPipe:read(-1)"
            return ""
        if self.buf:
            devlog("Returning %d bytes from cache of length %d"%(size,len(self.buf)))
            ret=self.buf[:size]
            self.buf=self.buf[size:]
            return ret

        (ret,data)=self.shell.ReadFile(self.fd,size)
        
        #0 on success, I see
        if not ret:
            data=str(data)
            print "Read from named pipe: %s \n%s"%(ret,prettyhexprint(data))
            return data
        return ""
        
    def write(self,data):
        if self.fd==-1:
            devlog("Not writing to non-open named pipe!")
            return -1
        devlog("Writing to named pipe %d wait=%d... \n%s"%(self.fd,self.wait,prettyhexprint(data)))
        ret=self.Transact(data)
        devlog("Named pipe %d returned %s"%(self.fd,ret))
        return ret
        #ret=self.shell.WriteFile(self.fd,data)
        #add transactnamedpipe here...
        #ret=self.shell.CallNamedPipe(self.name,data,40000,0)
        #self.buf=ret
        if ret not in ["",-1]:
            #0 on success?
            return 0
        return -1
        
    def close(self):
        if self.fd!=-1:
            self.shell.close(self.fd)
        return
    
