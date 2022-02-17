#! /usr/bin/env python
"""
win32Node.py

CANVAS License

A win32 MOSDEF node.

"""

from exploitutils import *
import socket, struct
from MOSDEFNode import MOSDEFNode
from MOSDEFSock import MOSDEFSock
import time

class win32Node(MOSDEFNode):
    def __init__(self):
        MOSDEFNode.__init__(self)
        self.nodetype="win32Node"
        self.pix="Win32MOSDEFNode"
        self.activate_text()
        self.shell=None
        self.capabilities+=["VFS","win32api","sock","Win32 Shell", "upload", "download"]
        self.colour="blue"
        return

    def decode(self,data):
        #print "win32Node decode called"
        return self.shell.decode(data)

    def update_pix(self):

        if self.busy:
            self.pix="Win32MOSDEFNodeBUSY"
        else:
            self.pix="Win32MOSDEFNode"
        #print "Updated picture to %s"%self.pix
            
    def findInterfaces(self):
        """
        Most nodes need to be able to find all the active interfaces
        on their host. (UnixShellNode cannot, for example. SQL nodes cannot...)
                                                                                    
        The Linux Node uses ioctl to do this - it can't be blocked by
        chroot, etc.
        """
        #print "YO! ADDING INTERFACES!!!!"
        self.log("Calling findInterfaces")

        vars = {}        
        code = """
        #import "remote","iphlpapi.dll|GetIpAddrTable" as "GetIpAddrTable"
        #import "remote","kernel32.dll|VirtualAlloc" as "VirtualAlloc"
        #import "remote","kernel32.dll|VirtualFree" as "VirtualFree"
        #import "local","sendint" as "sendint"
        #import "local","memset" as "memset"
        void main() {
            unsigned int d;
            unsigned int i;
            unsigned int ptr;
            unsigned int *buf;

            ptr = 0;
            // initial call to get the number of bytes required for ip table
            i = GetIpAddrTable(0x0, &ptr, 0); 
            buf = VirtualAlloc(NULL, ptr, 0x1000, 0x4);
            memset(buf, 0, ptr);
            
            i = GetIpAddrTable(buf, &ptr, 0);
            
            sendint(buf[0]); // sending dEntry (amount of entries)
            
            ptr = 1;
            i = 0;
            while(i < buf[0]) {              
                sendint(buf[ptr+1]);
                sendint(buf[ptr]);
                sendint(buf[ptr+2]);
                ptr = ptr + 6;
                i = i+1;
            }
            VirtualFree(buf, ptr, 0x4000);
        }
        """

        self.shell.clearfunctioncache()
        message=self.shell.compile(code,vars)
        self.shell.sendrequest(message)
        #dentry=self.shell.readbuf(80)
        #print hexdump(dentry)
        entries= self.shell.readint()
        if entries> 30:
            self.log("You can't have %d interfaces. We don't believe you.")
            self.log("This means data corruption in the MOSDEF stream - so we should bail")
            self.shell.leave()
            return []
        
        interfaces=[]
        """
        NOTE:
        -----
        remote returns in HOST order, so HOST=LE
        we need to call HOSTFUNCTIONS.htonl() to have a NETWORK (portable) order
        socket.* functions are in NETWORK order
        win32 returns "<LL>L" = (BE,LE,LE)
        """
        for a in range(0, entries):
            size = struct.calcsize("<L4sL")
            hostbuf = ''
            while len(hostbuf) < size:
                hostbuf += self.shell.readbuf(4)
            #print hexdump(hostbuf)
            ndx, addrbuf, mask = struct.unpack("<L4sL", hostbuf)
            addr = socket.inet_ntoa(addrbuf)
            mask = byteswap_32(mask)
            interfaces.append("#%d" % ndx)
            self.interfaces.add_ip( ("#%d" % ndx, addr, mask) )
            #print "Adding Interface: %s" % addr
        #dentry=self.shell.readbuf(64)
        #print hexdump(dentry)
        self.shell.leave()
        #print "End of getting interfaces on remote host"
        #we do this so we can show our IP in our display nicely
        self.activate_text()
        self.update_gui()
        self.update_pix()
        return interfaces

    def createListener(self,addr,port):
        """Create a listener for a connectback"""
        fd=self.shell.getListenSock(addr,port)
        if fd<0:
            return 0
        print "Created a listener socket: %d"%fd
        s=MOSDEFSock(fd,self.shell) #a mosdef object for that fd (wraps send, recv, etc) and implements timeouts
        s.set_blocking(0) #set non-blocking
        s.reuse()
        return s

    def conv_time(self, l,h):
        #converts 64-bit integer specifying the number of 100-nanosecond
        #intervals which have passed since January 1, 1601.
        #This 64-bit value is split into the
        #two 32 bits  stored in the structure.
        d=116444736000000000L #difference between 1601 and 1970
        #we divide by 10million to convert to seconds
        return (((long(h)<< 32) + long(l))-d)/10000000    
    

    def dir(self, directory):
        FILE_ATTRIBUTE_DIRECTORY  = 0x10
        result="\n Directory of %s\n\n" % directory
        (cfile, files)=self.shell.dodir(directory)

        # files format:
        #   0: attr
        #   1: size
        #   2: creattime
        #   3: File
        
        if cfile == -1:
            #return files # Error
            return "Error %x: when trying to open directory %s"%(files[0], files[1])
            ##New way that we return errors from dodir to allow recursive dir walks
        
        tsize = 0
        cdir  = 0
        for a in range(0, cfile):
            creattime = time.ctime(self.conv_time(files[a][2]['dwLowDateTime'], files[a][2]['dwHighDateTime']))
            if files[a][0] & FILE_ATTRIBUTE_DIRECTORY:
                dir= "%-16s" % "<DIR>"
                cdir+=1
            else:
                dir= "%16s" %  str(files[a][1])
                tsize+=files[a][1]
            result+= "%20s  %s  %-30s\n" % (creattime, dir,  files[a][3])
        result+="\n%5d File<s>    %d bytes\n%5d Dir<s>\n" % (cfile-cdir, tsize, cdir)
        return result
        
    # VFS Routines
    def vfs_dir(self, path):
        FILE_ATTRIBUTE_DIRECTORY  = 0x10
        # for testing until we do getdents logic
        if path in ["/", "\\"]:
            out = []
            drives=self.shell.GetDrives()
            for drive in drives:
                drivename=drive[0]
                drivetype=drive[1]
                #name, st_size, st_mtime, is_dir
                out.append((drivename, 0, 0, {"is_dir": True , "is_exe": False }))
            return out 
        else:
            #cut the / off the front
            path = path[1:]
            
        (cfile, files) = self.shell.dodir( path )
        out = []
        
        for a in range(0, cfile):
            if files[a][3] not in (".", ".."):
                isdir = bool(files[a][0] &FILE_ATTRIBUTE_DIRECTORY)
                isexe = False
                if len(files[a][3]) > 4:
                    isexe = files[a][3][-4:].lower() == ".exe"
                # name, st_size, st_mtime, is_dir = stat_result
                out.append( ( files[a][3], files[a][1],\
                              self.conv_time(files[a][2]['dwLowDateTime'], files[a][2]['dwHighDateTime']),  {"is_dir":isdir, "is_exe": isexe }) )
        return out
    
    def vfs_upload(self, path, dest):
        if not dest:
            devlog("win32", "Path passed to vfs_upload was blank!")
            return "Path was blank?"

        dest=unicode(dest)
        if dest[0] in [ u"/", u"\\"]:
            dest=dest[1:]
            
        ret = self.shell.upload( path, dest )
        return ret
    
    def vfs_download(self, path, dest):
        """
        Download a file - sets a default path if None is Dest
        """
        if dest==None:
            dest=self.engine.create_new_session_output_dir(self.get_interesting_interface(), "downloaded_files")
            
        path=unicode(path)
        if path[0] in [u"/", u"\\"]:
            path=path[1:] #strip off leading slash

        if not path:
            devlog("win32", "Path passed to vfs_download was blank!")
            return "Path was blank?"
        
        devlog("vfs", "Downloading %s to %s"%(path, dest))
        ret = self.shell.download( path, dest )
        devlog("vfs", "Finished Downloading %s to %s"%(path, dest))
        return ret    
    
    def vfs_stat(self, path):
        """
        Get the size and whether it's a directory or not from a path
        """
        devlog("vfs", "vfs_stat(%s)"%path)
        
        if type(path)!=type(u""):
            try:
                path=unicode(path)
            except:
                devlog("win32", "Could not unicode %r!"%path)

        if not len(path):
            #path is empty?!
            devlog("win32", "Error: Path sent to vfs_stat() was empty!!!")
            retstat    = (0, 0, {"is_dir":False} )
            return retstat #failed!
        
        FILE_ATTRIBUTE_DIRECTORY  = 0x10
        if path in ["/","\\"] :
            devlog("win32", "Root path found for vfs_stat()")
            return (0, 0, {"is_dir":True})
        
        if path[0] in ["/", "\\"]:
            #clean off the first / since it is not needed
            path=path[1:] 
            
        if path and path[-1]==u"\\" and len(path)==3:
            devlog("win32", "vfs_stat() of a root drive - returning that it is a directory")
            #we are looking at c:\ or similar
            #alternatively GetVolumePathName() can be used for this:
            #http://msdn.microsoft.com/en-us/library/aa364996(VS.85).aspx
            #that solution would slow things down a lot though (although it is more "technically correct")
            #force it to be a "directory" since it's a root drive name
            return (0, 0, {"is_dir": True})
       
            
        statbuf = self.shell.dostat(path)
        if statbuf[0] == -1:
            # failed
            devlog("win32", "Stat failed on %s"%path)
            retstat    = (0, 0, {"is_dir":False} )
        else:
            creattime = self.conv_time(statbuf[2]['dwLowDateTime'], statbuf[2]['dwHighDateTime'])
            isdir = bool(statbuf[0] & FILE_ATTRIBUTE_DIRECTORY)
            isexe = False
            if len(path) > 4:
                isexe = path[-4:].lower() == ".exe"
            #                attr       creattime  isdir?
            retstat        = ( statbuf[0], creattime, {"is_dir": isdir, "is_exe": isexe} )
            
        return retstat
    
    
        

class win32ShellInterfaceResolver(object):
    def __init__(self, node):
        self.node = node
        
    def findInterfaces(self):        
        data = self.node.shell.runcommand("route print")
        if len(data):            
            interfaces = parserouteprint(data)
            for x in interfaces:
                self.node.interfaces.add_ip(x)
            
        else:
            return []
                         
                
        
if __name__=="__main__":
    node=win32Node()

