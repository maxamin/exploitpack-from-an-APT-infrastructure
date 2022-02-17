#! /usr/bin/env python

""" 
PJL Node 

Used for owning printers.
"""

from CANVASNode import CANVASNode

class PJLNode(CANVASNode):

    def __init__(self):
        CANVASNode.__init__(self)
        self.nodetype     = "PJLNode"
        self.pix          = ""
        self.capabilities = ["VFS","upload","download"]
        self.activate_text()
        self.colour="yellow"
        
    ###### Node Messenging
    # A localnode uses standard "socket" objects.
    def send(self,sock,message):
        return

    def recv(self,sock,length):
        return


    def isactive(self, sock, timeout):
        return


  # VFS

    def vfs_upload(self, path, dest):
        #ret = self.shell.upload( path, dest )
        return ret

    def vfs_download(self, path, dest):
        #ret = self.shell.download( path, dest )
        return ret


    # VFS Routines
    def vfs_dir(self, path):


        #        out.append( ( files[a][3], files[a][1],\
        #                      self.conv_time(files[a][2]['dwLowDateTime'], files[a][2]['dwHighDateTime']),  {"is_dir":isdir, "is_exe": isexe }) )
        #print "XXXXXXXXX dir, path:", path
        return  self.shell.dodir( path )

    def vfs_stat(self, path):
        #if path == "/":
        #print "XXXXXXXXX stat"
        return (0, 0, {"is_dir":True})
        #statbuf = self.shell.dostat(path)
        #if statbuf[0] == -1:
        #    # failed
        #    retstat    = (0, 0, {"is_dir":False} )
        #else:
        #    creattime = self.conv_time(statbuf[2]['dwLowDateTime'], statbuf[2]['dwHighDateTime'])
        #    isdir = bool(statbuf[0] & FILE_ATTRIBUTE_DIRECTORY)
        #    isexe = False
        #    if len(path) > 4:
        #        isexe = path[-4:].lower() == ".exe"
        #    #                attr       creattime  isdir?
        #    retstat        = ( statbuf[0], creattime, {"is_dir": isdir, "is_exe": isexe} )



        #return retstat




if __name__=="__main__":
    node=PJLNode()

    
    
        
