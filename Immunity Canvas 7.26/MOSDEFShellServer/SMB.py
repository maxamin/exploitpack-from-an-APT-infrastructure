#! /usr/bin/env python
#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
SMB.py

Shellserver functionality for SMB connections.
Also see SMBNode.py for VFS equivalent.

"""
from __future__ import with_statement

import os
import time
import traceback

from shellserver import shellserver
from libs.newsmb.libsmb import SMBClientException, assert_unicode

class SMBShellServer(shellserver):
    def __init__(self, mysmbobj, node, host, logfunction=None):
        shellserver.__init__(self, None, type ="Active", logfunction=logfunction)
        self.host       = host
        self.node       = node
        self.smbobj     = mysmbobj
        self.connection = self.smbobj.s # set this up for self.interact()

        # We have to keep track of this here as remote server keeps no state
        self.cwd        = u'\\'

        node.shell      = self
    
    def smb_nt_64bit_time(self, longtime):
        """
        This is some crappy code that doesn't quite work. To be totally correct
        I'd need to know the server's time zone, which I don't.
        
        This was some seriously painful stuff
        """
        secs = long(longtime)/10000000L
        secs = secs-11644473600L

        return time.ctime(secs)
    
    def startup(self):
        # Nothing to do here
        return True
    
    def pwd(self):
        """
        Get current working directory.
        """
        return self.cwd

    def getcwd(self):
        return self.pwd()

    
    def dounlink(self, filename):
        """
        Delete filename.
        """

        if not filename:
            self.log('No filename passed to unlink!')
            return
        
        if filename[0] != u'\\':
            filename = u'%s\\%s' % (self.cwd, filename)

        try:
            self.smbobj.delete(filename)
        except SMBClientException:
            # maybe it's a directory
            try:
                self.smbobj.delete_directory(filename)
            except SMBClientException:
                return 0
        return 1

    
    def cd(self, directory):
        """
        Change working directory.
        Changes directory on the remote system by checking
        to see that that directory exists and then modifying our
        local copy of the directory. The server itself does not
        save state as to our current directory. That's only stored
        here on the client.
        """

        if not directory:
            self.log('No directory to cd into')
            return
        
        directory = assert_unicode(directory)

        if directory == u'..':
            self.cwd = u'\\' + u'\\'.join(self.cwd.split(u'\\')[:-1])
        elif directory != u'.':
            try:
                if directory[0] != u'\\':
                    new_dir = (self.cwd + u'\\' + directory).replace(u'\\\\', u'\\')
                else:
                    new_dir = directory
                self.smbobj.check_directory(new_dir)
                self.cwd = new_dir
            except SMBClientException, ex:
                self.log("Error: %s" % ex)
                self.log("Didn't change directory")
                return 0
        return 1

    def chdir(self, directory):
        """
        Change working directory.
        """
        
        # exploits/chdir expects 0 for success
        return 0 if self.cd(directory) else 1

    def dodir(self, directory=u"."):
        """
        Get a directory listing.
        Currently time is incorrect (:<)
        """

        if not directory: directory = u'.'
        
        if directory == u'.':
            searchstring = (self.cwd + u'\\*').replace(u'\\\\', u'\\')
        else:
            if directory[0] != u'\\':
                searchstring = (self.cwd + u'\\' + directory + u'\\*').replace(u'\\\\', u'\\')
            else:
                searchstring = (directory + u'\\*').replace(u'\\\\', u'\\')
                
            searchstring.replace(u'**', u'*')
            
        results = self.smbobj.dir(filename=searchstring)
        ret = u""

        if results:
            import time
            for f in results:
                ret += u"%26s %8s %10s %20s\n" % (f["FileName"], f["ExtFileAttributes"],
                                                  f["EndOfFile"], # filesize
                                                  self.smb_nt_64bit_time(f["LastChangeTime"]))
        return ret

    def mkdir(self, directory):
        """
        Make directory
        """

        if not directory:
            self.log('No directory given to mkdir!')
            return
        
        directory = assert_unicode(directory)

        if directory[0] != u'\\':
            directory = (self.cwd + u'\\' + directory).replace(u'\\\\', u'\\')

        try:
            self.smbobj.mkdir(directory)
        except SMBClientException:
            return 0

        return 1

    
    def upload(self, source, dest=u".", destfilename=u""):
        """
        Upload a file to the remote SMB server
        """

        if not dest: dest = u'.'
            
        if dest == u'.':
            dest = self.cwd
        elif dest[0] != u'\\':
            dest = u'%s\\%s' % (self.cwd, dest)

        
        filename = u'%s\\%s' % (dest, destfilename) if destfilename else u'%s\\%s' % (dest, os.path.basename(source))
        filename = filename.replace(u'\\\\', u'\\')
        
        self.log(u'Uploading %s' % source)

        try:
            with open(source, 'rb') as f:
                self.smbobj.put(f, filename)
                
        except SMBClientException, ex:
            self.log('Could not upload file: %s' % ex)
            return '[!] Could not upload file: %s' % ex
        except:
            self.log('Could not upload file: %s' % traceback.format_exc())
            return "[!] Could not upload file"

        self.log(u'Uploaded %s to %s' % (source, filename))
        return u"[+] Uploaded %s to %s" % (source, filename)
    
    def download(self, source, destdir):
        """
        Download a file from the remote SMB server
        """

        if source[0] != u'\\':
            source  = self.cwd + u'\\' + source
            
        self.log(u'Downloading %s' % source)

        try:
            with open(destdir, 'wb') as f:
                self.smbobj.get(source, f)
        except SMBClientException, ex:
            self.log(u'Could not download file: %s' % ex)
            return '[!] Could not download file: %s' % ex
        except:
            self.log(u'Could not download file: Error during SMB GET: %s' % traceback.format_exc())
            return "[!] Error during SMB GET"

        self.log(u'Downloaded %s to %s' % (source, destdir))
        return u"[+] Downloaded %s to %s" % (source, destdir)     
                
