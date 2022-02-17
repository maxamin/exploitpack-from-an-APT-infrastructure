#!/usr/bin/env python
#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
SMBNode.py

VFS operations for SMB nodes. This is my first attempt at doing this
and contains introductory functionality only. The operations currently
supported are download, upload and dir.

"""

import os
from VFSNode import VFSNode
from libs.newsmb.smbconst import ATTR_DIRECTORY
from libs.newsmb.libsmb import SMBQueryInformationException, assert_unicode

class SMBNode(VFSNode):
    def __init__(self, host):
        self.host = host
        VFSNode.__init__(self)

    def get_interesting_interface(self):
        return self.host

    def vfs_stat(self, path):
        """
        Do a stat operation on path.
        Return tuple with results.
        """
        path = assert_unicode(path)

        if path == u'':
            retstat = (0, 0, {"is_dir":False})
            return retstat # failed!
        
        if path in [u"/", u"\\"] :
            return (0, 0, {"is_dir":True})

        # Fix path to be universal
        path = path.replace(u'/', u'\\')
        ret = []

        self.log(u'vfs_stat: path is %s' % path)
        
        try:
            ret = self.shell.smbobj.query_information(path)
        except SMBQueryInformationException:
            pass

        if ret == []:
            retstat = (0, 0, {"is_dir":False})
        else:
            isexe = False
            if len(path) > 4:
                isexe = path[-4:].lower() == u".exe"
            retstat = (ret[0], ret[1], {"is_dir": ret[2], "is_exe": isexe})

        return retstat

    def vfs_dir(self, path=u''):
        path = assert_unicode(path)
        path = path.replace(u'/', u'\\') # Fix path to be universal
        res  = self.shell.smbobj.dir(filename=path + u'\\*')
        out  = []
        
        self.log(u'vfs_dir: path is %s' % path)        


        for i in res:
            name = i['FileName']
            if name not in (u".", u".."):
                is_dir = True if i['ExtFileAttributes'] & ATTR_DIRECTORY else False
                is_exe = False
                if len(name) > 4:
                    is_exe = name[-4:].lower() == u'.exe'
                out.append((name,
                            i['EndOfFile'],
                            self.shell.smb_nt_64bit_time(i['LastChangeTime']),
                            {"is_dir":is_dir, "is_exe":is_exe}))
        return out

    def vfs_upload(self, path, dest):
        (path, dest)            = map(assert_unicode, (path, dest))
        self.log(u'vfs_upload: %s to %s' % (path, dest))
        
        old_dir, self.shell.cwd = self.shell.cwd, u'\\'
        ret                     = self.shell.upload(path, dest.replace(u'/', u'\\'))
        self.shell.cwd          = old_dir

        return ret

    def vfs_download(self, path, dest):
        (path, dest) = map(assert_unicode, (path, dest))
        self.log(u'vfs_download: %s to %s' % (path, dest))
        outdir       = self.engine.create_new_session_output_dir(self.get_interesting_interface(), 'downloaded_files')
        directory    = os.path.join(outdir, path.replace(u'/', u'_').replace(u'\\', u'_'))
        directory    = directory.replace(u':', u'')

        return self.shell.download(path.replace(u'/', u'\\'), directory)

    
