#!/usr/bin/env python

from sys import argv, exit
from time import time

import paramiko

from fuse import FUSE, Operations, LoggingMixIn


class SFTP(LoggingMixIn, Operations):

    def __init__(self, host, path='.'):
        self.transport = paramiko.Transport(host)
        self.transport.connect(username='admin', password='admin')
        self.sftp = paramiko.SFTPClient.from_transport(self.transport)
        self.root = path

    def chmod(self, path, mode):
        return self.sftp.chmod(path, mode)

    def chown(self, path, uid, gid):
        return self.sftp.chown(path, uid, gid)

    def create(self, path, mode):
        f = self.sftp.open(path, 'w')
        f.chmod(mode)
        f.close()
        return 0

    def destroy(self, path):
        self.sftp.close()
        self.transport.close()

    def getattr(self, path, fh=None):
        st = self.sftp.lstat(path)
        return dict((key, getattr(st, key)) for key in ('st_atime', 'st_gid',
            'st_mode', 'st_mtime', 'st_size', 'st_uid'))

    def mkdir(self, path, mode):
        return self.sftp.mkdir(path, mode)

    def read(self, path, size, offset, fh):
        f = self.sftp.open(path)
        f.seek(offset, 0)
        buf = f.read(size)
        f.close()
        return buf

    def readdir(self, path, fh):
        return ['.', '..'] + [name.encode('utf-8')
                              for name in self.sftp.listdir(path)]

    def readlink(self, path):
        return self.sftp.readlink(path)

    def rename(self, old, new):
        return self.sftp.rename(old, self.root + new)

    def rmdir(self, path):
        return self.sftp.rmdir(path)

    def symlink(self, target, source):
        return self.sftp.symlink(source, target)

    def truncate(self, path, length, fh=None):
        return self.sftp.truncate(path, length)

    def unlink(self, path):
        return self.sftp.unlink(path)

    def utimens(self, path, times=None):
        return self.sftp.utime(path, times)

    def write(self, path, data, offset, fh):
        f = self.sftp.open(path, 'r+')
        f.seek(offset, 0)
        f.write(data)
        f.close()
        return len(data)


if __name__ == '__main__':
    if len(argv) < 3:
        print('usage: %s <host> <mountpoint>' % argv[0])
        exit(1)
    fuse = FUSE(SFTP(argv[1]), argv[2], foreground=True, debug=True, nothreads=True)
