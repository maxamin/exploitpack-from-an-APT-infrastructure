#!/usr/bin/env python
#
# Quick wrapper class for temporary directory creation on MOSDEFShellServers.
# This expects to run in a new context by use of 'with', so that creation and
# removal of the temporary directory are done based on the context.
#
# Did I mention I hate Python for not providing proper C++ RAII semantics?
#
#  -- Ronald Huizer
#
# vim: sw=4 ts=4 expandtab

import re

class MSSTempDir:
    def __init__(self, shell, template = "/tmp/mss_XXXXXX", templated = True):
        self.shell = shell
        self.template = template
        self.__templated = templated
        self.pathname = ""

    def __enter__(self):
        if self.__templated:
            self.pathname = self.shell.mkdtemp(self.template)
        else:
            self.shell.mkdir(self.template, 0700)
            self.pathname = self.template

        return self

    def __exit__(self, type, value, traceback):
        self.shell.rmdir(self.pathname)

class MSSTempDirs:
    def __init__(self, shell, pathname):
        self.shell = shell
        self.pathname = pathname
        self.__cleanup = []

    def __enter__(self):
        for path in self.shell.path.subpaths(self.pathname):
            # If the directory is already there, skip it.
            if self.shell.path.isDirectory(path):
                continue

            # This is under try/except, as __exit__ does not get called when
            # we raise an exception in __enter__.
            # We clean up here, and reraise the exception to signal error.
            try:
                self.shell.mkdir(path, 0700)
            except MSSError, e:
                for i in xrange(0, len(self.__cleanup)):
                    # XXX: right now does not raise MSSError.
                    self.shell.rmdir(self.__cleanup.pop())
                # Propagate the exception.
                raise

            # This directory did not exist, and we need to clean it out.
            self.__cleanup.append(path)

        return self

    def __exit__(self, type, value, traceback):
        for i in xrange(0, len(self.__cleanup)):
            self.shell.rmdir(self.__cleanup.pop())
