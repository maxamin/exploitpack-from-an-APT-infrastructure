#!/usr/bin/env python

class MSSError(Exception):
    def __init__(self, errno, function, msg):
        self.errno = errno
        self.function = function
        self.msg = msg

    def __str__(self):
        return "%s(): %s" % (self.function, self.msg)
