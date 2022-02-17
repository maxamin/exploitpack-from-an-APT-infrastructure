#! /usr/bin/env python

import sys
import traceback
import warnings
import debug

def deprecate(message = None, file = sys.stderr):
    """ warn when a deprecated function is called """

    if not debug.debug_enabled:
        pass
    
    tb = traceback.extract_stack()
    # stack is [?=main][...][caller][here=deprecated][extract_stack]

    if (len(tb) <= 2): # called by main?
        return

    if not message:
        message = ""
    (file, line, calling_func, deprecated_code) = tb[-3]
    #debug.devlog("!!! use of deprecated function %s in %s() [%s:%d] %s" % (f_deprecated, f_calling, file, line, message))
    debug.devlog("DEPRECATED File %s, line %d, in %s()" % (file, line, calling_func))
    debug.devlog("DEPRECATED -> %s" % message)
    debug.devlog("DEPRECATED code: %s" % deprecated_code)
    #warnings.warn(message, DeprecationWarning, stacklevel=3)

def warnings_safely_ignore(category):
    warnings.filterwarnings('ignore', category=category)

def warning_restore():
    warnings.resetwarnings()

def _test():
    def popo():
        deprecate("testing deprecate()")
        print "popo"

    def x():
        print "x"
        popo()

    print "1"
    x()
    print "2"

if __name__ == "__main__":
    _test()
