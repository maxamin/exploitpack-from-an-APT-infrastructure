#! /usr/bin/env python

import sys, os
import colors
import debug

logging_initialized = False

def logging_init():
    logging_initialized = True
    if debug.debug_enabled:
        display("debug activated", color=colors.GREEN)

def display(msg, color=None, prefix="[DEV] ", postfix="\n"):
    if os.name != "posix" or not color:
        colorprefix=""
        colorpostfix=""
    else:
        colorprefix=color
        colorpostfix=colors.EOC
    sys.stdout.flush() #flush this first
    sys.stderr.write("%s%s%s%s%s" % (colorprefix, prefix, msg.encode("utf-8"), postfix, colorpostfix))
    sys.stderr.flush()

if __name__ == "__main__":
    debug.devlog("devlog msg")

