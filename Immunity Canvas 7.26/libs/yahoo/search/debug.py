"""yahoo.search.debug - Debugging utilities

This module defines and provides some debugging utilities that can
be used when you encounter problems with the search APIs. Most
interesting is the various debugging levels:

     HTTP     - Various HTTP protocol related information.
     PARAMS   - Show debugging information about CGI parameters.
     PARSING  - Show parsing processing.

     RAWXML   - Show the raw XML.

     ALL      - Show everything.
"""

import sys


__revision__ = "$Id: debug.py,v 1.7 2005/10/26 20:32:27 zwoop Exp $"
__version__ = "$Revision: 1.7 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Wed Oct 26 11:15:36 PDT 2005"


# Debug levels, 32 bits of "features"
DEBUG_LEVELS = { 'ALL' : 2**32-1,
                 'HTTP' : 2**0,
                 'PARAMS': 2**1,
                 'PARSING' : 2**2,
                 
                 # These are very verbose
                 'RAWXML' : 2**31,
                 }


#
# Simple class to use instead of "object", to enable
# debugging messages etc.
#
class Debuggable(object):
    """Debuggable - Simple "base" class to implement debugging. You
    should use this instead of object as a base class. The only
    useful member function is _debug_msg, intentionally made
    private to avoid exposing it in docs and APIs.
    """
    def __init__(self, debug_level=0):
        self._debug_level = debug_level

    def _debug_msg(self, msg, level, *args):
        """Produce a debug message, if the current debug level is
        higher than the requested level.
        """
        if self._debug_level & level:
            sys.stderr.write("[debug: ")
            text = msg % args
            if isinstance(text, unicode):
                try:
                    text = text.encode("utf-8")
                except UnicodeError:
                    text = msg + " (encode() failed!)"
            sys.stderr.write(text)
            sys.stderr.write("]\n")



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
