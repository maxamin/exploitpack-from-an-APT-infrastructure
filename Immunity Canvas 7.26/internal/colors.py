#! /usr/bin/env python

# ANSI colors (for ANSI terminal) (ISO 6429)

EOC     = "\033[0m"
BRIGHT  = "\033[1m"
BROWN   = "\033[0;33m"
RED     = "\033[1;31m"
GREEN   = "\033[1;32m"
YELLOW  = "\033[1;33m"
CYAN    = "\033[1;34m"
MAGENTA = "\033[1;35m"
BLUE    = "\033[1;36m"

import sys

def color_text(text, status, bold, use_colors=True):
    if sys.stdout.isatty() and use_colors:
        attr = []
        if status == 1:
            # green - success
            attr.append('32')
        elif status == 2:
            # red - fail
            attr.append('31')
        if bold:
            attr.append('1')

        return '\x1b[%sm%s\x1b[0m' % (';'.join(attr), text)
    else:
        return text
