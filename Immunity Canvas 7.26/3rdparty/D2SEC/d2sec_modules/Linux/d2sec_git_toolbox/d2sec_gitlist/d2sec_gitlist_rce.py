#!/usr/bin/env python

from commands import getoutput
import urllib
import sys
 
if len(sys.argv) <= 1:
    print '%s: [url to git repo] [cmd]' % sys.argv[0]
    print '  Example: python %s http://localhost/gitlist/my_repo.git id' % sys.argv[0]
    sys.exit(1)
 
url = sys.argv[1]
url = url if url[-1] != '/' else url[:-1]
 
cmd = sys.argv[2]

mpath = "/blame/master/""`%s`" % cmd
mpath = url+urllib.quote(mpath)
out = getoutput("curl -s %s" % mpath)
print out

