#!/usr/bin/python2

#
# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2015
#


###
# STD Modules
###
import re, os, sys
import requests
import urllib

###
# Locals
###
GISTS_URL="https://gist.github.com"

def _request(URL):
  try:
    resp = requests.get(URL)
  except Exception, e:
    print >> sys.stderr, "[-] error while opening url: %s" % e
    return None
  return resp.text

def _raw(text):
  gists = re.findall(r'<a href="%s/(.*?)/(\w+)" class="link-overlay">'%GISTS_URL, text)
  for gist in gists:
    user = gist[0]
    gid1 = gist[1] 
    resp = _request('%s/%s/%s'%(GISTS_URL, user, gid1))
    if not resp:
      continue
    raws = re.findall(r'href="/%s/%s/raw/(\w+)/(.*?)"'%(user, gid1), resp)
    for raw in raws:
      gid2 = raw[0] 
      file = raw[1]
      resp = _request('https://gist.githubusercontent.com/%s/%s/raw/%s/%s'%(user, gid1, gid2, file))
      if not resp:
        continue
      dest_file = 'data/%s/%s'%(user, gid2)
      print '[+] %s' % dest_file
      if os.path.isfile(dest_file):
        continue
      if not os.path.exists(os.path.dirname(dest_file)):
        os.mkdir(os.path.dirname(dest_file))
      try:
        with open(dest_file, "w+") as f:
          f.write('%s'%resp.encode('utf-8'))
      except Exception, e:
        print >> sys.stderr, "[-] error while writing file: %s" % e
  
def main(keyword):
  print '[#] keyword: %s' % keyword 
  text = _request('%s/search?q=%s'%(GISTS_URL, urllib.quote_plus(keyword)))
  if text == None:
    sys.exit(0)
  m = re.findall("found (\d+) gist results", text)
  m = int(m[0])
  print '[#] found %d results' % m
  page = m/10
  i = 2
  _raw(text)
  while i < page:
    text = _request('%s/search?q=%s&p=%d'%(GISTS_URL, keyword, i))
    if text:
      _raw(text)
    i=i+1

if __name__ == "__main__":
  if len(sys.argv) < 2:
    print 'Usage: %s <keyword>' % sys.argv[0]
    sys.exit(0)
  main(sys.argv[1])
