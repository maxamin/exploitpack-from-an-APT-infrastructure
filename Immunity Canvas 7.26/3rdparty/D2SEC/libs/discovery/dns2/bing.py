#!/usr/bin/env python
# -*- coding: utf-8 -*-

import spidns
import re
import urllib
import sys
import urlparse

class bing(spidns.spidns):
  def __init__(self):
    spidns.spidns.__init__(self)
    self.domain = ''
    self.urls = list()

  def on_response(self, (url, data), header, content, method):
    for elt in re.findall('"sb_tlst"><h3><a href="(.*?)"', content):
      #self.urls.append(elt)
      elt = urllib.unquote(elt)
      elt = urlparse.urlparse(elt)[1]
      if self.domain in elt:
        self.urls.append(elt)

  def fetch(self,query):
    start = 1
    req = 'http://www.bing.com/search?q=%s&filt=all&first=%i&FORM=PORE' % (query, start)
    res, cont = self.get(req)
    while start < 50:
      start += 10
      req = 'http://www.bing.com/search?q=%s&filt=all&first=%i&FORM=PORE' % (query, start)
      self.get(req)

  def fetch_site(self,query): self.fetch("site:%s"%query)

  def fetch_dns(self,query): self.fetch("ip:%s"%query)

  def get_urls(self): return list(set(self.urls))

if __name__ == "__main__":
  g = bing()
  if len(sys.argv) < 2:
    g.fetch_site("google.com")
  else:
    g.fetch_site(sys.argv[1])
  print "\n".join(g.get_urls())

