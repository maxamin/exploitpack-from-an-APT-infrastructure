#!/usr/bin/env python
# -*- coding: utf-8 -*-

import spidns
import re
import urllib
import sys
import urlparse

class altavista(spidns.spidns):
    def __init__(self):
      spidns.spidns.__init__(self)
      self.domain = ''
      self.urls = list()

    def on_response(self, (url, data), header, content, method):
      for elt in re.findall('--/SIG=.*?/EXP=[0-9]{10}/\*\*(.*?)\'>', content):
          #self.urls.append(urllib.unquote(elt))
          elt = urllib.unquote(elt)
          elt = urlparse.urlparse(elt)[1]
          #if self.domain in elt[len(self.domain)-1:]:
          if self.domain in elt:
            self.urls.append(elt)
            

    def fetch(self, query):
      start = 0
      req = "http://www.altavista.com/web/results?itag=ody&kgs=1&kls=0&q=%s&stq=%i"%(query,start)
      res, cont = self.get(req)
      while start < 50:
          start += 10
          req = "http://www.altavista.com/web/results?itag=ody&kgs=1&kls=0&q=%s&stq=%i"%(query,start)
          res, cont = self.get(req)

    def fetch_site(self, query): 
      self.domain = query
      self.fetch("inurl:%s" % query)

    def get_urls(self):
      return list(set(self.urls))

if __name__ == "__main__":
    g = altavista()
    if len(sys.argv) < 2:
        g.fetch_site("google.com")
    else:
        g.fetch_site(sys.argv[1])
    print "\n".join(g.get_urls())
