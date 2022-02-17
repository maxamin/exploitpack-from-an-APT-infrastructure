#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import spidns,re
import string

class netcraft(spidns.spidns):
    def __init__(self):
        spidns.spidns.__init__(self)
        self.domain = ''
        self.urls = list()

    def on_response(self, (url, data), header, content, method):
      for e in ('>',':','=','"','<','/','\\','@'):
        content = string.replace(content,e,' ')
      r1 = re.compile('[a-zA-Z0-9.-_]*\.'+self.domain)
      res = r1.findall(content)
      for x in res:
        self.urls.append(x)

    def fetch(self,query):
        self.domain = query
        req = 'http://searchdns.netcraft.com/?host=%s&position=limited' % query
        res, cont = self.get(req)

    def fetch_site(self, query):
      self.domain = query
      self.fetch(query)

    def get_urls(self):
      return list(set(self.urls))

if __name__ == "__main__":
    g = netcraft()
    if len(sys.argv) < 2:
        g.fetch_site("google.com")
    else:
        g.fetch_site(sys.argv[1])
    print "\n".join(g.get_urls())
