#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import spidns,re
import urlparse

class exalead(spidns.spidns):
    def __init__(self):
        spidns.spidns.__init__(self)
        self.domain = ''
        self.urls = list()

    def on_response(self, (url, data), header, content, method):
        for elt in re.findall('<a class="url" href="(.*?)"   >',content):
            elt = urlparse.urlparse(elt)[1]
            if self.domain in elt:
              self.urls.append(elt)

    def fetch(self,query):
        start = 0
        req = 'http://www.exalead.com/search/web/results/?q=%s&elements_per_page=100&start_index=%i'%(query,start)
        res, cont = self.get(req)
        while start < 500:
            start += 100
            req = 'http://www.exalead.com/search/web/results/?q=%s&elements_per_page=100&start_index=%i'%(query,start)
            self.get(req)

    def fetch_site(self,query): 
      self.domain = query
      self.fetch("inurl:%s"%query)

    def get_urls(self):
      return list(set(self.urls))

if __name__ == "__main__":
    g = exalead()
    if len(sys.argv) < 2:
        g.fetch_site("google.com")
    else:
        g.fetch_site(sys.argv[1])
    print "\n".join(g.get_urls())
