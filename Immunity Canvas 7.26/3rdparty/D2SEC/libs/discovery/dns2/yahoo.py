#!/usr/bin/env python
#

import spidns, re, urllib, sys
import urlparse

class yahoo(spidns.spidns):
    def __init__(self):
        spidns.spidns.__init__(self)
        self.domain = ''
        self.urls = list()

    def on_response(self, (url, data), header, content, method):
        for elt in content.split('\n'):
            elt = elt.split('\t')
            if len(elt) == 4 and elt[1] != "URL":
              elt = urlparse.urlparse(elt[1])[1]
              if self.domain in elt:
                self.urls.append(elt)

    def fetch(self,query):
        start = 0
        req = 'http://siteexplorer.search.yahoo.com/export?p=http%%3A%%2F%%2F%s&bwm=p&bwms=p&fr=sfp&fr2=seo-rd-se' % (query)
        res, cont = self.get(req)

    def fetch_site(self, query):
      self.domain = query
      self.fetch("%s" % query)

    def get_urls(self): return list(set(self.urls))

if __name__ == "__main__":
    b = yahoo()
    if len(sys.argv) < 2:
        b.fetch_site("google.com")
    else:
        b.fetch_site(sys.argv[1])
    print "\n".join(b.get_urls())

