#!/usr/bin/env python
# -*- coding: utf-8 -*-

import spidns
import urlparse
import sys

class google(spidns.spidns):
    def __init__(self):
        spidns.spidns.__init__(self, )
        self.headers = dict()
        self.headers["Referer"] = "http://www.foundstone.com" # Viva el WSDigger
        self.domain = ''
        self.urls = list()

    def on_response(self,(url,data),header,content,method):
        try:
          import json
        except ImportError, e:
          print "[-] %s" % e
          print "[-] Install module python-simplejson"
          sys.exit(0)
        res = json.loads(content)["responseData"]
        if res <> None:
            cursor  = res["cursor"]
            for result in res["results"]:
                elt = urlparse.urlparse(result["url"])[1]
                if self.domain in elt:
                  self.urls.append(elt)

    def fetch(self,query):
        start = 0
        req   = "http://ajax.googleapis.com/ajax/services/search/web?v=1.0&rsz=large&start=%i&q=%s"%(start,query)
        res, cont = self.get(req)
        while cont.find("out of range start") == -1:
            start+=8
            req   = "http://ajax.googleapis.com/ajax/services/search/web?v=1.0&rsz=large&start=%i&q=%s"%(start,query)
            res,cont = self.get(req)

    def fetch_site(self,query):
      self.domain = query
      self.fetch("inurl:%s"%query)
      self.fetch("site:%s"%query)

    def get_urls(self):
      return list(set(self.urls))

if __name__ == "__main__":
    g = google()
    if len(sys.argv) < 2:
        g.fetch_site("google.com")
    else:
        g.fetch_site(sys.argv[1])
    print "\n".join(g.get_urls())
