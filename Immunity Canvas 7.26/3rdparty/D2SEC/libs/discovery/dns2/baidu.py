#!/usr/bin/env python
# -*- coding: utf-8 -*-
import spidns,re, sys
import urlparse


class baidu(spidns.spidns):
    def __init__(self):
        spidns.spidns.__init__(self)
        self.domain = ''
        self.urls = list()

    def on_response(self,(url,data),header,content,method):
        for elt in re.findall('" href="(.*?)"  target="_blank" ><font size="3">',content):
            #self.urls.append(urlparse.urlparse(elt)[1])
            elt = urlparse.urlparse(elt)[1]
            if self.domain in elt:
              self.urls.append(elt)

    def fetch(self,query):
        start = 0
        req = 'http://www.baidu.com/s?wd=%s&pn=%i'%(query,start)
        res, cont = self.get(req)
        while start < 50:
            start+=10
            req = 'http://www.baidu.com/s?wd=%s&pn=%i'%(query,start)
            self.get(req)

    def fetch_site(self,query): 
      self.domain = query
      self.fetch("url:%s"%query)

    def get_urls(self):
      return list(set(self.urls))

if __name__ == "__main__":
    g = baidu()
    if len(sys.argv) < 2:
        g.fetch_site("google.com")
    else:
        g.fetch_site(sys.argv[1])
    print "\n".join(g.get_urls())
