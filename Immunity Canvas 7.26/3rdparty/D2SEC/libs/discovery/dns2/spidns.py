#!/usr/bin/env python
# -*- coding: utf-8 -*-

import urllib
import httplib2
import socket
socket.setdefaulttimeout(9)
MAX_REDIRECT=10
UAS=["Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)",
     "Mozilla/4.0 (compatible; MSIE 5.5; Windows 98; Win 9x 4.90)"]


class spidns:
  def __init__(self, UA=UAS[0],max_redirect=MAX_REDIRECT):
    self.headers = dict()
    self.headers["User-agent"]     = UAS[0]
    self.headers["Accept-Charset"] = "utf-8;q=0.7,*;q=0.3"
    self.handler   = httplib2.Http()
    self.handler.follow_redirects = True

  def raw(self,url,method,data=None):
    response = dict()
    content  = ""
    try :
      if data != None:
        self.headers['Content-type'] = 'application/x-www-form-urlencoded'
        response, content = self.handler.request(url, method, headers=self.headers, body=urllib.urlencode(data),redirections=MAX_REDIRECT)
      elif data == None :
        response, content = self.handler.request(url, method, headers=self.headers,redirections=MAX_REDIRECT)
      self.on_response((url,data),response,content,method)
    except httplib2.RedirectLimit, e:
      self.log_error("Spider::%s too many redirect %s %s"%(method,url,e))
      response = e.response
      content  = e.content
    except httplib2.ServerNotFoundError,e:
      self.log_error("Spider::%s server unknown %s %s"%(method,url,e))
      return None,None
    #except socks.Socks5Error, e:
    #  self.log_error("Spider::%s error fetching %s %s"%(method,url,e))
    #  return None,None
    except socket.timeout, e:
      self.log_error("Spider::%s timeouted on %s %s"%(method,url,e))
      return None,None

        #except AttributeError, e:
        #    if self.handler.proxy_info <> None:
        #        raise Exception("Spider::No socks server on %s:%i"%(self.handler.proxy_info.proxy_host,self.handler.proxy_info.proxy_port))

    if 'set-cookie' in response.keys(): self.headers['Cookie'] = response['set-cookie']
    if data <> None: del self.headers['Content-type']
    return response, content

  def get(self,url):
    return self.raw(url,"GET")

  #def post(self,url,data):
  #  return self.raw(url,"POST",data)

  def log_error(self,msg):
    print msg

  def on_response(self,(url,data),header,content,method):
    pass

if __name__ == "__main__":
  spi = spidns()
  spi.get("http://google.com/")
