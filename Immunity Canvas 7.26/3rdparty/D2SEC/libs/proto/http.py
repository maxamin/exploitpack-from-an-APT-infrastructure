#!/usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import sys
import os
import base64
import httplib, urllib

# HTTP API
class apihttp:

  def __init__(self, host, port):
    self.host = host
    self.port = port
    self.usehttps = 0
    self.proxy_host = ''
    self.proxy_port = 0
    self.cnx = None 
    self.headers = {
      'User-agent': 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.14) Firefox/3.0.14',      
    }
    self.params = None

  def use_https(self, use):
    self.usehttps = use

  def setproxy(self, proxy_host, proxy_port):
    self.proxy_host = proxy_host
    self.proxy_port = proxy_port

  def setheaders(self, name, value):
    self.headers[name] = value

  def setparams(self, params):
    self.params = urllib.urlencode(params)
    
  def add_auth_basic(self, username, password):
    creds = base64.b64encode('%s:%s' % (username, password))
    self.setheader('Authorization', 'Basic %s' % creds)

  def connect(self):
    if self.proxy_host and self.proxy_port > 0:
      self.cnx = httplib.HTTPConnection(self.proxy_host, self.proxy_port, True, timeout=30)
    else:
      if self.usehttps == 0:
        self.cnx = httplib.HTTPConnection(self.host, self.port, True, timeout=30)
      else:
        self.cnx = httplib.HTTPSConnection(self.host, self.port, strict=True, timeout=30)
    return self.cnx

  def request(self, method, url):
    if self.proxy_host and self.proxy_port > 0:
      if self.usehttps == 0: self.cnx.request(method, "http://"+self.host+"/"+url, self.params, self.headers)
      else: self.cnx.request(method, "https://"+self.host+"/"+url, self.params, self.headers)
    else:
      self.cnx.request(method, url, self.params, self.headers)
    return self.cnx.getresponse()

  def get_info_header(self, r):
    server = r.getheader('Server')
    powered = r.getheader('X-Powered-By')
    cookie = r.getheader('Set-Cookie')
    return {'Server':server, 'Powered':powered, 'Cookie':cookie}

# HTTP Client
class http_client:
  def __init__(self):
    self.apihttphdl = None

  def open_http(self, host, port, https=0, proxy_host='', proxy_port=0):
    self.apihttphdl = apihttp(host, port)
    if https: self.apihttphdl.use_https(https)
    if proxy_host and proxy_port != 0: self.apihttphdl.setproxy(proxy_host, proxy_port)
    self.apihttphdl.cnx = self.apihttphdl.connect()
    if self.apihttphdl.cnx != None:
      return self.apihttphdl
    return None

  def send_request(self, method, url, headers, params):
    if headers:
      for header, value in headers.items():
        #self.apihttphdl.headers[header] = value
        self.apihttphdl.setheaders(header, value)
    if params:
      self.apihttphdl.setparams(params)
    res = self.apihttphdl.request(method, url)
    return [res.status, res.getheaders(), res.read()]

  def close_http(self):
    return self.apihttphdl.cnx.close()

def _send_request(method, host, port, url, headers, params):
  hdl = http_client()
  cnx = hdl.open_http(host, port)
  if cnx == None:
    return ''
  resp = hdl.send_request(method, url, headers, params)
  hdl.close_http()
  return resp

def send_get_request(host, port, url, headers):
  return _send_request('GET', host, port, url, headers, None)

def send_post_request(host, port, url, headers):
  return _send_request('POST', host, port, url, headers, None)

def send_options_request(host, port, url, headers):
  return _send_request('OPTIONS', host, port, url, headers, None)

def send_propfind_request(host, port, url, headers):
  return _send_request('PROPFIND', host, port, url, headers, None)

def send_post_request(host, port, url, headers, params):
  return _send_request('POST', host, port, url, headers, params)

def fingerprint(host, port):
  version = {
    'Lighttpd': 76943, # Tested on lighttpd 1.4.19
    'Apache': 8177,
    'IIS': 16383,
    'Squid': 32652,
    'GWS (Google)': 2048,
  }
  for server, size in version.iteritems():
    hdl = http_client()
    cnx = hdl.open_http(host, port)
    if cnx == None:
      return ''
    resp = hdl.send_request('GET', '/'+"A"*size, {'Host': '127.0.0.1'})
    if resp[0] == 414:
      hdl.close_http()
      return server
  return 'Unknown'
