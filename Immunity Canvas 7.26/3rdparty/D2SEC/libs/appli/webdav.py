import proto.http
import re
import string

def discovery(host, port):
  dav = msauthorvia = xmsdavext = ''
  headers = proto.http.send_options_request(host, port, '/', {})[1]
  for header in headers:
    if string.lower(header[0]) == 'dav': dav = header[1]
    if string.lower(header[0]) == 'ms-author-via': msauthorvia = header[1]
    if string.lower(header[0]) == 'x-msdavext': xmsdavext = header[1]
  if dav and msauthorvia == 'DAV':
    if xmsdavext:
      return 'SHAREPOINT DAV'
    return 'WEBDAV'
  else:
    return ''

def propfind_parse_href(data):
  nfo = []
  hrefs = re.findall('<D:href>.*?</D:href>', data, re.DOTALL)
  for href in hrefs:
    href = href.replace('<D:href>', '')
    href = href.replace('</D:href>', '')
    nfo.append(href)
  return nfo

def propfind_content(host, port):
  return proto.http.send_propfind_request(host, port, '/', {})
