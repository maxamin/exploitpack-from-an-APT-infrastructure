import os
import proto.http
import re
import string
from httplib import HTTPConnection, HTTPSConnection

def extract_value(source):
  tmp = re.findall('value=".*?"', source, re.DOTALL)[0]
  tmp = tmp.split('\"')[1]
  return tmp

def export_hash(host, port, page):
  i = 1
  j = 0
  unids = []
  hdl = proto.http.http_client()
  cnx = hdl.open_http(host, port)
  if cnx == None:
    return {}
  while j < page:
    url = '/names.nsf/\$defaultview?Readviewentries&Start=%d' % i
    results = hdl.send_request('GET', url, {}, {})[2]
    if results.find('unid') < 0:
      break
    tmps = re.findall('unid=".*?"', results, re.DOTALL)
    for tmp in tmps:
      unids.append(tmp.split('\"')[1])
    i = i+30
    j = j+1
  hash = {}
  for unid in unids:
    firstname = lastname = shortname = httppassword = ''
    url = '/names.nsf/\$defaultview/%s?OpenDocument' % unid
    results = hdl.send_request('GET', url, {}, {})[2]
    results = results.split('\n')
    for r in results:
      if r.find('"FirstName"') > -1: firstname = extract_value(r)
      if r.find('"LastName"') > -1:  lastname = extract_value(r)
      if r.find('"ShortName"') > -1: shortname = extract_value(r)
      if r.find('"HTTPPassword"') > -1: 
        httppassword = extract_value(r)
        httppassword = httppassword.replace('(', '')
        httppassword = httppassword.replace(')', '')
      hash[firstname] = [lastname, shortname, httppassword]
  hdl.close_http()
  return hash

def parser_html(host, port, url, stag, etag):
  nfo = proto.http.send_get_request(host, port, url, {})
  if nfo:
    if nfo[0] == 200:
      body = string.lower(nfo[2])
      start = body.find(stag)
      if start == -1:
        return ''
      end = body.find(etag, start+1)
      if end == -1:
        return '' 
      version = body[start+len(stag):end]
      return version
    if nfo[0] == 302:
      for header in nfo[1]:
        location = string.lower(header[0])
        if location == "location":
          return parser_html(host, port, '/%s' % header[1], stag, etag)
  return ''

def fingerprint(host, port):
  t_version = []

  inotes = ['/iNotes/Forms6.nsf', '/iNotes/Forms7.nsf']
  for inote in inotes:
    version = parser_html(host, port, inote, '<!-- domino release', '-->')
    version = version.strip()
    if version:
      if version not in t_version: t_version.append(version)

  version = parser_html(host, port, '/help/readme.nsf?OpenAbout', '<title>', '</title>')
  m = re.search('[0-9]\.*[0-9]*\.*[0-9]*', version)
  if m:
    version = (version[m.start():m.end()]).strip()
    if version not in t_version: t_version.append(version)

  filesets = ['/download/filesets/l_LOTUS_SCRIPT.inf', '/download/filesets/n_LOTUS_SCRIPT.inf',
    '/download/filesets/l_SEARCH.inf', '/download/filesets/n_SEARCH.inf']
  for fileset in filesets:
    version = parser_html(host, port, fileset, 'version=', '\n')
    version = version.strip()
    if version:
      if version not in t_version: t_version.append(version)


  #hdl = proto.http.http_client()
  #hdl.open_http(host, port)
  urls = ['/help/help%d_client.nsf?OpenAbout', '/help/help%d_designer.nsf?OpenAbout',
    '/help/help%d_admin.nsf?OpenAbout']
  vers = [5, 6, 65, 7, 8]
  for v in vers:
    for url in urls:
      nfo = proto.http.send_get_request(host, port, url % v, {})
      if not nfo:
        continue
      if nfo[0] == 302:
        for header in nfo[1]:
          location = string.lower(header[0])
          if location == "location":
            nfo = proto.http.hdl.send_get_request(host, port, '/%s' % header[1], {})
            if not nfo: continue
      if nfo[0] == 200:
        if v == 5:
          version = parser_html(host, port, '/help/help5_client.nsf', '<!-- lotus-domino', '-->')
          version = version.strip()
          if version:
            version = version.replace(' (', '')
            version = version.replace(')', '')
            if version not in t_version: t_version.append(version)
          else:
            version = parser_html(host, port, url % v, '<title>lotus notes', '</title>')
            version = version.strip()
            if version:
              version = '5.0.x'
              if version not in t_version: t_version.append(version)
        elif v == 65:
          version = parser_html(host, port, url % v, '<title>lotus notes', '</title>')
          version = version.strip()
          if version:
            version = '6.5.x'
            if version not in t_version: t_version.append(version)
        else:
          version = parser_html(host, port, url % v, '<title>lotus notes', '</title>')
          version = version.strip()
          if version:
            version = '%d.0.x' % v
            if version not in t_version: t_version.append(version)

  return t_version

def check_header_server(host, port):
  nfo = proto.http.send_head_request(host, port, '/', {})
  if not nfo:
    return ''    
  if not nfo[1]:
    return ''
  for header in nfo[1]:
    server = string.lower(header[0])
    if server == 'server':
      return header[1].strip()
  return ''

def checkacl(host, port):
  auth = []
  anonymous = []
  fileacl = os.path.join(os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-1]), 'lotus_acl.txt')
  acls = open(fileacl, 'r').readlines()
  for acl in acls:
    if acl[0] == '#': continue
    if len(acl) == 0: continue 
    acl = acl[:-1]
    nfo = proto.http.send_get_request(host, port, '/%s' % acl, {})
    if not nfo: continue
    if not nfo[2]: continue
    if nfo[0] in [404,500]: continue
    if nfo[0] in [302,403,401]:
      if nfo[0] == 401:
        auth.append(acl)
    if nfo[0] == 200:
      if nfo[2].find('names.nsf?Login') >= 0:
        auth.append(acl)
      else:
        anonymous.append(acl)
  return (auth, anonymous)
