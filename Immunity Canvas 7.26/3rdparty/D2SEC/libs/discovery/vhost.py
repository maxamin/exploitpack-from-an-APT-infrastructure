#!/usr/bin/env python

import urllib, re, sys

def bing_hosts(ip):
  results = []
  query = 'ip:%s' % ip
  start = 1
  lastres = None
  while True:
    res = _bing_query(query, start)
    if lastres == res:
      break
    total = len(res)
    lastres = list(res)
    start += 10
    for i in res:
      if i not in results:
        results.append(i)
    if total < 10:
      break
  results.sort()
  return results

def _bing_query(query, start=1):
  skip = [
    'bingj.com',
    'live.com',
    'microsoft.com',
    'msn.com',
    'www.microsofttranslator.com',
  ]
  final = []
  cpage = urllib.urlopen("http://www.bing.com/search?q=%s&first=%d" % (query, start))
  cpage_data = cpage.read()
  regex = re.compile('<a href="[a-z]+://([a-zA-Z0-9\-\.\_]*)')
  try:
    cpage_data = cpage_data.split('<div id="results_container">')[1].split('<div id="sidebar">')[0]
  except Exception, e:
    return final
  res = regex.findall(cpage_data)
  for host in res:
    match = False
    for skiphost in skip:
      if host.endswith(skiphost):
        match = True
        break
    if not match:
      final.append(host)
  return final

def serversniff_hosts(target):
  final = []
  try:
    cpage = urllib.urlopen("http://serversniff.net/hip-%s" % target)
    cpage_data = cpage.read()
  except Exception, e:
    return final
  regex = re.compile('<td><b> ([a-zA-Z0-9\-\.\_]*) </b></td>')
  final = regex.findall(cpage_data)
  return final

def getcname(target, port):
  try:
    from M2Crypto import SSL
  except ImportError, e:
    print "[-] %s" % e
    print "[-] Install module M2Crypto"
    return
  ctx = SSL.Context()
  ctx.set_allow_unknown_ca(True)
  ctx.set_verify(SSL.verify_none, 1)
  conn = SSL.Connection(ctx)
  conn.postConnectionCheck = None
  timeout = SSL.timeout(15)
  conn.set_socket_read_timeout(timeout)
  conn.set_socket_write_timeout(timeout)
  try:
    conn.connect((target, 443))
  except Exception, e:
    #print '%s' % e
    return
  cert = conn.get_peer_cert()
  try: cCN = cert.get_subject().CN
  except AttributeError: cCN = ''
  conn.close
  return cCN

def reversedns(target):
  try:
    from dns import reversename
    from dns import resolver
  except ImportError, e:
    print "[-] dnspython module not present"
    sys.exit(0)
  res = reversename.from_address(target)
  return resolver.query(res, 'PTR')[0]

def vhost_check(target):
  vhosts = []
  try: vhosts = bing_hosts(target)
  except Exception, e:
    print '%s' % e
  try: tmps = serversniff_hosts(target)
  except Exception, e:
    print '%s' % e
  for tmp in tmps:
    if tmp not in vhosts: vhosts.append(tmp)
  return vhosts

if __name__ == "__main__":
  if len(sys.argv) == 1:
    print "usage: %s <ip> [<port>]" % sys.argv[0]
    raise SystemExit
  target = sys.argv[1]
  port = 443
  if len(sys.argv) == 3:
    port = int(sys.argv[2])
  print 'vhosts discovery - target: %s\n' % target
  print 'DNS PTR: %s' % reversedns(target)
  print 'SSL CNAME: %s\n' % getcname(target, port)
  print 'Search engines:'
  print '\n'.join(vhost_check(target))


