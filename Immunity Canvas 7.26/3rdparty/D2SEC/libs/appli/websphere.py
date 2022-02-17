import proto.http

def ibm_console(host, port):
  url = '/ibm/console'
  https = 0 
  if port == 9043:
    https = 1
  hdl = proto.http.http_client()
  cnx = hdl.open_http(host, port, https)
  if cnx == None:
    return ''
  res = hdl.send_request('GET', url, None, None)
  hdl.close_http()
  info = []
  if res[0] == 401:
    info.append('IBM Websphere console available (%s) with an authentication\n' % url)
  if res[0] == 200:
    info.append('IBM Websphere console available (%s) !\n' % url)
  return info

def snoop(host, port):
  url = '/snoop'
  (status, headers, body) = proto.http.send_get_request(host, port, url, None)
  info = []
  if status == 401:
    info.append('Servlet snoop available on port %s (%s) with an authentication\n' % (url, port))
  if status == 200:
    info.append('Servlet snoop available on port %s (%s) \n' % (url, port))
  return info
