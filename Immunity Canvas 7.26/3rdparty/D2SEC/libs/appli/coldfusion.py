import proto.http
import re
import adobe

def solr_service_info(host, port):
  url = '/solr/data_medialibrary/admin/get-properties.jsp'
  ports = [8983]
  if port not in ports:
    ports.append(port)
  (status, headers, result) = proto.http.send_get_request(host, port, url, {})
  if status == 401: return ['[401] %s' % url]
  if status != 200: return []
  info = []
  info.append('CVE-2010-0185 (%s) !\n' % url)
  info.append('  %s\n' % result)
  return info
