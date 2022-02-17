import proto.http

def cve_2010_1587(host, port):
  urls = ['//admin/index.jsp', '//admin/queues.jsp', '//admin/topics.jsp']
  for url in urls:
    result = proto.http.send_get_request(host, port, url, {})[2]
    if not result: 
      continue
    elif 'Licensed to the Apache Software Foundation (ASF)' in result:
      return ['Vulnerable to CVE_2010_1587 (source code disclosure vulnerability)']
    else: 
      continue
  return ['Not vulnerable to CVE_2010_1587 (source code disclosure vulnerability)']

def directory_traversal(host, port):
  urls = ['/\../\../README.txt']
  for url in urls:
    result = proto.http.send_get_request(host, port, url, {})[0]
    if result == 200:
      return ['Vulnerable to directory traversal vulnerability (https://issues.apache.org/jira/browse/AMQ-2788)']
    else:
      continue
  return ['Not vulnerable to directory traversal vulnerability (https://issues.apache.org/jira/browse/AMQ-2788)']
