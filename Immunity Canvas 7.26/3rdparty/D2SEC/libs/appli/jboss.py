import proto.http
import re

def server_info(host, port):
  url = '/web-console/ServerInfo.jsp'
  (status, headers, result) = proto.http.send_get_request(host, port, url, {})
  if status == 401: return ['[401] %s' % url]
  if status != 200: return []
  info = []
  info.append('Infos available (%s) !\n' % url)
  tmps = re.findall('<p align="left"><font size="1"><b>.*?</b>.*?</font>', result, re.DOTALL)
  for tmp in tmps:
    tmp = tmp.replace('<p align="left"><font size="1"><b>', '')
    tmp = tmp.replace('<b>', '')
    tmp = tmp.replace('</b>', '')
    tmp = tmp.replace('</font>', '')
    info.append('  %s\n' % tmp)
  return info

def check_command(host, port):
  commands = {
    'addURL': '/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.deployment:type=DeploymentScanner,flavor=URL',
    'deploy': '/jmx-console/HtmlAdaptor?action=inspectMBean&name=jboss.system%3Aservice%3DMainDeployer',
  }

  nfo = ''
  for command, url in commands.items():
    (status, headers, result) = proto.http.send_get_request(host, port, url, {})
    if status == 401: nfo += '[401] %s\n' % command
    if status == 200 and result:
      parse = re.findall('void %s()' % command, result)
      if not parse:
        parse = re.findall("<td class='param'>%s</td>" % command, result)
      if len(parse):
        if not nfo:
          nfo += '  %s' % command
        else:
          nfo += ', %s' % command
  return nfo

def jmx_console(host, port):
  url = '/jmx-console/'
  (status, headers, result) = proto.http.send_get_request(host, port, url, {})
  if status == 401: return ['[401] %s' % url]
  if status != 200: return ['[%d] %s' % (status, url)]
  info = []
  info.append('[200] JMX Console found (%s) !' % url)
  commands = check_command(host, port)
  if commands:
    info.append('  Interesting available commands: %s\n' % commands)
  return info

def web_invoker(host, port):
  url = {
    'Web Console Invoker': '/web-console/Invoker',
    'JMX Invoker Servlet': '/invoker/JMXInvokerServlet',
    'EJB Invoker Servlet': '/invoker/EJBInvokerServlet',
  }
  result = ''
  info = []  
  for desc, url in url.items():
    (status, headers, result) = proto.http.send_get_request(host, port, url, {})
    if status == 200: info.append('[200] %s available (%s)' % (desc, url))
    elif status == 401: info.append('[401] %s' % url)
  return info
      
def vulnerabilities(host, port):
  vuln = {
    'CVE-2010-1429': '/status?full=true',
    'CVE-2005-2006': '%.',
    'CVE-2005-2006': '%server.policy',
    'CVE-2005-2006': '%login-config.xml',
    'Unknown': '/web-console/ServerInfo.jsp%00',
    'Unknown': ';index.jsp',
  }  
  result = ''
  info = []
  for cve, url in vuln.items():
    (status, headers, result) = proto.http.send_get_request(host, port, url, {})
    if status == 200: info.append('[200] %s not patched (%s)' % (cve, url))
    elif status == 401: info.append('[401] %s' % url)
  return info
