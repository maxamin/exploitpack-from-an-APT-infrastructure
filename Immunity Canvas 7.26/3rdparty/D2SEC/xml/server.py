#!/usr/bin/env python
# -*- coding: utf-8 -*-
###
#
# Console-based client
#
###

###
# STD modules
###
import sys, os, signal, re, stat, string, subprocess, time, sqlite3, logging, socket
from SimpleXMLRPCServer import SimpleXMLRPCServer, SimpleXMLRPCRequestHandler
from threading import Thread, Lock
import thread
import xmlrpclib, xml.sax

###
# Project
###
libpath = os.path.join(os.getcwd(), 'libs')
if libpath not in sys.path: sys.path.append(libpath)
libpath = os.path.join(os.getcwd(), 'libs/parser')
if libpath not in sys.path: sys.path.append(libpath)

import d2sec_config
import nmap
import log
import console
import net.banner
import autopwn_ftp
import autopwn_ssh
import autopwn_http
import autopwn_smtp
import autopwn_telnet
import autopwn_dns
import autopwn_finger
import autopwn_pop
import autopwn_sunrpc
import autopwn_ntp
import autopwn_imap
import autopwn_mssql
import autopwn_citrix
import autopwn_squid
import autopwn_mysql
import autopwn_jboss
import autopwn_lotus
import autopwn_webdav
import autopwn_tomcat
import autopwn_websphere
import autopwn_smb
import autopwn_netbios
import autopwn_activemq
import autopwn_coldfusion
import autopwn_ldap
import autopwn_joomla
import autopwn_drupal

###
# Django
###
sys.path.append(os.path.join(os.getcwd(), 'd2sec_modules/All/d2sec_django'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'settings'
try:
  import www.database
  import www.models
except:
  pass

XMLRPCPORT = 31337

class d2serv(Thread):
  def __init__(self, host='localhost', port=XMLRPCPORT):
    Thread.__init__(self)
    self.djangodb = 'd2sec_modules/All/d2sec_django/db_d2sec.sqlite3'
    try:
      self.server = SimpleXMLRPCServer((host, port), logRequests=False)
    except Exception, e:
      print '[-] %s' % e
      os._exit(0)
    self.server.register_function(self.suicide, 'suicide')
    self.server.register_function(self.parse_nmap_xml, 'parse_nmap_xml')
    self.server.register_function(self.createdb_django, 'createdb_django')
    self.server.register_function(self.deletedb_django, 'deletedb_django')
    self.server.register_function(self.listvar, 'listvar')
    self.server.register_function(self.setvar, 'setvar')
    self.server.register_function(self.unsetvar, 'unsetvar')
    self.server.register_function(self.checkvar, 'checkvar')
    self.server.register_function(self.listtargets, 'listtargets')
    self.server.register_function(self.dumpdb_by_host, 'dump')
    self.server.register_function(self.autopwn, 'autopwn')

    self.victim = None
    self.log_setup_cli()
    self.globals = {
      'CANVASPATH' : d2sec_config.CANVASPATH,
      'PYTHONPATH' : '',
      'NMAP_BIN'   : '',
      #'DICO'       : '',
      #'USER'       : ''
    }
    return

  def log_setup_cli(self):
    log.init()
    self.log, self.log_hdl_term = log.to_term(level=5)
    self.log = logging.getLogger('D2 LOG')

  def parse_nmap_xml(self, filename):
    if nmap.nmap_test_xml(filename): 
      return ('error', 'File %s not a xml nmap file') % filename
    (host, ip, ports) = nmap.nmap_parse(filename)
    if not ip or not ports:
      return ('error', 'No ip and ports')
    else:
      try:
        self.db = www.database.db()
        target  = self.db.db_unique_host(title=host, host=ip)
        for port in ports:
          service = self.db.db_unique_service(target, '%d/%s' % (int(port['port']), port['protocol']))
        return (ip, host, ports)
      except Exception, e:
        return ('error', '%s' % e)

  def createdb_django(self):
    if os.path.isfile(self.djangodb) == True:
      return ('info', 'Sqlite3 database found (%s)' % self.djangodb)
    if not self.globals['CANVASPATH']: return ('error', 'CANVASPATH not specified')
    if not self.globals['PYTHONPATH']: return ('error', 'PYTHONPATH not specified')
    cmd = '%s d2sec_modules/All/d2sec_django/manage.py -c' % self.globals['PYTHONPATH']
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    time.sleep(5)
    if os.path.isfile(self.djangodb) == False:
      return ('error', 'Database not found (%s)' % self.djangodb)
    else:
      return ('info', 'Done')

  def deletedb_django(self):
    try:
      os.unlink(self.djangodb)
      return ('info', 'Done')
    except Exception, e:
      return ('error', '%s' % e)

  def listvar(self):
    return self.globals

  def checkvar(self, var):
    return self.globals[var.upper()]

  def setvar(self, var, value):
    if var.upper() in self.globals:
      self.globals[var.upper()] = value
      return ('info', 'Done')
    else:
      return ('error', 'Var %s unknown\n' % var)

  def unsetvar(self, var):
    if var.upper() in self.globals:
      self.globals[var.upper()] = ''
      return ('info', 'Done')
    else:
      return ('error', 'Var %s unknown\n' % var)

  def listtargets(self):
    nfo = []
    nfo.append('Targets list')
    nfo.append('--------------')
    self.db = www.database.db()
    hosts = www.models.Host.objects.all()
    print hosts
    for target in hosts:
      nfo.append('%s - %s' % (target, target.host))
    return ('info', nfo)
  
  def dumpdb_by_host(self, host):
    nfo = []
    self.db = www.database.db()
    target = www.models.Host.objects.get(title=host)
    nfo.append('Target: %s' % target)
    nfo.append('-'*(9+len(host)))
    for info in www.models.Info.objects.filter(host=target, service=None):
      info.desc = info.desc.split('\n')
      for inf in info.desc:
        if inf:
          nfo.append('%s - %s - %s' % (info.title, info.module, inf))
    for vuln in www.models.Vuln.objects.filter(host=target, service=None):
      vuln.vuln_desc = vuln.vuln_desc.split('\n')
      for v in vuln.vuln_desc:
        if v:
          nfo.append('%s - %s - %s' % (vuln.title, vuln.module, v))
    for srv in self.db.db_get_host_services(host=target):
      for info in www.models.Info.objects.filter(host=target, service=srv):
        info.desc = info.desc.split('\n')
        for inf in info.desc:
          if inf:
            nfo.append('%s - %s - %s - %s' % (srv, info.title, info.module, inf))
      for vuln in www.models.Vuln.objects.filter(host=target, service=srv):
        vuln.vuln_desc = vuln.vuln_desc.split('\n')
        for v in vuln.vuln_desc:
          if v:
            nfo.append('%s - %s - %s - %s' % (srv, vuln.title, vuln.module, v))
    return ('info', nfo)

  def run_shell_command(self, args, outsplit=False, env=None, timeout=180):
    try:
      proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    except xmlrpclib.Fault, fault:
      print fault.faultString
    fin_time = time.time() + timeout
    while proc.poll() == None and fin_time > time.time():
      time.sleep(5)
      if fin_time < time.time():
        os.kill(proc.pid, signal.SIGKILL)
        return("Error: Process '%s' timeout has been reached" % args[0])
    if outsplit:
      return proc.stdout.readlines()
    return proc.stdout.read()

  def test_port_open(self, target, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(30)
    try:
      s.connect((target, port))
    except socket.error, msg:
      return False
    return True

  def scan(self, target, nmap):
    args = [nmap, '-sS', '-sV', '-P0', '-O', '-n', '--max-scan-delay', '4000', target]
    output = self.run_shell_command(args, timeout=300)
    info = self.db.db_unique_info(self.victim, None, 'Scan NMAP', '', output)
    ports = []
    res = re.compile('(\d+/tcp|\d+/udp)\s+open').findall(output)
    return res

  def run_by_appli(self, target, applis):
    pwn_by_appli = {
      'jboss' : autopwn_jboss,
      'citrix': autopwn_citrix,
      'mssql' : autopwn_mssql,
      'mysql' : autopwn_mysql,
      'squid' : autopwn_squid,
      'lotus' : autopwn_lotus,
      'webdav': autopwn_webdav,
      'tomcat': autopwn_tomcat,
      'websphere': autopwn_websphere,
      'activemq': autopwn_activemq,
      'coldfusion': autopwn_coldfusion,
      'joomla': autopwn_joomla,
      'drupal': autopwn_drupal,
      'struts': autopwn_struts,
    }
    for a in applis:
      appli, port = a.split('@')
      port = int(port)
      service = self.db.db_unique_service(self.victim, '%d/tcp' % port)
      for n, fct in pwn_by_appli.items():
        if n == string.lower(appli):
          self.log.info("%s application (port %s)" % (n, port))
          fct.run(self.log, self.db, self.victim, service).exploit(target, port)

  def run_by_port(self, target, ports):
    pwn_by_port = {
      21:    ['FTP',    autopwn_ftp],
      22:    ['SSH',    autopwn_ssh],
      23:    ['TELNET', autopwn_telnet],
      25:    ['SMTP',   autopwn_smtp],
      53:    ['DNS',    autopwn_dns],
      79:    ['FINGER', autopwn_finger],
      80:    ['HTTP',   autopwn_http],
      110:   ['POP3',   autopwn_pop],
      111:   ['RPC',    autopwn_sunrpc],
      123:   ['NTP',    autopwn_ntp],
      139:   ['NETBIOS', autopwn_netbios],
      143:   ['IMAP',   autopwn_imap],
      389:   ['LDAP',   autopwn_ldap],
      443:   ['HTTPS',  autopwn_http],
      445:   ['SMB',    autopwn_smb],
      1080:  ['HTTP',   autopwn_http],
      1433:  ['MSSQL',  autopwn_mssql],
      1494:  ['CITRIX', autopwn_citrix],
      3128:  ['SQUID',  autopwn_squid],
      3306:  ['MYSQL',  autopwn_mysql],
      8080:  ['HTTP',   autopwn_http],
      8083:  ['HTTP',   autopwn_http],
      8161:  ['ACTIVEMQ', autopwn_activemq],
      9043:  ['WEBSPHERE', autopwn_websphere],
      9060:  ['WEBSPHERE', autopwn_websphere],
      9080:  ['WEBSPHERE', autopwn_websphere],
    }
    service = None
    for r in ports:
      if isinstance(r, str) == True:
        r = r.replace('/tcp', '')
        r = int(r)
      trace = 0
      service = self.db.db_unique_service(self.victim, '%d/tcp' % r)
      for p, proto in pwn_by_port.items():
        if r == p:
          trace = 1
          break
      if not trace:  
        self.log.info("TCP port %s open" % r)
        banner = net.banner.bannergrab(target, r)
        if banner: 
          self.log.debug('%s' % banner)
          self.db.db_unique_info(self.victim, service, 'Banner grabbing', '', banner)
        if string.lower(banner).find(string.lower(proto[0])) > -1:
          trace = 1
      if trace:
        self.log.info("TCP port %s (%s) open" % (r, proto[0]))
        try:
          proto[1].run(self.log, self.db, self.victim, service).exploit(target, r)
        except:
          continue
    return

  def autopwn(self, host, lports, lapplis):
    try:
      path = self.checkvar('CANVASPATH')
      python = self.checkvar('PYTHONPATH')
    except xmlrpclib.Fault, fault:
      print fault.faultString
      return
    if os.path.isfile(self.djangodb) == False:
      return('error', 'Sqlite3 database not found. Use createdb command...')
    self.db = www.database.db()
    #try:
    #  target = www.models.Host.objects.get(title=host)
    #  if target:
    #    return('info', 'This host is already autopwn()ed.')
    #except:
    #  pass
    ip = socket.gethostbyname(host)
    self.victim = self.db.db_unique_host(title=host, host=ip)
    ports  = []
    applis = []
    if not lports and not lapplis:
      nmap = self.checkvar('NMAP_BIN')
      if not nmap:
        return ('error', 'NMAP_BIN not specified')
      if os.name == 'posix' and os.getuid() and not (stat.S_ISUID & stat.S_IMODE(os.stat(nmap).st_mode)):
        self.log.critical("Server needs UID 0 privileges (nmap -sS)")
        return ('error', 'Server needs UID 0 privileges (nmap -sS)')
      self.log.info('TCP port scan on host "%s"' % ip)
      nfo = self.scan(ip, nmap)
      if 'Error' in nfo:
        nfo = nfo.replace('Error:', '')
        return ('error', nfo)
      self.run_by_port(ip, nfo)
    else:
      if lports:
        if lports.find(',') > -1:
          ports = lports.split(',')
        else:
          lports = int(lports)
          if lports < 0 or lports > 65535:
            return ('error', 'Invalid lports value')
          if self.test_port_open(ip, lports) == False:
            return ('error', 'Connection refused on port %d' % lports)
          ports.append(lports)
        self.run_by_port(ip, ports)
      if lapplis:
        if lapplis.find(',') > -1:
          applis = lapplis.split(',')
        else:
          applis.append(lapplis)
        self.run_by_appli(ip, applis)
    return ('info', 'Info saved in database')

  def suicide(self):
    os._exit(0)

  def run(self):
    # timeoutsocket will raise timeouts
    while 1:
      try:
        self.server.serve_forever()
      except:
        pass

class StartServerThread:
  def __init__(self, host='localhost', port=XMLRPCPORT):
    self.server_thread = d2serv(host, port).run()
    self.server_thread.start()

  def server_shutdown(self):
    self.server_thread.shutdown()
    self.server_thread.suicide()

# so we can talk to the engine over XML-RPC
class XMLRPCRequest:
  def __init__(self, host='localhost', port=XMLRPCPORT):
    self.proxy = xmlrpclib.ServerProxy('http://%s:%d/' % (host, port))
    return

if __name__ == "__main__": StartServerThread().server_thread
