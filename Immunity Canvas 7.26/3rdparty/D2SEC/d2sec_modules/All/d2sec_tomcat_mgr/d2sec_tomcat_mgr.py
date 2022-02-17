#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import cmd
import getopt
import sys
import traceback
import urllib.request
import urllib.parse
import codecs
import getpass

usage = """
D2SEC (c) 2007-2015 d2sec_tomcat_mgr

This tools manage a tomcat server from the command line:
$ d2sec_tomcat_mgr [-u userid] [-p password] [-c command] [-b] manager_url 

__with__ :
    
  -u    the user to use for authentication
        with the tomcat application
  -p    the password to use for authentication
        with the tomcat application
  -c    command to run : 
          + deploy : deploy tomcat-test WAR
          + undeploy : undeploy tomcat-test WAR
          + start : start an app 
          + stop : stop an app 
          + reload : reload an app 
  -b   brure-force auth if user and password are defined
  -t   if it's a tomcat 7 
  -h   display this help and exit

For example:
$ python3 d2sec_tomcat_mgr.py -b http://10.0.2.5:8080/manager
$ python3 d2sec_tomcat_mgr.py -u a -p a http://10.0.2.5:8080/manager

"""

###
# Usage
###
class Usage(Exception):
  def __init__(self, msg):
    self.message = msg

###
# ExtendedRequest
###
class ExtendedRequest(urllib.request.Request):
  def __init__(self, url, data=None, headers={}, origin_req_host=None, unverifiable=False):
    urllib.request.Request.__init__(self, url, data, headers, origin_req_host,  unverifiable)
    self.method = None

  def get_method(self):
    if self.method == None:
      if self.data:
        return "POST"
      else:
        return "GET"
    else:
      return self.method

###
# TomcatException
###
class TomcatException(Exception):
  def __init__(self, msg):
    self.message = msg

  def __str__(self):
    return self.message

###
# TomcatManager
###
class TomcatManager:
  def __init__(self, url="http://localhost:8080/manager", userid=None, password=None):
    self.__userid = userid
    self.__password = password
    self.hasConnected = False
    
    self.__managerURL = url
    if userid and password:
      self.__passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
      self.__passman.add_password(None, self.__managerURL, self.__userid, self.__password)
      self.__auth_handler = urllib.request.HTTPBasicAuthHandler(self.__passman)
      self.__opener = urllib.request.build_opener(self.__auth_handler)
    else:
      self.__opener = urllib.request.build_opener()


  def _execute(self, cmd, params=None, data=None, headers={}, method=None):
    """execute a tomcat command and check status returning a file obj for further processing
    
    fobj = _execute(url)
    
    """
    url = self.__managerURL + "/" + cmd
    if params:
      url = url + "?%s" % urllib.parse.urlencode(params)
    req = ExtendedRequest(url, data, headers)
    if method:
      req.method = method
    response = self.__opener.open(req)
    content = codecs.iterdecode(response,"utf-8")
    status = next(content).rstrip()
    self.hasConnected = True
    if not status[:4] == "OK -":
      raise TomcatException(status)
    return content


  def list(self, msg):
    if msg == 1:
      print('[+] list of all applications currently installed')
    response = self._execute("list")
    apps = []
    for line in response:
      apps.append(line.rstrip().split(":"))   
    cw = [24, 7, 8, 36]
    # build the format string from the column widths so we only
    # have the column widths hardcoded in one place
    fmt = " ".join(list(map(lambda x: "%"+str(x)+"s",cw)))
    dashes = "-"*80
    print(fmt % ("Path".ljust(cw[0]), "Status".ljust(cw[1]), "Sessions".rjust(cw[2]), "Directory".ljust(cw[3])))
    print(fmt % (dashes[:cw[0]], dashes[:cw[1]], dashes[:cw[2]], dashes[:cw[3]]))
    for app in apps:
      path, status, session, directory = app[:4]
      print(fmt % (app[0].ljust(cw[0]), app[1].ljust(cw[1]), app[2].rjust(cw[2]), app[3].ljust(cw[3])))

  def serverinfo(self):
    print('[+] get information about the server')
    response = self._execute("serverinfo")
    serverinfo = {}
    for line in response:
      key, value = line.rstrip().split(":",1)
      serverinfo[key] = value.lstrip()
    return serverinfo
  
  def stop(self, path):
    print('[+] stop %s application'%path)
    response = self._execute("stop", {'path': path})

  def start(self, path):
    print('[+] start %s application'%path)
    response = self._execute("start", {'path': path})

  def reload(self, path):
    print('[+] reload %s application'%path)
    response = self._execute("reload", {'path': path})

  def deploy(self, path, fname, update=False, tag=None):
    print('[+] deploy %s WAR file at %s path'%(fname, path))
    """read a WAR file from a local fileobj and deploy it at path
    
    Arguments:
    path     the path on the server to deploy this war to
    fileobj  a file object opened for binary reading, from which the war file will be read
    update   whether to update the existing path (default False)
    tag      a tag for this application (default None)
     
    """
    fileobj = open(fname, "rb")
    wardata = fileobj.read()
    headers = {}
    headers['Content-type'] = "application/octet-stream"
    headers['Content-length'] = str(len(wardata))
    params = {'path': path}
    if update:
      params['update'] = "true"
    if tag:
      params['tag'] = tag
    response = self._execute("deploy", params, wardata, headers, "PUT")
    print('[+] %s WAR file deployed'%fname)
    self.list(0)
  

  def undeploy(self, path):
    print('[+] undeploy %s application'%path)
    response = self._execute("undeploy", {'path': path})


###
# Connect
###
def connect(url, user, password, bflag):
  users = ['admin', 'manager', 'role1', 'root', 'tomcat', 'both']
  passwords = ['', 'admin', 'manager', 'role1', 'root', 'tomcat', 's3cret']
  itm = None
  msg = 1
  try:
    if user and password:
      itm = TomcatManager(url, user, password)
      itm.list(msg)
      print('[+] connected to tomcat manager at %s with %s/%s'%(url, user, password))
    elif bflag == 1:
      msg = 0
      for u in users:
        for p in passwords:
          try:
            print('[+] try to connect with %s/%s'%(u, p))
            itm = TomcatManager(url, u, p)
            itm.list(msg)
            print('[+] connected to tomcat manager at %s with %s/%s'%(url, u, p))
            break
          except Exception as e:
            continue
    else:
      itm = TomcatManager()   
      itm.list(msg)
      print('[+] connected to tomcat manager at %s'%url)
  except urllib.request.HTTPError as e:
    if e.code == 401:
      print('[-] login failed')
    elif e.code == 403:
      print('[-] login failed')
    elif e.code == 404:
      print('[-] tomcat manager not found at %s' % url)
    else:
      print('[-] error: %s'%e) 
    return None
  except TomcatException as e:
    print('[-] error: %s'%e) 
    return None
  except Exception as e:
    print('[-] error: %s'%e) 
    return None
  return itm

###
# Main
###
def main(argv=None):
  print("[#] D2SEC (c) 2007-2015 d2sec_tomcat_mgr")
  if argv is None:
    argv = sys.argv

  user = None
  password = None
  url = None
  command = None
  bflag = 0
  tomcat7 = 0

  try:
    try:
      opts, args = getopt.getopt(argv[1:], 'u:p:c:tbh')
    except getopt.error as msg:
      raise Usage(msg)
    for opt, param in opts:
      if opt == "-h":
        global usage
        print(usage)
        return
      elif opt == "-u":
        user = param
      elif opt == "-p":
        password = param
      elif opt == "-c":
        command = param
      elif opt == "-b":
        bflag = 1
      elif opt == "-t":
        tomcat7 = 1
    url = "%s/manager"%args[0]
    if tomcat7:
      url = "%s/text"%url
    itm = connect(url, user, password, bflag)
    if itm == None or command == None:
      return
    try:
      fct = {
        'deploy': itm.deploy,
        'undeploy': itm.undeploy,
        'start': itm.start,
        'stop': itm.stop,
        'reload': itm.reload,
      }
      if command == "deploy":
        fct[command]("/tomcat-test", "./tomcat-test.war", False)
      else:
        fct[command]("/tomcat-test")
    except Exception as e:
      print('[-] %s: command not found'%e, file=sys.stderr)
      print('for help use -h', file=sys.stderr)
      return

  except Usage as err:
    print(err.message, file=sys.stderr)
    print('for help use -h', file=sys.stderr)
    return

if __name__ == "__main__":
  sys.exit(main())
