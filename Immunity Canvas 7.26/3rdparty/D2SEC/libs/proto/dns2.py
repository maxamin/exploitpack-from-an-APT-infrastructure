import sys, os

libpath = os.path.sep.join(os.path.abspath(__file__).split(os.path.sep)[:-2])
if libpath not in sys.path: sys.path.append(libpath)
extlibpath = os.path.join(libpath, 'ext')
if extlibpath not in sys.path: sys.path.append(extlibpath)

import libs.ext.dns.query
import libs.ext.dns.resolver
import libs.ext.dns.zone
import libs.ext.dns.exception

def checkopen(target):
  libs.ext.dns.resolver.get_default_resolver().nameservers = [str(target)]
  #try: 
  res = libs.ext.dns.resolver.query("google-public-dns-a.google.com.", "A")
  #except libs.dns.exception.Timeout, e:
  #  return 2 
  #except Exception, e:
  #  return False
  if (str(res) == "8.8.8.8"):
    return True
  return False
