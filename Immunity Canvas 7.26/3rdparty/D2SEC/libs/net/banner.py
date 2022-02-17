import socket
import re

def bannergrab(host, port):
  banner = ''
  #try:
  sck = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sck.settimeout(20)
  sck.connect((host, port))
  #except Exception, e:
  #  print '%s' % e
  #  return ''
  while True:
    #try:
    data = sck.recv(1024)
    #if not data or len(data) < 1024:
    if not data:
      break
    banner += data
    #except socket.timeout, e:
    #except Exception, e:
    #  break
  if banner:
    reg = re.findall("([^\x00-\x7f]+)", banner)
    if reg:
      banner = ''.join(map(lambda c: '\\%s' % hex(ord(c))[2:].zfill(2), banner))
    if not banner:
      banner = '(null)\n'
  return banner
