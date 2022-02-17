import sys
import socket

def getinfo(host):
  #try:
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((socket.gethostbyname(host), 79))
  sock.send('\n')
  #except Exception, e:
  #  print '[!] Connection failed: %s\n' % e
  #  return

  finger = ''

  while True:
    try:
      data = sock.recv(1024)
      finger += data
      if not data or len(data) < 1024:
        break
    except socket.timeout, e:
      break
  return finger
