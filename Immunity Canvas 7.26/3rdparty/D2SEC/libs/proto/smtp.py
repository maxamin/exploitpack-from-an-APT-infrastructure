import socket

def testrelay(host, port=25):
  sock = socket.socket()
  #sock.set_timeout(20)
	
  try:
    sock.connect((host, port))
  except Exception, e:
    print '%s' % e
    return
  data = sock.recv(4096)

  requests = ['HELO d2', 'MAIL FROM: d2@hotmail.com', 'RCPT TO: d2@d2@d2@d2']
  result = ''
  for request in requests:
    try:
      sock.sendall(request+'\r\n')
    except Exception, e:
      print '%s' % e
      continue
    try:
      data = sock.recv(4096)
    except Exception, e:
      sock.close()
      print '%s' % e
      continue
    result += '\"%s\" - %s' % (request, data)	
  sock.close()
  return result 
