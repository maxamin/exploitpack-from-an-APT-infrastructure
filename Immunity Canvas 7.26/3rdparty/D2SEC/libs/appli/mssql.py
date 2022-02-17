import socket

def ping(host):
  output = None
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.settimeout(30)
  #try:
  s.connect((host, 1434))
  #except socket.error, msg:
    #self.log.warning("%s: Connection refused: %s" % (self.name, msg[1]))
    #print "%s: Connection refused: %s" % (self.name, msg[1])
    #return None
  req='\x02'
  #try:
  s.send(req)
  output=dict()
  data = s.recv(1024).split(";")
  output["ServerName"]   = data[1]
  output["InstanceName"] = data[3]
  output["IsClustered"]  = data[5]
  output["Version"]      = data[7]
  #except Exception,e:
    #self.log.warning('MSSQL %s problem %s' % (host,e))
    #print 'MSSQL %s problem %s' % (host,e)
    #return None
  return output
