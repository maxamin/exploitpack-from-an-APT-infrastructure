import ftplib

class api:
  def __init__(self, host):
    self.ftp = None
    self.host = host

  def connect(self):
    #try:
    self.ftp = ftplib.FTP(self.host)
    #except Exception, e:
    #  print '%s' % e
    return self.ftp

  def bannergrab(self):
    return self.ftp.getwelcome()

  def anonymous(self):
    try:
      data = self.ftp.login('anonymous', 'ftp@microsoft.com')
    except Exception, e:
      #print '%s' % e
      return 0
    return 1

  def dirlist(self):
    list = ''
    #try:
    list = self.ftp.retrlines('LIST')
    #except Exception, e:
    #  pass
    #  print '%s' % e
    #return list
    return self.ftp.retrlines('LIST')
