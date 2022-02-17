#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

# Original from nmapxml canvas module

#from xml.sax.handler import ContentHandler
import xml.sax 

class nmapxml(xml.sax.handler.ContentHandler):
  def __init__(self):
    self.mapping = {}
    self.ignore = False

  def test(self, filename):
    try:
      header = file(filename,"r").read(5000)
    except:
      return 0
    if header[:22] == '<?xml version="1.0" ?>':
      return 1
    return 0

  def startElement(self, name, attributes):
    if name == 'address':
      self.buffer = ''
      self.address = attributes["addr"]
      self.host = {'address':self.address, 'hostname':'', 'ports':[] }
    elif name == 'port':
      self.inPorts=1
      self.port=attributes['portid']
      self.host['ports'].append( { 'protocol':attributes['protocol'], 'port':attributes['portid'], 'state':'closed', 'service':'', 'data':'' } )
    elif name == 'status':
      if attributes['state'].strip() == "down":
        self.ignore = True
    elif name == 'hostname':
      self.host['hostname'] = attributes['name']
    elif name == 'state':
      self.host['ports'][-1]['state'] = attributes['state']
    elif name == 'service':
      self.host['ports'][-1]['service'] = attributes['name']

  def characters(self, data):
    self.buffer = data

  def endElement(self, name):
    if name == 'host':
      if (len(self.address) > 0) and not self.ignore:
        if len(self.host['ports']) > 0:
          self.mapping[self.address] = self.host.copy()
        self.host = {'address':self.address, 'hostname':'', 'ports':[] }
      else:
        self.ignore = False
        self.address = ''
        self.host = {'address':self.address, 'hostname':'', 'ports':[] }

def nmap_test_xml(filename):
  t = nmapxml().test(filename)
  if t == 0:
    return 1
  return 0

def nmap_parse(filename):
  ip = ''
  parser = xml.sax.make_parser()
  handler = nmapxml()
  parser.setContentHandler(handler)
  parser.parse(filename)
  for i in handler.mapping:
    ip = handler.mapping[i]['address']
    host = handler.mapping[i]['hostname']
  return (host, ip, handler.mapping[i]['ports'])
