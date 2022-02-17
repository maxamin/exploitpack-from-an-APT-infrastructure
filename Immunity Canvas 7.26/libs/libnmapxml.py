#!/usr/bin/env python



import os, sys
import xml.sax
import copy

#-----------------------------------------------------
# Code orginally used for in house application for ACS
# Released in open domain
# Coders of the Project:  Tim Shelton
#                         Jeremy LaChausse
#                         Dan Felts
#------------------------------------------------------



class	nmapxml(xml.sax.handler.ContentHandler):


	def	__init__(self):
		self.mapping = {}
		self.host = { }
		self.addresses = []
		self.ignore = False

	def	startElement(self, name, attributes):
		if name == 'address':
			self.buffer = ''
			self.addresses.append(attributes["addr"])
			self.host = {'hostname':'', 'ports':[] }
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

	def	characters(self, data):
				
		self.buffer = data

	def	endElement(self, name):

		if name == 'host':
			if(len(self.addresses) > 0) and not self.ignore:
				if len(self.host['ports']) > 0:
                                        for address in self.addresses:
                                                self.mapping[address] = {'address':address,
                                                                         'hostname':self.host['hostname'],
                                                                         'ports':copy.deepcopy(self.host['ports'])
                                                }
				self.host = {'hostname':'', 'ports':[] }
                                self.addresses = []
			else:
				self.ignore = False
				self.addresses = []
				self.host = {'hostname':'', 'ports':[] }

if __name__ == '__main__':

	file = "test"


	if(len(sys.argv) > 1):
		file = sys.argv[1]
 
	parser = xml.sax.make_parser()
	handler = nmapxml()
	parser.setContentHandler(handler)
	parser.parse(file)
	for i in handler.mapping:
	        print "Host: %s (%s)" % (handler.mapping[i]['address'], handler.mapping[i]['hostname'])
	        for m in  handler.mapping[i]['ports']:
	                print "Port: %s" % m['port']
	                print "Service: %s" % m['service']
