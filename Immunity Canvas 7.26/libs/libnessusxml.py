#!/usr/bin/env python



import os, sys
import xml.sax

#-----------------------------------------------------
# Code orginally used for in house application for ACS
# Released in open domain
# Coders of the Project:  Tim Shelton
#                         Jeremy LaChausse
#                         Dan Felts
#------------------------------------------------------



class	nessusxml(xml.sax.handler.ContentHandler):


	def	__init__(self):
		self.mapping = {}
		self.host = {'address':'', 'hostname':'', 'ports':[] }
		self.port = ''
		self.__indata = False

	def	startElement(self, name, attributes):
		if name == 'host':
			self.buffer = ''
			try:
				self.host['address'] = attributes["ip"]
				self.host['hostname'] = attributes['name']
			except:
				pass
			
		elif name == 'port':
			protocol=''
			try:
				self.port=attributes['portid']
			except:
				self.port=''

			try:
				protocol = attributes['protocol']
			except:
				protocol = 'tcp'

			if self.port:
				self.host['ports'].append( { 'protocol':protocol, 'port':self.port, 'state':'open', 'service':'', 'data':[] } )


		elif name == 'service':
			if self.port:
				self.host['ports'][-1]['service'] = attributes['name']


		elif name == 'data':
			self.__indata = True

	def	characters(self, data):
		if(self.__indata):		
			if(len(data.strip()) > 0):
				self.buffer += data.strip() + "\n"

	def	endElement(self, name):
		if(self.__indata):
			self.__indata = False
			if (len(self.host['address']) > 0) and self.port:
				la = self.buffer.replace("&","&amp;")
                                la = la.replace("\n'\n","'")
                                la = la.replace(">","&gt;")
                                la = la.replace("\n&gt;\n","&gt;")
                                la = la.replace("<","&lt;")
                                la = la.replace("\n&lt;\n","&lt;")

				self.host['ports'][-1]['data'].append(la) # += la

			self.buffer = ''

		if name=='result':
			if( (len(self.host['address']) > 0) and (len(self.host['ports']) > 0 ) ):
				self.mapping[self.host['address']] = self.host.copy()
			self.host = {'address':'', 'hostname':'', 'ports':[] }

if __name__ == '__main__':

	file = "test"


	if(len(sys.argv) > 1):
		file = sys.argv[1]
 
	parser = xml.sax.make_parser()
	handler = nessusxml()
	parser.setContentHandler(handler)
	parser.parse(file)

	#print handler.mapping

	for i in handler.mapping:
		print "Host: %s (%s)" % (handler.mapping[i]['hostname'], handler.mapping[i]['address'])
		for m in  handler.mapping[i]['ports']:
                  	print "Port: %s" % p['port']
			print "Data: %s" % m['data']
