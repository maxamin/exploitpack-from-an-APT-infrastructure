#! /usr/bin/env python

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2009
#

import sys, os, getopt

try:
	from twisted.internet import reactor
	from twisted.web import http
	from twisted.web.proxy import Proxy, ProxyRequest
	from twisted.python import log
except:
	print "You need to install twisted module\n"
	sys.exit(0)


def usage():
	print "Usage: d2sec_proxy.py [-p port] [-l logfile]\n"
	sys.exit(0)

filedesc = None

class VerboseProxyRequest(ProxyRequest):
	def process(self):
		if self.uri:
			filedesc.write(self.uri+'\n')
		ProxyRequest.process(self)

class VerboseProxy(Proxy):
	requestFactory = VerboseProxyRequest

if __name__ == '__main__':
	port = -1 
	logfile = ''

	print "D2SEC (c) 2007-2009 d2sec_proxy\n"
	log.startLogging(sys.stdout)
	if len(sys.argv) == 1:
		usage()

	try:
		opts, args = getopt.getopt(sys.argv[1:], "p:l:")
		for opt, arg in opts:
			if opt == "-p":
				port = int(arg)
			if opt == "-l":
				logfile = arg
	except getopt.GetoptError, err:
		usage()

	if port < 0 or port > 65535:
		print "port invalid !\n"
		sys.exit(0)

	if not logfile:
		print "logfile not specified !\n"
		sys.exit(0)

	filedesc = open(logfile, 'a')

	factory = http.HTTPFactory()
	factory.protocol = VerboseProxy

	reactor.listenTCP(port, factory)
	reactor.run()
