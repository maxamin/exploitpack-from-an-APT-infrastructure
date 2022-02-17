#!/usr/bin/env python
#
# DHCP library

import sys
import time
import string
if "." not in sys.path: sys.path.append(".")

import socket
from dhcppacket import *
import dhcppacket

# The client/server should behave pretty similar        
class DHCPServer:
	def __init__(self, addr = "0.0.0.0", listenport = 67, destport = 68, iface="eth0"):
		self.ListenAddr = (addr, listenport)
		self.destport = destport
		self.srcport  = listenport
		self.packet = None
		self.iface = iface
		self.dsocket = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
		self.dsocket.setsockopt( socket.SOL_SOCKET, socket.SO_BROADCAST, 1 )
		self.dsocket.bind(self.ListenAddr)
		
		self._handlers = {1: self.handleDiscover, 2: self.handleOffer, 3: self.handleRequest, 4: self.handleDecline,\
							5: self.handleAck, 6: self.handleNAck, 7: self.handleRelease, 8: self.handleInform,\
							9: self.handleForceNew, 10: self.handleLeaseQuery }
		
		
	def send(self, dest, packet):
		self.dsocket.sendto(packet.raw(), (dest, self.destport))
	
	
	def run(self):
		# temporary until it gets complex
		while True:
			self.getPacket()

			
	def getPacket(self):
		print "Default getPacket() called."
		sdata = ""      
		packet = dhcppacket.DHCPPacket()
		
	
		while(sdata==""):
			sdata = self.dsocket.recv(4096)
			time.sleep(0.5)
		
		packet.get(sdata)
		
		self.handlePacket(packet, True)
				
		return packet
		
	
			
	def handlePacket(self, packet, silent=False):
		self.handleGeneral()
		try:
			self._handlers[packet.getOptionbyTag(53)](packet) # message type
		except KeyError:
			raise Exception("Packet %d not supported" % packet.getOptionbyTag(53))


	# This handler is useful if you want to do something before the packets are handled
	def handleGeneral(self):
		pass
	
	def handleDiscover(self, packet):
		pass
	
	def handleOffer(self, packet):
		pass

	def handleRequest(self, packet):
		pass

	def handleDecline(self, packet):
		pass

	def handleAck(self, packet):
		pass

	def handleNAck(self, packet):
		pass

	def handleRelease(self, packet):
		pass

	def handleInform(self, packet):
		pass

	def handleForceNew(self, packet):
		pass

	def handleLeaseQuery(self, packet):
		pass

