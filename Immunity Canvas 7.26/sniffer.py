#! /usr/bin/env python
"""
sniffer.py
"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2003
#http://www.immunityinc.com/CANVAS/ for more information


#Part of CANVAS For licensing information, please refer to your
#Immunity CANVAS licensing documentation

#read this:
#http://www.faqs.org/faqs/internet/tcp-ip/raw-ip-faq/
#http://mail.python.org/pipermail/python-list/2001-November/070526.html



import socket
import select
import os, sys
import struct

from exploitutils import *
from internal import *
from db.oui import MACresolve
#resolving mac addresses currently takes a long time, since we have it in a large
#gzipped file, rather than in memory
resolve_mac_addresses=False
TCPFLAGS={}
TCPFLAGS[0x01]="FIN"
TCPFLAGS[0x02]="SYN"
TCPFLAGS[0x04]="RST"
TCPFLAGS[0x08]="PSH"
TCPFLAGS[0x10]="ACK"
TCPFLAGS[0x20]="URG"
TCPFLAGS[0x40]="ECN"
TCPFLAGS[0x80]="CNG"
r_TCPFLAGS={}
for x in TCPFLAGS.keys():
    r_TCPFLAGS[TCPFLAGS[x]]=x

ip2iface={}

#ip2iface is a string representation of the ip address mapped to a string representation of the interface
#it's a global in this module so we essentially have this cached at startup.
gateway_from_iface={}

# http://www.iana.org/assignments/ethernet-numbers
# ethereal/epan/etypes.h
ETHTYPE = {}
ETHTYPE['IP'] =   0x0800
ETHTYPE['ARP'] =  0x0806
ETHTYPE['DEC'] =  0x6000
ETHTYPE['RARP'] = 0x8035
ETHTYPE['IPv6'] = 0x86DD
ETHTYPE['PPP']  = 0x880b
ETH_HEADER_SIZE = 20

IPPROTO = {}
IPPROTO[ 1] = 'ICMP'
IPPROTO[ 2] = 'IGMP'
IPPROTO[ 4] = 'IPIP'
IPPROTO[ 6] = 'TCP'
IPPROTO[ 8] = 'EGP'
IPPROTO[17] = 'UDP'
IPPROTO[46] = 'RSVP'
IPPROTO[47] = 'GRE'
IPPROTO[41] = 'IPV6'
IPPROTO[50] = 'ESP'

# We need to back-map IPPROTO, it's order is reversed
# so adding RAW_IP_PROTO in the interim
RAW_IP_PROTO = {}
RAW_IP_PROTO["ICMP"] = 1
RAW_IP_PROTO["IGMP"] = 2
RAW_IP_PROTO["IPIP"] = 4
RAW_IP_PROTO["TCP"]  = 6
RAW_IP_PROTO["EGP"]  = 8
RAW_IP_PROTO["UDP"]  = 17
RAW_IP_PROTO["RSVP"] = 46
RAW_IP_PROTO["GRE"]  = 47
RAW_IP_PROTO["IPV6"] = 41
RAW_IP_PROTO["ESP"]  = 50

# Layer I - 802.11 subtypes
SUBTYPE_80211 = {
    "ASSOCIATION":0x00,
    "REASSOCIATION":0x20,
    "ASSOCIATION_RESPONSE":0x10,
    "BECON":0x80,
    "PROBE":0x40,
    "PROBE_RESPONSE":0x50,
    "ACK":0xD4,
    "NULL_FUNC":0x48,
    "DATA":0x08,
    "QOSDATA":0x88,
    "AUTH":0xB0,
    "RTS":0xb4,
    "CTS":0xc4,
    "DEASC":0xa0,
    "DEAUTH":0xc0
}


# Driver header table offsets list of [name, size, fingerprint] elements
DRIVER_80211_HDR = [
    ["madwifi", 0x90, "\x44\x00\x00\x00\x90\x00\x00\x00"],
#    ["ipw3945", 0x19, "\x00\x00\x19\x00\x6f\x08\x00\x00"],
    ["ipw3945", 0x00, "\x00\x00\x19\x00\x6f\x08\x00\x00"],
    ["atheros", 0x00, "\xca\xfb"],
    ["ipwraw", 0x00, "\xC0\x01\xBA\xBE"]
]



def ip_from_hex(hex):
    """
    "0100470A" -> "10.71.0.1"
    """
    a=hex[0:2]
    b=hex[2:4]
    c=hex[4:6]
    d=hex[6:8]
    ret="%s.%s.%s.%s"%(int(d,16),int(c,16),int(b,16),int(a,16))
    return ret

def init_gateway_iface():
    interfaces=getInterfaceData()
    for i in interfaces:
        ip2iface[i[1]]=i[0]

    try:
        data=open("/proc/net/route").readlines()
        have_routes=True
    except IOError:
        have_routes=False
    if have_routes:
        data=data[1:] #strip first line
        for line in data:
            line=line.replace("\t"," ")
            line=no_double_spaces(line)
            #print "Line:%s"%line
            interface_name,destination,gateway=line.split(" ")[:3]
            #print "%s %s %s"%(interface_name,destination,gateway)
            if gateway!="00000000":
                #TODO: Make gateway an ip address instead of a useless retarded number
                gateway_from_iface[interface_name]=ip_from_hex(gateway)


# Deprecating this for now as the ip's are almost never cached, replaced with a
# arp resolve function
#"""
#/proc/net/arp
#IP address       HW type     Flags       HW address            Mask     Device
#172.16.177.129   0x1         0x2         00:0C:29:F5:05:81     *        vmnet1
#"""
mac_from_ip={}
ip_mac_map = {}
try:
    data=open("/proc/net/arp").readlines()
    have_arp=True
except IOError:
    have_arp=False
if have_arp:
    data=data[1:] #strip first line
    for line in data:
        line=line.replace("\t"," ")
        line=no_double_spaces(line)
        lp=line.split(" ")
        mac_from_ip[lp[0]]=lp[3]

def get_iface_from_target(target):
    """
    Gets the interface from the target - useful for passing to sender()
    """
    init_gateway_iface()

    real_ip=get_source_ip(target)
    if real_ip==None:
        devlog("sniffer","You have no default gateway for target ip %s"%target)
        devlog("sniffer","Cannot continue - exiting")
        return ""
    #devlog("sniffer","Real_IP: *%r*"%real_ip)
    #devlog("sniffer","ip2iface: %r"%ip2iface)
    try:
        iface=ip2iface[real_ip] #actual ip->interface mapping done here so we know our gateway
    except IndexError:
        iface=None
    return iface


def get_ethernet_header(target, iface1=None):
    """
    Given a destination, get the ethernet header we need to pack onto the IP
    data to send this packet out using our sender framework

    Target argument must be an IP address, not a domain name!
    """
    if iface1:
        iface = iface1
    else:
        iface=get_iface_from_target(target)

    try:
        mysender = sender(iface)
    except socket.error:
        devlog("sniffer","Cannot use raw socket!")
        return ""


    init_gateway_iface()
    gateway=gateway_from_iface.get(iface,None)
    if not gateway:
        dstip = target
    else:
        dstip = gateway

    try:

        import iputils
        if dstip == iputils.getIfaceIP(iface):
            dest_mac_address = iputils.getIfaceMAC(iface)
        else:
            if ip_mac_map.has_key(dstip):
                dest_mac_address = ip_mac_map[dstip]
            else:
                dest_mac_address = iputils.get_remote_mac(iface, dstip, 1, 10)
                if dest_mac_address == False:
                    dest_mac_address = "00:00:00:00:00:00"
                ip_mac_map[dstip] = dest_mac_address

    except Exception:
        if mac_from_ip.get(target):
            dest_mac_address=mac_from_ip[target]
        else:
            gateway=gateway_from_iface.get(iface,None)
            if not gateway:
                devlog("sniffer","No gateway found, must be on local network")
                dest_mac_address=mac_from_ip.get(target)
                if not dest_mac_address:
                    devlog("sniffer","Cannot get mac address for %s - perhaps ping it to add it to arp cache?"%target)
                    return ""
                else:
                    self.log("dest_mac_address=%s"%dest_mac_address)
                    pass
            else:
                devlog("sniffer","Gateway found: %s"%gateway)
                dest_mac_address=mac_from_ip.get(gateway)
                if dest_mac_address==None:
                    devlog("sniffer","Cannot find destination mac address for %s"%gateway)
                    return ""


    devlog("sniffer","Destination mac address: %s"%dest_mac_address)
    myconstructor=packetConstructor()
    myconstructor.Ethernet(mysender.hardware_address,dest_mac_address,"IP")
    eth_header=myconstructor.get()
    return eth_header


def parse_dns_name(name_data, total_packet):
    """
    Returns a name from DNS formated name
    [<length as one byte><data>]...
    or 0xc0 0xXX where XX is a byte offset into our packet where a name starts
    """
    #handle offset encoding
    if name_data[0]==chr(0xc0):
        offset=ord(name_data[1])
        #recurse to handle this
        answer, blah = parse_dns_name(total_packet[offset:], total_packet)
        return (answer, name_data[2:])

    length=True
    ret=[]
    while length!=0:
        length=ord(name_data[0])
        if not length:
            name_data=name_data[1:] #strip off trailing null
            break
        ret+=[name_data[1:1+length]]
        name_data=name_data[1+length:]

    return (".".join(ret), name_data)

def dns_reply_parse(packet, attribs):
    """
    Attribs is a dictionary we set our gathered information into
    packet is the data after the UDP header.
    """
    total_packet=packet
    attribs["dnsreply"]=True
    if len(packet) < 12:
        devlog("sniffer", "Error: DNS packet too short")
        return False
    else:
        txid=str2int16(packet[0:2])
        attribs["txid"]=txid
        dnsflags=str2int16(packet[2:4])
        attribs["dnsflags"]=dnsflags
        question_rrs=str2int16(packet[4:6])
        attribs["question_rrs"]=question_rrs
        answer_rrs=str2int16(packet[6:8])
        attribs["answer_rrs"]=answer_rrs
        authority_rrs=str2int16(packet[8:10])
        attribs["authority_rrs"]=authority_rrs
        additional_rrs=str2int16(packet[10:12])
        attribs["additional_rrs"]=additional_rrs
        packet=packet[12:] #skip data we just parsed
        try:
            #do questions
            for question in range(question_rrs):
                name, packet=parse_dns_name(packet, total_packet)
                packet=packet[4:] #class and type ignored

            all_addresses = {}
            for answer in range(answer_rrs):
                #now packet is pointing to answer_rr's
                answer_name, packet=parse_dns_name(packet, total_packet)
                attribs["answer_name"]=answer_name
                devlog("sniffer", "Answer name: %s"%answer_name)
                dns_type = struct.unpack(">H", packet[0:2])[0]
                packet=packet[8:] #skip type,class, time to live
                datalength=str2int16(packet[:2])
                packet=packet[2:]
                addr_data=packet[:datalength]
                if dns_type == 5:
                    t_ip = str(addr_data)
                elif dns_type == 1:
                    t_ip = addr_data
                else:
                    #print "Unhandled DNS type: ", dns_type
                    continue

                attribs["answer_address"]=t_ip
                all_addresses[t_ip] = answer_name

                packet = packet[datalength:]

            attribs["all_addresses"] = all_addresses


        except IndexError:
            devlog("sniffer", "Corrupted DNS reply?")
            return False
        devlog("sniffer", "TXID: %x DNSFLAGS: %x"%(txid,dnsflags))
    return True

class packetParser:
    """ Packet parser for 802.11, ARP, ETH: IPv4,IPv6[TCP{nbt},UDP,ICMP]
    This takes in data from the sniffer, so it assumes quite low level packets.

    """

    def __init__(self, driver=None, fp=False):
        self.packet=None
        self.stats = {}
        self.reset()
        self.driver=driver
        self.offset=self.find_offset()
        self.fp_sil=fp
        self.ethernet_cache = None
        return


    def find_offset(self):
        # A driver was specified this saves a lot of processing time to init the driver here
        if self.driver:
            devlog("sniffer", "Looking for driver: "+self.driver)
            for x_data in DRIVER_80211_HDR:
                if x_data[0] == self.driver:
                    devlog("sniffer", "Found wireless driver, processing speed will now be faster")
                    return int(x_data[1])
        return 0


    def reset(self):
        self.fields = ""
        self.attribs = {}

    def setPacket(self,packet):
        """
        Return true if this was a parsed packet. We don't parse 127.0.0.1 -> 127.0.0.1
        """
        self.ethernet_cache = None
        self.packet=packet
        self.paklen = len(self.packet)

        # Make it available for both 802.11x and 802.3x
        self.fields+="packet(%s) "%packet
        self.attribs["packet"] = packet

        # Ethernet packet
        if self.isEth():
            self.attribs["layer"]="ethernet"
            self.fields+="layer(ethernet) "

            self.attribs["sniffedinfos"] = {'IP':[], 'ARP':[]}
            tret =self.ethernet()
            if(tret == False):
                return

            (offset,frommac,tomac,type) = tret
            self.attribs["frommac"]=frommac
            self.attribs["tomac"]=tomac
            self.fields+="tomac(%s) "%self.prettymac(tomac).split(" ")[0]
            self.fields+="frommac(%s) "%self.prettymac(frommac).split(" ")[0]

            self.attribs["ethtype"] = self.ethtype(type)

            devlog("sniffer", "SMAC: "+ self.prettymac(frommac) + " DMAC: "+ self.prettymac(tomac) + " ETHTYPE: "+ str(type), fp=self.fp_sil)


            if type == ETHTYPE['ARP']:
                t = self.ARP()

                self.fields+="type(ARP) "
                self.attribs["type"]="ARP"
                if t:
                    arptype = int(t[0])
                    self.fields+="arptype(%d) "%arptype
                    self.attribs["arptype"] = arptype

                    srcip = socket.inet_ntoa(struct.pack(">L", t[1]))
                    self.fields+="srcip(%s) "%srcip
                    self.attribs["srcip"] = srcip

                    dstip = socket.inet_ntoa(struct.pack(">L", t[2]))
                    self.fields+="dstip(%s) "%dstip
                    self.attribs["dstip"] = dstip

                    devlog("sniffer", "type: ARP SRCIP: "+ srcip + " DSTIP: "+ dstip + " ARPTYPE: "+ str(arptype), fp=self.fp_sil)


            elif type == ETHTYPE['IP']:

                t = self.IPv4()
                self.fields+="type(ETH) "
                self.attribs["type"]="ETH"

                if not t:
                    return None
                (offset,source,dest,protocol,ttl) = t

                #If you reject localhost packets you can't udpportscan
                #localhost, annoyingly. How much does this slow us down?
                #a lot - because this would mean we look at every outgoing
                #packet?
                if source=="127.0.0.1" or dest=="127.0.0.1":
                    devlog("sniffer", "Rejecting localhost packets")
                    return None

                self.attribs["ipsource"]=source
                self.fields+="ipsource(%s) "%source
                self.attribs["ipdest"]=dest
                self.fields+="ipdest(%s) "%dest
                self.attribs["ipproto"]=protocol
                self.fields+="ipproto(%s) "%protocol
                self.fields+="ipttl(%s) "%ttl
                self.attribs["ipttl"]=ttl
                devlog("sniffer", "type: IPV4 SRCIP: "+ source +" DSTIP: "+ dest + " IPPROTO: "+ str(protocol) + " TTL: "+ str(ttl), fp=self.fp_sil)
                ipsource = source
                ipdest = dest

                if protocol=="TCP":
                    t_r=self.TCP(offset=offset)
                    if not t_r:
                        return None
                    (offset,source,dest,flags,chksum) = t_r
                    #print "TCP: SourcePort(%d) DestPort(%d)"%(source,dest)
                    self.attribs["tcpsport"]=source
                    self.fields+="tcpsport(%s) "%source

                    self.attribs["tcpdport"]=dest
                    self.fields+="tcpdport(%s) "%dest

                    self.attribs["tcpcsum"]=chksum
                    self.fields+="tcpcsum(%s) "%chksum


                    self.attribs["tcpflags"]=[]
                    for key in TCPFLAGS:
                        if ord(flags) & key:
                            flag=TCPFLAGS[key]
                            self.fields+="tcpflags(%s) "%flag
                            self.attribs["tcpflags"]+=["%s"%flag]

                    self.tcpbody=self.packet[offset:]
                    self.attribs["tcpbody"]=self.tcpbody
                    self.fields+="tcpbody(%s) "%self.tcpbody

                    devlog("sniffer", "type: TCP SRCPORT: "+ str(source) + " DSTPORT: "+ str(dest), fp=self.fp_sil)


                if protocol == "UDP":
                    try:
                        (offset, source, dest) = self.UDP(offset=offset)
                    except struct.error, e:
                        devlog('corrupt UDP packet: %s' % repr(packet))
                        return None

                    self.udpdatax = self.packet[offset:]
                    self.attribs["udpsource"] = source
                    self.attribs["udpdest"]   = dest
                    self.attribs["udpdata"]  = self.udpdatax
                    self.fields+="udpsource(%s) "%source
                    self.fields+="udpdest(%s) "%dest
                    self.fields+="udpdata(%s) "%self.udpdatax

                    devlog("sniffer", "type: UDP SRCPORT: "+ str(source) + " DSTPORT: "+ str(dest), fp=self.fp_sil)
                    if self.is_nbHostAnnounce():
                        devlog("sniffer", " HOST ANNOUNCEMENT", fp=self.fp_sil)
                        upint = self.get_nbUpdatePeriod()
                        if self.nbMatchIntervals(upint):
                            nbname = self.get_nbName()
                            nbcomment = self.get_nbComment()
                            devlog("sniffer", " Name: "+ nbname +" Comment: "+nbcomment, fp=self.fp_sil)
                            self.attribs["nbname"] = nbname
                            self.fields+="nbname(%s) "%nbname
                            self.attribs["nbcomment"] = nbcomment
                            self.fields+="nbcomment(%s) "%nbcomment
                            #print "Windows Machine: IP:", ipsource, "Name: ", nbname, "Comment: ", nbcomment
                    elif source==53:
                        devlog("sniffer", "Parsing UDP packet as DNS reply")
                        dns_reply_parse(self.udpdatax, self.attribs)



                if protocol == "ICMP":
                    (offset, type, code, identifier, seqnum) = self.ICMP(offset=offset)
                    self.attribs["icmptype"]       = type
                    self.attribs["icmpcode"]       = code
                    self.attribs["identifier"] = identifier
                    self.attribs["seqnum"]     = seqnum
                    self.attribs["icmpdata"]   = self.packet[offset:]
                    self.fields+="icmpsource(%s) "%source
                    self.fields+="icmptype(%s) "%type
                    self.fields+="icmpcode(%s) "%code

                    devlog("sniffer", "type: ICMP CODE: "+ str(code), fp=self.fp_sil)


            elif type == ETHTYPE['IPv6']:

                t = self.IPv6()
                if not t:
                    return None
                (offset,source,dest,protocol) = t
                self.attribs["ipsource"]=source
                self.fields+="ipsource(%s) "%source
                self.attribs["ipdest"]=dest
                self.fields+="ipdest(%s) "%dest
                self.fields+="ip(%s) "%source
                self.fields+="ip(%s) "%dest
                self.attribs["ipproto"]=protocol
                self.fields+="ipproto(%s) "%protocol
                devlog("sniffer", "type: IPV6", fp=self.fp_sil)



        # Layer I - 802.11 packet
        elif self.is_80211():
            self.attribs["layer"]="80211"
            self.fields+="layer(80211) "

            try:
                self.fields+="type(80211) "
                self.attribs["type"]="80211"

                subtype = self.get_80211_type()

                # Iterate for the subtypes we know
                for st in SUBTYPE_80211:
                    if SUBTYPE_80211[st] == subtype:
                        self.fields+="subtype(0x%x) "%subtype
                        self.attribs["subtype"]=subtype

                        subd = subtype&0xf
                        self.fields+="subtyped(0x%x) "%subd
                        self.attribs["subtyped"]=subd

                        encr    = self.check_80211_enc()
                        self.fields+="encryption(%s) "%(str(encr))
                        self.attribs["encryption"]=encr

                        fromtods = self.get_80211_fromtods()
                        self.fields+="fromtods(0x%x) "%fromtods
                        self.attribs["fromtods"]=fromtods


                        statc = self.get_80211_status_code(st)
                        if statc != -1:
                            devlog("sniffer", "STATUS-CODE: "+str(hex(statc)))
                            self.fields+="status-code(0x%x) "%statc
                            self.attribs["status-code"]=statc

                        devlog("sniffer", "Subtype: "+ str(hex(subtype))+" Encrypted: "+ str(encr) + " Size: "+ str(self.paklen))

                        (smac, bssid, dmac) = self.get_80211_addrs(st, fromtods)

                        if smac:
                            devlog("sniffer", "SMAC: "+smac)
                            self.fields+="smac_80211(%s) "%smac
                            self.attribs["smac_80211"]=smac

                        if bssid:
                            devlog("sniffer", "BSSID: "+bssid)
                            self.fields+="bssid(%s) "%bssid
                            self.attribs["bssid"]=bssid

                        if dmac:
                            devlog("sniffer", "DMAC: "+dmac)
                            self.fields+="dmac_80211(%s) "%dmac
                            self.attribs["dmac_80211"]=dmac

                        if encr:
                            encr_type = self.get_80211_enc_type(st)
                            iv        = self.get_80211_iv(encr_type, st)

                            self.fields+="iv(0x%x) "%iv
                            self.attribs["iv"]=iv

                            devlog("sniffer", "EncrType: %s IV: 0x%x"%(encr_type,iv))

                            if encr_type == "WEP":

                                icv     = self.get_80211_icv()
                                devlog("sniffer", "ICV: 0x%x"%icv)

                                self.fields+="icv(0x%x) "%icv
                                self.attribs["icv"]=icv

                                # Currently only for WEP
                                enc_payload = self.get_80211_enc_payload(encr_type)
                                self.attribs["enc_payload"]=enc_payload

                                if self.check_80211_arp(st):

                                    self.fields+="potencr(ARP) "
                                    self.attribs["potencr"]="ARP"

                                    if self.is_80211_arpreq(dmac):
                                        ttbuf = "ARP-REQUEST"
                                    else:
                                        ttbuf = "ARP-REPLY"

                                    self.fields+="potarptype(%s) "%ttbuf
                                    self.attribs["potarptype"]=ttbuf

                                    devlog("sniffer", "Potentially encrypted "+ttbuf+" packet")

                                    if ttbuf == "ARP-REQUEST":
                                        # This could be useful for re-injection
                                        self.fields+="arpreqp(%s) "%self.packet
                                        self.attribs["arpreqp"]=self.packet

                                    potpayload = self.get_80211_arpayload(subtype)
                                    self.fields+="potarpayload(%s) "%potpayload
                                    self.attribs["potarpayload"]=potpayload


                        # Check if its an EPOL packet
                        if self.is_80211_epol(st):
                            self.fields+="xauth(EPOL) "
                            self.attribs["xauth"]="EPOL"

                            nonce = self.get_80211_nonce()
                            self.attribs["nonce"]=nonce

                            eapolsize = self.get_80211_eapol_size()
                            self.attribs["eapolsize"]=eapolsize

                            eapol = self.get_80211_eapol()
                            self.attribs["eapol"]=eapol

                            wpaver = self.get_80211_wpaver(eapol)
                            self.fields+="wpaver(%d) "%wpaver
                            self.attribs["wpaver"] = wpaver

                            mic = self.get_80211_mic()
                            self.attribs["mic"]=mic

                            repcount = self.get_80211_repcount()
                            self.attribs["repcount"]=repcount

                            repcountbuf = self.get_80211_repcountbuf()
                            self.attribs["repcountbuf"]=repcountbuf

                            devlog("sniffer", "WPAVER: %d NONCE: %r, MIC: %r"%(wpaver, nonce, mic))


                        # Extract some further details from specific packets
                        if (st == "BECON" or self.has_hidden_ssid(st)) and not encr:
                            bret = self.LAYERI80211_BECON(st)
                            if bret:
                                bessid = bret[2]
                                self.fields+="bessid(%s) "%bessid
                                self.attribs["bessid"]=bessid
                                devlog("sniffer", "BESSID: "+ bessid)

                                # For becon packets we get more stuff
                                if st == "BECON":

                                    bcapainfo = bret[3]
                                    self.fields+="bcapainfo(0x%x) "%bcapainfo
                                    self.attribs["bcapainfo"]=bcapainfo
                                    devlog("sniffer", "BCOMPINFO: "+ str(bcapainfo))

                                    btagparam = bret[4]
                                    self.fields+="tagparam(%s) "%btagparam
                                    self.attribs["tagparam"]=btagparam

                        if st == "AUTH":
                            auth_seq = self.get_80211_auth_seq()
                            self.fields+="auth_seq(%d) "%auth_seq
                            self.attribs["auth_seq"]=auth_seq
                            devlog("sniffer", "AUTHSEQ: "+ str(auth_seq))

                            auth_algo = self.get_80211_auth_algo()
                            self.fields+="auth_algo(%d) "%auth_algo
                            self.attribs["auth_algo"]=auth_algo
                            devlog("sniffer", "AUTHALGO: "+ str(auth_algo))

                            # This potentially indicates a 3way handshake challenge exchange
                            if auth_seq == 2:
                                auth_challenge = self.get_80211_auth_challenge(auth_seq)
                                self.attribs["auth_challenge"]=auth_challenge

                                auth_challenge_size = self.get_80211_auth_challenge_size()
                                self.attribs["auth_challenge_size"]=auth_challenge_size
                                devlog("sniffer", "AUTH CHALLENGE SIZE: "+ str(auth_challenge_size))

                                auth_challenge_payload = self.get_80211_auth_challenge_payload()
                                self.attribs["auth_challenge_payload"]=auth_challenge_payload

                                # Get broken payload response for windows machines that do not honor the size pkt header value
                                auth_challenge_payload_broken = self.get_80211_auth_challenge_payload_broken()
                                self.attribs["auth_challenge_payload_broken"]=auth_challenge_payload_broken


            except Exception:
                import traceback
                traceback.print_exc(file=sys.__stdout__)
                traceback.print_exc(file=sys.__stderr__)

        else:
            devlog("sniffer", "Unknown packet"+  repr(self.packet))

        return True


    # Check to see if its an 802.11 layer I packet
    def is_80211(self):
        # Driver was specified skip some tests to optimize for speed
        if self.driver:
            if self.is_known_80211_subtype(self.offset):
                return True
            else:
                return False

        # No driver was specified :( this will run slower
        else:
            devlog("sniffer", "No wireless driver was specified prepare to waste time and packets")
            # Check for fingerprints to identify radiotap header
            for x_data in DRIVER_80211_HDR:
                chk_len = int(x_data[1])
                fingerprint_80211 = x_data[2]
                if(self.paklen>chk_len):
                    pkthdr = struct.unpack(">"+str(len(fingerprint_80211))+"s", self.packet[:len(fingerprint_80211)])
                    if(fingerprint_80211 == pkthdr[0]):
                        self.offset = chk_len
                        devlog("sniffer", "Driverdetect: found wireless driver "+x_data[0])
                        return True

            devlog("sniffer", "No radiotap header found or not an 802.11 packet")

            # If there is no magic radiotap header here we try to see if the packet
            # has a known subtype code and if so we process it
            if(self.is_known_80211_subtype(0)):
                self.offset = 0
                return True

        return False


    # Check if the subtype is a known 80211 packet
    def is_known_80211_subtype(self, offset):
        if self.paklen > offset:
            subt = struct.unpack(">B", self.packet[offset])[0]
            for x in SUBTYPE_80211:
                if subt == SUBTYPE_80211[x]:
                    return True
        else:
            devlog("sniffer", "Packet too short to read subtype")
            return False


    # Get the 80211 subtype
    def get_80211_type(self):
        if(self.paklen>(1+self.offset)):
            return struct.unpack(">B", self.packet[self.offset])[0]
        return False


    # Get encryption type
    def get_80211_enc_type(self, st):
        return "WEP"
        #encr = "WEP"

        #enoff = 27
        #if st=="QOSDATA":
        #    enoff+=2

        #byt = struct.unpack(">B", self.packet[self.offset+enoff])[0]
        #byt1 = struct.unpack(">B", self.packet[self.offset+(enoff-1)])[0]

        # Mask out 2 least significant bits which contain the key (11111100)
        #if byt & 0xfc:
        #    if byt1:
        #        encr = "TKIP"
        #    else:
        #        encr = "CCMP"

        #return encr


    # Gets fromtods field to rearrane mac headers
    def get_80211_fromtods(self):
        if self.paklen<0x18:
            return False
        return (ord(self.packet[1])&3)


    # Get WEP Encrypted packet payload past the IV excluding the ICV
    def get_80211_enc_payload(self, encr_type):
        if encr_type == "WEP":
            if self.paklen>0x1c:
                return self.packet[0x1c:]
        return False


    # Get IV from packet
    def get_80211_iv(self, encr, st):
        lower_lim = 24+self.offset
        if st == "QOSDATA":
            lower_lim+=2
        upper_lim = lower_lim + 3

        if encr != "WEP":
            upper_lim += 5

        if(self.paklen>upper_lim):
            # CCMP & TKIP use 8byte long IV
            if encr != "WEP":
                return struct.unpack(">Q", self.packet[lower_lim:upper_lim])[0]
            else:
                return int(struct.unpack(">L", self.packet[lower_lim-1:upper_lim])[0])&0x00ffffff

        return False

    # Get wpa version from packet
    def get_80211_wpaver(self, eapol):
        if len(eapol)<6:
            return False
        return (ord(eapol[6])&7)


    # Get EAPOL size
    def get_80211_eapol_size(self):
        if self.paklen<0x23:
            return False

        return int((ord(self.packet[0x22])<<8) + ord(self.packet[0x23]) + 4)

    # Get EAPOL
    def get_80211_eapol(self):
        if self.paklen<32:
            return False
        eapolsize = self.get_80211_eapol_size()
        if not eapolsize:
            return False
        return self.packet[32:(eapolsize+32)]


    # Get Nonce from packet
    def get_80211_nonce(self):
        if self.paklen<0x50:
            return False

        return struct.unpack(">32s", self.packet[0x31:0x51])[0]


    # Get replay counter from EPOL packet
    def get_80211_repcount(self):
        if self.paklen<0x30:
            return False
        return (ord(self.packet[0x30]))


    # Get 8byte replay counter buffer from EPOL
    def get_80211_repcountbuf(self):
        if self.paklen<0x31:
            return False
        return self.packet[0x29:0x31]

    # Get MIC from packet
    def get_80211_mic(self):
        if self.paklen<0x81:
            return False

        return struct.unpack(">16s", self.packet[0x71:0x81])[0]


    # Checks if the packet is of EPOL type
    def is_80211_epol(self, st):
        if (self.paklen < 0x3a) or st != "DATA":
            return False
        magic_lll = "\xaa\xaa\x03\x00\x00\x00\x88\x8e"
        logic_link_control = struct.unpack(">8s", self.packet[0x18:0x20])[0]
        if magic_lll == logic_link_control:
            return True
        return False


    # Get potential arp packet payload
    def get_80211_arpayload(self, st):
        # driver header + 802.11 header + wep iv
        lower_lim = self.offset+28
        if st == "QOSDATA":
            lower_lim+=2
        upper_lim = lower_lim+16
        if self.paklen >= upper_lim:
            return self.packet[lower_lim:upper_lim]
        else:
            return ""

    # Get ICV from packet
    def get_80211_icv(self):
        return int(struct.unpack(">L", self.packet[-4:])[0])


    # Check if packet is encrypted
    def check_80211_enc(self):
        if(self.paklen>(27+self.offset)):
            flags = struct.unpack(">B", self.packet[self.offset+1])[0]
            # Mask out the WEP bit in the flags
            if flags & 0x40 == 0x40:
                return True
        return False


    # Gets an authentication sequence number from packet
    def get_80211_auth_seq(self):
        if self.paklen>0x1a:
            return ord(self.packet[0x1a])
        return 0

    # Gets the authentication algorithm used 0: open, 1: shared
    def get_80211_auth_algo(self):
        if self.paklen>0x18:
            return ord(self.packet[0x18])
        return False


    # Gets an authentication challenge string from packet
    def get_80211_auth_challenge(self, seq):
        rd_size = self.get_80211_auth_challenge_size()+0x20
        # only the second packet in the sequence has the challenge string
        if (seq == 2) and (self.paklen>=rd_size):
            return self.packet[0x20:rd_size]
        return False

    # Gets the payload for the challenge text
    def get_80211_auth_challenge_payload(self):
        start_offset = 0x18 #everything from the start of the wireless management frame
        end_offset   = self.get_80211_auth_challenge_size()+0x20 # everything up to the end of the challenge text
        if self.paklen>=end_offset:
            return self.packet[start_offset:end_offset]
        return False

    # This function is for buggy windows hosts that do not check the size of the challenge
    def get_80211_auth_challenge_payload_broken(self):
        start_offset = 0x18 #everything from the start of the wireless management frame
        if self.paklen>start_offset:
            return self.packet[start_offset:]
        return False


    # Gets the authentication challenge size
    def get_80211_auth_challenge_size(self):
        if self.paklen > 0x1f:
            return ord(self.packet[0x1f])
        return False

    # Check if encrypted packet is potentially an ARP
    def check_80211_arp(self, st):
        dedct = self.paklen-self.offset
        if ((st == "QOSDATA") and ((dedct == 0x46) or (dedct == 0x58))) or ((st == "DATA") and ((dedct == 0x44) or (dedct == 0x56))):
            return True
        return False


    # Check if the encrypted packet is potentially an ARP request (otherwise assume arp reply)
    def is_80211_arpreq(self, dst):
        if dst == "FF:FF:FF:FF:FF:FF":
            return True
        return False

    # check if packet has BSSID and SRCMAC
    def has_80211_srcifo(self, subt):
        if subt in [ "RTS", "CTS", "ACK" ]:
            return False
        return True


    # Gets the addresses from the frame header
    def get_80211_addrs(self, st, fromtods):

        dmac = self.get_80211_dst_mac()

        # some packets do not provide a source or bssid
        if self.has_80211_srcifo(st):

            smac = self.get_80211_src_mac()
            bssid = self.get_80211_bssid()

            # currently we get first d then s then b
            # dsb = 0 this is our default dont do anything
            # dbs = 2
            # bsd = 1
            # we need bsd so swap b with d
            if fromtods == 1:
                bssid, dmac = dmac, bssid
            # we need dbs so swap s with b
            elif fromtods == 2:
                smac, bssid = bssid, smac

        else:
            smac = bssid = False

        return (smac, bssid, dmac)


    # Read the destination mac address
    def get_80211_dst_mac(self):
        return self.get_80211_mac(4+self.offset)

    # Read the source mac address
    def get_80211_src_mac(self):
        return self.get_80211_mac(10+self.offset)


    # Read the bssid mac address
    def get_80211_bssid(self):
        return self.get_80211_mac(16+self.offset)


    # Get a mac address at offset
    def get_80211_mac(self, offset):
        if(self.paklen>=(offset+6)):
            mac = struct.unpack(">6s", self.packet[offset:offset+6])
            mac = mac[0]
            rmac = "%02X:%02X:%02X:%02X:%02X:%02X"%(ord(mac[0]),ord(mac[1]),ord(mac[2]),ord(mac[3]),ord(mac[4]),ord(mac[5]))
            return rmac

        devlog("sniffer", "We failed for packet: "+repr(self.packet)+ " offset was: "+ str(offset) +"length of packet was: "+ str(self.paklen))

        return False


    # Get capability information from BECON packet
    def get_80211_capability_info(self):
        lower = 0x22+self.offset
        upper = lower + 2
        if self.paklen >= upper:
            ret = struct.unpack(">h", self.packet[lower:upper])
            return int(ret[0])
        else:
            return 0


    # Get status code from authentication and association frames
    def get_80211_status_code(self, st):
        check = False

        # authentication frame
        if st == "AUTH":
            lower = 0x1c+self.offset
            upper = lower+2
            check = True

        # association response frame
        elif st == "ASSOCIATION_RESPONSE":
            lower = 0x1a+self.offset
            upper = lower + 2
            check = True

        if check and (self.paklen >= upper):
            return int(struct.unpack(">h", self.packet[lower:upper])[0])
        return -1


    # Get tagged parameters from BECON packet
    def get_80211_tagged_parameters(self):
        if self.paklen >= (self.offset+0x1c):
            lower = 0x24+self.offset
            return self.packet[lower:]
        else:
            return ""


    # Get some data from packet (this does not only apply to becon packets
    def LAYERI80211_BECON(self, st):

        if st == "ASSOCIATION":
            curoffset = self.offset-8
        else:
            curoffset = self.offset

        if(self.paklen>=(38+curoffset)):
            ssid_size = struct.unpack(">B", self.packet[37+curoffset])
            ssid_size=int(ssid_size[0])
            upper_lim = 38+ssid_size+curoffset
            lower_lim = 38+curoffset
            if(self.paklen>=upper_lim):
                ssid = struct.unpack(">"+ str(ssid_size) + "s", self.packet[lower_lim:upper_lim])
                smac = self.get_80211_src_mac()
                dmac = self.get_80211_dst_mac()
                cifo = self.get_80211_capability_info()
                tagp = self.get_80211_tagged_parameters()
                return (smac, dmac, ssid[0], cifo, tagp)
            #else:
            #    print "2-Packet size: ", len(self.packet), "offset: ", curoffset, "upper_lim:", upper_lim, "ssid_size:", ssid_size, "lower_lim:", lower_lim, "packet: ", self.hex_dump(self.packet)

        # The wireless driver in Monitor mode by nokia800 is known to corrupt the data past the MAC/LLC part so packets may come in scrambled
        # previous firmware flush corrupted the payload of the SSID header fields, associated with the scan module this should be revealed
        #else:
        #    devlog("sniffer", "Packet size: "+ str(len(self.packet)), "Offset: "+ str(self.offset) +"Size offset failed for: "+ str(self.hex_dump(self.packet)))


        return False


    # hex dumps a packet
    def hex_dump(self, p):
        count=0
        for x in p:
            print "["+ hex(ord(x)) +"]", count,
            count+=1
        return


    # Check is the packet subtype contains a hidden ssid
    def has_hidden_ssid(self, st):

        # Packets that will reveal our hidden ssid
        pkts = [ "ASSOCIATION", "REASSOCIATION", "PROBE_RESPONSE" ]

        if st in pkts:
            return True

        return False



    def ethtype(self, type):
        for key in ETHTYPE.keys():
            if ETHTYPE[key] == type:
                return key
        return "unknown (0x%04x)" % type

    def getline(self):
        """
        Suitable for a tcpdump like output
        """
        return self.fields



    # checks if packet is of ethernet type
    def isEth(self):
        # we need at least the MAC header
        if(self.paklen<15):
            devlog("sniffer", "Small packet not of ethernet type")
            return False

        type = struct.unpack("H", self.packet[12:14])[0]

        # Currently we only parse ARP and ETH packets
        if(type == 8 or type == 1544):
            devlog("sniffer", "Found ethernet type packet")
            return True

        return False


    # Check if its a netbios host announcement packet
    def is_nbHostAnnounce(self):
        if self.paklen>0xd2 and ord(self.packet[0xd2])==1:
            return True

        return False


    # Finds the update interval in the host announcement packet
    def get_nbUpdatePeriod(self):
        if self.paklen > 218:
            return self.packet[212:216]
        return False


    # Finds the netbios name of a host
    def get_nbName(self):
        if self.paklen > 0xe7:
            return self.packet[0xd8:0xe7]
        return False


    # Find the comment of the host
    def get_nbComment(self):
        if self.paklen > 0xf2:
            return self.packet[0xf2:]
        return False


    # Match time interval
    def nbMatchIntervals(self, tval):
        time_ints = [ "\x80\xfc\x0a\x00" ] #12m XPSP0-2
        for time_int in time_ints:
            if time_int == tval:
                return True
        return False


    def ethernet(self):
        if self.ethernet_cache:
            return self.ethernet_cache
        p=self.packet
        if len(p)<15:
            devlog("sniffer", "Ethernet packet header is too small, not processing")
            return False

        (tomac, frommac, typeofpacket) = struct.unpack(">6s6sH", p[:14])
        self.addsniffARP(self.macstring(tomac))
        self.addsniffARP(self.macstring(frommac))
        bodyoffset=14
        self.ethernet_cache = (bodyoffset,frommac,tomac,typeofpacket)
        return self.ethernet_cache

    def IP(self):
        ethhdr = self.ethernet()
        if ethhdr[3] == ETHTYPE['IP']:
            return self.IPv4()
        elif ethhdr[3] == ETHTYPE['IPv6']:
            return self.IPv6()
        else:
            devlog('sniffer::IP', "ethernet type: %s 0x%04x" % (self.ethtype(ethhdr[3]), ethhdr[3]))
            return None

    def IPv4(self):
        ethhdr = self.ethernet()
        if ethhdr[3] != ETHTYPE['IP']:
            devlog('sniffer::IPv4', "wrong ethernet type: 0x%04x" % ethhdr[3])
            return None

        offset=ethhdr[0]
        p=self.packet[offset:]
        if len(p)<20:
            print "[BUGBUG] Length of IP packet is %d"%len(p)
            return None #(0,"AAAA","BBBB",1)

        (version_hdrlen, differentiatedServicesField, totalLength, identification, \
         flags_fragoff, TTL, protocol, checksum, source, dest) = struct.unpack(">BBHHHBBHLL", p[:20])
        self.attribs["ip_differentiatedServicesField"]=differentiatedServicesField
        self.attribs["ip_ttl"]=TTL
        # we don't need to unpack that
        if version_hdrlen != 0x45:
            devlog('sniffer::IPv4', "broken packet (version:0x%x, header len:%d)" % \
                   (version_hdrlen >> 4, version_hdrlen & 0xf))
            return None

        if protocol in IPPROTO.keys():
            protocol = IPPROTO[protocol]
        else:
            protocol = "IPPROTO%02d" % protocol

        old_source=source
        source = self.longIP2host(source)
        dest = self.longIP2host(dest)
        devlog("sniffer","Adding sniffed source IP %s"%source)
        self.addsniffIP(source)
        self.addsniffIP(dest)
        bodyoffset=offset+20
        return (bodyoffset,source,dest,protocol,TTL)

    def IPv6(self):
        ethhdr = self.ethernet()
        if ethhdr[3] != ETHTYPE['IPv6']:
            devlog('sniffer::IPv6', "wrong ethernet type: 0x%04x" % ethhdr[3])
            return None

        offset=ethhdr[0]
        p=self.packet[offset:]

        (version_class_flow, payload_length, hdrtype, hoplim, src, dst) = struct.unpack(">LHBB16s16s", p[:40])
        version = version_class_flow >> 28
        if version != 6:
            devlog('sniffer::IPv6', "wrong version %d" % version)
            return None

        # TODO
        return (offset + 40, src, dst, hdrtype)

    def TCP(self,offset=None):
        self.updatestats('IPv4', 'TCP')
        if offset==None:
            t = self.IP()
            if not t:
                return
            offset = t[0]
        p=self.packet[offset:]

        try:
            (sourcePort, destPort, sequenceNumber, ackNum, header_len,flags, window, checksum, urg) =  struct.unpack(">HHLLBBHHH", p[:20])
        except struct.error:
            return False

        #set all the attributes
        self.attribs["tcp_source_port"]=sourcePort
        self.attribs["tcp_dest_port"]=destPort
        self.attribs["tcp_sequence_number"]=sequenceNumber
        self.attribs["tcp_ack_num"]=ackNum
        self.attribs["tcp_flags"]=flags
        self.attribs["tcp_window"]=window
        self.attribs["tcp_urg"]=urg
        self.attribs["tcp_checksum"]=checksum
        #now set the fields which are used for the sniffer callback filters
        self.fields+="tcp_source_port(%d) tcp_dest_port(%d) "%(sourcePort, destPort)
        headerLength = flags >> 10
        flags = chr(flags & 0xff) # should not be a char...
        #should validate checksum
        #options parser
        options=[]
        for i in range(20,headerLength):
            #print i
            options+=p[i]
        bodyoffset=offset+headerLength
        return (bodyoffset,sourcePort,destPort,flags,checksum)

    def UDP(self, offset=None):
        self.updatestats('IPv4', 'UDP')
        p = self.packet[offset:]
        (sourcePort, destPort, UDPlength, checksum) = struct.unpack(">HHHH", p[:8])
        return (offset+8, sourcePort, destPort)

    def ICMP(self, offset=None):
        self.updatestats('IPv4', 'ICMP')
        p = self.packet[offset:]
        (type, code, checksum, identifier, seqnum) = struct.unpack(">BBHHH", p[:8])
        return (offset + 4, type, code, identifier, seqnum)

    def macstring(self, macaddr):
        assert len(macaddr) == 6, "mac addr string has %d chars" % len(macaddr)
        macstr = ""
        for i in range(0, 6):
            if i: macstr += ":"
            macstr += "%02X" % ord(macaddr[i])
        return macstr

    def prettymac(self, macaddr):
        """
        MACresolve is a very slow function, so THIS is a very slow function
        """
        buf = self.macstring(macaddr)
        #this module-wide flag is used to determine if we should run this slow little
        #function
        if resolve_mac_addresses:
            compname = MACresolve(macaddr)
            if compname:
                buf += " (%s)" % compname
        return buf

    def prettyprint(self):
        (offset,frommac,tomac,type)=self.ethernet()
        print "Ethernet (type 0x%04x):" % type
        print "From MAC=%s" % self.prettymac(frommac)
        print "To MAC=%s" % self.prettymac(tomac)

        if not type in [ETHTYPE['IP'], ETHTYPE['IPv6']]:
            return

        t = self.IP()
        if not t:
            return
        (offset,source,dest,protocol) = t
        print "IP: Source=%s Dest=%s Protocol=%s" % (source, dest, protocol)
        if protocol=="TCP":
            t_r=self.TCP()
            if not t_r:
                return
            (offset,source,dest,flags,checksum) = t_r

            print "TCP: SourcePort(%d) DestPort(%d)"%(source,dest)
            for key in TCPFLAGS:
                if ord(flags) & key:
                    print TCPFLAGS[key],

        elif protocol=="UDP":
            pass
        elif protocol=="ICMP":
            pass
        else:
            print "Protocol not recognized"

        if offset!=self.paklen:
            data=self.packet[offset:]
            for i in range(0,len(data),8):
                line=data[i:i+8]
                for c in line:
                    print "%2.2x"%ord(c),
                print " "*(40-len(line)*3),
                for c in line:
                    print "%s"%(prettyprint(c)),
                print ""
        print ""
        return

    def ARP(self):
        ARP_REQUEST = 0x0001
        ARP_REPLY =   0x0002

        self.updatestats('ARP')
        p = self.packet[14:]
        (hwtype, prototype, hwsize, protosize, opcode) = struct.unpack(">HHBBH", p[:8])
        if hwtype != 0x0001 or hwsize != 6: # Ethernet
            return
        if prototype != 0x0800 or protosize != 4: # IP
            return
        if opcode == ARP_REQUEST or opcode == ARP_REPLY:
            (senderMAC, senderIP, targetMAC, targetIP) = struct.unpack(">6sL6sL", p[8:28])
            self.addsniffARP(self.macstring(senderMAC))

            devlog("sniffer", "Adding sniffed sender ip: %s"% self.longIP2host(senderIP))
            self.addsniffIP(senderIP)
            if opcode == ARP_REPLY:
                self.addsniffARP(self.macstring(targetMAC))
                self.addsniffIP(targetIP)
        else:
            devlog("sniffer", "Not sure of opcode for ARP packet: %s"%opcode)


        return [opcode, senderIP, targetIP]


    def addsniffinfos(self, key, info):
        devlog("sniffer","Add sniff info: %s %s"%(key, info))
        sniffedinfos = self.attribs["sniffedinfos"]
        if not sniffedinfos.has_key(key):
            sniffedinfos[key] = []
        if not info in sniffedinfos[key]:
            sniffedinfos[key] += [info]
        return

    def addsniffIP(self, ip):
        if not type(ip) == type(""):
            ip = self.longIP2host(ip)
        self.addsniffinfos('IP', ip)

    def addsniffARP(self, arp):
        self.addsniffinfos('ARP', arp)

    def longIP2host(self, longIP):
        return socket.inet_ntoa(int2str32(longIP))

    def updatestats(self, type, proto="ALL"):
        if not self.stats.has_key(type):
            self.stats[type] = {proto: 1}
        elif not self.stats[type].has_key(proto):
            self.stats[type][proto] = 1
        else:
            self.stats[type][proto] += 1

    def dispstats(self):
        if self.stats == {}:
            devlog('packetParser::stats', "sniffer didn't sniff anything")
            return
        devlog('packetParser::stats', "%s %s" % (self.stats, self.stats.keys()))
        print "\n------------------------\npacket parser statistics\n------------------------"
        for type in self.stats.keys():
            devlog('packetParser::stats', "type: %s, keys: %s" % (type, self.stats[type].keys()))
            if self.stats[type].keys() == ["ALL"]:
                devlog('packetParser::stats', "ALL, values: %s" % self.stats[type].values())
                print "  %s packets sniffed: %d" % (type, self.stats[type]['ALL'])
            else:
                for proto in self.stats[type].keys():
                    print "  %s:%s packets sniffed: %d" % (type, proto, self.stats[type][proto])
                print "  %s total: %d" % (type, sum(self.stats[type].values()))


def checksum(str):
    """
    Generate checksum for packets you send by hand
    """
    #pad to 16 bit length
    if len(str)%2!=0:
        str+="\x00"

    sum=0
    countTo=(len(str)/2)*2
    count=0
    while (count < countTo):
        thisVal=nstr2halfword(str[count:count+2])
        sum=sum+thisVal
        sum=sum & 0xffffffffL # Necessary?
        count=count+2

    #print "sum: %8x"%sum

    top=(sum & 0xffff0000L) >> 16
    bottom=sum & 0x0000ffff
    sum=top+bottom
    #sum=sum+(sum >> 16)+(sum &0xffff)
    #print "top: %8x bottom: %8x sum: %8x"%(top,bottom,sum)
    while (sum>>16):
        sum= (sum & 0xffff) + (sum >> 16)
    answer=~sum
    answer=answer & 0xffff
    #answer=answer >> 8 | (answer << 8 & 0xff00)
    return answer


def dns_name_encode(name):
    """
    Take a name and encode it in the way dns will expect
    """
    ret=""
    splitme=name.split(".")
    for astr in splitme:
        ret+=chr(len(astr))+astr
    if ret[-1]!="\x00":
        ret+="\x00" #null terminate
    return ret

class packetConstructor:
    """
    Constructs simple TCP/UDP/ICMP packets for use by CANVAS modules
    Use sender to send this out
    """
    def __init__(self):
        self.clear()

    def clear(self):
        self.buffer=""

    # from SILICA/CODE/arppacket.py
    def mac2nbo(self, mac):
        if len(mac)==6:
            #not a string, just the hardware address we already need!
            return mac
        nmac = mac.split(":")
        if(len(nmac)!=6):
            print "Invalid MAC: ", mac
            return False

        for x in range(0, len(nmac)):
            nmac[x] = int(nmac[x], 16)

        return struct.pack("BBBBBB", nmac[0], nmac[1], nmac[2], nmac[3], nmac[4], nmac[5])



    # Heavily borrowed from SILICA/CODE/arppacket.py
    def Ethernet( self, srcmac, dstmac, ethtype):

        srcmac = self.mac2nbo(srcmac)

        if(dstmac == "00:00:00:00:00:00"):
            dstmac = "ff:ff:ff:ff:ff:ff"
        dstmac = self.mac2nbo(dstmac)

        if(srcmac==False or dstmac==False):
            return False

        ether_frame = struct.pack(">6s6sH", dstmac, srcmac, ETHTYPE[ethtype])
        self.buffer += "".join( ether_frame )

        return


    def IP( self, srcaddress, dstaddress, data, ttl = 64, protocol = "UDP", ipid=0x1234, flags=0x00, tos=0x00 ):
        """
        Creates the IP header and includes whatever data you want.
        """
        ip_packet = []

        # Version (4bits) Headersize(4bits)
        ip_packet += ["\x45"]
        # TOS (8bits)
        ip_packet += [chr(tos)]
        # Total Length IP + DATA (16bits)
        ip_packet += [halfword2bstr( len(data) + ETH_HEADER_SIZE )]
        # ID (16bits)
        ip_packet += [halfword2bstr(ipid)]
        # Flag (3bits) + Fragment Offset (13bits)
        fragment_offset=0
        ip_packet += [halfword2bstr(flags | fragment_offset)] #0x4000 is DF set
        # TTL (8bits)
        ip_packet += [int2str16(ttl)[1:]]
        # Protocol (8bits)
        ip_packet += [int2str16( RAW_IP_PROTO[ protocol ] )[1:] ]
        # Checksum (16bits)
        ip_packet += ["\x00\x00"] #checksum initially set to zero
        # Source IP (32bits)
        ip_packet += socket.inet_aton( srcaddress )
        # Destination IP (32bits)
        ip_packet += socket.inet_aton( dstaddress )

        ip_header_checksum = checksum("".join( ip_packet ))
        ip_packet[7]=halfword2bstr(ip_header_checksum)

        self.buffer += "".join( ip_packet )
        self.buffer += data #add the data as well
        return

    def ICMP( self, ipsrc, ipdest, type=0, code=0, data="", tos=0x00 ):
        """
        Creates an ICMP buffer, including the IP header
        """
        packet=[]
        packet+=[chr(type)]
        packet+=[chr(code)]
        packet+=["\x00\x00"] #cleared checksum so we can do checksum calculation
        packet+=[data]

        buffer = "".join(packet)
        mychecksum=checksum(buffer)
        #now redo packet because of checksum
        packet=[]
        packet+=[chr(type)]
        packet+=[chr(code)]
        packet+=[int2str16(mychecksum)]
        packet+=[data]
        buffer = "".join(packet)
        self.IP(ipsrc, ipdest, buffer, protocol="ICMP", tos=tos)
        return

    def ICMP_ECHO_REQUEST(self, ipsrc, ipdest, id, sequence_number, data="", code=0, tos=0x00):
        """
        Creates an ICMP Echo Request (a ping packet)

        code of non-zero is used for ip fingerprinting
        """
        datalist=[]
        datalist+=[int2str16(id)]
        datalist+=[int2str16(sequence_number)]
        datalist+=[data]
        mydata="".join(datalist)
        self.ICMP(ipsrc, ipdest, 8, code, mydata, tos=tos)
        return

    def UDP(self, ipsrc, ipdest, sport, dport, data):
        """
        To calculate UDP checksum a "pseudo header" is added to the UDP header. This includes:

        IP Source Address 4 bytes
        IP Destination Address 4 bytes
        Protocol 2 bytes
        UDP Length  2 bytes

        OCTET 1,2 Source Port
        OCTET 3,4 Destination Port
        OCTET 5,6 Length
        OCTET 7,8 Checksum
        OCTET 9,10 Data
        """
        buffer=[]
        #psuedoheader start
        buffer+=[socket.inet_aton(ipsrc)]
        buffer+=[socket.inet_aton(ipdest)]
        buffer+=[halfword2bstr(17)] #UDP protocol
        udp_length=8+len(data)
        buffer+=[halfword2bstr(udp_length)] #header and data length
        #psuedoheader end
        buffer+=[halfword2bstr(sport)]
        buffer+=[halfword2bstr(dport)]
        buffer+=[halfword2bstr(len(data)+8)]
        #checksum is set to zero first, then calculated
        #this changes in IPv6, annoyingly.
        buffer+=[halfword2bstr(0)]
        buffer+=[data]
        #need to pad the buffer to a multiple of two octets with zeros
        buffer="".join(buffer)
        if len(buffer)%2!=0:
            buffer+="\x00" #make it divisible by two
        mychecksum=checksum(buffer)
        #ok, now do it for real
        buffer=[]
        buffer+=[halfword2bstr(sport)]
        buffer+=[halfword2bstr(dport)]
        buffer+=[halfword2bstr(len(data)+8)]
        #checksum is set to zero first, then calculated
        #this changes in IPv6, annoyingly.
        #now we have it, so we put it in.
        buffer+=[halfword2bstr(mychecksum)]
        buffer+=[data]
        self.buffer+="".join(buffer)
        return

    def TCP(self,source,destination,flags,sport,dport,data):
        """
        Construct a TCP packet for sending on raw socket
        """
        buffer=[]
        buffer+=[halfword2bstr(sport)]
        buffer+=[halfword2bstr(dport)]
        seq_number=44
        buffer+=[big_order(seq_number)]
        ack_num=45
        buffer+=[big_order(ack_num)]
        headerLength=32
        buffer+=[chr(headerLength<<2)]
        flagbits=0
        for k in TCPFLAGS:
            if TCPFLAGS[k] in flags:
                flagbits+=k
        buffer+=[chr(flagbits)]

        windowSize=5840 #???
        buffer+=[halfword2bstr(windowSize)]
        csum=0
        clen=len(self.buffer+"".join(buffer))
        buffer+=[halfword2bstr(csum)]
        buffer+=["\x01"*2+"\x01"*10] #options (12 bytes)
        buffer+=["\x00"*2] #?!?!?
        buffer+=[data]
        Note="""
            http://www.geocities.com/SiliconValley/2072/rawsock.htm
            But wait! We're not done yet. TCP checksums also use a 12-byte "pseudo-header" which takes information from the IP header. It has 4 fields:

            1. The source IP address.
            2. The destination IP address.
            3. The protocol number. (This will always be 6 for TCP.)
            4. The 16-bit length of the entire TCP segment, in bytes.

            We'll place this in newbuf
            """

        self.buffer+="".join(buffer) #finally create it

        newbuf=socket.inet_aton(source)
        newbuf+=socket.inet_aton(destination)
        newbuf+=halfword2bstr(6)
        newbuf+=halfword2bstr(len(self.buffer))


        #fails - so we leave it as zero. :<
        csum=halfword2bstr(checksum(self.buffer+newbuf))
        self.buffer=stroverwrite(self.buffer,csum,clen)
        return

    def DNSQuery(self, txid, name, recursion_requested=True):
        """
        from rfc2136.txt (etc)
      0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                      ID                       |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |QR|   Opcode  |          Z         |   RCODE   |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ZOCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    PRCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    UPCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |                    ADCOUNT                    |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

        """
        buffer=[]
        buffer+=[halfword2bstr(txid)]
        #now set flags
        flags=0x0000 #and Z and RCODE
        if recursion_requested:
            flags=flags | 0x0100 #recursion is desired
        #flags=flags | 0x010 #non-authenticated data is ok
        #print "Flags: %x"%flags
        buffer+=[halfword2bstr(flags)]
        questions=1
        buffer+=[halfword2bstr(questions)]
        buffer+=[halfword2bstr(0)] #answer RR's
        buffer+=[halfword2bstr(0)] #authority RR's
        buffer+=[halfword2bstr(0)] #additional RR's
        name_e=dns_name_encode(name)
        devlog("dns","Name Encoded: %s"%repr(name_e))
        buffer+=[name_e]
        buffer+=[halfword2bstr(1)] #type A
        buffer+=[halfword2bstr(1)] #class IN

        self.buffer+="".join(buffer)
        return

    def DNSResponse(self, txid, name, authorityname, answer_ip):
        """
        name is the DNS name of the query
        authorityname is a name we put in the authority record
        answer_ip is what respond with for both authorityname and name
        """
        #cow.com from www.cow.com
        domain=".".join(name.split(".")[1:])

        buffer=[]
        buffer+=[halfword2bstr(txid)]
        #now set flags (Answer)
        flags=0x8000 #and Z and RCODE
        flags=flags | 0x100 #recursion is desired
        flags=flags | 0x0400 #We are the authority for the domain
        #flags=flags | 0x010 #non-authenticated data is ok
        #print "Flags: %x"%flags
        buffer+=[halfword2bstr(flags)]
        questions=1
        buffer+=[halfword2bstr(questions)]
        buffer+=[halfword2bstr(1)] #answer RR's
        buffer+=[halfword2bstr(1)] #authority RR's
        buffer+=[halfword2bstr(1)] #additional RR's
        #query for our name
        buffer+=[dns_name_encode(name)]
        buffer+=[halfword2bstr(1)] #type A
        buffer+=[halfword2bstr(1)] #class IN
        #Answer Section
        buffer+=[dns_name_encode(name)] #could use compressed names here
        buffer+=[halfword2bstr(1)] #type A
        buffer+=[halfword2bstr(1)] #class IN
        buffer+=[big_order(0x0000012c)] #5 minutes
        buffer+=[halfword2bstr(4)] #data length - one ip address
        buffer+=[socket.inet_aton(answer_ip)]
        #Authority Section
        buffer+=[dns_name_encode(domain)]
        buffer+=[halfword2bstr(2)] #type: Name Server
        buffer+=[halfword2bstr(1)] #class IN
        buffer+=[big_order(0x0000b5c5)] #12 hours
        authorityname_e=dns_name_encode(authorityname)
        buffer+=[halfword2bstr(len(authorityname_e))] #data length
        buffer+=authorityname_e #add our name here
        #additional section
        buffer+=[authorityname_e] #could use compressed names here
        buffer+=[halfword2bstr(1)] #type A
        buffer+=[halfword2bstr(1)] #class IN
        buffer+=[big_order(0x0000b5c5)] #12 hours
        buffer+=[halfword2bstr(4)] #data length - one ip address
        buffer+=[socket.inet_aton(answer_ip)]
        #end of packet

        self.buffer+="".join(buffer)
        return

    def get(self):
        return self.buffer


class quickrawsock(object):
    """
    Helper class - we ALWAYS want to return a socket, even on remote nodes' raw socks
    """
    def __init__(self, sock, node):
        self.sock=sock
        self.node=node
        return

    def send(self, data):
        if self.node:
            ret=self.node.shell.send(self.sock, data)
        else:
            ret=self.sock.send(data)
        return ret

    def close(self):
        if self.node:
            ret=self.node.shell.close(self.sock)
        else:
            ret=self.sock.close()
        return ret

def bindraw(interface, protocol):
    """
    Helper function for LocalNode raw sockets - in this file to keep all our raw socket stuff in the right place
    Returns None on failure
    """
    sock=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, protocol)
    if sock:
        sock.bind((interface, protocol))
        sock=quickrawsock(sock, None) #localnode has None as "Node" argument
    else:
        sock=None
    return sock

class sender:
    """

    A raw socket sender for use by CANVAS modules that want to send raw packets
    out for some reason, such as for port scanning or TCP/ACK, ICMP communication

    """
    def __init__(self, iface=None, target=None):
        """
        This is called with from can_scanrand
        """
        self.iface = None

        if iface==None and target!=None:
            devlog("sniffer", "Sender() Getting interface for target %s"%target)
            iface=get_iface_from_target(target)

        if not iface:
            ##SHOULD NEVER GET THIS _ IF YOU DO YOU NEED TO FIX YOUR CALLING CODE
            msg = "***sender in sniffer called incorrectly, you need to specify an interface or a target explicitly"
            devlog("sniffer", msg)
            raise RuntimeError(msg)

        devlog("sniffer","Sender init using iface: %s"%iface)

        self.ips=socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.IPPROTO_IP)

        if self.ips is not None:

            try:
                self.ips.bind((iface, socket.IPPROTO_IP))
            except socket.error:
                devlog("sniffer", "Failed to bind to iface:IPPROTO_IP %s"%iface)
                raise

            self.interface_name,self.interface_protocol,self.packet_type,self.hardware_type,self.hardware_address = self.ips.getsockname()
            self.arps=socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
            self.pgms=socket.socket(socket.AF_INET, socket.SOCK_RAW, 113)
            self.tcps=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            self.udps=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            #self.udps.bind((iface, socket.IPPROTO_UDP))
            self.icmps=socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            self.iface = iface
            #print "TCPS=%s"%self.tcps

        return


    def send(self,packet,proto):
        if proto=="IP":
            devlog("sniffer","Sending %d bytes to raw ip socket"%len(packet))
            self.ips.send(packet)
        elif proto=="ICMP":
            devlog("sniffer","Sending %d bytes to raw icmp socket"%len(packet))
            self.icmps.send(packet)
        elif proto=="UDP":
            self.udps.send(packet)
        elif proto=="TCP":
            self.tcps.send(packet)
        elif proto=="ARP":
            self.arps.bind((self.iface, 0x0806))
            self.arps.send(packet)
        elif proto == "RAWIP":
            #doesn't exist?!?
            self.rawips.send(packet)
        else:
            print "Packet sender: protocol not supported %s"%proto
        return


    def sendto(self,packet,proto,dest):
        if proto=="PGM":
            self.pgms.sendto(packet, dest)
        if proto=="TCP":
            #print "Before sendto"
            try:
                ret=self.tcps.sendto(packet,dest)
            except socket.error,err:
                #print "Permission denied?"
                if err[0]=="113":
                    print "Host unreachable"
                elif err[0]=="101":
                    print "Network unreachable"
                else:
                    print "sendto: unknown error: %s"%err
            #print "ret=%s"%ret It always thinks it sends out the data
            #print "After sendto"
        elif proto=="UDP":
            #print "Sending UDP packet"
            ret=self.udps.sendto(packet, dest)
        elif proto=="IP":
            ret=self.ips.sendto(packet, dest)
        elif proto=="ICMP":
            ret=self.icmps.sendto(packet, dest)
        return

    def close(self):
        """
        Explicitly close sockets
        """
        for s in (self.ips,self.arps,self.icmps,self.udps,self.tcps):
            #catch an exception, if one is even possible.
            try:
                s.close()
            except Exception:
                pass

class sniffer:
    """
    A simple cross-platform sniffer that uses raw sockets for use by CANVAS

    Must be called by root or administrator...
    """

    def __init__(self):
        self.sockList=[]
        self.timeout=5
        #self.listen()

    def listen(self):
        """
        Initialize raw sockets and add them to our sockList
        """
        #clear this off first
        self.sockList=[]

        #this is known to work on Linux 2.4
        #needs to be tested on windows (or an alternative provided)
        if os.name in ["nt"]:
            #not supported (posix is cygwin)
            return 0
        else:
            devlog("sniffer" ,"Unix sockets - trying raw sockets")

            try:
                sock=socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.htons(socket.SOCK_RAW))

                if sock is not None:
                    self.sockList.append(sock)
                else:
                    return 0

            except Exception:
                try:
                    devlog("sniffer", "Trying a raw socket (UDP)")
                    ip=socket.socket(socket.AF_INET, socket.SOCK_RAW, 17)
                    # do not set this and see select block forever
                    ip.set_timeout(self.timeout)
                    #ip.setsockopt(socket.AF_INET, socket.SO_SNDBUF, 80000)
                    #ip.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    self.sockList.append(ip)
                    #print "socketlist=%s"%(self.sockList)
                except Exception:
                    return 0
        return 1

    def recv(self):
        """
        Recieve data from our raw socket - we get up to 80000 bytes
        """

        a = []
        if os.name=="nt":
            (a,b,c)=select.select(self.sockList,[],[],None)
        else:
            # Lets not block forever
            try:
                (a,b,c)=select.select(self.sockList,[],self.sockList,self.timeout)
            except select.error, info:
                if info[0] == 4: # EINTR,
                    pass
                else:
                    raise
        #we don't handle errors properly yet
        if a==[]:
            devlog("sniffer", "recv: No data received, timeout may have expired")
            return 0
        #print "%s, %s, %s"%(a,b,c)
        if a[0]==None:
            devlog("sniffer", "Select recv read set is empty")
            return 0
        try:
            if os.name=="nt":
                data=a[0].recvfrom(80000)[0]
            else:
                data=a[0].recv(1500)
        except AttributeError:
            #we were exiting anyways...so a[0] went to none in front of us.
            return 0

        return data

if __name__=="__main__":
    sniff=sniffer()
    sniff.listen()
    print "Started Sniffer"

    if 0:
        #test sniffer
        parser=packetParser()
        while 1:
            data=sniff.recv()
            if data==0:
                sys.exit(1)
            parser.setPacket(data)
            print "Parsing..."
            parser.prettyprint()

    if 0:
        data=binstring("""
07D0
0050
0000
0001
0000
0002
5002
0200
0000
0000
0102
0304
7F00
0001
0006
0014
""")
        print "Checksum: %4x"%checksum(data)
        data=binstring("""
                       4500
0028
1FFD
4000
8006
0000
C0A8
3B0A
C0A8
3B32	""")

        print "Checksum: %4x"%checksum(data)

    if 1:
        dest="192.168.1.1"
        mysender=sender(target=dest)
        mpacker=packetConstructor()
        source="192.168.1.106"
        mpacker.TCP(source,dest,["SYN"],53,1,"")
        mysender.sendto(mpacker.get(),"TCP",(dest,0))

