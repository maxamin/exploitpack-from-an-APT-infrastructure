#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  rdp_sniff.py
## Description:
##            :
## Created_On :  Tue Jun 11 2019

## Created_By :  X.
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import os
import sys
import logging
import copy
from scapy.all import *

if '.' not in sys.path:
    sys.path.append('.')

from libs.rdp.rdpconst import *
import libs.rdp.mcs as mcs
import libs.rdp.gcc as gcc
import librdp

CON_NO_CON                         = 0
CON_TCP_ESTABLISHED                = 5
CON_CONNECT_INIT_RECEIVED          = 10
CON_CONNECT_RESP_RECEIVED          = 20
CON_SEC_EXCHANGE_RECEIVED          = 30
CON_CLT_INFO_RECEIVED              = 40
CON_LICENSE_ERR_VALID_CLT_RECEIVED = 50
CON_SRV_DEMAND_ACTIVE_RECEIVED     = 60
CON_MONITOR_LAYOUT_PDU_RECEIVED    = 70
CON_CLT_CONFIRM_ACTIVE_RECEIVED    = 80


class Sniffer(object):
    
    def __init__(self):
        self.target = None
        self.iface = None
        self.must_stop = False
        self.state = CON_NO_CON
        self.rdp = librdp.RDP(None)
        self.rdp._crandom = 'A'*32

    def set_target(self, target):
        self.target = target

    def set_iface(self, iface):
        self.iface = iface

    def may_stop(self, x):
        return self.must_stop

    def decrypt_server_frame(self, data, mac=None):
        '''
        Decrypt Srv -> Client
        '''
        return self.rdp.decrypt(data, mac=mac)

    def decrypt_client_frame(self, data):
        '''
        Decrypt Client -> Srv
        '''
        return self.rdp.encrypt(data)

    def start(self):
        #sniff(offline="your_file.pcap", ...)
        filter_string = "tcp and host %s and port 3389" % self.target
        packets = sniff(iface=self.iface, prn=self.fast_packet_handler, filter=filter_string, stop_filter=self.may_stop)
        return packets

    def fast_packet_handler(self, pkt):
        '''
        Fast handler.
        '''

        if not pkt.haslayer(TCP):
            return

        if (pkt['IP'].dst == self.target) and ('S' == pkt['TCP'].flags):
            logging.info('=========== Connection started (target:%s) ===============' % self.target)
            return

        elif (pkt['IP'].src == self.target or pkt['IP'].dst == self.target) and ('R' in pkt['TCP'].flags):
            logging.info('=========== Connection ended ================')
            self.must_stop = True
            return

        if pkt.haslayer('Raw'):
            #print pkt.summary()
            payload = str(pkt['Raw'])
            logging.info("%s [%d]" % (payload.encode('hex'), len(payload)))

    def handle_packet(self, pkt):
        '''
        Packet parser.
        '''

        if 'S' == pkt['TCP'].flags:
            self.target = pkt['IP'].dst
            logging.info('=========== Connection started (target:%s) ===============' % self.target)
            return

        if 'R' in pkt['TCP'].flags:            
            logging.info('=========== Connection ended ================')
            return

        if pkt.haslayer('Raw'):
            payload = str(pkt['Raw'])
            logging.info('--------------------------------------------------')
            logging.info(pkt['TCP'].summary())
            logging.info('------')
            logging.info('Raw: %s [%d]' % (payload.encode('hex'), len(payload)))
            logging.info('------')
            rdp_pkt = librdp.RdpPacket()
            rdp_pkt.unserialize(payload)

            if rdp_pkt.has_layer(librdp.RdpConnectionReq):
                self.state = CON_TCP_ESTABLISHED
                logging.info(rdp_pkt)
                return

            if rdp_pkt.has_layer(mcs.MCSConnectInit):
                self.state = CON_CONNECT_INIT_RECEIVED
                logging.info(rdp_pkt)
                return

            if rdp_pkt.has_layer(mcs.MCSConnectResp):
                self.state = CON_CONNECT_RESP_RECEIVED
                logging.info(rdp_pkt)

                if not rdp_pkt.has_layer(librdp.SCNet):
                    logging.error('Invalid response: expected an SCNet layer')
                    return

                # First get the channel IDs
                scnet_layer = rdp_pkt.get_layer(librdp.SCNet)
                if not scnet_layer:
                    logging.error('Invalid response: expected an SCSecurity layer')
                    return

                self.io_channel_id = scnet_layer.get_io_channel_id()
                self.channel_ids = scnet_layer.get_channel_ids()

                logging.info('MCSChannelID:%d' % (self.io_channel_id))
                logging.info('ChanIDs:%s' % (self.channel_ids))

                scSecurity = rdp_pkt.get_layer(librdp.SCSecurity)
                if not scSecurity:
                    logging.error('Invalid response: expected an SCSecurity layer')
                    return

                # First let's extract the important parameters
                self.rdp._srandom = scSecurity['serverRandom']
                self.rdp._e = scSecurity['serverCertificate']['PublicKeyBlob']['pubExp']
                self.rdp._n = scSecurity['serverCertificate']['PublicKeyBlob']['modulus']
                self.rdp.generate_keys()
                logging.info('srandom: %s' % self.rdp._srandom.encode('hex'))
                logging.info('crandom: %s' % self.rdp._crandom.encode('hex'))
                logging.info('e: %s' % self.rdp._e)
                logging.info('n: %s' % self.rdp._n)
                logging.info('PreMasterSecret: %s' % self.rdp._PreMasterSecret.encode('hex'))
                logging.info('MasterSecret: %s' % self.rdp._MasterSecret.encode('hex'))
                logging.info('MACKey128: %s' % self.rdp._MACKey128.encode('hex'))
                logging.info('InitialClientDecryptKey128: %s' % self.rdp.InitialClientDecryptKey128.encode('hex'))
                logging.info('InitialClientEncryptKey128: %s' % self.rdp.InitialClientEncryptKey128.encode('hex')) 
                return

            if rdp_pkt.has_layer(mcs.MCSSendDataRequest) and pkt['IP'].dst == self.target:
                msdr = rdp_pkt.get_layer(mcs.MCSSendDataRequest)
                raw_data = msdr.get_payload()
                flags = struct.unpack('<L', raw_data[:4])[0]

                logging.info('Flags=%x' % flags)

                if flags & SEC_ENCRYPT:
                    logging.debug('Encrypted payload detected!')
                    decrypted_data = self.decrypt_client_frame(raw_data[12:]) #, mac=raw_data[4:12])
                    logging.debug("Decrypted payload: %s[...]" % decrypted_data.encode('hex')[:64])
                    old_raw_data = raw_data
                    raw_data = decrypted_data

                if flags & SEC_EXCHANGE_PKT:
                    logging.info('Detected a SecurityExchange PDU')
                    self.state = CON_SEC_EXCHANGE_RECEIVED
                    sepd = librdp.SecurityExchangePDUData()
                    rdp_pkt.append(sepd.deserialize(raw_data))
                    rdp_pkt.payload = ''
                    logging.info(rdp_pkt)
                    return

                if flags & SEC_INFO_PKT:
                    logging.info('Detected a Client Info PDU Data')
                    self.state = CON_CLT_INFO_RECEIVED
                    cipd = librdp.ClientInfoPDUData().deserialize(old_raw_data[:12])
                    ip = librdp.InfoPacket().deserialize(raw_data)
                    rdp_pkt.append(cipd)
                    rdp_pkt.append(ip)
                    rdp_pkt.payload = ''
                    logging.info(rdp_pkt)
                    return

                if self.state == CON_MONITOR_LAYOUT_PDU_RECEIVED and (flags & SEC_RESET_SEQNO | SEC_IGNORE_SEQNO):
                    logging.info('Detected a Client Confirm Active PDU')
                    self.state = CON_CLT_CONFIRM_ACTIVE_RECEIVED
                    hdr = librdp.NonFipsSecurityHeader().deserialize(old_raw_data[:12])
                    capd = librdp.ConfirmActivePDUData(0).deserialize(raw_data)
                    rdp_pkt.append(hdr)
                    rdp_pkt.append(capd)
                    rdp_pkt.payload = ''
                    logging.info(rdp_pkt)
                    return

                if len(raw_data) >= 18:
                    hdr = librdp.ShareDataHeader()
                    hdr.deserialize(raw_data)

                    if hdr['pduType2'] == PDUTYPE2_INPUT:
                        ciepd = librdp.ClientInputEventPDUData(0)
                        ciepd.deserialize(raw_data)
                        rdp_pkt.append(ciepd)
                        rdp_pkt.payload = ciepd['slowPathInputEvents']

                    else:
                        rdp_pkt.append(hdr)
                        rdp_pkt.payload = raw_data[18:] 

                logging.info(rdp_pkt)
                return

            if rdp_pkt.has_layer(mcs.MCSSendDataIndication) and pkt['IP'].src == self.target:
                msdi = rdp_pkt.get_layer(mcs.MCSSendDataIndication)
                raw_data = msdi.get_payload()
                flags = struct.unpack('<L', raw_data[:4])[0]
                if flags & SEC_ENCRYPT:
                    logging.debug('Encrypted payload detected!')
                    decrypted_data = self.decrypt_server_frame(raw_data[12:])
                    raw_data = decrypted_data
                    logging.debug("Decrypted payload: %s" % decrypted_data.encode('hex')[:64])
                else:
                    logging.info('Packet is not encrypted!')

                if flags & SEC_LICENSE_PKT:
                    logging.info('Server License Error PDU - Valid Client PDU detected!')
                    self.state = CON_LICENSE_ERR_VALID_CLT_RECEIVED
                    # TODO: PARSING
                    #vcld = ValidClientLicenseData()
                    #vcld.deserialize(raw_data[12:])
                    logging.info(rdp_pkt)
                    return

                if self.state == CON_LICENSE_ERR_VALID_CLT_RECEIVED:
                    logging.info('Server Demand Active PDU detected!')
                    self.state = CON_SRV_DEMAND_ACTIVE_RECEIVED
                    # TODO: PARSING
                    logging.info(rdp_pkt)
                    return

                if self.state == CON_SRV_DEMAND_ACTIVE_RECEIVED:
                    logging.info('Monitor Layout PDU detected!')
                    self.state = CON_MONITOR_LAYOUT_PDU_RECEIVED
                    # TODO: PARSING
                    logging.info(rdp_pkt)
                    return

                if len(raw_data) >= 18:
                    hdr = librdp.ShareDataHeader()
                    rdp_pkt.append(hdr.deserialize(raw_data))
                    rdp_pkt.payload = raw_data[18:]

                logging.info(rdp_pkt)
                return

            if rdp_pkt.is_fast_path_update_pdu():
                sfpup = rdp_pkt.get_layer(librdp.ServerFastPathUpdatePDU)
                if sfpup.payload_is_encrypted():
                    logging.info('Encrypted payload detected!')
                    if pkt['IP'].src == self.target:
                        decrypted = self.decrypt_server_frame(sfpup['fpOutputUpdates'])
                    else:
                        decrypted = self.decrypt_client_frame(sfpup['fpOutputUpdates'])
                    sfpup['fpOutputUpdates'] = decrypted
                    rdp_pkt.payload = decrypted
                    rdp_pkt.unserialize_fastpath_outputupdates(decrypted)
                else:
                    logging.info('Packet is not encrypted!')
                    logging.info('NOT HANDLED FOR NOW.')
                
                logging.info(rdp_pkt)
                return

            # Nothing to do with this packet
            logging.info(rdp_pkt)
            return

        else:
            # Do/print something if required.
            pass


def __handle_fused_packets(packets, idx):
    new_packets = copy.deepcopy(packets)
    for i in xrange(len(packets)):
        pkt = packets[i]
        if pkt.haslayer('Raw'):
            payload = str(pkt['Raw'])
            # We only deal with TPKT packets
            if payload[0] != '\x03':
                continue
            length = struct.unpack('>H', payload[2:4])[0]
            if length < len(payload):
                logging.info("TCP packet %d has two fused TPKT payloads [hdr_length=%d vs payload_length=%d]" % (i, length, len(payload)))
                payload1 = payload[:length]
                payload2 = payload[length:]
                # Mandatory to circumvent a (current) scapy limitation.
                pkt[Raw].load = Raw()
                # Without a payload we can proceed to copy the faulty packet
                new_pkt = pkt.copy()
                # We reintegrate the payloads
                pkt[Raw].load = Raw(payload1)
                new_pkt[Raw].load = Raw(payload2)
                # Finally the new packet is inserted
                new_packets[i] = pkt
                new_packets.insert(i+1, new_pkt)
                return new_packets, i+2

    return new_packets, -1

def handle_fused_packets(packets):
    """
    In some cases you will have two fused TPKT payloads.
    This would be a problem for the decryption so we need to:
        - Find the fused packets
        - Unfuse them
    It should be noted that payloads are not handled by Packet.copy()
    within scapy so we have no choice but to remove the payload before
    the copy.
    """


    idx = 0
    old_packets = copy.deepcopy(packets)

    while 1:

        nr_packets1 = len(old_packets)
        new_packets, idx = __handle_fused_packets(old_packets, idx)
        nr_packets2 = len(new_packets)
        if nr_packets1 == nr_packets2:
            break

        old_packets = copy.deepcopy(new_packets)

    return new_packets


def __handle_splitted_packets(packets, idx):

    new_packets = copy.deepcopy(packets)
    nr_packets = len(packets)# - idx

    for i in xrange(idx, nr_packets):

        pkt = new_packets[i]
        if not pkt.haslayer('Raw'):
            continue

        payload = str(pkt['Raw'])
        # We only deal with TPKT packets
        if payload[0] != '\x03':
            continue

        length = struct.unpack('>H', payload[2:4])[0]
        if length > len(payload):
            logging.info("TCP packet %d has his TPKT payloads splitted! [hdr_length=%d vs payload_length=%d]" % (i, length, len(payload)))
            required_length = length - len(payload)
            for j in xrange(1,5):
                if i+j < len(packets):
                    next_pkt = new_packets[i+j]
                    if next_pkt.haslayer('Raw'):
                        next_payload = str(next_pkt['Raw'])

                        if (len(payload) + len(next_payload)) == length:
                            logging.debug("Found an exact candidate at position %d" % (i+j))
                            payload1 = payload + next_payload
                            pkt[Raw].load = Raw(payload1)
                            new_packets.remove(next_pkt)
                            return new_packets, i+j

                        if (len(payload) + len(next_payload)) < length:
                            logging.debug("Found an intermediary candidate at position %d" % (i+j))
                            pkt[Raw].load = Raw(payload + next_payload)
                            new_packets.remove(next_pkt)
                            return new_packets, i+0

    return new_packets, -1

def handle_splitted_packets(packets):
    """
    In some cases you will a fused TPKT payload splitted in two.
    This would be a problem for the decryption! So we need to:
        - Find the splitted packets
        - Fuse them
    It should be noted that payloads are not handled by Packet.copy()
    within scapy so we have no choice but to remove the payload before
    the copy.
    """

    idx = 0
    old_packets = copy.deepcopy(packets)

    while 1:

        nr_packets1 = len(old_packets)
        new_packets, idx = __handle_splitted_packets(old_packets, idx)
        nr_packets2 = len(new_packets)

        if nr_packets1 == nr_packets2:
            break

        old_packets = copy.deepcopy(new_packets)

    return new_packets


if __name__ == "__main__":

    Log = logging.getLogger()
    Log.setLevel(logging.INFO)

    sniffer = Sniffer()
    sniffer.set_target('192.168.1.175')
    sniffer.set_iface('enp0s20f0u1')
    packets = sniffer.start()

    L1 = [ pkt for pkt in packets]
    nr_packets = len(L1)
    logging.info("[+] Sniffed %d packets" % nr_packets)

    logging.info("[+] Attempting to locate fused TPKT payload within tcp packets")
    L2 = handle_fused_packets(L1)
    nr_packets2 = len(L2)
    if nr_packets2 < nr_packets:
        raise RuntimeError("Corrupted list of packets!")
    if nr_packets2 > nr_packets:
        logging.info("\t-> Fixed %d packet(s)" % (nr_packets2 - nr_packets))

    logging.info("[+] Attempting to locate splitted TPKT payloads within tcp packets")
    L3 = handle_splitted_packets(L2)
    nr_packets3 = len(L3)
    if nr_packets3 > nr_packets2:
        raise RuntimeError("Corrupted list of packets!")
    if nr_packets3 < nr_packets2:
        logging.info("\t-> Fixed %d packet(s)" % (nr_packets2 - nr_packets3))

    logging.info("[+] Parsing packets")
    for pkt in L3:
        sniffer.handle_packet(pkt)
