#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2010
#

import socket
from struct import pack, unpack

def int_ip_to_str(ip_num):
  return socket.inet_ntoa(pack('!L', ip_num))

def str_ip_to_int(ip):
  return unpack('!L',socket.inet_aton(ip))
