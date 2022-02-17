#!/usr/bin/env python
"""
Httpcommander.py - 
Starts a webserver on a port
executes a command given in the arguments of any request
"""

import socket
import sys
import getopt
import urllib 
import os 
def usage():
    print "./httpcommander.py -p port"
    return 

def server(port):
    s=socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0",port))
    s.listen(5)
    s.settimeout(None)
    
    while 1:
        (fd, addr)=s.accept()
        print "Got connection from %s"%str(addr)
        try:
            data=fd.recv(5000)
            command=data.split("command=")[1]
            command=command.split(" ")[0]
            command=urllib.unquote_plus(command)
            print "Executing command %s"%command 
            if command=="quit":
                sys.exit(1)
            os.system(command)
            fd.sendall("200 OK HTTP/1.0\r\n\r\nDone\r\n")
            fd.close()
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)

        
def main(args):
    port=80
    try:
        (opt, args) = getopt.getopt(args,"p:")
    except:
        usage()
        
    for o,a in opt:
        if o=="-p":
            port=int(a)
    
    print "Running server on port %d"%port 
    server(port)

if __name__=="__main__":
    main(sys.argv[1:])