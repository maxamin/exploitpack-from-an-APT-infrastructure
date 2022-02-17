#!/usr/bin/env python

import sys
import optparse

from CLI.cli import CommandLineInterface
# the pyconsole.BANNER import breaks on headless/non-X boxen due to the 
# gtk imports that happen in pyconsole ... we only need the banner though ...
BANNER = ''
BANNER += ' _____ _____ _____ _____ _____ _____ \n'
BANNER += '|     |  _  |   | |  |  |  _  |   __|\n'
BANNER += '|   --|     | | | |  |  |     |__   |\n'
BANNER += '|_____|__|__|_|___|\___/|__|__|_____|\n'
BANNER += '         *** XMLRPC cmdline v0.1 *** \n'
from CLI.xmlrpc import StartServerThread
from CLI.xmlrpc import XMLRPCPORT
        
if __name__ == '__main__':
    p = optparse.OptionParser(description='CANVAS Command Line Interface',\
                              prog='cmdline',\
                              version='XMLRPC-cmdline v0.1',\
                              usage='%prog [--engine host] [--server start]')
    
    p.add_option('--engine', '-e', default=None)
    p.add_option('--server', '-s', default=None)
    options, arguments = p.parse_args()
    
    host = 'localhost'
    if options.engine:
        print "Engine specified at: %s" % options.engine
        host = options.engine
        
    if options.server:
        print "Auto Starting XMLRPC Engine Wrapper"
        CANVASServer = StartServerThread().server_thread
    else:
        print BANNER
        CANVASShell = CommandLineInterface(host=host)
        CANVASShell.interact()
        
