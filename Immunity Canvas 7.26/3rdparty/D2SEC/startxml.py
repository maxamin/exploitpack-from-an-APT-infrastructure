#!/usr/bin/env python
# -*- coding: utf-8 -*-
###
#
# Console-based client
#
###

###
# STD modules
###
import os, sys, getopt

###
# Project
###
xmlpath = os.path.join(os.path.dirname(__file__), 'xml')
if xmlpath not in sys.path: sys.path.append(xmlpath)

import client
import server

def usage(cmd):
  print "%s [-sc]\n" % cmd
  print "  -s : start server"
  print "  -c : start client"

if __name__ == '__main__':
  print 'D2XML (c) 2007-2011 DSquare Security\n'
  try:
    opts, args = getopt.getopt(sys.argv[1:], "sc")
  except getopt.GetoptError, err:
    print str(err)
    usage(sys.argv[0])
    raise SystemExit
  for o, a in opts:
    if o == "-s": 
      server.StartServerThread().server_thread
    elif o == "-c": 
      client.app().start_cli()
    else:
      print "[-] option not recognized"
      usage(sys.argv[0])
      raise SystemExit
  if len(sys.argv) == 1:
    usage(sys.argv[0])
    raise SystemExit

