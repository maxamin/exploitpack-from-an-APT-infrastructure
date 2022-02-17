#! /usr/bin/env python
# -*- coding: UTF-8  -*-

# Copyright (c) 2007-2011 DSquare Security, LLC
# All rights reserved.

import urllib, sys, getopt
from BeautifulSoup import BeautifulSoup

class dpl:
  def __init__(self):
    self.db = []

  def get_db_phenoelit(self):
    dpl_url = 'http://www.phenoelit-us.org/dpl/dpl.html'
    content = ''
    try:
      content = urllib.urlopen(dpl_url)  
      soup = BeautifulSoup(content)
      frame = soup.find("frame")
      content = urllib.urlopen(frame["src"]).read()
    except Exception, e:
      print '[-] %s' % e      
      return
    soup = BeautifulSoup(content)
    for tr in soup('tr'):
      dp = ''
      for td in tr('td'):
        if td.contents:
          dp += '%s;' % td.contents[0]
        else:
          dp += ';'
      if 'Vendor' in dp:
        continue
      self.db.append(dp.replace('<br />', ''))

  def get_db_cve(self):
    content = open('cve.txt', 'r').readlines()
    for c in content:
      if c[0] == '#':
        continue
      self.db.append(c[:-1])
  
def format_dpl(d):
  d = d.split(';')
  print '%-12s :   %s' % ('Vendor',      d[0])
  print '%-12s :   %s' % ('Model',       d[1])
  print '%-12s :   %s' % ('Version',     d[2])
  print '%-12s :   %s' % ('Access Type', d[3])
  print '%-12s :   %s' % ('Username',    d[4])
  print '%-12s :   %s' % ('Passwd',      d[5])
  print '%-12s :   %s' % ('Privileges',  d[6])
  print '%-12s :   %s' % ('Notes',       d[7])
  print '%-12s :   %s' % ('CVE',         d[8])
  print '-' * 80 

def display_dpl(dpl, vendor, model):
  for d in dpl:
    if not vendor and not model:
      format_dpl(d)
    if vendor and not model and vendor in d:
      format_dpl(d) 
    if model and not vendor and model in d:
      format_dpl(d) 
    if vendor and model and vendor in d and model in d:
      format_dpl(d) 

def usage(cmd):
  print "$ %s -v vendor -m model\n" % cmd
  print """Display all default login/passwd if vendor and/or model 
are not specified.\n"""
  sys.exit(-1)

if __name__ == "__main__":
  try:
    opts, args = getopt.getopt(sys.argv[1:], "hv:m:")
  except getopt.GetoptError, err:
    print str(err)
    usage(sys.argv[0])
    raise SystemExit
  vendor = model = ''
  for o, a in opts:
    if o == "-v": vendor = a
    elif o == "-m": model = a
    elif o == "-h": 
      usage(sys.argv[0])
      raise SystemExit
    else:
      print "[-] option not recognized"
      usage(sys.argv[0])
      raise SystemExit
  dpl = dpl()
  dpl.get_db_phenoelit()
  dpl.get_db_cve()
  display_dpl(dpl.db, vendor, model)
