#! /usr/bin/env python2
# -*- coding: utf-8 -*-

###
# STD modules
###
import subprocess

###
# Project modules
###
import lib.db

###
# Celerey modules 
###
from celery import Celery
from celery.schedules import crontab
from celery.decorators import periodic_task

celery = Celery('bfk',
             broker='redis://localhost:6379',
             backend='redis://localhost:6379',
             include=['tasks'])

def _parse_results(file):
  db = lib.db.db()
  db.params['dbname'] = 'databases/d2bfs.db'
  db.params['table'] = 'results'
  db.connect()
  lines = open(file, 'r').readlines()
  for line in lines:
    if '[ssh]' in line and 'host:' in line:
      line = line.split()
      host = line[2]
      user = line[4]
      passwd = line[6]
      db.select('SELECT * FROM ' + db.params['table'] + ' WHERE host=? AND user=? AND pass=?', (host, user, passwd, ))
      if db.params['selects']:
        continue
      else:
        db.params['cursor'].execute('INSERT INTO ' + db.params['table'] + ' VALUES  (NULL, ?, ?, ?)', (host, user, passwd,))
        db.params['connex'].commit()
  db.close()

@celery.task
def run_bf_ssh(cmdline, file_results):
  print "[+] Cmdline: %s" % cmdline
  try:
    p = subprocess.Popen(cmdline)
    p.communicate()
    _parse_results(file_results)
  except Exception, e:
    print '[-] error: %s' % e

