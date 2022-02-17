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
import os, sys, cmd, signal, time, logging, socket, subprocess
from threading import Thread, Lock

###
# Project
###
import d2sec_config
import server, xmlrpclib
import console

class app(console.app):
  '''Console based UI'''

  OPTIONS = [
    ('level', 'Log level from 1 (critical) to 5 (debug). Default: 4', 4),
  ]

  ###
  # Execution
  ###
  def start(self, args=None, histfile=d2sec_config.HISTORY):
    try:
      self.rpc = server.XMLRPCRequest('localhost')
    except Exception, e:
      self.log.error('%s' % e)
      return
    super(app, self).start()

  ###
  # Command: nmap
  ###
  def help_nmap(self):
    self.log.warning('nmap <file_xml>')

  def nmap_parse(self, filename):
    res = ''
    if os.path.isfile(filename) == False:
      return ('error', 'File %s not found\n' % filename) 
    try:
      res = self.rpc.proxy.parse_nmap_xml(filename)
    except Exception, e:
      self.log.error(e)
    return res

  def do_nmap(self, args):
    '''Handle xml nmap file'''
    if args[0]:
      res = self.nmap_parse(args[0])
      if res[0] == 'error':
        self.log.error(res[1])
      else:
        self.log.info('Info saved in database')
        for port in res[2]:
          self.log.info('%s (%s) - %d/%s' % (res[0], res[1], int(port['port']), port['protocol']))

  ###
  # Command: createdb
  ###
  def do_createdb(self, args):
    '''Create django (sqlite3) database'''

    self.log.info('Create django (sqlite3) database')
    try:
      res = self.rpc.proxy.createdb_django()
    except Exception, e:
      self.log.error(e)
      return
    if res[0] == 'info':
      self.log.info(res[1])
    else:
      self.log.error(res[1])

  ###
  # Command: deletedb
  ###
  def do_deletedb(self, args):
    '''Delete django (sqlite3) database'''

    self.log.info('Delete django (sqlite3) database')
    try:
      res = self.rpc.proxy.deletedb_django()
    except Exception, e:
      self.log.error(e)
      return
    if res[0] == 'info':
      self.log.info(res[1])
    else:
      self.log.error(res[1])
   
  ###
  # Command: autopwn
  ###
  def help_autopwn(self):
    self.log.warning('autopwn [options] <args>')
    self.log.warning('with : ')
    self.log.warning('  -t <host> -p [<port1,port2,...>] -a [<appli1@port, appli2@port,...>]')
    self.log.warning('  -n <nmap xml file>')

  def do_autopwn(self, args):
    '''Autopwn a target'''

    host = ports = applis = ''
    if len(args) >= 2:
      if '-p' in args and '-a' in args:
        self.log.error('Only one option -p or -a')
        return
      if args[0] == '-t':
        host = args[1]
        if len(args) == 4 and args[2] == '-p': ports = args[3]
        if len(args) == 4 and args[2] == '-a': applis = args[3]
      elif args[0] == '-n':
        res = self.nmap_parse(args[1])
        if res[0] == 'error':
          self.log.error(res[1])
          return
        else:
          host = res[1]
          for port in res[2]:
            ports += port['port'] + ','
          ports = ports[:-1]
      else:
        self.log.error('Options invalid')
        return
      try:
        res = self.rpc.proxy.autopwn(host, ports, applis)
      except Exception, e:
        self.log.error(e)
        return
      if res[0] == 'error':
        self.log.error(res[1])
      else:
        self.log.info(res[1])
        thost = []
        thost.append(host)
        self.do_dump(thost)

  ###
  # Command: target
  ###
  def do_target(self, args):
    '''List autopwn()ed targets'''

    try:
      res = self.rpc.proxy.listtargets()
    except Exception, e:
      self.log.error(e)
      return
    if res[0] == 'info':
      for nfo in res[1]:
        self.log.info(nfo)
    else:
        self.log.error(res[1])
        
  ###
  # Command: dump
  ###
  def help_dump(self):
    self.log.warning('dump <ip>')

  def do_dump(self, args):
    '''Dump info about an autopwn()ed target'''

    if args:
      for arg in args:
        try:
          res = self.rpc.proxy.dump(arg)
        except Exception, e:
          self.log.error(e)
          return
        if res[0] == 'info':
          for nfo in res[1]:
            self.log.info(nfo)
        else:
          self.log.error(res[1])

  ###
  # Command: listvar
  ###
  def do_listvar(self, args):
    '''List environment variables'''

    try:
      self.log.info('Variables')
      self.log.info('--------------\n')
      vars = self.rpc.proxy.listvar()
      for var, value in vars.iteritems():
        self.log.info('%s = %s' % (var, value))
    except Exception, e:
      self.log.error(e)

  ###
  # Command: setvar
  ###
  def help_setvar(self):
    self.log.warning('setvar <varname> <value>')

  def do_setvar(self, args):
    '''Set an environment variable'''

    if len(args) == 2:
      self.log.info('Set %s = %s' % (args[0], args[1]))
      try:
        res = self.rpc.proxy.setvar(args[0], args[1])
      except Exception, e:
        self.log.error(e)
        return
      if res[0] == 'info':
        self.log.info(res[1])
      else:
        self.log.error(res[1])

  ###
  # Command: unsetvar
  ###
  def help_setvar(self):
    self.log.warning('unsetvar <varname>')

  def do_unsetvar(self, args):
    '''Unset an environment variable'''

    if len(args) == 1:
      self.log.info('Unset %s' % args[0])
      try:
        res = self.rpc.proxy.unsetvar(args[0])
      except Exception, e:
        self.log.error(e)
        return
      if res[0] == 'info':
        self.log.info(res[1])
      else:
        self.log.error(res[1])

  ###
  # Command: suicide
  ###
  def do_suicide(self, args):
    '''Stop threaded xmlrpc server'''

    try:
      self.rpc.proxy.suicide()
    except Exception, e:
      pass



if __name__ == "__main__": app().start_cli()
