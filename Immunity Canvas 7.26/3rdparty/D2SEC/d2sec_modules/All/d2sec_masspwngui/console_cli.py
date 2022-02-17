#!/usr/bin/env python

# CANVAS: Command Line Interface
# Bas Alberts, v0.1

# Modified by DSquare Security, LLC, 2007-2010

import os
import sys
import shutil
import select
import time
import code
import subprocess
import sqlite3
import socket

from threading import Lock

try:
    import readline
except ImportError:
    print 'Module readline not available'
    
import rlcompleter    

class CANVASCompleter(rlcompleter.Completer):
    def __init__(self):
        rlcompleter.Completer.__init__(self)
        return
    
    def complete(self, text, state):
        return rlcompleter.Completer.complete(self, text, state)

# so we can filter output ... has to be thread safe for auto engine   
class StdoutCache:
    def __init__(self):
        self.out    = []
        self.lock   = Lock()
        return
    
    def reset(self):
        self.lock.acquire()
        self.out = []
        self.lock.release()
        return
    
    def write(self, line):
        self.lock.acquire()
        self.out.append(line)
        self.lock.release()
        return
    
    def flush(self):
        self.lock.acquire()
        out = ''.join(self.out)
        self.lock.release()
        self.reset()
        return out
            
def select_stdin_for_reading(timeout = 0.2, stdin=sys.stdin):
    try:
        rd = []
        wr = []
        ex = []
        if hasattr(stdin, 'isactive'):
            if stdin.isactive() == True:
                rd += [stdin.fileno()]
        else:
            rd, wr, ex = select.select([stdin.fileno()], [], [], timeout)
    except TypeError:
        raise
    except select.error, (errcode, errmsg):
        if errcode == 10038: # win32 ENOTSOCK
            import os
            if os.name != 'nt':
                raise
            import msvcrt
            while True:
                rd = []
                wr = []
                ex = []
                if msvcrt.kbhit():
                    rd += [stdin.fileno()]
                if rd != []:
                    return (rd, [], [])
            raise select.error
    return (rd, [], [])
    
class CommandLineInterface(code.InteractiveConsole):
  def __init__(self, host='localhost'):
    self.stdout = sys.stdout
    self.cache  = StdoutCache()
    code.InteractiveConsole.__init__(self)
    try:
      readline.parse_and_bind('tab: complete')
      readline.set_completer(CANVASCompleter().complete)
    except NameError:
      ##Probably Windows where the readline package hasn't been installed - no special history of tab complete for them!
      pass
              
    self.python = False
    # commands that get handle before any scripting
    self.commands_conf = {
    # COMMAND, usage, valid argument counts, command callback
      'SET'           : ['[var=<value>] -- Sets a variable to a value', [0, 1], self.setvar],
      'HELP'          : ['[<command>]   -- Shows help for a command', [0, 1], self.help]
    }

    self.commands_pwn = {
      # COMMAND, usage, valid argument counts, command callback
      'PWN'           : ['[<host>]      -- Run d2sec_masspwn', [1], self.pwn],
    }

    self.commands_db = {
      # COMMAND, usage, valid argument counts, command callback
      'TARGET'        : ['              -- List masspwn()ed target', [0], self.listtarget],
    } 

    self.globals = {
      'CANVASPATH' : '',
      'PYTHONPATH' : '',
      'DICO'       : '',
      'USER'       : ''
    }
    return
    
  def help(self, args):
    if len(args) == 2:
      nfo = 0
      for c in [self.commands_conf, self.commands_pwn, self.commands_db]:
        if args[1].upper() in c:
          sys.stdout.write('%s\t%s\n' % (args[1].upper(), c[args[1].upper()][0]))
          nfo = 1
          break
      if not nfo:
        sys.stdout.write('No such command')
    else:        
      print '\nConfiguration'
      print '--------------------\n'
      for command in self.commands_conf:
        sys.stdout.write('%s\t%s\n' % (command, self.commands_conf[command][0]))
      print '\nMass Pwn'
      print '--------------\n'
      for command in self.commands_pwn:
        sys.stdout.write('%s\t%s\n' % (command, self.commands_pwn[command][0]))
      print '\nDatabase info'
      print '-------------------\n'
      for command in self.commands_db:
        sys.stdout.write('%s\t%s\n' % (command, self.commands_db[command][0]))
    print
    return
    
  # XXX: needs more intelligent arg parsing
  def handle_command_line(self, line):
    command = line.split(' ')
    commands = {}
    nfo = 0
    for c in [self.commands_conf, self.commands_pwn, self.commands_db]:
      if command[0].upper() in c:
        nfo = 1
        commands = c
        break
    if not nfo:
      return False
    else:
      # checks for matching amount of args, -1 means variable n args
      if commands[command[0].upper()][1][0] != -1:
        if len(command) - 1 not in commands[command[0].upper()][1]:
          sys.stdout.write('Usage: ' + command[0].upper() + ' ' + commands[command[0].upper()][0] + '\n')
          return True
      else:
        # variable command args with no args ... dump usage
        if not len(command) - 1:
          sys.stdout.write('Usage: ' + command[0].upper() + ' ' + commands[command[0].upper()][0] + '\n') 
          return True
      # call the handler for that command
      # handlers are responsible for type conversion
      try:
        commands[command[0].upper()][2](command)
      except:
        import traceback
        traceback.print_exc(file=sys.stderr)
        sys.stdout.write('[+] Check your command please\n')
    return True
    
  # we can intercept commands here
  def filter_line(self, line):
    if self.handle_command_line(line) == True:
      return None
    return line

  def checkvar(self, var):
    if not self.globals[var]:
      sys.stdout.write("Set %s variable with command SET\n\n" % var)
      return False
    return True

  def setvar(self, args):
    if len(args) == 2:
      (var, value) = args[1].split('=')
      if var.upper() in self.globals:
        self.globals[var.upper()] = value
      else:
        print "Variable %s unknown\n" % var
    else:
      sys.stdout.write('\n')
      for v, k in self.globals.items():
        if not k:
          print "%s = ''" % v
        else:
          print "%s = %s" % (v, k)
      print
    return

  def pwn(self, args):
    if not self.checkvar('CANVASPATH'): return
    os.chdir(self.globals['CANVASPATH'])
    if not self.checkvar('PYTHONPATH'): return
    cmd = '%s 3rdparty/D2SEC/exploits/d2sec_masspwn/d2sec_masspwn.py -t %s -O guimode:txt' % (self.globals['PYTHONPATH'], args[1])
    if self.globals['DICO']: cmd += "-O dico:%s " % self.globals['DICO']
    if self.globals['USER']: cmd += "-O newuser:%s" % self.globals['USER']
    res = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    line = res.stdout.readline()
    print
    while line:
      if "[D2]" in line:
        sys.stdout.write(line.replace("[D2]", ""))
      sys.stdout.flush()
      line = res.stdout.readline()
    print
    return

  def listtarget(self, args):
    if not self.checkvar('CANVASPATH'): return
    os.chdir(self.globals['CANVASPATH'])
    db = '3rdparty/D2SEC/d2sec_modules/All/d2sec_django/db_d2sec.sqlite3'
    if not os.path.exists(db):
      print '\n[-] Django database not found.\n[-] See 3rdparty/D2SEC/d2sec_modules/All/d2sec_django/README to create it.\n'
      return
    try:
      conn = sqlite3.connect(db)
    except Exception, e:
      print '[-] %s' % e
      return
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT host from www_host")
    selects = cursor.fetchall()
    cursor.close()
    conn.close()

    print '\nTargets list'
    print '--------------\n'
    for select in selects:
      print '%s - %s' % (select[0], socket.gethostbyaddr(select[0])[0])
    print
    return
