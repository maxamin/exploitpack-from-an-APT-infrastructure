#! /usr/bin/env python

import sys, os, optparse

# Django
try:
  import django.core.management
  import django.core.management.commands.syncdb
  import settings
except Exception, e:
  print '[D2 LOG] %s' % e
  print 'Django (http://www.djangoproject.com/) installed ?'
  raise SystemExit

class guidjango:
  def __init__(self):
    self.username = 'd2sec'
    self.password = 'd2sec'
    self.port = 12345

  def run(self):
    if not os.path.exists(settings.DATABASE_NAME):
      print '[D2 LOG] No database found. Creating new ...'
      django.core.management.commands.syncdb.Command().handle_noargs()
      try:
        user = django.contrib.auth.models.User.objects.create_user(self.username, '%s@localhost' % self.username, self.password)
        user.is_staff = True
        user.is_superuser = True
        user.save()
        print '[D2 LOG] Created user "%s" successfully.' % self.username
      except Exception, e:
        print '[D2 LOG] Error creating user: %s' % e
        return 0

    opts = optparse.OptionParser(usage='%prog [options] [<arg>] [...]')
    opts.add_option('-p', '--port',
      dest='port', default=self.port, metavar='NUM',
      help='TCP port number to listen on')
    opt, args = opts.parse_args()
    sys.argv = sys.argv[:1]
    sys.argv.append('runserver')
    sys.argv.append('0.0.0.0:%s' % opt.port)
    print '[D2 LOG] Starting Web Interface...'
    print '[D2 LOG] Login: %s ; Password: %s' % (self.username, self.password)
    django.core.management.execute_manager(settings)
    return 1

if __name__ == '__main__':
  guidjango().run()
