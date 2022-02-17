import threading
import models
import django.contrib.auth.models

class db:

    def __init__(self):
        self.db_lock = threading.Lock()

    def db_unique_host(self, title=None, host=None):
        if title is not None:
            target = self.db_get_host(title=title)
        else:
            target = self.db_get_host(host=host)
        if not target:
            if title is None:
                title = host
            target = self.db_new_host(title=title, host=host)
        else:
            if title is not None:
                target.title = title
            self.db_lock.acquire()
            target.save()
            self.db_lock.release()
        return target 

    def db_new_host(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Host(**attrs)
            obj.save()
            print 'd2sec_django - Saved new host "%s" to database OK' % attrs['title']
        except Exception, e:
            print 'd2sec_django - Failed to save new host "%s" : %s' % (attrs['title'], e)
            obj = None
        self.db_lock.release()
        return obj

    def db_get_host(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Host.objects.get(**attrs)
        except Exception, e:
            obj = None
        self.db_lock.release()
        return obj

    def db_get_host_services(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Service.objects.filter(**attrs)
        except Exception, e:
            obj = None
        self.db_lock.release()
        return obj

    def db_get_hosts_all(self):
        self.db_lock.acquire()
        try:
            obj = models.Host.objects.all()
        except Exception, e:
            obj = None
        self.db_lock.release()
        return obj

    def db_new_info(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Info(**attrs)
            obj.save()
            print 'd2sec_django - Saved "%s" for host "%s" to database OK' % (attrs['title'], attrs['host'])
        except Exception, e:
            print 'd2sec_django - Failed to save info "%s" for host "%s" : %s' % (attrs['title'], attrs['host'], e)
            obj = None
        self.db_lock.release()
        return obj

    def db_get_info(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Info.objects.get(**attrs)
        except Exception, e:
            obj = None
        self.db_lock.release()
        return obj

    def db_get_infos(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Info.objects.filter(**attrs)
        except Exception, e:
            obj = []
        self.db_lock.release()
        return obj

    def db_unique_info(self, host, service, title, module, desc):
        if not desc:
            return None
        info = self.db_get_info(host=host, service=service, title=title)
        if not info:
            info = self.db_new_info(host=host, service=service, title=title, module=module, desc=desc)
        else:
            print 'd2sec_django - Info "%s" for host "%s" : Already exists' % (title, host)
            self.db_lock.acquire()
            info.desc = desc
            info.save()
            self.db_lock.release()
        return info

    def db_unique_vuln(self, **attrs):
        vuln = self.db_get_vuln(host=attrs["host"], service=attrs["service"], title=attrs["title"])
        if not vuln:
            vuln = self.db_new_vuln(**attrs)
        else:
            print 'd2sec_django - Vulnerability "%s" for host "%s" : Already exists' % (attrs['title'], attrs['host'])
            # self.db_lock.acquire()
            # vuln.desc = desc
            # vuln.save()
            # self.db_lock.release()
        return vuln

    def db_new_vuln(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Vuln(**attrs)
            obj.save()
            print 'd2sec_django - New vulnerability "%s" for host "%s"' % (attrs['title'], attrs['host'])
        except Exception, e:
            print '[D2 LOG] Failed to save vulnerability "%s" for host "%s" : %s' % (attrs['title'], attrs['host'], e)
            obj = None
        self.db_lock.release()
        return obj

    def db_get_vuln(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Vuln.objects.get(**attrs)
        except Exception, e:
            obj = None
        self.db_lock.release()
        return obj

    def db_get_vulns(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Vuln.objects.filter(**attrs)
        except Exception, e:
            obj = []
        self.db_lock.release()
        return obj

    def db_new_service(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Service(**attrs)
            obj.save()
            print 'd2sec_django - Saved service "%s" for host "%s" to database OK' % (attrs['title'], attrs['host'])
        except Exception, e:
            print 'd2sec_django - Failed to save service "%s" for host "%s" : %s' % (attrs['title'], attrs['host'], e)
            obj = None
        self.db_lock.release()
        return obj

    def db_get_service(self, **attrs):
        self.db_lock.acquire()
        try:
            obj = models.Service.objects.get(**attrs)
        except Exception, e:
            obj  = None
        self.db_lock.release()
        return obj

    def db_unique_service(self, host, title):
        srvnfo = title.split('/')
        try:
            port = int(srvnfo[0])
        except Exception, e:
            print 'd2sec_django - Failed to save service "%s" : %s' % (title, e)
            return None
        srvdb = self.db_get_service(host=host, title=title, port=port, layer=srvnfo[1])
        if not srvdb:
            srvdb = self.db_new_service(host=host, title=title, port=port, layer=srvnfo[1])
        else:
            print 'd2sec_django - Service "%s" for host "%s" : Already exists' % (title, host)
        return srvdb

    def db_new_user(self, **attrs):
      self.db_lock.acquire()
      try:
        obj = models.User(**attrs)
        obj.save()
        print 'd2sec_django - New user "%s" for host "%s"' % (attrs['user'], attrs['host'])
      except Exception, e:
        print 'd2sec_django - Failed to save user "%s" for host "%s" : %s' % (attrs['user'], attrs['host'], e)
        obj = None
      self.db_lock.release()
      return obj

    def db_get_user(self, **attrs):
      self.db_lock.acquire()
      try:
        obj = models.User.objects.get(**attrs)
      except Exception, e:
        obj  = None
      self.db_lock.release()
      return obj

    def db_unique_user(self, host, user, passwd):
		usr = self.db_get_user(host=host, user=user)
		if not usr:
			usr = self.db_new_user(host=host, user=user, passwd=passwd)
		else:
			print 'd2sec_django - User "%s" for host "%s" : Already exists' % (user, host)
		return usr

