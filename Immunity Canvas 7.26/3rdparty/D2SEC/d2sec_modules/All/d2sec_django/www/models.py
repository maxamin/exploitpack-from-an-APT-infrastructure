from django.db import models

class Host(models.Model):
  title                   = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  date_init               = models.DateTimeField(auto_now_add=True)
  date_last               = models.DateTimeField(auto_now=True)
  host                    = models.CharField(max_length=64, db_index=True)

  PRIMARY                 = 'host'

  def __unicode__(self):
    return self.title

  def shortlist_services(self):
    return ', '.join([str(i.title) for i in self.service_set.all().order_by('pk') ])
  shortlist_services.short_description = 'Services'

  def shortnum_infos(self):
    return str(len(self.info_set.all()))
  shortnum_infos.short_description = 'Infos'

  def shortnum_vulns(self):
    return str(len(self.vuln_set.all()))
  shortnum_vulns.short_description = 'Vulns'

  def get_services(self):
    return self.service_set.all().order_by('port')

class Service(models.Model):
  host                    = models.ForeignKey(Host, blank=False, null=False)
  date_init               = models.DateTimeField(auto_now_add=True)
  date_last               = models.DateTimeField(auto_now=True)
  title                   = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  port                    = models.PositiveIntegerField(blank=False, null=False, db_index=True)
  layer                   = models.CharField(max_length=32, blank=False, null=False, db_index=True)

  def __unicode__(self):
    return self.title

class Vuln(models.Model):
  host                    = models.ForeignKey(Host, blank=False, null=False)
  date_init               = models.DateTimeField(auto_now_add=True)
  date_last               = models.DateTimeField(auto_now=True)
  service                 = models.ForeignKey(Service, blank=False, null=False)
  title                   = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  module                  = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  vuln_desc               = models.TextField(db_index=False)

  def __unicode__(self):
    return self.title

class Info(models.Model):
  host                    = models.ForeignKey(Host, blank=False, null=False)
  date_init               = models.DateTimeField(auto_now_add=True)
  date_last               = models.DateTimeField(auto_now=True)
  service                 = models.ForeignKey(Service, blank=True, null=True)
  title                   = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  module                  = models.CharField(max_length=255, blank=False, null=False, db_index=True)
  desc                    = models.TextField(db_index=False)

  def __unicode__(self):
    return self.title

  def short_desc(self):
    if len(self.desc) > 150:
      return self.desc[:150] + '...'
    return self.desc

class User(models.Model):
  host                    = models.ForeignKey(Host, blank=False, null=False)
  date_init               = models.DateTimeField(auto_now_add=True)
  date_last               = models.DateTimeField(auto_now=True)
  user                    = models.CharField(max_length=255)
  passwd                  = models.CharField(max_length=255)

  def __unicode__(self):
    return self.host
