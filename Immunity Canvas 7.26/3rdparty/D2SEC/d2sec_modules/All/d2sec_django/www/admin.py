import django.contrib.admin
import models

class InfoAdminInline(django.contrib.admin.TabularInline):
  model               = models.Info

class VulnAdminInline(django.contrib.admin.TabularInline):
  model               = models.Vuln

class UserAdminInline(django.contrib.admin.TabularInline):
  model               = models.User

class HostAdmin(django.contrib.admin.ModelAdmin):
  date_hierarchy      = 'date_init'
  ordering            = ['date_last']
  save_on_top         = True
  search_title        = ['title', 'service_title', 'service_port', 'service_layer']
  list_display        = ('title', 'host', 'shortlist_services', 'shortnum_infos', 'shortnum_vulns')
  fields              = ['title', 'host']
  inlines             = [InfoAdminInline, VulnAdminInline]

class VulnAdmin(django.contrib.admin.ModelAdmin):
  search_fields       = ['title', 'vuln_desc', 'host__host', 'host__title', 'module', 'service__title', 'service__port', 'service__layer']
  list_display        = ('title', 'host', 'module', 'service', 'date_last')
  save_on_top         = True

class InfoAdmin(django.contrib.admin.ModelAdmin):
  search_fields       = ['title', 'desc', 'host__host', 'host__title', 'module', 'service__title', 'service__port', 'service__layer']
  list_display        = ('title', 'host', 'module', 'service', 'short_desc', 'date_last')
  save_on_top         = True

class UserAdmin(django.contrib.admin.ModelAdmin):
  search_fields       = ['host__host', 'user']
  list_display        = ('host', 'user', 'passwd')
  save_on_top         = True

django.contrib.admin.site.register(models.Host, HostAdmin)
django.contrib.admin.site.register(models.Vuln, VulnAdmin)
django.contrib.admin.site.register(models.Info, InfoAdmin)
django.contrib.admin.site.register(models.User, UserAdmin)
