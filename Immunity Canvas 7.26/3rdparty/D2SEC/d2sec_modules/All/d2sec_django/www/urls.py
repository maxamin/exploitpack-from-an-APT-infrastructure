import django.contrib.admin
from django.conf.urls.defaults import *

django.contrib.admin.autodiscover()
urlpatterns = patterns('',
	(r'^(.*)$', django.contrib.admin.site.root),
)
