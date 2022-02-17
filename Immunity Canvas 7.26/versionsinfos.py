#! /usr/bin/env python

import os
from internal import add_python_paths


def check_supported_attr(name, object, attr_list):
    assert object
    assert attr_list
    supported_attr = []
    missing_attr = []
    if not name:
        name = "unknown"
    for attr in attr_list:
        if hasattr(object, attr):
            supported_attr += [attr]
        else:
            missing_attr += [attr]
    #if supported_attr:
    #    print "[.] %s supports: %s" % (name, supported_attr)
    #if missing_attr:
    #    print "[!] %s does NOT support: %s" % (name, supported_attr)
    return supported_attr


def gtk_supported():
    supporteddict = {}
    try:
        import gobject, gtk 
    except ImportError:
        return {}
    liststore = gtk.ListStore(gobject.TYPE_STRING)
    supporteddict['gtk.ListStore'] = check_supported_attr("gtk.ListStore", liststore, \
        ["reorder", "swap", "iter_is_valid", "move_before", "move_after"])
    supporteddict['gtk.TreeModel'] = check_supported_attr("gtk.TreeModel", liststore, \
        ["get_string_from_iter", "get", "filter_new", "get_string_from_iter"])
    return supporteddict


def versionsinfos():
    versionsdict = {'error_msgs': []}
    
    has_os_name = False
    # <platform>
    try:
        import platform
        versionsdict['python_version'] = "Python v%s (%s)" % (platform.python_version(), platform.python_compiler())
        #print "[+] Python v%s (%s)" % (platform.python_version(), platform.python_compiler())
        versionsdict['platform.py'] = "platform.py v%s (%s %s, %s %s)" % (platform.__version__, \
            platform.architecture()[0], platform.processor(), platform.machine(), platform.release())
        #print "[.] platform.py v%s (%s %s, %s %s)" % (platform.__version__, \
        #    platform.architecture()[0], platform.processor(), platform.machine(), platform.release())
        uname_str = str(platform.uname())
        libc = platform.libc_ver()
        if libc != ("", ""):
            versionsdict['libc'] = "libc: %s %s" % platform.libc_ver()
        #print "[.] libc: %s %s" % libc
    except:
        versionsdict['error_msgs'] += ["can not import platform"]
        #print "[!] can not import platform"
        if hasattr(os, 'uname'):
            uname = os.uname()
            uname_str = "%s %s (%s) - %s" % (uname[0], uname[2], uname[3], uname[4])
        else:
            uname_str = os.name
            has_os_name = True
    # </platform>
    if not has_os_name:
        versionsdict['os_name'] = "os.name: %s" % os.name
    #print "[+] os.name: %s" % os.name
    versionsdict['uname'] = "uname: %s" % uname_str
    #print "[-] uname: %s %s (%s) - %s" % (uname[0], uname[2], uname[3], uname[4])
    
    
    # <site>
    import sys
    if sys.modules.has_key('site'):
        #print "[.] %s" % sys.modules['site']
        versionsdict['site'] = "%s" % sys.modules['site']
    else:
        #print "[!] can't find path of module 'site'"
        versionsdict['error_msgs'] += ["can't find path of module 'site'"]
    # </site>
    
    
    # <gobject>
    try:
        import gobject
        if hasattr(gobject, "glib_version"):
            versionsdict['gobject_glib'] = "gobject: glib v%d.%d.%d" % gobject.glib_version
            #print "[.] gobject: glib v%d.%d.%d" % gobject.glib_version
        if hasattr(gobject, "pygtk_version"):
            versionsdict['gobject_pygtk'] = "gobject: pygtk v%d.%d.%d" % gobject.pygtk_version
            #print "[.] gobject: pygtk v%d.%d.%d" % gobject.pygtk_version
    except:
        #print "[!] can not import gobject"
        versionsdict['error_msgs'] += ["can not import gobject"]
    # </gobject>
    
    
    # <gtk>
    try:
        import gtk
        if hasattr(gtk, "gtk_version"):
            #print "[.] gtk: gtk v%d.%d.%d" % gtk.gtk_version
            versionsdict['gtk'] = "gtk v%d.%d.%d" % gtk.gtk_version
        if hasattr(gtk, "pygtk_version"):
            #print "[.] gtk: pygtk v%d.%d.%d" % gtk.pygtk_version
            versionsdict['gtk_pygtk'] = "gtk: pygtk v%d.%d.%d" % gtk.pygtk_version
        
        gtk_supported_funcs = gtk_supported()
        versionsdict['gtk.ListStore'] = "gtk.ListStore supports: %s" % gtk_supported_funcs['gtk.ListStore']
        versionsdict['gtk.TreeModel'] = "gtk.TreeModel supports: %s" % gtk_supported_funcs['gtk.TreeModel']
        
    except RuntimeError:
        display = os.getenv("DISPLAY")
        if display:
            #print "[!] can not connect to %s" % display
            versionsdict['error_msgs'] += ["can not connect to DISPLAY=%s" % display]
        else:
            #print "[!] DISPLAY not set"
            versionsdict['error_msgs'] += ["$DISPLAY not set"]
        #print "[!] can not import gtk"
        versionsdict['error_msgs'] += ["can not import gtk"]
    except:
        #print "[!] can not import gtk"
        versionsdict['error_msgs'] += ["can not import gtk"]
    # </gtk>
    
    if versionsdict['error_msgs'] == []:
        versionsdict.pop('error_msgs')
    
    return versionsdict


if __name__=="__main__":
    
    add_python_paths()
    infos = versionsinfos()
    def dinfo(flag, key, desc = ""):
        global infos
        if infos.has_key(key):
            print "[%s] %s%s" % (flag, desc, infos[key])
    
    #print infos
    #for ik in infos.keys():
    #    print "<%s> %s" % (ik, infos[ik])
    
    dinfo('+', 'python_version')
    dinfo('.', 'platform.py')
    dinfo('.', 'libc')
    dinfo('+', 'os_name')
    dinfo('-', 'uname')
    dinfo('.', 'site')
    dinfo('.', 'gobject_glib')
    dinfo('.', 'gobject_pygtk')
    dinfo('.', 'gtk', "gtk: ")
    dinfo('.', 'gtk_pygtk')
    dinfo('.', 'gtk.ListStore')
    dinfo('.', 'gtk.TreeModel')

