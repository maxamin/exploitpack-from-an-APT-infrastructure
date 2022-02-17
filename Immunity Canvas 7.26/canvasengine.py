#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  canvasengine.py
## Description:
##            :
## Created_On :  Thu Aug 20 12:09:47 2009
## Created_By :  Rich
## Modified_On:  Mon Mar 22 13:43:57 2010
## Modified_By:  Rich
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
#! /usr/bin/env python
#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

"""
canvasengine.py

CANVAS's Engine
"""


from __future__ import with_statement
from datetime import datetime
import logging
import warnings

#Change this to enable Project BALLOON features
BALLOON = 0

import os, sys
#this is a quick check to see if they are running the exploit from the wrong directory
if "." not in sys.path: sys.path.append(".")

import re
import time
import shutil
import platform

USE_COLORS = True
if platform.system() == "Windows":
    USE_COLORS = False


from internal import *
# activate debugging if --debug in argv (for customers)
_debug_opt = "--debug"
_debug_file = "debug.log"
if _debug_opt in sys.argv:
    sys.stderr = file(_debug_file, 'ab')
    sys.stderr.write("\n\n-----[ NEW DEBUG SESSION ]-----\n\n\n")
    add_debug_level('all')
    # cleaning argv in case
    while _debug_opt in sys.argv:
        sys.argv.remove(_debug_opt)

from internal.utils import setup_logging, setup_session_logging
setup_logging(enable_debug=debug_enabled)

########################
#translation support
import gettext
do_auto_translations = False
if 0:
    #define this if you are doing automatic translations
    #but we cannot distribute this because it means people
    #cannot run CANVAS headless
    from gui.canvasguigtk2 import do_auto_translations
if do_auto_translations:
    #use to create a .po
    from gui.canvasguigtk2 import output_translatable_string

    _=output_translatable_string
else:
    #normal behavior
    _ = gettext.gettext
gettext.bindtextdomain("CANVAS",localedir = "gui/locale/")
gettext.textdomain("CANVAS")
######

from engine import CanvasConfig
from engine.config import canvas_root_directory
from engine.config import canvas_resources_directory
from engine.config import canvas_reports_directory
from libs.daveutil import dmkdir

from engine.http_mosdef import http_mosdef

#for Unixshell Nodes
from libs.ctelnetlib import Telnet
from shelllistener import shelllistener
from shelllistener import androidShellListener
from shelllistener import shellfromtelnet

# Import our stuff first
sys.path.insert(0, os.path.abspath('./libs'))

from libs import yaml
import socket
from exploitutils import *

#import Threading
from threading import RLock, Thread

# mutexing
import mutex

from exploitmanager import exploitmanager
import ConfigParser
sys.path = uniqlist(sys.path)

import extras.versioncheck as versioncheck
import libs.canvasos as canvasos

if CanvasConfig['sound']:
    import sounds.sound as sound

if CanvasConfig['sniffer']:
    try:
        import sniffer
        from localsniffer import localsniffer
    except:
        logging.warning("No sniffer - CRI version?")

from localNode import localNode
#    from SQLNode import SQLNode

# new style shellservers support ..
from MOSDEFShellServer import MosdefShellServer

# new reporter
from libs import reports

from internal.colors import color_text
from engine.features import *


VERSION = "5.0" #GUI Version, not CANVAS version
DEFAULTCOLOR = "black"

# ???
PHPMULTI = "PHP MULTI OS"
UNIXSHELL = "UNIXSHELL"
ANDROIDSHELL = "ANDROID SHELL"

# making a push to sanitize and clean our naming conventions ..
FREEBSDMOSDEF_INTEL = "FREEBSD MOSDEF INTEL"
WIN32MOSDEF_INTEL   = "WIN32 MOSDEF INTEL"
WIN32MOSDEF_INTEL_FCT = "WIN32 MODSEF INTEL FromCreateThread"
WIN64MOSDEF_INTEL   = "WIN64 MOSDEF INTEL"
OSXMOSDEF_PPC       = "OSX MOSDEF PPC"
OSXMOSDEF_INTEL     = "OSX MOSDEF INTEL"
OSXMOSDEF_X64       = "OSX MOSDEF X64"
AIXMOSDEF_51_PPC    = "AIX 5.1 MOSDEF PPC"
AIXMOSDEF_52_PPC    = "AIX 5.2 MOSDEF PPC"
SOLARISMOSDEF_INTEL = "SOLARIS MOSDEF INTEL"
SOLARISMOSDEF_SPARC = "SOLARIS MOSDEF SPARC"
LINUXMOSDEF_INTEL   = "LINUX MOSDEF INTEL"
LINUXMOSDEF_X64     = "LINUX MOSDEF X64"
LINUXEXECVE_INTEL   = "LINUX EXECVE INTEL"
HTTPMOSDEF          = "HTTP MOSDEF PLAINTEXT"
HTTPMOSDEF_SSL      = "HTTP MOSDEF SSL"
JAVASERVER          = "JAVA MOSDEF"
UNIVERSAL_MOSDEF    = "Universal MOSDEF"
DNSMOSDEF           = "DNS MOSDEF"
LINUXMOSDEF_ARM9    = "LINUX MOSDEF ARM9"
POWERSHELL_MOSDEF   = "POWERSHELL MOSDEF"

# backwards compatibility with old listener types ..
SOLARISSPARCMOSDEF = SOLARISMOSDEF_SPARC # backwards compatibility
LINUXMOSDEF = LINUXMOSDEF_INTEL # all the old sploits using this will be using intel
HTTPSMOSDEF = HTTPMOSDEF_SSL
WIN32MOSDEF = WIN32MOSDEF_INTEL
WIN64MOSDEF = WIN64MOSDEF_INTEL


def set_session_name(name=None, eng=None):
    """
    Initialise/change a CANVAS session name
    """
    # set our session name
    global SESSION_NAME
    if not name:
        SESSION_NAME = CanvasConfig["canvas_session_name"]
    else:
        SESSION_NAME = name

    global CANVAS_OUTPUT_DIR
    CANVAS_OUTPUT_DIR = os.path.join(CanvasConfig["canvas_output"], SESSION_NAME)
    dmkdir(CANVAS_OUTPUT_DIR)

    logging.warning("Setting CANVAS session to: %s" % (SESSION_NAME))

    # If we have been passed an existing canvasengine then we also need to update the logfile locations & reset
    # our output directory for other output
    if eng:
        eng.reporter = reports.Reporter(SESSION_NAME, _backup_overwrite=True)
        setup_session_logging(name=SESSION_NAME)

##Set our initial CANVAS session name
set_session_name()

#used by ms03026.py. Fd's placed in this list will not be closed when
#the exploit is done
global socket_save_list
socket_save_list=[]

global canvaslanguage
canvaslanguage = "EN" #english by default

# TODO use Fortune() from exploitutils
try:
    fortunes = open("misfortunes.txt").readlines()
except:
    try:
        fortunes = open("fortunes.txt").readlines()
    except:
        fortunes = ["",""]
import random
random.shuffle(fortunes)
currentfortune=0

from libs.smartlist import smartlist, load_smartlist

def capme(astr):
    """
    ABDC -> Abcd
    """
    if not astr:
        return ""
    if len(astr) == 1:
        return astr.upper()
    ret = astr[0].upper() + astr[1:].lower()
    return ret

def csvit(anobject):
    """
    converts an object to a string and removes commas (which mess up our comma seperated values format)
    """
    anobject = str(anobject).replace(",", "-")
    return anobject

def html_docs_from_module(module):
    """
    Returns a sort of HTML documentation string from a canvas module
    You'll want to see gui/text_with_markup.py for rendering

    TODO: order all documentations the same way instead of randomly based on the hash table's whims

    TODO: support links and images in documentation
    """

    # sometimes this blows up on instance methods ..
    try:
        if not hasattr(module, "DOCUMENTATION"):
            module.DOCUMENTATION = {}
    except:
        return "", ""

    docdic = module.DOCUMENTATION
    showdoc = "\n<module>\n"

    name = module.NAME.upper() # Reverted since we're not splitting

    # Alexm: Added for Customer request, behold the total lack of regular expressions!
    if module.DOCUMENTATION.has_key("CVE Name") and module.DOCUMENTATION["CVE Name"] != None:
        docslite = name + " - " + module.DOCUMENTATION["CVE Name"] + " - "
        # There's not a standard CVE URL vs. CVE Url, so I figured it better to be safe
        if module.DOCUMENTATION.has_key("CVE Url") and module.DOCUMENTATION["CVE Url"] != None:
            docslite += module.DOCUMENTATION["CVE Url"] + "\n"
        else:
            docslite += module.DOCUMENTATION.get("CVE URL", "*Unknown*") + "\n"
    else:
        docslite = None

    csvdoc = [csvit(name)] #comma seperated value for spreadsheets

    # TITLE setting
    # XXX: header too strong imo
    showdoc += "<b>%s</b><br/>\n"%xmlencode(name)
    if module.DESCRIPTION and module.DESCRIPTION.upper() != module.NAME.upper():
        showdoc += "%s"%xmlencode(_(module.DESCRIPTION))
        showdoc += "<br/><br/>\n"
    else:
        showdoc += "<br/>\n"

    csvdoc += [csvit(_(module.DESCRIPTION))] #TODO ADD ENCODING

    # PROPERTY parsing
    if hasattr(module, "PROPERTY"):
        #handle properties dictionary
        for key in module.PROPERTY:
            if module.PROPERTY[key]: # XXX: don't do null strings or lists
                showdoc += "<b>%s: </b>%s<br/>\n"%(xmlencode(key.upper()),xmlencode(module.PROPERTY[key]))
                csvdoc += [csvit(key)+":"+csvit(module.PROPERTY[key])] #TODO ADD ENCODING
        cKeys = module.PROPERTY.keys()
    else:
        cKeys = []

    # DOCUMENTATION parsin
    for ea in docdic.keys():
        # XXX: if key is already handled by PROPERTY dict, don't show it here
        # sometimes MSADV is shown double
        if ea in cKeys:
            pass
        elif docdic[ea]: # XXX: do not show empty strings
            showdoc += "<b>%s: </b>%s<br/>\n"%(xmlencode(ea.upper()),xmlencode(docdic.get(ea)))
            csvdoc += [csvit(ea)+":"+csvit(docdic.get(ea))] #TODO ADD ENCODING
    showdoc += "<br/>\n" #newline to separate our documentation from our other data
    if not hasattr(module, "theexploit"):
        logging.error("Module does not have 'theexploit' method")
        return
    sploit = module.theexploit()

    try:
        connectbackdata = sploit.neededListenerTypes()
    except:
        connectbackdata = []
    if connectbackdata != []:
        showdoc += "<b>Connectback type: </b>%s<br/>\n"%(connectbackdata)


    if sploit.listenerArgsDict.get("fromcreatethread", 0):
        #some modules, like ifids, have fromcreatethread set, but are
        #not connectbacks
        if not hasattr(sploit, "needsNoShellcode") or not sploit.needsNoShellcode:
            showdoc += "<b>Commandline usage: </b>" + xmlencode("Requires a fromcreatethread WIN32 MOSDEF listener") + "\n"
    showdoc += "</module>\n\n"
    # XXX: why is this returning a tuple ? (also edit gui code if you edit return type here)
    return showdoc, csvdoc, docslite

class CANVASENGINEException(Exception):
    pass

defaultmodules=["osdetect", "addhost", "gethostbyname", "emailsender", "startservice"]
#,"oraclegetinfo","oraclegetuser","oraclegetpwd"]
#defaultmodules+=["ms05_040","enumservices","osdetect"]
defaultmodules += ["userenum"]
defaultmodules += ["shareenum"]

def interestingDirlist(dirlist, topdir = ".", wantdir = True):
    """
    remove uninteresting dirs/files
    i.e.: CVS .svn .vim.swp
    """
    retlist = []
    for dirname in dirlist:
        # Temporary code for dealing with our new tree organization
        if dirname in ["local",
                       "remote",
                       "clientside",
                       "trojan",
                       "DoS",
                       "tool",
                       "reporting",
                       "server",
                       "config",
                       "fuzzer",
                       "command",
                       "recon",
                       "web",
                       "incomplete",
                       "importexport"]:
            continue
        if dirname in ["CVS"] or dirname[0] == '.' or (wantdir and not os.path.isdir(topdir + os.path.sep + dirname)):
            devlog('interestingDirlist', "%s discarded" % dirname)
            continue
        retlist.append(dirname)
    return retlist

def checkAndSetPath(name):
    dirname = ""
    # not in root directory (e.g. VisualSploit)
    cwd = os.getcwd()
    if cwd.find("VisualSploit") != -1:
        dirname = ".." + os.path.sep + "exploits" + os.path.sep + name
        logging.info("Dirname set to: %s" % dirname)
        # set ../ relative paths for anything that has ../../
        # print sys.path
        for path in sys.path:
            if path.find("../../") != -1 or path.find("..\\..\\") != -1:
                # we have to be cross os.path.sep compatible, because we hardcode "../../" a lot
                # therefor we can't actually use os.path.sep effectively.
                logging.info("Fixing path for VisualSploit: %s" % path)
                path = path.replace("../../", ".." + os.path.sep) # doesn't change if not there
                path = path.replace("..\\..\\", ".." + os.path.sep) # doesn't change if not there
                if path not in sys.path:
                    sys.path.insert(0, path)
    else:
        path = ""
        # This is a shortcut lookup table set by registerAll to make it easy for us
        for k,v in moduleDirectoryMap.iteritems():
            if name in v:
                path = k
                break

        dirname =  os.path.join(path, name)
    return dirname

#global list of all exploit modules...
__exploitmods_old = {}    # keep for compatibility *DEPRECATED*
__exploitmods = {} # new way

class CanvasModule:
    """
    1 instance for each module
    """

    def __init__(self, name, path, mod = None):
        self.name = name
        self.path = path
        self.mod  = mod

        self.processModule()

    def __str__(self):
        return "<loaded CANVAS Module '%s'>" % self.name

    def reload(self):
        sys.path.insert(0, self.path)
        self.mod = reload(self.mod)
        sys.path.remove(self.path)
        self.processModule()
        return self.mod

    def processModule(self):
        """
        Here, we can perform set up for each module, such as processing/validating its PROPERTY dict. This
        used to be done in the gui tree populationg code, but obviously doesn't belong in there.
        """
        exploitmod = self.mod
        name = self.name
        #Changed name from "property" to "propertyDict", since the first one is reserved.
        if hasattr(exploitmod, "PROPERTY"):
            devlog("canvasengine", "Exploitmod %s has PROPERTY" % name)
            propertyDict = exploitmod.PROPERTY
        else:
            logging.error("Attribute error found while processing %s/%s.py" % (self.path, self.name))
            logging.error("PROPERTY{} dictionary is missing")
            logging.error("Import of %s/%s.py failed" % (self.path, self.name))
            raise AssertionError
        # check properties
        property_ref = {
            'TYPE': "",
            'SITE': "",
            'ARCH': [],
            'PROC': [],
            '0DAY': False,
            'MSADV': "",
        }

        # normalize property's keys -> all in CAPS
        for key in propertyDict.keys():
            if not key.isupper():
                propertyDict[key.upper()] = propertyDict[key]
                del propertyDict[key]

        # check property's types once
        for key in property_ref.keys():
            if propertyDict.has_key(key):
                assert type(propertyDict[key]) is type(property_ref[key]), \
                       "\n\n%s.PROPERTY['%s'] is %s\n%s expected\n" % \
                       (name, key, type(propertyDict[key]), type(property_ref[key]))
            else:
                # set default
                propertyDict[key] = property_ref[key]

        # we want DOCUMENTATION{}
        if not hasattr(exploitmod, "DOCUMENTATION"):
            devlog('import_exploits', "%s.DOCUMENTATION missing" % name)
            exploitmod.DOCUMENTATION = {}

        # process MSADV
        if propertyDict['MSADV'] != "":
            propertyDict['MSADV'] = propertyDict['MSADV'].upper()
            if propertyDict['MSADV'][0:2] != "MS":
                propertyDict['MSADV'] = "MS%s" % propertyDict['MSADV']
            assert propertyDict['MSADV'][4] == "-", "MSADV has to be in the form \"MSxx-xxx\""
            # force DOCUMENTATION['MSADV']
            exploitmod.DOCUMENTATION['MSADV'] = propertyDict['MSADV']

        if 'ARCH' not in propertyDict:
            devlog('import_exploits', "%s.PROPERTY['ARCH'] missing" % name)

        # push update into module for now, so that canvasos.fromModule gets it
        # but before we butcher up Arch/Version/OS next :(
        exploitmod.PROPERTY = propertyDict
        exploitmod.TARGET_CANVASOS_LIST = canvasos.fromModule(exploitmod)

        if not propertyDict['0DAY'] and "0DAY" in exploitmod.DESCRIPTION.upper():
            devlog('import_exploits', "0DAY in description, but %s.PROPERTY['0DAY']=True not set" % name)
            propertyDict['0DAY'] = True

        if propertyDict['0DAY'] and exploitmod.DESCRIPTION[0:6] != "[0day]":
            devlog('import_exploits', "%s.PROPERTY['0DAY']=True but not '[0day]' in description" % name)
            exploitmod.DESCRIPTION = "[0day] " + exploitmod.DESCRIPTION

        # </transition>

        # common to 0days
        if propertyDict['0DAY']:
            # some exploits files are copy/paste from public bug
            # and have some wrong "release date"
            # here we reset that to be more coherent.
            if exploitmod.DOCUMENTATION.has_key("Date public") and \
               exploitmod.DOCUMENTATION["Date public"] not in \
               ["Not public/0day", "Not Public / 0day", "Not Public/0day"]:
                devlog('import_exploits', "%s.PROPERTY['0DAY']=True but 'Date public' is %s" % \
                       (name, exploitmod.DOCUMENTATION["Date public"]))
            exploitmod.DOCUMENTATION["Date public"] = "Not public/0day"

        #Removed the "OS" property, since in 1179 modules it is literally never used.

        for x in exploitPacks.itervalues():
            if self.name in x.modules:
                exploitmod.exploitPack = x
                break

        exploitmod.PROPERTY = propertyDict


    def aaa__processModule(self):
        """
        Here, we can perform set up for each module, such as processing/validating its PROPERTY dict. This
        used to be done in the gui tree populationg code, but obviously doesn't belong in there.
        """
        exploitmod = self.mod
        name = self.name

        if hasattr(exploitmod, "PROPERTY"):
            devlog("canvasengine", "Exploitmod %s has PROPERTY" % name)
            property = exploitmod.PROPERTY
        else:
            logging.error("Attribute error found while processing %s/%s.py" % (self.path, self.name))
            logging.error("PROPERTY{} dictionary is missing")
            logging.error("Import of %s/%s.py failed" % (self.path, self.name))
            raise AssertionError

        # check properties
        property_ref = {
            'TYPE': "",
            'SITE': "",
            'ARCH': [],
            'OS': [],
            'PROC': [],
            '0DAY': False,
            'MSADV': "",
        }

        # normalize property's keys -> all in CAPS
        for key in property.keys():
            if not key.isupper():
                property[key.upper()] = property[key]
                del property[key]

        # check property's types once
        for key in property_ref.keys():
            if property.has_key(key):
                assert type(property[key]) is type(property_ref[key]), \
                       "\n\n%s.PROPERTY['%s'] is %s\n%s expected\n" % \
                       (name, key, type(property[key]), type(property_ref[key]))
            else:
                # set default
                property[key] = property_ref[key]

        # we want DOCUMENTATION{}
        if not hasattr(exploitmod, "DOCUMENTATION"):
            devlog('import_exploits', "%s.DOCUMENTATION missing" % name)
            exploitmod.DOCUMENTATION = {}

        # process MSADV
        if property['MSADV'] != "":
            property['MSADV'] = property['MSADV'].upper()
            if property['MSADV'][0:2] != "MS":
                property['MSADV'] = "MS%s" % property['MSADV']
            assert property['MSADV'][4] == "-", "MSADV has to be in the form \"MSxx-xxx\""
            # force DOCUMENTATION['MSADV']
            exploitmod.DOCUMENTATION['MSADV'] = property['MSADV']

        # we would like PROPERTY['ARCH']
        if not len(property['ARCH']):
            devlog('import_exploits', "%s.PROPERTY['ARCH'] missing" % name)

        # push update into module for now, so that canvasos.fromModule gets it
        # but before we butcher up Arch/Version/OS next :(
        exploitmod.PROPERTY = property
        exploitmod.TARGET_CANVASOS_LIST = canvasos.fromModule(exploitmod)

        # :(
        #if len(exploitmod.TARGET_CANVASOS_LIST) == 0 and property['TYPE'] in ["Exploit", "Web Exploit"]:
        #    raise AssertionError("Module %s has no targets, according to canvasos.fromModule. ARCH: %s" % (name, property['ARCH']))

        # build ARCH from OS + PROC
        for OS in property['OS']:
            f = True
            # avoid duplicate ARCH / OS
            for aOS in property['ARCH']:
                #assert type(aOS) == type([])
                if aOS[0] == OS:
                    f = False
            if not f:
                continue
            aOS = [OS]
            if property.has_key('PROC'):
                for proc in property['PROC']:
                    aOS.append(proc)
            property['ARCH'].append(aOS)

        # TODO: clean that for()
        devlog('gui::fillmoduletree', "property[ARCH] = %s" % property['ARCH'])
        for arch in property['ARCH']:
            if len(arch) == 1:
                versions_list = ["All"]
            else:
                versions_list = arch[1:]
            # for Windows, expand Version list
            if arch[0] == "Windows": # caps?
                if property.has_key('VERSION'):
                    import string
                    property['VERSION'] = map(string.upper, property['VERSION'])
                    if "ALL" in property['VERSION']:
                        #arch.append("ALL")
                        arch = ["Windows", "All"]
                    else:
                        versions_list = property['VERSION']
                    del property['VERSION']
                else:
                    #arch.append("ALL")
                    arch = ["Windows", "All"]
                if arch == ["Windows", "All"]: #len(arch) == 2 and arch[1].upper() == "ALL":
                    del arch[1]
                    versions_list = ["NT", "2000", "XP", "2003", "Vista"]

            arch += versions_list

        devlog('gui::fillmoduletree', "property[ARCH] = %s" % property['ARCH'])

        if not property['0DAY'] and "0DAY" in exploitmod.DESCRIPTION.upper():
            devlog('import_exploits', "0DAY in description, but %s.PROPERTY['0DAY']=True not set" % name)
            property['0DAY'] = True

        if property['0DAY'] and exploitmod.DESCRIPTION[0:6] != "[0day]":
            devlog('import_exploits', "%s.PROPERTY['0DAY']=True but not '[0day]' in description" % name)
            exploitmod.DESCRIPTION = "[0day] " + exploitmod.DESCRIPTION

        # </transition>

        # common to 0days
        if property['0DAY']:
            # some exploits files are copy/paste from public bug
            # and have some wrong "release date"
            # here we reset that to be more coherent.
            if exploitmod.DOCUMENTATION.has_key("Date public") and \
               exploitmod.DOCUMENTATION["Date public"] not in \
               ["Not public/0day", "Not Public / 0day", "Not Public/0day"]:
                devlog('import_exploits', "%s.PROPERTY['0DAY']=True but 'Date public' is %s" % \
                       (name, exploitmod.DOCUMENTATION["Date public"]))
            exploitmod.DOCUMENTATION["Date public"] = "Not public/0day"

        ep = None
        for x in exploitPacks.itervalues():
            if self.name in x.modules:
                ep = x
                break

        if ep:
            exploitmod.exploitPack = ep

        # Make sure changes are propagated back into the module.
        exploitmod.PROPERTY = property

class __RegisterModulesLog:
    def __init__(self):
        self.modnum     = 0
        self.curidx     = 0

    def run(self, func):
        func()

    def setcuridx(self, idx):
        self.curidx = idx

    def setmax(self, maxnum):
        self.modnum = maxnum

    def log(self, name):
        writeflush_for_status("[+] Loading %s ..." % name)

    def setstatus(self, succeeded = 1):
        out = {1: " ok ", 2: "fail"}
        text = "[" + color_text(out[succeeded], succeeded, True, use_colors=USE_COLORS) + "]\n"
        # writeflush(text)
        self.curidx += 1
        return text

    def succeeded(self):
        self.setstatus()

    def failed(self):
        self.setstatus(2)

registermoduleslog = __RegisterModulesLog()

class __CanvasModules:
    """
    1 instance that hold all modules
    """

    def __init__(self):
        pass

# This stores a map of module names and the directory we are to load it from
# keys are directory names, value is a list of exploits from that directory
moduleDirectoryMap = {}

EXPLOITPACK_LICENSE_FLAG=".exploitPackLicenseSeen"

class ExploitPackError(Exception):
    pass

class ExploitPack:
    """One of these is instantiated for each CANVAS exploit pack"""

    def __init__(self, path):
        self.path            = path
        self.exploitdirs     = []
        self.exploitSections = {}
        self.modules         = []
        self.third_party     = True
        self.loadInfo(path)
        self.setup()

        #print "ExploitPack (%s)->%s"%(self.name, self.modules)

    def hasModule(self, module):
        """ Returns true if the module is one of ours """
        return module in self.modules

    def setup(self):
        for p in self.libdirsWalked:
            if p not in sys.path:
                sys.path.append(p)

    def unsetup(self):
        for p in self.libdirsWalked:
            if p in sys.path:
                sys.path.remove(p)

    def isDemo(self):
        return self.demo == "Yes"

    def loadInfo(self, path):
        configPath = os.path.join(path, "package.info")
        if os.path.exists(configPath):
            cp = ConfigParser.SafeConfigParser()
            try:
                cp.read(configPath)
            except:
                logging.error("Failed to load config file: %s" % configPath)
                #print this out because that pack will need to fix it:
                logging.error("Printing exception for CANVAS Exploit Pack")
                import traceback
                traceback.print_exc(file=sys.stderr)
                logging.error("Exploit pack config file could not be read: %s" % configPath)
                raise ExploitPackError()

            #this is where self.name comes from
            for k in ["name", "longName", "author", "version", "libdirs", "demo", "readme", "contactUrl", "contactEmail", "contactPhone", "license"]:
                setattr(self, k, cp.get("main", k))

            # If exploit pack author == Immunity, it is not a third party pack
            try:
                if self.author.lower() == 'immunity': self.third_party = False
            except Exception:
                pass

            self.license = os.path.join(path, self.license)
            if not os.path.exists(self.license):
                raise ExploitPackError("CANVAS Exploit pack License file %s missing" % self.license)

            self.readme = os.path.join(path, self.readme)
            if not os.path.exists(self.readme):
                raise ExploitPackError("CANVAS Exploit pack Readme file %s missing" % self.readme)

            if self.demo not in ["Yes", "No"]:
                raise ExploitPackError("CANVAS Exploit Pack demo value %s is not one of 'Yes' or 'No'")

            libdirs = []
            def addDir(arg, dirname, names):
                libdirs.append(dirname)

            for i in self.libdirs.split(","):
                os.path.walk(os.path.join(self.path, i), addDir, None)

            self.libdirsWalked = libdirs

            logging.info("Initializing exploit pack: [%s]" % self.longName)

            for section in cp.sections():
                if section == "main":
                    continue
                x = os.path.join(path, section)

                if os.path.exists(x):
                    self.exploitdirs.append(x)
                    devlog("canvasengine: Added exploit pack exploit path: %s" % x)
                    logging.info("Exploit pack [%s] initialized correctly" % self.longName)
                    # print "[+] Exploit pack (%s) initialized" % self.longName
                    # registermoduleslog.succeeded()
                else:
                    raise ExploitPackError("Exploits directory (%s) specified in exploit pack (%s) is missing" % (x, self.name))

            # print ""

            for d in self.exploitdirs:
                self.modules += processModuleDir(d)


        else:
            raise ExploitPackError("No package.info file in exploit pack directory %s" % path)

# Stores a name:exploitPack instances dict
exploitPacks = {}
loadedExploitPaths = None

def loadExploitPaths():
    """Single place to handle paths to exploit collections"""
    # This might be called multiple times, so it must be safe to do so.

    global exploitPacks
    global loadedExploitPaths

    if loadedExploitPaths != None:
        return loadedExploitPaths

    #
    # XXX: We are still including exploits/ allowing people to simply drop modules
    #      in there only to provide time before the final change
    #
    exploitdirslist = ["exploits/web",
                       "exploits/remote/universal",
                       "exploits/remote/windows",
                       "exploits/remote/unix",
                       "exploits/remote/cisco",
                       "exploits/local/windows",
                       "exploits/local/unix",
                       "exploits/clientside/universal",
                       "exploits/clientside/windows",
                       "exploits/clientside/unix",
                       "exploits/trojan",
                       "exploits/command/universal",
                       "exploits/command/windows",
                       "exploits/command/unix",
                       "exploits/recon",
                       "exploits/DoS",
                       "exploits/tool",
                       "exploits/reporting",
                       "exploits/server",
                       "exploits/config",
                       "exploits/importexport",
                       "exploits/fuzzer",
                       "exploits"]

    for d in exploitdirslist:
        processModuleDir(d)

    exploitpacks = CanvasConfig.get("exploit_pack_dirs", "").split(",")
    if "EXPLOITPACKS" in os.environ:
        for d in os.environ["EXPLOITPACKS"].split(","):
            exploitpacks.append(d)

    for epd in exploitpacks:
        if os.path.exists(epd):
            for i in os.listdir(epd):
                if i == ".svn":
                    continue
                p = os.path.join(epd, i)
                if os.path.isdir(p):
                    try:
                        ep = ExploitPack(p)
                        if ep.name not in exploitPacks.keys():
                            exploitPacks[ep.name] = ep
                        else:
                            # If we have both the demo and the full versions of the same pack, we discard the demo one
                            # in favour of the full-flavoured version.
                            if ep.demo == "No" and exploitPacks[ep.name].demo == "Yes":
                                exploitPacks[ep.name].unsetup()
                                exploitPacks[ep.name] = ep

                        exploitdirslist += ep.exploitdirs
                    except ExploitPackError, i:
                        logging.error("Error loading exploit pack from %s: %s" % (p, i))


    if "MOREEXPLOITS" in os.environ:
        newpath = os.environ["MOREEXPLOITS"]
        devlog("canvasengine", "Loading more exploits from %s" % newpath)
        exploitdirslist.append(newpath)
        processModuleDir(newpath)

    loadedExploitPaths = exploitdirslist
    return exploitdirslist

def processModuleDir(mydir):
    global moduleDirectoryMap

    exploitsNames = os.listdir(mydir)
    exploitsNames = interestingDirlist(exploitsNames, mydir)
    exploitsNames.sort()

    moduleDirectoryMap[mydir] = exploitsNames

    return exploitsNames

def exploitmodsGet(extmode = False):
    global __exploitmods_old
    global __exploitmods
    if extmode:
        return __exploitmods
    return __exploitmods_old

def registeredModuleList(extmode = False, functype = 'keys'):
    modulelist = getattr(exploitmodsGet(extmode), functype)()
    modulelist.sort()
    return modulelist

def registerModule(name):
    """
    Imports and adds an exploit module to our list, returns 1 on success"
    """
    assert not '-' in name, "[-] Can't import modules with '-' in name (tried to import %s)" % name

    global __exploitmods_old
    if __exploitmods_old.has_key(name):
        devlog('registerModule', "return module from cache: %s" % __exploitmods_old[name])
        return __exploitmods_old[name]

    # Too verbose - A.
    # registermoduleslog.log(name)
    loadExploitPaths()
    dirname = checkAndSetPath(name)

    rname = name

    sys.path.insert(0, dirname)
    # XXX TODO clean VSP code here.
    try:
        exploitmod = __import__(rname, globals(), locals(), [dirname])
    except ImportError:
        # first module import on VisualSploit will fail because sys.path was not fixed yet
        cwd = os.getcwd()
        if cwd.find("VisualSploit") != -1:
            logging.warning("Ignoring initial exception due to VisualSploit path fix")
            dirname = checkAndSetPath(name)
            try:
                exploitmod = __import__(rname, globals(), locals(), [dirname])
            except ImportError:
                if debug_enabled:
                    import traceback
                    traceback.print_exc(file=sys.stdout)
                    devlog('all', "Was unable to import %s" % name)
                exploitmod = None #failure
        else:
            if debug_enabled:
                import traceback
                traceback.print_exc(file=sys.stdout)
                # XXX shouldn't be a print here? to tell the user smth is wrong.
                devlog('all', "Was unable to import %s" % name)
            exploitmod = None #failure

    sys.path.remove(dirname)

    if exploitmod:
        yaml_path = os.path.join(dirname, "canvas.yaml")
        if os.path.isfile(yaml_path):
            try:
                with open(yaml_path) as f:
                    metadata = yaml.load(f)

                for _key, _val in metadata.iteritems():
                    setattr(exploitmod, _key, _val)
                if not hasattr(exploitmod, "EXPLOIT_PACK_NAME"):
                    setattr(exploitmod, "EXPLOIT_PACK_NAME", getExploitPackName(exploitmod))
            except Exception as e:
                logging.error("Error while loading %s (%s)" % (exploitmod, str(e)))

        try:
            mod = CanvasModule(name, dirname, exploitmod)
            __exploitmods_old[name] = exploitmod
            __exploitmods[name] = mod
        except Exception, ex:
            registermoduleslog.failed()
            bugreport()
        # Too verbose - A
        # registermoduleslog.succeeded()
    else:
        devlog('registerModule', "exploitmod[%s] == None?" % name)
        logging.error("Error while loading %s" % name)
        bugreport(print_traceback_stderr = False)
    return exploitmod #success

def count_registered_modules():
    return len(exploitmodsGet())

def unregisterModule(name):
    if __exploitmods.has_key(name):
        del __exploitmods[name]
    if __exploitmods_old.has_key(name):
        del __exploitmods_old[name]

def registerSomeModules(modulelist, notify_complete = False):
    """
    For exploits that need to register a few modules, but you don't
    want to register ALL the modules
    """
    # map(registerModule, modulelist)
    registeredModules = 0
    for module in modulelist:
        if registerModule(module):
            registeredModules += 1

    if notify_complete:
        notify_complete()

    return registeredModules

registeredallmodules = 0

# def registerAllModules():
def registerAllModules(notify_complete = False):
    """
    Note that if you have the environment variable MOREEXPLOITS set, we can also load from another
    directory tree...
    """

    logging.info("Registering modules...")
    exploitdirslist = loadExploitPaths()
    registeredallmodules = 1

    registeredModules = 0

    for mydir in exploitdirslist:
        exploitsNames = processModuleDir(mydir)
        number_of_modules = len(exploitsNames)
        #have to multiply by two because we do 2 pushes for each module (on success/failure)
        registermoduleslog.setcuridx(count_registered_modules())
        registermoduleslog.setmax(number_of_modules * 2)
        devlog("canvasengine", "Exploit names loading %d modules" % len(exploitsNames))
        mods_registered = registerSomeModules(exploitsNames)
        registeredModules += mods_registered

    mods = "%d" % registeredModules
    logging.info("Registered %s modules" % color_text(mods, status=0, bold=True, use_colors=USE_COLORS))
    get_root_m = getModule("GetRoot")
    if get_root_m:
        logging.info("Checking launching preconditions...")
        get_root_m.checkModules()

    if notify_complete:
        notify_complete()

class modulesInThread(Thread):
    """Used to load modules in one thread while gui displays status about that
    in another window"""
    def __init__(self):
        Thread.__init__(self)
        self.mylock=RLock()

    def run(self):
        self.mylock.acquire()
        devlog("Waiting for gui to come up before starting to register modules")
        time.sleep(3) #wait for gui to come up
        devlog( "Waited")
        registerAllModules()
        self.mylock.release()
        return

def registerAllModulesInThread():
    """
    Used to load the modules in one thread while the GUI updates in another
    """
    mit=modulesInThread()
    # print "[+] Starting loading modules in thread"
    mit.start() #start new thread
    time.sleep(1) #wait for Rlock to be acquired
    return mit

def reloadAllModules():
    for mod in registeredModuleList(extmode=True, functype = 'values'):
        devlog('all', "reloading %s" % mod, nodesc = True)
        mod.reload()

def unloadAllModules():
    for mod in registeredModuleList(extmode=True, functype = 'values'):
        del mod

def getModule(name, extmode = False):
    #print "[C] Getting module %s"%name
    exploitslist = exploitmodsGet(extmode)
    if not exploitslist.has_key(name):
        registerModule(name)
    if exploitslist.has_key(name):
        return exploitslist[name]
    # if we didn't add the new modules to the list before, smth is wrong :/
    logging.warning("Loaded modules: %s" % exploitslist.keys())
    raise CANVASENGINEException, "[-] Module %s not found" % name

def getModules(names):
    """Get a list of modules from a list of names"""
    return map(getModule,names)

def getModuleExploitClass(name, which='theexploit'):
    # XXX not safe, could raise CANVASENGINEException
    return getattr(getModule(name), which)
    #return getModule(name).theexploit

def getModuleExploit(name):
    # XXX not safe, could raise CANVASENGINEException
    return getModule(name).theexploit()

def delModule(name):
    unregisterModule(name)

def genericDocumentation(exploitType):
    #
    # Pass this function your exploit type PROPERTY["TYPE"] or PROPERTY["SITE"] and recieve documentation!
    exploitType = exploitType.upper()

    if "WEB" in exploitType:
        docs = """
        Web exploits are generally called directly from the GUI by double clicking on the module name and are
        written for Linux hosts.

        Web exploits are usually bugs in PHP applications that allow us to include code to be run server side. This is
        usually via include/eval/RFI/LFI/etc means.
        """

    elif "CLIENT" in exploitType:
        docs = """
        Clientsides can be run from the built in httpserver by specifying the clientside module name in the "module name"
        argument for httpserver. Targets were then have to browse to your instance of httpserver to be served the exploit.

        Double clicking the exploit directly will generate a file or set of files for you to serve yourself. Be sure you have
        a listener running as CANVAS may not start one for you automatically in this instance.

        Clientsides are vulnerabilities that require some type of user interaction to achieve exploitation. Typically this means a
        vulnerability is reachable via the browser and a user must browse to you to be exploited. Sometimes the bug is in
        code not reachable via the browser and the user must open a file to be exploited.

        A free tutorial for clientsides is available at: http://forum.immunityinc.com/index.php?topic=298.0
        """

    elif "REMOTE" in exploitType:
        docs = """
        Remote exploits are run by double clicking on the module directly.

        Remote exploits take advantage of vulnerabilities in code reachable over the network. Some remote exploits require
        authentication and others do not, double click your exploit to see.
        """

    elif "LOCAL" in exploitType:
        docs = """
        Local exploits require that you have some level of access to the host already, usually this means a MOSDEF shell.
        By clicking on a node in your node management Window you set that node as your focus and now exploits will be run
        from the perspective of that host. This is required of local exploits.
        """
    else:
        docs = "No expanded documentation for this module"

    return docs

def getAllListenerOptions():
    """
    This function is mostly used to fill up the dialog box that pops up
    when you try to start a new MOSDEF listener manually
    """

    # listener types .. try to keep these organized by os and arch !

    # XXX: do not reorder these, some of our static payloads rely on
    # XXX: these indexes to remain the same ...

    return [WIN32MOSDEF_INTEL,
            WIN32MOSDEF_INTEL_FCT,
            WIN64MOSDEF_INTEL,
            LINUXMOSDEF_INTEL,
            LINUXEXECVE_INTEL,
            HTTPMOSDEF,
            HTTPMOSDEF_SSL,
            PHPMULTI,
            OSXMOSDEF_INTEL,
            OSXMOSDEF_PPC,
            FREEBSDMOSDEF_INTEL,
            SOLARISMOSDEF_SPARC,
            SOLARISMOSDEF_INTEL,
            AIXMOSDEF_51_PPC,
            AIXMOSDEF_52_PPC,
            JAVASERVER,
            UNIXSHELL,
            UNIVERSAL_MOSDEF,
            ANDROIDSHELL,
            OSXMOSDEF_X64,
            DNSMOSDEF,
            LINUXMOSDEF_ARM9,
            LINUXMOSDEF_X64,
            POWERSHELL_MOSDEF,
            ] # indexes into this list are the MOSDEF types, do not add new types anywhere but to the end of this list

class runExploitClass(Thread):
    """
    Used just for starting up an exploit in its own thread, so the start up
    process itself doesn't freeze any potential gui. We set it
    as a Daemon thread.
    """
    def __init__(self,engine,module,argsDict):
        Thread.__init__(self)
        self.engine=engine
        self.module=module
        self.argsDict=argsDict
        self.setDaemon(1)

    def run(self):
        runExploit(self.engine,self.module,self.argsDict)




# XXX: daemonFlag added for better control of threading semantics
# XXX: daemonFlag controls setDeamon(True/False) in exploitmanager
# XXX: __init__ ... this is needed e.g. for SILICA engine inits
# XXX: the default is None, so it defaults to old behaviour and will
# XXX: remain to work without any daemonFlag arguments

# SILICA note:
# what was happening was that for alex, the only active thread
# was a daemon thread, as per python threading specs, it will exit
# the python program when there are no active non-deamon threads..so
# we needed to be able to setDeamon True/False explicitly in
# situations where the only active thread is the runexploit thread

def runExploit(engine, module, argsDict, daemonFlag=None, silicaGui=None):
    """
    GUI independent code that runs the exploit

    Because we start up a callback listener on demand if we cannot find one already
    started, this routine may sometimes block. Hence, it should always be in
    its own thread (not the Main thread).

    Returns the Thread and the CANVASEXPLOIT object. If you want to halt the thread nicely
    call CANVASEXPLOIT.halt().
    On failure returns (0, None)
    So check for that.

    This function will return a LIST of (manager, exploit) objects
    if engine.target_hosts has more than one host in it
    """
    #print "Version is %d"%version
    #print "Method is %d"%method
    #print "runExploit()"
    ret=[]
    devlog("canvasengine", "Running exploit on %d hosts"%len(engine.target_hosts))
    for targethost in engine.target_hosts:

        #for each host, we run the exploit!
        app=module.theexploit()

        if (hasattr(targethost, "interface")):
            devlog("canvasengine", "Running exploit %s on host %s"%(app.name,targethost.interface))
        app.setId(engine.getNewListenerId())
        app.engine=engine
        app.gui=engine.gui
        if(silicaGui):
            app.gui = silicaGui
        app.argsDict = argsDict
        #need to set the method first since module.neededListener type requires it - SER
        #also move the setVersion higher up since in some of the sploits app.neededListenerTypes() checks for it
        app.setLogFunction(engine.exploitlog)
        app.setDebugFunction(engine.exploitdebuglog)

        app.setDataViewColumnsFunction(engine.DataViewColumns)
        app.setDataViewInfoFunction(engine.DataViewInfo)

        #print "Setting info"
        app.setInfo(app.getInfo())
        #print "Adding Listener"
        engine.addExploitLine(app)
        app.setCovertness(engine.getCovertness())
        #print "starting"
        #set the three main variables for the exploit
        app.argsDict["passednodes"]=engine.passednodes
        app.version=app.argsDict["version"]

        if targethost==None:
            logging.error("Weird error in engine with target_host==None!")
            return False
        if hasattr(targethost,"interface")==False:
            devlog("canvasengine","runExploit: engine.target_host.interface==None?! %s"%str(targethost))
        app.target=targethost

        if app.version==0: # XXX is that code correct? if you know write an explanation here please.
            devlog('canvasengine', "Test version found ... starting")
            manager=exploitmanager(app, engine, daemonFlag)
            manager.start()
            ret+=[ (manager, app) ]
            continue

        devlog('canvasengine', "%s.neededListenerTypes=%s"%(app.name,app.neededListenerTypes()))
        #sys.stdout.flush()
        #this code is duplicated in exploitmanager, be careful
        neededlistenertypes=app.neededListenerTypes()

        # XXX we needed no-autofind control for httpserver (can't match target to callback there!)
        autoFind = True
        if hasattr(app, "autoFind"):
            autoFind = app.autoFind

        # check for http proxy port control from httpserver
        if 'HTTPPROXYPORT' in app.listenerArgsDict:
            HTTPPROXYPORT = int(app.listenerArgsDict['HTTPPROXYPORT'])
        else:
            HTTPPROXYPORT = 0

        if neededlistenertypes != []:
            logging.info("Running autolistener for exploit that wants listener: %s" % repr(neededlistenertypes))
            devlog("canvasengine", "Doing autolistener from canvasengine::RunExploit")
            listener = engine.autoListener(app, neededlistenertypes[0], host=app.target.interface, autoFind=autoFind, HTTPPROXYPORT=HTTPPROXYPORT)

            if listener == None: #still none? Then print error message
                engine.log("[-] You need to select a valid listener %s for this exploit!"%(app.neededListenerTypes()))
                return 0, None

            if not hasattr(app, "fromcreatethread") or not app.fromcreatethread:
                #if the exploit does not have fromcreatethread then we need
                #to explicitly set it to false
                devlog("canvasengine", "Setting fromcreatethread to false!")
                listener.argsDict["fromcreatethread"]=False

            if listener.type!=UNIVERSAL_MOSDEF:
                devlog('canvasengine', "Setting listener: %s, argsdict: %s" % (listener, app.listenerArgsDict))
                listener.argsDict=app.listenerArgsDict
                listener.current_exploit=app
        else:
            listener=None


        app.callback=listener #note: this is a listener, not an interface!
        devlog('canvasengine', "Set app.callback to %s"%app.callback)
        manager=exploitmanager(app, engine, daemonFlag)
        devlog('canvasengine', "calling manager.start()")
        manager.start()

        engine.log("[+] Running exploit %s"%_(module.DESCRIPTION))
        ret+=[(manager, app)]

    if len(engine.target_hosts)==1:
        #one host selected, choosing compatability mode
        #we don't want to return a list in this case
        ret=ret[0]

    return ret



from threading import Thread

class threadListenerStarter(Thread):
    """
    When the engine receives a new callback (typically from pyGTK's event loop)
    it spawns this threadListenerStarter to handle doing the actual initialization.

    If the callback is coming back to a MOSDEFSock, this class is not used.

    We're threaded to get the socket work out of the Main thread. You don't want to
    do any of the slow stuff we do in the gui thread.
    """
    def __init__(self):
        Thread.__init__(self, verbose=debug_threads)
        self.setDaemon(1)
        self.engine = None
        self.listener = None
        self.newsocket = None
        self.newip = None

    def log(self, msg):
        self.engine.log(msg)

    def run(self):
        logging.info("Starting our new listener")
        newshell=self.engine.new_node_connection(self.listener,self.newsocket, self.newip)

        if newshell in [0]:
            #failed to get our new listener!
            devlog("engine", "Failed to get a new listener - did it die while we were doing startup?")
            return 0

        self.listener.lastnewnode = newshell

        devlog("Started up new node")
        newshell.started=1
        try:
            fd = self.newsocket.fileno()
        except:
            logging.error("Failed to init new shell server :<")
            #failed. :<
            return 1
        #if newshell.parentnode.nodetype=="LocalNode":
        #    id1 = self.engine.gui.input_add(newsocket, self.gui.get_input_read(), lambda x,y:self.activeListener(newshell.shell,x,y))
        return


class hostadder(Thread):
    """
    This class is used to put all host adding into its own thread
    Otherwise the gui can potentially lock up...
    """
    def __init__(self,kline,host):
        Thread.__init__(self, verbose=debug_threads)
        self.setDaemon(1)
        self.host = host
        self.kline = kline

    def run(self):
        kLine = self.kline
        host = self.host
        node = kLine.parent
        #gethostbyname can potentilly time out...rocky has all sorts of issues here
        host = node.gethostbyname(host) #always use the IP
        if host in node.get_all_known_hosts():
            return

        newhost = node.new_host(host)
        #newhost.add_knowledge("OS: %s"%os) #add later
        #self.gui.addknownhost(newhost,None,None)
        return

class proxyThread(Thread):
    def __init__(self, engine, ssl, server_port, mosdef_host, mosdef_port, passednodes):
        Thread.__init__(self)
        self.engine         = engine
        self.server_port    = server_port
        self.mosdef_host    = mosdef_host
        self.mosdef_port    = mosdef_port
        self.ssl            = ssl
        self.passednodes    = passednodes
        self.http_proxy     = None

    def run(self):
        self.http_proxy = self.engine.getModuleExploit('http_proxy')
        self.http_proxy.link(self.engine)
        self.http_proxy.argsDict['port']         = int(self.server_port)
        self.http_proxy.argsDict['mosdef_host']  = self.mosdef_host
        self.http_proxy.argsDict['mosdef_port']  = self.mosdef_port
        self.http_proxy.argsDict['useSSL']       = self.ssl
        self.http_proxy.argsDict['passednodes']  = self.passednodes
        return self.http_proxy.run()

    def halt_gracefully(self):
        # halt gracefully ...
        self.http_proxy.state = self.http_proxy.HALT

    def suicide(self):
        # hard teardown (will take down CANVAS with it)
        os._exit(0)

class dnsProxyThread(Thread):
    def __init__(self, engine, mosdef_host, mosdef_port, passednodes):
        Thread.__init__(self)
        self.engine         = engine
        self.mosdef_host    = mosdef_host
        self.mosdef_port    = mosdef_port
        self.passednodes    = passednodes
        self.dns_proxy      = None
        return

    def run(self):
        self.dns_proxy = self.engine.getModuleExploit('dns_proxy')
        self.dns_proxy.link(self.engine)
        self.dns_proxy.argsDict['mosdef_host']  = self.mosdef_host
        self.dns_proxy.argsDict['mosdef_port']  = self.mosdef_port
        self.dns_proxy.argsDict['passednodes']  = self.passednodes
        return self.dns_proxy.run()

    def halt_gracefully(self):
        # halt gracefully ...
        self.dns_proxy.state = self.dns_proxy.HALT

    def suicide(self):
        # hard teardown (will take down CANVAS with it)
        os._exit(0)

class canvasengine:
    """
    This class has all the canvas logic in it - hopefully none of the GTK stuff will slip in here...
    """

    #valid modes for osdetect:
    ASSUME_ONE_LANG         = "Assume One Language" #assume we are English
    ASSUME_NEAREST_NEIGHBOR = "Assume Nearest Neighbor" #assume we are similar to our neighbors
    ASSUME_NO_RUN           = "Assume Don't Run" #don't run if we can't get the language/sp

    def __init__(self, gui=None, silica=False, session_name=None):
        devlog("engine", "Initializing engine")

        self.allexploits                         = []
        self.debug                               = debug_enabled
        self.logfile                             = None
        self.silica                              = silica

        # Generic event layer, pretty basic for now
        # Ideally you want event classes => finegrained hooking
        self.event_handlers                      = []

        # dictionary for session-based logging
        # in the form: node_logging_sessions[IP] => [ timestamp, current_log_file ]
        self.node_logging_sessions               = {}
        self.current_logging_host                = None

        #dictonary of our http mosdef listeners sorted by port
        self.http_mosdef_listeners               = {}

        self.passednodes                         = []
        self.notnewgui                           = 0 #1 for old gui
        #turn this on for debugging prints - good if the gui is broken
        self.localnode                           = None
        self.allListeners                        = []
        self.nodeList                            = []
        self.useAutoListener                     = 1 #1 for start a new listener when none is selected
        self.config                              = CanvasConfig

        if gui == None:
            from gui.defaultgui import defaultgui
            gui = defaultgui(handle_callbacks=1)

        registerSomeModules(defaultmodules)
        self.gui = gui

        banner = color_text("\n[***] CANVAS Started [***]\n", status=0, bold=True, use_colors=USE_COLORS)
        self.do_new_version_check()

        ##RICH
        self.proxy_threads = []
        if session_name:
            set_session_name(session_name, self)

        self.OUTPUT_DIR = CANVAS_OUTPUT_DIR

        self.country_exclude_list = []

        try:
            f = file("country_exclude_list")
            self.country_exclude_list=f.readlines()
        except:
            logging.warning("No country exclude list loaded")

        #future iterations of this need to be per-host. Each host can have N listeners
        self.maxListenerId = 0

        # self.log(banner)
        print banner

        self.knownhosts = []
        self.idlock = RLock()
        self.covertness = int(self.config['default_covertness', "1"]) #default is very reliable
        node = self.loadLocalNode()
        node.engine= self
        node.findLocalHosts()

        self.mosdefid = 1
        self.newMosdefIDlock = RLock()

        #a dictionary of all our ID's connected to exploits
        #if you're clearing out all known exploits you'll also have to clear this!
        self.mosdef_shellcode_ids = {}
        self.mosdef_shellcode_modules = {} # maintains a reverse mapping of module to id

        self.localsniffer = None #we need this to define the variable
        self.callback_interface = None

        # set target
        if self.config['default_target_ip']:
            target = node.get_known_host(self.config['default_target_ip'])
            logging.info("Using default target ip <%s>" % self.config['default_target_ip'])
        else:
            target = node.get_first_known_host()

        self.target_hosts = [target]
        target.set_as_target()
        self.set_target_host(target)
        self.reset_callback_interface()
        self.set_first_node(node) #select this node by default - some exploits use this

        to_ip = node.interfaces.get_last()

        self.nodeTree = node
        self.snifferfilterstring = "ip(%s)"%self.callback_interface.ip
        if self.config['sniffer']:
            self.initLocalSniffer()

        #LANGUAGE AND SP DETECTION DEFAULTS (essentially configuration)
        #This defaults to "ASSUME_NO_RUN" because when a VM starts up, it will
        #not have printer service started yet, which means that you will get
        #[English, Japanese, Korean, etc.] as your language list. We need
        #to not attack in those cases or we will kill a process

        self.osdetect_mode = canvasengine.ASSUME_NO_RUN
        self.osdetect_lang = "English" #language to assume if we need to

        #smartlist loading
        self.smartlist = load_smartlist()


        # Let's check whether we need to startup a default listener
        # as dictated in the canvas.conf file
        if self.config['auto_listener']:
            # default auto-listener
            newinterface=self.localnode.getMatchingInterface(self.config["auto_listener_interface"])
            self.start_listener( newinterface, self.config["auto_listener_type"], int(self.config["auto_listener_port"]), self.config["auto_listener_createthread"] )

            # more auto-listeners
            auto_listeners = set([x for x in self.config.keys() if re.match('auto_listener_.+_interface', x)])

            for l in auto_listeners:
                base = l[:-10]
                newinterface = self.localnode.getMatchingInterface(self.config[l])
                self.start_listener(newinterface, self.config[base+'_type'], int(self.config[base+'_port']), self.config[base+'_createthread'])

        # new shell startup mutexing
        self.newshell_mutex            = mutex.mutex()

        #MeatNode stuff
        self.registered_contact_routes = []
        self.current_contact_routes    = {}

        self.reporter                  = reports.Reporter(session_name, _backup_overwrite=True)
        self.canvasversion             = self.getCANVASVersion()
        self.getLicenseData()

        #Avoid being shut down twice
        self.was_shutdown              = False

        # Add the reporter event handler as it doesn't keep a reference
        # to canvasengine

        self.add_event_handler(self.reporter.new_event)

    def add_event_handler(self, callback):
        """
        Add a callback function that will be executed when
        canvasengine.new_event gets called.

        Callback prototype should be identical to canvasengine.new_event.
        Multiple handlers can be active and will be executed in sequence,
        last to first.
        """
        self.event_handlers.append(callback)

    def remove_event_handler(self, callback):
        self.event_handlers.remove(callback)

    def new_event(self, name, data, module_name='canvas'):
        """
        Call all registered event handlers with the new event data.
        """
        devlog('event', '%s (%s): %s' % (name, module_name, repr(data)))
        [f(name, data, module_name) for f in reversed(self.event_handlers)]

    def getLicenseData(self):
        userdatafilename=os.path.join(canvas_root_directory,"userdata")
        try:
            expiredate,contactemail,username=file(userdatafilename,"r").readlines()[:3]
        except:
            expiredate,contactemail,username=("None","None","None")
        self.licensedata=(expiredate,contactemail,username)
        return

    def getCANVASVersion(self):
        return CanvasConfig['version']

    def cve_from_exploit(self, exploit):
        """
        Occasionally you want to get the CVE string from an exploit object - these
        are not stored in the exploit object themselves so it is best to get it from here.
        """
        ret="N/A"
        devlog("canvasengine", "cve_from_exploit: %r"%exploit)
        module=self.getModule(exploit.__module__)
        try:
            #finally get our CVE ID
            ret = module.DOCUMENTATION.get("CVE Name")
        except:
            devlog("canvasengine", "No DOCUMENTATION CVE NAME for %s"%exploit.__module__)

        return ret

    def do_new_version_check(self, callback=None, ps=""):
        """
        Throw up a new thread to check to see if we are running the latest version
        """
        if not callback:
            #Default
            cb = self.gui.out_of_date_action

        myversioncheck = versioncheck.versionchecker(self, ps=ps, callback=cb)
        myversioncheck.start() #start the new thread
        return

    def run_commandline(self, commandline):
        """
        Runs a commandline that was passed to us from the GUI

        This should be in its own thread, not the GUI thread!

        """
        #empty?
        if not commandline:
            return

        logging.info("Running commandline from GUI: %s" % commandline)
        modulename = commandline.split(" ")[0]
        args = " ".join(commandline.split(" ")[1:])
        try:
            app = self.getModuleExploit(modulename)
        except CANVASENGINEException:
            #no module named that.
            logging.error("No module named: %s" % modulename)
            return False
        self.addExploitLine(app)
        commandline_fromengine(app, self.passednodes, args)
        return True

    def reset_callback_interface(self):
        """
        Called on __init__ to set a default callback interface, but also called
        when a node is closed that has our callback interface on it - we reset that to
        our LocalNode's callback
        """
        node=self.localnode
        # set callback
        if self.config['default_callback_ip']:
            callback = node.interfaces.get_ip(self.config['default_callback_ip'])
            assert callback != None, "[EE] No interface with ip address %s available" % (self.config["default_callback_ip"])
            logging.info("Using default callback ip <%s> with interface <%s>" % (callback.ip, callback.interface))
        elif self.config['default_callback_interface']:
            callback = node.interfaces.get_interface(self.config['default_callback_interface'])
            if callback:
                logging.info("Using default callback interface <%s> with ip <%s>" % (callback.interface, callback.ip))
        else:
            callback = node.interfaces.get_last("ipv4")

        assert callback, "[EE] Could not get default interface, something is wrong"
        self.set_callback_interface(callback) #CALL BACK TO THIS IP
        callback.set_as_callback()
        return


    def shutdown(self):
        """
        This function is responsible for stopping any threads only the engine
        knows about
        """
        #import traceback
        #traceback.print_stack(file=sys.stderr)
        if self.was_shutdown:
            devlog("engine", "Already shut down!")
            return False
        #tiny race condition here, but we are not raced.
        self.was_shutdown = True

        try:
            self.localsniffer.shutdown()
        except:
            devlog('LocalSniffer', "No localsniffer to shutdown")
        # tear down any and all lingering proxy threads
        try:
            for t in self.proxy_threads:
                t.suicide()
        except:
            import traceback
            traceback.print_exc(file=sys.stderr)
            pass

        return

    def getModuleExploit(self, modulename):
        """
        Gets a new exploit and assigns its engine
        to us.

        Example
        getModuleExploit("connecttoservice")
        """
        newexploit = getModuleExploit(modulename)
        newexploit.engine = self
        return newexploit

    def getAllModules(self):
        ret=[]
        for module in registeredModuleList():
            ret+=[self.getModule(module)]
        return ret

    def getModulesOfType(self, moduletype):
        """
        Used by automater utilities - returns a list of modules of a given type (in PROPERTY)
        """
        return self.getModulesByProperty("TYPE", moduletype)

    def getModulesByProperty(self, key, value):
        ret=[] #list of all modules of type moduletype
        #print "In getModules(%s)"%moduletype
        for module in self.getAllModules():
            #print "Module %s"%module.NAME
            if hasattr(module, "PROPERTY"):
                #print "Module %s type: %s"%(module.NAME, module.PROPERTY.get(key))
                if module.PROPERTY.get(key)==value:
                    ret+=[module]
        return ret

    def getModule(self,modulename):
        return getModule(modulename)

    def initLocalSniffer(self):
        """
        The localsniffer operates in its own thread, and recvs packets continually
        and when you've assigned a callback, will also send you the packets
        If you are not running as root, or Admin on a support win32 interface,
        you won't be able to sniff and some moduleses won't work.

        This interface is meant to replace the older sniffer interface,
        which relied on tethereal and pipes.
        """

        try:
            self.localsniffer = localsniffer(engine=self)
        except:
            logging.warning("No local sniffer... CRI version")
            return 0
        if not self.localsniffer.running():
            #self.log("Could not open sniffer - not running as root/admin?")
            logging.error("Sniffer open failed - Sniffing and some modules disabled")
            return 0

        self.localsniffer.start()
        logging.info("Sniffer filter string set to: %s" % self.snifferfilterstring)
        # Q: Why register a callback that does nothing?
        # A: if you don't register atleast 1 callback, the sniffer does not sniff ...
        # Note: sniffer filterstring is set to local callback ip
        # Note: other options include:
        # filterstring = "layer(ethernet)"
        # filterstring = "type(arp)"
        # filterstring = "layer(ethernet) ipproto(tcp)
        # etc.
        self.register_sniffer_callback(self.sniffer_active,self.snifferfilterstring)
        logging.info("Started Sniffer")
        return 1

    def register_sniffer_callback(self,callback,filterstring): # here we could add restartparser option later
        # XXX sometimes sniffer can not start, and we have self.localsniffer = None
        # FIXME we catch AttributeError for now, but miss a better way
        devassert('all', self.localsniffer, "self.localsniffer is %s" % self.localsniffer)
        try:
            self.localsniffer.registercallback(callback,filterstring)
        except AttributeError:
            pass
        return

    def unregister_sniffer_callback(self,callback):
        devassert('all', self.localsniffer, "self.localsniffer is %s" % self.localsniffer)
        try:
            self.localsniffer.unregistercallback(callback)
        except AttributeError:
            pass
        return

    def sniffer_isactive(self):
        """
        return True if localsniffer is active, False else.
        """
        try:
            return self.localsniffer.running()
        except AttributeError:
            #if sniffer was disabled from canvas.conf we don't have a localsniffer object.
            return False

    def sniffer_active(self,parser): # this is a callback...
        #don't do this
        #self.sniffer_log(parser.getline())
        return

    def sniffer_log(self,message,color=DEFAULTCOLOR):
        message+="\n"
        #don't do this for threading reasons...
        #if for every packet we generate a gui_queue message, then we get
        #into an infinite loop, since our sniffer will see the packets the
        #gui_queue generates...
        #self.gui.gui_queue_append("snifferlogmessage",[message,color])
        return

    def save_session_state(self):
        """
        Save the state of all the objects/knowledge we can
        """
        self.log("Saving session state:")

        ##Read in state save manifest
        manifest_name       = ".state.save"
        state_dir           = self.create_new_session_output_dir("SavedState")
        saved_state_details = None

        try:
            fd = open(os.path.join(state_dir, manifest_name), "r")
            ## date/time - session name
            saved_state_details = fd.read()
            fd.close()
        except IOError, err:
            pass

        if self.gui:
            msg="""
            Are you sure you want to save CANVAS
            state from this session?
            """
            if saved_state_details:

                msg += """
            Doing this will overwrite the
            previously saved session:

            %s
                """ % (saved_state_details)

            sure = self.gui.pop_are_you_sure_box(msg, "Save session...")
            if not sure:
                logging.error("Session state save aborted by user")
                return

        ##Save all hosts associated with the Localnode
        self.localnode.hostsknowledge.save_state_all()
        for iface in self.localnode.interfaces.get_children():
            ## Save all the interfaces associated with localnode
            iface.save_state()

        ##Save all our current status objects - TODO

        ##Write manifest currently just date/time but eventually will hold user comments/tags etc
        manifest_name = ".state.save"
        state_dir     = self.create_new_session_output_dir("SavedState")

        try:
            fd = open(os.path.join(state_dir, manifest_name), "w")
            ## date/time - session name
            fd.write("%s %s"%(time.ctime(), SESSION_NAME))
            fd.close()
            logging.info("State manifest written")
        except IOError, err:
            logging.error("Error writing the state save manifest: %s"%(err))
            logging.error("Session state save failed")
            return 0

        logging.info("Session state saved")

    def restore_session_state(self):
        self.log("Restoring session state:")
        ##Read in state save manifest
        manifest_name = ".state.save"
        state_dir     = self.create_new_session_output_dir("SavedState")

        try:
            fd = open(os.path.join(state_dir, manifest_name), "r")
            ## date/time - session name
            saved_state_details = fd.read()
            fd.close()
        except IOError, err:
            logging.error("Error reading the state save manifest: %s. No state to restore"%(err))
            logging.error("Session state restore failed")
            return 0

        if self.gui:
            msg = """
            Are you sure you want to restore
            CANVAS state from the saved session:

            %s

            (Doing this will overwrite all your
             current session data.)
            """ % (saved_state_details)

            sure = self.gui.pop_are_you_sure_box(msg, "Restore session...")
            if not sure:
                logging.error("Session state restore aborted by user")
                return

        ##Save all hosts associated with the Localnode
        self.localnode.loadSavedHosts()

        logging.info("Session state restored")

    def create_new_session_output_dir(self, ip="", subdir=""):
        """
        Rich: new general method to place data we want to save to disk
        (screenshots/ram dumps etc) into the directory determined by
        canvas_output_dir in canvas.conf and to put it there with the correct
        directory structuring

        Response to Dave Bug: dir creation now falls back to creating output in
                              the current working dir if for some reason the
                              CANVAS_REPORT_DIR fails :)
        """
        ##Check if we have already created a subdir in canvas_output_dir for this CANVAS run
        try:
            dest_subdir=os.path.join(CANVAS_OUTPUT_DIR, ip ,subdir)

            if not os.path.exists(dest_subdir):
                logging.info("Creating new data output directory subdir %s" % (dest_subdir))
                dmkdir(dest_subdir)
            elif not os.path.isdir(dest_subdir):
                logging.error("New data output directory subdir already exists and is a file (%s)" % (dest_subdir))
                raise Exception, "[EE] Error while creating Report path %s" % (dest_subdir)

        except Exception, err:
            logging.error("Error while creating Report path: %s (permission problem?)" % err)
            dest_subdir = os.path.join(os.path.curdir, ip ,subdir)
            dmkdir(dest_subdir)
            logging.info("Falling back to using CURRENT WORKING DIRECCTORY '%s'" % (dest_subdir))

        ##If we are writing to the Reports subdir that means we are writing html so we need the css etc to make it look pretty, copy it from resources
        if "Reports" in subdir:
            template_files=["immunity.css", "header.gif"]

            for f in template_files:
                try:
                    os.stat(os.path.join(dest_subdir, f))
                except OSError:
                    ##File not already there so copy it
                    shutil.copy(os.path.join(CanvasConfig["canvas_resources"], f), dest_subdir )

        return dest_subdir

    def log(self, message, color=DEFAULTCOLOR, enter="\n", maxlength=130, startlength=80):
        """
        This function is deprecated since CANVAS 7.05

        Refactoring the entirety of our old modules is unnecessary, the way we
        are staying compatible is by leaving this function here and use the new
        logging mechanism rather than the old one
        """

        # This is sort of horrible but harmless
        # Ideally we want canvas to use unicode objects internally, but
        # this isn't always the case
        if not isinstance(message, unicode):
            try:
                message = message.decode('UTF-8')
            except UnicodeDecodeError:
                pass

        #
        # Try to uniform old log messages and use new logging mechanism
        #
        m = logging.info
        if ("[-]" or "[EE]") in message:
            m = logging.error
        elif "[!]" in message:
            m = logging.warning

        message = message.replace("[-] ", "").replace("[!] ", "").replace("[+] ", "").replace("[ii] ", "").replace("[EE] ", "")
        m(message)

    def debuglog(self, message, color=DEFAULTCOLOR, enter="\n"):
        """
        Deprecated in CANVAS 7.05, use logging.debug and set `logging_default_level`
        to debug in canvas.conf. Here for retrocompat

        Might be run in the thread context of the exploit, and not the gui
        """
        if self.debug:
            logging.debug(message)

        return

    def DataViewColumns(self, args):
        if self.gui:
            self.gui.gui_queue_append("set_data_view_columns",[args])
        return

    def DataViewInfo(self, args):
        if self.gui:
            self.gui.gui_queue_append("set_data_view_info",[args])
        return

    def threads_enter(self):
        #print "Engine: Thread enter."
        # XXX should not have gui in engine
        self.gui.gdk.threads_enter()
        return

    def threads_leave(self):
        #print "Engine: Thread leave."
        # XXX should not have gui in engine
        self.gui.gdk.threads_leave()
        return

    def closeSniffer(self):
        if self.snifferpipe!=None:
            # XXX should not have gui in engine
            if self.gui:
                self.gui.input_remove(self.sniffergtkid)
            self.snifferpipe=None
            logging.info("Closed old sniffer")
        return

    def successfortune(self):
        """logs a funny fortune from fortunes.txt"""
        global fortunes

        if len(fortunes)==0:
            # no fortunes, so we just return
            return

        global currentfortune
        if currentfortune==(len(fortunes)-1):
            currentfortune=0
        else:
            currentfortune+=1

        if self.gui: # DO I NEED THIS HERE?
            self.gui.play("OWN")
        self.log(fortunes[currentfortune].replace("&", "\n"), color="red")
        return

    def activeSniffer(self,source,condition):
        newline = self.snifferpipe[1].readline()
        if newline == "":
            logging.info("Received blank line from sniffer, closing")
            self.closeSniffer()
            return
        #print "New Sniffer Line: "+newline
        # XXX should not have gui in engine
        if self.gui:
            self.gui.addSnifferLine(newline)
        return

    def setSnifferFilterstring(self,filterstring):
        self.snifferfilterstring=filterstring
        return

    def set_covert_value(self,value):
        """
        Used by the gui to change our covert value
        """
        oldc = self.covertness
        self.covertness = round(value)
        if self.covertness != oldc:
            logging.info("Global covertness value set to %d" % self.covertness)
        return self.covertness

    def getCovertness(self):
        """
        In the future, this can do something interesting with the targetip - like see if it's
        an important host...
        """
        return self.covertness

    def exploitlog(self,message, color="black", enter="\n"):
        self.log(message,color, enter)

    def exploitdebuglog(self, message, color="black", enter="\n"):
        self.debuglog(message, color, enter)

    def addExploitLine(self,exploit):
        """
        This can be called from any thread
        """
        devlog("canvasengine", "Registering new exploit...%s"%exploit)
        self.gui.gui_queue_append("Register New Exploit",[exploit])

        return

    def haltAllExploits(self):
        """
        Sends the halt signal to every exploit we remember
        """
        for e in self.allexploits:
            e.halt()
        return

    def clearAllExploits(self):
        """
        Forget about all the exploits we've run. Useful for Silica
        """
        self.allexploits=[]
        return

    def clearLocalNode(self):
        """
        This function is used by silica when it initializes after
        attaching to a new network. At this point we should not know about
        any hosts yet.
        """
        self.localnode.init_me(silica=True)
        return

    def addLine(self,obj):
        """
        This function just appends the object to the addLine gui queue
        """
        #print "canvasengine::addLine(%s)"%obj
        if not self.gui:
            return

        self.gui.gui_queue_append("addLine",[obj])

    def deleteLine(self,obj):
        """
        ThreadSafe way to delete a line from our new GUI
        """
        #print "canvasengine::deleteLine(%s)"%obj
        if not self.gui:
            return
        self.gui.gui_queue_append("deleteLine",[obj])

    def update(self,obj):
        """
        Perfectly safe to call from any thread - but almost always called
        from a non-main thread.
        """
        #print "canvasengine:update(%s)"%obj
        if not self.gui:
            return
        self.gui.gui_queue_append("update",[obj])

    def addNode(self,node):
        self.nodeList+=[node]
        node.parentnode.child_nodes.append(node)
        devlog('canvasengine::addNode', "Adding node with parent: %s" % node.parentnode)
        self.gui.gui_queue_append("addNode",[node])
        return

    def addListener(self,mylistener):
        self.allListeners.append(mylistener)
        #print "SETTING ENGINE"
        mylistener.setEngine(self)
        self.addLine(mylistener)
        return

    def removeListener(self,mylistener):
        """removes a listener from the gui display"""
        i = mylistener.getID()

        self.gui.gui_queue_append("Remove Listener",[i])
        #self.gui.removeListener(id)
        self.allListeners.remove(mylistener)
        return

    def getListenerListenerBySock(self,sock):
        return self.getListenerBySock(sock)

    def getActiveListenerBySock(self,sock):
        return self.getListenerBySock(sock)

    def set_target_host(self,target_host):
        """
        Sets the interface used by the shellcode creation tools to call back to
        when needed.
        """

        if isinstance(target_host, basestring):
            # if we are a string (aka, an ip address), then lets get the
            # currently selected nodes knowledge
            ip = target_host
            target_host=self.passednodes[0].get_known_host(ip)
            if target_host==None:
                devlog("canvasengine", "Did not find %s in the node's host knowledge!"%ip)

        #here we unset the older targets
        oldhosts=self.target_hosts[:]
        for oldtarget in oldhosts:
            #don't unset our target - that would be bad
            if oldtarget == target_host:
                continue

            if(oldtarget == None):
                devlog("canvasengine", "Empty target host provided!")
                continue

            oldtarget.unset_as_target()

            if self.gui:
                self.update(oldtarget)

        #now we set our target as the only member of our targets list
        self.target_hosts=[target_host]
        #and update its gui

        if self.gui:
            # targethost is a hostKnowledge line
            self.gui.gui_queue_append("set target ip", [target_host.interface])
            self.update(target_host)

        self.new_event('new target', target_host)


    def set_additional_target_host(self, target_host):
        """
        Set another target host in our list
        """
        if target_host in self.target_hosts:
            #no need to add this host to our target hosts list
            return

        self.target_hosts.append(target_host)

        if self.gui:
            # add all target ip's to the display list
            IPlist = []

            for target in self.target_hosts:
                IPlist.append(target.interface)

            self.gui.gui_queue_append("set target ip", [' + '.join(IPlist)])
            self.update(target_host)

        self.new_event('new additional target', target_host)


    def unset_target_host(self, target_host):
        """
        Unsets target host. Will fail if the target host is our primary target
        (self.target_hosts[0])
        """
        if self.target_hosts[0]==target_host:
            devlog("canvasengine", "Cannot unset primary target host")
            return False #failed

        if target_host not in self.target_hosts:
            devlog("canvasengine", "Cannot unset target that is not set")
            return False

        self.target_hosts.remove(target_host)

        # udate gui
        if self.gui:
            # add all target ip's to the display list
            IPlist = []
            for target in self.target_hosts:
                IPlist.append(target.interface)
            self.gui.gui_queue_append("set target ip", [' + '.join(IPlist)])
            self.update(target_host)

        self.new_event('removed target', target_host)

        return True

    def set_first_node(self,node):
        """
        Sets this node as the first node in a nodelist
        which we pass to all modules
        """
        index=0
        for n in self.passednodes:
            #unset all these
            n.unselect()
        self.passednodes=[node]
        node.appended(index) #change display to reflect index in nodelist
        return

    def append_node(self,node):
        """appends a node to our list and updates its display"""
        index = len(self.passednodes)
        if node not in self.passednodes: #duplicate protection
            self.passednodes.append(node)
            node.appended(index) #change display to reflect index in nodelist

        return

    def remove_node(self, node):
        """removes a node from our list (But does not delete it - think unselect node)"""
        try:
            ##del self.passednodes[ self.passednodes.index(node) ] - hmmm ? Rich
            self.passednodes.remove(node)
        except ValueError:
            ##Node we are told to remove itsn't in list - how strange?
            logging.error("Attempted to remove a node not in list")
            return

        ##And reorder remaining nodes accordingly to their order in the list
        for n in self.passednodes:
            n.appended(self.passednodes.index(n))

        node.unselect()

    def set_callback_interface(self,interface):
        """
        NEWGUI support
        Sets the interface used by the shellcode creation tools to call back to
        when needed
        """
        assert interface
        devlog("engine","set_callback_interface called: %s"%interface)
        if self.callback_interface==interface:
            devlog("engine","set_callback_interface returned (same interface)")
            return
        if self.callback_interface!=None:
            self.callback_interface.unset_as_callback()

        self.callback_interface = interface

        if self.gui:
            ifip = str(interface)
            if hasattr(interface, "ip"):
                ifip=interface.ip

            self.gui.gui_queue_append("set local ip",[ifip])

        self.update(interface)
        self.new_event('callback changed', interface)
        devlog("engine","set_callback_interface returned (updated)")

    def get_callback_interface(self, target=None):
        """
        If you pass a target into this, it will pick your callback interface
        for you. This is especially useful when SYN scanning, because then you
        need to forge the packet from the proper IP!

        This is dangerous because on one hand it will return an interface object
        and on the other hand, it returns a string "IP address"
        """
        if not target:
            return self.callback_interface
        callback_ip = get_source_ip(target)
        if callback_ip == None:
            #failed to get a callback ip from that host - not routable?
            return self.callback_interface
        return callback_ip

    def getListenerBySock(self,sock):
        listeners = self.allListeners
        for i in listeners:
            #print "Sock is %s - testing %s"%(str(sock),str(i.getSocket()))
            #GTK2 uses the fd, GTK1 uses the sock object - terrific.
            if i.getSocket() == None:
                continue
            try:
                if i.getSocket() == sock or i.getSocket().fileno() == sock:
                    return i
            except:
                #might be a MOSDEFSock, and we don't need to look at those
                #and they don't have fileno()
                pass
        return None

    def getListenerByID(self, id):
        """
        Gets a listener by ID
        """
        for lst in self.allListeners:
            if lst.getID() == id:
                return lst

        return None

    def getExploitByID(self, id):
        """
        Gets an exploit by ID
        """
        for expl in self.allexploits:
            if expl.id == id:
                return expl
        return None

    def getListenerTypeByID(self, id):
        lst = self.getListenerByID(id)
        if lst == None:
            return ""
        return lst.getType()

    def getListeningListenerPort(self, id):
        lst = self.getListenerByID(id)
        if lst == None:
            return None
        return lst.getPort()

    def activeListener(self,shell,source,condition):
        """
        Called any time an active or listening gets any data
        """
        #gtk.threads_enter()
        # print "Active Listener"
        mylistener = self.getActiveListenerBySock(source)
        if mylistener == None:
            #print "No such mylistener!"
            #print "Couldn't find an active listener with that socket - why are we receiving data from it?!"
            return 0
        if mylistener.handleData() == 0:
            #print "Removing!"
            #we have to remove it from the select() loop gtk is doing, if it was closed
            self.gui.input_remove(mylistener.getGtkID())
            #and we remove it from the window as well
            self.removeListener(mylistener)
            id = mylistener.getID()
            self.gui.gui_queue_append("Remove Listener",[id])
            #self.gui.removeListener(id)
            logging.info("Removed listener %d from window since it was closed or suffered an error" % mylistener.getID())
        #gtk.threads_leave()
        #print "Returning!"
        return 1

    def getNewListenerId(self):
        self.idlock.acquire()
        old = self.maxListenerId
        self.maxListenerId += 1
        self.idlock.release()
        return old

    def newNode(self, node, listener_type, exploit=None):
        """
        Takes a node and attaches it to our model. Also adds this data to our reporter.
        """
        self.addNode(node)
        self.report_node(node, listener_type, exploit)

        node.update_gui()
        if self.gui and "noshell" not in node.capabilities: # XXX
            self.gui.gui_queue_append("do_listener_shell",[node])

        # we're keeping the startup call in exploitManager :>
        try:
            startup_exploit = CanvasConfig['node_startup_exploit']
            startup=self.getModuleExploit(startup_exploit)
            startup.link(self) #this is probably NOT what we want here. canvasengine is not an exploit instance
            startup.argsDict["passednodes"]=[node]
            startup.engine = self
            #set to primary target
            startup.target= self.target_hosts[0]
            startup.run()
        except socket.error:
            logging.error("Tried to do a startup on new node and it failed for some reason")

    def report_node(self, node, listener_type, exploit=None):
        def get_node(node):
            return {
                'type': node.nodetype,
                'name': node.getname(),
                'parent': get_node(node.parentnode) if node.parentnode else None,
                'ip': node.get_interesting_interface(),
                'ips': node.getallips(),
                'listener': node.listener_type,
                }

        data = get_node(node)

        devlog('reports', 'new node exploit: %s' % exploit)
        if exploit:
            data['exploit'] = {
                'name': exploit.module_name,
                'id': exploit.id,
                }
        else:
            data['exploit'] = None

        self.new_event('new node', data)

    # for commandline interface ..
    def start_http_mosdef(self, port, ssl=False):
        logging.info("Getting a Commandline HTTP Proxy on port %d" % port)
        # from the commandline we bind our own listener
        # and the -p argument controls the listener port
        # it then automagically spawns its own TCP listener
        # in the case of the gui, listenport represents
        # the gui randomized listener port for the TCP listener
        t = proxyThread(self,\
                        ssl,\
                        port,\
                        #this is a local connection between node and proxy
                        '127.0.0.1',\
                        port + 1,\
                        [self.getLocalNode()])
        self.proxy_threads += [t]
        t.start()
        return True

    # cli for the dns proxy
    def start_dns_mosdef(self, host, port):
        logging.info("Getting a Commandline DNS Proxy on port %d" % port)

        t = dnsProxyThread(self,\
                        #this is a local connection between node and proxy
                        host,\
                        port,\
                        [self.getLocalNode()])
        self.proxy_threads += [t]
        t.start()
        return True

    def newShellServer(self,shell):
        if not shell.async:
            return
        node=shell.node
        #if node.type=="LocalNode":
        #    id1 = self.gui.input_add(shell.getSocket(), self.gui.get_input_read(), lambda x,y:self.activeListener(shell.shell,x,y))
        #print "GTK ID = %d"%id1
        #print "New shell is fd=%s"%shell.connection.fileno()
        self.newNode(shell)
        if self.gui: # XXX
            self.gui.gui_queue_append("do_listener_shell",[shell])
        #self.gui.do_listener_shell(shell)
        return

    def handleNewListenerConnection(self, callback, source, condition):
        """
        called whenever a new listener connects to a socket
        This is run in the context of the gui thread, so no thread protection is needed.

        We then find the listener
        """

        #gtk.threads_enter()

        devlog("handleNewListenerConnection called")
        devlog("callback, source, condition=%s,%s,%s"%(callback,source,condition))

        if condition != self.gui.get_input_read():
            devlog("handleNewListenerConnection: not readable condition %d" % condition)

        listener = callback.getListenerBySock(source)
        debugnote = """
        <noir> gui/canvasengine.py line 510
        <noir> do you have an explanation ? since it pops out randomly during sploit
          runtime
        <dave_> that means we got activity (select() returned on us) for a socket that
          we have registered. Then we go to look up which listener handles
          that socket, and we get nothing.
        """
        if listener == None:
            logging.error("CANVAS couldn't find a listener for that socket")
            return
        #now we need to start a new Node on that socket
        try:
            newsocket, addr = listener.sock.accept()
        except:
            logging.error("Failed on new listener accept()")
            return 0

        logging.info("Connected to by %s" % str(addr))
        if listener.type != UNIVERSAL_MOSDEF:
            #UNIVERSAL MOSDEF listeners don't have a single client
            logging.info("Informing client that we got a connection")
            listener.informClient()
        #this has to be in a new thread
        tls = threadListenerStarter()
        tls.listener = listener
        tls.newsocket = newsocket
        tls.newip = str(addr)
        tls.engine = self
        tls.start()
        return 1

    # Shortcut for running module/exploit
    def runmod_exp(self, ename, node):
        mod = self.getModuleExploit(ename)
        mod.passedNodes = [node]
        mod.argsDict["passednodes"] = [node]
        mod.run()
        return mod

    # iterates through listener host list and if it finds the host in there
    # it means it has already been exploited
    def check_ip_state(self, listener, ip):
        for x in listener.silres:
            if x[0] == ip:
                logging.info("IP %s is being or has already been exploited" % ip)
                return True
        devlog("engine", "Did not find IP: %s continuing to exploit"%ip)
        return False


    # This will find the ip in the object and replace the state with the result
    def append_result(self, listener, ip, result):
        for x in range(len(listener.silres)):
            if listener.silres[x][0] == ip:
                listener.silres[x][1] = result
                devlog("engine", "Found IP: %s and replaced result with: %s",(ip, result))
                return True
        devlog("engine", "Did not find IP: %s already in list"%(ip,))
        return False

    def getMosdefType(self, mosdef):
        """
        Gets an integer from the mosdef type enum.
        Returns -1 on "not found"
        """
        listeneroptions = getAllListenerOptions() #returns a list of listeners
        ret = -1
        try:
            ret = listeneroptions.index(mosdef)
        except ValueError, msg:
            devlog("engine", "ERROR: Did not find type within listener options! %s"%mosdef)

        return ret

    def clear_mosdef_ids(self):
        """
        A reset function, used if you ever want to clear them
        """
        with self.newMosdefIDlock:
            self.mosdefid=1
            self.mosdef_shellcode_ids={}
            self.mosdef_shellcode_modules = {}
        return

    def getNewMosdefID(self, exploit):
        """
        Returns a new mosdef ID and attaches it to an exploit
        """

        ret = None #ERROR if we ever return this.

        with self.newMosdefIDlock:
            #increment us to the next ID
            self.mosdefid+=1
            #save us in the dictionary
            devlog("canvasengine", "Adding MOSDEF ID %d for exploit %s"%(self.mosdefid, exploit))
            self.mosdef_shellcode_ids[self.mosdefid] = exploit
            self.mosdef_shellcode_modules[exploit] = self.mosdefid
            ret=self.mosdefid

        return ret

    def universal_mosdef_loader(self, newsocket):
        """
        First we recv() a listener_type, then an ID that uniquely identifies this shellcode.

        returns: success, type, shell_id.
        shell_id is 0 for a mosdef_callback.exe or other non-attached shellcode.
        """
        try:
            data = ""
            while len(data)!=4:
                data += newsocket.recv(1)
        except:
            #catching timeouts and socket.error here
            devlog("canvasengine", "Failed to get any data when reading listener_type for universal mosdef listener")
            return False, None, None


        if len(data) != 4:
            devlog("canvasengine", "Failed to get enough data when reading listener_type for universal mosdef listener")
            return False, None, None

        #we have enough data to determine the listener type
        #these are sent over the wire in network byte order
        listeneroptions = getAllListenerOptions() #returns a list of listeners
        listener_type_num = str2int32(data)
        if len(listeneroptions) > listener_type_num:
            mosdeftype = listeneroptions[listener_type_num]
        else:
            logging.error("Invalid mosdef type received on universal listener: %x" % listener_type_num)
            return False, None, None

        devlog("canvasengine", "Got a %d when reading listener type"%listener_type_num)

        #ok, now get ID number
        try:
            data = ""
            while len(data)!=4:
                data += newsocket.recv(1)
        except:
            devlog("canvasengine", "Failed to get any data when reading ID for universal mosdef listener")
            return False, None, None

        if len(data) != 4:
            devlog("canvasengine", "Failed to get enough data when reading ID for universal mosdef listener")
            return False, None, None

        shell_id = str2int32(data)
        devlog("canvasengine", "Found mosdeftype: %s, ID: %x"%(mosdeftype, shell_id))
        success = True
        return success, mosdeftype, shell_id

    # default to inited newip so we remain backwards compatible ..
    def new_node_connection(self, listener, newsocket, newip="127.0.0.1", mosdef_type=None):
        """
        Given a socket, and a callback,  starts up a new node from that socket
        Will start in some random thread, and won't complete until the new
        Node has been started up completely.

        Returns the new CANVAS Node.
        """
        devlog("new_node_connection")
        if not mosdef_type:
            pnode = listener.parent.parent.parent
            devlog("pnode set to %s" % pnode)
            type = listener.type

        else:
            #we are comming in from a commandline handler (see commandlineInterface.py) or similar
            type = mosdef_type
            pnode = self.getLocalNode()

        logging.info("new_node_connection on %s" % type)
        logging.info("Starting up a %s Server" % type)

        exploit = None
        shell_id = None
        if type == UNIVERSAL_MOSDEF:
            #First we recv() a listener_type, then an ID that uniquely identifies this shellcode.
            success, type, shell_id = self.universal_mosdef_loader(newsocket)
            if not success:
                logging.error("Was not able to load the universal mosdef shell")
                return False
            else:
                logging.info("Received mosdef_type: %s, with shell_id: %s" % (type, shell_id))
                #now inform the exploit that they got their shell
                exploit = self.mosdef_shellcode_ids.get(shell_id)
                if exploit:
                    exploit.succeeded = True #Tell him he won
                    for informer in exploit.inform_succeeded:
                        #list of functions to call
                        #tell them all that this exploit succeeded!
                        if not hasattr(informer, "child_succeeded"):
                            devlog("canvasengine", "%s has an inform_suceeded object (%s) without a child_succeeded method!" % (exploit, informer))
                        else:
                            #tell it that we suceeded. This is
                            #typically something like the clientd SessionState object
                            informer.child_succeeded(exploit)

        # has to be ported to newschool
        if type == SOLARISMOSDEF_SPARC:
            from solarisNode import solarisNode
            newshell = solarisNode()
            pnode.newNode(newshell)
            import solarisMosdefShellServer
            shell = solarisMosdefShellServer.solarisshellserver(newsocket,newshell,logfunction=self.log)

        # has to be ported to newschool
        elif type == OSXMOSDEF_PPC:
            from osxNode import osxNode
            newshell = osxNode()
            devlog("1 newshell.parent: %s"%newshell.parent)
            pnode.newNode(newshell)
            devlog("2 newshell.parent: %s"%newshell.parent)
            import osxMosdefShellServer
            shell = osxMosdefShellServer.osxshellserver(newsocket,newshell,logfunction=self.log)
            devlog("3 newshell.parent: %s"%newshell.parent)

        # the new school
        elif type == OSXMOSDEF_INTEL:
            from osxNode import osxNode
            newshell    = osxNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('OSX', 'x86')(newsocket, newshell, logfunction=self.log)

        elif type == OSXMOSDEF_X64:
            from osxNode import osxNode
            newshell    = osxNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('OSX', 'x64')(newsocket, newshell, logfunction=self.log)

        elif type == LINUXMOSDEF_ARM9:
            from linuxNode import linuxNode
            newshell = linuxNode(proctype='ARM9')
            pnode.newNode(newshell)
            shell    = MosdefShellServer('Linux', 'ARM9')(newsocket, newshell, logfunction=self.log)

        elif type == LINUXMOSDEF_X64:
            from linuxNode import linuxNode
            newshell = linuxNode(proctype='x64')
            pnode.newNode(newshell)
            shell    = MosdefShellServer('Linux', 'x64')(newsocket, newshell, logfunction=self.log)

        elif type == AIXMOSDEF_51_PPC:
            from aixNode import aixNode
            logging.info("Connected, AIX 5.1 MOSDEF PPC")
            newshell    = aixNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('AIX', 'PowerPC')(newsocket, newshell, version='5.1', logfunction=self.log)

        elif type == AIXMOSDEF_52_PPC:
            from aixNode import aixNode
            logging.info("Connected, AIX 5.2 MOSDEF PPC")
            newshell    = aixNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('AIX', 'PowerPC')(newsocket, newshell, version='5.2', logfunction=self.log)

        elif type == UNIXSHELL:
            from unixShellNode import unixShellNode
            telnetshell         = Telnet()
            telnetshell.sock    = newsocket
            shell               = shelllistener(shellfromtelnet(telnetshell),logfunction=self.log)
            newshell            = unixShellNode()
            newshell.shell      = shell
            pnode.newNode(newshell)

        elif type == ANDROIDSHELL:
            from unixShellNode import unixShellNode
            telnetshell         = Telnet()
            telnetshell.sock    = newsocket
            shell               = androidShellListener(shellfromtelnet(telnetshell),logfunction=self.log)
            newshell            = unixShellNode()
            newshell.shell      = shell
            pnode.newNode(newshell)

        elif type == LINUXEXECVE_INTEL:
            from unixShellNode import unixShellNode
            newshell    = unixShellNode()
            pnode.newNode(newshell)
            import linuxMosdefShellServer
            shell       = linuxMosdefShellServer.execveshellserver(newsocket,newshell,logfunction=self.log)

        # the new school
        elif type == LINUXMOSDEF_INTEL:
            from linuxNode import linuxNode
            newshell    = linuxNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('Linux', 'i386')(newsocket, newshell, logfunction=self.log)

        # the new school
        elif type == SOLARISMOSDEF_INTEL:
            from solarisNode import solarisNode
            newshell    = solarisNode()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('Solaris', 'intel')(newsocket, newshell, logfunction=self.log)

        elif type == WIN32MOSDEF_INTEL:
            from win32Node import win32Node
            newshell    = win32Node()
            pnode.newNode(newshell)
            import win32MosdefShellServer
            shell       = win32MosdefShellServer.win32shellserver(newsocket,newshell,logfunction=self.log)

        elif type == WIN32MOSDEF_INTEL_FCT:
            #from create thread listener
            from win32Node import win32Node
            newshell    = win32Node()
            pnode.newNode(newshell)
            import win32MosdefShellServer
            shell       = win32MosdefShellServer.win32shellserver(newsocket,newshell,logfunction=self.log)
            shell.fromcreatethread=True
            shell.argsDict["fromcreatethread"]=True

        elif type == WIN64MOSDEF_INTEL:
            from win64Node import win64Node
            newshell    = win64Node()
            pnode.newNode(newshell)
            shell       = MosdefShellServer('Win64', 'X64')(newsocket, newshell, logfunction=self.log)

        # XXX: only win32 support, so assume a win32 mosdef start up
        elif type in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
            from win32Node import win32Node
            newshell    = win32Node()
            pnode.newNode(newshell)
            import win32MosdefShellServer
            shell       = win32MosdefShellServer.win32shellserver(newsocket, newshell, logfunction=self.log)

        elif type == FREEBSDMOSDEF_INTEL:
            from bsdNode import bsdNode
            newshell    = bsdNode()
            pnode.newNode(newshell)
            import bsdMosdefShellserver
            shell       = bsdMosdefShellserver.bsdshellserver(newsocket, newshell)

        elif type == PHPMULTI:
            import phplistener
            from ScriptNode import ScriptNode
            node        = ScriptNode()
            pnode.newNode(node)
            from ScriptShellServer import phpshellserver
            shell       = phpshellserver(newsocket, node, logfunction=self.log)
            newshell    = node

        elif type == JAVASERVER:
            from Nodes.JavaShellServer import javashellserver
            from JavaNode import JavaNode
            node        = JavaNode()
            pnode.newNode(node)
            shell       = javashellserver(newsocket, node)
            newshell    = node

        elif type == POWERSHELL_MOSDEF:
            from Nodes.PSShellServer import psshellserver
            from PowerShellNode import PowerShellNode
            try:
                node        = PowerShellNode()
                pnode.newNode(node)
                shell       = psshellserver(newsocket, node, shell_id)
                newshell    = node
            except:
                logging.error("Something went wrong: Is this the correct listener type?")
                return 0

        #else SQL ?

        else:
            logging.error("Cannot find the requested type of listener (%s)" % type)
            return 0

        # set the listener_type for the new node
        newshell.listener_type = type

        #this is how we pass variables down to the shellserver from the exploits
        #they go through the listener in the argsDict
        #by default, argsDict is empty
        if listener!=None and listener.type!=UNIVERSAL_MOSDEF:
            devlog("canvasengine", "Listener argsDict=%s"%listener.argsDict)
            for key in listener.argsDict.keys():
                shell.argsDict[key] = listener.argsDict[key]

        #print "Starting up listener..."
        try:
            devlog("canvasengine", "About to do newshell.startup")
            # startup shell
            newshell.startup()

            devlog("canvasengine", "Finished newshell.startup")
        except Exception, e:
            import traceback
            traceback.print_exc(file=sys.stderr)
            logging.error("Newshell startup caused exception: %s" % e)
            return 0

        logging.info("Done with new Node startup")
        self.successfortune()
        devlog("5 newshell.parent: %s"%newshell.parent)

        # Add new member to shell object
        newshell.shell.__dict__['whoami_username']  = ''
        if hasattr(newshell, "shell") and hasattr(newshell.shell, "popen2") and newshell.shell.popen2:
            newshell.shell.__dict__['whoami_username']  = newshell.shell.popen2('whoami')

        self.newNode(newshell, type, exploit) # draw node

        logging.info("Done handling a new Listener Connection")
        if listener:
            listener.totalnodes += [newshell]

        return newshell

    def isSpecialInterface(self,interface):
        """
        returns true if the interface argument is a special one, currently
        just NAT interfaces
        """
        if interface.isSpecial():
            return True
        return False

    def autoListener(self, exploit, listenertype, host=None, autoFind=True, HTTPPROXYPORT=0):
        """
        starts a listener or uses an existing listener that has been set up

        Should never run in the main thread!

        """
        #if I'm running on the local node and supply a target host, then automatically
        #choose the correct interface
        localNode=self.getLocalNode()
        devlog("engine", "Getting a new listenertype of %s for exploit %s"%(listenertype, exploit))
        if(self.callback_interface==None):
            devlog("engine", "self.callback is none")
        elif(self.callback_interface.parent==None):
            devlog("engine", "self.callback.parent is none")
        elif(self.callback_interface.parent.parent==None):
            devlog("engine", "self.callback_parent.parent is none")
        else:
            devlog("engine", "self.callback_interface.parent.parent=%s" % self.callback_interface.parent.parent)

        #This giant block of code here is just about finding which INTERFACE
        #we want to listen on.
        #LocalExploits have this attribute set
        if exploit and hasattr(exploit,"use_local_interface") and exploit.use_local_interface:
            devlog("engine", "It's a local exploit! Using a local interface as our callback.")
            #Get node
            node=exploit.argsDict['passednodes'][0]
            #get interface object on that node to call back to localhost
            interface=node.getMatchingInterface("127.0.0.1")
            if not interface:
                devlog("engine", "Failed to get localnode interface for node %s" % node.get_name())
                #this seems like something the user might want to know also
                logging.error("Failed to get localnode interface for node %s" % node.get_name())
                return None
            else:
                devlog("engine","Got interface for remote node's (%s) localhost" % node.get_name())
        else:
            devlog("engine", "Not a local exploit. Targeted Host=%s"%host)

            # XXX: we needed autofind control from the exploitmodule for httpserver special case! self.autoFind controls it.
            if autoFind == False:
                logging.info("Autofind off. Special case callback interface, using hand selected")
                interface = self.callback_interface
            elif (self.callback_interface.parent == None) or not (self.isSpecialInterface(self.callback_interface)) and host:
                devlog("engine", "Autofinding callback interface")
                logging.info("Choosing correct callback interface for you")
                callback = self.get_callback_interface(host)
                logging.info("Callback chosen: %s" % callback)
                interface = localNode.getMatchingInterface(callback)
                if not interface:
                    self.log("[ii] Could not find a matching interface for %s" % callback)
                    logging.info("Using default interface")
                    interface = self.callback_interface
            else:
                #use the one selected
                logging.info("Autolistener: Special interface chosen, so using that")
                interface = self.callback_interface

        devlog("engine", " Chose interface: %s"%interface)

        #Ok, now we know which INTERFACE we want. We need to look to see
        #if we can re-use a listener that already exists, or if we need to
        #create one!

        #check for old listener that will work
        if listenertype in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
            real_type = UNIVERSAL_MOSDEF
        else:
            real_type = listenertype

        found = False

        for l in interface.children:
            if l.type == real_type and (not l.busy):
                #NOTE: Threading issue here - if l.busy is false, we need to essentially have a mutex here
                #otherwise some other thread could set it to busy after we return it...

                if listenertype == HTTPMOSDEF:
                    if l.http_proxy_endpoint and not l.http_proxy_endpoint.ssl: found = True
                elif listenertype == HTTPMOSDEF_SSL:
                    if l.http_proxy_endpoint and l.http_proxy_endpoint.ssl: found = True
                else:
                    if not l.http_proxy_endpoint: found = True

            if found:
                devlog("engine","Autolistener", "Success finding listener on our interface: %s" % l.text)
                return l

        devlog('engine',"Did not find a ready-to-go listener on that interface")

        ports       = []
        pref_ports  = []

        try:
            pref_ports = CanvasConfig["preferred_ports"].split(",")
        except:
            pass

        #makes sure our preffered ports are within the allowed port range for that interface
        for p in pref_ports:
            p = int(p)
            if p in range(interface.startport, interface.endport):
                ports+=[p]

        #Now pick some random ports in case we cannot listen on those ports
        for i in range(0,4):
            #NATs have a smaller range
            ports+=[random.randint(interface.startport, interface.endport)]

        for port in ports:
            logging.info("Starting %s listener on port %s" % (listenertype, port))

            if listenertype in [HTTPMOSDEF, HTTPMOSDEF_SSL]:
                logging.info("Using universal listener for HTTP MOSDEF")
                real_type = UNIVERSAL_MOSDEF
            else:
                real_type = listenertype

            devlog("engine" , "Starting listener on port %d"%port)

            l = self.start_listener(interface, real_type, port)
            if l:
                # start a new http proxy and update the listener callback port
                if listenertype in [HTTPMOSDEF,
                                    HTTPMOSDEF_SSL]:

                    # try defaults and randomize by default
                    if not HTTPPROXYPORT:
                        logging.info("Randomizing HTTP Proxy port")
                        pref_ports = [80, 443, 8000, 8080]
                    else:
                        if HTTPPROXYPORT:
                            pref_ports = [HTTPPROXYPORT]
                        else:
                            pref_ports = []

                    for i in range(0, 8):
                        # add some random ports in case they all fail
                        # NATs have a smaller range
                        #print "Startport: %d Endport: %d"%(interface.startport, interface.endport)
                        pref_ports += [random.randint(interface.startport, interface.endport)]

                    # check which HTTP port is available for bind (XXX)
                    found_port = False
                    for p in pref_ports:
                        try:
                            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE') == True:
                                # windows
                                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
                            else:
                                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                            host = '0.0.0.0'
                            if not interface.isNAT:
                                host = interface.ip
                            s.bind((host, int(p)))
                            found_port = True
                            break
                        except:
                            #import traceback
                            #traceback.print_exc(file=sys.stderr)
                            s.close()
                            found_port = False

                    if found_port == True:
                        # spawn a http proxy on the available port
                        s.close()

                        logging.info("Getting a GUI HTTP Proxy on port %d" % p)
                        # from the commandline we bind our own listener
                        # and the -p argument controls the listener port
                        # it then automagically spawns its own TCP listener
                        # in the case of the gui, listenport represents
                        # the gui randomized listener port for the TCP listener

                        # we are assuming the thread will go okay ... bad
                        ssl_dict = { HTTPMOSDEF : False, HTTPMOSDEF_SSL : True }
                        t = proxyThread(self,\
                                        ssl_dict[listenertype],\
                                        int(p),\
                                        l.ip,\
                                        l.port,\
                                        [interface.parent.parent])
                        self.proxy_threads += [t]
                        t.start()
                        l.set_http_endpoint(t)
                    else:
                        # super mega fail
                        logging.error("HTTP Proxy could not find a port to bind to")
                        return None
                return l
            else:
                logging.error("Error while listening on the specified port, trying a new one")

        logging.error("AutoListener: Could not get interface to callback to")
        devlog("engine", " Failed to get an auto-listener set up!")
        return None

    def start_listener(self, interface, listener_type, listenport, fromcreatethread=False, commandline=False):
        """
        starts a listener and registers it with this engine
        Args:
        interface - None (for default of self.callback_interface) or interface to start listener on
        listenter_type - enum of type of listener, for example PHPMULTI
        port - port to start listener on

        returns none on failure or a newlistener on success
        """

        ipv6 = 0
        http_mosdef = None

        if listener_type == UNIVERSAL_MOSDEF:
            #we just turn this off, because it's handled by the Universalness
            fromcreatethread = False
        elif listener_type == WIN32MOSDEF_INTEL_FCT:
            fromcreatethread = True

        if not interface:
            interface = self.callback_interface
            assert interface

        if type(interface) == type(""):
            #we have a string, we need to change to an interface object
            newinterface = self.localnode.getMatchingInterface(interface)
            if not newinterface:
                logging.error("Could not find interface matching %s" % interface)
                return None
            interface = newinterface

        if interface.isNAT:
            listenhost = "0.0.0.0" # XXX: hrmm "::" is the ipv6 equiv, would it come into play?
        else:
            listenhost = interface.ip
            if ":" in str(interface.ip):
                logging.info("Switching MOSDEF listener into IPv6 mode")
                ipv6 = 1

        node = interface.parent.parent

        logging.info("%s Listener Startup Requested on %s:%d (%s)" % \
                 (listener_type, listenhost, listenport, node.nodetype))

        # XXX ???
        gtkid = -1

        # if we are called with a listener type of HTTPMOSDEF
        # it means we are getting started manually from the gui
        # thus we need to bind our proxy port first, and then
        # adjust our listener type and port to a regular tcp
        if listener_type in [HTTPMOSDEF, HTTPMOSDEF_SSL] and node.nodetype == "LocalNode":
            found_port  = False

            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                host = '0.0.0.0'

                if not interface.isNAT:
                    host = interface.ip

                s.bind((host, int(listenport)))
                found_port = True
            except Exception:
                found_port = False
            finally:
                s.close()

            if found_port == True:
                # spawn a http proxy on the available port

                logging.info("Getting a GUI HTTP Proxy on port %d" % listenport)
                # from the commandline we bind our own listener
                # and the -p argument controls the listener port
                # it then automagically spawns it's own TCP listener
                # in the case of the gui, listenport represents
                # the gui randomized listener port for the TCP listener

                # we are assuming the thread will go okay ... bad
                ssl_dict = { HTTPMOSDEF : False, HTTPMOSDEF_SSL : True }
                t = proxyThread(self,\
                                ssl_dict[listener_type],\
                                int(listenport),\
                                listenhost,\
                                int(listenport + 1000),\
                                [interface.parent.parent])
                self.proxy_threads += [t]
                t.start()
                http_mosdef = t

                # switch the type and the port and continue
                listener_type   = UNIVERSAL_MOSDEF
                listenport      += 1000

            else:
                # super mega fail
                logging.error("HTTP Proxy could not find a port to bind to")
                return None

        elif listener_type in [DNSMOSDEF] and node.nodetype == "LocalNode":
            dns_mosdef = True
            found_port  = False
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                host = '0.0.0.0'
                if not interface.isNAT:
                    host = interface.ip
                s.bind((host, int(listenport)))
                found_port = True
            except:
                s.close()
                found_port = False
                pass

            if found_port == True:
                logging.info("Getting a GUI DNS Proxy on port %s" % listenport)

                # we are assuming the thread will go okay ... bad
                t = dnsProxyThread(self,\
                                listenhost,\
                                int(listenport),\
                                [interface.parent.parent])
                self.proxy_threads += [t]
                t.start()

                listener_type   = WIN32MOSDEF

            else:
                # super mega fail
                logging.error("Could not find a port to bind to")
                return None

        # XXX: this code needs love in a big way
        if node.nodetype == "LocalNode":
            if ipv6:
                s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            else:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

            if hasattr(socket, 'SO_EXCLUSIVEADDRUSE') == True:
                # windows
                s.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            else:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                if "%" in listenhost:
                    logging.info("Parsing out IPv6 Scope ID")
                    listenhost = listenhost[:listenhost.find("%")]
                try:
                    s.bind((listenhost, listenport))
                except:
                    if ":" in listenhost:
                        listenhost = "::"
                        s.bind((listenhost, listenport))
                    else:
                        logging.error("Could not bind to %s:%d" % (listenhost, listenport))
                        raise
                try:
                    s.set_timeout(None)
                except:
                    logging.warning("Likely an ipv6 socket, set_timeout not supported")
                s.listen(5)
            except:
                return 0

            def callback(source, condition):
                self.handleNewListenerConnection(interface, source, condition)
                # The return value is checked in order to determine if the callback
                # should stay active
                return True

            if self.gui: # FIXME no gui code in engine
                gtkid = self.gui.input_add(s, self.gui.get_input_read(), callback)

        elif hasattr(node, 'createListener'):
            # XXX: ipv6 warning for now
            if ipv6:
                logging.error("IPv6 listeners only supported on localnodes for now")
                return 0
            # XXX: end of ipv6 warning

            s = node.createListener(listenhost, listenport)
            if s == 0:
                logging.error("Could not create listener on %s:%d" % (listenhost,listenport))
                return 0

        else:
            msg = "%s does not have support for creating listeners"
            logging.error(msg % node.nodetype)
            return 0

        from listenerLine import listenerLine

        if listener_type != UNIVERSAL_MOSDEF and fromcreatethread:
            newlistener = listenerLine(listener_type, listenport, self.getNewListenerId(), gtkid, s, self.log, interface, True)
        else:
            newlistener = listenerLine(listener_type, listenport, self.getNewListenerId(), gtkid, s, self.log, interface)

        if http_mosdef:
            newlistener.set_http_endpoint(http_mosdef)

        self.addListener(newlistener)

        ##For state save/restore not our listeners
        interface.listeners_that_are_listening.append([listener_type, listenport, fromcreatethread])

        self.new_event('new listener', {'node'             : node.getname(),
                                        'ip'               : interface.ip,
                                        'interface'        : interface.interface,
                                        'type'             : listener_type,
                                        'port'             : listenport,
                                        'fromcreatethread' : fromcreatethread})
        return newlistener

    def listener_server_close(self, id):
        logging.info("Closing active listener with ID=%d" % id)
        listeners = self.allListeners
        found = 0
        for tmp in listeners:
            if tmp.getID() == id:
                found = 1
                obj = tmp
                break
        if found:
            self.removeListener(obj)
            obj.closeme()
        else:
            logging.error("Listener not found (ID=%d)" % id)
        return

    def do_post_actions(self, newnode, successful_exploit):
        #now we need to restart services or whatever else
        #we have in postactions
        exp = successful_exploit
        ret = newnode
        for action in exp.postactions:
            #action is (STRING,args[])
            if action[0] == "restart service":
                logging.info("Restarting Services on Node %s" % ret.getname())
                restart = self.getModuleExploit("restartservice")
                restart.link(exp)
                restart.argsDict["passednodes"] = [ret]
                for service in action[1] :
                    logging.info("Restarting %s" % service)
                    restart.argsDict["serviceName"] = service
                    restart.run()
                    logging.info("Running restart service again, to be sure")
                    restart.run() #run twice
            elif action[0] == "reverttoself":
                logging.info("Reverting to self")
                exp.exploitnodes("setthreadtoken", [ret])
            elif action[0] == "mosdefmigrate":
                logging.info("Migrating into LSASS as fast as we can")
                exp.exploitnodes("mosdefmigrate", [ret])
                logging.info("Migration DONE")
            elif action[0] == "hideport":
                logging.info("Hiding remote network port using the rootkit")
                exp.argsDict["hideport"] = action[1]
                exp.exploitnodes("hideport", [ret])
                logging.info("Hide port successful")
            elif action[0] == "testomatic":
                logging.info("Testomatic requesting post action")
                msg = exp.exploitnodes(action[1], nodes = [ret])
                logging.info("Msg: %s" % msg)

                try:
                    for i in msg:
                        if i == -1 or i == "-1" or i is None or i == "" or "error" in str(i).lower() or "failed" in str(i).lower():
                            exp.succeeded = False
                            exp.result_error = "testomaticerror"
                        else:
                            logging.info("Value of i: %s" % str(i))
                except:
                    exp.succeeded = False
                    exp.result_error = "testomaticerror"

                logging.info("Ran the testomatic post action.")

        if hasattr(exp, "doPostAction"):
            exp.doPostAction(self, ret)

        logging.info("Finished postactions on node %s" % ret.getname())
        return

    ###############################EXPLOIT HANDLERS###################################


    def printvalidtokens(self,listener):
        """ prints all the valid tokens in a win32 server"""
        try:
            self.log(listener.printvalidtokens())
        except:
            logging.error("Error trying to print all valid tokens:")
            import traceback
            print '-' * 60
            traceback.print_exc(file=sys.stdout)
            print '-' * 60
        return

    def runsetthreadtoken(self, token, listener):
        ret = listener.SetThreadToken(0, token)
        self.log("SetThreadToken returned %d" % ret)

    def runexitthread(self, exitcode, listener):
        ret = listener.doexitthread(exitcode)
        self.log("ExitThread returned %d" % ret)

    def runsetuid(self, uid, listener):
        ret = listener.dosetuid(uid)
        self.log("setuid returned %d" % ret)

    def runsetgid(self, gid, listener):
        ret = listener.dosetgid(gid)
        self.log("getuid returned %d" % ret)

    def detectos(self, target):
        try:
            exp = getModuleExploit("osdetect")
        except:
            return "Unknown"
        exp.setLogFunction(self.exploitlog)
        exp.setDebugFunction(self.exploitdebuglog)
        exp.target = target
        argsDict = {}
        argsDict["passednodes"] = [localNode()]
        exp.argsDict = argsDict
        exp.engine = canvasengine(None)

        result = exp.run()

        if result == 0:
            return "Unknown"
        #otherwise result is a os!
        return exp.result

    def gethost(self, host):
        """
        Gets a host using the host's name
        in the future will also take in a fromhost,
        since each host knows about a different set of hosts
        """
        for h in self.knownhosts:
            if h.name == host:
                return h
        return None

    def registerPotentialVuln(self, fromhost, tohost, vulnname, vulndesc):
        """
        register a vuln in the target host so when we click on it
        it'll pop up
        """
        #should be fromhost.knownhosts, but whatever - we'll wait until the big 5.0
        #rewrite for that.

        for h in self.knownhosts:
            if h.name == tohost:
                h.addVuln(vulnname, vulndesc)
                return
        return

    # XXX:
    def addKnowledge(self, hoststring, key, knowledge, percentage):
        logging.error("Error. addKnowledge() not implemented")
        return

    def addknownhost(self, kLine, host):
        """adds a host to our internal list and then to the gui's list"""
        ha = hostadder(kline, host)
        ha.start()
        return


    ###################################################################################
    #Listener-Shell Listener Handlers

    def shellcommand(self, node, wTree2, modulename, argsDict):
        """
        calls the equivalent of popen on the listener
        """
        devlog("canvasengine", "Running module: %s" % modulename)
        #now I want to run an exploit with shell as my first node in the list.
        app = getModuleExploit(modulename)
        #set the three main variables for the exploit
        argsDict["passednodes"] = [node]
        #logging?
        app.argsDict = argsDict
        app.engine = self
        manager = exploitmanager(app,self)
        manager.listener_log(wTree2)
        manager.start()
        #self.log("listener id %d getpwd() returned %s"%(id,ret))
        return #exploit is running in another thread...

    def pwd(self, node, wTree2):
        """
        calls the equivalent of pwd on the listener
        """
        self.shellcommand(node, wTree2, "getcwd", {})

    def runcommand(self, node, wTree2, command):
        """
        calls the equivalent of popen on the listener
        """
        argsDict = {}
        argsDict["command"] = command
        self.shellcommand(node, wTree2, "runcommand", argsDict)
        return #exploit is running in another thread...

    def runcd(self, node, wTree2, directory):
        argsDict = {}
        argsDict["directory"] = directory
        self.shellcommand(node, wTree2, "chdir", argsDict)
        return #exploit is running in another thread...

    def rundownload(self, node, wTree2, source, directory):
        argsDict = {}
        argsDict["source"]    = source
        argsDict["directory"] = directory
        self.shellcommand(node, wTree2, "download", argsDict)
        return #exploit is running in another thread...

    def runupload(self, node, wTree2, source):
        argsDict = {}
        argsDict["source"] = source
        self.shellcommand(node, wTree2, "upload", argsDict)
        return #exploit is running in another thread...

    def rundir(self, node, wTree2, directory):
        argsDict = {}
        argsDict["directory"] = directory
        self.shellcommand(node, wTree2, "dir", argsDict)
        return #exploit is running in another thread...

    def rununlink(self, node, wTree2, filename):
        argsDict = {}
        argsDict["filename"] = filename
        self.shellcommand(node, wTree2, "unlink", argsDict)
        return #exploit is running in another thread...

    def runspawn(self, node, wTree2, filename):
        argsDict = {}
        argsDict["filename"] = filename
        self.shellcommand(node, wTree2, "spawn", argsDict)
        return #exploit is running in another thread...

    def runcreateprocessasuser(self, node, wTree2, command):
        """
        Calls create process as user to execute a process with the current thread token.
        Only available on Win32
        """
        argsDict = {}
        argsDict["directory"] = directory
        self.shellcommand(node, wTree2, "notdoneyet", argsDict)
        return #exploit is running in another thread...

    def getLocalNode(self):
        return self.localnode

    def loadLocalNode(self):
        """
        Special code to start up our local node and add it to the engine
        """
        if self.localnode:
            return self.localnode
        ln = localNode(self)
        ln.startup()
        #self.addNode(ln)
        self.localnode = ln
        self.set_first_node(ln)
        return ln

    def find_geteip(self, mnemonic, platform, startaddress, buffer):
        """
        If we have CANVAS World Service, go out and ask a smart
        routine to find me something, otherwise, just do a mosdef
        search here for ff e4 or similar
        you'll be able to attach to a find_geteip from anyone
        you want, not just Immunity.
        """
        #just a stub here for now!
        from MOSDEF import mosdef
        bytes = mosdef.assemble(mnemonic, platform)
        index = buffer.find(bytes)
        if index == -1:
            return None
        return startaddress + index

    ##MeatNode stuff
    def set_contact_routes(self, routes):
        ##Set a list of applicable route that the meatnode knows how to do stuff with
        self.registered_contact_routes = routes

        ##For each of these routes set a dictionary for the targets of these default routes
        for r in routes:
            self.current_contact_routes[r.lower()] = []

    def get_contact_routes(self):
        return self.registered_contact_routes

    def set_default_contact_route(self, route, set=1):
        if set:
            logging.info("Adding %s as default contact route for %s" % (route, route.get_type()))
            self.current_contact_routes[route.get_type()].append(route)
        else:
            logging.info("Removing %s as default contact route for %s" % (route, route.get_type()))
            try:
                loc = self.current_contact_routes[route.get_type()].index(route)
                self.current_contact_routes[route.get_type()] = self.current_contact_routes[route.get_type()][:loc] + self.current_contact_routes[route.get_type()][loc + 1:]
            except ValueError:
                #self.log("Removing %s as default contact route for %s"%(route, route.get_type()) )
                pass

        logging.info("CanvasEngine contact routes: %s" % (self.current_contact_routes))

    def get_email_routes(self):
        """
        Return all email contacts in our default routes
        """
        return self.current_contact_routes["email"]

def generate_parse_tables():
    """
    Generate all the parse tables we need for super fast parsing
    but making sure the tables reflect the current grammar and parser
    versions. Shipping parse tables statically will just cause a world
    of pain
    """
    from MOSDEF import cparse2
    try:
        ret = cparse2.generate_parse_tables()
        logging.info("Parse tables successfully generated")
    except Exception, err:
        logging.error("Error while generating parse tables")
        raise

def license_check():
    """
    Prints out and continues when the user accepts the license
    """

    #does the license file exist?
    try:
        fd = file("licensecheck","rb")
        #if so, return
        return
    except:
        fd = None

    ##Rich: OK this looks like its the first time this canvas has been run so lets generate our parse tables
    generate_parse_tables()

    ##First try a gui window (needs to do this for bundles) else fall
    ## back to console output
    with warnings.catch_warnings():
        warnings.filterwarnings('error')

        try:
            from gui import gtk_license
            ret = gtk_license.show()
            if ret != 1:
                sys.exit()
            else:
                fd = file("licensecheck","wb")
                fd.write("yes")
                fd.close()
                return

        # Catch any GTK-Warning at this point as they are likely to be related
        # to a headless session (e.g. over SSH)
        except Warning, Exception:
            data = file("LICENSE.txt").readlines()
            i = 0
            for line in data:
                print line
                i = i + 1
                if i > 20:
                    print "Please press enter to continue"
                    sys.stdout.flush()
                    raw_input()
                    i = 0

            print "If terms are accepted, type yes, otherwise, type no to exit program."
            while 1:
                ret = raw_input()
                if ret.lower() == "yes":
                    fd = file("licensecheck","wb")
                    fd.write(ret)
                    fd.close()
                    return
                if ret.lower() == "no":
                    logging.warning("Exiting")
                    sys.stdout.flush()
                    sys.exit()
                else:
                    logging.error("Please type 'yes' or 'no' to continue")
                    sys.stdout.flush()

# temporary hook kludge
def runAnExploit_gtk2(*args):
    from gui.canvasguigtk2 import runAnExploit_gtk2 as hooked_runAnExploit_gtk2
    return hooked_runAnExploit_gtk2(*args)

def getExploitsOfType(exploit_type):
    """
    Return data about exploits of type specified: i.e. 'Web Exploits'
    Case insensitive
    """
    exploit_type = exploit_type.lower()
    registerAllModules()
    print "[+] Displaying: %s" % (exploit_type)
    print "[+] Exploit Name\t ARCH\t VERSION\t CVE \t References"
    count = 0
    for key, obj in __exploitmods_old.items():
        msg = ""
        try:
            if obj.PROPERTY["TYPE"].lower() == exploit_type:
                msg += "%s\t " % (key)
                msg += "%s\t " % (obj.PROPERTY.get('ARCH', "NONE"))
                msg += "%s\t " % (obj.PROPERTY.get('VERSION', "NONE"))
                msg += "%s "   % (obj.DOCUMENTATION.get("CVE Name", "NONE"))
                msg += "%s "   % (obj.DOCUMENTATION.get("References", "NONE"))
                print msg
                count += 1
        except:
            pass

    print "[+] Total = %d" % (count)

def propertyPrint():
    import re
    propertyList = []
    property_fd = file("Properties.txt","wb")
    property_fd.write("Full property dict for each module\n\n")
    registerAllModules()
    osList = ["Windows", "Linux", "Solaris", "AIX", "HP/UX"]
    for key in __exploitmods_old.keys():
        property_fd.write("module: %s has the following properties\n"%key)
        for propkey in __exploitmods_old[key].PROPERTY.keys():
            temp = "\t %s : "%propkey
            if type(__exploitmods_old[key].PROPERTY[propkey]) == bool:
                if __exploitmods_old[key].PROPERTY[propkey]:
                    temp += "True \n"
                else:
                    temp += "False \n"
            elif type(__exploitmods_old[key].PROPERTY[propkey]) == str:
                temp += __exploitmods_old[key].PROPERTY[propkey] + "\n"

            elif type(__exploitmods_old[key].PROPERTY[propkey]) == list and propkey != "ARCH":
                try:
                    if len(__exploitmods_old[key].PROPERTY[propkey]) > 0:
                        for item in __exploitmods_old[key].PROPERTY[propkey]:
                            temp += item + "\n"
                    else:
                        temp += "\n"
                except:
                    temp += "List within list\n"

            elif propkey == "ARCH" and len(__exploitmods_old[key].PROPERTY[propkey]) > 0:
                for arch in __exploitmods_old[key].PROPERTY[propkey][0]:
                    if arch in osList:
                        temp += arch + ": "
                    else:
                        temp += arch + ", "
                temp = temp[0:-2]
                temp += "\n"

            else:
                temp += "\n"
            property_fd.write(temp)
        property_fd.write("\n")
    property_fd.close()

def docPrint():
    csvLiteList = []
    counter = 0
    csv_fd = file("Docs.csv","wb")
    csvLite_fd = file("Docs-Lite.txt", "wb")
    f = file("Docs.xml","wb")
    f.write("<?xml-stylesheet href=\"canvas.css\" type=\"text/css\"?><all_documentation>")
    csvLite_fd.write("#####################################################################\n")
    csvLite_fd.write("# Listing of CANVAS Attack Modules\n")
    logging.info("Generating documentation")
    registerAllModules()
    print __exploitmods_old
    for key in __exploitmods_old.keys():
        logging.info("Generating documentation from module %s" % key)
        ret = html_docs_from_module(__exploitmods_old[key])
        if not ret:
            continue
        html, csv, docslite = ret
        f.write(html)
        csv_fd.write(",".join(csv).replace("\n","")+"\n") #write our comma seperated value to disk
        if docslite:
            counter += 1
            csvLiteList.append(docslite)
    f.write("</all_documentation>")
    f.close()
    csv_fd.close()
    csvLite_fd.write("# Total Number of Attack Modules: %d\n"%counter)
    csvLite_fd.write("#\n# Module Name - CVE Number - CVE URL\n")
    csvLite_fd.write("#####################################################################\n")
    for line in csvLiteList:
        csvLite_fd.write(line)
    csvLite_fd.close()
    logging.info("Wrote Docs.csv, Docs.xml and Docs-Lite.txt to your CANVAS directory")

def getExploitPackName(name):
    """
    From a module name get the exploit pack it comes from and return that name as a string. Used
    to create the XML document with all the exploit data.
    """
    for ep in exploitPacks.keys():
        if exploitPacks[ep].hasModule(name):
            return ep
    return "CANVAS" #default exploit pack

def listExploits(arch=None,version=None):
    """
    Generate a printed list of the exploits this CANVAS Engine can find.
    """
    #ARCH [['Windows','2000','XP','2003']] Sometimes the ["VERSION"] gets concatenated into ["ARCH"] for some reason
    #so we work around that

    registerAllModules()
    exploit_dict = {}
    ordered_exploit_list = []
    for name in __exploitmods:
        exploitmod = getModule(name)

        if hasattr(exploitmod, "PROPERTY"):
            if 'EXPLOIT' not in exploitmod.PROPERTY['TYPE'].upper():
                continue
            else:
                if arch and version:
                    try:
                        if arch in exploitmod.PROPERTY["ARCH"][0]:
                            if version in exploitmod.PROPERTY["ARCH"][0]: #for some reason PROPERTY["VERSION"] gets concated into PROPERTY["ARCH"] by the time it gets here!
                                #found a module that fits our search critera - adding to our dict
                                exploit_dict[exploitmod]={}
                                exploit_dict[exploitmod].update(exploitmod.PROPERTY)
                                #print exploit_dict
                            else:
                                continue
                        else:
                            #print "this is not the ARCH that we wanted"
                            continue
                    except IndexError:
                        logging.error("PROPERTY[\"ARCH\"] not set in %s" % name)
                        continue

                elif arch and not version:
                    try:
                        if arch in exploitmod.PROPERTY["ARCH"][0]:
                            #this is the ARCH that we wanted!"
                            exploit_dict[exploitmod]={}
                            exploit_dict[exploitmod].update(exploitmod.PROPERTY)
                        else:
                            continue

                    except IndexError:
                        logging.error("PROPERTY[\"ARCH\"] not set in %s" % name)
                        continue
                else:
                    exploit_dict[exploitmod]={}
                    exploit_dict[exploitmod].update(exploitmod.PROPERTY)

        if hasattr(exploitmod, "DOCUMENTATION"):
            try:
                exploit_dict[exploitmod].update(exploitmod.DOCUMENTATION)
            except KeyError:
                print exploit_dict.keys()

        if hasattr(exploitmod, "__name__"):
            exploit_dict[exploitmod].update({"MODULE NAME":exploitmod.__name__})

        ##The name attribute is really used as a short description in the GUI so lets put that
        ## in the DESCRITION KEY for searching
        if hasattr(exploitmod, "NAME"):
            exploit_dict[exploitmod].update({"DESCRIPTION":[[exploitmod.NAME]]})

        if hasattr(exploitmod, "DOCUMENTATION"):
            #a dictionary
            exploit_dict[exploitmod].update({"DOCUMENTATION":exploitmod.DOCUMENTATION})

        if hasattr(exploitmod, "DESCRIPTION"):
            if exploit_dict[exploitmod].has_key("DESCRIPTION"):
                exploit_dict[exploitmod]["DESCRIPTION"][0].append(_(exploitmod.DESCRIPTION))
            else:
                exploit_dict[exploitmod].update({"DESCRIPTION":[[_(exploitmod.DESCRIPTION)]]})

        ##Remove empty enires as will save us loop iterations later when comparing
        if not exploit_dict[exploitmod]:
            del exploit_dict[exploitmod]

        ##alphbetise the order of the modules for prettyness

        ordered_exploit_list=exploit_dict.keys()
        ordered_exploit_list.sort()

    print "[+] Module name : Short description (CVE ID)"
    xml_exploits = {}
    for exploitmod in ordered_exploit_list:

        name = exploit_dict[exploitmod]['MODULE NAME']
        descr = exploit_dict[exploitmod]['DESCRIPTION'][0][0]
        if exploit_dict[exploitmod].has_key('CVE Name'):
            cveid = exploit_dict[exploitmod]['CVE Name']
        else:
            if exploit_dict[exploitmod].has_key("CVE"):
                cveid = exploit_dict[exploitmod]['CVE']
            # Deal with case where we have Url but not proper number
            elif exploit_dict[exploitmod].has_key("CVE Url"):
                temp = exploit_dict[exploitmod]['CVE Url'][-9:]
                if len(temp) != 9:
                    # Usually this means we get a result of "N/A"
                    cveid = None
                else:
                    cveid = "CVE-" + temp
            else:
                cveid = None


        print "[+] %s : %s (%s)" % (name, descr, cveid)
        if cveid not in [None, "", "None", "N/A", "Unknown"]:
            #dictionary is returned if there is no DOCUMENTATION
            documentation = exploit_dict[exploitmod].get("DOCUMENTATION",{})
            exploit_pack_name = getExploitPackName(name)
            if exploit_pack_name not in xml_exploits:
                xml_exploits[exploit_pack_name]={}
            if cveid in xml_exploits[exploit_pack_name]:
                cveid += '-1'
            xml_exploits[exploit_pack_name][cveid] = (name, descr, documentation)

    if arch == None:
        arch = ""
    if version == None:
        version = ""
    print "\n[+] Total: %d %s %s" % (len(ordered_exploit_list), arch, version)
    print "\n[+] Exploits with CVE's: %s" % len(xml_exploits.keys())
    write_xml_exploits(xml_exploits)
    return

def write_xml_exploits(xml_exploits_dict, filename = "exploits.xml"):
    """
    Write out our exploit information keyed by CVE ID
    """
    import xml.dom.minidom
    from exploitutils import b64encode
    doc = xml.dom.minidom.Document()
    exploit_pack_list = doc.createElement("ExploitPackList")
    doc.appendChild(exploit_pack_list)

    for packname in xml_exploits_dict.keys():
        exploits_dict = xml_exploits_dict[packname]
        exploit_pack = doc.createElement("CANVASExploitPack")
        exploit_pack.setAttribute("name", packname )
        exploit_pack.setAttribute("date", time.asctime())
        exploit_pack_list.appendChild(exploit_pack)
        exploits = doc.createElement("Exploits")
        exploit_pack.appendChild(exploits)

        #now add all the exploits that have CVE numbers
        for cve in exploits_dict.keys():
            name, desc, documentation = exploits_dict[cve]
            #so now we have CVE NAME and DESC
            newExploit=doc.createElement("Exploit")
            newExploit.setAttribute("name", name)
            newExploit.setAttribute("cve", cve)
            newExploit.setAttribute("desc", desc)
            documentation_element = doc.createElement("DOCUMENTATION")
            #update this when we get permission from other CEP's
            if packname in ["CANVAS","White_Phosphorus", "VOIPPACK"]:
                for documentation_key in documentation.keys():
                    documentation_element_key = doc.createElement("DocumentationKey")
                    documentation_element_key.setAttribute("name", str(documentation_key))
                    documentation_element_key.setAttribute("value", b64encode(str(documentation[documentation_key])))
                    documentation_element.appendChild(documentation_element_key)

            newExploit.appendChild(documentation_element)
            exploits.appendChild(newExploit)

    final = doc.toprettyxml()
    #print final
    file(filename,"wb").write(final)
    return final

def do_splash():
    """
    Call the progress bar routines
    - We do inner imports in this function to avoid having any GUI dependancies in case
      engine is imported by commandline program (such as massattack, which has to reload all modules)
    """
    from gui import progressbar

    class LoadProgress(progressbar.ProgGen):
        """
        Special class that derives from progressbar class - used to
        customize it for showing progress while loading CANVAS modules
        """
        def run(self):
            """
            This is an overloaded ProgressGen which just kicks the pulse
            method of the GTK progress bar every 0.01 secs until all the
            modules are loaded
            """
            import gtk
            modules_still_loading = True
            # exploitdirslist       = loadExploitPaths()
            # registeredallmodules  = 1
            # exploitsNames         = []
            # number_of_modules     = 0

            # for mydir in exploitdirslist:
            #     exploitsNames.extend( processModuleDir(mydir) )
            #     number_of_modules += len(exploitsNames)

            # Thread(target=registerSomeModules, args=(exploitsNames, self.notify)).start()
            Thread(target=registerAllModules, args=(self.notify,)).start()

            while modules_still_loading:
                if self.stopthread.isSet():
                    ##Needed if we are loading modules from more than one dir
                    self.stopthread.clear()
                    break

                self.update_bar_visually(1)
                time.sleep(0.01)

            ##Tear down the gtk loop so the main gui can operate
            gtk.main_quit()

        def notify(self):
            """
            This is a callback registerSomeModules uses to let us know
            when it is done loading stuff
            """
            modules_still_loading = False
            self.stop()

    progressbar.go("GTK", LoadProgress)


def canvasmain():
    bugtracker(__canvasmain)

def __canvasmain():
    license_check()
    from gui import loadgtk
    loadgtk()
    global registermoduleslog
    splashscreen=CanvasConfig["splashscreen"]

    init_threads=True

    if splashscreen or sys.platform == 'darwin':
        do_splash()
    else:
        registerAllModules()

    from gui import canvasguimain
    canvasguimain(init_threads=init_threads)
    threadutils_cleanup()

if __name__ == '__main__':
    logging.info("CANVAS is started using the runcanvas script")
    logging.info("You can generate documentation for modules by passing this script -D")
    logging.info("You can generate a listing of all CANVAS module PROPERTY fields by passing this script -P")
    logging.info("You can generate a listing of all exploit modules and associated advisory/vendor ID number -e")

    if len(sys.argv) == 1:
        sys.exit(1)
    if sys.argv[1]=="-P":

        if len(sys.argv) > 2 :
            ##Get a subset of properties for exploit of type specified
            getExploitsOfType(sys.argv[2])
        else:
            ##Get all properties for all exploits
            propertyPrint()

    if sys.argv[1] == "-D":
        docPrint()
    if sys.argv[1] == "-e":
        arch_dict = {}
        arch_dict["Windows"] = ["2000","XP","2003","Vista"]
        arch_dict["Linux"] = []
        arch_dict["Solaris"] = []
        arch_dict["Unix"] = []
        try:
            arch = sys.argv[2].lower().capitalize()

            if arch not in arch_dict.keys():
                logging.error("Please provide a valid Architecture from the following Options: %s" % arch_dict.keys())
                sys.exit()
        except IndexError:
            arch = None

        try:
            version = sys.argv[3].lower().capitalize()
            if version == "Xp":
                version = "XP"
            if version not in arch_dict[arch]:
                logging.error("Please provide a valid version from the following options: %s" % arch_dict[arch])
                sys.exit()
        except IndexError:
            version = None

        listExploits(arch, version)
