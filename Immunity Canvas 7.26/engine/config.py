#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity Fl0w3r, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information
# 

"""
ideally we have a XML config file
but we want to parse argv[] and envp[] options as well.

entrypoints should return booleans only.

no more than 1 instance per process.

we have to parse the first and only one method available:
- xml
- .config, canvas.conf
then accept cmdline bypass option

"""

#this is the directory we load resources like ifids.txt from. Ideally not the root directory
#but that will be something we change later.

import os

##TODO - do a proper determination of where we are executing from and make us be able to execute from anywhere
canvas_root_directory=os.environ.get("canvas_root_directory",".")
#canvas_resources_directory=os.environ.get("canvas_resources_directory",os.path.join(canvas_root_directory,"Resources"))
#canvas_reports_directory=os.path.join(canvas_root_directory,"Reports")

ConfigFile = os.path.join(canvas_root_directory, "canvas.conf")

ConfigFileSeparator = '='

import sys
sys.path += ['.']
from internal import devlog

from types import DictType
import re

class _CanvasConfig(DictType):
    """
    Contains the CANVAS configuration information for our engine
    """
    __default_config = """
    sniffer                   = yes
    dnsresolve                = yes
    sound                     = yes
    xml_header_scale          = 1.6
    geoip                     = yes
    timestamps                = yes
    guitimestamps             = no
    ssl_mosdef                = no
    ensure_disconnect_shellcode     = no
    canvas_output             = Sessions
    canvas_session_name       = default
    session_logging           = yes
    canvas_session_name       = default
    break_php_safemode        = no
    node_startup_exploit      = startup

    commander                 = 127.0.0.1
    commander_bind_ip         = *
    commander_pub_port        = 4445
    commander_pull_port       = 4446
    operator_alias            =
    operator_uuid             =
    """

    def __init__(self, argv = None):
        DictType.clear(self)

        # first of all we load default CANVAS config (at the top of that file)
        for line in self.__default_config.split('\n'):
            self.__parse_configline(line, 'Config::DefaultConf')

        # then we parse user's config file
        self.load_configfile()

        # and at the end we overwrite config with cmdline options
        self.parse_argv()

    def __setitem__(self, name, val):
        if type(val) == type("") and val.lower() in ['no', 'false']:
            val = False
        DictType.__setitem__(self, name, val)

    def load_configfile(self, filename = ConfigFile):
        devlog('Config::ParseFile', "parsing file %s" % filename)
        try:
            fd = file(filename)
        except IOError:
            #failed to open CANVAS.conf
            print "Could not open CANVAS.conf!"
            return
        for line in fd.readlines():
            self.__parse_configline(line, 'Config::ParseFile')
        fd.close()

    def __parse_configline(self, line, devloglevel = 'Config::parse_configline'):

        comment_type_table = {'#': "DESC", ';': "COMMENTED"}
        line = line.strip()
        if re.match('^\s*$', line):
            return
        if re.match('^\s*(#|;)', line):
            ignored, comment_type, comment = re.split('^\s*(#|;)\s*', line)
            devlog(devloglevel, "%s> %s" % (comment_type_table[comment_type], comment))
            return
        val = True
        seppos = line.find(ConfigFileSeparator)
        if seppos != -1:
            name = line[:seppos].strip()
            val = line[seppos+1:].strip()
        else:
            name = line
        devlog(devloglevel, "OPTION> %s = %s" % (name, val))
        self.__setitem__(name, val)

    def parse_argv(self, argv = None):
        """
        only longopt for now.

        --opt    -> opt=True
        --opt=a  -> opt=a
        --no-opt -> opt=False
        """
        if argv == None:
            import sys
            argv = sys.argv[1:]
        if type(argv) == type(""): # dangerous?
            argv = argv.split(' ')
        assert type(argv) == type([]), "expecting a list for argv, got %s" % type(argv)
        for arg in argv:
            val = True
            name = arg[2:]
            if name[:3] == 'no-':
                val = False
                name = name[3:]
            if '=' in name:
                s = name.split('=')
                name = s[0]
                val = s[1]
            if val in ['no', 'False']:
                val = False
            devlog('Config::ParseArgv', "%s: %s" % (name, val))
            self.__setitem__(name, val)

    def __getitem__(self, *kargs):
        value = False
        name = kargs[0]
        if type(name) == type(()):
            name, value = name[:2]
        if DictType.__contains__(self, name):
            value = DictType.__getitem__(self, name)
        devlog('Config::GetItem', "%s = %s" % (name, value))
        return value

    def __str__(self):
        return "<CANVAS Config instance %s>" % DictType.__repr__(self)

global CanvasConfig
CanvasConfig = _CanvasConfig()

##Now set old style variables in use in many places in the system for legacy compatibility - eventually this will be removed
canvas_resources_directory=CanvasConfig["canvas_resources"]
canvas_reports_directory=CanvasConfig["canvas_output"]
#print CanvasConfig

if __name__ == "__main__":
    from internal import add_debug_level
    add_debug_level(['Config::ParseArgv', 'Config::ParseFile'])
    config = CanvasConfig
    config.parse_argv("--no-sniffer --username=maradona --uid=123 --broadcast")
    print config
    print repr(config)
    print config['sniffer']
    print config['sniffer', True]
    print config['uhuh', 42]
    print config['timestamps']

