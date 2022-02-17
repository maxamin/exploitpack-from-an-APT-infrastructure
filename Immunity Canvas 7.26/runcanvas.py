#!/usr/bin/env python
##ImmunityHeader v1
###############################################################################
## File       :  runcanvas.py
## Description:
##            :
## Created_On :  Thu Nov  5 11:54:26 2009
## Created_By :  Rich
## Modified_On:  Thu Nov  5 12:01:31 2009
## Modified_By:  Rich
##
## (c) Copyright 2009, Immunity, Inc. all rights reserved.
###############################################################################
#!/usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2009
#http://www.immunityinc.com/CANVAS/ for more information

#Part of CANVAS For licensing information, please refer to your
#Immunity CANVAS licensing documentation

"""
Runs CANVAS
"""
import os, sys
try:
    from extras import immunity
except:
    pass

##Set an env var to show we are running as some parts of the code
## take different behaviour standalone vs when running as CANVAS
os.environ["CANVAS_RUNNING"] = "YES"

##here we change location to where our install path is, ideally
our_dir=os.path.abspath(os.path.join(os.path.dirname(sys.argv[0]),'.'))
os.chdir(our_dir)

##Are we running from a standalone bundle (py2app/py2exe) or from a
## tarball/zip that will use the system Python & dependencies ?
#TODO - dynmaically work this out
if "runcanvas." in sys.argv[0]:
    STANDALONE   = False
    OPEN_CONSOLE = False
else:
    STANDALONE   = True
    OPEN_CONSOLE = False

from internal.debug import debug_enabled
from internal.utils import setup_logging
setup_logging(enable_debug=debug_enabled)

import logging

if not STANDALONE:
    ##Using the standard system Python etc
    ##So we do a pre-flight check for things CANVAS requires
    ## - this is OS independent (Win32/Linux/OS X) - pops gui message boxes
    import dep_check

    if not os.getenv("$DISPLAY"):
        os.environ["$DISPLAY"] = "0.0"

    if dep_check.run():
        ##Dependencies satified - continue
        from canvasengine import canvasmain
        canvasmain()
    else:
        logging.critical("Failed dependency check - Exiting")

else:
    ##Using a standalone bundle that already has Python + dependencies
    ## we just to fix up a few paths for font rendering etc dynamically
    ## as well as set some GTK specific enviromental variables away from
    ## the standard system values

    def set_paths(filename, base):
        """
        Fix up relative paths for gtk/pango config files
        IN  : full path to desired @path file
        OUT : True/False
        """
        src = filename + '.in'
        dst = filename

        try:
            #print "+++Processing: ",src
            data = open(src, 'r').readlines()
            if [line for line in data if '@path' in line]:
                #print '[+] setting paths ...'
                patched = [line.replace('@path', base)\
                           for line in data]
                #print "+++Writing to: %s"%dst
                f = open(dst, 'w')
                f.writelines(patched)
                f.close()
        except Exception, err:
            #print err
            #print '[+] could not set paths in %s' % filename
            return False
        return True

    sys.path.insert(0, "./" )

    ##BUG BUG: If the bundle name has a space in it we break - fix me
    app_dir=os.getcwd()

    ## gtk/gdk
    os.environ['GTK_EXE_PREFIX']  = app_dir
    os.environ['GTK_DATA_PREFIX'] = app_dir
    os.environ['GTK_PATH']        = app_dir
    mod_config = os.path.join(app_dir, 'etc', 'gtk-2.0', 'gdk-pixbuf.loaders')
    os.environ['GDK_PIXBUF_MODULE_FILE'] = mod_config
    set_paths(mod_config, app_dir)

    ## pango & fonts
    font_config = os.path.join(app_dir,'etc', 'fonts', 'fonts.conf')
    os.environ['FONTCONFIG_FILE'] = font_config
    pango_conf = os.path.join(app_dir, 'etc', 'pango', 'pango.modules')
    set_paths(pango_conf, app_dir)
    pango_rc = os.path.join( app_dir, 'etc', 'pango', 'pangorc')
    set_paths(pango_rc, app_dir)
    os.environ['PANGO_RC_FILE'] = pango_rc

    if sys.platform == "darwin":
        if OPEN_CONSOLE:
            try:
                import subprocess
                subprocess.Popen(["open","/Applications/Utilities/Console.app"])
            except:
                logging.error("Could not open Console.app")

        ##Py2app specific as the CANVAS python code lives in:
        ##  <CANVAS>.app/Contents/Resources/CANVAS
        os.chdir("./CANVAS")

    from canvasengine import canvasmain
    canvasmain()
