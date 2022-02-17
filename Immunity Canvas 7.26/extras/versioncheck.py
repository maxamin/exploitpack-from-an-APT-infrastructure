#!/usr/bin/python

import sys
import socket
if "." not in sys.path: sys.path.append(".")

from threading import Thread
import os
import time, datetime
import logging

#try to get uname so we know windows/linux and up2date python or not
try:
    import platform
    uname = str(platform.uname()) + "_" + platform.python_version()
except:
    uname = "PlatformImportFailed"

import base64
import urllib
import libs.spkproxy as spkproxy

from engine.config import canvas_root_directory
from internal import *


class versionchecker(Thread):
    """
    Calls out to a remote resource to check if we are at current version
    """
    def __init__(self, engine, ps="", callback=None):
        """
        Callback is a callable object that is specified by the code invoking the check. The callable object should be able to handle
        two arguments: arg1 whether we are at the current version (True if we are or False if we're not)
                       arg2 a string with a message about what version we are at etc

        What the callable does is completely up to it obviously
        """
        Thread.__init__(self)

        self.engine = engine
        self.URL = "https://canvas.immunityinc.com/last_version"

        # This is the function that is called when we find out the most current
        # version is not running, what it does is up to you
        self.out_of_date_callback = callback
        self.ps = ps

        return

    def subscription_still_valid(self):
        """
        Compare todays date and the expiry date and see if the customers
        update subscription has expired.
        Return False if expired, True if it hasn't
        """
        if self.expiredate == "None":
            ##Developer version from svn tree - obviously still valid
            return 1

        today = datetime.date.today()
        #Convert expiry date into a real date format that can be compared instead of MM/DD/YY
        (m, d, y) = self.expiredate.split("/")
        ##A year value of zero means never expires but doesn't work with
        ## datetime so skip anyway
        if int(y) != 0:
            exp_date = datetime.date(int(y), int(m), int(d))

            dif = exp_date - today
            if dif.days <= 0:
                #expired
                return 0

        #not expired
        return 1

    def check(self, URL):
        if not self.engine.config["VersionCheck"] and self.ps != "manual_check":
            logging.debug("No version check due to configuration")
            return False
        try:
            logging.debug("Connecting to URL: %s" % URL)
            f = spkproxy.urlopen(URL)
            version = f.read()
            # no trailing \n
            version = version.strip()
            # version = "test fail"
            # self.expiredate = "02/01/2009"

            # in the case of a non-internet host - we return the spkproxy.py error about "no server there"

            #
            # XXX: Ideally we deal with this through PEP 440 which requires a revision
            #      to our versioning format
            #
            if self.currentversion < version and "No server there" not in version:
                logging.info("Newest version available is: %s, your version is %s. You might want to upgrade to a more current version." % ( version, self.currentversion))

                if callable(self.out_of_date_callback):

                    hdr = """A newer version of CANVAS is available to download.

Current version you are running:

%s

The latest version of CANVAS available:

%s
                    """ % (self.currentversion, version)

                    #self.expiredate="07/15/2009"
                    ##Is the customers update subscription still valid?
                    ret = self.subscription_still_valid()
                    if ret :
                        #NOT EXPIRED
                        msg = """%s
Your subscription is still valid (until %s) so click the 'Download'
button to go to the Immunity website and download the
latest version or navigate to:
https://canvas.immunityinc.com/getcanvas""" % (hdr, self.expiredate)

                    else:
                        #EXPIRED
                        msg = """%s
However it appears your CANVAS update subscription expired
on %s. If you would like to renew your subscription to
receive CANVAS updates please contact:

admin@immunityinc.com
or
+1 786 220 0600""" % (hdr, self.expiredate)

                at_latest_ver = False
            elif "No server there" in version:
                msg = "Error while retrieving version information"
                logging.debug(msg)
                at_latest_ver = False
            else:
                logging.debug("Version (%s) is current version on server" % version)
                msg = "You are at the most current version of CANVAS:\n\n%s" % (self.currentversion)
                at_latest_ver = True
        except Exception, err:
            import traceback
            error = traceback.format_exc()
            devlog("versionchecker", "Failed to connect to remote machine for version check: %s" % error)
            return

        if self.out_of_date_callback:
            self.out_of_date_callback(at_latest_ver, msg)


    def run(self):
        """
        Calls the self.realrun function but catches
        when sys.exit is called
        """
        i=1
        try:
            self.realrun()
        except:
            #true will be "none" when sys.exit(1) is called
            if devlog!=None:
                # print "Reraising"
                raise
        return

    def realrun(self):
        userdatafilename = os.path.join(canvas_root_directory, "userdata")
        try:
            self.expiredate, contactemail, username = file(userdatafilename, "r").readlines()[:3]
        except:
            self.expiredate, contactemail, username = ("None_ExpireDate", "None_ContactEmail", "None_Username")
        username = username.strip()
        currentversion = self.engine.getCANVASVersion()
        self.currentversion = currentversion
        alldata = str(uname) + "_" + str(username) + "_" + str(currentversion)
        if len(self.ps) > 0:
            alldata += "_" + str(self.ps)
        logging.debug("Checking version: %s" % alldata)
        URL = self.URL
        if not self.check(URL):
            pass
            #self.engine.log("Running CANVAS Version: %s"%currentversion)
        return

if __name__=="__main__":
    #testing our version checker
    import canvasengine
    from internal import debug
    debug.add_debug_level("versionchecker")
    myengine = canvasengine.canvasengine()
    myversionchecker = versionchecker(myengine)
    myversionchecker.run()
    time.sleep(5)

