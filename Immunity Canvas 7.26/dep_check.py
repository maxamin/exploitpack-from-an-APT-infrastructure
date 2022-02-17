import logging

##Pre flight checks for CANVAS dependencies, if we are missing anything we
## use the awesome pyembryo to pop a box to the user in a cross platform way

PROJ_NAME    = "Immunity CANVAS"

#TODO pass user id /args with the GET so as we can track who has problems ?
URL_MOD     = "http://www.immunityinc.com/canvas-dependencies.shtml"
URL_PY      = URL_MOD
URL_ARGS    = []

##What Checks do you want to perform
REQ_CHECKS   = [ "PY", "MOD" ]

##Python modules which are required for program to run
REQ_MOD     = { "darwin": ["gtk", "gobject", "cairo", "gtk.glade", "pyasn1", "Crypto", "bcrypt", "nacl"],
                "win32":  ["gtk", "gobject", "cairo", "gtk.glade", "pyasn1", "Crypto", "bcrypt", "nacl"],
                "linux2": ["gtk", "gobject", "cairo", "gtk.glade", "pyasn1", "Crypto", "bcrypt", "nacl"],
                "linux3": ["gtk", "gobject", "cairo", "gtk.glade", "pyasn1", "Crypto", "bcrypt", "nacl"],
              }

#TODO Optional modules ??

##Major and Minor Python versions that are required
REQ_PY       = { "darwin": [[2,5],[2,6],[2,7]],
                 "win32":  [[2,5],[2,6],[2,7]],
                 "linux2": [[2,5],[2,6],[2,7]],
                 "linux3": [[2,5],[2,6],[2,7]],
               }


## Do not edit below here ##################################################

try:
    import libs.embryo as embryo
except:
    logging.error("embryo GUI module not found")
try:
    import sys
except:
    logging.error("sys module not found")
try:
    import webbrowser
except:
    logging.error("webbrowser module not found")
try:
    import imp
except:
    logging.error("imp module not found")


class DependencyCheck:
    """
    OS agnostic Pythonic dependency checker that pops message box
    feedback to the user and optionally directs them to a URL for
    more info ARGS can also be added to the URL to help keep stats
    on common problems or specific users with problems.

    Should be fail safe, if they can run Python then they should
    get sensible output - hence the obscene amount of try/excepts
    """
    def __init__(self):
        ##What checks do we want to perform?
        check_map = {"PY" : self.check_python,
                     "MOD": self.check_modules}
        self.req_checks = []
        for check in REQ_CHECKS:
            try:
                self.req_checks.append(check_map[check])
            except KeyError:
                logging.warning("Check type '%s' could not be found, skipping")

    def pop_box(self, msg_str, url=None):
        """
        Pop an embryo box listing the missing dependencies
        and opening a browser window to the URL if OK is pressed.

        msg_str - string to print to the user
        url     - string url to go to on OK (optional)
        """
        try:
            ##Pop OS independent box
            response = embryo.message_box(
            msg_str,
            title='%s Dependency Checker'%(PROJ_NAME),
            cancel_button=True)
        except:
            ##Something must be really wrong i.e. gtk not even installed
            try:
                fd         = open("Changelog.txt","r")
                canvas_ver = fd.readline()
                fd.close()
            except:
                canvas_ver = "Unavailable"

            print "\n[EE] Serious error, please make sure core Python is installed correctly\n"
            print "Please contact us at support@immunityinc.com for further assistance\nquoting the following:\n\n"
            try:
                import traceback
                traceback.print_exc()
            except:
                logging.error("Traceback Module unavailable")
            print "\nSystem: %s\nPython: %s\nCANVAS: %s\n" % (sys.platform, sys.version.replace("\n",""), canvas_ver)
            return False

        ##Was OK pressed? - if so browse to the URL
        if response and url:
            try:
                try:
                    ##This is more reliable on linux that default embryo version
                    ## but is only available on Python > 2.5
                    webbrowser.open_new_tab(url)
                except:
                    embryo.open_url(url)
            except:
                ##Something went wrong!
                ##(on linux likely browser env var not set) Notify user
                response = embryo.message_box(
                'The web browser could not be opened, please browse to %s for further assistance'%(URL),
                title='%s Dependency Checker'%(PROJ_NAME),
                cancel_button=False)

    def check_modules(self):
        """
        Check for all the dependencies specific to this system type
        If any cannot be found pop an embryo box telling the user
        and if they agree take them to a website explaining things
        in more detail
        """
        MISSING_DEPS = []
        f            = None
        try:
            for m in REQ_MOD[sys.platform]:
                mod_found = True

                try:
                    if "." in m:
                        ## submodule import foo.bar.x.y...
                        orig_m     = m
                        components = m.split(".")
                        parents    = components[:-1]
                        m          = components[-1]
                        par_mod    = None

                        for par in parents:
                            if par_mod:
                                f, p, d = imp.find_module(par, par_mod.__path__)
                                par_mod = imp.load_module(par, f, p, d)
                            else:
                                f, p, d = imp.find_module(par)
                                par_mod = imp.load_module(par, f, p, d)
                            if f:
                                f.close()
                                f = None

                        f, p, d = imp.find_module("%s" % m, par_mod.__path__)

                    else:
                        ## standard import foobar
                        orig_m  = m
                        f, p, d = imp.find_module("%s" % m)

                except ImportError:
                    mod_found = False

                if f:
                    try:
                        f.close()
                    except:
                        pass

                #
                # This is for EGG python modules
                #
                if not mod_found:
                    for item in sys.path:
                        importer = sys.path_importer_cache.get(item)
                        if isinstance(importer, imp.NullImporter):
                            continue

                        if importer:
                            try:
                                result = importer.find_module("%s" % m)
                                if result:
                                    mod_found = True
                            except ImportError:
                                pass

                    if not mod_found:
                        # import traceback
                        # traceback.print_stack()
                        MISSING_DEPS.append(orig_m)

        except KeyError:
            ##Unsupported Platform
            MISSING_DEPS.append("Unsupported Platform!")

        if len(MISSING_DEPS) > 0:
            ##Make dependency list pretty
            dep_str = ""
            for d in MISSING_DEPS:
                # print d
                dep_str+="%s, "%(d)
            dep_str = dep_str[:-2]

            msg = 'The following dependencies required by CANVAS\r\ncould not be found:\n\n%s\n' % (dep_str)
            self.pop_box(msg + "\nPress OK to go to the CANVAS dependencies webpage", URL_MOD)

            logging.error("%s" % (msg))
            return False
        else:
            logging.info("dep_check passed: All dependencies satisfied")
            return True


    def check_python(self):
        """
        Check the system is running a version of Python that we require
        """
        running_ver     = sys.version_info
        running_ver_str = "%s.%s.%s"%(running_ver[0],running_ver[1],running_ver[2])
        for req_ver in REQ_PY[sys.platform]:
            if (running_ver[0] == req_ver[0]) and (running_ver[1] == req_ver[1]):
                ##We match, life is good
                logging.info("Required version of Python found: %s" % (running_ver_str))
                return True

        required_ver_str = ""
        for req_ver in REQ_PY[sys.platform]:
            required_ver_str += "%s.%s.x, "%(req_ver[0], req_ver[1])
        required_ver_str = required_ver_str[:-2]

        msg = "Required version of Python NOT found.\r\nRequired versions: %s\r\nRunning version: %s" % (required_ver_str, running_ver_str)
        logging.error("%s" % (msg))
        self.pop_box(msg, URL_PY)
        return False

    def __call__(self):
        """
        Call all the required checks
        """
        for c in self.req_checks:

            if not c():
                return False

        return True


def run():

    DC  = DependencyCheck()
    return DC()

if __name__ == "__main__":
    #Maybe do a get dependencies from a file autogenerated by
    # py2app / generate_cd or something so they don't have to
    # be maintained by hand ?
    ret = run()
    sys.exit(ret)

#TODO do a similar thing for crashes & errors for easy submission?
# embryo will still be usable on gui errors
