#!/usr/bin/env python

##ImmunityHeader v1
###############################################################################
## File       :  utils.py
## Description:
##            :
## Created_On :  Fri Sep 11 11:54:26 2009
## Created_By :  J
##
## (c) Copyright 2015, Immunity, Inc. all rights reserved.
###############################################################################

# Proprietary CANVAS source code - use only under the license agreement
# specified in LICENSE.txt in your CANVAS distribution
# Copyright Immunity, Inc, 2002-2009
# http://www.immunityinc.com/CANVAS/ for more information

# Part of CANVAS For licensing information, please refer to your
# Immunity CANVAS licensing documentation

import os
import imp, sys

#
# This is needed because we have a local module named "logging", we skip
# the local path from the search
#
f, path, desc = imp.find_module("logging", sys.path[1:])
logging = imp.load_module("logging", f, path, desc)
if f is not None:
    f.close()

f, path, desc = imp.find_module("handlers", logging.__path__)
logging_handlers = imp.load_module("handlers", f, path, desc)
if f is not None:
    f.close()

from engine import CanvasConfig

root  = logging.getLogger()
f     = logging.Formatter("%(asctime)s [%(filename)26s] - %(levelname)s - %(message)s")

#
# Here we store the current session logger so that we can remove it when
# setting a new one
#
session_logger = None


def setup_session_logging(name=None):
    """
    Setup session logging if required
    """
    global session_logger
    if CanvasConfig["session_logging"]:
        session_name = (name if name else CanvasConfig["canvas_session_name"])
        output_dir   = CanvasConfig["canvas_output"]
        threshold    = None
        backups      = None
        h            = None

        if CanvasConfig["session_logging_threshold"]:
            threshold    = int(CanvasConfig["session_logging_threshold"])
            backups      = int(CanvasConfig["backups"])

        path    = os.path.join(output_dir, session_name)
        if not os.path.exists(output_dir):
            os.mkdir(output_dir)
        if not os.path.exists(path):
            os.mkdir(path)

        logging.warning("Using '%s' as base session output directory" % path)

        path    = os.path.join(path, "CANVAS.log")
        logging.warning("New session being logged at (%s)" % path)

        #
        # If we have a threshold defined we need a TimedRotatingFileHandler,
        # otherwise simply use a FileHandler
        #
        if threshold is not None and backups is not None:
            h   = logging_handlers.TimedRotatingFileHandler(path,
                                                            when="s",
                                                            interval=threshold,
                                                            backupCount=backups)
        else:
            h   = logging.FileHandler(path, mode='a')

        h.setFormatter(f)

        # remove old session logger
        if session_logger is not None:
            root.removeHandler(session_logger)

        session_logger = h

        # add new one
        root.addHandler(h)

def setup_logging(enable_debug=False):
    """
    Setup initial stdout/sessions logging

    enable_debug is passed since we have 2 mechanisms currently to enable debug statements,
    one is the old one that configures the whole product in debug mode (touch CANVAS_ROOT/.debug)
    while the other enables debug only for the new logging mechanism through our configuration
    file
    """
    if not len(root.handlers):
        level = CanvasConfig["logging_default_level"]

        # stdout
        h     = logging.StreamHandler(sys.stdout)
        h.setFormatter(f)

        if enable_debug or level == "debug":
            root.setLevel(logging.DEBUG)
        elif level == "warning":
            root.setLevel(logging.WARNING)
        elif level == "error":
            root.setLevel(logging.ERROR)
        elif level == "critical":
            root.setLevel(logging.CRITICAL)
        else:
            root.setLevel(logging.INFO)

        root.addHandler(h)

    # sessions
    if session_logger is None:
        setup_session_logging()
