# -*- coding: utf-8 -*-
###
#
# Project Configuration
#
###

###
# STD modules
###
import os, sys

newpath = os.path.join(os.path.dirname(__file__), 'lib')
if newpath not in sys.path: sys.path.append(newpath)
newpath = os.path.join(os.path.dirname(__file__), 'ext')
if newpath not in sys.path: sys.path.append(newpath)

#############################################################################
# Main
#############################################################################
# Project name and version
PROJ_NAME           = 'D2BFK'
PROJ_VERSION        = '0.0.1'

# Full path to installation. Default: autodetect.
PROJ_DIR            = os.path.abspath(os.path.split(__file__)[0])

# Full path to installation. Default: autodetect.
HISTORY             = os.path.join(PROJ_DIR, '.history')
