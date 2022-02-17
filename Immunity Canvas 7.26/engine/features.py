#!/usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import logging

"""
We include all optional CANVAS features (and detection tests) here.
"""

CONTROL_ENABLED         = False
LIB_ZMQ_INSTALLED       = False
LIB_PYOPENSSL_INSTALLED = False

# Strategic add-on

try:
    from control.event import Event
    CONTROL_ENABLED = True
except ImportError:
    logging.warning('C&C add-on for CANVAS is not available')

# pyOpenSSL
try:
    import OpenSSL
    logging.info('pyOpenSSL loaded: %s %s' % (OpenSSL.__name__, OpenSSL.__version__))
    LIB_PYOPENSSL_INSTALLED = True
except ImportError:
    logging.warning('Could not import pyOpenSSL, make sure it is installed')


try:
    import zmq
    LIB_ZMQ_INSTALLED = True
except ImportError:
    if CONTROL_ENABLED:
        logging.warning("Could not import ZeroMQ, C&C functionality will be disabled")
