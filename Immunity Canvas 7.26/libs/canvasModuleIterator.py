#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2015
#http://www.immunityinc.com/CANVAS/ for more information

import sys
if "." not in sys.path:
    sys.path.append(".")

import os, getopt, string
import re
import socket
import locale
import random
import base64
import math
import re
import logging

import urllib2

from datetime import datetime
import ast

from exploitutils import *

from canvasexploit import canvasexploit
from exploitmanager import exploitmanager
from ExploitTypes.localcommand import LocalCommand
import canvasengine
import CANVASNode

class canvasModuleIterator(LocalCommand):
    def __init__(self):
        LocalCommand.__init__(self)
        return

    def cry_not_vulnerable(self, exploit_name, node_name):
        logging.info("Exploit (%s) claims node %s is not vulnerable, skipping", exploit_name, node_name)
    
    def getListener(self, app):
        """
        Returns -1 on failure (extremely rare).
        Returns none if no listener is needed
        returns a listener otherwise
        """
        neededtypes=app.neededListenerTypes()
        if neededtypes!=[]:
            listener= self.engine.autoListener(None, neededtypes[0])
            if listener==None: #still none? Then print error message
                logging.warning("You need to select a valid listener %s for this exploit! (Is it blue?)"%(app.neededListenerTypes()))
                return -1
            listener.argsDict=app.listenerArgsDict

        else:
            listener=None
        app.callback=listener
        return listener

    def setExploit(self, app, app_class):
        app.argsDict = self.argsDict
        app.argsDict["passednodes"] = self.argsDict["passednodes"]
        app.target = self.target
        app.setId(self.engine.getNewListenerId())
        app.engine = self.engine
        app.setLogFunction(self.engine.exploitlog)
        app.setDebugFunction(self.engine.exploitdebuglog)
        app.setInfo(app.getInfo())
        app.setCovertness(self.engine.getCovertness())
        self.manager=exploitmanager(app, self.engine)
        return self.manager

    def runExploit(self, app):
        """
        run the exploit , including set up the listeners it needs for callbacks
        """
        ret = self.manager.run()
        #self.exploits.append(app)

        ##Did we succeed in exploiting the box ?
        if isinstance(ret, CANVASNode.CANVASNode) or app.ISucceeded():
            logging.info("Exploit succeeded!")
            return ret
        return ret


    def run_exploits(self, node, exploit_list, exploit_params = None):
        # NN: allow the user to either print out the LPEs, save them in Knowledge for later manual use
        for exploit in exploit_list:
            logging.info("Running LPE: \"%s\"" % exploit.NAME)
            lpe = exploit.theexploit()
            lpe.link(self)
            if exploit_params:
                if exploit.__name__ not in exploit_params:
                    logging.error("Exploit %s is not in exploit_params dictionary.", exploit.__name__)
                    raise KeyError
                if exploit_params[exploit.__name__]:
                    for par_name, par_value in exploit_params[exploit.__name__].iteritems():
                        setattr(lpe, par_name, par_value)
            lpe.argsDict["passednodes"] = [node]
            manager = self.setExploit(lpe, exploit)
            listener = self.getListener(lpe)

            if hasattr(lpe, "is_vulnerable"):
                if not lpe.is_vulnerable():
                    self.cry_not_vulnerable(exploit.__name__, str(node))
                    continue

            # lpe_ret = lpe.run()
            lpe_ret = self.runExploit(lpe)

            logging.info("\"%s\" returned: %s" % (exploit.__name__, str(lpe_ret)))

            if not lpe_ret:
                continue
            else:
                break

    def canonicalize_exploit_name(self, name):
        return name.lower().strip("-").strip("_")
