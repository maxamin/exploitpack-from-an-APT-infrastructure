# -*- coding: utf-8 -*-
###
#
# Object templates
#
###

###
# STD modules
###
import os, sys, optparse, logging, cmd, readline, atexit, re

###
# Project
###
import config
import log

class app(object):
    '''Generic d2bfs application'''

    def __init__(self, *args, **kwargs):
        super(app, self).__init__(*args, **kwargs)
        if not hasattr(self, 'name'):
            self.name = 'client'
        #log.init()
        #self.log, self.log_hdl_term = log.to_term(level=5)
        #self.log = logging.getLogger(self.name)
        #self.log.info('%s client v%s' % (config.PROJ_NAME, config.PROJ_VERSION))

    ###
    # Execution management
    ###
    def start_cli(self, args=None, histfile=config.HISTORY):
        self.args = args or None
        self.histfile = histfile
        #log.to_file(level=5, filename='logs/debug_log.txt')
        self.log, self.log_hdl_term = log.to_term(level=5)
        self.log = logging.getLogger(self.name)
        opt = optparse.OptionParser(usage='%prog [options] [<arg>] [...]')
        opt.add_option('-v', '--verbosity',
            dest='verb', metavar="LEVEL", default=4,
            help='From 1 (quiet) to 5 (debug). Default: 4')
        self.opts, self.args = opt.parse_args()
        self.log_level = int(self.opts.verb)
        log.set_level(self.log_level)
        self.start(args=self.args)

    def start(self):
        self.log.info("Proxy usage: %s" % os.environ['%s_PROXY' % config.PROJ_NAME])

    def stop(self):
        self.log.info('Shutting down ...')

    ###
    # History manipulation
    ###
    def init_history(self, histfile):
        if hasattr(readline, "read_history_file"):
            try:
                readline.read_history_file(histfile)
            except IOError, e:
                self.log.debug('Failed to load history file "%s" : %s' % (histfile, e))
            atexit.register(readline.write_history_file, histfile)

    ###
    # CLI management / options
    ###
    def cli_setup(self):
        self.opt = optparse.OptionParser(usage='%prog [options] [<arg>] [...]')
        self.cli_options_common()
        self.opts, self.args = self.opt.parse_args()
        log.set_level(int(self.opts.verb), self.log_hdl_term)

    def cli_options_common(self):
        self.opt.add_option('-v', '--verbosity',
            dest='verb', metavar="LEVEL", default=4, help='From 1 (quiet) to 5 (debug). Default: 4')
        self.opt.add_option('-n', '--noproxy',
            action='store_true', dest='proxy', default=False, help='Don\'t use a proxy. Default: False')

    ###
    # Filters
    ###
    def filter_before(self, magic, force=False, test=False):
        matches = re.compile(magic).findall(self.reply['data'])
        if matches:
            pos = self.reply['data'].find(str(matches[0]))
            if pos > -1:
                if not test:
                    self.reply['data'] = self.reply['data'][:pos]
                    self.reply['error'] = False
                return True
        if force and not test:
            self.reply['error'] = True
        return False

    def filter_after(self, magic, force=False, test=False):
        matches = re.compile(magic).findall(self.reply['data'])
        if matches:
            pos = self.reply['data'].find(str(matches[0]))
            if pos > -1:
                if not test:
                    self.reply['data'] = self.reply['data'][pos + len(matches[0]):]
                    self.reply['error'] = False
                return True
        if force and not test:
            self.reply['error'] = True
        return False

    ###
    # Callback: Option 'level'
    ###
    def callback_opt_level(self, args):
        try:
            level = int(args[0])
            if level < 1 or level > 5:
                raise Exception("")
        except Exception, e:
            self.log.error('Invalid log level "%s"' % args[0])
            return False
        mwef.routines.log.set_level(level, self.log_hdl_term)
        return args
