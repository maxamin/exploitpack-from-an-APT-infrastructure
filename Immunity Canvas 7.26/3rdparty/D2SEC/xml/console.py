# -*- coding: utf-8 -*-
###
#
# Console application template
#
###

###
# STD modules
###
import os, sys, optparse, logging, cmd, readline, atexit, traceback, code, shlex

###
# Project
###
import d2sec_config
import log
import term
import templates

class app(templates.app, cmd.Cmd):
    '''Generic console application'''

    TERM            = term.TerminalController()
    FMT_CONSOLE     = TERM.GREEN+'%(levelname)-8s '+TERM.NORMAL+'%(name)-30s - %(message)s'
    RULER_SIZE      = 80
    IGNORE_CMDS     = ['do_EOF', 'do_shell', 'do_exit', 'do_q']
    OPTIONS         = []

    def __init__(self, *args, **kwargs):
        super(app, self).__init__(*args, **kwargs)
        cmd.Cmd.__init__(self)

    ###
    # Execution
    ###
    def start(self):
        #if kwargs and kwargs.has_key("histfile") and kwargs["histfile"]:
        #    self.histfile = kwargs["histfile"]
        #if kwargs and kwargs.has_key("args") and kwargs["args"]:
        #    self.args = kwargs["args"]
        #self.args = args or []
        #self.log, self.log_hdl_term = log.to_term(level=self.log_level, format=self.FMT_CONSOLE)
        #self.log = logging.getLogger(config.PROJ_NAME)
        #self.log.info('%s client v%s' % (config.PROJ_NAME, config.PROJ_VERSION))
        self.log.info('Starting console UI for %s-%s ...' % (d2sec_config.PROJ_NAME, d2sec_config.PROJ_VERSION))
        self.py = {}
        self.py['_'] = script(self)
        self.py['sh'] = self.new_console()
        self.py['buf'] = False
        self.py['on'] = False
        self.prompt_color = self.TERM.RED
        self.prompt_mode = d2sec_config.PROJ_NAME.lower()
        self.prompt_path = []
        self.opt = {}
        self.opt_callback_prefix = 'callback_opt_'
        #self.refresh_callbacks()
        #self.own_commands = copy.copy(self.get_commands())
        #self.opts_add('Global', self.OPTIONS)
        #if session:
        #    self.load_session(session, args=self.args)
        self.prompt_refresh()
        self.init_history(self.histfile)
        self.log.info('Interactive console started. Type ? or help for a list of commmands.')
        while True:
            if 1:#try:
                self.cmdloop()
            #except KeyboardInterrupt:
            #    self.log.info('Aborted (keyboard signal received)')
            #except Exception, e:
            #    self.log.error(str(e))
            #    self.log.error('Aborted due to error. See debug log for full traceback.')
            #    logfd = open('logs/debug_log.txt', 'a')
            #    traceback.print_exc(file=logfd)
            #    logfd.close()

    ###
    # Commands management
    ###
    def get_commands(self):
        self.commands = [a[3:] for a in self.get_names() if (a.startswith("do_") and a not in self.IGNORE_CMDS)]
        self.commands.sort()
        return self.commands

    ###
    # cmd.py overrides
    ###
    def onecmd(self, line):
        if self.py['on'] and line.rstrip() != '!!':
            self.py['buf'] = self.py['sh'].push(line)
            return False
        if self.py['buf'] and not line.startswith('!') and not line.startswith('shell'):
            self.do_shell([], flush=True)
        return super(app, self).onecmd(line)
        #return cmd.Cmd.onecmd(self, line)

    def postcmd(self, stop, line):
        self.prompt_refresh()
        return stop

    def get_names(self):
        return dir(self)

    def complete(self, text, state):
        if self.py['on']:
            return []
        origline = readline.get_line_buffer()
        self._complete_cmd, self._complete_args, line = self.parseline(origline)
        return super(app, self).complete(self._complete_args, state)
        #return cmd.Cmd.complete(self, self._complete_args, state)

    def completenames(self, args, *ignored):
        return ["%s " % a for a in self.get_commands() if a.startswith(self._complete_cmd)]

    def default(self, text):
        self.log.error('No such command "%s"' % text)

    def emptyline(self):
        self.log.error('Type \'quit\' to terminate this session or type ? for help')

    def parseline(self, line):
        self._current_line = line
        curcmd, arg, line = super(app, self).parseline(line)
        #curcmd, arg, line = cmd.Cmd.parseline(self, line)
        if curcmd is None:
            curcmd = ''
        args = ['']
        if arg:
            try:
                args = shlex.split(arg)
            except Exception, e:
                return curcmd, [''], line
        return curcmd, args, line

    ###
    # Command: Help
    ###
    def do_help(self, args):
        '''Show a list of commands or detailed help on a topic'''
        if args[0]:
            try:
                func = getattr(self, 'help_' + args[0])()
            except AttributeError:
                try:
                    doc = getattr(self, 'do_' + args[0]).__doc__
                    if doc:
                        self.stdout.write("%s\n"%str(doc))
                    else:
                        raise AttributeError("No doc")
                except AttributeError:
                    self.stdout.write("%s\n"%str(self.nohelp % (args[0],)))
        else:
            self._do_help_commands('Global', self.get_commands())
    do_help.usage = "[<command>]"

    def _do_help_commands(self, app, cmds):
        head = '%-24s %-70s %s' % ("%s commands name" % app, "Description", "Usage")
        print "\n%s" % head
        print '-' * len(head)
        for title in cmds:
            cmd = getattr(self, "do_%s" % title)
            if hasattr(cmd, 'alias') and cmd.alias:
                continue
            if hasattr(cmd, 'usage'):
                usage = cmd.usage
            else:
                usage = ''
            print '%-24s %-70s %s' % (title, cmd.__doc__, usage)

    def complete_help(self, args, line, begidx, endidx):
        options = ["%s " % a for a in self.get_commands() if a.startswith(args[0])]
        if len(options) == 1 \
            and options[0].lower().strip() == args[0].lower().strip() \
            and line.lower().startswith('help %s' % options[0].lower()):
                name = 'complete_help_%s' % options[0].lower().strip()
                if hasattr(self, name):
                    if len(args) == 1:
                        args.append('')
                    return getattr(self, name)(args[1:])
                return []
        return options

    ###
    # Command: Exit
    ###
    def do_quit(self, args):
        '''Exit program'''
        self.log.info('Terminating console UI ...')
        sys.exit(0)

    def do_EOF(self, args):
        print ''
        return self.do_quit(args)

    do_q = do_quit
    do_exit = do_quit

    ###
    # Misc
    ###
    def new_console(self):
        return code.InteractiveConsole(locals={
            'app'   : self,
            '_'     : self.py['_'],
        }, filename="<console>")

    def prompt_refresh(self, mode=None):
        cwd = ('~', '%s' % '/'.join(self.prompt_path))[bool(self.prompt_path)]
        if mode:
            self.prompt_mode = mode
        #self.prompt = self.TERM.BLUE+self.prompt_mode+self.TERM.GREEN+'['+self.prompt_color+cwd+self.TERM.GREEN+']'+self.TERM.NORMAL+'# '
        self.prompt = self.TERM.BLUE+self.prompt_mode+self.TERM.NORMAL+'$ '

    def prompt_set(self, value, level=0, color=None):
        self.prompt_color = color or self.TERM.RED
        try: level = int(level)
        except: level = 0
        if level < 0: level = 0
        while (len(self.prompt_path) < (level + 1)):
            self.prompt_path.append('')
        while (len(self.prompt_path) > (level + 1)):
            self.prompt_path.pop()
        self.prompt_path[level] = value
        self.prompt_refresh()

###
# Python scripting mode - extra commands
###
class script:
    '''Scripting mode commands'''

    def __init__(self, app):
        self.app = app
