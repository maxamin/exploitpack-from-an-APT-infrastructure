# -*- coding: utf-8 -*-

###
# STD modules
###
import logging

###
# Project
###
import term

TERM        = term.TerminalController()
FMT_TIME    = '%H:%M:%S'
FMT_DATE    = '%d-%m-%y %H:%M:%S'
FMT_CONSOLE = TERM.YELLOW+'%(asctime)s - '+TERM.GREEN+'%(levelname)-8s'+TERM.NORMAL+' - %(message)s'
LEVELS      = {
    'HOSTVULN'  : 90,
    'HOSTINFO'  : 80,
}
for name, lvl in LEVELS.items(): logging.addLevelName(lvl, name)

###
# Logger Types
###
def init(level=5):
    set_level(level, logging.root)
    return logging.root

def to_term(name='', level=5, format=FMT_CONSOLE):
    log2term = ConsoleHandler()
    log2term.setFormatter(logging.Formatter(format, datefmt=FMT_TIME))
    if not name:
        logger = logging.root
    else:
        logger = logging.getLogger(name)
    logger.addHandler(log2term)
    set_level(level, log2term)
    return logger, log2term

###
# Colored Console handler
###
class ConsoleHandler(logging.StreamHandler):
    def emit(self, record):
        try:
            msg = self.format(record)
            fs = "%s\n"
            msg = msg.replace('CRITICAL', TERM.RED+'CRITICAL'+TERM.NORMAL)
            msg = msg.replace('ERROR', TERM.RED+'ERROR'+TERM.NORMAL)
            msg = msg.replace('WARNING', TERM.RED+'WARNING'+TERM.NORMAL)
            msg = msg.replace('DEBUG', TERM.CYAN+'DEBUG'+TERM.NORMAL)
            msg = msg.replace('HOSTVULN', TERM.MAGENTA+'HOSTVULN'+TERM.NORMAL)
            msg = msg.replace('HOSTINFO', TERM.BLUE+'HOSTINFO'+TERM.NORMAL)
            try:
                self.stream.write(fs % msg)
            except UnicodeError:
                self.stream.write(fs % msg.encode("UTF-8"))
            self.flush()
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

###
# Set logger verbosity
###
def set_level(level=4, logger=None):
    try: lvl = 60 - (int(level) * 10)
    except: lvl = 20
    if logger: return logger.setLevel(level=lvl)
    return logging.root.setLevel(level=lvl)
