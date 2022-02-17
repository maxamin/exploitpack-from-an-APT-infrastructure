#! /usr/bin/env python
"""
Debug.py 


"""


TODO = """
_debug_separator in isdebug()
"""

import os

# XXX __debug__ check here (if !__debug__ -> debug_enabled = False

#cannot move these files to canvas_root_directory because this
#module is imported by engine.config as well

# run at load
debug_levels = []
__DEBUG_OPTIONS_FILE =  ".debug"
__DEBUG_OUTPUT_FILE = "DEBUG.log"
__debug_config = os.getcwd() + os.path.sep + __DEBUG_OPTIONS_FILE
__debug_output = os.getcwd() + os.path.sep + __DEBUG_OUTPUT_FILE
debug_enabled = os.path.exists(__debug_config)
debug_threads = False # XXX exported?
global debug_output
debug_output = None

if os.path.exists(__debug_output):
    debug_output = file(__debug_output, "ab")

import logging
import colors

_debug_initialized = False

if __debug__:
    
    _debug_separator = "::"
    _debug_level_negator_char = '!'
    _debug_level_ignore_char = '#'
    _debug_levels_ignored = []
    
    def _debug_init():
        global _debug_initialized
        if _debug_initialized:
            return
        _debug_initialized = True
        global debug_enabled
        if debug_enabled:
            debug_file = open(__debug_config, 'rb')
            for line in debug_file.readlines():
                _add_debug_level(line.strip('\n'))
            debug_file.close()
    
    def _add_debug_level(level):
        global _debug_initialized
        if not _debug_initialized:
            _debug_init()
        global debug_levels
        if not len(level):
            return
        if level[0] in [_debug_level_negator_char, _debug_level_ignore_char]:
            flag = level[0]
            level = level[1:]
            if flag == _debug_level_ignore_char and level in debug_levels:
                debug_levels.remove(level)
            global _debug_levels_ignored
            if flag == _debug_level_negator_char and level not in _debug_levels_ignored + ["all"]:
                _debug_levels_ignored += [level]
        elif not level in debug_levels:
            if level == "all":
                debug_levels.insert(0, "all")
            else:
                debug_levels += [level]
            if level == "Threads":
                global debug_threads
                debug_threads = True

def add_debug_level(klevel):
    if __debug__:
        if type(klevel) != type([]):
            klevel = [klevel]
        for level in klevel:
            _add_debug_level(level)

def debug_init():
    if __debug__:
        _debug_init()
        if "all" in debug_levels:
            logging.display("logging ALL levels", color=colors.GREEN)
        else:
            for level in debug_levels:
                logging.display("logging level: %s" % level, color=colors.GREEN)

def force_debug_level(klevel): # XXX check here, do we force?
    if __debug__:
        add_debug_level(level)

def isdebug(level):
    if __debug__:
        global _debug_initialized
        if not _debug_initialized:
            _debug_init()
        global debug_levels
        if level == "all" or level in debug_levels:
            return True
        global _debug_levels_ignored
        if "all" in debug_levels:
            if level in _debug_levels_ignored:
                return False
            return True
        # XXX TODO check split code - use of rfind()
        #now we check to see if the level matches
        #we split by the symbol :: and see if we are in any combination
        #for example:
        # devlog("somefile::somefunction","hi") would match both ("somefile") and ("somefile::somefunction")
        #first we check for an exact match
        return False # XXX for now
        for testlevel in debug_levels:
            splitlevels = level.split(_debug_separator)            
            #print "testlevel=%s splitlevels=%s"%(testlevel,splitlevels)
            if testlevel in splitlevels:
                return True
    return False

# log msg for dev ppl
# if fp is passed it should be an open writeable file
def devlog(level, msg = None, color = colors.RED, desc = None, nodesc = False, nofile = False, fp=False):
    # write data to file
    if fp:
        fp.write(str(msg)+"\n")
        
    if __debug__:
        global _debug_initialized
        if not _debug_initialized:
            _debug_init()
        
        
        # fix for old devlog() way
        if not msg:
            msg = level
            level = "all"
        
        if nodesc:
            desc = ""
        elif desc == None:
            desc = level
        if desc != "":
            desc += ": "
        
        if debug_output and not nofile:
            debug_output.write("%s%s\n" % (desc, msg))

        global debug_enabled
        if not debug_enabled or not isdebug(level):
            return
        
        logging.display("%s%s" % (desc, msg), color=color)

# exec code for dev ppl
def devexec(level, code = None):
    if __debug__:
        global _debug_initialized, debug_enabled
        if not _debug_initialized:
            _debug_init()
        if not debug_enabled:
            return
        
        if not code:
            code = level
            level = "all"
        
        if isdebug(level):
            exec code
            # TODO return value ?

# assert for dev ppl
def devassert(level, condition, expression=None, exception=AssertionError):
    if __debug__:
        global _debug_initialized, debug_enabled
        if not _debug_initialized:
            _debug_init()
        if not debug_enabled or not isdebug(level):
            return
        
        if not condition:
            devlog(level, "Assertion Error! raising %s..." % exception)
            if expression:
                devlog(level, "ASSERTION> %s" % expression)
                raise exception, expression
            else:
                raise exception

def backtrace(exit=False, limit=None, file=None):
    import traceback
    traceback.print_stack(limit=limit, file=file)
    if exit:
        raise SystemExit

if __name__ == "__main__":
    devlog('all', "logging in yellow is gay", colors.YELLOW)
    devexec("""print "dev code executed" """)
    try:
        devassert('all', 2 < 1, "dev assert test", OverflowError)
    except OverflowError:
        print "OverflowError! (correct)"
    #except:
    #    print "smth broken here"
    add_debug_level('test1')
    add_debug_level(['!test2', 'test3'])
    devlog('test1', "test1")
    add_debug_level('all')
    devlog('test2', "test2")
    devlog('test3', "test3")
    devlog('test4', "test4")
    
    print "tests done."
