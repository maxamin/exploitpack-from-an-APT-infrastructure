#! /usr/bin/env python

__all__ = [
    ############
    # submodules
    ############
    
    #'logging',
    #'debug',
    #'path',
    'colors',
    #'portability',
    #'uniqlist',
    #'threadutils',
    #'PySystemAPI',
    
    ###########
    # functions
    ###########
    
    # debug
    'debug_enabled', 'debug_threads',
    'devlog', 'isdebug', 'devassert', 'devexec', 'add_debug_level', 'backtrace',
    
    # portability
    'deprecate', 'warnings_safely_ignore', 'warning_restore',
    
    # path
    'add_python_paths', 'pathlist',
    
    # uniqlist
    'uniqlist',
    
    # threadutils
    'threadutils_add', 'threadutils_del', 'threadutils_exiting', 'threadutils_cleanup',

    # PySystemAPI
    'systemapi',
]

import logging
import debug
import uniqlist
import path
import portability
from threadutils import *
import PySystemAPI

logging.logging_init()
debug.debug_init()

# var
debug_enabled = debug.debug_enabled
debug_threads = debug.debug_threads

# func
devlog = debug.devlog
isdebug = debug.isdebug
devassert = debug.devassert
devexec = debug.devexec
add_debug_level = debug.add_debug_level
backtrace = debug.backtrace
deprecate = portability.deprecate
warnings_safely_ignore = portability.warnings_safely_ignore
warning_restore = portability.warning_restore
add_python_paths = path.add_python_paths
pathlist = path.pathlist
uniqlist = uniqlist.uniqlist

# instances from modules
systemapi = PySystemAPI.SystemAPI()

