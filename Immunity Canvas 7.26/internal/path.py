#! /usr/bin/env python

import os, sys
import debug
from uniqlist import uniqlist

def pathstr(path):
    if len(path):
        if path[-1] != os.path.sep:
            path += os.path.sep
    return path

def pathjoin(dirname, filename):
    return dirname + os.path.sep + filename

class pathlist(uniqlist):
    def __iadd__(self, tlist):
        def _pathstr(pathstr):
            if len(pathstr):
                if pathstr[-1] != os.path.sep:
                    pathstr += os.path.sep
            return pathstr
        return uniqlist.__iadd__(self, map(pathstr, tlist))

def get_python_paths():
    python_paths = []
    # FIXME: unix only -> think about win32
    for path in ["", "/usr", "/usr/local", "/opt/local"]:
        pathlib = pathjoin(path, "lib")
        try:
            entries = os.listdir(pathlib)
        except OSError:
            continue
        for entry in entries:#os.listdir(pathlib):
            subpathlib = pathjoin(pathlib, entry)
            if os.path.isdir(subpathlib) and entry[0:6] == "python":
                python_paths += [subpathlib]
    return pathlist(python_paths)

def add_python_paths():
    if os.name != "posix" or sys.platform in ["cygwin", "nt", "win32"]:
        return
    for path in get_python_paths():
        debug.devlog("adding python path %s" % path)
        sys.path.append(pathstr(pathjoin(path, "site-packages")))

