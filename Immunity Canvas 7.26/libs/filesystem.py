#!/usr/bin/env python

"""
Filesystem.py 

Useful utilities for browsing around the filesystem
"""

import os

def lsdashr(basedir,excludelist=[],suffixexcludelist=[]):
    """
    emulates ls -r
    """
    ret=[] #files returned
    dirs=[basedir] #directories returned
    files=os.listdir(basedir)
    for file in files:
        if file in excludelist:
            continue
        name=os.path.join(basedir,file)
        #print "Found %s:"%name
        if os.path.basename(name) in excludelist:
            continue
        skip=False 
        for suffix in suffixexcludelist:
            if os.path.basename(name).endswith(suffix):
                skip=True 
                break
        if skip:
            continue
        
        if os.path.isdir(name):
            nret,ndirs=lsdashr(name,excludelist)
            ret+=nret
            dirs+=ndirs
        else:
            ret+=[name]
    return ret,dirs

