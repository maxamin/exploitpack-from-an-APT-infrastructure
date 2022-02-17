#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

__all__ = ['canvasguigtk2', 'defaultgui', 'gui_queue', 'newgui', 'text_with_markup', 'loadgtk',"file_browser"]

# caching, only one gui per session is enough.
global __canvasguimain
__canvasguimain = None

def loadgtk():
    from canvasguigtk2 import loadgtk as __loadgtk
    return __loadgtk()

def canvasguimain(init_threads=True):
    global __canvasguimain
    if __canvasguimain == None:
        import canvasguigtk2
        __canvasguimain = canvasguigtk2.canvasguimain(init_threads=init_threads)
    return __canvasguimain
