#!/usr/bin/env python
# ctypes-opencv - A Python wrapper for OpenCV using ctypes

# Copyright (c) 2008, Minh-Tri Pham
# All rights reserved.

# Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

#    * Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
#    * Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
#    * Neither the name of ctypes-opencv's copyright holders nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

#THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# For further inquiries, please contact Minh-Tri Pham at pmtri80@gmail.com.
# ----------------------------------------------------------------------------

from libs.opencv.cxcore import *
from libs.opencv.cv import *
from libs.opencv.highgui import *
from libs.opencv.interfaces import *
from libs.opencv.cvaux import *

try:
    from libs.opencv.ml import *
except ImportError:
    pass

# On Win32, bring in support for a Python implementation of a background
# image thread.
import sys
if sys.platform == 'win32':
    from highgui_win32 import *

# ----------------------------------------------------------------------------
# Begin of code section contributed by David Bolen
# ----------------------------------------------------------------------------
#
# Publish an optional "cx" namespace intended for use without having to import
# all the names into the local namespace, but minimizing duplication by
# removing any "cv" or "cv_" prefix.  With "from opencv import cx as cv" it
# then permits usage as "cv.Foo" instead of "cvFoo".
#

class _cx(object):
    """OpenCV namespace for functions/types/constants with any "cv"/"cv_"
    prefix removed.  Symbols not starting with cv/cv_ retain their full name.

    A leading underscore is retained in the following cases:
    - Structures/Data types (CvXxx).  E.g., cx._Mat is the CvMat structure
      and cx.Mat is the cvMat constructor
    - Names for which removing the full prefix yields an invalid identifier.
      Generally just constants with leading digits.  E.g., CV_32F is cx._32F
    - Names which otherwise collide, where a preference is for cvXxx
      functions.  E.g., CV_SVD is cx._SVD while the cvSVD function is cx.SVD
    """
    pass

cx = _cx()

# Process names in reverse order so functions/factories cvXXX will show up
# before structures (CvXXX) or constants (CV_) and thus functions/factories
# get preference in terms of collisions

for sym, val in sorted(locals().items(), reverse=True):
    if sym.startswith('__'):
        continue

    if sym.startswith('Cv'):
        sname = '_' + sym[2:]
    elif sym.lower().startswith('cv'):
        if sym[2:3] == '_' and not sym[3:4].isdigit():
            sname = sym[3:]
        else:
            sname = sym[2:]
    else:
        sname = sym

    # Use underscore to distinguish conflicts
    if hasattr(cx, sname):
        sname = '_' + sname

    # If still have a conflict, punt and just install full name
    if not hasattr(cx, sname):
        setattr(cx, sname, val)
    else:
        setattr(cx, sym, val)

# ----------------------------------------------------------------------------
# End of code section contributed by David Bolen
# ----------------------------------------------------------------------------
