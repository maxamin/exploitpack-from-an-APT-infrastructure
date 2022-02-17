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

from ctypes import *
from libs.opencv.cxcore import *

CV_EIGOBJ_NO_CALLBACK = 0

#void cvCalcEigenObjects( int nObjects, void* input, void* output, int ioFlags,
#                         int ioBufSize, void* userData, CvTermCriteria* calcLimit,
#                         IplImage* avg, float* eigVals );

cvCalcEigenObjects = cfunc('cvCalcEigenObjects', _auDLL, None,
    ('nObjects', c_int, 1), 
    ('input',  ListByRef(CvArr) , 1), 
    ('output', ListByRef(CvArr), 1), 
    ('ioFlags', c_int, 1), 
    ('ioBufSize', c_int, 1), 
    ('userData', c_void_p, 1), 
    ('calcLimit',  CvTermCriteria_r, 1), 
    ('avg',  CvArr_r, 1), 
    ('eigVals', c_float_p, 1), 
)
# void cvEigenDecomposite( IplImage* obj, int eigenvec_count, void* eigInput,
#                         int ioFlags, void* userData, IplImage* avg, float* coeffs );


cvEigenDecomposite = cfunc('cvEigenDecomposite', _auDLL, None,
    ('obj',  CvArr_r, 1), 
    ('eigenvec_count', c_int, 1), 
    ('eigInput', ListByRef(CvArr), 1), 
    ('ioFlags', c_int, 1), 
    ('userData', c_void_p, 1), 
    ('avg',  CvArr_r, 1), 
    ('coeffs', c_float_p, 1), 
)


#void cvEigenProjection( int nEigObjs, void* eigInput, int ioFlags,
#                        void* userData, float* coeffs,
#                        IplImage* avg, IplImage* proj );
cvEigenProjection = cfunc('cvEigenProjection', _auDLL, None,
    ('eigInput', ListByRef(CvArr), 1), 
    ('nEigObjs', c_int, 1), 
    ('ioFlags', c_int, 1), 
    ('userData', c_void_p, 1), 
    ('coeffs', c_float_p, 1), 
    ('avg',  CvArr_r, 1), 
    ('proj',  CvArr_r, 1), 
)
