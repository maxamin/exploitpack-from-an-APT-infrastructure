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
from libs.opencv.highgui import CV_CVTIMG_SWAP_RB


#=============================================================================
# Helpers for access to images for other GUI packages
#=============================================================================

__all__ = []

#-----------------------------------------------------------------------------
# wx -- by Gary Bishop
#-----------------------------------------------------------------------------
# modified a bit by Minh-Tri Pham
try:
    import wx

    def cvIplImageAsBitmap(self, flip=True):
        flags = CV_CVTIMG_SWAP_RB
        if flip:
            flags |= CV_CVTIMG_FLIP
        cvConvertImage(self, self, flags)
        return wx.BitmapFromBuffer(self.width, self.height, self.data_as_string())
        
    IplImage.as_wx_bitmap = cvIplImageAsBitmap
        
    __all__ += ['cvIplImageAsBitmap']
except ImportError:
    pass

#-----------------------------------------------------------------------------
# PIL -- by Jeremy Bethmont
#-----------------------------------------------------------------------------
try:
    from PIL import Image
    from cv import cvCvtColor, CV_RGB2BGR

    def pil_to_ipl(im_pil):
        im_ipl = cvCreateImageHeader(cvSize(im_pil.size[0], im_pil.size[1]),
IPL_DEPTH_8U, 3)
        data = im_pil.tostring('raw', 'RGB', im_pil.size[0] * 3)
        cvSetData(im_ipl, cast(data, POINTER(c_byte)), im_pil.size[0] * 3)
        cvCvtColor(im_ipl, im_ipl, CV_RGB2BGR)
        im_ipl._depends = (data,)
        return im_ipl

    def ipl_to_pil(im_ipl):
        size = (im_ipl.width, im_ipl.height)
        data = im_ipl.data_as_string()
        im_pil = Image.fromstring(
                    "RGB", size, data,
                    'raw', "BGR", im_ipl.widthStep
        )
        return im_pil

    __all__ += ['ipl_to_pil', 'pil_to_ipl']
except ImportError:
    pass

#-----------------------------------------------------------------------------
# numpy's ndarray -- by Minh-Tri Pham
#-----------------------------------------------------------------------------
try:
    import numpy as NP

    # create a read/write buffer from memory
    from_memory = pythonapi.PyBuffer_FromReadWriteMemory
    from_memory.restype = py_object
    
    def as_numpy_2darray(ctypes_ptr, width_step, width, height, dtypename, nchannels=1):
        esize = NP.dtype(dtypename).itemsize
        if width_step == 0:
            width_step = width*esize
        buf = from_memory(ctypes_ptr, width_step*height)
        arr = NP.frombuffer(buf, dtype=dtypename, count=width*nchannels*height)
        if nchannels > 1:
            arr = arr.reshape(height, width, nchannels)
            arr.strides = (width_step, esize*nchannels, esize)
        else:
            arr = arr.reshape(height, width)
            arr.strides = (width_step, esize)
        return arr
        
    ipldepth2dtype = {
        IPL_DEPTH_1U: 'bool',
        IPL_DEPTH_8U: 'uint8',
        IPL_DEPTH_8S: 'int8',
        IPL_DEPTH_16U: 'uint16',
        IPL_DEPTH_16S: 'int16',
        IPL_DEPTH_32S: 'int32',
        IPL_DEPTH_32F: 'float32',
        IPL_DEPTH_64F: 'float64',
    }

    def _iplimage_as_numpy_array(self):
        """Converts an IplImage into ndarray"""
        return as_numpy_2darray(self.imageData, self.widthStep, self.width, self.height, ipldepth2dtype[self.depth], self.nChannels)
            
    IplImage.as_numpy_array = _iplimage_as_numpy_array


    def cvCreateImageFromNumpyArray(a):
        """Creates an IplImage from a numpy array. Raises TypeError if not successful.

        Inline function: cvGetImage(cvCreateMatFromNumpyArray(a))
        """
        return cvGetImage(cvCreateMatFromNumpyArray(a))



    matdepth2dtype = {
        CV_8U: 'uint8',
        CV_8S: 'int8',
        CV_16U: 'uint16',
        CV_16S: 'int16',
        CV_32S: 'int32',
        CV_32F: 'float32',
        CV_64F: 'float64',
    }

    def _cvmat_as_numpy_array(self):
        """Converts a CvMat into ndarray"""
        return as_numpy_2darray(self.data.ptr, self.step, self.cols, self.rows, matdepth2dtype[CV_MAT_DEPTH(self.type)], CV_MAT_CN(self.type))
        
    CvMat.as_numpy_array = _cvmat_as_numpy_array


    def cvCreateMatFromNumpyArray(a):
        """Creates a CvMat from a numpy array. Raises TypeError if not successful.

        The numpy array must be of rank 1 or 2.
        If it is of rank 1, it is converted into a row vector.
        If it is of rank 2, it is converted into a matrix.
        """
        if not isinstance(a, NP.ndarray):
            raise TypeError("'a' is not a numpy ndarray.")

        for i in matdepth2dtype:
            if NP.dtype(matdepth2dtype[i]) == a.dtype:
                mattype = i
                break
        else:
            raise TypeError("The dtype of 'a' is not supported.")

        rank = len(a.shape)
        if rank == 1:
            b = cvMat(a.shape[0], 1, mattype, a.ctypes.data, a.strides[0])
        elif rank == 2:
            b = cvMat(a.shape[0], a.shape[1], mattype, a.ctypes.data, a.strides[0])
        else:
            raise TypeError("The rank of 'a' must be either 1 or 2.")

        b.depends = (a,)

        return b



    def _cvmatnd_as_numpy_array(self):
        """Converts a CvMatND into ndarray"""
        nc = CV_MAT_CN(self.type)
        dtypename = matdepth2dtype[CV_MAT_DEPTH(self.type)]
        esize = NP.dtype(dtypename).itemsize
        
        sd = self.dim[:self.dims]
        strides = [x.step for x in sd]
        size = [x.size for x in sd]
        
        if nc > 1:
            strides += [esize]
            size += [nc]
            
        buf = from_memory(self.data.ptr, strides[0]*size[0])
        arr = NP.frombuffer(buf, dtype=dtypename, count=NP.prod(size)).reshape(size)
        arr.strides = tuple(strides)
            
        return arr
        
    CvMatND.as_numpy_array = _cvmatnd_as_numpy_array

	
    def cvCreateMatNDFromNumpyArray(a):
        """Creates a CvMatND from a numpy array. Raises TypeError if not successful."""
        if not isinstance(a, NP.ndarray):
            raise TypeError("'a' is not a numpy ndarray.")

        for i in matdepth2dtype:
            if NP.dtype(matdepth2dtype[i]) == a.dtype:
                mattype = i
                break
        else:
            raise TypeError("The dtype of 'a' is not supported.")

        b = cvMatND(a.shape, mattype, a.ctypes.data)
        for i in range(len(a.strides)):
            b.dim[i].stype = a.strides[i]
        b.depends = (a,)

        return b

    __all__ += ['cvCreateImageFromNumpyArray', 'cvCreateMatFromNumpyArray', 
        'cvCreateMatNDFromNumpyArray']
except ImportError:
    pass

