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

import os, sys
import ctypes
import ctypes.util
from ctypes import *
from math import floor, ceil, pi

# Use xrange if available (pre-3.0)
try:
    range = xrange
except NameError:
    pass


#=============================================================================
# Begin of basic stuff
#=============================================================================


# Added by Minh-Tri Pham
c_int_p = POINTER(c_int)
c_int8_p = POINTER(c_int8)
c_ubyte_p = POINTER(c_ubyte)
c_float_p = POINTER(c_float)
c_double_p = POINTER(c_double)
c_void_p_p = POINTER(c_void_p)
c_short_p = POINTER(c_short)

# ----Load the DLLs ----------------------------------------------------------
# modified a little bit by Minh-Tri Pham
# fixed and improved by Jeremy Bethmont and David Bolen
# Jeremy's note: default OpenCV libraries are located in /opt/local/lib when 
# they are installed with macports. They cannot be loaded with LoadLibrary alone.
def detect_opencv():
    def find_lib(name):
        z = ctypes.util.find_library(name)
        if z is None:
            raise ImportError("OpenCV's shared library '%s' is not found. Make sure you have its path included in your PATH variable." % name)
        return z
        
    if os.name == 'posix':
        cxDLL = cdll.LoadLibrary(find_lib('cxcore'))
        cvDLL = cdll.LoadLibrary(find_lib('cv'))
        hgDLL = cdll.LoadLibrary(find_lib('highgui'))
        auDLL = cdll.LoadLibrary(find_lib('cvaux'))

    elif os.name == 'nt':
        try:
            cxDLL = cdll.cxcore110
            cvDLL = cdll.cv110
            hgDLL = cdll.highgui110
            auDLL = cdll.cvaux110
        except:
            try:
                cxDLL = cdll.cxcore100
                cvDLL = cdll.cv100
                hgDLL = cdll.highgui100
                auDLL = cdll.cvaux100
            except:
                raise ImportError("Cannot import OpenCV's .DLL files. Make sure you have their paths included in your PATH variable.")

    else:
        raise NotImplementedError("Your OS is not supported. Or you can rewrite this detect_opencv() function to support it.")
    
    return cxDLL, cvDLL, hgDLL, auDLL

_cxDLL, _cvDLL, _hgDLL, _auDLL = detect_opencv()    

def detect_version():
    try:
        _cvDLL.cvExtractSURF
        return 110
    except AttributeError:
        return 100

cvVersion = detect_version()        
#------

# make function prototypes a bit easier to declare
def cfunc(name, dll, result, *args):
    '''build and apply a ctypes prototype complete with parameter flags
    e.g.
cvMinMaxLoc = cfunc('cvMinMaxLoc', _cxDLL, None,
                    ('image', IplImage_p, 1),
                    ('min_val', c_double_p, 2),
                    ('max_val', c_double_p, 2),
                    ('min_loc', CvPoint_p, 2),
                    ('max_loc', CvPoint_p, 2),
                    ('mask', IplImage_p, 1, None))
means locate cvMinMaxLoc in dll _cxDLL, it returns nothing.
The first argument is an input image. The next 4 arguments are output, and the last argument is
input with an optional value. A typical call might look like:

min_val,max_val,min_loc,max_loc = cvMinMaxLoc(img)
    '''
    atypes = []
    aflags = []
    for arg in args:
        atypes.append(arg[1])
        aflags.append((arg[2], arg[0]) + arg[3:])
    return CFUNCTYPE(result, *atypes)((name, dll), tuple(aflags))
    
def default_errcheck(result, func, args):
    if not result:
        raise WinError('Calling function '+str(func)+' was not successful.')
    return args

    
# Enhanced ctypes.Structure class
class _Structure(Structure):
    _fields_ = []
    
    def __repr__(self):
        '''Print the fields'''
        res = []
        for field in self._fields_:
            res.append('%s=%s' % (field[0], repr(getattr(self, field[0]))))
        return self.__class__.__name__ + '(' + ','.join(res) + ')'

    @classmethod
    def from_param(cls, obj):
        '''Magically construct from a tuple'''
        if isinstance(obj, cls):
            return obj
        if isinstance(obj, tuple):
            return cls(*obj)
        raise TypeError

    # Permit structures with equivalent values to compare equally to each
    # other or to types (basically tuples at this point) supported by the
    # above from_param method to construct equivalent structures.  Since
    # ctypes data types with the same value don't compare as equal (e.g.,
    # c_int(10) != c_int(10)) compare against the underlying value if
    # present, or the address pointed to by a pointer type.  Otherwise,
    # just leave it up to the field object.

    def _values(self, obj):
        values = []
        for f in obj._fields_:
            v = getattr(obj, f[0])
            # If we look like a pointer type, just worry about the address
            # to which we are pointing, otherwise try to obtain the ctypes
            # data type value.  Note that ctypes can raise ValueError if we
            # accidentally try to access faulty pointers, so just safety
            # block the whole process.
            try:
                if isinstance(v, ctypes._Pointer):
                    # We'd like two NULL pointers to be equal, but ctypes will
                    # fail obtaining the address, so use None for such pointers
                    v = addressof(v.contents) if v else None
                elif isinstance(v, ctypes._SimpleCData):
                    v = v.value
            except Exception:
                pass
            values.append(v)
        return values

    def __eq__(self, other):
        try:
            other = self.__class__.from_param(other)
        except:
            return False

        return self._values(self) == self._values(other)

    def __ne__(self, other):
        return not self.__eq__(other)

        
class ListPOINTER(object):
    '''Just like a POINTER but accept a list of ctype as an argument'''
    def __init__(self, etype):
        self.etype = etype

    def from_param(self, param):
        if isinstance(param, (list,tuple)):
            return (self.etype * len(param))(*param)
        else:
            return param

class ListByRef(object):
    '''An argument that converts a list/tuple of ctype elements into a pointer to an array of pointers to the elements'''
    def __init__(self, etype):
        self.etype = etype
        self.etype_p = POINTER(etype)

    def from_param(self, param):
        if isinstance(param, (list,tuple)):
            val = (self.etype_p * len(param))()
            for i,v in enumerate(param):
                if isinstance(v, self.etype):
                    val[i] = self.etype_p(v)
                else:
                    val[i] = v
            return val
        else:
            return param

class ListPOINTER2(object):
    '''Just like POINTER(POINTER(ctype)) but accept a list of lists of ctype'''
    def __init__(self, etype):
        self.etype = etype
        self.etype_p = POINTER(etype)

    def from_param(self, param):
        if isinstance(param, (list,tuple)):
            val = (self.etype_p * len(param))()
            for i,v in enumerate(param):
                if isinstance(v, (list,tuple)):
                    val[i] = (self.etype * len(v))(*v)
                else:
                    val[i] = v
            return val
        else:
            return param

class ByRefArg(object):
    '''Just like a POINTER but accept an argument and pass it byref'''
    def __init__(self, atype):
        self.atype = atype

    def from_param(self, param):
        return byref(param) if isinstance(param, self.atype) else param

def pointee(ptr, *depends_args):
    """Returns None if ptr is NULL else ptr's object with dependency tuple associated"""
    if bool(ptr):
        z = ptr[0]
        z._depends = depends_args
        return z
    return None
    
def _ptr_add(ptr, offset):
    pc = ptr[0]
    return pointer(type(pc).from_address(addressof(pc) + offset))
    
    
def as_c_array(data, n=None, elem_ctype=None):
    """Converts data into a c_array.
    
    :Parameters:
        data : a list/tuple/c_array of elements
        elem_ctype : ctype of an element; if elem_ctype is None, then elem_ctype=type(data[0])
        n : number of elements; if n==None, then n=len(data)
    :Returns:
        a (elem_ctype*n) c_array;
            if data is a c_array:
                if n==len(data), data is returned
                otherwise, a c_array sharing the same memory allocation is returned
            otherwise, a new c_array is created
    """
    if n is None:
        n = len(data)
    if elem_ctype is None:
        elem_ctype = type(data[0])
    if isinstance(data, (list, tuple)):
        return (elem_ctype*n)(*data)
    if n == len(data):
        return data
    z = (elem_ctype*n).from_address(addressof(data))
    z._depends = (data,)
    return z


#=============================================================================
# End of basic stuff
#=============================================================================




#=============================================================================
# Begin of cxcore/cvver.h
#=============================================================================

if cvVersion == 110:
    CV_MAJOR_VERSION    = 1
    CV_MINOR_VERSION    = 1
    CV_SUBMINOR_VERSION = 0
    CV_VERSION          = "1.1.0"
elif cvVersion == 100:
    CV_MAJOR_VERSION    = 1
    CV_MINOR_VERSION    = 0
    CV_SUBMINOR_VERSION = 0
    CV_VERSION          = "1.0.0"
else:
    raise NotImplementedError("This version of OpenCV is not supported.")

#=============================================================================
# End of cxcore/cvver.h
#=============================================================================




#=============================================================================
# Begin of cxcore/cxtypes.h
#=============================================================================

class CvArr(_Structure):
    _fields_ = []
    
CvArr_p = POINTER(CvArr)
CvArr_r = ByRefArg(CvArr)

class Cv32suf(Union):
    _fields_ = [
        ('i', c_int32),
        ('u', c_uint32),
        ('f', c_float),
    ]
Cv32suf_p = POINTER(Cv32suf)

class Cv64suf(Union):
    _fields_ = [
        ('i', c_int64),
        ('u', c_uint64),
        ('f', c_double),
    ]
Cv64suf_p = POINTER(Cv64suf)


#-----------------------------------------------------------------------------
# Common macros and inline functions
#-----------------------------------------------------------------------------

CV_PI = pi
CV_LOG2 = 0.69314718055994530941723212145818

# Round to nearest integer
def cvRound(val):
    return int(round(val))

# Round to nearest integer
def cvFloor(val):
    return int(floor(val))

# Round to nearest integer
def cvCeil(val): # here, this function is not correct
    return int(ceil(val))

#-----------------------------------------------------------------------------
# Random number generation
#-----------------------------------------------------------------------------

# Minh-Tri's note: I'd rather use a random generator other than CvRNG.
# It's slow and doesn't guarrantee a large cycle.

CvRNG = c_uint64
CvRNG_p = POINTER(CvRNG)
CvRNG_r = ByRefArg(CvRNG)

def cvRNG(seed=-1):
    """CvRNG cvRNG( int64 seed = CV_DEFAULT(-1))
    
    Initializes random number generator and returns the state. 
    """
    if seed != 0:
        return CvRNG(seed)
    return CvRNG(-1)

def cvRandInt(rng):
    """unsigned cvRandInt( CvRNG rng )
    
    Returns random 32-bit unsigned integer. 
    """
    temp = rng.value
    temp = c_uint32(temp*1554115554).value + (temp >> 32)
    rng.value = temp
    return c_uint32(temp).value
    
def cvRandReal(rng):
    """double cvRandReal( CvRNG rng )
    
    Returns random floating-point number between 0 and 1.
    """
    return c_double(cvRandInt(rng).value*3283064365386962890625e-10) # 2^-32

    
#-----------------------------------------------------------------------------
# Image type (IplImage)
#-----------------------------------------------------------------------------

# Image type (IplImage)
IPL_DEPTH_SIGN = 0x80000000

IPL_DEPTH_1U =  1
IPL_DEPTH_8U =  8
IPL_DEPTH_16U = 16
IPL_DEPTH_32F = 32
IPL_DEPTH_64F = 64

IPL_DEPTH_8S = IPL_DEPTH_SIGN + IPL_DEPTH_8U
IPL_DEPTH_16S = IPL_DEPTH_SIGN + IPL_DEPTH_16U
IPL_DEPTH_32S = IPL_DEPTH_SIGN + 32

_iplimage_depth2ctype = {
    IPL_DEPTH_8U: c_uint8,
    IPL_DEPTH_8S: c_int8,
    IPL_DEPTH_16U: c_uint16,
    IPL_DEPTH_16S: c_int16,
    IPL_DEPTH_32S: c_int32,
    IPL_DEPTH_32F: c_float,
    IPL_DEPTH_64F: c_double,
}

IPL_DATA_ORDER_PIXEL = 0
IPL_DATA_ORDER_PLANE = 1

IPL_ORIGIN_TL = 0
IPL_ORIGIN_BL = 1

IPL_ALIGN_4BYTES = 4
IPL_ALIGN_8BYTES = 8
IPL_ALIGN_16BYTES = 16
IPL_ALIGN_32BYTES = 32

IPL_ALIGN_DWORD = IPL_ALIGN_4BYTES
IPL_ALIGN_QWORD = IPL_ALIGN_8BYTES

IPL_BORDER_CONSTANT = 0
IPL_BORDER_REPLICATE = 1
IPL_BORDER_REFLECT = 2
IPL_BORDER_WRAP = 3

class IplTileInfo(_Structure):
    _fields_ = []    
IplTileInfo_p = POINTER(IplTileInfo)

class IplROI(_Structure):
    _fields_ = [
        ('coi', c_int), # 0 - no COI (all channels are selected), 1 - 0th channel is selected ...
        ('xOffset', c_int),
        ('yOffset', c_int),
        ('width', c_int),
        ('height', c_int),
    ]    
IplROI_p = POINTER(IplROI)

IPL_IMAGE_HEADER = 1
IPL_IMAGE_DATA = 2
IPL_IMAGE_ROI = 4

IPL_BORDER_REFLECT_101    = 4

# IPL image header
# allows to access pixels directly using image indexing with 2 parameters (row then column)
# If you want image slicing, convert the image into a CvMat.
# e.g.: let img be an instance of IplImage
# img[3,4] means the pixel located at row 3, column 4 (zero-based) in the image
#    a pixel can be a ctype array or a number variable, depending on its type specified by img.depth
# img[3:4] is *invalid*
# img[3] is *invalid*
class IplImage(CvArr):
    def data_as_string(self):
        return string_at(self.imageData, self.imageSize)        
    data_as_buffer = data_as_string

    def get_pixel(self, key):
        if not isinstance(key, tuple) or len(key) != 2 or not isinstance(key[0], int) or not isinstance(key[1], int):
            raise KeyError("Key (%s) is not a tuple of 2 integers." % str(key))
        
        h = self.height
        y = key[0]
        if not 0 <= y < h:
            raise IndexError("Row %d is not in [0,%d)" % (y, h))

        w = self.width
        x = key[1]
        if not 0 <= x < w:
            raise IndexError("Column %d is not in [0,%d)" % (x, w))

        d = self.depth
        if d < 0:
            d += 0x100000000
        datatype = _iplimage_depth2ctype[d]*self.nChannels
        return datatype.from_address(addressof(self.imageData.contents)+self.widthStep*y+x*sizeof(datatype))

    def __getitem__(self, key):
        pixel = self.get_pixel(key)
        return pixel if len(pixel) > 1 else pixel[0]
        
    def __setitem__(self, key, value):
        pixel = self.get_pixel(key)

        if isinstance(value, CvScalar):
            for i in range(len(pixel)):
                pixel[i] = value.val[i]
        elif getattr(value, '__getitem__', None) is not None:
            for i in range(len(pixel)):
                pixel[i] = value[i]
        else:
            pixel[0] = value
            
    _owner = 0 # default: owns nothing
        
    def __del__(self):
        if self._owner == 1: # own header only
            _cvReleaseImageHeader(IplImage_p(self))
        elif self._owner == 2: # own data but not header
            _cvReleaseData(self)
        elif self._owner == 3: # own header and data
            _cvReleaseImage(IplImage_p(self))

    def __repr__(self):
        '''Print the fields'''
        res = []
        for field in self._fields_:
            if field[0] in ['imageData', 'imageDataOrigin']: continue
            res.append('%s=%s' % (field[0], repr(getattr(self, field[0]))))
        return self.__class__.__name__ + '(' + ','.join(res) + ')'
        
IplImage_p = POINTER(IplImage)
IplImage_r = ByRefArg(IplImage)

IplImage._fields_ = [("nSize", c_int),
        ("ID", c_int),
        ("nChannels", c_int),
        ("alphaChannel", c_int),
        ("depth", c_int),
        ("colorModel", c_char * 4),
        ("channelSeq", c_char * 4),
        ("dataOrder", c_int),
        ("origin", c_int),
        ("align", c_int),
        ("width", c_int),
        ("height", c_int),
        ("roi", IplROI_p),
        ("maskROI", IplImage_p),
        ("imageID", c_void_p),
        ("tileInfo", IplTileInfo_p),
        ("imageSize", c_int),
        ("imageData", c_int8_p),
        ("widthStep", c_int),
        ("BorderMode", c_int * 4),
        ("BorderConst", c_int * 4),
        ("imageDataOrigin", c_int8_p)]
        
CV_TYPE_NAME_IMAGE = "opencv-image"


#-----------------------------------------------------------------------------
# CvSlice
#-----------------------------------------------------------------------------

class CvSlice(_Structure):
    _fields_ = [('start_index', c_int),
                ('end_index', c_int)]
CvSlice_p = POINTER(CvSlice)                
                
def cvSlice(start, end):
    """CvSlice cvSlice(int start, int end)
    
    Constructs a CvSlice
    """
    return CvSlice(c_int(start), c_int(end))
    
#Viji Periapoilan 5/23/2007(start)
CV_WHOLE_SEQ_END_INDEX = 0x3fffffff
CV_WHOLE_SEQ = CvSlice(0, CV_WHOLE_SEQ_END_INDEX)
#Viji Periapoilan 5/23/2007(end)

#-----------------------------------------------------------------------------
# Matrix type (CvMat) 
#-----------------------------------------------------------------------------

# Matrix type (CvMat)
CV_CN_MAX = 4
CV_CN_SHIFT = 3
CV_DEPTH_MAX = (1 << CV_CN_SHIFT)

CV_8U = 0
CV_8S = 1
CV_16U = 2
CV_16S = 3
CV_32S = 4
CV_32F = 5
CV_64F = 6
CV_USRTYPE1 = 7

def CV_MAKETYPE(depth,cn):
    return ((depth) + (((cn)-1) << CV_CN_SHIFT))
CV_MAKE_TYPE = CV_MAKETYPE

CV_8UC1 = CV_MAKETYPE(CV_8U,1)
CV_8UC2 = CV_MAKETYPE(CV_8U,2)
CV_8UC3 = CV_MAKETYPE(CV_8U,3)
CV_8UC4 = CV_MAKETYPE(CV_8U,4)

CV_8SC1 = CV_MAKETYPE(CV_8S,1)
CV_8SC2 = CV_MAKETYPE(CV_8S,2)
CV_8SC3 = CV_MAKETYPE(CV_8S,3)
CV_8SC4 = CV_MAKETYPE(CV_8S,4)

CV_16UC1 = CV_MAKETYPE(CV_16U,1)
CV_16UC2 = CV_MAKETYPE(CV_16U,2)
CV_16UC3 = CV_MAKETYPE(CV_16U,3)
CV_16UC4 = CV_MAKETYPE(CV_16U,4)

CV_16SC1 = CV_MAKETYPE(CV_16S,1)
CV_16SC2 = CV_MAKETYPE(CV_16S,2)
CV_16SC3 = CV_MAKETYPE(CV_16S,3)
CV_16SC4 = CV_MAKETYPE(CV_16S,4)

CV_32SC1 = CV_MAKETYPE(CV_32S,1)
CV_32SC2 = CV_MAKETYPE(CV_32S,2)
CV_32SC3 = CV_MAKETYPE(CV_32S,3)
CV_32SC4 = CV_MAKETYPE(CV_32S,4)

CV_32FC1 = CV_MAKETYPE(CV_32F,1)
CV_32FC2 = CV_MAKETYPE(CV_32F,2)
CV_32FC3 = CV_MAKETYPE(CV_32F,3)
CV_32FC4 = CV_MAKETYPE(CV_32F,4)

CV_64FC1 = CV_MAKETYPE(CV_64F,1)
CV_64FC2 = CV_MAKETYPE(CV_64F,2)
CV_64FC3 = CV_MAKETYPE(CV_64F,3)
CV_64FC4 = CV_MAKETYPE(CV_64F,4)

CV_AUTO_STEP = 0x7fffffff
CV_WHOLE_ARR  = cvSlice( 0, 0x3fffffff )

CV_MAT_CN_MASK = ((CV_CN_MAX - 1) << CV_CN_SHIFT)
def CV_MAT_CN(flags):
    return ((((flags) & CV_MAT_CN_MASK) >> CV_CN_SHIFT) + 1)
CV_MAT_DEPTH_MASK = (CV_DEPTH_MAX - 1)
def CV_MAT_DEPTH(flags):
    return ((flags) & CV_MAT_DEPTH_MASK)
CV_MAT_TYPE_MASK = (CV_DEPTH_MAX*CV_CN_MAX - 1)
def CV_MAT_TYPE(flags):
    ((flags) & CV_MAT_TYPE_MASK)
CV_MAT_CONT_FLAG_SHIFT = 9
CV_MAT_CONT_FLAG = (1 << CV_MAT_CONT_FLAG_SHIFT)
def CV_IS_MAT_CONT(flags):
    return ((flags) & CV_MAT_CONT_FLAG)
CV_IS_CONT_MAT = CV_IS_MAT_CONT
CV_MAT_TEMP_FLAG_SHIFT = 10
CV_MAT_TEMP_FLAG = (1 << CV_MAT_TEMP_FLAG_SHIFT)
def CV_IS_TEMP_MAT(flags):
    return ((flags) & CV_MAT_TEMP_FLAG)

CV_MAGIC_MASK = 0xFFFF0000
CV_MAT_MAGIC_VAL = 0x42420000
CV_TYPE_NAME_MAT = "opencv-matrix"

def type2ctype(depth):   
    _type2ctype = {
        CV_8U: c_uint8,
        CV_8S: c_int8,
        CV_16U: c_uint16,
        CV_16S: c_int16,
        CV_32S: c_int32,
        CV_32F: c_float,
        CV_64F: c_double,
    }
    
    cn = ((depth >> CV_CN_SHIFT)&7)+1
    return _type2ctype[depth&7]*cn

def check_slice(sl, length):
    if isinstance(sl, slice):
        start = 0 if sl.start is None else sl.start
        if not 0 <= start < length:
            raise IndexError("Item %d is not in range [0,%d)" % (start, length))

        step = 1 if sl.step is None else sl.step
            
        stop = length if step >= 0 else -1
        if sl.stop is not None:
            if step >= 0:
                if stop > sl.stop:
                    stop = sl.stop
                if stop < start:
                    stop = start
            else:
                if stop < sl.stop:
                    stop = sl.stop
                if stop > start:
                    stop = start
    else:
        sl = int(sl)
        if not 0 <= sl < length:
            raise IndexError("Item %d is not in [0,%d)" % (sl, length))
        start = sl
        stop = sl+1
        step = 1
        
    return slice(start, stop, step)

class CvMatData(Union):
    _fields_ = [
        ('ptr', c_ubyte_p),
        ('s', c_short_p),
        ('i', c_int_p),
        ('fl', c_float_p),
        ('db', c_double_p),
        ('address', c_int), # added by Minh-Tri Pham
    ]
CvMatData_p = POINTER(CvMatData)
    
class CvMatRows(Union):
    _fields_ = [
        ('rows', c_int),
        ('height', c_int),
    ]    
CvMatRows_p = POINTER(CvMatRows)
    
class CvMatCols(Union):
    _fields_ = [
        ('cols', c_int),
        ('width', c_int),
    ]    
CvMatCols_p = POINTER(CvMatCols)
    
# Multi-channel matrix
#  - Allows to access pixels directly using image indexing with 2 parameters, row then column
# and also image slicing, for CvMat
#  - Iteration of rows. For example:
#      for x in mat:
#        <do something with row x>
#    would iterate on the rows of mat (x = cvGetRows(mat, i, i+1)).
#  - Iteration of columns. For example:
#      for y in mat.colrange():
#        <do something with column y>
#    would iterate on the columns of mat (y = cvGetCols(mat, i, i+1)).
class CvMat(CvArr):
    def data_as_string(self):
        return string_at(self.data.ptr, self.step * self.rows)        
    data_as_buffer = data_as_string

    def get_pixel_or_slice2d(self, key):
        if not isinstance(key, tuple):
            key = (key, slice(None))
            
        if len(key) < 2:
            key = (key[0], slice(None))
        
        if len(key) > 2:
            raise TypeError("Key cannot be a tuple with more than 2 items.")
    
        if isinstance(key[0], int) and isinstance(key[1], int): # a pixel
            h = self.rows
            y = key[0]
            if not 0 <= y < h:
                raise IndexError("Row %d is not in [0,%d)" % (y, h))

            w = self.cols
            x = key[1]
            if not 0 <= x < w:
                raise IndexError("Column %d is not in [0,%d)" % (x, w))
                    
            datatype = type2ctype(self.type)
            return datatype.from_address(addressof(self.data.ptr.contents)+self.step*y+x*sizeof(datatype))
            
        # a 2d-slice
        w = self.cols
        sx = check_slice(key[1], w)
        if sx.step != 1:
            raise IndexError("Column slice must be positively continuous, i.e. step_x == 1.")
            
        h = self.rows
        sy = check_slice(key[0], h)        
        if sy.step == 0:
            raise IndexError("Row slice cannot have zero step, i.e. step_y != 0.")
            
        cols = sx.stop-sx.start
        if sy.step > 0:
            rows = (sy.stop-sy.start) / sy.step
        else:
            rows = (sy.start-sy.stop) / (-sy.step)
        step = sy.step*self.step
        
        datatype = type2ctype(self.type)
        data_address = addressof(self.data.ptr.contents)+self.step*sy.start+sx.start*sizeof(datatype)
        
        z = cvMat(rows, cols, self.type, c_void_p(data_address), step)
        z._depends = (self,) # make sure z is deleted before self is deleted, don't care about self.data!!
        return z

    def __getitem__(self, key):
        z = self.get_pixel_or_slice2d(key)
        return z if isinstance(z, CvMat) or len(z) > 1 else z[0]
                    
    def __setitem__(self, key, value):
        z = self.get_pixel_or_slice2d(key)
        if isinstance(z, CvMat):
            if isinstance(value, CvMat):
                cvCopy(value, z)
            elif isinstance(value, tuple) or isinstance(value, list):
                for y in range(z.rows):
                    vy = value[y]
                    for x in range(z.cols):
                        z[y,x] = vy[x]
            else:
                if not isinstance(value, CvScalar):
                    value = cvScalar(value)
                cvSet(z, value)
        else:
            y = getattr(value, '__getitem__', None)
            if y:
                for i in range(len(z)):
                    z[i] = value[i]
            else:
                z[0] = value
            
    def __getslice__(self, i, j):
        return self.__getitem__(slice(i,j))
        
    def __setslice__(self, i, j, value):
        self.__setitem__(slice(i,j), value)
        
    def __iter__(self):
        for i in range(self.rows):
            yield cvGetRows(self, i, i+1)
        
    def colrange(self):
        for i in range(self.cols):
            yield cvGetCols(self, i, i+1)
            
    _owner = False
            
    def __del__(self):
        if self._owner is True:
            _cvReleaseMat(CvMat_p(self))

    _fields_ = [("type", c_int),
                ("step", c_int),
                ("refcount", c_void_p),
                ("hdr_refcount", c_int),
                ("data", CvMatData),
                ("r", CvMatRows),
                ("c", CvMatCols)]
    _anonymous_ = ("r", "c",)

CvMat_p = POINTER(CvMat)
CvMat_r = ByRefArg(CvMat)
    

#-----------------------------------------------------------------------------
# Multi-dimensional dense array (CvMatND)
#-----------------------------------------------------------------------------

CV_MATND_MAGIC_VAL    = 0x42430000
CV_TYPE_NAME_MATND    = "opencv-nd-matrix"

CV_MAX_DIM = 32
CV_MAX_DIM_HEAP = (1 << 16)

# Multi-dimensional dense multi-channel matrix
class CvMatNDdim(_Structure):
    _fields_ = [("size", c_int),
                ("step", c_int)]                
CvMatNDdim_p = POINTER(CvMatNDdim)
CvMatNDdim_r = ByRefArg(CvMatNDdim)
                
class CvMatND(CvArr):
    _fields_ = [("type", c_int),
                ("dims", c_int),
                ("refcount", c_void_p),
                ("hdrefcount", c_int),
                ("data", CvMatData),
                ("dim", CvMatNDdim*CV_MAX_DIM)]
    
    _owner = False
    
    def __del__(self):
        if self._owner is True:
            _cvReleaseMat(CvMatND_p(self))
                
CvMatND_p = POINTER(CvMatND)
CvMatND_r = ByRefArg(CvMatND)


#-----------------------------------------------------------------------------
# Memory storage
#-----------------------------------------------------------------------------

class CvMemBlock(_Structure): # forward declaration
    pass
CvMemBlock_p = POINTER(CvMemBlock)
CvMemBlock._fields_ = [
    ('prev', CvMemBlock_p),
    ('next', CvMemBlock_p),
]

CV_STORAGE_MAGIC_VAL = 0x42890000

# Memory storage
class CvMemStorage(_Structure): # forward declaration
    
    def __del__(self):
        _cvReleaseMemStorage(CvMemStorage_p(self))
    
CvMemStorage_p = POINTER(CvMemStorage)
CvMemStorage_r = ByRefArg(CvMemStorage)
CvMemStorage._fields_ = [
    ("signature", c_int),
    ("bottom", CvMemBlock_p), # first allocated block
    ("top", CvMemBlock_p), # current memory block - top of the stack
    ("parent", CvMemStorage_p), # borrows new blocks from
    ("block_size", c_int), # block size
    ("free_space", c_int)] # free space in the current block
    
class CvMemStoragePos(_Structure):
    _fields_ = [('top', CvMemBlock_p),
                ('free_space', c_int)]                
CvMemStoragePos_p = POINTER(CvMemStoragePos)
CvMemStoragePos_r = ByRefArg(CvMemStoragePos)
    
#-----------------------------------------------------------------------------
# Sequence
#-----------------------------------------------------------------------------

class _CvSeqStructure(CvArr):
    def asarrayptr(self, elem_type):
        """Converts this CvSeq into an array of element pointers. The pointers are of type 'elem_type'."""
        reader = cvStartReadSeq(self)
        z = [None]*self.total
        for i in range(self.total):
            try:
                z[i] = elem_type(reader.ptr)
            except TypeError:
                z[i] = cast(reader.ptr, elem_type)
            cvSetSeqReaderPos(reader, 1, 1)
        return z
        
    def asarray(self, elem_type):
        """Converts this CvSeq into an array of elements of type 'elem_type'."""
        reader = cvStartReadSeq(self)
        z = [None]*self.total
        for i in range(self.total):
            z[i] = elem_type.from_address(reader.ptr)
            cvSetSeqReaderPos(reader, 1, 1)
        return z
        
    def append(self, element):
        """Adds element to sequence end
        
        :Parameters:
            element : an element, whose content is to be copied
                the element should be an instance of a subclass of _Structure
        """        
        cvSeqPush(self, c_void_p(addressof(element)))
        
    def vrange(self):
        """
        generator function iterating along v_next
        """
        s = self
        yield s
        t = type(self)
        while s.v_next:
            s = cast(s.v_next, POINTER(t))[0]
            yield s
            
    def hrange(self):
        """
        generator function iterating along h_next
        """
        s = self
        yield s
        t = type(self)
        while s.h_next:
            s = cast(s.h_next, POINTER(t))[0]
            yield s
            

class CvSeqBlock(_Structure): # forward declaration
    pass
CvSeqBlock_p = POINTER(CvSeqBlock)
CvSeqBlock_r = ByRefArg(CvSeqBlock)
CvSeqBlock._fields_ = [
    ('prev', CvSeqBlock_p), # previous sequence block
    ('next', CvSeqBlock_p), # next sequence block
    ('start_index', c_int), # index of the first element in the block + sequence->first->start_index
    ('count', c_int), # number of elements in the block
    ('data', c_char_p), # POINTER to the first element of the block
]

def CV_TREE_NODE_FIELDS(node_type):
    return [
        ('flags', c_int), # micsellaneous flags
        ('header_size', c_int), # size of sequence header
        ('h_prev', POINTER(node_type)), # previous sequence
        ('h_next', POINTER(node_type)), # next sequence
        ('v_prev', POINTER(node_type)), # 2nd previous sequence
        ('v_next', POINTER(node_type)), # 2nd next sequence
    ]

class CvSeq(_CvSeqStructure): # forward declaration
    pass
CvSeq_p = POINTER(CvSeq)
CvSeq_r = ByRefArg(CvSeq)
    
def CV_SEQUENCE_FIELDS():
    return CV_TREE_NODE_FIELDS(CvSeq) + [
        ('total', c_int), # total number of elements
        ('elem_size', c_int), # size of sequence element in bytes
        ('block_max', c_char_p), # maximal bound of the last block
        ('ptr', c_char_p), # current write POINTER
        ('delta_elems', c_int), # how many elements allocated when the seq grows
        ('storage', CvMemStorage_p), # where the seq is stored
        ('free_blocks', CvSeqBlock_p), # free blocks list
        ('first', CvSeqBlock_p), # POINTER to the first sequence block
    ]

# Sequence
CvSeq._fields_ = CV_SEQUENCE_FIELDS()

CV_TYPE_NAME_SEQ             = "opencv-sequence"
CV_TYPE_NAME_SEQ_TREE        = "opencv-sequence-tree"

#-----------------------------------------------------------------------------
# Set
#-----------------------------------------------------------------------------

class CvSetElem(_Structure):
    pass
CvSetElem_p = POINTER(CvSetElem)
CvSetElem_r = ByRefArg(CvSetElem)
CvSetElem._fields_ = [
    ('flags', c_int),
    ('next_free', CvSetElem_p)]
    
class CvSet(CvSeq):
    _fields_ = [('free_elems', CvSetElem_p),
                ('active_count', c_int)]
CvSet_p = POINTER(CvSet)
CvSet_r = ByRefArg(CvSet)
    
CV_SET_ELEM_IDX_MASK   = ((1 << 26) - 1)
CV_SET_ELEM_FREE_FLAG  = (1 << (sizeof(c_int)*8-1))

# Checks whether the element pointed by ptr belongs to a set or not
def CV_IS_SET_ELEM(ptr):
    return cast(ptr, CvSetElem_p)[0].flags >= 0

#-----------------------------------------------------------------------------
# Multi-dimensional sparse array (CvSparseMat) 
#-----------------------------------------------------------------------------

CV_SPARSE_MAT_MAGIC_VAL    = 0x42440000
CV_TYPE_NAME_SPARSE_MAT    = "opencv-sparse-matrix"

class CvSparseMat(CvArr):
    _fields_ = [('type', c_int),
                ('dims', c_int),
                ('refcount', c_int_p),
                ('hdr_refcount', c_int),
                ('heap', CvSet_p),
                ('hashtable', c_void_p_p),
                ('hashsize', c_int),
                ('valoffset', c_int),
                ('idxoffset', c_int),
                ('size', c_int * CV_MAX_DIM)]
                
    def __del__(self):
        _cvReleaseSparseMat(CvSparseMat_p(self))
        
CvSparseMat_p = POINTER(CvSparseMat)
CvSparseMat_r = ByRefArg(CvSparseMat)
                
class CvSparseNode(_Structure):
    pass
CvSparseNode_p = POINTER(CvSparseNode)
CvSparseNode_r = ByRefArg(CvSparseNode)
CvSparseNode._fields_ = [
        ('hashval', c_uint),
        ('next', CvSparseNode_p),
    ]

class CvSparseMatIterator(_Structure):
    _fields_ = [
        ('mat', CvSparseMat_p),
        ('node', CvSparseNode_p),
        ('curidx', c_int),
    ]
CvSparseMatIterator_p = POINTER(CvSparseMatIterator)
CvSparseMatIterator_r = ByRefArg(CvSparseMatIterator)
    
#-----------------------------------------------------------------------------
# Histogram
#-----------------------------------------------------------------------------

CvHistType = c_int

CV_HIST_MAGIC_VAL     = 0x42450000
CV_HIST_UNIFORM_FLAG  = (1 << 10)

CV_HIST_RANGES_FLAG   = (1 << 11)

CV_HIST_ARRAY         = 0
CV_HIST_SPARSE        = 1
CV_HIST_TREE          = CV_HIST_SPARSE

CV_HIST_UNIFORM       = 1


#-----------------------------------------------------------------------------
# CvRect
#-----------------------------------------------------------------------------

# offset and size of a rectangle
class CvRect(_Structure):
    _fields_ = [("x", c_int),
                ("y", c_int),
                ("width", c_int),
                ("height", c_int)]
    def bloat(self, s):
        return CvRect(self.x-s, self.y-s, self.width+2*s, self.height+2*s)
CvRect_p = POINTER(CvRect)
CvRect_r = ByRefArg(CvRect)
        
def cvRect(x, y, width, height):
    return CvRect(c_int(x), c_int(y), c_int(width), c_int(height))
    
def cvRectToROI(rect, coi):
    """IplROI cvRectToROI(CvRect rect, int coi)
    
    Converts from CvRect to IplROI
    """
    return IplROI(coi, rect.x, rect.y, rect.width, rect.height)
    
def cvROIToRect(roi):
    """CvRect cvROIToRect(IplROI roi)
    
    Converts from IplROI to CvRect
    """
    return CvRect(roi.xOffset, roi.yOffset, roi.width, roi.height)
    
#-----------------------------------------------------------------------------
# CvTermCriteria
#-----------------------------------------------------------------------------

CV_TERMCRIT_ITER    = 1
CV_TERMCRIT_NUMBER  = CV_TERMCRIT_ITER
CV_TERMCRIT_EPS     = 2

# Termination criteria for iterative algorithms
class CvTermCriteria(_Structure):
    _fields_ = [("type", c_int),
                ("max_iter", c_int),
                ("epsilon", c_double)]
CvTermCriteria_p = POINTER(CvTermCriteria)
CvTermCriteria_r = ByRefArg(CvTermCriteria)
                
def cvTermCriteria(type, max_iter, epsilon):
    return CvTermCriteria(c_int(type), c_int(max_iter), c_double(epsilon))
    
#-----------------------------------------------------------------------------
# CvPoint and variants
#-----------------------------------------------------------------------------

# 2D point with integer coordinates
class CvPoint(_Structure):
    _fields_ = [("x", c_int),
                ("y", c_int)]
CvPoint_p = POINTER(CvPoint)
CvPoint_r = ByRefArg(CvPoint)
                
def cvPoint(x, y):
    return CvPoint(c_int(x), c_int(y))

# 2D point with floating-point coordinates
class CvPoint2D32f(_Structure):
    _fields_ = [("x", c_float),
                ("y", c_float)]
CvPoint2D32f_p = POINTER(CvPoint2D32f)
CvPoint2D32f_r = POINTER(CvPoint2D32f)
                
def cvPoint2D32f(x, y):
    return CvPoint2D32f(c_float(x), c_float(y))
    
def cvPointTo32f(point):
    """Converts a CvPoint into a CvPoint2D32f"""
    return CvPoint2D32f(point.x, point.y)

# Minh-Tri's helper function
def cvPointFrom32f(point):
    """Converts a CvPoint32f into a CvPoint"""
    return CvPoint(cvRound(point.x), cvRound(point.y))

# 3D point with floating-point coordinates
class CvPoint3D32f(_Structure):
    _fields_ = [("x", c_float),
                ("y", c_float),
                ("z", c_float)]
CvPoint3D32f_p = POINTER(CvPoint3D32f)
CvPoint3D32f_r = POINTER(CvPoint3D32f)

def cvPoint3D32f(x, y, z):
    return CvPoint3D32f(c_float(x), c_float(y), c_float(z))

# 2D point with double precision floating-point coordinates
class CvPoint2D64f(_Structure):
    _fields_ = [("x", c_double),
                ("y", c_double)]
CvPoint2D64f_p = POINTER(CvPoint2D64f)
CvPoint2D64d = CvPoint2D64f
CvPoint2D64d_p = CvPoint2D64f

def cvPoint2D64f(x, y):
    return CvPoint2D64f(float(x), float(y))
cvPoint2D64d = cvPoint2D64f

# 3D point with double precision floating-point coordinates
class CvPoint3D64f(_Structure):
    _fields_ = [("x", c_double),
                ("y", c_double),
                ("z", c_double)]
CvPoint3D64f_p = POINTER(CvPoint3D64f)
CvPoint3D64d = CvPoint3D64f
CvPoint3D64d_p = CvPoint3D64f

def cvPoint3D64f(x, y, z):
    return CvPoint3D64f(float(x), float(y), float(z))
cvPoint3D64d = cvPoint3D64f
    
#-----------------------------------------------------------------------------
# CvSize's & CvBox
#-----------------------------------------------------------------------------

# pixel-accurate size of a rectangle
class CvSize(_Structure):
    _fields_ = [("width", c_int),
                ("height", c_int)]
CvSize_p = POINTER(CvSize)
CvSize_r = ByRefArg(CvSize)
                
def cvSize(x, y):
    return CvSize(c_int(x), c_int(y))

# sub-pixel accurate size of a rectangle
class CvSize2D32f(_Structure):
    _fields_ = [("width", c_float),
                ("height", c_float)]
CvSize2D32f_p = POINTER(CvSize2D32f)
                
def cvSize2D32f(x, y):
    return CvSize2D32f(c_float(x), c_float(y))

class CvBox2D(_Structure):
    _fields_ = [('center', CvPoint2D32f),
                ('size', CvSize2D32f),
                ('angle', c_float)]
CvBox2D_p = POINTER(CvBox2D)
CvBox2D_r = ByRefArg(CvBox2D)
                
class CvLineIterator(_Structure):
    _fields_ = [
        ('ptr', c_ubyte_p), # POINTER to the current point
        ('err', c_int),
        ('plus_delta', c_int),
        ('minus_delta', c_int),
        ('plus_step', c_int),
        ('minus_step', c_int),        
    ]
CvLineIterator_p = POINTER(CvLineIterator)
CvLineIterator_r = ByRefArg(CvLineIterator)
    
    
#-----------------------------------------------------------------------------
# CvScalar
#-----------------------------------------------------------------------------

# A container for 1-,2-,3- or 4-tuples of numbers
# improved by David Bolen
class CvScalar(_Structure):
    _fields_ = [("val", c_double * 4)]
    def __init__(self, *vals):
        '''Enable initialization with multiple parameters instead of just a tuple'''
        super(CvScalar, self).__init__(vals + (0.0,) * (4-len(vals)))

    # Normal _Structure printing isn't as helpful for Scalar as its only field
    # is the value array which doesn't display its contents.  So generate our
    # own display including field values (shortening tail 0's for common cases)
    def __repr__(self):
        vals = list(self.val)
        while vals and not vals[-1]:
            vals.pop()
        if not vals:
            vals = [0.0]
        return self.__class__.__name__ + \
               '(' + ', '.join([str(x) for x in vals]) + ')'

CvScalar_p = POINTER(CvScalar)
CvScalar_r = ByRefArg(CvScalar)

def cvScalar(val0, val1=0, val2=0, val3=0):
    return CvScalar(val0, val1, val2, val3)
    
def cvRealScalar(val0):
    return CvScalar(val0)
    
def cvScalarAll(val0123):
    return CvScalar(val0123, val0123, val0123, val0123)

    
#-----------------------------------------------------------------------------
# Graph
#-----------------------------------------------------------------------------

# Graph
class CvGraphEdge(_Structure): # forward declaration
    pass
CvGraphEdge_p = POINTER(CvGraphEdge)
CvGraphEdge_r = ByRefArg(CvGraphEdge)
    
class CvGraphVtx(_Structure): # forward declaration
    pass
CvGraphVtx_p = POINTER(CvGraphVtx)
CvGraphVtx_r = ByRefArg(CvGraphVtx)
    
def CV_GRAPH_EDGE_FIELDS():
    return [
        ('flags', c_int),
        ('weight', c_float),
        ('next', CvGraphEdge_p*2),
        ('vtx', CvGraphVtx_p*2),
    ]

def CV_GRAPH_VERTEX_FIELDS():
    return [('flags', c_int),
            ('first', CvGraphEdge_p)]

CvGraphEdge._fields_ = CV_GRAPH_EDGE_FIELDS()
CvGraphVtx._fields_ = CV_GRAPH_VERTEX_FIELDS()

class CvGraphVtx2D(CvGraphVtx):
    _fields_ = [('ptr', CvPoint2D32f_p)]
CvGraphVtx2D_p = POINTER(CvGraphVtx2D)
    
#    Graph is "derived" from the set (this is set a of vertices) and includes another set (edges)
class CvGraph(CvSet): 
    _fields_ = [('edges', CvSet_p)]
CvGraph_p = POINTER(CvGraph)
CvGraph_r = ByRefArg(CvGraph)
    
CV_TYPE_NAME_GRAPH = "opencv-graph"

# CvGraphScanner is taken out from cxcore.h
class CvGraphScanner(_Structure):
    _fields_ = [
        ('vtx', CvGraphVtx_p), # current graph vertex (or current edge origin)
        ('dst', CvGraphVtx_p), # current graph edge destination vertex
        ('edge', CvGraphEdge_p), # current edge
        ('graph', CvGraph_p), # the graph
        ('stack', CvSeq_p), # the graph vertex stack
        ('index', c_int), # the lower bound of certainly visited vertices
        ('mask', c_int), # event mask
    ]
    
    def __del__(self):
        _cvReleaseGraphScanner(CvGraphScanner_p(self))
        
CvGraphScanner_p = POINTER(CvGraphScanner)
CvGraphScanner_r = ByRefArg(CvGraphScanner)
    
    
#-----------------------------------------------------------------------------
# Chain/Countour
#-----------------------------------------------------------------------------

# Chain/contour
class CvChain(CvSeq):
    _fields_ = [('origin', CvPoint)]
CvChain_p = POINTER(CvChain)
CvChain_r = ByRefArg(CvChain)
    
class CvContour(CvSeq):
    _fields_ = [('rect', CvRect),
                ('color', c_int),
                ('reserved', c_int*3)]
CvContour_p = POINTER(CvContour)    
CvContour_r = ByRefArg(CvContour)

CvPoint2DSeq = CvContour

#-----------------------------------------------------------------------------
# Sequence types
#-----------------------------------------------------------------------------

#Viji Periapoilan 5/21/2007(start)
#/****************************************************************************************\
#*                                    Sequence types                                      *
#\****************************************************************************************/

CV_SEQ_MAGIC_VAL            = 0x42990000

#define CV_IS_SEQ(seq) \
#    ((seq) != NULL && (((CvSeq*)(seq))->flags & CV_MAGIC_MASK) == CV_SEQ_MAGIC_VAL)

CV_SET_MAGIC_VAL           = 0x42980000
#define CV_IS_SET(set) \
#    ((set) != NULL && (((CvSeq*)(set))->flags & CV_MAGIC_MASK) == CV_SET_MAGIC_VAL)

CV_SEQ_ELTYPE_BITS         = 9
CV_SEQ_ELTYPE_MASK         =  ((1 << CV_SEQ_ELTYPE_BITS) - 1)
CV_SEQ_ELTYPE_POINT        =  CV_32SC2  #/* (x,y) */
CV_SEQ_ELTYPE_CODE         = CV_8UC1   #/* freeman code: 0..7 */
CV_SEQ_ELTYPE_GENERIC      =  0
CV_SEQ_ELTYPE_PTR          =  CV_USRTYPE1
CV_SEQ_ELTYPE_PPOINT       =  CV_SEQ_ELTYPE_PTR  #/* &(x,y) */
CV_SEQ_ELTYPE_INDEX        =  CV_32SC1  #/* #(x,y) */
CV_SEQ_ELTYPE_GRAPH_EDGE   =  0  #/* &next_o, &next_d, &vtx_o, &vtx_d */
CV_SEQ_ELTYPE_GRAPH_VERTEX =  0  #/* first_edge, &(x,y) */
CV_SEQ_ELTYPE_TRIAN_ATR    =  0  #/* vertex of the binary tree   */
CV_SEQ_ELTYPE_CONNECTED_COMP= 0  #/* connected component  */
CV_SEQ_ELTYPE_POINT3D      =  CV_32FC3  #/* (x,y,z)  */

CV_SEQ_KIND_BITS           = 3
CV_SEQ_KIND_MASK           = (((1 << CV_SEQ_KIND_BITS) - 1)<<CV_SEQ_ELTYPE_BITS)


# types of sequences
CV_SEQ_KIND_GENERIC        = (0 << CV_SEQ_ELTYPE_BITS)
CV_SEQ_KIND_CURVE          = (1 << CV_SEQ_ELTYPE_BITS)
CV_SEQ_KIND_BIN_TREE       = (2 << CV_SEQ_ELTYPE_BITS)

#Viji Periapoilan 5/21/2007(end)

# types of sparse sequences (sets)
CV_SEQ_KIND_GRAPH       = (3 << CV_SEQ_ELTYPE_BITS)
CV_SEQ_KIND_SUBDIV2D    = (4 << CV_SEQ_ELTYPE_BITS)

CV_SEQ_FLAG_SHIFT       = (CV_SEQ_KIND_BITS + CV_SEQ_ELTYPE_BITS)

# flags for curves
CV_SEQ_FLAG_CLOSED     = (1 << CV_SEQ_FLAG_SHIFT)
CV_SEQ_FLAG_SIMPLE     = (2 << CV_SEQ_FLAG_SHIFT)
CV_SEQ_FLAG_CONVEX     = (4 << CV_SEQ_FLAG_SHIFT)
CV_SEQ_FLAG_HOLE       = (8 << CV_SEQ_FLAG_SHIFT)

# flags for graphs
CV_GRAPH_FLAG_ORIENTED = (1 << CV_SEQ_FLAG_SHIFT)

CV_GRAPH               = CV_SEQ_KIND_GRAPH
CV_ORIENTED_GRAPH      = (CV_SEQ_KIND_GRAPH|CV_GRAPH_FLAG_ORIENTED)

# point sets
CV_SEQ_POINT_SET       = (CV_SEQ_KIND_GENERIC| CV_SEQ_ELTYPE_POINT)
CV_SEQ_POINT3D_SET     = (CV_SEQ_KIND_GENERIC| CV_SEQ_ELTYPE_POINT3D)
CV_SEQ_POLYLINE        = (CV_SEQ_KIND_CURVE  | CV_SEQ_ELTYPE_POINT)
CV_SEQ_POLYGON         = (CV_SEQ_FLAG_CLOSED | CV_SEQ_POLYLINE )
CV_SEQ_CONTOUR         = CV_SEQ_POLYGON
CV_SEQ_SIMPLE_POLYGON  = (CV_SEQ_FLAG_SIMPLE | CV_SEQ_POLYGON  )

# chain-coded curves
CV_SEQ_CHAIN           = (CV_SEQ_KIND_CURVE  | CV_SEQ_ELTYPE_CODE)
CV_SEQ_CHAIN_CONTOUR   = (CV_SEQ_FLAG_CLOSED | CV_SEQ_CHAIN)

# binary tree for the contour
CV_SEQ_POLYGON_TREE    = (CV_SEQ_KIND_BIN_TREE  | CV_SEQ_ELTYPE_TRIAN_ATR)

# sequence of the connected components
CV_SEQ_CONNECTED_COMP  = (CV_SEQ_KIND_GENERIC  | CV_SEQ_ELTYPE_CONNECTED_COMP)

# sequence of the integer numbers
CV_SEQ_INDEX           = (CV_SEQ_KIND_GENERIC  | CV_SEQ_ELTYPE_INDEX)

# CV_SEQ_ELTYPE( seq )   = ((seq)->flags & CV_SEQ_ELTYPE_MASK)
# CV_SEQ_KIND( seq )     = ((seq)->flags & CV_SEQ_KIND_MASK )

#-----------------------------------------------------------------------------
# Sequence writer & reader
#-----------------------------------------------------------------------------

# Sequence writer & reader
def CV_SEQ_WRITER_FIELDS():
    return [
        ('header_size', c_int),
        ('seq', CvSeq_p), # the sequence written
        ('block', CvSeqBlock_p), # current block
        ('ptr', c_char_p), # POINTER to free space
        ('block_min', c_char_p), # POINTER to the beginning of block
        ('block_max', c_char_p), # POINTER to the end of block
    ]

class CvSeqWriter(_Structure):
    _fields_ = CV_SEQ_WRITER_FIELDS()
CvSeqWriter_p = POINTER(CvSeqWriter)
CvSeqWriter_r = ByRefArg(CvSeqWriter)
    
def CV_SEQ_READER_FIELDS():
    return [
        ('header_size', c_int),
        ('seq', CvSeq_p), # sequence, begin read
        ('block', CvSeqBlock_p), # current block
        ('ptr', c_void_p), # POINTER to free space
        ('block_min', c_char_p), # POINTER to the beginning of block
        ('block_max', c_char_p), # POINTER to the end of block
        ('delta_index', c_int), # = seq->first-.start_index
        ('prev_elem', c_char_p), # POINTER to previous element
    ]

class CvSeqReader(_Structure):
    _fields_ = CV_SEQ_READER_FIELDS()
CvSeqReader_p = POINTER(CvSeqReader)
CvSeqReader_r = ByRefArg(CvSeqReader)
    
#-----------------------------------------------------------------------------
# Data structures for persistence (a.k.a serialization) functionality
#-----------------------------------------------------------------------------

# File storage
class CvFileStorage(_Structure):
    _fields_ = []
    
    def __del__(self):
        _cvReleaseFileStorage(CvFileStorage_p(self))
    
CvFileStorage_p = POINTER(CvFileStorage)
CvFileStorage_r = ByRefArg(CvFileStorage)
    
# Data structures for persistence (a.k.a serialization) functionality
CV_STORAGE_READ = 0
CV_STORAGE_WRITE = 1
CV_STORAGE_WRITE_TEXT = CV_STORAGE_WRITE
CV_STORAGE_WRITE_BINARY = CV_STORAGE_WRITE
CV_STORAGE_APPEND = 2

# List of attributes
class CvAttrList(_Structure):
    pass
CvAttrList_p = POINTER(CvAttrList)
CvAttrList_r = ByRefArg(CvAttrList)
CvAttrList._fields_ = [
    ("attr", POINTER(c_char_p)), # NULL-terminated array of (attribute_name,attribute_value) pairs
    ("next", CvAttrList_p), # POINTER to next chunk of the attributes list
]

def cvAttrList(attr=None, next=None):
    """CvAttrList cvAttrList( const char** attr=NULL, CvAttrList next=None )
    
    Initializes CvAttrList structure
    """
    return CvAttrList(attr, None) if next is None else CvAttrList(attr, next)

class CvTypeInfo(_Structure): # forward declaration
    pass
CvTypeInfo_p = POINTER(CvTypeInfo)
CvTypeInfo_r = ByRefArg(CvTypeInfo)
    
CV_NODE_NONE        = 0
CV_NODE_INT         = 1
CV_NODE_INTEGER     = CV_NODE_INT
CV_NODE_REAL        = 2
CV_NODE_FLOAT       = CV_NODE_REAL
CV_NODE_STR         = 3
CV_NODE_STRING      = CV_NODE_STR
CV_NODE_REF         = 4 # not used
CV_NODE_SEQ         = 5
CV_NODE_MAP         = 6
CV_NODE_TYPE_MASK   = 7

def CV_NODE_TYPE(flags):
    return flags & CV_NODE_TYPE_MASK

# file node flags
CV_NODE_FLOW        = 8 # used only for writing structures to YAML format
CV_NODE_USER        = 16
CV_NODE_EMPTY       = 32
CV_NODE_NAMED       = 64

def CV_NODE_IS_INT(flags):
    return CV_NODE_TYPE(flags) == CV_NODE_INT
    
def CV_NODE_IS_REAL(flags):
    return CV_NODE_TYPE(flags) == CV_NODE_REAL
    
def CV_NODE_IS_STRING(flags):
    return CV_NODE_TYPE(flags) == CV_NODE_STRING
    
def CV_NODE_IS_SEQ(flags):
    return CV_NODE_TYPE(flags) == CV_NODE_SEQ
    
def CV_NODE_IS_MAP(flags):
    return CV_NODE_TYPE(flags) == CV_NODE_MAP
    
def CV_NODE_IS_COLLECTION(flags):
    return CV_NODE_TYPE(flags) >= CV_NODE_SEQ
    
def CV_NODE_IS_FLOW(flags):
    return bool(flags & CV_NODE_FLOW)
    
def CV_NODE_IS_EMPTY(flags):
    return bool(flags & CV_NODE_EMPTY)
    
def CV_NODE_IS_USER(flags):
    return bool(flags & CV_NODE_USER)
    
def CV_NODE_HAS_NAME(flags):
    return bool(flags & CV_NODE_NAMED)

CV_NODE_SEQ_SIMPLE = 256
def CV_NODE_SEQ_IS_SIMPLE(seq):
    return bool(seq[0].flags & CV_NODE_SEQ_SIMPLE)

class CvString(_Structure):
    _fields_ = [("len", c_int),
                ("ptr", c_char_p)]
CvString_p = POINTER(CvString)
                
class CvStringHashNode(_Structure):
    pass
CvStringHashNode_p = POINTER(CvStringHashNode)
CvStringHashNode_r = ByRefArg(CvStringHashNode)
CvStringHashNode._fields_ = [("hashval", c_uint32),
                ("str", CvString),
                ("next", CvStringHashNode_p)]

class CvFileNodeHash(_Structure):
    _fields_ = [] # CvGenericHash, to be expanded in the future
CvFileNodeHash_p = POINTER(CvFileNodeHash)
    
class CvFileNode(_Structure): # forward declaration
    pass
CvFileNode_p = POINTER(CvFileNode)
CvFileNode_r = ByRefArg(CvFileNode)
    
class CvFileNodeData(Union):
    _fields_ = [
        ('f', c_double), # scalar floating-point number
        ('i', c_int), # scalar integer number
        ('str', CvString), # text string
        ('seq', CvFileNode_p), # sequence (ordered collection of file nodes)
        ('map', CvFileNodeHash_p), # map (collection of named file nodes)
    ]
CvFileNodeData_p = POINTER(CvFileNodeData)
    
CvFileNode._fields_ = [
    ('tag', c_int),
    ('info', CvTypeInfo_p), # type information(only for user-defined object, for others it is 0)
    ('data', CvFileNodeData),
]

CvIsInstanceFunc = CFUNCTYPE(c_int, c_void_p)
CvReleaseFunc = CFUNCTYPE(None, c_void_p_p)
CvReadFunc = CFUNCTYPE(c_void_p, CvFileStorage_p, CvFileNode_p)
CvWriteFunc = CFUNCTYPE(None, CvFileStorage_p, c_char_p, c_void_p, CvAttrList)
CvCloneFunc = CFUNCTYPE(c_void_p, c_void_p)

CvTypeInfo._fields_ = [
    ('flags', c_int),
    ('header_size', c_int),
    ('prev', CvTypeInfo_p),
    ('next', CvTypeInfo_p),
    ('type_name', c_char_p),
    ('is_instance', CvIsInstanceFunc),
    ('release', CvReleaseFunc),
    ('read', CvReadFunc),
    ('write', CvWriteFunc),
    ('clone', CvCloneFunc),
]
    

# System data types

class CvPluginFuncInfo(_Structure):
    _fields_ = [
        ('func_addr', c_void_p_p),
        ('default_func_addr', c_void_p),
        ('func_names', c_char_p),
        ('search_modules', c_int),
        ('loaded_from', c_int),
    ]
CvPluginFuncInfo_p = POINTER(CvPluginFuncInfo)

class CvModuleInfo(_Structure):
    pass
CvModuleInfo_p = POINTER(CvModuleInfo)
CvModuleInfo_r = ByRefArg(CvModuleInfo)
CvModuleInfo._fields_ = [
    ('next', CvModuleInfo_p),
    ('name', c_char_p),
    ('version', c_char_p),
    ('func_tab', CvPluginFuncInfo_p),
]

#=============================================================================
# End of cxcore/cxtypes.h
#=============================================================================




#=============================================================================
# Begin of of cxcore/cxcore.h
#=============================================================================


#-----------------------------------------------------------------------------
# Memory allocation/deallocation for CvArr_p
#-----------------------------------------------------------------------------

# Deallocates memory buffer
_cvFree = cfunc('cvFree_', _cxDLL, None,
    ('ptr', c_void_p, 1), # void* ptr
)
_cvFree.__doc__ = """void cvFree(CvArr_p ptr)

Deallocates memory buffer. 
"""
    
# Allocates memory buffer
_cvAlloc = cfunc('cvAlloc', _cxDLL,  CvArr,
    ('size', c_ulong, 1), # size_t size 
)
_cvAlloc.__doc__ = """CvArr cvAlloc(size_t size)

Allocates memory buffer
"""    
        
#-----------------------------------------------------------------------------
# Array allocation, deallocation, initialization and access to elements
#-----------------------------------------------------------------------------
def cvAlloc(size):
    """CvMat cvAlloc(int size)

    Creates new matrix
    """
    z = pointee(_cvAlloc(size))
    z._owner = True
    return z


# Releases image header
_cvReleaseImageHeader = cfunc('cvReleaseImageHeader', _cxDLL, None,
    ('image', ByRefArg(IplImage_p), 1), # IplImage** image 
)

# Allocates, initializes, and returns structure IplImage
_cvCreateImageHeader = cfunc('cvCreateImageHeader', _cxDLL, IplImage_p,
    ('size', CvSize, 1), # CvSize size
    ('depth', c_int, 1), # int depth
    ('channels', c_int, 1), # int channels 
)

def cvCreateImageHeader(size, depth, channels):
    """IplImage cvCreateImageHeader(CvSize size, int depth, int channels)

    Allocates, initializes, and returns structure IplImage
    """
    z = pointee(_cvCreateImageHeader(size, depth, channels))
    z._owner = 1 # header only
    return z

# Initializes allocated by user image header
_cvInitImageHeader = cfunc('cvInitImageHeader', _cxDLL, IplImage_p,
    ('image', IplImage_r, 1), # IplImage* image
    ('size', CvSize, 1), # CvSize size
    ('depth', c_int, 1), # int depth
    ('channels', c_int, 1), # int channels
    ('origin', c_int, 1, 0), # int origin
    ('align', c_int, 1, 4), # int align
)

def cvInitImageHeader(image, size, depth, channels, origin=0, align=4):
    """IplImage cvInitImageHeader(IplImage image, CvSize size, int depth, int channels, int origin=0, int align=4)

    Initializes allocated by user image header
    """
    return pointee(_cvInitImageHeader(image, size, depth, channels, origin=origin, align=align))

# Releases header and image data
_cvReleaseImage = cfunc('cvReleaseImage', _cxDLL, None,
    ('image', ByRefArg(IplImage_p), 1), # IplImage** image 
)

# Creates header and allocates data
_cvCreateImage = cfunc('cvCreateImage', _cxDLL, IplImage_p,
    ('size', CvSize, 1), # CvSize size
    ('depth', c_int, 1), # int depth
    ('channels', c_int, 1), # int channels 
)

def cvCreateImage(size, depth, channels):
    """IplImage cvCreateImage(CvSize size, int depth, int channels)

    Creates header and allocates data
    """
    z = pointee(_cvCreateImage(size, depth, channels))
    z._owner = 3 # both header and data
    return z

# Makes a full copy of image (widthStep may differ)
_cvCloneImage = cfunc('cvCloneImage', _cxDLL, IplImage_p,
    ('image', IplImage_r, 1), # const IplImage* image 
)

def cvCloneImage(image):
    """IplImage cvCloneImage(const IplImage image)

    Makes a full copy of image (widthStep may differ)
    """
    z = pointee(_cvCloneImage(image))
    z._owner = 3 # as a clone, z owns both header and data
    return z

# Sets channel of interest to given value
cvSetImageCOI = cfunc('cvSetImageCOI', _cxDLL, None,
    ('image', IplImage_r, 1), # IplImage* image
    ('coi', c_int, 1), # int coi 
)
cvSetImageCOI.__doc__ = """void cvSetImageCOI(IplImage image, int coi)

Sets channel of interest to given value
"""

# Returns index of channel of interest
cvGetImageCOI = cfunc('cvGetImageCOI', _cxDLL, c_int,
    ('image', IplImage_r, 1), # const IplImage* image 
)
cvGetImageCOI.__doc__ = """int cvGetImageCOI(const IplImage image)

Returns index of channel of interest
"""

# Sets image ROI to given rectangle
cvSetImageROI = cfunc('cvSetImageROI', _cxDLL, None,
    ('image', IplImage_r, 1), # IplImage* image
    ('rect', CvRect, 1), # CvRect rect 
)
cvSetImageROI.__doc__ = """void cvSetImageROI(IplImage image, CvRect rect)

Sets image ROI to given rectangle
"""

# Releases image ROI
cvResetImageROI = cfunc('cvResetImageROI', _cxDLL, None,
    ('image', IplImage_r, 1), # IplImage* image 
)
cvResetImageROI.__doc__ = """void cvResetImageROI(IplImage image)

Releases image ROI
"""

# Returns image ROI coordinates
cvGetImageROI = cfunc('cvGetImageROI', _cxDLL, CvRect,
    ('image', IplImage_r, 1), # const IplImage* image 
)
cvGetImageROI.__doc__ = """CvRect cvGetImageROI(const IplImage image)

Returns image ROI coordinates
"""

# Deallocates matrix
_cvReleaseMat = cfunc('cvReleaseMat', _cxDLL, None,
    ('mat', ByRefArg(CvMat_p), 1), # CvMat** mat 
)

# Creates new matrix header
_cvCreateMatHeader = cfunc('cvCreateMatHeader', _cxDLL, CvMat_p,
    ('rows', c_int, 1), # int rows
    ('cols', c_int, 1), # int cols
    ('type', c_int, 1), # int type 
)

def cvCreateMatHeader(rows, cols, cvmat_type):
    """CvMat cvCreateMatHeader(int rows, int cols, int type)

    Creates new matrix header
    """
    z = pointee(_cvCreateMatHeader(rows, cols, cvmat_type))
    z._owner = True
    return z

CV_AUTOSTEP = 0x7fffffff

# Initializes matrix header
_cvInitMatHeader = cfunc('cvInitMatHeader', _cxDLL, CvMat_p,
    ('mat', CvMat_r, 1), # CvMat* mat
    ('rows', c_int, 1), # int rows
    ('cols', c_int, 1), # int cols
    ('type', c_int, 1), # int type
    ('data', c_void_p, 1, None), # void* data
    ('step', c_int, 1, CV_AUTOSTEP), # int step
)

def cvInitMatHeader(mat, rows, cols, cvmat_type, data=None, step=CV_AUTOSTEP):
    """CvMat cvInitMatHeader(CvMat mat, int rows, int cols, int type, void* data=NULL, int step=CV_AUTOSTEP)

    Initializes matrix header
    """
    _cvInitMatHeader(mat, rows, cols, cvmat_type, data=data, step=step)
    if data is not None:
        mat._depends = (data,)
    return mat
    
def cvMat(rows, cols, cvmat_type, data=None, step=CV_AUTOSTEP):
    return cvInitMatHeader(CvMat(), rows, cols, cvmat_type, data, step)

# Creates new matrix
_cvCreateMat = cfunc('cvCreateMat', _cxDLL, CvMat_p,
    ('rows', c_int, 1), # int rows
    ('cols', c_int, 1), # int cols
    ('type', c_int, 1), # int type 
)

def cvCreateMat(rows, cols, cvmat_type):
    """CvMat cvCreateMat(int rows, int cols, int type)

    Creates new matrix
    """
    z = pointee(_cvCreateMat(rows, cols, cvmat_type))
    z._owner = True
    return z

# Minh-Tri's helpers
def cvCreateMatFromCvPoint2D32fList(points):
    """CvMat cvCreateMatFromCvPoint2D32fList(list_or_tuple_of_CvPoint2D32f points)
    
    Creates a new matrix from a list/tuple of CvPoint2D32f points
    """
    cols = len(points)
    z = cvCreateMat(1, cols, CV_32FC2)
    for i in range(cols):
        x = points[i]
        y = z[0,i]
        y[0] = x.x
        y[1] = x.y
    return z

def cvCreateMatFromCvPointList(points):
    """CvMat cvCreateMatFromCvPointList(list_or_tuple_of_CvPoint points)
    
    Creates a new matrix from a list/tuple of CvPoint points
    """
    cols = len(points)
    z = cvCreateMat(1, cols, CV_32SC2)
    for i in range(cols):
        x = points[i]
        y = z[0,i]
        y[0] = x.x
        y[1] = x.y
    return z

# Creates matrix copy
_cvCloneMat = cfunc('cvCloneMat', _cxDLL, CvMat_p,
    ('mat', CvMat_r, 1), # const CvMat* mat 
)

def cvCloneMat(mat):
    """CvMat cvCloneMat(const CvMat mat)

    Creates matrix copy
    """
    z = pointee(_cvCloneMat(mat))
    z._owner = True
    return z

# Returns matrix header corresponding to the rectangular sub-array of input image or matrix
_cvGetSubRect = cfunc('cvGetSubRect', _cxDLL, CvArr_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('submat', CvMat_r, 1), # CvMat* submat
    ('rect', CvRect, 1), # CvRect rect 
)

def cvGetSubRect(arr, submat, rect):
    """CvMat cvGetSubRect(const CvArr arr, CvMat submat, CvRect rect)

    Returns matrix header corresponding to the rectangular sub-array of input image or matrix
    [ctypes-opencv] If 'submat' is None, it is internally created.
    """
    if submat is None:
        submat = CvMat()
    _cvGetSubRect(arr, submat, rect)
    submat._depends = (arr,)
    return submat

cvGetSubArr = cvGetSubRect

# Returns array row or row span
_cvGetRows = cfunc('cvGetRows', _cxDLL, CvMat_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('submat', CvMat_r, 1), # CvMat* submat
    ('start_row', c_int, 1), # int start_row
    ('end_row', c_int, 1), # int end_row
    ('delta_row', c_int, 1, 1), # int delta_row
)

def cvGetRows(arr, submat, start_row, end_row, delta_row=1):
    """CvMat cvGetRows(const CvArr arr, CvMat submat, int start_row, int end_row, int delta_row=1)

    Returns array row or row span
    [ctypes-opencv] If 'submat' is None, it is internally created.
    """
    if submat is None:
        submat = CvMat()
    return pointee(_cvGetRows(arr, submat, start_row, end_row, delta_row=delta_row), arr, submat)
    
def cvGetRow(arr, submat=None, row=0):
    return cvGetRows(arr, submat, row, row+1)

# Returns array column or column span
_cvGetCols = cfunc('cvGetCols', _cxDLL, CvMat_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('submat', CvMat_r, 1), # CvMat* submat
    ('start_col', c_int, 1), # int start_col
    ('end_col', c_int, 1), # int end_col 
)

def cvGetCols(arr, submat, start_col, end_col):
    """CvMat cvGetCols(const CvArr arr, CvMat submat, int start_col, int end_col)

    Returns array column or column span
    [ctypes-opencv] If 'submat' is None, it is internally created.
    """
    if submat is None:
        submat = CvMat()
    return pointee(_cvGetCols(arr, submat, start_col, end_col), arr, submat)
    
def cvGetCol(arr, submat=None, col=0):
    return cvGetCols(arr, submat, col, col+1)

# Returns one of array diagonals
_cvGetDiag = cfunc('cvGetDiag', _cxDLL, CvMat_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('submat', CvMat_r, 1), # CvMat* submat
    ('diag', c_int, 1, 0), # int diag
)

def cvGetDiag(arr, submat=None, diag=0):
    """CvMat cvGetDiag(const CvArr arr, CvMat submat, int diag=0)

    Returns one of array diagonals
    [ctypes-opencv] If 'submat' is None, it is internally created.
    """
    if submat is None:
        submat = CvMat()
    return pointee(_cvGetDiag(arr, submat, diag=diag), arr, submat)

# Creates new matrix header
_cvCreateMatNDHeader = cfunc('cvCreateMatNDHeader', _cxDLL, CvMatND_p,
    ('dims', c_int, 1), # int dims
    ('sizes', ListPOINTER(c_int), 1), # const int* sizes
    ('type', c_int, 1), # int type 
)

def cvCreateMatNDHeader(sizes, type):
    """CvMatND cvCreateMatNDHeader(list_or_tuple_of_int sizes, int type)

    Creates new matrix header
    """
    z = pointee(_cvCreateMatNDHeader(len(sizes), sizes, type))
    z._owner = True
    return z

# Creates multi-dimensional dense array
_cvCreateMatND = cfunc('cvCreateMatND', _cxDLL, CvMatND_p,
    ('dims', c_int, 1), # int dims
    ('sizes', ListPOINTER(c_int), 1), # const int* sizes
    ('type', c_int, 1), # int type 
)

def cvCreateMatND(sizes, type):
    """CvMatND cvCreateMatND(list_or_tuple_of_int sizes, int type)

    Creates multi-dimensional dense array
    """
    z = pointee(_cvCreateMatND(len(sizes), sizes, type))
    z._owner = True
    return z

# Initializes multi-dimensional array header
_cvInitMatNDHeader = cfunc('cvInitMatNDHeader', _cxDLL, CvMatND_p,
    ('mat', CvMatND_r, 1), # CvMatND* mat
    ('dims', c_int, 1), # int dims
    ('sizes', ListPOINTER(c_int), 1), # const int* sizes
    ('type', c_int, 1), # int type
    ('data', c_void_p, 1, None), # void* data
)

def cvInitMatNDHeader(mat, sizes, type, data=None):
    """CvMatND cvInitMatNDHeader(CvMatND mat, list_or_tuple_of_int sizes, int type, void* data=NULL)

    Initializes multi-dimensional array header
    """
    _cvInitMatNDHeader(mat, len(sizes), sizes, type, data=data)
    if data is not None:
        mat._depends = (data,)
    return mat
    
def cvMatND(sizes, mattype, data=None):
    return cvInitMatNDHeader(CvMatND(), sizes, mattype, data=data)
    
_cvCloneMatND = cfunc('cvCloneMatND', _cxDLL, CvMatND_p,
    ('mat', CvMatND_r, 1), # const CvMatND* mat 
)

# Creates full copy of multi-dimensional array
def cvCloneMatND(mat):
    """CvMatND cvCloneMatND(const CvMatND mat)

    Creates full copy of multi-dimensional array
    """
    return pointee(_cvCloneMatND(mat))

# Deallocates sparse array
_cvReleaseSparseMat = cfunc('cvReleaseSparseMat', _cxDLL, None,
    ('mat', ByRefArg(CvSparseMat_p), 1), # CvSparseMat** mat 
)

# Creates sparse array
_cvCreateSparseMat = cfunc('cvCreateSparseMat', _cxDLL, CvSparseMat_p,
    ('dims', c_int, 1), # int dims
    ('sizes', ListPOINTER(c_int), 1), # const int* sizes
    ('type', c_int, 1), # int type 
)

def cvCreateSparseMat(sizes, type):
    """CvSparseMat cvCreateSparseMat(list_or_tuple_of_int sizes, int type)

    Creates sparse array
    """
    return pointee(_cvCreateSparseMat(len(sizes), sizes, type))

# Creates full copy of sparse array
_cvCloneSparseMat = cfunc('cvCloneSparseMat', _cxDLL, CvSparseMat_p,
    ('mat', CvSparseMat_r, 1), # const CvSparseMat* mat 
)

def cvCloneSparseMat(mat):
    """CvSparseMat cvCloneSparseMat(const CvSparseMat mat)

    Creates full copy of sparse array
    """
    return pointee(_cvCloneSparseMat(mat))
    
# Initializes sparse array elements iterator
_cvInitSparseMatIterator = cfunc('cvInitSparseMatIterator', _cxDLL, CvSparseNode_p,
    ('mat', CvSparseMat_r, 1), # const CvSparseMat* mat
    ('mat_iterator', CvSparseMatIterator_r, 1), # CvSparseMatIterator* mat_iterator
)

def cvInitSparseMatIterator(mat, mat_iterator=None):
    """(CvSparseMatIterator iterator, CvSparseNode first) = cvInitSparseMatIterator(CvSparseMat node, CvSparseMatIterator mat_iterator)
    
    Initializes sparse array elements iterator
    [ctypes-opencv] If mat_iterator is None, it is internally created.
    """
    if mat_iterator is None:
        mat_iterator = CvSparseMatIterator()
    z = pointee(_cvInitSparseMatIterator(mat, mat_iterator), mat)
    mat_iterator._depends = (mat,) # to make sure mat is deleted after mat_iterator is deleted
    return (mat_iterator, z)
    
# Initializes sparse array elements iterator
def cvGetNextSparseNode(mat_iterator):
    """CvSparseNode cvGetNextSparseNode(CvSparseMatIterator mat_iterator)
    
    Initializes sparse array elements iterator
    """
    if bool(mat_iterator.node[0].next):
        mat_iterator.node = mat_iterator.node[0].next
        return pointee(mat_iterator.node, mat_iterator.mat)

    mat_iterator.curidx += 1
    for idx in range(mat_iterator.curidx, mat_iterator.mat[0].hashsize):
        node = cast(mat_iterator.mat[0].hashtable, POINTER(CvSparseNode_p))[idx]
        if bool(node):
            mat_iterator.curidx = idx
            mat_iterator.node = node
            return node
    return None

        
#-----------------------------------------------------------------------------
# Accessing Elements and sub-Arrays
#-----------------------------------------------------------------------------


# Returns type of array elements
cvGetElemType = cfunc('cvGetElemType', _cxDLL, c_int,
    ('arr', CvArr_r, 1), # const CvArr* arr 
)
cvGetElemType.__doc__ = """int cvGetElemType(const CvArr arr)

Returns type of array elements
"""

# Return number of array dimensions and their sizes or the size of particular dimension
_cvGetDims = cfunc('cvGetDims', _cxDLL, c_int,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('sizes', c_int_p, 1, None), # int* sizes
)

cvGetDimSize = cfunc('cvGetDimSize', _cxDLL, c_int,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('index', c_int, 1), # int index 
)
cvGetDimSize.__doc__ = """int cvGetDimSize(const CvArr arr, int index)

Return the size of a particular dimension
"""

# Return a tuple of array dimensions
def cvGetDims(arr, sizes=None):
    """tuple_of_ints cvGetDims(const CvArr arr, c_int_p sizes=NULL)

    Return a tuple of array dimensions
    [ctypes-opencv] If 'sizes' is None, it is internally created.
    """
    if sizes is None:
        sizes = (c_int*32)()
    ndims = _cvGetDims(arr, sizes)
    return tuple(sizes[:ndims])


# Return POINTER to the particular array element
cvPtr1D = cfunc('cvPtr1D', _cxDLL, c_void_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('type', c_int_p, 1, None), # int* type
)
cvPtr1D.__doc__ = """uchar* cvPtr1D(const CvArr arr, int idx0, int* type=NULL)

Return POINTER to the particular array element
"""

cvPtr2D = cfunc('cvPtr2D', _cxDLL, c_void_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('type', c_int_p, 1, None), # int* type
)
cvPtr2D.__doc__ = """uchar* cvPtr2D(const CvArr arr, int idx0, int idx1, int idx2, int* type=NULL)

Return POINTER to the particular array element
"""

cvPtr3D = cfunc('cvPtr3D', _cxDLL, c_void_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('idx2', c_int, 1), # int idx2
    ('type', c_int_p, 1, None), # int* type
)
cvPtr3D.__doc__ = """uchar* cvPtr3D(const CvArr arr, int idx0, int idx1, int idx2, int* type=NULL)

Return POINTER to the particular array element
"""

cvPtrND = cfunc('cvPtrND', _cxDLL, c_void_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx
    ('type', c_int_p, 1, None), # int* type
    ('create_node', c_int, 1, 1), # int create_node
    ('precalc_hashval', POINTER(c_uint32), 1, None), # unsigned* precalc_hashval
)
cvPtrND.__doc__ = """uchar* cvPtrND(const CvArr arr, list_or_tuple_of_int idx, int* type=NULL, int create_node=1, int* precalc_hashval=NULL)

Return POINTER to the particular array element
"""


# Return the particular array element
cvGet1D = cfunc('cvGet1D', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0 
)
cvGet1D.__doc__ = """CvScalar cvGet1D(const CvArr arr, int idx0)

Return the particular array element
"""

cvGet2D = cfunc('cvGet2D', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1 
)
cvGet2D.__doc__ = """CvScalar cvGet2D(const CvArr arr, int idx0, int idx1)

Return the particular array element
"""

cvGet3D = cfunc('cvGet3D', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('idx2', c_int, 1), # int idx2 
)
cvGet3D.__doc__ = """CvScalar cvGet3D(const CvArr arr, int idx0, int idx1, int idx2)

Return the particular array element
"""

cvGetND = cfunc('cvGetND', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx 
)
cvGetND.__doc__ = """CvScalar cvGetND(const CvArr arr, list_or_tuple_of_int idx)

Return the particular array element
"""

# Return the particular element of single-channel array
cvGetReal1D = cfunc('cvGetReal1D', _cxDLL, c_double,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0 
)
cvGetReal1D.__doc__ = """double cvGetReal1D(const CvArr arr, int idx0)

Return the particular element of single-channel array
"""

cvGetReal2D = cfunc('cvGetReal2D', _cxDLL, c_double,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1 
)
cvGetReal2D.__doc__ = """double cvGetReal2D(const CvArr arr, int idx0, int idx1)

Return the particular element of single-channel array
"""

cvGetReal3D = cfunc('cvGetReal3D', _cxDLL, c_double,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('idx2', c_int, 1), # int idx2 
)
cvGetReal3D.__doc__ = """double cvGetReal3D(const CvArr arr, int idx0, int idx1, int idx2)

Return the particular element of single-channel array
"""

cvGetRealND = cfunc('cvGetRealND', _cxDLL, c_double,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx 
)
cvGetRealND.__doc__ = """double cvGetRealND(const CvArr arr, list_or_tuple_of_int idx)

Return the particular element of single-channel array
"""

# Change the particular array element
cvSet1D = cfunc('cvSet1D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('value', CvScalar, 1), # CvScalar value 
)
cvSet1D.__doc__ = """void cvSet1D(CvArr arr, int idx0, CvScalar value)

Change the particular array element
"""

cvSet2D = cfunc('cvSet2D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('value', CvScalar, 1), # CvScalar value 
)
cvSet2D.__doc__ = """void cvSet2D(CvArr arr, int idx0, int idx1, CvScalar value)

Change the particular array element
"""

cvSet3D = cfunc('cvSet3D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('idx2', c_int, 1), # int idx2
    ('value', CvScalar, 1), # CvScalar value 
)
cvSet3D.__doc__ = """void cvSet3D(CvArr arr, int idx0, int idx1, int idx2, CvScalar value)

Change the particular array element
"""

cvSetND = cfunc('cvSetND', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx
    ('value', CvScalar, 1), # CvScalar value 
)
cvSetND.__doc__ = """void cvSetND(CvArr arr, list_or_tuple_of_int idx, CvScalar value)

Change the particular array element
"""

# Change the particular array element
cvSetReal1D = cfunc('cvSetReal1D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('value', c_double, 1), # double value 
)
cvSetReal1D.__doc__ = """void cvSetReal1D(CvArr arr, int idx0, double value)

Change the particular array element
"""

cvSetReal2D = cfunc('cvSetReal2D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('value', c_double, 1), # double value 
)
cvSetReal2D.__doc__ = """void cvSetReal2D(CvArr arr, int idx0, int idx1, double value)

Change the particular array element
"""

cvSetReal3D = cfunc('cvSetReal3D', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx0', c_int, 1), # int idx0
    ('idx1', c_int, 1), # int idx1
    ('idx2', c_int, 1), # int idx2
    ('value', c_double, 1), # double value 
)
cvSetReal3D.__doc__ = """void cvSetReal3D(CvArr arr, int idx0, int idx1, int idx2, double value)

Change the particular array element
"""

cvSetRealND = cfunc('cvSetRealND', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx
    ('value', c_double, 1), # double value 
)
cvSetRealND.__doc__ = """void cvSetRealND(CvArr arr, list_or_tuple_of_int idx, double value)

Change the particular array element
"""

# Clears the particular array element
cvClearND = cfunc('cvClearND', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('idx', ListPOINTER(c_int), 1), # int* idx 
)
cvClearND.__doc__ = """void cvClearND(CvArr arr, list_or_tuple_of_int idx)

Clears the particular array element
"""

# Returns matrix header for arbitrary array
_cvGetMat = cfunc('cvGetMat', _cxDLL, CvMat_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('header', CvMat_r, 1), # CvMat* header
    ('coi', ByRefArg(c_int), 1, None), # int* coi
    ('allowND', c_int, 1, 0), # int allowND
)

def cvGetMat(arr, header=None, coi=None, allowND=0):
    """CvMat mat[, int output_coi] = cvGetMat(const CvArr arr, CvMat header=None, c_int coi=None, int allowND=0)

    Returns matrix header for arbitrary array
    [ctypes-opencv] If 'header' is None, it is internally created.
    [ctypes-opencv] 'coi' can be:
        an instance of c_int: its value will hold the output coi
        True: the returning object is a tuple of CvMat and the output coi
        None: no output coi is returned
    """
    if header is None:
        header = CvMat()
    if coi is not True:
        return pointee(_cvGetMat(arr, header, coi=coi, allowND=allowND), arr, header)
    coi = c_int()
    return (pointee(_cvGetMat(arr, header, coi=coi, allowND=allowND), arr, header), coi.value)

# Returns image header for arbitrary array
_cvGetImage = cfunc('cvGetImage', _cxDLL, IplImage_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('image_header', IplImage_r, 1), # IplImage* image_header 
)

def cvGetImage(arr, image_header=None):
    """IplImage cvGetImage(const CvArr arr, IplImage image_header=None)

    Returns image header for arbitrary array
    [ctypes-opencv] If 'image_header' is None, it is internally created.
    """
    if image_header is None:
        image_header = IplImage()
    return pointee(_cvGetImage(arr, image_header), arr, image_header)


#-----------------------------------------------------------------------------
# Transforms and Permutations
#-----------------------------------------------------------------------------


# Changes shape of multi-dimensional array w/o copying data
cvReshapeMatND = cfunc('cvReshapeMatND', _cxDLL, c_void_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('sizeof_header', c_int, 1), # int sizeof_header
    ('header', CvArr_r, 1), # CvArr* header
    ('new_cn', c_int, 1), # int new_cn
    ('new_dims', c_int, 1), # int new_dims
    ('new_sizes', c_int_p, 1), # int* new_sizes 
)
cvReshapeMatND.__doc__ = """CvArr cvReshapeMatND(const CvArr arr, int sizeof_header, CvArr header, int new_cn, int new_dims, int* new_sizes)

Changes shape of multi-dimensional array w/o copying data
"""

# Changes shape of matrix/image without copying data
_cvReshape = cfunc('cvReshape', _cxDLL, CvMat_p,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('header', CvMat_r, 1), # CvMat* header
    ('new_cn', c_int, 1), # int new_cn
    ('new_rows', c_int, 1, 0), # int new_rows
)

def cvReshape(arr, header, new_cn, new_rows=0):
    """CvMat cvReshape(const CvArr arr, CvMat header, int new_cn, int new_rows=0)

    Changes shape of matrix/image without copying data
    [ctypes-opencv] If 'header' is None, it is internally created.
    """
    if header is None:
        header = CvMat()
    return pointee(_cvReshape(arr, header, new_cn, new_rows=new_rows), arr, header)

# Fill destination array with tiled source array
cvRepeat = cfunc('cvRepeat', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvRepeat.__doc__ = """void cvRepeat(const CvArr src, CvArr dst)

Fill destination array with tiled source array
"""


#-----------------------------------------------------------------------------
# Manipulating the data of a CvArr
#-----------------------------------------------------------------------------

# Minh-Tri's note: OpenCV's CvMat has a reference counter for its data pointer.
# So there's no need to worry about memory leak when setting/releasing data.
# However, IplImage does not. Thus, I implemented a guard against this leak.

# Allocates array data
_cvCreateData = cfunc('cvCreateData', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr 
)

def cvCreateData(arr):
    """void cvCreateData(CvArr arr)

    Allocates array data
    """
    _cvCreateData(arr)
    if isinstance(arr, IplImage):
        arr._owner |= 2 # now arr owns data

# Releases array data
_cvReleaseData = cfunc('cvReleaseData', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr 
)

def cvReleaseData(arr):
    """void cvReleaseData(CvArr arr)

    Releases array data
    """
    _cvReleaseData(arr)
    if isinstance(arr, IplImage):
        arr._owner &= ~2 # arr does not own data anymore

# Assigns user data to the array header
_cvSetData = cfunc('cvSetData', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('data', c_void_p, 1), # void* data
    ('step', c_int, 1), # int step 
)

def cvSetData(arr, data, step):
    """void cvSetData(CvArr arr, void* data, int step)

    Assigns user data to the array header
    """
    if isinstance(arr, IplImage):
        if arr._owner & 2:
            cvReleaseData(arr) # release old data if arr owns it
        _cvSetData(arr, data, step)
    else:
        _cvSetData(arr, data, step)

# Retrieves low-level information about the array
cvGetRawData = cfunc('cvGetRawData', _cxDLL, None,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('data', POINTER(POINTER(c_byte)), 1), # uchar** data
    ('step', c_int_p, 1, None), # int* step
    ('roi_size', CvSize_r, 1, None), # CvSize* roi_size
)
cvGetRawData.__doc__ = """void cvGetRawData(const CvArr arr, uchar** data, int* step=NULL, CvSize roi_size=NULL)

Retrieves low-level information about the array
"""

# Returns size of matrix or image ROI
cvGetSize = cfunc('cvGetSize', _cxDLL, CvSize,
    ('arr', CvArr_r, 1), # const CvArr* arr 
)
cvGetSize.__doc__ = """CvSize cvGetSize(const CvArr arr)

Returns size of matrix or image ROI
"""


#-----------------------------------------------------------------------------
# Copying and Filling
#-----------------------------------------------------------------------------


# Copies one array to another
cvCopy = cfunc('cvCopy', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvCopy.__doc__ = """void cvCopy(const CvArr src, CvArr dst, const CvArr mask=NULL)

Copies one array to another
"""

# Sets every element of array to given value
cvSet = cfunc('cvSet', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr
    ('value', CvScalar, 1), # CvScalar value
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvSet.__doc__ = """void cvSet(CvArr arr, CvScalar value, const CvArr mask=NULL)

Sets every element of array to given value
"""

# Clears the array
cvSetZero = cfunc('cvSetZero', _cxDLL, None,
    ('arr', CvArr_r, 1), # CvArr* arr 
)
cvSetZero.__doc__ = """void cvSetZero(CvArr arr)

Clears the array
"""

cvZero = cvSetZero


#-----------------------------------------------------------------------------
# Manipulating channels
#-----------------------------------------------------------------------------


# Divides multi-channel array into several single-channel arrays or extracts a single channel from the array
cvSplit = cfunc('cvSplit', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst0', CvArr_r, 1, None), # CvArr* dst0
    ('dst1', CvArr_r, 1, None), # CvArr* dst1
    ('dst2', CvArr_r, 1, None), # CvArr* dst2
    ('dst3', CvArr_r, 1, None), # CvArr* dst3
)
cvSplit.__doc__ = """void cvSplit(const CvArr src, CvArr dst0, CvArr dst1, CvArr dst2, CvArr dst3)

Divides multi-channel array into several single-channel arrays or extracts a single channel from the array
"""

# Composes multi-channel array from several single-channel arrays or inserts a single channel into the array
cvMerge = cfunc('cvMerge', _cxDLL, None,
    ('src0', CvArr_r, 1), # const CvArr* src0
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('src3', CvArr_r, 1), # const CvArr* src3
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvMerge.__doc__ = """void cvMerge(const CvArr src0, const CvArr src1, const CvArr src2, const CvArr src3, CvArr dst)

Composes multi-channel array from several single-channel arrays or inserts a single channel into the array
"""

# Copies several channels from input arrays to certain channels of output arrays
_cvMixChannels = cfunc('cvMixChannels', _cxDLL, None,
    ('src', ListPOINTER(CvArr_p), 1), # const CvArr*** src
    ('src_count', c_int, 1), # int src_count
    ('dst', ListPOINTER(CvArr_p), 1), # CvArr*** dst
    ('dst_count', c_int, 1), # int dst_count
    ('from_to', ListPOINTER(c_int), 1), # const int* from_to
    ('pair_count', c_int, 1), # int pair_count
)    

def cvMixChannels(src, dst, from_to):
    """void cvMixChannels(list_or_tuple_of_CvArr_p src, list_or_tuple_of_CvArr_p dst, list_or_tuple_of_int from_to)
    
    Copies several channels from input arrays to certain channels of output arrays
    """
    return _cvMixChannels(src, len(src), dst, len(dst), from_to, len(from_to))


#-----------------------------------------------------------------------------
# Image conversion with scaling
#-----------------------------------------------------------------------------


# Converts one array to another with optional linear transformation
cvConvertScale = cfunc('cvConvertScale', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('scale', c_double, 1, 1), # double scale
    ('shift', c_double, 1, 0), # double shift
)
cvConvertScale.__doc__ = """void cvConvertScale(const CvArr src, CvArr dst, double scale=1, double shift=0)

Converts one array to another with optional linear transformation
"""

cvCvtScale = cvConvertScale

cvScale = cvConvertScale

def cvConvert(src, dst):
    cvConvertScale(src, dst, 1, 0)

# Converts input array elements to 8-bit unsigned integer another with optional linear transformation
cvConvertScaleAbs = cfunc('cvConvertScaleAbs', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('scale', c_double, 1, 1), # double scale
    ('shift', c_double, 1, 0), # double shift
)
cvConvertScaleAbs.__doc__ = """void cvConvertScaleAbs(const CvArr src, CvArr dst, double scale=1, double shift=0)

Converts input array elements to 8-bit unsigned integer another with optional linear transformation
"""

cvCvtScaleAbs = cvConvertScaleAbs


#-----------------------------------------------------------------------------
# Termination Criteria
#-----------------------------------------------------------------------------


# checks termination criteria validity and sets eps to default_eps (if it is not set),
# max_iter to default_max_iters (if it is not set)
cvCheckTermCriteria = cfunc('cvCheckTermCriteria', _cxDLL, CvTermCriteria,
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('default_eps', c_double, 1), # double default_eps
    ('default_max_iters', c_int, 1), # int default_max_iters
)


#-----------------------------------------------------------------------------
# Arithmetic, Logic and Comparison
#-----------------------------------------------------------------------------

# Performs look-up table transform of array
cvLUT = cfunc('cvLUT', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('lut', CvArr_r, 1), # const CvArr* lut 
)
cvLUT.__doc__ = """void cvLUT(const CvArr src, CvArr dst, const CvArr lut)

Performs look-up table transform of array
"""

# Computes per-element sum of two arrays
cvAdd = cfunc('cvAdd', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAdd.__doc__ = """void cvAdd(const CvArr src1, const CvArr src2, CvArr dst, const CvArr mask=NULL)

Computes per-element sum of two arrays
"""

# Computes sum of array and scalar
cvAddS = cfunc('cvAddS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', CvScalar, 1), # CvScalar value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAddS.__doc__ = """void cvAddS(const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL)

Computes sum of array and scalar
"""

# Computes per-element difference between two arrays
cvSub = cfunc('cvSub', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvSub.__doc__ = """void cvSub(const CvArr src1, const CvArr src2, CvArr dst, const CvArr mask=NULL)

Computes per-element difference between two arrays
"""

# Computes difference between array and scalar
def cvSubS(src, value, dst, mask=None):
    """void cvSubS( const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL )

    Computes difference between array and scalar
    """
    # dst(mask) = src(mask) - value = src(mask) + (-value)
    cvAddS(src, cvScalar( -value.val[0], -value.val[1], -value.val[2], -value.val[3]), dst, mask)

# Computes difference between scalar and array
cvSubRS = cfunc('cvSubRS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', CvScalar, 1), # CvScalar value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvSubRS.__doc__ = """void cvSubRS(const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL)

Computes difference between scalar and array
"""

# Calculates per-element product of two arrays
cvMul = cfunc('cvMul', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('scale', c_double, 1, 1), # double scale
)
cvMul.__doc__ = """void cvMul(const CvArr src1, const CvArr src2, CvArr dst, double scale=1)

Calculates per-element product of two arrays
"""

# Performs per-element division of two arrays
cvDiv = cfunc('cvDiv', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('scale', c_double, 1, 1), # double scale
)
cvDiv.__doc__ = """void cvDiv(const CvArr src1, const CvArr src2, CvArr dst, double scale=1)

Performs per-element division of two arrays
"""

# Calculates sum of scaled array and another array
cvScaleAdd = cfunc('cvScaleAdd', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('scale', CvScalar, 1), # CvScalar scale
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst 
)

cvScaleAdd.__doc__ = """void cvScaleAdd(const CvArr src1, CvScalar scale, const CvArr src2, CvArr dst)

Calculates sum of scaled array and another array
"""

# Computes weighted sum of two arrays
cvAddWeighted = cfunc('cvAddWeighted', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('alpha', c_double, 1), # double alpha
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('beta', c_double, 1), # double beta
    ('gamma', c_double, 1), # double gamma
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvAddWeighted.__doc__ = """void cvAddWeighted(const CvArr src1, double alpha, const CvArr src2, double beta, double gamma, CvArr dst)

Computes weighted sum of two arrays
"""

# Calculates dot product of two arrays in Euclidian metrics
cvDotProduct = cfunc('cvDotProduct', _cxDLL, c_double,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2 
)
cvDotProduct.__doc__ = """double cvDotProduct(const CvArr src1, const CvArr src2)

Calculates dot product of two arrays in Euclidian metrics
"""

# Calculates per-element bit-wise conjunction of two arrays
cvAnd = cfunc('cvAnd', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAnd.__doc__ = """void cvAnd(const CvArr src1, const CvArr src2, CvArr dst, const CvArr mask=NULL)

Calculates per-element bit-wise conjunction of two arrays
"""

# Calculates per-element bit-wise conjunction of array and scalar
cvAndS = cfunc('cvAndS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', CvScalar, 1), # CvScalar value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAndS.__doc__ = """void cvAndS(const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL)

Calculates per-element bit-wise conjunction of array and scalar
"""

# Calculates per-element bit-wise disjunction of two arrays
cvOr = cfunc('cvOr', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvOr.__doc__ = """void cvOr(const CvArr src1, const CvArr src2, CvArr dst, const CvArr mask=NULL)

Calculates per-element bit-wise disjunction of two arrays
"""

# Calculates per-element bit-wise disjunction of array and scalar
cvOrS = cfunc('cvOrS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', CvScalar, 1), # CvScalar value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvOrS.__doc__ = """void cvOrS(const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL)

Calculates per-element bit-wise disjunction of array and scalar
"""

# Performs per-element bit-wise "exclusive or" operation on two arrays
cvXor = cfunc('cvXor', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvXor.__doc__ = """void cvXor(const CvArr src1, const CvArr src2, CvArr dst, const CvArr mask=NULL)

Performs per-element bit-wise "exclusive or" operation on two arrays
"""

# Performs per-element bit-wise "exclusive or" operation on array and scalar
cvXorS = cfunc('cvXorS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', CvScalar, 1), # CvScalar value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvXorS.__doc__ = """void cvXorS(const CvArr src, CvScalar value, CvArr dst, const CvArr mask=NULL)

Performs per-element bit-wise "exclusive or" operation on array and scalar
"""

# Performs per-element bit-wise inversion of array elements
cvNot = cfunc('cvNot', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvNot.__doc__ = """void cvNot(const CvArr src, CvArr dst)

Performs per-element bit-wise inversion of array elements
"""

# Checks that array elements lie between elements of two other arrays
cvInRange = cfunc('cvInRange', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('lower', CvArr_r, 1), # const CvArr* lower
    ('upper', CvArr_r, 1), # const CvArr* upper
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvInRange.__doc__ = """void cvInRange(const CvArr src, const CvArr lower, const CvArr upper, CvArr dst)

Checks that array elements lie between elements of two other arrays
"""

# Checks that array elements lie between two scalars
cvInRangeS = cfunc('cvInRangeS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('lower', CvScalar, 1), # CvScalar lower
    ('upper', CvScalar, 1), # CvScalar upper
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvInRangeS.__doc__ = """void cvInRangeS(const CvArr src, CvScalar lower, CvScalar upper, CvArr dst)

Checks that array elements lie between two scalars
"""

CV_CMP_EQ = 0
CV_CMP_GT = 1
CV_CMP_GE = 2
CV_CMP_LT = 3
CV_CMP_LE = 4
CV_CMP_NE = 5

# Performs per-element comparison of two arrays
cvCmp = cfunc('cvCmp', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('cmp_op', c_int, 1), # int cmp_op 
)
cvCmp.__doc__ = """void cvCmp(const CvArr src1, const CvArr src2, CvArr dst, int cmp_op)

Performs per-element comparison of two arrays
"""

# Performs per-element comparison of array and scalar
cvCmpS = cfunc('cvCmpS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', c_double, 1), # double value
    ('dst', CvArr_r, 1), # CvArr* dst
    ('cmp_op', c_int, 1), # int cmp_op 
)
cvCmpS.__doc__ = """void cvCmpS(const CvArr src, double value, CvArr dst, int cmp_op)

Performs per-element comparison of array and scalar
"""

# Finds per-element minimum of two arrays
cvMin = cfunc('cvMin', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvMin.__doc__ = """void cvMin(const CvArr src1, const CvArr src2, CvArr dst)

Finds per-element minimum of two arrays
"""

# Finds per-element maximum of two arrays
cvMax = cfunc('cvMax', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvMax.__doc__ = """void cvMax(const CvArr src1, const CvArr src2, CvArr dst)

Finds per-element maximum of two arrays
"""

# Finds per-element minimum of array and scalar
cvMinS = cfunc('cvMinS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', c_double, 1), # double value
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvMinS.__doc__ = """void cvMinS(const CvArr src, double value, CvArr dst)

Finds per-element minimum of array and scalar
"""

# Finds per-element maximum of array and scalar
cvMaxS = cfunc('cvMaxS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('value', c_double, 1), # double value
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvMaxS.__doc__ = """void cvMaxS(const CvArr src, double value, CvArr dst)

Finds per-element maximum of array and scalar
"""

# Calculates absolute difference between two arrays
cvAbsDiff = cfunc('cvAbsDiff', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvAbsDiff.__doc__ = """void cvAbsDiff(const CvArr src1, const CvArr src2, CvArr dst)

Calculates absolute difference between two arrays
"""

# Calculates absolute difference between array and scalar
cvAbsDiffS = cfunc('cvAbsDiffS', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('value', CvScalar, 1), # CvScalar value 
)
cvAbsDiffS.__doc__ = """void cvAbsDiffS(const CvArr src, CvArr dst, CvScalar value)

Calculates absolute difference between array and scalar
"""

def cvAbs(src, dst):
    """void cvAbs(const CvArr src, CvArr dst)
    
    Calculates absolute value of every element in array
    """
    cvAbsDiffS(src, dst, cvScalar(0))

    
#-----------------------------------------------------------------------------
# Math operations
#-----------------------------------------------------------------------------


# Calculates magnitude and/or angle of 2d vectors
cvCartToPolar = cfunc('cvCartToPolar', _cxDLL, None,
    ('x', CvArr_r, 1), # const CvArr* x
    ('y', CvArr_r, 1), # const CvArr* y
    ('magnitude', CvArr_r, 1), # CvArr* magnitude
    ('angle', CvArr_r, 1, None), # CvArr* angle
    ('angle_in_degrees', c_int, 1, 0), # int angle_in_degrees
)
cvCartToPolar.__doc__ = """void cvCartToPolar(const CvArr x, const CvArr y, CvArr magnitude, CvArr angle=NULL, int angle_in_degrees=0)

Calculates magnitude and/or angle of 2d vectors
"""

# Calculates cartesian coordinates of 2d vectors represented in polar form
cvPolarToCart = cfunc('cvPolarToCart', _cxDLL, None,
    ('magnitude', CvArr_r, 1), # const CvArr* magnitude
    ('angle', CvArr_r, 1), # const CvArr* angle
    ('x', CvArr_r, 1), # CvArr* x
    ('y', CvArr_r, 1), # CvArr* y
    ('angle_in_degrees', c_int, 1, 0), # int angle_in_degrees
)
cvPolarToCart.__doc__ = """void cvPolarToCart(const CvArr magnitude, const CvArr angle, CvArr x, CvArr y, int angle_in_degrees=0)

Calculates cartesian coordinates of 2d vectors represented in polar form
"""

# Raises every array element to power
cvPow = cfunc('cvPow', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('power', c_double, 1), # double power 
)
cvPow.__doc__ = """void cvPow(const CvArr src, CvArr dst, double power)

Raises every array element to power
"""

# Calculates exponent of every array element
cvExp = cfunc('cvExp', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvExp.__doc__ = """void cvExp(const CvArr src, CvArr dst)

Calculates exponent of every array element
"""

# Calculates natural logarithm of every array element absolute value
cvLog = cfunc('cvLog', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvLog.__doc__ = """void cvLog(const CvArr src, CvArr dst)

Calculates natural logarithm of every array element absolute value
"""

# Calculates angle of 2D vector
cvFastArctan = cfunc('cvFastArctan', _cxDLL, c_float,
    ('y', c_float, 1), # float y
    ('x', c_float, 1), # float x 
)
cvFastArctan.__doc__ = """float cvFastArctan(float y, float x)

Calculates angle of 2D vector
"""

# Calculates cubic root
cvCbrt = cfunc('cvCbrt', _cxDLL, c_float,
    ('value', c_float, 1), # float value 
)
cvCbrt.__doc__ = """float cvCbrt(float value)

Calculates cubic root
"""

CV_CHECK_RANGE = 1
CV_CHECK_QUIET = 2

# Checks every element of input array for invalid values
cvCheckArr = cfunc('cvCheckArr', _cxDLL, c_int,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('flags', c_int, 1, 0), # int flags
    ('min_val', c_double, 1, 0), # double min_val
    ('max_val', c_double, 1, 0), # double max_val
)
cvCheckArr.__doc__ = """int cvCheckArr(const CvArr arr, int flags=0, double min_val=0, double max_val=0)

Checks every element of input array for invalid values
"""

cvCheckArray = cvCheckArr

CV_RAND_UNI = 0
CV_RAND_NORMAL = 1

# Fills array with random numbers and updates the RNG state
cvRandArr = cfunc('cvRandArr', _cxDLL, None,
    ('rng', CvRNG_r, 1), # CvRNG* rng
    ('arr', CvArr_r, 1), # CvArr* arr
    ('dist_type', c_int, 1), # int dist_type
    ('param1', CvScalar, 1), # CvScalar param1
    ('param2', CvScalar, 1), # CvScalar param2 
)
cvRandArr.__doc__ = """void cvRandArr(CvRNG rng, CvArr arr, int dist_type, CvScalar param1, CvScalar param2)

Fills array with random numbers and updates the RNG state
"""

# Shuffles the matrix by swapping randomly chosen pairs of the matrix elements on each iteration
cvRandShuffle = cfunc('cvRandShuffle', _cxDLL, None,
    ('mat', CvArr_r, 1), # CvArr* arr
    ('rng', CvRNG_r, 1), # CvRNG* rng
    ('iter_factor', c_double, 1, 1.0), # double iter_factor=1
)
cvRandShuffle.__doc__ = """void cvRandShuffle( CvArr mat, CvRNG rng, double iter_factor=1. )

Shuffles the matrix by swapping randomly chosen pairs of the matrix elements on each iteration
"""

# Finds real roots of a cubic equation
cvSolveCubic = cfunc('cvSolveCubic', _cxDLL, None,
    ('coeffs', CvArr_r, 1), # const CvArr* coeffs
    ('roots', CvArr_r, 1), # CvArr* roots 
)
cvSolveCubic.__doc__ = """void cvSolveCubic(const CvArr coeffs, CvArr roots)

Finds real roots of a cubic equation
"""

if cvVersion == 110:
    # Finds real and complex roots of a polynomial equation with real coefficients
    cvSolvePoly = cfunc('cvSolvePoly', _cxDLL, None,
        ('coeffs', CvArr_r, 1), # const CvArr* coeffs
        ('roots', CvArr_r, 1), # CvArr* roots 
        ('maxiter', c_int, 1, 10), # int maxiter
        ('fig', c_int, 1, 10), # int fig
    )
    
#-----------------------------------------------------------------------------
# Matrix operations
#-----------------------------------------------------------------------------


# Calculates cross product of two 3D vectors
cvCrossProduct = cfunc('cvCrossProduct', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvCrossProduct.__doc__ = """void cvCrossProduct(const CvArr src1, const CvArr src2, CvArr dst)

Calculates cross product of two 3D vectors
"""

CV_GEMM_A_T = 1
CV_GEMM_B_T = 2
CV_GEMM_C_T = 4

# Performs generalized matrix multiplication
cvGEMM = cfunc('cvGEMM', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('alpha', c_double, 1), # double alpha
    ('src3', CvArr_r, 1), # const CvArr* src3
    ('beta', c_double, 1), # double beta
    ('dst', CvArr_r, 1), # CvArr* dst
    ('tABC', c_int, 1, 0), # int tABC
)
cvGEMM.__doc__ = """void cvGEMM(const CvArr src1, const CvArr src2, double alpha, const CvArr src3, double beta, CvArr dst, int tABC=0)

Performs generalized matrix multiplication
"""

cvMatMulAddEx = cvGEMM

def cvMatMulAdd(src1, src2, src3, dst):
    """void cvMatMulAdd(const CvArr src1, const CvArr src2, const CvArr src3, CvArr dst)
    
    Performs dst = src1*src2+src3
    """
    cvGEMM(src1, src2, 1, src3, 1, dst, 0)

def cvMatMul(src1, src2, dst):
    """void cvMatMul(const CvArr src1, const CvArr src2, CvArr dst)
    
    Performs dst = src1*src2
    """
    cvMatMulAdd(src1, src2, 0, dst)

# Performs matrix transform of every array element
cvTransform = cfunc('cvTransform', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('transmat', CvMat_r, 1), # const CvMat* transmat
    ('shiftvec', CvMat_r, 1, None), # const CvMat* shiftvec
)
cvTransform.__doc__ = """void cvTransform(const CvArr src, CvArr dst, const CvMat transmat, const CvMat shiftvec=NULL)

Performs matrix transform of every array element
"""

cvMatMulAddS = cvTransform

# Performs perspective matrix transform of vector array
cvPerspectiveTransform = cfunc('cvPerspectiveTransform', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mat', CvMat_r, 1), # const CvMat* mat 
)
cvPerspectiveTransform.__doc__ = """void cvPerspectiveTransform(const CvArr src, CvArr dst, const CvMat mat)

Performs perspective matrix transform of vector array
"""

# Calculates product of array and transposed array
cvMulTransposed = cfunc('cvMulTransposed', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('order', c_int, 1), # int order
    ('delta', CvArr_r, 1, None), # const CvArr* delta
)
cvMulTransposed.__doc__ = """void cvMulTransposed(const CvArr src, CvArr dst, int order, const CvArr delta=NULL)

Calculates product of array and transposed array
"""

# Transposes matrix
cvTranspose = cfunc('cvTranspose', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvTranspose.__doc__ = """void cvTranspose(const CvArr src, CvArr dst)

Transposes matrix
"""

cvT = cvTranspose

# Flip a 2D array around vertical, horizontall or both axises
cvFlip = cfunc('cvFlip', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1, None), # CvArr* dst
    ('flip_mode', c_int, 1, 0), # int flip_mode
)
cvFlip.__doc__ = """void cvFlip(const CvArr src, CvArr dst=NULL, int flip_mode=0)

Flip a 2D array around vertical, horizontall or both axises
"""

cvMirror = cvFlip

CV_SVD_MODIFY_A = 1
CV_SVD_U_T = 2
CV_SVD_V_T = 4

# Performs singular value decomposition of real floating-point matrix
cvSVD = cfunc('cvSVD', _cxDLL, None,
    ('A', CvArr_r, 1), # CvArr* A
    ('W', CvArr_r, 1), # CvArr* W
    ('U', CvArr_r, 1, None), # CvArr* U
    ('V', CvArr_r, 1, None), # CvArr* V
    ('flags', c_int, 1, 0), # int flags
)
cvSVD.__doc__ = """void cvSVD(CvArr A, CvArr W, CvArr U=NULL, CvArr V=NULL, int flags=0)

Performs singular value decomposition of real floating-point matrix
"""

# Performs singular value back substitution
cvSVBkSb = cfunc('cvSVBkSb', _cxDLL, None,
    ('W', CvArr_r, 1), # const CvArr* W
    ('U', CvArr_r, 1), # const CvArr* U
    ('V', CvArr_r, 1), # const CvArr* V
    ('B', CvArr_r, 1), # const CvArr* B
    ('X', CvArr_r, 1), # CvArr* X
    ('flags', c_int, 1), # int flags 
)
cvSVBkSb.__doc__ = """void cvSVBkSb(const CvArr W, const CvArr U, const CvArr V, const CvArr B, CvArr X, int flags)

Performs singular value back substitution
"""

CV_LU = 0
CV_SVD = 1
CV_SVD_SYM = 2

# Finds inverse or pseudo-inverse of matrix
cvInvert = cfunc('cvInvert', _cxDLL, c_double,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('method', c_int, 1, CV_LU), # int method
)
cvInvert.__doc__ = """double cvInvert(const CvArr src, CvArr dst, int method=CV_LU)

Finds inverse or pseudo-inverse of matrix
"""

cvInv = cvInvert

# Solves linear system or least-squares problem
cvSolve = cfunc('cvSolve', _cxDLL, c_int,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('method', c_int, 1, CV_LU), # int method
)
cvSolve.__doc__ = """int cvSolve(const CvArr src1, const CvArr src2, CvArr dst, int method=CV_LU)

Solves linear system or least-squares problem
"""

# Returns determinant of matrix
cvDet = cfunc('cvDet', _cxDLL, c_double,
    ('mat', CvArr_r, 1), # const CvArr* mat 
)
cvDet.__doc__ = """double cvDet(const CvArr mat)

Returns determinant of matrix
"""

# Returns trace of matrix
cvTrace = cfunc('cvTrace', _cxDLL, CvScalar,
    ('mat', CvArr_r, 1), # const CvArr* mat 
)
cvTrace.__doc__ = """CvScalar cvTrace(const CvArr mat)

Returns trace of matrix
"""

# Computes eigenvalues and eigenvectors of symmetric matrix
cvEigenVV = cfunc('cvEigenVV', _cxDLL, None,
    ('mat', CvArr_r, 1), # CvArr* mat
    ('evects', CvArr_r, 1), # CvArr* evects
    ('evals', CvArr_r, 1), # CvArr* evals
    ('eps', c_double, 1, 0), # double eps
)
cvEigenVV.__doc__ = """void cvEigenVV(CvArr mat, CvArr evects, CvArr evals, double eps=0)

Computes eigenvalues and eigenvectors of symmetric matrix
"""

# Initializes scaled identity matrix
cvSetIdentity = cfunc('cvSetIdentity', _cxDLL, None,
    ('mat', CvArr_r, 1), # CvArr* mat
    ('value', CvScalar, 1, cvRealScalar(1)), # CvScalar value
)
cvSetIdentity.__doc__ = """void cvSetIdentity(CvArr mat, CvScalar value=cvRealScalar(1))

Initializes scaled identity matrix
"""

# Fills matrix with given range of numbers
cvRange = cfunc('cvRange', _cxDLL, None,
    ('mat', CvArr_r, 1), # CvArr* mat
    ('start', c_double, 1), # double start
    ('end', c_double, 1), # double end
)
cvRange.__doc__ = """void cvRange( CvArr mat, double start, double end )

Fills matrix with given range of numbers
"""

CV_COVAR_SCRAMBLED = 0
CV_COVAR_NORMAL = 1
CV_COVAR_USE_AVG = 2
CV_COVAR_SCALE = 4
CV_COVAR_ROWS = 8
CV_COVAR_COLS = 16

# Calculates covariation matrix of the set of vectors
cvCalcCovarMatrix = cfunc('cvCalcCovarMatrix', _cxDLL, None,
    ('vects', c_void_p_p, 1), # const CvArr*** vects
    ('count', c_int, 1), # int count
    ('cov_mat', CvArr_r, 1), # CvArr* cov_mat
    ('avg', CvArr_r, 1), # CvArr* avg
    ('flags', c_int, 1), # int flags 
)
cvCalcCovarMatrix.__doc__ = """void cvCalcCovarMatrix(const CvArr** vects, int count, CvArr cov_mat, CvArr avg, int flags)

Calculates covariation matrix of the set of vectors
"""

CV_PCA_DATA_AS_ROW = 0
CV_PCA_DATA_AS_COL = 1
CV_PCA_USE_AVG = 2

# Performs Principal Component Analysis of a vector set
cvCalcPCA = cfunc('cvCalcPCA', _cxDLL, None,
    ('data', CvArr_r, 1), # CvArr* data
    ('mean', CvArr_r, 1), # CvArr* mean
    ('eigenvalues', CvArr_r, 1), # CvArr* eigenvalues
    ('eigenvectors', CvArr_r, 1), # CvArr* eigenvectors
    ('flags', c_int, 1), # int flags
)
cvCalcPCA.__doc__ = """void cvCalcPCA( const CvArr data, CvArr avg, CvArr eigenvalues, CvArr eigenvectors, int flags )

Performs Principal Component Analysis of a vector set
"""

# Projects vectors to the specified subspace
cvProjectPCA = cfunc('cvProjectPCA', _cxDLL, None,
    ('data', CvArr_r, 1), # CvArr* data
    ('mean', CvArr_r, 1), # CvArr* mean
    ('eigenvectors', CvArr_r, 1), # CvArr* eigenvectors
    ('result', CvArr_r, 1), # CvArr* result
)
cvProjectPCA.__doc__ = """void cvProjectPCA( const CvArr data, const CvArr avg, const CvArr eigenvectors, CvArr result )

Projects vectors to the specified subspace
"""

# Reconstructs the original vectors from the projection coefficients
cvBackProjectPCA = cfunc('cvBackProjectPCA', _cxDLL, None,
    ('proj', CvArr_r, 1), # CvArr* proj
    ('mean', CvArr_r, 1), # CvArr* mean
    ('eigenvectors', CvArr_r, 1), # CvArr* eigenvectors
    ('result', CvArr_r, 1), # CvArr* result
)
cvBackProjectPCA.__doc__ = """void cvBackProjectPCA( const CvArr proj, const CvArr avg, const CvArr eigenvectors, CvArr result )

Reconstructs the original vectors from the projection coefficients
"""

# Calculates Mahalonobis distance between two vectors
cvMahalanobis = cfunc('cvMahalanobis', _cxDLL, c_double,
    ('vec1', CvArr_r, 1), # const CvArr* vec1
    ('vec2', CvArr_r, 1), # const CvArr* vec2
    ('mat', CvArr_r, 1), # CvArr* mat 
)
cvMahalanobis.__doc__ = """double cvMahalanobis(const CvArr vec1, const CvArr vec2, CvArr mat)

Calculates Mahalonobis distance between two vectors
"""

cvMahalonobis = cvMahalanobis

    
#-----------------------------------------------------------------------------
# Array Statistics
#-----------------------------------------------------------------------------


# Summarizes array elements
cvSum = cfunc('cvSum', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr 
)
cvSum.__doc__ = """CvScalar cvSum(const CvArr arr)

Summarizes array elements
"""

# Counts non-zero array elements
cvCountNonZero = cfunc('cvCountNonZero', _cxDLL, c_int,
    ('arr', CvArr_r, 1), # const CvArr* arr 
)
cvCountNonZero.__doc__ = """int cvCountNonZero(const CvArr arr)

Counts non-zero array elements
"""

# Calculates average (mean) of array elements
cvAvg = cfunc('cvAvg', _cxDLL, CvScalar,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAvg.__doc__ = """CvScalar cvAvg(const CvArr arr, const CvArr mask=NULL)

Calculates average (mean) of array elements
"""

# Calculates average (mean) of array elements
cvAvgSdv = cfunc('cvAvgSdv', _cxDLL, None,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('mean', CvScalar_r, 1), # CvScalar* mean
    ('std_dev', CvScalar_r, 1), # CvScalar* std_dev
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAvgSdv.__doc__ = """void cvAvgSdv(const CvArr arr, CvScalar mean, CvScalar std_dev, const CvArr mask=NULL)

Calculates average (mean) of array elements
"""

# Finds global minimum and maximum in array or subarray
_cvMinMaxLoc = cfunc('cvMinMaxLoc', _cxDLL, None,
                    ('arr', CvArr_r, 1),
                    ('min_val', ByRefArg(c_double), 1),
                    ('max_val', ByRefArg(c_double), 1),
                    ('min_loc', CvPoint_r, 1, None),
                    ('max_loc', CvPoint_r, 1, None),
                    ('mask', CvArr_r, 1, None))
                    
# Finds global minimum and maximum in array or subarray
def cvMinMaxLoc(arr, min_val=True, max_val=True, min_loc=None, max_loc=None, mask=None):
    """[double min_val][, double max_val][, CvPoint min_loc][, CvPoint max_loc] = cvMinMaxLoc(const CvArr arr, c_double min_val=True, c_double max_val=True, CvPoint min_loc=None, CvPoint max_loc=None, const CvArr mask=None)

    Finds global minimum and maximum in array or subarray, and their locations
    [ctypes-opencv] Depending on the input arguments, the returning object may be None, a single output argument, or a tuple of output arguments.
    [ctypes-opencv] min_val can be:
        True: returns the minimum value
        an instance of c_double: this holds the minimum value instead
    [ctypes-opencv] max_val can be:
        True: returns the maximum value
        an instance of c_double: this holds the maximum value instead
    [ctypes-opencv] min_loc can be:
        None: the location of the minimum value is not returned
        True: returns the location of the minimum value
        an instance of CvPoint: this holds the location of the minimum value instead
    [ctypes-opencv] max_loc can be:
        None: the location of the maximum value is not returned
        True: returns the location of the maximum value
        an instance of CvPoint: this holds the location of the maximum value instead
    """
    min_val_p = c_double() if min_val is True else min_val
    max_val_p = c_double() if max_val is True else max_val
    min_loc_p = CvPoint() if min_loc is True else min_loc
    max_loc_p = CvPoint() if max_loc is True else max_loc
    
    _cvMinMaxLoc(arr, min_val=min_val_p, max_val=max_val_p, min_loc=min_loc_p, max_loc=max_loc_p, mask=mask)
    
    res = []
    if min_val is True:
        res.append(min_val_p.value)
    if max_val is True:
        res.append(max_val_p.value)
    if min_loc is True:
        res.append(min_loc_p)
    if max_loc is True:
        res.append(max_loc_p)
        
    if len(res) > 1:
        return tuple(res)
    if len(res) == 1:
        return res[0]

CV_C = 1
CV_L1 = 2
CV_L2 = 4
CV_NORM_MASK = 7
CV_RELATIVE = 8
CV_DIFF = 16
CV_MINMAX = 32
CV_DIFF_C = (CV_DIFF | CV_C)
CV_DIFF_L1 = (CV_DIFF | CV_L1)
CV_DIFF_L2 = (CV_DIFF | CV_L2)
CV_RELATIVE_C = (CV_RELATIVE | CV_C)
CV_RELATIVE_L1 = (CV_RELATIVE | CV_L1)
CV_RELATIVE_L2 = (CV_RELATIVE | CV_L2)

# Calculates absolute array norm, absolute difference norm or relative difference norm
cvNorm = cfunc('cvNorm', _cxDLL, c_double,
    ('arr1', CvArr_r, 1), # const CvArr* arr1
    ('arr2', CvArr_r, 1, None), # const CvArr* arr2
    ('norm_type', c_int, 1, CV_L2), # int norm_type
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvNorm.__doc__ = """double cvNorm(const CvArr arr1, const CvArr arr2=NULL, int norm_type=CV_L2, const CvArr mask=NULL)

Calculates absolute array norm, absolute difference norm or relative difference norm
"""

# Normalizes array to a certain norm or value range
cvNormalize = cfunc('cvNormalize', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # const CvArr* dst
    ('a', c_double, 1, 1), # double a
    ('b', c_double, 1, 0), # double b
    ('norm_type', c_int, 1, CV_L2), # int norm_type
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvNormalize.__doc__ = """void cvNormalize( const CvArr src, CvArr dst, double a=1, double b=0, int norm_type=CV_L2, const CvArr mask=NULL )

Normalizes array to a certain norm or value range
"""

CV_REDUCE_SUM = 0
CV_REDUCE_AVG = 1
CV_REDUCE_MAX = 2
CV_REDUCE_MIN = 3

# Reduces matrix to a vector
cvReduce = cfunc('cvReduce', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # const CvArr* dst
    ('op', c_int, 1, CV_REDUCE_SUM), # int op
)
cvReduce.__doc__ = """void cvReduce( const CvArr src, CvArr dst, int op=CV_REDUCE_SUM )

Reduces matrix to a vector
"""

    
#-----------------------------------------------------------------------------
# Discrete Linear Transforms and Related Functions
#-----------------------------------------------------------------------------


# Performs forward or inverse Discrete Fourier transform of 1D or 2D floating-point array
CV_DXT_FORWARD = 0
CV_DXT_INVERSE = 1
CV_DXT_SCALE = 2     # divide result by size of array
CV_DXT_INV_SCALE = CV_DXT_SCALE | CV_DXT_INVERSE
CV_DXT_INVERSE_SCALE = CV_DXT_INV_SCALE
CV_DXT_ROWS = 4     # transfor each row individually
CV_DXT_MUL_CONJ = 8     # conjugate the second argument of cvMulSpectrums

# Performs forward or inverse Discrete Fourier transform of 1D or 2D floating-point array
cvDFT = cfunc('cvDFT', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('flags', c_int, 1), # int flags
    ('nonzero_rows', c_int, 1, 0), # int nonzero_rows
)
cvDFT.__doc__ = """void cvDFT( const CvArr src, CvArr dst, int flags, int nonzero_rows=0 )

Performs forward or inverse Discrete Fourier transform of 1D or 2D floating-point array
"""

cvFFT = cvDFT

# Performs per-element multiplication of two Fourier spectrums
cvMulSpectrums = cfunc('cvMulSpectrums', _cxDLL, None,
    ('src1', CvArr_r, 1), # const CvArr* src1
    ('src2', CvArr_r, 1), # const CvArr* src2
    ('dst', CvArr_r, 1), # CvArr* dst
    ('flags', c_int, 1), # int flags 
)
cvMulSpectrums.__doc__ = """void cvMulSpectrums(const CvArr src1, const CvArr src2, CvArr dst, int flags)

Performs per-element multiplication of two Fourier spectrums
"""

# Returns optimal DFT size for given vector size
cvGetOptimalDFTSize = cfunc('cvGetOptimalDFTSize', _cxDLL, c_int,
    ('size0', c_int, 1), # int size0 
)
cvGetOptimalDFTSize.__doc__ = """int cvGetOptimalDFTSize(int size0)

Returns optimal DFT size for given vector size
"""

# Performs forward or inverse Discrete Cosine transform of 1D or 2D floating-point array
cvDCT = cfunc('cvDCT', _cxDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('flags', c_int, 1), # int flags 
)
cvDCT.__doc__ = """void cvDCT( const CvArr src, CvArr dst, int flags )

Performs forward or inverse Discrete Cosine transform of 1D or 2D floating-point array
"""

    
#-----------------------------------------------------------------------------
# Dynamic Data Structure: Memory Storages
#-----------------------------------------------------------------------------


# Releases memory storage
_cvReleaseMemStorage = cfunc('cvReleaseMemStorage', _cxDLL, None,
    ('storage', ByRefArg(CvMemStorage_p), 1), # CvMemStorage** storage 
)

# Creates memory storage
_cvCreateMemStorage = cfunc('cvCreateMemStorage', _cxDLL, CvMemStorage_p,
    ('block_size', c_int, 1, 0), # int block_size
)

def cvCreateMemStorage(block_size=0):
    """CvMemStorage cvCreateMemStorage(int block_size=0)

    Creates memory storage
    """
    return pointee(_cvCreateMemStorage(block_size))

# Creates child memory storage
_cvCreateChildMemStorage = cfunc('cvCreateChildMemStorage', _cxDLL, CvMemStorage_p,
    ('parent', CvMemStorage_r, 1), # CvMemStorage* parent 
)

def cvCreateChildMemStorage(parent):
    """CvMemStorage cvCreateChildMemStorage(CvMemStorage parent)

    Creates child memory storage
    """
    return pointee(_cvCreateChildMemStorage(parent), parent)

# Clears memory storage
cvClearMemStorage = cfunc('cvClearMemStorage', _cxDLL, None,
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)
cvClearMemStorage.__doc__ = """void cvClearMemStorage(CvMemStorage storage)

Clears memory storage
"""

# Saves memory storage position
cvSaveMemStoragePos = cfunc('cvSaveMemStoragePos', _cxDLL, None,
    ('storage', CvMemStorage_r, 1), # const CvMemStorage* storage
    ('pos', CvMemStoragePos_r, 1), # CvMemStoragePos* pos 
)
cvSaveMemStoragePos.__doc__ = """void cvSaveMemStoragePos(const CvMemStorage storage, CvMemStoragePos pos)

Saves memory storage position
"""

# Restores memory storage position
cvRestoreMemStoragePos = cfunc('cvRestoreMemStoragePos', _cxDLL, None,
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('pos', CvMemStoragePos_r, 1), # CvMemStoragePos* pos 
)
cvRestoreMemStoragePos.__doc__ = """void cvRestoreMemStoragePos(CvMemStorage storage, CvMemStoragePos pos)

Restores memory storage position
"""

# Allocates memory buffer in the storage
cvMemStorageAlloc = cfunc('cvMemStorageAlloc', _cxDLL, c_void_p,
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('size', c_ulong, 1), # size_t size 
)
cvMemStorageAlloc.__doc__ = """void* cvMemStorageAlloc(CvMemStorage storage, size_t size)

Allocates memory buffer in the storage
"""

# Allocates text string in the storage
cvMemStorageAllocString = cfunc('cvMemStorageAllocString', _cxDLL, CvString,
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('ptr', c_char_p, 1), # const char* ptr
    ('len', c_int, 1, -1), # int len
)
cvMemStorageAllocString.__doc__ = """CvString cvMemStorageAllocString(CvMemStorage storage, const char* ptr, int len=-1)

Allocates text string in the storage
"""

    
#-----------------------------------------------------------------------------
# Dynamic Data Structure: Sequences
#-----------------------------------------------------------------------------


# Calculates the sequence slice length
cvSliceLength = cfunc('cvSliceLength', _cxDLL, c_int,
    ('slice', CvSlice, 1), # CvSlice slice
    ('seq', CvSeq_r, 1), # const CvSeq* seq
)
cvSliceLength.__doc__ = """int cvSliceLength( CvSlice slice, const CvSeq seq )

Calculates the sequence slice length
"""

# Creates sequence
_cvCreateSeq = cfunc('cvCreateSeq', _cxDLL, CvSeq_p,
    ('seq_flags', c_int, 1), # int seq_flags
    ('header_size', c_int, 1), # int header_size
    ('elem_size', c_int, 1), # int elem_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)

def cvCreateSeq(seq_flags, header_size, elem_size, storage):
    """CvSeq cvCreateSeq(int seq_flags, int header_size, int elem_size, CvMemStorage storage)

    Creates sequence
    """
    return pointee(_cvCreateSeq(seq_flags, header_size, elem_size, storage), storage)

# Sets up sequence block size
cvSetSeqBlockSize = cfunc('cvSetSeqBlockSize', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('delta_elems', c_int, 1), # int delta_elems 
)
cvSetSeqBlockSize.__doc__ = """void cvSetSeqBlockSize(CvSeq seq, int delta_elems)

Sets up sequence block size
"""

# Adds element to sequence end
cvSeqPush = cfunc('cvSeqPush', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('element', c_void_p, 1, None), # void* element
)
cvSeqPush.__doc__ = """char* cvSeqPush(CvSeq seq, void* element=NULL)

Adds element to sequence end
"""

# Adds element to sequence beginning
cvSeqPushFront = cfunc('cvSeqPushFront', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('element', c_void_p, 1, None), # void* element
)
cvSeqPushFront.__doc__ = """char* cvSeqPushFront(CvSeq seq, void* element=NULL)

Adds element to sequence beginning
"""

# Removes element from sequence end
cvSeqPop = cfunc('cvSeqPop', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('element', c_void_p, 1, None), # void* element
)
cvSeqPop.__doc__ = """void cvSeqPop(CvSeq seq, void* element=NULL)

Removes element from sequence end
"""

# Removes element from sequence beginning
cvSeqPopFront = cfunc('cvSeqPopFront', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('element', c_void_p, 1, None), # void* element
)
cvSeqPopFront.__doc__ = """void cvSeqPopFront(CvSeq seq, void* element=NULL)

Removes element from sequence beginning
"""

CV_FRONT = 1
CV_BACK = 0

# Pushes several elements to the either end of sequence
cvSeqPushMulti = cfunc('cvSeqPushMulti', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('elements', c_void_p, 1), # void* elements
    ('count', c_int, 1), # int count
    ('in_front', c_int, 1, 0), # int in_front
)
cvSeqPushMulti.__doc__ = """void cvSeqPushMulti(CvSeq seq, void* elements, int count, int in_front=0)

Pushes several elements to the either end of sequence
"""

# Removes several elements from the either end of sequence
cvSeqPopMulti = cfunc('cvSeqPopMulti', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('elements', c_void_p, 1), # void* elements
    ('count', c_int, 1), # int count
    ('in_front', c_int, 1, 0), # int in_front
)
cvSeqPopMulti.__doc__ = """void cvSeqPopMulti(CvSeq seq, void* elements, int count, int in_front=0)

Removes several elements from the either end of sequence
"""

# Inserts element in sequence middle
cvSeqInsert = cfunc('cvSeqInsert', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('before_index', c_int, 1), # int before_index
    ('element', c_void_p, 1, None), # void* element
)
cvSeqInsert.__doc__ = """char* cvSeqInsert(CvSeq seq, int before_index, void* element=NULL)

Inserts element in sequence middle
"""

# Removes element from sequence middle
cvSeqRemove = cfunc('cvSeqRemove', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('index', c_int, 1), # int index 
)
cvSeqRemove.__doc__ = """void cvSeqRemove(CvSeq seq, int index)

Removes element from sequence middle
"""

# Clears sequence
cvClearSeq = cfunc('cvClearSeq', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq 
)
cvClearSeq.__doc__ = """void cvClearSeq(CvSeq seq)

Clears sequence
"""

# Returns POINTER to sequence element by its index
cvGetSeqElem = cfunc('cvGetSeqElem', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('index', c_int, 1), # int index 
)
cvGetSeqElem.__doc__ = """char* cvGetSeqElem(const CvSeq seq, int index)

Returns POINTER to sequence element by its index
"""

def CV_GET_SEQ_ELEM(TYPE, seq, index):
    result = cvGetSeqElem(seq, index)
    return cast(result, POINTER(TYPE))

# Returns index of concrete sequence element
_cvSeqElemIdx = cfunc('cvSeqElemIdx', _cxDLL, c_int,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('element', c_void_p, 1), # const void* element
    ('block', ByRefArg(CvSeqBlock_p), 1, None), # CvSeqBlock** block
)

# Returns index of concrete sequence element
def cvSeqElemIdx(seq, element, block_ptr=None):
    """int index[, CvSeqBlock block] = cvSeqElemIdx(const CvSeq seq, const void* element, CvSeqBlock_p block_ptr=None)

    Returns index of concrete sequence element
    [ctypes-opencv] block_ptr can be:
        None: the associated block is not returned
        True: returns the associated block
        an instance of CvSeqBlock_p: this holds the address of the associated block instead
    """
    if block_ptr is not True:
        return _cvSeqElemIdx(seq, element, block_ptr)
    block_ptr = CvSeqBlock_p()
    return (_cvSeqElemIdx(seq, element, block_ptr), pointee(block_ptr, seq))

# Initializes process of writing data to sequence
_cvStartAppendToSeq = cfunc('cvStartAppendToSeq', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('writer', CvSeqWriter_r, 1), # CvSeqWriter* writer 
)

def cvStartAppendToSeq(seq, writer=None):
    """CvSeqWriter cvStartAppendToSeq(CvSeq seq, CvSeqWriter writer=None)

    Initializes process of writing data to sequence
    [ctypes-opencv] If 'writer' is None, it is internally created. In any case, 'writer' is returned.
    """
    if writer is None:
        writer = CvSeqWriter()
    _cvStartAppendToSeq(seq, writer)
    writer._depends = (seq,)
    return writer

# Creates new sequence and initializes writer for it
_cvStartWriteSeq = cfunc('cvStartWriteSeq', _cxDLL, None,
    ('seq_flags', c_int, 1), # int seq_flags
    ('header_size', c_int, 1), # int header_size
    ('elem_size', c_int, 1), # int elem_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('writer', CvSeqWriter_r, 1), # CvSeqWriter* writer 
)

def cvStartWriteSeq(seq_flags, header_size, elem_size, storage, writer=None):
    """CvSeqWriter cvStartWriteSeq(int seq_flags, int header_size, int elem_size, CvMemStorage storage, CvSeqWriter writer=None)

    Creates new sequence and initializes writer for it
    [ctypes-opencv] If 'writer' is None, it is internally created. In any case, 'writer' is returned.
    """
    if writer is None:
        writer = CvSeqWriter()
    _cvStartWriteSeq(seq_flags, header_size, elem_size, storage, writer)
    writer._depends = (storage,) # to make sure storage is always deleted after writer is deleted
    return writer
    

# Finishes process of writing sequence
_cvEndWriteSeq = cfunc('cvEndWriteSeq', _cxDLL, CvSeq_p,
    ('writer', CvSeqWriter_r, 1), # CvSeqWriter* writer 
)

def cvEndWriteSeq(writer):
    """CvSeq cvEndWriteSeq(CvSeqWriter writer)

    Finishes process of writing sequence
    """
    return pointee(_cvEndWriteSeq(writer), *writer._depends)

# Updates sequence headers from the writer state
cvFlushSeqWriter = cfunc('cvFlushSeqWriter', _cxDLL, None,
    ('writer', CvSeqWriter_r, 1), # CvSeqWriter* writer 
)
cvFlushSeqWriter.__doc__ = """void cvFlushSeqWriter(CvSeqWriter writer)

Updates sequence headers from the writer state
"""

# Initializes process of sequential reading from sequence
_cvStartReadSeq = cfunc('cvStartReadSeq', _cxDLL, None,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('reader', CvSeqReader_r, 1), # CvSeqReader* reader
    ('reverse', c_int, 1, 0), # int reverse
)

def cvStartReadSeq(seq, reader=None, reverse=0):
    """CvSeqReader cvStartReadSeq(const CvSeq seq, CvSeqReader reader=None, int reverse=0)

    Initializes process of sequential reading from sequence
    [ctypes-opencv] If 'reader' is None, it is internally created. In any case, 'reader' is returned.
    """
    if reader is None:
        reader = CvSeqReader()
    _cvStartReadSeq(seq, reader, reverse)
    reader._depends = (seq,)
    return reader

# Returns the current reader position
cvGetSeqReaderPos = cfunc('cvGetSeqReaderPos', _cxDLL, c_int,
    ('reader', CvSeqReader_r, 1), # CvSeqReader* reader 
)
cvGetSeqReaderPos.__doc__ = """int cvGetSeqReaderPos(CvSeqReader reader)

Returns the current reader position
"""

# Moves the reader to specified position
cvSetSeqReaderPos = cfunc('cvSetSeqReaderPos', _cxDLL, None,
    ('reader', CvSeqReader_r, 1), # CvSeqReader* reader
    ('index', c_int, 1), # int index
    ('is_relative', c_int, 1, 0), # int is_relative
)
cvSetSeqReaderPos.__doc__ = """void cvSetSeqReaderPos(CvSeqReader reader, int index, int is_relative=0)

Moves the reader to specified position
"""

# Copies sequence to one continuous block of memory
cvCvtSeqToArray = cfunc('cvCvtSeqToArray', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('elements', c_void_p, 1), # void* elements
    ('slice', CvSlice, 1, CV_WHOLE_SEQ), # CvSlice slice
)
cvCvtSeqToArray.__doc__ = """void* cvCvtSeqToArray(const CvSeq seq, void* elements, CvSlice slice=CV_WHOLE_SEQ)

Copies sequence to one continuous block of memory
"""

# Constructs sequence from array
_cvMakeSeqHeaderForArray = cfunc('cvMakeSeqHeaderForArray', _cxDLL, CvSeq_p,
    ('seq_type', c_int, 1), # int seq_type
    ('header_size', c_int, 1), # int header_size
    ('elem_size', c_int, 1), # int elem_size
    ('elements', c_void_p, 1), # void* elements
    ('total', c_int, 1), # int total
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('block', CvSeqBlock_r, 1), # CvSeqBlock* block 
)

def cvMakeSeqHeaderForArray(seq_type, header_size, elem_size, elements, total, seq, block):
    """CvSeq cvMakeSeqHeaderForArray(int seq_type, int header_size, int elem_size, void* elements, int total, CvSeq seq, CvSeqBlock block)

    Constructs sequence from array
    [ctypes-opencv] If 'seq' is None, it is internally created.
    """
    if seq is None:
        seq = CvSeq()
    _cvMakeSeqHeaderForArray(seq_type, header_size, elem_size, elements, total, seq, block)
    seq._depends = (elements,)
    return seq

# Makes separate header for the sequence slice
_cvSeqSlice = cfunc('cvSeqSlice', _cxDLL, CvSeq_p,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('slice', CvSlice, 1), # CvSlice slice
    ('storage', CvMemStorage_r, 1, None), # CvMemStorage* storage
    ('copy_data', c_int, 1, 0), # int copy_data
)

def cvSeqSlice(seq, slice, storage=None, copy_data=0):
    """CvSeq cvSeqSlice(const CvSeq seq, CvSlice slice, CvMemStorage storage=NULL, int copy_data=0)

    Makes separate header for the sequence slice
    """
    z = CvSeq()
    _cvSeqSlice(seq, slice, storage=storage, copy_data=copy_data)
    if storage is not None:
        z._depends = (storage,)
    return z

# Creates a copy of sequence
def cvCloneSeq(seq, storage=None):
    """CvSeq cvCloneSeq( const CvSeq seq, CvMemStorage storage=NULL )

    Creates a copy of sequence
    """
    return cvSeqSlice(seq, CV_WHOLE_SEQ, storage, 1)

# Removes sequence slice
cvSeqRemoveSlice = cfunc('cvSeqRemoveSlice', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('slice', CvSlice, 1), # CvSlice slice 
)
cvSeqRemoveSlice.__doc__ = """void cvSeqRemoveSlice(CvSeq seq, CvSlice slice)

Removes sequence slice
"""

# Inserts array in the middle of sequence
cvSeqInsertSlice = cfunc('cvSeqInsertSlice', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('before_index', c_int, 1), # int before_index
    ('from_arr', CvArr_r, 1), # const CvArr* from_arr 
)
cvSeqInsertSlice.__doc__ = """void cvSeqInsertSlice(CvSeq seq, int before_index, const CvArr from_arr)

Inserts array in the middle of sequence
"""

# a < b ? -1 : a > b ? 1 : 0
CvCmpFunc = CFUNCTYPE(c_int, # int
    c_void_p, # const void* a
    c_void_p, # const void* b
    c_void_p) # void* userdata

# Sorts sequence element using the specified comparison function
cvSeqSort = cfunc('cvSeqSort', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('func', CvCmpFunc, 1), # CvCmpFunc func
    ('userdata', c_void_p, 1, None), # void* userdata
)
cvSeqSort.__doc__ = """void cvSeqSort(CvSeq seq, CvCmpFunc func, void* userdata=NULL)

Sorts sequence element using the specified comparison function
"""

# Searches element in sequence
cvSeqSearch = cfunc('cvSeqSearch', _cxDLL, c_void_p,
    ('seq', CvSeq_r, 1), # CvSeq* seq
    ('elem', c_void_p, 1), # const void* elem
    ('func', CvCmpFunc, 1), # CvCmpFunc func
    ('is_sorted', c_int, 1), # int is_sorted
    ('elem_idx', c_int_p, 1), # int* elem_idx
    ('userdata', c_void_p, 1, None), # void* userdata
)
cvSeqSearch.__doc__ = """char* cvSeqSearch(CvSeq seq, const void* elem, CvCmpFunc func, int is_sorted, int* elem_idx, void* userdata=NULL)

Searches element in sequence
"""

# Reverses the order of sequence elements
cvSeqInvert = cfunc('cvSeqInvert', _cxDLL, None,
    ('seq', CvSeq_r, 1), # CvSeq* seq 
)
cvSeqInvert.__doc__ = """void cvSeqInvert(CvSeq seq)

Reverses the order of sequence elements
"""

# Splits sequence into equivalency classes
cvSeqPartition = cfunc('cvSeqPartition', _cxDLL, c_int,
    ('seq', CvSeq_r, 1), # const CvSeq* seq
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('labels', POINTER(CvSeq_p), 1), # CvSeq** labels
    ('is_equal', CvCmpFunc, 1), # CvCmpFunc is_equal
    ('userdata', c_void_p, 1), # void* userdata 
)
cvSeqPartition.__doc__ = """int cvSeqPartition(const CvSeq seq, CvMemStorage storage, CvSeq** labels, CvCmpFunc is_equal, void* userdata)

Splits sequence into equivalency classes
"""

    
#-----------------------------------------------------------------------------
# Dynamic Data Structure: Sets
#-----------------------------------------------------------------------------


# Creates empty set
_cvCreateSet = cfunc('cvCreateSet', _cxDLL, CvSet_p,
    ('set_flags', c_int, 1), # int set_flags
    ('header_size', c_int, 1), # int header_size
    ('elem_size', c_int, 1), # int elem_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)

def cvCreateSet(set_flags, header_size, elem_size, storage):
    """CvSet cvCreateSet(int set_flags, int header_size, int elem_size, CvMemStorage storage)

    Creates empty set
    """
    return pointee(_cvCreateSet(set_flags, header_size, elem_size, storage), storage)

# Occupies a node in the set
_cvSetAdd = cfunc('cvSetAdd', _cxDLL, c_int,
    ('set_header', CvSet_r, 1), # CvSet* set_header
    ('elem', CvSetElem_r, 1, None), # CvSetElem* elem
    ('inserted_elem', ByRefArg(CvSetElem_p), 1, None), # CvSetElem** inserted_elem
)

# Occupies a node in the set
def cvSetAdd(set_header, elem=None, inserted_elem_ptr=None):
    """int[, CvSetElem inserted_elem] = cvSetAdd(CvSet set_header, CvSetElem elem=None, CvSetElem_p inserted_elem_ptr=None)

    Occupies a node in the set
    [ctypes-opencv] inserted_elem_ptr can be:
        None: the inserted element is not returned
        True: returns the inserted element
        an instance of CvSetElem_p: this holds the address of the inserted element instead
    """
    if not inserted_elem_ptr is True:
        return _cvSetAdd(set_header, elem=elem, inserted_elem=inserted_elem_ptr)
    z = CvSetElem_p()
    return (_cvSetAdd(set_header, elem=elem, inserted_elem=z), pointee(z, set_header))

# Adds element to set (fast variant)
def cvSetNew(set_header):
    """CvSetElem cvSetNew( CvSet set_header )
    
    Adds element to set (fast variant)
    [ctypes-opencv] Warning: I have not tested this function.
    [ctypes-opencv] returns None if not successful
    """
    elem = set_header.free_elems
    if elem:
        set_header.free_elems = elem[0].next_free
        elem[0].flags &= CV_SET_ELEM_IDX_MASK
        set_header.active_count += 1
    else:
        cvSetAdd( set_header, None, elem )
    return pointee(elem)

# Removes set element given its pointer
def cvSetRemoveByPtr(set_header, elem):
    """void cvSetRemoveByPtr( CvSet set_header, CvSetElem elem )
    
    Removes set element given its pointer
    [ctypes-opencv] Warning: I have not tested this function.
    """
    assert elem.flags >= 0
    elem.next_free = set_header.free_elems
    elem.flags = (elem.flags & CV_SET_ELEM_IDX_MASK) | CV_SET_ELEM_FREE_FLAG
    set_header.free_elems = pointer(elem)
    set_header.active_count -= 1
    
# Removes element from set
cvSetRemove = cfunc('cvSetRemove', _cxDLL, None,
    ('set_header', CvSet_r, 1), # CvSet* set_header
    ('index', c_int, 1), # int index 
)
cvSetRemove.__doc__ = """void cvSetRemove(CvSet set_header, int index)

Removes element from set
"""

# Returns a set element by index. If the element doesn't belong to the set, NULL is returned
def cvGetSetElem(set_header, index):
    """CvSetElem cvGetSetElem( const CvSet set_header, int index )
    
    Returns a set element by index. If the element doesn't belong to the set, NULL is returned
    [ctypes-opencv] Warning: I have not tested this function.
    """
    elem = cvGetSeqElem(set_header, index)
    return pointee(cast(elem, POINTER(CvSetElem)), set_header) if bool(elem) and CV_IS_SET_ELEM( elem ) else None

    
# Clears set
cvClearSet = cfunc('cvClearSet', _cxDLL, None,
    ('set_header', CvSet_r, 1), # CvSet* set_header 
)
cvClearSet.__doc__ = """void cvClearSet(CvSet set_header)

Clears set
"""

    
#-----------------------------------------------------------------------------
# Dynamic Data Structure: Graphs
#-----------------------------------------------------------------------------


# Creates empty graph
_cvCreateGraph = cfunc('cvCreateGraph', _cxDLL, CvGraph_p,
    ('graph_flags', c_int, 1), # int graph_flags
    ('header_size', c_int, 1), # int header_size
    ('vtx_size', c_int, 1), # int vtx_size
    ('edge_size', c_int, 1), # int edge_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)

def cvCreateGraph(graph_flags, header_size, vtx_size, edge_size, storage):
    """CvGraph cvCreateGraph(int graph_flags, int header_size, int vtx_size, int edge_size, CvMemStorage storage)

    Creates empty graph
    """
    return pointee(_cvCreateGraph(graph_flags, header_size, vtx_size, edge_size, storage), storage)

# Adds vertex to graph
_cvGraphAddVtx = cfunc('cvGraphAddVtx', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('vtx', CvGraphVtx_r, 1, None), # const CvGraphVtx* vtx
    ('inserted_vtx', ByRefArg(CvGraphVtx_p), 1, None), # CvGraphVtx** inserted_vtx
)

# Adds vertex to graph
def cvGraphAddVtx(graph, vtx=None, inserted_vtx_ptr=None):
    """int[, CvGraphVtx inserted_vtx] = cvGraphAddVtx(CvGraph graph, const CvGraphVtx vtx=None, CvGraphVtx_p inserted_vtx_ptr=None)

    Adds vertex to graph
    [ctypes-opencv] inserted_vtx_ptr can be:
        None: the inserted vertex is not returned
        True: returns the inserted vertex
        an instance of CvGraphVtx_p: this holds the address of the inserted vertex instead
    """
    if inserted_vtx_ptr is not True:
        return _cvGraphAddVtx(graph, vtx=vtx, inserted_vtx=inserted_vtx_ptr)
    z = CvGraphVtx_p()
    return (_cvGraphAddVtx(graph, vtx=vtx, inserted_vtx=z), pointee(z, graph))

# Removes vertex from graph
cvGraphRemoveVtx = cfunc('cvGraphRemoveVtx', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('index', c_int, 1), # int index 
)
cvGraphRemoveVtx.__doc__ = """int cvGraphRemoveVtx(CvGraph graph, int index)

Removes vertex from graph
"""

# Removes vertex from graph
cvGraphRemoveVtxByPtr = cfunc('cvGraphRemoveVtxByPtr', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('vtx', CvGraphVtx_r, 1), # CvGraphVtx* vtx 
)
cvGraphRemoveVtxByPtr.__doc__ = """int cvGraphRemoveVtxByPtr(CvGraph graph, CvGraphVtx vtx)

Removes vertex from graph
"""

# Adds edge to graph
_cvGraphAddEdge = cfunc('cvGraphAddEdge', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('start_idx', c_int, 1), # int start_idx
    ('end_idx', c_int, 1), # int end_idx
    ('edge', CvGraphEdge_r, 1, None), # const CvGraphEdge* edge
    ('inserted_edge', ByRefArg(CvGraphEdge_p), 1, None), # CvGraphEdge** inserted_edge
)

# Adds edge to graph
def cvGraphAddEdge(graph, start_idx, end_idx, edge=None, inserted_edge_ptr=None):
    """int[, CvGraphEdge inserted_edge] = cvGraphAddEdge(CvGraph graph, int start_idx, int end_idx, const CvGraphEdge edge=None, CvGraphEdge_p inserted_edge_ptr=None)

    Adds edge to graph
    [ctypes-opencv] inserted_edge_ptr can be:
        None: the inserted edge is not returned
        True: returns the inserted edge
        an instance of CvGraphEdge_p: this holds the address of the inserted edge instead
    """
    if inserted_edge_ptr is not True:
        return _cvGraphAddEdge(graph, start_idx, end_idx, edge=edge, inserted_edge=inserted_edge_ptr)
    z = CvGraphEdge_p()
    return (_cvGraphAddEdge(graph, start_idx, end_idx, edge=edge, inserted_edge=z), pointee(z, graph))

# Adds edge to graph by pointer
_cvGraphAddEdgeByPtr = cfunc('cvGraphAddEdgeByPtr', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('start_vtx', CvGraphVtx_r, 1), # CvGraphVtx* start_vtx
    ('end_vtx', CvGraphVtx_r, 1), # CvGraphVtx* end_vtx
    ('edge', CvGraphEdge_r, 1, None), # const CvGraphEdge* edge
    ('inserted_edge', ByRefArg(CvGraphEdge_p), 1, None), # CvGraphEdge** inserted_edge
)

# Adds edge to graph by pointer
def cvGraphAddEdgeByPtr(graph, start_vtx, end_vtx, edge=None, inserted_edge_ptr=None):
    """int[, CvGraphEdge inserted_edge] = cvGraphAddEdgeByPtr(CvGraph graph, CvGraphVtx start_vtx, CvGraphVtx end_vtx, const CvGraphEdge edge=None, CvGraphEdge_p inserted_edge_ptr=None)

    Adds edge to graph by pointer
    [ctypes-opencv] inserted_edge_ptr can be:
        None: the inserted edge is not returned
        True: returns the inserted edge
        an instance of CvGraphEdge_p: this holds the address of the inserted edge instead
    """
    if inserted_edge_ptr is not True:
        return _cvGraphAddEdgeByPtr(graph, start_vtx, end_vtx, edge=edge, inserted_edge=inserted_edge_ptr)
    z = CvGraphEdge_p()
    return (_cvGraphAddEdgeByPtr(graph, start_vtx, end_vtx, edge=edge, inserted_edge=z), pointee(z, graph))

# Removes edge from graph
cvGraphRemoveEdge = cfunc('cvGraphRemoveEdge', _cxDLL, None,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('start_idx', c_int, 1), # int start_idx
    ('end_idx', c_int, 1), # int end_idx 
)
cvGraphRemoveEdge.__doc__ = """void cvGraphRemoveEdge(CvGraph graph, int start_idx, int end_idx)

Removes edge from graph
"""

# Removes edge from graph
cvGraphRemoveEdgeByPtr = cfunc('cvGraphRemoveEdgeByPtr', _cxDLL, None,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('start_vtx', CvGraphVtx_r, 1), # CvGraphVtx* start_vtx
    ('end_vtx', CvGraphVtx_r, 1), # CvGraphVtx* end_vtx 
)
cvGraphRemoveEdgeByPtr.__doc__ = """void cvGraphRemoveEdgeByPtr(CvGraph graph, CvGraphVtx start_vtx, CvGraphVtx end_vtx)

Removes edge from graph
"""

# Finds edge in graph
_cvFindGraphEdge = cfunc('cvFindGraphEdge', _cxDLL, CvGraphEdge_p,
    ('graph', CvGraph_r, 1), # const CvGraph* graph
    ('start_idx', c_int, 1), # int start_idx
    ('end_idx', c_int, 1), # int end_idx 
)

def cvFindGraphEdge(graph, start_idx, end_idx):
    """CvGraphEdge cvFindGraphEdge(const CvGraph graph, int start_idx, int end_idx)

    Finds edge in graph
    [ctypes-opencv] returns None if no edge is found
    """
    return pointee(_cvFindGraphEdge(graph, start_idx, end_idx), graph)

cvGraphFindEdge = cvFindGraphEdge

# Finds edge in graph
_cvFindGraphEdgeByPtr = cfunc('cvFindGraphEdgeByPtr', _cxDLL, CvGraphEdge_p,
    ('graph', CvGraph_r, 1), # const CvGraph* graph
    ('start_vtx', CvGraphVtx_r, 1), # const CvGraphVtx* start_vtx
    ('end_vtx', CvGraphVtx_r, 1), # const CvGraphVtx* end_vtx 
)

def cvFindGraphEdgeByPtr(graph, start_vtx, end_vtx):
    """CvGraphEdge cvFindGraphEdgeByPtr(const CvGraph graph, const CvGraphVtx start_vtx, const CvGraphVtx end_vtx)

    Finds edge in graph
    [ctypes-opencv] returns None if no edge is found
    """
    return pointee(_cvFindGraphEdgeByPtr(graph, start_vtx, end_vtx), graph)

cvGraphFindEdgeByPtr = cvFindGraphEdgeByPtr

# Counts edges indicent to the vertex
cvGraphVtxDegree = cfunc('cvGraphVtxDegree', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # const CvGraph* graph
    ('vtx_idx', c_int, 1), # int vtx_idx 
)
cvGraphVtxDegree.__doc__ = """int cvGraphVtxDegree(const CvGraph graph, int vtx_idx)

Counts edges indicent to the vertex
"""

# Finds edge in graph
cvGraphVtxDegreeByPtr = cfunc('cvGraphVtxDegreeByPtr', _cxDLL, c_int,
    ('graph', CvGraph_r, 1), # const CvGraph* graph
    ('vtx', CvGraphVtx_r, 1), # const CvGraphVtx* vtx 
)
cvGraphVtxDegreeByPtr.__doc__ = """int cvGraphVtxDegreeByPtr(const CvGraph graph, const CvGraphVtx vtx)

Finds edge in graph
"""

# Retrieves graph vertex by given index
def cvGetGraphVtx(graph, idx):
    """CvGraphVtx cvGetGraphVtx( CvGraph graph, int vtx_idx )
    
    Retrieves graph vertex by given index
    [ctypes-opencv] returns None if no CvGraphVtx is found
    """
    return pointee(cast(cvGetSetElem(graph, idx), POINTER(CvGraphVtx)), graph)

# Retrieves index of a graph vertex given its pointer
def cvGraphVtxIdx(graph, vtx):
    """int cvGraphVtxIdx( CvGraph graph, CvGraphVtx vtx )
    
    Retrieves index of a graph vertex given its pointer
    """
    return vtx.flags & CV_SET_ELEM_IDX_MASK

# Returns index of graph edge
def GraphEdgeIdx(graph, edge):
    """int cvGraphEdgeIdx( CvGraph graph, CvGraphEdge edge )
    
    Returns index of graph edge
    """
    return edge.flags & CV_SET_ELEM_IDX_MASK

def cvGraphGetVtxCount(graph):
    """int cvGraphGetVtxCount(CvGraph graph)
    
    Returns the number of vertices of the graph
    """
    return graph.active_count

def cvGraphGetEdgeCount(graph):
    """int cvGraphGetEdgeCount(CvGraph graph)
    
    Returns the number of edges of the graph
    """
    return graph.edges[0].active_count

CV_GRAPH_VERTEX = 1
CV_GRAPH_TREE_EDGE = 2
CV_GRAPH_BACK_EDGE = 4
CV_GRAPH_FORWARD_EDGE = 8
CV_GRAPH_CROSS_EDGE = 16
CV_GRAPH_ANY_EDGE = 30
CV_GRAPH_NEW_TREE = 32
CV_GRAPH_BACKTRACKING = 64
CV_GRAPH_OVER = -1
CV_GRAPH_ALL_ITEMS = -1
CV_GRAPH_ITEM_VISITED_FLAG = 1 << 30

def CV_IS_GRAPH_VERTEX_VISITED(vtx):
    """bool CV_IS_GRAPH_VERTEX_VISITED(CvGraphVtx vtx)
    
    Returns whether a vertex is visited
    """
    return bool(vtx.flags & CV_GRAPH_ITEM_VISITED_FLAG)

def CV_IS_GRAPH_EDGE_VISITED(edge):
    """bool CV_IS_GRAPH_EDGE_VISITED(CvGraphEdge edge)
    
    Returns whether an edge is visited
    """
    return bool(edge.flags & CV_GRAPH_ITEM_VISITED_FLAG)

CV_GRAPH_SEARCH_TREE_NODE_FLAG = 1 << 29
CV_GRAPH_FORWARD_EDGE_FLAG = 1 << 28
    
# Clears graph
cvClearGraph = cfunc('cvClearGraph', _cxDLL, None,
    ('graph', CvGraph_r, 1), # CvGraph* graph 
)
cvClearGraph.__doc__ = """void cvClearGraph(CvGraph graph)

Clears graph
"""

# Clone graph
_cvCloneGraph = cfunc('cvCloneGraph', _cxDLL, CvGraph_p,
    ('graph', CvGraph_r, 1), # const CvGraph* graph
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)

def cvCloneGraph(graph, storage):
    """CvGraph cvCloneGraph(const CvGraph graph, CvMemStorage storage)

    Clone graph
    """
    return pointee(_cvCloneGraph(graph, storage), storage)

# -------- Functions dealing with CvGraphScanner --------


# Finishes graph traversal procedure
_cvReleaseGraphScanner = cfunc('cvReleaseGraphScanner', _cxDLL, None,
    ('scanner', ByRefArg(CvGraphScanner_p), 1), # CvGraphScanner** scanner 
)

_cvCreateGraphScanner = cfunc('cvCreateGraphScanner', _cxDLL, CvGraphScanner_p,
    ('graph', CvGraph_r, 1), # CvGraph* graph
    ('vtx', CvGraphVtx_r, 1, None), # CvGraphVtx* vtx
    ('mask', c_int, 1, CV_GRAPH_ALL_ITEMS), # int mask
)

# Creates structure for depth-first graph traversal
def cvCreateGraphScanner(graph, vtx=None, mask=CV_GRAPH_ALL_ITEMS):
    """CvGraphScanner cvCreateGraphScanner(CvGraph graph, CvGraphVtx vtx=NULL, int mask=CV_GRAPH_ALL_ITEMS)

    Creates structure for depth-first graph traversal
    """
    return pointee(_cvCreateGraphScanner(graph, vtx, mask), graph)

# Makes one or more steps of the graph traversal procedure
cvNextGraphItem = cfunc('cvNextGraphItem', _cxDLL, c_int,
    ('scanner', CvGraphScanner_r, 1), # CvGraphScanner* scanner 
)
cvNextGraphItem.__doc__ = """int cvNextGraphItem(CvGraphScanner scanner)

Makes one or more steps of the graph traversal procedure
"""

    
#-----------------------------------------------------------------------------
# Dynamic Data Structure: Trees
#-----------------------------------------------------------------------------


class CvTreeNodeIterator(_Structure):
    _fields_ = [
        ('node', c_void_p),
        ('level', c_int),
        ('max_level', c_int),
    ]
CvTreeNodeIterator_p = POINTER(CvTreeNodeIterator)
CvTreeNodeIterator_r = ByRefArg(CvTreeNodeIterator)

# Initializes tree node iterator
_cvInitTreeNodeIterator = cfunc('cvInitTreeNodeIterator', _cxDLL, None,
    ('tree_iterator', CvTreeNodeIterator_r, 1), # CvTreeNodeIterator* tree_iterator
    ('first', c_void_p, 1), # const void* first
    ('max_level', c_int, 1), # int max_level 
)

def cvInitTreeNodeIterator(tree_iterator, first, max_level):
    """CvTreeNodeIterator cvInitTreeNodeIterator(const void* first, int max_level)

    Initializes tree node iterator
    [ctypes-opencv] If 'tree_iterator' is None, it is internally created.
    """
    if tree_iterator is None:
        tree_iterator = CvTreeNodeIterator()
    _cvInitTreeNodeIterator(tree_iterator, first, max_level)
    tree_iterator._depends = (first,)
    return tree_iterator

# Returns the currently observed node and moves iterator toward the next node
cvNextTreeNode = cfunc('cvNextTreeNode', _cxDLL, c_void_p,
    ('tree_iterator', CvTreeNodeIterator_r, 1), # CvTreeNodeIterator* tree_iterator 
)
cvNextTreeNode.__doc__ = """void* cvNextTreeNode(CvTreeNodeIterator tree_iterator)

Returns the currently observed node and moves iterator toward the next node
"""

# Returns the currently observed node and moves iterator toward the previous node
cvPrevTreeNode = cfunc('cvPrevTreeNode', _cxDLL, c_void_p,
    ('tree_iterator', CvTreeNodeIterator_r, 1), # CvTreeNodeIterator* tree_iterator 
)
cvPrevTreeNode.__doc__ = """void* cvPrevTreeNode(CvTreeNodeIterator tree_iterator)

Returns the currently observed node and moves iterator toward the previous node
"""

# Gathers all node pointers to the single sequence
_cvTreeToNodeSeq = cfunc('cvTreeToNodeSeq', _cxDLL, CvSeq_p,
    ('first', c_void_p, 1), # const void* first
    ('header_size', c_int, 1), # int header_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage 
)

def cvTreeToNodeSeq(first, header_size, storage):
    """CvSeq cvTreeToNodeSeq(const void* first, int header_size, CvMemStorage storage)

    Gathers all node pointers to the single sequence
    """
    return pointee(_cvTreeNodeSeq(first, header_size, storage), storage)

# Adds new node to the tree
cvInsertNodeIntoTree = cfunc('cvInsertNodeIntoTree', _cxDLL, None,
    ('node', c_void_p, 1), # void* node
    ('parent', c_void_p, 1), # void* parent
    ('frame', c_void_p, 1), # void* frame 
)
cvInsertNodeIntoTree.__doc__ = """void cvInsertNodeIntoTree(void* node, void* parent, void* frame)

Adds new node to the tree
"""

# Removes node from tree
cvRemoveNodeFromTree = cfunc('cvRemoveNodeFromTree', _cxDLL, None,
    ('node', c_void_p, 1), # void* node
    ('frame', c_void_p, 1), # void* frame 
)
cvRemoveNodeFromTree.__doc__ = """void cvRemoveNodeFromTree(void* node, void* frame)

Removes node from tree
"""

    
#-----------------------------------------------------------------------------
# Drawing Functions: Curves and Shapes
#-----------------------------------------------------------------------------


CV_FILLED = -1
CV_AA = 16

# Constructs a color value
def CV_RGB(r, g, b):
    return CvScalar(b, g, r)

# Draws a line segment connecting two points
cvLine = cfunc('cvLine', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('pt1', CvPoint, 1), # CvPoint pt1
    ('pt2', CvPoint, 1), # CvPoint pt2
    ('color', CvScalar, 1), # CvScalar color
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)
cvLine.__doc__ = """void cvLine(CvArr img, CvPoint pt1, CvPoint pt2, CvScalar color, int thickness=1, int line_type=8, int shift=0)

Draws a line segment connecting two points
"""

# Draws simple, thick or filled rectangle
cvRectangle = cfunc('cvRectangle', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('pt1', CvPoint, 1), # CvPoint pt1
    ('pt2', CvPoint, 1), # CvPoint pt2
    ('color', CvScalar, 1), # CvScalar color
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)
cvRectangle.__doc__ = """void cvRectangle(CvArr img, CvPoint pt1, CvPoint pt2, CvScalar color, int thickness=1, int line_type=8, int shift=0)

Draws simple, thick or filled rectangle
"""

# Draws a circle
cvCircle = cfunc('cvCircle', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('center', CvPoint, 1), # CvPoint center
    ('radius', c_int, 1), # int radius
    ('color', CvScalar, 1), # CvScalar color
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)
cvCircle.__doc__ = """void cvCircle(CvArr img, CvPoint center, int radius, CvScalar color, int thickness=1, int line_type=8, int shift=0)

Draws a circle
"""

# Draws simple or thick elliptic arc or fills ellipse sector
cvEllipse = cfunc('cvEllipse', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('center', CvPoint, 1), # CvPoint center
    ('axes', CvSize, 1), # CvSize axes
    ('angle', c_double, 1), # double angle
    ('start_angle', c_double, 1), # double start_angle
    ('end_angle', c_double, 1), # double end_angle
    ('color', CvScalar, 1), # CvScalar color
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)
cvEllipse.__doc__ = """void cvEllipse(CvArr img, CvPoint center, CvSize axes, double angle, double start_angle, double end_angle, CvScalar color, int thickness=1, int line_type=8, int shift=0)

Draws simple or thick elliptic arc or fills ellipse sector
"""

def cvEllipseBox(img, box, color, thickness=1, line_type=8, shift=0):
    """void cvEllipseBox( CvArr img, CvBox2D box, CvScalar color, int thickness=1, int line_type=8, int shift=0 )
    
    Draws simple or thick elliptic arc or fills ellipse sector
    """
    cvEllipse(img, CvPoint(int(box.center.x), int(box.center.y)),
              CvSize(int(box.size.height*0.5),int(box.size.width*0.5)),
              box.angle, 0, 360, color, thickness, line_type, shift)


# Fills polygons interior
_cvFillPoly = cfunc('cvFillPoly', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('pts', ListPOINTER2(CvPoint), 1), # CvPoint** pts
    ('npts', ListPOINTER(c_int), 1), # int* npts
    ('contours', c_int, 1), # int contours
    ('color', CvScalar, 1), # CvScalar color
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)

def cvFillPoly(img, pts, color, line_type=8, shift=0):
    """void cvFillPoly(CvArr img, list_of_list_of_CvPoint pts, CvScalar color, int line_type=8, int shift=0)

    Fills polygons interior
    """
    _cvFillPoly(img, pts, [len(x) for x in pts], len(pts), color, line_type, shift)

# Fills convex polygon
_cvFillConvexPoly = cfunc('cvFillConvexPoly', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('pts', ListPOINTER(CvPoint), 1), # CvPoint* pts
    ('npts', c_int, 1), # int npts
    ('color', CvScalar, 1), # CvScalar color
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)

def cvFillConvexPoly(img, pts, color, line_type=8, shift=0):
    """void cvFillConvexPoly(CvArr img, list_or_tuple_of_CvPoint pts, CvScalar color, int line_type=8, int shift=0)

    Fills convex polygon
    """
    _cvFillConvexPoly(img, pts, len(pts), color, line_type, shift)

# Draws simple or thick polygons
_cvPolyLine = cfunc('cvPolyLine', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('pts', ListPOINTER2(CvPoint), 1), # CvPoint** pts
    ('npts', ListPOINTER(c_int), 1), # int* npts
    ('contours', c_int, 1), # int contours
    ('is_closed', c_int, 1), # int is_closed
    ('color', CvScalar, 1), # CvScalar color
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('shift', c_int, 1, 0), # int shift
)

def cvPolyLine(img, pts, is_closed, color, thickness=1, line_type=8, shift=0):
    """void cvPolyLine(CvArr img, list_of_list_of_CvPoint pts, int is_closed, CvScalar color, int thickness=1, int line_type=8, int shift=0)

    Draws simple or thick polygons
    """
    _cvPolyLine(img, pts, [len(x) for x in pts], len(pts), is_closed, color, thickness, line_type, shift)

cvDrawRect = cvRectangle
cvDrawLine = cvLine
cvDrawCircle = cvCircle
cvDrawEllipse = cvEllipse
cvDrawPolyLine = cvPolyLine

    
#-----------------------------------------------------------------------------
# Drawing Functions: Text
#-----------------------------------------------------------------------------


CV_FONT_HERSHEY_SIMPLEX = 0
CV_FONT_HERSHEY_PLAIN = 1
CV_FONT_HERSHEY_DUPLEX = 2
CV_FONT_HERSHEY_COMPLEX = 3
CV_FONT_HERSHEY_TRIPLEX = 4
CV_FONT_HERSHEY_COMPLEX_SMALL = 5
CV_FONT_HERSHEY_SCRIPT_SIMPLEX = 6
CV_FONT_HERSHEY_SCRIPT_COMPLEX = 7
CV_FONT_ITALIC = 16
CV_FONT_VECTOR0 = CV_FONT_HERSHEY_SIMPLEX

# Font
class CvFont(_Structure):
    _fields_ = [("font_face", c_int),
                ("ascii", c_int_p),
                ("greek", c_int_p),
                ("cyrillic", c_int_p),
                ("hscale", c_float),
                ("vscale", c_float),
                ("shear", c_float),
                ("thickness", c_int),
                ("dx", c_float),
                ("line_type", c_int)]
CvFont_p = POINTER(CvFont)
CvFont_r = ByRefArg(CvFont)
                
# Initializes font structure
_cvInitFont = cfunc('cvInitFont', _cxDLL, None,
    ('font', CvFont_r, 1), # CvFont* font
    ('font_face', c_int, 1), # int font_face
    ('hscale', c_double, 1), # double hscale
    ('vscale', c_double, 1), # double vscale
    ('shear', c_double, 1, 0), # double shear
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
)

def cvInitFont(font, font_face, hscale, vscale, shear=0, thickness=1, line_type=8):
    """CvFont cvInitFont(CvFont font, int font_face, double hscale, double vscale, double shear=0, int thickness=1, int line_type=8)

    Initializes font structure
    [ctypes-opencv] If 'font' is None, it is internally created.
    """
    if font is None:
        font = CvFont()
    _cvInitFont(font, font_face, hscale, vscale, shear, thickness, line_type)
    return font

def cvFont(scale, thickness=1):
    """CvFont cvFont( double scale, int thickness=1)
    
    Returns a CV_FONT_HERSHEY_PLAIN font with given scale and thickness
    """
    return cvInitFont(None, CV_FONT_HERSHEY_PLAIN, scale, scale, 0, thickness, CV_AA)
                
# Draws text string
cvPutText = cfunc('cvPutText', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('text', c_char_p, 1), # const char* text
    ('org', CvPoint, 1), # CvPoint org
    ('font', CvFont_r, 1), # const CvFont* font
    ('color', CvScalar, 1), # CvScalar color 
)
cvPutText.__doc__ = """void cvPutText(CvArr img, const char* text, CvPoint org, const CvFont font, CvScalar color)

Draws text string
"""

# Retrieves width and height of text string
cvGetTextSize = cfunc('cvGetTextSize', _cxDLL, None,
    ('text_string', c_char_p, 1), # const char* text_string
    ('font', CvFont_r, 1), # const CvFont* font
    ('text_size', CvSize_p, 2), # CvSize* text_size
    ('baseline', POINTER(c_int), 2), # int* baseline 
)
cvGetTextSize.__doc__ = """(CvSize text_size, int baseline) = cvGetTextSize(const char* text_string, const CvFont font, CvSize text_size, int* baseline)

Retrieves width and height of text string
"""

    
#-----------------------------------------------------------------------------
# Drawing Functions: Point Sets and Contours
#-----------------------------------------------------------------------------


# Draws contour outlines or interiors in the image
cvDrawContours = cfunc('cvDrawContours', _cxDLL, None,
    ('img', CvArr_r, 1), # CvArr* img
    ('contour', CvSeq_r, 1), # CvSeq* contour
    ('external_color', CvScalar, 1), # CvScalar external_color
    ('hole_color', CvScalar, 1), # CvScalar hole_color
    ('max_level', c_int, 1), # int max_level
    ('thickness', c_int, 1, 1), # int thickness
    ('line_type', c_int, 1, 8), # int line_type
    ('offset', CvPoint, 1, CvPoint(0,0)), # CvPoint offset      
)
cvDrawContours.__doc__ = """void cvDrawContours(CvArr img, CvSeq contour, CvScalar external_color, CvScalar hole_color, int max_level, int thickness=1, int line_type=8, CvPoint offset=CV_DEFAULT(cvPoint(0,0)))

Draws contour outlines or interiors in the image
"""

# Initializes line iterator
_cvInitLineIterator = cfunc('cvInitLineIterator', _cxDLL, c_int,
    ('image', CvArr_r, 1), # const CvArr* image
    ('pt1', CvPoint, 1), # CvPoint pt1
    ('pt2', CvPoint, 1), # CvPoint pt2
    ('line_iterator', CvLineIterator_r, 1), # CvLineIterator* line_iterator
    ('connectivity', c_int, 1, 8), # int connectivity
    ('left_to_right', c_int, 1, 0), # int left_to_right
)

def cvInitLineIterator(image, pt1, pt2, line_iterator=None, connectivity=8, left_to_right=0):
    """(int, CvLineIterator) cvInitLineIterator(const CvArr image, CvPoint pt1, CvPoint pt2, CvLineIterator line_iterator=None, int connectivity=8, int left_to_right=0)

    Initializes line iterator
    [ctypes-opencv] If 'line_iterator' is None, it is internally created.
    """
    if line_iterator is None:
        line_iterator = CvLineIterator()
    _cvInitLineIterator(image, pt1, pt2, line_iterator, connectivity, left_to_right)
    line_iterator._depends = (image,)
    return line_iterator

# Moves iterator to the next line point
def CV_NEXT_LINE_POINT(line_iterator):
    """void CV_NEXT_LINE_POINT(CvLineIerator line_iterator)
    
    Moves iterator to the next line point
    [ctypes-opencv] Warning: I haven't tested this function.
    """
    mask = -1 if line_iterator.err < 0 else 0
    line_iterator.err += line_iterator.minus_delta + (line_iterator.plus_delta & mask)
    line_iterator.ptr = _ptr_add(line_iterator.ptr, line_iterator.minus_step + (line_iterator.plus_step & mask))

# Clips the line against the image rectangle
cvClipLine = cfunc('cvClipLine', _cxDLL, c_int,
    ('img_size', CvSize, 1), # CvSize img_size
    ('pt1', CvPoint_r, 1), # CvPoint* pt1
    ('pt2', CvPoint_r, 1), # CvPoint* pt2 
)
cvClipLine.__doc__ = """int cvClipLine(CvSize img_size, CvPoint pt1, CvPoint pt2)

Clips the line against the image rectangle
"""

# Approximates elliptic arc with polyline
cvEllipse2Poly = cfunc('cvEllipse2Poly', _cxDLL, c_int,
    ('center', CvPoint, 1), # CvPoint center
    ('axes', CvSize, 1), # CvSize axes
    ('angle', c_int, 1), # int angle
    ('arc_start', c_int, 1), # int arc_start
    ('arc_end', c_int, 1), # int arc_end
    ('pts', CvPoint_r, 1), # CvPoint* pts
    ('delta', c_int, 1), # int delta 
)
cvEllipse2Poly.__doc__ = """int cvEllipse2Poly(CvPoint center, CvSize axes, int angle, int arc_start, int arc_end, CvPoint pts, int delta)

Approximates elliptic arc with polyline
"""

    
#-----------------------------------------------------------------------------
# Data Persistence and RTTI: File Storage
#-----------------------------------------------------------------------------


# Opens file storage for reading or writing data
_cvOpenFileStorage = cfunc('cvOpenFileStorage', _cxDLL, CvFileStorage_p,
    ('filename', c_char_p, 1), # const char* filename
    ('memstorage', CvMemStorage_r, 1), # CvMemStorage* memstorage
    ('flags', c_int, 1), # int flags 
)

def cvOpenFileStorage(filename, memstorage, flags):
    """CvFileStorage cvOpenFileStorage(const char* filename, CvMemStorage memstorage, int flags)

    Opens file storage for reading or writing data
    [ctypes-opencv] returns None if no file storage is opened
    """
    return pointee(_cvOpenFileStorage(filename, memstorage, flags), memstorage)

# Releases file storage
_cvReleaseFileStorage = cfunc('cvReleaseFileStorage', _cxDLL, None,
    ('fs', ByRefArg(CvFileStorage_p), 1), # CvFileStorage** fs 
)
_cvReleaseFileStorage.__doc__ = """void cvReleaseFileStorage(CvFileStorage** fs)

Releases file storage
"""

cvAttrValue = cfunc('cvAttrValue', _cxDLL, c_char_p,
    ('attr', CvAttrList_r, 1), # const CvAttrList* attr
    ('attr_name', c_char_p, 1), # const char* attr_name
)
cvAttrValue.__doc__ = """const char* cvAttrValue( const CvAttrList attr, const char* attr_name )

Returns attribute value or 0 (NULL) if there is no such attribute
"""
   
    
#-----------------------------------------------------------------------------
# Data Persistence and RTTI: Writing Data
#-----------------------------------------------------------------------------


# Starts writing a new structure
cvStartWriteStruct = cfunc('cvStartWriteStruct', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('struct_flags', c_int, 1), # int struct_flags
    ('type_name', c_char_p, 1, None), # const char* type_name
    ('attributes', CvAttrList, 1, cvAttrList()), # CvAttrList attributes
)
cvStartWriteStruct.__doc__ = """void cvStartWriteStruct(CvFileStorage fs, const char* name, int struct_flags, const char* type_name=NULL, CvAttrList attributes=cvAttrList())

Starts writing a new structure
"""

# Ends writing a structure
cvEndWriteStruct = cfunc('cvEndWriteStruct', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs 
)
cvEndWriteStruct.__doc__ = """void cvEndWriteStruct(CvFileStorage fs)

Ends writing a structure
"""

# Writes an integer value
cvWriteInt = cfunc('cvWriteInt', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('value', c_int, 1), # int value 
)
cvWriteInt.__doc__ = """void cvWriteInt(CvFileStorage fs, const char* name, int value)

Writes an integer value
"""

# Writes a floating-point value
cvWriteReal = cfunc('cvWriteReal', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('value', c_double, 1), # double value 
)
cvWriteReal.__doc__ = """void cvWriteReal(CvFileStorage fs, const char* name, double value)

Writes a floating-point value
"""

# Writes a text string
cvWriteString = cfunc('cvWriteString', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('str', c_char_p, 1), # const char* str
    ('quote', c_int, 1, 0), # int quote
)
cvWriteString.__doc__ = """void cvWriteString(CvFileStorage fs, const char* name, const char* str, int quote=0)

Writes a text string
"""

# Writes comment
cvWriteComment = cfunc('cvWriteComment', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('comment', c_char_p, 1), # const char* comment
    ('eol_comment', c_int, 1), # int eol_comment 
)
cvWriteComment.__doc__ = """void cvWriteComment(CvFileStorage fs, const char* comment, int eol_comment)

Writes comment
"""

# Starts the next stream
cvStartNextStream = cfunc('cvStartNextStream', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs 
)
cvStartNextStream.__doc__ = """void cvStartNextStream(CvFileStorage fs)

Starts the next stream
"""

# Writes user object
cvWrite = cfunc('cvWrite', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('ptr', c_void_p, 1), # const void* ptr
    ('attributes', CvAttrList, 1, cvAttrList()), # CvAttrList attributes
)
cvWrite.__doc__ = """void cvWrite(CvFileStorage fs, const char* name, const void* ptr, CvAttrList attributes=cvAttrList())

Writes user object
"""

# Writes multiple numbers
cvWriteRawData = cfunc('cvWriteRawData', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('src', c_void_p, 1), # const void* src
    ('len', c_int, 1), # int len
    ('dt', c_char_p, 1), # const char* dt 
)
cvWriteRawData.__doc__ = """void cvWriteRawData(CvFileStorage fs, const void* src, int len, const char* dt)

Writes multiple numbers
"""

# Writes file node to another file storage
cvWriteFileNode = cfunc('cvWriteFileNode', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('new_node_name', c_char_p, 1), # const char* new_node_name
    ('node', CvFileNode_r, 1), # const CvFileNode* node
    ('embed', c_int, 1), # int embed 
)
cvWriteFileNode.__doc__ = """void cvWriteFileNode(CvFileStorage fs, const char* new_node_name, CvFileNode node, int embed)

Writes file node to another file storage
"""
   
    
#-----------------------------------------------------------------------------
# Data Persistence and RTTI: Reading Data
#-----------------------------------------------------------------------------


# Retrieves one of top-level nodes of the file storage
_cvGetRootFileNode = cfunc('cvGetRootFileNode', _cxDLL, CvFileNode_p,
    ('fs', CvFileStorage_r, 1), # const CvFileStorage* fs
    ('stream_index', c_int, 1, 0), # int stream_index
)

def cvGetRootFileNode(fs, stream_index=0):
    """CvFileNode cvGetRootFileNode(const CvFileStorage fs, int stream_index=0)

    Retrieves one of top-level nodes of the file storage
    [ctypes-opencv] returns None if no root file node is found
    """
    return pointee(_cvGetRootFileNode(fs, stream_index), fs)

# Finds node in the map or file storage
_cvGetFileNodeByName = cfunc('cvGetFileNodeByName', _cxDLL, CvFileNode_p,
    ('fs', CvFileStorage_r, 1), # const CvFileStorage* fs
    ('map', CvFileNode_r, 1), # const CvFileNode* map
    ('name', c_char_p, 1), # const char* name 
)

def cvGetFileNodeByName(fs, map, name):
    """CvFileNode cvGetFileNodeByName(const CvFileStorage fs, const CvFileNode map, const char* name)

    Finds node in the map or file storage
    [ctypes-opencv] returns None if no file node is found
    """
    return pointee(_cvGetFileNodeByName(fs, map, name), fs, map)

# Returns a unique POINTER for given name
_cvGetHashedKey = cfunc('cvGetHashedKey', _cxDLL, CvStringHashNode_p,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('name', c_char_p, 1), # const char* name
    ('len', c_int, 1, -1), # int len
    ('create_missing', c_int, 1, 0), # int create_missing
)

def cvGetHashedKey(fs, name, len=-1, create_missing=0):
    """CvStringHashNode cvGetHashedKey(CvFileStorage fs, const char* name, int len=-1, int create_missing=0)

    Returns a unique POINTER for given name
    [ctypes-opencv] returns None if no string hash node is found
    """
    return pointee(_cvGetHashedKey(fs, name, len, create_missing), fs)

# Finds node in the map or file storage
_cvGetFileNode = cfunc('cvGetFileNode', _cxDLL, CvFileNode_p,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('map', CvFileNode_r, 1), # CvFileNode* map
    ('key', CvStringHashNode_r, 1), # const CvStringHashNode* key
    ('create_missing', c_int, 1, 0), # int create_missing
)

def cvGetFileNode(fs, map, key, create_missing=0):
    """CvFileNode cvGetFileNode(CvFileStorage fs, CvFileNode map, const CvStringHashNode key, int create_missing=0)

    Finds node in the map or file storage
    [ctypes-opencv] returns None if no file node is found
    """
    return pointee(_cvGetFileNode(fs, map, key, create_missing), fs, map)

# Returns name of file node
cvGetFileNodeName = cfunc('cvGetFileNodeName', _cxDLL, c_char_p,
    ('node', CvFileNode_r, 1), # const CvFileNode* node 
)
cvGetFileNodeName.__doc__ = """const char* cvGetFileNodeName(CvFileNode node)

Returns name of file node
"""

# Retrieves integer value from file node
def cvReadInt(node, default_value=0):
    """int cvReadInt( const CvFileNode node, int default_value=0)
    
    Retrieves integer value from file node
    """
    if node is None:
        return default_value
    if CV_NODE_IS_INT(node.tag):
        return node.data.i
    return cvRound(node.data.f) if CV_NODE_IS_REAL(node.tag) else 0x7fffffff

# Finds file node and returns its value
def cvReadIntByName(fs, map, name, default_value=0):
    """int cvReadIntByName( const CvFileStorage fs, const CvFileNode map, const char* name, int default_value=0)
    
    Finds file node and returns its value
    """
    return cvReadInt( cvGetFileNodeByName( fs, map, name ), default_value )

# Retrieves floating-point value from file node
def cvReadReal(node, default_value=0.0):
    """double cvReadReal( const CvFileNode node, double default_value=0.0)
    
    Retrieves floating-point value from file node
    """
    if node is None:
        return default_value
    if CV_NODE_IS_INT(node.tag):
        return float(node.data.i)
    return node.data.f if CV_NODE_IS_REAL(node.tag) else 1e300

# Finds file node and returns its value
def cvReadRealByName(fs, map, name, default_value=0.0):
    """double cvReadRealByName( const CvFileStorage fs, const CvFileNode map, const char* name, double default_value=0.0)
    
    Finds file node and returns its value
    """
    return cvReadReal( cvGetFileNodeByName( fs, map, name ), default_value )

# Retrieves text string from file node
def cvReadString(node, default_value=None):
    """const char* cvReadString( const CvFileNode node, const char* default_value=NULL)
    
    Retrieves text string from file node
    """
    if node is None:
        return default_value
    return node.data.str.ptr if CV_NODE_IS_STRING(node.tag) else None

# Finds file node and returns its value
def cvReadStringByName(fs, map, name, default_value=None):
    """const char* cvReadStringByName( const CvFileStorage fs, const CvFileNode map, const char* name, const char* default_value CV_DEFAULT(NULL) )
    
    Finds file node and returns its value
    """
    return cvReadString( cvGetFileNodeByName( fs, map, name ), default_value )


# Decodes object and returns POINTER to it
cvRead = cfunc('cvRead', _cxDLL, c_void_p,
    ('fs', CvFileStorage_r, 1), # CvFileStorage* fs
    ('node', CvFileNode_r, 1), # CvFileNode* node
    ('attributes', CvAttrList_r, 1, None), # CvAttrList* attributes
)
cvRead.__doc__ = """void* cvRead(CvFileStorage fs, CvFileNode node, CvAttrList attributes=NULL)

Decodes object and returns POINTER to it
"""

# Reads multiple numbers
cvReadRawData = cfunc('cvReadRawData', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # const CvFileStorage* fs
    ('src', CvFileNode_r, 1), # const CvFileNode* src
    ('dst', c_void_p, 1), # void* dst
    ('dt', c_char_p, 1), # const char* dt 
)
cvReadRawData.__doc__ = """void cvReadRawData(const CvFileStorage fs, const CvFileNode src, void* dst, const char* dt)

Reads multiple numbers
"""

# Initializes file node sequence reader
cvStartReadRawData = cfunc('cvStartReadRawData', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # const CvFileStorage* fs
    ('src', CvFileNode_r, 1), # const CvFileNode* src
    ('reader', CvSeqReader_r, 1), # CvSeqReader* reader 
)
cvStartReadRawData.__doc__ = """void cvStartReadRawData(const CvFileStorage fs, const CvFileNode src, CvSeqReader reader)

Initializes file node sequence reader
"""

# Initializes file node sequence reader
cvReadRawDataSlice = cfunc('cvReadRawDataSlice', _cxDLL, None,
    ('fs', CvFileStorage_r, 1), # const CvFileStorage* fs
    ('reader', CvSeqReader_r, 1), # CvSeqReader* reader
    ('count', c_int, 1), # int count
    ('dst', c_void_p, 1), # void* dst
    ('dt', c_char_p, 1), # const char* dt 
)
cvReadRawDataSlice.__doc__ = """void cvReadRawDataSlice(const CvFileStorage fs, CvSeqReader reader, int count, void* dst, const char* dt)

Initializes file node sequence reader
"""
   
    
#-----------------------------------------------------------------------------
# Data Persistence and RTTI: RTTI and Generic Functions
#-----------------------------------------------------------------------------


# Registers new type
cvRegisterType = cfunc('cvRegisterType', _cxDLL, None,
    ('info', CvTypeInfo_r, 1), # const CvTypeInfo* info 
)
cvRegisterType.__doc__ = """void cvRegisterType(const CvTypeInfo info)

Registers new type
"""

# Unregisters the type
cvUnregisterType = cfunc('cvUnregisterType', _cxDLL, None,
    ('type_name', c_char_p, 1), # const char* type_name 
)
cvUnregisterType.__doc__ = """void cvUnregisterType(const char* type_name)

Unregisters the type
"""

# Returns the beginning of type list
_cvFirstType = cfunc('cvFirstType', _cxDLL, CvTypeInfo_p,
)

def cvFirstType():
    """CvTypeInfo cvFirstType(void)

    Returns the beginning of type list
    [ctypes-opencv] returns None if no type info is found
    """
    return pointee(_cvFirstType())

# Finds type by its name
_cvFindType = cfunc('cvFindType', _cxDLL, CvTypeInfo_p,
    ('type_name', c_char_p, 1), # const char* type_name 
)

def cvFindType(type_name):
    """CvTypeInfo cvFindType(const char* type_name)

    Finds type by its name
    [ctypes-opencv] returns None if no type info is found
    """
    return pointee(_cvFindType(type_name))

# Returns type of the object
_cvTypeOf = cfunc('cvTypeOf', _cxDLL, CvTypeInfo_p,
    ('struct_ptr', c_void_p, 1), # const void* struct_ptr 
)

def cvTypeOf(struct_ptr):
    """CvTypeInfo cvTypeOf(const void* struct_ptr)

    Returns type of the object
    [ctypes-opencv] returns None if no type info is found
    """
    return pointee(_cvTypeOf(struct_ptr))
    

# Releases the object
_cvRelease = cfunc('cvRelease', _cxDLL, None,
    ('struct_ptr', c_void_p_p, 1), # void** struct_ptr 
)
_cvRelease.__doc__ = """void cvRelease(void** struct_ptr)

Releases the object
"""

# Makes a clone of the object
_cvClone = cfunc('cvClone', _cxDLL, c_void_p,
    ('struct_ptr', c_void_p, 1), # const void* struct_ptr 
)
_cvClone.__doc__ = """void* cvClone(const void* struct_ptr)

Makes a clone of the object
"""

# Saves object to file
cvSave = cfunc('cvSave', _cxDLL, None,
    ('filename', c_char_p, 1), # const char* filename
    ('struct_ptr', CvArr_r, 1), # const void* struct_ptr
    ('name', c_char_p, 1, None), # const char* name
    ('comment', c_char_p, 1, None), # const char* comment
    ('attributes', CvAttrList, 1, CvAttrList()), # CvAttrList attributes
)
cvSave.__doc__ = """void cvSave(const char* filename, const void* struct_ptr, const char* name=NULL, const char* comment=NULL, CvAttrList attributes=cvAttrList())

Saves object to file
"""

# Loads object from file
cvLoad = cfunc('cvLoad', _cxDLL, c_void_p,
    ('filename', c_char_p, 1), # const char* filename
    ('memstorage', CvMemStorage_r, 1, None), # CvMemStorage* memstorage
    ('name', c_char_p, 1, None), # const char* name
    ('real_name', POINTER(c_char_p), 1, None), # const char** real_name
)
cvLoad.__doc__ = """void* cvLoad(const char* filename, CvMemStorage memstorage=NULL, const char* name=NULL, const char** real_name=NULL)

Loads object from file
"""

# Load and cast to given type
def cvLoadCast(filename, ctype):
    '''Use cvLoad and then create a ctype object of the results'''
    return ctype.from_address(cvLoad(filename))
   
    
#-----------------------------------------------------------------------------
# Miscellaneous Functions
#-----------------------------------------------------------------------------


# Splits set of vectors by given number of clusters
cvKMeans2 = cfunc('cvKMeans2', _cxDLL, None,
    ('samples', CvArr_r, 1), # const CvArr* samples
    ('cluster_count', c_int, 1), # int cluster_count
    ('labels', CvArr_r, 1), # CvArr* labels
    ('termcrit', CvTermCriteria, 1), # CvTermCriteria termcrit 
)
cvKMeans2.__doc__ = """void cvKMeans2(const CvArr samples, int cluster_count, CvArr labels, CvTermCriteria termcrit)

Splits set of vectors by given number of clusters
"""
   
    
#-----------------------------------------------------------------------------
# Error Handling
#-----------------------------------------------------------------------------


# Returns the current error status
cvGetErrStatus = cfunc('cvGetErrStatus', _cxDLL, c_int,
)
cvGetErrStatus.__doc__ = """int cvGetErrStatus(void)

Returns the current error status
"""

# Sets the error status
cvSetErrStatus = cfunc('cvSetErrStatus', _cxDLL, None,
    ('status', c_int, 1), # int status 
)
cvSetErrStatus.__doc__ = """void cvSetErrStatus(int status)

Sets the error status
"""

# Returns the current error mode
cvGetErrMode = cfunc('cvGetErrMode', _cxDLL, c_int,
)
cvGetErrMode.__doc__ = """int cvGetErrMode(void)

Returns the current error mode
"""

# Sets the error mode
CV_ErrModeLeaf = 0
CV_ErrModeParent = 1
CV_ErrModeSilent = 2

# Sets the error mode
cvSetErrMode = cfunc('cvSetErrMode', _cxDLL, c_int,
    ('mode', c_int, 1), # int mode 
)
cvSetErrMode.__doc__ = """int cvSetErrMode(int mode)

Sets the error mode
"""

# Raises an error
cvError = cfunc('cvError', _cxDLL, c_int,
    ('status', c_int, 1), # int status
    ('func_name', c_char_p, 1), # const char* func_name
    ('err_msg', c_char_p, 1), # const char* err_msg
    ('file_name', c_char_p, 1), # const char* file_name
    ('line', c_int, 1), # int line 
)
cvError.__doc__ = """int cvError(int status, const char* func_name, const char* err_msg, const char* file_name, int line)

Raises an error
"""

# Returns textual description of error status code
cvErrorStr = cfunc('cvErrorStr', _cxDLL, c_char_p,
    ('status', c_int, 1), # int status 
)
cvErrorStr.__doc__ = """const char* cvErrorStr(int status)

Returns textual description of error status code
"""

# Sets a new error handler
CvErrorCallback = CFUNCTYPE(c_int, # int
    c_int, # int status
    c_char_p, # const char* func_name
    c_char_p, # const char* err_msg
    c_char_p, # const char* file_name
    c_int) # int line

# Sets a new error handler
cvRedirectError = cfunc('cvRedirectError', _cxDLL, CvErrorCallback,
    ('error_handler', CvErrorCallback, 1), # CvErrorCallback error_handler
    ('userdata', c_void_p, 1, None), # void* userdata
    ('prev_userdata', c_void_p_p, 1, None), # void** prev_userdata
)
cvRedirectError.__doc__ = """CvErrorCallback cvRedirectError( CvErrorCallback error_handler, void* userdata=NULL, void** prev_userdata=NULL )

Sets a new error handler
"""

# Provide standard error handling
cvNulDevReport = cfunc('cvNulDevReport', _cxDLL, c_int,
    ('status', c_int, 1), # int status
    ('func_name', c_char_p, 1), # const char* func_name
    ('err_msg', c_char_p, 1), # const char* err_msg
    ('file_name', c_char_p, 1), # const char* file_name
    ('line', c_int, 1), # int line
    ('userdata', c_void_p, 1), # void* userdata 
)
cvNulDevReport.__doc__ = """int cvNulDevReport(int status, const char* func_name, const char* err_msg, const char* file_name, int line, void* userdata)

Provide standard error handling
"""

# Provide standard error handling
cvStdErrReport = cfunc('cvStdErrReport', _cxDLL, c_int,
    ('status', c_int, 1), # int status
    ('func_name', c_char_p, 1), # const char* func_name
    ('err_msg', c_char_p, 1), # const char* err_msg
    ('file_name', c_char_p, 1), # const char* file_name
    ('line', c_int, 1), # int line
    ('userdata', c_void_p, 1), # void* userdata 
)
cvStdErrReport.__doc__ = """int cvStdErrReport( int status, const char* func_name, const char* err_msg, const char* file_name, int line, void* userdata )

Provide standard error handling
"""

# Provide standard error handling
cvGuiBoxReport = cfunc('cvGuiBoxReport', _cxDLL, c_int,
    ('status', c_int, 1), # int status
    ('func_name', c_char_p, 1), # const char* func_name
    ('err_msg', c_char_p, 1), # const char* err_msg
    ('file_name', c_char_p, 1), # const char* file_name
    ('line', c_int, 1), # int line
    ('userdata', c_void_p, 1), # void* userdata 
)
cvGuiBoxReport.__doc__ = """int cvGuiBoxReport( int status, const char* func_name, const char* err_msg, const char* file_name, int line, void* userdata )

Provide standard error handling
"""
   
    
#-----------------------------------------------------------------------------
# System and Utility Functions
#-----------------------------------------------------------------------------


# Returns number of tics
cvGetTickCount = cfunc('cvGetTickCount', _cxDLL, c_longlong,
)
cvGetTickCount.__doc__ = """int64 cvGetTickCount(void)

Returns number of tics
"""

# Returns number of tics per microsecond
cvGetTickFrequency = cfunc('cvGetTickFrequency', _cxDLL, c_double,
)
cvGetTickFrequency.__doc__ = """double cvGetTickFrequency(void)

Returns number of tics per microsecond
"""

# Registers another module
cvRegisterModule = cfunc('cvRegisterModule', _cxDLL, c_int,
    ('module_info', CvModuleInfo_r, 1), # const CvModuleInfo* module_info 
)
cvRegisterModule.__doc__ = """int cvRegisterModule(CvModuleInfo module_info)

Registers another module
"""

# Retrieves information about the registered module(s) and plugins
cvGetModuleInfo = cfunc('cvGetModuleInfo', _cxDLL, None,
    ('module_name', c_char_p, 1), # const char* module_name
    ('version', POINTER(c_char_p), 1), # const char** version
    ('loaded_addon_plugins', POINTER(c_char_p), 1), # const char** loaded_addon_plugins 
)
cvGetModuleInfo.__doc__ = """void cvGetModuleInfo(const char* module_name, const char** version, const char** loaded_addon_plugins)

Retrieves information about the registered module(s) and plugins
"""

# Switches between optimized/non-optimized modes
cvUseOptimized = cfunc('cvUseOptimized', _cxDLL, c_int,
    ('on_off', c_int, 1), # int on_off 
)
cvUseOptimized.__doc__ = """int cvUseOptimized(int on_off)

Switches between optimized/non-optimized modes
"""
   
    
#-----------------------------------------------------------------------------
# Multi-threading -- using OpenMP
#-----------------------------------------------------------------------------


# Returns the current number of threads used
cvGetNumThreads = cfunc('cvGetNumThreads', _cxDLL, c_int,
)
cvGetNumThreads.__doc__ = """int cvGetNumThreads(void)

Returns the current number of threads used
"""

# Sets the number of threads
cvSetNumThreads = cfunc('cvSetNumThreads', _cxDLL, c_int,
    ('threads', c_int, 1, 0), # int threads=0
)
cvSetNumThreads.__doc__ = """void cvSetNumThreads( int threads=0 )

Sets the number of threads
"""

# Returns index of the current thread
cvGetThreadNum = cfunc('cvGetThreadNum', _cxDLL, c_int,
)
cvGetThreadNum.__doc__ = """int cvGetThreadNum(void)

Returns index of the current thread
"""


# --- 1 Operations on Arrays -------------------------------------------------

# --- 1.1 Initialization -----------------------------------------------------

# --- 1.2 Accessing Elements and sub-Arrays ----------------------------------

# --- 1.3 Copying and Filling ------------------------------------------------

# --- 1.4 Transforms and Permutations ----------------------------------------

# --- 1.5 Arithmetic, Logic and Comparison -----------------------------------

# --- 1.6 Statistics ---------------------------------------------------------

# --- 1.7 Linear Algebra -----------------------------------------------------

# --- 1.8 Math Functions -----------------------------------------------------

# --- 1.9 Random Number Generation -------------------------------------------

# --- 1.10 Discrete Transforms -----------------------------------------------

# --- 2 Dynamic Structures ---------------------------------------------------

# --- 2.1 Memory Storages ----------------------------------------------------

# --- 2.2 Sequences ----------------------------------------------------------

# --- 2.3 Sets ---------------------------------------------------------------

# --- 2.4 Graphs -------------------------------------------------------------

# --- 2.5 Trees --------------------------------------------------------------

# --- 3 Drawing Functions ----------------------------------------------------

# --- 3.1 Curves and Shapes --------------------------------------------------

# --- 3.2 Text ---------------------------------------------------------------

# --- 3.3 Point Sets and Contours --------------------------------------------

# --- 4 Data Persistence and RTTI --------------------------------------------

# --- 4.1 File Storage -------------------------------------------------------

# --- 4.2 Writing Data -------------------------------------------------------

# --- 4.3 Reading Data -------------------------------------------------------

# --- 4.4 RTTI and Generic Functions -----------------------------------------

# --- 5 Miscellaneous Functions ----------------------------------------------

# --- 6 Error Handling and System Functions ----------------------------------

# --- 6.1 Error Handling -----------------------------------------------------

# --- 6.2 System and Utility Functions ---------------------------------------


#=============================================================================
# End of of cxcore/cxcore.h
#=============================================================================




#=============================================================================
# Wrap up all the functions and constants into __all__
#=============================================================================
__all__ = [x for x in locals().keys() \
    if  x.startswith('CV') or \
        x.startswith('cv') or \
        x.startswith('Cv') or \
        x.startswith('IPL') or \
        x.startswith('Ipl') or \
        x.startswith('ipl')]
        
__all__ += [
    'c_int_p', 'c_int8_p', 'c_ubyte_p', 'c_float_p', 'c_double_p', 
    'c_void_p_p', 'c_short_p',
    '_cxDLL', '_cvDLL', '_hgDLL','_auDLL',
    'cfunc', 'default_errcheck',
    '_Structure', '_CvSeqStructure', 'ListPOINTER', 'ListPOINTER2', 'ListByRef',
    'ByRefArg', 'pointee', 'sizeof', 'as_c_array',
]
        

