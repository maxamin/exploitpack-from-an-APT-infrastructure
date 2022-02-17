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

# Use xrange if available (pre-3.0)
try:
    range = xrange
except NameError:
    pass

#=============================================================================
# Begin of of cv/cvtypes.h
#=============================================================================


# spatial and central moments
class CvMoments(_Structure):
    _fields_ = [
        # spatial moments
        ('m00', c_double),
        ('m10', c_double),
        ('m20', c_double),
        ('m11', c_double),
        ('m02', c_double),
        ('m30', c_double),
        ('m21', c_double),
        ('m12', c_double),
        ('m03', c_double),
        
        # central moments
        ('mu20', c_double),
        ('mu11', c_double),
        ('mu02', c_double),
        ('mu30', c_double),
        ('mu21', c_double),
        ('mu12', c_double),
        ('mu03', c_double),
        
        # m00 != 0 ? 1/sqrt(m00) : 0
        ('inv_sqrt_m00', c_double),
    ]
CvMoments_p = POINTER(CvMoments)
CvMoments_r = ByRefArg(CvMoments)
    
# Hu invariants
class CvHuMoments(_Structure):
    _fields_ = [ # Hu invariants
        ('hu1', c_double),
        ('hu2', c_double),
        ('hu3', c_double),
        ('hu4', c_double),
        ('hu5', c_double),
        ('hu6', c_double),
        ('hu7', c_double),
    ]
CvHuMoments_p = POINTER(CvHuMoments)
CvHuMoments_r = ByRefArg(CvHuMoments)
    
# Connected Component
class CvConnectedComp(_Structure):
    _fields_ = [('area', c_double), # area of the connected component
                ('value', CvScalar), # average color of the connected component
                ('rect', CvRect), # ROI of the component
                ('contour', CvSeq_p)] # optional component boundary
CvConnectedComp_p = POINTER(CvConnectedComp)
CvConnectedComp_r = ByRefArg(CvConnectedComp)
                
#Viji Periapoilan 4/16/2007 (start)
#Added constants for contour retrieval mode - Apr 19th
CV_RETR_EXTERNAL = 0
CV_RETR_LIST     = 1
CV_RETR_CCOMP    = 2
CV_RETR_TREE     = 3

#Added constants for contour approximation method  - Apr 19th
CV_CHAIN_CODE               = 0
CV_CHAIN_APPROX_NONE        = 1
CV_CHAIN_APPROX_SIMPLE      = 2
CV_CHAIN_APPROX_TC89_L1     = 3
CV_CHAIN_APPROX_TC89_KCOS   = 4
CV_LINK_RUNS                = 5
#Viji Periapoilan 4/16/2007(end)

# this structure is supposed to be treated like a blackbox, OpenCV's design
class CvContourScanner(_Structure):
    _fields_ = []

# Freeman chain reader state
class CvChainPtReader(CvSeqReader):
    _fields_ = [
        ('code', c_char),
        ('pt', CvPoint),
        ('deltas', ((c_char*2)*8)),
    ]
CvChainPtReader_p = POINTER(CvChainPtReader)
CvChainPtReader_r = ByRefArg(CvChainPtReader)
    
# Contour tree header
class CvContourTree(CvSeq):
    _fields_ = [
        ('p1', CvPoint), # the first point of the binary tree root segment
        ('p2', CvPoint), # the last point of the binary tree root segment
    ]
CvContourTree_p = POINTER(CvContourTree)
CvContourTree_r = ByRefArg(CvContourTree)
    
# Finds a sequence of convexity defects of given contour
class CvConvexityDefect(_Structure):
    _fields_ = [
        ('start', CvPoint_p), # point of the contour where the defect begins
        ('end', CvPoint_p), # point of the contour where the defect ends
        ('depth_point', CvPoint_p), # the farthest from the convex hull point within the defect
        ('depth', c_float), # distance between the farthest point and the convex hull
    ]

# Data structures and related enumerations for Planar Subdivisions
CvSubdiv2DEdge = c_size_t

class CvSubdiv2DPoint(_Structure):
    pass
CvSubdiv2DPoint_p = POINTER(CvSubdiv2DPoint)
CvSubdiv2DPoint_r = ByRefArg(CvSubdiv2DPoint)
    
def CV_QUADEDGE2D_FIELDS():
    return [
        ('flags', c_int),
        ('pt', CvSubdiv2DPoint_p*4),
        ('next', CvSubdiv2DEdge*4),
    ]

def CV_SUBDIV2D_POINT_FIELDS():
    return [
        ('flags', c_int),
        ('first', CvSubdiv2DEdge),
        ('pt', CvPoint2D32f),
    ]

CV_SUBDIV2D_VIRTUAL_POINT_FLAG = (1 << 30)

class CvQuadEdge2D(_Structure):
    _fields_ = CV_QUADEDGE2D_FIELDS()
CvQuadEdge2D_p = POINTER(CvQuadEdge2D)
CvQuadEdge2D_r = ByRefArg(CvQuadEdge2D)
    
CvSubdiv2DPoint._fields_ = CV_SUBDIV2D_POINT_FIELDS()

class CvSubdiv2D(CvGraph):
    _fields_ = [('quad_edges', c_int),
                ('is_geometry_valid', c_int),
                ('recent_edge', CvSubdiv2DEdge),
                ('topleft', CvPoint2D32f),
                ('bottomright', CvPoint2D32f)]
CvSubdiv2D_p = POINTER(CvSubdiv2D)    
CvSubdiv2D_r = ByRefArg(CvSubdiv2D)    
    
CvSubdiv2DPointLocation = c_int
CV_PTLOC_ERROR = -2
CV_PTLOC_OUTSIDE_RECT = -1
CV_PTLOC_INSIDE = 0
CV_PTLOC_VERTEX = 1
CV_PTLOC_ON_EDGE = 2

CvNextEdgeType = c_int
CV_NEXT_AROUND_ORG   = 0x00
CV_NEXT_AROUND_DST   = 0x22
CV_PREV_AROUND_ORG   = 0x11
CV_PREV_AROUND_DST   = 0x33
CV_NEXT_AROUND_LEFT  = 0x13
CV_NEXT_AROUND_RIGHT = 0x31
CV_PREV_AROUND_LEFT  = 0x20
CV_PREV_AROUND_RIGHT = 0x02

# Gets the next edge with the same origin point (counterwise)
def CV_SUBDIV2D_NEXT_EDGE( edge ):
    """CvSubdiv2DEdge CV_SUBDIV2D_NEXT_EDGE(CvSubdiv2DEdge edge)
    
    Gets the next edge with the same origin point (counterwise)
    """
    ev = edge.value
    return cast(c_void_p(ev & ~3), CvQuadEdge2D_p)[0].next[ev&3]


# Defines for Distance Transform
CV_DIST_USER    = -1  # User defined distance
CV_DIST_L1      = 1   # distance = |x1-x2| + |y1-y2|
CV_DIST_L2      = 2   # the simple euclidean distance
CV_DIST_C       = 3   # distance = max(|x1-x2|,|y1-y2|)
CV_DIST_L12     = 4   # L1-L2 metric: distance = 2(sqrt(1+x*x/2) - 1))
CV_DIST_FAIR    = 5   # distance = c^2(|x|/c-log(1+|x|/c)), c = 1.3998
CV_DIST_WELSCH  = 6   # distance = c^2/2(1-exp(-(x/c)^2)), c = 2.9846
CV_DIST_HUBER   = 7   # distance = |x|<c ? x^2/2 : c(|x|-c/2), c=1.345

CvFilter = c_int
CV_GAUSSIAN_5x5 = 7

# Older definitions
CvVect32f = c_float_p
CvMatr32f = c_float_p
CvVect64d = c_double_p
CvMatr64d = c_double_p

class CvMatrix3(_Structure):
    _fields_ = [('m', (c_float*3)*3)]

# Computes "minimal work" distance between two weighted point configurations
CvDistanceFunction = CFUNCTYPE(c_float, # float
    c_float_p, # const float* f1
    c_float_p, # const float* f2
    c_void_p) # void* userdata

# CvRandState
class CvRandState(_Structure):
    _fields_ = [
        ('state', CvRNG), # RNG state (the current seed and carry)
        ('disttype', c_int), # distribution type
        ('param', CvScalar*2), # parameters of RNG
    ]
CvRandState_p = POINTER(CvRandState)
CvRandState_r = ByRefArg(CvRandState)
    
# CvConDensation
class CvConDensation(_Structure):
    _fields_ = [
        ('MP', c_int),
        ('DP', c_int),
        ('DynamMatr', c_float_p), # Matrix of the linear Dynamics system
        ('State', c_float_p), # Vector of State
        ('SamplesNum', c_int), # Number of the Samples
        ('flSamples', POINTER(c_float_p)), # arr of the Sample Vectors
        ('flNewSamples', POINTER(c_float_p)), # temporary array of the Sample Vectors
        ('flConfidence', c_float_p), # Confidence for each Sample
        ('flCumulative', c_float_p), # Cumulative confidence
        ('Temp', c_float_p), # Temporary vector
        ('RandomSample', c_float_p), # RandomVector to update sample set
        ('RandS', CvRandState_p), # Array of structures to generate random vectors
    ]
    
    def __del__(self):
        _cvReleaseCondensation(CvConDensation_p(self))
        
CvConDensation_p = POINTER(CvConDensation)
CvConDensation_r = ByRefArg(CvConDensation)
    
# standard Kalman filter (in G. Welch' and G. Bishop's notation):
#
#  x(k)=A*x(k-1)+B*u(k)+w(k)  p(w)~N(0,Q)
#  z(k)=H*x(k)+v(k),   p(v)~N(0,R)
class CvKalman(_Structure):
    _fields_ = [
        ('MP', c_int), # number of measurement vector dimensions
        ('DP', c_int), # number of state vector dimensions
        ('CP', c_int), # number of control vector dimensions
        
        # backward compatibility fields
        ('PosterState', c_float_p), # =state_pre->data.fl
        ('PriorState', c_float_p), # =state_post->data.fl
        ('DynamMatr', c_float_p), # =transition_matrix->data.fl
        ('MeasurementMatr', c_float_p), # =measurement_matrix->data.fl
        ('MNCovariance', c_float_p), # =measurement_noise_cov->data.fl
        ('PNCovariance', c_float_p), # =process_noise_cov->data.fl
        ('KalmGainMatr', c_float_p), # =gain->data.fl
        ('PriorErrorCovariance', c_float_p), # =error_cov_pre->data.fl
        ('PosterErrorCovariance', c_float_p), # =error_cov_post->data.fl
        ('Temp1', c_float_p), # temp1->data.fl
        ('Temp2', c_float_p), # temp2->data.fl
        
        ('state_pre', CvMat_p), # predicted state (x'(k))
        ('state_post', CvMat_p), # corrected state (x(k))
        ('transition_matrix', CvMat_p), # state transition matrix (A)
        ('control_matrix', CvMat_p), # control matrix (B)
        ('measurement_matrix', CvMat_p), # measurement matrix (H)
        ('process_noise_cov', CvMat_p), # process noise covariance matrix (Q)
        ('measurement_noise_cov', CvMat_p), # measurement noise covariance matrix (R)
        ('error_cov_pre', CvMat_p), # priori error estimate covariance matrix (P'(k))
        ('gain', CvMat_p), # Kalman gain matrix (K(k))
        ('error_cov_post', CvMat_p), # posteriori error estimate covariance matrix (P(k))
        ('temp1', CvMat_p),
        ('temp2', CvMat_p),
        ('temp3', CvMat_p),
        ('temp4', CvMat_p),
        ('temp5', CvMat_p),
    ]
    
    def __del__(self):
        _cvReleaseKalman(CvKalman_p(self))
        
CvKalman_p = POINTER(CvKalman)
CvKalman_r = ByRefArg(CvKalman)
    
# Haar-like Object Detection structures

CV_HAAR_MAGIC_VAL    = 0x42500000
CV_TYPE_NAME_HAAR    = "opencv-haar-classifier"
CV_HAAR_FEATURE_MAX  = 3

class CvHaarFeatureRect(_Structure):
    _fields_ = [
        ('r', CvRect),
        ('weight', c_float),
    ]    

class CvHaarFeature(_Structure):
    _fields_ = [
        ('titled', c_int),
        ('rect', CvHaarFeatureRect*CV_HAAR_FEATURE_MAX),
    ]
CvHaarFeature_p = POINTER(CvHaarFeature)

class CvHaarClassifier(_Structure):
    _fields_ = [
        ('count', c_int),
        ('haar_feature', CvHaarFeature_p),
        ('threshold', c_float_p),
        ('left', c_int_p),
        ('right', c_int_p),
        ('alpha', c_float_p),
    ]
CvHaarClassifier_p = POINTER(CvHaarClassifier)

class CvHaarStageClassifier(_Structure):
    _fields_ = [
        ('count', c_int),
        ('threshold', c_float),
        ('classifier', CvHaarClassifier_p),
        ('next', c_int),
        ('child', c_int),
        ('parent', c_int),
    ]
CvHaarStageClassifier_p = POINTER(CvHaarStageClassifier)

class CvHidHaarClassifierCascade(_Structure): # not implemented yet
    _fields_ = []
CvHidHaarClassifierCascade_p = POINTER(CvHidHaarClassifierCascade)

class CvHaarClassifierCascade(_Structure):
    _fields_ = [
        ('flags', c_int),
        ('count', c_int),
        ('orig_window_size', CvSize),
        ('real_window_size', CvSize),
        ('scale', c_double),
        ('stage_classifier', CvHaarStageClassifier_p),
        ('hid_cascade', CvHidHaarClassifierCascade_p),
    ]
    
    def __del__(self):
        _cvReleaseHaarClassifierCascade(CvHaarClassifierCascade_p(self))
        
CvHaarClassifierCascade_p = POINTER(CvHaarClassifierCascade)
CvHaarClassifierCascade_r = ByRefArg(CvHaarClassifierCascade)

class CvAvgComp(_Structure):
    _fields_ = [
        ('rect', CvRect),
        ('neighbors', c_int),
    ]

    
#=============================================================================
# End of of cv/cvtypes.h
#=============================================================================




#=============================================================================
# Begin of of cv/cv.h
#=============================================================================


#-----------------------------------------------------------------------------
# Image Processing: Gradients, Edges and Corners
#-----------------------------------------------------------------------------


CV_SCHARR = -1
CV_MAX_SOBEL_KSIZE = 7

# Calculates first, second, third or mixed image derivatives using extended Sobel operator
cvSobel = cfunc('cvSobel', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('xorder', c_int, 1), # int xorder
    ('yorder', c_int, 1), # int yorder
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvSobel.__doc__ = """void cvSobel(const CvArr src, CvArr dst, int xorder, int yorder, int aperture_size=3)

Calculates first, second, third or mixed image derivatives using extended Sobel operator
"""

# Calculates Laplacian of the image
cvLaplace = cfunc('cvLaplace', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvLaplace.__doc__ = """void cvLaplace(const CvArr src, CvArr dst, int aperture_size=3)

Calculates Laplacian of the image
"""

CV_CANNY_L2_GRADIENT = 1 << 31

# Implements Canny algorithm for edge detection
cvCanny = cfunc('cvCanny', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('edges', CvArr_r, 1), # CvArr* edges
    ('threshold1', c_double, 1), # double threshold1
    ('threshold2', c_double, 1), # double threshold2
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvCanny.__doc__ = """void cvCanny(const CvArr image, CvArr edges, double threshold1, double threshold2, int aperture_size=3)

Implements Canny algorithm for edge detection
"""

# Calculates feature map for corner detection
cvPreCornerDetect = cfunc('cvPreCornerDetect', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('corners', CvArr_r, 1), # CvArr* corners
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvPreCornerDetect.__doc__ = """void cvPreCornerDetect(const CvArr image, CvArr corners, int aperture_size=3)

Calculates feature map for corner detection
"""

# Calculates eigenvalues and eigenvectors of image blocks for corner detection
cvCornerEigenValsAndVecs = cfunc('cvCornerEigenValsAndVecs', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('eigenvv', CvArr_r, 1), # CvArr* eigenvv
    ('block_size', c_int, 1), # int block_size
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvCornerEigenValsAndVecs.__doc__ = """void cvCornerEigenValsAndVecs(const CvArr image, CvArr eigenvv, int block_size, int aperture_size=3)

Calculates eigenvalues and eigenvectors of image blocks for corner detection
"""

# Calculates minimal eigenvalue of gradient matrices for corner detection
cvCornerMinEigenVal = cfunc('cvCornerMinEigenVal', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('eigenval', CvArr_r, 1), # CvArr* eigenval
    ('block_size', c_int, 1), # int block_size
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvCornerMinEigenVal.__doc__ = """void cvCornerMinEigenVal(const CvArr image, CvArr eigenval, int block_size, int aperture_size=3)

Calculates minimal eigenvalue of gradient matrices for corner detection
"""

# Harris edge detector
cvCornerHarris = cfunc('cvCornerHarris', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('harris_responce', CvArr_r, 1), # CvArr* harris_responce
    ('block_size', c_int, 1), # int block_size
    ('aperture_size', c_int, 1, 3), # int aperture_size
    ('k', c_double, 1, 0.04), # double k
)
cvCornerHarris.__doc__ = """void cvCornerHarris(const CvArr image, CvArr harris_responce, int block_size, int aperture_size=3, double k=0.04)

Harris edge detector
"""

# Refines corner locations
_cvFindCornerSubPix = cfunc('cvFindCornerSubPix', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('corners', CvPoint2D32f_p, 1), # CvPoint2D32f* corners
    ('count', c_int, 1), # int count
    ('win', CvSize, 1), # CvSize win
    ('zero_zone', CvSize, 1), # CvSize zero_zone
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria 
)

def cvFindCornerSubPix(image, corners, win, zero_zone, criteria):
    """c_array_of_CvPoint2D32f cvFindCornerSubPix(const CvArr image, array_of_CvPoint2D32f corners, CvSize win, CvSize zero_zone, CvTermCriteria criteria)

    Refines corner locations
    [ctypes-opencv] If 'corners' is a list or a tuple of CvPoint2D32f points, it is converted into a c_array_of_CvPoint2D32f before the actual function call.
    [ctypes-opencv] During the call, 'corners',  now as a c_array_of_CvPoint2D32f, has its content updated with refined corners.
    [ctypes-opencv] After the call, 'corners' is returned.
    """
    corners = as_c_array(corners, elem_ctype=CvPoint2D32f)
    _cvFindCornerSubPix(image, corners, len(corners), win, zero_zone, criteria)
    return corners

# Determines strong corners on image
_cvGoodFeaturesToTrack = cfunc('cvGoodFeaturesToTrack', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('eig_image', CvArr_r, 1), # CvArr* eig_image
    ('temp_image', CvArr_r, 1), # CvArr* temp_image
    ('corners', CvPoint2D32f_p, 1), # CvPoint2D32f* corners
    ('corner_count', ByRefArg(c_int), 1), # int* corner_count
    ('quality_level', c_double, 1), # double quality_level
    ('min_distance', c_double, 1), # double min_distance
    ('mask', CvArr_r, 1, None), # const CvArr* mask
    ('block_size', c_int, 1, 3), # int block_size
    ('use_harris', c_int, 1, 0), # int use_harris
    ('k', c_double, 1, 0.04), # double k
)

def cvGoodFeaturesToTrack(image, eig_image, temp_image, corners, corner_count, quality_level, min_distance, mask=None, block_size=3, use_harris=0, k=0.04):
    """c_array_of_CvPoint2D32f cvGoodFeaturesToTrack(const CvArr image, CvArr eig_image, CvArr temp_image, array_of_CvPoint2D32f corners, int corner_count, double quality_level, double min_distance, const CvArr mask=NULL, int block_size=3, int use_harris=0, double k=0.04)

    Determines strong corners on image
    [ctypes-opencv] If 'eig_image' is None, it is internally created.
    [ctypes-opencv] If 'temp_image' is None, it is internally created.
    [ctypes-opencv] If 'corners' is None, an c_array of 'corner_count' CvPoint2D32f items is internally created before the actual function call.
    [ctypes-opencv] If 'corners' is a list or a tuple of CvPoint2D32f points, it is converted into a c_array_of_CvPoint2D32f before the actual function call.
    [ctypes-opencv] The returned object is a c_array of CvPoint2D32f items sharing the same memory allocation with 'corners'. The actual number of detected corners is the length of this c_array.
    """
    if eig_image is None:
        eig_image = cvCreateMat(image.height, image.width, CV_32FC1)
    if temp_image is None:
        temp_image = cvCreateMat(image.height, image.width, CV_32FC1)
    corners = (CvPoint2D32f*corner_count)() if corners is None else as_c_array(corners, elem_ctype=CvPoint2D32f)
    count = c_int(corner_count)
    _cvGoodFeaturesToTrack(image, eig_image, temp_image, corners, count, quality_level, min_distance, mask, block_size, use_harris, k)
    return as_c_array(corners, n=count.value, elem_ctype=CvPoint2D32f)

#-----------------------------------------------------------------------------
# Speeded Up Robust Features
#-----------------------------------------------------------------------------

if cvVersion == 110:
    class CvSURFPoint(_Structure):
        _fields_ = [
            ('pt', CvPoint2D32f),
            ('laplacian', c_int),
            ('size', c_int),
            ('dir', c_float),
            ('hessian', c_float),
        ]

    def cvSURFPoint(pt, laplacian, size, dir=0, hessian=0):
        kp = CvSURFPoint()
        kp.pt = pt
        kp.laplacian = laplacian
        kp.size = size
        kp.dir = dir
        kp.hessian = hessian
        return kp

    class CvSURFParams(_Structure):
        _fields_ = [
            ('extended', c_int),
            ('hessianThreshold', c_double),
            ('nOctaves', c_int),
            ('nOctaveLayers', c_int),
        ]

    def cvSURFParams(hessianThreshold, extended=0, nOctaves=3, nOctaveLayers=4):
        z = CvSURFParams()
        z.hessianThreshold = hessianThreshold
        z.extended = extended
        z.nOctaves = nOctaves
        z.nOctaveLayers = nOctaveLayers
        return z
        
    # Extracts Speeded Up Robust Features from image
    _cvExtractSURF = cfunc('cvExtractSURF', _cvDLL, None,
        ('img', CvArr_r, 1), # const CvArr* img
        ('mask', CvArr_r, 1), # const CvArr* mask
        ('keypoints', ByRefArg(CvSeq_p), 1), # CvSeq** keypoints
        ('descriptors', ByRefArg(CvSeq_p), 1), # CvSeq** descriptors
        ('storage', ByRefArg(CvMemStorage), 1), # CvMemStorage* storage
        ('params', CvSURFParams, 1), # CvSURFParams params
    )
    
    # Extracts Speeded Up Robust Features from image
    def cvExtractSURF(img, mask, keypoints_ptr, descriptors_ptr, storage, params):
        """CvSeq keypoints, [CvSeq descriptors] = cvExtractSURF(const CvArr img, const CvArr mask, CvSeq_p keypoints_ptr, CvSeq_p descriptors_ptr, CvMemStorage storage, CvSURFParams params)
        
        Extracts Speeded Up Robust Features from image
        [ctypes-opencv] If 'keypoints_ptr' is not None, it holds the address of the returning 'keypoints'.
        [ctypes-opencv] 'descriptors_ptr' can be:
            None: 'descriptors' is not returned.
            True: 'descriptors' is also returned.
            an instance of CvSeq_p: 'descriptors' is also returned. Its address is stored in 'descriptors_ptr'.
        """
        if keypoints_ptr is None:
            keypoints_ptr = CvSeq_p()
        
        if descriptors_ptr is None:
            _cvExtractSURF(img, mask, keypoints_ptr, None, storage, params)
            return pointee(keypoints_ptr, storage)

        if descriptors_ptr is True:
            descriptors_ptr = CvSeq_p()        
        _cvExtractSURF(img, mask, keypoints_ptr, descriptors_ptr, storage, params)
        return (pointee(keypoints_ptr, storage), pointee(descriptors_ptr, storage))
             

#-----------------------------------------------------------------------------
# Image Processing: Sampling, Interpolation and Geometrical Transforms
#-----------------------------------------------------------------------------


# Reads raster line to buffer
cvSampleLine = cfunc('cvSampleLine', _cvDLL, c_int,
    ('image', CvArr_r, 1), # const CvArr* image
    ('pt1', CvPoint, 1), # CvPoint pt1
    ('pt2', CvPoint, 1), # CvPoint pt2
    ('buffer', c_void_p, 1), # void* buffer
    ('connectivity', c_int, 1, 8), # int connectivity
)
cvSampleLine.__doc__ = """int cvSampleLine(const CvArr image, CvPoint pt1, CvPoint pt2, void* buffer, int connectivity=8)

Reads raster line to buffer
"""

# Retrieves pixel rectangle from image with sub-pixel accuracy
cvGetRectSubPix = cfunc('cvGetRectSubPix', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('center', CvPoint2D32f, 1), # CvPoint2D32f center 
)
cvGetRectSubPix.__doc__ = """void cvGetRectSubPix(const CvArr src, CvArr dst, CvPoint2D32f center)

Retrieves pixel rectangle from image with sub-pixel accuracy
"""

# Retrieves pixel quadrangle from image with sub-pixel accuracy
cvGetQuadrangleSubPix = cfunc('cvGetQuadrangleSubPix', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('map_matrix', CvMat_r, 1), # const CvMat* map_matrix 
)
cvGetQuadrangleSubPix.__doc__ = """void cvGetQuadrangleSubPix(const CvArr src, CvArr dst, const CvMat map_matrix)

Retrieves pixel quadrangle from image with sub-pixel accuracy
"""

#Viji Periapoilan 4/16/2007 (start)
# Added the following constants to work with facedetect sample
CV_INTER_NN     = 0 #nearest-neigbor interpolation, 
CV_INTER_LINEAR = 1 #bilinear interpolation (used by default) 
CV_INTER_CUBIC  = 2 # bicubic interpolation. 
CV_INTER_AREA = 3 #resampling using pixel area relation. It is preferred method for image decimation that gives moire-free results. In case of zooming it is similar to CV_INTER_NN method.
#Viji Periapoilan 4/16/2007(end)

# Resizes image
cvResize = cfunc('cvResize', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('interpolation', c_int, 1, CV_INTER_LINEAR), # int interpolation
)
cvResize.__doc__ = """void cvResize(const CvArr src, CvArr dst, int interpolation=CV_INTER_LINEAR)

Resizes image
"""

CV_WARP_FILL_OUTLIERS = 8
CV_WARP_INVERSE_MAP = 16

# Applies affine transformation to the image
cvWarpAffine = cfunc('cvWarpAffine', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('map_matrix', CvMat_r, 1), # const CvMat* map_matrix
    ('flags', c_int, 1, CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS), # int flags
    ('fillval', CvScalar, 1, cvScalarAll(0)), # CvScalar fillval
)
cvWarpAffine.__doc__ = """void cvWarpAffine(const CvArr src, CvArr dst, const CvMat map_matrix, int flags=CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS, CvScalar fillval=cvScalarAll(0)

Applies affine transformation to the image
"""

# Calculates affine transform from 3 corresponding points
_cvGetAffineTransform = cfunc('cvGetAffineTransform', _cvDLL, CvMat_p,
    ('src', CvPoint2D32f_r, 1), # const CvPoint2D32f* src
    ('dst', CvPoint2D32f_r, 1), # const CvPoint2D32f* dst
    ('map_matrix', CvMat_r, 1), # CvMat* map_matrix
)

def cvGetAffineTransform(src, dst, map_matrix=None):
    """CvMat cvGetAffineTransform(const CvPoint2D32f src, const CvPoint2D32f dst)

    Calculates affine transform from 3 corresponding points
    [ctypes-opencv] If 'map_matrix' is None, a CV_64FC1 2x3 CvMat is internally created.
    """
    if map_matrix is None:
        map_matrix = cvCreateMat(2, 3, CV_64FC1)
    _cvGetAffineTransform(src, dst, map_matrix)
    return map_matrix

# Calculates affine matrix of 2d rotation
cv2DRotationMatrix = cfunc('cv2DRotationMatrix', _cvDLL, CvMat_p,
    ('center', CvPoint2D32f, 1), # CvPoint2D32f center
    ('angle', c_double, 1), # double angle
    ('scale', c_double, 1), # double scale
    ('map_matrix', CvMat_r, 1), # CvMat* map_matrix 
)

def cv2DRotationMatrix(center, angle, scale, map_matrix=None):
    """CvMat cv2DRotationMatrix(CvPoint2D32f center, double angle, double scale)

    Calculates affine matrix of 2d rotation
    [ctypes-opencv] If 'map_matrix' is None, a Cv_64FC1 2x3 CvMat is internally created.
    """
    if map_matrix is None:
        map_matrix = cvCreateMat(2, 3, CV_64FC1)
    _cv2DRotationMatrix(center, angle, scale, map_matrix)
    return map_matrix

# Applies perspective transformation to the image
cvWarpPerspective = cfunc('cvWarpPerspective', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('map_matrix', CvMat_r, 1), # const CvMat* map_matrix
    ('flags', c_int, 1, CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS), # int flags
    ('fillval', CvScalar, 1, cvScalarAll(0)), # CvScalar fillval
)
cvWarpPerspective.__doc__ = """void cvWarpPerspective(const CvArr src, CvArr dst, const CvMat map_matrix, int flags=CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS, CvScalar fillval=cvScalarAll(0)

Applies perspective transformation to the image
"""

# Calculates perspective transform from 4 corresponding points
_cvGetPerspectiveTransform = cfunc('cvGetPerspectiveTransform', _cvDLL, CvMat_p,
    ('src', CvPoint2D32f_r, 1), # const CvPoint2D32f* src
    ('dst', CvPoint2D32f_r, 1), # const CvPoint2D32f* dst
    ('map_matrix', CvMat_r, 1), # CvMat* map_matrix 
)

def cvGetPerspectiveTransform(src, dst, map_matrix):
    """CvMat cvGetPerspectiveTransform(const CvPoint2D32f src, const CvPoint2D32f dst)

    Calculates perspective transform from 4 corresponding points
    [ctypes-opencv] If map_matrix is None, a CV_64FC1 3x3 CvMat is internally created.
    """
    if map_matrix is None:
        map_matrix = cvCreateMat(3, 3, CV_64FC1)
    _cvGetPerspectiveTransform(src, dst, map_matrix)
    return map_matrix

# Applies generic geometrical transformation to the image
cvRemap = cfunc('cvRemap', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('mapx', CvArr_r, 1), # const CvArr* mapx
    ('mapy', CvArr_r, 1), # const CvArr* mapy
    ('flags', c_int, 1, CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS), # int flags
    ('fillval', CvScalar, 1, cvScalarAll(0)), # CvScalar fillval
)
cvRemap.__doc__ = """void cvRemap(const CvArr src, CvArr dst, const CvArr mapx, const CvArr mapy, int flags=CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS, CvScalar fillval=cvScalarAll(0)

Applies generic geometrical transformation to the image
"""

# Remaps image to log-polar space
cvLogPolar = cfunc('cvLogPolar', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('center', CvPoint2D32f, 1), # CvPoint2D32f center
    ('M', c_double, 1), # double M
    ('flags', c_int, 1, CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS), # int flags
)
cvLogPolar.__doc__ = """void cvLogPolar(const CvArr src, CvArr dst, CvPoint2D32f center, double M, int flags=CV_INTER_LINEAR+CV_WARP_FILL_OUTLIERS)

Remaps image to log-polar space
"""


#-----------------------------------------------------------------------------
# Image Processing: Morphological Operations
#-----------------------------------------------------------------------------


CV_SHAPE_RECT = 0
CV_SHAPE_CROSS = 1
CV_SHAPE_ELLIPSE = 2
CV_SHAPE_CUSTOM = 100

class IplConvKernel(_Structure):
    _fields_ = [
        ('nCols', c_int),
        ('nRows', c_int),
        ('anchorX', c_int),
        ('anchorY', c_int),
        ('values', c_int_p),
        ('nShiftR', c_int),
    ]
    
    def __del__(self):
        _cvReleaseStructuringElement(IplConvKernel_p(self))
    
IplConvKernel_p = POINTER(IplConvKernel)
IplConvKernel_r = ByRefArg(IplConvKernel)
    
class IplConvKernelFP(_Structure):
    _fields_ = [
        ('nCols', c_int),
        ('nRows', c_int),
        ('anchorX', c_int),
        ('anchorY', c_int),
        ('values', c_int_p),
    ]    
IplConvKernelFP_p = POINTER(IplConvKernelFP)

# Deletes structuring element
_cvReleaseStructuringElement = cfunc('cvReleaseStructuringElement', _cvDLL, None,
    ('element', ByRefArg(IplConvKernel_p), 1), # IplConvKernel** element 
)

# Creates structuring element
_cvCreateStructuringElementEx = cfunc('cvCreateStructuringElementEx', _cvDLL, IplConvKernel_p,
    ('cols', c_int, 1), # int cols
    ('rows', c_int, 1), # int rows
    ('anchor_x', c_int, 1), # int anchor_x
    ('anchor_y', c_int, 1), # int anchor_y
    ('shape', c_int, 1), # int shape
    ('values', c_int_p, 1, None), # int* values
)

def cvCreateStructuringElementEx(cols, rows, anchor_x, anchor_y, shape, values=None):
    """IplConvKernel cvCreateStructuringElementEx(int cols, int rows, int anchor_x, int anchor_y, int shape, int* values=NULL)

    Creates structuring element
    [ctypes-opencv] returns None if IplConvKernel is not created
    """
    return pointee(_cvCreateStructuringElementEx(cols, rows, anchor_x, anchor_y, shape, values))

# Erodes image by using arbitrary structuring element
cvErode = cfunc('cvErode', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('element', IplConvKernel_r, 1, None), # IplConvKernel* element
    ('iterations', c_int, 1, 1), # int iterations
)
cvErode.__doc__ = """void cvErode(const CvArr src, CvArr dst, IplConvKernel element=NULL, int iterations=1)

Erodes image by using arbitrary structuring element
"""

# Dilates image by using arbitrary structuring element
cvDilate = cfunc('cvDilate', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('element', IplConvKernel_r, 1, None), # IplConvKernel* element
    ('iterations', c_int, 1, 1), # int iterations
)
cvDilate.__doc__ = """void cvDilate(const CvArr src, CvArr dst, IplConvKernel element=NULL, int iterations=1)

Dilates image by using arbitrary structuring element
"""

CV_MOP_OPEN = 2
CV_MOP_CLOSE = 3
CV_MOP_GRADIENT = 4
CV_MOP_TOPHAT = 5
CV_MOP_BLACKHAT = 6

# Performs advanced morphological transformations
cvMorphologyEx = cfunc('cvMorphologyEx', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('temp', CvArr_r, 1), # CvArr* temp
    ('element', IplConvKernel_r, 1), # IplConvKernel* element
    ('operation', c_int, 1), # int operation
    ('iterations', c_int, 1, 1), # int iterations
)
cvMorphologyEx.__doc__ = """void cvMorphologyEx(const CvArr src, CvArr dst, CvArr temp, IplConvKernel element, int operation, int iterations=1)

Performs advanced morphological transformations
"""


#-----------------------------------------------------------------------------
# Image Processing: Filters and Color Conversion
#-----------------------------------------------------------------------------


CV_BLUR_NO_SCALE = 0
CV_BLUR = 1
CV_GAUSSIAN = 2
CV_MEDIAN = 3
CV_BILATERAL = 4

# Smooths the image in one of several ways
cvSmooth = cfunc('cvSmooth', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('smoothtype', c_int, 1, CV_GAUSSIAN), # int smoothtype
    ('param1', c_int, 1, 3), # int param1
    ('param2', c_int, 1, 0), # int param2
    ('param3', c_double, 1, 0), # double param3
    ('param4', c_double, 1, 0), # double param4
)
cvSmooth.__doc__ = """void cvSmooth(const CvArr src, CvArr dst, int smoothtype=CV_GAUSSIAN, int param1=3, int param2=0, double param3=0, double param4=0)

Smooths the image in one of several ways
"""

# Convolves image with the kernel
cvFilter2D = cfunc('cvFilter2D', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('kernel', CvMat_r, 1), # const CvMat* kernel
    ('anchor', CvPoint, 1, cvPoint(-1,-1)), # CvPoint anchor
)
cvFilter2D.__doc__ = """void cvFilter2D(const CvArr src, CvArr dst, const CvMat kernel, CvPoint anchor=cvPoint(-1, -1)

Convolves image with the kernel
"""

# Copies image and makes border around it
cvCopyMakeBorder = cfunc('cvCopyMakeBorder', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('offset', CvPoint, 1), # CvPoint offset
    ('bordertype', c_int, 1), # int bordertype
    ('value', CvScalar, 1, cvScalarAll(0)), # CvScalar value
)
cvCopyMakeBorder.__doc__ = """void cvCopyMakeBorder(const CvArr src, CvArr dst, CvPoint offset, int bordertype, CvScalar value=cvScalarAll(0)

Copies image and makes border around it
"""

# Calculates integral images
cvIntegral = cfunc('cvIntegral', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('sum', CvArr_r, 1), # CvArr* sum
    ('sqsum', CvArr_r, 1, None), # CvArr* sqsum
    ('tilted_sum', CvArr_r, 1, None), # CvArr* tilted_sum
)
cvIntegral.__doc__ = """void cvIntegral(const CvArr image, CvArr sum, CvArr sqsum=NULL, CvArr tilted_sum=NULL)

Calculates integral images
"""


CV_BGR2BGRA =   0
CV_RGB2RGBA =   CV_BGR2BGRA

CV_BGRA2BGR =   1
CV_RGBA2RGB =   CV_BGRA2BGR

CV_BGR2RGBA =   2
CV_RGB2BGRA =   CV_BGR2RGBA

CV_RGBA2BGR =   3
CV_BGRA2RGB =   CV_RGBA2BGR

CV_BGR2RGB  =   4
CV_RGB2BGR  =   CV_BGR2RGB

CV_BGRA2RGBA =  5
CV_RGBA2BGRA =  CV_BGRA2RGBA

CV_BGR2GRAY =   6
CV_RGB2GRAY =   7
CV_GRAY2BGR =   8
CV_GRAY2RGB =   CV_GRAY2BGR
CV_GRAY2BGRA =  9
CV_GRAY2RGBA =  CV_GRAY2BGRA
CV_BGRA2GRAY =  10
CV_RGBA2GRAY =  11

CV_BGR2BGR565 = 12
CV_RGB2BGR565 = 13
CV_BGR5652BGR = 14
CV_BGR5652RGB = 15
CV_BGRA2BGR565 = 16
CV_RGBA2BGR565 = 17
CV_BGR5652BGRA = 18
CV_BGR5652RGBA = 19

CV_GRAY2BGR565 = 20
CV_BGR5652GRAY = 21

CV_BGR2BGR555  = 22
CV_RGB2BGR555  = 23
CV_BGR5552BGR  = 24
CV_BGR5552RGB  = 25
CV_BGRA2BGR555 = 26
CV_RGBA2BGR555 = 27
CV_BGR5552BGRA = 28
CV_BGR5552RGBA = 29

CV_GRAY2BGR555 = 30
CV_BGR5552GRAY = 31

CV_BGR2XYZ =    32
CV_RGB2XYZ =    33
CV_XYZ2BGR =    34
CV_XYZ2RGB =    35

CV_BGR2YCrCb =  36
CV_RGB2YCrCb =  37
CV_YCrCb2BGR =  38
CV_YCrCb2RGB =  39

CV_BGR2HSV =    40
CV_RGB2HSV =    41

CV_BGR2Lab =    44
CV_RGB2Lab =    45

CV_BayerBG2BGR = 46
CV_BayerGB2BGR = 47
CV_BayerRG2BGR = 48
CV_BayerGR2BGR = 49

CV_BayerBG2RGB = CV_BayerRG2BGR
CV_BayerGB2RGB = CV_BayerGR2BGR
CV_BayerRG2RGB = CV_BayerBG2BGR
CV_BayerGR2RGB = CV_BayerGB2BGR

CV_BGR2Luv =    50
CV_RGB2Luv =    51
CV_BGR2HLS =    52
CV_RGB2HLS =    53

CV_HSV2BGR =    54
CV_HSV2RGB =    55

CV_Lab2BGR =    56
CV_Lab2RGB =    57
CV_Luv2BGR =    58
CV_Luv2RGB =    59
CV_HLS2BGR =    60
CV_HLS2RGB =    61

CV_COLORCVT_MAX = 100

# Converts image from one color space to another
cvCvtColor = cfunc('cvCvtColor', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('code', c_int, 1), # int code 
)
cvCvtColor.__doc__ = """void cvCvtColor(const CvArr src, CvArr dst, int code)

Converts image from one color space to another
"""

CV_THRESH_BINARY = 0      # value = (value > threshold) ? max_value : 0
CV_THRESH_BINARY_INV = 1  # value = (value > threshold) ? 0 : max_value
CV_THRESH_TRUNC = 2       # value = (value > threshold) ? threshold : value
CV_THRESH_TOZERO = 3      # value = (value > threshold) ? value : 0
CV_THRESH_TOZERO_INV = 4  # value = (value > threshold) ? 0 : value
CV_THRESH_MASK = 7
CV_THRESH_OTSU = 8        # use Otsu algorithm to choose the optimal threshold value

# Applies fixed-level threshold to array elements
cvThreshold = cfunc('cvThreshold', _cvDLL, c_double if cvVersion==110 else None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('threshold', c_double, 1), # double threshold
    ('max_value', c_double, 1), # double max_value
    ('threshold_type', c_int, 1), # int threshold_type 
)
cvThreshold.__doc__ = """void cvThreshold(const CvArr src, CvArr dst, double threshold, double max_value, int threshold_type)

Applies fixed-level threshold to array elements
"""

CV_ADAPTIVE_THRESH_MEAN_C = 0
CV_ADAPTIVE_THRESH_GAUSSIAN_C = 1

# Applies adaptive threshold to array
cvAdaptiveThreshold = cfunc('cvAdaptiveThreshold', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('max_value', c_double, 1), # double max_value
    ('adaptive_method', c_int, 1, CV_ADAPTIVE_THRESH_MEAN_C), # int adaptive_method
    ('threshold_type', c_int, 1, CV_THRESH_BINARY), # int threshold_type
    ('block_size', c_int, 1, 3), # int block_size
    ('param1', c_double, 1, 5), # double param1
)
cvAdaptiveThreshold.__doc__ = """void cvAdaptiveThreshold(const CvArr src, CvArr dst, double max_value, int adaptive_method=CV_ADAPTIVE_THRESH_MEAN_C, int threshold_type=CV_THRESH_BINARY, int block_size=3, double param1=5)

Applies adaptive threshold to array
"""


#-----------------------------------------------------------------------------
# Image Processing: Pyramids
#-----------------------------------------------------------------------------


# Downsamples image
cvPyrDown = cfunc('cvPyrDown', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('filter', c_int, 1, CV_GAUSSIAN_5x5), # int filter
)
cvPyrDown.__doc__ = """void cvPyrDown(const CvArr src, CvArr dst, int filter=CV_GAUSSIAN_5x5)

Downsamples image
"""

# Upsamples image
cvPyrUp = cfunc('cvPyrUp', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('filter', c_int, 1, CV_GAUSSIAN_5x5), # int filter
)
cvPyrUp.__doc__ = """void cvPyrUp(const CvArr src, CvArr dst, int filter=CV_GAUSSIAN_5x5)

Upsamples image
"""


#-----------------------------------------------------------------------------
# Image Processing: Connected Components
#-----------------------------------------------------------------------------



# Fills a connected component with given color
cvFloodFill = cfunc('cvFloodFill', _cvDLL, None,
    ('image', CvArr_r, 1), # CvArr* image
    ('seed_point', CvPoint, 1), # CvPoint seed_point
    ('new_val', CvScalar, 1), # CvScalar new_val
    ('lo_diff', CvScalar, 1, cvScalarAll(0)), # CvScalar lo_diff
    ('up_diff', CvScalar, 1, cvScalarAll(0)), # CvScalar up_diff
    ('comp', CvConnectedComp_r, 1, None), # CvConnectedComp* comp
    ('flags', c_int, 1, 4), # int flags
    ('mask', CvArr_r, 1, None), # CvArr* mask
)
cvFloodFill.__doc__ = """void cvFloodFill(CvArr image, CvPoint seed_point, CvScalar new_val, CvScalar lo_diff=cvScalarAll(0), CvScalar up_diff=cvScalarAll(0), CvConnectedComp comp=None, int flags=4, CvArr mask=NULL)

Fills a connected component with given color
"""

CV_FLOODFILL_FIXED_RANGE = 1 << 16
CV_FLOODFILL_MASK_ONLY = 1 << 17

# Finds contours in binary image
_cvFindContours = cfunc('cvFindContours', _cvDLL, c_int,
    ('image', CvArr_r, 1), # CvArr* image
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('first_contour', ByRefArg(CvSeq_p), 1), # CvSeq** first_contour
    ('header_size', c_int, 1, sizeof(CvContour)), # int header_size
    ('mode', c_int, 1, CV_RETR_LIST), # int mode
    ('method', c_int, 1, CV_CHAIN_APPROX_SIMPLE), # int method
    ('offset', CvPoint, 1, cvPoint(0,0)), # CvPoint offset
)

# Finds contours in binary image
def cvFindContours(image, storage, first_contour_ptr=None, header_size=sizeof(CvContour), mode=CV_RETR_LIST, method=CV_CHAIN_APPROX_SIMPLE, offset=cvPoint(0,0)):
    """int ncontours, CvSeq first_contour = cvFindContours(CvArr image, CvMemStorage storage, CvSeq_p first_contour_ptr=None, int header_size=sizeof(CvContour), int mode=CV_RETR_LIST, int method=CV_CHAIN_APPROX_SIMPLE, CvPoint offset=cvPoint(0, 0)

    Finds contours in binary image
    [ctypes-opencv] If 'first_contour_ptr' is not None, it is filled with the address of 'first_contour'. In any case, both 'ncontours' and 'first_contour' are returned.
    """
    if first_contour_ptr is None:
        first_contour_ptr = CvSeq_p()
    n = _cvFindContours(image, storage, first_contour_ptr, header_size, mode, method, offset)
    return (n, pointee(first_contour_ptr, storage))

# Initializes contour scanning process
_cvStartFindContours = cfunc('cvStartFindContours', _cvDLL, CvContourScanner,
    ('image', CvArr_r, 1), # CvArr* image
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('header_size', c_int, 1, sizeof(CvContour)), # int header_size
    ('mode', c_int, 1, CV_RETR_LIST), # int mode
    ('method', c_int, 1, CV_CHAIN_APPROX_SIMPLE), # int method
    ('offset', CvPoint, 1, cvPoint(0,0)), # CvPoint offset
)

def cvStartFindContours(image, storage, header_size=sizeof(CvContour), mode=CV_RETR_LIST, method=CV_CHAIN_APPROX_SIMPLE, offset=CvPoint(0,0)):
    """CvContourScanner cvStartFindContours(CvArr image, CvMemStorage storage, int header_size=sizeofCvContour, int mode=CV_RETR_LIST, int method=CV_CHAIN_APPROX_SIMPLE, CvPoint offset=cvPoint(0, 0)

    Initializes contour scanning process
    """
    z = _cvStartFindContours(image, storage, header_size, mode, method, offset)
    z._depends = (storage,) # to make sure storage is always deleted after z is deleted
    return z

# Finds next contour in the image
_cvFindNextContour = cfunc('cvFindNextContour', _cvDLL, CvSeq_p,
    ('scanner', CvContourScanner, 1), # CvContourScanner scanner 
)

def cvFindNextContour(scanner):
    """CvSeq cvFindNextContour(CvContourScanner scanner)

    Finds next contour in the image
    """
    return pointee(_cvFindNextContour(scanner))

# Replaces retrieved contour
cvSubstituteContour = cfunc('cvSubstituteContour', _cvDLL, None,
    ('scanner', CvContourScanner, 1), # CvContourScanner scanner
    ('new_contour', CvSeq_r, 1), # CvSeq* new_contour 
)
cvSubstituteContour.__doc__ = """void cvSubstituteContour(CvContourScanner scanner, CvSeq new_contour)

Replaces retrieved contour
"""

# Finishes scanning process
_cvEndFindContours = cfunc('cvEndFindContours', _cvDLL, CvSeq_p,
    ('scanner', ByRefArg(CvContourScanner), 1), # CvContourScanner* scanner 
)

def cvEndFindContours(scanner):
    """CvSeq cvEndFindContours(CvContourScanner scanner)

    Finishes scanning process
    """
    return _cvEndFindContours(scanner)


#-----------------------------------------------------------------------------
# Segmentation
#-----------------------------------------------------------------------------


# Implements image segmentation by pyramids
_cvPyrSegmentation = cfunc('cvPyrSegmentation', _cvDLL, None,
    ('src', CvArr_r, 1), # CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('comp', ByRefArg(CvSeq_p), 1), # CvSeq** comp
    ('level', c_int, 1), # int level
    ('threshold1', c_double, 1), # double threshold1
    ('threshold2', c_double, 1), # double threshold2 
)

def cvPyrSegmentation(src, dst, storage, comp_ptr, level, threshold1, threshold2):
    """CvSeq comp = cvPyrSegmentation(CvArr src, CvArr dst, CvMemStorage storage, CvSeq_p comp_ptr, int level, double threshold1, double threshold2)

    Implements image segmentation by pyramids
    [ctypes-opencv] If 'comp_ptr' is not None, it holds the address of 'comp' as output. In any case, 'comp' is returned.
    """
    if comp_ptr is None:
        comp_ptr = CvSeq_p()
    _cvPyrSegmentation(src, dst, storage, comp_ptr, level, threshold1, threshold2)
    return pointee(comp_ptr, storage)

_default_cvTermCriteria = cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS, 5, 1)

# Does meanshift image segmentation
cvPyrMeanShiftFiltering = cfunc('cvPyrMeanShiftFiltering', _cvDLL, None,
    ('src', CvArr_r, 1), # CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('sp', c_double, 1), # double sp
    ('sr', c_double, 1), # double sr
    ('max_level', c_int, 1, 1), # int max_level=1
    ('termcrit', CvTermCriteria, 1, _default_cvTermCriteria), # CvTermCriteria termcrit=cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS,5,1)
)
cvPyrMeanShiftFiltering.__doc__ = """void cvPyrMeanShiftFiltering( const CvArr src, CvArr dst, double sp, double sr, int max_level=1, CvTermCriteria termcrit=cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS,5,1))

Does meanshift image segmentation
"""

# Does watershed segmentation
cvWatershed = cfunc('cvWatershed', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('markers', CvArr_r, 1), # CvArr* markers
)
cvWatershed.__doc__ = """void cvWatershed( const CvArr image, CvArr markers )

Does watershed segmentation
"""    


#-----------------------------------------------------------------------------
# Image and Contour moments
#-----------------------------------------------------------------------------


# Calculates all moments up to third order of a polygon or rasterized shape
cvMoments = cfunc('cvMoments', _cvDLL, None,
    ('arr', CvArr_r, 1), # const CvArr* arr
    ('moments', CvMoments_r, 1), # CvMoments* moments
    ('binary', c_int, 1, 0), # int binary
)
cvMoments.__doc__ = """void cvMoments(const CvArr arr, CvMoments moments, int binary=0)

Calculates all moments up to third order of a polygon or rasterized shape
"""

# Retrieves spatial moment from moment state structure
cvGetSpatialMoment = cfunc('cvGetSpatialMoment', _cvDLL, c_double,
    ('moments', CvMoments_r, 1), # CvMoments* moments
    ('x_order', c_int, 1), # int x_order
    ('y_order', c_int, 1), # int y_order 
)
cvGetSpatialMoment.__doc__ = """double cvGetSpatialMoment(CvMoments moments, int x_order, int y_order)

Retrieves spatial moment from moment state structure
"""

# Retrieves central moment from moment state structure
cvGetCentralMoment = cfunc('cvGetCentralMoment', _cvDLL, c_double,
    ('moments', CvMoments_r, 1), # CvMoments* moments
    ('x_order', c_int, 1), # int x_order
    ('y_order', c_int, 1), # int y_order 
)
cvGetCentralMoment.__doc__ = """double cvGetCentralMoment(CvMoments moments, int x_order, int y_order)

Retrieves central moment from moment state structure
"""

# Retrieves normalized central moment from moment state structure
cvGetNormalizedCentralMoment = cfunc('cvGetNormalizedCentralMoment', _cvDLL, c_double,
    ('moments', CvMoments_r, 1), # CvMoments* moments
    ('x_order', c_int, 1), # int x_order
    ('y_order', c_int, 1), # int y_order 
)
cvGetNormalizedCentralMoment.__doc__ = """double cvGetNormalizedCentralMoment(CvMoments moments, int x_order, int y_order)

Retrieves normalized central moment from moment state structure
"""

# Calculates seven Hu invariants
cvGetHuMoments = cfunc('cvGetHuMoments', _cvDLL, None,
    ('moments', CvMoments_r, 1), # CvMoments* moments
    ('hu_moments', CvHuMoments_r, 1), # CvHuMoments* hu_moments 
)
cvGetHuMoments.__doc__ = """void cvGetHuMoments(CvMoments moments, CvHuMoments hu_moments)

Calculates seven Hu invariants
"""


#-----------------------------------------------------------------------------
# Special Image Transforms
#-----------------------------------------------------------------------------


CV_HOUGH_STANDARD = 0
CV_HOUGH_PROBABILISTIC = 1
CV_HOUGH_MULTI_SCALE = 2
CV_HOUGH_GRADIENT = 3

# Finds lines in binary image using Hough transform
_cvHoughLines2 = cfunc('cvHoughLines2', _cvDLL, CvSeq_p,
    ('image', CvArr_r, 1), # CvArr* image
    ('line_storage', ByRefArg(CvMemStorage), 1), # void* line_storage
    ('method', c_int, 1), # int method
    ('rho', c_double, 1), # double rho
    ('theta', c_double, 1), # double theta
    ('threshold', c_int, 1), # int threshold
    ('param1', c_double, 1, 0), # double param1
    ('param2', c_double, 1, 0), # double param2
)

def cvHoughLines2(image, line_storage, method, rho, theta, threshold, param1=0, param2=0):
    """CvSeq cvHoughLines2(CvArr image, CvMemStorage_or_CvMat line_storage, int method, double rho, double theta, int threshold, double param1=0, double param2=0)

    Finds lines in binary image using Hough transform
    """
    return pointee(_cvHoughLines2(image, line_storage, method, rho, theta, threshold, param1=param1, param2=param2), line_storage)
    

# Finds circles in grayscale image using Hough transform
_cvHoughCircles = cfunc('cvHoughCircles', _cvDLL, CvSeq_p,
    ('image', CvArr_r, 1), # CvArr* image
    ('circle_storage', ByRefArg(CvMemStorage), 1), # void* circle_storage
    ('method', c_int, 1), # int method
    ('dp', c_double, 1), # double dp
    ('min_dist', c_double, 1), # double min_dist
    ('param1', c_double, 1, 100), # double param1
    ('param2', c_double, 1, 100), # double param2
    ('min_radius', c_int, 1, 0), # int min_radius
    ('max_radius', c_int, 1, 0), # int max_radius
)

def cvHoughCircles(image, circle_storage, method, dp, min_dist, param1=100, param2=100, min_radius=0, max_radius=0):
    """CvSeq cvHoughCircles(CvArr image, void* circle_storage, int method, double dp, double min_dist, double param1=100, double param2=100, min_radius=0, max_radius=0)

    Finds circles in grayscale image using Hough transform
    """
    return pointee(_cvHoughCircles(image, circle_storage, method, dp, min_dist, param1=param1, param2=param2, min_radius=min_radius, max_radius=max_radius), circle_storage)

CV_DIST_MASK_3 = 3
CV_DIST_MASK_5 = 5
CV_DIST_MASK_PRECISE = 0

# Calculates distance to closest zero pixel for all non-zero pixels of source image
cvDistTransform = cfunc('cvDistTransform', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('distance_type', c_int, 1, CV_DIST_L2), # int distance_type
    ('mask_size', c_int, 1, 3), # int mask_size
    ('mask', c_float_p, 1, None), # const float* mask
    ('labels', CvArr_r, 1, None), # CvArr* labels
)
cvDistTransform.__doc__ = """void cvDistTransform(const CvArr src, CvArr dst, int distance_type=CV_DIST_L2, int mask_size=3, const float* mask=NULL, CvArr labels=NULL)

Calculates distance to closest zero pixel for all non-zero pixels of source image
"""

CV_INPAINT_NS = 0
CV_INPAINT_TELEA = 1

# Inpaints the selected region in the image
cvInpaint = cfunc('cvInpaint', _cvDLL,  None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('mask', CvArr_r, 1), # const CvArr* mask
    ('dst', CvArr_r, 1), # const CvArr* dst
    ('flags', c_int, 1), # int flags
    ('inpaintRadius', c_double, 1), # double inpaintRadius
)
cvInpaint.__doc__ = """void cvInpaint( const CvArr src, const CvArr mask, CvArr dst, int flags, double inpaintRadius )

Inpaints the selected region in the image
"""


#-----------------------------------------------------------------------------
# Histograms
#-----------------------------------------------------------------------------


class CvHistogram(_Structure):
    _fields_ = [('type', c_int),
                ('bins', CvArr_p),
                ('thresh', (c_float*2)*CV_MAX_DIM), # for uniform histograms
                ('thresh2', POINTER(c_float_p)), # for non-uniform histograms
                ('mat', CvMatND)] # embedded matrix header for array histograms
                
    _owner = False
                
    def __del__(self):
        if self._owner is True:
            _cvReleaseHist(CvHistogram_p(self))
        
CvHistogram_p = POINTER(CvHistogram)
CvHistogram_r = ByRefArg(CvHistogram)
                

# Releases histogram
_cvReleaseHist = cfunc('cvReleaseHist', _cvDLL, None,
    ('hist', ByRefArg(CvHistogram_p), 1), # CvHistogram** hist 
)

_cvCreateHist = cfunc('cvCreateHist', _cvDLL, CvHistogram_p,
    ('dims', c_int, 1), # int dims
    ('sizes', ListPOINTER(c_int), 1), # int* sizes
    ('type', c_int, 1), # int type
    ('ranges', ListPOINTER2(c_float), 1, None), # float** ranges=NULL
    ('uniform', c_int, 1, 1), # int uniform=1
)

# Creates histogram
def cvCreateHist(sizes, type, ranges=None, uniform=1):
    """CvHistogram cvCreateHist(list_or_tuple_of_int sizes, int type, list_of_list_of_float ranges=None, int uniform=1)

    Creates histogram
    """
    z = pointee(_cvCreateHist(len(sizes), sizes, type, ranges=ranges, uniform=uniform))
    if z is not None:
        z._owner = True
    return z

# Sets bounds of histogram bins
cvSetHistBinRanges = cfunc('cvSetHistBinRanges', _cvDLL, None,
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('ranges', ListPOINTER2(c_float), 1), # float** ranges
    ('uniform', c_int, 1, 1), # int uniform
)
cvSetHistBinRanges.__doc__ = """void cvSetHistBinRanges(CvHistogram hist, list_of_list_of_float ranges, int uniform=1)

Sets bounds of histogram bins
"""

# Clears histogram
cvClearHist = cfunc('cvClearHist', _cvDLL, None,
    ('hist', CvHistogram_r, 1), # CvHistogram* hist 
)
cvClearHist.__doc__ = """void cvClearHist(CvHistogram hist)

Clears histogram
"""

# Makes a histogram out of array
_cvMakeHistHeaderForArray = cfunc('cvMakeHistHeaderForArray', _cvDLL, CvHistogram_p,
    ('dims', c_int, 1), # int dims
    ('sizes', c_int_p, 1), # int* sizes
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('data', c_float_p, 1), # float* data
    ('ranges', ListPOINTER2(c_float), 1, None), # float** ranges
    ('uniform', c_int, 1, 1), # int uniform
)

def cvMakeHistHeaderForArray(sizes, hist, data, ranges=None, uniform=1):
    """CvHistogram cvMakeHistHeaderForArray(list_or_tuple_of_int sizes, CvHistogram hist, float* data, list_of_list_of_float ranges=None, int uniform=1)

    Makes a histogram out of array
    [ctypes-opencv] If 'hist' is None, it is internally created. In any case, 'hist' is returned.
    """
    if hist is None:
        hist = CvHistogram()
    _cvMakeHistHeaderForArray(len(sizes), sizes, hist, data, ranges=ranges, uniform=uniform)
    hist._depends = (data,)
    return hist

# Finds minimum and maximum histogram bins
_cvGetMinMaxHistValue = cfunc('cvGetMinMaxHistValue', _cvDLL, None,
    ('hist', CvHistogram_r, 1), # const CvHistogram* hist
    ('min_value', ByRefArg(c_float), 1), # float* min_value
    ('max_value', ByRefArg(c_float), 1), # float* max_value
    ('min_idx', ByRefArg(c_int), 1, None), # int* min_idx
    ('max_idx', ByRefArg(c_int), 1, None), # int* max_idx
)

# Finds minimum and maximum histogram bins
def cvGetMinMaxHistValue(hist, min_val=True, max_val=True, min_idx=None, max_idx=None):
    """[float min_val][, float max_val][, int min_idx][, int max_idx] = cvGetMinMaxHistValue(const CvHistogram hist, c_float min_val=True, c_float max_val=True, c_int min_idx=None, c_int max_idx=None)

    Finds minimum and maximum histogram bins
    [ctypes-opencv] Depending on the input arguments, the returning object may be None, a single output argument, or a tuple of output arguments.
    [ctypes-opencv] min_val can be:
        True: returns the minimum value
        an instance of c_float: this holds the minimum value instead
    [ctypes-opencv] max_val can be:
        True: returns the maximum value
        an instance of c_float: this holds the maximum value instead
    [ctypes-opencv] min_idx can be:
        None: the index of the minimum value is not returned
        True: returns the index of the minimum value
        an instance of c_int: this holds the index of the minimum value instead
    [ctypes-opencv] max_idx can be:
        None: the index of the maximum value is not returned
        True: returns the index of the maximum value
        an instance of c_int: this holds the index of the maximum value instead
    """
    min_val_p = c_float() if min_val is True else min_val
    max_val_p = c_float() if max_val is True else max_val
    min_idx_p = c_int() if min_idx is True else min_idx
    max_idx_p = c_int() if max_idx is True else max_idx
    
    _cvGetMinMaxHistValue(hist, min_value=min_val_p, max_value=max_val_p, min_idx=min_idx_p, max_idx=max_idx_p)
    
    res = []
    if min_val is True:
        res.append(min_val_p.value)
    if max_val is True:
        res.append(max_val_p.value)
    if min_idx is True:
        res.append(min_idx_p.value)
    if max_idx is True:
        res.append(max_idx_p.value)
    
    if len(res) > 1:
        return tuple(res)
    if len(res) == 1:
        return res[0]

# Normalizes histogram
cvNormalizeHist = cfunc('cvNormalizeHist', _cvDLL, None,
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('factor', c_double, 1), # double factor 
)
cvNormalizeHist.__doc__ = """void cvNormalizeHist(CvHistogram hist, double factor)

Normalizes histogram
"""

# Thresholds histogram
cvThreshHist = cfunc('cvThreshHist', _cvDLL, None,
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('threshold', c_double, 1), # double threshold 
)
cvThreshHist.__doc__ = """void cvThreshHist(CvHistogram hist, double threshold)

Thresholds histogram
"""

CV_COMP_CORREL       = 0
CV_COMP_CHISQR       = 1
CV_COMP_INTERSECT    = 2
CV_COMP_BHATTACHARYYA= 3

# Compares two dense histograms
cvCompareHist = cfunc('cvCompareHist', _cvDLL, c_double,
    ('hist1', CvHistogram_r, 1), # const CvHistogram* hist1
    ('hist2', CvHistogram_r, 1), # const CvHistogram* hist2
    ('method', c_int, 1), # int method 
)
cvCompareHist.__doc__ = """double cvCompareHist(const CvHistogram hist1, const CvHistogram hist2, int method)

Compares two dense histograms
"""

# Copies histogram
_cvCopyHist = cfunc('cvCopyHist', _cvDLL, None,
    ('src', CvHistogram_r, 1), # const CvHistogram* src
    ('dst', ByRefArg(CvHistogram_p), 1, None), # CvHistogram** dst 
)

def cvCopyHist(src, dst=None):
    """CvHistogram cvCopyHist(const CvHistogram src, CvHistogram dst=None)

    Copies histogram
    [ctypes-opencv] If dst is None, a clone of src is created and returned. Otherwise, The histogram values in src are copied to dst. Warning: I haven't tested this function.
    """
    if dst is None:
        z = pointee(_cvCopyHist(src))
        if z is not None:
            z._owner = True
        return z
    _cvCopyHist(src, pointer(dst))
    return dst
    
# Calculate the histogram
cvCalcHist = cfunc('cvCalcArrHist', _cvDLL, None,
    ('image', ListByRef(CvArr), 1), # CvArr** image
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('accumulate', c_int, 1, 0), # int accumulate
    ('mask', CvArr_r, 1, None), # CvArr* mask
)
cvCalcHist.__doc = """void cvCalcHist( list_or_tuple_of_CvArr arr, CvHistogram hist, int accumulate=0, const CvArr mask=NULL )

Calculates array histogram
"""

cvCalcArrHist = cvCalcHist

# Calculates back projection
cvCalcBackProject = cfunc('cvCalcArrBackProject', _cvDLL, None,
    ('image', ListByRef(CvArr), 1), # CvArr** image
    ('back_project', CvArr_r, 1), # CvArr* back_project
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
)
cvCalcBackProject.__doc = """void cvCalcBackProject( list_or_tuple_of_CvArr image, CvArr back_project, const CvHistogram hist )

Calculates back projection
"""

# Calculates back projection
cvCalcBackProjectPatch = cfunc('cvCalcArrBackProjectPatch', _cvDLL, None,
    ('image', ListByRef(CvArr), 1), # CvArr** image
    ('dst', CvArr_r, 1), # CvArr* dst
    ('range', CvSize, 1), # CvSize range
    ('hist', CvHistogram_r, 1), # CvHistogram* hist
    ('method', c_int, 1), # int method
    ('factor', c_double, 1), # double factor
)
cvCalcBackProjectPatch.__doc = """void cvCalcBackProjectPatch( list_or_tuple_of_CvArr image, CvArr dst, CvSize range, CvHistogram hist, int method, double factor )

Calculates back projection
"""

cvCalcArrBackProjectPatch = cvCalcBackProjectPatch

# Divides one histogram by another
cvCalcProbDensity = cfunc('cvCalcProbDensity', _cvDLL, None,
    ('hist1', CvHistogram_r, 1), # const CvHistogram* hist1
    ('hist2', CvHistogram_r, 1), # const CvHistogram* hist2
    ('dst_hist', CvHistogram_r, 1), # CvHistogram* dst_hist
    ('scale', c_double, 1, 255), # double scale
)
cvCalcProbDensity.__doc__ = """void cvCalcProbDensity(const CvHistogram hist1, const CvHistogram hist2, CvHistogram dst_hist, double scale=255)

Divides one histogram by another
"""

def cvQueryHistValue_1D(hist, i1):
    """Queries value of histogram bin"""
    return cvGetReal1D(hist.bins, i1)

def cvQueryHistValue_2D(hist, i1, i2):
    """Queries value of histogram bin"""
    return cvGetReal2D(hist.bins, i1, i2)

def cvQueryHistValue_3D(hist, i1, i2, i3):
    """Queries value of histogram bin"""
    return cvGetReal2D(hist.bins, i1, i2, i3)

# Equalizes histogram of grayscale image
cvEqualizeHist = cfunc('cvEqualizeHist', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst 
)
cvEqualizeHist.__doc__ = """void cvEqualizeHist(const CvArr src, CvArr dst)

Equalizes histogram of grayscale image
"""

def cvGetHistValue_1D(hist, i1):
    """Returns pointer to histogram bin"""
    return cast(cvPtr1D(hist.bins, i1), c_float_p)

def cvGetHistValue_2D(hist, i1, i2):
    """Returns pointer to histogram bin"""
    return cast(cvPtr2D(hist.bins, i1, i2), c_float_p)

def cvGetHistValue_3D(hist, i1, i2, i3):
    """Returns pointer to histogram bin"""
    return cast(cvPtr3D(hist.bins, i1, i2, i3), c_float_p)


#-----------------------------------------------------------------------------
# Matching
#-----------------------------------------------------------------------------


CV_TM_SQDIFF = 0
CV_TM_SQDIFF_NORMED = 1
CV_TM_CCORR = 2
CV_TM_CCORR_NORMED = 3
CV_TM_CCOEFF = 4
CV_TM_CCOEFF_NORMED = 5

# Compares template against overlapped image regions
cvMatchTemplate = cfunc('cvMatchTemplate', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('templ', CvArr_r, 1), # const CvArr* templ
    ('result', CvArr_r, 1), # CvArr* result
    ('method', c_int, 1), # int method 
)
cvMatchTemplate.__doc__ = """void cvMatchTemplate(const CvArr image, const CvArr templ, CvArr result, int method)

Compares template against overlapped image regions
"""

CV_CONTOURS_MATCH_I1 = 1
CV_CONTOURS_MATCH_I2 = 2
CV_CONTOURS_MATCH_I3 = 3
CV_CONTOUR_TREES_MATCH_I1 = 1
CV_CLOCKWISE = 1
CV_COUNTER_CLOCKWISE = 2

# Compares two shapes
cvMatchShapes = cfunc('cvMatchShapes', _cvDLL, c_double,
    ('object1', c_void_p, 1), # const void* object1
    ('object2', c_void_p, 1), # const void* object2
    ('method', c_int, 1), # int method
    ('parameter', c_double, 1, 0), # double parameter
)
cvMatchShapes.__doc__ = """double cvMatchShapes(const void* object1, const void* object2, int method, double parameter=0)

Compares two shapes
"""

cvCalcEMD2 = cfunc('cvCalcEMD2', _cvDLL, c_float,
    ('signature1', CvArr_r, 1), # const CvArr* signature1
    ('signature2', CvArr_r, 1), # const CvArr* signature2
    ('distance_type', c_int, 1), # int distance_type
    ('distance_func', CvDistanceFunction, 1, None), # CvDistanceFunction distance_func
    ('cost_matrix', c_void_p, 1, None), # const CvArr* cost_matrix
    ('flow', CvArr_r, 1, None), # CvArr* flow
    ('lower_bound', c_float_p, 1, None), # float* lower_bound
    ('userdata', c_void_p, 1, None), # void* userdata
)
cvCalcEMD2.__doc__ = """float cvCalcEMD2( const CvArr signature1, const CvArr signature2, int distance_type, CvDistanceFunction distance_func=NULL, const CvArr cost_matrix=NULL, CvArr flow=NULL, float* lower_bound=NULL, void* userdata=NULL )

Computes earth mover distance between two weighted point sets (called signatures)
"""


#-----------------------------------------------------------------------------
# Contour Processing Functions
#-----------------------------------------------------------------------------


# Approximates Freeman chain(s) with polygonal curve
_cvApproxChains = cfunc('cvApproxChains', _cvDLL, CvSeq_p,
    ('src_seq', CvSeq_r, 1), # CvSeq* src_seq
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('method', c_int, 1, CV_CHAIN_APPROX_SIMPLE), # int method
    ('parameter', c_double, 1, 0), # double parameter
    ('minimal_perimeter', c_int, 1, 0), # int minimal_perimeter
    ('recursive', c_int, 1, 0), # int recursive
)

def cvApproxChains(src_seq, storage, method, parameter=0, minimal_perimeter=0, recursive=0):
    """CvSeq cvApproxChains(CvSeq src_seq, CvMemStorage storage, int method=CV_CHAIN_APPROX_SIMPLE, double parameter=0, int minimal_perimeter=0, int recursive=0)

    Approximates Freeman chain(s) with polygonal curve
    """
    return pointee(_cvApproxChains(src_seq, storage, method, parameter=parameter, minimal_perimeter=minimal_perimeter, recursive=recursive), storage)

# Initializes chain reader
_cvStartReadChainPoints = cfunc('cvStartReadChainPoints', _cvDLL, None,
    ('chain', CvChain_r, 1), # CvChain* chain
    ('reader', CvChainPtReader_r, 1), # CvChainPtReader* reader 
)

def cvStartReadChainPoints(chain, reader=None):
    """CvChainPtReader reader = cvStartReadChainPoints(CvChain chain, CvChainPtReader reader)

    Initializes chain reader
    [ctypes-opencv] If 'reader' is None, it is internally created. In any case, 'reader' is returned.
    """
    if reader is None:
        reader = CvChainPtReader()
    _cvStartReadChainPoints(chain, reader)
    reader._depends = (chain,) # to make sure chain is always deleted after reader is deleted
    return reader

# Gets next chain point
cvReadChainPoint = cfunc('cvReadChainPoint', _cvDLL, CvPoint,
    ('reader', CvChainPtReader_r, 1), # CvChainPtReader* reader 
)
cvReadChainPoint.__doc__ = """CvPoint cvReadChainPoint(CvChainPtReader reader)

Gets next chain point
"""

CV_POLY_APPROX_DP = 0

# Approximates polygonal curve(s) with desired precision
_cvApproxPoly = cfunc('cvApproxPoly', _cvDLL, CvSeq_p,
    ('src_seq', CvSeq_r, 1), # const CvSeq* src_seq
    ('header_size', c_int, 1), # int header_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('method', c_int, 1), # int method
    ('parameter', c_double, 1), # double parameter
    ('parameter2', c_int, 1, 0), # int parameter2
)

def cvApproxPoly(src_seq, header_size, storage, method, parameter, parameter2=0):
    """CvSeq cvApproxPoly(const CvSeq src_seq, int header_size, CvMemStorage storage, int method, double parameter, int parameter2=0)

    Approximates polygonal curve(s) with desired precision
    """
    return pointee(_cvApproxPoly(src_seq, header_size, storage, method, parameter, parameter2=parameter2), storage)

CV_DOMINANT_IPAN = 1

# Finds high-curvature points of the contour
_cvFindDominantPoints = cfunc('cvFindDominantPoints', _cvDLL, CvSeq_p,
    ('contour', CvSeq_r, 1), # CvSeq* contour
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('method', c_int, 1, CV_DOMINANT_IPAN), # int header_size
    ('parameter1', c_double, 1, 0), # double parameter1
    ('parameter2', c_double, 1, 0), # double parameter2
    ('parameter3', c_double, 1, 0), # double parameter3
    ('parameter4', c_double, 1, 0), # double parameter4
)

def cvFindDominantPoints(contour, storage, method=CV_DOMINANT_IPAN, parameter1=0, parameter2=0, parameter3=0, parameter4=0):
    """CvSeq cvFindDominantPoints( CvSeq contour, CvMemStorage storage, int method=CV_DOMINANT_IPAN, double parameter1=0, double parameter2=0, double parameter3=0, double parameter4=0)

    Finds high-curvature points of the contour
    """
    return pointee(_cvFindDominantPoints(contour, storage, method=method, parameter1=parameter1, parameter2=parameter2, parameter3=parameter3, parameter4=parameter4), storage)

# Calculates up-right bounding rectangle of point set
cvBoundingRect = cfunc('cvBoundingRect', _cvDLL, CvRect,
    ('points', CvArr_r, 1), # CvArr* points
    ('update', c_int, 1, 0), # int update
)
cvBoundingRect.__doc__ = """CvRect cvBoundingRect(CvArr points, int update=0)

Calculates up-right bounding rectangle of point set
"""

# Calculates area of the whole contour or contour section
cvContourArea = cfunc('cvContourArea', _cvDLL, c_double,
    ('contour', CvArr_r, 1), # const CvArr* contour
    ('slice', CvSlice, 1, CV_WHOLE_SEQ), # CvSlice slice
)
cvContourArea.__doc__ = """double cvContourArea(const CvArr contour, CvSlice slice=CV_WHOLE_SEQ)

Calculates area of the whole contour or contour section
"""

# Calculates contour perimeter or curve length
cvArcLength = cfunc('cvArcLength', _cvDLL, c_double,
    ('curve', CvSeq_r, 1), # const void* curve
    ('slice', CvSlice, 1, CV_WHOLE_SEQ), # CvSlice slice
    ('is_closed', c_int, 1, -1), # int is_closed
)
cvArcLength.__doc__ = """double cvArcLength(const CvSeq curve, CvSlice slice=CV_WHOLE_SEQ, int is_closed=-1)

Calculates contour perimeter or curve length
"""

def cvContourPerimeter(contour):
    """Calculates the contour perimeter of a contour."""
    return cvArcLength( contour, CV_WHOLE_SEQ, 1 )

# Creates hierarchical representation of contour
_cvCreateContourTree = cfunc('cvCreateContourTree', _cvDLL, CvContourTree_p,
    ('contour', CvSeq_r, 1), # const CvSeq* contour
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('threshold', c_double, 1), # double threshold 
)

def cvCreateContourTree(contour, storage, threshold):
    """CvContourTree cvCreateContourTree(const CvSeq contour, CvMemStorage storage, double threshold)

    Creates hierarchical representation of contour
    """
    return pointee(_cvCreateContourTree(contour, storage, threshold), storage)

# Restores contour from tree
_cvContourFromContourTree = cfunc('cvContourFromContourTree', _cvDLL, CvSeq_p,
    ('tree', CvContourTree_r, 1), # const CvContourTree* tree
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria 
)

def cvContourFromContourTree(tree, storage, criteria):
    """CvSeq cvContourFromContourTree(const CvContourTree tree, CvMemStorage storage, CvTermCriteria criteria)

    Restores contour from tree
    """
    return pointee(_cvContourFromContourTree(tree, storage, criteria), storage)

# Compares two contours using their tree representations
cvMatchContourTrees = cfunc('cvMatchContourTrees', _cvDLL, c_double,
    ('tree1', CvContourTree_r, 1), # const CvContourTree* tree1
    ('tree2', CvContourTree_r, 1), # const CvContourTree* tree2
    ('method', c_int, 1), # int method
    ('threshold', c_double, 1), # double threshold 
)
cvMatchContourTrees.__doc__ = """double cvMatchContourTrees(const CvContourTree tree1, const CvContourTree tree2, int method, double threshold)

Compares two contours using their tree representations
"""


#-----------------------------------------------------------------------------
# Computational Geometry
#-----------------------------------------------------------------------------


# Finds bounding rectangle for two given rectangles
cvMaxRect = cfunc('cvMaxRect', _cvDLL, CvRect,
    ('rect1', CvRect_r, 1), # const CvRect* rect1
    ('rect2', CvRect_r, 1), # const CvRect* rect2 
)
cvMaxRect.__doc__ = """CvRect cvMaxRect(const CvRect rect1, const CvRect rect2)

Finds bounding rectangle for two given rectangles
"""

# Initializes point sequence header from a point vector
_cvPointSeqFromMat = cfunc('cvPointSeqFromMat', _cvDLL, CvSeq_p,
    ('seq_kind', c_int, 1), # int seq_kind
    ('mat', CvArr_r, 1), # const CvArr* mat
    ('contour_header', CvContour_r, 1), # CvContour* contour_header
    ('block', CvSeqBlock_r, 1), # CvSeqBlock* block 
)

def cvPointSeqFromMat(seq_kind, mat, contour_header=None, block=None):
    """(CvSeq seq, CvContour contour_header, CvSeqBlock block) = cvPointSeqFromMat(int seq_kind, const CvArr mat, CvContour contour_header=None, CvSeqBlock block=None)

    Initializes point sequence header from a point vector
    [ctypes-opencv] If 'contour_header' is None, it is internally created.
    [ctypes-opencv] If 'block' is None, it is internally created.
    [ctypes-opencv] In any case, both 'seq', 'contour_header' and 'block' are returned.
    """
    if contour_header is None:
        contour_header = CvContour()
    if block is None:
        block = CvSeqBlock()
    return pointee(_cvPointSeqFromMat(seq_kind, mat, contour_header, block), mat, contour_header, block), contour_header, block

# Finds box vertices
_cvBoxPoints = cfunc('cvBoxPoints', _cvDLL, None,
    ('box', CvBox2D, 1), # CvBox2D box
    ('pt', CvPoint2D32f*4, 1), # CvPoint2D32f pt
)

def cvBoxPoints(box, pt=None):
    """CvPoint2D32f[4] cvBoxPoints(CvBox2D box, CvPoint2D32f pt[4]=None)

    Finds box vertices
    [ctypes-opencv] If 'pt' is None, it is internally created. In any case, 'pt' is returned.
    """
    if pt is None:
        pt = (CvPoint2D32f*4)()
    _cvBoxPoints(box, pt)
    return pt

# Fits ellipse to set of 2D points
cvFitEllipse2 = cfunc('cvFitEllipse2', _cvDLL, CvBox2D,
    ('points', CvArr_r, 1), # const CvArr* points 
)
cvFitEllipse2.__doc__ = """CvBox2D cvFitEllipse2(const CvArr points)

Fits ellipse to set of 2D points
"""

# Fits line to 2D or 3D point set
cvFitLine = cfunc('cvFitLine', _cvDLL, None,
    ('points', CvArr_r, 1), # const CvArr* points
    ('dist_type', c_int, 1), # int dist_type
    ('param', c_double, 1), # double param
    ('reps', c_double, 1), # double reps
    ('aeps', c_double, 1), # double aeps
    ('line', c_float_p, 1), # float* line 
)
cvFitLine.__doc__ = """void cvFitLine(const CvArr points, int dist_type, double param, double reps, double aeps, float* line)

Fits line to 2D or 3D point set
"""

# Finds convex hull of point set
_cvConvexHull2 = cfunc('cvConvexHull2', _cvDLL, CvSeq_p,
    ('input', CvArr_r, 1), # const CvArr* input
    ('hull_storage', CvArr_r, 1, None), # void* hull_storage
    ('orientation', c_int, 1, CV_CLOCKWISE), # int orientation
    ('return_points', c_int, 1, 0), # int return_points
)

def cvConvexHull2(input, hull_storage=None, orientation=CV_CLOCKWISE, return_points=0):
    """CvSeq_or_CvMat cvConvexHull2(list_or_tuple_of_CvPointXYZ input, void* hull_storage=NULL, int orientation=CV_CLOCKWISE, int return_points=0)

    Finds convex hull of point set
    [ctypes-opencv] OpenCV's note: a vertex of the detected convex hull can be represented by:
        a point of the same type with every point in 'input', if return_points==1
        an index to a point in 'input', if return_points==0 and hull_storage is a CvMat
        a pointer to a point in 'input', if return_points==0 and hull_storage is a CvStorage        
    [ctypes-opencv] If input is a (subclass of) CvSeq, 'hull_storage' can be:
        None: detected vertices are stored in input's storage
        an instance of CvStorage or CvMat: detected vertices are stored here
    [ctypes-opencv] If input is 1d CvMat of 2D 32-bit points, 'hull_storage' can be:
        None: 'hull_storage' is internally created as a 1d CvMat of 2D 32-bit points.
        an instance of CvStorage or CvMat: detected vertices are stored here
    [ctypes-opencv] In any case, the function returns a sequence (CvSeq) of detected vertices if 'hull_storage' is an instance CvStorage, or 'hull_storage' itself if otherwise.
    """
    if isinstance(input, _CvSeqStructure): # a sequence
            return pointee(_cvConvexHull2(input, hull_storage, orientation, return_points), input if hull_storage is None else hull_storage)
            
    if hull_storage is None:
        hull_storage = cvCreateMat(1, input.rows*input.cols, CV_MAT_TYPE(input) if return_points else CV_32SC1)
    _cvConvexHull2(input, hull_storage, orientation, return_points)
    return hull_storage

# Tests contour convex
cvCheckContourConvexity = cfunc('cvCheckContourConvexity', _cvDLL, c_int,
    ('contour', CvArr_r, 1), # const CvArr* contour 
)
cvCheckContourConvexity.__doc__ = """int cvCheckContourConvexity(const CvArr contour)

Tests contour convex
"""

# Finds convexity defects of contour
_cvConvexityDefects = cfunc('cvConvexityDefects', _cvDLL, CvSeq_p,
    ('contour', CvArr_r, 1), # const CvArr* contour
    ('convexhull', CvArr_r, 1), # const CvArr* convexhull
    ('storage', CvMemStorage_r, 1, None), # CvMemStorage* storage
)

def cvConvexityDefects(contour, convexhull, storage=None):
    """CvSeq cvConvexityDefects(const CvArr contour, const CvArr convexhull, CvMemStorage storage=NULL)

    Finds convexity defects of contour
    """
    return pointee(_cvConvexityDefects(contour, convexhull, storage=storage), storage)

# Point in contour test
cvPointPolygonTest = cfunc('cvPointPolygonTest', _cvDLL, c_double,
    ('contour', CvArr_r, 1), # const CvArr* contour
    ('pt', CvPoint2D32f, 1), # CvPoint2D32f pt
    ('measure_dist', c_int, 1), # int measure_dist 
)
cvPointPolygonTest.__doc__ = """double cvPointPolygonTest(const CvArr contour, CvPoint2D32f pt, int measure_dist)

Point in contour test
"""

# Finds circumscribed rectangle of minimal area for given 2D point set
cvMinAreaRect2 = cfunc('cvMinAreaRect2', _cvDLL, CvBox2D,
    ('points', CvArr_r, 1), # const CvArr* points
    ('storage', CvMemStorage_r, 1, None), # CvMemStorage* storage
)
cvMinAreaRect2.__doc__ = """CvBox2D cvMinAreaRect2(const CvArr points, CvMemStorage storage=NULL)

Finds circumscribed rectangle of minimal area for given 2D point set
"""

# Finds circumscribed circle of minimal area for given 2D point set
_cvMinEnclosingCircle = cfunc('cvMinEnclosingCircle', _cvDLL, c_int,
    ('points', CvArr_r, 1), # const CvArr* points
    ('center', ByRefArg(CvPoint2D32f), 1), # CvPoint2D32f* center
    ('radius', ByRefArg(c_float), 1), # float* radius 
)

def cvMinEnclosingCircle(points):
    """(int success, CvPoint2D32f center, float radius) = cvMinEnclosingCircle(const CvArr points)

    Finds circumscribed circle of minimal area for given 2D point set
    """
    center = CvPoint2D32f()
    radius = c_float()
    success = _cvMinEnclosingCircle(points, center, radius)
    return success, center, radius.value

# Calculates pair-wise geometrical histogram for contour
cvCalcPGH = cfunc('cvCalcPGH', _cvDLL, None,
    ('contour', CvSeq_r, 1), # const CvSeq* contour
    ('hist', CvHistogram_r, 1), # CvHistogram* hist 
)
cvCalcPGH.__doc__ = """void cvCalcPGH(const CvSeq contour, CvHistogram hist)

Calculates pair-wise geometrical histogram for contour
"""


#-----------------------------------------------------------------------------
# Planar Subdivisions
#-----------------------------------------------------------------------------


cvSubdiv2DNextEdge = CV_SUBDIV2D_NEXT_EDGE

# Returns one of edges related to given
def cvSubdiv2DGetEdge(edge, next_edge_type):
    """CvSubdiv2DEdge  cvSubdiv2DGetEdge( CvSubdiv2DEdge edge, CvNextEdgeType type )

    Returns one of edges related to given
    """
    ev = edge.value
    e = cast(c_void_p(ev & ~3), POINTER(CvQuadEdge2D))
    ev = e[0].next[(ev + next_edge_type) & 3]
    return CvSubdiv2DEdge((ev & ~3) + ((ev + (next_edge_type >> 4)) & 3))

# Returns another edge of the same quad-edge
def cvSubdiv2DRotateEdge(edge, rotate):
    """CvSubdiv2DEdge  cvSubdiv2DRotateEdge( CvSubdiv2DEdge edge, int rotate )

    Returns another edge of the same quad-edge
    """
    ev = edge.value
    return  CvSubdiv2DEdge((ev & ~3) + ((ev + rotate) & 3))

# Returns edge origin
def cvSubdiv2DEdgeOrg(edge):
    """CvSubdiv2DPoint cvSubdiv2DEdgeOrg( CvSubdiv2DEdge edge )

    Returns edge origin
    [ctypes-opencv] returns None if no point is found
    """
    ev = edge.value
    e = pointer(CvQuadEdge2D.from_address(ev & ~3))
    return pointee(e[0].pt[ev & 3])

# Returns edge destination
def cvSubdiv2DEdgeDst(edge):
    """CvSubdiv2DPoint cvSubdiv2DEdgeDst( CvSubdiv2DEdge edge )

    Returns edge destination
    [ctypes-opencv] returns None if no point is found
    """
    ev = edge.value
    e = cast(c_void_p(ev & ~3), POINTER(CvQuadEdge2D))
    return pointee(e[0].pt[(ev + 2) & 3])

# Initializes Delaunay triangulation
cvInitSubdivDelaunay2D = cfunc('cvInitSubdivDelaunay2D', _cvDLL, None,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubDiv2D* subdiv
    ('rect', CvRect, 1), # CvRect rect
)
cvInitSubdivDelaunay2D.__doc__ = """void cvInitSubdivDelaunay2D( CvSubdiv2D subdiv, CvRect rect )

Initializes Delaunay triangulation
"""

# Creates new subdivision
_cvCreateSubdiv2D = cfunc('cvCreateSubdiv2D', _cvDLL, CvSubdiv2D_p,
    ('subdiv_type', c_int, 1), # int subdiv_type
    ('header_size', c_int, 1), # int header_size
    ('vtx_size', c_int, 1), # int vtx_size
    ('quadedge_size', c_int, 1), # int quadedge_size
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
)

def cvCreateSubdiv2D(subdiv_type, header_size, vtx_size, quadedge_size, storage):
    """CvSubdiv2D cvCreateSubdiv2D( int subdiv_type, int header_size, int vtx_size, int quadedge_size, CvMemStorage storage )

    Creates new subdivision
    """
    return pointee(_cvCreateSubdiv2D(subdiv_type, header_size, vtx_size, quadedge_size, storage), storage)


# Simplified Delaunay diagram creation
def cvCreateSubdivDelaunay2D(rect, storage):
    """CvSubdiv2D* cvCreateSubdivDelaunay2D(CvRect rect, CvMemStorage storage)
    
    Simplified Delaunay diagram creation
    """
    subdiv = cvCreateSubdiv2D(CV_SEQ_KIND_SUBDIV2D, sizeof(CvSubdiv2D), sizeof(CvSubdiv2DPoint), sizeof(CvQuadEdge2D), storage)
    cvInitSubdivDelaunay2D(subdiv, rect)
    return subdiv
    
# Inserts a single point to Delaunay triangulation
_cvSubdivDelaunay2DInsert = cfunc('cvSubdivDelaunay2DInsert', _cvDLL, CvSubdiv2DPoint_p,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubdiv2D* subdiv
    ('pt', CvPoint2D32f, 1), # CvPoint2D32f pt
)
def cvSubdivDelaunay2DInsert(subdiv, pt):
    """CvSubdiv2DPoint cvSubdivDelaunay2DInsert(CvSubdiv2D subdiv, CvPoint2D32f pt)

    Inserts a single point to Delaunay triangulation
    [ctypes-opencv] returns None if no subdiv2dpoint is inserted
    """
    return pointee(_cvSubdivDelaunay2DInsert(subdiv, pt), subdiv)

# Inserts a single point to Delaunay triangulation
_cvSubdiv2DLocate = cfunc('cvSubdiv2DLocate', _cvDLL, CvSubdiv2DPointLocation,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubdiv2D* subdiv
    ('pt', CvPoint2D32f, 1), # CvPoint2D32f pt
    ('edge', ByRefArg(CvSubdiv2DEdge), 1), # CvSubdiv2DEdge* edge
    ('vertex', ByRefArg(CvSubdiv2DPoint_p), 1, None), # CvSubdiv2DPoint** vertex
)

def cvSubdiv2DLocate(subdiv, pt):
    """(CvSubdiv2DPointLocation res[, CvSubdiv2DEdge edge][, CvSubdiv2DPoint vertex]) = cvSubdiv2DLocate(CvSubdiv2D subdiv, CvPoint2D32f pt)

    Inserts a single point to Delaunay triangulation
    [ctypes-opencv] Depending on the value of 'res', addtional objects are returned. But the returning object is always a tuple.
    """
    edge = CvSubdiv2DEdge()
    vertex = CvSubdiv2DPoint_p()
    z = _cvSubdiv2DLocate(subdiv, pt, edge, vertex)
    return \
        (z, edge) if z == CV_PTLOC_INSIDE or z == CV_PTLOC_ONEDGE else \
        (z, vertex[0]) if z == CV_PTLOC_VERTEX else \
        (z,)

# Finds the closest subdivision vertex to given point
_cvFindNearestPoint2D = cfunc('cvFindNearestPoint2D', _cvDLL, CvSubdiv2DPoint_p,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubdiv2D* subdiv
    ('pt', CvPoint2D32f, 1), # CvPoint2D32f pt 
)

def cvFindNearestPoint2D(subdiv, pt):
    """CvSubdiv2DPoint cvFindNearestPoint2D(CvSubdiv2D subdiv, CvPoint2D32f pt)

    Finds the closest subdivision vertex to given point
    [ctypes-opencv] returns None if no subdiv2dpoint is found
    """
    return pointee(_cvFindNearestPoint2D(subdiv, pt), subdiv)

# Calculates coordinates of Voronoi diagram cells
cvCalcSubdivVoronoi2D = cfunc('cvCalcSubdivVoronoi2D', _cvDLL, None,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubdiv2D* subdiv 
)
cvCalcSubdivVoronoi2D.__doc__ = """void cvCalcSubdivVoronoi2D(CvSubdiv2D subdiv)

Calculates coordinates of Voronoi diagram cells
"""

# Removes all virtual points
cvClearSubdivVoronoi2D = cfunc('cvClearSubdivVoronoi2D', _cvDLL, None,
    ('subdiv', CvSubdiv2D_r, 1), # CvSubdiv2D* subdiv 
)
cvClearSubdivVoronoi2D.__doc__ = """void cvClearSubdivVoronoi2D(CvSubdiv2D subdiv)

Removes all virtual points
"""


#-----------------------------------------------------------------------------
# Accumulation of Background Statistics
#-----------------------------------------------------------------------------


# Adds frame to accumulator
cvAcc = cfunc('cvAcc', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('sum', CvArr_r, 1), # CvArr* sum
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvAcc.__doc__ = """void cvAcc(const CvArr image, CvArr sum, const CvArr mask=NULL)

Adds frame to accumulator
"""

# Adds the square of source image to accumulator
cvSquareAcc = cfunc('cvSquareAcc', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('sqsum', CvArr_r, 1), # CvArr* sqsum
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvSquareAcc.__doc__ = """void cvSquareAcc(const CvArr image, CvArr sqsum, const CvArr mask=NULL)

Adds the square of source image to accumulator
"""

# Adds product of two input images to accumulator
cvMultiplyAcc = cfunc('cvMultiplyAcc', _cvDLL, None,
    ('image1', CvArr_r, 1), # const CvArr* image1
    ('image2', CvArr_r, 1), # const CvArr* image2
    ('acc', CvArr_r, 1), # CvArr* acc
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvMultiplyAcc.__doc__ = """void cvMultiplyAcc(const CvArr image1, const CvArr image2, CvArr acc, const CvArr mask=NULL)

Adds product of two input images to accumulator
"""

# Updates running average
cvRunningAvg = cfunc('cvRunningAvg', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('acc', CvArr_r, 1), # CvArr* acc
    ('alpha', c_double, 1), # double alpha
    ('mask', CvArr_r, 1, None), # const CvArr* mask
)
cvRunningAvg.__doc__ = """void cvRunningAvg(const CvArr image, CvArr acc, double alpha, const CvArr mask=NULL)

Updates running average
"""


#-----------------------------------------------------------------------------
# Motion Templates
#-----------------------------------------------------------------------------


# Updates motion history image by moving silhouette
cvUpdateMotionHistory = cfunc('cvUpdateMotionHistory', _cvDLL, None,
    ('silhouette', CvArr_r, 1), # const CvArr* silhouette
    ('mhi', CvArr_r, 1), # CvArr* mhi
    ('timestamp', c_double, 1), # double timestamp
    ('duration', c_double, 1), # double duration 
)
cvUpdateMotionHistory.__doc__ = """void cvUpdateMotionHistory(const CvArr silhouette, CvArr mhi, double timestamp, double duration)

Updates motion history image by moving silhouette
"""

# Calculates gradient orientation of motion history image
cvCalcMotionGradient = cfunc('cvCalcMotionGradient', _cvDLL, None,
    ('mhi', CvArr_r, 1), # const CvArr* mhi
    ('mask', CvArr_r, 1), # CvArr* mask
    ('orientation', CvArr_r, 1), # CvArr* orientation
    ('delta1', c_double, 1), # double delta1
    ('delta2', c_double, 1), # double delta2
    ('aperture_size', c_int, 1, 3), # int aperture_size
)
cvCalcMotionGradient.__doc__ = """void cvCalcMotionGradient(const CvArr mhi, CvArr mask, CvArr orientation, double delta1, double delta2, int aperture_size=3)

Calculates gradient orientation of motion history image
"""

# Calculates global motion orientation of some selected region
cvCalcGlobalOrientation = cfunc('cvCalcGlobalOrientation', _cvDLL, c_double,
    ('orientation', CvArr_r, 1), # const CvArr* orientation
    ('mask', CvArr_r, 1), # const CvArr* mask
    ('mhi', CvArr_r, 1), # const CvArr* mhi
    ('timestamp', c_double, 1), # double timestamp
    ('duration', c_double, 1), # double duration 
)
cvCalcGlobalOrientation.__doc__ = """double cvCalcGlobalOrientation(const CvArr orientation, const CvArr mask, const CvArr mhi, double timestamp, double duration)

Calculates global motion orientation of some selected region
"""

# Segments whole motion into separate moving parts
_cvSegmentMotion = cfunc('cvSegmentMotion', _cvDLL, CvSeq_p,
    ('mhi', CvArr_r, 1), # const CvArr* mhi
    ('seg_mask', CvArr_r, 1), # CvArr* seg_mask
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('timestamp', c_double, 1), # double timestamp
    ('seg_thresh', c_double, 1), # double seg_thresh 
)

def cvSegmentMotion(mhi, seg_mask, storage, timestamp, seg_thresh):
    """CvSeq cvSegmentMotion(const CvArr mhi, CvArr seg_mask, CvMemStorage storage, double timestamp, double seg_thresh)

    Segments whole motion into separate moving parts
    """
    return pointee(_cvSegmentMotion(mhi, seg_mask, storage, timestamp, seg_thresh), storage)


#-----------------------------------------------------------------------------
# Object Tracking
#-----------------------------------------------------------------------------


# Finds object center on back projection
_cvMeanShift = cfunc('cvMeanShift', _cvDLL, c_int,
    ('prob_image', CvArr_r, 1), # const CvArr* prob_image
    ('window', CvRect, 1), # CvRect window
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('comp', CvConnectedComp_r, 1), # CvConnectedComp* comp 
)

def cvMeanShift(prob_image, window, criteria, comp=None):
    """(int niter, CvConnectedComp comp) = cvMeanShift(const CvArr prob_image, CvRect window, CvTermCriteria criteria, CvConnectedComp comp=None)

    Finds object center on back projection
    [ctypes-opencv] If 'comp' is None, it is internally created.
    """
    if comp is None:
        comp = CvConnectedComp()
    n = _cvMeanShift(prob_image, window, criteria, comp)
    return (n,comp)

# Finds object center, size, and orientation
_cvCamShift = cfunc('cvCamShift', _cvDLL, c_int,
    ('prob_image', CvArr_r, 1), # const CvArr* prob_image
    ('window', CvRect, 1), # CvRect window
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('comp', CvConnectedComp_r, 1), # CvConnectedComp* comp
    ('box', CvBox2D_r, 1, None), # CvBox2D* box
)

def cvCamShift(prob_image, window, criteria, comp=None, box=True):
    """(int niter, CvConnectedComp comp[, CvBox2D box]) = cvCamShift(const CvArr prob_image, CvRect window, CvTermCriteria criteria, CvConnectedComp=None, CvBox2D box=None)

    Finds object center, size, and orientation
    [ctypes-opencv] If 'comp' is None, it is internally created.
    [ctypes-opencv] 'box' can be:
        True: 'box' is internally created, filled with data, and returned.
        None: 'box' is neither created nor returned.
        an instance of CvBox2D: This holds the circumscribed box filled instead.
    [ctypes-opencv] returns number of iterations, converged component, and optionally circumscribed box
    """
    if comp is None:
        comp = CvConnectedComp()
    if box is not True:
        return (_cvCamShift(prob_image, window, criteria, comp, box), comp)
    box = CvBox2D()
    return (_cvCamShift(prob_image, window, criteria, comp, box), comp, box)

CV_VALUE = 1
CV_ARRAY = 2

# Changes contour position to minimize its energy
_cvSnakeImage = cfunc('cvSnakeImage', _cvDLL, None,
    ('image', CvArr_r, 1), # const CvArr* image
    ('points', ListPOINTER(CvPoint), 1), # CvPoint* points
    ('length', c_int, 1), # int length
    ('alpha', ListPOINTER(c_float), 1), # float* alpha
    ('beta', ListPOINTER(c_float), 1), # float* beta
    ('gamma', ListPOINTER(c_float), 1), # float* gamma
    ('coeff_usage', c_int, 1), # int coeff_usage
    ('win', CvSize, 1), # CvSize win
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('calc_gradient', c_int, 1, 1), # int calc_gradient
)

def cvSnakeImage(image, points, alpha, beta, gamma, coeff_usage, win, criteria, calc_gradient=1):
    """void cvSnakeImage(const CvArr image, list_or_tuple_of_CvPoint points, list_or_tuple_of_float alpha, list_or_tuple_of_float beta, list_or_tuple_of_float gamma, int coeff_usage, CvSize win, CvTermCriteria criteria, int calc_gradient=1)

    Changes contour position to minimize its energy
    """
    _cvSnakeImage(image, points, len(points), alpha, beta, gamma, coeff_usage, win, criteria, calc_gradient)


#-----------------------------------------------------------------------------
# Optical Flow
#-----------------------------------------------------------------------------


CV_LKFLOW_PYR_A_READY = 1
CV_LKFLOW_PYR_B_READY = 2
CV_LKFLOW_INITIAL_GUESSES = 4

# Calculates optical flow for two images
cvCalcOpticalFlowHS = cfunc('cvCalcOpticalFlowHS', _cvDLL, None,
    ('prev', CvArr_r, 1), # const CvArr* prev
    ('curr', CvArr_r, 1), # const CvArr* curr
    ('use_previous', c_int, 1), # int use_previous
    ('velx', CvArr_r, 1), # CvArr* velx
    ('vely', CvArr_r, 1), # CvArr* vely
    ('lambda', c_double, 1), # double lambda
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria 
)
cvCalcOpticalFlowHS.__doc__ = """void cvCalcOpticalFlowHS(const CvArr prev, const CvArr curr, int use_previous, CvArr velx, CvArr vely, double lambda, CvTermCriteria criteria)

Calculates optical flow for two images
"""

# Calculates optical flow for two images
cvCalcOpticalFlowLK = cfunc('cvCalcOpticalFlowLK', _cvDLL, None,
    ('prev', CvArr_r, 1), # const CvArr* prev
    ('curr', CvArr_r, 1), # const CvArr* curr
    ('win_size', CvSize, 1), # CvSize win_size
    ('velx', CvArr_r, 1), # CvArr* velx
    ('vely', CvArr_r, 1), # CvArr* vely 
)
cvCalcOpticalFlowLK.__doc__ = """void cvCalcOpticalFlowLK(const CvArr prev, const CvArr curr, CvSize win_size, CvArr velx, CvArr vely)

Calculates optical flow for two images
"""

# Calculates optical flow for two images by block matching method
cvCalcOpticalFlowBM = cfunc('cvCalcOpticalFlowBM', _cvDLL, None,
    ('prev', CvArr_r, 1), # const CvArr* prev
    ('curr', CvArr_r, 1), # const CvArr* curr
    ('block_size', CvSize, 1), # CvSize block_size
    ('shift_size', CvSize, 1), # CvSize shift_size
    ('max_range', CvSize, 1), # CvSize max_range
    ('use_previous', c_int, 1), # int use_previous
    ('velx', CvArr_r, 1), # CvArr* velx
    ('vely', CvArr_r, 1), # CvArr* vely 
)
cvCalcOpticalFlowBM.__doc__ = """void cvCalcOpticalFlowBM(const CvArr prev, const CvArr curr, CvSize block_size, CvSize shift_size, CvSize max_range, int use_previous, CvArr velx, CvArr vely)

Calculates optical flow for two images by block matching method
"""

# Calculates optical flow for a sparse feature set using iterative Lucas-Kanade method in   pyramids
_cvCalcOpticalFlowPyrLK = cfunc('cvCalcOpticalFlowPyrLK', _cvDLL, None,
    ('prev', CvArr_r, 1), # const CvArr* prev
    ('curr', CvArr_r, 1), # const CvArr* curr
    ('prev_pyr', CvArr_r, 1), # CvArr* prev_pyr
    ('curr_pyr', CvArr_r, 1), # CvArr* curr_pyr
    ('prev_features', CvPoint2D32f_p, 1), # const CvPoint2D32f* prev_features
    ('curr_features', CvPoint2D32f_p, 1), # CvPoint2D32f* curr_features
    ('count', c_int, 1), # int count
    ('win_size', CvSize, 1), # CvSize win_size
    ('level', c_int, 1), # int level
    ('status', c_char_p, 1), # char* status
    ('track_error', c_float_p, 1), # float* track_error
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('flags', c_int, 1, 0), # int flags 
)

def cvCalcOpticalFlowPyrLK(prev, curr, prev_pyr, curr_pyr, prev_features, curr_features, count, win_size, level, status=None, track_error=None, criteria=CvTermCriteria(), flags=0):
    """(curr_features, status) = cvCalcOpticalFlowPyrLK(const CvArr prev, const CvArr curr, CvArr prev_pyr, CvArr curr_pyr, array_of_CvPoint2D32f prev_features, array_of_CvPoint2D32f curr_features, int count, CvSize win_size, int level, c_array_of_c_char status=None, c_array_of_c_float track_error=None, CvTermCriteria criteria=CvTermCriteria(), int flags=0)

    Calculates optical flow for a sparse feature set using iterative Lucas-Kanade method in pyramids
    [ctypes-opencv] If 'count' is None, 'count=len(prev_features)'.
    [ctypes-opencv] If 'prev_features' is a list or a tuple of CvPoint2D32f points, it is converted into a c_array_of_CvPoint2D32f before the actual function call.
    [ctypes-opencv] If 'curr_features' is a list or a tuple of CvPoint2D32f points, it is converted into a c_array_of_CvPoint2D32f before the actual function call.
    [ctypes-opencv] If 'curr_features' is None, it is internally created as a c_array_of_CvPoint2D32f.
    [ctypes-opencv] If 'status' is None, it is internally created as a c_array_of_c_char.
    [ctypes-opencv] Returns a new list of features (curr_features) and a new status array.
    """
    if count is None:
        count = len(prev_features)
    prev_features = as_c_array(prev_features, elem_ctype=CvPoint2D32f)
    curr_features = (CvPoint2D32f*count)() if curr_features is None else as_c_array(curr_features, elem_ctype=CvPoint2D32f)
    if status is None:
        status = (c_char*count)()
    _cvCalcOpticalFlowPyrLK(prev, curr, prev_pyr, curr_pyr, prev_features, curr_features, count, win_size, level, status, track_error, criteria, flags)
    return curr_features, status


#-----------------------------------------------------------------------------
# Feature Matching
#-----------------------------------------------------------------------------


if cvVersion == 110:
    
    # supposed to be a black box
    class CvFeatureTree(_Structure):    
        def __del__(self):
            _cvReleaseFeatureTree(self)
        
    CvFeatureTree_p = POINTER(CvFeatureTree)
    CvFeatureTree_r = ByRefArg(CvFeatureTree)
        
    # Constructs a kd-tree of feature vectors
    _cvCreateFeatureTree = cfunc('cvCreateFeatureTree', _cvDLL, CvFeatureTree_p,
        ('desc', CvMat_r, 1), # CvMat* desc
    )
    
    def cvCreateFeatureTree(desc):
        """CvFeatureTree cvCreateFeatureTree(CvMat desc)
        
        Constructs a kd-tree of feature vectors
        """
        z = pointee(_cvCreateFeatureTree(desc), desc)
        z.desc = desc
        return z

    # Destroys a tree of feature vectors
    # ctypes-opencv: note this cvRelease...() is different from other cvRelease functions
    _cvReleaseFeatureTree = cfunc('cvCreateFeatureTree', _cvDLL, CvFeatureTree_p,
        ('tr', ByRefArg(CvFeatureTree), 1), # CvFeatureTree* tr
    )
    
    # Finds approximate k nearest neighbors of given vectors using best-bin-first search
    _cvFindFeatures = cfunc('cvFindFeatures', _cvDLL, None,
        ('tr', CvFeatureTree_r, 1), # CvFeatureTree* tr
        ('desc', CvMat_r, 1), # CvMat* desc
        ('result', CvMat_r, 1), # CvMat* result
        ('dist', CvMat_r, 1), # CvMat* dist
        ('k', c_int, 1, 2), # int k
        ('emax', c_int, 1, 20), # int emax
    )
    
    def cvFindFeatures(tr, desc, result=None, dist=None, k=2, emax=20):
        """(CvMat result, CvMat dist) = cvFindFeatures(CvFeatureTree tr, CvMat desc, CvMat result=None, CvMat dist=None, int k=2, int emax=20)
        
        Finds approximate k nearest neighbors of given vectors using best-bin-first search
        [ctypes-opencv] If 'result' is None, it is internally created as CV_32SC1 CvMat.
        [ctypes-opencv] If 'dist' is None, it is internally created as CV_64FC1 CvMat.
        """
        m = desc.rows
        if result is None:
            result = cvCreateMat(m, k, CV_32SC1)
        if dist is None:
            dist = cvCreateMat(m, k, CV_64FC1)
        _cvFindFeatures(tr, desc, result, dist, k=k, emax=emax)
        return (result, dist)
        
    # Orthogonal range search
    _cvFindFeaturesBoxed = cfunc('cvFindFeaturesBoxed', _cvDLL, c_int,
        ('tr', CvFeatureTree_r, 1), # CvFeatureTree* tr
        ('bounds_min', CvMat_r, 1), # CvMat* bounds_min
        ('bounds_max', CvMat_r, 1), # CvMat* bounds_max
        ('results', CvMat_r, 1), # CvMat* results
    )
    
    def cvFindFeaturesBoxed(tr, bounds_min, bounds_max, results=None):
        """(int nfeatures, CvMat results) = cvFindFeaturesBoxed(CvFeatureTree tr, CvMax bounds_min, CvMax bounds_max, CvMat results=None)
        
        Orthogonal range search
        [ctypes-opencv] If 'results' is None, it is internally created as CV_32SC1 CvMat.
        """
        if results is None:
            results = cvCreateMat(1, tr.desc.rows, CV_32SC1) if bounds_min.rows == 1 else cvCreateMat(tr.desc.rows, 1, CV_32SC1)
        n = _cvFindFeaturesBoxed(tr, bounds_min, bounds_max, results)
        return (n, results)
        
    

#-----------------------------------------------------------------------------
# Estimators
#-----------------------------------------------------------------------------


# Deallocates Kalman filter structure
_cvReleaseKalman = cfunc('cvReleaseKalman', _cvDLL, None,
    ('kalman', ByRefArg(CvKalman_p), 1), # CvKalman** kalman 
)

# Allocates Kalman filter structure
_cvCreateKalman = cfunc('cvCreateKalman', _cvDLL, CvKalman_p,
    ('dynam_params', c_int, 1), # int dynam_params
    ('measure_params', c_int, 1), # int measure_params
    ('control_params', c_int, 1, 0), # int control_params
)

def cvCreateKalman(dynam_params, measure_params, control_params=0):
    """CvKalman cvCreateKalman(int dynam_params, int measure_params, int control_params=0)

    Allocates Kalman filter structure
    [ctypes-opencv] returns None if no CvKalman is created
    """
    return pointee(_cvCreateKalman(dynam_params, measure_params, control_params=control_params))

# Estimates subsequent model state
_cvKalmanPredict = cfunc('cvKalmanPredict', _cvDLL, CvMat_p,
    ('kalman', CvKalman_r, 1), # CvKalman* kalman
    ('control', CvMat_r, 1, None), # const CvMat* control
)

def cvKalmanPredict(kalman, control=None):
    """const CvMat cvKalmanPredict(CvKalman kalman, const CvMat control=NULL)

    Estimates subsequent model state
    """
    return pointee(_cvKalmanPredict(kalman, control=control), kalman)

cvKalmanUpdateByTime = cvKalmanPredict

# Adjusts model state
_cvKalmanCorrect = cfunc('cvKalmanCorrect', _cvDLL, CvMat_p,
    ('kalman', CvKalman_r, 1), # CvKalman* kalman
    ('measurement', CvMat_r, 1), # const CvMat* measurement 
)

def cvKalmanCorrect(kalman, measurement):
    """const CvMat cvKalmanCorrect(CvKalman kalman, const CvMat measurement)

    Adjusts model state
    """
    return pointee(_cvKalmanCorrect(kalman, measurement), kalman)

cvKalmanUpdateByMeasurement = cvKalmanCorrect

# Deallocates ConDensation filter structure
_cvReleaseConDensation = cfunc('cvReleaseConDensation', _cvDLL, None,
    ('condens', ByRefArg(CvConDensation_p), 1), # CvConDensation** condens 
)

_cvCreateConDensation = cfunc('cvCreateConDensation', _cvDLL, CvConDensation_p,
    ('dynam_params', c_int, 1), # int dynam_params
    ('measure_params', c_int, 1), # int measure_params
    ('sample_count', c_int, 1), # int sample_count 
)

# Allocates ConDensation filter structure
def cvCreateConDensation(dynam_params, measure_params, sample_count):
    """CvConDensation cvCreateConDensation(int dynam_params, int measure_params, int sample_count)

    Allocates ConDensation filter structure
    [ctypes-opencv] returns None if no CvConDensation is created
    """
    return pointee(_cvCreateConDensation(dynam_params, measure_params, sample_count))

# Initializes sample set for ConDensation algorithm
cvConDensInitSampleSet = cfunc('cvConDensInitSampleSet', _cvDLL, None,
    ('condens', CvConDensation_r, 1), # CvConDensation* condens
    ('lower_bound', CvMat_r, 1), # CvMat* lower_bound
    ('upper_bound', CvMat_r, 1), # CvMat* upper_bound 
)
cvConDensInitSampleSet.__doc__ = """void cvConDensInitSampleSet(CvConDensation condens, CvMat lower_bound, CvMat upper_bound)

Initializes sample set for ConDensation algorithm
"""

# Estimates subsequent model state
cvConDensUpdateByTime = cfunc('cvConDensUpdateByTime', _cvDLL, None,
    ('condens', CvConDensation_r, 1), # CvConDensation* condens 
)
cvConDensUpdateByTime.__doc__ = """void cvConDensUpdateByTime(CvConDensation condens)

Estimates subsequent model state
"""


#-----------------------------------------------------------------------------
# Object Detection
#-----------------------------------------------------------------------------


# Releases haar classifier cascade
_cvReleaseHaarClassifierCascade = cfunc('cvReleaseHaarClassifierCascade', _cvDLL, None,
    ('cascade', ByRefArg(CvHaarClassifierCascade_p), 1), # CvHaarClassifierCascade** cascade 
)

# Loads a trained cascade classifier from file or the classifier database embedded in OpenCV
_cvLoadHaarClassifierCascade = cfunc('cvLoadHaarClassifierCascade', _cvDLL, CvHaarClassifierCascade_p,
    ('directory', c_char_p, 1), # const char* directory
    ('orig_window_size', CvSize, 1), # CvSize orig_window_size 
)

def cvLoadHaarClassifierCascade(directory, orig_window_size):
    """CvHaarClassifierCascade cvLoadHaarClassifierCascade(const char* directory, CvSize orig_window_size)

    Loads a trained cascade classifier from file or the classifier database embedded in OpenCV
    [ctypes-opencv] returns None if no cascade is loaded
    """
    return pointee(_cvLoadHaarClassifierCascade(directory, orig_window_size))


CV_HAAR_DO_CANNY_PRUNING = 1
CV_HAAR_SCALE_IMAGE = 2
if cvVersion == 110:
    CV_HAAR_FIND_BIGGEST_OBJECT = 4 
    CV_HAAR_DO_ROUGH_SEARCH = 8


# Detects objects in the image
_cvHaarDetectObjects = cfunc('cvHaarDetectObjects', _cvDLL, CvSeq_p,
    ('image', CvArr_r, 1), # const CvArr* image
    ('cascade', CvHaarClassifierCascade_r, 1), # CvHaarClassifierCascade* cascade
    ('storage', CvMemStorage_r, 1), # CvMemStorage* storage
    ('scale_factor', c_double, 1, 1.1), # double scale_factor
    ('min_neighbors', c_int, 1, 3), # int min_neighbors
    ('flags', c_int, 1, 0), # int flags
    ('min_size', CvSize, 1, cvSize(0,0)), # CvSize min_size
)

def cvHaarDetectObjects(image, cascade, storage, scale_factor=1.1, min_neighbors=3, flags=0, min_size=cvSize(0,0)):
    """CvSeq cvHaarDetectObjects(const CvArr image, CvHaarClassifierCascade cascade, CvMemStorage storage, double scale_factor=1.1, int min_neighbors=3, int flags=0, CvSize min_size=cvSize(0, 0)

    Detects objects in the image
    """
    return pointee(_cvHaarDetectObjects(image, cascade, storage, scale_factor=scale_factor, min_neighbors=min_neighbors, flags=flags, min_size=min_size), storage).asarray(CvRect)
    
# Assigns images to the hidden cascade
cvSetImagesForHaarClassifierCascade = cfunc('cvSetImagesForHaarClassifierCascade', _cvDLL, None,
    ('cascade', CvHaarClassifierCascade_r, 1), # CvHaarClassifierCascade* cascade
    ('sum', CvArr_r, 1), # const CvArr* sum
    ('sqsum', CvArr_r, 1), # const CvArr* sqsum
    ('tilted_sum', CvArr_r, 1), # const CvArr* tilted_sum
    ('scale', c_double, 1), # double scale 
)
cvSetImagesForHaarClassifierCascade.__doc__ = """void cvSetImagesForHaarClassifierCascade(CvHaarClassifierCascade cascade, const CvArr sum, const CvArr sqsum, const CvArr tilted_sum, double scale)

Assigns images to the hidden cascade
"""

# Runs cascade of boosted classifier at given image location
cvRunHaarClassifierCascade = cfunc('cvRunHaarClassifierCascade', _cvDLL, c_int,
    ('cascade', CvHaarClassifierCascade_r, 1), # CvHaarClassifierCascade* cascade
    ('pt', CvPoint, 1), # CvPoint pt
    ('start_stage', c_int, 1, 0), # int start_stage
)
cvRunHaarClassifierCascade.__doc__ = """int cvRunHaarClassifierCascade(CvHaarClassifierCascade cascade, CvPoint pt, int start_stage=0)

Runs cascade of boosted classifier at given image location
"""


#-----------------------------------------------------------------------------
# Camera Calibration
#-----------------------------------------------------------------------------


if cvVersion == 110:
    # Projects 3D points to image plane
    _cvProjectPoints2 = cfunc('cvProjectPoints2', _cvDLL, None,
        ('object_points', CvMat_r, 1), # const CvMat* object_points
        ('rotation_vector', CvMat_r, 1), # const CvMat* rotation_vector
        ('translation_vector', CvMat_r, 1), # const CvMat* translation_vector
        ('intrinsic_matrix', CvMat_r, 1), # const CvMat* intrinsic_matrix
        ('distortion_coeffs', CvMat_r, 1), # const CvMat* distortion_coeffs
        ('image_points', CvMat_r, 1), # CvMat* image_points
        ('dpdrot', CvMat_r, 1, None), # CvMat* dpdrot
        ('dpdt', CvMat_r, 1, None), # CvMat* dpdt
        ('dpdf', CvMat_r, 1, None), # CvMat* dpdf
        ('dpdc', CvMat_r, 1, None), # CvMat* dpdc
        ('dpddist', CvMat_r, 1, None), # CvMat* dpddist
        ('aspect_ratio', c_double, 1, 0), # double aspect_ratio
    )
    
    def cvProjectPoints2(object_points, rotation_vector, intrinsic_matrix, distortion_coeffs, image_points=None, dpdrot=None, dpdt=None, dpdf=None, dpdc=None, dpddist=None, aspect_ratio=0):
        """void cvProjectPoints2(const CvMat object_points, const CvMat rotation_vector, const CvMat translation_vector, const CvMat intrinsic_matrix, const CvMat distortion_coeffs, CvMat image_points=None, CvMat dpdrot=NULL, CvMat dpdt=NULL, CvMat dpdf=NULL, CvMat dpdc=NULL, CvMat dpddist=NULL, double aspect_ratio=0)
        
        Projects 3D points to image plane
        [ctypes-opencv] If 'image_points' is None, it is internally created. In any case, 'image_points' is returned.
        """
        if image_points is None:
            sz = (1, object_points.cols) if object_points.rows == 1 else (object_points.rows, 1)
            image_points = cvCreateMat(sz[0], sz[1], CV_MAKETYPE(CV_MAT_DEPTH(object_points), 2))
        _cvProjectPoints2(object_points, rotation_vector, intrinsic_matrix, distortion_coeffs, image_points, dpdrot, dpdt, dpdf, dpdc, dpddist, aspect_ratio)
        return image_points

    # Finds perspective transformation between two planes
    CV_LMEDS = 4
    CV_RANSAC = 8    

    _cvFindHomography = cfunc('cvFindHomography', _cvDLL, c_int,
        ('src_points', CvMat_r, 1), # const CvMat* src_points
        ('dst_points', CvMat_r, 1), # const CvMat* dst_points
        ('homography', CvMat_r, 1), # CvMat* homography 
        ('method', c_int, 1, 0), # int method
        ('ransacReprojThreshold', c_double, 1, 0), # double ransacReprojThreshold
        ('mask', CvMat_r, 1, None), # CvMat* mask
    )

    def cvFindHomography(src_points, dst_points, homography=None, method=0, ransacReprojThreshold=0, mask=None):
        """(CvMat homography, CvMat mask) = cvFindHomography(const CvMat src_points, const CvMat dst_points, CvMat homography=None, int method=0, double ransacReprojThreshold=0, CvMat mask=None)

        Finds perspective transformation between two planes
        [ctypes-opencv] If 'homography' is None, it is internally created as a 3x3 CV_64FC1 CvMat.
        [ctypes-opencv] Internally, OpenCV creates a temporary mask if 'mask' is not given. Thus, if 'mask' is None, it is internally created by ctypes-opencv as a CV_8U CvMat.
        [ctypes-opencv] A RuntimeError is raised if calling the function is not successful. Otherwise, both 'homography' and 'mask' are returned.
        """
        if homography is None:
            homography = cvCreateMat(3, 3, CV_64FC1)
        if mask is None:
            mask = cvCreateMat(dst_points.height, dst_points.width, CV_8U)
        result = _cvFindHomography(src_points, dst_points, homography, method, ransacReprojThreshold, mask)
        if not result:
            raise RuntimeError("Calling cvFindHomography() was not successful.")
        return (homography, mask)
        
    CV_CALIB_FIX_FOCAL_LENGTH = 16
    CV_CALIB_FIX_K1 = 32
    CV_CALIB_FIX_K2 = 64
    CV_CALIB_FIX_K3 = 128
    CV_CALIB_FIX_INTRINSIC = 256
    CV_CALIB_SAME_FOCAL_LENGTH = 512
    CV_CALIB_ZERO_DISPARITY = 1024
    
    # Finds intrinsic and extrinsic camera parameters using calibration pattern
    cvCalibrationMatrixValues = cfunc('cvCalibrationMatrixValues', _cvDLL, None,
        ('calibMatr', CvMat_r, 1), # const CvMat* calibMatr
        ('imgWidth', c_int, 1), # int imgWidth
        ('imgHeight', c_int, 1), # int imgHeight
        ('apertureWidth', c_double, 1, 0), # double apertureWidth
        ('apertureHeight', c_double, 1, 0), # double apertureHeight
        ('fovx', ByRefArg(c_double), 1, None), # double *fovx
        ('fovy', ByRefArg(c_double), 1, None), # double *fovy
        ('focalLength', ByRefArg(c_double), 1, None), # double focalLength
        ('principalPoint', ByRefArg(CvPoint2D64f), 1, None), # CvPoint2D64f* principalPoint
        ('pixelAspectRatio', ByRefArg(c_double), 1, None), # double* pixelAspectRatio
    )
    
    def cvCalibrationMatrixValues(calibMatr, image_size, apertureWidth=0, apertureHeight=0, fovx=None, fovy=None, focalLength=None, principalPoint=None, pixelAspectRatio=None):
        """(double fovx, double fovy, double focalLength, CvPoint2D64f principalPoint, double pixelAspectRatio) = cvCalibrationMatrixValues( const CvMat calibMatr, CvSize image_size, double apertureWidth=0, double apertureHeight=0, c_double fovx=NULL, c_double fovy=NULL, c_double focalLength=NULL, CvPoint2D64f principalPoint=NULL, c_double pixelAspectRatio=NULL )
        
        Finds intrinsic and extrinsic camera parameters using calibration pattern
        [ctypes-opencv] (imgWidth, imgHeight) is replaced by CvSize image_size
        [ctypes-opencv] For every output parameter, if it is 'None', it is internally created. In any case, all output parameters are returned by value.
        """
        if fovx is None:
            fovx = c_double()
        if fovy is None:
            fovy = c_double()
        if focalLength is None:
            focalLength = c_double()
        if principalPoint is None:
            principalPoint = CvPoint2D64f()
        if pixelAspectRatio is None:
            pixelAspectRatio = c_double()
        _cvCalibrationMatrixValues(calibMatr, image_size.width, image_size.height, apertureWidth, apertureHeight, fovx, fovy, focalLength, principalPoint, pixelAspectRatio)
        return fovx.value, fovy.value, focalLength.value, principalPoint, pixelAspectRatio.value
    
    # Calibrates stereo camera
    _cvStereoCalibrate = cfunc('cvStereoCalibrate', _cvDLL, None,
        ('object_points', CvMat_r, 1), # const CvMat* object_points
        ('image_points1', CvMat_r, 1), # const CvMat* image_points1
        ('image_points2', CvMat_r, 1), # const CvMat* image_points2
        ('point_counts', CvMat_r, 1), # const CvMat* point_counts
        ('camera_matrix1', CvMat_r, 1), # const CvMat* camera_matrix1
        ('dist_coeffs1', CvMat_r, 1), # CvMat* dist_coeffs1
        ('camera_matrix2', CvMat_r, 1), # const CvMat* camera_matrix2
        ('dist_coeffs2', CvMat_r, 1), # CvMat* dist_coeffs2
        ('image_size', CvSize, 1), # CvSize image_size
        ('R', CvMat_r, 1), # CvMat* R
        ('T', CvMat_r, 1), # CvMat* T
        ('E', CvMat_r, 1, None), # CvMat* E
        ('F', CvMat_r, 1, None), # CvMat* F
        ('term_crit', CvTermCriteria, 1, cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS, 30, 1e-6)), # CvTermCriteria term_crit
        ('flags', c_int, 1, CV_CALIB_FIX_INTRINSIC),
    )
    
    def cvStereoCalibrate(object_points, image_points1, image_points2, point_counts, camera_matrix1, dist_coeffs1, camera_matrix2, dist_coeffs2, image_size, R, T, E=None, F=None, term_crit=cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS,30,1e-6), flags=CV_CALIB_FIX_INTRINSIC):
        """(camera_matrix1, dist_coeffs1, camera_matrix2, dist_coeffs2) = cvStereoCalibrate( const CvMat object_points, const CvMat image_points1, const CvMat image_points2, const CvMat point_counts, CvMat camera_matrix1, CvMat dist_coeffs1, CvMat camera_matrix2, CvMat dist_coeffs2, CvSize image_size, CvMat R, CvMat T, CvMat E=None, CvMat F=None, CvTermCriteria term_crit=cvTermCriteria(CV_TERMCRIT_ITER+CV_TERMCRIT_EPS,30,1e-6), int flags=CV_CALIB_FIX_INTRINSIC )
                            
        Calibrates stereo camera
        [ctypes-opencv] 'camera_matrix1', 'dist_coeffs1', 'camera_matrix2', 'dist_coeffs2' are returned.
        """
        _cvStereoCalibrate(object_points, image_points1, image_points2, point_counts, camera_matrix1, dist_coeffs1, camera_matrix2, dist_coeffs2, image_size, R, T, E, F, term_crit, flags)
        return camera_matrix1, dist_coeffs1, camera_matrix2, dist_coeffs2
    
    # Computes rectification transform for stereo camera
    _cvStereoRectify = cfunc('cvStereoRectify', _cvDLL, None,
        ('camera_matrix1', CvMat_r, 1), # const CvMat* camera_matrix1
        ('camera_matrix2', CvMat_r, 1), # const CvMat* camera_matrix2
        ('dist_coeffs1', CvMat_r, 1), # const CvMat* dist_coeffs1
        ('dist_coeffs2', CvMat_r, 1), # const CvMat* dist_coeffs2
        ('image_size', CvSize, 1), # CvSize image_size
        ('R', CvMat_r, 1), # const CvMat* R
        ('T', CvMat_r, 1), # const CvMat* T
        ('R1', CvMat_r, 1), # CvMat* R1
        ('R2', CvMat_r, 1), # CvMat* R2
        ('P1', CvMat_r, 1), # CvMat* P1
        ('P2', CvMat_r, 1), # CvMat* P2
        ('Q', CvMat_r, 1, None), # CvMat* Q
        ('flags', c_int, 1, CV_CALIB_ZERO_DISPARITY), # int flags
    )
    
    def cvStereoRectify(camera_matrix1, camera_matrix2, dist_coeffs1, dist_coeffs2, image_size, R, T, R1=None, R2=None, P1=None, P2=None, Q=None, flags=CV_CALIB_ZERO_DISPARITY):
        """(R1, R2, P1, P2[, Q]) = void cvStereoRectify( const CvMat camera_matrix1, const CvMat camera_matrix2, const CvMat dist_coeffs1, const CvMat dist_coeffs2, CvSize image_size, const CvMat R, const CvMat T, CvMat R1=None, CvMat R2=None, CvMat P1=None, CvMat P2=None, CvMat Q=None, int flags=CV_CALIB_ZERO_DISPARITY )
        
        Computes rectification transform for stereo camera
        [ctypes-opencv] For each 'R1', 'R2', 'P1', 'P2', if it is None, it is internally created as a CV_64FC1 CvMat.
        [ctypes-opencv] 'Q' can be:
            None: 'Q' is neither computed nor returned.
            True: 'Q' is internally created as a CV_64FC1 CvMat, filled with output, and returned.
            an instance of CvMat: output for 'Q' is filled in this instance. The instance is also returned.
        """
        if R1 is None:
            R1 = cvCreateMat(3, 3, CV_64FC1)
        if R2 is None:
            R2 = cvCreateMat(3, 3, CV_64FC1)
        if P1 is None:
            P1 = cvCreateMat(3, 4, CV_64FC1)
        if P2 is None:
            P2 = cvCreateMat(3, 4, CV_64FC1)
        if Q is None:
            _cvStereoRectify(camera_matrix1, camera_matrix2, dist_coeffs1, dist_coeffs2, image_size, R, T, R1, R2, P1, P2, None, flags)
            return R1, R2, P1, P2

        if Q is True:
            Q = cvCreateMat(4, 4, CV_64FC1)
        _cvStereoRectify(camera_matrix1, camera_matrix2, dist_coeffs1, dist_coeffs2, image_size, R, T, R1, R2, P1, P2, Q, flags)
        return R1, R2, P1, P2, Q
        
    
    # Computes rectification transform for uncalibrated stereo camera
    _cvStereoRectifyUncalibrated = cfunc('cvStereoRectifyUncalibrated', _cvDLL, None,
        ('points1', CvMat_r, 1), # const CvMat* points1
        ('points2', CvMat_r, 1), # const CvMat* points2
        ('F', CvMat_r, 1), # const CvMat* F
        ('image_size', CvSize, 1), # CvSize image_size
        ('H1', CvMat_r, 1), # CvMat* H1
        ('H2', CvMat_r, 1), # CvMat* H2
        ('threshold', c_double, 1, 5), # double threshold
        
    )
    
    def cvStereoRectifyUncalibrated(points1, points2, F, image_size, H1=None, H2=None, threshold=5):
        """(H1, H2) = cvStereoRectifyUncalibrated( const CvMat points1, const CvMat points2, const CvMat F, CvSize image_size, CvMat H1=None, CvMat H2=None, double threshold=5 )
        
        Computes rectification transform for uncalibrated stereo camera
        [ctypes-opencv] If any of 'H1' or 'H2' is None, it is created internally created as a 3x3 CV_64FC1 CvMat. In any case, both of them are returned.
        """
        if H1 is None:
            H1 = cvCreateMat(3, 3, CV_64FC1)
        if H2 is None:
            H2 = cvCreateMat(3, 3, CV_64FC1)
        _cvStereoRectifyUncalibrated(points1, points2, F, image_size, H1, H2, threshold)
        return H1, H2
    
    # Computes undistortion+rectification transformation map a head of stereo camera
    _cvInitUndistortRectifyMap = cfunc('cvInitUndistortRectifyMap', _cvDLL, None,
        ('camera_matrix', CvMat_r, 1), # const CvMat* camera_matrix
        ('dist_coeffs', CvMat_r, 1), # const CvMat* dist_coeffs
        ('R', CvMat_r, 1), # const CvMat* R
        ('new_camera_matrix', CvMat_r, 1), # const CvMat* new_camera_matrix
        ('mapx', CvMat_r, 1), # const CvMat* mapx
        ('mapy', CvMat_r, 1), # const CvMat* mapy
    )
    
    def cvInitUndistortRectifyMap(camera_matrix, dist_coeffs, R, new_camera_matrix, mapx, mapy):
        """(new_camera_matrix, mapx, mapy) = cvInitUndistortRectifyMap( const CvMat* camera_matrix, const CvMat* dist_coeffs, const CvMat* R, const CvMat* new_camera_matrix, CvArr* mapx, CvArr* mapy )
        
        Computes undistortion+rectification transformation map a head of stereo camera
        [ctypes-opencv] If 'new_camera_matrix' is None, it is internally created as a 3x3 CV_64FC1 CvMat. In any case, 'new_camera_matrix', 'mapx', and 'mapy' are returned.
        """
        if new_camera_matrix is None:
            new_camera_matrix = cvCreateMat(3, 3, CV_64FC1)
        _cvInitUndistortRectifyMap(camera_matrix, dist_coeffs, R, new_camera_matrix, mapx, mapy)
        return new_camera_matrix, mapx, mapy
    
    # Computes the ideal point coordinates from the observed point coordinates
    cvUndistortPoints = cfunc('cvUndistortPoints', _cvDLL, None,
        ('src', CvMat_r, 1), # const CvMat* src
        ('dst', CvMat_r, 1), # const CvMat* dst
        ('camera_matrix', CvMat_r, 1), # const CvMat* camera_matrix
        ('dist_coeffs', CvMat_r, 1), # const CvMat* dist_coeffs
        ('R', CvMat_r, 1, None), # const CvMat* R
        ('P', CvMat_r, 1, None), # const CvMat* P
    )
    cvUndistortPoints.__doc = """void cvUndistortPoints( const CvMat src, CvMat dst, const CvMat camera_matrix, const CvMat dist_coeffs, const CvMat* R=NULL, const CvMat* P=NULL)
    
    Computes the ideal point coordinates from the observed point coordinates
    """

elif cvVersion == 100:
    # Projects 3D points to image plane
    _cvProjectPoints2 = cfunc('cvProjectPoints2', _cvDLL, None,
        ('object_points', CvMat_r, 1), # const CvMat* object_points
        ('rotation_vector', CvMat_r, 1), # const CvMat* rotation_vector
        ('translation_vector', CvMat_r, 1), # const CvMat* translation_vector
        ('intrinsic_matrix', CvMat_r, 1), # const CvMat* intrinsic_matrix
        ('distortion_coeffs', CvMat_r, 1), # const CvMat* distortion_coeffs
        ('image_points', CvMat_r, 1), # CvMat* image_points
        ('dpdrot', CvMat_r, 1, None), # CvMat* dpdrot
        ('dpdt', CvMat_r, 1, None), # CvMat* dpdt
        ('dpdf', CvMat_r, 1, None), # CvMat* dpdf
        ('dpdc', CvMat_r, 1, None), # CvMat* dpdc
        ('dpddist', CvMat_r, 1, None), # CvMat* dpddist
    )
    def cvProjectPoints2(object_points, rotation_vector, intrinsic_matrix, distortion_coeffs, image_points=None, dpdrot=None, dpdt=None, dpdf=None, dpdc=None, dpddist=None):
        """void cvProjectPoints2(const CvMat object_points, const CvMat rotation_vector, const CvMat translation_vector, const CvMat intrinsic_matrix, const CvMat distortion_coeffs, CvMat image_points=None, CvMat dpdrot=NULL, CvMat dpdt=NULL, CvMat dpdf=NULL, CvMat dpdc=NULL, CvMat dpddist=NULL)

        Projects 3D points to image plane
        [ctypes-opencv] If 'image_points' is None, it is internally created. In any case, 'image_points' is returned.
        """
        if image_points is None:
            sz = (1, object_points.cols) if object_points.rows == 1 else (object_points.rows, 1)
            image_points = cvCreateMat(sz[0], sz[1], CV_MAKETYPE(CV_MAT_DEPTH(object_points), 2))
        _cvProjectPoints2(object_points, rotation_vector, intrinsic_matrix, distortion_coeffs, image_points, dpdrot, dpdt, dpdf, dpdc, dpddist)
        return image_points

    # Finds perspective transformation between two planes
    _cvFindHomography = cfunc('cvFindHomography', _cvDLL, None,
        ('src_points', CvMat_r, 1), # const CvMat* src_points
        ('dst_points', CvMat_r, 1), # const CvMat* dst_points
        ('homography', CvMat_r, 1), # CvMat* homography 
    )

    def cvFindHomography(src_points, dst_points, homography=None):
        """CvMat homography = cvFindHomography(const CvMat src_points, const CvMat dst_points, CvMat homography=None)

        Finds perspective transformation between two planes
        [ctypes-opencv] If 'homography' is None, it is internally createed as a 3x3 CvMat. In any case, 'homography' is returned.
        """
        if homography is None:
            homography = cvCreateMat(3, 3, CV_64FC1)
        _cvFindHomography(src_points, dst_points, homography)
        return homography

CV_CALIB_USE_INTRINSIC_GUESS = 1
CV_CALIB_FIX_ASPECT_RATIO = 2
CV_CALIB_FIX_PRINCIPAL_POINT = 4
CV_CALIB_ZERO_TANGENT_DIST = 8

# Finds intrinsic and extrinsic camera parameters using calibration pattern
_cvCalibrateCamera2 = cfunc('cvCalibrateCamera2', _cvDLL, None,
    ('object_points', CvMat_r, 1), # const CvMat* object_points
    ('image_points', CvMat_r, 1), # const CvMat* image_points
    ('point_counts', CvMat_r, 1), # const CvMat* point_counts
    ('image_size', CvSize, 1), # CvSize image_size
    ('intrinsic_matrix', CvMat_r, 1), # CvMat* intrinsic_matrix
    ('distortion_coeffs', CvMat_r, 1), # CvMat* distortion_coeffs
    ('rotation_vectors', CvMat_r, 1, None), # CvMat* rotation_vectors
    ('translation_vectors', CvMat_r, 1, None), # CvMat* translation_vectors
    ('flags', c_int, 1, 0), # int flags
)

def cvCalibrateCamera2(object_points, image_points, point_counts, image_size, intrinsic_matrix=None, distortion_coeffs=None, rotation_vectors=None, translation_vectors=None, flags=0):
    """void cvCalibrateCamera2(const CvMat object_points, const CvMat image_points, const CvMat point_counts, CvSize image_size, CvMat intrinsic_matrix=None, CvMat distortion_coeffs=None, CvMat rotation_vectors=NULL, CvMat translation_vectors=NULL, int flags=0)

    Finds intrinsic and extrinsic camera parameters using calibration pattern
    [ctypes-opencv] If 'intrinsic_matrix' is None, it is internally created with random data.
    [ctypes-opencv] If 'distortion_coeffs' is None, it is internally created as a 1x5 CV_64FC1 CvMat.
    [ctypes-opencv] In any case, both 'intrinsic_matrix' and 'distortion_coeffs' are returned.
    """
    if intrinsic_matrix is None:
        intrinsic_matrix = cvCreateMat(3, 3, CV_64FC1)
    if distortion_coeffs is None:
        distortion_coeffs = cvCreateMat(1, 5, CV_64FC1)
    _cvCalibrateCamera2(object_points, image_points, point_counts, image_size, intrinsic_matrix, distortion_coeffs, rotation_vectors, translation_vectors, flags)
    return intrinsic_matrix, distortion_coeffs
        
# Finds extrinsic camera parameters for particular view
_cvFindExtrinsicCameraParams2 = cfunc('cvFindExtrinsicCameraParams2', _cvDLL, None,
    ('object_points', CvMat_r, 1), # const CvMat* object_points
    ('image_points', CvMat_r, 1), # const CvMat* image_points
    ('intrinsic_matrix', CvMat_r, 1), # const CvMat* intrinsic_matrix
    ('distortion_coeffs', CvMat_r, 1), # const CvMat* distortion_coeffs
    ('rotation_vector', CvMat_r, 1), # CvMat* rotation_vector
    ('translation_vector', CvMat_r, 1), # CvMat* translation_vector 
)

def cvFindExtrinsicCameraParams2(object_points, image_points, intrinsic_matrix, distortion_coeffs, rotation_vector=None, translation_vector=None):
    """(rotation_vector, translation_vector) = cvFindExtrinsicCameraParams2(const CvMat object_points, const CvMat image_points, const CvMat intrinsic_matrix, const CvMat distortion_coeffs, CvMat rotation_vector=None, CvMat translation_vector=None)

    Finds extrinsic camera parameters for particular view
    [ctypes-opencv] If any of 'rotation_vector' and 'translation_vector' is None, it is internally created as a 1x3 CV_64FC1 CvMat. In any case, both of them are returned.
    """
    if rotation_vector is None:
        rotation_vector = cvCreateMat(1, 3, CV_64FC1)
    if translation_vector is None:
        translation_vector = cvCreateMat(1, 3, CV_64FC1)
    _cvFindExtrinsicCameraParams2(object_points, image_points, intrinsic_matrix, distortion_coeffs, rotation_vector, translation_vector)
    return rotation_vector, translation_vector

# Converts rotation matrix to rotation vector or vice versa
cvRodrigues2 = cfunc('cvRodrigues2', _cvDLL, c_int,
    ('src', CvMat_r, 1), # const CvMat* src
    ('dst', CvMat_r, 1), # CvMat* dst
    ('jacobian', CvMat_r, 1, None), # CvMat* jacobian
)
cvRodrigues2.__doc__ = """int cvRodrigues2(const CvMat src, CvMat* dst, CvMat* jacobian=0)

Converts rotation matrix to rotation vector or vice versa
"""

# Transforms image to compensate lens distortion
cvUndistort2 = cfunc('cvUndistort2', _cvDLL, None,
    ('src', CvArr_r, 1), # const CvArr* src
    ('dst', CvArr_r, 1), # CvArr* dst
    ('intrinsic_matrix', CvMat_r, 1), # const CvMat* intrinsic_matrix
    ('distortion_coeffs', CvMat_r, 1), # const CvMat* distortion_coeffs 
)
cvUndistort2.__doc__ = """void cvUndistort2(const CvArr src, CvArr dst, const CvMat intrinsic_matrix, const CvMat distortion_coeffs)

Transforms image to compensate lens distortion
"""

# Computes undistorion map
cvInitUndistortMap = cfunc('cvInitUndistortMap', _cvDLL, None,
    ('intrinsic_matrix', CvMat_r, 1), # const CvMat* intrinsic_matrix
    ('distortion_coeffs', CvMat_r, 1), # const CvMat* distortion_coeffs
    ('mapx', CvArr_r, 1), # CvArr* mapx
    ('mapy', CvArr_r, 1), # CvArr* mapy 
)
cvInitUndistortMap.__doc__ = """void cvInitUndistortMap(const CvMat intrinsic_matrix, const CvMat distortion_coeffs, CvArr mapx, CvArr mapy)

Computes undistorion map
"""

CV_CALIB_CB_ADAPTIVE_THRESH = 1
CV_CALIB_CB_NORMALIZE_IMAGE = 2
CV_CALIB_CB_FILTER_QUADS = 4

_cvFindChessboardCorners = cfunc('cvFindChessboardCorners', _cvDLL, c_int,
    ('image', CvArr_r, 1), # const void* image
    ('pattern_size', CvSize, 1), # CvSize pattern_size
    ('corners', CvPoint2D32f_p, 1), # CvPoint2D32f* corners
    ('corner_count', ByRefArg(c_int), 1, None), # int* corner_count
    ('flags', c_int, 1, CV_CALIB_CB_ADAPTIVE_THRESH), # int flags
)

# Finds positions of internal corners of the chessboard
def cvFindChessboardCorners(image, pattern_size, corners=None, corner_count=None, flags=CV_CALIB_CB_ADAPTIVE_THRESH):
    """(int pattern_found, c_array_of_CvPoint2D32f out_corners) = cvFindChessboardCorners(const CvArr image, CvSize pattern_size, c_array_of_CvPoint2D32f corners=None, c_int corner_count=None, int flags=CV_CALIB_CB_ADAPTIVE_THRESH)

    Finds positions of internal corners of the chessboard
    [ctypes-opencv] If 'corners' is None, it is internally created as a c_array of CvPoint2D32f items.
    [ctypes-opencv] In any case, an integer indicating if the pattern was found, and a c_array of N CvPoint2D32f items is returned, where N is the number of detected corners. 
    """
    if corners is None:
        corners = (CvPoint2D32f*(pattern_size.width*pattern_size.height))()
    if corner_count is None:
        corner_count = c_int()
    found = _cvFindChessboardCorners(image, pattern_size, corners, corner_count, flags)
    return found, as_c_array(corners, n=corner_count.value, elem_ctype=CvPoint2D32f)
    
_cvDrawChessboardCorners = cfunc('cvDrawChessboardCorners', _cvDLL, None,
    ('image', CvArr_r, 1), # CvArr* image
    ('pattern_size', CvSize, 1), # CvSize pattern_size
    ('corners', CvPoint2D32f_p, 1), # CvPoint2D32f* corners
    ('count', c_int, 1), # int count
    ('pattern_was_found', c_int, 1), # int pattern_was_found 
)

# Renders the detected chessboard corners
def cvDrawChessboardCorners(image, pattern_size, corners, pattern_was_found):
    """void cvDrawChessboardCorners(CvArr image, CvSize pattern_size, c_array_of_CvPoint2D32f corners)

    Renders the detected chessboard corners
    """
    _cvDrawChessboardCorners(image, pattern_size, corners, len(corners), pattern_was_found)


#-----------------------------------------------------------------------------
# Pose Estimation
#-----------------------------------------------------------------------------


class CvPOSITObject(_Structure):
    _fields_ = [
        ('N', c_int), # int N
        ('inv_matr', c_float_p), # float* inv_matr
        ('obj_vecs', c_float_p), # float* obj_vecs
        ('img_vecs', c_float_p), # float* img_vecs
    ]
    
    def __del__(self):
        _cvReleasePOSITObject(CvPOSITObject_p(self))
        
CvPOSITObject_p = POINTER(CvPOSITObject)
CvPOSITObject_r = ByRefArg(CvPOSITObject)

# Deallocates 3D object structure
_cvReleasePOSITObject = cfunc('cvReleasePOSITObject', _cvDLL, None,
    ('posit_object', ByRefArg(CvPOSITObject_p), 1), # CvPOSITObject** posit_object 
)

_cvCreatePOSITObject = cfunc('cvCreatePOSITObject', _cvDLL, CvPOSITObject_p,
    ('points', ListPOINTER(CvPoint3D32f), 1), # CvPoint3D32f* points
    ('point_count', c_int, 1), # int point_count 
)

# Initializes structure containing object information
def cvCreatePOSITObject(points):
    """CvPOSITObject cvCreatePOSITObject(list_or_tuple_of_CvPoint3D32f points)

    Initializes structure containing object information
    [ctypes-opencv] returns None if no posit object is created
    """
    return pointee(_cvCreatePOSITObject(points, len(points)))

# Implements POSIT algorithm
cvPOSIT = cfunc('cvPOSIT', _cvDLL, None,
    ('posit_object', CvPOSITObject_r, 1), # CvPOSITObject* posit_object
    ('image_points', CvPoint2D32f_r, 1), # CvPoint2D32f* image_points
    ('focal_length', c_double, 1), # double focal_length
    ('criteria', CvTermCriteria, 1), # CvTermCriteria criteria
    ('rotation_matrix', CvMatr32f, 1), # CvMatr32f rotation_matrix
    ('translation_vector', CvVect32f, 1), # CvVect32f translation_vector 
)
cvPOSIT.__doc__ = """void cvPOSIT(CvPOSITObject posit_object, CvPoint2D32f image_points, double focal_length, CvTermCriteria criteria, CvMatr32f rotation_matrix, CvVect32f translation_vector)

Implements POSIT algorithm
"""

# Calculates homography matrix for oblong planar object (e.g. arm)
cvCalcImageHomography = cfunc('cvCalcImageHomography', _cvDLL, None,
    ('line', c_float_p, 1), # float* line
    ('center', CvPoint3D32f_r, 1), # CvPoint3D32f* center
    ('intrinsic', c_float_p, 1), # float* intrinsic
    ('homography', c_float_p, 1), # float* homography 
)
cvCalcImageHomography.__doc__ = """void cvCalcImageHomography(float* line, CvPoint3D32f center, float* intrinsic, float* homography)

Calculates homography matrix for oblong planar object (e.g. arm)
"""


#-----------------------------------------------------------------------------
# Epipolar Geometry
#-----------------------------------------------------------------------------


if cvVersion == 110:
    CV_FM_7POINT = 1
    CV_FM_8POINT = 2
    CV_FM_LMEDS_ONLY = CV_LMEDS
    CV_FM_RANSAC_ONLY = CV_RANSAC
    CV_FM_LMEDS = CV_LMEDS
    CV_FM_RANSAC = CV_RANSAC

    # Calculates fundamental matrix from corresponding points in two images
    cvFindFundamentalMat = cfunc('cvFindFundamentalMat', _cvDLL, c_int,
        ('points1', CvMat_r, 1), # const CvMat* points1
        ('points2', CvMat_r, 1), # const CvMat* points2
        ('fundamental_matrix', CvMat_r, 1), # CvMat* fundamental_matrix
        ('method', c_int, 1, CV_FM_RANSAC), # int method
        ('param1', c_double, 1, 3), # double param1
        ('param2', c_double, 1, 0), # double param2
        ('status', CvMat_r, 1, None), # CvMat* status
    )
    cvFindFundamentalMat.__doc__ = """int cvFindFundamentalMat(const CvMat points1, const CvMat points2, CvMat fundamental_matrix, int method=CV_FM_RANSAC, double param1=3., double param2=0, CvMat status=None)

    Calculates fundamental matrix from corresponding points in two images
    """

elif cvVersion == 100:
    CV_FM_7POINT = 1
    CV_FM_8POINT = 2
    CV_FM_LMEDS_ONLY = 4
    CV_FM_RANSAC_ONLY = 8
    CV_FM_LMEDS = CV_FM_LMEDS_ONLY + CV_FM_8POINT
    CV_FM_RANSAC = CV_FM_RANSAC_ONLY + CV_FM_8POINT

    # Calculates fundamental matrix from corresponding points in two images
    cvFindFundamentalMat = cfunc('cvFindFundamentalMat', _cvDLL, c_int,
        ('points1', CvMat_r, 1), # const CvMat* points1
        ('points2', CvMat_r, 1), # const CvMat* points2
        ('fundamental_matrix', CvMat_r, 1), # CvMat* fundamental_matrix
        ('method', c_int, 1, CV_FM_RANSAC), # int method
        ('param1', c_double, 1, 1), # double param1
        ('param2', c_double, 1, 0), # double param2
        ('status', CvMat_r, 1, None), # CvMat* status
    )
    cvFindFundamentalMat.__doc__ = """int cvFindFundamentalMat(const CvMat points1, const CvMat points2, CvMat fundamental_matrix, int method=CV_FM_RANSAC, double param1=1., double param2=0., CvMat status=None)

    Calculates fundamental matrix from corresponding points in two images
    """

# For points in one image of stereo pair computes the corresponding epilines in the other image
cvComputeCorrespondEpilines = cfunc('cvComputeCorrespondEpilines', _cvDLL, None,
    ('points', CvMat_r, 1), # const CvMat* points
    ('which_image', c_int, 1), # int which_image
    ('fundamental_matrix', CvMat_r, 1), # const CvMat* fundamental_matrix
    ('correspondent_lines', CvMat_r, 1), # CvMat* correspondent_lines
)
cvComputeCorrespondEpilines.__doc__ = """void cvComputeCorrespondEpilines(const CvMat points, int which_image, const CvMat fundamental_matrix, CvMat correspondent_line)

For points in one image of stereo pair computes the corresponding epilines in the other image
"""

# Convert points to/from homogeneous coordinates
if cvVersion == 110:
    cvConvertPointsHomogeneous = cfunc('cvConvertPointsHomogeneous', _cvDLL, None,
        ('src', CvMat_r, 1), # const CvMat* src
        ('dst', CvMat_r, 1), # CvMat* dst 
    )
    cvConvertPointsHomogeneous.__doc__ = """void cvConvertPointsHomogeneous(const CvMat src, CvMat dst)

    Convert points to/from homogeneous coordinates
    """
    
    cvConvertPointsHomogenious = cvConvertPointsHomogeneous
elif cvVersion == 100:
    cvConvertPointsHomogenious = cfunc('cvConvertPointsHomogenious', _cvDLL, None,
        ('src', CvMat_r, 1), # const CvMat* src
        ('dst', CvMat_r, 1), # CvMat* dst 
    )
    cvConvertPointsHomogenious.__doc__ = """void cvConvertPointsHomogeneous(const CvMat src, CvMat dst)

    Convert points to/from homogeneous coordinates
    """
    
    cvConvertPointsHomogeneous = cvConvertPointsHomogenious

if cvVersion == 110:
    class CvStereoBMState(_Structure):
        _fields_ = [
            # pre-filtering (normalization of input images)
            ('preFilterType', c_int),
            ('preFilterSize', c_int),
            ('preFilterCap', c_int),
            
            # correspondence using Sum of Absolute Difference (SAD)
            ('SADWindowSize', c_int),
            ('minDisparity', c_int),
            ('numberOfDisparities', c_int),
            
            # post-filtering
            ('textureThreshold', c_int),
            ('uniquenessRatio', c_int),
            ('speckleWindowSize', c_int),
            ('speckleRange', c_int),

            # temporary buffers
            ('preFilteredImg0', CvMat_p),
            ('preFilteredImg1', CvMat_p),
            ('slidingSumBuf', CvMat_p),
        ]
        
        def __del__(self):
            _cvReleaseStereoBMState(CvStereoBMState_p(self))
            
    CvStereoBMState_p = POINTER(CvStereoBMState)
    CvStereoBMState_r = ByRefArg(CvStereoBMState)
        
    CV_STEREO_BM_BASIC = 0
    CV_STEREO_BM_FISH_EYE = 1
    CV_STEREO_BM_NARROW = 2
    
    # Creates block matching stereo correspondence structure
    _cvCreateStereoBMState = cfunc('cvCreateStereoBMState', _cvDLL, CvStereoBMState_p,
        ('preset', c_int, 1, CV_STEREO_BM_BASIC), # int preset
        ('numberOfDisparities', c_int, 1, 0), # int numberOfDisparities
    )
    
    def cvCreateStereoBMState(preset=CV_STEREO_BM_BASIC, numberOfDisparities=0):
        """CvStereoBMState cvCreateStereoBMState( int preset=CV_STEREO_BM_BASIC, int numberOfDisparities=0 )
        
        Creates block matching stereo correspondence structure
        """
        return pointee(_cvCreateStereoBMState(preset=preset, numberOfDisparities=numberOfDisparities))
        
    # Releases block matching stereo correspondence structure
    _cvReleaseStereoBMState = cfunc('cvReleaseStereoBMState', _cvDLL, None,
        ('state', ByRefArg(CvStereoBMState_p), 1), # CvStereoBMState_p** state
    )
    
    # Computes the disparity map using block matching algorithm
    _cvFindStereoCorrespondenceBM = cfunc('cvFindStereoCorrespondenceBM', _cvDLL, None,
        ('left', CvArr_r, 1), # const CvArr* left
        ('right', CvArr_r, 1), # const CvArr* right
        ('disparity', CvArr_r, 1), # const CvArr* disparity
        ('state', CvStereoBMState, 1), # const CvStereoBMState* state
    )    
    
    def cvFindStereoCorrespondenceBM(left, right, disparity, state):
        """CvArr disparity = cvFindStereoCorrespondenceBM( const CvArr left, const CvArr right, CvArr disparity, CvStereoBMState state)
        
        Computes the disparity map using block matching algorithm
        [ctypes-opencv] If 'disparity' is None, it is internally created as a CV_16SC1 CvMat.
        """
        if disparity is None:
            disparity = cvCreateMat(left.rows, left.cols, CV_16SC1)
        _cvFindStereoCorrespondenceBM(left, right, disparity, state)
        return disparity
    
    # The structure for graph cuts-based stereo correspondence algorithm
    class CvStereoGCState(_Structure):
        _fields_ = [
            ('Ithreshold', c_int),            
            ('interactionRadius', c_int),
            ('K', c_float),
            ('lambdA', c_float),
            ('lambdA1', c_float),
            ('lambdA2', c_float),
            ('occlusionCost', c_int),
            ('minDisparity', c_int),
            ('numberOfDisparities', c_int),
            ('maxIters', c_int),

            # internal buffers
            ('left', CvMat),
            ('right', CvMat),
            ('dispLeft', CvMat),
            ('dispRight', CvMat),
            ('ptrLeft', CvMat),
            ('ptrRight', CvMat),
            ('vtxBuf', CvMat),
            ('edgeBuf', CvMat),
       ]
        
        def __del__(self):
            _cvReleaseStereoGCState(CvStereoGCState_p(self))
            
    CvStereoGCState_p = POINTER(CvStereoGCState)
    CvStereoGCState_r = ByRefArg(CvStereoGCState)
            
    # Creates the state of graph cut-based stereo correspondence algorithm
    _cvCreateStereoGCState = cfunc('cvCreateStereoGCState', _cvDLL, CvStereoGCState_p,
        ('numberOfDisparities', c_int, 1), # int numberOfDisparities
        ('maxIters', c_int, 1), # int maxIters
    )
    
    def cvCreateStereoGCState(numberOfDisparities, maxIters):
        """CvStereoGCState cvCreateStereoGCState( int numberOfDisparities, int maxIters )
        
        Creates the state of graph cut-based stereo correspondence algorithm
        """
        return pointee(_cvCreateStereoGCState(numberOfDisparities, maxIters))
        
    # Releases the state structure of the graph cut-based stereo correspondence algorithm
    _cvReleaseStereoGCState = cfunc('cvReleaseStereoGCState', _cvDLL, None,
        ('state', ByRefArg(CvStereoGCState_p), 1), # CvStereoGCState_p** state
    )
    
    # Computes the disparity map using graph cut-based algorithm
    _cvFindStereoCorrespondenceGC = cfunc('cvFindStereoCorrespondenceGC', _cvDLL, None,
        ('left', CvArr_r, 1), # const CvArr* left
        ('right', CvArr_r, 1), # const CvArr* right
        ('dispLeft', CvArr_r, 1), # const CvArr* left
        ('dispRight', CvArr_r, 1), # const CvArr* right
        ('state', CvStereoGCState, 1), # const CvStereoGCState* state
        ('useDisparityGuess', c_int, 1, 0), # const CvStereoGCState* state
    )
    
    def cvFindStereoCorrespondenceGC(left, right, dispLeft, dispRight, state, useDisparityGuess=0):
        """(dispLeft, dispRight) = cvFindStereoCorrespondenceGC( const CvArr left, const CvArr right, CvArr dispLeft, CvArr dispRight, CvStereoGCState state, int useDisparityGuess=0)
        
        Computes the disparity map using graph cut-based algorithm
        [ctypes-opencv] If any of 'dispLeft' and 'dispRight' is None, it is internally created as a CV_16SC1 CvMat.
        """
        if dispLeft is None:
            dispLeft = cvCreateMat(left.rows, left.cols, CV_16SC1)
        if dispRight is None:
            dispRight = cvCreateMat(left.rows, left.cols, CV_16SC1)
        _cvFindStereoCorrespondenceGC(left, righ, dispLeft, dispRight, state, useDisparityGuess)
        return dispLeft, dispRight
    
    # Reprojects disparity image to 3D space
    cvReprojectImageTo3D = cfunc('cvReprojectImageTo3D', _cvDLL, None,
        ('disparity', CvArr_r, 1), # const CvArr* disparity
        ('_3dimage', CvArr_r, 1), # CvArr* _3dimage
        ('Q', CvArr_r, 1), # const CvArr* Q
    )
    cvReprojectImageTo3D.__doc__ = """void cvReprojectImageTo3D( const CvArr disparity, CvArr _3dImage, const CvMat Q )
    
    Reprojects disparity image to 3D space
    """

# --- 1 Image Processing -----------------------------------------------------

# --- 1.1 Gradients, Edges and Corners ---------------------------------------

# --- 1.2 Sampling, Interpolation and Geometrical Transforms -----------------

# --- 1.3 Morphological Operations -------------------------------------------

# --- 1.4 Filters and Color Conversion ---------------------------------------

# --- 1.5 Pyramids and the Applications --------------------------------------

# --- 1.6 Connected Components -----------------------------------------------

# --- 1.7 Image and Contour moments ------------------------------------------

# --- 1.8 Special Image Transforms -------------------------------------------

# --- 1.9 Histograms ---------------------------------------------------------

# --- 1.10 Matching ----------------------------------------------------------

# --- 2 Structural Analysis --------------------------------------------------

# --- 2.1 Contour Processing Functions ---------------------------------------

# --- 2.2 Computational Geometry ---------------------------------------------

# --- 2.3 Planar Subdivisions ------------------------------------------------

# --- 3 Motion Analysis and Object Tracking ----------------------------------

# --- 3.1 Accumulation of Background Statistics ------------------------------

# --- 3.2 Motion Templates ---------------------------------------------------

# --- 3.3 Object Tracking ----------------------------------------------------

# --- 3.4 Optical Flow -------------------------------------------------------

# --- 3.5 Estimators ---------------------------------------------------------

# --- 4 Pattern Recognition --------------------------------------------------

# --- 4.1 Object Detection ---------------------------------------------------

# --- 5 Camera Calibration and 3D Reconstruction -----------------------------

# --- 5.1 Camera Calibration -------------------------------------------------

# --- 5.2 Pose Estimation ----------------------------------------------------

# --- 5.3 Epipolar Geometry --------------------------------------------------


#=============================================================================
# End of of cv/cv.h
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
