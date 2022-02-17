# Copyright (c) 2015, Hubert Kario
#
# See the LICENSE file for legal information regarding use of this file.
"""Methods for dealing with ECC points"""

from .codec import Parser, Writer
from .cryptomath import bytesToNumber, numberToByteArray, numBytes
from .compat import ecdsaAllCurves
from libs.ecdsa import ecdsa, curves

def decodeX962Point(data, curve=curves.NIST256p):
    """Decode a point from a X9.62 encoding"""
    parser = Parser(data)
    encFormat = parser.get(1)
    assert encFormat == 4
    bytelength = getPointByteSize(curve)
    xCoord = bytesToNumber(parser.getFixBytes(bytelength))
    yCoord = bytesToNumber(parser.getFixBytes(bytelength))
    return ecdsa.ellipticcurve.Point(curve.curve, xCoord, yCoord)

def encodeX962Point(point):
    """Encode a point in X9.62 format"""
    bytelength = numBytes(point.curve().p())
    writer = Writer()
    writer.add(4, 1)
    writer.bytes += numberToByteArray(point.x(), bytelength)
    writer.bytes += numberToByteArray(point.y(), bytelength)
    return writer.bytes

def getCurveByName(curveName):
    """Return curve identified by curveName"""
    curveMap = {'secp256r1':curves.NIST256p,
                'secp384r1':curves.NIST384p,
                'secp521r1':curves.NIST521p,
                'secp256k1':curves.SECP256k1}
    if ecdsaAllCurves:
        curveMap['secp224r1'] = curves.NIST224p
        curveMap['secp192r1'] = curves.NIST192p

    if curveName in curveMap:
        return curveMap[curveName]
    else:
        raise ValueError("Curve of name '{0}' unknown".format(curveName))

def getPointByteSize(point):
    """Convert the point or curve bit size to bytes"""
    curveMap = {curves.NIST256p.curve: 256//8,
                curves.NIST384p.curve: 384//8,
                curves.NIST521p.curve: (521+7)//8,
                curves.SECP256k1.curve: 256//8}
    if ecdsaAllCurves:
        curveMap[curves.NIST224p.curve] = 224//8
        curveMap[curves.NIST192p.curve] = 192//8

    if hasattr(point, 'curve'):
        if callable(point.curve):
            return curveMap[point.curve()]
        else:
            return curveMap[point.curve]
    raise ValueError("Parameter must be a curve or point on curve")
