#!/usr/bin/env python
"""
CANVAS NTLM for all your NTLM and NTLMv2 needs
"""

"""
http://en.wikipedia.org/wiki/LM_hash
The LM hash is computed as follows.[1]

   1. The user's password as an OEM string is converted to uppercase.
   2. This password is either null-padded or truncated to 14 bytes.
   3. The fixed-length password is split into two 7-byte halves.
   4. These values are used to create two DES keys, one from each 7-byte half.
   5. Each of these keys is used to DES-encrypt the constant ASCII string KGS!@#$%, resulting in two 8-byte ciphertext values.
   6. These two ciphertext values are concatenated to form a 16-byte value, which is the LM hash.

#another good resource is here.
   http://davenport.sourceforge.net/ntlm.html#type2MessageExample
"""
import sys
if "." not in sys.path: sys.path.append(".")

from exploitutils import *
import libs.Crypto.Cipher.DES as DES
#DES, in particular
import struct 
import libs.Crypto.Hash.MD4 as MD4 #for ntlm hash

def get_lanman_hash(password):
    """
    gets a lanman hash given a password
    """
    if password==None:
        password=""
    constant="KGS!@#$%"
    password=password.upper()
    password=stroverwrite("\x00"*14,password,0)[:14]
    d=DES.DES(password[:7])
    first=d.encrypt(constant)
    d=DES.DES(password[7:])
    last=d.encrypt(constant)
    total=first+last
    #pad out to 21 bytes
    total=total+"\x00"*(21-len(total))
    return total

def calculate_lanman_response(key, challenge):
    """
    key has been generated with get_lanman_hash
    challege is from remote server
    we return a 24 byte string (the response)
    """
    #three seven byte keys
    key1=key[:7]
    key2=key[7:14]
    key3=key[14:]
    if len(key3)<7:
        key3=key3+"\x00"*(7-len(key3))        
    #print "Key3: %s"%prettyhexprint(key3)
    resp1=DES.DES(key1).encrypt(challenge)
    resp2=DES.DES(key2).encrypt(challenge)
    resp3=DES.DES(key3).encrypt(challenge)
    return resp1+resp2+resp3

def is_passed_hash(password):
    """
    Users have the option to pass a NTLMv1 LM hash rather than
    using a password - this checks (stupidly) to see if
    that's what we have.
    """
    if not password:
        return False
    if len(password)==32 and isprint(password):
        return True 
    return False 
    
def ntlmHash(password):
    """
    Calculates the NTLM hash for the password
(from NTLM.html documentation)
The NTLM response is calculated as follows (see Appendix A for a sample Java implementation):

   1. The MD4 message-digest algorithm (described in RFC 1320) is applied to the Unicode mixed-case password. This results in a 16-byte value - the NTLM hash.
   2. The 16-byte NTLM hash is null-padded to 21 bytes.
   3. This value is split into three 7-byte thirds.
   4. These values are used to create three DES keys (one from each 7-byte third).
   5. Each of these keys is used to DES-encrypt the challenge from the Type 2 message (resulting in three 8-byte ciphertext values).
   6. These three ciphertext values are concatenated to form a 24-byte value. This is the NTLM response.

    """
    #password should be unicode so we do that first
    #(I have no idea how we plan to handle actual unicode passwords)
    
    #here we check to see if they passed in a password hash
    #as if they stole it using the getpasswordhashes module
    #and then we just use the hash as our password
    #rather than MD4ing it
    if is_passed_hash(password):
        return binstring(password) + "\x00"*5
    
    #otherwise, we have a normal password 
    password=backwardsunistring(password)
    m=MD4.MD4()
    m.update(password)
    ret=m.digest()
    return ret 

def get_ntlm_response(password, challenge):
    """
    does the NTLM hash and then the lanman response to get the full
    NTLM key from a password and a challenge
    """
    nt_key=ntlmHash(password)
    #uses lanman response after getting nt key (weird, but true)
    nt_key=calculate_lanman_response(nt_key, challenge)
    return nt_key 
    
def getNTLMauth(domain, hostname, username, password, unicode):
    """
    
    """
    auth=NTLM()
    auth.domain=domain
    auth.hostname=hostname
    auth.type=NTLMSSP_NEGOTIATE
    auth.add_security_buffer(auth.domain)
    auth.add_security_buffer(auth.hostname)
    auth.username=username
    auth.password=password
    auth.isunicode=unicode
    return auth 

try:
    from hashlib import md5
except ImportError:
    import md5

def hmacMD5(data, key):
    """
    generates the MD5 HMAC for any data
    http://www.ietf.org/rfc/rfc2104.txt
    see unit test below (seems to pass!)
    
    There appears to be an hmac python module in the
    standard distribution as well - probably should just
    replace this code with calls to that.
    """

    #we're really running a varient of HMAC-MD5
    #called HMACT64, which does this funky
    #thing to long keys
    old_md5 = hasattr(md5, 'new')
    if len(key) > 64:
        if old_md5 == True:
            m=md5.new()
        else:
            m=md5()
        m.update(key)
        key=m.digest()

    if old_md5 == True:
        m=md5.new()
    else:
        m=md5()
    ipad="\x36"*64
    opad="\x5c"*64
    #H(K XOR opad, H(K XOR ipad, text))
    key=key+"\x00"*(64-len(key))
    newkey=xorstrings(ipad, key)
    newkey2=newkey+data 
    m.update(newkey2)
    hdata=m.digest()

    if old_md5 == True:
        m=md5.new()
    else:
        m=md5()
    newkey3=xorstrings(opad, key)
    newkey4=newkey3+hdata 
    m.update(newkey4)
    ret=m.digest()
    return ret 

try:
    #first try to import hmac, which uses hashlib
    #and the C implementation
    import hmac 
    have_hmac=True
except:
    have_hmac=False
    #if we fail, we keep the above pure-python code

if have_hmac:
    def hmacMD5(data, key):
        """
        Uses python library hmac
        Presumably this is faster
        """
        #print "hmac: key=%s"%key
        #we're really running a varient of HMAC-MD5
        #called HMACT64, which does this funky
        #thing to long keys
        old_md5 = hasattr(md5, 'new')
        if len(key) > 64:
            if old_md5 == True:
                m=md5.new()
            else:
                m=md5()
            m.update(key)
            key=m.digest()

        h=hmac.new(key)
        h.update(data)
        ret=h.digest()
        return ret 

def hmacMD5_test():
    """
    Unit test for HMAC-MD5 code
    """
    key="\x0b"*16
    data="Hi There"
    digest_should_be=binstring("0x9294727a3638bb1c13f48ef8158bfc9d")
    testdata=hmacMD5(data,key)
    if testdata!=digest_should_be:
        print "Did not pass first HMAC-MD5 test"
    else:
        print "Passed HMAC-MD5 test 1"
    key="Jefe"
    data="what do ya want for nothing?"
    digest_should_be=binstring("0x750c783e6ab0b503eaa86e310a5db738")
    testdata=hmacMD5(data,key)
    if testdata!=digest_should_be:
        print "Did not pass second HMAC-MD5 test"
    else:
        print "Passed HMAC-MD5 test 2"
    return 

    
def ntlmv2Hash(domain, user, password):
    """
    Gets the NTLMv2 hash using our hmacMD5 code
    """
    ntlm_hash=ntlmHash(password)
    #print "NTLM Hash: %s"%prettyhexprint(ntlm_hash)
    #passed
    identity=backwardsunistring(user).upper() + backwardsunistring(domain)
    #print "Identity: %s"%prettyhexprint(identity)
    #passed
    ret=hmacMD5(identity, ntlm_hash)
    #print "ntlmv2 hash: %s"%prettyhexprint(ret)
    #passed
    return ret

import time

def getcurrentnttime():
    """
    Returns a 64 bit string 
    (in intel_order) which Windows will
    interpret as the time
    According to MS:
    System times should be within 30 minutes of each other. Otherwise, authentication can fail because the server might interpret the challenge from the client as having expired.
    """
    return int2str64_swapped(int((time.time()+11644473600)*(10**7)))

def createBlob(targetInformation, clientNonce):
    """
    
    """
    buf=""
    buf+=binstring("0x01010000") #constant signature
    buf+=binstring("0x00000000") #reserved
    buf+=getcurrentnttime()
    buf+=clientNonce #client nonce
    buf+=binstring("0x00000000") #unknown
    buf+=targetInformation
    buf+=binstring("0x00000000") #unknown
    return buf

def getNTLMv2Response(target, user, password, targetInformation, challenge, clientNonce):
    """
    
    """
    v2hash=ntlmv2Hash(target, user, password)
    blob=createBlob(targetInformation, clientNonce)
    ret=lmv2Response(v2hash, blob, challenge)
    return ret 

def lmv2Response(hash, clientdata, challenge):
    """
    Hash is the NTLMv2 hash
    clientdata is the client's data (blobby)
    challenge is the server's Type 2 message challenge
    """
    data=challenge+clientdata 
    mac=hmacMD5(data, hash)
    #print "Mac: %s"%prettyhexprint(mac)
    #passed
    lmv2=mac+clientdata 
    #passed
    return lmv2
    

NTLMSSP_NEGOTIATE=0x1
NTLMSSP_CHALLENGE=0x2
NTLMSSP_AUTH= 0x3
POINTERSIZE=8
class NTLMException(Exception):
    
    def __init__(self, args=None):
        self.args = args
        
    def __str__(self):
        return `self.args`


class NTLM:
    """
     NTLMSSP / RPC authetication class
     More info:
     http://www.innovation.ch/java/ntlm.html
    """
    SIGNATURE="NTLMSSP\0"
    _auth_type=0xa

    def __init__(self):
        self.type=0
        self.flags=0
        self.challenge=""
        self.password=""
        extra=""
        
        self.secbuf=[]
        self.list=[]
        self.domain= ""
        self.username= "administrator"
        self.hostname= "WIN2KBOB"
        self.sessionkey= "\0" *8
        self.vernum=1
        self.verbody="\0" * 12
        #this MUST be a real context ID if we're going locally
        self.contextid=random.randint(25000,50000)
        self.isunicode=0
        self.flagdict={}
        #self.parse_flags(0) #default flags?
        self.target_data="" 
        return 
    
    def get_contextid(self):
        return self.contextid
        
    def set_type(self, type): 
        self.type=type
        self.list=[]
        self.secbuf=[]

    def set_flag(self, flags):
        self.flags= flags
        
    def auth_type(self):
        return self._auth_type

    def set_domain(self, domain):
        devlog("msrpc","NTLM: Set domain: %s"%prettyprint(domain))
        self.domain=domain
        
    def set_auth(self):
        self.type=NTLMSSP_AUTH
        
    def add_security_buffer(self, buf):
        self.secbuf.append(buf)

    def set_user(self, username):
        self.username=username
        
    def set_password(self, plaintxtpasswd):
        self.password=plaintxtpasswd

    def clear_secbuf(self):
        self.secbuf=[]
        
    def raw(self, pos=0, my_nt_key=None, my_lm_key=None, my_challenge=None):
        """
        Creates a raw NTLM packet
        
        offsets as declared within NTLM packest are from the start of the packet.
        """
        buf=""
        buf = self.SIGNATURE + struct.pack("<L", self.type) 
        if self.type==NTLMSSP_NEGOTIATE:
            devlog("msrpc","NTLM NEGOTATE CREATING: %s"%self.secbuf)
            #self.flags|=0x80000000L
            #self.flags|=0x02000000
            #self.flags|=0x00800000
            #self.flags=0xa208b207L
            #is local call, I assume?
            #self.flags|=0x04000 #lets not negotiate this. We either are or we arn't.

            buf += struct.pack("<L", self.flags)
            self.add_security_buffer(self.domain)
            self.add_security_buffer(self.hostname)
            OS_Version_Structure = binstring("05 01 93 08 00 00 00 0f") #OS Version structure 
            self.add_security_buffer(OS_Version_Structure)
            data=data=self.get_secbuffer(len(buf), "")
            buf+=data
                
        elif self.type==NTLMSSP_AUTH:
            devlog("ntlm","NTLMSSP_AUTH generating")
            if not self.challenge:
                raise NTLMException, "Challenge not found, didn't receive NTLM_CHALLENGE info"

            #initialize it to null
            
            self.clear_secbuf()
            
            if not self.password and not self.username:
                #"Null session" for local pipes support
                #someone called forceauth=1
                lm_key=""
                nt_key=""
                
                self.add_secbuffer(lm_key)
                self.add_secbuffer(nt_key)
                self.add_secbuffer("") #domain
                self.add_secbuffer("") #username
                self.add_secbuffer("") #host
            elif not is_passed_hash(self.password) and self.flagdict.get("Negotiate NTLM2 Key"):
                devlog("ntlm", "Doing NTLM v2")
                #really good article on this
                #http://www.microsoft.com/technet/technetmag/issues/2006/08/SecurityWatch/
                #here's the problem with NTLMv2 - if you set the LmCompatibility flag to 5
                #which will make a server only support NTLMv2
                #the server will still advertise that it supports
                #NTLMv1 in the flags it sends us.
                #so if we are not getting a passed hash, we assume
                #that we want NTLMv2
                #and if we are passing a hash, or for whatever reason
                #you are attacking a pre-Win2KSP4 machine
                #then ideally it will not send a "I support NTLMv2" flag
                #XXX: need to test that this is true
                #anyways, that's why we default to NTLMv2
                client_data="\x01"*8 #random 8 byte nonce. Not so random.
                hash=ntlmv2Hash(self.domain, self.username, self.password)
                lm_key=lmv2Response(hash, client_data, self.challenge)
                nt_key=getNTLMv2Response(self.domain, self.username, self.password, self.target_data, self.challenge, client_data)

            elif self.flagdict.get("Negotiate NTLM"):
                devlog("ntlm", "Doing NTLM version 1")
                if not my_lm_key and not my_nt_key:
                    #we do have a username and password
                    #first get 21 byte lanman key
                    devlog("ntlm","Username: %s"%self.username)
                    devlog("ntlm","Password: %s"%self.password)
                    lm_key=get_lanman_hash(self.password)
                    #get 24 byte lanman response
                    devlog("ntlm","Challenge: %s"%hexprint(self.challenge))
                    lm_key=calculate_lanman_response(lm_key, self.challenge)
                    devlog("ntlm", "LM KEY: %s"%hexprint(lm_key))
                    nt_key=get_ntlm_response(self.password, self.challenge)
                    devlog("ntlm", "NT KEY: %s"%hexprint(nt_key))
                else:
                    devlog('ntlm', 'We were supplied our lm/nt keys!')
                    lm_key = my_lm_key
                    nt_key = my_nt_key
                    # XXX: testing
                    #test_lm_key = get_lanman_hash('immunity')
                    #test_lm_key = calculate_lanman_response(test_lm_key, my_challenge)
                    #test_nt_key = get_ntlm_response('immunity', my_challenge)
                    #print "XXX: testing keys for password 'immunity'"
                    #print "ANSI password: ",
                    #for c in test_lm_key:
                    #    sys.stdout.write('%.2x' % ord(c))
                    #sys.stdout.write('\n')
                    #print "UNI password: ",
                    #for c in test_nt_key:
                    #    sys.stdout.write('%.2x' % ord(c))
                    #sys.stdout.write('\n')
            else:
                #neither version 1 or version 2? Absurd!
                raise NTLMException, "Unknown NTLM type"
            
            #save these off for our smb code (which discards the data here, but uses these values directly)
            self.lm_key=lm_key
            self.nt_key=nt_key
            
            devlog("ntlm", "Adding lm_key and nt_key to secbuffer")
            self.add_secbuffer(lm_key)
            self.add_secbuffer(nt_key)

            if self.flagdict.get("NegotiateUnicode"):
                devlog("ntlm","NegotiateUnicode chosen")
                #convert them to ascii first
                self.domain=nounizeros(self.domain)
                if not self.username:
                    self.username=""
                if not self.password:
                    self.password=""
                self.username=nounizeros(self.username)
                self.hostname=nounizeros(self.hostname)
                #controlled in the data representation flags, I believe
                self.add_secbuffer(backwardsunistring(self.domain))
                self.add_secbuffer(backwardsunistring(self.username))
                self.add_secbuffer(backwardsunistring(self.hostname))
            else:
                #ascii 
                devlog("ntlm","Self.domain (should be ascii): %s"%prettyprint(nounizeros(self.domain)))
                self.add_secbuffer(nounizeros(self.domain))
                self.add_secbuffer(nounizeros(self.username))
                self.add_secbuffer(nounizeros(self.hostname))
    
            #who the heck knows what these 8 bytes are? I certainly don't.
            #session key is also 8 bytes....? This comes after the flags though,
            #not before.
            self.sessionkey=""
            
            self.add_secbuffer(self.sessionkey) #session key (arg)
            data=self.get_secbuffer(len(buf), middle=struct.pack("<L", self.flags)+self.sessionkey)
            devlog("ntlm","SecBuffer: %s"%hexprint(data))
            devlog("ntlm","Buf: %s"%hexprint(buf))
            buf+=data 

            #END NTLM AUTH PACKET
        else:
            devassert("Got an NTLM Type we did not understand! %s"%self.type)
                
        return buf
  
    def get_verifier(self):
        return struct.pack("L12s", self.vernum, self.verbody)
        
    # middle: between pointer and the pointer data
    def get_secbuffer(self, pos, middle=""):
        buf=""
        pointer_hdr="<HHL"
        pos+= struct.calcsize(pointer_hdr)*len(self.secbuf)+len(middle)
        #print self.secbuf
        for a in self.secbuf:
            sz=len(a)
            buf += struct.pack(pointer_hdr, sz, sz, pos)
            pos += sz
        buf+=middle #flags + sessionkey
        for a in self.secbuf:
            buf+=a
        return buf

    def add_secbuffer(self, securitybuffer):
        self.secbuf.append(securitybuffer)
    
    def get(self, rawdata):
        """
        Gets data from a NTLM Type 2 Message
        sets self.flags, self.challenge 
        """
        hdr1="<8sL"
        idx=0
        (sig,self.type)=struct.unpack(hdr1, rawdata[0:struct.calcsize(hdr1)])
        idx+=struct.calcsize(hdr1)
        #move beyond the NTLM signature and type
        if sig != self.SIGNATURE:
            raise NTLMException, "Wrong signature: %s!=%s from %s" % (prettyprint(str(sig)),prettyprint(str(self.SIGNATURE)),prettyprint(rawdata[:50]))
        if self.type== NTLMSSP_CHALLENGE:
            #this will be WIN2KBOB - which is actually the hostname. I ignore this wackyness so I can sleep.
            domain=self.read_pointer(rawdata,idx)
            self.set_domain(domain)
            idx+=POINTERSIZE
            hdr2="<L8s8s"
            (self.flags, self.challenge, self.reserved)=\
                struct.unpack(hdr2, rawdata[idx:idx+struct.calcsize(hdr2)])
            devlog("ntlm", "Challenge: %s"%hexprint(self.challenge))
            self.parse_flags()
            idx+= struct.calcsize(hdr2)
            
            rawlist=self.read_pointer(rawdata, idx)
            self.target_data=rawlist
            devlog("ntlm", "rawlist: %s"%prettyhexprint(rawlist))
            self.list=self.parse_list(rawlist)
        return 

    def set_unicode(self, uni):
        """
        Hardcodes our unicode - used by smb code
        """
        if uni:
            self.flagdict["NegotiateUnicode"]=True
        else:
            self.flagdict["NegotiateUnicode"]=False
        return 
    
    def set_ntlm_version(self, version):
        """
        Hardcodes what version we will use of NTLM authentication
        used by our SMB code
        """
        if version==1:
            self.flagdict["Negotiate NTLM"]=True
            self.flagdict["Negotiate NTLM2 Key"]=False
        elif version==2:
            self.flagdict["Negotiate NTLM"]=False 
            self.flagdict["Negotiate NTLM2 Key"]=True 
        else:
            devassert("Did not get a version we recognized! %s"%version)
        return 
    
    def parse_flags(self):
        """
        Here we parse the flags integer we've recieved to fill up
        a dictionary full of the values they requested
        """
        self.flagdict={}
        fillme=  ["NegotiateUnicode", "NegotiateOEM", "Negotiate NTLM"]
        fillme+= ["Request Target", 6]
        fillme+=["Negotiate Local Call", 8, "Negotiate Always Sign", "Target Type Domain"]
        fillme+=["Target Type Server", "Target Type Share", "Negotiate NTLM2 Key", 7]
        fillme+=["Negotiate Target Info", 5, "Negotiate 128", 5, "Negotiate 56"]
        bit=1
        for f in fillme:
            if type(f) == type(1):
                bit=bit<<f
                continue
            if self.flags&bit:
                val=True
            else:
                val=False 
            self.flagdict[f]=val
            bit=bit<<1
        devlog("ntlm", "Parse Flags: Flag dictionary: %s"%repr(self.flagdict))
        return 


    def read_pointer(self, rawdata, idx):
        fmt_ptr="HHL"
        (length, maxlen, offset)=\
         struct.unpack(fmt_ptr, rawdata[idx:idx+struct.calcsize(fmt_ptr)])
        return rawdata[offset: offset+length]
    
    def parse_list(self, our_list):
        idx=0
        result=[]
        hdr="=HH"
        #in case blank results come in
        if not our_list:
            return result
        while 1:
            (type, length)=struct.unpack(hdr, our_list[idx:idx+struct.calcsize(hdr)])
            idx+=struct.calcsize(hdr)
            if type==0x0:
                break 
            result.append((type, unicode2ascii(our_list[idx:idx+length])))
            idx+=length
        return result

def test():
    if 0:
        bob=get_lanman_hash("bob")
        print "get_lanman_hash(bob)=%s"%prettyhexprint(bob)
        key=binstring("16 f6 59 6f 51 09 dc 05 ")
        password="jbone"
        unipassword=get_ntlm_response(password,key)
        print "Uni: %s"%prettyhexprint(unipassword)
        unicheck=binstring("""6a 63 47 93 34 23 b3 36 
        bd 7a 62 53 14 62 e2 f0 
        95 06 91 e4 5e 83 46 cf """)
        if unicheck==unipassword:
            print "Check"
        else:
            print "uni failed!"
        
    hmacMD5_test()
    #tests based on NTLM.html paper
    if 0:
        print "Lanman v2.0 test from ntlm paper"
        client_data=binstring("0x0123456789abcdef")
        domain="DOMAIN"
        username="user"
        password="SecREt01"
    
        challenge=binstring("0x0123456789abcdef")
        client_data=binstring("ffffff0011223344")
        print "challenge: %s clientdata: %s domain: %s username: %s password: %s"%(prettyhexprint(challenge), prettyhexprint(client_data), domain, username, password)
        """
           1. The Unicode mixed-case password is "0x53006500630052004500740030003100" in hexadecimal; the MD4 hash of this value is calculated, giving "0xcd06ca7c7e10c99b1d33b7485a2ed808". This is the NTLM hash.
           2. The Unicode uppercase username is concatenated with the Unicode authentication target, giving "USERDOMAIN" (or "0x550053004500520044004f004d00410049004e00" in hexadecimal). HMAC-MD5 is applied to this value using the 16-byte NTLM hash from the previous step as the key, which yields "0x04b8e0ba74289cc540826bab1dee63ae". This is the NTLMv2 hash.
           3. A random 8-byte client nonce is created. From our NTLMv2 example, we will use "0xffffff0011223344".
           4. We then concatenate the Type 2 challenge with our client nonce:
    
          0x0123456789abcdefffffff0011223344
    
          Applying HMAC-MD5 to this value using the NTLMv2 hash from step 2 as the key gives us the 16-byte value "0xd6e6152ea25d03b7c6ba6629c2d6aaf0".
          5. This value is concatenated with the client nonce to obtain the 24-byte LMv2 response:
    
          0xd6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344 
        """
        should_be=binstring("0xd6e6152ea25d03b7c6ba6629c2d6aaf0ffffff0011223344")
        hash=ntlmv2Hash(domain, username, password)
        lm_key=lmv2Response(hash, client_data, challenge)
        print "lmkey: %s"%prettyhexprint(lm_key)
        print "shbey: %s"%prettyhexprint(should_be)

    
    #tests based on successfully sniffed logins against the Exchange Server
    print "Lanman v2.0 test from sniffed login"
    client_data=binstring("BE882D53F032BF46")
    challenge=binstring("091846333e28aa2f")
    
    
    hash=ntlmv2Hash("WORKGROUP", "Administrator", "jbone")
    lm_key=lmv2Response(hash, client_data, challenge)
    should_be=binstring("9b019820")
    print "lm_key: %s"%prettyhexprint(lm_key)
    print "should: %s"%prettyhexprint(should_be)

    print "Starting test of NTLM v1"
    challenge=binstring("17 F2 DE 98 8D 75 7E 76")
    domain=""
    username="Administrator"
    password="immunity"
    lm_key=get_lanman_hash(password)
    #get 24 byte lanman response
    lm_key=calculate_lanman_response(lm_key, challenge)
    print "LM KEY: %s"%hexprint(lm_key)
    nt_key=get_ntlm_response(password, challenge)
    print "NT KEY: %s"%hexprint(nt_key)
    return 

if __name__=="__main__":
    test()
