#! /usr/bin/env python
#
#SPIKE Proxy file: spkproxy.py
#
#Usage: python spkproxy.py [port:8080]

###################################################################
#Version 2.0
#Author: Dave Aitel (dave@immunityinc.com)
#License: CANVAS License

####################################################################
#Known Bugs:
#####################################################################

from __future__ import with_statement

#BEGIN IMPORTS
import socket
import sys
if "." not in sys.path: sys.path.append(".")
from threading import Thread
import string
import os
from libs.tlslite.api import *
import getopt

#default UI, could add others.
import spikeProxyUI
import daveutil
import time

import StringIO

#time all sockets out at ten seconds
import timeoutsocket
from libs.canvasntlm import *
#timeoutsocket.setDefaultSocketTimeout(3)

#import versioncheck
import re
import logging

#CANVAS IMPORTS
from internal import *
from engine.features import *

# 2.6+ ssl
SSL_REWRITE = False

if LIB_PYOPENSSL_INSTALLED:
    try:
        import ssl
        PRIVATE_KEY = '0\x82\x02\\\x02\x01\x00\x02\x81\x81\x00\xbb?\xb3\xfdy\xf4\x0f\x1d<"\xa7\x17\x0c0\xae\x96l-\xf7\x08\xa1\xd2D:\xe0\xc5\xb6\xcf\xd3\x82\x82\xea_\xf9\x856\x86:\xf7XPB\xfd\x1fQ\xb9I\x93\xc9!\x0c\xc46\x9d\xe9\x9b}\x0e\xb0*p\xce-M|\x11\x05C\x07^\\\xd5L\xbb\x80\xcc\x13\xec\x89T\x1e\xa1\xa0\x02\x92\xd4uxG\xf1\xeb\x85\xda\xfd\x93.\x19O\xcb\x03\xc0\xde\t\xae\xf5\xc7\x1aD\x02\xc6\xc1\xb7\xc3T\xc3Ts^Q\xe4\x87G\xae.\x1c\xf4\x8b3\x02\x03\x01\x00\x01\x02\x81\x80K\x13\xc6\xb2:D\x9e\x0e\xc5\xbe\xcb*\x15\x8c+dJ\xa9\xbfc\xe9\xa6*\x0fEr`\xd3Af\x11\xe1\xb1k\x95{\x00%\x02i\x99|\xd2\x8a\xcd4\xb2\x88\x9b\xdb1\x886\xb1\xe8)\x9c\xe1\xd7\xc6\x9c\x86>i#\xa1\x8a\xf0\x18\xc6\xc6U\x8c\xde\xf43\xa2|\xf2\x8f\n\xaeT|\x1b;\xd0\xc8\x1ak\x91\xcf\xc3\xb8\xdc\x98\xa0\x9d\x91\xf5+\x028\xc8\x90\xaa\x18?\x17\xe0\xf9\xb5?\xc6s\xaa\x9cM\xc8\xee\x93\xec\xb5\xf1\xa7\x12 \xb9\x02A\x00\xf0Io\xa6\xda\xb4\x14\\\x10\x1d8R\x1a\x07\xb5"\x82\x82(\xde;\x97o\xd7j\x11b\x8bD+\xd8\xc8\xfeg\x8a_<\x886\xf8x\xe3\xa7\xb1\xcb?\xddA\xf4\x85\xb3m\x81J\xa8(\x07\xbb\xa9\xe0\x18\x18 W\x02A\x00\xc7~_\xf1bI\xd2\xaaq\x86.\x07\xac\x0b\xf6\xa7\x127W\xa1\x83k\xb5\x0c\xd4_)\xfc\xd3\x1eL\xc9\xe3DE\xf4l\x91\xe0\x85\x14y!I\xef\xe6\x82\ni\xc1\x16WZn\xe0\xe2`\xbf\x9f\x95\xaf\x03r\x85\x02@x\x93\xf1bb\x87Q\\-}\xec@N\xed\xa58\xcf\x12\xef\xdd-<>\x14t\x16\x8bC\xe5\x8e\xb77\x8djy\xe6v\xa2\xc8+\x01\xc7\x03\xe4\xd5`\x93\xf0?\xfbC\xe1\xe4\xaa\x89\x1d\xa5[\xc7\xd0;g\x07\xfb\x02@\x06\xe6\x955\t\\Z`0\xfb\x1e>\x7f\xb2\x0e?+?$\xd5\xdep\xec[\\AJw\x87j\x05\xe7\xf9\xe7\x93\xaf\xe7\xcd\x88\x01\xb2z\x9a//\x90>\xb1S\x85-[\xaa2)\xafJ\xffu\xea\xbc\x9a\x16\xed\x02A\x00\xa1E\nI]\xcf\x8d\xab\xbd\xd3\x0et<\xc8\x88\x04\x1c\\dE\xdd9\x99*N\x1e\xc7\xab\x03L\x03\xd3L\xf3\x8b\x04\x1e[\x02\x0eM\x08;\xd4\xd6_S\x07\xec\n\x8eh\x9d2\xf1h\xdf\xb3e\x12\xc7\xcd\xe9/'
        SSL_REWRITE = True
    except ImportError:
        print 'Could not import SSL, Python 2.6+ needed for certificate rewriting.'


VERSION="1.5"
default404stringlist=["Page Not Found"]
#### you change these to say what hosts and pages are ALLOWED. If they
#are not set, ALL are allowed
restrictedhosts=[]
restrictedpages=[]


denied1="<html><head><title>Error</title></head><body>You are not allowed to visit that page during this test, sorry. Try unsetting your proxy temporarily.</body></html>"
deniedstring="HTTP/1.1 404 404 Access Denied !\r\nContent-Length: %d"%len(denied1)+"\r\n\r\n"+denied1
from engine.config import canvas_resources_directory

#Class myConnection is used to wrap sockets so we can have some basic
#abstraction over which ssl library we use, for example
#we basically wrap a few socket calls here
class MyConnection:
    def __init__(self, conn, directSSL=False):
        self.doSSL=0
        self.sslStarted = False
        self.mysocket=conn
        self.oldmysocket=None
        self.parent=None
        # if we're talking directly to a client and not acting as a proxy
        # e.g. HTTPS MOSDEF .. directSSL needs to be True
        self.directSSL = directSSL

    def recv(self,size):
        #if self.doSSL:
        #    devlog("spkproxy","Reciving data as ssl!")
        #print "Recieving %d bytes" % size
        if self.doSSL:
            #devlog("spkproxy","Reading since we are SSL")
            return self.mysocket.read(size)
        result=self.mysocket.recv(size)
        #devlog("spkproxy","Returned from recv()")
        return result

    #reliable send over socket
    def send(self,data):
        sizetosend=len(data)
        sentsize=0
        while sentsize<sizetosend:
            #print "sentsize="+str(sentsize)+"/"+str(sizetosend)
            try:
                #IF YOU ARE GETTING AN ERROR HERE, USE PYTHON VERSION 2.2!
                #FOR REDHAT 7.3 USERS, IT IS PROBABLY CALLED /usr/bin/python2 !
                sentsize+=self.mysocket.send(data[sentsize:])
            except (socket.error):
                #pass (this will cause it to loop forever, sucking CPU like a donkey)
                return sentsize
        return sentsize

    #DOES get used.
    def startSSLserver(self):
        """
        Returns true if an ssl server started up ok, false otherwise
        """
        debug_ssl=0

        # prevent unneeded reinits on existing objects
        if self.sslStarted == True:
            return True
        dir = os.path.dirname(sys.argv[0])
        if dir == '':
            dir = os.curdir
        if self.directSSL == False: # proxy mode
            self.mysocket.send("HTTP/1.1 200 Connection established\r\n\r\n")

        self.oldmysocket=self.mysocket
        connection = TLSConnection(self.mysocket)
        connection.closeSocket = True

        #
        # SSL CERTIFICATE REWRITE
        #
        # We need to check if pyOpenSSL is loaded and start rewriting certificates on the fly
        # If pyOpenSSL is not loaded, we go back to standard behavior (self-signed certificates)
        #

        if SSL_REWRITE and not self.directSSL:
            with self.parent.SSL_Lock:
                # Certificate generation is expensive, first check cache
                if self.sslHost in self.parent.SSLCertificateCache:
                    fake_cert, k = self.parent.SSLCertificateCache[self.sslHost]
                else:
                    cert = ssl.get_server_certificate((self.sslHost, int(self.sslPort)), ssl.PROTOCOL_SSLv23)
                    # ssl.get_server_certificate is buggy in Python 2.6
                    if '\n-----END CERTIFICATE-----' not in cert:
                        cert = cert.replace('-----END CERTIFICATE-----', '\n-----END CERTIFICATE-----')

                    devlog('chris', ':REWRITING SSL =======> %s' % self.sslHost)
                    cert   = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
                    name   = cert.get_subject()
                    if self.parent.cacert:
                        cacert = self.parent.cacert
                    else:
                        cacert = open(os.path.join(canvas_resources_directory, 'cacert.pem'), 'rb').read()

                    if self.parent.cakey:
                        cakey = self.parent.cakey
                        cakey  = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, cakey)
                    else:
                        cakey  = open(os.path.join(canvas_resources_directory, 'cakey.pem'), 'rb').read()
                        cakey  = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, cakey, 'immunity')

                    cacert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cacert)
                    k      = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_ASN1, PRIVATE_KEY)
                    serial = cert.get_serial_number()

                    # Generate our certificate, it is going to be based on the
                    # valid certificate with some modifications ;p

                    fake_cert = OpenSSL.crypto.X509()
                    fake_cert.set_subject(name)
                    fake_cert.set_issuer(cacert.get_subject())
                    cn = fake_cert.get_subject().CN

                    import operator, sha
                    serial = reduce(operator.add, map(ord, sha.sha(self.sslHost).digest()))
                    devlog('chris', 'cn: %s sslhost: %s, unique serial: %d' % (cn, self.sslHost, serial))

                    fake_cert.get_subject().CN = self.sslHost
                    fake_cert.set_serial_number(serial)
                    fake_cert.set_notBefore(cert.get_notBefore())
                    fake_cert.set_notAfter(cert.get_notAfter())
                    fake_cert.set_version(cert.get_version())
                    fake_cert.set_pubkey(k)
                    fake_cert.sign(cakey, 'SHA1')
                    self.parent.SSLCertificateCache[self.sslHost] = (fake_cert, k)

                # Transform our certificates to tlslite api
                x509 = X509()
                x509.parse(OpenSSL.crypto.dump_certificate(OpenSSL.crypto.FILETYPE_PEM, fake_cert))
                certChain = X509CertChain([x509])
                private = parsePEMKey(OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, k))
        else:
            # No pyOpenSSL, use self-signed certificate
            cert_file = open(os.path.join(canvas_resources_directory, 'server.cert'), 'rb').read()
            x509      = X509()
            x509.parse(cert_file)
            certChain = X509CertChain([x509])
            ctx_file  = open(os.path.join(canvas_resources_directory, 'server.pkey'), 'rb').read()
            private   = parsePEMKey(ctx_file)
        try:
            devlog("spkproxy", "Doing SSL Handshake")
            connection.handshakeServer(certChain=certChain, privateKey=private)
        except Exception:
            import traceback
            traceback.print_exc(file=sys.stderr)
            devlog("spkproxy", "Failed to do TLS handshake to client")
            return False

        self.doSSL = 1
        devlog("spkproxy", "Now using SSL to talk to client")
        self.mysocket = connection
        self.sslStarted = True
        return True

    #wraps socket.close
    def close(self):
        devlog("spkproxy", "calling connection.close on server sockets...")
        if self.mysocket:
            self.mysocket.close()
        if self.oldmysocket:
            self.oldmysocket.close()
        return

    #we read 0 and on any exception return 1
    def gotclosed(self):
        #print "Checking if we got closed"
        try:
            data=self.mysocket.send("")
        except Exception:
            #print "CAUGHT EXCEPTION CHECKING IF WE WERE CLOSED"
            return 1
        return 0


###########################################################################
#class header is what we use to store request and reponse headers
class header:
    def __init__(self,state="PROXYSERVER"):
        self.clear()
        self.state=state
        self.maxsize=20000

    #clears out the data structure - used for init
    def clear(self):
        self.data=[]
        self.done=0
        self.goodHeader=0
        self.cangzip=0
        self.clientisSSL=0
        self.verb=""
        #for the first request, we see a CONNECT verb
        self.sawCONNECT=0
        self.firstline="" #sheesh
        #1 if we are reading a response instead of a GET/POST, etc
        self.responseHeader=0
        self.wasChunked=0

        #here is basically what we return from parsing the headers
        self.URLargsDict={}
        self.headerValuesDict={}
        self.useSSL=0
        self.connectHost=""
        self.URL=""
        self.sawsslinit=0
        self.connectPort=0
        self.mybodysize=0
        self.useRawArguments=0
        self.allURLargs=""
        self.version="HTTP/1.1" #reset by parse first line
        self.status="200" #default is OK :>
        self.msg="OK" #default is really OK

        #set this to not send a content-length
        self.doSurpressContentLength=0

        #variables for server response headers
        self.returncode=""
        self.returnmessage=""
        self.proxyHeader=""
        self.orderlist=[]
        self.state="PROXYSERVER" #valid values: PROXYSERVER, SERVER

    def __str__(self):
        """
        Return string representation of this.
        """
        ret=""
        ret+="Header: %s SSL:%s %s %s"%(self.connectHost, self.useSSL, self.URL, str(self.URLargsDict))
        return ret

    def getArgsDict(self):
        return self.URLargsDict

    def getStringArguments(self, exclude=None):
        """
        Gets our url arguments as a string. Exclude parameters present
        in exclude list.
        """
        request=""
        #if we have arguments
        if self.useRawArguments:
            if len(self.allURLargs) > 0:
                request+="?"+self.allURLargs
        else:
            d         = self.URLargsDict
            orderlist = self.orderlist
            if exclude:
                d = dict((k,v) for k,v in self.URLargsDict.iteritems() if k not in exclude)
                if orderlist:
                    orderlist = [k for k in self.orderlist if k not in exclude]
            if len(d) > 0:
                request += "?"
                request += daveutil.joinargs(d, orderlist=orderlist)
        return request

    def setcanzip(self,header):
        """
        Automatically sets the cangzip value based on a client's header...
        """
        #http://support.microsoft.com/default.aspx?scid=kb;[LN];Q312496
        #IE 6 SP0 lies about being able to accept gzip!
        #http://developer.amazonwebservices.com/connect/thread.jspa?threadID=26466&tstart=0&start=15
        # Detect IE6 pre-SP2 and NN4.0x
        re_browsers_nogzip = re.compile('(Mozilla/4.[0678])|(MSIE\s[1-6]\.(?!.*SV1))|CFSCHEDULE')
        if re_browsers_nogzip.search( header.getStrValue(["User-Agent"])):
            #you matched a buggy user-agent. No GZIP for you
            self.cangzip = 0
            return self.cangzip

        if header.getStrValue(["Accept-Encoding"]).count("gzip"):
            self.cangzip=1

        return self.cangzip

    def getProxyHeader(self):
        return self.proxyHeader

    #fixes the URL to not have a ? in it if it happens to
    def normalize(self):
        devlog("spkproxy::normalize","SELF.URL=%s"%self.URL)
        if self.URL.count("?")>0 and self.URLargsDict=={} and self.useRawArguments==0:
            urlbit=self.URL[:]
            #if we have a url as well
            self.URL=urlbit.split("?")[0]
            #if we have arguments too
            if len(urlbit.split("?"))>1:
                self.allURLargs="?".join(urlbit.split("?")[1:])
                #print "SELF.allURLARGS=%s"%self.allURLargs

                self.URLargsDict=daveutil.splitargs(self.allURLargs,orderlist=self.orderlist)
                if self.URLargsDict==None:
                    self.URLargsDict={}
                    self.useRawArguments=1
                return
            else:
                self.URL+="?"
        return

    #returns a site tuple (used for VulnXML)
    def getSiteTuple(self):
        result=(self.connectHost,self.connectPort,self.clientisSSL)
        return result

    #sets us up from a site tuple
    def setSiteTuple(self,site):
        self.connectHost = site[0]
        self.connectPort = site[1]
        self.clientisSSL = site[2]

    #debug routine
    def printme(self):
        #print "All my stuff:"
        result = ""
        result += "Host: " + self.connectHost + "\n"
        result += "Port: " + str(self.connectPort) + "\n"
        result += "SSL : "
        if self.clientisSSL:
            result += "Yes"
        else:
            result += "No"
        result += "\n\n"
        result += self.verb
        for key in self.headerValuesDict.keys():
            for value in self.headerValuesDict[key]:
                result += key + ": " + value + "\n"
        return result

    #returns http://www.cnn.com from our header information
    def getSite(self):
        # Horrible but the alternative is to rewrite spike
        if not isinstance(self.connectPort, int):
            port = int(self.connectPort)
        else:
            port = self.connectPort

        pre = 'https://' if self.useSSL or port == 443 else 'http://'
        result = '%s%s' % (pre, self.connectHost)

        if port != 80 and port != 443:
            result += ':' + str(port)
        return result


    #returns 1 if 2 headers (self and other) are basically the same
    def issame(self,other):
        #we don't compare the header itself. That makes us
        #get false negatives with Date: headers and such
        #self.headerValuesDict==other.headerValuesDict and \\
        if cmp(self.URL,other.URL)==0 and \
           self.clientisSSL==other.clientisSSL and \
           self.firstline==other.firstline and \
           cmp(self.URLargsDict,other.URLargsDict)==0 and \
           self.connectPort==other.connectPort and \
           self.mybodysize==other.mybodysize and \
           daveutil.headerdictcmp(self.headerValuesDict,other.headerValuesDict) and \
           self.allURLargs==other.allURLargs:
            return 1
        return 0

    #returns a string that is a "hash"
    def genhash(self):
        hash=""
        hash+=self.verb+self.returncode
        hash+=daveutil.hashstring(self.URL+self.allURLargs)
        #hash the cookies
        if self.headerValuesDict.has_key("Cookie"):
            for key in self.headerValuesDict["Cookie"]:
                hash+=daveutil.hashstring(key)

        if self.headerValuesDict.has_key("Set-Cookie"):
            for key in self.headerValuesDict["Set-Cookie"]:
                hash+=daveutil.hashstring(key)

        #done!
        #return it encoded so we get rid of slashes
        return daveutil.strencode(hash,"A")

    def setSurpressContentLength(self):
        self.doSurpressContentLength=1
        return

    def surpressContentLength(self):
        return self.doSurpressContentLength

    def setclientSSL(self):
        self.useSSL=1
        self.clientisSSL=1
        return

    def addData(self,moredata):
        """
        This function is used when you are recieving a header
        from the remote side
        """
        #print "addData "+moredata
        self.data.append(moredata)
        #print self.data[-4:]
        if self.data[-4:]==['\r', '\n', '\r', '\n']:
            #print "Got end of header!"
            self.done=1
            #print "All data="+"".join(self.data)
            self.verifyHeader()
        #we shouldn't NEED this, but economist.com has a misbehaving
        #IIS 5.0 server which does this!!!
        if self.data[-2:]==['\n','\n']:
            print "Weird \\n\\n in header!"
            self.done=1
            self.verifyHeader()
        if len(self.data)>self.maxsize:
            self.done=1
        return

    #keys is a set of values for which we're going to look and
    #return an integer associated with them from the headers
    #we return the first value in the header list as an int
    def getIntValue(self,keys):
        #iterate over all the keys in the argument until we have a match
        #print "all header keys: "+str(self.headerValuesDict.keys())
        for akey in keys:
            if self.headerValuesDict.has_key(akey):
                #print "Int key: "+akey+" matched "+self.headerValuesDict[akey][0]
                #we just return the first one we encounter, sorry
                #so multiple headers will just be on a first come
                #first serve basis
                return dInt(self.headerValuesDict[akey][0])
        return 0

    #we return the first value in the header list as a string
    #KEYS IS A LIST, NOT A STRING!
    def getStrValue(self,keys):
        #print "all header keys: "+str(self.headerValuesDict.keys())
        for akey in keys:
            #print "str: "+akey
            if self.headerValuesDict.has_key(akey):
                return str(self.headerValuesDict[akey][0])
        return "0"

    def removeHeaders(self,hstring):
        #print "Headers: %s"%self.headerValuesDict
        if self.headerValuesDict.has_key(hstring):
            #print "Deleting header %s"%hstring
            del self.headerValuesDict[hstring]
            return True
        return False

    def hasHeader(self, key):
        """
        Return true if we have that as a header
        """
        if self.headerValuesDict.has_key(key):
            return True
        return False

    def addHeader(self,newheader,newheadervalue):
        """
        Adds a new header of X:Y to our dictionary (appending it to
        what we already have if necessary)
        """
        devlog("spkproxy", "Adding header "+newheader+": "+newheadervalue)
        #we special case this because we normally see Host twice:
        #once from the headers from the client
        #and once from the proxy first line
        #but theoretically we could have a different connecthost
        #from the Host: value.
        #so we just replace it here.
        if newheader.lower()=="host":
            self.headerValuesDict["Host"]=[newheadervalue]
            #import traceback
            #traceback.print_stack()
            devlog("spkproxy", "New header value for Host: %s"%str(self.headerValuesDict["Host"]))
            return

        #we get here if it was not Host: Somethign

        #now we store it, at last
        if not self.headerValuesDict.has_key(newheader):
            #intialize it as a list
            self.headerValuesDict[newheader]=[]
        else:
            #print "Duplicate KEY: "+newheader
            pass

        #just separating them by commas doesn't work for hotmail.com
        self.headerValuesDict[newheader].append(newheadervalue)
        return

    def verifyHeader(self):
        #this little ditty returns a list of lines, without \r\n's
        #the -2 is because there were 2 null \r\n thingies on the end
        self.allheaders="".join(self.data).split("\r\n")
        #print "Self.allheaders="+str(self.allheaders)
        firstline=self.allheaders[0]
        self.allheaders=self.allheaders[:-2]
        #this will fail if we can't parse the first line
        if not self.parseFirstLine(firstline):
            print "Couldn't parse first line!"
            return 0

        #did we see a CONNECT?
        if self.sawCONNECT:
            #print "Saw SSL CONNECT request!"
            self.sawsslinit=1
            return 1


        for headerLine in self.allheaders[1:]:
            #print "Doing header line: "+headerLine
            tempvalues=headerLine.split(": ")
            if len(tempvalues)<2:
                #MS hotmail login is lame - uses this header, notice no space:
                #P3P:CP="BUS CUR CONo FIN IVDo ONL OUR PHY SAMo TELo"
                #so we handle that condition now
                tempvalues=headerLine.split(":")
                if len(tempvalues)<2:
                    #print "len(tempvalues)!=2 ="+str(len(tempvalues))+" in "+str(tempvalues)
                    devlog("spkproxy", "Tempvalues is not >=2! Not sure why!")
                    return 0

            self.addHeader(tempvalues[0],":".join(tempvalues[1:]))

        #print "About to call massageHeaders"
        self.massageHeaders()
        #print "Headers="+str(self.headerValuesDict)
        #print "Got a good header."
        self.goodHeader=1


    def setHeader(self,headername,header):
        """Sets the header to a particular value after erasing the old value"""
        if self.headerValuesDict.has_key(headername):
            del self.headerValuesDict[headername]
        self.addHeader(headername,header)
        devlog("Set header: %s to %s"%(headername,header))
        return


    #this function takes in
    def massageHeaders(self):

        #print "Inside massageHeaders"

        #non-IE user Agent, for reference
        #User-Agent: Mozilla/5.0 Galeon/1.0.3 (X11; Linux i686; U;) Gecko/0
        #IE string
        IEstring="Mozilla/4.0 (compatible; MSIE 5.0; Windows NT; Bob)"
        IEstring="Mozilla/4.0 (compatible; MSIE 6.0; Windows NT; Bob)"
        nonIEstring="Mozilla/5.0 Galeon/1.0.3 (X11; Linux i686; U;) Gecko/0"
        #always massage chunked out of the way
        #this will cause problems if someone sends over a gig of data
        #I doubt that will happen though
        for name in ["Transfer-Encoding", "transfer-encoding"]:
            if self.getStrValue([name]) == "chunked":
                del self.headerValuesDict[name]
                self.wasChunked = 1
                break

        #by default, use IE 5.0
        replaceUserAgent=0
        userAgent=IEstring




        #change Proxy-Connection to Connection
        if self.headerValuesDict.has_key("Proxy-Connection"):
            #DEBUG
            #print "MassageHeaders: has key proxy-connection"
            self.headerValuesDict["Connection"]=self.headerValuesDict["Proxy-Connection"][:]
            #print "Connection is now: "+str(self.headerValuesDict["Connection"])
            del self.headerValuesDict["Proxy-Connection"]

        #replace the User-Agent
        if replaceUserAgent:
            #just overwrite the damn thing
            if self.headerValuesDict.has_key("User-Agent"):
                del self.headerValuesDict["User-Agent"]
            #comment out the next line for NO user agent
            self.addHeader("User-Agent",userAgent)
            pass


        #save this off before we delete it
        self.mybodysize=self.getIntValue(["Content-length","Content-Length"])
        #get rid of Content-Length or Content-length - this is
        #a requirement since we recalcuate it later for fun!
        if self.headerValuesDict.has_key("Content-length"):
            del  self.headerValuesDict["Content-length"]
        if self.headerValuesDict.has_key("Content-Length"):
            del  self.headerValuesDict["Content-Length"]

        #no return value for massageHeaders
        return


    def parseFirstLine(self,firstline):
        #print "firstline="+firstline
        templist=firstline.split(" ")
        if len(templist)<2:
            print "First line of header has less than 2 members!"
            return 0
        self.verb=templist[0]

        #XXX: uh, this is not the verb. The verb is "GET" or "POST"
        #this is where we parse the response though, so it has the same
        #effect on us, essentially.
        if self.verb in [ "HTTP/1.1", "HTTP/1.0" ]:
            #print "Response header - not verifying the first line of %s!" % (firstline)
            self.responseHeader=1
            if len(templist)>1:
                self.returncode=templist[1]
            if len(templist)>2:
                self.returnmessage=templist[2]
            self.firstline=firstline
            return 1

        #TODO: remove this code from the header class out into the spkProxy class
        #this is the only place we use self.connection!
        #SSL proxy check
        if self.verb=="CONNECT":
            #WE ARE SSL!
            #signifies we connect to server with ssl
            self.useSSL=1
            #signifies we connect to client with ssl
            self.clientisSSL=1
            self.sawCONNECT=1
            self.connectHost=templist[1].split(":")[0]

            #no port would be weird, but maybe it'll happen...
            if templist[1].split(":") < 2:
                self.connectPort=443
            else:
                self.connectPort=templist[1].split(":")[1]
            return 1

        if self.state=="PROXYSERVER":
            if not self.processProxyUrl(templist[1]):
                return 0
        elif self.state=="SERVER":
            self.URL=templist[1]

        #HTTP/1.1 or HTTP/1.0
        try:
            self.version=templist[2]
        except IndexError:
            devlog("spkproxy", "Did not get a valid request!")
            self.version="0"
            return 0
        #print "VERB="+self.verb+" URL="+self.URL+" version="+self.version
        return 1


    def processProxyUrl(self, proxyurl):
        """
        This is a bit of an ugly function to take something like http://bob.com/url?hey and do something with it
        We are used by spkproxy.urlopen() among other things.
        """
        devlog("spkproxy", "Processing ProxyURL: %s"%repr(proxyurl))

        #here is basically what we return
        self.URLargsDict={}
        self.useSSL=0
        self.connectHost=""
        #this might already be set if we got an SSL proxy request
        if not self.connectPort:
            self.connectPort=80
        self.URL=""

        #print "processProxyUrl: "+proxyurl
        #just in case we ARE doing ssl...
        urlbit=proxyurl
        #if we're not doing an SSL proxy
        if not self.clientisSSL:
            #print "proxyURL is not SSL"
            #rip the http:// off
            urltype=proxyurl.split("://")[0]
            if len(proxyurl.split("://")) < 2:
                print "Need something after the http:// - exiting this thread"
                return 0
            #else we are good to go...we reassign urlbit here
            #need to do join because of multiple :// in arguments and stuff
            #should fix bbc news error
            urlbit="://".join(proxyurl.split("://")[1:])
            if urltype=="https":
                #this is probably broken: REVISIT
                self.setclientSSL()
                #print "[SPX] setclientSSL()"
            elif urltype!="http":
                print "unknown url type "+urltype
                return 0

            #must have http://something
            if len(proxyurl.split("://"))<2:
                print "must have http://something"
                return 0

            self.connectHost=urlbit.split("/")[0]
            #here we add a Host: self.connectHost header
            #so that when we do HTTP/1.1 it is done properly.
            #don't add a Host header if we already have one.
            devlog("spkproxy","HOST = %s"%self.connectHost)
            if not self.hasHeader("Host"):
                self.addHeader("Host",self.connectHost)

            #get rid of the host from urlbit
            if len(urlbit.split("/"))<2:
                urlbit="/"
            else:
                urlbit="/".join(urlbit.split("/")[1:])

            if urlbit=="":
                urlbit="/"

            #lame, but should work
            if urlbit[0]!="/":
                urlbit="/"+urlbit

            if len(self.connectHost.split(":"))>1:
                port = ''
                for c in self.connectHost.split(':')[1]:
                    if c.isdigit():
                        port += c
                    else:
                        break
                self.connectPort = int(port)
                self.connectHost = self.connectHost.split(":")[0]
                #print "Set self.connectHost to "+self.connectHost
            elif self.useSSL:
                self.connectPort=443

            if self.connectHost=="":
                print "Error: empty connect host!"
                return 0

        #end if self.clientisSSL==0:

        #TODO: Fix this to work on blah.ng/asdf=asdf&asdf2=asdf2
        #this should work, but there's no way for me, as the client
        #to really know
        if urlbit.count("?")==0 and urlbit.count("=")>0:
            indexequal=urlbit.find("=")
            if indexequal!=-1:
                indexfirstslash=urlbit.rfind("/",0,indexequal)
                if indexfirstslash!=-1:
                    #print "original = "+urlbit
                    #print "indexequal="+str(indexequal)
                    #print "indexfirstslash="+str(indexfirstslash)
                    urlbit=urlbit[:indexfirstslash]+"?"+urlbit[indexfirstslash+1:]
                    #print "new="+urlbit

        #if we have a url as well
        self.URL=urlbit.split("?")[0]
        #if we have arguments too
        if len(urlbit.split("?"))>1:
            self.allURLargs="?".join(urlbit.split("?")[1:])
            #print "SELF.allURLARGS=%s"%self.allURLargs
            #print "SELF.URL=%s"%self.URL
            self.URLargsDict=daveutil.splitargs(self.allURLargs,orderlist=self.orderlist)
            if self.URLargsDict==None:
                self.URLargsDict={}
                self.useRawArguments=1
                return 1



        #got here! success!
        #we now have URLargsDict
        return 1

    def isdone(self):
        #print "self.isdone called "+str(self.done)
        if self.done==0:
            return 0
        return 1

    def gotGoodHeader(self):
        return self.goodHeader

    def bodySize(self):
        return self.mybodysize

    def getAllHeaders(self):
        """
        Returns dictionary consisting of all he headers
        Don't modify this dictionary, or you modify the headers.
        """
        return self.headerValuesDict

    def grabHeader(self,header):
        if self.headerValuesDict.has_key(header):
            returnstr=""
            #iterate over the list and add a line for each
            for value in self.headerValuesDict[header]:
                returnstr+=header+": "+value+"\r\n"
            return returnstr
        else:
            return ""

    def getHeaderValue(self,header):
        if self.headerValuesDict.has_key(header):
            # XXX maybe we should use another string that ""
            return "".join(self.headerValuesDict[header])
        else:
            return ""

    def replacere(self,headername, rx, group, newvalue):
        """ Replaces a header (if it exists) with a particular regex and
        newvalue. group is group to replace (0 for all of the string). Returns
        boolean of "did we replace it". Our return value is not used currently
        by any other function. """
        devlog("spkproxy","Replacere name=%s rx=%s newvalue=%s"%(headername, rx, newvalue))
        data=self.getHeaderValue(headername)

        if not data:
            devlog("spkproxy", "Nothing replaced because no header found for %s"%headername)
            return False #nothing replaced
        p=re.compile(rx)
        result=p.search(data)
        if not result:
            devlog("spkproxy", "Nothing replaced because no result found in %s"%(data))
            return False
        groupvalue=result.group(group)
        if not groupvalue:
            devlog("spkproxy","Refusing to replace blank string with our newvalue")
            return False
        data=data.replace(groupvalue,newvalue)

        devlog("spkproxy","Found %s as our target to replace"%groupvalue)
        #finalize it into our header
        self.setHeader(headername,data)
        return True

    def setProxyHeader(self,newheader):
        self.proxyHeader=newheader
        return

    def readdata(self,infd):
        while self.isdone()==0:
            try:
                data=infd.recv(1)
                #print "XXX: data ->" + repr(data)
            except Exception:
                #import traceback
                #traceback.print_exc(file=sys.stderr)
                print "Client closed connection"
                break
            if not data:
                if 0:
                    print "end of data"
                break
            self.addData(data)
        ret=self.isdone()
        return ret

class body:
    def __init__(self):
        self.mysize=0
        self.data=[]

    def printme(self):
        result= "".join(self.data)
        result=daveutil.prettyprint(result)
        return result

    def setSize(self,size):
        self.mysize=size
        return

    def setBody(self,body):
        """Body must be a string, not a list of strings"""
        self.setSize(len(body))
        self.data=[body]
        return

    #just compare sizes for speed.
    def issame(self,other):
        #and self.data==other.data:
        if self.mysize==other.mysize :
            return 1
        return 0

    def genhash(self):
        hash=""
        hash+=daveutil.hashstring("".join(self.data))
        return hash

    def getArgsDict(self):
        argsDict=daveutil.splitargs("".join(self.data))
        if argsDict==None:
            argsDict={}
        return argsDict

    def readBlock(self,connection,size):
        devlog("spkproxy", "body::readBlock (%d)"%size)
        targetsize=size
        tempdata=[]
        i=0 #timeout counter
        gotlength=0
        while targetsize > gotlength:
            #read some data
            try:
                newdata=connection.recv(targetsize-gotlength)
                tempdata+=[newdata]
                gotlength+=len(newdata)
            except timeoutsocket.Timeout:
                i+=1
                devlog("spkproxy", "Timeout exception while reading block. Timeout counter: %d"%i)
                break
            except socket.error:
                devlog("spkproxy", "socket.error exception while reading block")
                break

            if len(newdata)==0:
                devlog("spkproxy", "No data exception while reading block")
                #server promised us some data, but reneged on the deal
                break

            devlog("spkproxy", "Targetsize=%d, gotlength=%d" % (targetsize,gotlength))
        tempdata="".join(tempdata)
        devlog("spkproxy", "read "+str(len(tempdata))+" bytes of data in readblock, wanted "+str(size))
        self.data+=tempdata
        self.mysize+=targetsize
        return size

    #This handles chunked data cleanly - well, handles it anyways
    #this is the cruftiest function ever made.
    def read(self,connection,size,waschunked,readtillclosed):
        if not waschunked:
            if readtillclosed and size==0:
                devlog("spkproxy", "Not chunked and size=%d: reading till closed"%size)
                temp=""
                while 1:
                    #this is a lame way to do it, but hopefully it will work
                    try:
                        length=len(temp)
                        #print "len="+str(length)
                        temp+=connection.recv(1000)
                        #print "len2="+str(len(temp))
                        #WAY crufty here...
                        if (length==len(temp)):
                            #we didn't recieve any data
                            break
                        if len(temp)==size:
                            devlog("spkproxy", "Got all the data we needed %d"%len(temp))
                            break
                        if temp.count("</html>")>0:
                            #this is necessary because stupid hotmail will
                            #not send a fin after sending lots of data
                            #with connection: close!
                            #print "Noticed a </html> - breaking out of this"
                            #time.sleep(4)
                            #break
                            pass
                    #except (SSL.SysCallError,socket.error), diag:
                    #    #print "Caught exception in recv - "+str(diag)
                    #    break #no ssl for now
                    except Exception, e:
                        #some sort of exception sending or recieving data
                        import traceback
                        print "spkproxy: An exception occurred: %s" % traceback.print_exc()
                        connection.close()
                        break

                devlog("spkproxy", "Read till close occured - "+str(len(temp))+" bytes read")
                self.data+=temp
                self.mysize+=len(temp)

                return len(temp)
            else:
                #not reading until closed - we have a size. We may still want to close the socket, but at
                #least we know how much data to expect
                return self.readBlock(connection,size)

        else:
            devlog("spkproxy",  "Reading chunked data")
            while 1:
                #read in a chunked data stream and return the size
                linesize=[]
                while linesize[-2:]!=["\r","\n"]:
                    try:
                        linesize+=connection.recv(1)
                    except timeoutsocket.Timeout:
                        #we timed out on our recv...
                        devlog("spkproxy", "Got timeout in SSL recv")
                        linesize=None #no more...we're done
                        break
                    except socket.error:
                        #same
                        devlog("spkproxy", "Got socket.error in SSL recv")
                        linesize=None #no more...we're done
                        break

                if linesize==None:
                    break

                #ok, now we have the size as a list, transform that to an int
                #base 16, of course
                #print "linesize in str = "+"".join(linesize)
                linesize=int("".join(linesize),16)
                #print "linesize="+str(linesize)
                if linesize==0:
                    #print "done with chunked transfer!"
                    #clear this out
                    linesize=[]
                    while linesize[-2:]!=["\r","\n"]:
                        linesize+=connection.recv(1)
                    return self.mysize
                #print "calling self.readBlock with size "+str(linesize)
                self.readBlock(connection,linesize)
                #clear this out
                linesize=[]
                while linesize[-2:]!=["\r","\n"]:
                    linesize+=connection.recv(1)

    def gotGoodBody(self):
        if self.mysize==len(self.data):
            return 1
        else:
            return 0

class spkProxyConnection( Thread ):
    """
    this is the class that does most of the work of spike proxy.
    """
    def __init__(self,connection,myUI,proxy=None,ntlm=None,ssl_version=None):
        Thread.__init__(self)
        #client connection
        self.gettcpsock=None
        self.connection=connection
        self.clientisSSL=0
        self.currentHost=""
        self.currentPort=0
        self.haveSocket=0
        self.sslHost=""
        self.sslPort=""
        #serversion connection
        self.currentSocket=-1
        self.sawConnectionClose=0
        #new user interface
        self.myUI=myUI
        self.proxyHeader=""
        self.proxyHost=""
        self.proxyPort=0
        self.proxySSLHost=""
        self.proxySSLPort=0
        self.NTLMUser=""
        self.NTLMDomain=""
        self.NTLMPassword=""
        self.NTLMAuthState=""
        self.ssl_version = ssl_version

        #a list of tuples of regular expressions and replacements (new,pattern)
        #it's your responsibility right now to make sure the sizes
        #are the same - otherwise the Content-Length will be off!
        self.reList=[]
        #remove checks for right mouse
        self.reList+=[("0"*17,"event.button == 2")]
        self.reList+=[(" "*16,"PIB_KILL_SESSION")]

        #a list of tuples of regular expressions for URLS we will just not go to
        #this is here because of a website that automatically logged you out using their
        #logout page whenever you did anything fun
        self.reListDenyURLS=["Logoff"]

        self.parent=None #spkproxy class

        self.clientREList =[("A"*50000,"longa")]
        self.clientREList+=[("A"*1000,"shorta")]
        self.clientREList+=[("%n"*10,"formatstring")]
        self.clientREList+=[("<script>alert('hi')</script>"*10,"myalert1")]
        self.clientREList+=[("\"><script>alert('hi')</script>", "myalert2")]
        self.clientREList+=[("<~/XSS/*-*/STYLE=xss:e/**/xpression(alert('XSS'))>", "aspxss")]
        self.clientREList+=[("\"'>\">!--()&*","myescape")]

        if proxy!=None:
            (self.proxyHost,self.proxyPort,self.proxySSLHost,self.proxySSLPort)=proxy

        if ntlm!=None:
            (self.NTLMUser,self.NTLMPassword,self.NTLMDomain)=ntlm
            devlog("spkproxy","Initializing NTLM: %s@%s with password %s"%(self.NTLMUser,self.NTLMDomain,self.NTLMPassword))

        self.my404List=default404stringlist
        self.exploit=None
        self.setDaemon(1)
        return

    def setProxyHeader(self,myheader):
        #print "spkProxyConnection: Proxy header set to %s"%myheader
        self.proxyHeader=myheader
        return

    def run( self ):
        devlog("spkproxy", "Handling new connection")
        while 1:
            devlog("spkproxy", "entering while loop")
            myheader = header()
            #myheader.setConnection(self.connection)
            if self.clientisSSL:
                devlog("spkproxy","Client is SSL")
                myheader.setclientSSL()
                #also set the host and port here to the SSL data
                #so rewrite capture works
                myheader.connectHost=self.sslHost
                myheader.connectPort=self.sslPort

            # NOTE: read the request in from the client
            while myheader.isdone()==0:
                try:
                    data=self.connection.recv(1)
                except socket.timeout:
                    devlog("spkproxy", "Timeout while reading header")
                    continue
                except timeoutsocket.Timeout:
                    devlog("spkproxy", "Timeout while reading header")
                    continue
                except Exception:
                    devlog("spkproxy", "Client closed connection")
                    self.cleanup()
                    return

                if not data:
                    devlog("spkproxy","end of data")
                    break
                myheader.addData(data)

            if myheader.sawsslinit==1:
                devlog("spkproxy", "Saw SSL Init: %s"%prettyprint(str(myheader)))
                self.clientisSSL=1
                self.sslHost=myheader.connectHost
                self.sslPort=myheader.connectPort
                # XXX: chris
                self.connection.sslHost = self.sslHost
                self.connection.sslPort = self.sslPort

                ret=self.connection.startSSLserver()
                if not ret:
                    break
                continue

            #print "Continuing on with while loop!"
            mybody=body()
            devlog("spkproxy", "Done with header")
            #read the body from the client now
            if myheader.gotGoodHeader():
                devlog("spkproxy", "reading body")
                if myheader.bodySize()>0 or myheader.wasChunked:
                    devlog("spkproxy", "Reading body data")
                    #readtillclosed always 0 on client
                    mybody.read(self.connection,myheader.bodySize(),myheader.wasChunked,0)
                else:
                    devlog("spkproxy", "No body needed")
                    pass

                #reset this to the truth
                myheader.mybodysize=mybody.mysize

                if not mybody.gotGoodBody():
                    self.cleanup()
                    return
                devlog("spkproxy", "Done with body")
            else:
                devlog("spkproxy", "failed to get a good header, cleaning up.")
                devlog("spkproxy", "Header we got: %s"%("".join(myheader.data)))
                self.cleanup()
                return
            #done with the body. So now we have a header and a body
            #print "header data="+str(myheader.data)
            #print "body data="+str(mybody.data)
            #devlog("spkproxy","CLIENTRELIST: %s"%self.clientREList)
            #if spikeproxy sees "longa" it will transform it into a long string of A's
            for (new,pattern) in self.clientREList:
                #print "Doing %s expression"%pattern
                p=re.compile(pattern)
                #print "mybody.data=%s"%mybody.data
                data="".join(mybody.data)
                data,count=p.subn(new,data)
                #print "Found %d matches in body"%count
                mybody.data=list(data)
                data="".join(myheader.data)
                data,count=p.subn(new,data)
                myheader.data=list(data)
                #print "Found %d matches in header"%count


            #fix for a bug I can't find right now where connectHost is cleared
            if self.clientisSSL and not myheader.connectHost:
                myheader.connectHost=self.sslHost

            # NOTE: grab the response from the web server
            response = self.sendRequest(myheader,mybody)

            #print "Response : "+response
            sizetosend=len(response)
            sentsize=0

            # NOTE: send the data back to the client
            sentsize+=self.connection.send(response[sentsize:])
            devlog("spkproxy","Sentsize=%s"%sentsize)
            devlog("spkproxy", "Sent data to client.")
            #print "Header we sent: %s"%response.split("\r\n\r\n")[0]

            # NOTE: self.connection is the tcp connection to the client
            if self.connection.gotclosed():
                self.sawConnectionClose=1

            if self.sawConnectionClose:
                devlog("spkproxy", "Closing connection!")

                self.cleanup() #this is what actually closes SSL connection
                return

            devlog("spkproxy","Continuing while loop")

            continue #while loop

    #creates a string with the total reponse in it
    def constructResponse(self,myheader,mybody):
        ret=daveutil.constructResponse(myheader,mybody)
        for (new,pattern) in self.reList:
            p=re.compile(pattern)
            if p.match(ret):
                ret,count=p.subn(new,ret)
                devlog("spkproxy", "Found %d matches for %s"%(count,pattern))
                #TODO, recalculate body size...

        return ret

    #connects to a remote proxy hopefully.
    #1 on success, 0 on failure
    def doProxyConnect(self,host,port):
        if not self.exploit:
            devlog("spkproxy","Not using self.exploit...")
            newsocket=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        else:
            devlog("spkproxy","Using self.exploit to get a socket")
            newsocket=self.exploit.gettcpsock()
        if self.clientisSSL:
            #print "Connecting to SSL Proxy %s %s"%(self.proxySSLHost,self.proxySSLPort)
            newsocket.connect((self.proxySSLHost,dInt(self.proxyPort)))
            newsocket.send("CONNECT %s:%s HTTP/1.1\r\n\r\n"%(host,port))
            #get the response
            #print "Reading in until I get \\r\\n\\r\\n"
            data=daveutil.readuntil(newsocket,"\r\n\r\n")
            #print "Done reading in"
            if data.count("200")==0:
                devlog("spkproxy", "Failed to connect to SSL Server via Proxy")
                return 0
            #SSL doesn't use proxy headers - just raw urls
            self.setProxyHeader("")


        else:
            devlog("spkproxy", "Connecting to Proxy %s %s"%(self.proxyHost,self.proxyPort))
            newsocket.connect((self.proxyHost,dInt(self.proxyPort)))
            if newsocket==None:
                devlog("spkproxy", "Couldn't connect to proxy host!")
                return 0
            #we don't print the port if it's port 80
            if str(port)!="80":
                self.setProxyHeader("http://"+host+":"+str(port))
            else:
                self.setProxyHeader("http://"+host)


        self.currentSocket=newsocket
        #success connecting to proxy
        return 1


#####FIXME



    def closeServerSocket(self):
        """
        Close our server socket down nicely.
        In tlslite this blocks, which is painful.
        """
        if self.haveSocket:
            self.currentSocket.close()
        self.currentPort=0
        self.currentHost=""

        return


    def connectToWebServer(self, myheader):
        # XXX: shouldn't this be myheader.clientisSSL ?
        # XXX: or for both cases as temporary fix

        if self.clientisSSL or myheader.clientisSSL or myheader.connectPort==443:
            # print "[SPX] connectToWebServer is SSL"
            #do we already have a socket connected to the web server?
            #we need to set these just for the record

            # XXX: this should be the other way around no ?
            # XXX: OLD
            #myheader.connectHost=self.sslHost
            #myheader.connectPort=self.sslPort
            # XXX: EOO

            # XXX: if sslHost == "", we are likely coming from an urlopen
            # and need to set sslHost still
            if self.sslHost == "":
                self.sslHost = myheader.connectHost
                self.sslPort = myheader.connectPort
            # XXX: coming from an actual spike proxy thing
            else:
                myheader.connectHost = self.sslHost
                myheader.connectPort = self.sslPort


            #now we do some actual work
            if not self.haveSocket:
                self.haveSocket=1
                self.currentHost=self.sslHost
                self.currentPort=self.sslPort
                if self.gettcpsock:
                    self.currentSocket=self.gettcpsock()
                else:
                    self.currentSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                devlog("spkproxy","Connecting to "+str(self.sslHost)+" "+str(self.sslPort))


                if self.proxyHost!="":
                    #DO PROXY CONNECT HERE
                    if self.doProxyConnect(myheader.connectHost,myheader.connectPort)!=1:
                        return 0
                else:
                    try:
                        self.currentSocket.connect((self.sslHost,dInt(self.sslPort)))
                    except Exception:
                        #print "Connection refused"
                        self.currentHost=""
                        self.currentPort=0
                        return 0

                #HANDLE SSL HERE
                settings = HandshakeSettings()
                settings.minKeySize=512   # some servers have a very small key

                if self.ssl_version != None:
                    settings.maxVersion=self.ssl_version
                else:
                    settings.maxVersion=(3,3) # TLS 1.2
                devlog("spkproxy","Doing TLS Connection for %s" % self.currentHost)

                try:
                    connection=TLSConnection(self.currentSocket)
                    connection.handshakeClientCert(settings=settings)
                    # connection.handshakeClientCert()
                except Exception:
                    devlog("spkproxy","Connection failed to SSL server")
                    return 0
                connection.closeSocket=True
                self.currentSocket = connection

                devlog("spkproxy","Set up SSL")
            else:
                devlog("spkproxy", "SSL connection not done since we already had a connection.")

        else:
            #not SSL
            #do we already have a socket connected to the host
            #print "Connecting to "+str(myheader.connectHost)+" "+str(myheader.connectPort)
            devlog("spkproxy", "currentSocket=%s" % str(self.currentSocket))
            #this -1 compare is because sometimes the socket gets closed on us and we don't find out about it, so
            #we check to make sure - currentSocket!=<socket object, fd=-1, family=2, type=1, protocol=0>
            if self.currentHost==myheader.connectHost and self.currentPort==myheader.connectPort and str(self.currentSocket).count("-1")==0:
                devlog("spkproxy",  "passing because currentHost and currentPort are the same")
            else:
                #handle the condition where we have a socket, but it is the wrong host...
                if self.haveSocket:
                    self.currentSocket.close()

                #if we don't have a socket, or we had the wrong socket, we now need a socket
                #TODO: add error checking...
                if not self.exploit:
                    if self.gettcpsock:
                        devlog("spkproxy","Using self.gettcpsock to get a socket")
                        self.currentSocket = self.gettcpsock()
                    else:
                        devlog("spkproxy","Using socket.socket to get a socket")
                        self.currentSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                else:
                    devlog("spkproxy","Using self.exploit to get a socket")
                    self.currentSocket = self.exploit.gettcpsock()

                if self.proxyHost!="":
                    if self.doProxyConnect(myheader.connectHost,myheader.connectPort)!=1:
                        return 0

                else:
                    try:
                        self.currentSocket.connect((myheader.connectHost,dInt(myheader.connectPort)))
                    except Exception:
                        self.currentHost=""
                        self.currentPort=0
                        #print "Connection refused."
                        return 0

                self.currentHost=myheader.connectHost
                self.currentPort=myheader.connectPort

        #return success!
        return 1


    def massageResponse(self,serverheader,serverbody):
        """
        massageResponse() performs any additional changes on the response before we return it
        For example, this function handles false 200 responses that IIS misconfigurations do
        quite often
        """

        bodydata="".join(serverbody.data)
        #here we check for any misconfigured servers that return a 200 Success while
        #showing a lame "404 not found" page
        #404 string list is set up globally here
        for astring in self.my404List:
            if bodydata.count(astring):
                serverheader.returncode="404"

    def getNTLMEnv(self):
        """
        NTLM is quite a pain in the rear, and here you can see us return a NTLM structure for you.
        """
        env                  = {}
        env["LM"]            = 1
        env["NT"]            = 1
        env["UNICODE"]       = 1
        env["HOST"]          = (self.currentHost.upper())
        env["DOMAIN"]        = (self.NTLMDomain.upper())
        env["USER"]          = (self.NTLMUser.upper())
        env["FLAGS"]         = "06820000"
        env["NTLM_TO_BASIC"] = 0

        env['LM_HASHED_PW']  = get_lanman_hash(self.NTLMPassword)
        env['NT_HASHED_PW']  = ntlmHash(self.NTLMPassword)
        #whatever this is
        env["NTLM_MODE"]     = 0

        return env

    def sendRequest(self, myheader, mybody, noresponse=False, return_response_code=False):
        """
        Sends the request to the server, also does NTLM authentication if necessary.
        This is also called by the GUI, which creates new spike Proxy connections and uses them to send out the
        requests it creates from the rewrite request UI
        """

        for expression in self.reListDenyURLS:
            p=re.compile(expression)
            result=p.search(str(myheader))
            if result:
                devlog("spkproxy", "Matched regular expression: %r"%expression)
                byestring="Matched regular expression %s"%xmlencode(expression)
                return "HTTP/1.1 501 No Server There!\r\nContent-Length: "+str(len(byestring))+"\r\n\r\n"+byestring

        #aspsession is none or "" if we don't want to do a replace
        if self.parent and self.parent.aspsession:
            #replace group 2 (the id itself) with our new session id
            ret=myheader.replacere("Cookie",r".*ASPSESSIONID([A-Z]*)=([A-Z]*);*", 2, self.parent.aspsession)
            #regex this  ASPSESSIONIDCSRDTSQC=FIOJNLAAOJHDNBNCFIEAMEGI; lastCookieSaved=262791932...
            #to ASPSESSIONIDCSRDTSQC=WHATEVER YOU WANT; lastCookieSaved=262791932.
            if ret:
                devlog("spkproxy","Replaced ASP Session ID")
        if self.parent and self.parent.aspnetsession:
            ret=myheader.replacere("Cookie",r".*ASP.NET_SessionId=([a-z0-9]*)", 1, self.parent.aspnetsession)
            if ret:
                devlog("spkproxy","Replaced ASP.NET Session ID")

        ret=self.sendRequestRaw(myheader, mybody, noresponse=noresponse)

        #false is returned if noresponse is true but we DID get a connection
        if ret in [None, False]:
            return (ret, -1) if return_response_code else ret

        (response,serverheader,serverbody)=ret
        #check to see if we have to do the NTLM stuff and if so
        #try to authenticate
        if serverheader!=None:
            #print "Auth: "+serverheader.getStrValue(["WWW-Authenticate"])
            #print "self.NTLMUser="+self.NTLMUser
            pass

        if serverheader!=None and serverheader.getStrValue(["WWW-Authenticate"]) in ["NTLM","Negotiate"] and self.NTLMUser!="":
            devlog("spkproxy","Sending NTLM Authentication")
            #first, clean up our old socket...we're going to be reattempting
            #to open this socket and establish a connection
            #don't need this unless the socket is being kept open...
            #self.closeServerSocket()
            #send packet 1

            my_ntlm=NTLM()
            my_ntlm.type=NTLMSSP_NEGOTIATE
            my_ntlm.set_ntlm_version(1)
            #my_ntlm.isunicode=unicode
            # Flags we want: {'Target Type Share': False, 'Negotiate Target Info': False, 'NegotiateUnicode': True, 'Negotiate 56': False, 'Request Target': False, 'Negotiate Local Call': False, 'NegotiateOEM': True, 'Negotiate 128': False, 'Negotiate NTLM2 Key': False, 'Negotiate NTLM': False, 'Target Type Domain': False, 'Target Type Server': False, 'Negotiate Always Sign': False}
            my_ntlm.flags=0x1283
            #my_ntlm.flags = my_ntlm.flags | 0x04 #add request target to this
            my_ntlm.domain=self.NTLMDomain.upper()
            my_hostname="LOCALHOST"
            my_ntlm.hostname=my_hostname #hardcode this - shouldn't matter really.
            my_ntlm.username=self.NTLMUser
            data=my_ntlm.raw()

            ntlmstring1= b64encode(data).strip()

            #must add the Connection Keep-Alive in order to
            #not drop
            myheader.removeHeaders("Connection")
            myheader.addHeader("Connection", "Keep-Alive")

            myheader.removeHeaders("Authorization")
            myheader.addHeader("Authorization","NTLM "+ntlmstring1)
            #must lock this to HTTP/1.0 for auth requests - why? Because
            #stupid IIS won't send Keep-Alive if it is 1.1. IE does this as well.
            #XXX: Bluecoat proxy hates version 1.0.  Should we just say "We're not being proxied"
            myheader.version="HTTP/1.0"
            (response,serverheader,serverbody)=self.sendRequestRaw(myheader,mybody)
            ntlmchallenge=serverheader.getStrValue(["WWW-Authenticate"])
            #error checking...
            if ntlmchallenge=="Negotiate":
                devlog("spkproxy","Error in NTLM negotiation - at this point we should have a blog to parse")

            #strip off the header, whatever it may be
            ntlmchallenge=ntlmchallenge.replace("NTLM ","")
            ntlmchallenge=ntlmchallenge.replace("NEGOTIATE ","")
            decoded_challenge=b64decode(ntlmchallenge)
            #create nonce
            #get()
            new_ntlm=NTLM()
            new_ntlm.get(decoded_challenge)
            new_domain=new_ntlm.domain
            saved_flagdict=new_ntlm.flagdict
            saved_flagdict["Negotiate NTLM"]=True
            challenge=new_ntlm.challenge
            #nonce = ntlm_messages.parse_message2(ntlmchallenge)
            #print ntlm_messages.debug_message2(ntlmchallenge)
            #create new message
            final_ntlm=NTLM()
            final_ntlm.flags= 0x8201 #new_ntlm.flags & ~0xff028000 | 0x80 #add lanman key to it
            final_ntlm.parse_flags()
            #some weirdness with the flags here...wireshark not the same as in code?!?
            final_ntlm.set_ntlm_version(1)
            final_ntlm.domain="" #self.NTLMDomain.upper()   #new_domain.upper()
            final_ntlm.hostname=my_hostname
            final_ntlm.username=self.NTLMUser
            final_ntlm.password=self.NTLMPassword
            final_ntlm.type=NTLMSSP_AUTH
            final_ntlm.challenge=challenge
            data=final_ntlm.raw()

            NTLM_msg3 = b64encode(data).strip()
            #print  ntlm_messages.debug_message3(NTLM_msg3)
            myheader.removeHeaders("Authorization")
            myheader.addHeader("Authorization","NTLM "+NTLM_msg3)
            #now read in from the new serverheader the new challenge
            #now construct a response
            #now send it, should get a 200 ok back!
            (response,serverheader,serverbody)=self.sendRequestRaw(myheader,mybody)
            #print "Sent last raw request"

        if serverheader!=None and serverbody!=None and self.myUI:
            self.myUI.registerRequestandResponse(myheader, mybody, serverheader, serverbody)
        #print "Returning response: %s"%response

        responsecode = serverheader.returncode if serverheader is not None else -1
        try:
            responsecode = int(responsecode)
        except ValueError:
            responsecode = -1
        return (response, responsecode) if return_response_code else response


    def sendRequestRaw(self, myheader, mybody,newserverheader=None, newserverbody=None, noresponse=False):
        """
        Given a valid header and body, sends it off, and returns the result
        also checks to see if the ui wants the requests, and can redirect it there
        returns the response as a string
        CALLED BY User Interface for rewrite support!!!
        """
        debug_spkproxy=0
        myheader.normalize()

        if self.myUI and self.myUI.wantsRequest(myheader):
            #print "Diverting request to the UI"
            #we force a closed connection for IE - it apparantly will not work otherwise
            devlog("spkproxy", "UI handling this request - sawConnectionClose==1")
            self.sawConnectionClose=1
            return (self.myUI.handleRequest(myheader,mybody),None,None)

        # Check for Referer spoofing
        if 'SPIKE_REFERER' in myheader.URLargsDict:
            referer = myheader.URLargsDict['SPIKE_REFERER']
            myheader.setHeader('Referer', urllib.unquote_plus(referer))
            del myheader.URLargsDict['SPIKE_REFERER']
            if 'SPIKE_REFERER' in myheader.orderlist:
                myheader.orderlist.remove('SPIKE_REFERER')

        # Check for post data
        if 'SPIKE_DATA' in myheader.URLargsDict:
            data = urllib.unquote_plus(myheader.URLargsDict['SPIKE_DATA'])
            del myheader.URLargsDict['SPIKE_DATA']
            if 'SPIKE_DATA' in myheader.orderlist:
                myheader.orderlist.remove('SPIKE_DATA')
            mybody.data = data

        #here we handle any restricted conditions
        if restrictedpages!=[]:
            devlog("spkproxy", "Checking restricted pages")
            if myheader.URL not in restrictedpages:
                devlog("spkproxy", "Page not in restricted pages list")
                return (deniedstring, None, None)

        if restrictedhosts!=[]:
            if myheader.connectHost not in restrictedhosts:
                return (deniedstring, None, None)

        byestring="<html><head><title>Error</title></head><body><h1>  No server there, sorry.</h1></body></html>"
        if not self.connectToWebServer(myheader):
            #print "returning fake 501 page!"
            #import traceback
            #traceback.print_stack(file=sys.stdout)
            return ("HTTP/1.1 501 501 No Server There!\r\nContent-Length: "+str(len(byestring))+"\r\n\r\n"+byestring,None,None)

        #print "Setting proxy header to"+self.proxyHeader
        myheader.setProxyHeader(self.proxyHeader)

        #urg. I wish I could reference globals better
        myRequest = daveutil.constructRequest(myheader, mybody)

        #ok, now I have a socket connected to the host, send the data
        start_time = time.time()

        logging.debug("RAW REQUEST:\n%s" % myRequest)

        try:
            # print myRequest
            self.currentSocket.send(myRequest)
        except socket.error:
            if noresponse:
                return None
            return ("HTTP/1.1 501 No Server There!\r\nContent-Length: "+str(len(byestring))+"\r\n\r\n"+byestring,None,None)

        #print "Sent request:\n"+prettyprint(myRequest)

        if noresponse:
            #no need for a response
            #but we did get a good connection!
            return False

        returncode="100"
        #now read the response - we just ignore HTTP/1.1 100 Continue responses
        timeout_counter=0
        while returncode=="100":
            serverheader = header()
            #commented out for testing
            #serverheader.setConnection(self.currentSocket)

            #print "Reading response now"
            while serverheader.isdone()==0:
                try:
                    #print "recieving"
                    data=self.currentSocket.recv(1)
                    timeout_counter=0
                    #print "Read a byte: "+data
                except timeoutsocket.Timeout:
                    timeout_counter+=1
                    devlog("spkproxy","Timeout exception: continuing. Counter at: %d"%timeout_counter)
                    if timeout_counter>5:
                        devlog("spkproxy", "Timeout has reached 5 - leaving loop")
                        break
                    continue
                except socket.error:
                    devlog("spkproxy", "Connection reset by peer")
                    data=""
                except TLSAbruptCloseError:
                    devlog("spkproxy", "SSL Connection reset by peer")
                    data=""
                except Exception:
                    import traceback
                    traceback.print_exc(file=sys.stderr)
                    devlog("spkproxy", "Unknown SSL recv error")
                    data=""

                if not data:
                    #print "end of data in response!"
                    break
                serverheader.addData(data)
            returncode=serverheader.returncode
            devlog("spkproxy", "Return code from server response="+returncode)


        #print "end of header in response!"
        #+str(serverheader.data)
        #does a case insensitive match and returns us the content length
        #variable
        bodylength=serverheader.mybodysize
        #ok, now we're going to find out if we need to read-till-closed
        #or if we've got a 304 which naturally has no content-length
        if debug_spkproxy:
            print "Server: "+serverheader.getStrValue(["Server"])
            print "Connection: "+serverheader.getStrValue(["Connection"]).lower()
            print "Was chunked?:" + str(serverheader.wasChunked)
            print "Returncode: "+serverheader.returncode
            print "Bodylength: "+str(bodylength)
        readtillclosed=0

        #if you said to close, or you are redirecting AND you didn't bother to say,
        # then close the connection

        if serverheader.getStrValue(["Connection"]).lower() in ["close"] or (serverheader.returncode not in ["304","302","301"] and serverheader.getStrValue(["Connection"]).lower() in ["0"] ):
            if debug_spkproxy:
                print "Connection: close detected"
            readtillclosed=1
        else:
            if debug_spkproxy:
                print "Connection: close not detected or returncode of 304,302,301 reported "

        # special case for 401 with no body
        if (serverheader.returncode == "401" and bodylength == 0 and serverheader.wasChunked == 0):
            if debug_spkproxy:
                print "Empty response for 401"
            readtillclosed = 0

        #print "\nResponse Header:\n"+"".join(serverheader.data)
        serverbody=body()

        if bodylength>0 or readtillclosed or serverheader.wasChunked:
            devlog("spkproxy", "Reading a body of length " + str(bodylength) + " readtillclosed=" + str(readtillclosed) + " chunked=" + str(serverheader.wasChunked))
            serverbody.read(self.currentSocket,bodylength,serverheader.wasChunked,readtillclosed)

        devlog("spkproxy", "Body turned out to be " + str(serverbody.mysize) + " or " + str(len(serverbody.data)) + " bytes.")
        self.massageResponse(serverheader,serverbody)
        # Do callback stuff
        # Form a proper request URL
        url = myheader.getSite() + myheader.URL + myheader.getStringArguments()
        method = 'POST' if mybody.data else 'GET'
        data = None

        # Request POST data
        if len(mybody.data):
            data = "".join(mybody.data)
            myheader.verb = 'POST'
            myheader.setHeader('Content-Type', 'application/x-www-form-urlencoded')

        end_time = time.time()
        # WARNING: data may contain control characters that create invalid ANSI coloring
        # control sequences, which may result in exceptions.
        # devlog('chris', 'request: %s %s [DATA: %s]' % (method, url, data))

        # Dispatch on all registered callback functions
        if self.parent:
            with self.parent.callback_lock:
                req_d = myheader.headerValuesDict
                resp_d = serverheader.headerValuesDict.copy()

                # Decompress
                if resp_d.get('Content-Encoding', None) == ['gzip']:
                    del resp_d['Content-Encoding']
                    import gzip, cStringIO
                    gzipper = gzip.GzipFile(fileobj=cStringIO.StringIO(''.join(serverbody.data)))
                    resp_data = gzipper.read()
                else:
                    resp_data = ''.join(serverbody.data)

                status = serverheader.status
                msg = serverheader.msg

                req_d = dict((h, v[0]) for  h,v in req_d.iteritems())
                resp_d = dict((h, v[0]) for h,v in resp_d.iteritems())

                map(lambda x: x(url, req_d, data, resp_d, resp_data, status, msg, start_time, end_time),
                    self.parent.callbacks)

        response=self.constructResponse(serverheader,serverbody)
        if (readtillclosed):
            devlog("spkproxy", "Saw Connection Close setting to 1")
            self.closeServerSocket()
            self.sawConnectionClose=1


        if newserverheader!=None:
            newserverheader=serverheader

        if newserverbody!=None:
            newserverbody=serverbody

        return (response,serverheader,serverbody)

    def cleanup(self):
        #needs to close socket and stuff
        devlog("spkproxy","Cleanup() called")
        if self.haveSocket:
            self.currentSocket.close()
        self.connection.close()
        self.haveSocket=0
        #print "CLEANING UP"
        #time.sleep(4)
        return

class spkProxy:
    def __init__(self):
        self.mylistenport  = 8080
        self.mylistenhost  = '0.0.0.0'
        self.myUI          = spikeProxyUI.spkProxyUI()
        #here we set ourselves as the parent to the UI
        self.myUI.setParent(self)
        self.proxyHost     = ""
        self.proxyPort     = 0
        self.SSLProxyHost  = ""
        self.SSLProxyPort  = 0
        self.NTLMUser      = ""
        self.NTLMDomain    = ""
        self.NTLMPassword  = ""
        self.exploit       = None
        self.done          = 0
        #if we send out a request, we want to replace the ASP session ID with this!
        self.aspsession    = None
        self.aspnetsession = None
        # The following are used to register callback functions that are called
        # by SPIKE for every request that is generated
        self.callbacks           = set([])
        self.callback_lock       = threading.Lock()
        # The following are used when rewriting SSL certificates on the fly
        self.cacert              = None
        self.cakey               = None
        self.SSLCertificateCache = {}
        self.SSL_Lock            = threading.Lock()

    def addCallback(self, callback):
        """
        Add CALLBACK to the set of callback functions that we call for
        every request that we generate.
        """
        with self.callback_lock:
            self.callbacks.add(callback)

    def removeCallback(self, callback):
        """
        Remove CALLBACK from the set of callback functions that we call for
        every request that we generate.
        """
        with self.callback_lock:
            try:
                self.callbacks.remove(callback)
            except KeyError:
                pass

    def setCACert(self, file):
        """
        Set the file to use as a CA certificate when doing SSL MITM.
        """
        devlog('chris', 'Using custom CA cert: %s' % file)
        self.cacert = open(file, 'rb').read()

    def setCAKey(self, file):
        """
        Set the file to use as a CA key when doing SSL MITM.
        """
        devlog('chris', 'Using custom CA key: %s' % file)
        self.cakey = open(file, 'rb').read()

    def enableStore(self):
        """
        Enable the filesystem-backed store that is used by spikeProxyUI to save
        requests/responses.
        """
        self.myUI.enableStore()

    def disableStore(self):
        """
        Disable the filesystem-backed store that is used by spikeProxyUI to save
        requests/responses.
        """
        self.myUI.disableStore()

    def storeEnabled(self):
        """
        Return True if our filesystem-backed store is active and we save
        requests/responses.
        False otherwise.
        """
        return self.myUI.storeEnabled()

    def setPort(self,port):
        self.mylistenport=dInt(port)

    def setASPSESSIONID(self,id):
        """Sets the ASP Session ID we use for ALL requests to the argument "id" """
        self.aspsession=id
        devlog("spkproxy","Set aspsession to %s"%id)

    def setDotNetSessionID(self,id):
        """Sets the ASP.Net_SessionID"""
        self.aspnetsession=id
        devlog("spkproxy","Set asp.net session to %s"%id)

    def setListenHost(self,host):
        """Sets the listening host (for sockets) to host"""
        self.mylistenhost=host
        return

    def setProxyHost(self,host):
        """Sets our proxy to host"""
        if ":" in host:
            host,port=host,split(":")
            self.setProxyPort(port)
        self.proxyHost=host

    def setProxyPort(self,port):
        """Sets our proxy port to port"""
        self.proxyPort=port

    def setSSLProxyHost(self,host):
        self.SSLProxyHost=host

    def setSSLProxyPort(self,port):
        self.SSLProxyPort=port

    def setNTLMUser(self, user):
        self.NTLMUser=user

    def setNTLMDomain(self, domain):
        self.NTLMDomain=domain

    def setNTLMPassword(self, passwd):
        self.NTLMPassword=passwd

    def set404List(self,a404list):
        default404stringlist=a404list
        return

    def addTo404List(self,newstring):
        default404stringlist.append(newstring)
        return

    def removeFrom404List(self,oldstring):
        if oldstring in default404stringlist:
            default404stringlist.remove(oldstring)
        return

    def get404List(self):
        return default404stringlist

    def run(self):
        self.myUI.setNTLM((self.NTLMUser,self.NTLMPassword,self.NTLMDomain))
        self.myUI.setProxy((self.proxyHost,self.proxyPort,self.SSLProxyHost,self.SSLProxyPort))

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        print "SPIKEProxy listening on %s:%d"%(self.mylistenhost,self.mylistenport)
        s.bind((self.mylistenhost, self.mylistenport))
        s.listen(5)
        s.set_timeout(1)
        while 1:
            if self.done:
                s.close()
                #exiting
                break
            try:
                conn, addr = s.accept()
            except timeoutsocket.Timeout:
                continue

            conn.set_timeout(5)
            devlog("spkproxy",'Connected to by', addr)
            connection=MyConnection(conn)
            connection.parent=self
            self.handleConnection(connection)

    def handleConnection(self,connection):
        #this needs to spawn a new thread!!
        myntlm=None
        if self.NTLMUser:
            myntlm=(self.NTLMUser,self.NTLMPassword,self.NTLMDomain)
        connection=spkProxyConnection(connection,self.myUI,proxy=(self.proxyHost,self.proxyPort,self.SSLProxyHost,self.SSLProxyPort),ntlm=myntlm)
        connection.exploit=self.exploit
        connection.parent=self
        connection.start()
        #done. :>

#end of class spkProxy
class filetype_str(StringIO.StringIO):
    """
    Still here for backwards compat
    """
    pass


class Auth(object):
    """ base class for spkproxy auth types """
    def __init__(self):
        pass

class NTLMAuth(Auth):
    """
    NTLM Authentication object
    """
    def __init__(self, user="", password="", domain=""):
        self.ntlmuser=user
        self.ntlmpassword=password
        self.ntlmdomain=domain
        return

class BasicAuth(Auth):
    """
    http://en.wikipedia.org/wiki/Basic_access_authentication

    I believe basic auth also has a realm, but we ignore that for now
    """
    def __init__(self, user, password):
        self.user=user
        self.password=password

    def getHeader(self, myheader):
        from exploitutils import b64encode
        authdata=b64encode(self.user+":"+self.password)
        authdata="Basic "+authdata
        myheader.addHeader("Authorization", authdata.strip())
        #done
        return



#for quote_plus
import urllib , mimetypes

def encode_multipart_formdata(fields, files):
    """
    fields is a dictionary of {name: value} elements for regular form fields.
    files is a sequence of (name, filename, value) elements for data to be uploaded as files
    Return (content_type, body)

    TODO: Should we be encoding keys or values?
    TODO: Bug if nulls?
    """
    BOUNDARY = '----------ThIs_Is_tHe_bouNdaRY_$'
    CRLF = '\r\n'
    L = []
    for key in fields:
        value=fields[key]
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        L.append(value)
    for f in files:
        #optionally, they can append a content type, but by default we just
        #use mimetypes to find it.
        (key, filename, value)=f[:3]
        if len(f)==3:
            content_type=get_content_type(filename)
        else:
            content_type=f[3]
        L.append('--' + BOUNDARY)
        L.append('Content-Disposition: form-data; name="%s"; filename="%s"' % (key, filename))
        L.append('Content-Type: %s' % content_type)
        L.append('')
        L.append(value)
    L.append('--' + BOUNDARY + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % BOUNDARY
    return content_type, body

def get_content_type(filename):
    return mimetypes.guess_type(filename)[0] or 'application/octet-stream'

class UserAgent(object):
    """
    A wrapper class for urlopen.

    When you call this you should give a basepath like "http://hostip/"

    hostname is the virtual host you want to connect to. Sometimes this is the same as the hostip.

    The rest is simple and as you would expect.

    We DO support proxies via the proxyhost and proxyport arguments

    This module supports both basic-auth and NTLM authentication. But it does not currently look
    at the Authorization: header response from the server to see which one that supports.
    """
    def __init__(self, basepath, exploit=None, auth=None, hostname=None, proxyhost="", proxyport=None, ssl_version=None):
        self.basepath=basepath
        self.exploit=exploit
        self.auth=auth
        self.hostname=hostname
        self.cookies={}
        self.proxyhost=proxyhost
        self.proxyport=proxyport
        self.lastheader=""
        self.moreheaders=[]
        self.response_head=""
        self.response_body=""
        self.ssl_version=ssl_version
        return

    def ClearCookies(self):
        self.cookies={}
        return

    def SetCookie(self, name, value):
        self.cookies[name]=value
        return

    def SetCookies(self, data=""):
        """
        Data is the return from urlopen, so we need
        to parse it to get headers, and look for Set-Cookie
        """
        #in case someone wants the last header they saw
        #as a server response for extra parsing of their own
        self.lastheader=data

        head=data
        ret=""
        #print "Header's looking for cookies: %s"%head
        for line in head.split("\n"):
            if line.count("Set-Cookie: "):
                #found cookie line
                #strip off front
                line=line[len("Set-Cookie: "):]
                line=line.split(";")[0]
                ##check to keep base64 encoded cookie values complete (cookie=abcd= != cookie=abcd)
                if line.count("=") > 1:
                    first_eq = line.index("=")
                    tup = line[:first_eq], line[first_eq+1:]
                else:
                    tup=line.split("=")[:2]
                if len(tup)==2:
                    name, value=tup
                    #print "Found set-cookie: %s: %s"%(name, value)
                    self.SetCookie(name, value)

                    #return value
        return ret

    def getExtraHeaders(self):
        """
        Returns the headers necessary to maintain cookie state
        """
        extraheaders=[]
        #really slow with lots of cookies. Oh well!
        cookies=""
        for c in self.cookies:
            cookies+="%s=%s; "%(c,self.cookies[c])
        if cookies:
            extraheaders+=[("Cookie", cookies)]
        for tup in self.moreheaders:
            #additional headers are in tuple format ("Name", "Value")
            extraheaders+=[tup]

        return extraheaders

    def addHeader(self, name, value):
        devlog("spkproxy", "Adding header to user agent object: %s: %s"%(name,value))
        self.moreheaders+=[(name, value)]

    def clearHeaders(self):
        devlog("spkproxy", "Clearing headers in user agent object")
        self.moreheaders=[]

    def GET(self, args, noresponse=False, entireresponse=False, return_response_code=False):
        # If return_response_code is set to True, the return value is a tuple (response, retruncode)
        # If return_response_code is set to False (default) the return value is just the response

        extraheaders=self.getExtraHeaders()
        fd=urlopen(self.basepath+args, extraheaders=extraheaders, exploit=self.exploit,
                   hostname=self.hostname, auth=self.auth, useragent=self, proxyhost=self.proxyhost,
                   proxyport=self.proxyport,noresponse=noresponse, entireresponse=entireresponse,
                   return_response_code=return_response_code, ssl_version=self.ssl_version)
        if noresponse:
            #we return the file descriptor and don't wait for a response
            return fd
        else:
            #we wait for a response from the server
            if return_response_code:
                (fd, response_code) = fd
                return (fd.read(), response_code)
            else:
                data = fd.read()
                return data

    def HEAD(self, args, noresponse=False, entireresponse=False, return_response_code=False):
        # If return_response_code is set to True, the return value is a tuple (response, retruncode)
        # If return_response_code is set to False (default) the return value is just the response

        extraheaders=self.getExtraHeaders()

        fd=urlopen(self.basepath+args, extraheaders=extraheaders, verb="HEAD", exploit=self.exploit,
                   hostname=self.hostname, auth=self.auth, useragent=self, proxyhost=self.proxyhost,
                   proxyport=self.proxyport,noresponse=noresponse, entireresponse=entireresponse,
                   return_response_code=return_response_code, ssl_version=self.ssl_version)
        if noresponse:
            #we return the file descriptor and don't wait for a response
            return fd
        else:
            #we wait for a response from the server
            if return_response_code:
                (fd, response_code) = fd
                return (fd.read(), response_code)
            else:
                data = fd.read()
                return data

    def PUT(self, args, data, noresponse=False, return_response_code=False):
        # If return_response_code is set to True, the return value is a tuple (response, retruncode)
        # If return_response_code is set to False (default) the return value is just the response

        extraheaders=self.getExtraHeaders()
        fd=urlopen(self.basepath+args, extraheaders=extraheaders, data=data, verb="PUT", exploit=self.exploit,
                   hostname=self.hostname, auth=self.auth, useragent=self, proxyhost=self.proxyhost,
                   proxyport=self.proxyport, noresponse=noresponse, return_response_code=return_response_code, ssl_version=self.ssl_version)
        if noresponse:
            #we return the file descriptor and don't wait for a response
            return fd
        else:
            #we wait for a response from the server
            if return_response_code:
                (fd, response_code) = fd
                return (fd.read(), response_code)
            else:
                data = fd.read()
                return data

    def OPTIONS(self, entireresponse=True, noresponse=False, return_response_code=False):
        # If return_response_code is set to True, the return value is a tuple (response, retruncode)
        # If return_response_code is set to False (default) the return value is just the response

        extraheaders=self.getExtraHeaders()
        fd=urlopen(self.basepath, extraheaders=extraheaders, verb="OPTIONS", exploit=self.exploit,
                   hostname=self.hostname, auth=self.auth, useragent=self, proxyhost=self.proxyhost,
                   proxyport=self.proxyport, noresponse=noresponse, entireresponse=entireresponse,
                   return_response_code=return_response_code, ssl_version=self.ssl_version)
        if noresponse:
            #we return the file descriptor and don't wait for a response
            return fd
        else:
            #we wait for a response from the server
            if return_response_code:
                (fd, response_code) = fd
                return (fd.read(), response_code)
            else:
                data = fd.read()
                return data

    def POST(self, args, data, extraheaders=None, noresponse=False, return_response_code=False):
        # If return_response_code is set to True, the return value is a tuple (response, retruncode)
        # If return_response_code is set to False (default) the return value is just the response

        #some nonsense here to handle content-type properly in the
        #case the user already has one - we are the first so we will
        #be overwritten
        devlog("spkproxy","POST: %s->%s"%(self.basepath,args))
        eheaders=[("Content-Type", "application/x-www-form-urlencoded")]
        if not extraheaders and data:
            extraheaders=[]
        else:
            #copy this
            extraheaders=extraheaders[:]
        extraheaders=eheaders+self.getExtraHeaders()+extraheaders

        fd=urlopen(self.basepath+args, data=data, verb="POST", exploit=self.exploit,
                   hostname=self.hostname, auth=self.auth, extraheaders=extraheaders,
                   useragent=self,  proxyhost=self.proxyhost, proxyport=self.proxyport,
                   noresponse=noresponse, return_response_code=return_response_code, ssl_version=self.ssl_version)
        if noresponse:
            #we return the file descriptor and don't wait for a response
            return fd
        else:
            #we wait for a response from the server
            if return_response_code:
                (fd, response_code) = fd
                return (fd.read(), response_code)
            else:
                data = fd.read()
                return data

    def multipart(self, args, fields, files):
        content_type, body = encode_multipart_formdata(fields, files)
        extraheaders=[("Content-Type", content_type)]
        extraheaders+=self.getExtraHeaders()
        return self.POST(args, body, extraheaders=extraheaders)



def urlopen(url, extraheaders=None, data=None, proxies=None, exploit=None, verb="GET",
            auth=None, hostname=None, useragent=None, proxyhost="", proxyport=None,
            entireresponse=False, noresponse=False, return_response_code=False, ssl_version=None):
    """
    Replacement for urllib.urlopen that uses SPKProxy:
    Benefits:
    o Does TLSlite properly (urllib is not compatible with our timeoutsocket.py
    o MOSDEF (and CANVAS Node) compatible

    Returns a "file-like" object (like urllib.urlopen)

    If data is a dictionary it does "joinargs" on it, which is essentially making it a form submission

    If return_response_code is set to True, the return value is a tuple (response, retruncode)
    If return_response_code is set to False (default) the return value is just the response
    """
    devlog("spkproxy", "urlopen called on %s"%url[:50])
    myheader = header()

    if auth and hasattr(auth, "getHeader"):
        auth.getHeader(myheader)

    myheader.verb = verb
    #in the case the vHost is different from the IP (default)
    if hostname != None:
        myheader.removeHeaders("Host")
        myheader.addHeader("Host", hostname)

    #now handle extra headers
    #extraheaders is an array of tuples
    if extraheaders:
        #print "Extraheaders: %s"%extraheaders
        for h in extraheaders:
            myheader.removeHeaders(h[0])
            myheader.addHeader(h[0],h[1])

    mybody = body()

    myheader.processProxyUrl(url)
    if data:
        #quick switch to handle our argument as a string or a dictionary
        if isinstance(data, basestring):
            #if we have a string as our body, then we are
            #looking at just setting the body to one thing
            mybody.setBody(data)
        elif type(data) == type({}):
            #if we have a dictionary, then we need to make that
            #a string of urlencoded data and send that
            bodydata=daveutil.joinargs(data,quote_func=urllib.quote_plus)
            mybody.setBody(bodydata)


    #ok, now send the data
    if hasattr(auth,"ntlmuser"):
        ntlmtuple = (auth.ntlmuser,auth.ntlmpassword,auth.ntlmdomain)
    else:
        ntlmtuple = None

    myconn = spkProxyConnection(None, None, ntlm=ntlmtuple,ssl_version=ssl_version)

    myconn.proxyHost=proxyhost
    myconn.proxyPort=proxyport
    #if there is an exploit passed in, than we use that to get
    #our sockets
    if exploit:
        myconn.gettcpsock = exploit.gettcpsock

    # SPKPROXY DEBUG INFO
    logging.debug("URL      : %s" % url)
    logging.debug(myheader)
    logging.debug("Body     : %s" % mybody.printme())
    logging.debug("verb     : %s" % verb)
    logging.debug("useragent: %s" % useragent)
    logging.debug("hostname : %s" % hostname)

    response = myconn.sendRequest(myheader, mybody, noresponse=noresponse, return_response_code=return_response_code)
    if return_response_code:
        (response, responsecode) = response
    else:
        responsecode = -1

    logging.debug("response code: %d" % responsecode)
    logging.debug("RAW RESPONSE:\n%s" % response)

    if noresponse:
        #we don't wait for it, we just send it. This is "None" if we couldn't connect, and "False" if we could.
        #we have to close this here or else servers will feel like we are thumping them (we don't want
        #to wait for the GC to close sockets!)
        myconn.closeServerSocket()
        return (response, responsecode) if return_response_code else response

    if not entireresponse:
        #do we include the headers or not?
        #if we enter this block, we do not
        #print "Server Response: %s"%response
        head=response.split("\r\n\r\n")[0]
        #apparantly urlopen removes the header before it gives you the response
        response = "\r\n\r\n".join(response.split("\r\n\r\n")[1:])

        #print "Head: %s"%head
        if useragent:
            useragent.response_head=head
            useragent.response_body=response
            useragent.SetCookies(head)

    return (StringIO.StringIO(response), responsecode) if return_response_code else StringIO.StringIO(response)

class sForm(object):
    """
    Holds data needed to send to a form
    """
    default_args={}
    default_args["username"]="bob@bob.com"
    default_args["password"]="password"
    default_args["uid"]="0"
    default_args["email"]="bob@bob.com"
    default_args["zipcode"]="90210"
    def __init__(self):
        self.action=None
        self.method="POST"
        self.arguments={}
        self.bodyDict={} #stores arguments

    def __str__(self):
        return self.action+"?"+self.getBody()

    def copy(self):
        newform=sForm()
        newform.action=self.action
        newform.method=self.method
        newform.arguments=self.arguments
        return newform

    def addArgument(self, name, argtype):
        self.arguments[name]=argtype
        return

    def getKey(self):
        """
        A simple "hash"
        """
        return self.action+"?"+self.getBody()

    def getBody(self):
        """
        Gets the argument string or body of the request
        """
        ret=[]
        for arg in self.arguments:
            value=self.bodyDict.get(arg,None)
            if value==None:
                value=self.default_args.get(arg,"test")
            ret+=["%s=%s"%(arg,urllib.quote_plus(value))]
        return "&".join(ret)

def normalize_action(url, action):
    """
    takes "http://www.cnn.com/bob/cow.asp" and "sam.asp" and creates "http://www.cnn.com/bob/sam.asp"
    """

    #set up our http://www.cnn.com and currentdir=http://www.cnn.com/bob/
    url=str(url)
    spliturl=url.split("/")
    allbase="/".join(spliturl[:3])
    if len(spliturl)<=3:
        currentdir=allbase+"/"
    else:
        currentdir="/".join(spliturl[:-1])+"/"


    if action[0]=="/":
        #Relative to base of url
        ret=allbase+action
    elif action.startswith("http"):
        #has it's own url start in it
        ret=action
    else:
        #action is relative to current location
        ret=currentdir+action
    return ret

def parse_for_forms(url, page):
    """
    TODO: Replace this with something that really understands HTML (it kinda works now, but it'll never really work until we get an HTML parser in here)

    Parses a HTML page for forms and returns a list of sForm objects
    We normalize each sForm object so the action is a full http://url rather than a relative
    page.
    """
    ret=[]
    forms=page.split("<form")
    #print "Got: %d"%len(forms)


    if len(forms)==1:
        return ret #no forms
    #print forms
    forms=forms[1:]
    #print forms

    for form in forms:
        myform=sForm()
        lowered=form.lower()
        #first find "action="url""
        action_start=lowered.find("action=\"")
        action_start+=8
        action_end=lowered[action_start:].find("\"")
        action=form[action_start:action_start+action_end]
        if action=="":
            #Error Parsing Action
            continue


        myform.action=normalize_action(url, action)

        #now find METHOD=POST or METHOD=GET
        if lowered.count("method=post") or lowered.count("method=\"post\""):
            myform.method="POST"
            devlog("spider", "method=POST")
        else:
            myform.method="GET"

        #now look for inputs
        inputs=lowered.split("<input ")
        for input in inputs:
            #end of the input itself
            if input.find("/>") != -1:
                input=input[:input.find("/>")]

            things=input.split(" ")
            input_type=None
            input_name=None
            input_value=None
            for thing in things:
                devlog("spider", "Thing: %s"%thing)
                if thing.startswith("type="):
                    input_type=thing[5:]
                elif thing.startswith("name="):
                    input_name=thing[5:].replace("\"","")
                elif thing.startswith("value="):
                    input_value=thing[8:].replace("\"","")
                if input_name and input_type:
                    break

            if input_name==None or input_type==None:
                #no name or type?!?
                #fail
                continue

            myform.arguments[input_name]=input_type
            if input_value!=None:
                myform.bodyDict[input_name]=input_value
        #now we have all the inputs
        if len(myform.arguments)>0:
            ret+=[myform]
    #now we have all the forms
    return ret

class SPIDER(object):
    """
    A web spider used by CANVAS and SPIKE Proxy
    """
    #states
    NOT_STARTED="Not Started"
    RUNNING="Running"
    HALT="HALT"
    def __init__(self):
        self.state=self.NOT_STARTED
        self.initial_urls=[]
        self.totalpages=5000 #the top number of pages we will do so we don't go forever.
        self.eachpage=None #call me if I exist.
        self.after_add=None #call me during addUrl if I exist
        self.parent_log=None
        #endings we don't want to download and parse
        self.ignoreendings=[".zip",".pdf","tgz",".gz",".exe",".ppt",".odp",".odt",".sxw",".sxi",".jpg",".jpeg",".png",".gif",".mov",".avi",".rtf",".ps",".tar",".flv"]
        self.urlsDone={}
        return

    def getTotalUrlsDone(self):
        """
        Returns how many url's we've added to our urlsDone list. This is all the url's we KNOW about.
        """
        return len(self.urlsDone.keys())

    def getTotalForms(self):
        ret=0
        for url in self.urlsDone.keys():
            if self.urlsDone[url] != True:
                ret+=1
        return ret

    def log(self, msg):
        """
        Log to our parent's log message or just ignore it.
        """
        if self.parent_log:
            self.parent_log(msg)
        #else what? Nothing I guess.
        return

    def addUrl(self, newurl, do_after_add=True):
        """
        Adds it to our list of urls to do, if we haven't done that already
        returns True if done
        """
        if not self.urlsDone.get(newurl):
            self.log("Found new url: %s"%newurl)
            #add this to our list of TODO
            self.urllist+=[newurl]
            #now add it to our "added" dictionary
            self.urlsDone[newurl]=True
            if self.after_add and do_after_add:
                self.after_add(newurl)
            return True
        return False

    def haveForm(self, form):
        return form.getKey() in self.urlsDone

    def addForm(self, form, do_after_add=True):
        """
        Adds a form to our "url list"
        """
        key=form.getKey()
        devlog("spider", "Adding form: %s"%key)
        if not self.urlsDone.get(key):
            self.urllist+=[form]
            #todo - make into list
            self.urlsDone[key]=form
            if self.after_add and do_after_add:
                self.after_add(form)
            return True
        return False

    def spider(self):
        """
        Spiders starting with a list of URLS
        Calls "eachpage" if someone set that function pointer. This is for counting various things like email addresses.
        """
        from exploitutils import getsitebase
        #realistically we want to do a "distance measure" of our urls
        #so we don't do all 5000 urls very similar!
        pagecount=0
        self.urllist=self.initial_urls[:]
        self.urlsDone={} #hash table we store our done urls in. Done means "Added to self.urllist" not spidered.
        for url in self.urllist:
            self.urlsDone[url]=True
        overall_sitebases=[]
        for url in self.urllist:
            # we'll scan it HTTP or HTTPS - here we add to our overall_sitebases list which is
            # a whitelist of the websites we will allow ourselves to connect to
            overall_sitebases+=[getsitebase(url)]

        while pagecount < self.totalpages and len(self.urllist)>0:
            if self.state==self.HALT:
                break
            pagecount+=1
            url=self.urllist.pop()
            if type(url)==type(""):
                if url.count("/")<3:
                    url=url+"/"
                #site base is http://www.cnn.com/
                sitebase="/".join(url.split("/")[:3])+"/"
                dirbase="/".join(url.split("/")[:-1])+"/"
                self.log("sitebase: %s dirbase: %s"%(sitebase,dirbase))
                self.log("Scanning (%d/%d) %s"%(pagecount, self.totalpages,url))
                ua=UserAgent(url)
                data=ua.GET("") #no extra args
            else:
                #we have an sForm object to send
                form=url #better
                ua=UserAgent(form.action)
                devlog("spider", "Sending %s to %s"%(form.method,form.action))
                args=form.getBody()
                devlog("spider", "Args: %s"%args)

                if form.method=="POST":
                    data=ua.POST("", args)
                    devlog("spider", "POST Returned: %s"%data)
                elif form.method=="GET":
                    data=ua.GET(args)
                    devlog("spider", "GET Returned: %s"%data)
            #first, give the canvas module a chance to do something
            if self.eachpage:
                self.eachpage(url, data)

            #then collect the data the spider needs from the return page
            moreurls=daveutil.collectURLSFromPage(data)
            formList=parse_for_forms(url, data) #look for form data and return list of sForm objects
            devlog("spider", "Formlist=%s"%repr(formList))
            for form in formList:
                devlog("spider","Found form with action: %s"%form.action)
                if not self.haveForm(form):
                    devlog("spider", "Adding form %s"%form.action)
                    self.addForm(form)

            #now we have to handle all the urls
            #this includes mailto urls!
            for newurl in moreurls:
                #add a http to the front if it's not there (we do also support https)
                if not "http".count(newurl[:4]):
                    #self.log("newurl is relative to our site")
                    if "/" == newurl[0]:
                        #self.log("starts with a slash, so sitebase is appropriate")
                        newurl=sitebase+newurl
                    else:
                        #self.log("newurl is relative to our current working directory")
                        newurl=dirbase+newurl
                #self.log("Final URL after normalization: %s"%newurl)
                newsitebase=getsitebase(newurl)
                if newsitebase not in overall_sitebases:
                    self.log("%s is not on a whitelisted site...ignoring"%newsitebase)
                    continue

                #there's a wide range of URL types we don't want to get
                #so let's ignore them...
                inignorelist=False
                for ending in self.ignoreendings:
                    if newurl.lower().endswith(ending.lower()):
                        self.log("Not adding to todo list because it's a restricted file type")
                        inignorelist=True
                        break
                if inignorelist:
                    continue

                self.addUrl(newurl)

        numurls=len(self.urlsDone.keys())
        self.log("Spidered %d urls."%numurls)
        return numurls


def test():
    """
    -T is secret argument that does the test routine
    """
    ua=UserAgent("http://localhost:8080/")
    ua.addHeader("Referrer", "http://localhost/")
    data=ua.GET("")
    print "Data=%s"%data
    return


def usage():
    print """
    SPIKE Proxy Version "+VERSION+", Immunity, Inc.
    http://www.immunityinc.com/spike.html for more help and information
    usage: spkproxy.py [-p port] [-h proxyHost -H proxyPort] [-s proxySSLHost -S proxySSLPort]
           [-U NTLM Username -P NTLM Password -D NTLM Domain] [-l listenhost]
    """

#this stuff happens.
if __name__ == '__main__':

    print "Running SPIKE Proxy v "+VERSION
    print "SPIKE Proxy is copyright Dave Aitel 2002"
    print "Please visit www.immunityinc.com for updates and other useful tools!"
    print "*** To use the GUI, browse to http://spike/ ***"
    print "Let dave@immunityinc.com know if you like this project. :>"

    #VERSIONCHECK
    #just comment this out if it pisses you off
    #versioncheck.getversion(VERSION)


    #quit on control C and control break (win32)
    import signal
    signal.signal(signal.SIGINT,sys.exit)

    app = spkProxy()

    try:
        (opts,args)=getopt.getopt(sys.argv[1:],"h:H:p:s:S:U:P:D:l:T")
    except getopt.GetoptError:
        #print help
        usage()
        sys.exit(2)
    for o,a in opts:
        if o in ["-s"]:
            app.setSSLProxyHost(a)
        if o in ["-S"]:
            app.setSSLProxyPort(a)
        if o in ["-h"]:
            app.setProxyHost(a)
        if o in ["-H"]:
            app.setProxyPort(a)
        if o in ["-p"]:
            app.setPort(dInt(a))
        if o in ["-U"]:
            app.setNTLMUser(a)
        if o in ["-D"]:
            app.setNTLMDomain(a)
        if o in ["-P"]:
            app.setNTLMPassword(a)
        if o in ["-l"]:
            app.setListenHost(a)
        if o in ["-T"]:
            test()

    app.run()
