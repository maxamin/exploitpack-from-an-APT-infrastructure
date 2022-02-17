import socket, os, re, time, random
from TftpShared import *
from TftpPacketTypes import *
from TftpPacketFactory import *
import threading
import select
from exploitutils import *

#set this to an if:0 to disable debug logging or an if 1: if you want to see the info
#we don't import our devlog so we use this instead
if 1:
    
    def hu(msg):
        print msg
    logger.warn = hu
    logger.debug = hu
    logger.info = hu
    
class TftpServer(threading.Thread, TftpSession):
    """This class implements a tftp server object.
    It can be used in a threaded way (using start()) or as a single thread (using run()).
    """

    def __init__(self, tftproot='.', getsock=None, allfiles=None, alluploads=None):
        threading.Thread.__init__(self)
        """Class constructor. It takes a single optional argument, which is
        the path to the tftproot directory to serve files from and/or write
        them to."""
        self.allfiles=allfiles # if not None, then any request gets this data as if it was returned from file.read()xs
        self.getsock=getsock #A canvasexploit object 
        self.listenip = "0.0.0.0"
        self.listenport = 69
        self.sock = None
        self.root = tftproot
        self.alluploads=alluploads
        # A dict of handlers, where each session is keyed by a string like
        # ip:tid for the remote end.
        self.handlers = {}
        if self.allfiles==None and self.alluploads==None:
            #We only check to see if the tftproot is readable/etc if we are using it
            #which we are not doing if allfiles is set to a string (we just return that string)
            if os.path.exists(self.root):
                logger.debug("tftproot %s does exist" % self.root)
                if not os.path.isdir(self.root):
                    raise TftpException, "The tftproot must be a directory."
                else:
                    logger.debug("tftproot %s is a directory" % self.root)
                    if os.access(self.root, os.R_OK):
                        logger.debug("tftproot %s is readable" % self.root)
                    else:
                        raise TftpException, "The tftproot must be readable"
                    if os.access(self.root, os.W_OK):
                        logger.debug("tftproot %s is writable" % self.root)
                    else:
                        logger.warning("The tftproot %s is not writable" % self.root)
            else:
                raise TftpException, "The tftproot does not exist."

    def bind(self, listenip="", listenport=DEF_TFTP_PORT, timeout=SOCK_TIMEOUT):
        self.listenip = listenip
        self.listenport = listenport
        self.timeout = timeout

    def check_sockets(self):
        """
        Returns a list of sockets or empty list
        """
        # Build the inputlist array of sockets to select() on.
        inputlist = []
        inputlist.append(self.sock)
        for key in self.handlers:
            inputlist.append(self.handlers[key].sock)
        inputlist=uniquelist(inputlist)
        # Block until some socket has input on it.
        #logger.debug("Performing select on this inputlist: %s" % inputlist)
        #XXX: this is not getsock compatable!!!
        readyinput, readyoutput, readyspecial = select.select(inputlist,
                                                              [],
                                                              [],
                                                              SOCK_TIMEOUT)
        #logger.debug("readyinput: %s, readyspecial %s"%(readyinput,readyspecial))
        return readyinput
    
    def handle_active_sockets(self, readyinput=None):
        """
        Handle any incoming packets
        """
        if not readyinput:
            readyinput=self.check_sockets()
        if not readyinput:
            logger.info("No TFTP sockets were ready")
            #we're called for no reason?
            return False 
        else:
            logger.info("Socket ready for read!")
        
        deletion_list = []
        #we cannot do this twice in a row on the same socket since it completely breaks our logic
        readyinput=uniquelist(readyinput)
        logger.debug("readyinput = %s"%readyinput)        
        

        for readysock in readyinput:
            if readysock == self.sock:

                logger.debug("Data ready on our main socket")
                buffer, (raddress, rport) = self.sock.recvfrom(MAX_BLKSIZE)
                key = "%s:%s" % (raddress, rport)
                logger.debug("Read %d bytes from key %s" % (len(buffer),str(key)))
                recvpkt = self.tftp_factory.parse(buffer)


                if isinstance(recvpkt, TftpPacketRRQ):
                    logger.debug("RRQ packet from %s:%s" % (raddress, rport))
                    if not self.handlers.has_key(key):
                        try:
                            logger.debug("New download request, session key = %s"
                                    % key)
                            self.handlers[key] = TftpServerHandler(key,
                                                                   TftpState('rrq'),
                                                                   self.root,
                                                                   self.listenip,
                                                                   self.tftp_factory, 
                                                                   self.getsock, 
                                                                   self.allfiles,
                                                                   self.alluploads)
                            self.handlers[key].handle((recvpkt, raddress, rport))
                        except TftpException, err:
                            logger.error("Fatal exception thrown from handler: %s"
                                    % str(err))
                            logger.debug("Deleting handler: %s" % key)
                            deletion_list.append(key)

                    else:
                        logger.warn("Received RRQ for existing session!")
                        self.senderror(self.sock,
                                       TftpErrors.IllegalTftpOp,
                                       raddress,
                                       rport)
                        continue
                    
                elif isinstance(recvpkt, TftpPacketWRQ):
                    #handle a write request - send our ack, etc
                    if not self.handlers.has_key(key):
                        try:
                            logger.debug("New upload request, session key = %s"
                                    % key)
                            self.handlers[key] = TftpServerHandler(key,
                                                                   TftpState('wrq'),
                                                                   self.root,
                                                                   self.listenip,
                                                                   self.tftp_factory, 
                                                                   self.getsock, 
                                                                   self.allfiles,
                                                                   self.alluploads)
                            self.handlers[key].sock=self.sock
                            self.handlers[key].raddr=(raddress, rport)
                            self.handlers[key].handle((recvpkt, raddress, rport))
                        except TftpException, err:
                            logger.error("Fatal exception thrown from handler: %s"
                                    % str(err))
                            logger.debug("Deleting handler: %s" % key)
                            deletion_list.append(key)
                    
                    continue
                else:
                    try:
                        self.handlers[key].handle((recvpkt, raddress,rport))
                    except TftpException, message:
                        logger.info("Message: %s"%message)
                    # FIXME - this will have to change if we do symmetric UDP
                    #logger.error("Should only receive RRQ or WRQ packets "
                    #             "on main listen port. Received %s" % recvpkt)
                    #self.senderror(self.sock,
                    #               TftpErrors.IllegalTftpOp,
                    #               raddress,
                    #               rport)
                    continue
                
            else:
                for key in self.handlers:
                    if readysock == self.handlers[key].sock:
                        # FIXME - violating DRY principle with above code
                        try:
                            self.handlers[key].handle()
                            break
                        except TftpException, err:
                            deletion_list.append(key)
                            if self.handlers[key].state.state == 'fin':
                                logger.info("Successful transfer.")
                                break
                            else:
                                logger.error("Fatal exception thrown from handler: %s"
                                        % str(err))

                else:
                    logger.error("Can't find the owner for this packet.  Discarding.")

        logger.debug("Looping on all handlers to check for timeouts")
        now = time.time()
        for key in self.handlers:
            try:
                self.handlers[key].check_timeout(now)
            except TftpException, err:
                logger.error("Fatal exception thrown from handler: %s"
                        % str(err))
                deletion_list.append(key)

        logger.debug("Iterating deletion list.")
        for key in deletion_list:
            if self.handlers.has_key(key):
                logger.debug("Deleting handler %s" % key)
                del self.handlers[key]
                return 0
        deletion_list = []
        return 

    def listen(self):
        """
        Used by both run and CLE
        raises exceptions on error
        """
        self.tftp_factory = TftpPacketFactory()

        logger.info("Server requested on ip %s, port %s"
                % (self.listenip, self.listenport))
        try:
            # FIXME - sockets should be non-blocking?
            if self.getsock:
                logger.info("Getting socket from CANVAS exploit.")
                self.sock=self.getsock.getudpsock()
            else:
                logger.info("Getting native UDP socket.")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.bind((self.listenip, self.listenport))
        except socket.error, err:
            logger.error("TFTPD could not listen on that ip/port!")
            # Reraise it for now.
            raise
        return True 

    def close(self):
        """
        Close all our sockets
        """
        logger.info("Closing TFTPD socket")
        if self.sock:
            self.sock.close()
        for key in self.handlers.keys():
            del self.handlers[key]
        return 
    
    def run(self):
        """Start a server listening on the supplied interface and port. This
        defaults to INADDR_ANY (all interfaces) and UDP port 69. You can also
        supply a different socket timeout value, if desired."""
        self.listen()
        

        logger.info("Starting receive loop...")
        while True:
            readyinput=self.check_sockets()
            self.handle_active_sockets()
            #(buffer, (raddress, rport)) = self.sock.recvfrom(MAX_BLKSIZE)
            #recvpkt = tftp_factory.parse(buffer)
            #key = "%s:%s" % (raddress, rport)


class TftpServerHandler(TftpSession):
    """This class implements a handler for a given server session, handling
    the work for one download."""

    def __init__(self, key, state, root, listenip, factory, getsock=None, allfiles=None, alluploads=None):
        TftpSession.__init__(self)
        logger.info("Starting new handler. Key %s." % key)
        self.allfiles=allfiles
        self.getsock=getsock
        self.key = key
        self.host, self.port = self.key.split(':')
        self.port = int(self.port)
        self.listenip = listenip
        # Note, correct state here is important as it tells the handler whether it's
        # handling a download or an upload.
        self.state = state
        self.root = root
        self.mode = None
        self.filename = None
        self.sock = False
        self.options = {}
        self.blocknumber = 0
        self.buffer = None
        self.fileobj = None
        self.timesent = 0
        self.timeouts = 0
        self.tftp_factory = factory
        count = 0
        #for uploads
        self.got_blocks={}
        self.raddr=None #initialized when we are uploading
        self.alluploads= alluploads
        self.blocksize=512
        
        if not alluploads:
            #we are in download mode, not upload mode, so we need a new socket to send requests from
            while not self.sock:
                self.sock = self.gensock(listenip)
                count += 1
                if count > 10:
                    raise TftpException, "Failed to bind this handler to any port"

    def check_timeout(self, now):
        """This method checks to see if we've timed-out waiting for traffic
        from the client."""
        if self.timesent:
            if now - self.timesent > SOCK_TIMEOUT:
                self.timeout()

    def timeout(self):
        """This method handles a timeout condition."""
        logger.debug("Handling timeout for handler %s" % self.key)
        self.timeouts += 1
        if self.timeouts > TIMEOUT_RETRIES:
            raise TftpException, "Hit max retries, giving up."

        # FIXME - still need to handle Sorceror's Apprentice problem

        if self.state.state == 'dat' or self.state.state == 'fin':
            logger.debug("Timing out on DAT. Need to resend.")
            self.send_dat(resend=True)
        elif self.state.state == 'oack':
            logger.debug("Timing out on OACK. Need to resend.")
            self.send_oack()
        else:
            tftpassert(False,
                       "Timing out in unsupported state %s" %
                       self.state.state)

    def gensock(self, listenip):
        """This method generates a new UDP socket, whose listening port must
        be randomly generated, and not conflict with any already in use. For
        now, let the OS do this."""
        random.seed()
        port = random.randrange(1025, 65536)
        # FIXME - sockets should be non-blocking?
        if self.getsock==None:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        else:
            sock = self.getsock.getudpsock()
        logger.debug("Trying a handler socket on port %d" % port)
        try:
            sock.bind((listenip, port))
            return sock
        except socket.error, err:
            if err[0] == 98:
                logger.warn("Handler %s, port %d was already taken" % (self.key, port))
                return False
            else:
                raise
        logger.debug("Set up handler socket on port %s:%d"%(listenip,port))
        
    def handle(self, pkttuple=None):
        """This method informs a handler instance that it has data waiting on
        its socket that it must read and process."""
        recvpkt = raddress = rport = None
        if pkttuple:
            recvpkt, raddress, rport = pkttuple
            logger.debug("Handed pkt %s for handler %s" % (recvpkt, self.key))
        else:
            logger.debug("Data ready for handler %s" % self.key)
            buffer, (raddress, rport) = self.sock.recvfrom(MAX_BLKSIZE)
            logger.debug("Read %d bytes" % len(buffer))
            recvpkt = self.tftp_factory.parse(buffer)
            
        # FIXME - refactor into another method, this is too big
        if isinstance(recvpkt, TftpPacketRRQ):
            logger.debug("Handler %s received RRQ packet" % self.key)
            logger.debug("Requested file is %s, mode is %s" % (recvpkt.filename,
                                                               recvpkt.mode))
            # FIXME - only octet mode is supported at this time.
            if recvpkt.mode != 'octet':
                #force it to octet mode, incorrectly, but easily
                recvpkt.mode = "octet"
                #self.senderror(self.sock,
                #               TftpErrors.IllegalTftpOp,
                #               raddress,
                #               rport)
                #raise TftpException, "Unsupported mode: %s" % recvpkt.mode

            if self.state.state == 'rrq':
                logger.debug("Received RRQ. Composing response.")
                if self.allfiles==None:
                    #we're doing normal TFTP operations on a file on disk
                    #instead of reading a "file" from memory
                    self.filename = self.root + os.sep + recvpkt.filename
                    logger.debug("The path to the desired file is %s" %
                            self.filename)
                    self.filename = os.path.abspath(self.filename)
                    logger.debug("The absolute path is %s" % self.filename)
                    # Security check. Make sure it's prefixed by the tftproot.
                    if re.match(r'%s' % self.root, self.filename):
                        logger.debug("The path appears to be safe: %s" %
                                self.filename)
                    else:
                        logger.error("Insecure path: %s" % self.filename)
                        self.errors += 1
                        self.senderror(self.sock,
                                       TftpErrors.AccessViolation,
                                       raddress,
                                       rport)
                        raise TftpException, "Insecure path: %s" % self.filename
    
                    # Does the file exist?
                    if os.path.exists(self.filename):
                        logger.debug("File %s exists." % self.filename)
                    else:
                        logger.error("Requested file %s does not exist." %
                                     self.filename)
                        self.senderror(self.sock,
                                       TftpErrors.FileNotFound,
                                       raddress,
                                       rport)
                        raise TftpException, "Requested file not found: %s" % self.filename

                # Check options. Currently we only support the blksize
                # option.
                if recvpkt.options.has_key('blksize'):
                    logger.debug("RRQ includes a blksize option")
                    blksize = int(recvpkt.options['blksize'])
                    if blksize >= MIN_BLKSIZE and blksize <= MAX_BLKSIZE:
                        logger.debug("Client requested blksize = %d"
                                % blksize)
                        self.options['blksize'] = blksize
                    else:
                        logger.warning("Client %s requested invalid "
                                       "blocksize %d, responding with default"
                                       % (self.key, blksize))
                        self.options['blksize'] = DEF_BLKSIZE
    
                    logger.debug("Composing and sending OACK packet")
                    self.send_oack()
    
                elif len(recvpkt.options.keys()) > 0:
                    logger.warning("Client %s requested unsupported options: %s"
                            % (self.key, recvpkt.options))
                    logger.warning("Responding with negotiation error")
                    self.senderror(self.sock,
                                   TftpErrors.FailedNegotiation,
                                   self.host,
                                   self.port)
                    raise TftpException, "Failed option negotiation"

                else:
                    logger.debug("Client %s requested no options."
                            % self.key)
                    self.start_download()

          
            else:
                # We're receiving an RRQ when we're not expecting one.
                logger.error("Received an RRQ in handler %s "
                             "but we're in state %s" % (self.key, self.state))
                self.errors += 1

        elif isinstance(recvpkt, TftpPacketWRQ):
            #handle write request
            logger.debug("Received a WRQ packet from the client")
            logger.info("Got upload request for filename %s mode %s"%(recvpkt.filename, recvpkt.mode))
            self.state = TftpState("dat")
            #here we have a special blocknum of zero to ack the WRQ packet
            ack=TftpPacketACK()
            ack.blocknumber=0
            ack.encode()
            self.sock.sendto(ack.buffer, 0, self.raddr)
            self.timesent = time.time()
            
        elif isinstance(recvpkt, TftpPacketDAT):
            #handle DAT packet send after write request
            if self.state.state != "dat":
                logger.debug("Error: Got DAT packet while not in upload state (state=%s)"%self.state.state)
            else:
                #ack that packet
                if recvpkt.blocknumber not in self.got_blocks:
                    self.got_blocks[recvpkt.blocknumber]=True 
                    self.alluploads+=recvpkt.data
                    if len(recvpkt.data)<self.blocksize:
                        logger.info("Data transfer finished with block of size %d"%len(recvpkt.data))
                        self.state=TftpState('fin')
                        
                ack=TftpPacketACK()
                ack.blocknumber=recvpkt.blocknumber 
                ack.encode()
                self.sock.sendto(ack.buffer, 0, self.raddr)
                self.timesent = time.time()
  
        # Next packet type
        elif isinstance(recvpkt, TftpPacketACK):
            logger.debug("Received an ACK from the client.")
            if recvpkt.blocknumber == 0 and self.state.state == 'oack':
                logger.debug("Received ACK with 0 blocknumber, starting download")
                self.start_download()
            else:
                if self.state.state == 'dat' or self.state.state == 'fin':
                    if self.blocknumber == recvpkt.blocknumber:
                        logger.debug("Received ACK for block %d"
                                % recvpkt.blocknumber)
                        if self.state.state == 'fin':
                            raise TftpException, "Successful transfer."
                        else:
                            self.send_dat()
                    elif recvpkt.blocknumber < self.blocknumber:
                        logger.warn("Received old ACK for block number %d"
                                % recvpkt.blocknumber)
                    else:
                        logger.warn("Received ACK for block number "
                                    "%d, apparently from the future"
                                    % recvpkt.blocknumber)
                else:
                    logger.error("Received ACK with block number %d "
                                 "while in state %s"
                                 % (recvpkt.blocknumber,
                                    self.state.state))

        elif isinstance(recvpkt, TftpPacketERR):
            logger.error("Received error packet from client: %s" % recvpkt)
            if self.state.state!='dat':
                #if we are in an upload/download state, we ignore errors
                #because win32 tftp client seems to send access denied to us, and then go
                #ahead and try to download anyways
                self.state.state = 'err'
                raise TftpException, "Received error from client"
            else:
                logger.error("Ignoring error")
        # Handle other packet types.
        else:
            logger.error("Received packet %s while handling a download"
                    % recvpkt)
            self.senderror(self.sock,
                           TftpErrors.IllegalTftpOp,
                           self.host,
                           self.port)
            raise TftpException, "Invalid packet received during download"

    def start_download(self):
        """This method opens self.filename, stores the resulting file object
        in self.fileobj, and calls send_dat()."""
        self.state.state = 'dat'
        if self.allfiles:
            from libs.spkproxy import filetype_str
            self.fileobj=filetype_str(self.allfiles)
        else:
            self.fileobj = open(self.filename, "r")
        self.send_dat()

    def send_dat(self, resend=False):
        """This method sends a DAT packet based on what is in self.buffer."""
        if not resend:
            try:
                blksize = int(self.options['blksize'])
            except KeyError:
                blksize = DEF_BLKSIZE
            logger.debug("Blocksize=%d"%blksize)
            self.buffer = self.fileobj.read(blksize)
            logger.debug("Read %d bytes into buffer" % len(self.buffer))
            if self.buffer == "" or len(self.buffer) < blksize:
                logger.info("Reached EOF on file %s" % self.filename)
                self.state.state = 'fin'
            self.blocknumber += 1
            if self.blocknumber > 65535:
                logger.debug("Blocknumber rolled over to zero")
                self.blocknumber = 0
        else:
            pass
            #logger.warn("Resending block number %d" % self.blocknumber)
        dat = TftpPacketDAT()
        dat.data = self.buffer
        dat.blocknumber = self.blocknumber
        data=dat.encode().buffer 
        logger.debug("Sending DAT packet %d of length %s" % (self.blocknumber, len(data)))
        self.sock.sendto(data, (self.host, self.port))
        self.timesent = time.time()
        return 
    
    def send_oack(self):
        """This method sends an OACK packet based on current params."""
        logger.debug("Composing and sending OACK packet")
        oack = TftpPacketOACK()
        oack.options = self.options
        self.sock.sendto(oack.encode().buffer,
                         (self.host, self.port))
        self.timesent = time.time()
        self.state.state = 'oack'
