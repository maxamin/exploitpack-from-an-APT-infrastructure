#! /usr/bin/env python
"""
localsniffer.py
manages the local sniffer for the canvas engine

TODO: 
   Partner is saying that sniffer is reporting ports open outside the range desired because 
   somehow the sniffer is queuing up packets in recv() and reporting results from other
   network traffic that happened previously.

   Not a big issue, but certainly weird. I don't see it in the code.
"""

import sys
from threading import Thread
from sniffer import sniffer
from sniffer import packetParser
from internal import *
from exploitutils import *
import time

class packetfilter:
    def __init__(self, filterstring):
        #filterstring is "TCP" or "TCP AND NOT PORT 555" <-- XXX TODO ?
        self.fs=filterstring.lower().split(" ")
        return

    def match(self,parser):
        #matches a packet parser with our string
        for each in self.fs:
            if parser.fields.count(each)==0:
                return 0
        return 1



class localsniffer(Thread):
    def __init__(self, prelooping_delay=1, engine=None, driver=None, dstats=True, fp_sil=False):
        Thread.__init__(self, verbose=debug_threads)

        self.engine = engine
        self.maindone=1
        self.setDaemon(True) #don't wait for this thread to quit when we exit XXX
        self.prelooping_delay = prelooping_delay
        self.restartparser = False
        self.sniffer=sniffer()
        self.callbacks=[]
        self.done = 0
        self.driver=driver
        self.dstats=dstats

        if self.sniffer.listen()==0:
            #print "sniffer failed to listen"
            self.sniffer=None
    
        self.fp_sil = fp_sil

        return

    def listen(self):
        """
        Reinitialize our sniffer
        """
        self.sniffer.listen()
        return

    def running(self):
        if self.sniffer==None:
            return 0
        return 1

    def registercallback(self, callback, filterstring):
        #we reverse the order here of the callback and the filter string in our tuple <-- XXX ???
        pf=packetfilter(filterstring)
        self.callbacks.append((pf,callback)) #thread safe.
        devlog('localsniffer::registercallback', "Registered %s as a callback for string <%s>" % (callback, filterstring))
        return

    def unregistercallback(self,callback):
        for my_callback in self.callbacks:
            if my_callback[1]==callback:
                self.callbacks.remove(my_callback)
        return

    def addIPtoKnowledge(self, node, host):
        ##Stop 0.0.0.0 being added as that's just plain stupid
        if host == "0.0.0.0":
            host = "127.0.0.1"
            
        if not host:
            return
        if node.get_known_host(host):
            return
        if not host_is_interesting(host):
            return
        devlog('localsniffer::addIPtoKnowledge', "adding %s" % host)
        newhost=node.new_host(host)

    def run(self):
        """
        Calls the sniffer.realrun function but catches 
        when sys.exit is called
        """
        # this silences exceptions within this thread when the main
        # thread exits and Python starts shutting down while this thread
        # is still trying to do stuff
        try:
            self.realrun()
        except:
            #true will be "none" when sys.exit(1) is called
            if True:
                raise 
        return 
        
    def realrun(self):
        self.maindone=1
        #parser = None # to use with self.restartparser

        try:
            parser = packetParser(self.driver, fp=self.fp_sil)
        except Exception:
            import traceback
            traceback.print_exc()
            traceback.print_exc(file=sys.stdout)
            self.maindone = 0
            return 0

        #print "Local Sniffer started"
        while 1:
            if self.done:
                print "Sniffer set to halt, stopping now..."
                break

            parser.reset()
            #devlog("localsniffer", "Recving data from sniffer")
            if not self.sniffer:
                devlog("localsniffer", "No LocalSniffer (not Linux+root)")
                break 

            data=self.sniffer.recv()

            #no need to parse this data 
            if(data==0 or len(self.callbacks)==0):
                continue

            #we have someone trying to read from the raw socket
            #this parsing takes some CPU - we don't do it unless
            #we have a callback (meaning someone cares)
            try:
                ret=parser.setPacket(data)
                if not ret:
                    continue
            except Exception:
                buf = "\nFailed processing packet: %s\n"%repr(data)
                sys.stderr.write(buf)
                import traceback
                traceback.print_exc()
                traceback.print_exc(file=sys.stdout)
                
            
            if self.engine and self.engine.localnode:
                #get the host and and add it to the list if we don't already
                #know about it (which we might)
                srcmac=parser.attribs.get("frommac",None)
                dstmac=parser.attribs.get("tomac",None)
                ethtype = parser.attribs.get("ethtype", None)
                node = self.engine.localnode
                if ethtype == 'IP':
                    srchost=parser.attribs.get("ipsource",None)
                    dsthost=parser.attribs.get("ipdest",None)
                    devlog('localsniffer::IP', "srcmac:%s, srchost:%s, dstmac: %s, dsthost:%s" % \
                           (parser.macstring(srcmac), srchost, parser.macstring(dstmac), dsthost))
                    for host in [srchost]:
                        self.addIPtoKnowledge(node, host)
                elif ethtype == 'ARP':
                    parser.ARP()
                else:
                    devlog('localsniffer::NOIP', "sniffed ethernet type %s (%d bytes)" % (ethtype, len(data)))

                # we have 'IP' and 'ARP'
                # We only want to add this IP to our knowledge if it is
                # a SOURCE IP address, of course. Otherwise we will add
                # every host we scan with UDPScan or ICMPScan
                #sniffinfos = parser.attribs.get("sniffedinfos", None)
                #if sniffinfos and sniffinfos.has_key('IP'):
                #    for host in sniffinfos['IP']:
                #        self.addIPtoKnowledge(node, host)

            #print "Parser.fields: %s"%parser.fields
            #print "self.callbacks=%s"%self.callbacks
            for each in self.callbacks:
                #for each callback tuple, see if the packet matches, and 
                #if so, send it to the callback
                devlog("localsniffer", "Matching: %r"%each[0].fs)
                parser.fields = parser.fields.lower()
                if each[0].match(parser):
                    #should really call each[1](parser) in a new thread!
                    #we catch all exceptions here so our sniffer
                    #thread doesn't die!
                    devlog("localsniffer", "MATCHED on packet for %r\n"%parser.fields)
                    try:
                        #call our callback
                        each[1](parser)
                    except Exception:
                        import traceback
                        traceback.print_exc()
                else:
                    devlog("localsniffer", "NOT matched for packet: %r\n"%parser.fields)

        if parser and self.dstats:
            parser.dispstats()
        self.maindone = 0
        return 1


    # We block to wait for all threads to finish otherwise try to exit and see any running threads
    # throw an exception unexpected shutdown error
    def shutdown(self):
        # Sniffer is not running so dont do anything
        if(self.running()==0):
            return
        self.done=1
        #print "Waiting for parent to end cleanly...",
        while(self.maindone):
            time.sleep(1)
            if(self.maindone==0):
                break
        return


def callback(parser):
    print "callback"
    parser.prettyprint()
    return

if __name__=="__main__":
    import sys
    ls=localsniffer()
    ls.start() #start the thread
    if len(sys.argv)>1 and sys.argv[1]!="":
        ls.registercallback(callback,sys.argv[1])
