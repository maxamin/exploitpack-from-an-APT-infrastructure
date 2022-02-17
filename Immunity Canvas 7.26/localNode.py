#! /usr/bin/env python
"""
localNode.py

This is the only CANVAS Node that has thread support for now.

"""

from CANVASNode import CANVASNode
from exploitutils import *
from internal import *
from engine import CanvasConfig
import sys
from hostKnowledge import *
import os
from libs import filesystem

import errno

import logging


class localNode(CANVASNode):
    def __init__(self, engine=None):
        CANVASNode.__init__(self)

        self.engine = engine

        self.capabilities += ["threads"]
        self.nodetype="LocalNode"
        self.pix="LocalNode"
        self.init_me()
        self.hasrawsocks=None #not initialized yet
        if not platform_is_win32:
            self.capabilities+=["Unix Shell"]
        else:
            self.capabilities+=["Win32 Shell"]
        self.capabilities+=["sock"] #of course. :>
        self.capabilities+=["VFS"]
        self.capabilities+=["localnode"]
        self.colour="red"

        return

    def init_me(self, silica=False):
        self.activate_text()
        # In SILICA we need to re-init due to the up-down iface
        if(silica):
            self.interfaces=interfacesList(self)
            self.findInterfaces()
            #We forget about all our known hosts here
            self.hostsknowledge=knowledgeContainer(self)
            #except this host, obviously
            self.new_host("127.0.0.1")
            #we could probably go through the current self.connected_nodes and close them first, but shouldn't hurt not to.
            self.connected_nodes=nodesList(self)

        #self.findLocalHosts()

        ##Rich mod - disabled automatic reloading
        ##self.loadSavedHosts()
        return

    def hasRawSocks(self):
        """
        In a LocalNode we may or may not have raw socket support
        So we ask the engine if it was able to start up a sniffer
        and if it was, we return True.

        We only ask the Engine once, although this should be constant
        time anyways.
        """
        if self.hasrawsocks in [True, False]:
            return self.hasrawsocks

        if self.engine.localsniffer and self.engine.localsniffer.running():
            self.hasrawsocks=True
            return True
        else:
            self.hasrawsocks=False
            return False


    def findInterfaces(self):
        """
        Gets all the interfaces on this machine and adds them to
        our interfaces list
        """
        for ifc in getAllLocalIPs():
            devlog("localNode", "Found ip: %s"%ifc)
            #ifc is a ['vmnet1', '192.168.159.1', "255.255.255.0"] list
            self.interfaces.add_ip(ifc)
        return

    def findLocalHosts(self):
        devlog("localNode", "calling findLocalHosts")
        #import traceback
        #traceback.print_stack(file=sys.stdout)
        sys.stdout.flush()

        if self.engine==None:
            return 0

        #print "Engine=%s"%self.engine
        app=self.engine.getModuleExploit("addhost")
        app.link(self)
        argsDict={}
        argsDict["passednodes"]=[self]
        app.argsDict=argsDict

        arp_list = []
        if CanvasConfig["auto_add_hosts"]:
            arp_list = getIPfromARPTable()

        for ip in arp_list + CanvasConfig['local_static_ip_list', ""].split():
            argsDict["host"]=ip
            logging.info("Adding host %s in localNode" % ip)
            app.run()
        return 1

    ###### Node Messenging
    # A localnode uses standard "socket" objects.
    def send(self,sock,message):
        """
        sock is any object that supports send(). Here we send a message to another node.

        we'd like to use sendall for reliability - but this sometimes
        generates errors when it would block, and we're not sure
        how much data it has sent. So instead, we loop and keep
        counters and all that nonsense
        """
        devlog('localNode::send()', "\n%s" % c_array(message))
        sent=0
        while sent<len(message):
            try:
                sent+=sock.send(message[sent:])
            except socket.error, error:
                if error.errno == errno.EBADF:
                    devlog("localNode", "(send) bad file number, exiting.")
                    break
                
                if str(error).count("10035"):
                    #blocking error message...just continue
                    continue
        return

    def recv(self,sock,length):
        """
        Recv data from another node

        reliably read off our stream without being O(N). If you just
        do a data+=tmp, then you will run into serious problems with large
        datasets
        """
        devlog('localNode',"Node %s recving %d bytes" % (self.getname(), length))
        data=""
        datalist=[]
        readlength=0
        while readlength<length:
            #print "before recv...stalling?"
            try:
                #print "--- recv(%d)" % (length-readlength)
                tmp=sock.recv(length-readlength)
            except socket.error, error:
                if error.errno == errno.EBADF:
                    devlog("localNode", "(recv) bad file number, exiting.")
                    break
                
                devlog('localNode', "Socket.error recieved...nonblocking not on?: %s"% (str(error)))
                continue
            #devlog('localNode::recv', "recved %d bytes: %s" % (len(tmp), hexprint(tmp)))
            if tmp=="":
                devlog("localNode", "Connection broken? Recved no data!")
                logging.error("Connection broken?!?")
                break
            readlength+=len(tmp)
            #print "Before append, stall?"
            datalist.append(tmp)
        data="".join(datalist)
        devlog('localNode::recv', "Got %d bytes: %s" % (len(data), hexprint(data)))
        return data

    def loadSavedHosts(self):
        prefix=self.getname()+"_"
        self.hostsknowledge.restore_state(self.engine.OUTPUT_DIR, "Hosts",prefix=prefix)

        self.interfaces.restore_state(self.engine.OUTPUT_DIR,prefix=prefix, engine = self.engine)

    def isactive(self, sock, timeout):
        """
        Check to see if the node has anything waiting for us
        """

    def dir(self, directory):

        try:
            result = os.listdir(directory)
        except OSError:
            result = "Unknown directory: '%s'"%(directory)

        return result

    #VFS Routines
    def vfs_dir(self, path):
        if path[-1] != "/":
            path += "/"
        data = os.listdir(path)
        out = []
        for fname in data:
            try:
                statinfo = os.stat( path + fname )
                out.append( ( fname, statinfo.st_size, statinfo.st_mtime, {"is_dir": os.path.isdir(path +fname) }))
            except OSError:
                pass

        return data

    def vfs_stat(self, path):
        try:
            statinfo = os.stat(path)
        except OSError:
            #error such as bad link pointing to nowhere
            return None

        is_dir = os.path.isdir(path)
        return (statinfo.st_size, statinfo.st_mtime, {"is_dir": is_dir })

    def vfs_upload(self, path, dest):
        import shutil
        #print "VFS Upload: %s %s"%(path, dest)
        filename=path.split(os.sep)[-1]
        ret=shutil.copyfile(path, dest+"/"+filename)
        return ret

if __name__=="__main__":
    node=localNode()

