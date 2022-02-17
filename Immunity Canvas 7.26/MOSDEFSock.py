#! /usr/bin/env python
"""
MOSDEFSock.py

CANVAS License

A MOSDEF socket module.

"""

import sys
import socket
import timeoutsocket
from exploitutils import *
# a large number
NoTimeout=10000
from libs.tlslite.api import *

class MOSDEFSock:
   """
   A MOSDEF socket - used for listeners and exploits
   
   We hook a lot of socket functions here to provide services a normal socket
   couldn't, like timeouts
   """
   def __init__(self,fd,shell,proto="TCP"):
      self.fd=fd
      self.shell=shell #shellserver
      self.timeout=4 #default to huge timeout in seconds
      self.proto=proto
      self.peer = None
      self.port = None
      if self.fd==-1: #asking to allocate a new socket
         self.fd=self.shell.socket(self.proto)
         devlog("mosdefsock","New socket fd=%x"%self.fd)
      self.sslconnection=None #
   
   #def __int__(self):
   #   return self.getfd()
   
   #def __long__(self):
   #   return self.getfd()
   
   #def __float__(self):
   #   return self.getfd()
   
   def log(self,msg):
      devlog("mosdefsock", "MOSDEFSock FD=%s "%self.fd + msg)
      sys.stdout.flush()
      
   def connect(self,addr):
      #all connects can timeout
      host=addr[0]
      port=addr[1]
      self.log("Connecting to %s,%s"%(host,port))
      if self.timeout==None:
         timeout=NoTimeout
      else:
         timeout=self.timeout
      ret=self.shell.connect(self.fd,host,port,self.proto,timeout)
      if uint32(ret) == uint32(-2):
         #timed out
         raise timeoutsocket.Timeout
      if ret!=0: #I believe our connect() returns 0 on success, -1 on fail.
         raise socket.error #be nice like normal socket()...
      self.peer = host
      self.port = port
      self.log("Connect succeeded!")
      return 0 # success
   
   def connect_timeout(self,addr):
      host=addr[0]
      port=addr[1]
      self.log("Connecting to %s,%s with timeout %s"%(host,port,self.timeout))     
      try:
         self.fd=self.shell.connect_nonblock(host,port) #returns fd. connect itself will return -1, since we are non-blocking
         if self.iswritable():
            self.set_blocking(1)
            self.peer = host
            self.port = port
            return 0 #success is 0
         self.close()
         return -1 #failure
      except AttributeError:
         import traceback
         #traceback.print_exc(file=sys.stdout)
         #don't support non-blocking connect, etc.
         return self.connect((host,port))

   def iswritable(self):
      return self.shell.iswritable(self.fd,self.timeout)
      
   def getfd(self):
      return self.fd
   
   def reliable_recv(self,length):
      """reliable recv"""
      if self.fd==-1:
         return -1
      return self.shell.recv(self.fd,length)
   
   def recv(self,length,flags=0):
      """non reliable recv"""
      if self.fd==-1:
         return -1
      self.log("recv %d"%length)
      if self.timeout==None:
         timeout=NoTimeout
      else:
         timeout=self.timeout
      #self.shell.recv_lazy will raise a timeout or socket.error exception
      #if it sees one! (See Linux.py for a good example)
      #otherwise it's broken...
      ret=self.shell.recv_lazy(self.fd,timeout,length)
      if ret=="" and timeout:
         #we have a timeout
         raise timeoutsocket.Timeout
      
      return ret 
   
   def recv_lazy(self,timeout=-2,length=1000):
      #timeout is in seconds
      self.log("recv_lazy(%s,%s)"%(timeout,length))
      #this is silly, but it works
      if timeout==-2:
         timeout=self.timeout
         
      if timeout==None:
         timeout=NoTimeout
         
      if self.fd==-1:
         return -1
      ret=self.shell.recv_lazy(self.fd,timeout=timeout,length=length)
      return ret
   
   def send(self,data):
      """
      TODO: Make send use self.timeout as well 
      Right now our udpsweep does a send() but never gets an error message back
      We need to make this work on MOSDEFSock LinuxMOSDEF Nodes.
      """
      if self.fd == -1:
         devlog('mosdefsock', "send() called with fd=-1")
         return -1

      devlog('mosdefsock', "Sending %d bytes to fd %d" % (len(data), self.fd))

      try:
         ret = self.shell.send(self.fd, data)
      except:
         # e.g. Linux send() threw the 'send failed' exception
         raise socket.error

      return ret  
   
   # signed int accept()
   def accept(self):
      """
      returns a tuple at all times of ret,None
      returns -1 on failure
      """
      self.log("Running accept on %d"%self.fd)
      if sint32(self.fd)==-1:
         return -1,None
      active=1
      try:
         if self.shell.isactive(self.fd,timeout=self.timeout):
            self.log("Shell socket %d is active!"%self.fd)
            active=1
         else:
            active=0
            self.log("Accept fd is not active")
      except:
         #no isactive function - so we assume it is active
         pass
      
      if not active:
         devlog('mosdefsock', "accept() returning - socket %s not active" % self.fd)
         return -1,None

      devlog('mosdefsock', "self.shell is %s" % self.shell)
      devlog('mosdefsock', "self.shell.accept is %s" % self.shell.accept)
      ret=sint32(self.shell.accept(self.fd))
      devlog('MOSDEFSock::accept()', "self.shell.accept(fd=%d) = %d" % (self.fd, ret))
      if ret<=0:
         devlog('MOSDEFSock::accept()',"returning < 0")
         return -1,None
      
      #The socket we accept on has to be non-blocking , but we don't
      #want the socket we get to be non-blocking because if we're waiting
      #for input on it, we'll spin. (or worse, if we forget to
      #check for EWOULDBLOCK, we'll just return nothing, which will freeze
      #the whole Node. YUCK.
      self.shell.setblocking(ret,1) #make it a blocking socket now.
      ret=MOSDEFSock(ret,self.shell) #new sock object. :>   
      devlog('MOSDEFSock::accept()', "returning %s" % ret)
      return ret,None

   def ssl(self):
      """initialize ssl as a client on this socket
      returns a SSL connection object on success
      """
      #I assume this causes some sort of exception on failure
      connection=TLSConnection(self)
      connection.handshakeClientCert() #no arguments since no cert is supplied
      self.sslconnection=connection
      return connection
   
   def set_timeout(self,timeout):
      self.timeout=timeout
   
   def get_timeout(self):
      return self.timeout
   
   def settimeout(self,timeout):
      #for buggy interfaces
      self.set_timeout(timeout)
      
   def set_blocking(self,blocking):
      """sets blocking state on our socket"""
      return self.shell.setblocking(self.fd,blocking)
    
   def get_blocking(self):
      print "get_blocking not implemented yet. sorry"
      pass
   
   def close(self):
      self.log("Closing")

      if self.sslconnection:
         #close it nicely - may remove this if it causes problems
         self.sslconnection.close()
         self.sslconnection=None
         
      if self.fd!=-1:
         self.shell.close(self.fd)
      self.fd=-1
      self.peer=None
      self.port=None
      return
   
   def getpeername(self):
      return (self.peer, self.port)
   
   def getsockname(self):
      print "getsockname not done yet. sorry"
      return None
   
   def reuse(self):
      """
      set SO_REUSEADDR to 1
      """
      self.log("reuse")
      if self.fd==-1:
         print "Cannot reuse a non-initialized socket"
         return -1
      if hasattr(self.shell, 'SO_REUSEADDR'):
         SO_REUSEADDR = self.shell.SO_REUSEADDR
      elif hasattr(self.shell, 'libc'):
         SO_REUSEADDR = self.shell.libc.getdefine('SO_REUSEADDR')
      else:
         raise AssertionError, "SO_REUSEADDR not defined!"
      return self.shell.setsockopt(self.fd,SO_REUSEADDR,1)
   
   def sendall(self,data):
      self.log("Sendall")
      self.send(data)
      
   def read_until(self,match,timeout=None):
      """reads until a match is found, then returns entire data block"""
      
      self.log("read_until(%s,%s)"%(match,timeout))
      if self.fd==-1:
         return -1
      data=""
      tmp=""
      dlist=[]
      while not data.count(match):
         tmp=self.recv_lazy(timeout=timeout,length=1)
         dlist.append(tmp)
         data="".join(dlist)
         if tmp=="":
            #timed out
            break

      return data
   
   def read_eager(self):
      """
      Read any readily available data
      """
      return self.recv_lazy(timeout=0,length=1000)
      
   
   def isactive(self):
      """Are we waiting for a recv/accept/etc?"""
      if self.fd==-1:
         return -1
      return self.shell.isactive(self.fd,self.timeout)
    
   def bind(self, addr):
      """bind to a local address (input is a tuple of (localaddr,localport) )"""
      # fixed to take in fd arg as per function prototype 03/13/08
      return self.shell.bind(self.fd, addr)

   # listen added for remote listen support
   def listen(self, backlog):
      """ listen on remote socket """
      return self.shell.listen(self.fd, backlog)
   
   def __del__(self):
      """
      When we destruct, we close ourselves
      """
      if self.fd<0: 
         return
      #print "Closing fd %d on delete..."%self.fd
      self.close()
      return
   
