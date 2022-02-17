#! /usr/bin/env python
"""
MOSDEFNode.py

CANVAS License

A MOSDEF node.

"""

from CANVASNode import CANVASNode
from exploitutils import *

class MOSDEFNode(CANVASNode):
    def __init__(self):
        CANVASNode.__init__(self)
        self.nodetype="MOSDEFNode"
        self.pix=""
        self.activate_text()
        self.shell=None
    
    ###### Node Messenging
    # A MOSDEF node uses file handles/descriptors to communicate with downstream nodes
    def send(self,sock,message):
        """
        sock is any object that supports send(). Here we send a message to another node.
        """
        code="""
        reliablesend(sock, buffer);
        """
        #sock is a mosdef socket, not a fd
        #all mosdef nodes are <size>+message protocols
        try:
            fd=sock.getfd()
        except:
            #is it really an int?
            fd=int(sock)
        #print "MOSDEFNode.py node:%s send(%s,%s)"%(self.getname(),sock,len(message))        
        newmessage = self.shell.getsendcode(fd,message)
        newmessage = self.shell.order(len(newmessage))+newmessage #prepend with size
        
        # okay .. so .. the new design calls for a return check on the getsendcode()
        # so far only linux,win32,ScriptNode has it implemented .. what that means is if getsendcode()
        # returns a fail/success value .. this send should be followed by a recv
        ret = self.parentnode.send(self.shell.connection, newmessage)

        # XXX: add types as getsendcode() is ported correctly !!!

        if hasattr(self.shell, 'special_shellserver_send') == True:
            # read the retval int, assuming 4 bytes for an int ..
            check_send = self.parentnode.recv(self.shell.connection, 4)
            # XXX: in the future catch exceptions here and remove nodes if broken
        
        return ret 
    
    def recv(self,sock,length):
        """
        Recv data from another node. We always know exactly how much we want.
        Ex: A->B->C
        B wants to recv 4 bytes from C. B tells A to send a message to B
        that contains a recv() call which sends the data back to A. 
        
        Get it?
        """
        code="""
        reliablerecv(sock, buffer, length);
        reliablesend(self.fd, buffer, length);
        """
        
        try:
            fd=sock.getfd()
        except:
            #it's an int?
            fd=int(sock)
        devlog("MOSDEFNode","node:%s recv(%s,%s)"%(self.getname(),sock,length))
        newmessage=self.shell.getrecvcode(fd,length)
        #this right here is the sucky thing about it. It makes it
        #totally slow to have to send before every recv. :<
        #we can do some intelligent buffering, perhaps.
        if hasattr(self.shell,"send_buf"):
            self.shell.send_buf(newmessage)
        else:
            newmessage=self.shell.order(len(newmessage))+newmessage #prepend with size
            self.parentnode.send(self.shell.connection,newmessage)
            
        if hasattr(self.shell,"get_from_recv_code"):
            ret=self.shell.get_from_recv_code(length)
        else:
            ret=self.parentnode.recv(self.shell.connection,length)
        data=self.decode(ret)
        devlog("MOSDEFNode", "Data from bounced recv=%s"%hexprint(data))
        return data
        
            
    def isactive(self, sock, timeout):
        """
        Check to see if the node has anything waiting for us
        timeout should be 0 in most cases (or Null)
        """
        code="""
        select(sock,timeout);
        reliablesend(result);
        """
        fd=sock.getfd()
        newmessage=self.shell.getisactivecode(fd,timeout)
        self.parentnode.send(self.shell.connection,newmessage)
        data=self.parentnode.recv(self.shell.connection,4) 
        data=self.decode(data)
        return self.shell.str2int(data)
    
if __name__=="__main__":
    node=MOSDEFNode()

