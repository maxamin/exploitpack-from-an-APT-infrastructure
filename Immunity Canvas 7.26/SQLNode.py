#! /usr/bin/env python
"""
localNode.py
"""

from CANVASNode import CANVASNode
from exploitutils import *

class SQLNode(CANVASNode):
    def __init__(self):
        CANVASNode.__init__(self)
        self.nodetype     = "SQLNode"
        self.pix          = "SQLNode"
        self.capabilities = []
        self.activate_text()
        self.colour="red2"
            
    ###### Node Messenging
    # A localnode uses standard "socket" objects.
    def send(self,sock,message):
        """
        sock is any object that supports send(). Here we send a message to another node.
        
        should probably make this reliable
        """
        #sock.send(message)
        return 
    
    def recv(self,sock,length):
        """
        Recv data from another node

        reliably read off our stream without being O(N). If you just 
        do a data+=tmp, then you will run into serious problems with large
        datasets
        """
        #data=""
        #datalist=[]
        #readlength=0
        #while readlength<length:
            #tmp=sock.recv(length-readlength)
            #if tmp=="":
                #self.log("Connection broken?!?")
                #break
            #readlength+=len(tmp)
            #datalist.append(tmp)
        #data="".join(datalist)
        #return data
    
    def isactive(self, sock, timeout):
        """
        Check to see if the node has anything waiting for us
        """
    
if __name__=="__main__":
    node=SQLNode()

