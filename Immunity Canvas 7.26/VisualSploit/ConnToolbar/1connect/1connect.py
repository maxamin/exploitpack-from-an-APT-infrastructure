#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information


import sys
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar
from gettext import gettext as N_


class Toolobject(VisualToolbar):
    NAME = "connect"
    INDEXED = "COMMONTCP"
    INDEX_ADD = True
    
    GLADE_DIALOG = "dialog.glade2"
    filexpm = "connect.ico"
    button_label = "Add connect()"
    button_tooltip = N_("Add connect() to Program Flow")
    button_private_tooltip = "Private"
    button_signal = None
    color = "red"
    size = 20
    objectcomments = None
    fdlist=[]
    buf=[]
    NumberofXp =1


    def __init__(self):
        VisualToolbar.__init__(self)
        self.protocol="TCP"

    def setSize(self, size):
        self.size =size

    def setArg(self,args):
        """
    Get arguments from dialog box (I presume)
    (you presume well)
    """
        #print "Args in connect = %s"%str(args)
        self.connecttoh = args['connecttoh']
        self.connecttop = args['connecttop']
        try:
            self.cfd = args['fdlist']
        except:
            pass
        self.protocol = args.get("protocol",self.protocol)
        if not self.protocol:
            self.protocol="TCP"
        return 

    def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):

        connecttoh=dialog.get_widget('connecttoh')
        connecttop=dialog.get_widget('connecttop')
        connecttoh.set_text(self.connecttoh)
        connecttop.set_text(str(self.connecttop))
        proto=dialog.get_widget("protocol")
        #need to figure out what a gtk.ComboBox wants here...
        #proto.set_active_text(self.protocol)
        #self.cfd = fd


    def Show(self):
        return "%s: connect(%s:%d)" % (self.protocol, self.connecttoh,int(self.connecttop))

    def Help(self):
        return N_("The connect object allows you to connect to a remote host on a given\n\
port. It returns a socket which you can use to send and receive data on.\n\
\n\
e.g. to connect to a SMTPD on localhost:25 you would set Hostname to \n\
'localhost' and Port Number to 25.")

    def preparedialog(self,arga,argb,argc):
        pass

    def createPython(self,paddingfromrow):
        #for now, we manage sockets silently
        multiplier = str(paddingfromrow+1)
        padding="    " * int(multiplier)
        self.buf=[]
        #print "MY OBJECT PADDING %s" %padding
        if paddingfromrow > 0:
            self.buf.append(padding+"self.port=%s" % self.connecttop)
            self.buf.append(padding+"try:")
            self.buf.append(padding+padding+"self.host = self.target.interface\n")
            self.buf.append(padding+"except:")
            self.buf.append(padding+padding+"self.host=\"%s\"" %self.connecttoh)
            self.buf.append(padding+'self.port = int(self.argsDict.get("port", self.port))')
            #self.buf.append(padding+'FD_%s = self.gettcpsock()'% self.cfd)
            #getudpsock or gettcpsock, depending on self.protocol
            self.buf.append(padding+'FD_1 = self.get%ssock()'%self.protocol.lower())
            self.buf.append(padding+'self.log("'+self.protocol+': connect(%s,%s)" % ( self.host, self.port))')
            #self.buf.append(padding+"FD_%s.connect((self.host,self.port))" %self.cfd)
            self.buf.append(padding+"FD_1.connect((self.host,self.port))")
            self.buf.append(padding+'self.log("Connected!")')
        else:
            self.buf.append("self.port=%s" % self.connecttop)
            self.buf.append("try:")
            self.buf.append(padding+"self.host = self.target.interface")
            self.buf.append("except:")
            self.buf.append(padding+"self.host=\"%s\"" %self.connecttoh)
            self.buf.append('self.port = int(self.argsDict.get("port", self.port))')
            #self.buf.append('FD_%s = self.gettcpsock()'% self.cfd)
            self.buf.append('FD_1 = self.get%ssock()'%self.protocol.lower())
            self.buf.append('self.log("'+self.protocol+': connect(%s,%s)" % (self.host, self.port))')
            #self.buf.append("FD_%s.connect((self.host,self.port))" %self.cfd)
            self.buf.append("FD_1.connect((self.host,self.port))")
            self.buf.append('self.log("Connected!")')
        return  self.buf


    def save(self):
        savedic={}
        savedic['hostname']=self.connecttoh
        savedic['port']=self.connecttop
        savedic['cfd']=self.cfd
        savedic['protocol']=self.protocol
        if self.objectcomments:
            savedic['comment']=self.objectcomments.replace("\n","\\n")
        return savedic

    def load(self,args):
        if args.has_key('comment'):
            tmp = args['comment']
            self.objectcomments=tmp.replace("\\n","\n")

        if args.has_key('hostname'):
            self.connecttoh = args['hostname']

        if args.has_key('port'):
            self.connecttop = args['port']

        if args.has_key('cfd'):
            self.cfd = args['cfd']

        self.protocol=args.get('protocol', self.protocol)

    def getHost(self):
        return self.connecttoh

    def getPort(self):
        return self.connecttop



