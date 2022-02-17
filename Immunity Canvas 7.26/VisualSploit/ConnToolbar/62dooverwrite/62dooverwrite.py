#! /usr/bin/env python


#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002
#http://www.immunityinc.com/CANVAS/ for more information



import sys
import gtk
sys.path.append(".")
sys.path.append("../")
sys.path.append("../../")
from toolbar import VisualToolbar


class Toolobject(VisualToolbar):
    NAME = "Remote Overwrite"
    INDEXED = "HEAPEXERCISE"
    GLADE_DIALOG = "dialog.glade2"
    filexpm = "rimoutoo.ico"
    button_label = "Remote Overwrite"
    button_tooltip = "Remotely Overwrite a Heap Chunk"
    button_private_tooltip = "Private"
    objectcomments = None
    button_signal = None
    color = "cyan"
    size = 20
    boxargs={}
    xpacket2send=None
    cfd=None
    fdlist=[]
    xpacketlist=[]
    buf=[]
    NumberofXp = 1
    sendstring = ""
    sizeentry  = "0"
    OVERWRITE  = 3
    

    def __init__(self):
        VisualToolbar.__init__(self)

    def setSize(self, size):
        self.size =size

    def setArg(self,args):
        if args.has_key('preparexpacket' ) :
            self.xpacket2send = args['preparexpacket']

        if args.has_key('preparefd'):
            self.cfd = args['preparefd']

        if args.has_key('sizeentry'):
            self.sizeentry = args['sizeentry']  

        if args.has_key('sendstring'):
            self.sendstring= args['sendstring']
        

    def Show(self):
        if self.xpacket2send == None and self.sendstring == None:
            return "Overwrite... Nothing to write"
        elif self.xpacket2send:
            return "Overwrite(%s , Buffer %s)" % ( self.sizeentry, self.xpacket2send)
        else:
            return "Overwrite(%s, '%s')" % (self.sizeentry, self.sendstring)

    def Help(self):
        return "The Overwrite object allows you to allocate a chunk\n and overwrite its boundaries with a string\ or a previously created exploit buffer."

    def setDialog(self,dialog,cpacket,badchars,fdlist,xpacket):
        self.fdlist      = fdlist
        self.xpacketlist = xpacket
        sendstring       = dialog.get_widget('sendstring')
        sendstring.set_text(self.sendstring)
        sizeentry        = dialog.get_widget('sizeentry')
        sizeentry.set_text( self.sizeentry )

        
        hboxpreparexpacket = dialog.get_widget("hbox4")    
        hboxpreparefd      = dialog.get_widget("hbox5") 

        preparexpacket = gtk.combo_box_new_text()
        hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
        preparefd = gtk.combo_box_new_text()
        hboxpreparefd.pack_start(preparefd,expand=True, padding=0)


        preparexpacket.show()
        preparefd.show()

        if len(self.xpacketlist) == 0:
            preparexpacket.append_text('No Xpackets to write yet')
        else:
            preparexpacket.append_text('Select Xpacket to write')
            
        preparexpacket.append_text('Just write string')
        for a in self.xpacketlist:
            preparexpacket.append_text(str(self.xpacketlist.index(a) + 1))

        if len(self.fdlist) == 0:
            preparefd.append_text('No FD to use yet')
        else:
            preparefd.append_text('Select FD to use')
        for a in self.fdlist:
            preparefd.append_text(str(self.fdlist.index(a) + 1))

        try:
            preparexpacket.set_active(int(self.boxargs['preparexpacket']))
        except:
            preparexpacket.set_active(0)
        try:
            preparefd.set_active(int(self.boxargs['preparefd']))
        except:
            preparefd.set_active(0)



        preparexpacket.connect('changed', self.changedp,sendstring)
        preparefd.connect('changed', self.changedf)

    def preparedialog(self,widget,xpacketlist,fdlist):
        self.fdlist=fdlist
        self.xpacketlist = xpacketlist
        sendstring=widget.get_widget('sendstring')
        sendstring.set_text(self.sendstring)
        hboxpreparexpacket = widget.get_widget("hbox4")    
        hboxpreparefd = widget.get_widget("hbox5") 
        sizeentry = widget.get_widget('sizeentry')
        sizeentry.set_text( self.sizeentry )

        preparexpacket = gtk.combo_box_new_text()
        hboxpreparexpacket.pack_start(preparexpacket,expand=True, padding=0)
        preparefd = gtk.combo_box_new_text()
        hboxpreparefd.pack_start(preparefd,expand=True, padding=0)


        preparexpacket.show()
        preparefd.show()

        if len(xpacketlist) == 0:
            preparexpacket.append_text('No Buffers to write yet')
        else:
            preparexpacket.append_text('Select Buffer to write')
        preparexpacket.append_text('Just write string')
        for a in xpacketlist:
            preparexpacket.append_text(str(xpacketlist.index(a) + 1))

        if len(fdlist) == 0:
            preparefd.append_text('No FD to use yet')
        else:
            preparefd.append_text('Select FD to use')
        for a in fdlist:
            preparefd.append_text(str(fdlist.index(a) + 1))

        preparexpacket.set_active(0)
        preparefd.set_active(0)

        preparexpacket.connect('changed', self.changedp,sendstring)
        preparefd.connect('changed', self.changedf)

    def changedp(self, combobox,sendstring):
        model = combobox.get_model()
        index = combobox.get_active()
        if index != 1:
            sendstring.set_sensitive(False)
        else:
            sendstring.set_sensitive(True)
        self.boxargs['preparexpacket']=model[index][0]
        self.setArg(self.boxargs)
        return

    def changedf(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()
        self.boxargs['preparefd']=model[index][0]
        self.setArg(self.boxargs)
        return


    def createPython(self,paddingfromrow):
        multiplier = str(paddingfromrow+1)
        padding="    " * int(multiplier)
        rbuf=r'self.log("writing buffer of length %s..." % str(len(xpacket'

        if paddingfromrow > 0:
            if self.sendstring != "":
                self.buf=[]
                self.buf.append( '# Remote Overwrite')
                self.buf.append( 'writebuf="%s"' % self.sendstring)
                #s.send( struct.pack("LL", OVERWRITE, number) + command )
                self.buf.append( 'self.log("Overwrite with string of length %d (%s allocated)")' % (len(self.sendstring), self.sizeentry) )
                #self.buf.append(padding+'FD_%s.write(writebuf)' % self.cfd)
                #in this basic edition we will manage sockets silently
                self.buf.append( 'FD_1.send( struct.pack("LL", %d, %s) + writebuf )' % (self.OVERWRITE, self.sizeentry) )
                self.buf.append('time.sleep(1)')

            else:
                self.buf=[]
                self.buf.append( '# Remote Overwrite')
                self.buf.append( "xpacket%sbuf=self.createxPacket%s()" % (self.xpacket2send, self.xpacket2send))
                self.buf.append( 'self.log("Overwrite with xpacket of length %%s (%s allocated)" %% len(xpacket%sbuf) )' % (self.sizeentry, self.xpacket2send))
                #self.buf.append(padding+'FD_%s.write(xpacket%sbuf)'% (self.cfd,self.xpacket2send))
                #in this basic edition we will manage sockets silently
                self.buf.append( 'FD_1.send( struct.pack("LL", %d, %s) + xpacket%sbuf)' % (self.OVERWRITE, self.sizeentry, self.xpacket2send) )
                self.buf.append('time.sleep(1)')

        else:
            if self.sendstring != "":
                self.buf=[]
                self.buf.append( '# Remote Overwrite')
                self.buf.append( 'writebuf="%s"' % self.sendstring)
                #s.send( struct.pack("LL", OVERWRITE, number) + command )
                self.buf.append( 'self.log("Overwrite with string of length %d (%s allocated)")' % (len(self.sendstring), self.sizeentry) )
                #self.buf.append(padding+'FD_%s.write(writebuf)' % self.cfd)
                #in this basic edition we will manage sockets silently
                self.buf.append( 'FD_1.send( struct.pack("LL", %d, %s) + writebuf )' % (self.OVERWRITE, self.sizeentry) )
                self.buf.append('time.sleep(1)')

            else:
                self.buf=[]
                self.buf.append( '# Remote Overwrite')
                self.buf.append( "xpacket%sbuf=self.createxPacket%s()" % (self.xpacket2send, self.xpacket2send))
                self.buf.append( 'self.log("Overwrite with xpacket of length %%s (%s allocated)" %% len(xpacket%sbuf) )' % (self.sizeentry, self.xpacket2send))
                #self.buf.append(padding+'FD_%s.write(xpacket%sbuf)'% (self.cfd,self.xpacket2send))
                #in this basic edition we will manage sockets silently
                self.buf.append( 'FD_1.send( struct.pack("LL", %d, %s) + xpacket%sbuf)' % (self.OVERWRITE, self.sizeentry, self.xpacket2send) )
                self.buf.append('time.sleep(1)')

        return  self.buf



    def save(self):
        savedic={}
        if self.xpacket2send == None:
            savedic['sendstring']=self.sendstring
        else:
            savedic['xpacket2send']=self.xpacket2send
        savedic['cfd']       = self.cfd
        savedic['sizeentry'] = self.sizeentry
        if self.objectcomments:
            savedic['comment'] = self.objectcomments.replace("\n","\\n")
        return savedic

    def load(self,args):
        if args.has_key('comment'):
            tmp = args['comment']
            self.objectcomments=tmp.replace("\\n","\n")
        if args.has_key('xpacket2send'):
            self.xpacket2send = args['xpacket2send']
        if args.has_key('sendstring'):
            self.sendstring= args['sendstring']

        if args.has_key('cfd'):
            self.cfd = args['cfd']
            
        if args.has_key('sizeentry'):
            self.sizeentry = args['sizeentry']
            