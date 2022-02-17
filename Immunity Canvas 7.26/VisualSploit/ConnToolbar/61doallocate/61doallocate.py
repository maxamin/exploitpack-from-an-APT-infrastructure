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
    NAME = "DoAllocate"
    INDEXED = "HEAPEXERCISE"
    INDEX_ADD = True
    GLADE_DIALOG = "dialog.glade2"
    filexpm = "rimoutoa.ico"
    button_label = "Allocate Remotely"
    button_tooltip = "Allocate Remotely"
    button_private_tooltip = "Private"
    button_signal = None
    color = "green"
    size = 20
    boxargs={}
    cfd=None
    objectcomments = None
    fdlist=[]
    xpacketlist=[]
    buf=[]
    NumberofXp =1
    ALLOC = 0
    callnum = 0


    def __init__(self):
        VisualToolbar.__init__(self)

    def setSize(self, size):
        self.size =size

    def setArg(self,args):
        if args.has_key('readbuf' ) :
            self.readbuf = args['readbuf']

        if args.has_key('preparefd'):
            self.cfd = args['preparefd']
            
        #if args.has_key('preparefd'):
        #    self.cfd = args['preparefd']




    def Show(self):
        return "RemoteAllocate(%d)" % int(self.readbuf)

    def Help(self):
        return "The read object allows you to read data from a created file (see create help)."


    def setDialog(self,dialog,cpacket,badchars,fdlist,xpacketlist):
        self.fdlist=fdlist
        readbuf=dialog.get_widget('readbuf')
        readbuf.set_text(str(self.readbuf))


        hboxpreparefd = dialog.get_widget("hbox5") 
        preparefd = gtk.combo_box_new_text()
        hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
        preparefd.show()

        if len(self.fdlist) == 0:
            preparefd.append_text('No FD to use yet')
        else:
            preparefd.append_text('Select FD to use')
        for a in self.fdlist:
            preparefd.append_text(str(self.fdlist.index(a) + 1))

        try:
            preparefd.set_active(int(self.boxargs['preparefd']))
        except:
            preparefd.set_active(0)

        preparefd.connect('changed', self.changedf)

    def preparedialog(self,widget,xpacketlist,fdlist):
        self.fdlist   = fdlist
        self.callnum = len(fdlist)
        
        hboxpreparefd = widget.get_widget("hbox5") 
        preparefd     = gtk.combo_box_new_text()
        hboxpreparefd.pack_start(preparefd,expand=True, padding=0)
        #preparefd.show()
        if len(fdlist) == 0:
            preparefd.append_text('No FD to use yet')
        else:
            preparefd.append_text('Select FD to use')
        for a in fdlist:
            preparefd.append_text(str(fdlist.index(a) + 1))
        preparefd.set_active(0)
        preparefd.connect('changed', self.changedf)

    def changedf(self, combobox):
        model = combobox.get_model()
        index = combobox.get_active()

        self.boxargs['preparefd']=model[index][0]
        self.setArg(self.boxargs)
        return

    def createPython(self,paddingfromrow):
        multiplier = str(paddingfromrow+1)
        padding="    " * int(multiplier)        
        
        self.buf=[]
        self.buf.append('# Remote Allocation of size: %s'% self.readbuf)
        if paddingfromrow > 0:
            self.buf.append('read_buf = FD_1.send(struct.pack("LL", %s, %s))'% (self.ALLOC, self.readbuf))
            self.buf.append('time.sleep(1)')
            self.buf.append('var_alloc_%d = struct.unpack("L", FD_1.recv(4))[0]' % self.callnum )
            self.buf.append('self.log("doAllocate(%s) -> 0x%%08x" %% var_alloc_%d)' % (self.readbuf, self.callnum))
        else:
            #no fd in this ed.
            self.buf.append('read_buf = FD_1.send(struct.pack("LL", %s, %s))'% (self.ALLOC, self.readbuf))
            self.buf.append('time.sleep(1)')
            self.buf.append('var_alloc_%d = struct.unpack("L", FD_1.recv(4))[0]' % self.callnum )
            self.buf.append('self.log("doAllocate(%s) -> 0x%%08x" %% var_alloc_%d)' % (self.readbuf, self.callnum))


        return  self.buf


    def save(self):
        savedic={}
        savedic['readbuf']=self.readbuf
        savedic['cfd']=self.cfd
        if self.objectcomments:
            savedic['comment']=self.objectcomments.replace("\n","\\n")
        return savedic

    def load(self,args):
        if args.has_key('comment'):
            tmp = args['comment']
            self.objectcomments=tmp.replace("\\n","\n")
        if args.has_key('readbuf'):
            self.readbuf = args['readbuf']

        if args.has_key('cfd'):
            self.cfd = args['cfd']
            
            