#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

import sys
sys.path += ['.']

import xml.sax, xml.sax.handler
import pango
from internal import * #devlog
from engine import CanvasConfig

# needed for insert_text_with_markup
from cStringIO import StringIO

class markup_handler(xml.sax.handler.ContentHandler):
    """
    CANVAS uses a simple markup language of <b> 
    """
    def __init__(self,textbuf):
        xml.sax.handler.ContentHandler.__init__(self)        
        self.tags=[]
        self.text=""
        self.textbuf=textbuf
        return
    
    def flush(self):
        #finally, insert text into the textview at the beginning!
        tags=self.tags
        iter=self.textbuf.get_end_iter()
        #print "Tags=%s"%tags
        if tags:
            #print "Inserting with tags"
            self.textbuf.insert_with_tags(iter,self.text,*tags)        
        else:
            #always is a tag...
            #print "Insert without tags"
            self.textbuf.remove_all_tags(iter,iter)
            #self.textbuf.insert_with_tags(iter,self.text,None)        
            self.textbuf.insert(iter,self.text)
        self.text=""
        return
    
    def characters(self, content):
        self.text+=content
        #print "Text=%s"%self.text
        self.flush()
        return
    
    def startElement(self, name, attrs):
        """
        This gets each attribute (i.e. <b> will generate a b as name
        """
        tag=self.textbuf.create_tag()
        name=name.lower()
        if name=="b":
            #print "Bold Text Start"
            tag.set_property('weight', pango.WEIGHT_BOLD)
        if name=="h":
            #header
            tag.set_property('scale',pango.SCALE_XX_LARGE * float(CanvasConfig['xml_header_scale', 1]))
            tag.set_property('weight', pango.WEIGHT_BOLD)
        if name=="br":
            self.text+="\n"
            return
        self.tags.append(tag)
        #print "name=%s attrs=%s"%(name,attrs)
        
    def endElement(self, name):
        #print "Tags=%s"%self.tags
        if self.tags:
            self.tags.pop() 
        if name=="h":
            #end header
            self.text+="\n"
        self.flush()
        
def insert_text_with_markup(textbuffer,text):
    """
    Insert some text with a psuedo-HTML markup into a textview using pango, tags, and other complex stuff
    """
    
    #print "Parsed: %s"%text
    #parser = xml.sax.make_parser(['drv_libxml2'])
    parser = xml.sax.make_parser()
    # parser.setFeature(xml.sax.handler.feature_validation, True)
    parser.setContentHandler(markup_handler(textbuffer))
    try:
        parser.parse(StringIO(text))
    except xml.sax.SAXParseException:
        devlog('insert_text_with_markup', "ERROR: Couldn't use SAX to parse: %s" % text)


    return 


def on_button_clicked(button,buffer):
    insert_text_with_markup(buffer, "<start> Start <h>NOTES</h> <b> hi </b> Bye <b> whatever </b> </start>")
        
if __name__=="__main__":
    import gtk, gtk.gdk
    print "Text view with markup"
    sw = gtk.ScrolledWindow()
    sw.set_policy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
    textview = gtk.TextView()
    textbuffer = textview.get_buffer()
    sw.add(textview)
    win = gtk.Window()
    win.resize(300,500)
    win.connect('delete-event', gtk.main_quit)
    button = gtk.Button(u"Press me!")
    #command = 'dir -R %s' % os.getcwd()
    button.connect("clicked", on_button_clicked, textbuffer)
    vbox = gtk.VBox()
    vbox.pack_start(button, False)
    vbox.pack_start(sw)
    win.add(vbox)
    win.show_all()

    gtk.main()    
