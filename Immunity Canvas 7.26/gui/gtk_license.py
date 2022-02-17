## Show the license in a GUI window with accept / decline buttons
import os, sys
import gtk, gtk.glade
gtk_glade_hook = gtk.glade

def get_glade_file():
    __glade_file = "license_view.glade"
    moddir = os.path.dirname(sys.modules[__name__].__file__)
    if moddir != "":
        __glade_file = os.path.join(moddir, __glade_file)
    return __glade_file

def make_window():
    
    dname       = "license_view"
    wTree2      = gtk_glade_hook.XML(get_glade_file(),dname)
    dialog      = wTree2.get_widget(dname)
    
    try:
        fd=open("LICENSE.txt","r")
        lic_text=fd.read()
        fd.close()
    except IOError, err:
        ##Error opening file
        lic_text="Error opening license file: %s."%(err)

    tBuf=gtk.TextBuffer()
    tBuf.set_text(lic_text)
    
    lic_display=wTree2.get_widget("license_text")
    lic_display.set_buffer(tBuf)
    
    dialog = wTree2.get_widget(dname)
    dialog.set_title("CANVAS License")
    
    response = dialog.run()
    
    dialog.destroy() 
    
    return response

def show():
    return make_window()