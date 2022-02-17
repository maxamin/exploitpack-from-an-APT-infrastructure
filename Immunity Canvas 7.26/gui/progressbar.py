from threading import Thread
from threading import Event
import time, sys, os
import gtk, gobject, gtk.glade
gtk_glade_hook = gtk.glade

def get_glade_file():
    __glade_file = "progress.glade"
    moddir = os.path.dirname(sys.modules[__name__].__file__)
    if moddir != "":
        __glade_file = os.path.join(moddir, __glade_file)
    return __glade_file

##Need so gtk plays nice with threads
if sys.platform != 'win32':
    gtk.gdk.threads_init()

class GtkProgressBar(Thread):
    """
    Have a gtk progress bar setup and run in it's own thread
    """
    stopthread = Event()
    
    def __init__(self):
        """
        Set up the window and declare ouselves as thread
        """
        Thread.__init__(self)
        
        dname             = "loader"
        wTree             = gtk_glade_hook.XML(get_glade_file(),dname)
        self.dialog       = wTree.get_widget("loader")
        self.progress_bar = wTree.get_widget("progress_bar")
        
        ##Connect the 'destroy' event to the main_quit function
        self.dialog.connect('destroy', self.stop)
        self.dialog.set_decorated(False)
        self.dialog.set_position(gtk.WIN_POS_CENTER_ALWAYS)
        
        self.dialog.show_all()
        
        ##Initialise the mainthread gtk object which will actually visually
        ## update the gtk when it is called from the fraction generator
        self.progress_visualiser = gtk_fill_progress(self.progress_bar)
        
        self.destructor = self.stop

    def stop(self,a=None):
        
        self.progress_visualiser.kill(self.dialog)
        self.stopthread.set()
        
class gtk_fill_progress:
    """
    Object which can be called from any thread to update the progress bar
    """

    def __init__(self, gtk_progress_bar, pulse=True):
        """
        Initialise the progress bar widget that we are actually updating
        """
        self.progress_bar = gtk_progress_bar
        self.pulse = pulse
    
    def __call__(self, fraction):
        """
        When the gtk runtime has a sec let it update the progress bar
        Must operate from main thread
        """
        if not self.pulse:
            gobject.idle_add(self.progress_bar.set_fraction, fraction)
        else:
            self.progress_bar.set_pulse_step(0.01)
            gobject.idle_add(self.progress_bar.pulse)
            
            
    def kill(self, gtk_obj):
        """
        Kill a window
        """
        gobject.idle_add(gtk_obj.destroy)
            
class CliProgressBar(Thread):
    """
    Just an example ASCII update visulaliser
    """
    stopthread = Event()
    def __init__(self):
        
        Thread.__init__(self)
        
        self.progress_visualiser = self.update
        
        self.destructor = None
        
        self.set_screen()
        
    def run(self):
        
        while not self.stopthread.isSet():
            time.sleep(1)
            
        
    def set_screen(self):
        
        sys.stdout.write("\n|-")
        sys.stdout.flush()
    
    def finish_off(self):
        
        sys.stdout.write("-|\n")
        sys.stdout.flush()
        
        
    def update(self, fraction):
        
        sys.stdout.write( "=")
        sys.stdout.flush()
        
        if fraction == 1.0:
            self.finish_off()
        

class ProgGen(Thread):
    """
    Example function that periodically generates a fraction update that is
    sent to the appropriate visual progress indicator
    Runs as it's own thread
    """
    stopthread = Event()
    def __init__(self, maximum, visual_update, destructor = None):
       
        Thread.__init__(self)
        
        self.maximum = maximum
        self.destructor = destructor
        
        ##The function to call to visually represent the update to a user
        self.update_bar_visually = visual_update
    
    def run(self):
        """
        Silly loop to produce fractions
        """
        for i in xrange(self.maximum):
            
            if self.stopthread.isSet():
                break
            
            fraction = (i + 1) / float(self.maximum)
            time.sleep(0.01)
            
            self.update_bar_visually(fraction)
            
        self.stop()
        
        ##NOTE when over loading the run method YOU must decide when this
        ## is called - it will vary depending on what you are trying to do
        gtk.main_quit()
    
    def stop(self):
        ##Call GUI destructor if defined:
        if self.destructor:
            self.destructor()
            
        self.stopthread.set()

def sleeper():
    """
    Only used in win32 to stop gtk threads hanging
    """
    time.sleep(.001)
    return 1 # don't forget this otherwise the timeout will be removed

def go(bar_type, progress_generator):
    """
    bar_type is a string either 'CLI' or 'GTK'
    
    progress_generator is a class of type ProgGen mostly likely with 
    the run method overloaded
    """
    if bar_type == "GTK":
        if sys.platform == 'win32':
            ##Without this win32 does not work AT ALL
            gobject.timeout_add(40, sleeper)
        ##GTK progress bar
        pb = GtkProgressBar()
        
    else:
        ##Console progress bar
        pb = CliProgressBar()
        
        
    pg = progress_generator(100, pb.progress_visualiser, pb.destructor)
    pb.start()
    pg.start()
    
    try:       
        if bar_type == "GTK":
            gtk.main()
            ##stop the cu thread
            pg.stopthread.set()
        else:
            try:
                while not pg.stopthread.isSet():
                    ##Change to Q block
                    time.sleep(1)
                pb.stopthread.set()
            except KeyboardInterrupt:
                pb.stopthread.set()
                pg.stopthread.set()
                
            
    except KeyboardInterrupt:
        pg.stopthread.set()
        
    
    

if __name__ == "__main__":
    
    go("GTK", ProgGen)
    

    
    
    