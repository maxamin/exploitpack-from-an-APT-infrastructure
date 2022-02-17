#! /usr/bin/env python
######################################################################################
# White Phosphorus Exploit Pack
#
# Proprietary source code - use only under the license agreement in distribution
#
# This is the exploit pack dialog controller library file.
#
######################################################################################

"""
wp_dialog.py
"""

CHANGELOG="""

"""
######################################################################################

def wp_dialog_update(gtk, wt, theexploit, targets,port):
    try:
        import gobject
    except ImportError:
        return

    ghetto = []
    
    #set we are running from GUI
    theexploit.RunFromGUI = True

    dlg = wt.get_widget("exploit_dialog")
    # set name
    dlg.set_title(theexploit.name)
    
    spin = wt.get_widget("port")
    # set value
    if spin != None:
        spin.set_value(port) 

    # set payloads
    cb = wt.get_widget("payloadType")
    if cb.get_model()!=None: 
        return
    st = gtk.ListStore(gobject.TYPE_STRING)
    for s in theexploit.PAYLOADS:
        st.append([s])
    cb.set_model(st)

    cell = gtk.CellRendererText()
    cb.pack_start(cell, True)
    cb.add_attribute(cell, 'text',0)

    cb.connect("changed", wp_combo_cb, wt)
    cb.set_active(theexploit.DEFAULT_PAYLOAD)
    
    # do we need these extras
    #if "Execute Command" not in theexploit.SHELLS:
        #hide stuff
        #lab = wt.get_widget("payloadExecCmd")
        #lab.hide()
        #lab.visible = False
        #print "%s: %s %s" % (lab.name, type(lab),lab.visible)
    
    # set targets
    vbox = wt.get_widget("vboxTargets")
    button = None
    flag=0
    if len(targets) == 0:
        button = gtk.Label("N/A")
        vbox.pack_start(button, True, True, 0)
        button.show()        
    else:
        for k,v in targets.iteritems():
            button = gtk.RadioButton(button,v[0])
            button.set_name("radiobutton%d"%(k+1))
            if flag==0:
                button.set_active(True)
                flag=1
            vbox.pack_start(button, True, True, 0)
            button.show()
            ghetto.append(button)
   
    # Monkey see, monkey patch!
    # oooo ooo ooo ooo
    # <brachiate/> 
    def monkeytiem(prefix):
        l = wt.monkey_get_widget_prefix(prefix)
        return list(l) + ghetto

    if len(ghetto):
        wt.monkey_get_widget_prefix = wt.get_widget_prefix
        wt.get_widget_prefix = monkeytiem

    return

def wp_combo_cb(widget, wt):
    sbp = wt.get_widget("payloadBindPort")
    sec = wt.get_widget("payloadExecCmd")

    activeShell = widget.get_active_text()
	
    sbp.set_sensitive(False)
    sec.set_sensitive(False)

    if activeShell == "Bind MOSDEF Shell": #bindshell
        sbp.set_sensitive(True)
    elif activeShell == "Execute Command": #exec cmd
        sec.set_sensitive(True)
