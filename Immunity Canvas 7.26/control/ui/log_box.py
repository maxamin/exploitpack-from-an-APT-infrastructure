import os
import time
import logging

import gtk
import gtk.glade
import gobject
import pango

from canvasengine import canvas_root_directory as CANVAS_ROOT

from control.commander_loop import ReplayLoop
from control.state import Operator
from control.ui import gui_utils as utils

LOG_COLORS = {
    logging.DEBUG        : '#5b606a',   # grey
    logging.INFO         : None,
    logging.WARNING      : 'gold4',
    logging.ERROR        : 'red',
    logging.CRITICAL     : 'red',
    
    Operator.LOG_EXECUTE : '#286073',   # blue
    Operator.LOG_SUCCESS : '#319331',   # green
    Operator.LOG_FAILURE : '#B83D3D',   # red
    
    ReplayLoop.COMMANDER_LOG_NAME : '#5b606a',
    }

GLADE_FILE = os.path.join(CANVAS_ROOT, 'control', 'ui', 'log_box.glade')
MONOSPACE_FONT = pango.FontDescription('monospace 9')

class TreeStoreHandler(logging.Handler):
    """Writes logs to a gtk.TreeStore."""
    
    def __init__(self, model, gui_call, commander=None):
        logging.Handler.__init__(self)
        self.gui_call = gui_call
        self.commander = commander
        self.model = model
    
    def emit(self, record):
        com = self.commander
        model = self.model
        columns = model._columns
        
        # truncate
        line = record.message.splitlines()[0]
        if len(line) > 200:
            line = ' '.join([line[:200], '[truncated]'])
        
        sender = record.name
        if '.' in sender and com:
            # get the name of the operator, if any
            sender, name = record.name.rsplit('.', 1)
            oper = com.operators.get(name)
            if oper:
                name = oper.name
            sender = '.'.join([sender, name])
        
        message = record.message
        if record.exc_text:
            message = '\n'.join([message, record.exc_text])
        
        created = record.created
        color = LOG_COLORS[record.levelno]
        
        # set to event time if replaying
        if isinstance(com, ReplayLoop):
            if sender.startswith(ReplayLoop.OPERATOR_LOG_NAME):
                created = getattr(com, 'event_time_ref')
                color = LOG_COLORS[record.levelno]
            else:
                color = LOG_COLORS[ReplayLoop.COMMANDER_LOG_NAME]
        
        data = {
            'sender': sender,
            'message': line,
            '_message': message,
            'created': time.ctime(created),
            '_created': record.created,
            '_color': color,
            }
        
        self.gui_call(utils.append_model_data, model, columns, None, **data)

class LogBox(object):
    def __init__(self, loggers, gui_call, commander=None):
        self.loggers = loggers
        self.gui_call = gui_call
        self.commander = commander
        
        self.init_gui()
    
    ## initialization ##

    def init_gui(self):
        wt = gtk.glade.XML(GLADE_FILE)
        self.ui = utils.UI(wt.get_widget)
        
        # log view
        columns = [('sender', str), ('message', str), ('_message', str),
            ('created', str), ('_created', str), ('_color', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.model = root_model = gtk.TreeStore(*col_types)
        filter_model = root_model.filter_new()
        self.ui.log_model = model = gtk.TreeModelSort(filter_model)
        model.append = root_model.append
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        model.set_sort_column_id(columns['_created'], gtk.SORT_ASCENDING)
        
        view = self.ui.log_view
        view.set_model(model)
        view.modify_font(MONOSPACE_FONT)
        view.get_selection().set_mode(gtk.SELECTION_MULTIPLE)
        
        # columns
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Sender', render, text=columns['sender'],
            foreground=columns['_color'])
        column.set_resizable(True)
        column.set_sort_column_id(columns['sender'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Message', render, text=columns['message'],
            foreground=columns['_color'])
        column.set_resizable(True)
        column.set_expand(True)
        column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        column.set_sort_column_id(columns['message'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Created', render, text=columns['created'],
            foreground=columns['_color'])
        column.set_resizable(True)
        column.set_sort_column_id(columns['_created'])
        view.append_column(column)
        
        # autoscroll
        button = self.ui.log_autoscroll_button
        
        def toggled(button, view):
            if button.get_active():
                utils.scroll_treeview_to_bottom(view)
        button.connect('toggled', toggled, view)
        
        def scroll_to_bottom(model, path, it, view, button):
            if button.get_active():
                view.set_cursor(path)
        model.connect('row-inserted', scroll_to_bottom, view, button)
        
        # filter
        filter_model._filters = filters = {'sender': [], 'message': []}
        def visible(model, it, data):
            columns, filters = data
            def match_column(column, query):
                if not query:
                    return True
                value = model.get_value(it, columns[column])
                if not value:
                    return False
                if self._apply_log_filter(value, query):
                    return True
            return all([match_column(c, q) for c, q in filters.iteritems()])
        filter_model.set_visible_func(visible, (columns, filters))
        
        sender_entry = self.ui.log_filter_sender_entry
        message_entry = self.ui.log_filter_message_entry
        def changed(entry, column, filters, filter_model):
            filters[column] = self._parse_log_filter(entry.get_text())
            filter_model.refilter()
        sender_entry.connect('changed', changed, 'sender', filters, filter_model)
        message_entry.connect('changed', changed, 'message', filters, filter_model)
        
        button = self.ui.log_filter_button
        box = self.ui.log_filter_box
        def toggled(button, box, entry):
            active = button.get_active()
            box.set_property("visible", active)
            if active:
                gobject.idle_add(entry.grab_focus)
        button.connect('toggled', toggled, box, sender_entry)
        
        button = self.ui.log_filter_clear_button
        def clear(button, entries):
            for entry in entries:
                entry.set_text('')
        button.connect('clicked', clear, [sender_entry, message_entry])
        
        # mouse actions
        
        def button_press(view, event):
            if event.button == 1 and event.type == gtk.gdk._2BUTTON_PRESS:
                # double-click
                # popup a dialog with full log message
                columns = self.ui.log_model._columns
                dialog = self.ui.log_details_dialog
                buf = self.ui.log_details_view.get_buffer()
                
                row = utils.get_selected_rows(view)[0]
                
                self.ui.log_details_sender_label.set_text(row[columns['sender']])
                self.ui.log_details_time_label.set_text(row[columns['created']])
                
                buf.set_text(row[columns['_message']])
                
                dialog.show()
            elif event.button == 3:
                # popup menu
                menu = self.ui.log_menu
                menu.show_all()
                menu.popup(None, None, None, event.button, event.time)
                # allow right-click to select if 1 or less rows are selected
                return len(utils.get_selected_rows(view)) > 1
        view.connect('button-press-event', button_press)
        
        button = self.ui.log_details_ok_button
        button.connect('clicked', lambda x: self.ui.log_details_dialog.hide())
        self.ui.log_details_view.modify_font(MONOSPACE_FONT)
        
        def copy_messages(item, view, columns):
            clipboard = gtk.clipboard_get()
            buf = []
            for row in utils.get_selected_rows(view):
                buf.append(row[columns['_message']])
            clipboard.set_text('\n'.join(buf))
        self.ui.log_copy_messages_menuitem.connect('activate', copy_messages, view, columns)
        
        def copy_logs(item, view, columns):
            import io, csv
            
            buf = io.BytesIO()
            writer = csv.writer(buf)
            
            copy_columns = ['sender', '_message', 'created']
            for row in utils.get_selected_rows(view):
                writer.writerow([row[columns[c]] for c in copy_columns])
            
            clipboard = gtk.clipboard_get()
            clipboard.set_text(buf.getvalue())
        self.ui.log_copy_logs_menuitem.connect('activate', copy_logs, view, columns)
        
        # add logging handler
        for logger in self.loggers:
            handler = TreeStoreHandler(model, self.gui_call, self.commander)
            handler.setLevel(logging.INFO)
            logger.addHandler(handler)
    
    def create_tab(self, name, tab_style=None):
        tab = gtk.HBox()
        tab.set_spacing(4)
        
        if tab_style == 'CANVAS':
            name = '<b>%s</b>' % name
        else:
            image = gtk.Image()
            image.set_from_stock(gtk.STOCK_INDEX, gtk.ICON_SIZE_MENU)
            
            tab.pack_start(image, expand=False)
            tab.image = image
        
        label = gtk.Label()
        label.set_markup(name)
        tab.pack_start(label, expand=True)
        tab.label = label
        
        tab.show_all()
        return tab
    
    def clear(self):
        self.ui.model.clear()
    
    def _parse_log_filter(self, text):
        if not text.strip():
            return []
        return [[c.strip() for c in t.split('OR')] for t in text.split('AND')]
    
    def _apply_log_filter(self, text, query):
        return all([any([(_or in text) for _or in _and]) for _and in query])
