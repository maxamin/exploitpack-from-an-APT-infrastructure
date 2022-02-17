import sys
if '.' not in sys.path: sys.path.append('.')

import os
import cgi
import sys
import time
import logging
import itertools
import threading
import collections
import Queue as queue

import gtk
import gtk.glade
import pango
import gobject

# make sure we pull in the CANVAS version of gaphas
from engine.config import canvas_root_directory
path = os.path.join(canvas_root_directory, 'gui')
sys.path.insert(0, os.path.abspath(path))

from control.ui.log_box import LogBox
from control.ui.chat_box import ChatBox
from control.ui.node_map import NodeMap
from control.ui import gui_utils as utils
from control.commander_loop import ReplayLoop

from canvasengine import canvas_root_directory as CANVAS_ROOT

SESSIONS_PATH = os.path.join(CANVAS_ROOT, 'control', 'sessions')
GLADE_FILE = os.path.join(CANVAS_ROOT, 'control', 'ui', 'commander_window.glade')
MONOSPACE_FONT = pango.FontDescription('monospace 9')

GROUP_ALL = 'global'
GROUP_LABEL_ALL = '[All Operators]'
GROUP_LABEL_NONE = '[No Group]'

VIEW_GLOBAL = 'Global Summary'
VIEW_GROUP = 'Group Summary'
VIEW_OPER = 'Operator Details'

OPER_COLORS = {
    'active'        : None,
    'added'         : 'green',
    'disconnected'  : 'orange',
    'removed'       : 'red',
    }

NODE_IMAGES = {
    'target'    : gtk.STOCK_YES,
    'callback'  : gtk.STOCK_HOME,
    }

TAB_HIGHLIGHT = '<span foreground="#B83D3D"><b>%s</b></span>'

class CommanderWindow(object):
    # class-level replay to avoid log sharing
    replay_window = None
    
    def __init__(self, commander, title=None, gui_call=None, quit_on_exit=False, replay=False):
        self.commander    = commander
        self.gui_call     = gui_call or self._gui_call
        self.quit_on_exit = quit_on_exit        
        self._replay_mode = replay
        
        # the set of groups/operators to display in the command view
        # all operator groups and all operators within a group are included
        self._selected = collections.defaultdict(set)
        # actual selected opers/groups
        self._selection = {'opers': set(), 'groups': set()}
        
        # chat indexes
        self._next_channel_id = itertools.count(1)
        
        # reset command view in idle loop if True
        # prevents resetting too often
        self._reset_flag = False
        
        # set to True on exit
        self._exiting = False
        
        self.init_gui()
        self.ui.window.set_title(title or 'CANVAS Commander')
        
        gobject.idle_add(self.idle)
    
    def show(self):
        self.reset_command_view()
        self.ui.window.show_all()

    def destroy(self):
        self._exiting = True
        self.ui.window.destroy()
        self.commander.stop()

    def close(self, window, event=None):
        self.destroy()
        if self.quit_on_exit:
            gtk.main_quit()
    
    ## idle loop ##
    
    def idle(self):
        if self._exiting:
            return False
        try:
            with gtk.gdk.lock:
                if self._replay_mode:
                    self._refresh_replay_state()
                self.update_chat()
                self.update_operators()
                if self._reset_flag:
                    self.reset_command_view()
        except KeyboardInterrupt:
            self.close()
            return False
        
        time.sleep(0.01)
        
        return True
    
    ## initialization ##

    def init_gui(self):
        wt = gtk.glade.XML(GLADE_FILE)
        self.ui = utils.UI(wt.get_widget)

        settings = gtk.settings_get_default()
        settings.set_property('gtk-button-images', True)

        window = self.ui.window
        window.connect('delete-event', self.close)
        
        self.init_command()
        self.init_operators()
        self.init_logging()
        self.init_chat()
        self.init_map()
        self.init_replay()
        
        self.ui.add_accelerator('<Control>t', self.open_chat)
        
        def autorefresh(button):
            if self._exiting:
                return False
            with gtk.gdk.lock:
                if button.get_active():
                    self.refresh_command_view()
            return True
        button = self.ui.command_autorefresh_button
        gobject.timeout_add(1000, autorefresh, button)
        
        button = self.ui.command_refresh_button
        button.connect('clicked', lambda b: self.reset_command_view())
    
    def init_command(self):
        notebook = self.ui.command_notebook
        notebook._pages = {
            'command': 0,
            'operator': 1,
            }
        
        # command view
        
        buf = self.ui.command_view.get_buffer()
        
        buf.create_tag('group_heading',
            scale=pango.SCALE_XX_LARGE,
            weight=pango.WEIGHT_BOLD,
            foreground='blue',
            )
        buf.create_tag('operator_heading',
            scale=pango.SCALE_X_LARGE,
            weight=pango.WEIGHT_BOLD,
            )
        buf.create_tag('key_name',
            weight=pango.WEIGHT_BOLD,
            family='monospace',
            )
        buf.create_tag('code',
            family='monospace',
            )
        
        # operator view
        
        image = self.ui.operator_targets_image
        image.set_from_stock(NODE_IMAGES['target'], gtk.ICON_SIZE_MENU)
        
        image = self.ui.operator_callback_image
        image.set_from_stock(NODE_IMAGES['callback'], gtk.ICON_SIZE_MENU)
        
        self.init_node_model()
        self.init_history_model()
        self.init_knowledge_model()
        self.init_interface_model()
        self.init_listener_model()
        
    def init_node_model(self):
        columns = [('name', str), ('_name', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.node_model = model = gtk.TreeStore(*col_types)
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        view = self.ui.node_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Nodes', render, text=columns['name'])
        view.append_column(column)
        
        def cursor_changed(view):
            self._clear_node_views()
            self._refresh_node_details()
        view.connect('cursor-changed', cursor_changed)
    
    def init_history_model(self):
        columns = [('key', object), ('id', int), ('name', str),
            ('status', str), ('type', str), ('target', str), ('nodes', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.history_model = model = gtk.TreeStore(*col_types)
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        # sorting
        def sort(model, it1, it2, columns):
            name1 = model.get_value(it1, columns['key'])
            name2 = model.get_value(it2, columns['key'])
            return cmp(name1, name2)
        model.set_default_sort_func(sort, columns)
        model.set_sort_column_id(-1, gtk.SORT_ASCENDING)
        
        view = self.ui.history_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('ID', render, text=columns['id'])
        column.set_sort_column_id(-1)
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Module', render, text=columns['name'])
        column.set_sort_column_id(columns['name'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Status', render, text=columns['status'])
        column.set_sort_column_id(columns['status'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Type', render, text=columns['type'])
        column.set_sort_column_id(columns['type'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Target', render, text=columns['target'])
        column.set_sort_column_id(columns['target'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Nodes', render, text=columns['nodes'])
        column.set_sort_column_id(columns['nodes'])
        view.append_column(column)
        
        # show modules arguments
        def activated(view, path, column, model, columns):
            it = model.get_iter(path)
            session, id = model.get_value(it, columns['key'])
            name = model.get_value(it, columns['name'])
            
            key = (name, id, session)
            oper = self._selected_operators()[0]
            module = oper.modules[key]
            args = module['arguments']
            
            dialog = self.ui.module_arguments_dialog
            model = self.ui.module_arguments_model
            columns = model._columns
            
            model.clear()
            for key, value in args.iteritems():
                data = {'key': key, 'value': value}
                utils.append_model_data(model, columns, None, **data)
            
            self.ui.module_arguments_name_label.set_text(name)
            
            dialog.show()
        view.connect('row-activated', activated, model, columns)
        
        button = self.ui.module_arguments_ok_button
        button.connect('clicked', lambda x: self.ui.module_arguments_dialog.hide())
        
        # module arguments model
        columns = [('key', str), ('value', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.module_arguments_model = model = gtk.TreeStore(*col_types)
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        # sorting
        model.set_sort_column_id(0, gtk.SORT_ASCENDING)
        
        view = self.ui.module_arguments_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Arguments', render, text=columns['key'])
        column.set_sort_column_id(columns['key'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Value', render, text=columns['value'])
        column.set_sort_column_id(columns['value'])
        view.append_column(column)
        
        # show modules radio buttons
        def toggled(radio):
            self._clear_node_views()
            self.refresh_command_view()
        self.ui.history_show_all_radio.connect('toggled', toggled)
    
    def init_knowledge_model(self):
        columns = [('key', object), ('name', str), ('value', str), ('certainty', str),
            ('target', bool)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.node_knowledge_model = model = gtk.TreeStore(*col_types)
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        # sorting
        def sort(model, it1, it2, columns):
            name1 = model.get_value(it1, columns['name'])
            name2 = model.get_value(it2, columns['name'])
            return cmp(name1, name2)
        model.set_default_sort_func(sort, columns)
        model.set_sort_column_id(-1, gtk.SORT_ASCENDING)
        
        view = self.ui.node_knowledge_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Knowledge', render, text=columns['name'])
        column.set_sort_column_id(columns['name'])
        view.append_column(column)
        
        render = gtk.CellRendererPixbuf()
        render.props.stock_id = NODE_IMAGES['target']
        render.props.stock_size = gtk.ICON_SIZE_MENU
        column = gtk.TreeViewColumn(None, render, visible=columns['target'])
        icon = gtk.Image()
        icon.set_from_stock(NODE_IMAGES['target'], gtk.ICON_SIZE_MENU)
        icon.show()
        column.set_widget(icon)
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Value', render, text=columns['value'])
        column.set_resizable(True)
        column.set_expand(True)
        column.set_min_width(100)
        column.set_sizing(gtk.TREE_VIEW_COLUMN_FIXED)
        column.set_sort_column_id(columns['value'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Certainty', render, text=columns['certainty'])
        column.set_sort_column_id(columns['certainty'])
        view.append_column(column)
    
    def init_interface_model(self):
        columns = [('interface', str), ('ip', str), ('netmask', str),
            ('nat', bool), ('callback', bool)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.node_interfaces_model = model = gtk.TreeStore(*col_types)
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        model.set_sort_column_id(columns['interface'], gtk.SORT_ASCENDING)
        
        view = self.ui.node_interfaces_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Interface', render, text=columns['interface'])
        column.set_sort_column_id(columns['interface'])
        column.set_resizable(True)
        column.set_expand(True)
        view.append_column(column)
        
        render = gtk.CellRendererPixbuf()
        render.props.stock_id = NODE_IMAGES['callback']
        render.props.stock_size = gtk.ICON_SIZE_MENU
        column = gtk.TreeViewColumn(None, render, visible=columns['callback'])
        icon = gtk.Image()
        icon.set_from_stock(NODE_IMAGES['callback'], gtk.ICON_SIZE_MENU)
        icon.show()
        column.set_widget(icon)
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('IP', render, text=columns['ip'])
        column.set_sort_column_id(columns['ip'])
        column.set_resizable(True)
        view.append_column(column)
        
        render = gtk.CellRendererToggle()
        column = gtk.TreeViewColumn('NAT', render, active=columns['nat'])
        column.set_sort_column_id(columns['nat'])
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Netmask', render, text=columns['netmask'])
        column.set_sort_column_id(columns['netmask'])
        column.set_resizable(True)
        view.append_column(column)
    
    def init_listener_model(self):
        columns = [('key', object), ('type', str), ('ip', str), ('port', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.node_listeners_model = model = gtk.TreeStore(*col_types)
        model._iterators = {}
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        model.set_sort_column_id(columns['ip'], gtk.SORT_ASCENDING)
        
        view = self.ui.node_listeners_view
        view.set_model(model)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Type', render, text=columns['type'])
        column.set_sort_column_id(columns['type'])
        column.set_resizable(True)
        column.set_expand(True)
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('IP', render, text=columns['ip'])
        column.set_sort_column_id(columns['ip'])
        column.set_resizable(True)
        view.append_column(column)
        
        render = gtk.CellRendererText()
        column = gtk.TreeViewColumn('Port', render, text=columns['port'])
        column.set_sort_column_id(columns['port'])
        column.set_resizable(True)
        view.append_column(column)
    
    def init_operators(self):
        # model
        columns = [('alias', str), ('id', str), ('color', str),
            ('transient', bool), ('icon', gtk.gdk.Pixbuf), ('type', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.operator_model = model = gtk.TreeStore(*col_types)
        model._group_iterators = {}
        model._oper_iterators = collections.defaultdict(dict)
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        # sorting
        def sort(model, it1, it2, columns):
            name1 = model.get_value(it1, columns['alias'])
            name2 = model.get_value(it2, columns['alias'])
            if name1 == GROUP_LABEL_ALL:   return -1
            elif name2 == GROUP_LABEL_ALL: return 1
            return cmp(name1, name2)
        model.set_default_sort_func(sort, columns)
        model.set_sort_column_id(-1, gtk.SORT_ASCENDING)
        
        # view
        view = self.ui.operator_view
        view.set_model(model)
        
        # selections
        selection = view.get_selection()
        selection.set_mode(gtk.SELECTION_MULTIPLE)
        selection.connect('changed', lambda x: self.reset_command_view())
        
        # columns
        column = gtk.TreeViewColumn('Alias')
        view.append_column(column)
        
        render = gtk.CellRendererPixbuf()
        column.pack_start(render, expand=False)
        column.add_attribute(render, 'pixbuf', columns['icon'])
        
        render = gtk.CellRendererText()
        column.pack_start(render)
        column.add_attribute(render, 'text', columns['alias'])
        column.add_attribute(render, 'background', columns['color'])
        
        # popup menu
        def popup(view, event):
            if event.button == 3:
                # show the menu when idle, because the selection will
                # change after this call
                gobject.idle_add(self._show_operators_menu, event.button, event.time)
                # allow right-click to select if 1 or less rows are selected
                return len(utils.get_selected_rows(view)) > 1
        view.connect('button-press-event', popup)
        
        def forget(item):
            self.forget_operators([o.uuid for o in self._selected_operators()])
        item = self.ui.forget_operator_menuitem
        item.connect('activate', forget)
        
        item = self.ui.open_chat_menuitem
        item.connect('activate', self.open_chat)
        
        def filter_logs(item):
            log_box = self.ui.log_box
            names = [o.name for o in self._selected_operators()]
            log_box.ui.log_filter_sender_entry.set_text(' OR '.join(names))
            log_box.ui.log_filter_message_entry.set_text('')
        item = self.ui.filter_operator_logs_menuitem
        item.connect('activate', filter_logs)
    
    def init_logging(self):
        notebook = self.ui.log_notebook
        
        # log tab
        com = self.commander
        loggers = [com.commander_logger, com.operator_logger]
        self.ui.log_box = log_box = LogBox(loggers, self.gui_call, com)
        tab = log_box.create_tab('Log')
        
        page = log_box.ui.window
        page.tab = tab
        
        notebook._pages = {'log': page}
        notebook.append_page(page, tab)
        notebook.set_menu_label_text(page, 'Log')
        
        def switched(notebook, page_ptr, page_num):
            page = notebook.get_nth_page(page_num)
            name = notebook.get_menu_label_text(page)
            page.tab.label.set_text(name)
        notebook.connect('switch-page', switched)
    
    def init_chat(self):
        notebook = self.ui.log_notebook
        
        def switched(notebook, page_ptr, page_num):
            page = notebook.get_nth_page(page_num)
            if hasattr(page, 'chat_box'):
                view = page.chat_box.ui.message_view
                gobject.idle_add(view.grab_focus)
        notebook.connect('switch-page', switched)
        
        self._create_chat_tab('global', 'Global Chat')
    
    def init_map(self):
        self.ui.node_map = node_map = NodeMap()
        self.ui.node_map_view.add(node_map)
    
    def init_replay(self):
        replay = self._replay_mode
        
        self.ui.main_toolbar.set_property("visible", not replay)
        self.ui.replay_toolbar.set_property("visible", replay)
        
        event_fname = None
        event_writer = getattr(self.commander, 'event_writer', None)
        if event_writer:
            event_fname = os.path.abspath(event_writer._filename)
        button = self.ui.replay_open_button
        button.connect('clicked',
            lambda b: self.open_replay(self.ui.window, self.gui_call, event_fname))
        
        if not replay:
            return
        
        def clicked(button):
            com = self.commander
            state = com.event_state
            if state == com.RUNNING:
                com.call(com.pause)
            elif state == com.PAUSED:
                com.call(com.resume)
        button = self.ui.replay_play_button
        button.connect('clicked', clicked)
        
        button = self.ui.replay_step_button
        button.connect('clicked', lambda b: self.commander.call(self.commander.step))
        
        def clicked(button):
            self.ui.log_box.clear()
            self._reset_chat_boxes()
            self.commander.call(self.commander.replay)
        button = self.ui.replay_reset_button
        button.connect('clicked', clicked)
        
        def changed(scale, scroll_type, value):
            com = self.commander
            if com.event_reader.event_count > value > com.current_event_idx:
                com.call(com.step, jump_to=int(value))
            return False
        scale = self.ui.replay_progress
        scale.connect('change-value', changed)
        
        def changed(entry):
            self.commander.replay_speed = entry.get_value()
        entry = self.ui.replay_speed_entry
        entry.connect('value-changed', changed)
        
        # allow us to avoid unnecessary calculations
        self.ui.replay_delta_label._value = None
        self.ui.replay_progress_label._value = None
        
        ## gray out some schtuff ##
        
        self.ui.operators_menu.set_sensitive(False)
    
    ## commander actions ##
    
    def forget_operators(self, oper_ids=None):
        if not oper_ids:
            oper_ids = [o for o in self.commander.operators.values()
                if o.state == o.DISCONNECTED]
        self.commander.call(map, self.commander.forget, oper_ids)
    
    ## operator tree ##
    
    def update_operators(self):
        model = self.ui.operator_model
        group_iters = model._group_iterators
        oper_iters = model._oper_iterators
        
        groups = set([GROUP_ALL])
        opers = set()
        for oper in self.commander.operators.values():
            for group in oper.groups:
                groups.add(group)
            opers.add(oper)
        
        # update groups
        map(self._update_group, groups)
        
        # update operators
        map(self._update_operator, opers)
        
        # remove operators
        oper_ids = set(self.commander.operators.keys())
        dead_opers = set(oper_iters.keys()) - oper_ids
        map(self._remove_operator, dead_opers)
        
        # remove groups
        dead_groups = set(group_iters.keys()) - groups
        map(self._remove_group, dead_groups)
        
        if dead_groups or dead_opers:
            self._reset_flag = True
    
    def _update_group(self, group):
        model = self.ui.operator_model
        columns = model._columns
        iters = model._group_iterators
        
        it = iters.get(group)
        if it:
            # update (group state info?)
            pass
        else:
            icon = self.ui.window.render_icon(gtk.STOCK_DND_MULTIPLE,
                gtk.ICON_SIZE_MENU)
            data = {
                'alias': GROUP_LABEL_ALL if group == GROUP_ALL else group,
                'id': group,
                'color': OPER_COLORS['added'],
                'transient': True,
                'icon': icon,
                'type': 'all' if group == GROUP_ALL else 'group',
                }
            
            it = utils.append_model_data(model, columns, None, **data)
            iters[group] = it
            
            if group == GROUP_ALL:
                # select all operators group when it is added
                self.ui.operator_view.get_selection().select_path(model.get_path(it))
            
            def reset(model, it, columns):
                if model.iter_is_valid(it):
                    model.set_value(it, columns['transient'], False)
                    model.set_value(it, columns['color'], OPER_COLORS['active'])
            gobject.timeout_add(1000, reset, model, it, columns)
            
            self._reset_flag = True
    
    def _remove_group(self, group):
        model = self.ui.operator_model
        columns = model._columns
        iters = model._group_iterators
        
        it = iters.pop(group)
        model.remove(it)
    
    def _update_operator(self, oper):
        view = self.ui.operator_view
        model = self.ui.operator_model
        columns = model._columns
        iters = model._oper_iterators
        
        all_it = model._group_iterators[GROUP_ALL]
        group_iters = iters.get(oper.uuid)
        
        for group in oper.groups:
            it = group_iters.get(group) if group_iters else None
            
            if it and model.iter_is_valid(it):
                # update
                parent_it = model.iter_parent(it)
                parent_group = model.get_value(parent_it, columns['id'])
                
                if parent_group not in oper.groups:
                    model.remove(it)
                    self._update_operator(oper)
                    self._reset_flag = True
                    return
                
                color = {
                    oper.ACTIVE: OPER_COLORS['active'],
                    oper.DISCONNECTED: OPER_COLORS['disconnected'],
                    }
                
                model.set_value(it, columns['alias'], oper.name)
                
                transient = model.get_value(it, columns['transient'])
                if not transient:
                    model.set_value(it, columns['color'], color[oper.state])
            else:
                # add
                icon = self.ui.window.render_icon(gtk.STOCK_ORIENTATION_PORTRAIT,
                    gtk.ICON_SIZE_MENU)
                data = {
                    'alias': oper.name,
                    'id': oper.uuid,
                    'color': OPER_COLORS['added'],
                    'transient': True,
                    'icon': icon,
                    'type': 'operator',
                    }
                
                group_it = model._group_iterators[group]
                it = utils.append_model_data(model, columns, group_it, **data)
                iters[oper.uuid][group] = it
                view.expand_row(model.get_path(group_it), True)
                
                def reset(model, it, column):
                    if model.iter_is_valid(it):
                        model.set_value(it, column, False)
                gobject.timeout_add(1000, reset, model, it, columns['transient'])
                
                self._reset_flag = True
    
    def _remove_operator(self, oper_id):
        model = self.ui.operator_model
        columns = model._columns
        iters = model._oper_iterators
        
        group_iters = iters.pop(oper_id)
        for it in group_iters.values():
            if model.iter_is_valid(it):
                model.remove(it)
    
    def _show_operators_menu(self, button, time):
        item = self.ui.forget_operator_menuitem
        selected = self._selected_operators()
        forgettable = all([o.state == o.DISCONNECTED for o in selected])
        item.set_sensitive(bool(selected) and forgettable)
        
        menu = self.ui.operators_menu
        menu.show_all()
        menu.popup(None, None, None, button, time)
    
    ## command view ##
    
    def reset_command_view(self):
        """
        Sets the current set of operators that should be displayed in the
        command view.
        """
        notebook = self.ui.command_notebook
        view = self.ui.operator_view
        columns = self.ui.operator_model._columns
        
        # clear views
        model = self.ui.node_model
        model._iterators.clear()
        model.clear()
        
        self._clear_node_views()
        
        # get the selection
        self._selection['opers'] = oper_ids = set()
        self._selection['groups'] = group_ids = set()
        for row in utils.get_selected_rows(view):
            row_type = row[columns['type']]
            if row_type == 'all':
                break
            elif row_type == 'group':
                group_ids.add(row[columns['id']])
            elif row_type == 'operator':
                oper_ids.add(row[columns['id']])
            else:
                assert False, 'invalid row_type: %s' % row_type
        
        # determine the selected groups/operators
        command_opers = self.commander.operators.copy()
        selected = self._selected
        selected.clear()
        
        title = None
        if not (oper_ids or group_ids):
            # show global summary
            for oper in command_opers.itervalues():
                groups = oper.groups - set([GROUP_ALL])
                if not groups:
                    selected[None].add(oper)
                for group in groups:
                    selected[group].add(oper)
            title = VIEW_GLOBAL
            notebook.set_current_page(notebook._pages['command'])
        else:
            if oper_ids:
                for oper_id in oper_ids:
                    oper = command_opers.get(oper_id)
                    if oper:
                        groups = oper.groups - set([GROUP_ALL])
                        if not groups:
                            selected[None].add(oper)
                        for group in groups:
                            selected[group].add(oper)
                if len(oper_ids) == 1:
                    title = VIEW_OPER
                    notebook.set_current_page(notebook._pages['operator'])
                    
                    # set the current operator of the node map
                    self.ui.node_map.operator = oper
                
                else:
                    notebook.set_current_page(notebook._pages['command'])
            
            if group_ids:
                for oper in command_opers.itervalues():
                    for group in (oper.groups & group_ids):
                        selected[group].add(oper)
                notebook.set_current_page(notebook._pages['command'])
        
        if not title:
            title = VIEW_GROUP
        title = cgi.escape(title)
        self.ui.command_title_label.set_markup('<b>%s</b>' % title)
        
        # refresh the data
        self.refresh_command_view()
        
        self._reset_flag = False
    
    def refresh_command_view(self):
        """
        Refreshes the data for the currently selected operators.
        
        This is called periodically by the GUI.
        """
        notebook = self.ui.command_notebook
        if notebook.get_current_page() == notebook._pages['command']:
            self._refresh_command_view()
        else:
            self._refresh_operator_view()
    
    def _refresh_command_view(self):
        command_opers = self.commander.operators.copy()
        view = self.ui.command_view
        buf = view.get_buffer()
        end_iter = buf.get_end_iter
        
        buf.set_text('')
        
        sort_key = lambda x: x[0] if x[0] else 'z'
        for group, opers in sorted(self._selected.items(), key=sort_key):
            if group == GROUP_ALL:
                continue
            
            group = group or GROUP_LABEL_NONE
            buf.insert_with_tags_by_name(end_iter(), group, 'group_heading')
            buf.insert(end_iter(), '\n\n')
            
            for oper in sorted(opers):
                buf.insert_with_tags_by_name(end_iter(), oper.name, 'operator_heading')
                buf.insert(end_iter(), '\n')
                
                buf.insert_with_tags_by_name(end_iter(), '  UUID', 'key_name')
                buf.insert(end_iter(), ':\t\t%s\n' % oper.uuid)
                
                buf.insert_with_tags_by_name(end_iter(), '  State', 'key_name')
                buf.insert(end_iter(), ':\t%s\n' % oper.state)
                
                buf.insert_with_tags_by_name(end_iter(), '  Last seen', 'key_name')
                buf.insert(end_iter(), ':\t%s\n' % time.ctime(oper.last_seen))
                
                targets = self._format_targets(oper)
                buf.insert_with_tags_by_name(end_iter(), '  Targets', 'key_name')
                buf.insert_with_tags_by_name(end_iter(), ':\t%s\n' % targets, 'code')
                
                callback = self._format_callback(oper)
                buf.insert_with_tags_by_name(end_iter(), '  Callback', 'key_name')
                buf.insert_with_tags_by_name(end_iter(), ':\t%s\n' % callback, 'code')
                
                buf.insert(end_iter(), '\n\n')
    
    def _refresh_operator_view(self):
        # selected operator
        oper = self._selected_operators()[0]
        
        name = cgi.escape(oper.name)
        self.ui.operator_name_label.set_markup('<b>%s</b>' % name)
        self.ui.operator_uuid_label.set_text(oper.uuid)
        groups = oper.groups or [GROUP_LABEL_NONE]
        self.ui.operator_group_label.set_text(', '.join(sorted(groups)))
        self.ui.operator_state_label.set_text(oper.state)
        self.ui.operator_last_seen_label.set_text(time.ctime(oper.last_seen))
        
        self.ui.operator_targets_label.set_text(self._format_targets(oper))
        self.ui.operator_callback_label.set_text(self._format_callback(oper))
        
        # update nodes
        self._update_node(None, oper.node_tree)
        
        # select the root if nothing else is selected
        view = self.ui.node_view
        model = self.ui.node_model
        selection = view.get_selection()
        if not selection.get_selected()[1]:
            selection.select_iter(model.get_iter_root())
        
        self._refresh_node_details()
        self.ui.node_map.refresh()
    
    def _update_node(self, parent_it, node):
        view = self.ui.node_view
        model = self.ui.node_model
        columns = model._columns
        iters = model._iterators
        
        name = node['name']
        it = iters.get(name)
        if it:
            # update
            # remove children if necessary
            clear = False
            child_names = [c['name'] for c in node['children']]
            for child_it in list(utils.model_iter_children(model, it)):
                child_name = model.get_value(child_it, columns['_name'])
                if child_name not in child_names:
                    model.remove(child_it)
                    del iters[child_name]
                    clear = True
            if clear:
                self._clear_node_views()
        else:
            data = {
                'name': '%s (%s)' % (name, node['type']),
                '_name': name,
                }
            it = utils.append_model_data(model, columns, parent_it, **data)
            model._iterators[name] = it
            view.expand_to_path(model.get_path(it))
        
        # children
        for child in node['children']:
            self._update_node(it, child)
    
    def _refresh_history(self, node):
        model = self.ui.history_model
        columns = model._columns
        iters = model._iterators
        
        oper = self._selected_operators()[0]
        only_node = self.ui.history_show_selected_radio.get_active()
        
        for module in oper.modules.values():
            if only_node:
                node_names = [n['name'] for n in module['nodes']]
                if node['name'] not in node_names:
                    continue
            
            key = (module['session'], module['id'])
            it = iters.get(key)
            
            if it:
                data = {
                    'status': module['status'],
                    }
                utils.update_model_data(model, it, columns, **data)
            
            else:
                data = {
                    'key': key,
                    'id': module['id'],
                    'name': module['name'],
                    'status': module['status'],
                    'type': module['type'],
                    'target': module['target'],
                    'nodes': ', '.join(['%s (%s)' % (n['name'], n['type'])
                        for n in module['nodes']]),
                    }
                
                it = utils.append_model_data(model, columns, None, **data)
                iters[key] = it
    
    def _refresh_node_details(self):
        row = utils.get_selected_row(self.ui.node_view)
        if not row:
            self._clear_node_views()
            return
        
        # selected operator
        oper = self._selected_operators()[0]
        
        # get node
        node_name = row[self.ui.node_model._columns['_name']]
        node = self.commander._find_node(oper.node_tree, node_name)
        if not node:
            self._clear_node_views()
            return
        
        self._refresh_history(node)
        self._refresh_node_knowledge(node)
        self._refresh_node_interfaces(node)
        self._refresh_node_listeners(node)
        self._refresh_node_capabilities(node)
    
    def _refresh_node_knowledge(self, node):
        model = self.ui.node_knowledge_model
        columns = model._columns
        iters = model._iterators
        
        hosts = node['known_hosts']
        
        # remove hosts if necessary
        host_names = [h['host'] for h in hosts]
        for child_it in list(utils.model_iter_children(model, None)):
            host_name = model.get_value(child_it, columns['key'])
            if host_name not in host_names:
                model.remove(child_it)
                del iters[host_name]
        
        for host in hosts:
            host_name = host['host']
            it = iters.get(host_name)
            if it:
                # remove knowledge if necessary
                child_keys = set([(host_name, k['tag'], k['text'])
                    for k in host['knowledge']])
                for child_it in list(utils.model_iter_children(model, it)):
                    child_key = model.get_value(child_it, columns['key'])
                    if child_key not in child_keys:
                        model.remove(child_it)
                        del iters[child_key]
                
                # update
                data = {
                    'target': host['target'],
                    }
                utils.update_model_data(model, it, columns, **data)
            else:
                data = {
                    'key': host_name,
                    'name': host_name,
                    'value': '',
                    'certainty': '',
                    'target': host['target'],
                    }
                
                it = utils.append_model_data(model, columns, None, **data)
                iters[host_name] = it
            
            for k in host['knowledge']:
                self._refresh_host_knowledge(it, host_name, k)
    
    def _refresh_host_knowledge(self, host_it, host_name, knowledge):
        model = self.ui.node_knowledge_model
        columns = model._columns
        iters = model._iterators
        
        key = (host_name, knowledge['tag'], knowledge['text'])
        it = iters.get(key)
        if it:
            # update
            pass
        else:
            data = {
                'key': key,
                'name': knowledge['tag'],
                'value': knowledge['text'],
                'certainty': '%s%%' % knowledge['percent'],
                'target': False,
                }
            
            it = utils.append_model_data(model, columns, host_it, **data)
            iters[key] = it
            
            self.ui.node_knowledge_view.expand_to_path(model.get_path(it))
    
    def _refresh_node_interfaces(self, node):
        model = self.ui.node_interfaces_model
        columns = model._columns
        iters = model._iterators
        
        for interface in node['interfaces']:
            name = interface['interface']
            it = iters.get(name)
            if it:
                # update
                data = {
                    'callback': interface['callback'],
                    }
                utils.update_model_data(model, it, columns, **data)
            else:
                data = {
                    'interface': name,
                    'ip': interface['ip'],
                    'netmask': interface['netmask'],
                    'nat': interface['NAT'],
                    'callback': interface['callback'],
                    }
                
                it = utils.append_model_data(model, columns, None, **data)
                iters[name] = it
    
    def _refresh_node_listeners(self, node):
        model = self.ui.node_listeners_model
        columns = model._columns
        iters = model._iterators
        
        # {(interface['ip'], listener['port']): listener}
        listeners = dict([((i['ip'], l['port']), l)
            for i in node['interfaces']
            for l in i['listeners']])
        
        # remove
        child_keys = set(listeners.keys())
        for child_it in list(utils.model_iter_all(model)):
            child_key = model.get_value(child_it, columns['key'])
            if child_key not in child_keys:
                model.remove(child_it)
                del iters[child_key]
        
        # add/update
        for key, listener in listeners.iteritems():
            it = iters.get(key)
            if it:
                # update
                pass
            else:
                data = {
                    'key': key,
                    'type': listener['type'],
                    'ip': key[0],
                    'port': listener['port'],
                    }
                
                it = utils.append_model_data(model, columns, None, **data)
                iters[key] = it
    
    def _refresh_node_capabilities(self, node):
        key = lambda c: c.lower()
        cap = '\n'.join(sorted(node['capabilities'], key=key))
        
        view = self.ui.node_capabilities_view
        buf = view.get_buffer()
        if utils.get_textview_text(view) != cap:
            buf.set_text(cap)
    
    def _clear_node_views(self):
        model = self.ui.history_model
        model.clear()
        model._iterators.clear()
        
        model = self.ui.node_knowledge_model
        model.clear()
        model._iterators.clear()
        
        model = self.ui.node_interfaces_model
        model.clear()
        model._iterators.clear()
        
        model = self.ui.node_listeners_model
        model.clear()
        model._iterators.clear()
    
    ## chat ##
    
    def update_chat(self):
        try:
            source, dest, message, meta = self.commander.chat_queue.get_nowait()
        except queue.Empty:
            return
        
        # open a new channel for the operator if they tell directly
        # to the commander
        name = dest
        type = 'oper'
        create = False
        if dest == self.commander.COMMANDER_ALIAS:
            dest = source
            name = meta.get('alias', dest)
            create = True
        elif self._replay_mode:
            type = 'group'
            create = True
        
        chat_box = self._get_chat_box(dest)
        if not chat_box and create:
            chat_box = self._create_chat_tab(dest, name, type='oper',
                closeable=True)
        
        if chat_box:
            chat_box.append_message(source, dest, message, meta)
            self._highlight_tab(dest)
    
    def open_chat(self, item=None):
        notebook = self.ui.log_notebook
        
        channel = None
        if self.ui.command_title_label.get_text() == VIEW_GLOBAL:
            channel = 'global'
        else:
            for oper_id in self._selection['opers']:
                channel = oper_id
                if channel not in notebook._pages:
                    oper = self.commander.operators.get(oper_id)
                    if oper:
                        self._create_chat_tab(channel, oper.name, type='oper',
                            closeable=True)
            
            for group_id in self._selection['groups']:
                channel = group_id
                if channel not in notebook._pages:
                    self._create_chat_tab(channel, type='group', closeable=True)
        
        self._set_current_chat_page(channel)
    
    def _create_chat_tab(self, channel, name=None, type=None, closeable=False):
        notebook = self.ui.log_notebook
        
        name = cgi.escape(name or channel)
        closeable = closeable and not self._replay_mode
        
        chat_box = ChatBox(self.commander, channel=channel, is_commander=True,
            replay_mode=self._replay_mode)
        tab = chat_box.create_tab(name, closeable, tab_style=type)
        
        page = chat_box.ui.window
        # set some convenience attrs
        page.chat_box = chat_box
        page.tab = tab
        
        notebook.append_page(page, tab)
        notebook.set_menu_label_text(page, name)
        
        if closeable:
            def close_tab(button, notebook, channel):
                page = notebook._pages.pop(channel, None)
                if page:
                    notebook.remove_page(notebook.page_num(page))
            tab.button.connect('clicked', close_tab, notebook, channel)
        
        notebook._pages[channel] = page
        
        return chat_box
    
    def _reset_chat_boxes(self):
        notebook = self.ui.log_notebook
        for key, page in notebook._pages.iteritems():
            if key != 'log':
                notebook.remove_page(notebook.page_num(page))
        notebook._pages.clear()
        
        self._create_chat_tab('global', 'Global Chat')
    
    ## replay ##
    
    @classmethod
    def open_replay(cls, parent, gui_call=None, current_event_file=None):
        if cls.replay_window:
            cls.replay_window.ui.window.present()
            return
        
        dialog = gtk.FileChooserDialog('Open Event File...',
            parent, gtk.FILE_CHOOSER_ACTION_OPEN,
            (gtk.STOCK_CANCEL, gtk.RESPONSE_CANCEL, gtk.STOCK_OPEN, gtk.RESPONSE_OK))
        dialog.set_current_folder(SESSIONS_PATH)
        
        if current_event_file:
            filt = gtk.FileFilter()
            filt.add_custom(gtk.FILE_FILTER_FILENAME,
                (lambda i, d: i[0] != current_event_file), None)
            dialog.add_filter(filt)
        
        try:
            # Keep file chooser dialog open until user successfully opens a file
            while True:
                if dialog.run() == gtk.RESPONSE_OK:
                    filename = dialog.get_filename()
                    try:
                        loop = ReplayLoop(filename)
                    except Exception as e:
                        msg = '%r could not be opened:\n  %s' % (filename, e)
                        utils.show_error(msg, dialog)
                    else:
                        win = CommanderWindow(loop, 'CANVAS Replay', gui_call=gui_call, replay=True)
                        # set class attr
                        cls.replay_window = win
                        def on_hide(window):
                            cls.replay_window = None
                        win.ui.window.connect('hide', on_hide)
                        
                        win.show()
                        
                        x, y = parent.get_position()
                        win.ui.window.move(x + 50, y + 50)
                        win.ui.window.present()
                        
                        threading.Thread(target=loop.run, name='replay_loop').start()
                        break
                else:
                    return
        finally:
            dialog.destroy()
    
    def _refresh_replay_state(self):
        replay = self._replay_mode
        
        if not replay:
            return
        
        com = self.commander
        state = com.event_state
        size = gtk.ICON_SIZE_MENU
        
        if state == com.RUNNING:
            self.ui.replay_play_image.set_from_stock(gtk.STOCK_MEDIA_PAUSE, size)
            self.ui.replay_play_label.set_text('Pause')
            self.ui.replay_play_button.set_sensitive(True)
            self.ui.replay_step_button.set_sensitive(False)
            self.ui.replay_reset_button.set_sensitive(False)
        elif state == com.PAUSING:
            self.ui.replay_play_image.set_from_stock(gtk.STOCK_MEDIA_PAUSE, size)
            self.ui.replay_play_label.set_text('Pause')
            self.ui.replay_play_button.set_sensitive(False)
            self.ui.replay_step_button.set_sensitive(False)
            self.ui.replay_reset_button.set_sensitive(False)
        elif state == com.PAUSED:
            self.ui.replay_play_image.set_from_stock(gtk.STOCK_MEDIA_PLAY, size)
            self.ui.replay_play_label.set_text('Play')
            self.ui.replay_play_button.set_sensitive(True)
            self.ui.replay_step_button.set_sensitive(True)
            self.ui.replay_reset_button.set_sensitive(True)
        
        if com.current_event_idx == com.event_reader.event_count:
            self.ui.replay_play_button.set_sensitive(False)
            self.ui.replay_step_button.set_sensitive(False)
        
        progress = self.ui.replay_progress
        if com.event_reader.event_count > 0:
            progress.set_range(0, com.event_reader.event_count)
        if progress.get_value() != com.current_event_idx:
            progress.set_value(com.current_event_idx)
        
        # time delta
        delta = com.event_delta
        label = self.ui.replay_delta_label
        if label._value != delta:
            label._value = delta
            m = '%03d' % int((delta - int(delta)) * 1000)
            dt = time.strftime('[%H:%M:%S.%%s]', time.gmtime(delta)) % m
            label.set_text(dt)
        
        # current time
        current = com.event_time_ref or com.event_reader.start_time or 0
        label = self.ui.replay_progress_label
        if label._value != current:
            label._value = current
            m = '%03d' % int((current - int(current)) * 1000)
            t = time.localtime(current) if current else time.gmtime(0)
            t = time.strftime('[%H:%M:%S.%%s]', t) % m
            label.set_text(t)
    
    ## utils ##
    
    def _highlight_tab(self, tab_key):
        notebook = self.ui.log_notebook
        page = notebook._pages.get(tab_key)
        if page and notebook.page_num(page) != notebook.get_current_page():
            name = notebook.get_menu_label_text(page)
            page.tab.label.set_markup(TAB_HIGHLIGHT % cgi.escape(name))
    
    def _get_chat_box(self, channel):
        notebook = self.ui.log_notebook
        page = notebook._pages.get(channel)
        if page:
            return page.chat_box
    
    def _set_current_chat_page(self, channel):
        notebook = self.ui.log_notebook
        page = notebook._pages.get(channel)
        i = notebook.page_num(page) if page else -1
        if i != -1:
            notebook.set_current_page(i)
    
    def _selected_operators(self):
        return [o for opers in self._selected.values() for o in opers]
    
    def _format_targets(self, oper):
        return ', '.join(['%s:%s' % (x['node'], x['host']) for x in oper.targets])
    
    def _format_callback(self, oper):
        if oper.callback:
            return '%(node)s:%(ip)s (%(interface)s)' % oper.callback
        else:
            return 'None'
    
    def _gui_call(self, func, *args, **kwargs):
        if not self._exiting:
            with gtk.gdk.lock:
                func(*args, **kwargs)

def test():
    try:
        import faulthandler
        faulthandler.enable()
    except ImportError:
        pass
    
    import threading
    from control.commander_loop import CommanderLoop, ReplayLoop
    
    gtk.threads_init()

    if len(sys.argv) > 1:
        print 'Replaying events from: %s' % sys.argv[1]
        commander = ReplayLoop(playback_session=sys.argv[1])
    else:
        commander = CommanderLoop()
        
    window = CommanderWindow(commander, quit_on_exit=True)
    window.show()
    
    threading.Thread(target=commander.run, name='ioloop').start()
    
    gtk.main()

if __name__ == '__main__':
    test()
