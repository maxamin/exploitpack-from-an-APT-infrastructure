import os
import time
import collections

import gtk
import gtk.glade
import gobject
import pango

from canvasengine import canvas_root_directory as CANVAS_ROOT

from control.ui import gui_utils as utils

COMMANDER_ALIAS = 'commander'
COMMANDER_LABEL = '[Commander]'
GROUP_ALL = 'global'
GROUP_LABEL_CHAT = '[Global]'

CHAT_COLORS = {
    'self'  : 'blue',
    'other' : '#319331',    # green
    'system': '#5b606a',    # grey
    }

CHANNEL_COLORS = {
    'active'            : None,
    'added'             : 'green',
    'disconnected'      : 'orange',
    'removed'           : 'red',
    'new_message'       : '#eadf64',    # yellow
    }

GLADE_FILE = os.path.join(CANVAS_ROOT, 'control', 'ui', 'chat_box.glade')
VIEW_FONT = pango.FontDescription('sans 9')
MONOSPACE_FONT = pango.FontDescription('monospace 9')

class ChatBox(object):
    def __init__(self, event_loop, channel=None, is_commander=False,
            replay_mode=False):
        self.event_loop = event_loop
        self.is_commander = is_commander
        self.replay_mode = replay_mode
        
        self._channel = channel
        self.history = collections.defaultdict(list)
        
        self.init_gui()
        
        if not self.is_commander:
            gobject.idle_add(self.idle)
    
    ## idle loop ##
    
    def idle(self):
        try:
            with gtk.gdk.lock:
                self.update_groups()
        except KeyboardInterrupt:
            return False
        
        time.sleep(0.01)
        return not self.event_loop.terminated
    
    ## initialization ##

    def init_gui(self):
        wt = gtk.glade.XML(GLADE_FILE)
        self.ui = utils.UI(wt.get_widget)
        
        button = self.ui.join_group_button
        button.connect('clicked', lambda b: self.join_group())
        
        if self.is_commander:
            pane = self.ui.channel_pane
            pane.set_no_show_all(True)
            pane.hide()
        else:
            self.init_channels()
        
        self.init_chat()
    
    def init_channels(self):
        # model
        columns = [('alias', str), ('id', str), ('color', str),
            ('transient', bool), ('icon', gtk.gdk.Pixbuf), ('type', str)]
        col_names = [x[0] for x in columns]
        col_types = [x[1] for x in columns]
        self.ui.channel_model = model = gtk.TreeStore(*col_types)
        model._group_iterators = {}
        model._oper_iterators = collections.defaultdict(dict)
        model._columns = columns = dict((v, i) for i, v in enumerate(col_names))
        
        # sorting
        def sort(model, it1, it2, columns):
            name1 = model.get_value(it1, columns['alias'])
            name2 = model.get_value(it2, columns['alias'])
            if name1 == GROUP_LABEL_CHAT:   return -1
            elif name2 == GROUP_LABEL_CHAT: return 1
            elif name1 == COMMANDER_LABEL:  return -1
            elif name2 == COMMANDER_LABEL:  return 1
            return cmp(name1, name2)
        model.set_default_sort_func(sort, columns)
        model.set_sort_column_id(-1, gtk.SORT_ASCENDING)
        
        # view
        view = self.ui.channel_view
        view.set_model(model)
        view.modify_font(VIEW_FONT)
        
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
        
        # selection
        selection = view.get_selection()
        selection.connect('changed', lambda x: self.refresh_chat_view())
        
        # popup menu
        def popup(view, event):
            if event.button == 3:
                # show the menu when idle, because the selection will
                # change after this call
                def show(button, time):
                    menu = self.ui.channel_menu
                    menu.show_all()
                    menu.popup(None, None, None, button, time)
                gobject.idle_add(show, event.button, event.time)
                # allow right-click to select
                return False
        view.connect('button-press-event', popup)
        
        def leave(item, view, columns):
            row = utils.get_selected_row(view)
            group = row[columns['id']]
            self.leave_group(group)
        item = self.ui.leave_group_menuitem
        item.connect('activate', leave, view, columns)
        
        # add global group
        self.update_groups()
    
    def init_chat(self):
        # chat view
        view = self.ui.chat_view
        view.modify_font(MONOSPACE_FONT)
        
        # colors
        buf = view.get_buffer()
        buf.create_tag('self', foreground=CHAT_COLORS['self'])
        buf.create_tag('other', foreground=CHAT_COLORS['other'])
        buf.create_tag('system', foreground=CHAT_COLORS['system'],
            weight=pango.WEIGHT_BOLD)
        
        # message view
        message_view = self.ui.message_view
        message_view.modify_font(MONOSPACE_FONT)
        
        if self.replay_mode:
            self.ui.send_button.set_sensitive(False)
            return
        
        def key_press(view, event):
            # enter to send, ctrl+enter for newline
            if event.keyval in [gtk.keysyms.Return, gtk.keysyms.KP_Enter]:
                if event.state & gtk.gdk.CONTROL_MASK:
                    view.get_buffer().insert_at_cursor('\n')
                else:
                    self.send_message()
                return True
            return False
        message_view.connect('key-press-event', key_press)
        
        button = self.ui.send_button
        button.connect('clicked', lambda b: self.send_message())
    
    def create_tab(self, name, closeable=False, tab_style=None):
        tab = gtk.HBox()
        tab.set_spacing(4)
        
        if tab_style == 'CANVAS':
            name = '<b>%s</b>' % name
        else:
            image = gtk.Image()
            if tab_style == 'oper':
                image.set_from_stock(gtk.STOCK_ORIENTATION_PORTRAIT, gtk.ICON_SIZE_MENU)
            elif tab_style == 'group':
                image.set_from_stock(gtk.STOCK_DND_MULTIPLE, gtk.ICON_SIZE_MENU)
            else:
                image.set_from_stock(gtk.STOCK_EDIT, gtk.ICON_SIZE_MENU)
            
            tab.pack_start(image, expand=False)
            tab.image = image
        
        label = gtk.Label()
        label.set_markup(name)
        tab.pack_start(label, expand=True)
        tab.label = label
        
        if closeable:
            # add a close button
            image = gtk.Image()
            image.set_from_stock(gtk.STOCK_CLOSE, gtk.ICON_SIZE_MENU)
            
            button = gtk.Button()
            button.add(image)
            button.set_relief(gtk.RELIEF_NONE)
            button.set_focus_on_click(False)
            
            style = gtk.RcStyle()
            style.xthickness = 0
            style.ythickness = 0
            button.modify_style(style)
            
            tab.pack_start(button, expand=False)
            tab.button = button
        
        tab.show_all()
        return tab
    
    ## groups ##
    
    def update_groups(self):
        self._update_group(COMMANDER_ALIAS)
        
        model = self.ui.channel_model
        oper_iters = model._oper_iterators
        group_iters = model._group_iterators
        
        group_opers = self.event_loop.groups
        groups = set(group_opers.keys())
        groups.add(GROUP_ALL)
        
        # update groups
        map(self._update_group, groups)
        
        # update operators
        for group, opers in self.event_loop.groups.iteritems():
            map(lambda op: self._update_operator(group, op), opers.values())
        
        # remove operators
        for oper, iters in oper_iters.items():
            for group, it in iters.items():
                try:
                    group_opers[group][oper]
                except KeyError:
                    print group, oper
                    del iters[group]
                    model.remove(it)
        
        # remove groups
        dead_groups = set(group_iters.keys()) - groups
        map(self._remove_group, dead_groups)
        
        # if there is no selection, select global
        if not self._get_channel():
            self.ui.channel_view.get_selection().select_path((0,))
    
    def _update_group(self, group):
        model = self.ui.channel_model
        columns = model._columns
        iters = model._group_iterators
        
        it = iters.get(group)
        if it:
            # update (group state info?)
            pass
        else:
            icon = self.ui.window.render_icon(gtk.STOCK_DND_MULTIPLE,
                gtk.ICON_SIZE_MENU)
            name = group
            if group == GROUP_ALL:
                name = GROUP_LABEL_CHAT
            elif group == COMMANDER_ALIAS:
                name = COMMANDER_LABEL
                icon = self.ui.window.render_icon(gtk.STOCK_ORIENTATION_PORTRAIT,
                    gtk.ICON_SIZE_MENU)
            data = {
                'alias': name,
                'id': group,
                'color': CHANNEL_COLORS['added'],
                'transient': True,
                'icon': icon,
                'type': 'all' if group == GROUP_ALL else 'group',
                }
            
            it = utils.append_model_data(model, columns, None, **data)
            iters[group] = it
            
            def reset(model, it, columns):
                if model.iter_is_valid(it):
                    model.set_value(it, columns['transient'], False)
                    model.set_value(it, columns['color'], CHANNEL_COLORS['active'])
            gobject.timeout_add(1000, reset, model, it, columns)
    
    def _update_operator(self, group, oper):
        model = self.ui.channel_model
        columns = model._columns
        iters = model._oper_iterators
        group_iters = model._group_iterators
        
        oper_id = oper['uuid']
        alias = oper['alias']
        
        try:
            it = iters[oper_id][group]
        except KeyError:
            it = None
        
        if it:
            pass
        else:
            icon = self.ui.window.render_icon(gtk.STOCK_ORIENTATION_PORTRAIT,
                gtk.ICON_SIZE_MENU)
            data = {
                'alias': alias,
                'id': oper_id,
                'color': CHANNEL_COLORS['added'],
                'transient': True,
                'icon': icon,
                'type': 'operator',
                }
            
            group_it = group_iters[group]
            it = utils.append_model_data(model, columns, group_it, **data)
            iters[oper_id][group] = it
            
            def reset(model, it, columns):
                if model.iter_is_valid(it):
                    model.set_value(it, columns['transient'], False)
                    model.set_value(it, columns['color'], CHANNEL_COLORS['active'])
            gobject.timeout_add(1000, reset, model, it, columns)
    
    def _remove_group(self, group):
        if group == COMMANDER_ALIAS:
            return
        
        model = self.ui.channel_model
        iters = model._group_iterators
        
        it = iters.pop(group)
        model.remove(it)
    
    def join_group(self):
        dialog = self.ui.join_group_dialog
        dialog.show_all()
        entry = self.ui.join_group_entry
        gobject.idle_add(entry.grab_focus)
        while True:
            if dialog.run() == 0:
                group = entry.get_text().strip()
                if not group:
                    utils.show_error('Invalid group name: %s' % group, dialog)
                    continue
                
                loop = self.event_loop
                loop.call(loop.join_group, group)
            break
        entry.set_text('')
        dialog.hide()
    
    def leave_group(self, group):
        loop = self.event_loop
        loop.call(loop.leave_group, group)
    
    ## chat ##
    
    def refresh_chat_view(self):
        columns = self.ui.channel_model._columns
        view = self.ui.channel_view
        row = utils.get_selected_row(view)
        if not row:
            return
        
        channel = row[columns['id']]
        
        self._highlight_channel(channel, False)
        
        chat_view = self.ui.chat_view
        buf = chat_view.get_buffer()
        buf.set_text('')
        
        loop = self.event_loop
        name = loop.COMMANDER_ALIAS if self.is_commander else loop.uuid
        
        for args in self.history[channel]:
            self.append_message(*args, history=False)
    
    def send_message(self):
        message_view = self.ui.message_view
        message = utils.get_textview_text(message_view).strip()
        if not message:
            return
        
        dest = self._get_channel()
        if not dest:
            return
        
        # send message
        loop = self.event_loop
        loop.call(loop.tell, message, dest)
        
        # display message in chat view
        if self.is_commander:
            self.append_message(loop.COMMANDER_ALIAS, dest, message)
        
        # clear message
        message_view.get_buffer().set_text('')
    
    def append_message(self, source, dest, message, meta=None, history=True):
        meta = meta or {}
        name = meta.get('alias', source)
        
        tag = 'other'
        loop = self.event_loop
        if self.is_commander:
            if dest == loop.COMMANDER_ALIAS:
                dest = source
            if name == loop.COMMANDER_ALIAS:
                tag = 'self'
        else:
            if dest == loop.uuid:
                dest = source
            if name == loop.name:
                tag = 'self'
        
        event = meta.get('event')
        if event == 'join':
            tag = 'system'
            message = 'Operator %s has joined group %s' % (name, dest)
        elif event == 'depart':
            tag = 'system'
            message = 'Operator %s has left group %s' % (name, dest)
        
        if not message:
            return
        
        if history:
            self.history[dest].append((source, dest, message, meta))
        
        if dest != self._get_channel():
            self._highlight_channel(dest)
            return
        
        view = self.ui.chat_view
        buf = view.get_buffer()
        
        secs = getattr(self.event_loop, 'event_time_ref', None)
        t = time.strftime('%H:%M', time.localtime(secs))
        
        if tag == 'system':
            prefix = '%s *** ' % t
        else:
            prefix = '%s <%s> ' % (t, name)
        utils.append_buffer(buf, prefix, tag)
        
        if tag != 'system':
            tag = None
        
        lprefix = len(prefix)
        lines = message.splitlines()
        utils.append_buffer(buf, '%s\n' % lines[0], tag)
        for line in lines[1:]:
            utils.append_buffer(buf, '%s%s\n' % (' ' * lprefix, line), tag)
        
        utils.scroll_textview_to_bottom(view)
    
    ## utils ##
    
    def _get_channel(self):
        if self._channel:
            return self._channel
        
        columns = self.ui.channel_model._columns
        row = utils.get_selected_row(self.ui.channel_view)
        if row:
            return row[columns['id']]
    
    def _highlight_channel(self, channel, highlight=True):
        model = self.ui.channel_model
        columns = model._columns
        it = model._group_iterators.get(channel)
        if it:
            data = {'color': CHANNEL_COLORS['new_message'] if highlight else None}
            utils.update_model_data(model, it, columns, **data)
