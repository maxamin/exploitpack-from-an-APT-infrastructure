import gtk
import contextlib

@contextlib.contextmanager
def disabled_sorting(model):
    column, order = model.get_sort_column_id()
    model.set_sort_column_id(-1, gtk.SORT_ASCENDING)
    yield
    if column is not None and order is not None:
        model.set_sort_column_id(column, order)

@contextlib.contextmanager
def disabled_model(view, model):
    view.freeze_child_notify()
    with disabled_sorting(model):
        yield
    view.thaw_child_notify()

@contextlib.contextmanager
def set_cursor(widget, cursor_name):
    cursor = gtk.gdk.Cursor(getattr(gtk.gdk, cursor_name.upper()))
    widget.window.set_cursor(cursor)
    gtk.main_iteration()
    try:
        yield
    finally:
        widget.window.set_cursor(None)

def show_message(text, parent=None, icon=gtk.MESSAGE_INFO, title=None):
    dlg = gtk.MessageDialog(parent, gtk.DIALOG_DESTROY_WITH_PARENT,
        icon, gtk.BUTTONS_OK, text)

    if title: dlg.set_title(title)

    try:
        dlg.run()
    finally:
        dlg.destroy()

def show_warning(text, parent=None, title='Warning'):
    show_message(text, parent, gtk.MESSAGE_WARNING, title)

def show_error(text, parent=None, title='Error'):
    show_message(text, parent, gtk.MESSAGE_ERROR, title)

def show_question(text, parent=None, title=None):
    dlg = gtk.MessageDialog(parent, gtk.DIALOG_DESTROY_WITH_PARENT,
        gtk.MESSAGE_QUESTION, gtk.BUTTONS_YES_NO, text)

    if title: dlg.set_title(title)

    try:
        return dlg.run() == gtk.RESPONSE_YES
    finally:
        dlg.destroy()

def append_buffer(buf, text, tag=None):
    it = buf.get_end_iter()
    buf.insert_with_tags_by_name(it, text, tag) if tag else buf.insert(it, text)

def append_model_data(model, columns, parent, **kwargs):
    data = [''] * len(columns)
    
    for name, value in kwargs.iteritems():
        column = columns[name]
        data[column] = value
    
    return model.append(parent, data)

def update_model_data(model, it, columns, **kwargs):
    for name, value in kwargs.items():
        column = columns[name]
        model.set_value(it, column, value)

def model_iter_children(model, parent_it):
    child_it = model.iter_children(parent_it)
    while child_it:
        yield child_it
        child_it = model.iter_next(child_it)

def model_iter_all_children(model):
    for parent in model:
        for child_it in model_iter_children(model, parent.iter):
            yield child_it

def model_iter_all(model):
    for parent in model:
        parent_it = parent.iter
        yield parent_it
        for child_it in model_iter_children(model, parent_it):
            yield child_it

def get_textview_text(textview):
    buf = textview.get_buffer()
    return buf.get_text(buf.get_start_iter(), buf.get_end_iter())

def get_selected_row(view):
    model, it = view.get_selection().get_selected()
    if it: return model[model.get_path(it)]

def get_selected_rows(view):
    model, paths = view.get_selection().get_selected_rows()
    return [model[path] for path in paths]

def scroll_textview_to_bottom(view):
    buffer = view.get_buffer()
    buffer.place_cursor(buffer.get_end_iter())
    view.scroll_mark_onscreen(buffer.get_insert())

def scroll_treeview_to_bottom(view):
    model = view.get_model()
    if model:
        cnt = model.iter_n_children(None) - 1
        if cnt > -1:
            view.set_cursor((cnt,))

class UI:
    """
    A get_widget helper.
    """
    def __init__(self, get_widget):
        self._get_widget = get_widget
    
    def __getattr__(self, name):
        widget = self._get_widget(name)
        if not widget:
            raise KeyError('no such widget: %s' % name)
        return widget
    
    def __setattr__(self, name, value):
        self.__dict__[name] = value
    
    def add_accelerator(self, accel, callback):
        if not hasattr(self, 'accelerator_group'):
            self.accelerator_group = gtk.AccelGroup()
            self.window.add_accel_group(self.accelerator_group)
        
        group = self.accelerator_group
        keyval, mod = gtk.accelerator_parse(accel)
        group.connect_group(keyval, mod, gtk.ACCEL_VISIBLE, lambda *a: callback())
    
    def set_stock_image(self, widget, stock_id, size=gtk.ICON_SIZE_MENU):
        image = gtk.Image()
        image.set_from_stock(stock_id, size)
        widget.set_image(image)
    
    def on_view_clicked(self, view, event, column_name):
        path = view.get_path_at_pos(int(event.x), int(event.y))
        if path:
            path, column, x, y = path
            if column.get_title() == column_name:
                view.set_cursor(path, column, True)
