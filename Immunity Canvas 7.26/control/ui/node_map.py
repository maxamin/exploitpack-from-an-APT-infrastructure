import locale
import collections

import gtk
import gobject

import gaphas
import gaphas.tool
import gaphas.util
import gaphas.aspect

from control.ui import items
from control.ui import animation
from control.ui import tree_layout

BACKGROUND_COLOR = '#000000'

NODE_RADIUS = 40
NODE_CONNECTOR_OFFSET = 18
TREE_LAYOUT_SCALE_FACTOR = 150

NODE_COLORS = {
    'LocalNode':    (0.72, 0.24, 0.24), # red
    'JavaNode':     (0.72, 0.48, 0.24), # coffee
    'osxNode':      (0.90, 0.51, 0.51), # pink
    'linuxNode':    (0.57, 0.29, 0.49), # purple
    'win32Node':    (0.16, 0.38, 0.45), # blue
    'win64Node':    (0.19, 0.57, 0.19), # green
    '<target>':     (1.00, 1.00, 1.00), # white
    '<attack>':     (0.92, 0.24, 0.24), # red
    None:           (1.00, 1.00, 1.00), # white
    }

NODE_TEXT = {
    'font':  'Monospace 14',
    'color': (1.0, 1.0, 1.0),
    }

class NodeMap(gaphas.GtkView):
    def __init__(self):
        super(NodeMap, self).__init__()
        
        self.modify_bg(gtk.STATE_NORMAL, gtk.gdk.color_parse(BACKGROUND_COLOR))
        self.canvas = gaphas.Canvas()
        
        self._operator = None
        self._nodes = {}
        self._targets = {}
        
        self._animator = animation.Animator(self)
        
        # tool chain
        self.tool = chain = gaphas.tool.ToolChain(self)
        chain.append(gaphas.tool.HoverTool())
        chain.append(items.PanTool())
        chain.append(items.ZoomTool())
        chain.append(gaphas.tool.ItemTool())
        chain.append(gaphas.tool.RubberbandTool())
    
    @property
    def operator(self):
        return self._operator
    
    @operator.setter
    def operator(self, oper):
        self._operator = oper
        self.clear()
    
    def center_view(self):
        node = self._nodes.get('0')
        if not node:
            return
        
        alloc = self.get_allocation()
        x, y = self.get_matrix_i2v(node).transform_point(0, 0)
        
        x = (alloc.width / 2) - x
        y = NODE_RADIUS*2 if y == 0 else 0
        
        self.matrix.translate(x, y)
    
    def clear(self):
        canvas = self.canvas
        # unregister view before updating to avoid view de-sync
        canvas.unregister_view(self)
        
        self._animator.clear_transitions()
        self._nodes.clear()
        self._targets.clear()
        for item in canvas.get_all_items():
            try:
                canvas.remove(item)
            except KeyError:
                pass
        
        self.canvas = canvas
    
    def refresh(self):
        oper = self._operator
        
        # nodes
        updated = set(self._all_node_names(oper.node_tree))
        self._refresh_node(oper.node_tree)
        
        # remove any items that were not updated
        for name, node_item in self._nodes.items():
            if name not in updated:
                self._remove_node(node_item)
        
        # modules
        self._refresh_modules()
        
        self.queue_draw_refresh()
    
    def _refresh_layout(self):
        def build_tree(tree, node, targets, callback):
            tree['name'] = node['name']
            children = tree.setdefault('children', [])
            
            for child_node in node['children']:
                children.append(build_tree({}, child_node, targets, callback))
            
            # add targets
            for target in targets:
                if callback['node'] == node['name']:
                    children.append({'name': target.key, 'children': []})
            return tree
        
        oper = self._operator
        tree = build_tree({}, oper.node_tree, self._targets.values(), oper.callback)
        layout = tree_layout.build(tree, scale=TREE_LAYOUT_SCALE_FACTOR)
        
        for name, item in self._nodes.items():
            pos = layout.get(name)
            if pos:
                if item.pos == (0, 0):
                    item.pos = pos
                    item.request_update()
                else:
                    self._animator.add_transition(0.5, item, 'pos', item.pos, pos)
        
        for host, item in self._targets.items():
            pos = layout.get(host)
            if pos:
                item.pos = pos
                item.request_update()
    
    def _refresh_node(self, node, parent_item=None):
        name = node['name']
        
        node_item = self._nodes.get(name)
        if not node_item:
            node_item = self._add_node(node, parent_item)
        
        for child in node['children']:
            transition = self._animator.last_transition(node_item)
            if transition:
                refresh = lambda t, c, n: self._refresh_node(c, n)
                transition.connect('transition-complete', refresh, child, node_item)
            else:
                self._refresh_node(child, node_item)
    
    def _add_node(self, node, parent_item=None):
        name = node['name']
        item = NodeItem(node, parent_item)
        self.canvas.add(item)
        self._nodes[name] = item
        
        if parent_item:
            connector = self._connect_nodes(parent_item, item)
            connector.color = parent_item.color
            
            # fade in connector
            self._animator.add_transition(0.2, connector, 'alpha', 0.0, 0.8)
        
        # fade in
        self._animator.add_transition(0.2, item, 'alpha', 0.0, 0.8)
        
        self._refresh_layout()
        return item
    
    def _remove_node(self, item):
        def remove(t, item):
            self._animator.clear_transitions(item)
            self.canvas.remove(item)
            del self._nodes[item.name]
            self._refresh_layout()
        
        t = self._animator.add_transition(0.2, item, 'alpha', item.alpha, 0.0)
        t.connect('transition-complete', remove, item)
    
    def _add_target(self, host, module_name, parent_item):
        item = TargetItem(host, module_name, callback=parent_item.name)
        self.canvas.add(item)
        self._targets[(host, module_name)] = item
        
        connector = self._connect_nodes(parent_item, item)
        connector.color = item.color
        connector.alpha = item.alpha
        
        # fade in
        self._animator.add_transition(0.2, item, 'alpha', 0.0, item.alpha)
        self._animator.add_transition(0.2, item, 'text_alpha', 0.0, item.text_alpha)
        self._animator.add_transition(0.2, connector, 'alpha', 0.0, connector.alpha)
        
        self._refresh_layout()
    
    def _remove_target(self, item):
        def remove(t, item):
            self._animator.clear_transitions(item)
            self.canvas.remove(item)
            del self._targets[item.key]
            self._refresh_layout()
        
        def result(x):
            t = self._animator.add_transition(0.2, item, 'alpha', item.alpha, 0.0)
            t.connect('transition-complete', remove, item)
        
        t = self._animator.add_transition(0.2, item, 'color', item.color, get_node_color('<target>'))
        t.connect('transition-complete', result)
    
    def _refresh_modules(self):
        oper = self._operator
        
        # get items that have modules running against them
        updated = set()
        running = collections.defaultdict(list)
        for module in oper.modules.values():
            module_name = module['name']
            
            if module['status'] == 'RUNNING':
                if module['type'] == 'remote':
                    name = oper.callback['node']
                    host = module['target']
                    
                    key = (host, module_name)
                    updated.add(key)
                    
                    item = self._targets.get(key)
                    if item:
                        continue
                    
                    parent_item = self._nodes[name]
                    self._add_target(host, module_name, parent_item)
                
                else:
                    for node in module['nodes']:
                        name = node['name']
                        running[name].append(module)
        
        # remove any finished targets
        for key, item in self._targets.items():
            if key not in updated:
                self._remove_target(item)
        
        # check nodes
        for item in self._nodes.values():
            modules = running.get(item.name)
            if modules:
                color = get_node_color('<attack>')
                connect_color = color
                item.current_modules.update([mod['name'] for mod in modules])
            else:
                color = get_node_color(item.node['type'])
                connect_color = item.parent.color if item.parent else None
                item.current_modules.clear()
                    
            if item.color != color:
                self._animator.add_transition(0.2, item, 'color', None, color)
                if item.parent:
                    self._animator.add_transition(0.2, item._connector,
                        'color', None, connect_color)
    
    def _connect_nodes(self, parent, child):
        def connect_port(item, line, handle, port):
            conn = gaphas.aspect.Connector(line, handle)
            sink = gaphas.aspect.ConnectionSink(item, port)
            conn.connect(sink)
        
        connector = items.ConnectorItem()
        self.canvas.add(connector, child)
        child._connector = connector
        
        handles = connector.handles()
        head, tail = handles[0], handles[-1]
        
        connect_port(parent, connector, head, parent._sport)
        connect_port(child, connector, tail, child._dport)
        
        return connector
    
    def _all_node_names(self, node):
        yield node['name']
        for child in node['children']:
            for name in self._all_node_names(child):
                yield name

class NodeItem(items.Circle):
    def __init__(self, node, parent=None):
        super(NodeItem, self).__init__()
        
        self.node = node
        self.parent = parent
        self.children = set()
        if parent:
            parent.children.add(self)
        
        self.current_modules = set()
        
        self.radius = radius = NODE_RADIUS
        self.color = get_node_color(node['type'])
        
        x = self._handle.pos.x
        offset = NODE_CONNECTOR_OFFSET
        self._sport = self.add_port((x, radius + offset))
        self._dport = self.add_port((x, -radius - offset))
        
        # any connection to the parent
        self._connector = None
    
    @property
    def name(self):
        return self.node['name']
    
    def draw(self, context):
        super(NodeItem, self).draw(context)
        cr = context.cairo
        
        text_color = NODE_TEXT['color'] + (self.alpha,)
        cr.set_source_rgba(*text_color)
        gaphas.util.text_set_font(cr, NODE_TEXT['font'])
        gaphas.util.text_align(cr, 0, 0, self.name)
        
        if self.current_modules:
            w, h = gaphas.util.text_extents(cr, self.name)
            modules = sorted(self.current_modules, cmp=locale.strcoll)
            gaphas.util.text_align(cr, 0, h*2, ', '.join(modules))
    
    def post_update(self, context):
        # center views only after root node has been updated
        if self.name == '0':
            for view in self.canvas._registered_views:
                view.center_view()

class TargetItem(items.Circle):
    def __init__(self, host, module_name, callback):
        super(TargetItem, self).__init__()
        
        self.key = (host, module_name)
        self.host = host
        self.module = module_name
        self.callback = callback
        
        self.radius = radius = NODE_RADIUS
        self.color = get_node_color('<attack>')
        self.alpha = 0.5
        self.text_alpha = 1.0
        self.fill = False
        
        offset = NODE_CONNECTOR_OFFSET
        self._dport = self.add_port((self._handle.pos.x, -radius - offset))
        
        # any connection to the parent
        self._connector = None
    
    def draw(self, context):
        cr = context.cairo
        cr.set_dash([5], 1)
        super(TargetItem, self).draw(context)
        cr.set_dash([], 0)
        
        text_color = NODE_TEXT['color'] + (self.text_alpha,)
        cr.set_source_rgba(*text_color)
        gaphas.util.text_set_font(cr, NODE_TEXT['font'])
        gaphas.util.text_align(cr, 0, 0, self.host)
        
        w, h = gaphas.util.text_extents(cr, self.host)
        gaphas.util.text_align(cr, 0, h*2, self.module)

def get_node_color(node_type):
    return NODE_COLORS.get(node_type, NODE_COLORS[None])
