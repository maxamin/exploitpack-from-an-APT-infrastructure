import collections

import cairo
import gtk.gdk

import gaphas
import gaphas.tool
import gaphas.util
from gaphas import connector

Position = collections.namedtuple('Position', 'x y')

def rgba_brightness(rgba, adjust):
    return tuple([c + adjust for c in rgba])

class Colorable(object):
    """
    Adjective:	
        1. Apparently correct or justified: "a colorable legal claim".
        2. Counterfeit.
    """
    def __init__(self):
        self.color = (0.0, 0.0, 0.0)
        self.alpha = 1.0
    
    @property
    def rgba(self):
        return self.color + (self.alpha,)

class Item(gaphas.Item, Colorable):
    def __init__(self):
        super(Item, self).__init__()
        Colorable.__init__(self)
        
        self._pos = Position(0, 0)
        self._handle = handle = gaphas.Handle()
        handle.visible = False
        handle.movable = False
        self._handles.append(handle)
    
    @property
    def x(self):
        return self._pos.x
    
    @x.setter
    def x(self, x):
        tx = x - self._pos.x
        self._pos = self._pos._replace(x=x)
        self.matrix.translate(tx, 0.0)
    
    @property
    def y(self):
        return self._pos.y
    
    @y.setter
    def y(self, y):
        ty = y - self._pos.y
        self._pos = self._pos._replace(y=y)
        self.matrix.translate(0.0, ty)
    
    @property
    def pos(self):
        return self._pos
    
    @pos.setter
    def pos(self, xy):
        self.x, self.y = xy
    
    def add_port(self, pos):
        port = connector.PointPort(connector.Position(pos))
        self._ports.append(port)
        return port
    
    def draw(self, context):
        cr = context.cairo
        cr.set_source_rgba(*self.rgba)
        cr.set_line_cap(cairo.LINE_CAP_ROUND)

class ConnectorItem(gaphas.Line, Colorable):
    def __init__(self):
        super(ConnectorItem, self).__init__()
        Colorable.__init__(self)
        
        self.dashed = False
        
        handles = self.handles()
        handles[0].visible = False
        handles[-1].visible = False
    
    def draw(self, context):
        cr = context.cairo
        cr.set_source_rgba(*self.rgba)
        if self.dashed:
            cr.set_dash([5], 1)
        super(ConnectorItem, self).draw(context)
        if self.dashed:
            cr.set_dash([], 0)

class Circle(Item):
    def __init__(self):
        super(Circle, self).__init__()
        self._radius = 10
        self.fill = True
    
    @property
    def radius(self):
        return self._radius
    
    @radius.setter
    def radius(self, r):
        p = self._handle.pos
        self._radius = ((r - p.x) ** 2 + (r - p.y) ** 2) ** 0.5
    
    def draw(self, context):
        super(Circle, self).draw(context)
        cr = context.cairo
        
        r = 2 * self._radius
        gaphas.util.path_ellipse(cr, 0, 0, r, r)
        
        if self.fill:
            cr.fill()
            
            rgba = rgba_brightness(self.rgba, 0.1)
            cr.set_source_rgba(*rgba)
            cr.set_line_width(max(cr.device_to_user_distance(2, 2)))
            gaphas.util.path_ellipse(cr, 0, 0, r, r)
            cr.stroke()
        else:
            cr.stroke()

class PanTool(gaphas.tool.PanTool):
    def on_scroll(self, event):
        return False

class ZoomTool(gaphas.tool.ZoomTool):
    def on_scroll(self, event):
        event.state |= gtk.gdk.CONTROL_MASK
        return super(ZoomTool, self).on_scroll(event)
