import time
import collections

import gobject

class Animator(object):
    def __init__(self, view):
        self.view = view
        self._transitions = collections.defaultdict(set)
    
    def add_transition(self, duration, item, attr, start_value, stop_value):
        if not self._transitions:
            gobject.idle_add(self._animate)
        
        if start_value is None:
            start_value = getattr(item, attr)
        
        if isinstance(start_value, float):
            transition = Transition(duration, item, attr, start_value, stop_value)
        
        elif isinstance(start_value, tuple):
            transition = TupleTransition(duration, item, attr, start_value, stop_value)
        
        else:
            raise ValueError('unsupported transition type: %s' % type(start_value))
        
        self._transitions[item].add(transition)
        return transition
    
    def last_transition(self, item):
        transitions = self._transitions.get(item)
        if not transitions:
            return None
        return max([(t.stop_time, t) for t in transitions])[1]
    
    def clear_transitions(self, item=None):
        if item:
            for t in self._transitions.pop(item, []):
                t.disconnect_all()
        else:
            try:
                item, transitions = self._transitions.popitem()
                while item:
                    for t in transitions:
                        t.disconnect_all()
                    item, transitions = self._transitions.popitem()
            except KeyError:
                pass
    
    def _animate(self):
        if not self._transitions:
            return False
        for item, transitions in self._transitions.items():
            for t in transitions.copy():
                if not t.step():
                    transitions.remove(t)
                self.view.queue_draw_refresh()
            if not transitions:
                self._transitions.pop(item, None)
        return True

class Transition(gobject.GObject):
    __gsignals__ = {
        'transition-complete': (gobject.SIGNAL_RUN_LAST, gobject.TYPE_NONE, ()),
        }
    
    def __init__(self, duration, item, attr, start_value, stop_value):
        super(Transition, self).__init__()
        
        self.duration = float(duration)
        self.item = item
        self.attr = attr
        
        self.start_value = self.preprocess_value(start_value)
        self.stop_value = self.preprocess_value(stop_value)
        self.diff = self.calc_diff(start_value, stop_value)
        
        # set initial value
        self._set_value(self.start_value)
        
        self.start_time = time.time()
        self.stop_time = self.start_time + self.duration
        
        # keep track of connections internally to make disconnects simpler
        self._handler_ids = set()
    
    def connect(self, *args):
        handler_id = super(Transition, self).connect(*args)
        self._handler_ids.add(handler_id)
    
    def disconnect_all(self):
        map(self.disconnect, self._handler_ids)
        self._handler_ids.clear()
    
    def step(self):
        # check for stop state
        ct = time.time() - self.start_time
        dur = self.duration
        if ct > dur:
            self._set_value(self.stop_value)
            self.emit('transition-complete')
            return False
        
        # calculate the current value
        step = ct / dur
        v = self.calc_value(step)
        
        # update the item
        self._set_value(v)
        
        return True
    
    def _set_value(self, value):
        setattr(self.item, self.attr, value)
        self.item.request_update()
    
    def calc_value(self, step):
        return self.start_value + self.diff * step
    
    def calc_diff(self, start, stop):
        return stop - start
    
    def preprocess_value(self, value):
        return value

class TupleTransition(Transition):
    def calc_value(self, step):
        return tuple([sv + dv * step for sv, dv in zip(self.start_value, self.diff)])
    
    def calc_diff(self, start, stop):
        return [sp-st for st, sp in zip(start, stop)]
