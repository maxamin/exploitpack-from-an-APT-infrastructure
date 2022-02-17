import os
import imp
import datetime

from exploitutils import devlog
from engine import CanvasConfig

EXPLOIT_DIR = 'exploits'

class LoadError(ImportError):
    pass

class Data(dict):
    """A dict subclass that allows attribute access to values.
    
    Attributes can be accessed directly or using the standard dict API.
    Any attribute/value that is missing will return `None`.
    """
    def __init__(self, *args, **kwargs):
        super(Data, self).__init__(*args, **kwargs)
        self.__dict__ = self
    
    def __getitem__(self, key):
        try:
            return super(Data, self).__getitem__(key)
        except KeyError:
            return
    
    def __getattribute__(self, name):
        try:
            return super(Data, self).__getattribute__(name)
        except AttributeError:
            return

class DefaultData(Data):
    """A Data subclass that returns *<unknown>* instead of `None`.
    
    This class is useful to pass to templates so that values will display
    *<unknown>* rather than *None*.
    """
    def __getitem__(self, key):
        value = super(DefaultData, self).__getitem__(key)
        if isinstance(value, dict) and not isinstance(value, DefaultData):
            value = DefaultData(value)
        return '<unknown>' if value is None else value
    
    def __getattribute__(self, name):
        value = super(Data, self).__getattribute__(name)
        if isinstance(value, dict) and not isinstance(value, DefaultData):
            value = DefaultData(value)
        return '<unknown>' if value is None else value

def get_canvas_path(*path):
    return os.path.abspath(os.path.join(*path))

def get_module_dir(module_file):
    return os.path.abspath(os.path.dirname(module_file))

def get_template_path(module_file):
    return os.path.join(get_module_dir(module_file), 'report_template.odt')

def get_reports_path(session=None, filename=''):
    session = session or CanvasConfig['canvas_session_name']
    output = CanvasConfig['canvas_output']
    return os.path.abspath(os.path.join(output, session, filename))

def get_resources_path(filename=''):
    return os.path.abspath(os.path.join(CanvasConfig['canvas_resources'], filename))

def generate_output_filename(name, ext='odt'):
    t = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return 'report_%s_%s.%s' % (name, t, ext)

def find_exploit_report(name):
    if name.lower() == 'canvas':
        path = os.path.dirname(__file__)
        module_name = 'canvas_report'
    else:
        path = os.path.join(EXPLOIT_DIR, name)
        module_name = 'report'
    if not os.path.exists(path):
        raise LoadError(name)
    try:
        modargs = imp.find_module(module_name, [path])
        return imp.load_module(name, *modargs)
    except ImportError as e:
        devlog('reports', str(e))
        raise LoadError(name)

def format_datetime(t):
    return datetime.datetime.fromtimestamp(t).ctime()

def closest_int(v, l):
    """Returns the value from *l* which is closest to the value *v*."""
    return min((abs(v - i), i) for i in l)[1]

def time_resolution(delta, resolutions=None):
    """Returns an appropriate time resolution for *delta*."""
    minute = 60
    hour = minute * 60
    resolutions = resolutions or [
        minute, 10 * minute, 30 * minute, 60 * minute,
        2 * hour, 5 * hour, 10 * hour, 24 * hour]
    return closest_int(delta, resolutions)

def total_seconds(td):
    """Return the total number of seconds contained in the duration."""
    return (td.microseconds + (td.seconds + td.days * 24 * 3600) * 10**6) / float(10**6)

def round_int(v, resolution, floor=True):
    """Round *v* to the nearest value in the range of *resolution*."""
    d = v % resolution
    op = -1 if floor else 1
    return int(v + (op * d))
 
def fix_unicode(s):
    try:
        return s.decode('utf-8')
    except UnicodeError:
        try:
            return s.decode('latin-1')
        except UnicodeError:
            return s.decode('utf-8', errors='replace')

def dict_fix_unicode(d):
    def inner(d):
        for key, value in d.iteritems():
            yield (fix_unicode(key), fix_unicode(value))
    return dict(inner(d))
