import os
import re
import time
import uuid
import datetime
import threading
import collections
try:
    import cPickle as pickle
except ImportError:
    import pickle

from exploitutils import devlog
from libs.reports import utils

DEFAULT_DATA_FILE = 'report.pkl'

class VersionError(Exception):
    pass

class Event(collections.namedtuple('Event', 'name data module time session_id')):
    """A namedtuple for reporting event data."""
    
    @property
    def datetime(self):
        """Returns a datetime object for the :attr:`time` attribute of the
        event."""
        return datetime.datetime.fromtimestamp(self.time)

class Reporter(object):
    """A :class:`Reporter` provides an interface to a CANVAS event file.
    
    Instances of this class will check files for a supported version value.
    A :exc:`VersionError` exception will be thrown for unsupported files.
    
    The format for an event file is as follows:
        
        +---------------+
        | Version (int) |
        +---------------+
        | Event         |
        +---------------+
        | Event         |
        +---------------+
        | ...           |
        +---------------+
    
    Events are stored as a simple tuple::
        
        (name, data, module, time, session_id)
    
    However, the :meth:`events` method returns an :class:`Event` namedtuple,
    for convenience.
    """
    
    #: The default version for the event file.
    VERSION = 2
    
    def __init__(self, session_name=None, data_path=None, _backup_overwrite=False):
        self._lock = threading.Lock()
        
        fname = data_path or utils.get_reports_path(session_name, DEFAULT_DATA_FILE)
        file, version = self._open(fname)
        if not version:
            print '\n<%s>' % ('-' * 70)
            print '    An unsupported or old event file was found at:\n      %s' % fname
            
            # _backup_overwrite is an internal argument
            # it should only be used by canvasengine on startup
            if _backup_overwrite:
                # back up
                bak_fname = fname + '.bak'
                os.rename(fname, bak_fname)
                print '    The file was backed up to:\n      %s' % bak_fname
                print '    The original file will be overwritten with new events.'
                
                # overwrite
                file, version = self._open(fname, 'w+b')
            else:
                # unsupported or non-existant version number
                raise VersionError('unsupported event file: %s\n'
                    'You may need to upgrade your version of CANVAS.' % fname)
            
            print '<%s>\n' % ('-' * 70)
        
        self._version = version
        devlog('reports', 'opened event file: %s (version: %s)' % (fname, version))
        
        self._file = file
        self._filename = fname
        self._session_id = uuid.uuid1().hex
    
    def __del__(self):
        self._file.close()
    
    @property
    def filename(self):
        """The filename of the event file."""
        return self._filename
    
    @property
    def version(self):
        """The actual version of the event file."""
        return self._version
    
    def new_event(self, name, data, module=None):
        """Creates a new event and writes it to the event file."""
        # dump as a simple tuple to avoid the need to import this lib when
        # data is loaded
        module = module or 'canvas'
        event = (name, data, module, time.time(), self._session_id)
        devlog('reports', 'new event: %s' % str(event))
        
        data = pickle.dumps(event)
        with self._lock:
            self._file.write(data)
            self._file.flush()
    
    def events(self, name=None, pattern=None):
        """Returns an iterator over the events in the event file.
        
        If *name* is provided, only events matching *name* will be returned.
        If *pattern* is provided, it should be a regex pattern that will
        be matched against event names to return.
        """
        f = self._file
        pos = f.tell()
        f.seek(0)
        version = pickle.load(f)
        while True:
            try:
                event = Event(*pickle.load(f))
            except EOFError:
                break
            if not (name or pattern):
                yield event
            else:
                pattern_match = not pattern or re.match(pattern, event.name)
                name_match = not name or event.name == name
                if name_match and pattern_match:
                    yield event
    
    def _open(self, fname, mode='a+b'):
        file = open(fname, mode)
        version = self._check_version(file)
        return file, version
    
    def _check_version(self, file):
        with self._lock:
            file.seek(0, os.SEEK_END)
            if file.tell() == 0:
                pickle.dump(self.VERSION, file)
                file.flush()
                return self.VERSION
            
            file.seek(0)
            version = pickle.load(file)
            if not isinstance(version, int) or version > self.VERSION:
                return
            
            file.seek(0, os.SEEK_END)
            return version
