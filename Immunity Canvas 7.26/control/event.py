import os
import time
import cPickle as pickle

from collections import namedtuple
from control.exceptions import EventVersionMismatch, EventFileDamaged

class Event(namedtuple('Event', 'source time name data')):
    pass

class EventFile(object):
    """
    This is the base class for event file reader/writers in CANVAS.
    Common bits of functionality are here.
    """
    
    # Minimum supported version
    VERSION = 1

    # Metadata block size
    METABLOCK_SIZE = 500

    def __init__(self, filename, mode):
        self._filename  = filename
        self._file      = open(filename, mode)
        self.meta_size  = None
        self.version    = None

        # Metadata
        self.start_time  = None
        self.end_time    = None
        self.event_count = 0
    
    def close(self):
        self._file.close()

    def repair(self):
        """
        Try and repair a damaged event pickle file.

        Damaged in this case means a missing metablock, which will be the
        case on any sort of crash, as the metablock is written just before
        the event file is properly closed.
        """
        try:
            self._file.seek(self.meta_size, os.SEEK_SET)

            while True:
                try:
                    event = Event(*pickle.load(self._file))
                    self.event_count += 1
                    pos = self._file.tell()
                    if not self.start_time: self.start_time = event.time
                    self.end_time = event.time
                except EOFError:
                    break
        except Exception:
            if self.event_count:
                # Seek to last known 'good' file position
                self._file.seek(pos, os.SEEK_SET)

        if self.event_count:
            # Truncate file
            self._file.truncate()
            
            # Reset file pointer
            self._file.seek(0, os.SEEK_SET)
            
            # Discard version and metablock size 
            _ = pickle.load(self._file)
            _ = pickle.load(self._file)
            
            # Write metablock
            pickle.dump((self.start_time,
                         self.end_time,
                         self.event_count),
                         self._file, protocol=2)
            
            self._file.seek(self.meta_size, os.SEEK_SET)
            return self.event_count

        raise EventFileDamaged('Event file %s is damaged and could not be repaired' % self._filename)
        
    def validate(self):
        self.version = pickle.load(self._file)
        
        if self.version < self.VERSION:
            raise EventVersionMismatch('Version %s is too old, minimum supported is: %s' % (self.version, self.VERSION))

        self.meta_size = pickle.load(self._file)

        # Load the metadata
        try:
            self.start_time, self.end_time, self.event_count  = pickle.load(self._file)
        except Exception:
            self.repair()
            
        self._file.seek(self.meta_size, os.SEEK_SET)

    def __del__(self):
        self.close()
        

class EventWriter(EventFile):
    """
    Writes events (tuples) into CANVAS pickle files.
    """
    
    def __init__(self, filename, overwrite=False):
        if os.path.exists(filename):
            EventFile.__init__(self, filename, 'rb+')
        else:
            EventFile.__init__(self, filename, 'wb+')

        self._file.seek(0, os.SEEK_END)
            
        if self._file.tell() == 0:
            # New file
            self._file.write('\xff'*EventFile.METABLOCK_SIZE)
            self._file.seek(0, os.SEEK_SET)
            pickle.dump(self.VERSION, self._file, protocol=2)
            pickle.dump(EventFile.METABLOCK_SIZE, self._file, protocol=2)
            self._file.seek(EventFile.METABLOCK_SIZE, os.SEEK_SET)
            self._file.flush()
        else:
            # Append events to existing file
            self._file.seek(0, os.SEEK_SET)
            # First verify it
            self.validate()
            # Seek to the end of the event stream
            self._file.seek(0, os.SEEK_END)

    def dump(self, sender, name, data):
        unixtime = time.time()
        
        if not self.start_time: self.start_time = unixtime
        self.end_time = unixtime
        
        pickle.dump((sender, unixtime, name, data), self._file, protocol=2)
        self._file.flush()

        self.event_count += 1

    def close(self):
        # Write the metadata at the start of the file
        self._file.seek(0, os.SEEK_SET)

        # Discard version
        _ = pickle.load(self._file)

        # Discard metablock size
        _ = pickle.load(self._file)

        # Write metadata
        pickle.dump((self.start_time,
                     self.end_time,
                     self.event_count),
                     self._file, protocol=2)

        EventFile.close(self)
        

class EventReader(EventFile):
    """
    Reads events from CANVAS pickle files, can be used as an iterator.
    Returns named tuple `Event' instances.
    """
    def __init__(self, filename):
        EventFile.__init__(self, filename, 'rb+')

        self.validate()
        self.data_pos = self._file.tell()
                    
    def __iter__(self):
        self._file.seek(self.data_pos, os.SEEK_SET)
        return self

    def events(self):
        return self.__iter__()

    def next(self):
        try:
            return Event(*pickle.load(self._file))
        except EOFError:
            raise StopIteration
