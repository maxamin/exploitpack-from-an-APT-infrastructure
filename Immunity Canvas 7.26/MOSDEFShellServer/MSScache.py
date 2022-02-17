#!/usr/bin/env python
#
# Implements a size limited cache using a LRU replacement strategy.
#
# The implementation uses a dict and a heap to track key/value pairs and their
# respective timestamps.  Timestamps are taken as a trivial counter, which
# makes this structure unusable for persistent storage.
#
# The dictionary uses the cache keys as keys, and heap entries as values.
# Heap entries come in the form of MSScacheEntry instances, which record
# key/value/count/type.  The count is used to determine their heap position,
# and type records if the entry is valid.
#
# On removal of a cache entry, we need to remove the corresponding heap entry.
# This normally has a O(log n) performance, and heapq does not implement it.
# Calling heapify would run O(n) which is even worse.  Therefore, we mark
# heap entries that are removed as INVALID, and remove then at our leisure
# when we reach the maximum cache size.
#
# Better implementations are possible, the python OrderedDict seems promising,
# as does implementing a good multi-index container.
# This however does not perform poorly, in the same Big-O as python dict does,
# and was fast to implement.
#
#  -- Ronald Huizer / Immunity Inc (C) 2011
#
# vim: sw=4 ts=4 expandtab

from heapq import heappush, heappop

class MSScache:
    ENTRY_VALID     = 0
    ENTRY_INVALID   = 1

    class MSScacheEntry:
        def __init__(self, key, value, count):
            self.key = key
            self.value = value
            self.count = count
            self.type = MSScache.ENTRY_VALID

        # Entries are sorted by their count value.
        def __cmp__(self, other):
            return cmp(self.count, other.count)

    def __init__(self, size = 1024):
        self.size = 0
        self.maxsize = size
        self.__cache = {}
        self.__heap = []
        self.__counter = 0

    def __len__(self):
        return self.size

    def __getitem__(self, key):
        try:
            entry = self.__cache[key]
        except KeyError:
            return None

        self.addItem(entry.key, entry.value)

        # Mark our current entry invalid.
        entry.type = self.ENTRY_INVALID
        return entry.value

    def __setitem__(self, key, value):
        # We already have this entry.  Mark it invalid.
        if self.__cache.has_key(key):
            entry = self.__cache[key]
            entry.type = self.ENTRY_INVALID

        # And now add a new entry.
        self.addItem(key, value)

    def addItem(self, key, value):
        # If we have reached the maximum size, pop an element.
        if self.size == self.maxsize:
            entry = heappop(self.__heap)
            # Don't delete the dict entry if the entry is INVALID.
            if entry.type != self.ENTRY_INVALID:
                del self.__cache[entry.key]
            self.size = self.size - 1

        newentry = self.MSScacheEntry(key, value, self.__counter)
        self.__cache[key] = newentry
        heappush(self.__heap, newentry)
        self.size = self.size + 1
        self.__counter = self.__counter + 1

if __name__ == "__main__":
    cache = MSScache(3)

    cache["foo"] = "bar"
    print cache["foo"]
    cache["foo"] = "quux"
    print cache["foo"]
    cache["baz"] = "quux"
    print cache["foo"]
    cache["baz"] = "quux"
    print cache["foo"]
    print len(cache)
