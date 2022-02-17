#!/usr/bin/env python

import sys

if '.' not in sys.path: sys.path.append('.')

import zmq
import zmq.eventloop.ioloop as ioloop

TRACEBACK_FRAMES = 10

class EventLoop(object):
    """
    Conveniently wraps a ZMQ Tornado IOLoop.
    Classes that embed an IO loop, should inherit from us.
    """

    def __init__(self):
        # State
        self.running            = False
        self.terminated         = False
        
        self.ioloop             = ioloop.IOLoop()
        self.shutdown_handlers  = []
        self.exception_handlers = {}

    def add_callback(self, callback):
        """
        Schedule callback to run on next IOLoop iteration.
        This method can be called from any thread.
        """
        self.ioloop.add_callback(callback)
    
    def call(self, callback, *args, **kwargs):
        self.add_callback(lambda:callback(*args, **kwargs))

    def start(self):
        """
        Main method.
        Starts the ZMQ IO loop (which will keep control), cleanups at stop.

        Only returns when IO loop stops or exception is raised.
        """

        self.running = True
        
        try:
            self.ioloop.start()
        except: # We do want to catch everything here
            # Handle the exception if we have a registered handler
            exc_type, exc_value = sys.exc_info()[:2]
            if exc_type in self.exception_handlers:
                [x(exc_value) for x in self.exception_handlers[exc_type]]
            else:
                # Default handler
                import traceback
                tb = traceback.format_exc(TRACEBACK_FRAMES)
                print 'Unhandled exception @ start(): %s' % tb

        self.running = False

        try:
            # The following can raise an exception which seems like a ZMQ bug
            # ioloop.close() should never fault if called after ioloop.start() 
            # has returned which is always the case here
            self.ioloop.close()
        except IOError:
            pass
            
        # Run the shutdown handlers
        for x in reversed(self.shutdown_handlers):
            try:
                x()
            except Exception:
                import traceback
                tb = traceback.format_exc(TRACEBACK_FRAMES)
                print 'Unhandled exception @ shutdown handler: %s' % tb
                
        self.terminated = True

    def stop(self):
        """
        Stops the IO loop.
        This method can be called from any thread.
        """
        self.add_callback(lambda: self.ioloop.stop())

    def add_exception_handler(self, exc_type, handler):
        """
        Adds a handler for exc_type to our handler dictionary.
        Multiple handlers for the same exc_type can be active at any time,
        and will all be executed in sequence (first to last) on match.
        """
        if exc_type in self.exception_handlers:
            self.exception_handlers[exc_type].append(handler)
        else:
            self.exception_handlers[exc_type] = [handler]

    def add_shutdown_handler(self, handler):
        """
        Adds a handler that will be executed on shutdown.
        Multiple handlers can be active and will be executed in sequence,
        with order last installed to first.
        """
        self.shutdown_handlers.append(handler)
