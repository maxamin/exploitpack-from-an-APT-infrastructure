#! /usr/bin/env python

from debug import devlog

_threadutils_threads_pool = []

def threadutils_add(thread):
    global _threadutils_threads_pool
    devlog('threadutils_add', "adding thread %s to thread pool" % thread.getName())
    if thread.isDaemon():
        devlog('threadutils_add', "thread %s IS daemon" % thread.getName())
    _threadutils_threads_pool.append(thread)

def threadutils_del(thread, timeout=10):
    global _threadutils_threads_pool
    name = None
    if hasattr(thread, 'name'):
        name = thread.name
    else:
        name = thread.getName()
    if thread.isAlive():
        devlog('threadutils_del', "thread is alive")
    if hasattr(thread, 'shutdown'):
        devlog('threadutils_del', "calling thread.shutdown()")
        thread.shutdown()
    else:
        devlog('threadutils_del', "thread doesn't have shutdown() function...")
    # we are mad and pissed of, no time to play
    if hasattr(thread, '_Thread__stop'):
        devlog('threadutils_del', "calling _Thread__stop()!")
        thread._Thread__stop()
    if thread.isDaemon():
        devlog('threadutils_del', "can not join Daemon thread")
    else:
        devlog('threadutils_del', "trying to join thread")
        thread.join(timeout)
    print "[T] %s exited" % name
    if thread in _threadutils_threads_pool:
        _threadutils_threads_pool.remove(thread)

def threadutils_exiting(thread):
    global _threadutils_threads_pool
    devlog('threadutils_exiting', "thread %s exiting" % thread.getName())
    if thread in _threadutils_threads_pool:
        _threadutils_threads_pool.remove(thread)

def threadutils_cleanup():
    global _threadutils_threads_pool
    if _threadutils_threads_pool == []:
        devlog('threadutils_cleanup', "no threads in pool")
    else:
        for thread in _threadutils_threads_pool:
            devlog('threadutils_cleanup', "cleaning thread %s" % thread.getName())
            threadutils_del(thread)

