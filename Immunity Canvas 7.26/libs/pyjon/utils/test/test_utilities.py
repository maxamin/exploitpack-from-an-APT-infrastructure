# -*- encoding: utf-8 -*-

from pyjon.utils import Singleton
from pyjon.utils import create_function

def argument_returner(*args):
    """a function that just returns its args as a list
    """
    return list(args)

def test_singleton_instanciation():
    """test that the singleton can be instanciated correctly
    either first or second time
    """
    class C(object):
        __metaclass__ = Singleton
        def __init__(self, foo):
            self.foo = foo

    assert C('bar').foo == 'bar'
    assert C().foo == 'bar'

def test_create_function_1():    
    """test that the create_function call
    """
    range_5 = create_function(range, args=[5])
    assert callable(range_5)
    assert range_5() == [0, 1, 2, 3, 4]

def test_complex_create_function():
    my_func = create_function(argument_returner, args=[1, '2'])
    assert callable(my_func)
    assert my_func() == [1, '2']

def test_create_function_exception():
    my_other_func = create_function(argument_returner, args=[1, '2'],
            caller_args_count=2)
    assert callable(my_other_func)
    exc = False
    try:
        my_other_func()
    except TypeError:
        #TypeError: function takes exactly 2 arguments (0 given)
        exc = True

    assert exc == True
def test_create_function_with_caller_args():
    my_other_func = create_function(argument_returner, args=[1, '2'],
            caller_args_count=2)
    assert callable(my_other_func)
    assert my_other_func('foo', 'bar') == ['foo', 'bar', 1, '2'] 

