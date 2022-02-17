import unittest

from nose.tools import raises

from pyjon.utils import substitute

class TestSubstitute(unittest.TestCase):
    """test the substitute function"""
    def tearDown(self):
        pass

    def setUp(self):
        pass

    def test_no_sub(self):
        """test that no substitution happen"""
        s = "foo bar"
        d = {'key1': 'value1', 'key2': 'value2', 'key3': 'value3'}

        expected = "foo bar"
        result = substitute(s, d.get)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

    def test_single_case(self):
        """test a single substitution case"""
        s = "foo {key1} baz"

        # callback returns nothing
        d = {}

        expected = "foo  baz"
        result = substitute(s, d.get)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

        # callback returns nothing but we have a default value
        d = {}

        expected = "foo blah baz"
        result = substitute(s, d.get, default="blah")
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

        # callback returns a value
        d = {'key1': 'bar', 'key2': 'toto', 'key3': 'plouf'}

        expected = "foo bar baz"
        result = substitute(s, d.get)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

        # callback returns an empty string, leave it that way!
        d = {'key1': '', 'key2': 'toto', 'key3': 'plouf'}

        expected = "foo  baz"
        result = substitute(s, d.get, default="blah")
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

    def test_multiple_case(self):
        """test multiple substitution in the same string"""
        s = "foo {key1} baz {key2} {key3} blah"

        # callback returns nothing
        d = {'key1': 'bar', 'key2': 'toto'}

        expected = "foo bar baz toto  blah"
        result = substitute(s, d.get)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

        # callback returns nothing but we have a default value
        d = {'key1': 'bar', 'key2': 'toto'}

        expected = "foo bar baz toto yay blah"
        result = substitute(s, d.get, default="yay")
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

        # callback returns a value
        d = {'key1': 'bar', 'key2': 'toto', 'key3': 'plouf'}

        expected = "foo bar baz toto plouf blah"
        result = substitute(s, d.get)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

    def test_no_sub_if_none(self):
        """test no substitution is None"""
        s = "foo {key1} baz {key2} {key3} blah"

        d = {'key1': 'bar', 'key2': 'toto'}

        expected = "foo bar baz toto {key3} blah"
        result = substitute(s, d.get, sub_if_none=False)
        assert result == expected, "Got '%s' instead of '%s'" % (result, expected)

    @raises(ValueError)
    def test_failure_default(self):
        """test error on incorrect default value"""
        s = "foo {key1} baz"
        d = {}

        result = substitute(s, d.get, default=1)

    @raises(ValueError)
    def test_failure_callback(self):
        """test error on incorrect callback return value"""
        s = "foo {key1} baz"
        d = {'key1': 1}

        result = substitute(s, d.get)

    @raises(IndexError)
    def test_failure_regex(self):
        """test error on an incorrect regex"""
        s = "foo {key1} baz"
        d = {'key1': "1"}

        result = substitute(s, d.get, regex=r'.*')
        
# vim: expandtab tabstop=4 shiftwidth=4:

