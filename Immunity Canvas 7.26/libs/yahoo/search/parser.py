"""Base class for search results parsing

This package implements the interface and base class that should be
used for all parsers of the web results. It is used by the DOM parsers
that we provide as defaults.
"""

__revision__ = "$Id: parser.py,v 1.4 2005/10/26 20:32:27 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Wed Oct 26 11:24:50 PDT 2005"


#
# Exceptions and error handling
#
class Error(Exception):
    """Base class for all Yahoo DOM Parser exceptions."""

class ClassError(Error):
    """This can only occur if the APIs aren't installed or configured
    properly. If it happens, please contact the author."""

class XMLError(Error):
    """This exception can occur if, and only if, Yahoo returns malformed
    XML results."""


#
# Data conversion utilities
#
def string_to_bool(string):
    """Convert a string to a boolean value"""
    string = string.lower()
    if string == "false":
        return False
    elif string == "true":
        return True
    else:
        return bool(string)


#
# Simple wrapper around a dict, to present the dict keys
# as "properties"
#
class ResultDict(dict):
    """ResultDict - Simple class to wrap the results
    """
    def __getattr__(self, key):
        try:
            return self[key]
        except KeyError:
            raise AttributeError("Result object has no attribute '%s'" % key)


#
# Yahoo Search Web Services result classes/parsers (e.g. DOM)
#
class ResultParser(object):
    """Yahoo Search Web Service Results - base class

    This is the base class for all Yahoo Search Web Service result parsers.
    If you build your own result parser (e.g. non-DOM based), please sub-
    class ResultParser.  The following attributes are always available:

        total_results_available
        total_results_returned
        first_result_position

        results


    Results are a list of dictionaries, which can be a custom class as
    required. An interator generator is provided for easy access to the
    list of results. For example, to iterate over all results, you would do
    something like:

        dom = ws.get_results()
        results = ws.parse_results(dom)
        dom.unlink()

        for res in results:
            print res['Url']
            print res.Summary


    As you can see, each result is a customizable dictionary. The default
    results dict supports accessing each key as a "property", like the
    above example (res.Summary).

    You can also get the list of results directly, using the results
    attribute. An optional res_dict argument can be used to provide an
    alternative dictionary implementation to use for the results.

    """
    def __init__(self, service, res_dict=ResultDict):
        self._service = service

        self._total_results_available = 0
        self._total_results_returned = 0
        self._first_result_position = 0

        self._results = []
        self._res_dict = res_dict
        self._res_fields = []
        self._init_res_fields()

    def __iter__(self):
        return iter(self._results)

    def _init_res_fields(self):
        """Initialize the valid result fields."""
        self._res_fields = [('Title', None, None),
                            ('Summary', None, None),
                            ('Url', None, None),
                            ('ClickUrl', None, None)]

    def _get_results(self):
        """Get the results."""
        return self._results
    results = property(_get_results, None, None,
                       "The list of all results")

    def _get_service(self):
        """Get the service for this DOM parser."""
        return self._service
    def _set_service(self, service):
        """Set the service for this DOM parser."""
        self._service = service
    service = property(_get_service, _set_service, None,
                       "The Search Web Service object for this results parser")

    def parse_results(self, result_set):
        """Parse the results."""
        err = "Search Result class %s must implement a parse_result()" % (
            self._service.svc_name)
        raise ClassError(err)

    def _get_total_results_available(self):
        """Get the total number of results for the query."""
        return self._total_results_available
    total_results_available = property(_get_total_results_available, None, None,
                                       "Total number of results for the query")
    totalResultsAvailable = property(_get_total_results_available, None, None,
                                     "Total number of results for the query")

    def _get_total_results_returned(self):
        """Get the number of results returned."""
        return self._total_results_returned
    total_results_returned = property(_get_total_results_returned, None, None,
                                      "The number of results returned")
    totalResultsReturned = property(_get_total_results_returned, None, None,
                                    "The number of results returned")

    def _get_first_result_position(self):
        """Get the first result position."""
        return self._first_result_position
    first_result_position = property(_get_first_result_position, None, None,
                                     "The first result position")
    firstResultPosition = property(_get_first_result_position, None, None,
                                   "The first result position")



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
