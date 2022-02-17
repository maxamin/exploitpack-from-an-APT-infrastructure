"""yahoo.search.term - Term Extraction web services module

This module implements the the Term Extraction web service, to extract
significant words and phrases from a larger context. There is currently
only one class implemented, TermExtraction.

An application ID (appid) is always required when instantiating a search
object. Additional parameters are documented in the TermExtraction class.
Example:

    from yahoo.search.term import TermExtraction

    srch = TermExtraction(app_id="YahooDemo", query="Yahoo")
    srch.context = "portal news sports mail messenger"

    for res in srch.parse_results():
       print res
"""

import types

import yahoo.search
import yahoo.search.dom.term


__revision__ = "$Id: term.py,v 1.5 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.5 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 14:26:00 MST 2007"


#
# VideoSearch class
#
class TermExtraction(yahoo.search._Search):
    """TermExtraction - Extract words or phrases from a larger content

    This class implements the Web Search Spelling Suggestion web service
    APIs. The only allowed parameter is:

        context      - The context to extract terms from (UTF-8 encoded)
        query        - An optional query to help with the extraction
                       process
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    The Term Extraction service provides a list of significant words or
    phrases extracted from a larger content. It is one of the technologies
    used in Y!Q. Full documentation for this service is available at:

        http://developer.yahoo.net/content/V1/termExtraction.html
    """
    NAME = "termExtraction"
    SERVICE = "ContentAnalysisService"
    METHOD = "POST"
    _RESULT_FACTORY = yahoo.search.dom.term.TermExtraction

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, False),
            "context" : (types.StringTypes, None, None, None, None, True),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
