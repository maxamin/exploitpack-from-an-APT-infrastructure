"""yahoo.search.news - News Search service module

This module implements the News Search web services, searching news
articles. There is currently only one class implemented, NewsSearch.

An application ID (appid) is always required when instantiating a search
object. Additional parameters are documented in the NewsSearch class.

Example:

    from yahoo.search.news import NewsSearch

    srch = NewsSearch(app_id="YahooDemo", query="Yahoo")
    srch.results = 10

    for res in srch.parse_results():
       print res.NewsSource
"""

import types

import yahoo.search
import yahoo.search.dom.news


__revision__ = "$Id: news.py,v 1.4 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 17:20:45 MST 2007"


#
# NewsSearch class
#
class NewsSearch(yahoo.search._BasicSearch):
    """NewsSearch - perform a Yahoo News Search

    This class implements the News Search web service APIs. Allowed
    parameters are:
    
        query        - The query to search for.
        type         - The kind of search to submit:
                         * "all" returns results with all query terms.
                         * "any" resturns results with one or more of the
                           query terms.
                         * "phrase" returns results containing the query
                          terms as a phrase.
        results      - The number of results to return (1-50).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        sort         - Sort articles by relevance ('rank') or most-recent
                       ('date'). Default is by relevance.
        language     - The language the results are written in.
        site         - A domain to restrict your searches to (e.g.
                       www.yahoo.com). You may submit up to 30 values
                       (e.g. ["www.yahoo.com", "www.cnn.com"]).
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/news/V1/newsSearch.html
    """
    NAME = "newsSearch"
    SERVICE = "NewsSearchService"
    _RESULT_FACTORY = yahoo.search.dom.news.NewsSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(NewsSearch, self)._init_valid_params()
        self._valid_params.update({
            "type" : (types.StringTypes, "any", str.lower,
                      ("all", "any", "phrase"), None, False),
            "sort" : (types.StringTypes, "rank", str.lower, ("date", "rank"),
                      None, False),
            "language" : (types.StringTypes, "en", str.lower,
                          self.languages.keys(), None, False),
            "site" : (types.StringTypes, [], None, None,
                      "a list of up to 30 domains", False),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
