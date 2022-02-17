"""yahoo.search.web - Web Search services module

This module implements the Web Search web services, searching web content.
The supported classes of web searches are:
    
    WebSearch           - Web Search
    ContextSearch       - Web Search with a context added
    RelatedSuggestion	- Web Search Related Suggestion
    SpellingSuggestion	- Web Search Spelling Suggestion

An application ID (appid) is always required when instantiating a search
object. In addition, each search class takes different set of parameters,
as defined by this table

                 Web   Context  Related  Spelling
                -----  -------  -------  --------
    query        [X]     [X]      [X]       [X]
    region       [X]      .        .         .
    context       .      [X]       .         .
    type         [X]     [X]       .         .
    results      [X]     [X]      [X]        .
    start        [X]     [X]       .         .

    format       [X]     [X]       .         .
    adult_ok     [X]     [X]       .         .
    similar_ok   [X]     [X]       .         .
    language     [X]     [X]       .         .
    country      [X]     [X]       .         .
    site         [X]      .        .         .
    subscription [X]      .        .         .

    output       [X]     [X]      [X]       [X]
    callback     [X]     [X]      [X]       [X]


Each of these parameter is implemented as an attribute of each
respective class. For example, you can set parameters like:

    from yahoo.search.web import WebSearch

    srch = WebSearch(app_id="YahooDemo")
    srch.query = "Leif Hedstrom"
    srch.results = 40

    for res in srch.parse_results():
       print res.Url
"""

import types

import libs.yahoo.search
import libs.yahoo.search.dom.web


__revision__ = "$Id: web.py,v 1.10 2007/02/28 05:20:11 zwoop Exp $"
__version__ = "$Revision: 1.10 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Sun Feb 25 21:47:52 MST 2007"


#
# WebSearch class
#
class WebSearch(libs.yahoo.search._CommonSearch):
    """WebSearch - perform a Yahoo Web Search

    This class implements the Web Search web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        region       - The regional search engine on which the service
                       performs the search. For example, region=uk will give
                       you the search engine at uk.search.yahoo.com.
        type         - The kind of search to submit (all, any or phrase)
                          * all returns results with all query terms.
                          * any resturns results with one or more of the
                            query terms.
                          * phrase returns results containing the query
                            terms as a phrase.
        results      - The number of results to return (1-100).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        format       - Specifies the kind of web file to search for.
        adult_ok     - The service filters out adult content by default.
                       Enter a 1 to allow adult content.
        similar_ok   - Specifies whether to allow multiple results with
                       similar content. Enter a 1 to allow similar content
        language     - The language the results are written in.
        country      - The country code for the country the website is
                       located in.
        site         - A domain to restrict your searches to (e.g.
                       www.yahoo.com). You may submit up to 30 values
                       (e.g. ["www.yahoo.com", "www.cnn.com"]).
        subscription - Any subscriptions to premium content that should
                       also be searched. You may submit multiple values.
        license      - The Creative Commons license that the contents are
                       licensed under. You may submit multiple values (e.g.
                       [cc_commercial, cc_modifiable] ).
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.

    Supported values for 'format' are

        html      - Regular HTML / XHTML
        msword    - Microsoft Word
        pdf       - Adobe PDF
        ppt       - Microsoft PowerPoint
        rss       - RSS feed
        txt       - Text file
        xls       - Microsft Excel


    Full documentation for this service is available at:

        http://developer.yahoo.net/web/V1/webSearch.html
    """
    NAME = "webSearch"
    SERVICE = "WebSearchService"
    _RESULT_FACTORY = libs.yahoo.search.dom.web.WebSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(WebSearch, self)._init_valid_params()
        self._valid_params.update({
            "region" : (types.StringTypes, "us", str.lower,
                        self.regions.keys(), None, False),
            "results" : (types.IntType, 10, int, lambda x: x > -1 and x < 101,
                         "the range 1 to 100", False),
            "format" : (types.StringTypes, "any", str.lower,
                        ("all", "any", "html", "msword", "pdf", "ppt",
                         "rss", "txt", "xls"), None, False),
            "similar_ok" : (types.IntType, None, int, (1,), None, False),
            "language" : (types.StringTypes, "en", str.lower,
                          self.languages.keys(), None, False),
            "country" : (types.StringTypes, "default", str.lower,
                         self.countries.keys(), None, False),
            "site" : (types.StringTypes, [], None, None,
                      "a list of up to 30 domains", False),
            "subscription" : (types.StringTypes, [], str.lower,
                              self.subscriptions.keys(), None, False),
            "license" : (types.StringTypes, [], str.lower,
                         self.cc_licenses.keys(), None, False),
            })


#
# ContextSearch class, very similar to WebSearch
#
class ContextSearch(libs.yahoo.search._CommonSearch):
    """ContextSearch - perform a Yahoo Web Search with a context

    This class implements the Contextual Web Search service APIs, which is
    very similar to a regular web search. Allowed parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        context      - The context to extract meaning from (UTF-8 encoded).
        type         - The kind of search to submit (all, any or phrase).
                          * all returns results with all query terms.
                          * any resturns results with one or more of the
                            query terms.
                          * phrase returnes results containing the query
                            terms as a phrase.
        results      - The number of results to return (1-100).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        format       - Specifies the kind of web file to search for.
        adult_ok     - The service filters out adult content by default.
                       Enter a 1 to allow adult content.
        similar_ok   - Specifies whether to allow multiple results with
                       similar content. Enter a 1 to allow similar content.
        language     - The language the results are written in.
        country      - The country code for the country the website is
                       located in.
        license      - The Creative Commons license that the contents are
                       licensed under. You may submit multiple values (e.g.
                       license=cc_commercial&license=cc_modifiable).
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.
        

    Supported formats are

        html      - Regular HTML / XHTML
        msword    - Microsoft Word
        pdf       - Adobe PDF
        ppt       - Microsoft PowerPoint
        rss       - RSS feed
        txt       - Text file
        xls       - Microsft Excel


    Full documentation for this service is available at:

        http://developer.yahoo.net/web/V1/contextSearch.html
    """
    NAME = "contextSearch"
    SERVICE = "WebSearchService"
    METHOD = "POST"
    _RESULT_FACTORY = libs.yahoo.search.dom.web.WebSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(ContextSearch, self)._init_valid_params()
        self._valid_params.update({
            "results" : (types.IntType, 10, int,  lambda x: x > -1 and x < 101,
                         "the range 1 to 100", False),
            "context" : (types.StringTypes, None, None, None, None, True),
            "format" : (types.StringTypes, "any", str.lower,
                        ("all", "any", "html", "msword", "pdf", "ppt",
                         "rss", "txt", "xls"), None, False),
            "similar_ok" : (types.IntType, None, int, (1,), None, False),
            "language" : (types.StringTypes, "en", str.lower,
                          self.languages.keys(), None, False),
            "country" : (types.StringTypes, "default", str.lower,
                         self.countries.keys(), None, False),
            "license" : (types.StringTypes, [], str.lower,
                         self.cc_licenses.keys(), None, False),
            })


#
# RelatedSuggestion class
#
class RelatedSuggestion(libs.yahoo.search._Search):
    """RelatedSuggestion - perform a Yahoo Web Related Suggestions search

    This class implements the Web Search Related Suggestion web service
    APIs. The only allowed parameters are:

        query        - The query to get related searches from
        results      - The number of results to return (1-50)
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/web/V1/relatedSuggestion.html
    """
    NAME = "relatedSuggestion"
    SERVICE = "WebSearchService"
    _RESULT_FACTORY = libs.yahoo.search.dom.web.RelatedSuggestion

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, True),
            "results" : (types.IntType, 10, int,  lambda x: x > -1 and x < 51,
                         "the range 1 to 50", False),
            })


#
# SpellingSuggestion class
#
class SpellingSuggestion(libs.yahoo.search._Search):
    """SpellingSuggestion - perform a Yahoo Web Spelling Suggestion search

    This class implements the Web Search Spelling Suggestion web service
    APIs. The only allowed parameter is:

        query        - The query to get spelling suggestions for
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/web/V1/spellingSuggestion.html
    """
    NAME = "spellingSuggestion"
    SERVICE = "WebSearchService"
    _RESULT_FACTORY = libs.yahoo.search.dom.web.SpellingSuggestion

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, True),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
