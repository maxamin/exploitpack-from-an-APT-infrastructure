"""DOM parser for Web search results

Implement a simple DOM parsers for the Yahoo Search Web Services
web search APIs. This provides parser for the following Web search
classes:

    WebSearch           - Web Search
    ContextSearch       - Web Search with a context added
    RelatedSuggestion	- Web Search Related Suggestion
    SpellingSuggestion	- Web Search Spelling Suggestion
"""


__revision__ = "$Id: web.py,v 1.5 2005/10/27 18:07:59 zwoop Exp $"
__version__ = "$Revision: 1.5 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Thu Oct 27 10:46:03 PDT 2005"

from libs.yahoo.search import dom


#
# DOM parser for WebSearch and ContextSearch
#
class WebSearch(dom.DOMResultParser):
    """WebSearch - DOM parser for Web Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - The title of the web page.
        Summary          - Summary text associated with the web page.
        Url              - The URL for the web page.
        ClickUrl         - The URL for linking to the page.

    The following attributes are optional, and might not be set:

        ModificationDate - The date the page was last modified, Unix time.
        MimeType         - The MIME type of the page.
        Cache            - The URL of the cached result, and its size.

    If present, the Cache value is in turn another dictionary, which will
    have the following keys:

        Url             - URL to cached data.
        Size            - Size of the cached entry, in bytes.


    Example:
        results = ws.parse_results(dom)
        for res in results:
            if res.has_key('Cache'):
                print "Cache URL: ", res['Cache']['Url']
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(WebSearch, self)._init_res_fields()
        self._res_fields.extend((('ModificationDate', "", None),
                                 ('MimeType', "", None)))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(WebSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Cache')
        if node:
            res['Cache'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                        ('Size', None, None)))
        else:
            res['Cache'] = None
        return res


#
# DOM parser for RelatedSuggestion
#
class RelatedSuggestion(dom.DOMResultParser):
    """RelatedSuggestion - DOM parser for Web Related Suggestions
    
    Simple related suggestions web service, returning a list of the
    candidate result strings. Note that the results from this service
    is slightly different compared to the other services, since each
    result can only be a string.
    """
    def _parse_result_set(self, result_set):
        """Internal method to parse one Result node"""
        cnt = 0
        for result in result_set.getElementsByTagName('Result'):
            cnt += 1
            self._results.append(self._get_text(result.childNodes))
        
        self._total_results_available = cnt
        self._total_results_returned = cnt
        if cnt > 0:
            self._first_result_position = 1


#
# DOM parser for SpellingSuggestion
#
class SpellingSuggestion(dom.DOMResultParser):
    """SpellingSuggestion - DOM parser for Web Spelling Suggestions
    
    Simple spell checking web service, there can be only zero or one
    result from the query. Also note that the results from the search
    are slightly different compared to the other services, the one
    (possible) result is just simple string (not a dictionary).
    """
    def _parse_result_set(self, result_set):
        """Internal method to parse one Result node"""
        cnt = 0
        for result in result_set.getElementsByTagName('Result'):
            cnt += 1
            self._results.append(self._get_text(result.childNodes))
        
        self._total_results_available = cnt
        self._total_results_returned = cnt
        if cnt > 0:
            self._first_result_position = 1



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
