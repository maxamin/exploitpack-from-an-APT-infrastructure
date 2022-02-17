"""DOM parser for Term Extraction search results

Implement a simple DOM parser for the Yahoo Search Web Services
term extraction search APIs.
"""


__revision__ = "$Id: term.py,v 1.1 2005/10/17 01:41:47 zwoop Exp $"
__version__ = "$Revision: 1.1 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Sat Oct 15 15:44:48 PDT 2005"

from yahoo.search import dom


#
# News Search DOM parser
#
class TermExtraction(dom.DOMResultParser):
    """TermExtraction - DOM parser for Term Extraction queries
    
    Return the list of words and phrases related to the context and
    the optional query string. The results from this search are slightly
    different compared to other services, it's just a simple list of
    words and phrases.

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
