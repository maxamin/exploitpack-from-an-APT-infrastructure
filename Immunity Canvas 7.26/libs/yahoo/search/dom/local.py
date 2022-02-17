"""DOM parser for Local search results

Implement a simple DOM parser for the Yahoo Search Web Services
local search APIs.
"""


__revision__ = "$Id: local.py,v 1.7 2007/02/28 05:20:11 zwoop Exp $"
__version__ = "$Revision: 1.7 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 16:57:05 MST 2007"

from yahoo.search import dom, parser
from yahoo.search.parser import ResultDict


#
# News Search DOM parser
#
class LocalSearch(dom.DOMResultParser):
    """LocalSearch - DOM parser for Local Search

    This subclass of the SearchParser extends the parser with support for
    the Result Set Map Url. This adds an extra attribute

        results.result_set_map_url

    This attribute holds a URL pointing to a Yahoo Locals map with all the
    results shown on the map.

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - Name of the result.
        Address          - Street address of the result.
        City             - City in which the result is located.
        State            - State in which the result is located.
        Phone            - Phone number of the business, if known.
        Latitude         - The latitude of the location.
        Longitude        - The longitude of the location.
        Distance         - The distance to the business or service.
        Url              - The URL for the local file or stream.
        ClickUrl         - The URL for linking to the detailed page.
        MapUrl           - The URL of a map for the address.
        Categories       - Contains all the categories in which this
                           listing is classified.

    The following attributes are optional, and might not be set:

        Rating           - Rating information (see below)
        BusinessUrl      - The URL fo the business website, if known.
        BusinessClickUrl - The URL for linking to the business website,
                           if known.

    The Rating dictionary contains the following keys:

        AverageRating     - Average score of end-user ratings for the
                            business or service. 
        TotalRatings      - The total number of ratings submitted for
                            the business or service.
        TotalReviews      - The total number of reviews submitted for
                            the business or service. Reviews can be viewed
                            at the location pointed to by the ClickUrl tag.
        LastReviewDate    - The date of the last review submitted for the
                            business or service unix timestamp format. 
        LastReviewIntro   - The first few words of the last review
                            submitted for the business or service.

    Categories is a list of tuples with

        Name   - Textual "name" value
        Id     - Unique identifier (internal yahoo ID).
        

    Example:
        results = ws.parse_results()
        for res in results:
            print "%s  is %s %s away" % (res.Title, res.Distance[0],
                                         res.Distance[1])
    """
    def __init__(self, service, res_dict=ResultDict):
        super(LocalSearch, self).__init__(service, res_dict)
        self._result_set_map_url = ""
        
    def parse_results(self, dom_object):
        """Specialized DOM parser for LocalSearch, to allow for the Map
        URL in the result.
        """
        super(LocalSearch, self).parse_results(dom_object)
        try:
            url_node = dom_object.getElementsByTagName('ResultSetMapUrl')
            self._result_set_map_url = self._get_text(url_node[0].childNodes)
        except:
            raise parser.XMLError("DOM object has no ResultSetMapUrl")

    def _get_result_set_map_url(self):
        """Get the Yahoo Locals map with all the results."""
        return self._result_set_map_url
    result_set_map_url = property(_get_result_set_map_url, None, None,
                                  "The Yahoo Locals map with all the results")
    ResultSetMapUrl = property(_get_result_set_map_url, None, None,
                               "The Yahoo Locals map with all the results")

    def _init_res_fields(self):
        """Initialize the valid result fields."""
        # Local search is special, and doesn't have all the standard
        # result fields ...
        self._res_fields = ((('Title', None, None),
                             ('Address', None, None),
                             ('City', None, None),
                             ('State', None, None),
                             ('Phone', None, None),
                             ('Latitude', None, float),
                             ('Longitude', None, float),
                             ('Url', None, None),
                             ('ClickUrl', None, None),
                             ('MapUrl', None, None),
                             ('BusinessUrl', "", None),
                             ('BusinessClickUrl', "", None)))
                                
    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(LocalSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Distance')
        if node:
            unit = node[0].getAttribute('unit')
            if unit == "":
                unit = "miles"
            res['Distance'] = (self._get_text(node[0].childNodes), unit)
        else:
            raise parser.XMLError("LocalSearch DOM object has no Distance")
        node = result.getElementsByTagName('Rating')
        if node:
            res['Rating'] = self._tags_to_dict(node[0], (('AverageRating', None, float),
                                                         ('TotalRatings', None, int),
                                                         ('TotalReviews', None, int),
                                                         ('LastReviewDate', 0, int),
                                                         ('LastReviewIntro', "", None)))
        else:
            res['Rating'] = None
        node = result.getElementsByTagName('Categories')
        if node:
            res['Categories'] = self._parse_list_node(node[0], 'Category')
        else:
            res['Categories'] = None
        return res



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
