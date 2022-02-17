"""yahoo.search.local - Local Search services module

This module implements the the Local Search web service, to do search
queries on various local formats. There is currently only one class
implemented, LocalSearch.

An application ID (appid) is always required when instantiating a search
object. Additional parameters are documented in the LocalSearch class.

Example:

    from yahoo.search.local import LocalSearch

    srch = LocalSearch(app_id="YahooDemo", zip="94019", query="BevMo")
    srch.results = 1

    for res in srch.parse_results():
       print res.MapUrl
"""

import types

import yahoo.search
import yahoo.search.dom.local


__revision__ = "$Id: local.py,v 1.4 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 17:04:24 MST 2007"


#
# LocalSearch class
#
class LocalSearch(yahoo.search._BasicSearch):
    """LocalSearch - perform a Yahoo Local Search

    This class implements the Local Search web service APIs. Allowed
    parameters are:
    
        query         - The query to search for. Using a query of "*"
                        returns all values that match other criteria in the
                        search (category, radius, and so on).
        listing_id    - The id associated with a specific business listing.
                        It corresponds with the id attribute of Result
                        entities. At least one of query or listing id must
                        be specified.
        results       - The number of results to return (1-20).
        start         - The starting result position to return (1-based).
                        The finishing position (start + results - 1) cannot
                        exceed 1000.
        sort          - Sorts the results by the chosen criteria.
        radius        - How far from the specified location to search for
                        the query terms.
        street        - Street name. The number is optional.
        city          - City name.
        state         - The United States state. You can spell out the
                        full state name or you can use the two-letter
                        abbreviation.
        zip           - The five-digit zip code, or the five-digit code
                        plus four-digit extension.
        location      - Free form field for location (see below).
        latitude      - Latitude of the starting location (-90.0 - 90.0).
        longitude     - Longitude of the starting location (-180.0 - 180.0).
        category      - The id of a category to search in. This id
                        corresponds to the id attribute of the Category
                        entity. If you specify multiple categories, results
                        are taken from entries that appear in all of the
                        specified categories.
        omit_category  - The id of a category to omit results from. Multiple
                         categories may be omitted, and a result will not be
                         returned if it appears in any of the specified
                         categories.
        minimum_rating - The minimum average rating (on a five point scale)
                         for a result. If this is specified, no results
                         without ratings will be returned.
        output         - The format for the output result. If json or php is
                         requested, the result is not XML parseable, so we
                         will simply return the "raw" string.
        callback       - The name of the callback function to wrap around
                         the JSON data.


    If both latitude and longitude are specified, they will take priority
    over all other location data. If only one of latitude or longitude is
    specified, both will be ignored.

    The sort parameter is one of

        relevance
        title
        distance
        rating

    The free text of the location parameter can hold any of

        * city, state
        * city,state, zip
        * zip
        * street, city, state
        * street, city, state, zip
        * street, zip

    If location is specified, it will take priority over the individual
    fields in determining the location for the query. City, state and zip
    will be ignored.
                        

    Full documentation for this service is available at:

        http://developer.yahoo.net/search/local/V3/localSearch.html
    """
    NAME = "localSearch"
    SERVICE = "LocalSearchService"
    VERSION = "V3"
    SERVER = "local.yahooapis.com"
    _RESULT_FACTORY = yahoo.search.dom.local.LocalSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(LocalSearch, self)._init_valid_params()
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, False),
            "listing_id" : (types.StringTypes, None, None, None, None, False),
            "results" : (types.IntType, 10, int, range(1, 21),
                         "the range 1 to 20", False),
            "sort" : (types.StringTypes, "relevance", str.lower,
                      ("relevance", "title", "distance", "rating"), None, False),
            "radius" : (types.FloatType, None, float, None, None, False),
            "street" : (types.StringTypes, None, None, None, None, False),
            "city" : (types.StringTypes, None, None, None, None, False),
            "state" : (types.StringTypes, None, None, None, None, False),
            "zip" : (types.StringTypes, None, None, None, None, False),
            "location" : (types.StringTypes, None, None, None, None, False),
            "latitude" : (types.FloatType, None, float,
                          lambda x: x > (-90) and x < 90,
                          "-90 < val < 90", False),
            "longitude" : (types.FloatType, None, float,
                           lambda x: x > (-180) and x < 180,
                           "-180 < val < 180", False),
            "category" : (types.IntType, [], int, None, "a list of integers", False),
            "omit_category" : (types.IntType, [], int, None, "a list of integers", False),
            "minimum_rating" : (types.IntType, None, int, range(1, 6),
                                "the range 1 to 5", False),
            })

        self._require_oneof_params = ["query", "listing_id"]


#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
