"""yahoo.search.image - Image Search services module

This module implements the the Image Search web service, to do search
queries on various image formats. There is currently only one class
implemented, ImageSearch.

An application ID (appid) is always required when instantiating a search
object. Additional parameters are documented in the ImageSearch class.

Example:

    from yahoo.search.image import ImageSearch

    srch = ImageSearch(app_id="YahooDemo", query="Yahoo")
    srch.results = 10

    for res in srch.parse_results():
       print res.Thumbnail.Url
"""

import types

import yahoo.search
import yahoo.search.dom.image


__revision__ = "$Id: image.py,v 1.4 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 14:51:16 MST 2007"


#
# ImageSearch class
#
class ImageSearch(yahoo.search._CommonSearch):
    """ImageSearch - perform a Yahoo Image Search

    This class implements the Image Search web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        type         - The kind of search to submit (all, any or phrase).
        results      - The number of results to return (1-50).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        type         - The kind of search to submit:
                          * "all" returns results with all query terms.
                          * "any" resturns results with one or more of the
                            query terms.
                          * "phrase" returns results containing the query
                            terms as a phrase.
        format       - Specifies the kind of image file to search for.
        adult_ok     - The service filters out adult content by default.
                       Enter a 1 to allow adult content.
        coloration   - The coloration type of the images (default, bw or
                       color).
        site         - A domain to restrict your searches to (e.g.
                       www.yahoo.com). You may submit up to 30 values
                       (e.g. ["www.yahoo.com", "www.cnn.com"]).
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Supported formats are

        any     - Any format
        bmp     - Bitmap (windows)
        gif     - GIF
        jpeg    - JPEG
        png     - PNG


    Full documentation for this service is available at:

        http://developer.yahoo.net/image/V1/imageSearch.html
    """
    NAME = "imageSearch"
    SERVICE = "ImageSearchService"
    _RESULT_FACTORY = yahoo.search.dom.image.ImageSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(ImageSearch, self)._init_valid_params()
        self._valid_params.update({
            "format" : (types.StringTypes, "any", str.lower,
                        ("all", "any", "bmp", "gif", "jpeg", "png"), None,
                        False),
            "coloration" : (types.StringTypes, "default", str.lower,
                            ("default", "bw", "color", "colour"), None, False),
            "site" : (types.StringTypes, [], None, None,
                      "a list of up to 30 domains", False),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
