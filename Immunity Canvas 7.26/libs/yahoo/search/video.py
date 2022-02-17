"""yahoo.search.video - Video Search services module

This module implements the the Video Search web service, to do search
queries on various video formats. There is currently only one class
implemented, VideoSearch.

An application ID (appid) is always required when instantiating a search
object. Additional parameters are documented in the VideoSearch class.

Example:

    from yahoo.search.video import VideoSearch

    srch = VideoSearch(app_id="YahooDemo", query="Yahoo", results=10)
    for res in srch.parse_results():
        print res.Title
"""

import types

import yahoo.search
import yahoo.search.dom.video


__revision__ = "$Id: video.py,v 1.6 2007/02/28 05:20:11 zwoop Exp $"
__version__ = "$Revision: 1.6 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 21:13:43 MST 2007"


#
# VideoSearch class
#
class VideoSearch(yahoo.search._CommonSearch):
    """VideoSearch - perform a Yahoo Video Search

    This class implements the Video Search web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
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
        format       - Specifies the kind of video file to search for.
        adult_ok     - The service filters out adult content by default.
                       Enter a 1 to allow adult content.
        site         - A domain to restrict your searches to (e.g.
                       www.yahoo.com). You may submit up to 30 values
                       (e.g. ["www.yahoo.com", "www.cnn.com"]).
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Supported formats are

        any         - Match all formats
        avi         - AVI
        flash       - Flash
        mpeg        - MPEG
        msmedia     - Microsoft Media
        quicktime   - Apple Quicktime
        realmedia   - Realmedia


    Full documentation for this service is available at:

        http://developer.yahoo.net/video/V1/videoSearch.html
    """
    NAME = "videoSearch"
    SERVICE = "VideoSearchService"
    _RESULT_FACTORY = yahoo.search.dom.video.VideoSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(VideoSearch, self)._init_valid_params()
        self._valid_params.update({
            "format" : (types.StringTypes, "any", str.lower,
                        ("all", "all", "avi", "flash", "mpeg", "msmedia",
                         "quicktime", "realmedia"), None, False),
            "site" : (types.StringTypes, [], None, None,
                      "a list of up to 30 domains", False),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
