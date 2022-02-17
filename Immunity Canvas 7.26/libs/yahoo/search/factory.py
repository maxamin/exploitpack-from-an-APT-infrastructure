"""Search Factory - simple API to create search objects

This module implements a few convenience functions to make it easy and safe
to create search objects. This is not the most efficient way to use the web
services, but it's convenient. Future releases of the APIs will hopefully
also make this factory implementation less cumbersome.

"""

from yahoo.search import *


__revision__ = "$Id: factory.py,v 1.11 2007/09/11 21:38:43 zwoop Exp $"
__version__ = "$Revision: 1.11 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Sep 11 15:33:28 MDT 2007"


#
# This is a "convenience" dictionary, providing a (very) short
# description of all available Search classes. The factory function
# uses this dictionary to make a "simple" interface to instantiate
# and configure a search object in one call.
#
SERVICES = {
    'video':(video.VideoSearch, "Video Search"),
    'image':(image.ImageSearch, "Image Search"),
    'web':(web.WebSearch, "Web Search"),
    'context':(web.ContextSearch, "Contextual Web Search"),
    'related':(web.RelatedSuggestion, "Web Search Related Suggestion"),
    'spelling':(web.SpellingSuggestion, "Web Search Spelling Suggestion"),
    'news':(news.NewsSearch, "News Search"),
    'local':(local.LocalSearch, "Local Search"),
    'term':(term.TermExtraction, "Term extraction service"),
    'artist':(audio.ArtistSearch, "Information on a musical performer"),
    'album':(audio.AlbumSearch, "Search for a specific music album"),
    'song':(audio.ArtistSearch, "Search for a music song"),
    'songdownload':(audio.SongDownloadLocation, "Find song download locations"),
    'podcast':(audio.PodcastSearch, "Search for a Podcast site/feed"),
    'pagedata':(site.PageData, "Find all pages belonging to a domain"),
    'inlinkdata':(site.InlinkData, "Show pages linking to a specific page"),
    }


#
# Create a search object, using some convenient argument "parsing"
#
def create_search(name, app_id, xml_parser=None, result_factory=None,
                  debug_level=0, **args):
    """Create a Yahoo Web Services object, and configure it

    This is a simple "factory" function to instantiate and configure
    a Yahoo Web Services object. For example:

        app_id = "YahooDemo"
        srch = create_search("Web", app_id, query="Yahoo", results=4)
        if srch is not None:
            dom = srch.get_results()

    The first argument is one of the following "classes" of searches:

        Web	       - Web search
        Context        - Contextual Web search
        Related	       - Web search Related Suggestions
        Spelling       - Web search Spelling Suggestions

        Video	       - Video search
        Image	       - Image search
        News	       - News article search
        Local	       - Local search
        Term           - Term extraction service

        Artist         - Find information on a musical performer
        Album          - Find information about albums
        Song           - Provide information about songs
        SongDownload   - Find links to various song providers of a song
        Podcast        - Search for a Podcast site/feed

        PageData       - Find all pages belonging to a domain
        InlinkData     - Show pages linking to a specific page


    The second argument, app_id (or appid), is an application specific
    identifier, provided by Yahoo. The web services will not accept any
    requests without a proper AppID.

    All other arguments must be valid named arguments, and the allowed
    set of parameters depends on the specific class of search being
    instantiated. See http://developer.yahoo.net/search/ for a more
    comprehensive list and documentation of allowed parameters for all
    types of searches.
    """

    name = name.lower()
    if not SERVICES.has_key(name):
        return None

    obj = SERVICES[name][0](app_id, xml_parser=xml_parser,
                            result_factory=result_factory,
                            debug_level=debug_level)
    if obj and args:
        obj.set_params(args)
    return obj



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
