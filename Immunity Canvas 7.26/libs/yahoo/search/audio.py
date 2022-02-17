"""yahoo.search.audio - Audio Search services module

This module implements the the Audio Search web service, to do search
queries on various audio formats.

The supported classes of web searches are:
    
    ArtistSearch          - Information on a particular musical performer
    AlbumSearch           - Find information about albums
    SongSearch            - Provide information about songs
    SongDownloadLocation  - Find links to various providers of a song
    PodcastSearch         - Search for a Podcast site/feed


An application ID (appid) is always required when instantiating a search
object. In addition, each search class takes different set of parameters,
as defined by this table:

             AlbumSearch  ArtistSearch  SongSearch  SongDownloadLocation
             -----------  ------------  ----------  --------------------
    type         [X]          [X]          [X]               .
    results      [X]          [X]          [X]              [X]
    start        [X]          [X]          [X]              [X]
                                         
    artist       [X]          [X]          [X]               .
    artistid     [X]          [X]          [X]               .
    album        [X]           .           [X]               .
    albumid      [X]           .           [X]               .

    song          .            .           [X]              [X]
    songid        .            .           [X]               .

    source        .            .            .               [X]

    output       [X]          [X]          [X]              [X]
    callback     [X]          [X]          [X]              [X]


Each of these parameter is implemented as an attribute of each
respective class. For example, you can set parameters like:

    from yahoo.search.audio import AlbumSearch

    srch = AlbumSearch(app_id="YahooDemo")
    srch.album = "Like"
    srch.results = 40

    for res in srch.parse_results():
       print res.Artist

The PodcastSearch service takes a different set of parameters, see the
documentation for this class for further details.
"""

import types

import yahoo.search
import yahoo.search.dom.audio


__revision__ = "$Id: audio.py,v 1.9 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.9 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 14:08:31 MST 2007"


#
# Song download sources. XXX ToDo: These need descriptions.
#
DOWNLOAD_SOURCES = {'audiolunchbox':"",
                    'artistdirect':"",
                    'buymusic':"",
                    'dmusic':"",
                    'emusic':"",
                    'epitonic':"",
                    'garageband':"",
                    'itunes':"",
                    'yahoo':"",
                    'livedownloads':"",
                    'mp34u':"",
                    'msn':"",
                    'musicmatch':"",
                    'mapster':"",
                    'passalong':"",
                    'rhapsody':"",
                    'soundclick':"",
                    'theweb':""}

               
#
# Base class for some Audio Search classes
#
class _Audio(yahoo.search._Search):
    """Yahoo Search WebService - Common Audio Search parameters

    Setup the basic CGI parameters for some Audio Search services
    Since many of these services do not take a query argument, we
    can't subclass the Basic or Common search classes.
    """
    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "artist" : (types.StringTypes, None, None, None, None, False),
            "artistid" : (types.StringTypes, None, None, None, None, False),
            "type" : (types.StringTypes, "all", str.lower,
                      ("all", "any", "phrase"), None, False),
            "results" : (types.IntType, 10, int, lambda x: x > -1 and x < 51,
                         "the range 1 to 50", False),
            "start" : (types.IntType, 1, int, lambda x: x > -1 and x < 1001,
                       "the range 1 to 1000", False),
            })

    def _get_download_sources(self):
        """Get the list of all supported download sources."""
        return DOWNLOAD_SOURCES
    download_sources = property(_get_download_sources, None, None,
                                "List of all supported download sources")


#
# AlbumSearch class
#
class AlbumSearch(_Audio):
    """AlbumSearch - perform a Yahoo Album Search

    This class implements the Album Search web service APIs, which allows
    you to find information on music albums. Supported parameters are:
    
        results    - The number of results to return (1-50).
        start      - The starting result position to return (1-based).
                     The finishing position (start + results - 1) cannot
                     exceed 1000.
        artist     - The artist or partial artist string to search for
                     (UTF-8 encoded).
        artistid   - The specific id for an artist.
        album      - The album name or partial album string to search for
                     (UTF-8 encoded).
        albumid    - The specific id for an album. Ids are internal to the
                     Music Search Service and will be returned with album
                     references. At least one of artist, artistid, album or
                     albumid is required.
        type       - The kind of search to submit:
                        * "all" returns results with all query terms.
                        * "any" resturns results with one or more of the
                          query terms.
                        * "phrase" returns results containing the query
                          terms as a phrase.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/audio/V1/albumSearch.html
    """
    NAME = "albumSearch"
    SERVICE = "AudioSearchService"
    _RESULT_FACTORY = yahoo.search.dom.audio.AlbumSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(AlbumSearch, self)._init_valid_params()
        self._valid_params.update({
            "album" : (types.StringTypes, None, None, None, None, False),
            "albumid" : (types.StringTypes, None, None, None, None, False),
            })
        self._require_oneof_params = ["artist", "artistid", "album", "albumid"]


#
# ArtistSearch class
#
class ArtistSearch(_Audio):
    """ArtistSearch - perform a Yahoo Artist Search

    This class implements the Artist Search web service APIs. Allowed
    parameters are:
    
        results    - The number of results to return (1-50).
        start      - The starting result position to return (1-based).
                     The finishing position (start + results - 1) cannot
                     exceed 1000.
        artist     - The artist or partial artist string to search for
                     (UTF-8 encoded).
        artistid   - The specific id for an artist. Ids are internal to
                     the Music Search Service and will be returned with
                     artist references. One of artist or artistid is
                     always required.
        type       - The kind of search to submit:
                        * "all" returns results with all query terms.
                        * "any" resturns results with one or more of the
                          query terms.
                        * "phrase" returns results containing the query
                          terms as a phrase.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/audio/V1/artistSearch.html
    """
    NAME = "artistSearch"
    SERVICE = "AudioSearchService"
    _RESULT_FACTORY = yahoo.search.dom.audio.ArtistSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(ArtistSearch, self)._init_valid_params()
        self._require_oneof_params = ["artist", "artistid"]


#
# SongSearch class
#
class SongSearch(_Audio):
    """AlbumSearch - perform a Yahoo Album Search

    This class implements the Album Search web service APIs, which allows
    you to find information on music albums. Supported parameters are:
    
        results    - The number of results to return (1-50).
        start      - The starting result position to return (1-based).
                     The finishing position (start + results - 1) cannot
                     exceed 1000.
        artist     - The artist or partial artist string to search for
                     (UTF-8 encoded).
        artistid   - The specific id for an artist.
        album      - The album name to search for (UTF-8 encoded).
        albumid    - The specific id for an album.
        song       - The song title to search for (UTF-8 encoded).
        songid     - The specific id for a song. At least one of artist,
                     artistid, album, albumid, song or songid is required.
        type       - The kind of search to submit:
                        * "all" returns results with all query terms.
                        * "any" resturns results with one or more of the
                          query terms.
                        * "phrase" returns results containing the query
                          terms as a phrase.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/audio/V1/songSearch.html
    """
    NAME = "songSearch"
    SERVICE = "AudioSearchService"
    _RESULT_FACTORY = yahoo.search.dom.audio.SongSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(SongSearch, self)._init_valid_params()
        self._valid_params.update({
            "album" : (types.StringTypes, None, None, None, None, False),
            "albumid" : (types.StringTypes, None, None, None, None, False),
            "song" : (types.StringTypes, None, None, None, None, False),
            "songid" : (types.StringTypes, None, None, None, None, False),
            })
        self._require_oneof_params = ["artist", "artistid", "album", "albumid",
                                      "song", "songid"]


#
# SongDownlocaLocation class
#
class SongDownloadLocation(_Audio):
    """SongDownloadLocation - find places to download songs

    This class implements the Song Download Location web service APIs.
    Allowed parameters are:
    
        songid     - The specific id for a song.
        results    - The number of results to return (1-50).
        start      - The starting result position to return (1-based). The
                     finishing position (start + results - 1) cannot exceed
                     1000.
        source     - The source of the download. You may specify multiple
                     values, e.g. ["yahoo", "itunes"].
        results    - The number of results to return (1-50).
        start      - The starting result position to return (1-based).
                     The finishing position (start + results - 1) cannot
                     exceed 1000.


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/audio/V1/artistSearch.html
    """
    NAME = "songDownloadLocation"
    SERVICE = "AudioSearchService"
    _RESULT_FACTORY = yahoo.search.dom.audio.SongDownloadLocation

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "songid" : (types.StringTypes, None, None, None, None, True),
            "results" : (types.IntType, 10, int, lambda x: x > -1 and x < 51,
                         "the range 1 to 50", False),
            "start" : (types.IntType, 1, int, lambda x: x > -1 and x < 1001,
                       "the range 1 to 1000", False),
            "source" : (types.StringTypes, [], str.lower,
                        self.download_sources.keys(), None, False),
            })


#
# PodcastSearch class
#
class PodcastSearch(yahoo.search._CommonSearch):
    """PodcastSearch - perform a Yahoo Podcast Search

    This class implements the Podcast Search web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        type         - The kind of search to submit (all, any or phrase).
        results      - The number of results to return (1-50).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        format       - Specifies the kind of audio file to search for.
        adult_ok     - The service filters out adult content by default.
                       Enter a 1 to allow adult content.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around
                       the JSON data.


    Supported formats are

        all       - All formats (default)
        aiff      - AIFF
        midi      - MIDI file
        mp3       - MP3 (MPEG-3) format
        msmedia   - Microsoft media
        quicktime - Apple QuickTime
        realmedia - Real media
        wav       - Wave file
        other     - Other


    Full documentation for this service is available at:

        http://developer.yahoo.net/audio/V1/podcastSearch.html
    """
    NAME = "podcastSearch"
    SERVICE = "AudioSearchService"
    _RESULT_FACTORY = yahoo.search.dom.audio.PodcastSearch

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(PodcastSearch, self)._init_valid_params()
        self._valid_params.update({
            "format" : (types.StringTypes, "any", str.lower,
                        ("all", "any", "aiff", "midi", "msmedia", "quicktime",
                         "realmedia", "wav", "other"), None, False),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
