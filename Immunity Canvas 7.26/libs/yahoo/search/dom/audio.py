"""DOM parser for Audio search results

Implement a simple DOM parser for the Yahoo Search Web Services
audio search APIs.
"""


__revision__ = "$Id: audio.py,v 1.4 2007/02/28 05:20:11 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 14:19:41 MST 2007"

from yahoo.search import dom
from yahoo.search import parser


#
# Custom DOM parser for some Audio classes. This will handle the
# "id" attribute of artists and songs etc. properly
#
class _AudioParser(dom.DOMResultParser):
    """_AudioParser - Custom DOM parser for some Audio classes
    """
    def _tags_to_dict(self, node, tags, parse_id=True):
        """This specialized version will convert the "id" attribute of
        the tag to an attribute.
        """
        res = super(_AudioParser, self)._tags_to_dict(node, tags)
        if parse_id:
            attr = node.attributes.getNamedItem('id')
            if attr:
                res['Id'] = str(attr.nodeValue)
            else:
                raise parser.XMLError("Result has no id attr")
        return res


#
# Album Search DOM parser
#
class AlbumSearch(_AudioParser):
    """AlbumSearch - DOM parser for Album Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title          - The title of the album.
        Artist         - The performer of the album, and the unique ID
        Publisher      - The publisher of the album.
        ReleaseDate    - The date of the album's release.
        Id             - Internal ID of the album, unique identifier.

    The following attributes are optional, and might not be set:

        Tracks         - Number of tracks on the album.
        Thumbnail      - The URL of a thumbnail picture of the album cover.
        RelatedAlbums  - Contains a list of related (similar) albums (IDs).

    Thumbnail is in turn another dictionary, which will have the following
    keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail, in pixels (optional).
        Width           - Width of the thumbnail, in pixels (optional).

    The two attributes Artist and RelatedAlbums are both lists of
    dictionaries, with the following two keys:

        Name            - Textual "name" value.
        Id              - Unique identifier (internal yahoo ID).


    Example:
        results = ws.parse_results()
        for res in results:
            print "%s - %s bytes" % (res.Artist.Name, res.Artist.Id)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(AlbumSearch, self)._init_res_fields()
        self._res_fields = [('Title', None, None),
                            ('Publisher', None, None),
                            ('ReleaseDate', None, None),
                            ('Tracks', 0, int),
                            ]

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(AlbumSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Thumbnail')
        if node:
            res['Thumbnail'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                            ('Height', 0, int),
                                                            ('Width', 0, int)),
                                                  parse_id=False)
        else:
            res['Thumbnail'] = None
        node = result.getElementsByTagName('Artist')
        if node:
            res['Artist'] = self._id_attribute_to_dict(node[0])
        else:
            res['Artist'] = None
        node = result.getElementsByTagName('RelatedAlbums')
        if node:
            res['RelatedAlbums'] = self._parse_list_node(node[0], 'Album')
        else:
            res['RelatedAlbums'] = None
        return res


#
# Artist Search DOM parser
#
class ArtistSearch(_AudioParser):
    """ArtistSearch - DOM parser for Artist Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Name           - The name of the artist.
        Id             - Internal ID of the artist, unique identifier.

    The following attributes are optional, and might not be set:

        Thumbnail      - The URL of the thumbnail file.
        RelatedArtists - Contains a list of related artists that fans of
                         the artist in this Result might like.
        PopularSongs   - Contains a list of popular songs by this artist.
        YahooMusicPage - The URL to link to the artist's page on the
                         Yahoo Music site. This can be empty!

    Thumbnail is in turn another dictionary, which will have the following
    keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail, in pixels (optional).
        Width           - Width of the thumbnail, in pixels (optional).

   Both RelatedArtist and PopularSongs are lists of IDs, which can be
   used as an identifier into subsequent Yahoo Audio search calls.

    Example:
        results = ws.parse_results()
        for res in results:
            print "%s - %s bytes" % (res.Name, res.YahooMusicPage)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(ArtistSearch, self)._init_res_fields()
        self._res_fields = [('Name', None, None),
                            ('YahooMusicPage', "", None),
                            ]

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(ArtistSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Thumbnail')
        if node:
            res['Thumbnail'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                            ('Height', 0, int),
                                                            ('Width', 0, int)),
                                                  parse_id=False)
        else:
            res['Thumbnail'] = None
        node = result.getElementsByTagName('RelatedArtists')
        if node:
            res['RelatedArtists'] = self._parse_list_node(node[0], 'Artist')
        else:
            res['RelatedArtists'] = None
        node = result.getElementsByTagName('PopularSongs')
        if node:
            res['PopularSongs'] = self._parse_list_node(node[0], 'Song')
        else:
            res['PopularSongs'] = None
        return res


#
# Song Search DOM parser
#
class SongSearch(_AudioParser):
    """SongSearch - DOM parser for Song Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title          - The title of the song.
        Id             - Internal ID of the song, unique identifier.
        Album          - The album from which the song was taken, and ID.
        Artist         - The performer of the album, and the unique ID.
        Publisher      - The publisher of the album.
        Length         - The length of the song in seconds.
        ReleaseDate    - The date of the album's release.
        Track          - The track number on the album.
        ClickUrl       - The URL for linking to the audio file.

    The following attributes are optional, and might not be set:

        Thumbnail      - The URL of a thumbnail picture of the album cover.

    Thumbnail is in turn another dictionary, which will have the following
    keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail, in pixels (optional).
        Width           - Width of the thumbnail, in pixels (optional).

    The two attributes Artist and RelatedAlbums are both lists of dicts,
    with the keys:

        Name            - Textual "name" value.
        Id              - Unique identifier (internal yahoo ID).


    Example:
        results = ws.parse_results()
        for res in results:
            print "%s - %s bytes" % (res.Artist.Name, res.Title)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        self._res_fields = [('Title', None, None),
                            ('Publisher', None, None),
                            ('Length', None, int),
                            ('ReleaseDate', None, None),
                            ('Track', None, int),
                            ('ClickUrl', "", None),
                            ]

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(SongSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Thumbnail')
        if node:
            res['Thumbnail'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                            ('Height', 0, int),
                                                            ('Width', 0, int)),
                                                  parse_id=False)
        else:
            res['Thumbnail'] = None
        node = result.getElementsByTagName('Artist')
        if node:
            res['Artist'] = self._id_attribute_to_dict(node[0])
        else:
            res['Artist'] = None
        node = result.getElementsByTagName('Album')
        if node:
            res['Album'] = self._id_attribute_to_dict(node[0])
        else:
            res['Album'] = None
        return res


#
# Song Download Location DOM parser
#
class SongDownloadLocation(dom.DOMResultParser):
    """SongDownloadLocation - DOM parser for Song Download Location

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Source        - The source provider for the file.
        Url           - The url for accessing the file.
        Format        - The format the file has been encoded in.

    The following attributes are optional, and might not be set:

        Price         - The price, in dollars, of the song.
        Length        - The length of the song in seconds.
        Channels      - The number of channels. Usually 1 (mono) or
                        2 (stereo).
        Restrictions  - A space-separated list of restrictions:
                          * drm denotes files with some form of digital
                            rights management.
                          * subrequired means a subscription to the
                            appropriate service is required.
                          * subnotrequired means a subscription to the
                            appropriate service is not required.
                          * win denotes files that will play on Windows.
                          * mac denotes files that will play on Macintosh.
                          * copyokay means this file may be copied.
                          * copynotokay means this file may not be copied.
                          * cdokay means this file may be burned to CD.
        Quality       - A quality metric for files found on the web. Values
                        range from 1 (worst) to 5 (best).

    Example:
        results = ws.parse_results()
        for res in results:
            print "%s - %s bytes" % (res.Name, res.YahooMusicPage)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(SongDownloadLocation, self)._init_res_fields()
        self._res_fields = [('Source', None, None),
                            ('Url', None, None),
                            ('Format', None, None),
                            ('Price', 0.0, float),
                            ('Length', 0, int),
                            ('Channels', "", None),
                            ('Restrictions', "", None),
                            ('Quality', 0, int),
                            ]


#
# Podcast Search DOM parser
#
class PodcastSearch(dom.DOMResultParser):
    """PodcastSearch - DOM parser for Podcast Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - The title of the audio file.
        Summary          - Summary text associated with the audio file.
        Url              - The URL for the audio file or stream.
        ClickUrl         - The URL for linking to the audio file.
        RefererUrl       - The URL of the web page hosting the content.
        FileSize         - The size of the file, in bytes.
        FileFormat       - One of aiff, midi, mp3, msmedia, quicktime,
                           realmedia, wav or other.
        Duration         - The duration of the audio file in seconds.
        Streaming        - Whether the audio file is streaming or not.

    The following attributes are optional, and might not be set:

        SampleSize       - The number of bits used in sampling the sound.
        Channels         - The number of channels in the audio. Usually
                           1 (mono) or 2 (stereo).
        Publisher        - The creator of the video file.
        Restrictions     - Provides any restrictions for this media
                           object. Restrictions include noframe and
                           noinline. See developer site for more info.
        Copyright        - The copyright owner.

    If present, the Thumbnail value is in turn another dictionary, which will
    have these keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail in pixels (optional).
        Width           - Width of the thumbnail in pixels (optional).


    Example:

        results = ws.parse_results(dom)
        for res in results:
            print "%s - %s bytes" % (res.Title, res.FileSize)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(PodcastSearch, self)._init_res_fields()
        self._res_fields.extend((('RefererUrl', None, None),
                                 ('FileSize', None, int),
                                 ('FileFormat', None, None),
                                 ('Streaming', None, parser.string_to_bool),
                                 ('Duration', None, float),
                                 ('SampleSize', 0, int),
                                 ('Channels', "", None),
                                 ('Publisher', "", None),
                                 ('Restrictions', "", None),
                                 ('Copyright', "", None)))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(PodcastSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Thumbnail')
        if node:
            res['Thumbnail'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                            ('Height', 0, int),
                                                            ('Width', 0, int)))
        else:
            res['Thumbnail'] = None
        return res



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
