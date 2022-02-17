"""DOM parser for Video search results

Implement a simple DOM parser for the Yahoo Search Web Services
video search APIs.
"""


__revision__ = "$Id: video.py,v 1.4 2005/10/27 18:07:59 zwoop Exp $"
__version__ = "$Revision: 1.4 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Thu Oct 27 10:47:24 PDT 2005"

from yahoo.search import parser, dom


#
# Video Search DOM parser
#
class VideoSearch(dom.DOMResultParser):
    """VideoSearch - DOM parser for Video Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - The title of the video file.
        Summary          - Summary text associated with the video file.
        Url              - The URL for the video file or stream.
        ClickUrl         - The URL for linking to the video file.
        RefererUrl       - The URL of the web page hosting the content.
        FileSize         - The size of the file, in bytes.
        FileFormat       - One of avi, flash, mpeg, msmedia, quicktime
                           or realmedia.
        Duration         - The duration of the video file in seconds.
        Streaming        - Whether the video file is streaming or not.

    The following attributes are optional, and might not be set:

        Height           - The height of the keyframe Yahoo! extracted
                           from the video, in pixels.
        Width            - The width of the keyframe Yahoo! extracted
                           from the video, in pixels.
        Channels         - Channels in the audio stream.
        Thumbnail        - The URL of the thumbnail file.
        Publisher        - The creator of the video file.
        Restrictions     - Provides any restrictions for this media
                           object. Restrictions include noframe and
                           noinline.
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
        super(VideoSearch, self)._init_res_fields()
        self._res_fields.extend((('RefererUrl', None, None),
                                 ('FileSize', None, int),
                                 ('FileFormat', None, str),
                                 ('Height', 0, int),
                                 ('Width', 0, int),
                                 ('Streaming', None, parser.string_to_bool),
                                 ('Duration', None, float),
                                 ('Channels', "", str),
                                 ('Publisher', "", None),
                                 ('Restrictions', "", str),
                                 ('Copyright', "", None)))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(VideoSearch, self)._parse_result(result)
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
