"""DOM parser for Image search results

Implement a simple DOM parser for the Yahoo Search Web Services
image search APIs.
"""


__revision__ = "$Id: image.py,v 1.5 2005/10/27 18:07:59 zwoop Exp $"
__version__ = "$Revision: 1.5 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Thu Oct 27 10:47:11 PDT 2005"

from yahoo.search import dom, parser


#
# Image Search DOM parser
#
class ImageSearch(dom.DOMResultParser):
    """ImageSearch - DOM parser for Image Search

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - The title of the image file.
        Summary          - Summary text associated with the image file.
        Url              - The URL for the image file or stream.
        ClickUrl         - The URL for linking to the image file.
        RefererUrl       - The URL of the web page hosting the content.
        FileSize         - The size of the file, in bytes.
        FileFormat       - One of bmp, gif, jpg or png.
        Thumbnail        - The URL of the thumbnail file.

    The following attributes are optional, and might not be set:

        Height           - The height of the image in pixels.
        Width            - The width of the image in pixels.
        Publisher        - The creator of the image file.
        Restrictions     - Provides any restrictions for this media
                           object. Restrictions include noframe and
                           noinline.
        Copyright        - The copyright owner.

    The Thumbnail is in turn another dictionary, which will have the
    following keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail, in pixels (optional).
        Width           - Width of the thumbnail, in pixels (optional).


    Example:
        results = ws.parse_results(dom)
        for res in results:
            print "%s - %s bytes" % (res.Title, res.FileSize)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(ImageSearch, self)._init_res_fields()
        self._res_fields.extend((('RefererUrl', None, None),
                                 ('FileSize', None, int),
                                 ('FileFormat', None, None),
                                 ('Height', 0, int),
                                 ('Width', 0, int),
                                 ('Publisher', "", None),
                                 ('Restrictions', "", None),
                                 ('Copyright', "", None)))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(ImageSearch, self)._parse_result(result)
        node = result.getElementsByTagName('Thumbnail')
        if node:
            res['Thumbnail'] = self._tags_to_dict(node[0], (('Url', None, None),
                                                            ('Height', 0, int),
                                                            ('Width', 0, int)))
        else:
            raise parser.XMLError("ImageSearch DOM object has no Thumbnail")
        return res



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
