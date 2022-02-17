"""DOM parser for News search results

Implement a simple DOM parser for the Yahoo Search Web Services
news search APIs.
"""


__revision__ = "$Id: news.py,v 1.2 2005/10/27 02:59:15 zwoop Exp $"
__version__ = "$Revision: 1.2 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Wed Oct 26 15:02:17 PDT 2005"

from yahoo.search import dom


#
# News Search DOM parser
#
class NewsSearch(dom.DOMResultParser):
    """NewsSearch - DOM parser for News Search
    
    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - Title of the article.
        Summary          - Summary of the text associated with the article.
        Url              - The URL for the article.
        ClickUrl         - The URL for linking to the article.
        NewsSource       - The company that distributed the news article.
        NewsSourceUrl    - The URL for the news source.
        Language         - Language of the News article.
        PubslishDate     - Publish date of the article.

    The following attributes are optional, and might not be set:

        ModificationDate - Date entry was modified.
        Thumbnail        - The URL of the thumbnail file.

    If present, the Thumbnail value is in turn another dictionary, which will
    have these keys:

        Url             - URL of the thumbnail.
        Height          - Height of the thumbnail in pixels (optional).
        Width           - Width of the thumbnail in pixels (optional).
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        super(NewsSearch, self)._init_res_fields()
        self._res_fields.extend((('NewsSource', None, None),
                                 ('NewsSourceUrl', None, None),
                                 ('Language', None, None),
                                 ('PublishDate', None, None),
                                 ('ModificationDate', "", None)))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        res = super(NewsSearch, self)._parse_result(result)
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
