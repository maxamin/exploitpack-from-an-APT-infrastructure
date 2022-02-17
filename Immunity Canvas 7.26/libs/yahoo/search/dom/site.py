"""DOM parser for Site Explorer results

Implement a simple DOM parsers for the Yahoo Search Web Services site
explorer APIs. This provides parser for the following classes:

    PageData      - Shows a list of all pages belonging to a domain
    InlinkData    - Shows the pages from other sites linking in to a page
"""


__revision__ = "$Id: site.py,v 1.3 2007/02/28 23:21:30 zwoop Exp $"
__version__ = "$Revision: 1.3 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Wed Feb 28 16:21:14 MST 2007"

from yahoo.search import dom


#
# DOM parser for PageData and InlinkData (same schema)
#
class PageData(dom.DOMResultParser):
    """PageData - DOM parser for PageData results

    Each result is a dictionary populated with the extracted data from the
    XML results. The following keys are always available:

        Title            - The title of the web page.
        Url              - The URL for the web page.
        ClickUrl         - The URL for linking to the page.


    Example:
        results = ws.parse_results(dom)
        for res in results:
            print "%s - %s" % (res.Title, res.Url)
    """
    def _init_res_fields(self):
        """Initialize the valid result fields."""
        self._res_fields = [('Title', None, None),
                            ('Url', None, None),
                            ('ClickUrl', None, None)]


#
# DOM parser for UpdateNotification
#
class UpdateNotification(dom.DOMResultParser):
    """UpdateNotification - DOM parser for Site Update Notification
    
    The return value for this is always a list with one single
    element, a dictionary with

        Success    - Did we succeed or not (True or False)
        Error      - In case of a failure, the error message
    """
    def parse_results(self, dom_object):
        """Internal method to parse one Result node"""
        res = self._res_dict()
        try:
            success = dom_object.getElementsByTagName('Success')[0]
            error = None
        except:
            success = None
            error = dom_object.getElementsByTagName('Error')[0]

        if success:
            res['Success'] = True
            res['Error'] = None
        elif error:
            res['Success'] = False
            try:
                message = error.getElementsByTagName('Message')[0]
                res['Error'] = self._get_text(message.childNodes)
            except:
                res['Error'] = "Unknown"
        else:
            res['Success'] = False
            res['Error'] = "Unknown"

        self._total_results_available = 1
        self._total_results_returned = 1
        self._first_result_position = 1
        self._results.append(res)



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
