"""yahoo.search.site - Site Explorer services module

This module implements the Site Explorer web services, which can be used
gain a unique perspective on your online presence. The supported classes
of site explorer are:
    
    PageData      - Shows a list of all pages belonging to a domain
    InlinkData    - Shows the pages from other sites linking in to a page

    Update Notification  - Notify Yahoo! of changes to your site


An application ID (appid) is always required when instantiating a search
object. In addition, each search class takes different set of parameters,
as defined by this table

                  PageData  InlinkData  Update Notification
                  --------  ----------  -------------------
    query          [X]         [X]              .
    results        [X]         [X]              .
    start          [X]         [X]              .

    domain_only    [X]          .               .
    entire_site     .          [X]              .
    omit_inlinks    .          [X]              .

    url             .           .              [X]

    output         [X]         [X]              .
    callback       [X]         [X]              .


Each of these parameter is implemented as an attribute of each
respective class. For example, you can set parameters like:

    from yahoo.search.site import PageData

    srch = PageData(appid="YahooDemo")
    srch.query = "http://www.ogre.com"
    srch.results = 75

    for res in srch.parse_results():
       print res.Url
"""

import types

import yahoo.search
import yahoo.search.dom.site


__revision__ = "$Id: site.py,v 1.3 2007/02/28 05:20:09 zwoop Exp $"
__version__ = "$Revision: 1.3 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 21:54:42 MST 2007"


#
# PageData class
#
class PageData(yahoo.search._BasicSearch):
    """PageData - discover what is in the Yahoo! index

    This class implements the Page Data web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        results      - The number of results to return (1-100).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        domain_only  - Specifies whether to provide results for all
                       subdomains (such as http://search.yahoo.com for
                       http://www.yahoo.com) of the domain query, or just the
                       specifically requested domain. If the query is not a
                       domain URL (i.e. it contains path information, such as
                       http://smallbusiness.yahoo.com/webhosting/), this
                       parameter has no effect. Allowed values are 0 (default)
                       or 1.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/siteexplorer/V1/pageData.html
    """
    NAME = "pageData"
    SERVICE = "SiteExplorerService"
    _RESULT_FACTORY = yahoo.search.dom.site.PageData

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(PageData, self)._init_valid_params()
        self._valid_params.update({
            "results" : (types.IntType, 50, int, lambda x: x > -1 and x < 101,
                         "the range 1 to 100", False),
            "domain_only" : (types.IntType, 0, int, (0, 1), None, False),
            })


#
# InlinkData class
#
class InlinkData(yahoo.search._BasicSearch):
    """InlinkData - discover what pages link to your website

    This class implements the Inlink Data web service APIs. Allowed
    parameters are:
    
        query        - The query to search for (UTF-8 encoded).
        results      - The number of results to return (1-100).
        start        - The starting result position to return (1-based).
                       The finishing position (start + results - 1) cannot
                       exceed 1000.
        entire_site  - Specifies whether to provide results for the entire
                       site, or just the page referenced by the query. If the
                       query is not a domain URL (i.e. it contains a path,
                       such as http://smallbusiness.yahoo.com/webhosting/),
                       this parameter has no effect. Allowed values are
                       0 (default) or 1.
        omit_inlinks - If specified, inlinks will not be returned if they
                       are from pages in the same domain/subdomain as the
                       requested page. Allowed values are domain or
                       subdomain.
        output       - The format for the output result. If json or php is
                       requested, the result is not XML parseable, so we
                       will simply return the "raw" string.
        callback     - The name of the callback function to wrap around


    Full documentation for this service is available at:

        http://developer.yahoo.net/search/siteexplorer/V1/inlinkData.html
    """
    NAME = "inlinkData"
    SERVICE = "SiteExplorerService"
    _RESULT_FACTORY = yahoo.search.dom.site.PageData

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        super(InlinkData, self)._init_valid_params()
        self._valid_params.update({
            "results" : (types.IntType, 50, int, lambda x: x > -1 and x < 101,
                         "the range 1 to 100", False),
            "entire_site" : (types.IntType, 0, int, (0, 1), None, False),
            "omit_inlinks" : (types.StringTypes, None, str.lower,
                              ("domain", "subdomain"), None, False),
            })

#
# UpdateNotification class
#
class UpdateNotification(yahoo.search._Search):
    """UpdateNotification - Tell the Yahoo! to index your URLs

    This class implements the Update Notification web service APIs. Allowed
    parameters are:
    
        url        - The URL to submit


    Full documentation for this service is available at:

     http://developer.yahoo.com/search/siteexplorer/V1/updateNotification.html
    """
    NAME = "updateNotification"
    SERVICE = "SiteExplorerService"
    _RESULT_FACTORY = yahoo.search.dom.site.UpdateNotification

    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params = ({
            "url" : (types.StringTypes, None, None, None, None, True),
            })

#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
