"""Yahoo Search Web Services

---   NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE ---

     This module is deprecated, please see the documentation for

         yahoo.search

     and use the new class structures. The old DOM parser is also
     obsolote, and not distributed with this package at all. For
     documentation on the results produced by the various search
     classes, please refer to the appropriate DOM parser docs.

---   NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE NOTE ---


This module implements a set of classes and functions to work with the
Yahoo Search Web Services. All results from these services are properly
formatted XML, and this package facilitates for proper parsing of these
result sets. Some of the features include:

    * Extendandable API, with replaceable backend XML parsers, and
      I/O interface.
    * Type and value checking on search parameters, including
      automatic type conversion (when appropriate and possible)
    * Flexible return format, including DOM objects, or fully
      parsed result objects


You can either instantiate a search object directly, or use the factory
function create_search() in this module (see below). The supported classes
of searches are:
    
    VideoSearch	- Video Search
    ImageSearch	- Image Search
    WebSearch	- Web Search
    NewsSearch	- News Search
    LocalSearch	- Local Search

    RelatedSuggestion	- Web Search Related Suggestion
    SpellingSuggestion	- Web Search Spelling Suggestion

    TermExtraction - Term Extraction service
    ContextSearch  - Web Search with a context


The different sub-classes of Search supports different sets of query
parameters. They all require an application ID parameter (app_id). The
following tables describes all other allowed parameters for each of the
supported services:

                Web   Related  Spelling  Context   Term
               -----  -------  --------  -------  ------
    query       [X]     [X]       [X]      [X]      [X]
    type        [X]      .         .       [X]       .
    results     [X]     [X]        .       [X]       .
    start       [X]      .         .       [X]       .

    format      [X]      .         .        .        .
    adult_ok    [X]      .         .       [X]       .
    similar_ok  [X]      .         .       [X]       .
    language    [X]      .         .        .        .
    country     [X]      .         .        .        .
    context      .       .         .       [X]      [X]


                Image  Video  News   Local
                -----  -----  -----  -----
    query        [X]    [X]    [X]    [X]
    type         [X]    [X]    [X]     . 
    results      [X]    [X]    [X]    [X]
    start        [X]    [X]    [X]    [X]

    format       [X]    [X]     .      .
    adult_ok     [X]    [X]     .      .
    language      .      .      .     [X]
    country       .      .      .      .
    sort          .      .     [X]    [X]
    coloration   [X]     .      .      .

    radius        .      .      .     [X]
    street        .      .      .     [X]
    city          .      .      .     [X]
    state         .      .      .     [X]
    zip           .      .      .     [X]
    location      .      .      .     [X]
    longitude     .      .      .     [X]
    latitude      .      .      .     [X]


Each of these parameter is implemented as an attribute of each
respective class. For example, you can set parameters like:

    from yahoo.search.webservices import WebSearch

    app_id = "YahooDemo"
    srch = WebSearch(app_id)
    srch.query = "Leif Hedstrom"
    srch.results = 40

or, if you are using the factory function:
    
    from yahoo.search.webservices import create_search

    app_id = "YahooDemo"
    srch = create_search("Web", app_id, query="Leif Hedstrom", results=40)

or, the last alternative, a combination of the previous two:

    from yahoo.search.webservices import WebSearch

    app_id = "YahooDemo"
    srch = WebSearch(app_id, query="Leif Hedstrom", results=40)

To retrieve a certain parameter value, simply access it as any normal
attribute:

    print "Searched for ", srch.query


For more information on these parameters, and their allowed values, please
see the official Yahoo Search Services documentation available at

    http://developer.yahoo.net/

Once the webservice object has been created, you can retrieve a parsed
object (typically a DOM object) using the get_results() method:

    dom = srch.get_results()

This DOM object contains all results, and can be used as is. For easier
use of the results, you can use the built-in results factory, which will
traverse the entire DOM object, and create a list of results objects.

    results = srch.parse_results(dom)

or, by using the implicit call to get_results():

    results = srch.parse_results()
    
The default XML parser and results factories should be adequate for most
users, so use the parse_results() when possible. However, both the XML
parser and the results parser can easily be overriden. See the examples
below for details.


EXAMPLES:

This simple application will create a search object using the first
command line argument as the "type" (e.g. "web" or "news"), and all
subsequent arguments forms the query string:

    #!/usr/bin/python

    import sys
    from yahoo.search.webservices import create_search

    service = sys.argv[1]
    query = " ".join(sys.argv[2:])
    app_id = "YahooDemo"
    srch = create_search(service, app_id, query=query, results=5)
    if srch is None:
        srch = create_search("Web", app_id, query=query, results=5)

    dom = srch.get_results()
    results = srch.parse_results(dom)

    for res in results:
        url = res.Url
        summary = res['Summary']
        print "%s -> %s" (summary, url)


The same example using the PyXML 4DOM parser:

    #!/usr/bin/python

    import sys
    from yahoo.search.webservices import create_search
    from xml.dom.ext.reader import Sax2

    query = " ".join(sys.argv[2:])
    srch = create_search(sys.argv[1], "YahooDemo", query=query, results=5)

    if srch is not None:
        reader = Sax2.Reader()
        srch.install_xml_parser(reader.fromStream)
        .
        .
        .


The last example will produce the same query, but uses an HTTP proxy
for the request:

    #!/usr/bin/python

    import sys
    from yahoo.search.webservices import create_search
    import urllib2

    query = " ".join(sys.argv[2:])
    srch = create_search(sys.argv[1], "YahooDemo", query=query, results=5)

    if srch is not None:
        proxy = urllib2.ProxyHandler({"http" : "http://octopus:3128"})
        opener = urllib2.build_opener(proxy)
        srch.install_opener(opener)
        .
        .
        .


You can obviously "mix and match" as necessary here. I'm using the
installer methods above for clarity, the APIs allows you to pass those
custom handlers as arguments as well (see the documentation below).
"""

#
# Merge the new namespace into this obsolote namespace.
#
from yahoo.search.web import *
from yahoo.search.news import *
from yahoo.search.video import *
from yahoo.search.image import *
from yahoo.search.local import *
from yahoo.search.term import *

from yahoo.search import LANGUAGES
from yahoo.search import COUNTRIES
from yahoo.search import CC_LICENSES
from yahoo.search import SUBSCRIPTIONS

from yahoo.search.factory import SERVICES
from yahoo.search.factory import create_search


__revision__ = "$Id: webservices.py,v 1.32 2007/09/11 21:38:43 zwoop Exp $"
__version__ = "$Revision: 1.32 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Sep 11 15:37:37 MDT 2007"



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
