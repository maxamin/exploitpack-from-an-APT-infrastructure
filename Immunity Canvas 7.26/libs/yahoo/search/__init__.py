"""Yahoo Search Web Services

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
function create_search() from the factory module. The supported classes
of searches are:
    
    NewsSearch	   - News article search
    VideoSearch	   - Video and movie search
    ImageSearch	   - Image search
    LocalSearch	   - Local area search

    WebSearch	        - Web search
    ContextSearch       - Web search with a context
    RelatedSuggestion	- Web search Related Suggestion
    SpellingSuggestion	- Web search Spelling Suggestion

    TermExtraction - Term Extraction service

    AlbumSearch    - Find information about albums
    ArtistSearch   - Information on a particular musical performer
    SongDownload   - Find links to various song providers of a song
    PodcastSearch  - Search for a Podcast site/feed
    SongSearch     - Provide information about songs

    PageData       - Shows a list of all pages belonging to a domain
    InlinkData     - Shows the pages from other sites linking to a page


The different sub-classes of search supports different sets of query
parameters. For details on all allowed parameters, please consult the
specific module documentation.

Each of these parameter is implemented as an attribute of each
respective class. For example, you can set parameters like:

    from yahoo.search.web import WebSearch

    app_id = "YahooDemo"
    srch = WebSearch(app_id)
    srch.query = "Leif Hedstrom"
    srch.results = 40

or, if you are using the factory function:
    
    from yahoo.search.factory import create_search

    app_id = "YahooDemo"
    srch = create_search("Web", app_id, query="Leif Hedstrom", results=40)
    if srch is not None:
        # srch object ready to use
        ...
    else:
        print "error"

or, the last alternative, a combination of the previous two:

    import yahoo.search.web

    app_id = "YahooDemo"
    srch = web.WebSearch(app_id, query="Leif Hedstrom", results=40)

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
below for details. More information about the DOM parsers are available
in the yahoo.search.dom module, and it's subclasses.


EXAMPLES:

This simple application will create a search object using the first
command line argument as the "type" (e.g. "web" or "news"), and all
subsequent arguments forms the query string:

    #!/usr/bin/python

    import sys
    from yahoo.search.factory import create_search

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
    from yahoo.search.factory import create_search
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
    from yahoo.search.factory import create_search
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

__revision__ = "$Id: __init__.py,v 1.19 2007/09/11 21:38:43 zwoop Exp $"
__version__ = "$Revision: 1.19 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Sep 11 15:32:26 MDT 2007"


import urllib
import urllib2
import types
import re
import time
#CANVAS Change
from libs.yahoo.search import debug

__revision__ = "$Id: __init__.py,v 1.19 2007/09/11 21:38:43 zwoop Exp $"
__version__ = "$Revision: 1.19 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Thu Jul  7 14:22:16 PDT 2005"


#
# List of all sub-packages that we expose directly
#
__all__ = ["web", "news", "video", "image", "local", "term",
           "audio", "site"]


#
# List of all supported languages.
#
LANGUAGES = {'default':"english", 'ar':"arabic", 'bg':"bulgarian",
             'ca':"catalan", 'szh':"chinese-simplified",
             'tzh':"chinese-traditional", 'hr':"croatian", 'cs':"czech",
             'da':"danish", 'nl':"dutch", 'en':"english", 'et':"estonian",
             'fi':"finnish", 'fr':"french", 'de':"german", 'el':"greek",
             'he':"hebrew", 'hu':"hungarian", 'is':"icelandic",
             'id':"indonesian", 'it':"italian", 'ja':"japanese", 'ko':"korean",
             'lv':"latvian", 'lt':"lithuanian", 'no':"norwegian", 'fa':"persian",
             'pl':"polish", 'pt':"portuguese", 'ro':"romanian", 'ru':"russian",
             'sk':"slovak", 'sr':"serbian", 'sl':"slovenian", 'es':"spanish",
             'sv':"swedish", 'th':"thai", 'tr':"turkish"}


#
# List of all supported countries.
#
COUNTRIES = {'default':"any", 'any':"any", 'ar':"Argentina", 'au':"Australia",
             'at':"Austria", 'be':"Belgium", 'br':"Brazil", 'ca':"Canada",
             'cn':"China", 'cz':"Czechoslovakia", 'dk':"Denmark", 'fi':"Finland",
             'fr':"France", 'de':"Germany", 'it':"Italy", 'jp':"Japan",
             'kr':"Korea", 'nl':"Netherlands", 'no':"Norway", 'pl':"Poland",
             'rf':"Russian Federation", 'es':"Spain",'se':"Sweden",
             'ch':"Switzerland", 'tw':"Taiwan", 'uk':"United Kingdom",
             'us':"United States"}

#
# List of all supported regions.
#
REGIONS = { 'default':"us", 'ar':"Argentina", 'au':"Australia", 'at':"Austria",
            'br':"Brazil", 'ca':"Canada", 'ct':"Catalan", 'dk':"Denmark",
            'fi':"Finland", 'fr':"France", 'de':"Germany", 'in':"India",
            'id':"Indonesia", 'it':"Italy", 'my':"Malaysia", 'mx':"Mexico",
            'nl':"Netherlands", 'no':"Norway", 'ph':"Phillipines",
            'ru':"Russian Federation", 'sg':"Singapore", 'es':"Spain",
            'se':"Sweden", 'ch':"Switzerland", 'th':"Thailand",
            'uk':"United Kingdom & Ireland", 'us':"United States (yahoo.com)"}


#
# List of all Creative Content licenses.
#
CC_LICENSES = {'cc_any':"Any",
               'cc_commercial':"Commercial",
               'cc_modifiable':"Modifiable"}


#
# List of all subscription types
#
SUBSCRIPTIONS = {'cr':"Consumer Reports",
                 'ft':"FT.com",
                 'forrester':"Forrester Research",
                 'ieee':"IEEE publications",
                 'nejm':"New England Journal of Medicine",
                 'thestreet':"TheStreet.com",
                 'wsj':"Wall Street Journal"}


#
# Regular expressions
#
CALLBACK_REGEX = re.compile("^[a-zA-Z0-9\.\[\]\_]+$")


#
# Exceptions and error handling
#
class Error(Exception):
    """Base class for all Yahoo Web Services exceptions."""

class ParameterError(Error):
    """A parameter is missing, or has bad value"""
    pass

class ServerError(Error):
    """The Yahoo server is unavailable."""
    pass

class ClassError(Error):
    """This can only occur if the APIs aren't installed or configured
    properly. If it happens, please contact the author."""

class SearchError(Error):
    """An exception/error occured in the search."""
    def __init__(self, err):
        Error.__init__(self, err)
        self.msg = "unknown error"
        for line in err.readlines():
            start = line.find("<Message>")
            if start > -1:
                stop = line.find("</Message>")
                if stop > -1:
                    self.msg = line[start+9:stop]

    def __str__(self):
        return self.msg


#
# First a couple of base classes for the Search services. Most of them
# are almost identical, so good candidates to sub-class one of these.
#
class _Search(debug.Debuggable, object):
    """Yahoo Search WebService - base class

    This class implements the core functionality of all Yahoo Search
    Services.
    """
    NAME = "Search"
    SERVICE = "Search"
    PROTOCOL = "http"
    SERVER = "search.yahooapis.com"
    VERSION = "V1"
    METHOD = "GET"
    _NEXT_QID = 1
    _RESULT_FACTORY = None

    def __init__(self, app_id, opener=None, xml_parser=None,
                 result_factory=None, debug_level=0, **args):
        """The app_id is a required argument, the Yahoo search services will
        not accept requests without a proper app_id. A valid app_id is a
        combination of 8 - 40 characters, matching the regexp

            "^[a-zA-Z0-9 _()\[\]*+\-=,.:\\\@]{8,40}$"

        Please visit http://developer.yahoo.net/search/ to request an App ID
        for your own software or application.
            
        Four optional arguments can also be passed to the constructor:
        
            opener         - Opener for urllib2
            xml_parser     - Function to parse XML (default: minidom)
            result_factory - Result factory class (default: none)
            debug_devel    - Debug level (if any)

        All other "named" arguments are passed into as a dictionary to the
        set_params() method.

        The result factory is specific to the particular web service used,
        e.g. the different Yahoo Search services will each implement their
        own factory class.

        Both of these settings can be controlled via their respective
        install method (see below).
        """
        super(_Search, self).__init__(debug_level)
        self._service = {'name' : self.NAME,
                         'protocol' :  self.PROTOCOL,
                         'server' : self.SERVER,
                         'version' : self.VERSION,
                         'service' : self.SERVICE}

        self._app_id = None
        self.app_id = app_id
        self._require_oneof_params = []
        self._urllib_opener = opener
        self._xml_parser = xml_parser
        if result_factory:
            self._result_factory = result_factory
        else: 
            self._result_factory = self._RESULT_FACTORY

        if self._xml_parser is None:
            import xml.dom.minidom
            self._xml_parser = xml.dom.minidom.parse
        self._default_xml_parser = self._xml_parser

        self._qid = self._NEXT_QID
        self._NEXT_QID += 1

        # All Search APIs now supports "output" and "callback".
        self._valid_params = {
            "output" : (types.StringTypes, "xml", str.lower,
                        ("xml", "json", "php"), None, False),
            "callback" : (types.StringTypes, None, None,
                          lambda x: CALLBACK_REGEX.match(x) is not None,
                          "the characters A-Z a-z 0-9 . [] and _.",
                          False),
            }

        self._init_valid_params()
        self._params = {}
        if args:
            self.set_params(args)

    # Implement the attribute handlers, to avoid confusion
    def __setattr__(self, name, value):
        if (hasattr(getattr(self.__class__, name, None), '__set__') or
              name[0] == '_'):
            super(_Search, self).__setattr__(name, value)
        else:
            # Special case for "output", since we need to disable the
            # XML parser as well.
            if (name == "output"):
                if (value in ("json", "php")):
                    self._xml_parser = None
                else:
                    self._xml_parser = self._default_xml_parser
            self.set_param(name, value)

    def __getattr__(self, name):
        if (hasattr(getattr(self.__class__, name, None), '__get__') or
              name[0] == '_'):
            return super(_Search, self).__getattr__(name)
        else:
            return self.get_param(name)

    def _init_valid_params(self):
        """Initialize the valid params, this is a virtual function and
        should be overriden properly."""
        err = """Yahoo Search Service class %s must implement a \
_init_valid_params()""" % (self.svc_name)
        raise ClassError(err)

    def reset(self):
        """Reset all the parameter values for the object instance."""
        self._params = {}

    def _get_svc_name(self):
        """Get the descriptive service name."""
        return self._service['name']
    def _set_svc_name(self, value):
        """Set the descriptive service name."""
        self._service['name'] = value
    svc_name = property(_get_svc_name, _set_svc_name, None,
                        "Descriptive name of the service")

    def _get_svc_protocol(self):
        """Get the service protocol (e.g. HTTP)."""
        return self._service['protocol']
    def _set_svc_protocol(self, value):
        """Set the service protocol (must be supported)."""
        self._service['protocol'] = value
    svc_protocol = property(_get_svc_protocol, _set_svc_protocol, None,
                            "Service protocol (e.g. HTTP)")

    def _get_svc_service(self):
        """Get the URL path for the service."""
        return self._service['service']
    def _set_svc_service(self, value):
        """Set the URL path for the service."""
        self._service['service'] = value
    svc_service = property(_get_svc_service, _set_svc_service, None,
                           "Service path")

    def _get_svc_server(self):
        """Get the service server name or IP."""
        return self._service['server']
    def _set_svc_server(self, value):
        """Set the service server name or IP."""
        self._service['server'] = value
    svc_server = property(_get_svc_server, _set_svc_server, None,
                          "Service server name or IP")

    def _get_svc_version(self):
        """Get the service version string."""
        return self._service['version']
    def _set_svc_version(self, value):
        """Set the service version string."""
        self._service['version'] = value
    svc_version = property(_get_svc_version, _set_svc_version, None,
                           "Service version string")

    def _get_app_id(self):
        """Get the application ID."""
        return self._app_id
    def _set_app_id(self, app_id):
        """Set the application ID, which is required."""
        if isinstance(app_id, types.StringTypes):
            self._app_id = app_id
        else:
            raise ValueError("""`app_id' can contain \
a-zA-Z0-9 _()\[\]*+\-=,.:\\\@ (8-40 char long)""")
    app_id = property(_get_app_id, _set_app_id, None,
                      "Application ID (issued by Yahoo), same ass appid")
    appid = property(_get_app_id, _set_app_id, None,
                     "Application ID (issued by Yahoo)")

    # Manage service parameters
    def set_params(self, args):
        """Set one or several query parameters from a dictionary"""
        for (param, value) in args.items():
            self.set_param(param, value)

    def get_param(self, param):
        """Get the value of a query parameter, or the default value if unset"""
        if not self._valid_params.has_key(param):
            err = "`%s' is not a valid parameter for `%s'" % (
                param, self._service['name'])
            raise ParameterError(err)
        if self._params.has_key(param):
            return self._params[param]
        else:
            return self._valid_params[param][1]

    #
    # The valid_params is a list with the following elements:
    #   [0] - Allowed data type (e.g. types.StringTypes)
    #   [1] - Default value (e.g. 10)
    #   [2] - Data conversion/casting function (e.g. int)
    #   [3] - List of valid values -or- validation function
    #   [4] - Help text for error messages
    #   [5] - Boolean indicating if the parameter is required
    #
    def set_param(self, param, value):
        """Set the value of a query parameter"""
        if not self._valid_params.has_key(param):
            err = "`%s' is not a valid parameter for `%s'" % (
                param, self._service['name'])
            raise ParameterError(err)
        pinfo = self._valid_params[param]
        if value is None:
            err = "`%s' can not have an undefined value" % (param)
            raise ValueError(err)

        # Do explicit type conversions (if possible)
        if pinfo[2] is not None:
            try:
                if isinstance(value, (types.ListType, types.TupleType)):
                    value = [pinfo[2](val) for val in value]
                    # ToDo XXX: Should we make sure each value is unique?
                else:
                    value = pinfo[2](value)
            except ValueError:
                value = value
        # Check the type validity of the value
        err = False
        if isinstance(value, (types.ListType, types.TupleType)):
            for val in value:
                if not isinstance(val, pinfo[0]):
                    err = True
                    break
        elif not isinstance(value, pinfo[0]):
            err = True
        if err:
            raise TypeError("`%s' only takes values of type %s" % (
                param, str(pinfo[0])))

        # Check validity of the value (if possible)
        err = False
        if callable(pinfo[3]):
            if isinstance(value, (types.ListType, types.TupleType)):
                for val in value:
                    if not pinfo[3](val):
                        err = True
                        break
            else:
                if not pinfo[3](value):
                    err = True
        elif isinstance(pinfo[3], (types.TupleType, types.ListType)):
            if isinstance(value, (types.ListType, types.TupleType)):
                for val in value:
                    if not val in pinfo[3]:
                        err = True
                        break
            elif not value in pinfo[3]:
                err = True
        if err:
            if pinfo[4] is not None:
                hlp = pinfo[4]
            else:
                hlp = str(pinfo[3])
            raise ValueError("`%s' only handles values in: %s" % (param, hlp))

        # Update the parameter only if it's different from the default
        if value != pinfo[1]:
            self._params[param] = value
        elif self._params.has_key(param):
            self._params.pop(param)

    def get_valid_params(self):
        """Return a list of all valid parameters for this search"""
        return self._valid_params.keys()

    def missing_params(self):
        """Validate that the search object is propertly setup with all
        required parameters etc. This is called automatically before a
        search is actually performed, but you can also call it manually
        if desired. It will return a list of zero or more paramters that
        are missing.
        """
        ret = []
        for (param, pinfo) in self._valid_params.items():
            if pinfo[5]:
                if (not self._params.has_key(param) or
                    not self._params[param]):
                    ret.append(param)
        # Check "require_oneof" list, if necessary
        if len(ret) == 0:
            for param in self._require_oneof_params:
                if self._params.has_key(param):
                    return []
            return self._require_oneof_params
        else:
            return ret

    def _get_languages(self):
        """Get the list of all supported languages."""
        return LANGUAGES
    languages = property(_get_languages, None, None,
                         "List of all supported languages")

    def _get_countries(self):
        """Get the list of all supported contry codes."""
        return COUNTRIES
    countries = property(_get_countries, None, None,
                         "List of all supported county codes")

    def _get_regions(self):
        """Get the list of all supported region codes."""
        return REGIONS
    regions = property(_get_regions, None, None,
                       "List of all supported region codes")

    def _get_cc_licenses(self):
        """Get the list of all supported CC licenses."""
        return CC_LICENSES
    cc_licenses = property(_get_cc_licenses, None, None,
                           "List of all supported Creative Commons licenses")

    def _get_subscriptions(self):
        """Get the list of supported premium subscriptions."""
        return SUBSCRIPTIONS
    subscriptions = property(_get_subscriptions, None, None,
                             "List of all supported premium subscriptions")

    # Manage (install) the Opener, XML parser and result factory (parser)
    def install_opener(self, opener):
        """Install a URL opener (for use with urllib2), overriding the
        default opener. This is rarely required.
        """
        self._urllib_opener = opener
        
    def install_xml_parser(self, xml_parser):
        """Install an XML parser that will be used for all results for this
        object. The parser is expected to "read" the data from the supplied
        stream argument. To uninstall the parser (e.g. to make sure we
        return raw XML data) simply call this method with an argument of
        None.
        """
        self._default_xml_parser = xml_parser
        self._xml_parser = xml_parser

    def install_result_factory(self, result_factory):
        """Install a python class (not an instance!) that should be used as a
        factory for creating result(s) objects.
        """
        self._result_factory = result_factory

    # Methods working on connection handling etc.
    def encode_params(self):
        """URL encode the list of parameter values."""
        params = self._params.copy()
        params.update({'appid' : self._app_id})
        return urllib.urlencode(params, 1)

    def get_url(self, with_params=True):
        """Return the URL for this request object"""
        
        url = "%s://%s/%s/%s/%s" % (self._service['protocol'],
                                    self._service['server'],
                                    self._service['service'],
                                    self._service['version'],
                                    self._service['name'])
        if with_params:
            return "%s?%s" % (url, self.encode_params())
        else:
            return url

    def open(self, opener=None, retries=2):
        """Open a connection to the webservice server, and request the URL.
        The return value is a "stream", which can be read calling the
        read(), readline() or readlines() methods. If you override this
        method, please make sure to call the missing_params() method before
        you try to send a request to the Web server.
        """
        missing = self.missing_params()
        if missing:
            if len(missing) > 1:
                err = "Missing these parameters: `%s'" % str(missing)
            else:
                err = "Missing the parameter `%s'" % missing[0]
            raise ParameterError(err)

        if opener is not None:
            urllib2.install_opener(opener)
        elif self._urllib_opener is not None:
            urllib2.install_opener(self._urllib_opener)

        if self.METHOD == "POST":
            url = self.get_url(with_params=False)
            data = self.encode_params()
        else:
            url = self.get_url(with_params=True)
            data = None
        self._debug_msg("Opening URL = %s",
                        debug.DEBUG_LEVELS['HTTP'], url)
        if data:
            self._debug_msg("POSTing data = %s",
                            debug.DEBUG_LEVELS['HTTP'], data)

        try:
            resp = urllib2.urlopen(url, data)
        except urllib2.HTTPError, err:
            if err.code == 503:
                retries -= 1
                if retries >= 0:
                    self._debug_msg("Retrying open(), URL = %s",
                                    debug.DEBUG_LEVELS['HTTP'], url)
                    time.sleep(0.05)
                    return self.open(opener, retries=retries)
                raise ServerError("""Internal WebService error, temporarily \
unavailable""")
            else:
                raise SearchError(err)
            raise ServerError("WebService server unavailable")
        return resp

    def get_results(self, stream=None, xml_parser=None, close=True):
        """Read the stream (if provided) and either return the raw XML, or
        send the data to the provided XML parser for further processing.
        If no stream is provided, it will call the open() method using the
        default opener. The stream will be closed upon return from this
        method, unless the close=False is passed as an argument.
        """
        self._debug_msg("VALID_PARAMS = %s",
                        debug.DEBUG_LEVELS['PARAMS'],
                        self._valid_params.keys())
        if stream is None:
            stream = self.open()
        if xml_parser is None:
            xml_parser = self._xml_parser

        if xml_parser is not None:
            res = xml_parser(stream)
            try:
                self._debug_msg("XML results are:\n%s",
                                debug.DEBUG_LEVELS['RAWXML'],
                                res.toprettyxml())
            except AttributeError:
                pass
        else:
            res = "".join(stream.readlines())
        if close:
            stream.close()
        return res

    def parse_results(self, xml=None):
        """Get the result from the request, and instantiate the appropriate
        result class. This class will be populated with all the data from
        the XML object.
        """
        if self._result_factory is None:
            return None

        if xml is None:
            xml = self.get_results()
        res = self._result_factory(service=self)
        res.parse_results(xml)
        return res


    def _get_debug_level(self):
        """Get the current debug level."""
        return self._debug_level
    def _set_debug_level(self, level):
        """Set the new debug level to be used."""
        self._debug_level = level
    debug_level = property(_get_debug_level, _set_debug_level, None,
                           "Set and modify the debug level")


#
# Basic parameters, supported by all regular search classes
#
class _BasicSearch(_Search):
    """Yahoo Search WebService - basic params service

    Setup the basic CGI parameters that all (normal) search services
    supports. This is used by most services (classes) to provision for
    the basic parameters they all use.
    """
    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, True),
            "results" : (types.IntType, 10, int, lambda x: x > -1 and x < 51,
                         "the range 1 to 50", False),
            "start" : (types.IntType, 1, int, lambda x: x > -1 and x < 1001,
                       None, False),
            })


#
# Common search parameters, shared by several packages, but not all.
#
class _CommonSearch(_Search):
    """Yahoo Search WebService - common params service
    
    Several search services share a few non-basic parameters, so
    this sub-class of _BasicParams saves some typing.
    """
    def _init_valid_params(self):
        """Initialize the set of valid parameters."""
        self._valid_params.update({
            "query" : (types.StringTypes, None, None, None, None, True),
            "results" : (types.IntType, 10, int,  lambda x: x > -1 and x < 51,
                         "the range 1 to 50", False),
            "start" : (types.IntType, 1, int, lambda x: x > -1 and x < 1001,
                       None, False),
            "type" : (types.StringTypes, "any", str.lower,
                      ("all", "any", "phrase"), None, False),
            "adult_ok" : (types.IntType, None, int, (1,), None, False),
            })



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
