"""Base class for search results parsing

This package implements the interface and base class that should be
used for all parsers of the web results. It is used by the DOM parsers
that we provide as defaults.
"""


__revision__ = "$Id: __init__.py,v 1.6 2007/02/28 05:20:11 zwoop Exp $"
__version__ = "$Revision: 1.6 $"
__author__ = "Leif Hedstrom <leif@ogre.com>"
__date__ = "Tue Feb 27 16:27:58 MST 2007"

from libs.yahoo.search import parser
import libs.yahoo.search.debug


#
# DOM parser implementation of the search parser.
#
class DOMResultParser(parser.ResultParser):
    """DomResultParser - Base class for Yahoo Search DOM result parsers

    This is a DOM specific parser that is used as a base class for all
    Yahoo Search result parsers. It obviously must implement the main entry
    entry point, parse_results().
    """
    def parse_results(self, dom_object):
        """This is a simple DOM parser for all Yahoo Search services. It
        expects to find a top-level node named ResultSet. This is the main
        entry point for the DOM parser, and it requires a properly con-
        structed DOM object (e.g. using minidom).
        """
        try:
            result_set = dom_object.getElementsByTagName('ResultSet')[0]
        except:
            raise parser.XMLError("DOM object has no ResultSet")
        self._parse_result_set(result_set)


    def _get_text(self, nodelist, casting=None):
        """Find all text nodes for the nodelist, and concatenate them
        into one resulting strings. This is a helper method for the
        DOM parser.
        """
        rcode = ""
        for node in nodelist:
            if node.nodeType == node.TEXT_NODE:
                rcode = rcode + node.data
        if casting is not None:
            if rcode == "":
                return rcode
            else:
                return casting(rcode)
        else:
            return rcode

    def _tag_to_list(self, node, tag, casting=None):
        """Turn a number of tag elements into a list of values."""
        ret = []
        if casting is not None:
            for item in node.getElementsByTagName(tag):
                ret.append(casting(self._get_text(item.childNodes)))
        else:
            for item in node.getElementsByTagName(tag):
                ret.append(self._get_text(item.childNodes))

    def _tags_to_dict(self, node, tags):
        """Internal method to parse and extract a list of tags from a
        particular node. We return a dict, which can potentially be empty.
        The tags argument is a list of lists, where each sub-list is

            (tag-name, default value/None, casting function/None)

        The default "type" of a value is string, so there is no reason
        to explicitly cast to a str.
        """
        res = self._res_dict()
        for tag in tags:
            elem = node.getElementsByTagName(tag[0])
            if elem:
                val = self._get_text(elem[0].childNodes, tag[2])
            elif tag[1] is not None:
                val = tag[1]
            else:
                raise parser.XMLError("Result is missing a %s node" % tag[0])
            res[tag[0]] = val
        return res

    def _id_attribute_to_dict(self, node):
        """Internal method to parse and extract a node value, which
        has an "id" attribute as well. This will return a result dict
        with two values:

            { 'Name' :  <node-text>, 'Id' : <id attribute> }
        """
        res = self._res_dict()
        res['Name'] = self._get_text(node.childNodes)
        node_id = node.attributes.getNamedItem('id')
        if node_id:
            res['Id'] = str(node_id.nodeValue)
        else:
            raise parser.XMLError("%s node has no id attribute" % node.nodeName)
        return res

    def _parse_list_node(self, node, tag):
        """Internal method to parse a result node, which contains one
        or more data nodes. Each such node is converted to a dict (see
        _id_attribute_to_dict), and we return a list of such dicts.
        """
        res = []
        for elem in node.getElementsByTagName(tag):
            res.append(self._id_attribute_to_dict(elem))
        return res

    def _parse_result_set(self, result_set):
        """Internal method to parse a ResultSet node"""
        
        attributes = result_set.attributes
        if not attributes:
            raise parser.XMLError("ResultSet has no attributes")

        attr = attributes.getNamedItem('totalResultsAvailable')
        if attr:
            self._total_results_available = int(attr.nodeValue)
        else:
            raise parser.XMLError("ResultSet has no totalResultsAvailable attr")
        attr = attributes.getNamedItem('totalResultsReturned')
        if attr:
            self._total_results_returned = int(attr.nodeValue)
        else:
            raise parser.XMLError("ResultSet has no totalResultsReturned attr")
        attr = attributes.getNamedItem('firstResultPosition')
        if attr:
            self._first_result_position = int(attr.nodeValue)
        else:
            raise parser.XMLError("ResultSet has no firstRestultPosition attr")

        self._service._debug_msg("Results = %d / %d / %d",
                                 libs.yahoo.search.debug.DEBUG_LEVELS['PARSING'],
                                 self._total_results_available,
                                 self._total_results_returned,
                                 self._first_result_position);

        for res in result_set.getElementsByTagName('Result'):
            self._results.append(self._parse_result(res))

    def _parse_result(self, result):
        """Internal method to parse one Result node"""
        return self._tags_to_dict(result, self._res_fields)



#
# local variables:
# mode: python
# indent-tabs-mode: nil
# py-indent-offset: 4
# end:
