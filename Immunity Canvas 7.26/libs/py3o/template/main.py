"""
Modified: 07/11/12 by miguel@immunityinc.com
- Removed lxml dependency
- Simplified control blocks:
    Rather than insert links for if/for/etc... blocks, simply
    apply a style starting with "pycode" to a paragraph containing
    the code block. The end of the code block should be marked in
    another "pycode"-styled paragraph containing a slash: "/<blocktype>".
"""

import zipfile
from StringIO import StringIO
import urllib
from libs.genshi.template import MarkupTemplate
from libs.pyjon.utils import get_secure_filename
import os
import decimal
from xml.etree import ElementTree as etree

GENSHI_URI = 'http://genshi.edgewall.org/'
PY3O_URI = 'http://py3o.org/'

def get_parent(element):
    return element._parent

def replace(element, old, new):
    i = element._children.index(old)
    element._children[i] = new
    new._parent = element

def iter_siblings(element):
    found_self = False
    for child in get_parent(element):
        if child is element:
            found_self = True
            continue
        elif not found_self:
            continue
        else:
            yield child

def move_siblings(start, end, new_):
    old_ = get_parent(start)

    # copy any tail we find
    if start.tail:
        new_.text = start.tail

    # get all siblings
    for node in list(iter_siblings(start)):
        old_.remove(node)
        if node is not end:
            # and stuff them in our new node
            new_.append(node)
            node._parent = new_
        else:
            # if this is already the end boundary, then we are done
            break

    # replace start boundary with new node
    replace(old_, start, new_)

class Template(object):
    templated_files = ['content.xml', 'styles.xml']

    def __init__(self, template, outfile):
        """A template object exposes the API to render it to an OpenOffice
        document.

        @param template: a py3o template file. ie: a OpenDocument with the
        proper py3o markups
        @type template: a string representing the full path name to a py3o
        template file.

        @param outfile: the desired file name for the resulting ODT document
        @type outfile: a string representing the full filename for output
        """
        self.template = template
        self.outputfilename = outfile
        self.infile = zipfile.ZipFile(self.template, 'r')
        
        self.content_trees = [self._parse_map(self.infile.open(filename))
                              for filename in self.templated_files]
        self.tree_roots = [tree.getroot() for tree in self.content_trees]
        
        self._prepare_namespaces()
    
    def _parse_map(self, file):
        events = ["start", "start-ns", "end-ns"]
        root = None
        nsmap = []
        
        for event, elem in etree.iterparse(file, events):
            if event == "start-ns":
                nsmap.append(elem)
            elif event == "end-ns":
                nsmap.pop()
            elif event == "start":
                if root is None:
                    root = elem
                    root._parent = None
                elem.nsmap = dict(nsmap)
        
        tree = etree.ElementTree(root)
        # ElementTree retardedly doesn't link to the parent
        for parent in tree.getiterator():
            for child in parent:
                child._parent = parent
        return tree

    def _prepare_namespaces(self):
        """create proper namespaces for our document
        """
        # create needed namespaces
        self.namespaces = dict(
            text="urn:text",
            draw="urn:draw",
            table="urn:table",
            office="urn:office",
            xlink="urn:xlink",
            svg="urn:svg",
            )

        # copy namespaces from original docs
        for tree_root in self.tree_roots:
            self.namespaces.update(tree_root.nsmap)

        # remove any "root" namespace
        self.namespaces.pop(None, None)

        # declare the genshi namespace
        self.namespaces['py'] = GENSHI_URI
        # declare our own namespace
        self.namespaces['py3o'] = PY3O_URI
        
        for tree_root in self.tree_roots:
            self._set_prefixes(tree_root, self.namespaces)

    def _handle_instructions(self):
        # find all links that have a py3o
        opened_starts = list()
        starting_tags = list()
        closing_tags = dict()
        
        for content_tree in self.content_trees:
            for link in content_tree.getiterator('text:p'):
                if not link.attrib.get('text:style-name', '').lower().startswith('pycode'):
                    continue
                if not link.text:
                    continue
                py3o_statement = link.text.rstrip(':')
    
                if not py3o_statement.startswith("/"):
                    opened_starts.append((content_tree, link))
                    starting_tags.append((content_tree, link, py3o_statement))
    
                else:
                    closing_tags[id(opened_starts.pop()[1])] = (content_tree, link)
        return starting_tags, closing_tags

    def _handle_link(self, content_tree, link, py3o_base, closing_link):
        """transform a py3o link into a proper Genshi statement
        rebase a py3o link a a proper place in the tree
        to be ready for Genshi replacement
        """
        parent = get_parent(link)
        if parent.tag == "table:table-cell":
            # we are in a table
            opening_row = get_parent(get_parent(link))
            closing_row = get_parent(get_parent(closing_link))

        elif parent.tag in ["office:text", "span"]:
            # we are in a text paragraph
            opening_row = link
            closing_row = closing_link

        else:
            raise NotImplementedError("We handle urls in tables or text paragraph only")
        
        # max split is one
        instruction, instruction_value = py3o_base.split(" ", 1)

        attribs = dict()
        attribs['py:strip'] = 'True'
        attribs['py:%s' % instruction] = instruction_value
        
        genshi_node = etree.Element('span', attrib=attribs)
        
        move_siblings(opening_row, closing_row, genshi_node)
        
    def _prepare_userfield_decl(self):
        self.field_info = dict()
        
        for content_tree in self.content_trees:
            for userfield in content_tree.getiterator('text:user-field-decl'):
                if not userfield.attrib.get('text:name', '').startswith('py3o.'):
                    continue
                
                value = userfield.attrib['text:name'][5:]
                value_type = userfield.attrib.get('office:value-type', 'string')
                
                self.field_info[value] = dict(name=value, value_type=value_type)

    def _prepare_usertexts(self):
        """user-field-get"""
        for content_tree in self.content_trees:
            for userfield in content_tree.getiterator('text:user-field-get'):
                if not userfield.attrib.get('text:name', '').startswith('py3o.'):
                    continue
                
                parent = get_parent(userfield)
                value = userfield.attrib['text:name'][5:]
                value_type = self.field_info[value]['value_type']
                
                # we try to override global var type with local settings
                value_type_attr = 'office:value-type'
                rec = 0
                npar = parent
                
                # special case for float which has a value info on top level
                # overriding local value
                found_node = False
                while rec <= 5:
                    if npar is None:
                        break
                    
                    if value_type_attr in npar.attrib:
                        value_type = npar.attrib[value_type_attr]
                        found_node = True
                        break
                    
                    npar = get_parent(npar)
                    
                if value_type == 'float':
                    value_attr = 'office:value'
                    rec = 0
                    
                    if found_node:
                        npar.attrib[value_attr] = "${%s}" % value
                    else:
                        npar = userfield
                        while rec <= 7:
                            if npar is None:
                                break
                            
                            if value_attr in npar.attrib:
                                npar.attrib[value_attr] = "${%s}" % value
                                break
                            
                            npar = get_parent(npar)
                            
                    value = "format_float(%s)" % value
                    
                if value_type == 'percentage':
                    del npar.attrib[value_attr]
                    value = "format_percentage(%s)" % value
                    npar.attrib[value_type_attr] = "string"
                    
                attribs = dict()
                attribs['{%s}strip' % GENSHI_URI] = 'True'
                attribs['{%s}content' % GENSHI_URI] = value
                
                genshi_node = etree.Element('span', attrib=attribs)
    
                if userfield.tail:
                    genshi_node.tail = userfield.tail
    
                replace(parent, userfield, genshi_node)

    def render_flow(self, data):
        """render the OpenDocument with the user data

        @param data: the input stream of userdata. This should be a
        dictionnary mapping, keys being the values accessible to your
        report.
        @type data: dictionnary
        """
        
        newdata = dict(decimal=decimal,
                       format_float = (lambda val: (isinstance(val, decimal.Decimal)
                                                   or isinstance(val, float))
                                                   and str(val).replace('.', ',') or val),
                       format_percentage = (lambda val: ("%0.2f %%" % val).replace('.', ','))
                       )

        # first we need to transform the py3o template into a valid
        # Genshi template.
        starting_tags, closing_tags = self._handle_instructions()
        for content_tree, link, py3o_base in starting_tags:
            assert id(link) in closing_tags, 'missing closing tag: "%s"' % link.text
            self._handle_link(content_tree, link, py3o_base, closing_tags[id(link)][1])
        
        self._prepare_userfield_decl()
        self._prepare_usertexts()
        
        self.output_streams = list()
        for fnum, content_tree in enumerate(self.content_trees):
            template = MarkupTemplate(self._tostring(content_tree.getroot()))
            # then we need to render the genshi template itself by
            # providing the data to genshi
            self.output_streams.append((self.templated_files[fnum],
                                        template.generate(**dict(data.items() + newdata.items()))))

        # then reconstruct a new ODT document with the generated content
        for status in self._save_output():
            yield status

    def render(self, data):
        """render the OpenDocument with the user data

        @param data: the input stream of userdata. This should be a
        dictionnary mapping, keys being the values accessible to your
        report.
        @type data: dictionnary
        """
        for status in self.render_flow(data):
            if not status:
                raise ValueError, "unknown error"
    
    def _set_prefixes(self, elem, prefix_map):
        # check if this is a tree wrapper
        if not etree.iselement(elem):
            elem = elem.getroot()
    
        # build uri map and add to root element
        uri_map = {}
        for prefix, uri in prefix_map.items():
            uri_map[uri] = prefix
            elem.set("xmlns:" + prefix, uri)
    
        # fixup all elements in the tree
        memo = {}
        for e in elem.getiterator():
            self._fixup_element_prefixes(e, uri_map, memo)
    
    def _fixup_element_prefixes(self, elem, uri_map, memo):
        def fixup(name):
            try:
                return memo[name]
            except KeyError:
                if name[0] != "{":
                    return
                uri, tag = name[1:].split("}")
                if uri in uri_map:
                    new_name = uri_map[uri] + ":" + tag
                    memo[name] = new_name
                    return new_name
        # fix element name
        name = fixup(elem.tag)
        if name:
            elem.tag = name
        # fix attribute names
        for key, value in elem.items():
            name = fixup(key)
            if name:
                elem.set(name, value)
                del elem.attrib[key]
    
    def _fixup_xmlns(self, elem, maps=None):
        if maps is None:
            maps = [{}]
    
        # check for local overrides
        xmlns = {}
        for key, value in elem.items():
            if key[:6] == "xmlns:":
                xmlns[value] = key[6:]
        if xmlns:
            uri_map = maps[-1].copy()
            uri_map.update(xmlns)
        else:
            uri_map = maps[-1]
    
        # fixup this element
        self._fixup_element_prefixes(elem, uri_map, {})
    
        # process elements
        maps.append(uri_map)
        for elem in elem:
            self._fixup_xmlns(elem, maps)
        maps.pop()
    
    def _tostring(self, elem):
        if not etree.iselement(elem):
            elem = elem.getroot()
        
        self._fixup_xmlns(elem)
        
        return etree.tostring(elem)

    def _save_output(self):
        """Saves the output into a native OOo document format.
        """
        out = zipfile.ZipFile(self.outputfilename, 'w')

        # copy everything from the source archive expect content.xml
        for info_zip in self.infile.infolist():
            if info_zip.filename not in self.templated_files:
                out.writestr(info_zip,
                             self.infile.read(info_zip.filename))

            else:
                # get a temp file
                streamout = open(get_secure_filename(), "w+b")
                fname, output_stream = self.output_streams[
                                self.templated_files.index(info_zip.filename)]

                # write the whole stream to it
                for chunk in output_stream.serialize():
                    streamout.write(chunk.encode('utf-8'))
                    yield True

                # close the temp file to flush all data and make sure we get
                # it back when writing to the zip archive.
                streamout.close()

                # write the full file to archive
                out.write(streamout.name, fname)

                # remove tempfile
                os.unlink(streamout.name)

        # close the zipfile before leaving
        out.close()
        yield True
