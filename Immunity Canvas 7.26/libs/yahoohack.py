#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

#Part of CANVAS For licensing information, please refer to your
#Immunity CANVAS licensing documentation

import sys
if "." not in sys.path: sys.path.append(".")

import string

from libs.yahoo.search.web import WebSearch

from xml.sax import make_parser, handler
import xml.sax.saxutils as saxutils



class DBParser(handler.ContentHandler):

    def __init__(self):
        self.elements = {}
        self.site = ""
        
    def startElement(self, name, attrs):
        self.name = name

    def characters(self, content):
        content = string.strip(saxutils.escape(content))
        if content:
            self.elements[ self.name ] = content
        
    def endElement(self, name):
        if name == "signature":
            #print ">>", self.elements['signatureReferenceNumber'], self.elements['querystring']
            srch = WebSearch(app_id="CANVAS")
            querystring = self.elements['querystring'] + " site:%s" % self.site
            srch.query = querystring
            srch.results = 100
            found = srch.parse_results()
            count = 0
            
            for a in found:
                count+=1
                
            if count:
                print "Found (%s) %s %d" % ( self.elements['signatureReferenceNumber'], self.elements['shortDescription'], count )
                print querystring
                print "   %s" % a.Url
            self.elements = {}
        
    def endDocument(self):
        pass
    
    def run(self, site, conffile = "libs/GHDB.xml"):
        self.site = site
        parser = make_parser()    
        parser.setContentHandler(self)
        parser.parse( conffile ) 

if __name__== '__main__':
    p = DBParser()
    p.run(sys.argv[1])
    
    