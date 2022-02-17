#!/usr/bin/env python

"""
Search API for CANVAS - wraps searches up
"""

import sys
if "." not in sys.path: sys.path.append(".")
import libs.yahoo.search.web as yahoo_search
from exploitutils import contactemail, uniquelist

def getWebDomains(query):
        """
        Returns all domains for a particular query. So a search on "Immunity CANVAS" would
        return www.immunityinc.com and www.immunitysec.com, etc.
        
        This is used by smtp_mass_scan.
        """
        appid="C_"+contactemail
        try:
                search = yahoo_search.WebSearch(appid)
                
        except:
                print "Could not create factory for search!"
                raise                

        search.query=query
        search.results=100
        try:
                results=search.parse_results()
        except:
                print "Could not run search"
                #raise
                return []
        ret=[]
        for res in results:
                #print "Result URL: %s"%res.Url
                domain=res.Url
                domain=domain.split("://")[1]
                domain=domain.split("/")[0]

                ret+=[domain]
        ret=uniquelist(ret)
        return ret
        
def tester():
        ret=getWebDomains("Immunity CANVAS")
        print "Domain list: %s"%ret




#this stuff happens.
if __name__ == '__main__':
        print "Running search api tester"
        tester()

