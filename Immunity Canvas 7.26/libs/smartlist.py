#!/usr/bin/env python
"""
SmartList.py  

Black listing by IP ignores the real problem: until we conduct active recon against
a host, possibly going so far as to exploit it, we don't know if this host is in scope or not.

So this module takes in a list of attributes of the hosts we don't want to attack, for example
netbios names, logged in users, ip ranges, languages, services, etc and allows the CANVAS engine to
tell modules not to attack them.

Probably the best way is a regular expression, as much as I hate them.
"""

from engine.config import canvas_resources_directory
import os
import sys
if "." not in sys.path: sys.path.append(".")
import re

class smartlist:
    """
    Hold the regular expressions tha define the smartlist, collects potential data about the smartlist
    and performs the checks needed against things that come in (hostnames, etc)
    """
    def __init__(self):
        self.netbios_names=[]
        return
    
    def check_regex(self,teststr,regexlist):
        """
        Returns true if target matches any regexes
        """
        #sometimes people pass a hostKnowledge:knowledgePrimitive into us as teststr
        try:
            teststr=teststr.get_known_text()
        except:
            pass
            
        for re_value in regexlist:
            if re.compile(re_value).match(teststr):
                return True #matched teststring
        return False #did not match teststring
            
    def check_netbios(self, netbios_name):
        """
        Returns true if the netbios name matches our regular expression
        """
        ret=self.check_regex(netbios_name,self.netbios_names)
        return ret
        
#############################################
#end of smartlist class
        
def load_smartlist():
    """
    Goes into resources directory and loads all the smartlist files into our smartlist class
    Files used:
      sl_netbios.txt
    """
    filename=os.path.join(canvas_resources_directory,"sl_netbios.txt")
    netbios_names=[]
    sl=smartlist()
    try:
        ret=file(filename,"rb").readlines()
        for name in ret:
            #comments start with a pound sign
            if name[0]=="#":
                continue
            sl.netbios_names+=[name.strip()]
    except:
        pass
        
    return sl
    
def main():
    load_smartlist()
    
if __name__=="__main__":
    main()
