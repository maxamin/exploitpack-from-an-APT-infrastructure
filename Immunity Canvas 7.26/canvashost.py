#! /usr/bin/env python
"""
canvashost.py

"""

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2004
#http://www.immunityinc.com/CANVAS/ for more information

class canvashost:
    def __init__(self):
        self.name=""
        self.os="Unknown" 
        self.vulnto=[] #all the exploits I'm vuln to
        self.knownhosts=[] #all the hosts I can reach from myself
        self.knowledge={} #dictionary of lists
    
    def addVuln(self,vuln,vulndesc):
        if vuln not in self.vulnto:
            self.vulnto.append((vuln,vulndesc))
            
    def addKnownHost(self,host):
        self.knownhosts.append(host)
        return
    
    def addKnowledge(self,key,knowledge,percentage):
        if key in self.knowledge:
            self.knowledge[key]+=[(knowledge,percentage)]
        else:
            self.knowledge[key]=[(knowledge,percentage)]            
        return
    
