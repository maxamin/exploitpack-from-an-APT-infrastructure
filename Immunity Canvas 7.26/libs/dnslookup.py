#! /usr/bin/env python

#Proprietary CANVAS source code - use only under the license agreement
#specified in LICENSE.txt in your CANVAS distribution
#Copyright Immunity, Inc, 2002-2006
#http://www.immunityinc.com/CANVAS/ for more information

from threading import Thread
import socket, thread
from internal import *
from engine import CanvasConfig

class dnslookup(Thread):
    def __init__(self,newhost):
        Thread.__init__(self)
        
        self.newhost=newhost
        
        ##Set the DNS condition as pending - can stop race conditions like in Worldview cuz we know the query is taking place rather than failed
        newhost.add_knowledge("DNSName","Pending", 100)
        
        self.setDaemon(1)

    def run(self):
        
        if not CanvasConfig['dnsresolve']:
            self.newhost.forget("DNSName")
            return
        
        newhost = self.newhost
        ip = newhost.interface
        
        try:
            name,somelist,ipaddrlist=socket.gethostbyaddr(ip)
            devlog("dns","Found name %s for ip %s"%(name,ip))
        except socket.herror:
            devlog("dns","timed out on name lookup for %s"%ip)
            name=""
        except socket.gaierror, errmsg_tuple:
            devlog("dns","gethostbyaddr: %s" % errmsg_tuple[1])
            name=""
        except:
            ret = newhost.forget("DNSName")
            raise 
        
        if name:
            newhost.add_knowledge("DNSName", name, 100)
        else:
            ##Remove pending tag
            ret = newhost.forget("DNSName")
    
if __name__=="__main__":
    
    class fakehost:
        def __init__(self):
            self.interface="1.2.3.4"
    
    print "Testing dnslookup"
    
    lookup = dnslookup(fakehost())
    lookup.start()
    
    
