from exploitutils import *
import libs.canvasos as canvasos

class mdnsdetect:
    def __init__(self):
        return
    
    def run_mdnsdetect(self):
        result = None
        
        sck = self.getudpsock()
        try:
            sck.connect((self.host, 5353))
        except:
            return None
        
        buf = intel_short(random.randint(0,65535)) #transaction ID
        buf += intel_short(1) #flags (standard)
        buf += halfword2bstr(1) #questions 1
        buf += halfword2bstr(0) #Answer RRs
        buf += halfword2bstr(0) #authority RRs
        buf += halfword2bstr(0) #additional RRs
        
        #Query, name:
        for a in ["_workstation","_tcp","local"]:
            buf += chr(len(a))+a 
        buf += "\x00" #end string
        buf += halfword2bstr(0xc) #Type: PTR
        buf += halfword2bstr(1) #class ANY
        
        sck.send(buf)
        
        try:
            data = sck.recv(1000)
        except:
            data=""
            self.log("MDNS DETECT: Got no Rendezvous data, socket closed or did not respond within 5 seconds")
        if data:
            self.log("MDNS DETECT: Got Rendezvous data: %s"%prettyprint(data))
            for osd in [ "ubuntu", "fedora", "debian", "linux"]:
                if osd in data.lower():
                    self.log("MDNS DETECT: Found linux via mdns")
                    result = canvasos.new("Linux")
                    if osd != "linux": 
                        #not a generic signature
                        result.family = osd
                    return result
            
            self.log("MDNS DETECT: Found data (%r), but not sure what kind of box"%data)
            return None
            
        return result