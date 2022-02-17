# a refactoring of exploits/spdetect for os detect

from exploitutils import uniquelist

class spdetect:
    def __init__(self):
        # should inherit self.engine from calling module
        # should inherit self.target from calling module
        self.servicepack = []
        self.baseos = ''
        self.port = 135
        return

    def getEndpoints(self,UUID):
        module = self.engine.getModuleExploit('dcedump')
        module.link(self)
        connectionList = module.getEndpointbyUUID(UUID)
        return connectionList
    
    def doIfids(self):
        ifids=self.engine.getModuleExploit('ifids')
        ifids.namedpipe='\\\\browser'
        ifids.link(self)
        ifids.version=2
        ifids.port=445
        ifids.run()
        return ifids.result

    def getSPInfo(self):
        if self.baseos.count('XP') > 0:
            connectionList=self.getEndpoints('0a74ef1c-41a4-4e06-83ae-dc74fb1cdd53')
            if len(connectionList)==0: #anonymously we didn't get anything back, so SP2/SP3 it is
                self.servicepack.append('SP2')
                self.servicepack.append('SP3')
                return

            connectionList = self.getEndpoints('5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc')
            found=False
            for endpoint in connectionList:
                if endpoint.count('[\\PIPE\\AudioSrv]')>0:
                    self.servicepack.append('SP0')
                    return
                elif endpoint.count('ncalrpc:[AudioSrv]')>0:
                    self.servicepack.append('SP1')
                    found=True
                    break
            if found==False:
                #On XP SP3, AudioSrv can be found in:
                #- d674a233-5829-49dd-90f0-60cf9ceb7129,
                #- 06bba54a-be05-49f9-b0a0-30f790261023,
                #- 2f5f6521-cb55-1059-b446-00df0bce31db
                self.servicepack.append('SP2')
                self.servicepack.append('SP3')

            #This one is bad: a XP where nobody has logged in will be detected as SP0
            #connectionList=self.getEndpoints('4b112204-0e19-11d3-b42b-0000f81feb9f') #requires someone to have logged on locally
            #found=False
            #for endpoint in connectionList:
            #    if endpoint.count('[\\PIPE\\DAV RPC SERVICE]')>0:
            #        found=True
            #        break
            #if found==False:
            #    self.servicepack.append('SP0')

        elif self.baseos.count('2000') > 0:
            connectionList = self.getEndpoints('5a7b91f8-ff00-11d0-a9b2-00c04fb6e6fc')
            for endpoint in connectionList:
                if endpoint.count('ncalrpc:[DNSResolver]')>0:
                    self.servicepack.append('SP3')
                    self.servicepack.append('SP4')
                    break

                #the rest if either SP0,SP1,SP2 or SP2,SP3,SP4 with MS03-043                
        return

    # takes in a canvasos object with a os.base of 'Windows'
    def run_spdetect(self, os=None):
        self.baseos=os
        self.getSPInfo()
        if type(os.servicepack) != type([]):
            self.log("XXX: osdetection/servicepack.py: OS Object has assigned string to servicepack .. should be list! Fix Me! (%s)" % \
                 repr(os.servicepack))
            if type(os.servicepack) == type(''):
                os.servicepack = [os.servicepack]
            else:
                os.servicepack = []
        if type(self.servicepack) != type([]):
            self.log("XXX: osdetection/servicepack.py: SP Detect has assigned string to servicepack .. should be list! Fix Me! (%s)" % \
                 repr(self.servicepack))
            if type(self.servicepack) == type(''):
                self.servicepack = [self.servicepack]
            else:
                self.servicepack = []
        os.servicepack = uniquelist(os.servicepack + self.servicepack)
        if len(os.servicepack):
            self.log("SP DETECT: %s" % repr(os.servicepack))
            os.servicepack = repr(os.servicepack)
        return os


