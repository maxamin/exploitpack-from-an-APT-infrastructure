#IIS smtp checks, port 25
#
#SP3: 220 immunity-nl16dh Microsoft ESMTP MAIL Service, Version: 5.0.2195.5329 ready at  Thu, 1 Apr 2004 03:00:56 +0200
#SP4: 220 powerpuff Microsoft ESMTP MAIL Service, Version: 5.0.2195.6713 ready at  Wed, 31 Mar 2004 16:59:29 -0800
#SP0: 220 immunity-nl16dh Microsoft ESMTP MAIL Service, Version: 5.0.2172.1 ready at  Thu, 1 Apr 2004 03:17:22 +0200
#SP1: 220 immunity-nl16dh Microsoft ESMTP MAIL Service, Version: 5.0.2195.1600 ready at  Thu, 1 Apr 2004 03:28:41 +0200
#SP2: 220 immunity-nl16dh Microsoft ESMTP MAIL Service, Version: 5.0.2195.2966 ready at  Thu, 1 Apr 2004 03:35:37 +0200

import libs.canvasos as canvasos
from osexception import OSException

class smtpdetect:
    def __init__(self):
        return
    
    def run_smtpdetect(self):
        
        spMinorDict = {}
        
        spMinorDict["6.0.2600.1106"] = "Windows XP SP1a"
        spMinorDict["5.0.2195.6713"] = "Windows 2000 SP4"
        spMinorDict["5.0.2195.5329"] = "Windows 2000 SP3"
        spMinorDict["5.0.2195.2966"] = "Windows 2000 SP2"
        spMinorDict["5.0.2195.1600"] = "Windows 2000 SP1"
        spMinorDict["5.0.2172.1"] = "Windows 2000 SP0"

        self.log('Running SMTP detection')
        
        try:
            sck = self.gettcpsock()
            sck.set_timeout(3)
            ret = sck.connect((self.host, 25))
            self.log('SMTP ret = %s' % ret)
            
            rd = 0
            if self.isactive(sck):
                rd = 1    
            if not rd:
                raise OSException("Can't recv from socket")

            buf = sck.recv(4000)

            # I like lower() because it makes sure we don't run into unneeded mismatches
            if buf.lower().find('microsoft esmtp') != -1:
                
                version = buf.split(',')[1]
                number = version.split(' ')[2]

                try:

                    self.log('SMTP DETECT: Using SMTP IIS version number...')
                    result = spMinorDict[number]
                    self.log('SMTP DETECT: Detailed result: %s' % result)
                    major,minor,sp = result.split(' ')
                    newos = canvasos.new(major) #major is always "Windows"
                    newos.version = minor
                    newos.servicepack =[sp]
                    self.log('SMTP DETECT: Found %s on host %s' % (self.result, self.host))
                    return newos
                
                except:
                    raise OSException('SMTP DETECT: Could not detect SP level. Fingerprint is not in the dictionary.')
                
            else:
                raise OSException('SMTP DETECT: Not Microsoft ESMTP service.')

        except Exception, msg:
            self.log('MS-SMTP OS detection failed: %s' % str(msg))
            
        return None
