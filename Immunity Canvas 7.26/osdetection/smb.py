import socket
import libs.canvasos as canvasos

from libs.newsmb.libsmb import SMBClient, SMBException
from timeoutsocket import Timeout

class smbdetect:
    def __init__(self):
        self.user = None
        self.password = None

    #  error,errstr,uid,os,lanman,domain=smb_session_setup(s,auth, capabilities, domain=domain)
    def do_smb(self):
        """ do windows SMB detection """
        result = None
        self.log("SMB DETECT: Doing SMB OS Detection")
        smbobj = None
        port = 445
        nativeos = u''
        lanman = u''
        domain = u''
        server = u''

        def get_socket():
            if ':' in self.host:
                return self.gettcpsock(AF_INET6=1)
            else:
                return self.gettcpsock()
        
        try:
            sockaddr = (self.host, port)
            s = get_socket()
            s.connect(sockaddr)
            
            # First do the negotiation without extended security (get domainname/servername)
            smbobj = SMBClient(s, username=self.user, password=self.password)
            smbobj.is_unicode = True
            smbobj.extended_security = False
            smbobj.negotiate()
            s.close()
            domain = unicode(smbobj.primarydomain)
            server = unicode(smbobj.servername)

            # Now we do a complete session setup exchange
            s = get_socket()
            s.connect(sockaddr)
            smbobj = SMBClient(s, username=self.user, password=self.password)
            smbobj.is_unicode = True
            smbobj.extended_security = True
            smbobj.negotiate()
            smbobj.session_setup()
            s.close()
            nativeos = unicode(smbobj.nativeos)
            lanman = unicode(smbobj.nativelanman)

        except SMBException, ex:
            self.log('SMB error: %s' % ex)
            return None
        except socket.error:
            self.log('Error when connecting to %s' % self.host)
            return None
        except Timeout:
            self.log('Timed out when connecting to %s' % self.host)
            return None
            
        self.log('SMB DETECT: SMB OS Detection (port=%d) returned %s' % (port, nativeos))
        if lanman.lower() != 'unknown': 
            self.log("SMB DETECT: Adding lanman knowledge: %s" % lanman)
            self.target.add_knowledge("Lanman", lanman, 100)
            self.log("SMB DETECT: Adding domain knowledge: %s" % domain)
            self.target.add_knowledge("SMBDomain", domain, 100)
            self.log("SMB DETECT: Adding server knowledge: %s" % server)
            self.target.add_knowledge("SMBServer", server, 100)
            self.engine.new_event("smb", {
                "remote_ip": str(self.target.interface),
                "lanman": str(lanman),
                "domain": str(domain),
                "server": server,
                }, 'osdetect')

        # Check native OS, assume Linux for SAMBA
        if 'UNIX' in nativeos.upper():
            if 'SUSE' in lanman.upper():
                result = canvasos.new("Linux")
                result.version = "SuSE"
        # Windows SMB muck
        elif 'VISTA' in nativeos.upper():
            result = canvasos.new('Windows')
            result.version = 'Vista'
            for subversion in ['Ultimate']:
                if nativeos.find(subversion) != -1:
                    result.family = subversion
        elif 'LAN MANAGER 4.0' in nativeos.upper():
            result = canvasos.new('Windows')
            result.version = 'NT 4.0'
        elif 'WINDOWS' in nativeos.upper():
            result = canvasos.new('Windows')
            if nativeos.find('Windows 5.0') != -1:
                result.version = '2000'
            elif nativeos.find('Windows 5.1') != -1:
                result.version = 'XP'
            elif nativeos.find('Windows .NET 5.2') != -1:
                result.version = '.NET RC2'
            elif nativeos.find('Windows NT 4.0') != -1:
                result.version = 'NT'
            elif nativeos.find('Windows 4.0') != -1:
                result.version = '9x'
            elif nativeos.find('Windows Server 2003') != -1:
                result.version = '2003'
                if nativeos.find('Service Pack 1') != -1:
                    result.servicepack.append('SP1')
                elif nativeos.find('Service Pack 2') != -1:
                    result.servicepack.append('SP2')
                else:
                    result.servicepack.append('SP0')

        return result

    def run_smbdetect(self):
        return self.do_smb()
