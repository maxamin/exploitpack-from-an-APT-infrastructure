# inherits self.target/self.engine
import libs.canvasos as canvasos
from libs.wuftplib import FTP

class ftpdetect:
    def __init__(self):
        return

    def ftp_connect(self, host, port):
        self.log("FTP connect to %s:%s" % (host, port))
        s = self.gettcpsock()
        s.connect((host, port))
        return s

    def ftpBannerCheck(self, host, login=True):
        
        # MOSDEF sock safe
        try:
            s = self.ftp_connect(host, 21)
        except Exception, msg:
            self.log("FTP DETECT: FTP connect failed (%s)" % msg)
            return 0

        # inits ftp object and grabs welcome banner
        ftp = FTP(host, s)

        self.log("FTP DETECT: Got FTP banner: %s" % ftp.banner)

        # check anonymous login
        if login == True:
            try:
                # Sometimes servers will spit more verbose banners after successful login
                postAuthBanner = ftp.login(user = 'anonymous', passwd = 'test@test.com')
                self.log("FTP DETECT: Anonymous FTP login allowed on %s !" % host)
            except Exception, msg:
                self.log("FTP DETECT: Anonymous FTP login not allowed (%s)" % msg)
                postAuthBanner=""
                
        # banner dict
        banners = {}
        defaults = {}

        ### FTP banner sigs and default logins go here

        # XXX: move this away from object dicts ... !
        
        # APC PowerChutes
        banners['APC FTP'] = canvasos.new('Embedded')
        banners['APC FTP'].version = 'APC PowerChute'
        
        banners['DELLLASER'] = canvasos.new("Embedded")
        banners['DELLLASER'].version = "Dell Laser Printer"
        
        banners['RICOH Aficio']= canvasos.new('Embedded')
        banners['RICOH Aficio'].version="Ricoh Aficio Printer"
        
        banners['220 SAVIN SLP38c FTP server (1.83)']= canvasos.new('Embedded')
        banners['220 SAVIN SLP38c FTP server (1.83)'].version="220 SAVIN SLP38c FTP server (1.83)"
        
        banners['Hewlett-Packard FTP Print Server']= canvasos.new('Embedded')
        banners['Hewlett-Packard FTP Print Server'].version = "Hewlett-Packard FTP Print Server"

        defaults['APC FTP'] = ['APC', 'APC']

        # Bas's FTP for testing
        banners['lunar FTP server ready.'] = canvasos.new("Solaris")
        banners['lunar FTP server ready.'].version = "10"
        banners['lunar FTP server ready.'].arch = "SPARC"
        defaults['lunar FTP server ready.'] = ['bas:abc123']

        # AXIS cams
        k = 'Axis'
        banners[k] = canvasos.new('Embedded')
        banners[k].version = 'Axis Network Camera'
        defaults[k] = ['root:pass']

        ###

        for key in banners:
            # check any available default logins
            if key in defaults.keys() and login == True:
                for default in defaults[key]:
                    user = default.split(':')[0]
                    if len(default.split(":"))>1:
                        passwd = default.split(':')[1]
                    else:
                        passwd = ""

                    try:
                        ftp.login(user = user, passwd = passwd)
                        self.log("FTP DETECT: Default FTP login of %s:%s allowed on %s !" % (user, passwd, host))
                    except Exception, msg:
                        self.log("FTP DETECT: Default FTP login of %s:%s not allowed (%s)" % (user, passwd,  msg))

            # return any matching OS object ..
            if key.lower() in ftp.banner.lower():
                return banners[key]
        
            if key.lower() in postAuthBanner.lower():
                return banners[key]
            
        return None

    def run_ftpdetect(self):
        
        ###
        # ftp banner detection
        ###
        result = None
        
        try:
            result = self.ftpBannerCheck(self.target.interface)
        except Exception, msg:
            self.log("FTP DETECT: No known FTP banner available (%s)" % msg)
            
        if result:
            self.log("FTP DETECT: Found OS for %s as %s through FTP banner" % (self.target.interface, result))

        return result
