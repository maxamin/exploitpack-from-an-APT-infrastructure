import libs.addressdb as addressdb
import libs.dtspcd_client as dtspcd_client
import libs.canvasos as canvasos

class dtspcd_detect(object):
    """
    Connects to dtspcd and detects the remote operating system
    """

    def do_dtspc(self):
        """ do dtpspcd based detection """

        result = None

        try:
            dtuname = dtspcd_client.DTSPCDClient(self.host,exploit=self)
            dtuname.setup()
            unamedict = dtuname.get_uname()

            self.log("DTSPCD DETECT: unamedict from dtspcd = %s" % unamedict)

            OS = unamedict['os'].upper()

            # Solaris
            if 'SUNOS' in OS:

                solDict     = {}
                solDict[-2] = "Solaris"
                solDict[6]  = "2.6"

                for i in range(7, 11):
                    solDict[i] = "%d" % i
                
                norm            = addressdb.SolarisAddress()
                rel             = norm.rel_normalize(unamedict["version"])
                result          = canvasos.new("Solaris")
                result.version  = solDict[rel]
                
                if unamedict["arch"] == "i86pc":
                    self.log("DTSPCD DETECT: Arch found: x86")
                    result.arch = "x86"
                    
                if unamedict["arch"] == "sun4u":
                    self.log("DTSPCD DETECT: Arch found: SPARC")
                    result.arch = "SPARC"

            # AIX
            elif 'AIX' in OS:
                result          = canvasos.new('AIX')
                result.version  = '5.%d' % int(unamedict['version'])
                result.arch     = 'PPC'

            else:
                # do nothing for now! when the AiX, HP-UX or others use it ...
                pass

            self.log('DTSPCD DETECT: dtspcd returned: %s' % result)

        except Exception, msg:
            self.log("DTSPCD DETECT: dtspcd OS detection returned: %s" % str(msg))
            
        return result
