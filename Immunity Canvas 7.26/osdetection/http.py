import libs.spkproxy as spkproxy
import libs.canvasos as canvasos

class httpdetect:
    def __init__(self):
        return

    def guessFromWWWHeader(self, header):
        # XXX: move this to a flat file format ! objects == mem :(
        
        # XXX: modified to return CANVAS OS objects - 08/2007
        keylist = {}

        k = canvasos.new("Windows")
        k.version = "2008"
        keylist["IIS/7.0"] = k

        k = canvasos.new("Windows")
        k.version = "2003"
        keylist["IIS/6.0"] = k

        k = canvasos.new("Windows")
        k.version = "2000"
        keylist["IIS/5.0"] = k

        k = canvasos.new("Windows")
        k.version = "XP"
        k.family="Professional"
        keylist["IIS/5.1"] = k

        k = canvasos.new("Linux")
        k.version = "Linksys Router"
        keylist["Linksys"] = k

        k = canvasos.new("Linux")
        k.version = "RedHat"
        keylist["Red-Hat"] = k

        k = canvasos.new("Linux")
        k.version = "Fedora"
        keylist["Fedora"] = k

        k = canvasos.new("Linux")
        k.version = "Red Hat"
        keylist["Red Hat"] = k

        k = canvasos.new("Linux")
        k.version = "Ubuntu"
        keylist["Ubuntu"] = k

        #Fedora Core 6 special 
        k = canvasos.new("Linux")
        k.version = "Fedora"
        k.build = "6"
        keylist["Apache/2.2.3 (Fedora)"] = k

        k = canvasos.new("Linux")
        k.version = "SuSE"
        keylist["SuSE"] = k

        k = canvasos.new("Linux")
        k.version = "Mandrake"
        keylist["Mandrake"] = k

        k = canvasos.new("Linux")
        k.version = "Slackware"
        keylist["Slackware"] = k

        k = canvasos.new("Linux")
        k.version = "Debian"
        keylist["Debian"]=k

        k = canvasos.new("Linux")
        k.version = "Gentoo"
        keylist["Gentoo"] = k

        #I believe Dapper is Server: Apache/2.0.55 (Ubuntu) DAV/2 PHP/5.1.2 mod_ssl/2.0.55 OpenSSL/0.9.8a
        k = canvasos.new("Linux")
        k.version = "Ubuntu"
        k.build = "6.06" #Dapper, I believe
        keylist["Apache/2.0.55 (Ubuntu) DAV/2 PHP/5.1.2 mod_ssl/2.0.55 OpenSSL/0.9.8a"] = k

        k = canvasos.new("Linux")
        k.version = "Sun Cobalt"
        keylist["Cobalt"] = k

        k = canvasos.new("Windows")
        k.version = "NT/2000/XP"
        keylist["Win32"] = k

        k = canvasos.new("Embedded")
        k.version = "Observer XT DSL Gateway"
        keylist["DSL Gateway"] = k
        keylist["Observer XT"] = k

        k = canvasos.new("Embedded")
        k.version = "DLink Wireless Router 624"
        keylist['realm="DI-624"'] = k

        k = canvasos.new("Embedded")
        k.version = "DLink DSL Router (DT-504T)"
        keylist['realm="DSL-504T Admin Login"'] = k

        k = canvasos.new("Embedded")
        k.version = "DLink Wireless Router (DI-524)"
        keylist['realm="DI-524"'] = k

        k = canvasos.new("Embedded")
        k.version = "Linksys Router WRT54GX"
        keylist["WRT54G"] = k

        k = canvasos.new("Embedded")
        k.version = "Linksys Router"
        keylist["Allegro-Software-RomPager"] = k

        k = canvasos.new("IOS")
        k.version = "CISCO Router"
        keylist["cisco-IOS"] = k

        k = canvasos.new("Macintosh")
        k.version = "Unknown"
        keylist["AppleShareIP"] = k

        k = canvasos.new("OS X")
        keylist["Darwin"] = k

        k = canvasos.new("IRIX")
        k.version = "Unknown"
        keylist["Netscape-Fasttrack"] = k

        k = canvasos.new("Embedded")
        k.version = "HP JetDirect"
        keylist["Agranat-EmWeb/R5"] = k
        keylist["Virata-EmWeb/"] = k
        keylist["<title>Hewlett Packard</title>"] = k

        k = canvasos.new("Embedded")
        k.version= "HP LaserJet"
        keylist["<title>HP Color Laserjet"] = k
        keylist["HP-ChaiSOE/1.0"] = k
        keylist["HP LaserJet"] = k

        k = canvasos.new("Embedded")
        k.version = "f5"
        keylist ["F5 Networks"] = k
         
        #k = canvasos.new("Embedded")
        #k.version= "Generic HP Printer"
        #keylist["hp/device/this.LCDispatcher"] = k

        #k = canvasos.new("Linux")
        #k.version="XPanel" #large host controller
        #keylist["Main.html"]=k

        k = canvasos.new("Embedded")
        k.version = "Ricoh Printer"
        keylist["<title>Web Image Monitor</title>"] = k

        k = canvasos.new("Embedded")
        k.version = "Canon Printer"
        keylist["CANON HTTP Server "] = k

        k = canvasos.new("Embedded")
        k.version = "Brother Printer"
        keylist["Debut/0.07"] = k

        k = canvasos.new("Novell Netware")
        keylist["NetWare"] = k

        k = canvasos.new("Embedded")
        k.version = "Netgear MR314"
        keylist["MR314"] = k

        k = canvasos.new("Embedded")
        k.version = "Netgear RT3"
        keylist["RT3"] = k

        k = canvasos.new("Embedded")
        k.version = "D-Link AirPlus G Wireless Access Point"
        keylist["DWL-G700AP"] = k

        k = canvasos.new("Embedded")
        k.version = "D-Link Wireless Access Point"
        keylist["DWL"] = k


        k = canvasos.new("IBM ICS")
        k.version = "AS/400"
        keylist["IBM-ICS-AS400"] = k

        k = canvasos.new("Embedded")
        k.version = "3Com"
        keylist["3Com"] = k

        k = canvasos.new("BeOS")
        keylist["BeOS"] = k

        k = canvasos.new("Embedded")
        k.version = "Linksys Router WRT54G"
        keylist["Intoto"] = k

        k = canvasos.new("Embedded")
        k.version = "Netgear WGR 614 Wireless AP"
        keylist["WGR614"] = k

        k = canvasos.new("Embedded")
        k.version = "Netgear WGR series"
        keylist["WGR"] = k

        k = canvasos.new("Embedded")
        k.version = "Netopia DSL Switch"
        keylist["Netopia"] = k

        #default is admin/""
        k = canvasos.new("Embedded")
        k.version = "Kyocera EVDO Router (powered by D-link)"
        keylist["Embedded HTTP Server RK1008"] = k

        k = canvasos.new("Embedded")
        k.version = "3COM Wireless Router"
        keylist["IP_SHARER"] = k

        k = canvasos.new("Embedded")
        k.version = "Sweex Broadband Router"
        keylist["GoAhead-Webs"] = k

        k = canvasos.new("Embedded")
        k.version = "Prestige 645" #DSL router
        keylist["Prestige 645"] = k

        k = canvasos.new("Embedded")
        k.version = "Roving Access Server"
        keylist["Roving"] = k

        k = canvasos.new("Embedded")
        k.version= "Axis Camera" #password root:pass
        keylist["Boa/0.92o"] = k

        k = canvasos.new("Embedded")
        k.version = "Netbotz Camera" #password netbotz/netbotz
        keylist["realm=\"NetBotz Appliance\""] = k

        k = canvasos.new("Embedded")
        k.version = "Dell Laser Printer"
        keylist["Dell Laser Printer"]=k

        k = canvasos.new("Embedded")
        k.version= "Internet Subscriber Server II" #hotel thingy
        keylist["<title>User Configuration Interface</title>"] = k
        
        k = canvasos.new("Embedded")
        k.version= "Canon Printer" #Canon webserver in big printers
        keylist["CANON HTTP Server"] = k
        
        k = canvasos.new("Windows")
        k.version = "Microsoft ISA Server"
        keylist["<H1 id=L_defaultr_2 style=\"FONT: 13pt/15pt verdana; COLOR: #000000\"><ID id=L_defaultr_3>"] = k #the labels here has quite specific names
        
        k = canvasos.new("Embedded") #FTP is a better guess
        k.version= "Server: Web-Server/3.0"
        keylist["Savin or Ricoh printer"] = k
        
        for k in keylist:
            #print "Checking: %s"% k.upper()
            import sys
            #s = sys.stdin.read(1)
            if header.upper().find(k.upper()) != -1:
                self.log("Found %s in HTTP header"%k)
                return keylist[k] # success

        return None # no success

    def run_httpdetect(self):
        
        self.log("HTTP DETECT: Looking at webserver header")
        result = None

        try:

            for hostname in [self.target.resolved_from, "localhost", self.host, "www"]:

                # XXX: check both protocols
                httpOpen = True
                sslOpen = True

                for protocol in [ "http", "https" ]:
                    # skip further checks on the same ip when the http/ssl is down
                    if httpOpen == False and sslOpen == False:
                        break 

                    self.log("HTTP DETECT: Using Hostname: %s" % hostname)

                    # this returns a filetype_str object that pretends to be an fd
                    header_fd = spkproxy.urlopen(protocol+"://"+self.host+"/",exploit=self, hostname=hostname, entireresponse=True) 
                    header = header_fd.read() # kludge .. is read() in filetype_str being overloaded? and ending up in the while 1 ?

                    if header.upper().count("501 NO SERVER THERE"):
                        if protocol == "http":
                            httpOpen = False
                            continue
                        else:
                            sslOpen = False
                            continue

                    # handle real header
                    header = header[:1000] #also includes body, so we'll do some truncation
                    self.log("HTTP DETECT: Web header = %s" % header)
                    result = self.guessFromWWWHeader(header)

                # break out of the main loop to prevent unneeded reps
                if httpOpen == False and sslOpen == False:
                    break
        except:
            self.log("HTTP DETECT: Exception in HTTP header check ...")
            import traceback
            traceback.print_exc(file=sys.stderr)

        return result
