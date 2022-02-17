import libs.canvasos as canvasos

class sshdetect:
    def __init__(self):
        return
    
    def run_sshdetect(self):
        result = None
        
        banner = self.engine.getModuleExploit("telnetbanner")
        banner.link(self)
        banner.argsDict["port"] = 22
        banner.argsDict["nologin"] = True
        ret = banner.run()

        # Improved this to add support for more SSH fingerprinting
        if ret or banner.result:
            banner_result = banner.result
            
            ssh_strs = { "Sun_SSH":"Solaris",
                         "osso":"Nokia N800 Tablet",
                         "Tru64":"Tru64 UNIX", 
                         "ubuntu":"Ubuntu Linux", 
                         "Debian":"Debian Linux", 
                         "FreeBSD":"FreeBSD",
                         "SSH-2.0-OpenSSH_4.4":"Linux"
                     }

            for ssh_str in ssh_strs.keys():
                if ssh_str in banner_result:
                    result = canvasos.new(ssh_strs[ssh_str])

                    #little fingerprint from our server
                    if "SSH-2.0-Sun_SSH_1.1" in banner_result:
                        result.version = "10"

                    self.log("SSH DETECT: Found %s on host %s" % (result, self.host))

        return result
    