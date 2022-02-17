class telnetdetect:
    def __init__(self):
        return

    def run_telnetdetect(self):
        # XXX: ???
        
        result = None
        
        banner = self.engine.getModuleExploit("telnetbanner")
        banner.link(self)
        banner.argsDict["port"] = 23

        result = banner.get_os()
        banner.setProgress(100)
        if result:
            self.log("TELNET DETECT: Found %s on host %s" % (result, self.host))
            
        return result

