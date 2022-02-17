#!/usr/bin/python
"""
rpc.py - for osdetection only. Cannot be run from the commandline.
"""

class rpcdetect:
    """
    Attempts to find the OS value from UNCRPC (aka, SunRPC). 
    
    This class is usually multiply inherited from a CANVAS exploit (which is
    why you see references to self.engine).
    
    """
    def __init__(self):
        return
    
    def do_rpcdump(self):
        result = None        
        try:
            rpcd = self.engine.getModuleExploit("rpcdump")
            rpcd.link(self)
            rpcd.setPort(111)
            rpcd.run()
            found_os = rpcd.get_os()
            if found_os.base.lower() != "unknown":
                result = found_os
        except:
            pass
        
        return result
    
    
    def run_rpcdetect(self):     
        result = self.do_rpcdump()
        return result

