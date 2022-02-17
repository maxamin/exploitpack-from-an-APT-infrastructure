# inherits self.target, self.engine from parent class osdetect

import libs.canvasos as canvasos
from libs import mysqllib

class sqldetect:
    def __init__(self):        
        return

    def run_sqldetect(self):
        
        result = None
        
        # MySQL OS detection through status detection
        try:
            self.log("SQL DETECT: Doing MySQL status os detection")
            m = mysqllib.MySQL()
            m.connect((self.host, 3306))
            for x in [ "root", "mysql", "anonymous", "nobody" ]:
                try:
                    ret = m.authenticate(x, '')
                    # This username failed move on to next one
                except:
                    continue
                if ["Access denied" not in ret ]:
                    self.log("SQL DETECT: Successfully found open MySQL account: "+x)
                    # add in vulnassess report the open mysql username that we found
                    self.target.add_knowledge("MySQL-OpenUsername",x,100)
                    self.log("SQL DETECT: Trying to discover os of remote SQL server")
                    tk = m.simple_command(mysqllib.COM_STATISTICS, 'status')
                    
                    for y in ["linux", "freebsd", "windows"]:
                        if y in tk.lower():
                            self.log("SQL DETECT: Discovered remote OS: " + y)
                            self.target.add_knowledge('OS', y, 100)
                            result = canvasos.new(y)
                            break			    
            m.close()
            del(m)

        except Exception, msg:
            self.log("SQL DETECT: MySQL detection failed (%s)" % msg)
                
        return result
