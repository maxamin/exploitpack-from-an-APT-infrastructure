#!/usr/bin/env python
"""
Do all ips loads a file and runs a module on that file

Here's one easy way to get your file, if you have an nmap greppable database
sitting around (example is a user targeting ftpd):
grep 21/open *_nmap.txt  | awk {'print $2'} > allftpd.txt
extras/do_all_ips.py alldb.txt ftpd_check 
"""

import os,sys
ips=file(sys.argv[1],"rb").readlines()
modulename=sys.argv[2]
if len(sys.argv)>2:
    args=" ".join(sys.argv[3:])
else:
    args=""
    
for ip in ips:
    ip=ip.strip()
    command="python exploits/%s/%s.py -t %s %s"%(modulename,modulename,ip,args)
    print "Command: %s"%command
    os.system(command)