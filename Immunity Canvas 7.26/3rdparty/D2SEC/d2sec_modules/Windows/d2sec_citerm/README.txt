D2 Exploitation Pack
====================

Copyright (c) 2007-2008 DSquare Security, LLC


License information
-------------------

See the file "LICENSE.txt" for information on the history of this
software, terms & conditions for usage, and a DISCLAIMER OF ALL
WARRANTIES.


D2CiTerm - Owning Citrix & Terminal Services Client 
---------------------------------------------------

Several vulnerabilities can help you to compromise a Citrix server or 
a Terminal Services server. So the question is: what can you do when 
you have a privileged access on these Citrix and Terminal Services 
servers? The answer is simple: try to compromise Citrix and TS clients.

There are at least two interesting ways to access client data
1) Spying his session to get passwords from a published application
2) Accessing his local drives if they are mapped in the session

D2CiTerm is designed to help you in this kind of work. Here are two
demonstrations of this tool:

1) From a remote SYSTEM access after the exploitation of Citrix MPS 4.0 
   IMA Service Heap overflow: http://www.d2sec.com/d2citerm_1.htm
  
2) From a privileged Citrix session: http://www.d2sec.com/d2citerm_2.htm 


Main commands of D2CiTerm:

  cmd <num>          Start remote cmd.exe for session <num>
  disconnect <num>   Disconnect session <num>
  exit               Exit
  help               Display help
  info <num>         Get information about session <num>
  kill <pid>         Kill process with PID <pid>
  klog <num>         Start keylogger for session <num>
  list               Enumerate sessions
  process <num>      Get list of processes for session <num>
  setreg             Set registry settings to force drive mapping
  start <exe> <num>  Start <exe> for session <num>
