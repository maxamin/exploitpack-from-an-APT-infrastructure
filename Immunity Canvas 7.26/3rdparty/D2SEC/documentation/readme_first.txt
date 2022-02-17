D2 Exploitation Pack (c) 2007-2010 DSquare Security, LLC

The D2 Exploitation Pack is a bundle of more than 220 security modules, most of 
which are designed to be used with Immunity CANVAS software (D2SEC/exploits), 
the others in standalone mode (D2SEC/d2sec_modules).

Several video demonstrations of some D2 tools are available on D2 website :

 - D2 Qualys Report Analyzer - http://www.d2sec.com/d2qualys.htm
 - D2Lotus - http://www.d2sec.com/d2lotus_1.htm and d2lotus_2.htm
 - D2CiTerm - http://www.d2sec.com/d2citerm_1.htm and d2citerm_2
 - D2 Nessus Report Analyzer - http://www.d2sec.com/d2nessus.htm
 - D2 Client Insider - http://www.d2sec.com/d2clientinsider.htm
 - D2 SMB MOSDEF - http://www.d2sec.com/d2smbmosdef.htm
 - D2 SSH MOSDEF - http://www.d2sec.com/d2sshmosdef.htm
 - D2 CMDLINE - http://www.d2sec.com/d2cmdline.htm

Several modules save informations in a sqlite3 database at  
D2SEC/d2sec_modules/All/d2sec_django/db_d2sec.sqlite3. It is necessary that the 
database is created with the D2SEC/d2sec_modules/All/d2sec_django/manage.py script.

You can use a classical sqlite3 client to consult this database or use a Django
Web interface with the same script manage.py. Use d2sec/d2sec as login/password 
with this interface. Django must be installed.
