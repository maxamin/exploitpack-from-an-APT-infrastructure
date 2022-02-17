#! /bin/bash

TMP="/tmp/.asuscomm"

for o in 50465D 08606E 10BF48 3085A9; 
do
  echo "[#] creating MAC address file with $o OUI";
  #for (( i=0 ; i<=0xFFFFFF ; i++ )) ; do printf "$o%06X\n" $i ; done > "$TMP/$o.txt";
  echo "[#] bruteforcing IP address";
  cat "$TMP/$o.txt" | parallel --gnu -k -j0 'dig +noall A$(echo -n {} | md5sum | cut -d\   -f1).asuscomm.com +answer';
  echo "[#] done\n"
done

rm -fr $TMP
