#!/bin/sh

uri=$1

cache=`curl -s "$1/config.ini" | grep -i cache`
echo "[#] $1"
echo $cache
