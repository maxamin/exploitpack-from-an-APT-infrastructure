#!/bin/sh

cd git
wget --mirror --include-directories=/.git http://$1/.git
cd $1
git reset --hard

