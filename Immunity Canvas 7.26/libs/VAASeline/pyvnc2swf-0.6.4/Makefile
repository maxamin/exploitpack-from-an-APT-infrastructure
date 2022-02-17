# Makefile
# $Id: Makefile,v 1.11 2005/08/22 02:55:53 euske Exp $

CVSROOT=:ext:euske@cvs.sourceforge.net:/cvsroot/vnc2swf
PACKAGE=pyvnc2swf
VERSION=0.6.4

all:

clean:
	-rm *.pyc *~ '.#*'

up: clean
	sshon2
	cvs -d$(CVSROOT) update
diff:
	sshon2
	cvs -d$(CVSROOT) diff -u
commit: clean
	sshon2
	cvs -d$(CVSROOT) commit

pack: clean
	ln -s $(PACKAGE) ../$(PACKAGE)-$(VERSION)
	tar c -z -C.. -f ../$(PACKAGE)-$(VERSION).tar.gz $(PACKAGE)-$(VERSION) \
		--dereference --numeric-owner --exclude CVS --exclude '.*'
	rm ../$(PACKAGE)-$(VERSION)
